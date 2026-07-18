"""
go-integer-overflow-config-clamp-fire31.py

Detects Go config, price, factor, limit, or threshold values narrowed with a
native integer cast before range validation. Large inputs can silently wrap
into an apparently valid value and then flow into configured limits.

The detector is intentionally narrow:
- source expression must look config-like,
- cast must narrow to int8/int16/int32 or uint8/uint16/uint32,
- no rejecting guard may appear before the cast for the source value,
- the narrowed alias must either be validated/clamped after the cast or flow
  into a config-like sink.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-integer-overflow-config-clamp-fire31"

_CONFIG_TERM_RE = re.compile(
    r"(cfg|config|params|settings|price|factor|threshold|limit|cap|max|min|"
    r"rate|ratio|bps|multiplier|scale|window|timeout|size|risk|leverage|"
    r"slippage|spread|tick|margin|haircut)",
    re.IGNORECASE,
)

_CONFIG_SINK_RE = re.compile(
    r"(Config|Params|Settings|Price|Factor|Threshold|Limit|Cap|Max|Min|"
    r"Rate|Ratio|Bps|Multiplier|Scale|Window|Timeout|Size|Risk|Leverage|"
    r"Slippage|Spread|Tick|Margin|Haircut)"
)

_NARROW_CAST_ASSIGN_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*(?::=|=)\s*"
    r"(?P<cast>u?int(?:8|16|32))\s*\((?P<expr>[^)\n]+)\)"
)

_IF_BLOCK_RE = re.compile(
    r"if\s+(?P<cond>[^{}]{0,320})\{(?P<body>[^{}]{0,320})\}",
    re.DOTALL,
)

_RETURN_OR_PANIC_RE = re.compile(r"\b(return|panic)\b")
_COMPARISON_RE = re.compile(
    r"(?:>|<|>=|<=|overflow|underflow|fits|fit|MaxUint|MaxInt|math\.Max)",
    re.IGNORECASE,
)
_NARROW_LIMIT_RE = re.compile(
    r"(?:MaxUint(?:8|16|32)|MaxInt(?:8|16|32)|math\.Max(?:U?int)?(?:8|16|32)|"
    r"1\s*<<\s*(?:8|16|32)|255|65535|4294967295|uint(?:8|16|32)|int(?:8|16|32)|"
    r"overflow|underflow|fits|fit)",
    re.IGNORECASE,
)

_CLAMP_ASSIGN_RE = re.compile(
    r"if\s+(?P<alias>[A-Za-z_]\w*)\s*>\s*(?P<limit>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)"
    r"\s*\{\s*(?P=alias)\s*=\s*(?P=limit)\s*\}",
    re.DOTALL,
)

_MIN_CLAMP_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*(?::=|=)\s*"
    r"(?:min|math\.Min|Min[A-Za-z_]\w*|Clamp[A-Za-z_]\w*)\s*\(",
    re.IGNORECASE,
)

_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'' )


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments_and_strings(src: str) -> str:
    src = re.sub(r"//.*", _blank, src)
    src = re.sub(r"/\*.*?\*/", _blank, src, flags=re.S)
    return _STRING_RE.sub(_blank, src)


def _source_terms(expr: str) -> set[str]:
    tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", expr))
    dotted = set(re.findall(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\b", expr))
    terms: set[str] = set()
    for token in tokens | dotted:
        if _CONFIG_TERM_RE.search(token):
            terms.add(token)
    if _CONFIG_TERM_RE.search(expr):
        terms.add(expr.strip())
    return {term for term in terms if term}


def _mentions_any(text: str, terms: set[str]) -> bool:
    for term in terms:
        if re.search(r"\b" + re.escape(term) + r"\b", text):
            return True
    return False


def _has_pre_cast_reject_guard(prefix: str, terms: set[str]) -> bool:
    if not terms:
        return False
    for match in re.finditer(r"if\s+(?P<cond>[^{]{0,360})\{", prefix):
        cond = match.group("cond")
        tail = prefix[match.end(): match.end() + 520]
        block = cond + tail
        if not _mentions_any(block, terms):
            continue
        if not _RETURN_OR_PANIC_RE.search(tail):
            continue
        if _COMPARISON_RE.search(cond) or re.search(r"(==|!=)", cond):
            return True
        if _NARROW_LIMIT_RE.search(block):
            return True
    return False


def _has_post_cast_validation(tail: str, alias: str) -> bool:
    alias_re = re.compile(r"\b" + re.escape(alias) + r"\b")
    for match in _IF_BLOCK_RE.finditer(tail[:900]):
        block = match.group(0)
        if not alias_re.search(block):
            continue
        if _COMPARISON_RE.search(match.group("cond")) and (
            _RETURN_OR_PANIC_RE.search(match.group("body"))
            or re.search(r"\b" + re.escape(alias) + r"\b\s*=", match.group("body"))
        ):
            return True
    return bool(
        _CLAMP_ASSIGN_RE.search(tail[:900])
        and re.search(r"\b" + re.escape(alias) + r"\b", _CLAMP_ASSIGN_RE.search(tail[:900]).group(0))
    )


def _has_alias_config_sink(tail: str, alias: str) -> bool:
    alias_pat = re.escape(alias)
    assign_re = re.compile(
        r"\b(?:[A-Za-z_]\w*\.)*(?=[A-Za-z_]\w*" + _CONFIG_SINK_RE.pattern + r")"
        r"[A-Za-z_]\w*\s*(?:=|\+=)\s*(?:u?int(?:64)?\s*\()?"
        r"[^;\n]*\b" + alias_pat + r"\b",
        re.IGNORECASE,
    )
    setter_re = re.compile(
        r"\bSet[A-Za-z_]\w*" + _CONFIG_SINK_RE.pattern
        + r"[A-Za-z_]\w*\s*\([^)]*\b" + alias_pat + r"\b",
        re.IGNORECASE | re.DOTALL,
    )
    literal_re = re.compile(
        r"\b[A-Za-z_]\w*" + _CONFIG_SINK_RE.pattern
        + r"[A-Za-z_]\w*\s*:\s*(?:u?int(?:64)?\s*\()?[^,\n}]*\b"
        + alias_pat
        + r"\b",
        re.IGNORECASE,
    )
    return bool(assign_re.search(tail[:1200]) or setter_re.search(tail[:1200]) or literal_re.search(tail[:1200]))


def _config_cast_reason(body_text: str) -> str | None:
    for match in _NARROW_CAST_ASSIGN_RE.finditer(body_text):
        expr = match.group("expr").strip()
        if not _CONFIG_TERM_RE.search(expr):
            continue
        terms = _source_terms(expr)
        if _has_pre_cast_reject_guard(body_text[: match.start()], terms):
            continue

        alias = match.group("alias")
        tail = body_text[match.end():]
        has_validation = _has_post_cast_validation(tail, alias)
        has_sink = _has_alias_config_sink(tail, alias)
        if not has_validation and not has_sink:
            continue

        if has_validation and has_sink:
            return (
                f"{alias} narrows {expr} with {match.group('cast')} before "
                f"post-cast validation and then updates configuration"
            )
        if has_validation:
            return (
                f"{alias} narrows {expr} with {match.group('cast')} before "
                f"post-cast validation"
            )
        return (
            f"{alias} narrows {expr} with {match.group('cast')} before "
            f"flowing into a config-like sink"
        )
    return None


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        if not _CONFIG_TERM_RE.search(fn_text):
            continue

        body_text = _strip_comments_and_strings(engine.text(body))
        reason = _config_cast_reason(body_text)
        if reason is None:
            continue

        hits.append(
            {
                "severity": "medium",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` casts a config-like value to a narrower "
                    f"integer before validating it: {reason}. Validate the "
                    f"original wide value against the narrow type and "
                    f"business bounds before casting. "
                    f"(class: integer-overflow-clamp)"
                ),
            }
        )
    return hits
