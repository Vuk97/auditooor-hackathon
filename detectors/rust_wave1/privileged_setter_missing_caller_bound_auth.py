"""
privileged_setter_missing_caller_bound_auth.py

Narrow Rust admin-bypass sibling detector.

Flags public privileged setter/rotator functions that directly mutate
owner/admin/operator/authority/config state without an obvious caller-bound
auth check in the same function body or Anchor account context.

Scope is intentionally narrow:
  - function name must look like a privileged setter/rotator
  - body must directly write privileged state
  - comments are stripped before matching
  - explicit local auth signals suppress the hit

This complements, but is narrower than:
  - admin_origin_or_role_guard_missing.py
  - missing_require_auth_on_mutation.py
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    source_nocomment,
    text_of,
)


_PRIV_FN_RE = re.compile(
    r"(?ix)"
    r"^(?:"
    r"(?:set|change|update|rotate|transfer)\s*[_]?"
    r"(?:admin|owner|operator|authority|governance|governor|controller|config)|"
    r"(?:pause|unpause)"
    r")$"
)

_PRIV_WRITE_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\b(?:cfg|config|state|settings|self|ctx\s*\.\s*accounts\s*\.\s*\w+)"
    r"\s*\.\s*(?:admin|owner|operator|authority|governance|governor|controller|paused|config)\s*=|"
    r"\b\w+\s*\.\s*(?:admin|owner|operator|authority|governance|governor|controller|paused)\s*=|"
    r"::\s*(?:put|insert|mutate|try_mutate)\s*\([^;\n]*(?:Admin|Owner|Operator|Authority|Config|Paused)|"
    r"\.\s*(?:set|update|insert)\s*\([^;\n]*(?:\"|')(?:admin|owner|operator|authority|config|paused)(?:\"|')|"
    r"Symbol::new\s*\([^;\n]*(?:\"|')(?:admin|owner|operator|authority|config|paused)(?:\"|')"
    r")"
)

_AUTH_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\.require_auth\s*\(|"
    r"\bensure_root\s*\(|"
    r"\bensure_signed\s*\(|"
    r"\bensure_origin\s*\(|"
    r"\bhas_role\s*\(|"
    r"\bonly_owner\s*\(|"
    r"\bonly_admin\s*\(|"
    r"\bonly_operator\s*\(|"
    r"\bassert_admin\s*\(|"
    r"\bassert_owner\s*\(|"
    r"\bcheck_admin\s*\(|"
    r"\bcheck_owner\s*\(|"
    r"\.is_signer\b|"
    r"\bensure!\s*\([^;\n]*(?:has_role|is_signer)|"
    r"\bassert(?:_eq)?!\s*\([^;\n]*(?:has_role|is_signer)"
    r")"
)

_STRING_RE = re.compile(
    r"(?s)b?r#*\".*?\"#*|b?\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'"
)

_ANCHOR_MARKER_RE = re.compile(
    r"(anchor_lang::|use\s+anchor_lang|Context\s*<|Signer\s*<|#\[\s*derive\s*\(\s*Accounts\s*\)\s*\])"
)

_ANCHOR_SAFE_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"has_one\s*=|"
    r"constraint\s*=|"
    r"signer\b"
    r")"
)

_PRIV_ROLE_TOKEN_RE = re.compile(
    r"(?ix)(?:^|[.:>(\s])(?:admin|owner|operator|authority|governance|governor|controller)\b"
)
_CALLER_EXPR_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)*"
    r"(?:caller|who|authority|admin|owner|operator|governance|governor|controller)"
    r"(?:\s*\.\s*key\s*\(\s*\))?"
    r"|invoker\s*\(\s*\)"
    r")"
)
_COMPARISON_RE = re.compile(
    r"(?ix)"
    r"([A-Za-z_][A-Za-z0-9_:\.<>\(\)]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\s*\))?)*)"
    r"\s*(==|!=)\s*"
    r"([A-Za-z_][A-Za-z0-9_:\.<>\(\)]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\s*\))?)*)"
)


def _signature_text(fn, source: bytes) -> str:
    full = text_of(fn, source)
    return full.split("{", 1)[0]


def _blank_preserve_newlines(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_string_literals(src: str) -> str:
    return _STRING_RE.sub(_blank_preserve_newlines, src)


def _extract_braced_body(text: str, open_pos: int) -> str:
    depth = 0
    start = None
    for idx in range(open_pos, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
            if depth == 1:
                start = idx + 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:idx]
    return ""


def _anchor_context_names(signature: str) -> list[str]:
    names = re.findall(r"Context\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>", signature)
    return names


def _normalize_expr(expr: str) -> str:
    return re.sub(r"\s+", "", expr)


def _looks_like_privileged_guard_expr(expr: str) -> bool:
    normalized = _normalize_expr(expr)
    return bool(_PRIV_ROLE_TOKEN_RE.search(normalized))


def _has_caller_bound_guard(body_text: str) -> bool:
    for left, _, right in _COMPARISON_RE.findall(body_text):
        left_is_caller = bool(_CALLER_EXPR_RE.fullmatch(left.strip()))
        right_is_caller = bool(_CALLER_EXPR_RE.fullmatch(right.strip()))
        if left_is_caller and _looks_like_privileged_guard_expr(right):
            return True
        if right_is_caller and _looks_like_privileged_guard_expr(left):
            return True
    return False


def _has_key_eq_guard(body_text: str) -> bool:
    for macro_name in ("require_keys_eq!", "assert_keys_eq!"):
        for args_text in re.findall(rf"\b{re.escape(macro_name)}\s*\(([^;\n]*)\)", body_text):
            if _CALLER_EXPR_RE.search(args_text) and _PRIV_ROLE_TOKEN_RE.search(args_text):
                return True
            if args_text.count(",") >= 1:
                left, right = [part.strip() for part in args_text.split(",", 1)]
                left_is_caller = bool(_CALLER_EXPR_RE.fullmatch(left))
                right_is_caller = bool(_CALLER_EXPR_RE.fullmatch(right))
                if left_is_caller and _looks_like_privileged_guard_expr(right):
                    return True
                if right_is_caller and _looks_like_privileged_guard_expr(left):
                    return True
    return False


def _anchor_context_has_guard(signature: str, source_text: str) -> bool:
    for ctx_name in _anchor_context_names(signature):
        struct_match = re.search(r"\bstruct\s+" + re.escape(ctx_name) + r"\b", source_text)
        if not struct_match:
            continue
        open_pos = source_text.find("{", struct_match.end())
        if open_pos == -1:
            continue
        struct_body = _extract_braced_body(source_text, open_pos)
        if not _ANCHOR_SAFE_RE.search(struct_body):
            continue
        for field_match in re.finditer(
            r"(?is)(?P<attrs>(?:#\[[^\]]*\]\s*)*)"
            r"pub\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<typ>[^,\n{]+)",
            struct_body,
        ):
            field_name = field_match.group("name")
            if not re.fullmatch(
                r"(?ix)(?:authority|admin|owner|operator|governance|governor|controller)",
                field_name,
            ):
                continue
            attrs = field_match.group("attrs")
            field_typ = field_match.group("typ")
            if not re.search(r"\bSigner\s*<", field_typ) and not re.search(
                r"(?i)\bsigner\b",
                attrs,
            ):
                continue
            if re.search(r"\bhas_one\s*=\s*" + re.escape(field_name) + r"\b", struct_body):
                return True
            if re.search(
                r"\bconstraint\s*=\s*[^;\n#]*\b" + re.escape(field_name) + r"\b",
                struct_body,
            ):
                return True
            return True
    return False


def _has_auth(fn, body_text: str, source: bytes, source_text: str) -> bool:
    if _AUTH_RE.search(body_text):
        return True
    if _has_caller_bound_guard(body_text):
        return True
    if _has_key_eq_guard(body_text):
        return True
    signature = _signature_text(fn, source)
    anchor_text = source_nocomment(source)
    if _ANCHOR_MARKER_RE.search(anchor_text) and _anchor_context_has_guard(signature, anchor_text):
        return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    source_text = _strip_string_literals(source_nocomment(source))

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        if not _PRIV_FN_RE.search(name):
            continue

        body_nc = _strip_string_literals(body_text_nocomment(body, source))
        if not _PRIV_WRITE_RE.search(body_nc):
            continue
        if _has_auth(fn, body_nc, source, source_text):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, 220),
            "message": (
                f"pub fn `{name}` directly mutates privileged owner/admin/"
                f"operator/authority/config state without an obvious caller-"
                f"bound auth check. Add require_auth, ensure_root/"
                f"ensure_signed-derived authorization, has_role/only_owner, "
                f"or Anchor signer validation."
            ),
        })

    return hits
