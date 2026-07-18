"""
rust_oracle_deviation_cached_baseline_fire29.py

Rust Fire29 lift for oracle-price-manipulation.

Flags oracle update paths that compare a new price or heartbeat sample against
a mutable cached baseline, write the new sample into that live baseline, and
only then execute another acceptance guard. The vulnerable shape lets an
invalid sample poison the next comparison baseline before freshness,
confidence, positivity, source, or round guards have all completed.

Capability posture: detector-fixture smoke only. A hit is source-review input,
not submit-ready proof.

Source refs:
  - reference/patterns.dsl/r94-loop-oracle-heartbeat-no-fallback.yaml
  - reference/invariants/oracle-freshness.md
  - reference/patterns.dsl/glider-pyth-oracle-no-freshness-validation.yaml
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
)


_ORACLE_CONTEXT_RE = re.compile(
    r"(?i)(oracle|price|pyth|chainlink|feed|round|heartbeat|fresh|stale|"
    r"publish_time|updated_at|confidence|deviation|twap|answer)"
)

_BASELINE_NAME_RE = re.compile(
    r"(?i)(cache|cached|last|previous|prev|baseline|reference|stored|"
    r"anchor|observed|good|accepted)"
)
_PRICE_OR_TIME_RE = re.compile(
    r"(?i)(price|answer|rate|round|timestamp|publish_time|updated_at|time)"
)

_BASELINE_EXPR_RE = re.compile(
    r"(?i)\b(?:self|state|market|feed|oracle|cache|storage|ctx|account)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*){0,4}"
    r"\s*\.\s*[A-Za-z_][A-Za-z0-9_]*"
    r"(?:cache|cached|last|previous|baseline|reference|stored|anchor|"
    r"observed|good|accepted)"
    r"[A-Za-z0-9_]*(?:price|answer|rate|round|timestamp|publish_time|"
    r"updated_at|time)"
)

_BASELINE_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\:[^=;]+)?=\s*(?P<rhs>[^;]{1,360});"
)

_CACHE_WRITE_RE = re.compile(
    r"(?is)(?P<stmt>"
    r"(?P<lhs>\b(?:self|state|market|feed|oracle|cache|storage|ctx|account)"
    r"[^;\n=]{1,220})"
    r"\s*=\s*(?P<rhs>[^;]{1,260});)"
)

_STAGING_WRITE_RE = re.compile(
    r"(?i)(pending|candidate|staged|tmp|scratch|shadow|proposed|local)"
)

_GUARD_STMT_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:ensure|require|assert|debug_assert)!\s*\([^;]{0,900}\)|"
    r"\b(?:ensure|require)\s*\([^;]{0,900}\)\s*\?|"
    r"\bif\s+[^\{;]{0,900}\{[^{}]{0,520}"
    r"(?:return\s+Err|Err\s*\(|panic!|return\s+false)"
    r"[^{}]{0,260}\}"
    r")"
)

_FIRST_PHASE_GUARD_RE = re.compile(
    r"(?i)(abs_diff|deviation|deviation_bps|max_deviation|bps|basis|"
    r"percent|max_change|min_price|max_price|heartbeat|fresh|stale|"
    r"max_age|publish_time|updated_at|timestamp|round)"
)

_LATE_GUARD_RE = re.compile(
    r"(?i)(publish_time|updated_at|timestamp|confidence|conf|expo|exponent|"
    r"positive|nonzero|zero|>\s*0|max_age|stale|fresh|heartbeat|source|"
    r"signer|authorized|round|sequence|status|paused|circuit|bounds|valid|"
    r"deviation)"
)

_ROLLBACK_RE = re.compile(
    r"(?i)(rollback|restore|revert_cache|reset_cache|old_cache|previous_price)"
)


def _has_oracle_context(name: str, body: str) -> bool:
    return bool(_ORACLE_CONTEXT_RE.search(name) or _ORACLE_CONTEXT_RE.search(body))


def _baseline_vars_before(body: str, offset: int) -> set[str]:
    vars_found: set[str] = set()
    for match in _BASELINE_ASSIGN_RE.finditer(body, 0, offset):
        var_name = match.group("var")
        rhs = match.group("rhs")
        combined = f"{var_name} {rhs}"
        if not _BASELINE_NAME_RE.search(combined):
            continue
        if not _PRICE_OR_TIME_RE.search(combined):
            continue
        if not (_BASELINE_EXPR_RE.search(rhs) or _BASELINE_NAME_RE.search(var_name)):
            continue
        vars_found.add(var_name)
    return vars_found


def _contains_var(text: str, var_name: str) -> bool:
    return re.search(rf"\b{re.escape(var_name)}\b", text) is not None


def _guard_uses_baseline(guard_text: str, baseline_vars: set[str]) -> bool:
    if _BASELINE_EXPR_RE.search(guard_text):
        return True
    return any(_contains_var(guard_text, var_name) for var_name in baseline_vars)


def _has_first_phase_guard(body: str, offset: int, baseline_vars: set[str]) -> bool:
    for guard in _GUARD_STMT_RE.finditer(body, 0, offset):
        guard_text = guard.group(0)
        if not _FIRST_PHASE_GUARD_RE.search(guard_text):
            continue
        if _guard_uses_baseline(guard_text, baseline_vars):
            return True
    return False


def _has_late_guard(body: str, start: int) -> bool:
    for guard in _GUARD_STMT_RE.finditer(body, start):
        guard_text = guard.group(0)
        if _LATE_GUARD_RE.search(guard_text):
            return True
    return False


def _has_rollback_window(body: str, write_end: int) -> bool:
    window = body[write_end : write_end + 420]
    return bool(_ROLLBACK_RE.search(window) and _CACHE_WRITE_RE.search(window))


def _first_cached_baseline_write_before_final_guard(body: str) -> tuple[str, str] | None:
    for write in _CACHE_WRITE_RE.finditer(body):
        lhs = " ".join(write.group("lhs").split())
        rhs = write.group("rhs")
        if not (_BASELINE_NAME_RE.search(lhs) and _PRICE_OR_TIME_RE.search(lhs)):
            continue
        if _STAGING_WRITE_RE.search(lhs):
            continue
        if not _ORACLE_CONTEXT_RE.search(f"{lhs} {rhs}"):
            continue

        baseline_vars = _baseline_vars_before(body, write.start())
        prefix = body[: write.start()]
        has_direct_baseline_read = _BASELINE_EXPR_RE.search(prefix) is not None
        if not baseline_vars and not has_direct_baseline_read:
            continue

        if not _has_first_phase_guard(body, write.start(), baseline_vars):
            continue

        if not _has_late_guard(body, write.end()):
            continue

        if _has_rollback_window(body, write.end()):
            continue

        return lhs, "cached baseline write occurs before a later oracle guard"
    return None


def _is_candidate_function(fn_node, name: str, body: str, source: bytes) -> bool:
    if is_pub(fn_node, source):
        return True
    return bool(
        re.search(
            r"(?i)(update|refresh|set|submit|ingest|validate|accept|record)_?"
            r"(price|oracle|feed|round|sample)",
            name,
        )
        or _ORACLE_CONTEXT_RE.search(body)
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body_node = fn_body(fn)
        if body_node is None:
            continue

        name = fn_name(fn, source)
        body = body_text_nocomment(body_node, source)
        if not _is_candidate_function(fn, name, body, source):
            continue
        if not _has_oracle_context(name, body):
            continue

        hit = _first_cached_baseline_write_before_final_guard(body)
        if hit is None:
            continue

        lhs, reason = hit
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"Rust oracle update fn `{name}` compares a new sample "
                    f"against a mutable cached baseline and writes `{lhs}` "
                    f"before all oracle guards finish. {reason}; invalid "
                    f"freshness, confidence, source, or round data can poison "
                    f"the next deviation baseline."
                ),
            }
        )
    return hits
