"""
p2sh_sigop_mode_mismatch_fire21.py

Fire21 Rust lift for consensus divergence via P2SH sigop mode mismatch.

Seed miss:
- zebra-p2sh-sigop-legacy-mode-gap-positive

Flags consensus validation code that counts P2SH redeem-script sigops through
a hard-coded legacy or inaccurate mode while a block, transaction, height,
network-upgrade, or validation context is available. Hits are candidate
evidence only; Zebra 4.5.0 shapes are public-advisory recall baselines unless
extension-distinct source evidence is proven.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
    text_of,
)


DETECTOR_ID = "rust_wave1.p2sh_sigop_mode_mismatch_fire21"

_FN_NAME_RE = re.compile(
    r"(?i)(p2sh|sigop|sigops|script|redeem|input|transaction|tx|block|verify|check|valid)"
)

_P2SH_RE = re.compile(
    r"(?i)(p2sh|pay_to_script_hash|is_pay_to_script_hash|script_hash|scriptSig|"
    r"redeem(?:ed)?_script|redeemed_bytes|GetP2SHSigOpCount)"
)

_SIGOP_RE = re.compile(
    r"(?i)(sigop|sigops|sig_op|sig_ops|signature_operations|"
    r"MAX_BLOCK_SIGOPS|block verifier|consensus|zcashd)"
)

_VALIDATION_CONTEXT_RE = re.compile(
    r"(?i)\b(block|transaction|tx|input|spent_output|height|network_upgrade|"
    r"network|upgrade|activation|consensus_branch|branch_id|context|ctx|"
    r"validate|verify|transparent::Input|transparent::Output)\b"
)

_HARDCODED_LEGACY_CALL_RE = re.compile(
    r"(?is)("
    r"legacy_sigop_count_script\s*\(|"
    r"GetSigOpCount\s*\(\s*false\s*\)|"
    r"sig_op_count\s*\(\s*false\s*\)|"
    r"sigops?_count\s*\(\s*false\s*\)|"
    r"count_sigops?\s*\([^;{}]{0,220}\b(?:false|ScriptMode\s*::\s*Legacy|"
    r"SigOpMode\s*::\s*Legacy|SigopsMode\s*::\s*Legacy|Mode\s*::\s*Legacy|"
    r"LegacySigOps|LegacyRules|legacy_mode)\b|"
    r"fAccurate\s*[:=]\s*false|accurate\s*[:=]\s*false"
    r")"
)

_HARDCODED_MODE_BINDING_RE = re.compile(
    r"(?is)\b(?:let\s+)?(?P<var>"
    r"sigop_mode|sigops_mode|script_mode|mode|legacy_mode|accurate"
    r")\b\s*(?::[^=;]+)?=\s*(?P<value>"
    r"false|true|ScriptMode\s*::\s*Legacy|SigOpMode\s*::\s*Legacy|"
    r"SigopsMode\s*::\s*Legacy|Mode\s*::\s*Legacy|LegacySigOps|LegacyRules"
    r")"
)

_SIGOP_COUNT_WITH_VAR_TEMPLATE = (
    r"(?is)\b(?:count_sigops?|sigops?_count|sig_op_count|legacy_sigop_count_script)"
    r"\s*\([^;{{}}]{{0,260}}\b{var}\b"
)

_DERIVED_MODE_RE = re.compile(
    r"(?is)\b(?:let\s+)?(?:sigop_mode|sigops_mode|script_mode|mode)\b"
    r"\s*(?::[^=;]+)?=\s*[^;{}]{0,220}\b("
    r"block|transaction|tx|height|network_upgrade|network|upgrade|"
    r"activation|consensus_branch|branch_id|context|ctx|spent_output"
    r")\b[^;{}]{0,220}\b("
    r"sigop|script|mode|legacy|accurate|upgrade|activation|height"
    r")\b"
)


def _is_repo_test_file(filepath: str) -> bool:
    normalized = filepath.replace("\\", "/")
    if "/test_fixtures/" in normalized:
        return False
    return normalized.endswith("/tests.rs") or "/tests/" in normalized


def _compact(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _dangerous_mode_evidence(body: str) -> str | None:
    direct = _HARDCODED_LEGACY_CALL_RE.search(body)
    if direct:
        return _compact(direct.group(0))

    for binding in _HARDCODED_MODE_BINDING_RE.finditer(body):
        var_name = binding.group("var").lower()
        value = binding.group("value").lower()
        if value == "true" and "legacy" not in var_name:
            continue
        if value == "false" and "legacy" in var_name:
            continue

        var = re.escape(binding.group("var"))
        if re.search(_SIGOP_COUNT_WITH_VAR_TEMPLATE.format(var=var), body):
            return _compact(binding.group(0))

    return None


def run(tree, source: bytes, filepath: str):
    hits = []
    if _is_repo_test_file(filepath):
        return hits

    file_text = source.decode("utf-8", errors="replace")

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        fn_text = text_of(fn, source)
        body_nc = body_text_nocomment(body, source)
        haystack = f"{filepath}\n{name}\n{fn_text}"

        if not _P2SH_RE.search(haystack):
            continue
        if not _SIGOP_RE.search(haystack):
            continue
        if not _VALIDATION_CONTEXT_RE.search(haystack):
            continue

        evidence = _dangerous_mode_evidence(body_nc)
        if evidence is None:
            continue

        if _DERIVED_MODE_RE.search(body_nc) and "legacy_sigop_count_script" not in body_nc:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "critical",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"fn `{name}` counts P2SH redeem-script sigops with hard-coded "
                    f"mode evidence `{evidence}` while block/transaction consensus "
                    "context is available. Derive the sigop mode from the validated "
                    "object or network-upgrade context before counting."
                ),
            }
        )

    return hits
