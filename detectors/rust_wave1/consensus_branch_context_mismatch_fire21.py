"""
consensus_branch_context_mismatch_fire21.py

Fire21 Rust lift for consensus branch context mismatch.

Confirmed source:
- zebra-network-upgrade-height-gate-gap-positive

Detector hits are candidate evidence only. The detector looks for
consensus validation that chooses a network upgrade, branch id, era, or
rule set from local/default context while the validated object exposes
its own height, network, branch, or upgrade context.
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
)


DETECTOR_ID = "rust_wave1.consensus_branch_context_mismatch_fire21"

_VALIDATION_FN_RE = re.compile(
    r"(?i)(verify|validate|check|accept|reject|read|parse|deserialize|"
    r"sighash|signature|proof|branch|upgrade|transaction|block|header|"
    r"consensus|era|ruleset|rule_set)"
)

_CONSENSUS_SURFACE_RE = re.compile(
    r"(?i)\b(NetworkUpgrade|ConsensusBranchId|BranchId|network_upgrade|"
    r"consensus_branch_id|branch_id|activation_height|sighash|SigHasher|"
    r"sapling|orchard|groth|halo2|zcash|consensus|era|rule_set|ruleset)\b"
)

_CONSENSUS_SINK_RE = re.compile(
    r"(?i)\b(verify|validate|check|read|from_bytes|Transaction::read|"
    r"SigHasher::new|sighash|verify_[A-Za-z0-9_]*proof|batch::verify|"
    r"verify_[A-Za-z0-9_]*|groth|halo2|orchard|sapling|"
    r"apply_consensus_rules)\s*\("
)

_OBJECT_CONTEXT_RE = re.compile(
    r"(?i)\b(?:tx|transaction|block|header|candidate|request|payload|"
    r"message|object|data|received|remote|claimed)"
    r"(?:\.[A-Za-z0-9_]+)*\.(?:height|network|network_upgrade|"
    r"branch_id|consensus_branch_id|era|rule_set|ruleset)\b"
    r"|\b(?:tx|transaction|block|header|candidate|request|payload|"
    r"message|object|data|received|remote|claimed)_"
    r"(?:height|network|upgrade|branch|era|rule_set|ruleset)\b"
)

_LOCAL_CONTEXT_RE = re.compile(
    r"(?i)\b(?:self|state|chain|context|ctx|params|config|cfg)"
    r"(?:\.[A-Za-z0-9_]+)*\.(?:tip_height|best_height|current_height|"
    r"latest_height|height|network|configured_network|default_network|"
    r"network_upgrade|branch_id|consensus_branch_id|era|rule_set|ruleset)\b"
    r"|\b(?:tip_height|best_height|current_height|latest_height|"
    r"local_height|state_height|default_network|configured_network|"
    r"local_network|default_branch|default_upgrade|current_upgrade|"
    r"current_branch|local_branch|local_era|default_era)\b"
)

_CURRENT_SELECTOR_RE = re.compile(
    r"(?is)\b(?:NetworkUpgrade|ConsensusBranchId|BranchId|Era|RuleSet)"
    r"\s*::\s*(?:current|for_height|at_height|from_height|"
    r"current_with_activation_height)\s*\((?P<args>[^;{}]{0,260})\)"
)

_DEFAULT_SELECTOR_RE = re.compile(
    r"(?is)(?:network_upgrade|consensus_branch_id|branch_id|era|rule_set|"
    r"ruleset)\s*\(\s*\)\s*\.\s*(?:unwrap_or|unwrap_or_else)"
    r"\s*\([^;{}]{0,180}\b(?:NetworkUpgrade|ConsensusBranchId|"
    r"BranchId|Era|RuleSet)\s*::"
)

_CONSTANT_SELECTOR_RE = re.compile(
    r"(?s)\b(?:let\s+)?(?:selected_|current_|local_|default_)?"
    r"(?:upgrade|branch|branch_id|era|ruleset|rule_set)\b"
    r"\s*=\s*(?:NetworkUpgrade|ConsensusBranchId|BranchId|Era|RuleSet)"
    r"\s*::\s*[A-Z][A-Za-z0-9_]*\b"
)

_EXPECTED_SELECTOR_GUARD_RE = re.compile(
    r"(?is)(?:expected|actual|current)_[A-Za-z0-9_]*(?:upgrade|branch|"
    r"era|rule)"
    r"[^;{}]{0,260}(?:==|!=)"
    r"[^;{}]{0,260}(?:network_upgrade|consensus_branch_id|branch_id|"
    r"era|rule_set|ruleset)\s*\("
    r"|(?:network_upgrade|consensus_branch_id|branch_id|era|rule_set|"
    r"ruleset)\s*\(\s*\)"
    r"[^;{}]{0,260}(?:==|!=)"
    r"[^;{}]{0,260}(?:expected|actual|current)_[A-Za-z0-9_]*"
    r"(?:upgrade|branch|era|rule)"
)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _compact(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _has_object_context(text: str) -> bool:
    return bool(_OBJECT_CONTEXT_RE.search(text))


def _args_bind_to_object_context(args: str) -> bool:
    return _has_object_context(args)


def _safe_expected_selector_guard(text: str) -> bool:
    return bool(_EXPECTED_SELECTOR_GUARD_RE.search(text))


def _local_current_selector_gap(text: str) -> str | None:
    for match in _CURRENT_SELECTOR_RE.finditer(text):
        args = match.group("args")
        if _args_bind_to_object_context(args):
            continue
        if not _LOCAL_CONTEXT_RE.search(args):
            continue
        return (
            "derives a consensus branch selector from local height or "
            f"network context `{_compact(match.group(0))}` while the "
            "validated object carries separate context"
        )
    return None


def _default_selector_gap(text: str) -> str | None:
    match = _DEFAULT_SELECTOR_RE.search(text)
    if not match:
        return None
    return (
        "defaults a missing object branch, upgrade, era, or rule-set field "
        f"with `{_compact(match.group(0))}` instead of rejecting or deriving "
        "from the object's consensus context"
    )


def _constant_selector_gap(text: str) -> str | None:
    match = _CONSTANT_SELECTOR_RE.search(text)
    if not match:
        return None
    return (
        "uses a constant consensus branch, upgrade, era, or rule-set "
        f"selector `{_compact(match.group(0))}` while the validated object "
        "carries separate context"
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        name = fn_name(fn, source)
        if not _VALIDATION_FN_RE.search(name):
            continue

        body_node = fn_body(fn)
        if body_node is None:
            continue

        signature = _signature_text(fn, body_node, source)
        body = body_text_nocomment(body_node, source)
        joined = f"{name}\n{signature}\n{body}"

        if not _CONSENSUS_SURFACE_RE.search(joined):
            continue
        if not _CONSENSUS_SINK_RE.search(body):
            continue
        if not _has_object_context(joined):
            continue
        if _safe_expected_selector_guard(joined):
            continue

        reason = (
            _local_current_selector_gap(joined)
            or _default_selector_gap(joined)
            or _constant_selector_gap(joined)
        )
        if reason is None:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "file": filepath,
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"consensus branch context mismatch in `{name}`: "
                    f"{reason}. Bind branch selection to the validated "
                    "object's height, network, branch, or upgrade context "
                    "before consensus proof or transaction validation. "
                    "attack_class=consensus-branch-context-mismatch."
                ),
            }
        )

    return hits
