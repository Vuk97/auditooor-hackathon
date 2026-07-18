"""
zebra_network_upgrade_height_gate_gap.py

Flags Rust consensus or proof validation functions that select a Zcash
network upgrade, consensus branch id, or proof mode without deriving that
selector from both the configured network and block height.

Zebra-fit recall class: network-upgrade height-gate validation gaps.
Safe idioms include `NetworkUpgrade::current(network, height)`,
`ConsensusBranchId::current(network, height)`, and activation-height
guards that bind the rule to the configured network.
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


_FN_NAME_RE = re.compile(
    r"(check|valid|verify|validate|accept|reject|read|parse|deserialize|"
    r"sighash|signature|proof|branch|upgrade|transaction|block|merkle|"
    r"history|subsidy|coinbase|commitment)",
    re.IGNORECASE,
)

_CONSENSUS_SURFACE_RE = re.compile(
    r"(NetworkUpgrade|ConsensusBranchId|BranchId|network_upgrade\s*\(|"
    r"consensus_branch_id|nConsensusBranchId|SigHasher|sighash|"
    r"zcash_primitives|zcash_history|sapling|orchard|groth|halo2|"
    r"ZIP[-_ ]?\d+)",
    re.IGNORECASE,
)

_UPGRADE_OR_BRANCH_SELECTOR_RE = re.compile(
    r"(NetworkUpgrade::(?:Overwinter|Sapling|Blossom|Heartwood|Canopy|"
    r"Nu5|Nu6|Nu6_1|Nu7|ZFuture)|"
    r"\.network_upgrade\s*\(|NetworkUpgrade::try_from\s*\(|"
    r"\.branch_id\s*\(|BranchId::try_from\s*\(|"
    r"ConsensusBranchId\s*\(|consensus_branch_id)",
    re.IGNORECASE,
)

_CONSENSUS_SINK_RE = re.compile(
    r"(verify|check|validate|read\s*\(|from_bytes\s*\(|"
    r"Transaction::read|SigHasher::new|sighash|verify_.*proof|"
    r"batch::verify|groth|halo2|orchard|sapling|merkle|history)",
    re.IGNORECASE,
)

_SAFE_CURRENT_RE = re.compile(
    r"(NetworkUpgrade|ConsensusBranchId)::current(?:_with_activation_height)?"
    r"\s*\(\s*&?\s*[A-Za-z_][\w\.]*\s*,\s*&?\s*[A-Za-z_][\w\.]*",
)

_SAFE_ACTIVATION_RE = re.compile(
    r"(\.activation_height\s*\([^)]*(network|net|params)[^)]*\)"
    r"(?s:.{0,240})(height|Height)|"
    r"(height|Height)(?s:.{0,240})\.activation_height\s*\([^)]*"
    r"(network|net|params)[^)]*\))",
    re.IGNORECASE,
)

_SAFE_NETWORK_HEIGHT_MATCH_RE = re.compile(
    r"(match\s*\([^)]*(network|net|Network::)[^)]*,[^)]*(height|Height)"
    r"[^)]*\)|"
    r"match\s*\([^)]*(height|Height)[^)]*,[^)]*(network|net|Network::)"
    r"[^)]*\)|"
    r"minimum_difficulty_spacing_for_height\s*\([^)]*(network|net)"
    r"[^)]*,[^)]*(height|Height)[^)]*\))",
    re.IGNORECASE,
)

_SAFE_EXPECTED_SELECTOR_RE = re.compile(
    r"((expected|current|actual)_[A-Za-z_]*(upgrade|branch|nu)|"
    r"(upgrade|branch|nu)_[A-Za-z_]*(expected|current|actual))"
    r"(?s:.{0,160})(==|!=)|"
    r"(==|!=)(?s:.{0,160})"
    r"((expected|current|actual)_[A-Za-z_]*(upgrade|branch|nu)|"
    r"(upgrade|branch|nu)_[A-Za-z_]*(expected|current|actual))",
    re.IGNORECASE,
)

_PARAMETER_MODULE_RE = re.compile(
    r"/parameters/(network_upgrade|network)(?:\.rs|/)|"
    r"/parameters/(tests|arbitrary)\.rs$|/transaction/(tests|arbitrary)\.rs$"
)


def _compact(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _function_signature(fn, source: bytes) -> str:
    text = text_of(fn, source)
    return text.split("{", 1)[0]


def _has_network_height_binding(text: str) -> bool:
    if _SAFE_CURRENT_RE.search(text):
        return True
    if _SAFE_ACTIVATION_RE.search(text):
        return True
    if _SAFE_NETWORK_HEIGHT_MATCH_RE.search(text):
        return True
    return False


def _has_expected_selector_guard(text: str) -> bool:
    return bool(_SAFE_EXPECTED_SELECTOR_RE.search(text))


def _skip_low_level_parameter_helper(filepath: str, name: str) -> bool:
    if filepath.endswith("/parameters/arbitrary.rs"):
        return True
    if not _PARAMETER_MODULE_RE.search(filepath):
        return False
    return bool(
        re.search(
            r"^(current|current_with_activation_height|activation_height|"
            r"is_activation_height|branch_id|branch_id_list|try_from|"
            r"iter|target_spacing|averaging_window_timespan)",
            name,
        )
    )


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn in function_items(root):
        if in_test_cfg(fn, source):
            continue

        name = fn_name(fn, source)
        if _skip_low_level_parameter_helper(filepath, name):
            continue
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        signature = _function_signature(fn, source)
        body_nc = body_text_nocomment(body, source)
        haystack = f"{signature}\n{body_nc}"

        if not _CONSENSUS_SURFACE_RE.search(haystack):
            continue
        if not _UPGRADE_OR_BRANCH_SELECTOR_RE.search(haystack):
            continue
        if not _CONSENSUS_SINK_RE.search(body_nc):
            continue

        if _has_network_height_binding(haystack):
            continue
        if _has_expected_selector_guard(haystack):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"fn `{name}` selects a network upgrade, consensus "
                    f"branch id, or proof mode without a local network-height "
                    f"binding. Zebra consensus paths should derive branch "
                    f"or upgrade selection with NetworkUpgrade::current("
                    f"network, height), ConsensusBranchId::current(network, "
                    f"height), or an activation-height guard before proof "
                    f"or transaction validation. Selector evidence: "
                    f"`{_compact(_UPGRADE_OR_BRANCH_SELECTOR_RE.search(haystack).group(0))}`."
                ),
            }
        )

    return hits
