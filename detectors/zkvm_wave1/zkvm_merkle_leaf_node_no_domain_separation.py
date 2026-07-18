from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from . import _util
except ImportError:
    import importlib.util as _ilu
    import sys
    _UTIL = Path(__file__).resolve().parent / "_util.py"
    _spec = _ilu.spec_from_file_location("zkvm_wave1__util", _UTIL)
    _util = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)

DETECTOR_ID = "zkvm_merkle_leaf_node_no_domain_separation"

# leaf hash and internal-node hash should differ by a domain tag / tweak / prefix.
_LEAF = re.compile(r"(hash_leaf|leaf_hash|hash_single|hash_data)\s*\(")
_NODE = re.compile(r"(hash_combine|combine|compress|hash_two|hash_pair|hash_internal|hash_nodes?)\s*\(")
_DOMAIN = re.compile(r"(tweak|domain|0x0[01]\b|LEAF_|NODE_|prefix|tag|separat)", re.I)


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_merkle_file(source):
        return []
    src = _util.strip_comments(source)
    lm = _LEAF.search(src)
    nm = _NODE.search(src)
    if not (lm and nm):
        return []
    # if any domain-separation signal exists in the file, assume handled
    if _DOMAIN.search(src):
        return []
    line, col = _util.line_col(source, lm.start())
    return [{
        "detector_id": DETECTOR_ID,
        "line": line, "col": col, "severity": "high",
        "message": (
            f"Merkle tree hashes leaves (`{lm.group(1)}`) and internal nodes (`{nm.group(1)}`) "
            f"with no visible domain-separation signal (tweak / domain tag / 0x00 vs 0x01 prefix) "
            f"anywhere in this file. Without leaf-vs-node domain separation a leaf can be "
            f"reinterpreted as an internal node (second-preimage / commitment-binding break)."),
        "snippet": _util.snippet_at(src, lm.start()),
    }]
