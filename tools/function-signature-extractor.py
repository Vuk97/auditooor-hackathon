#!/usr/bin/env python3
"""function-signature-extractor — Walk a repo, extract one JSON record per
function (per sub-report 06 §"Function-signature extractor").

Language support:
  - Go:       regex extractor.
  - Solidity: tree-sitter-solidity (Wave-9); regex fallback when unavailable.
  - Rust:     structured regex extractor (multi-line signatures + where-clause
              tolerant), tree-sitter-rust not required.

CLI:
    python3 tools/function-signature-extractor.py <repo-path> \
        --language go [--out report.jsonl] [--audit-pin <sha>] [--limit N]

Output: one JSON object per line:
    {
      "file_path": "protocol/x/affiliates/keeper/msg_server.go",
      "language": "go",
      "function_name": "UpdateAffiliateTiers",
      "function_signature": "func (k msgServer) UpdateAffiliateTiers(...)",
      "receiver_type": "msgServer",
      "visibility": "exported",
      "line_start": 142, "line_end": 187,
      "modifiers": ["pointer-receiver"],
      "params": [{"name":"ctx","type":"context.Context"}, ...],
      "return_types": ["*types.MsgUpdateAffiliateTiersResponse","error"],
      "calls_made": ["k.GetAuthority","sdk.UnwrapSDKContext","..."],
      "guards_detected": ["authority-check","blocked-addr-bypass-skip"]
    }

Solidity records additionally carry:
      "state_mutability": "view"|"pure"|"payable"|"nonpayable",
      "is_constructor": bool,
      "is_fallback": bool,
      "is_receive": bool,
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# tree-sitter-solidity availability flag (Wave-9)
# ---------------------------------------------------------------------------

_TREE_SITTER_SOLIDITY_AVAILABLE = False
try:
    import tree_sitter_solidity as _tss_mod  # type: ignore
    from tree_sitter import Language as _TSLanguage, Parser as _TSParser  # type: ignore
    _TREE_SITTER_SOLIDITY_AVAILABLE = True
except ImportError:
    pass


# ----------------------------- regex bank ----------------------------------

# func [(receiver type)] Name(params) [returns] [{
RX_GO_FUNC = re.compile(
    r"^func\s*"
    r"(?:\((?P<recv>[^)]+)\)\s*)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*\((?P<params>[^)]*)\)"
    r"\s*(?P<ret>(?:\([^)]*\)|[\*A-Za-z0-9_.\[\]\s,<>{}]+)?)"
    r"\s*\{",
    re.MULTILINE,
)

# Detect just the start of a func decl (handles multi-line signatures by
# scanning forward).
RX_GO_FUNC_START = re.compile(r"^func\s")

# Rust function start (captures the function name; signature body is parsed by
# a bounded scanner to support multi-line params, generics, and where clauses).
RX_RUST_FN_START = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"(?:const\s+)?(?:extern\s+\"[^\"]+\"\s+)?fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)

GUARD_PATTERNS = [
    ("authority-check", re.compile(r"\bk\.GetAuthority\b|authoritytypes?\.Module|govtypes\.ModuleName|msg\.Authority\b")),
    ("authority-mismatch-revert", re.compile(r"!=\s*k\.GetAuthority\(\)|Authority\b.*!=")),
    ("blocked-addr-check", re.compile(r"\bBlockedAddr\b|BlockedAddresses\b|blockedAddrs\b")),
    ("reentrancy-guard", re.compile(r"\bnonReentrant\b|ReentrancyGuard")),
    ("pause-check", re.compile(r"\bwhenNotPaused\b|isPaused\(\)|notPaused\b|paused\(\)")),
    ("sender-eq-check", re.compile(r"\bmsg\.Sender\b\s*==\s*|\bSender\b\s*!=")),
    ("subaccount-owner-check", re.compile(r"SubaccountId.*Owner|GetSubaccount\(.*Owner")),
    ("zero-addr-check", re.compile(r"==\s*\"\"|\.Empty\(\)|IsZeroAddress")),
    ("validate-basic", re.compile(r"\.ValidateBasic\(\)")),
    ("require-auth", re.compile(r"\brequire_auth\b|require!\s*\(")),
    ("only-owner", re.compile(r"\bonlyOwner\b|onlyAdmin\b")),
    ("error-return", re.compile(r"return\s+(?:nil,\s*)?(?:err|fmt\.Errorf|errors\.New)")),
    ("panic-on-error", re.compile(r"\bpanic\(")),
    ("write-store", re.compile(r"\.Set\(.*\)|\.Store\(.*\)|prefix\.NewStore.*Set\b|sdk\.Context.*KVStore")),
    ("delete-store", re.compile(r"\.Delete\(.*\)")),
]

# ---------------------------------------------------------------------------
# Solidity guard classification
# ---------------------------------------------------------------------------

# Modifier-name to guard-class mapping (Solidity-specific).
_SOL_MODIFIER_GUARD_MAP: Dict[str, str] = {
    "onlyOwner": "authority-check",
    "onlyAdmin": "authority-check",
    "onlyGovernance": "authority-check",
    "onlyAuthorized": "authority-check",
    "onlyRole": "authority-check",
    "nonReentrant": "reentrancy-guard",
    "noReentrancy": "reentrancy-guard",
    "whenNotPaused": "pause-guard",
    "notPaused": "pause-guard",
    "_blockedAddrCheck": "blocked-addr-guard",
    "requireUnblocked": "blocked-addr-guard",
}

# Body-grep patterns for Solidity (applied when modifier-name alone isn't
# enough).
_SOL_BODY_GUARD_PATTERNS: List[tuple] = [
    ("authority-check", re.compile(
        r"require\s*\(\s*msg\.sender\s*==\s*owner|"
        r"require\s*\(\s*msg\.sender\s*==\s*_owner|"
        r"_checkOwner\s*\(\)|"
        r"onlyOwner|"
        r"hasRole\s*\("
    )),
    ("reentrancy-guard", re.compile(
        r"\bnonReentrant\b|"
        r"ReentrancyGuard|"
        r"_reentrancyGuard\b"
    )),
    ("pause-guard", re.compile(
        r"\bwhenNotPaused\b|"
        r"if\s*\(\s*paused\s*\)\s*revert|"
        r"require\s*\(\s*!paused"
    )),
    ("zero-addr-check", re.compile(
        r"require\s*\(\s*\w+\s*!=\s*address\s*\(\s*0\s*\)|"
        r"if\s*\(\s*\w+\s*==\s*address\s*\(\s*0\s*\)\s*\)\s*revert"
    )),
    ("require-sender", re.compile(
        r"require\s*\(\s*msg\.sender\s*==|"
        r"if\s*\(\s*msg\.sender\s*!="
    )),
]


def _sol_classify_guards(modifiers: List[str], body: str) -> List[str]:
    """Return guard class names from modifier list + body heuristics."""
    guards: List[str] = []
    seen: set = set()

    def _add(g: str) -> None:
        if g not in seen:
            seen.add(g)
            guards.append(g)

    for mod in modifiers:
        g = _SOL_MODIFIER_GUARD_MAP.get(mod)
        if g:
            _add(g)
    for label, rx in _SOL_BODY_GUARD_PATTERNS:
        if rx.search(body):
            _add(label)
    return guards


# ---------------------------------------------------------------------------
# Solidity fine-grained shape features (Wave-11)
# ---------------------------------------------------------------------------
#
# Wave-9 Track D found that coarse shape_hash (visibility + mutability +
# param/return types + flag-vector + family) under-discriminates Solidity:
# every `external`/no-guard function with the same param/return-type
# silhouette collapses to the same hash, starving Scorer S1
# (shape-similarity) of signal. Wave-11 adds discriminative body-level
# features used ONLY for shape_hash_fine; coarse shape_hash is unchanged.
#
# All features are derivable from the tree-sitter `function_body` text,
# kept cheap (regex / counts only — no AST re-walk).

# Sorted list of canonical guard-modifier signatures we treat as
# "guard-bearing" for the fine hash. The set is intentionally small:
# pinning to a high-frequency canonical subset keeps the feature stable
# under modifier-name jitter (e.g. `onlyOwner` vs `onlyAdmin`).
_SOL_FINE_AUTHORITY_GUARD_MODS = {
    "onlyOwner", "onlyAdmin", "onlyGovernance", "onlyAuthorized",
    "onlyRole", "requiresAuth", "auth",
}
_SOL_FINE_REENTRANCY_GUARD_MODS = {
    "nonReentrant", "noReentrancy", "nonReentrantView",
}

# External-call sinks: count occurrences of these surface forms in the
# function body. We exclude internal library/lib-using sites by tying the
# match to the `.<sink>(` form on an expression boundary.
_RX_SOL_EXTERNAL_CALL = re.compile(
    r"\.(?:call|transfer|send|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\("
)

# Storage-write proxy: count top-level `<lhs> =` assignments inside the
# body that aren't comparisons / inequality / arithmetic-assign-only.
# This is approximate (we deliberately accept some FP/FN to keep the
# feature cheap and stable); the exact value matters less than the
# *distribution* of values across functions.
#
# Strategy: count `=` tokens that are
#   - NOT preceded by `=`, `!`, `<`, `>`, `+`, `-`, `*`, `/`, `%`, `&`, `|`, `^`
#   - NOT followed by `=`
# This catches plain `x = y`, `a.b = c`, `mapping[k] = v` and the
# compound-assign families `+=`, `-=`, etc.
_RX_SOL_WRITE = re.compile(r"(?<![=!<>+\-*/%&|^])=(?!=)")

# require( / revert( presence (boolean).
_RX_SOL_REQUIRE_REVERT = re.compile(r"\b(?:require|revert)\s*\(")

# assembly { ... } block presence (boolean).
_RX_SOL_ASSEMBLY = re.compile(r"\bassembly\s*\{")


def _strip_sol_comments_and_strings(body: str) -> str:
    """Best-effort scrub of `//`, `/* */`, and string-literal contents from a
    Solidity function-body text so feature regexes don't false-positive on
    commented-out code or `=` inside `"foo=bar"`. Cheap; not perfect.
    """
    # Block comments first (non-greedy).
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    # Line comments.
    body = re.sub(r"//[^\n]*", "", body)
    # Double-quoted strings (no escape handling — sufficient for counting).
    body = re.sub(r'"[^"\n]*"', '""', body)
    # Single-quoted strings.
    body = re.sub(r"'[^'\n]*'", "''", body)
    return body


def _solidity_shape_features(
    *,
    visibility: str,
    state_mutability: str,
    params: List[Dict[str, str]],
    return_types: List[str],
    modifiers: List[str],
    body: str,
) -> Dict[str, Any]:
    """Compute the Wave-11 fine-grained Solidity shape feature dict.

    Returns a dict with stable key ordering — the consumer
    (`tools/shape-hash.py`) hashes a canonical concatenation, so the keys
    here ARE part of the wire format. Do not reorder without bumping the
    consumer's canonicalization.
    """
    clean = _strip_sol_comments_and_strings(body or "")
    mod_set = set(modifiers or [])
    return {
        "visibility": (visibility or "internal").lower(),
        "state_mutability": (state_mutability or "nonpayable").lower(),
        "param_count": len(params or []),
        "return_count": len(return_types or []),
        # Sorted modifier list — order-independent so cosmetic reorderings
        # don't change the hash.
        "modifiers_sorted": sorted(mod_set),
        "has_authority_modifier": int(
            bool(mod_set & _SOL_FINE_AUTHORITY_GUARD_MODS)
        ),
        "has_reentrancy_modifier": int(
            bool(mod_set & _SOL_FINE_REENTRANCY_GUARD_MODS)
        ),
        "storage_write_count": len(_RX_SOL_WRITE.findall(clean)),
        "external_call_count": len(_RX_SOL_EXTERNAL_CALL.findall(clean)),
        "has_require_or_revert": int(bool(_RX_SOL_REQUIRE_REVERT.search(clean))),
        "has_assembly_block": int(bool(_RX_SOL_ASSEMBLY.search(clean))),
    }


def _sol_node_text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _sol_extract_params(fn_node, source: bytes) -> List[Dict[str, str]]:
    """Extract parameters from a function/constructor node."""
    params: List[Dict[str, str]] = []
    for child in fn_node.children:
        if child.type == "parameter":
            # parameter children: type_name, identifier (optional)
            type_str = ""
            name_str = ""
            for pc in child.children:
                if pc.type == "type_name":
                    type_str = _sol_node_text(pc, source).strip()
                elif pc.type == "identifier":
                    name_str = _sol_node_text(pc, source).strip()
            if type_str or name_str:
                params.append({"name": name_str, "type": type_str})
    return params


def _sol_extract_return_types(fn_node, source: bytes) -> List[str]:
    """Extract return type strings from return_type_definition node."""
    returns: List[str] = []
    for child in fn_node.children:
        if child.type == "return_type_definition":
            for rc in child.children:
                if rc.type == "parameter":
                    # named return: "uint256 a" or unnamed: "bytes32"
                    type_str = ""
                    name_str = ""
                    for pc in rc.children:
                        if pc.type == "type_name":
                            type_str = _sol_node_text(pc, source).strip()
                        elif pc.type == "identifier":
                            name_str = _sol_node_text(pc, source).strip()
                    # combine like "uint256 a" or just "bytes32"
                    if type_str and name_str:
                        returns.append(f"{type_str} {name_str}")
                    elif type_str:
                        returns.append(type_str)
                    elif name_str:
                        returns.append(name_str)
    return returns


def _extract_solidity_via_tree_sitter(source: bytes, file_path: str) -> List[Dict[str, Any]]:
    """Extract function signatures from Solidity source via tree-sitter-solidity.

    Returns per-function records with full visibility, mutability, modifier,
    param, and return-type data — enabling unique shape_hashes per function.
    Falls back to empty list on any parse failure (caller will use regex path).
    """
    try:
        lang = _TSLanguage(_tss_mod.language())
        parser = _TSParser(lang)
        tree = parser.parse(source)
    except Exception:
        return []

    out: List[Dict[str, Any]] = []
    source_text = source.decode("utf-8", errors="replace")
    lines = source_text.splitlines(keepends=True)
    # Pre-build byte-to-line mapping for line_start / line_end
    # (tree-sitter nodes carry start_point.row directly)

    fn_node_types = {"function_definition", "constructor_definition",
                     "fallback_receive_definition"}

    def _walk(node):
        if node.type in fn_node_types:
            yield node
        for child in node.children:
            yield from _walk(child)

    for fn_node in _walk(tree.root_node):
        fn_type = fn_node.type
        is_constructor = fn_type == "constructor_definition"
        is_fallback_receive = fn_type == "fallback_receive_definition"

        # Determine is_fallback / is_receive from first keyword child
        is_fallback = False
        is_receive = False
        function_name = ""
        visibility = "internal"  # Solidity default
        state_mutability = "nonpayable"
        modifiers: List[str] = []

        for child in fn_node.children:
            ct = child.type
            if ct == "identifier":
                function_name = _sol_node_text(child, source)
            elif ct == "visibility":
                visibility = _sol_node_text(child, source).strip()
            elif ct == "state_mutability":
                state_mutability = _sol_node_text(child, source).strip()
            elif ct == "modifier_invocation":
                mod_name = ""
                for mc in child.children:
                    if mc.type == "identifier":
                        mod_name = _sol_node_text(mc, source).strip()
                        break
                if mod_name:
                    modifiers.append(mod_name)
            elif ct == "receive":
                is_receive = True
            elif ct == "fallback":
                is_fallback = True
            elif ct == "constructor":
                pass  # is_constructor already set

        # Build synthetic function names for special forms
        if is_constructor:
            function_name = "<constructor>"
        elif is_receive:
            function_name = "<receive>"
        elif is_fallback:
            function_name = "<fallback>"

        # Extract params and return types
        params = _sol_extract_params(fn_node, source)
        return_types = _sol_extract_return_types(fn_node, source)

        # Body text for guard heuristics
        body = ""
        for child in fn_node.children:
            if child.type == "function_body":
                body = _sol_node_text(child, source)
                break

        guards_detected = _sol_classify_guards(modifiers, body)
        shape_features = _solidity_shape_features(
            visibility=visibility,
            state_mutability=state_mutability,
            params=params,
            return_types=return_types,
            modifiers=modifiers,
            body=body,
        )

        # Build normalized signature (no body)
        param_str = ", ".join(
            f"{p['type']} {p['name']}".strip() if p["name"] else p["type"]
            for p in params
        )
        ret_str = ""
        if return_types:
            ret_str = " returns (" + ", ".join(return_types) + ")"

        mod_str = (" " + " ".join(modifiers)) if modifiers else ""
        if is_constructor:
            sig = f"constructor({param_str}){mod_str}"
        elif is_receive:
            sig = f"receive() external payable"
        elif is_fallback:
            sig = f"fallback() external"
        else:
            vis_mut = f" {visibility}" if visibility else ""
            mut_str = f" {state_mutability}" if state_mutability and state_mutability != "nonpayable" else ""
            sig = f"function {function_name}({param_str}){vis_mut}{mut_str}{mod_str}{ret_str}"

        line_start = fn_node.start_point[0] + 1
        line_end = fn_node.end_point[0] + 1

        rec: Dict[str, Any] = {
            "file_path": file_path,
            "language": "solidity",
            "function_name": function_name,
            "function_signature": sig,
            "visibility": visibility,
            "state_mutability": state_mutability,
            "line_start": line_start,
            "line_end": line_end,
            "modifiers": modifiers,
            "params": params,
            "return_types": return_types,
            "guards_detected": guards_detected,
            "is_constructor": is_constructor,
            "is_fallback": is_fallback,
            "is_receive": is_receive,
            # Wave-11: fine-grained body-derived feature dict consumed by
            # tools/shape-hash.py to compute shape_hash_fine.
            "shape_features": shape_features,
        }
        out.append(rec)

    return out


# Regex fallback for Solidity (used when tree-sitter-solidity is unavailable).
RX_SOL_FN = re.compile(
    r"^\s*function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def _extract_solidity_regex_fallback(text: str, file_path: str) -> List[Dict[str, Any]]:
    """Regex-only Solidity extraction. Provides function names and line numbers
    only; no visibility/params/return_types/modifiers (shape_hash quality is
    reduced compared to tree-sitter path)."""
    out: List[Dict[str, Any]] = []
    for m in RX_SOL_FN.finditer(text):
        name = m.group("name")
        line = text.count("\n", 0, m.start()) + 1
        out.append({
            "file_path": file_path,
            "language": "solidity",
            "function_name": name,
            "function_signature": f"function {name}(...)",
            "visibility": "unknown",
            "state_mutability": "unknown",
            "line_start": line,
            "line_end": line,
            "modifiers": [],
            "params": [],
            "return_types": [],
            "guards_detected": [],
            "is_constructor": False,
            "is_fallback": False,
            "is_receive": False,
            # Wave-11: regex fallback cannot derive body-level features;
            # emit an empty/default feature dict so the JSONL schema stays
            # stable across paths. Coarse shape_hash is unaffected;
            # shape_hash_fine will collapse for fallback records.
            "shape_features": {
                "visibility": "unknown",
                "state_mutability": "unknown",
                "param_count": 0,
                "return_count": 0,
                "modifiers_sorted": [],
                "has_authority_modifier": 0,
                "has_reentrancy_modifier": 0,
                "storage_write_count": 0,
                "external_call_count": 0,
                "has_require_or_revert": 0,
                "has_assembly_block": 0,
            },
        })
    return out


def extract_solidity_functions(text: str, file_path: str) -> List[Dict[str, Any]]:
    """Public dispatcher: tree-sitter if available, else regex fallback."""
    if _TREE_SITTER_SOLIDITY_AVAILABLE:
        source = text.encode("utf-8", errors="replace")
        recs = _extract_solidity_via_tree_sitter(source, file_path)
        if recs:  # non-empty parse succeeded
            return recs
        # Empty result could mean parse failure or genuinely empty file;
        # fall through to regex for safety.
    return _extract_solidity_regex_fallback(text, file_path)


def visibility_go(name: str) -> str:
    if name and name[0].isupper():
        return "exported"
    return "unexported"


def find_matching_brace(text: str, start_brace_pos: int) -> int:
    """Return index of the matching `}` after the `{` at start_brace_pos.
    Returns -1 if unbalanced.
    """
    depth = 0
    i = start_brace_pos
    n = len(text)
    in_str: Optional[str] = None
    in_line_cmt = False
    in_block_cmt = False
    while i < n:
        ch = text[i]
        if in_line_cmt:
            if ch == "\n":
                in_line_cmt = False
            i += 1
            continue
        if in_block_cmt:
            if ch == "*" and i + 1 < n and text[i + 1] == "/":
                in_block_cmt = False
                i += 2
                continue
            i += 1
            continue
        if in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            in_line_cmt = True
            i += 2
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            in_block_cmt = True
            i += 2
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def parse_params(params_s: str) -> List[Dict[str, str]]:
    """Best-effort param parser. Handles `name type, name type` and
    `name1, name2 type` shorthand. Not bulletproof for closures."""
    if not params_s.strip():
        return []
    out: List[Dict[str, str]] = []
    parts = _split_top_level(params_s, ",")
    pending_names: List[str] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # split on whitespace, last token = type if multi-token, else type-only
        toks = part.rsplit(None, 1)
        if len(toks) == 2:
            names_blob, ty = toks
            names = [n.strip() for n in names_blob.split(",") if n.strip()]
            if not names:
                names = pending_names
                pending_names = []
            for n in names:
                out.append({"name": n, "type": ty})
        else:
            # type-only (rare in Go) or just-name with shared type next
            pending_names.append(part)
    for n in pending_names:
        out.append({"name": "", "type": n})
    return out


def _split_top_level(s: str, sep: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    angle_depth = 0
    buf = []
    for ch in s:
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == "<":
            angle_depth += 1
        elif ch == ">":
            angle_depth = max(0, angle_depth - 1)
        if ch == sep and depth == 0 and angle_depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def parse_returns(ret_s: str) -> List[str]:
    ret_s = ret_s.strip()
    if not ret_s:
        return []
    if ret_s.startswith("(") and ret_s.endswith(")"):
        ret_s = ret_s[1:-1].strip()
    parts = _split_top_level(ret_s, ",")
    out: List[str] = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        # in Go: "name type" or just "type"
        tokens = p.split()
        if len(tokens) >= 2 and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", tokens[0]) and not _looks_like_type(tokens[0]):
            out.append(" ".join(tokens[1:]))
        else:
            out.append(p)
    return out


def _find_top_level_colon(s: str) -> int:
    depth = 0
    angle_depth = 0
    for i, ch in enumerate(s):
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth = max(0, depth - 1)
        elif ch == "<":
            angle_depth += 1
        elif ch == ">":
            angle_depth = max(0, angle_depth - 1)
        if depth or angle_depth:
            continue
        if ch == ":":
            prev_ch = s[i - 1] if i > 0 else ""
            next_ch = s[i + 1] if i + 1 < len(s) else ""
            if prev_ch == ":" or next_ch == ":":
                continue
            return i
    return -1


def _find_balanced_close(s: str, start_idx: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    for i in range(start_idx, len(s)):
        ch = s[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return -1


def _find_rust_signature_terminator(s: str, start_idx: int) -> int:
    depth = 0
    angle_depth = 0
    for i in range(start_idx, len(s)):
        ch = s[i]
        if ch in "([":  # keep '{' for terminator check
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif ch == "<":
            angle_depth += 1
        elif ch == ">":
            angle_depth = max(0, angle_depth - 1)
        if depth == 0 and angle_depth == 0 and ch in "{;":
            return i
    return -1


def parse_rust_params(params_s: str) -> Tuple[List[Dict[str, str]], Optional[str], List[str]]:
    params: List[Dict[str, str]] = []
    receiver_type: Optional[str] = None
    receiver_mods: List[str] = []
    for raw in _split_top_level(params_s, ","):
        part = raw.strip()
        if not part:
            continue
        if part in ("self", "mut self", "&self", "&mut self"):
            receiver_type = "Self"
            if part.startswith("&"):
                receiver_mods.append("reference-receiver")
            continue
        colon_idx = _find_top_level_colon(part)
        if colon_idx == -1:
            params.append({"name": "", "type": part})
            continue
        left = part[:colon_idx].strip()
        right = part[colon_idx + 1 :].strip()
        if not right:
            continue
        left_tokens = [t for t in left.replace("mut ", " ").split() if t and t != "ref"]
        name = left_tokens[-1] if left_tokens else ""
        params.append({"name": name, "type": right})
    return params, receiver_type, receiver_mods


def parse_rust_returns(ret_s: str) -> List[str]:
    rs = ret_s.strip()
    if not rs:
        return []
    # Strip a trailing top-level `where ...` clause from the return tail.
    depth = 0
    angle_depth = 0
    where_idx = -1
    for m in re.finditer(r"\bwhere\b", rs):
        i = m.start()
        for ch in rs[:i]:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
            elif ch == "<":
                angle_depth += 1
            elif ch == ">":
                angle_depth = max(0, angle_depth - 1)
        if depth == 0 and angle_depth == 0:
            where_idx = i
            break
        depth = 0
        angle_depth = 0
    if where_idx != -1:
        rs = rs[:where_idx].strip()
    if rs.startswith("(") and rs.endswith(")"):
        inner = rs[1:-1].strip()
        if not inner:
            return []
        return [p.strip() for p in _split_top_level(inner, ",") if p.strip()]
    return [rs]


def _looks_like_type(tok: str) -> bool:
    return tok[0].isupper() or "." in tok or tok in ("error", "int", "string", "bool", "byte", "rune", "uint", "uint64", "int64", "uint32", "int32")


def receiver_type_of(recv: Optional[str]) -> Tuple[Optional[str], List[str]]:
    """Return (receiver_type, modifiers)."""
    if not recv:
        return None, []
    recv = recv.strip()
    mods: List[str] = []
    # "k *Keeper" or "k Keeper"
    parts = recv.split()
    if len(parts) >= 2:
        ty = parts[-1]
    else:
        ty = parts[0]
    if ty.startswith("*"):
        mods.append("pointer-receiver")
        ty = ty[1:]
    return ty, mods


def detect_calls_made(body: str, max_calls: int = 40) -> List[str]:
    out: List[str] = []
    seen = set()
    for m in re.finditer(r"\b([a-zA-Z_][\w.]*)\s*\(", body):
        c = m.group(1)
        if c in ("if", "for", "switch", "return", "func", "go", "defer", "make", "len", "cap", "append", "new", "panic", "recover"):
            continue
        if c in seen:
            continue
        seen.add(c)
        out.append(c)
        if len(out) >= max_calls:
            break
    return out


def detect_guards(body: str) -> List[str]:
    hits: List[str] = []
    for label, rx in GUARD_PATTERNS:
        if rx.search(body):
            hits.append(label)
    return hits


# Wave-14: Go-specific body features for shape_hash_fine differentiation.
# Used by tools/shape-hash.py to break the file-level-hash-collapse FP
# (multiple funcs in one .go file sharing identical coarse hash). See
# audit/postmortems/wave14-ranker-file-level-fp-2026-05-11.md.
_RX_GO_MAP_OP = re.compile(r"map\[[A-Za-z0-9_.\*\[\]]+\]")
_RX_GO_SLICE_OP = re.compile(r"\[\]([A-Za-z0-9_.\*]+)")
_RX_GO_APPEND = re.compile(r"\bappend\s*\(")
_RX_GO_LEN = re.compile(r"\blen\s*\(")
_RX_GO_RANGE = re.compile(r"\brange\s+")
_RX_GO_GOROUTINE = re.compile(r"\bgo\s+[A-Za-z_]")
_RX_GO_DEFER = re.compile(r"\bdefer\s+[A-Za-z_]")


def compute_body_features(body: str, calls_made: List[str], return_types: List[str]) -> Dict[str, int]:
    """Return Go-body shape features for shape_hash_fine canonicalization.

    Features chosen to break ties between functions that share the same
    param-type / return-type sequence but otherwise differ structurally.
    They are intentionally coarse (bucket counts, presence-bits) so that
    semantically-equivalent reorderings still collide.
    """
    if not body:
        body = ""
    body_lines = body.count("\n") + (1 if body else 0)
    # Bucket the line count to avoid over-fragmenting on cosmetic edits.
    if body_lines <= 5:
        line_bucket = "xs"
    elif body_lines <= 15:
        line_bucket = "s"
    elif body_lines <= 40:
        line_bucket = "m"
    elif body_lines <= 100:
        line_bucket = "l"
    else:
        line_bucket = "xl"
    call_count = len(calls_made or [])
    if call_count == 0:
        call_bucket = "0"
    elif call_count <= 3:
        call_bucket = "1-3"
    elif call_count <= 10:
        call_bucket = "4-10"
    else:
        call_bucket = "11+"
    map_ops = len(_RX_GO_MAP_OP.findall(body))
    slice_ops = len(_RX_GO_SLICE_OP.findall(body))
    has_append = 1 if _RX_GO_APPEND.search(body) else 0
    has_len = 1 if _RX_GO_LEN.search(body) else 0
    has_range = 1 if _RX_GO_RANGE.search(body) else 0
    has_goroutine = 1 if _RX_GO_GOROUTINE.search(body) else 0
    has_defer = 1 if _RX_GO_DEFER.search(body) else 0
    returns_error = 1 if any(r.strip().endswith("error") or r.strip() == "error" for r in return_types or []) else 0
    return {
        "line_bucket": line_bucket,
        "call_bucket": call_bucket,
        "map_op_count": min(map_ops, 5),
        "slice_op_count": min(slice_ops, 5),
        "has_append": has_append,
        "has_len": has_len,
        "has_range": has_range,
        "has_goroutine": has_goroutine,
        "has_defer": has_defer,
        "returns_error": returns_error,
        "return_count": len(return_types or []),
    }


def extract_go_functions(text: str, file_path: str) -> List[Dict[str, Any]]:
    """Find each `^func ...` and extract a function record."""
    out: List[Dict[str, Any]] = []
    # We anchor on regex matches, then verify by finding brace close.
    for m in RX_GO_FUNC.finditer(text):
        sig_start = m.start()
        sig_end_brace = text.find("{", m.start("name"))
        if sig_end_brace == -1:
            continue
        close = find_matching_brace(text, sig_end_brace)
        if close == -1:
            continue
        body = text[sig_end_brace + 1 : close]
        signature = text[sig_start:sig_end_brace].strip()
        name = m.group("name")
        params = parse_params(m.group("params") or "")
        ret_types = parse_returns(m.group("ret") or "")
        recv_str = m.group("recv")
        recv_type, recv_mods = receiver_type_of(recv_str)
        line_start = text.count("\n", 0, sig_start) + 1
        line_end = text.count("\n", 0, close) + 1
        calls = detect_calls_made(body)
        rec = {
            "file_path": file_path,
            "language": "go",
            "function_name": name,
            "function_signature": signature,
            "receiver_type": recv_type,
            "visibility": visibility_go(name),
            "line_start": line_start,
            "line_end": line_end,
            "modifiers": recv_mods,
            "params": params,
            "return_types": ret_types,
            "calls_made": calls,
            "guards_detected": detect_guards(body),
            "body_features": compute_body_features(body, calls, ret_types),
        }
        out.append(rec)
    return out


def extract_rust_functions(text: str, file_path: str) -> List[Dict[str, Any]]:
    """Find Rust `fn` declarations and extract structured signature records.

    Bounded, regex-anchored scanner that tolerates:
      - multi-line params
      - generic parameter blocks (`fn f<T, U>(...)`)
      - trailing where clauses
      - impl-method receivers (`&self`, `&mut self`)
    """
    out: List[Dict[str, Any]] = []
    for m in RX_RUST_FN_START.finditer(text):
        fn_start = m.start()
        name = m.group("name")
        after_name = m.end()
        i = after_name
        while i < len(text) and text[i].isspace():
            i += 1
        if i < len(text) and text[i] == "<":
            close_generic = _find_balanced_close(text, i, "<", ">")
            if close_generic == -1:
                continue
            i = close_generic + 1
            while i < len(text) and text[i].isspace():
                i += 1
        if i >= len(text) or text[i] != "(":
            continue
        params_close = _find_balanced_close(text, i, "(", ")")
        if params_close == -1:
            continue
        params_blob = text[i + 1 : params_close]
        sig_term = _find_rust_signature_terminator(text, params_close + 1)
        if sig_term == -1:
            sig_term = min(len(text), params_close + 300)
        signature = text[fn_start:sig_term].strip()
        vis = "exported" if re.search(r"\bpub\b", m.group(0)) else "unexported"
        params, recv_type, recv_mods = parse_rust_params(params_blob)
        tail = text[params_close + 1 : sig_term]
        return_types: List[str] = []
        arrow_idx = tail.find("->")
        if arrow_idx != -1:
            return_types = parse_rust_returns(tail[arrow_idx + 2 :])
        line_start = text.count("\n", 0, fn_start) + 1
        line_end = text.count("\n", 0, sig_term) + 1
        body = ""
        term_char = text[sig_term] if sig_term < len(text) else ""
        if term_char == "{":
            close = find_matching_brace(text, sig_term)
            if close != -1:
                body = text[sig_term + 1 : close]
                line_end = text.count("\n", 0, close) + 1
        calls = detect_calls_made(body)
        rec = {
            "file_path": file_path,
            "language": "rust",
            "function_name": name,
            "function_signature": signature,
            "receiver_type": recv_type,
            "visibility": vis,
            "line_start": line_start,
            "line_end": line_end,
            "modifiers": recv_mods,
            "params": params,
            "return_types": return_types,
            "calls_made": calls,
            "guards_detected": detect_guards(body),
        }
        out.append(rec)
    return out


# ------------------------------ walker -------------------------------------


SKIP_DIRS = {".git", "node_modules", "vendor", "third_party", "testdata", ".idea", ".vscode"}
# Backward-compat alias
GO_SKIP_DIRS = SKIP_DIRS
GO_SUFFIX = ".go"
SOL_SUFFIX = ".sol"
RUST_SUFFIX = ".rs"


def iter_go_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith(GO_SUFFIX):
                yield Path(dirpath) / fn


def iter_sol_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith(SOL_SUFFIX):
                yield Path(dirpath) / fn


def iter_rust_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith(RUST_SUFFIX):
                yield Path(dirpath) / fn


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("repo_path", help="Path to repo root")
    p.add_argument("--language", default="go", choices=["go", "solidity", "rust"],
                   help="Language to extract. Solidity uses tree-sitter when available.")
    p.add_argument("--out", help="Output JSONL path. Default: stdout.")
    p.add_argument("--audit-pin", help="Optional SHA tag for record metadata.")
    p.add_argument("--limit", type=int, default=0, help="Cap number of records emitted (debug).")
    p.add_argument("--sample", type=int, default=0, help="After scan, print N sample records to stderr.")
    p.add_argument("--filter-test-files", action="store_true", help="Skip *_test.go / test_*.sol files.")
    p.add_argument("--force-regex", action="store_true",
                   help="Force regex-only extraction even if tree-sitter is available (testing/comparison).")
    args = p.parse_args(argv)

    root = Path(args.repo_path).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    out_fh = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    samples: List[Dict[str, Any]] = []
    total_funcs = 0
    files_scanned = 0

    language = args.language

    if language == "solidity":
        file_iter = iter_sol_files(root)
    elif language == "rust":
        file_iter = iter_rust_files(root)
    else:
        file_iter = iter_go_files(root)

    try:
        for fp in file_iter:
            if args.filter_test_files and (fp.name.endswith("_test.go") or
                                           fp.name.startswith("test_")):
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            files_scanned += 1
            try:
                rel = fp.relative_to(root)
            except ValueError:
                rel = fp
            rel_str = str(rel)

            if language == "solidity":
                if args.force_regex:
                    recs = _extract_solidity_regex_fallback(text, rel_str)
                else:
                    recs = extract_solidity_functions(text, rel_str)
            elif language == "rust":
                recs = extract_rust_functions(text, rel_str)
            else:
                recs = extract_go_functions(text, rel_str)

            for rec in recs:
                if args.audit_pin:
                    rec["audit_pin_sha"] = args.audit_pin
                out_fh.write(json.dumps(rec, sort_keys=True) + "\n")
                total_funcs += 1
                if len(samples) < args.sample:
                    samples.append(rec)
                if args.limit and total_funcs >= args.limit:
                    break
            if args.limit and total_funcs >= args.limit:
                break
    finally:
        if args.out:
            out_fh.close()

    ts_status = ("tree-sitter" if (_TREE_SITTER_SOLIDITY_AVAILABLE and not getattr(args, "force_regex", False))
                 else "regex-fallback")
    if language == "solidity":
        print(
            f"files_scanned={files_scanned} functions_extracted={total_funcs} "
            f"extraction_backend={ts_status}",
            file=sys.stderr,
        )
    elif language == "rust":
        print(
            f"files_scanned={files_scanned} functions_extracted={total_funcs} "
            f"extraction_backend=regex-structured",
            file=sys.stderr,
        )
    else:
        print(
            f"files_scanned={files_scanned} functions_extracted={total_funcs}",
            file=sys.stderr,
        )
    for i, s in enumerate(samples, 1):
        print(
            f"  sample[{i}]: {s['file_path']}:{s['line_start']} "
            f"{s.get('receiver_type') or ''} {s['function_name']} "
            f"vis={s.get('visibility','')} "
            f"mods={s.get('modifiers',[])} "
            f"guards={s['guards_detected']}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
