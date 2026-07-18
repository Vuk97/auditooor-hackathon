#!/usr/bin/env python3
"""
CCIA — Cross-Contract Interaction Analyzer

Fast regex-based analysis of Solidity source to build:
  - Call graphs (internal + external)
  - State dependency maps
  - Trust boundary crossings
  - Reentrancy surfaces
  - Attacker-angle suggestions

No compilation required. Works on raw .sol files.

Usage:
  python3 tools/ccia.py <workspace-dir> [--src <subdir>]
  python3 tools/ccia.py <workspace-dir> --contract <Name>
  python3 tools/ccia.py <workspace-dir> --list-contracts
  python3 tools/ccia.py <workspace-dir> --json [--out report.json]
  python3 tools/ccia.py <workspace-dir> --attack-angles [--out angles.json]
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


COMMON_SOURCE_ROOTS = (
    "src",
    "contracts",
    "external/contracts/src",
    "packages/contracts-bedrock/src",
    "packages/contracts/src",
    "external/base/packages/contracts-bedrock/src",
    # Hardhat-style monorepos with packages/<pkg>/contracts/ layout
    # (The Graph, Aave-style, Centrifuge, etc.). find_sol_files() recurses,
    # so pointing at the parent monorepo root lets it pick up every package
    # without per-package config.
    "external/contracts/packages",
    "packages",
)


# OUT-OF-SCOPE / non-production .sol directory segments (vendored deps + build
# artifacts + test/script/doc/mock/historical trees). Kept in sync with
# workspace-scan-orchestrator's _VENDORED_SOL_SEGMENTS + _NON_PRODUCTION_SOL_SEGMENTS
# so CCIA does not surface cross-contract "attack angles" in forge-std, soldeer
# dependencies/, scripts, mocks or doc mirrors (which read as OOS noise).
_CCIA_SKIP_SEGMENTS = (
    "lib", "node_modules", "dependencies", "vendor", "@openzeppelin",
    "out", "cache", "artifacts",
    "test", "tests", "mock", "mocks", "script", "scripts", "docs",
    "previousVersions",
)


def find_sol_files(src_dir: Path) -> List[Path]:
    """Find production .sol files under src_dir, excluding vendored/test/script/
    mock/doc/historical trees and Foundry .t.sol/.s.sol files (all OOS)."""
    sols = []
    for p in src_dir.rglob("*.sol"):
        if not p.is_file():
            continue
        if p.name.endswith((".t.sol", ".s.sol")):
            continue
        if set(p.parts) & set(_CCIA_SKIP_SEGMENTS):
            continue
        sols.append(p)
    return sorted(sols)


def _metadata_source_roots(workspace: Path) -> List[str]:
    """Return optional source roots declared by workspace metadata files."""
    roots: List[str] = []
    for name in ("workspace.json", ".auditooor.json", "scope.json"):
        path = workspace / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for key in ("source_roots", "sourceRoots", "src_roots", "solidity_source_roots"):
            value = data.get(key)
            if isinstance(value, list):
                roots.extend(str(item) for item in value if str(item).strip())
        for key in ("source_root", "sourceRoot", "src", "solidity_source_root"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                roots.append(value)
    return roots


def _source_candidate(workspace: Path, rel_or_abs: str) -> Path:
    path = Path(rel_or_abs).expanduser()
    if path.is_absolute():
        return path
    return workspace / path


def _expanded_source_candidates(candidate: Path) -> List[Path]:
    """Expand a directory candidate to monorepo-aware alternatives.

    For Hardhat-style ``packages/<pkg>/contracts/`` layouts, the parent
    ``packages/`` directory has no direct ``.sol`` files but its descendants
    do. ``find_sol_files()`` recurses, so the parent itself is a valid
    source root — but only if at least one descendant ``*/contracts/``
    actually contains Solidity. This helper returns the parent (and any
    immediate ``*/contracts`` children that exist) so callers can choose
    the broadest viable root.
    """
    extras: List[Path] = []
    if not candidate.is_dir():
        return extras
    # Walk one level: pick up <candidate>/<pkg>/contracts/ patterns.
    try:
        children = sorted(p for p in candidate.iterdir() if p.is_dir())
    except OSError:
        return extras
    for child in children:
        nested = child / "contracts"
        if nested.is_dir():
            extras.append(nested)
    return extras


def resolve_source_root(workspace: Path, src_arg: str = "src") -> Tuple[Optional[Path], List[Path]]:
    """Resolve the Solidity source root for workspaces with nested repo layouts.

    Canonical engage historically passes ``--src src``. Some competitions place
    scoped Solidity under roots such as ``external/contracts/src`` instead, so
    the default source root should be discoverable without every caller knowing
    the workspace-specific checkout layout.
    """
    seen: Set[str] = set()
    candidates: List[Path] = []

    def _push(candidate: Path) -> None:
        key = str(candidate)
        if key in seen:
            return
        seen.add(key)
        candidates.append(candidate)

    for raw in [src_arg, *_metadata_source_roots(workspace), *COMMON_SOURCE_ROOTS]:
        if not raw:
            continue
        candidate = _source_candidate(workspace, raw).resolve()
        _push(candidate)
        # For Hardhat-monorepo parents (packages/, external/contracts/packages/),
        # also expose the per-package contracts/ subdirs so a metadata-free
        # workspace can still resolve to a real source root.
        for nested in _expanded_source_candidates(candidate):
            _push(nested.resolve())

    existing = [candidate for candidate in candidates if candidate.exists()]
    for candidate in existing:
        if candidate.is_dir() and find_sol_files(candidate):
            return candidate, candidates

    return (existing[0] if existing else None), candidates


def find_contracts(parsed_files: Iterable[Dict]) -> List[Dict[str, str]]:
    """List available contract/library/interface definitions plus file aliases."""
    contracts = []
    for pf in parsed_files:
        relpath = pf["filepath"]
        file_alias = Path(relpath).stem
        for contract in pf["contracts"]:
            contracts.append({
                "name": contract["name"],
                "kind": contract["kind"],
                "file": relpath,
                "file_alias": file_alias,
            })
    return sorted(contracts, key=lambda c: (c["name"].lower(), c["file"].lower()))


def resolve_contract_filter(parsed_files: List[Dict], contract_name: str) -> Tuple[str, Set[str]]:
    """Resolve a contract/file-stem query into the contract names it should focus."""
    query = contract_name.strip()
    if not query:
        raise ValueError("contract filter cannot be empty")

    exact_matches = []
    ci_matches = []
    for pf in parsed_files:
        relpath = pf["filepath"]
        file_alias = Path(relpath).stem
        contract_names = [c["name"] for c in pf["contracts"]]

        if query == file_alias or query in contract_names:
            exact_matches.append(pf)
            continue

        query_lower = query.lower()
        if query_lower == file_alias.lower() or any(query_lower == name.lower() for name in contract_names):
            ci_matches.append(pf)

    matches = exact_matches or ci_matches
    if not matches:
        available = ", ".join(
            sorted({entry["name"] for entry in find_contracts(parsed_files)})
        )
        raise ValueError(
            f"unknown contract '{contract_name}'. Use --list-contracts to inspect available names. "
            f"Known contracts: {available}"
        )

    canonical = query
    selected_contracts: Set[str] = set()
    for pf in matches:
        file_alias = Path(pf["filepath"]).stem
        if query.lower() == file_alias.lower():
            canonical = file_alias
        for contract in pf["contracts"]:
            selected_contracts.add(contract["name"])
            if query.lower() == contract["name"].lower():
                canonical = contract["name"]

    return canonical, selected_contracts


def filter_ccia_for_contract(
    ccia: Dict[str, Any],
    angles: List[Dict[str, Any]],
    selected_contracts: Set[str],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Keep only CCIA artifacts that involve the selected contract(s)."""
    focused = {
        "contracts": [],
        "libraries": ccia["libraries"],
        "call_graph": [],
        "trust_boundaries": [],
        "reentrancy_surfaces": [],
        "unauth_privileged_funcs": [],
        "state_races": [],
    }
    involved_contracts = set(selected_contracts)

    for edge in ccia["call_graph"]:
        if edge["from"] in selected_contracts or edge["to"] in selected_contracts:
            focused["call_graph"].append(edge)
            involved_contracts.update((edge["from"], edge["to"]))

    for boundary in ccia["trust_boundaries"]:
        source_contract = boundary["source"].split(".")[0]
        target_contract = boundary["target"].split(".")[0]
        if source_contract in selected_contracts or target_contract in selected_contracts:
            focused["trust_boundaries"].append(boundary)
            involved_contracts.update((source_contract, target_contract))

    for surface in ccia["reentrancy_surfaces"]:
        called_contracts = {call[0] for call in surface["calls"]}
        if surface["contract"] in selected_contracts or called_contracts & selected_contracts:
            focused["reentrancy_surfaces"].append(surface)
            involved_contracts.add(surface["contract"])
            involved_contracts.update(called_contracts)

    for func in ccia["unauth_privileged_funcs"]:
        if func["contract"] in selected_contracts:
            focused["unauth_privileged_funcs"].append(func)
            involved_contracts.add(func["contract"])

    for race in ccia["state_races"]:
        race_contracts = set(race["readers"]) | set(race["writers"])
        if race_contracts & selected_contracts:
            focused["state_races"].append(race)
            involved_contracts.update(race_contracts)

    focused_angles = []
    for angle in angles:
        angle_contracts = set(angle.get("contracts", []))
        if angle_contracts & selected_contracts:
            focused_angles.append(angle)
            involved_contracts.update(angle_contracts)

    focused["contracts"] = sorted(involved_contracts)
    return focused, focused_angles


def parse_contract(filepath: Path, src_dir: Path) -> Optional[Dict]:
    """Parse a single .sol file into contract definitions."""
    text = filepath.read_text(errors="ignore")
    lines = text.splitlines()

    # Extract pragma
    pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', text)
    pragma = pragma_match.group(1).strip() if pragma_match else "unknown"

    # Find all contract/library/interface definitions
    contract_pattern = re.compile(
        r'\b(contract|library|interface)\s+(\w+)\s*(?:is\s+([^{]+))?\s*\{',
        re.DOTALL
    )

    contracts = []
    for m in contract_pattern.finditer(text):
        kind, name, inheritance = m.groups()
        start_pos = m.end() - 1  # position of {
        # Find matching closing brace (naive, but works for most cases)
        brace_count = 0
        end_pos = start_pos
        for i, ch in enumerate(text[start_pos:], start_pos):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i
                    break

        body = text[start_pos:end_pos+1]
        body_lines = text[:start_pos].count('\n')

        contracts.append({
            "file": str(filepath.relative_to(src_dir)),
            "pragma": pragma,
            "kind": kind,
            "name": name,
            "line": text[:m.start()].count('\n') + 1,
            "inherits": [x.strip() for x in inheritance.split(',')] if inheritance else [],
            "body": body,
            "functions": parse_functions(body, body_lines),
            "state_vars": parse_state_vars(body),
            "modifiers": parse_modifiers(body),
        })

    return {"filepath": str(filepath), "contracts": contracts}


def parse_functions(body: str, base_line: int) -> List[Dict]:
    """Extract function definitions from contract body."""
    func_pattern = re.compile(
        r'\b(function\s+(\w+)|modifier\s+(\w+)|constructor\s*\()',
        re.DOTALL
    )

    funcs = []
    for m in func_pattern.finditer(body):
        is_modifier = m.group(3) is not None
        is_constructor = "constructor" in m.group(0)
        fname = m.group(3) if is_modifier else (m.group(2) if not is_constructor else "constructor")

        # Extract signature up to {
        sig_start = m.start()
        sig_end = body.find('{', sig_start)
        if sig_end == -1:
            sig_end = len(body)
        sig = body[sig_start:sig_end]
        sig_line = base_line + body[:sig_start].count('\n') + 1

        # Find function body
        body_start = sig_end
        brace_count = 0
        body_end = body_start
        for i, ch in enumerate(body[body_start:], body_start):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    body_end = i
                    break

        func_body = body[body_start:body_end+1]

        funcs.append({
            "name": fname,
            "line": sig_line,
            "signature": sig.strip(),
            "body": func_body,
            "is_modifier": is_modifier,
            "is_constructor": is_constructor,
            "visibility": extract_visibility(sig),
            "modifiers": extract_modifiers(sig),
            "external_calls": find_external_calls(func_body),
            "state_reads": find_state_reads(func_body),
            "state_writes": find_state_writes(func_body),
        })

    return funcs


def parse_state_vars(body: str) -> List[Dict]:
    """Extract state variable declarations."""
    vars = []
    # Match patterns like: Type public|private|internal name [= value];
    pattern = re.compile(
        r'\b(mapping\s*\([^)]+\)|[\w\[\]]+(?:\s+\w+)?)\s+'
        r'(public|private|internal|constant|immutable)?\s*'
        r'(\w+)\s*(?:=\s*([^;]+))?;',
        re.DOTALL
    )
    for m in pattern.finditer(body):
        type_str = m.group(1).strip()
        visibility = (m.group(2) or "").strip()
        name = m.group(3).strip()
        # Skip if this looks like a local variable (inside a function)
        # Heuristic: if preceded by { within 50 chars, it's probably local
        preceding = body[max(0, m.start()-50):m.start()]
        if '{' in preceding and '}' not in preceding.split('{')[-1]:
            continue
        vars.append({"type": type_str, "visibility": visibility, "name": name})
    return vars


def parse_modifiers(body: str) -> List[str]:
    """Extract modifier names defined in contract."""
    mods = []
    pattern = re.compile(r'\bmodifier\s+(\w+)')
    for m in pattern.finditer(body):
        mods.append(m.group(1))
    return mods


def extract_visibility(sig: str) -> str:
    """Extract function visibility."""
    vis_pattern = re.compile(r'\b(public|external|internal|private)\b')
    m = vis_pattern.search(sig)
    return m.group(1) if m else "public"  # default for free functions


def extract_modifiers(sig: str) -> List[str]:
    """Extract modifier names applied to a function."""
    # Remove function keyword and name, extract modifiers between params and {
    mod_section = re.sub(r'^function\s+\w+\s*\([^)]*\)', '', sig)
    mod_section = re.sub(r'\b(public|external|internal|private|pure|view|payable|override|virtual|returns\s*\([^)]*\))\b', '', mod_section)
    # What's left should be modifiers
    mods = [m.strip() for m in re.split(r'[\s{]', mod_section) if m.strip() and not m.strip().startswith('//')]
    return mods


def _is_inside_revert(body: str, pos: int) -> bool:
    """Check if position is inside a revert(...) expression."""
    # Look backward for 'revert' before any statement boundary
    preceding = body[max(0, pos-200):pos]
    # Remove nested parentheses content to simplify
    # Simple heuristic: if 'revert' appears after the last ';', '{', '}', or newline
    # and before pos, we're likely inside a revert()
    last_boundary = max(preceding.rfind(';'), preceding.rfind('{'), preceding.rfind('}'))
    segment = preceding[last_boundary+1:]
    return 'revert' in segment


def find_external_calls(body: str) -> List[Tuple[str, str, str]]:
    """Find external calls in function body. Returns (target, function, type)."""
    calls = []

    # Pattern 1: contract.function() or address.function()
    pattern1 = re.compile(r'\b(\w+)\.(\w+)\s*\(')
    for m in pattern1.finditer(body):
        target = m.group(1)
        func = m.group(2)
        # Skip common non-external patterns (built-ins, cheatcodes, console)
        if target in ("msg", "block", "tx", "abi", "keccak256", "require", "assert", "revert", "this", "super",
                      "vm", "console", "stdstorage", "string", "bytes", "math"):
            continue
        if func in ("length", "push", "pop", "add", "sub", "mul", "div", "concat"):
            continue
        # Skip revert CustomError() patterns
        if _is_inside_revert(body, m.start()):
            continue
        calls.append((target, func, "high_level"))

    # Pattern 2: low-level calls (call, delegatecall, staticcall)
    pattern2 = re.compile(r'\.(call|delegatecall|staticcall)\s*\{')
    for m in pattern2.finditer(body):
        calls.append(("?", m.group(1), "low_level"))

    # Pattern 3: transfer / send
    pattern3 = re.compile(r'\.(transfer|send)\s*\(')
    for m in pattern3.finditer(body):
        calls.append(("?", m.group(1), "eth_transfer"))

    return calls


def find_state_reads(body: str) -> List[str]:
    """Find state variable reads in function body."""
    reads = []
    # Pattern: _varName or varName (not local, not msg.sender, etc.)
    # This is heuristic - we look for identifiers that aren't known locals
    known_locals = {"msg", "block", "tx", "abi", "this", "super", "now", "gasleft"}
    pattern = re.compile(r'\b([a-z_]\w*)\b')
    seen = set()
    for m in pattern.finditer(body):
        name = m.group(1)
        if name in known_locals or name in seen:
            continue
        # Skip if it looks like a type or keyword
        if name in ("uint256", "address", "bool", "bytes", "string", "memory", "storage", "calldata",
                    "return", "if", "else", "for", "while", "continue", "break", "new", "delete"):
            continue
        seen.add(name)
        reads.append(name)
    return sorted(reads)


def find_state_writes(body: str) -> List[str]:
    """Find state variable writes in function body."""
    writes = []
    # Pattern: var = ... or var += ... or var -= ... or var++ or var--
    pattern = re.compile(r'\b([a-z_]\w*)\s*(?:=|\+=|-=|\+\+|--)')
    seen = set()
    for m in pattern.finditer(body):
        name = m.group(1)
        if name in seen:
            continue
        # Skip common non-state patterns
        if name in ("return", "if", "for", "while"):
            continue
        seen.add(name)
        writes.append(name)
    return sorted(writes)


def is_auth_gated(func: Dict, contract_mods: List[str]) -> bool:
    """Check if function has access control modifiers."""
    auth_keywords = {"onlyowner", "onlyadmin", "auth", "authorized", "restricted",
                     "onlyoperator", "onlyrole", "requireauth", "pausable",
                     "only_minter", "only_burner", "only_guardian", "only_governance",
                     "onlyownerorself", "onlyoperatororowner",
                     "onlyoracle", "onlyoptimisticoracle",
                     "onlysafe", "onlyroot", "onlyguardian"}
    for mod in func["modifiers"]:
        if any(kw in mod.lower() for kw in auth_keywords):
            return True
    # Check body for msg.sender validation in require() or if()
    body_lower = func["body"].lower()
    if "msg.sender" in body_lower and ("==" in body_lower or "!=" in body_lower):
        # Match msg.sender on either side of the comparison operator,
        # anywhere inside the require/if condition.
        sender_cmp = r'(?:msg\.sender\s*[!=]=|[!=]=\s*msg\.sender)'
        if re.search(r'require\s*\([^)]*' + sender_cmp, body_lower):
            return True
        if re.search(r'if\s*\([^)]*' + sender_cmp, body_lower):
            return True
    return False


def build_cross_contract_map(parsed_files: List[Dict]) -> Dict[str, Any]:
    """Build cross-contract interaction map from parsed files."""
    all_contracts = {}
    contract_by_name = {}
    libraries = set()

    for pf in parsed_files:
        for c in pf["contracts"]:
            cname = c["name"]
            all_contracts[cname] = c
            contract_by_name[cname] = pf["filepath"]
            if c["kind"] == "library":
                libraries.add(cname)

    result = {
        "contracts": list(all_contracts.keys()),
        "libraries": sorted(libraries),
        "call_graph": [],
        "trust_boundaries": [],
        "reentrancy_surfaces": [],
        "unauth_privileged_funcs": [],
        "state_races": [],
    }

    # Pre-compute auth-gated internal functions per contract for call-tracing
    contract_internal_auth = {}
    for cname, cdata in all_contracts.items():
        internal_auth = set()
        for func in cdata["functions"]:
            if func["is_modifier"]:
                continue
            if func["visibility"] in ("internal", "private"):
                if is_auth_gated(func, cdata["modifiers"]):
                    internal_auth.add(func["name"])
        contract_internal_auth[cname] = internal_auth

    def has_internal_auth_call(func_body: str, cname: str) -> bool:
        """Check if function body calls an internal auth-gated function."""
        for auth_func in contract_internal_auth.get(cname, set()):
            # Match funcName( but not emit funcName( or type funcName(
            pattern = re.compile(r'(?<![\w\.]\s)(?<!emit\s)(?<!\w\.)\b' + re.escape(auth_func) + r'\s*\(')
            if pattern.search(func_body):
                return True
        return False

    for cname, cdata in all_contracts.items():
        for func in cdata["functions"]:
            if func["is_modifier"]:
                continue

            visibility = func["visibility"]
            gated = is_auth_gated(func, cdata["modifiers"])
            # Trace internal calls: if body calls an internal auth-gated func, treat as gated
            if not gated and visibility in ("public", "external"):
                gated = has_internal_auth_call(func["body"], cname)
            ext_calls = func["external_calls"]

            # Call graph edges
            for target, fname, ctype in ext_calls:
                if target in all_contracts and target != cname and target not in libraries:
                    result["call_graph"].append({
                        "from": cname,
                        "to": target,
                        "func": func["name"],
                        "target_func": fname,
                        "type": ctype,
                    })

            # Trust boundaries: unauthenticated → auth-gated
            if visibility in ("public", "external") and not gated:
                for target, fname, ctype in ext_calls:
                    if target in all_contracts:
                        target_funcs = {f["name"]: f for f in all_contracts[target]["functions"]}
                        if fname in target_funcs:
                            if is_auth_gated(target_funcs[fname], all_contracts[target]["modifiers"]):
                                result["trust_boundaries"].append({
                                    "source": f"{cname}.{func['name']}",
                                    "target": f"{target}.{fname}",
                                    "source_line": func["line"],
                                })

            # Reentrancy surface
            # Filter out library calls and cheatcodes — only untrusted external calls matter
            reentrant_calls = [(t, f, c) for t, f, c in ext_calls if t not in libraries and t not in ("vm", "console")]
            if reentrant_calls and func["state_writes"]:
                # Check if external call happens before state write
                body = func["body"]
                ext_positions = []
                for target, fname, ctype in reentrant_calls:
                    # Find position of this call in body
                    pat = re.escape(target) + r'\.' + re.escape(fname)
                    for m in re.finditer(pat, body):
                        ext_positions.append(m.start())

                write_positions = []
                for sv in func["state_writes"]:
                    pat = r'\b' + re.escape(sv) + r'\s*(?:=|\+=|-=|\+\+|--)'
                    for m in re.finditer(pat, body):
                        write_positions.append(m.start())

                if ext_positions and write_positions:
                    if min(ext_positions) < max(write_positions):
                        result["reentrancy_surfaces"].append({
                            "contract": cname,
                            "function": func["name"],
                            "line": func["line"],
                            "calls": reentrant_calls,
                            "writes_after": func["state_writes"],
                        })

            # Unauthenticated privileged functions
            # Skip constructors, pure/view functions, and well-known pure patterns
            is_pure_view = "pure" in func["signature"].lower() or "view" in func["signature"].lower()
            is_constructor = func["is_constructor"]
            is_known_pure = func["name"] in ("supportsInterface", "onERC1155Received", "onERC1155BatchReceived", "name", "symbol", "decimals", "version", "DOMAIN_SEPARATOR")
            if visibility in ("public", "external") and not gated and not is_pure_view and not is_constructor and not is_known_pure:
                if func["state_writes"] and not ext_calls:
                    result["unauth_privileged_funcs"].append({
                        "contract": cname,
                        "function": func["name"],
                        "line": func["line"],
                        "writes": func["state_writes"],
                        "severity": "HIGH" if len(func["state_writes"]) > 2 else "MEDIUM",
                    })

    # State races: same var read/written by multiple contracts
    # Heuristic: skip common local-variable names that are almost never state vars
    common_locals = {
        "i", "j", "k", "n", "m", "x", "y", "z", "w", "a", "b", "c", "d", "p", "q", "r", "t", "u", "v",
        "amount", "value", "sender", "recipient", "to", "from", "caller", "operator", "initiator", "executor", "relayer",
        "length", "size", "count", "index", "idx", "start", "end", "mid", "lo", "hi", "left", "right",
        "result", "res", "ret", "tmp", "temp", "data", "buf", "buffer", "hash", "sig", "signature", "proof", "input", "output",
        "old", "new", "prev", "next", "curr", "current", "e", "err", "error", "ok", "success", "valid",
        "one", "two", "three", "zero", "first", "last", "dec", "hex", "str", "bytes",
    }
    # Build set of all declared state variable names across all contracts
    declared_state_vars = set()
    for cdata in all_contracts.values():
        for sv in cdata.get("state_vars", []):
            declared_state_vars.add(sv["name"])

    state_readers = defaultdict(set)
    state_writers = defaultdict(set)
    for cname, cdata in all_contracts.items():
        for func in cdata["functions"]:
            for sv in func["state_reads"]:
                if sv not in common_locals and sv in declared_state_vars:
                    state_readers[sv].add(cname)
            for sv in func["state_writes"]:
                if sv not in common_locals and sv in declared_state_vars:
                    state_writers[sv].add(cname)

    for sv, readers in state_readers.items():
        writers = state_writers.get(sv, set())
        all_contracts_involved = readers | writers
        if len(all_contracts_involved) > 1 and len(writers) > 1:
            result["state_races"].append({
                "var": sv,
                "readers": sorted(readers),
                "writers": sorted(writers),
            })

    return result


def detect_erc4626_patterns(all_contracts: Dict) -> List[Dict]:
    """Detect ERC4626 vault patterns that are prone to share price manipulation."""
    angles = []
    erc4626_funcs = {"convertToShares", "convertToAssets", "previewDeposit", "previewMint",
                     "previewWithdraw", "previewRedeem", "deposit", "mint", "withdraw", "redeem",
                     "totalAssets", "maxDeposit", "maxMint", "maxWithdraw", "maxRedeem"}
    for cname, cdata in all_contracts.items():
        has_erc4626 = any(f["name"] in erc4626_funcs for f in cdata["functions"])
        if has_erc4626:
            # Check for price/oracle dependency
            has_price = any("price" in f["name"].lower() or "oracle" in f["name"].lower()
                           for f in cdata["functions"])
            angles.append({
                "id": "A-ERC4626",
                "severity": "HIGH" if has_price else "MEDIUM",
                "title": f"ERC4626 share price manipulation surface: {cname}",
                "description": f"{cname} implements ERC4626-style vault operations. "
                               f"Check for share price manipulation via donation, inflation attack, or oracle skew. "
                               f"{'Price oracle dependency detected — check for stale price exploitation.' if has_price else ''}",
                "contracts": [cname],
            })
    return angles


def detect_oracle_patterns(all_contracts: Dict) -> List[Dict]:
    """Detect oracle integration patterns prone to manipulation."""
    angles = []
    oracle_funcs = {"getPrice", "latestAnswer", "latestRoundData", "consult", "getQuote",
                    "getRate", "getExchangeRate", "getUnderlyingPrice", "peek", "read"}
    for cname, cdata in all_contracts.items():
        for func in cdata["functions"]:
            if func["name"] in oracle_funcs:
                # Check if oracle result is used in arithmetic without validation
                has_arith = any(op in func["body"] for op in ("*", "/", "+", "-"))
                has_validation = "require" in func["body"] or "if" in func["body"]
                angles.append({
                    "id": "A-ORACLE",
                    "severity": "HIGH" if has_arith and not has_validation else "MEDIUM",
                    "title": f"Oracle manipulation surface: {cname}.{func['name']}",
                    "description": f"{cname}.{func['name']} reads oracle data. "
                                   f"{'Used in arithmetic without validation — check for price manipulation.' if has_arith and not has_validation else 'Check for stale price, flash loan manipulation, or multi-block MEV.'}",
                    "contracts": [cname],
                    "line": func.get("line"),
                })
    return angles


def detect_upgradeable_patterns(all_contracts: Dict) -> List[Dict]:
    """Detect upgradeable contract gaps."""
    angles = []
    for cname, cdata in all_contracts.items():
        is_upgradeable = any(f["name"] in {"_authorizeUpgrade", "upgradeTo", "upgradeToAndCall"}
                            for f in cdata["functions"])
        if is_upgradeable:
            has_gap = any("__gap" in sv["name"] for sv in cdata.get("state_vars", []))
            has_initializer = any(f["name"] == "initialize" for f in cdata["functions"])
            has_disable = "_disableInitializers" in str(cdata.get("functions", []))
            if not has_gap:
                angles.append({
                    "id": "A-UPGRADE",
                    "severity": "MEDIUM",
                    "title": f"Missing storage gap in upgradeable contract: {cname}",
                    "description": f"{cname} is upgradeable but lacks a __gap array. Future upgrades may corrupt storage layout.",
                    "contracts": [cname],
                })
            if has_initializer and not has_disable:
                angles.append({
                    "id": "A-UPGRADE",
                    "severity": "MEDIUM",
                    "title": f"Initializer not disabled in implementation: {cname}",
                    "description": f"{cname} has initialize() but implementation may not call _disableInitializers(). Check for reinitialization risk.",
                    "contracts": [cname],
                })
    return angles


def detect_delegatecall_surfaces(all_contracts: Dict) -> List[Dict]:
    """Detect delegatecall surfaces."""
    angles = []
    for cname, cdata in all_contracts.items():
        for func in cdata["functions"]:
            if "delegatecall" in func["body"]:
                angles.append({
                    "id": "A-DELEGATE",
                    "severity": "HIGH",
                    "title": f"Delegatecall surface: {cname}.{func['name']}",
                    "description": f"{cname}.{func['name']} uses delegatecall. Verify target contract cannot be manipulated by attacker.",
                    "contracts": [cname],
                    "line": func.get("line"),
                })
    return angles


def detect_flashloan_surfaces(all_contracts: Dict) -> List[Dict]:
    """Detect flash loan integration points and callback surfaces."""
    angles = []
    flashloan_funcs = {"flashLoan", "flashBorrow", "flash", "onFlashLoan", "executeOperation",
                       "onFlashLoan", "onFlashSwap", "flashLoanSimple"}
    for cname, cdata in all_contracts.items():
        for func in cdata["functions"]:
            if func["name"] in flashloan_funcs:
                # Check if callback is properly reentrancy-guarded
                has_reentrancy_guard = any(g in " ".join(func["modifiers"]).lower()
                                            for g in ("nonreentrant", "reentrancyguard", "lock"))
                body = func["body"]
                has_cei = True  # assume ok unless we see external call before state write
                ext_positions = []
                for m in re.finditer(r'\.[a-zA-Z_][a-zA-Z0-9_]*\s*\(', body):
                    ext_positions.append(m.start())
                write_positions = []
                for sv in func["state_writes"]:
                    for m in re.finditer(r'\b' + re.escape(sv) + r'\s*(?:=|\+=|-=|\+\+|--)', body):
                        write_positions.append(m.start())
                if ext_positions and write_positions and min(ext_positions) < max(write_positions):
                    has_cei = False
                severity = "HIGH" if not has_reentrancy_guard and not has_cei else "MEDIUM"
                angles.append({
                    "id": "A-FLASH",
                    "severity": severity,
                    "title": f"Flash loan surface: {cname}.{func['name']}",
                    "description": f"{cname}.{func['name']} is a flash loan entry point or callback. "
                                   f"{'CEI violation detected — external call before state write.' if not has_cei else 'Check for reentrancy via callback manipulation.'} "
                                   f"{'No reentrancy guard found.' if not has_reentrancy_guard else 'Reentrancy guard present.'}",
                    "contracts": [cname],
                    "line": func.get("line"),
                })
    return angles


def detect_timestamp_dependence(all_contracts: Dict) -> List[Dict]:
    """Detect block.timestamp / block.number used in conditionals without safeguards.
    Skip view/pure functions — they cannot change state so timestamp manipulation
    is not exploitable as a vulnerability (though off-chain behavior may vary)."""
    angles = []
    for cname, cdata in all_contracts.items():
        for func in cdata["functions"]:
            # Skip view/pure — no state change means no exploitable timestamp manipulation
            sig_lower = func["signature"].lower()
            if "view" in sig_lower or "pure" in sig_lower:
                continue
            body = func["body"]
            has_timestamp = "block.timestamp" in body or "block.number" in body or "now" in body
            if not has_timestamp:
                continue
            # Check for safeguard (oracle, commit-reveal, or multiple block confirmation)
            has_safeguard = any(k in body for k in ("oracle", "commit", "reveal", "blockDelay",
                                                      "minBlocks", "deadline", "expiration"))
            # Check if used in conditional (require, if, comparison)
            in_conditional = bool(re.search(r'(require|if|assert|revert).*\b(block\.timestamp|block\.number|now)\b', body) or
                                  re.search(r'\b(block\.timestamp|block\.number|now)\b.*[<>=!]', body))
            if in_conditional and not has_safeguard:
                angles.append({
                    "id": "A-TIMESTAMP",
                    "severity": "MEDIUM",
                    "title": f"Timestamp dependence: {cname}.{func['name']}",
                    "description": f"{cname}.{func['name']} uses block.timestamp/block.number in a conditional without oracle or commit-reveal safeguard. Miners can manipulate timestamps within ~15s.",
                    "contracts": [cname],
                    "line": func.get("line"),
                })
    return angles


def detect_access_control_bypasses(all_contracts: Dict) -> List[Dict]:
    """Detect tx.origin usage and single-step ownership patterns."""
    angles = []
    for cname, cdata in all_contracts.items():
        for func in cdata["functions"]:
            body = func["body"]
            # tx.origin auth
            if "tx.origin" in body and ("==" in body or "!=" in body):
                angles.append({
                    "id": "A-TXORIGIN",
                    "severity": "HIGH",
                    "title": f"tx.origin authentication: {cname}.{func['name']}",
                    "description": f"{cname}.{func['name']} uses tx.origin for access control. Phishing attacks can bypass this via middle-contract calls.",
                    "contracts": [cname],
                    "line": func.get("line"),
                })
            # Single-step ownership transfer (no 2-step)
            if "transferOwnership" in func["name"] or ("owner" in func["name"].lower() and "transfer" in func["name"].lower()):
                if "propose" not in func["name"].lower() and "pending" not in body.lower():
                    angles.append({
                        "id": "A-OWNERSHIP",
                        "severity": "MEDIUM",
                        "title": f"Single-step ownership transfer: {cname}.{func['name']}",
                        "description": f"{cname}.{func['name']} transfers ownership in one step. A typo in the new owner address is irreversible. Consider 2-step (propose/accept) pattern.",
                        "contracts": [cname],
                        "line": func.get("line"),
                    })
            # Self-destruct / delegatecall to arbitrary address
            if "selfdestruct" in body or "suicide" in body:
                angles.append({
                    "id": "A-DESTRUCT",
                    "severity": "HIGH",
                    "title": f"Self-destruct present: {cname}.{func['name']}",
                    "description": f"{cname}.{func['name']} contains selfdestruct. Verify only authorized roles can trigger this and it is intentional.",
                    "contracts": [cname],
                    "line": func.get("line"),
                })
    return angles


def generate_attack_angles(ccia: Dict, all_contracts: Dict = None) -> List[Dict]:
    angles = []

    # Reentrancy angles
    for rs in ccia.get("reentrancy_surfaces", []):
        cross_contract = [c for c in rs["calls"] if c[0] in ccia["contracts"] and c[0] != rs["contract"] and c[0] not in ccia.get("libraries", set())]
        if cross_contract:
            angles.append({
                "id": "A-REENT",
                "severity": "HIGH",
                "title": f"Cross-contract reentrancy: {rs['contract']}.{rs['function']}",
                "description": f"External call(s) to {[c[0]+'.'+c[1] for c in cross_contract]} followed by state writes. Check for callback manipulation.",
                "contracts": list(set([c[0] for c in cross_contract] + [rs["contract"]])),
                "line": rs.get("line"),
            })

    # Trust boundary angles
    for tb in ccia.get("trust_boundaries", []):
        angles.append({
            "id": "A-TRUST",
            "severity": "MEDIUM",
            "title": f"Trust boundary crossing: {tb['source']} → {tb['target']}",
            "description": f"Unauthenticated function calls auth-gated target. Verify privilege escalation is not possible.",
            "contracts": [tb["source"].split(".")[0], tb["target"].split(".")[0]],
            "line": tb.get("line"),
        })

    # Unauth state write angles
    for upf in ccia.get("unauth_privileged_funcs", []):
        angles.append({
            "id": "A-AUTH",
            "severity": upf["severity"],
            "title": f"Unauthenticated state write: {upf['contract']}.{upf['function']}",
            "description": f"Public/external function writes state without access control modifier.",
            "contracts": [upf["contract"]],
            "line": upf.get("line"),
        })

    # State race angles
    for sr in ccia.get("state_races", [])[:5]:
        angles.append({
            "id": "A-RACE",
            "severity": "MEDIUM",
            "title": f"Cross-contract state race on '{sr['var']}'",
            "description": f"Variable written by {sr['writers']} and read by {sr['readers']}. Check for TOCTOU.",
            "contracts": sorted(set(sr["readers"] + sr["writers"])),
        })

    # New pattern-based angles
    if all_contracts:
        angles.extend(detect_erc4626_patterns(all_contracts))
        angles.extend(detect_oracle_patterns(all_contracts))
        angles.extend(detect_upgradeable_patterns(all_contracts))
        angles.extend(detect_delegatecall_surfaces(all_contracts))
        angles.extend(detect_flashloan_surfaces(all_contracts))
        angles.extend(detect_timestamp_dependence(all_contracts))
        angles.extend(detect_access_control_bypasses(all_contracts))

    return angles


def render_markdown(ccia: Dict, angles: List[Dict], contract_filter: Optional[str] = None) -> str:
    lines = []
    lines.append("# CCIA Report — Cross-Contract Interaction Analysis")
    lines.append("")
    lines.append("## Summary")
    if contract_filter:
        lines.append(f"- Contract filter: `{contract_filter}`")
    lines.append(f"- Contracts analyzed: {len(ccia['contracts'])}")
    lines.append(f"- Cross-contract call edges: {len(ccia['call_graph'])}")
    lines.append(f"- Trust boundaries crossed: {len(ccia['trust_boundaries'])}")
    lines.append(f"- Reentrancy surfaces: {len(ccia['reentrancy_surfaces'])}")
    lines.append(f"- Unauthenticated privileged functions: {len(ccia['unauth_privileged_funcs'])}")
    lines.append(f"- Generated attack angles: {len(angles)}")
    lines.append("")

    if angles:
        lines.append("## Attack Angles (Prioritized)")
        for angle in angles:
            lines.append(f"### {angle['id']} — {angle['severity']} — {angle['title']}")
            lines.append(f"{angle['description']}")
            lines.append(f"**Contracts:** {', '.join(angle['contracts'])}")
            if angle.get("line"):
                lines.append(f"**Line:** {angle['line']}")
            lines.append("")

    if ccia["call_graph"]:
        lines.append("## Call Graph")
        for edge in ccia["call_graph"]:
            lines.append(f"- `{edge['from']}.{edge['func']}` → `{edge['to']}.{edge['target_func']}` ({edge['type']})")
        lines.append("")

    if ccia["trust_boundaries"]:
        lines.append("## Trust Boundaries")
        for tb in ccia["trust_boundaries"]:
            lines.append(f"- `{tb['source']}` → `{tb['target']}` (line {tb.get('line', '?')})")
        lines.append("")

    if ccia["reentrancy_surfaces"]:
        lines.append("## Reentrancy Surfaces")
        for rs in ccia["reentrancy_surfaces"]:
            lines.append(f"- `{rs['contract']}.{rs['function']}` (line {rs.get('line', '?')})")
            for c in rs["calls"]:
                lines.append(f"  - calls `{c[0]}.{c[1]}` ({c[2]})")
        lines.append("")

    if ccia["unauth_privileged_funcs"]:
        lines.append("## Unauthenticated State Writes")
        for upf in ccia["unauth_privileged_funcs"]:
            lines.append(f"- `{upf['contract']}.{upf['function']}` writes: {upf['writes']} (severity: {upf['severity']})")
        lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────
# Callgraph emit (Kimi 20/10 Step 3a)
# ─────────────────────────────────────────────────────────────────────────
#
# `build_callgraph()` produces a structured cross-contract callgraph
# that the detector-composer (Step 3b) consumes to demote name-collision
# A-RACE briefs that lack proven shared mutable state.
#
# Schema (versioned via "schema_version"):
#   {
#     "schema_version": 1,
#     "workspace": "<absolute path>",
#     "source_root": "<resolved src dir>",
#     "nodes": [
#       {
#         "id": "Contract.function(args)",
#         "contract": "<name>",
#         "function": "<name>",
#         "visibility": "public|external|internal|private",
#         "is_constructor": bool,
#         "is_modifier": bool,
#         "file": "<rel path>",
#         "line": <int>,
#       }, ...
#     ],
#     "edges": [
#       {
#         "src": "Contract.foo()",
#         "dst": "Other.bar()",
#         "kind": "external_call|internal_call|library_call|delegate_call|low_level_call",
#         "shared_storage_keys": ["balances", "owner"],   # may be []
#         "src_file": "<rel path>",
#         "src_line": <int>,
#       }, ...
#     ],
#     "contract_storage": {"Contract": ["balances", "owner"], ...},
#     "stats": {
#       "nodes": N, "edges": M,
#       "edges_with_shared_storage": K,
#       "contracts": C,
#     },
#   }
#
# `shared_storage_keys` is the intersection of:
#   (state vars READ or WRITTEN by `src` fn body) ∩
#   (state vars DECLARED by `dst` contract or any of its parents)
#
# This is a deliberately conservative proxy for "the two endpoints touch
# the same storage". It is regex-based — a function-reachability graph
# with a storage-name overlay — not a Slither IR walk. Kimi's spec calls
# out this fallback explicitly: "If Slither IR doesn't expose what's
# needed for shared_storage_keys → ship PR-A with a partial schema +
# document the gap as a follow-up." A future PR can replace
# `_state_vars_for_contract` / `_storage_overlap` with a Slither IR walk
# that reflects struct-member writes and inherited state across
# diamond/proxy boundaries; the schema is forward-compatible.


# Regex used by the callgraph emit path to extract state-variable
# declarations directly from a contract body. Independent from
# `parse_state_vars` (which is used by the existing CCIA report and has
# its own quirks we do not want to regress here). We strip nested
# function bodies first, then match top-level declarations of the form:
#   <type> [public|private|internal|constant|immutable] <name> [= ...];
# Including mappings, arrays, and user-defined types.
_STATE_VAR_RE = re.compile(
    r'^\s*'
    r'(?P<type>'
    r'mapping\s*\([^;]+?\)'                       # mapping(...)
    r'|[A-Za-z_]\w*(?:\s*\[\s*\w*\s*\])*'         # base[, base[10]]
    r')'
    r'(?:\s+(?:public|private|internal|external|constant|immutable|override))*'
    r'\s+(?P<name>[A-Za-z_]\w*)\s*(?:=\s*[^;]+)?\s*;',
    re.MULTILINE,
)

# Solidity reserved keywords that should never count as state-var names
# even if a sloppy regex match returns them.
_NOT_STATE_VAR_NAMES = frozenset({
    "return", "if", "else", "for", "while", "do", "break", "continue",
    "new", "delete", "memory", "storage", "calldata", "constant",
    "immutable", "public", "private", "internal", "external",
    "uint", "uint256", "int", "int256", "address", "bool", "bytes",
    "string", "function", "modifier", "constructor", "fallback", "receive",
})


def _strip_function_bodies(body: str) -> str:
    """Remove function bodies (between matching braces) so a state-var
    regex sees only the top-level contract scope. Naive brace counter
    that handles nested blocks but ignores braces inside strings — good
    enough for Solidity contract bodies in our fixtures and real
    repos."""
    out: List[str] = []
    depth = 0
    i = 0
    n = len(body)
    # We want to keep the OUTERMOST braces (depth 1 contents) at depth 0
    # i.e. we strip everything from the FIRST '{' after a function/
    # modifier/constructor signature down to its matching '}'. We detect
    # such headers by scanning for `function|modifier|constructor` then
    # the next '{' — drop until the brace count balances.
    header_re = re.compile(r'\b(function\s+\w*|modifier\s+\w+|constructor)\b')
    last = 0
    for m in header_re.finditer(body):
        # Append everything up to this header
        out.append(body[last:m.end()])
        # Find the next '{' after the header
        brace = body.find("{", m.end())
        if brace == -1:
            last = m.end()
            continue
        # Walk the brace count
        depth = 0
        j = brace
        while j < n:
            ch = body[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        # Skip past the closing '}' (or to end if unbalanced)
        last = (j + 1) if j < n else n
    out.append(body[last:])
    return "".join(out)


def _extract_state_var_names(contract_body: str) -> Set[str]:
    """Tight extractor used only by the callgraph emit path. See
    `_STATE_VAR_RE` above for matched shapes."""
    stripped = _strip_function_bodies(contract_body)
    names: Set[str] = set()
    for m in _STATE_VAR_RE.finditer(stripped):
        name = m.group("name")
        if not name or name in _NOT_STATE_VAR_NAMES:
            continue
        names.add(name)
    return names


def _build_inheritance_index(all_contracts: Dict[str, Dict]) -> Dict[str, Set[str]]:
    """For each contract, return the set of names of its declared and
    transitively inherited contracts (its own name included). Used to
    resolve which storage variables are reachable from the dst side of
    an edge."""
    index: Dict[str, Set[str]] = {}

    def _resolve(name: str, seen: Set[str]) -> Set[str]:
        if name in seen:
            return set()
        seen.add(name)
        if name not in all_contracts:
            return set()
        result = {name}
        for parent in all_contracts[name].get("inherits", []) or []:
            # Strip generics / args defensively (`Foo(arg)` shows up rarely).
            parent_name = parent.split("(")[0].strip()
            if not parent_name:
                continue
            result |= _resolve(parent_name, seen)
        return result

    for cname in all_contracts:
        index[cname] = _resolve(cname, set())
    return index


def _state_vars_for_contract(
    cname: str,
    all_contracts: Dict[str, Dict],
    inheritance_index: Dict[str, Set[str]],
) -> Set[str]:
    """Set of all state-variable names declared by `cname` or any parent.

    Uses the callgraph-local `_extract_state_var_names` (which strips
    function bodies + uses a tighter regex than `parse_state_vars`) so
    we correctly capture mappings, arrays, and one-line declarations
    that the legacy parser drops. Result is the union over the
    contract's own body + all transitive ancestors."""
    keys: Set[str] = set()
    for ancestor in inheritance_index.get(cname, {cname}):
        body = all_contracts.get(ancestor, {}).get("body", "")
        if body:
            keys |= _extract_state_var_names(body)
    return keys


def _func_signature_id(contract_name: str, func: Dict) -> str:
    """Stable id like `Bank.withdraw()`. We do not unparse arg types
    (regex parser does not capture them reliably); the function name +
    contract name is sufficient for callgraph identity within one
    workspace because Solidity does not allow function-name overloads
    that share a contract scope without distinguishing arity in source.
    Constructors get `Bank.constructor()`."""
    fname = func.get("name") or "<anon>"
    return f"{contract_name}.{fname}()"


def _classify_edge_kind(call_type: str, target_name: str, libraries: Set[str]) -> str:
    """Map find_external_calls() type triple → callgraph edge `kind`."""
    if call_type == "low_level":
        # find_external_calls() returns ('?', 'delegatecall', 'low_level')
        # for delegatecall specifically; we recover that here from the
        # *function* name, which the caller passes through `target_name`'s
        # companion field. The call site that builds edges has both fields.
        return "low_level_call"
    if call_type == "eth_transfer":
        return "low_level_call"
    if target_name in libraries:
        return "library_call"
    return "external_call"


def build_callgraph(parsed_files: List[Dict]) -> Dict[str, Any]:
    """Build the cross-contract callgraph + storage overlap.

    Returns a dict matching the schema documented at module level. Pure
    function of the regex-parsed `parsed_files` list — no I/O, no Slither.
    """
    all_contracts: Dict[str, Dict] = {}
    libraries: Set[str] = set()
    for pf in parsed_files:
        for c in pf["contracts"]:
            all_contracts[c["name"]] = c
            if c["kind"] == "library":
                libraries.add(c["name"])

    inheritance_index = _build_inheritance_index(all_contracts)

    # state_vars_by_contract: cname → set of state-var names (incl. inherited)
    state_vars_by_contract: Dict[str, Set[str]] = {
        cname: _state_vars_for_contract(cname, all_contracts, inheritance_index)
        for cname in all_contracts
    }

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for cname, cdata in all_contracts.items():
        rel_file = cdata.get("file", "")
        for func in cdata.get("functions", []):
            node_id = _func_signature_id(cname, func)
            nodes.append({
                "id": node_id,
                "contract": cname,
                "function": func.get("name") or "<anon>",
                "visibility": func.get("visibility", "public"),
                "is_constructor": bool(func.get("is_constructor")),
                "is_modifier": bool(func.get("is_modifier")),
                "file": rel_file,
                "line": int(func.get("line", 0)),
            })

            # Storage touched by THIS function (reads ∪ writes).
            # find_state_reads / find_state_writes are heuristic; we
            # narrow to identifiers that are also declared as state vars
            # somewhere in the workspace (caller-resolved).
            src_touched: Set[str] = set(func.get("state_reads") or []) | set(
                func.get("state_writes") or []
            )

            # Edges: external calls observed in body
            for target, fname, ctype in func.get("external_calls", []) or []:
                # Skip calls to unknown targets (target='?') for the
                # cross-contract graph — they are valuable for taint
                # tracking but cannot be linked to a destination node.
                if target == "?" or target not in all_contracts:
                    continue
                if target == cname:
                    # Self-call: we still record it but mark kind as internal_call
                    kind = "internal_call"
                elif fname == "delegatecall":
                    kind = "delegate_call"
                else:
                    kind = _classify_edge_kind(ctype, target, libraries)

                # Resolve dst storage scope (declared + inherited)
                dst_storage = state_vars_by_contract.get(target, set())
                shared = sorted(src_touched & dst_storage)

                # Build dst id; prefer matched fname else stub
                target_funcs = {f["name"]: f for f in all_contracts[target].get("functions", [])}
                if fname in target_funcs:
                    dst_id = _func_signature_id(target, target_funcs[fname])
                else:
                    dst_id = f"{target}.{fname}()"

                edges.append({
                    "src": node_id,
                    "dst": dst_id,
                    "kind": kind,
                    "shared_storage_keys": shared,
                    "src_file": rel_file,
                    "src_line": int(func.get("line", 0)),
                })

    edges_with_storage = sum(1 for e in edges if e["shared_storage_keys"])

    # contract_storage: cname → sorted list of declared+inherited state-var
    # names. Consumers (detector-composer) query this to answer "do these
    # two contracts share any mutable state at all?" without needing every
    # call edge to be resolved (the regex parser cannot resolve
    # typed-local-var calls like `vault.foo()` to `Vault.foo()`).
    contract_storage = {
        cname: sorted(state_vars_by_contract.get(cname, set()))
        for cname in sorted(all_contracts.keys())
    }

    return {
        "schema_version": 1,
        "nodes": nodes,
        "edges": edges,
        "contract_storage": contract_storage,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "edges_with_shared_storage": edges_with_storage,
            "contracts": len(contract_storage),
        },
    }


def emit_callgraph(workspace: Path, parsed_files: List[Dict], src_dir: Path) -> Path:
    """Build the callgraph and write it to <workspace>/ccia/callgraph.json.

    Idempotent: the file is fully overwritten on each call. Returns the
    output path."""
    cg = build_callgraph(parsed_files)
    cg["workspace"] = str(workspace)
    cg["source_root"] = str(src_dir)

    out_dir = workspace / "ccia"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "callgraph.json"
    out_path.write_text(json.dumps(cg, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return out_path


def main():
    parser = argparse.ArgumentParser(description="CCIA — Cross-Contract Interaction Analyzer")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument(
        "--src",
        default="src",
        help="Source subdirectory (default: src; falls back to workspace metadata and common nested source roots)",
    )
    parser.add_argument("--contract", help="Focus the report on one contract or file stem while preserving whole-workspace CCIA context")
    parser.add_argument("--list-contracts", action="store_true", help="List available contracts/libraries/interfaces and exit")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--attack-angles", action="store_true", help="Output attack angles as JSON")
    parser.add_argument("--out", help="Output file")
    parser.add_argument(
        "--emit-callgraph",
        action="store_true",
        help="Build cross-contract callgraph + shared-storage overlay; "
             "write to <workspace>/ccia/callgraph.json (Kimi 20/10 Step 3a)",
    )
    args = parser.parse_args()

    ws = Path(args.workspace)
    src, candidates = resolve_source_root(ws, args.src)
    if not src or not src.exists():
        tried = ", ".join(str(p) for p in candidates)
        print(f"Error: source directory not found (tried: {tried})")
        sys.exit(1)

    print(f"[CCIA] Scanning {src} for Solidity files...")
    sol_files = find_sol_files(src)
    if not sol_files:
        print(f"Error: no Solidity files found under source directory: {src}")
        sys.exit(1)
    print(f"[CCIA] Found {len(sol_files)} .sol files")

    parsed = []
    for f in sol_files:
        result = parse_contract(f, src)
        if result:
            parsed.append(result)

    print(f"[CCIA] Parsed {sum(len(p['contracts']) for p in parsed)} contracts")

    if args.emit_callgraph:
        out_path = emit_callgraph(ws, parsed, src)
        cg = json.loads(out_path.read_text(encoding="utf-8"))
        stats = cg.get("stats", {})
        print(
            f"[CCIA] Callgraph written to {out_path} "
            f"(nodes={stats.get('nodes', 0)}, edges={stats.get('edges', 0)}, "
            f"edges_with_shared_storage={stats.get('edges_with_shared_storage', 0)})"
        )
        return

    if args.list_contracts:
        for entry in find_contracts(parsed):
            alias_note = f" (file alias: {entry['file_alias']})" if entry["file_alias"] != entry["name"] else ""
            print(f"{entry['name']} [{entry['kind']}] — {entry['file']}{alias_note}")
        return

    contract_filter = None
    selected_contracts: Set[str] = set()
    if args.contract:
        try:
            contract_filter, selected_contracts = resolve_contract_filter(parsed, args.contract)
        except ValueError as exc:
            print(f"Error: {exc}")
            sys.exit(1)
        print(
            f"[CCIA] Applying contract filter '{contract_filter}' "
            f"(matching contracts: {', '.join(sorted(selected_contracts))})"
        )

    ccia = build_cross_contract_map(parsed)
    all_contracts = {}
    for pf in parsed:
        for c in pf["contracts"]:
            all_contracts[c["name"]] = c
    angles = generate_attack_angles(ccia, all_contracts)

    if selected_contracts:
        ccia, angles = filter_ccia_for_contract(ccia, angles, selected_contracts)

    if args.attack_angles:
        output = json.dumps(angles, indent=2)
    elif args.json:
        callgraph = build_callgraph(parsed)
        output = json.dumps({
            "ccia": ccia,
            "attack_angles": angles,
            "callgraph_summary": {
                "coverage_claim": "none_regex_source_shape_only",
                "stats": callgraph.get("stats", {}),
                "edge_worklist": [
                    {
                        "src": edge.get("src", ""),
                        "dst": edge.get("dst", ""),
                        "kind": edge.get("kind", ""),
                        "shared_storage_keys": edge.get("shared_storage_keys") or [],
                        "src_file": edge.get("src_file", ""),
                        "src_line": edge.get("src_line", 0),
                        "detector_next_action": "consider callgraph-aware detector predicate or demote unsupported cross-contract claim",
                    }
                    for edge in (callgraph.get("edges") or [])[:50]
                    if isinstance(edge, dict)
                ],
            },
        }, indent=2)
    else:
        output = render_markdown(ccia, angles, contract_filter=contract_filter)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"[CCIA] Report written to {args.out}")
    else:
        print(output)


if __name__ == "__main__":
    main()
