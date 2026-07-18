#!/usr/bin/env python3
"""
contract-snapshot.py — One-page human-readable contract summary

Reads a single .sol file and produces a concise summary of:
  - Contract header (name, inherits, kind, lines of code)
  - State variables (name, type, visibility)
  - Function table (name, visibility, modifiers, auth-gated?, external calls, state writes)
  - Highlighted surfaces (unauth state writes, external calls, delegatecall, selfdestruct)
  - Inheritance chain

Usage:
    contract-snapshot.py <path/to/Contract.sol>
    contract-snapshot.py ~/audits/<project>/src/<path>/<Contract>.sol
    contract-snapshot.py <contract.sol> --json
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def extract_contracts(text: str) -> List[Dict[str, Any]]:
    """Extract all contract definitions from source text."""
    # Pattern: contract Name [is Parent] { ... }
    # Use brace counting to find body end
    pattern = re.compile(r'\b(contract|library|interface)\s+(\w+)\s*(?:is\s+([^\{]+))?\s*\{', re.DOTALL)
    contracts = []
    for m in pattern.finditer(text):
        kind = m.group(1)
        name = m.group(2)
        inheritance = m.group(3)
        start = m.end() - 1  # position of opening brace
        brace_count = 0
        end = start
        for i, ch in enumerate(text[start:], start):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i
                    break
        body = text[start:end+1]
        line_num = text[:m.start()].count('\n') + 1
        contracts.append({
            "name": name,
            "kind": kind,
            "line": line_num,
            "inheritance": [x.strip() for x in inheritance.split(',')] if inheritance else [],
            "body": body,
            "raw_text": text[m.start():end+1],
        })
    return contracts


def parse_functions(body: str, base_line: int) -> List[Dict[str, Any]]:
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
            "state_writes": find_state_writes(func_body),
            "has_delegatecall": "delegatecall" in func_body,
            "has_selfdestruct": "selfdestruct" in func_body or "suicide" in func_body,
        })
    return funcs


def extract_visibility(sig: str) -> str:
    """Extract function visibility from signature."""
    for vis in ("external", "public", "internal", "private"):
        if re.search(r'\b' + vis + r'\b', sig):
            return vis
    return "public"  # default


def extract_modifiers(sig: str) -> List[str]:
    """Extract modifiers from function signature."""
    # After visibility and before returns/{, any identifiers are modifiers
    mods = []
    # Simple pattern: match words after visibility keywords
    m = re.search(r'\b(?:external|public|internal|private)\s+((?:\w+\s+)*\w+)\s*(?:returns|\{|$)', sig)
    if m:
        mod_str = m.group(1)
        # Filter out common non-modifiers
        non_mods = {"view", "pure", "override", "virtual", "payable", "constant", "memory", "storage", "calldata"}
        for word in mod_str.split():
            if word and word not in non_mods:
                mods.append(word)
    return mods


def find_external_calls(body: str) -> List[Tuple[str, str, str]]:
    """Find external calls in function body."""
    calls = []
    # High-level calls: target.function()
    pattern1 = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
    seen = set()
    for m in pattern1.finditer(body):
        target = m.group(1)
        func = m.group(2)
        if target in ("msg", "block", "tx", "abi", "keccak256", "require", "assert", "revert", "this", "super"):
            continue
        if func in ("length", "push", "pop", "add", "sub", "mul", "div"):
            continue
        key = (target, func)
        if key not in seen:
            seen.add(key)
            calls.append((target, func, "high_level"))

    # Low-level calls
    pattern2 = re.compile(r'\.(call|delegatecall|staticcall)\s*\{')
    for m in pattern2.finditer(body):
        calls.append(("?", m.group(1), "low_level"))

    # transfer / send
    pattern3 = re.compile(r'\.(transfer|send)\s*\(')
    for m in pattern3.finditer(body):
        calls.append(("?", m.group(1), "eth_transfer"))

    return calls


def find_state_writes(body: str) -> List[str]:
    """Find state variable writes in function body."""
    writes = []
    pattern = re.compile(r'\b([a-z_][a-zA-Z0-9_]*)\s*(?:=|\+=|-=|\+\+|--)')
    seen = set()
    for m in pattern.finditer(body):
        name = m.group(1)
        if name in seen or name in ("return", "if", "for", "while"):
            continue
        seen.add(name)
        writes.append(name)
    return writes


def is_auth_gated(func: Dict) -> bool:
    """Check if function has access control."""
    auth_keywords = {"onlyowner", "onlyadmin", "auth", "authorized", "restricted",
                     "onlyoperator", "onlyrole", "requireauth", "pausable",
                     "only_minter", "only_burner", "only_guardian", "only_governance"}
    for mod in func["modifiers"]:
        if any(kw in mod.lower() for kw in auth_keywords):
            return True
    body_lower = func["body"].lower()
    if "msg.sender" in body_lower and ("==" in body_lower or "!=" in body_lower):
        if re.search(r'require\s*\(\s*msg\.sender\s*[!=]=', body_lower):
            return True
        if re.search(r'if\s*\(\s*msg\.sender\s*[!=]=', body_lower):
            return True
    return False


def parse_state_vars(body: str) -> List[Dict[str, str]]:
    """Extract state variable declarations."""
    vars_list = []
    # Pattern: type visibility? name; or type name;
    # This is heuristic — we look for declarations at contract level
    pattern = re.compile(
        r'\b(mapping|uint\d*|int\d*|bytes\d*|address|bool|string|struct|enum|IERC\w*|I\w+)\s+'
        r'(?:public|private|internal)?\s*'
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*;'
    )
    for m in pattern.finditer(body):
        vars_list.append({
            "type": m.group(1),
            "name": m.group(2),
            "visibility": "public" if "public" in m.group(0) else "internal",
        })
    return vars_list


def render_snapshot(contract: Dict, funcs: List[Dict], state_vars: List[Dict]) -> str:
    """Render human-readable snapshot."""
    lines = []
    lines.append(f"# Snapshot — {contract['name']}")
    lines.append("")
    lines.append(f"**Kind:** {contract['kind']} | **Line:** {contract['line']} | **LOC:** {contract['body'].count(chr(10))}")
    if contract['inheritance']:
        lines.append(f"**Inherits:** {', '.join(contract['inheritance'])}")
    lines.append("")

    # State variables
    if state_vars:
        lines.append("## State Variables")
        for sv in state_vars[:20]:  # cap at 20
            lines.append(f"- `{sv['name']}`: {sv['type']} ({sv['visibility']})")
        if len(state_vars) > 20:
            lines.append(f"- ... and {len(state_vars) - 20} more")
        lines.append("")

    # Functions table
    lines.append("## Functions")
    lines.append("")
    lines.append("| Function | Visibility | Modifiers | Auth? | Ext Calls | State Writes | Surfaces |")
    lines.append("|---|---|---|---|---|---|---|")
    for f in funcs:
        if f["is_modifier"]:
            continue
        auth = "✅" if is_auth_gated(f) else "❌"
        ext = ", ".join(set(c[1] for c in f["external_calls"])) if f["external_calls"] else "—"
        writes = ", ".join(f["state_writes"]) if f["state_writes"] else "—"
        surfaces = []
        if f["has_delegatecall"]:
            surfaces.append("delegatecall")
        if f["has_selfdestruct"]:
            surfaces.append("selfdestruct")
        if not is_auth_gated(f) and f["visibility"] in ("public", "external") and f["state_writes"] and not f["is_constructor"]:
            surfaces.append("unauth-write")
        if f["external_calls"] and f["state_writes"]:
            surfaces.append("reentrancy-risk")
        surf_str = ", ".join(surfaces) if surfaces else "—"
        mod_str = ", ".join(f["modifiers"]) if f["modifiers"] else "—"
        lines.append(f"| `{f['name']}` | {f['visibility']} | {mod_str} | {auth} | {ext} | {writes} | {surf_str} |")
    lines.append("")

    # Highlighted surfaces
    lines.append("## Highlighted Surfaces")
    lines.append("")
    unauth_writes = [f for f in funcs if not f["is_modifier"] and not is_auth_gated(f)
                     and f["visibility"] in ("public", "external") and f["state_writes"] and not f["is_constructor"]]
    if unauth_writes:
        lines.append("### Unauthenticated State Writes")
        for f in unauth_writes:
            lines.append(f"- `{f['name']}` (line {f['line']}): writes {f['state_writes']}")
        lines.append("")

    reentrant = [f for f in funcs if not f["is_modifier"] and f["external_calls"] and f["state_writes"]]
    if reentrant:
        lines.append("### Reentrancy Risk (external call + state write)")
        for f in reentrant:
            calls = ", ".join(f"{c[0]}.{c[1]}" for c in f["external_calls"])
            lines.append(f"- `{f['name']}` (line {f['line']}): calls {calls}, writes {f['state_writes']}")
        lines.append("")

    delegate_funcs = [f for f in funcs if f["has_delegatecall"]]
    if delegate_funcs:
        lines.append("### Delegatecall")
        for f in delegate_funcs:
            lines.append(f"- `{f['name']}` (line {f['line']})")
        lines.append("")

    destruct_funcs = [f for f in funcs if f["has_selfdestruct"]]
    if destruct_funcs:
        lines.append("### Selfdestruct")
        for f in destruct_funcs:
            lines.append(f"- `{f['name']}` (line {f['line']})")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Contract snapshot analyzer")
    parser.add_argument("contract", help="Path to .sol file")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--out", help="Output file")
    args = parser.parse_args()

    path = Path(args.contract).expanduser().resolve()
    if not path.exists():
        print(f"[snapshot] File not found: {path}")
        sys.exit(1)

    text = path.read_text()
    contracts = extract_contracts(text)

    if not contracts:
        print(f"[snapshot] No contract found in {path}")
        sys.exit(1)

    # If multiple contracts in file, pick the main one (largest body)
    main_contract = max(contracts, key=lambda c: len(c["body"]))
    funcs = parse_functions(main_contract["body"], main_contract["line"])
    state_vars = parse_state_vars(main_contract["body"])

    if args.json:
        output = json.dumps({
            "contract": main_contract,
            "functions": funcs,
            "state_vars": state_vars,
        }, indent=2, default=str)
    else:
        output = render_snapshot(main_contract, funcs, state_vars)

    if args.out:
        Path(args.out).write_text(output)
        print(f"[snapshot] Written to {args.out}")
    else:
        print(output)


if __name__ == "__main__":
    main()
