#!/usr/bin/env python3
"""
irdump.py — dump Slither IR for sub-agents that can't run inline Python.

Usage:
    python3 tools/irdump.py <sol-file-or-project-dir> [contract_name] [function_name]

Output goes to stdout; redirect to a file for Read-tool consumption:
    python3 tools/irdump.py Foo.sol > /tmp/irdump.txt
"""

import sys
import os

def _type_name(ir):
    return type(ir).__name__

def _node_son_ids(node):
    return [str(s.node_id) for s in node.sons]

def dump_function(f):
    lines = []

    # --- function header ---
    lines.append(f"FUNCTION: {f.name}")
    lines.append(f"  visibility       : {f.visibility}")
    lines.append(f"  modifiers        : {[m.name for m in f.modifiers]}")
    lines.append(f"  parameters       : {[(p.name, str(p.type)) for p in f.parameters]}")

    try:
        sv_written = [sv.name for sv in f.state_variables_written]
    except Exception as e:
        sv_written = [f"[ERROR reading state_variables_written: {e}]"]
    try:
        sv_read = [sv.name for sv in f.state_variables_read]
    except Exception as e:
        sv_read = [f"[ERROR reading state_variables_read: {e}]"]

    lines.append(f"  state_vars_written: {sv_written}")
    lines.append(f"  state_vars_read  : {sv_read}")

    # high_level_calls: list of (target_contract_name, function_name) pairs
    try:
        hlc = []
        for n in f.nodes:
            for ir in n.irs:
                if _type_name(ir) == "HighLevelCall":
                    try:
                        dest = str(ir.destination.type) if hasattr(ir, "destination") else "?"
                        fname = ir.function_name if hasattr(ir, "function_name") else "?"
                        hlc.append(f"{dest}.{fname}")
                    except Exception:
                        hlc.append(str(ir))
        lines.append(f"  high_level_calls : {hlc}")
    except Exception as e:
        lines.append(f"  high_level_calls : [ERROR: {e}]")

    # internal_calls
    try:
        icalls = []
        for n in f.nodes:
            for ir in n.irs:
                if _type_name(ir) == "InternalCall":
                    try:
                        icalls.append(ir.function.name)
                    except Exception:
                        icalls.append(str(ir))
        lines.append(f"  internal_calls   : {icalls}")
    except Exception as e:
        lines.append(f"  internal_calls   : [ERROR: {e}]")

    # solidity_calls
    try:
        scalls = []
        for n in f.nodes:
            for ir in n.irs:
                if _type_name(ir) == "SolidityCall":
                    try:
                        scalls.append(ir.function.name)
                    except Exception:
                        scalls.append(str(ir))
        lines.append(f"  solidity_calls   : {scalls}")
    except Exception as e:
        lines.append(f"  solidity_calls   : [ERROR: {e}]")

    lines.append("")

    # --- nodes ---
    try:
        for node in f.nodes:
            son_ids = _node_son_ids(node)
            lines.append(f"  NODE[{node.type}] id={node.node_id} sons={son_ids}")
            for ir in node.irs:
                lines.append(f"    IR: {_type_name(ir)} :: {ir}")
            if not node.irs:
                lines.append("    (no IR)")
    except Exception as e:
        lines.append(f"  [ERROR iterating nodes: {e}]")

    return "\n".join(lines)


def dump_contract(c, function_filter=None):
    lines = []
    lines.append(f"=" * 72)
    lines.append(f"CONTRACT: {c.name}")
    lines.append(f"  kind        : {c.contract_kind}")
    try:
        lines.append(f"  inheritance : {[b.name for b in c.inheritance]}")
    except Exception as e:
        lines.append(f"  inheritance : [ERROR: {e}]")
    lines.append(f"=" * 72)
    lines.append("")

    try:
        fns = c.functions_and_modifiers_declared
    except Exception as e:
        lines.append(f"[ERROR accessing functions_and_modifiers_declared: {e}]")
        return "\n".join(lines)

    for f in fns:
        if function_filter and f.name != function_filter:
            continue
        try:
            lines.append(dump_function(f))
        except Exception as e:
            lines.append(f"[ERROR dumping function {f.name}: {e}]")
        lines.append("")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 irdump.py <sol-file-or-project-dir> [contract_name] [function_name]")
        sys.exit(1)

    target = sys.argv[1]
    contract_filter = sys.argv[2] if len(sys.argv) > 2 else None
    function_filter = sys.argv[3] if len(sys.argv) > 3 else None

    try:
        from slither import Slither
    except ImportError as e:
        print(f"[ERROR] slither-analyzer not installed: {e}")
        sys.exit(1)

    try:
        s = Slither(target)
    except Exception as e:
        print(f"[ERROR] Slither failed to compile {target!r}: {e}")
        sys.exit(1)

    try:
        cu = s.compilation_units[0]
    except (IndexError, AttributeError) as e:
        print(f"[ERROR] No compilation units found: {e}")
        sys.exit(1)

    try:
        contracts = cu.contracts
    except Exception as e:
        print(f"[ERROR] Cannot access contracts: {e}")
        sys.exit(1)

    printed = 0
    for c in contracts:
        if contract_filter and c.name != contract_filter:
            continue
        print(dump_contract(c, function_filter=function_filter))
        printed += 1

    if printed == 0:
        if contract_filter:
            print(f"[WARN] No contract named {contract_filter!r} found in {target}")
        else:
            print(f"[WARN] No contracts found in {target}")


if __name__ == "__main__":
    main()
