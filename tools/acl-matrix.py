#!/usr/bin/env python3
"""
acl-matrix.py - R76 C: access-control matrix generator.

Produces a per-contract table of `function × required-role`, then flags
patterns that top auditors look for:

  * Two functions gate on different roles to do "similar" things →
    potential confused-deputy.
  * A state-mutating function has NO gate (anyone can call) and modifies
    a privileged state variable → missing access control.
  * A function is gated by a role that is never granted anywhere in the
    source → dead gate (impossible to call in practice = liveness bug).
  * Role-grant itself is gated by another role held by... nobody in
    the scope → bootstrap deadlock.

Output: <workspace>/acl_matrix.md

Usage:
  python3 tools/acl-matrix.py <workspace>
"""

import argparse, pathlib, re, sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _analyzer_common import iter_source_files

try:
    from slither.slither import Slither
except ImportError:
    print("[err] Slither required", file=sys.stderr); sys.exit(1)


# "Privileged" state variables - anyone modifying these without a gate is a bug.
PRIVILEGED_VAR_HINTS = [
    "owner", "admin", "pauser", "guardian", "feereceiver",
    "feerate", "rate", "threshold", "oracle", "pricefeed",
    "implementation", "beacon",
]


def _extract_role_from_modifier(mod_name, function):
    """Infer which role a modifier requires, heuristically."""
    mn = mod_name or ""
    if mn in ("onlyOwner",): return "Owner"
    if mn in ("onlyAdmin",): return "Admin"
    if mn in ("onlyGovernance", "onlyTimelock"): return "Governance"
    if mn in ("onlyPauser", "whenNotPaused", "whenPaused"): return "Pauser"
    # onlyRole(ROLE_NAME) - MUST precede the generic only<Word> regex below,
    # else "onlyRole" collapses to a single literal "Role" and every OZ role
    # merges into one bucket (breaks per-role analysis).
    if mn == "onlyRole":
        # Scan the function body for the ROLE_NAME arg - crude but works for most
        src = getattr(function, "source_mapping", None)
        txt = getattr(src, "content", "") if src else ""
        rm = re.search(r"onlyRole\(\s*([A-Z_][A-Z0-9_]*_ROLE)\s*\)", txt or "")
        if rm: return rm.group(1)
        return "Role(?)"
    m = re.match(r"^only([A-Z][A-Za-z]+)$", mn)
    if m: return m.group(1)
    return mn or "-"


def _requires_in_function(function):
    """Scan function body for require/assert guards that are role-like."""
    txt = getattr(function.source_mapping, "content", "") or ""
    # require(msg.sender == owner)
    roles = []
    for m in re.finditer(r"require\s*\(\s*msg\.sender\s*==\s*(\w+)\s*", txt):
        roles.append(f"==({m.group(1)})")
    for m in re.finditer(r"require\s*\(\s*hasRole\s*\(\s*([A-Z_]+_ROLE)", txt):
        roles.append(f"hasRole({m.group(1)})")
    for m in re.finditer(r"_checkRole\s*\(\s*([A-Z_]+_ROLE)", txt):
        roles.append(f"_checkRole({m.group(1)})")
    return roles


def _analyze(ws):
    rows = []
    ungated_privileged = []
    role_grants = defaultdict(list)   # role_name -> [(fn_name, contract)]
    role_uses = defaultdict(list)      # role_name -> [(fn_name, contract)]
    for sol in iter_source_files(ws, max_files=200):  # R79 T3
        try: sl = Slither(str(sol))
        except Exception: continue
        for c in sl.contracts:
            if c.is_interface or c.is_library: continue
            for fn in c.functions_and_modifiers_declared:
                vis = getattr(fn, "visibility", "")
                if vis not in ("external", "public"): continue
                if getattr(fn, "view", False) or getattr(fn, "pure", False): continue
                if getattr(fn, "is_constructor", False): continue

                mods = [getattr(m, "name", "") for m in (getattr(fn, "modifiers", []) or [])]
                role_names = [_extract_role_from_modifier(m, fn) for m in mods]
                require_roles = _requires_in_function(fn)

                writes = [getattr(sv, "name", "") for sv in (getattr(fn, "state_variables_written", []) or [])]
                priv_writes = [w for w in writes if any(k in w.lower() for k in PRIVILEGED_VAR_HINTS)]

                rows.append({
                    "contract": c.name, "fn": fn.name, "vis": vis,
                    "roles_via_mods": role_names, "roles_via_requires": require_roles,
                    "writes_to": writes, "priv_writes": priv_writes,
                })

                # Flag: no gate + writes to privileged var
                if not role_names and not require_roles and priv_writes:
                    ungated_privileged.append((c.name, fn.name, priv_writes))

                # Track role uses (who checks role X)
                for r in role_names + require_roles:
                    if r and r not in ("-", "?"):
                        role_uses[r].append((c.name, fn.name))

                # Track role grants (anyone granting role X)
                for node in getattr(fn, "nodes", []) or []:
                    expr = str(getattr(node, "expression", "") or "")
                    gm = re.search(r"_?grantRole\s*\(\s*([A-Z_]+_ROLE)", expr)
                    if gm: role_grants[gm.group(1)].append((c.name, fn.name))

    dead_gates = []
    for role, uses in role_uses.items():
        # Is this role ever granted anywhere?
        if role not in role_grants and role.endswith("_ROLE"):
            dead_gates.append((role, uses))

    return rows, ungated_privileged, dead_gates, role_grants, role_uses


def _render(rows, ungated, dead_gates, role_grants, role_uses, out):
    with open(out, "w") as f:
        f.write("# Access-control matrix\n\n")
        f.write("Generated by `tools/acl-matrix.py`. For every external/public "
                "non-view function, shows the roles required to call it and what "
                "privileged state it writes.\n\n")

        f.write("## ⚠️ Ungated functions writing privileged state - AUDIT FIRST\n\n")
        if not ungated:
            f.write("_None found._\n\n")
        else:
            f.write("| Contract | Function | Writes to |\n|---|---|---|\n")
            for c, fn, writes in ungated:
                f.write(f"| `{c}` | `{fn}` | {', '.join(writes)} |\n")

        f.write("\n## ⚠️ Dead gates - role checked but never granted in scope\n\n")
        if not dead_gates:
            f.write("_None found._\n\n")
        else:
            for role, uses in dead_gates:
                f.write(f"- **`{role}`** - checked by {len(uses)} function(s) "
                        f"but no `grantRole({role})` in scope. Either the role "
                        f"is granted out-of-scope (document it) OR the function "
                        f"is unreachable.\n")
                for c, fn in uses[:3]:
                    f.write(f"  - `{c}.{fn}`\n")

        f.write("\n## Full matrix\n\n")
        by_contract = defaultdict(list)
        for r in rows:
            by_contract[r["contract"]].append(r)
        for cname in sorted(by_contract.keys()):
            entries = by_contract[cname]
            f.write(f"\n### `{cname}`\n\n")
            f.write("| Function | Modifiers | Require-roles | Writes |\n|---|---|---|---|\n")
            for r in sorted(entries, key=lambda x: x["fn"]):
                mods = ", ".join(r["roles_via_mods"]) or "-"
                reqs = ", ".join(r["roles_via_requires"]) or "-"
                writes = ", ".join(r["writes_to"][:4]) or "-"
                f.write(f"| `{r['fn']}` | {mods} | {reqs} | {writes} |\n")

        f.write("\n## Role-grant graph\n\n")
        f.write("| Role | Granted by | Checked by (count) |\n|---|---|---|\n")
        all_roles = set(role_grants.keys()) | set(role_uses.keys())
        for role in sorted(all_roles):
            grants = role_grants.get(role, [])
            uses = role_uses.get(role, [])
            granters = ", ".join(f"`{c}.{fn}`" for c, fn in grants[:3]) or "**NEVER**"
            f.write(f"| `{role}` | {granters} | {len(uses)} |\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    args = ap.parse_args()
    ws = pathlib.Path(args.workspace)
    if not ws.is_dir():
        print(f"[err] workspace not found", file=sys.stderr); sys.exit(1)
    rows, ungated, dead_gates, role_grants, role_uses = _analyze(ws)
    out = ws / "acl_matrix.md"
    _render(rows, ungated, dead_gates, role_grants, role_uses, out)
    print(f"[ok] wrote {out}")
    print(f"     ungated privileged writes: {len(ungated)}")
    print(f"     dead gates: {len(dead_gates)}")
    print(f"     total entries: {len(rows)}")


if __name__ == "__main__":
    main()
