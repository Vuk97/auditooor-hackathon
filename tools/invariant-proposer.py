#!/usr/bin/env python3
"""
invariant-proposer.py — R76 H: generate candidate invariants from
contract shape + feed them to invariant-hunt.sh.

Top auditors enumerate "what must always be true" before starting line-by-line
review. They ask: for every state variable, what's the relationship to other
state vars / totals / balances? Every violated relationship = a bug.

This tool does that enumeration mechanically:

  1. For every contract, list state variables + their types.
  2. Classify each: mapping-of-amounts, total counter, monotonic counter,
     address-ref, flag.
  3. Propose invariants from a library of templates:
     - `sum(balances) == totalSupply`  (ERC20-like)
     - `totalDebt <= totalSupply`
     - `sum(userBal) == internalAccounting`
     - `nonces[user]` strictly non-decreasing
     - `paused` transitions only via pause/unpause functions
     - after any mutation: `invariant_name()` should still return true
  4. Emit a Foundry StatefulHandler test that asserts each invariant.

Output: <workspace>/invariant_hunt/auto_proposed/<contract>.invariants.sol

The operator can import these into the invariant-hunt harness.
(`tools/invariant-hunt.sh` will auto-pick them up.)

Usage:
  python3 tools/invariant-proposer.py <workspace>
  python3 tools/invariant-proposer.py <workspace> --contract Vault
"""

import argparse, json, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _analyzer_common import iter_source_files
from collections import defaultdict

try:
    from slither.slither import Slither
except ImportError:
    print("[err] Slither required", file=sys.stderr); sys.exit(1)


def propose_ccia_invariants(ccia_data: dict) -> list:
    """Generate cross-contract invariants from CCIA analysis."""
    props = []
    ccia = ccia_data.get("ccia", {})

    # Trust boundary invariants: unauthenticated functions should NOT be able
    # to trigger auth-gated state changes
    for tb in ccia.get("trust_boundaries", []):
        source = tb.get("source", "")
        target = tb.get("target", "")
        props.append((
            f"cross_invariant_auth_boundary_{source.replace('.', '_')}_{target.replace('.', '_')}",
            f"// Trust boundary: {source} must NOT bypass auth on {target}",
            f"// Operator: call {source} from non-owner; assert {target} state unchanged",
        ))

    # Reentrancy invariants: after any external call, critical state must be consistent
    for rs in ccia.get("reentrancy_surfaces", []):
        c = rs.get("contract", "")
        f = rs.get("function", "")
        writes = rs.get("writes_after", [])
        for w in writes:
            props.append((
                f"cross_invariant_reentrancy_{c}_{f}_{w}",
                f"// Reentrancy: after external call in {c}.{f}, {w} must be consistent",
                f"// Operator: reenter during {c}.{f}; assert {w} is not corrupted",
            ))

    # State race invariants: multi-contract variables should stay synchronized
    for sr in ccia.get("state_races", []):
        var = sr.get("var", "")
        readers = sr.get("readers", [])
        writers = sr.get("writers", [])
        if len(readers) == 1 and len(writers) == 1:
            # Simple 1:1 mapping
            props.append((
                f"cross_invariant_sync_{var}",
                f"// State sync: {writers[0]}.{var} must equal {readers[0]}.{var}",
                f"// Operator: mutate via {writers[0]}; assert {readers[0]}.{var}() matches",
            ))
        else:
            # Multi-party: sum or consistency check
            props.append((
                f"cross_invariant_consistency_{var}",
                f"// State consistency: {var} must be consistent across {len(readers)} readers and {len(writers)} writers",
                f"// Operator: after any write, read from all readers and assert consistency",
            ))

    # Unauthenticated state write invariants: these should be auth-gated
    for upf in ccia.get("unauth_privileged_funcs", []):
        c = upf.get("contract", "")
        f = upf.get("function", "")
        writes = upf.get("writes", [])
        for w in writes:
            props.append((
                f"cross_invariant_auth_{c}_{f}_{w}",
                f"// Access control: {c}.{f} writes {w} without auth — verify this is intentional",
                f"// Operator: call {c}.{f} from arbitrary address; if it succeeds, verify no harm",
            ))

    return props


def classify(sv):
    """Classify a state variable into an invariant-bearing category."""
    t = str(getattr(sv, "type", ""))
    n = (sv.name or "").lower()
    if "mapping(address => uint" in t or "mapping (address => uint" in t:
        return "user_amount_map"
    if "mapping(uint" in t or "mapping (uint" in t:
        return "id_amount_map"
    if n.startswith("total") and t.startswith("uint"):
        return "total_counter"
    if "nonces" in n or "nonce" in n and t.startswith("uint"):
        return "monotonic_counter"
    if t == "bool" and ("paused" in n or "enabled" in n or "initialized" in n):
        return "pause_flag"
    if t == "address":
        return "address_ref"
    if t.startswith("uint") and ("index" in n or "id" in n or "counter" in n):
        return "monotonic_counter"
    return "other"


def propose_invariants(contract):
    """Walk state vars, emit a list of (name, body) invariant proposals."""
    props = []
    classes = defaultdict(list)
    for sv in contract.state_variables_ordered:
        if getattr(sv, "is_constant", False) or getattr(sv, "is_immutable", False):
            continue
        c = classify(sv)
        classes[c].append(sv)

    # ERC20-like sum(balances) == totalSupply
    if "user_amount_map" in classes and "total_counter" in classes:
        for bal in classes["user_amount_map"]:
            if "balance" in bal.name.lower() or "bal" in bal.name.lower():
                for tot in classes["total_counter"]:
                    if "supply" in tot.name.lower() or "total" in tot.name.lower():
                        props.append((
                            f"invariant_sum_{bal.name}_eq_{tot.name}",
                            f"// sum({bal.name}[users]) must equal {tot.name}",
                            f"// Operator: iterate actors, sum their {bal.name}, assertEq to target.{tot.name}()",
                        ))

    # Monotonic counter must not decrease
    for mv in classes.get("monotonic_counter", []):
        props.append((
            f"invariant_{mv.name}_monotonic",
            f"// {mv.name} must never decrease across any tx",
            f"uint256 curr = target.{mv.name}(actor); assertGe(curr, ghost_{mv.name}); ghost_{mv.name} = curr;",
        ))

    # Paused flag state machine: reaching paused=true requires calling `pause`
    for pf in classes.get("pause_flag", []):
        props.append((
            f"invariant_{pf.name}_transition_only_via_privileged",
            f"// {pf.name} only flips on calls to pause/unpause functions",
            f"// Operator: snapshot {pf.name} pre-call; if changed, assert caller has pauser role.",
        ))

    # Address-ref must be non-zero post-init
    for ar in classes.get("address_ref", []):
        props.append((
            f"invariant_{ar.name}_nonzero",
            f"// {ar.name} must not be address(0) after initialization",
            f"assertTrue(target.{ar.name}() != address(0), \"{ar.name} is zero\");",
        ))

    return props


def render_sol(contract, proposals):
    cname = contract.name
    body_parts = []
    for name, comment, stmt in proposals:
        body_parts.append(f"""
    /// {comment}
    function {name}() public view {{
        {stmt}
    }}""")
    body = "\n".join(body_parts) or "\n    // No invariants proposed for this contract."

    return f"""// SPDX-License-Identifier: MIT
// Auto-proposed invariants for {cname} by tools/invariant-proposer.py
// Review each invariant and promote to invariant-hunt harness.
pragma solidity ^0.8.20;

import {{Test, StdInvariant}} from "forge-std/Test.sol";

interface I{cname} {{
    // Operator: declare the target's external/public interface here.
}}

contract AutoInvariant_{cname} is StdInvariant, Test {{
    I{cname} public target;
    // Ghost storage for monotonicity checks:
    uint256 internal ghost_nonce;
{body}
}}
"""


def render_ccia_sol(ccia_proposals: list) -> str:
    """Render cross-contract invariants from CCIA into a single test file."""
    body_parts = []
    for name, comment, stmt in ccia_proposals:
        body_parts.append(f"""
    /// {comment}
    function {name}() public view {{
        {stmt}
    }}""")
    body = "\n".join(body_parts) or "\n    // No cross-contract invariants proposed."

    return f"""// SPDX-License-Identifier: MIT
// Auto-proposed CROSS-CONTRACT invariants by tools/invariant-proposer.py --ccia
// Review each invariant and promote to invariant-hunt harness.
pragma solidity ^0.8.20;

import {{Test, StdInvariant}} from "forge-std/Test.sol";

contract AutoInvariant_CrossContract is StdInvariant, Test {{
    // Operator: deploy all involved contracts here.
{body}
}}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    ap.add_argument("--contract", default=None)
    ap.add_argument("--ccia", help="Path to CCIA JSON output for cross-contract invariants")
    args = ap.parse_args()
    ws = pathlib.Path(args.workspace)
    if not ws.is_dir(): print("[err] not a dir", file=sys.stderr); sys.exit(1)
    out_dir = ws / "invariant_hunt" / "auto_proposed"
    out_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for sol in iter_source_files(ws, max_files=200):  # R79 T3
        try: sl = Slither(str(sol))
        except Exception: continue
        for c in sl.contracts:
            if c.is_interface or c.is_library: continue
            if args.contract and c.name != args.contract: continue
            props = propose_invariants(c)
            if not props: continue
            sol_out = out_dir / f"{c.name}.invariants.sol"
            sol_out.write_text(render_sol(c, props))
            written += 1
            print(f"  [ok] {c.name}: {len(props)} invariants → {sol_out.name}")

    # Cross-contract invariants from CCIA
    if args.ccia:
        ccia_path = pathlib.Path(args.ccia)
        if ccia_path.exists():
            ccia_data = json.loads(ccia_path.read_text())
            ccia_props = propose_ccia_invariants(ccia_data)
            if ccia_props:
                ccia_out = out_dir / "CrossContract.invariants.sol"
                ccia_out.write_text(render_ccia_sol(ccia_props))
                written += 1
                print(f"  [ok] CCIA cross-contract: {len(ccia_props)} invariants → {ccia_out.name}")
        else:
            print(f"  [warn] CCIA file not found: {args.ccia}")

    print(f"\n[ok] wrote {written} invariant files under {out_dir}")
    print(f"     Next: wire each into your Foundry invariant harness + run tools/invariant-hunt.sh.")


if __name__ == "__main__":
    main()
