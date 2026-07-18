#!/usr/bin/env python3
"""Non-vacuity fixture test for the Phase 1 Solidity data-flow slice.

Asserts (R-C mutation-verified non-vacuity discipline):
  - vulnerable.sol emits a DefUsePath to transferFrom with call_depth >= 2 AND
    unguarded == True (NO require dominating the multi-hop slice).
  - clean.sol emits the SAME multi-hop path (call_depth >= 2) but unguarded == False
    AND a populated guard_nodes list (the require(amt<=cap) is detected).
  - The recovered path crosses >= 2 CALL HOPS (not intra-function) - this is the
    non-vacuity witness: a single-function slice would have call_depth 0 and the
    test would FAIL, proving the inter-procedural reconstruction is load-bearing.

The contrast between the two fixtures (identical flow, guard the only difference)
is the mutation pair: the guard is the injected/removed behavior, and the
unguarded flag flips accordingly - an assert(true) property cannot do that.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "dataflow-slice.py"
FIX = REPO / "tests" / "fixtures" / "dataflow"


def _run(fixture_name: str, extra_args=None):
    sol = FIX / fixture_name
    assert sol.exists(), f"fixture missing: {sol}"
    ws = Path(tempfile.mkdtemp(prefix=f"dftest_{fixture_name}_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    out = ws / ".auditooor" / "dataflow_paths.jsonl"
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--workspace", str(ws),
         "--target", str(sol), "--json"] + (extra_args or []),
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"tool failed rc={proc.returncode}\n{proc.stderr}\n{proc.stdout}"
    assert out.exists(), f"no jsonl written: {out}"
    recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    return recs, proc.stdout


def _transferfrom_amount_path(recs):
    """The amount->transferFrom multi-hop slice (arg_pos 2, the value arg)."""
    cands = [r for r in recs
             if r["sink"]["callee"] == "transferFrom"
             and r["sink"]["arg_pos"] == 2
             and r["source"]["var"] == "amount"]
    assert len(cands) == 1, f"expected exactly 1 amount->transferFrom path, got {len(cands)}: {cands}"
    return cands[0]


def test_vulnerable_unguarded_multihop():
    recs, _ = _run("vulnerable.sol")
    p = _transferfrom_amount_path(recs)
    # non-vacuity: >= 2 call hops (inter-procedural), not intra-function
    assert p["call_depth"] >= 2, f"vulnerable path call_depth={p['call_depth']} (<2 = not multi-hop)"
    assert p["unguarded"] is True, f"vulnerable path should be unguarded, got {p['unguarded']}"
    assert p["confidence"] == "semantic-ssa", f"expected semantic-ssa, got {p['confidence']}"
    assert p["degraded"] is False
    # hops actually cross internal calls
    internal_hops = [h for h in p["hops"] if h["via"] in ("internal_call", "high_level")]
    assert len(internal_hops) >= 2, f"expected >=2 inter-procedural hops, got {internal_hops}"


def test_clean_guarded_multihop():
    recs, _ = _run("clean.sol")
    p = _transferfrom_amount_path(recs)
    assert p["call_depth"] >= 2, f"clean path call_depth={p['call_depth']} (<2 = not multi-hop)"
    assert p["unguarded"] is False, f"clean path should be guarded, got unguarded={p['unguarded']}"
    assert len(p["guard_nodes"]) >= 1, f"clean path must have populated guard_nodes, got {p['guard_nodes']}"
    # the guard must reference the bound check on the tainted var
    guard_exprs = " ".join(g["expr"] for g in p["guard_nodes"])
    assert "cap" in guard_exprs or "require" in guard_exprs.lower(), \
        f"guard_nodes should capture the require(amt<=cap), got {p['guard_nodes']}"


def test_nonvacuity_guard_flips_unguarded():
    """Mutation-pair witness: same flow, the ONLY difference (the require) flips unguarded."""
    rv, _ = _run("vulnerable.sol")
    rc, _ = _run("clean.sol")
    pv = _transferfrom_amount_path(rv)
    pc = _transferfrom_amount_path(rc)
    # identical structural slice (same sink, same source var, same hop count)
    assert pv["call_depth"] == pc["call_depth"] >= 2, \
        f"slices not structurally identical: {pv['call_depth']} vs {pc['call_depth']}"
    # the unguarded flag is the discriminator - it MUST differ
    assert pv["unguarded"] is True and pc["unguarded"] is False, \
        f"non-vacuity FAILED: vuln.unguarded={pv['unguarded']} clean.unguarded={pc['unguarded']}"


# ---------------------------------------------------------------------------
# DEEPEN gap 1: MULTI-CALLER fan-out (backward_df_all follows ALL caller frames)
# ---------------------------------------------------------------------------
def _payouts(recs):
    """The amount->transferFrom multi-hop slices in the multi_caller fixture."""
    return [r for r in recs
            if r["sink"]["callee"] == "transferFrom"
            and r["sink"]["arg_pos"] == 2
            and r["call_depth"] >= 2]


def test_multicaller_fanout_recovers_all_chains():
    """Fan-out witness: the shared sink _pay() is reached from TWO distinct caller
    chains (withdrawA->_routeA and withdrawB->_routeB). A correct fan-out must
    recover BOTH, each at call_depth >= 2 with distinct top-level source vars."""
    recs, _ = _run("multi_caller.sol")
    paths = _payouts(recs)
    assert len(paths) >= 2, f"fan-out should recover >=2 caller chains, got {len(paths)}: " \
        f"{[(p['source']['fn'], p['source']['var']) for p in paths]}"
    src_vars = {p["source"]["var"] for p in paths}
    # the two chains start from DIFFERENT top-level params (amount vs qty)
    assert "amount" in src_vars and "qty" in src_vars, \
        f"fan-out must recover both distinct caller frames, got source vars {src_vars}"
    for p in paths:
        assert p["call_depth"] >= 2, f"chain {p['source']['var']} depth={p['call_depth']} (<2)"
        assert p["confidence"] == "semantic-ssa"
        internal = [h for h in p["hops"] if h["via"] in ("internal_call", "high_level")]
        assert len(internal) >= 2, f"chain {p['source']['var']} has <2 inter-proc hops: {internal}"


def test_nonvacuity_fanout_vs_single_chain():
    """Mutation-pair witness for the fan-out: the legacy single-chain walk
    (--no-fanout) recovers only ONE caller chain; the default fan-out recovers
    BOTH. Disabling the fan-out logic FLIPS the recovered-chain count -> the
    fan-out is load-bearing, not an assert(true)."""
    fan, _ = _run("multi_caller.sol")
    single, _ = _run("multi_caller.sol", extra_args=["--no-fanout"])
    fan_vars = {p["source"]["var"] for p in _payouts(fan)}
    single_vars = {p["source"]["var"] for p in _payouts(single)}
    assert len(fan_vars) >= 2, f"fan-out should see both chains, got {fan_vars}"
    assert len(single_vars) == 1, \
        f"single-chain walk should recover exactly 1 chain (non-vacuity), got {single_vars}"
    assert single_vars < fan_vars, \
        f"fan-out must strictly superset single-chain: fan={fan_vars} single={single_vars}"


# ---------------------------------------------------------------------------
# DEEPEN gap 2: STORAGE-MEDIATED cross-function def-use (via:"storage")
# ---------------------------------------------------------------------------
def _storage_credit_payout(recs):
    """The credit(write balances) -> payout(read balances) storage-mediated path."""
    cands = [r for r in recs
             if r.get("mode") == "storage-mediated"
             and "credit" in (r["source"]["fn"] or "")
             and "payout" in (r["sink"]["fn"] or "")
             and r["source"]["var"] == "balances"]
    assert len(cands) == 1, f"expected exactly 1 credit->payout storage path, got {len(cands)}: {cands}"
    return cands[0]


def test_storage_mediated_unguarded():
    recs, _ = _run("storage_unguarded.sol",
                   extra_args=["--mode", "storage", "--storage-var", "balances"])
    p = _storage_credit_payout(recs)
    assert p["source"]["kind"] == "state_var", f"source.kind should be state_var, got {p['source']['kind']}"
    vias = [h["via"] for h in p["hops"]]
    assert "storage" in vias, f"expected a via:'storage' hop, got {vias}"
    assert p["unguarded"] is True, f"unguarded storage flow should be unguarded:true, got {p['unguarded']}"
    assert p["call_depth"] >= 1, f"storage hop must count toward call_depth, got {p['call_depth']}"
    assert p["confidence"] in ("semantic-ssa", "syntactic")
    assert p["degraded"] is False


def test_storage_mediated_guarded():
    recs, _ = _run("storage_guarded.sol",
                   extra_args=["--mode", "storage", "--storage-var", "balances"])
    p = _storage_credit_payout(recs)
    assert p["unguarded"] is False, f"guarded storage flow should be unguarded:false, got {p['unguarded']}"
    assert len(p["guard_nodes"]) >= 1, f"guarded variant must populate guard_nodes, got {p['guard_nodes']}"


def test_nonvacuity_storage_guard_flips_unguarded():
    """Mutation-pair witness for storage mode: same write->read storage flow, the
    ONLY difference (the require over balances) flips unguarded."""
    ru, _ = _run("storage_unguarded.sol",
                 extra_args=["--mode", "storage", "--storage-var", "balances"])
    rg, _ = _run("storage_guarded.sol",
                 extra_args=["--mode", "storage", "--storage-var", "balances"])
    pu = _storage_credit_payout(ru)
    pg = _storage_credit_payout(rg)
    # structurally identical: same source/sink fns, same via:storage hop count
    assert pu["call_depth"] == pg["call_depth"], \
        f"storage slices not structurally identical: {pu['call_depth']} vs {pg['call_depth']}"
    assert pu["unguarded"] is True and pg["unguarded"] is False, \
        f"storage non-vacuity FAILED: unguarded.u={pu['unguarded']} guarded.g={pg['unguarded']}"


# ---------------------------------------------------------------------------
# KEYSTONE Part 1: D-connect (closure-aware `unguarded`) - up-graph guard
# ---------------------------------------------------------------------------
def _run_source(sol_text: str, extra_args=None, suffix="mut"):
    """Compile an in-memory Solidity source string and return its records."""
    ws = Path(tempfile.mkdtemp(prefix=f"dftest_src_{suffix}_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    sol = ws / f"{suffix}.sol"
    sol.write_text(sol_text)
    out = ws / ".auditooor" / "dataflow_paths.jsonl"
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--workspace", str(ws),
         "--target", str(sol), "--json"] + (extra_args or []),
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"tool failed rc={proc.returncode}\n{proc.stderr}\n{proc.stdout}"
    recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()] if out.exists() else []
    return recs, proc.stdout


def _upgraph_transferfrom_path(recs):
    cands = [r for r in recs
             if r["sink"]["callee"] == "transferFrom"
             and r["sink"].get("arg_pos") == 2
             and (r["source"].get("fn") or "").endswith("withdraw(uint256)")]
    assert len(cands) == 1, f"expected 1 withdraw->transferFrom path, got {len(cands)}: " \
        f"{[(r['source'].get('fn'), r['sink'].get('arg_pos')) for r in cands]}"
    return cands[0]


def test_closure_default_off_byte_identical():
    """Default-off: WITHOUT --closure-unguarded the up-graph guard is INVISIBLE
    (slice-local), so the record is unguarded=true and carries NO closure_* keys.
    This pins the additive/default-off contract: the records are byte-identical to
    the pre-D-connect engine."""
    recs, _ = _run("up_graph_guard.sol")
    p = _upgraph_transferfrom_path(recs)
    assert p["unguarded"] is True, f"slice-local should miss the up-graph guard, got {p['unguarded']}"
    assert "closure_consulted" not in p, "default-off must NOT add closure keys (byte-identical)"
    assert "unguarded_closure_corrected" not in p


def test_closure_flips_unguarded_via_upgraph_modifier():
    """D-connect keystone: WITH --closure-unguarded the up-graph onlyOwner modifier
    guard is folded by the inter-procedural closure (has_guard_in_closure on the
    source entrypoint), flipping unguarded true -> false."""
    recs, _ = _run("up_graph_guard.sol", extra_args=["--closure-unguarded"])
    p = _upgraph_transferfrom_path(recs)
    assert p.get("closure_consulted") is True, "closure must be consulted"
    assert p["unguarded"] is False, f"closure must flip unguarded to false, got {p['unguarded']}"
    assert p.get("unguarded_closure_corrected") is True
    assert p.get("closure_guarded") is True
    assert "source-closure" in (p.get("closure_note") or "")


def test_closure_nonvacuity_remove_upgraph_guard_flips_back():
    """Mutation-pair witness for D-connect: remove the ONLY up-graph guard (the
    require in the onlyOwner modifier body) and the SAME closure pass leaves
    unguarded=true (no flip). The guard - and only the guard - drives the flip, so
    the closure correction is non-vacuous (not an assert(true))."""
    base = (FIX / "up_graph_guard.sol").read_text()
    mutant = base.replace('require(msg.sender == owner, "not owner");', "/* GUARD REMOVED */")
    assert mutant != base, "mutation did not change the source"
    recs, _ = _run_source(mutant, extra_args=["--closure-unguarded"], suffix="upgraph_nomod")
    p = _upgraph_transferfrom_path(recs)
    assert p.get("closure_consulted") is True
    assert p["unguarded"] is True, \
        f"with the up-graph guard removed the path must stay unguarded, got {p['unguarded']}"
    assert p.get("unguarded_closure_corrected") is not True, \
        "no guard exists -> closure must NOT flip (non-vacuity)"


def test_closure_degrade_is_honest():
    """R80: when the predicates module is reachable but the sink/source fn cannot be
    resolved (synthetic record), the closure pass marks closure_degraded and does
    NOT silently claim a guard. Verified via the engine API directly on an unresolvable
    record."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_df_mod", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # a record whose source/sink fns are not in any compilation unit
    fake = mod.dfs.new_path(
        path_id="x", language="solidity", direction="backward",
        engine="t", source={"kind": "param-entrypoint", "fn": "Nope.ghost()", "var": "a", "file": None, "line": None},
        sink={"kind": "transfer", "callee": "transfer", "arg_pos": 0, "fn": "Nope.ghost()", "file": None, "line": None},
        hops=[], confidence="semantic-ssa",
    )

    class _Empty:
        compilation_units = []
    eng = mod.DataFlowEngine.__new__(mod.DataFlowEngine)
    eng.sl = _Empty()
    stats = eng.apply_closure_unguarded([fake])
    assert fake.get("closure_degraded") is True, f"unresolvable fn must degrade, got {fake}"
    assert fake["unguarded"] is True, "degrade must NOT change unguarded (R80)"
    assert stats["degraded"] >= 1


# ---------------------------------------------------------------------------
# KEYSTONE Part 2: economic storage-value sink (sink-taxonomy extension)
# ---------------------------------------------------------------------------
def _storage_value_sinks(recs):
    return [r for r in recs if r.get("mode") == "storage-value"]


def test_storage_value_default_off_byte_identical():
    """Default-off: WITHOUT --emit-storage-value no storage-value sink is emitted,
    even in storage mode. Byte-identical to the pre-extension engine."""
    recs, _ = _run("storage_value_econ.sol", extra_args=["--mode", "storage"])
    assert _storage_value_sinks(recs) == [], "default-off must emit NO storage-value sinks"


def test_storage_value_econ_write_surfaced():
    """Economic storage WRITE (operatorEthVUnits +=/delete) surfaces as a
    storage-value sink; the non-economic write (lastSeen timestamp) does NOT."""
    recs, _ = _run("storage_value_econ.sol",
                   extra_args=["--mode", "storage", "--emit-storage-value"])
    sv = _storage_value_sinks(recs)
    callees = {r["sink"]["callee"] for r in sv}
    assert "operatorEthVUnits" in callees, f"economic write must be a storage-value sink, got {callees}"
    assert "lastSeen" not in callees, f"non-economic (timestamp) write must NOT be tagged, got {callees}"
    for r in sv:
        assert r["sink"]["kind"] == "storage-value"
        assert r["confidence"] in ("semantic-ssa", "syntactic")
        assert r["degraded"] is False


def test_storage_value_nonvacuity_rename_var_kills_sink():
    """Mutation-pair witness for the sink taxonomy: rename the economic var to a
    NON-economic name (operatorEthVUnits -> operatorTag) and the storage-value sink
    DISAPPEARS. The economic-name heuristic - and only it - drives detection, so
    the new sink kind is non-vacuous."""
    base = (FIX / "storage_value_econ.sol").read_text()
    mutant = base.replace("operatorEthVUnits", "operatorTag")
    assert mutant != base
    recs, _ = _run_source(mutant,
                          extra_args=["--mode", "storage", "--emit-storage-value"],
                          suffix="econ_renamed")
    sv = _storage_value_sinks(recs)
    callees = {r["sink"]["callee"] for r in sv}
    assert "operatorTag" not in callees, \
        f"renaming the var to a non-economic name must KILL the sink, got {callees}"


def test_storage_value_closure_corrects_role_gated_write():
    """Combined keystone: with --emit-storage-value AND --closure-unguarded, the
    role-gated removeOperator (delete operatorEthVUnits, onlyRegistrar) storage-value
    sink is closure-corrected to unguarded=false, while the permissionless accrueUnits
    storage-value sink stays unguarded=true."""
    recs, _ = _run("storage_value_econ.sol",
                   extra_args=["--mode", "storage", "--emit-storage-value", "--closure-unguarded"])
    sv = {r["sink"]["fn"].split(".")[-1]: r for r in _storage_value_sinks(recs)}
    accrue = sv.get("accrueUnits(uint64,uint256)")
    remove = sv.get("removeOperator(uint64)")
    assert accrue is not None and remove is not None, f"missing sinks: {list(sv)}"
    assert accrue["unguarded"] is True, "permissionless economic write must stay unguarded"
    assert remove["unguarded"] is False, "role-gated economic write must be closure-corrected"
    assert remove.get("unguarded_closure_corrected") is True


# ---------------------------------------------------------------------------
# KEYSTONE Part 3: BACKWARD-ENTRYPOINT closure (internal value-mover guarded
# at its caller entrypoints, NOT in its own forward closure)
# ---------------------------------------------------------------------------
def _move_path(recs, mover_suffix):
    """The amount->transferFrom path whose SOURCE fn is the given internal mover."""
    cands = [r for r in recs
             if r["sink"]["callee"] == "transferFrom"
             and (r["source"].get("fn") or "").endswith(mover_suffix)]
    assert len(cands) == 1, \
        f"expected exactly 1 {mover_suffix} path, got {len(cands)}: " \
        f"{[(r['source'].get('fn')) for r in cands]}"
    return cands[0]


def test_backward_default_off_byte_identical():
    """Default-off: WITHOUT --closure-unguarded the internal mover's caller-side
    guard is invisible (slice-local), the record is unguarded=true and carries NO
    closure_* keys. Pins the additive/default-off contract for the backward pass."""
    recs, _ = _run("backward_entrypoint_guard.sol")
    p = _move_path(recs, "_moveGuarded(uint256)")
    assert p["unguarded"] is True, f"slice-local should miss caller guard, got {p['unguarded']}"
    assert "closure_consulted" not in p, "default-off must NOT add closure keys"
    assert "backward_entrypoints_total" not in p
    assert "unguarded_closure_corrected" not in p


def test_backward_flips_when_all_entrypoints_guarded():
    """Backward keystone: an INTERNAL value-mover (_moveGuarded) whose ONLY
    reaching entrypoints (pull, pullAlt) are BOTH external onlyOwner is flipped to
    unguarded=false via the backward caller-closure pass (guarded-via-all-entrypoints).
    The forward pass alone leaves it unguarded (the guard is on the caller)."""
    recs, _ = _run("backward_entrypoint_guard.sol", extra_args=["--closure-unguarded"])
    p = _move_path(recs, "_moveGuarded(uint256)")
    assert p.get("closure_consulted") is True
    assert p["unguarded"] is False, \
        f"all-entrypoints-guarded internal mover must flip to guarded, got {p['unguarded']}"
    assert p.get("unguarded_closure_corrected") is True
    assert p.get("backward_entrypoints_total") == 2, f"expected 2 entrypoints, got {p.get('backward_entrypoints_total')}"
    assert p.get("backward_entrypoints_guarded") == 2, \
        f"expected 2 guarded entrypoints, got {p.get('backward_entrypoints_guarded')}"
    assert "guarded-via-all-entrypoints" in (p.get("closure_note") or "")


def test_backward_never_overflips_with_one_unguarded_entrypoint():
    """Never-over-flip negative: a sibling internal mover (_moveMixed) reached by
    one onlyOwner entrypoint (pullMixed) AND one permissionless entrypoint
    (pullOpen) is genuinely reachable unguarded. The backward pass MUST keep it
    unguarded=true (>=1 unguarded entrypoint blocks the flip)."""
    recs, _ = _run("backward_entrypoint_guard.sol", extra_args=["--closure-unguarded"])
    p = _move_path(recs, "_moveMixed(uint256)")
    assert p.get("closure_consulted") is True
    assert p["unguarded"] is True, \
        f"mover with an unguarded entrypoint must STAY unguarded, got {p['unguarded']}"
    assert p.get("unguarded_closure_corrected") is not True, "must NOT over-flip"
    assert p.get("backward_entrypoints_total") == 2
    assert p.get("backward_entrypoints_guarded") == 1, \
        f"expected 1 guarded entrypoint, got {p.get('backward_entrypoints_guarded')}"
    assert "backward-kept-unguarded" in (p.get("closure_note") or "")


def test_backward_nonvacuity_remove_entrypoint_guard_flips_back():
    """Mutation-pair witness for the backward pass: take the all-guarded fixture
    and REMOVE the onlyOwner modifier from ONE entrypoint (pullAlt). The same
    backward pass now sees one unguarded entrypoint and KEEPS _moveGuarded
    unguarded=true (no flip). The entrypoint guard - and only it - drives the
    flip, so the backward correction is non-vacuous (not an assert(true))."""
    base = (FIX / "backward_entrypoint_guard.sol").read_text()
    mutant = base.replace(
        "function pullAlt(uint256 amount) external onlyOwner {",
        "function pullAlt(uint256 amount) external {")
    assert mutant != base, "mutation did not change the source"
    recs, _ = _run_source(mutant, extra_args=["--closure-unguarded"], suffix="backward_nomod")
    p = _move_path(recs, "_moveGuarded(uint256)")
    assert p.get("closure_consulted") is True
    assert p["unguarded"] is True, \
        f"with one entrypoint guard removed _moveGuarded must stay unguarded, got {p['unguarded']}"
    assert p.get("unguarded_closure_corrected") is not True, \
        "with an unguarded entrypoint the backward pass must NOT flip (non-vacuity)"
    assert p.get("backward_entrypoints_guarded") == 1


def test_backward_skips_public_source_and_degrade_is_honest():
    """The backward pass runs ONLY for internal/private source fns, and degrades
    honestly. Verified via the engine API directly:
      - a public-source record is NOT touched by the backward pass.
      - an unresolvable record degrades (unguarded untouched, R80)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_df_mod_bw", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fake = mod.dfs.new_path(
        path_id="x", language="solidity", direction="backward",
        engine="t", source={"kind": "param-entrypoint", "fn": "Nope.ghost()", "var": "a", "file": None, "line": None},
        sink={"kind": "transfer", "callee": "transfer", "arg_pos": 0, "fn": "Nope.ghost()", "file": None, "line": None},
        hops=[], confidence="semantic-ssa",
    )

    class _Empty:
        compilation_units = []
    eng = mod.DataFlowEngine.__new__(mod.DataFlowEngine)
    eng.sl = _Empty()
    stats = eng.apply_closure_unguarded([fake])
    # unresolvable -> degraded, unguarded untouched, backward NOT consulted
    assert fake.get("closure_degraded") is True
    assert fake["unguarded"] is True
    assert "backward_entrypoints_total" not in fake, "degraded record must not run backward pass"
    assert stats.get("backward_consulted", 0) == 0


def test_econ_value_heuristic_unit():
    """Unit test the economic-value heuristic directly (selective: value nouns yes,
    address/timestamp/config no)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_df_mod_h", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    f = mod._is_economic_value_var
    # economic value vars
    assert f("operatorEthVUnits", "mapping(uint64 => uint256)") is True
    assert f("balances", "mapping(address => uint256)") is True
    assert f("daoTotalEthVUnits", "uint256") is True
    assert f("debt", "uint256") is True
    # NOT economic
    assert f("lastSeen", "mapping(uint64 => uint256)") is False  # timestamp deny
    assert f("feeRecipient", "address") is False                 # address veto + deny
    assert f("operatorCount", "uint256") is False                # count deny
    assert f("paused", "bool") is False
    # name match but address-typed value-leg -> type veto
    assert f("rewardRecipient", "mapping(uint64 => address)") is False


if __name__ == "__main__":
    test_vulnerable_unguarded_multihop()
    print("PASS test_vulnerable_unguarded_multihop")
    test_clean_guarded_multihop()
    print("PASS test_clean_guarded_multihop")
    test_nonvacuity_guard_flips_unguarded()
    print("PASS test_nonvacuity_guard_flips_unguarded")
    test_multicaller_fanout_recovers_all_chains()
    print("PASS test_multicaller_fanout_recovers_all_chains")
    test_nonvacuity_fanout_vs_single_chain()
    print("PASS test_nonvacuity_fanout_vs_single_chain")
    test_storage_mediated_unguarded()
    print("PASS test_storage_mediated_unguarded")
    test_storage_mediated_guarded()
    print("PASS test_storage_mediated_guarded")
    test_nonvacuity_storage_guard_flips_unguarded()
    print("PASS test_nonvacuity_storage_guard_flips_unguarded")
    # KEYSTONE Part 1: D-connect
    test_closure_default_off_byte_identical()
    print("PASS test_closure_default_off_byte_identical")
    test_closure_flips_unguarded_via_upgraph_modifier()
    print("PASS test_closure_flips_unguarded_via_upgraph_modifier")
    test_closure_nonvacuity_remove_upgraph_guard_flips_back()
    print("PASS test_closure_nonvacuity_remove_upgraph_guard_flips_back")
    test_closure_degrade_is_honest()
    print("PASS test_closure_degrade_is_honest")
    # KEYSTONE Part 2: economic storage-value sink
    test_storage_value_default_off_byte_identical()
    print("PASS test_storage_value_default_off_byte_identical")
    test_storage_value_econ_write_surfaced()
    print("PASS test_storage_value_econ_write_surfaced")
    test_storage_value_nonvacuity_rename_var_kills_sink()
    print("PASS test_storage_value_nonvacuity_rename_var_kills_sink")
    test_storage_value_closure_corrects_role_gated_write()
    print("PASS test_storage_value_closure_corrects_role_gated_write")
    test_econ_value_heuristic_unit()
    print("PASS test_econ_value_heuristic_unit")
    # KEYSTONE Part 3: backward-entrypoint closure
    test_backward_default_off_byte_identical()
    print("PASS test_backward_default_off_byte_identical")
    test_backward_flips_when_all_entrypoints_guarded()
    print("PASS test_backward_flips_when_all_entrypoints_guarded")
    test_backward_never_overflips_with_one_unguarded_entrypoint()
    print("PASS test_backward_never_overflips_with_one_unguarded_entrypoint")
    test_backward_nonvacuity_remove_entrypoint_guard_flips_back()
    print("PASS test_backward_nonvacuity_remove_entrypoint_guard_flips_back")
    test_backward_skips_public_source_and_degrade_is_honest()
    print("PASS test_backward_skips_public_source_and_degrade_is_honest")
    print("ALL PASS (22/22)")
