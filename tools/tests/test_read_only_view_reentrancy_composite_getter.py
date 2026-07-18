"""Regression tests for
tools/read-only-view-reentrancy-unguarded-composite-getter.py.

Proves the read-only view-reentrancy set-difference reasoning query
COMPOSED_ACROSS_WINDOW \\ REENTRANCY_GUARDED, joined to a value-release consumer,
over the OWNED Slither-CFG-derived facts (getters / callback-window mutators) + the
dataflow_paths.jsonl consumer substrate. The reasoning core `compute_set_difference`
is exercised directly with SYNTHETIC facts so the set/join logic is proven without a
Solidity compile.

Cases (2 and 3 are the NON-VACUITY MUTATION pair):
  1. a composite view getter sharing a component with a callback-window mutator, with
     NO nonReentrant guard and a value-release consumer, IS a survivor (fires);
  2. MUTATION-KILL A: add the nonReentrant guard to the SAME getter -> it moves into
     REENTRANCY_GUARDED, the set-difference empties -> NOT emitted;
  3. MUTATION-KILL B: getter shares NO component with any callback-window mutator ->
     COMPOSED_ACROSS_WINDOW is empty -> NOT emitted (proves the shared-component
     cross-function JOIN, not a per-getter shape, is load-bearing);
  4. CONSUMER-JOIN GATE: an unguarded composed getter with NO value-release consumer
     (and a present dataflow substrate) is NOT emitted - the finding requires the
     downstream value-release consumer JOIN;
  5. join_unavailable fallback: with the dataflow substrate ABSENT, a name-ranked
     financial composite (get_virtual_price) is KEPT and flagged join_unavailable so a
     real lead is not silently dropped;
  6. the module-level analyze_workspace over a Go-only (no sol project) workspace is a
     clean language-not-applicable cited-empty, not a degraded substrate.
"""
import importlib.util
from pathlib import Path

_MOD_PATH = (Path(__file__).resolve().parents[1]
             / "read-only-view-reentrancy-unguarded-composite-getter.py")
_spec = importlib.util.spec_from_file_location("ror_composite", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _getter(reads, guarded=False, rank=0, arith=True, is_mock=False):
    return {"reads": set(reads), "arith": arith, "guarded": guarded,
            "file": "src/Vault.sol", "line": 42, "rank": rank, "is_mock": is_mock}


def _base_facts():
    # G composes two components; M rewrites both around an extcall (callback window).
    getters = {("Vault", "getPrice()"): _getter({"totalAssets", "totalShares"})}
    window_mut = {("Vault", "withdraw(uint256)"): {"writes": {"totalAssets", "totalShares"}}}
    # a value-release consumer reads one of G's components
    consumer_by_var = {"totalAssets": {"Lending.liquidate(address)"}}
    return getters, window_mut, consumer_by_var


# --------------------------------------------------------------------------
def test_1_unguarded_composed_with_consumer_fires():
    getters, window_mut, consumer_by_var = _base_facts()
    survivors, summary = mod.compute_set_difference(
        getters, window_mut, consumer_by_var, dataflow_present=True)
    assert summary["composed"] == 1
    assert summary["guarded"] == 0
    assert summary["survivors"] == 1
    row = survivors[0]
    assert row["contract"] == "Vault" and row["function"] == "getPrice()"
    assert set(row["composite_components_read"]) == {"totalAssets", "totalShares"}
    assert row["callback_window_mutators"] == ["Vault.withdraw(uint256)"]
    assert row["downstream_value_release_consumers"] == ["Lending.liquidate(address)"]
    assert row["consumer_join"] == "value-release-consumer-confirmed"


def test_2_mutation_add_nonreentrant_guard_empties_setdiff():
    # MUTATION-KILL A: same facts, getter now carries the reentrancy lock.
    getters, window_mut, consumer_by_var = _base_facts()
    getters[("Vault", "getPrice()")]["guarded"] = True
    survivors, summary = mod.compute_set_difference(
        getters, window_mut, consumer_by_var, dataflow_present=True)
    assert summary["composed"] == 1        # still composed...
    assert summary["guarded"] == 1         # ...but now in GUARDED
    assert summary["survivors"] == 0       # set-difference empty
    assert survivors == []


def test_3_mutation_no_shared_component_empties_composed():
    # MUTATION-KILL B: getter reads UNRELATED components -> no shared-component JOIN.
    getters = {("Vault", "getPrice()"): _getter({"feeNumerator", "feeDenominator"})}
    window_mut = {("Vault", "withdraw(uint256)"): {"writes": {"totalAssets", "totalShares"}}}
    consumer_by_var = {"totalAssets": {"Lending.liquidate(address)"}}
    survivors, summary = mod.compute_set_difference(
        getters, window_mut, consumer_by_var, dataflow_present=True)
    assert summary["composed"] == 0
    assert summary["survivors"] == 0


def test_4_consumer_join_gate_no_release_consumer_not_emitted():
    getters, window_mut, _ = _base_facts()
    # dataflow substrate PRESENT but NO value-release consumer reads any component.
    survivors, summary = mod.compute_set_difference(
        getters, window_mut, consumer_by_var={}, dataflow_present=True)
    assert summary["composed"] == 1
    assert summary["survivors"] == 0       # gated: no value-release consumer


def test_5_join_unavailable_keeps_name_ranked_financial_composite():
    getters = {("Curve", "get_virtual_price()"): _getter(
        {"D", "totalSupply"}, rank=1)}
    window_mut = {("Curve", "remove_liquidity(uint256)"): {"writes": {"D", "totalSupply"}}}
    # substrate ABSENT -> consumer join cannot run.
    survivors, summary = mod.compute_set_difference(
        getters, window_mut, consumer_by_var={}, dataflow_present=False)
    assert summary["survivors"] == 1
    assert survivors[0]["consumer_join"] == (
        "join_unavailable-kept-name-ranked-financial-composite")
    # a NON-name-ranked composite in the same substrate-absent case is still dropped
    getters2 = {("X", "f()"): _getter({"a", "b"}, rank=0)}
    wm2 = {("X", "g()"): {"writes": {"a", "b"}}}
    _s2, sm2 = mod.compute_set_difference(getters2, wm2, {}, dataflow_present=False)
    assert sm2["survivors"] == 0


def test_6_go_only_workspace_is_language_not_applicable(tmp_path):
    # No foundry.toml / hardhat.config.* and no sol dataflow rows -> clean not-applicable.
    ws = tmp_path
    (ws / ".auditooor").mkdir()
    (ws / "main.go").write_text("package main\nfunc main(){}\n")
    survivors, summary, warnings = mod.analyze_workspace(
        ws, ws / ".auditooor" / "dataflow_paths.jsonl")
    assert survivors == []
    assert summary["language_applicable"] is False
    assert "EVM-only" in summary["reason"]
