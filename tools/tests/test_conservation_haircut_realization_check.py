"""Regression tests for tools/conservation-haircut-realization-check.py (LOGIC #5).

Proves the value-realization-without-haircut set-difference reasoning query over
the owned dataflow backend + conservation-invariant-family JOIN:
  1. a value-release entrypoint whose closure REACHES a haircut / second-source
     cross-check is KEPT (removed from VALUE_RELEASE\\HAIRCUT_XCHECK) - NOT emitted;
  2. a value-release entrypoint whose closure reaches NO haircut/xcheck is a
     SURVIVOR and IS emitted as a conservation-haircut-realization obligation;
  3. the HAIRCUT_XCHECK is a CLOSURE property: a haircut reached only through an
     N-hop HELPER record (not the fn's own record) still removes the fn -
     impossible for a same-body regex;
  4. the haircut/xcheck node predicate distinguishes a haircut / deviation /
     balance-snapshot conservation from an access-control / nil-error / bound guard;
  5. a fund-IN pull (safeTransferFrom) / mint never populates VALUE_RELEASE, and a
     ctx/address-only flow with no value var and no release name is excluded;
  6. the quote/valuation arm fires on a name-gated valuation fn over a value even
     with no funds-out sink;
  7. a fully DEGRADED substrate yields an empty diff + a warning, --fail-closed=3;
  8. survivors JOIN to a conservation invariant-family ledger row citing the fn;
  9. vendored / out-of-workspace files never carry an obligation.
"""
import importlib.util
import json
from pathlib import Path

_MOD_PATH = (Path(__file__).resolve().parents[1]
             / "conservation-haircut-realization-check.py")
_spec = importlib.util.spec_from_file_location("cons_haircut", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# --------------------------------------------------------------------------
def _rec(lang, entry_fn, entry_file, sink_kind, guard_exprs, *,
         sink_callee="X", line=10, sink_fn=None, var="amount"):
    return {
        "schema": "dataflow_path.v1",
        "language": lang,
        "direction": "backward",
        "degraded": False,
        "source": {"kind": "param-entrypoint", "fn": entry_fn,
                   "file": entry_file, "line": line, "var": var},
        "sink": {"kind": sink_kind, "callee": sink_callee,
                 "fn": sink_fn or entry_fn, "file": entry_file, "line": line + 5},
        "hops": [],
        "guard_nodes": [{"file": entry_file, "line": line + 1, "expr": e}
                        for e in guard_exprs],
    }


def _mk_ws(tmp_path, records, ledger=None):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "src").mkdir(parents=True)
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    with df.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    if ledger is not None:
        (ws / ".auditooor" / "invariant_ledger.json").write_text(
            json.dumps({"rows": ledger}), encoding="utf-8")
    return ws


def _run(ws, **kw):
    argv = ["--workspace", str(ws), "--json"]
    for k, v in kw.items():
        flag = "--" + k.replace("_", "-")
        if v is True:
            argv.append(flag)
        elif v is not None:
            argv.extend([flag, str(v)])
    return mod.run(argv)


def _load_obligations(ws):
    p = ws / ".auditooor" / "conservation_haircut_obligations.jsonl"
    if not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


# --------------------------------------------------------------------------
# 1 + 2: KEPT (haircut) vs SURVIVOR (raw), the core set-difference
# --------------------------------------------------------------------------
def test_haircut_kept_raw_emitted(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Lend.sol")
    recs = [
        # SAFE: borrow release whose closure applies an LTV haircut.
        _rec("solidity", "Lend.borrow(uint256)", f, "value-move",
             ["borrowAmount <= collateralValue * ltv / 1e18"], var="amount"),
        # BUG: withdraw release consuming a raw price/amount, only a bound guard.
        _rec("solidity", "Lend.withdraw(uint256)", f, "value-move",
             ["msg.sender == owner", "amount > 0"], var="amount"),
    ]
    ws = _mk_ws(tmp_path, recs)
    out = _run(ws)
    assert out["size_VALUE_RELEASE"] == 2
    assert "borrow" in out["kept_release_and_haircut"]
    surv = {s["fn"] for s in out["survivors"]}
    assert surv == {"withdraw"}, surv
    obls = _load_obligations(ws)
    assert len(obls) == 1
    assert obls[0]["function"] == "withdraw"
    assert obls[0]["obligation_type"] == "conservation-haircut-realization"


# --------------------------------------------------------------------------
# 3: HAIRCUT_XCHECK is a CLOSURE property - reached via a helper record
# --------------------------------------------------------------------------
def test_haircut_reached_through_helper_closure(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Vault.sol")
    recs = [
        _rec("solidity", "Vault.redeem(uint256)", f, "safeTransfer", [],
             var="shares"),
        _rec("solidity", "Vault.redeem(uint256)", f, "state-write",
             ["priceDeviation < maxDeviation"], line=40, var="shares"),
    ]
    ws = _mk_ws(tmp_path, recs)
    out = _run(ws)
    assert out["size_VALUE_RELEASE"] == 1
    assert out["survivors"] == []
    assert "redeem" in out["kept_release_and_haircut"]
    assert _load_obligations(ws) == []


# --------------------------------------------------------------------------
# 4: the haircut/xcheck predicate semantics
# --------------------------------------------------------------------------
def test_haircut_xcheck_pred_semantics():
    p = mod.haircut_xcheck_pred
    # haircut scale-downs
    assert p("amount * collateralFactor / 1e18")
    assert p("value <= collateral * ltv")
    assert p("payout = notional * liquidationDiscount / 10000")
    # second-source cross-checks
    assert p("abs(spot - twap) < deviation")
    assert p("price = min(oracleA, oracleB)")
    assert p("require(block.timestamp - updatedAt < staleness)")
    # balance-snapshot conservation
    assert p("balBefore - balAfter == amount")
    # NOT a realization: access-control / nil / plain bound / empty
    assert not p("msg.sender == owner")
    assert not p("amount > 0")
    assert not p("t19 != nil:error")
    assert not p("i < destinationAddresses.length")
    assert not p("")


# --------------------------------------------------------------------------
# 5: fund-IN pull / mint never populate VALUE_RELEASE; ctx-only flow excluded
# --------------------------------------------------------------------------
def test_fund_in_and_ctxonly_excluded(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Vault.sol")
    recs = [
        # deposit PULL - value moves IN, not a release
        _rec("solidity", "Vault.deposit(uint256)", f, "safeTransferFrom", [],
             var="amount"),
        # mint - increase, not a release
        _rec("solidity", "Vault.issue(uint256)", f, "mint", [], var="amount"),
        # a value-move but the flow is a ctx/recipient plumbing var and the fn
        # name is NOT a release path -> not a value-realization
        _rec("go", "(*keeper.Keeper).Route", f, "value-move", [],
             var="ctx", sink_callee="Send"),
    ]
    ws = _mk_ws(tmp_path, recs)
    out = _run(ws)
    assert out["size_VALUE_RELEASE"] == 0
    assert _load_obligations(ws) == []


# --------------------------------------------------------------------------
# 6: the quote / valuation arm (name-gated over a value, no funds-out sink)
# --------------------------------------------------------------------------
def test_quote_valuation_arm(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Oracle.sol")
    recs = [
        # a valuation fn over a price, reaching only a state read, raw -> survivor
        _rec("solidity", "Oracle.getPrice(address)", f, "state_var_read", [],
             var="price"),
    ]
    ws = _mk_ws(tmp_path, recs)
    out = _run(ws)
    surv = {s["fn"] for s in out["survivors"]}
    assert surv == {"getPrice"}, surv
    assert out["survivors"][0]["arm"] == "quote/valuation"


# --------------------------------------------------------------------------
# 7: degraded substrate -> empty diff + warning; --fail-closed exits 3
# --------------------------------------------------------------------------
def test_degraded_substrate_warns_and_fail_closed(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    df.write_text(json.dumps({
        "schema": "dataflow_path.v1", "language": "go", "degraded": True,
        "source": {"kind": "none"}, "sink": {"kind": "none"}, "guard_nodes": [],
    }) + "\n", encoding="utf-8")
    out = _run(ws)
    assert out["size_VALUE_RELEASE"] == 0
    assert out["substrate_degraded"] is True
    assert any("DEGRADED" in w for w in out["warnings"])
    rc = mod.run(["--workspace", str(ws), "--json", "--fail-closed"])
    assert rc == 3


# --------------------------------------------------------------------------
# 8: survivor JOINS to a conservation invariant-family ledger row
# --------------------------------------------------------------------------
def test_conservation_invariant_join(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Lend.sol")
    recs = [
        _rec("solidity", "Lend.withdraw(uint256)", f, "value-move",
             ["amount > 0"], var="amount"),
    ]
    ledger = [{
        "id": "INV-CONS-042",
        "invariant_family": "accounting_conservation",
        "statement": "withdraw must conserve: value_out <= collateral held",
        "source_citations": ["Lend.sol:withdraw"],
    }]
    ws = _mk_ws(tmp_path, recs, ledger=ledger)
    out = _run(ws)
    assert out["n_survivors_joined_to_invariant"] == 1
    obls = _load_obligations(ws)
    assert obls[0]["broken_invariant_ids"] == ["INV-CONS-042"]
    assert "INV-CONS-042" in obls[0]["joined_conservation_invariants"]


# --------------------------------------------------------------------------
# 9: vendored / out-of-workspace files never carry an obligation
# --------------------------------------------------------------------------
def test_vendored_out_of_ws_excluded(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "src").mkdir(parents=True)
    infile = str(ws / "src" / "Real.sol")
    vendored = "/Users/somebody/go/pkg/mod/cosmossdk.io/bank/keeper/send.go"
    outside = str(tmp_path / "elsewhere" / "Other.sol")
    recs = [
        _rec("solidity", "Real.withdraw(uint256)", infile, "value-move", [],
             var="amount"),
        _rec("go", "(*keeper.BaseKeeper).SendCoins", vendored, "value-move", [],
             var="amt"),
        _rec("solidity", "Other.withdraw(uint256)", outside, "value-move", [],
             var="amount"),
    ]
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    with df.open("w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    out = _run(ws)
    survs = {s["fn"] for s in out["survivors"]}
    assert survs == {"withdraw"}, survs
    files = {s["file"] for s in out["survivors"]}
    assert files == {infile}, files
