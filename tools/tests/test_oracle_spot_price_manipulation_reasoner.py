"""Regression tests for tools/oracle-spot-price-manipulation-reasoner.py.

Proves the Mango/Cheese/Inverse spot-price set-difference reasoning query over
the owned dataflow backend (SPOT_TO_VALUE \\ TWAP_XSOURCE):
  1. a value-decision entrypoint priced by a SPOT read whose closure reaches NO
     TWAP/second-source is a SURVIVOR and IS emitted as an obligation;
  2. NON-VACUITY MUTATION: the SAME entrypoint, with a TWAP/second-source node
     ADDED anywhere in its closure, is KEPT (removed from the diff) - proving the
     TWAP node is load-bearing (the query is a closure set-difference, not a
     `getReserves`-present regex; if it were a shape the mutation would not flip
     the verdict);
  3. the TWAP cross-check is a CLOSURE property: a TWAP read reached only through
     an N-hop HELPER record (not the priced fn's own record) still removes the fn
     - impossible for a same-body regex;
  4. a HAIRCUT (collateral-factor / LTV / discount) does NOT satisfy TWAP_XSOURCE
     - the fn stays a survivor (the Mango distinction: weights applied, still
     drained), separating this reasoner from the conservation-haircut one;
  5. a non-value-decision sink (a plain admin state-write / config setter) never
     enters SPOT_TO_VALUE even when spot-priced;
  6. a cumulative-price read is a TWAP building block, NOT a spot source (it does
     not enter SPOT_TO_VALUE on its own);
  7. vendored / out-of-workspace files never carry an obligation;
  8. a fully DEGRADED substrate yields an empty diff + a warning and
     --fail-closed exits 3.
"""
import importlib.util
import json
from pathlib import Path

_MOD_PATH = (Path(__file__).resolve().parents[1]
             / "oracle-spot-price-manipulation-reasoner.py")
_spec = importlib.util.spec_from_file_location("oracle_spot_reasoner", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# --------------------------------------------------------------------------
# synthetic dataflow_paths.jsonl builder
# --------------------------------------------------------------------------
def _rec(entry_fn, entry_file, sink_kind, *, sink_callee="Pay",
         hops=None, guard_exprs=(), source_var="price", line=10,
         lang="solidity", sink_fn=None, degraded=False):
    """A backward dataflow_path.v1 record: entrypoint `entry_fn` reaches sink
    `sink_kind`, carrying `hops` and closure `guard_exprs`."""
    return {
        "schema": "dataflow_path.v1",
        "language": lang,
        "direction": "backward",
        "degraded": degraded,
        "source": {"kind": "param-entrypoint", "fn": entry_fn,
                   "file": entry_file, "line": line, "var": source_var},
        "sink": {"kind": sink_kind, "callee": sink_callee,
                 "fn": sink_fn or entry_fn, "file": entry_file, "line": line + 5},
        "hops": list(hops or []),
        "guard_nodes": [{"file": entry_file, "line": line + 1, "expr": e}
                        for e in guard_exprs],
    }


def _mk_ws(tmp_path, records):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "src").mkdir(parents=True)
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    with df.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return ws


def _run(ws):
    return mod.run(["--workspace", str(ws), "--json"])


def _emitted_fns(ws):
    p = ws / ".auditooor" / "oracle_spot_price_obligations.jsonl"
    out = []
    if p.is_file():
        for line in p.read_text().splitlines():
            if line.strip():
                out.append(json.loads(line)["function"])
    return out


# --------------------------------------------------------------------------
# 1 + 2: the non-vacuity mutation. Same fn, only difference is a TWAP node in
# the closure. Survivor -> KEPT when the TWAP node is present.
# --------------------------------------------------------------------------
_SPOT_SRC = "reserve0 = pair.getReserves()"  # the manipulable single-block read


def test_survivor_when_spot_priced_and_no_twap(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Lend.sol")
    ws = _mk_ws(tmp_path, [
        _rec("Lend.borrow(uint256)", f, "value-move",
             hops=[{"fn": "Lend.priceOf(address)", "ir": _SPOT_SRC,
                    "via": "internal_call"}]),
    ])
    summary = _run(ws)
    assert summary["size_SPOT_TO_VALUE"] == 1
    assert summary["size_DIFF_survivors"] == 1
    assert "borrow" in _emitted_fns(ws)


def test_mutation_twap_node_removes_survivor(tmp_path):
    """NON-VACUITY: add a TWAP/second-source node to the SAME fn's closure - it
    must flip from SURVIVOR to KEPT. A body-scoped regex on `getReserves` would
    NOT flip; the set-difference does."""
    f = str(tmp_path / "ws" / "src" / "Lend.sol")
    ws = _mk_ws(tmp_path, [
        _rec("Lend.borrow(uint256)", f, "value-move",
             hops=[{"fn": "Lend.priceOf(address)", "ir": _SPOT_SRC,
                    "via": "internal_call"}],
             # the load-bearing mutation: a TWAP cross-check now reached in-closure
             guard_exprs=["require(spot <= twap * 101 / 100, 'deviation')"]),
    ])
    summary = _run(ws)
    assert summary["size_SPOT_TO_VALUE"] == 1
    assert summary["size_DIFF_survivors"] == 0, \
        "TWAP node in closure must remove the fn from SPOT\\TWAP"
    assert _emitted_fns(ws) == []


# --------------------------------------------------------------------------
# 3: TWAP reached only through an N-hop helper record still removes the fn.
# --------------------------------------------------------------------------
def test_twap_in_helper_hop_is_closure_property(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Lend.sol")
    ws = _mk_ws(tmp_path, [
        # priced fn's own record: spot source + value sink, NO twap here
        _rec("Lend.borrow(uint256)", f, "value-move",
             hops=[{"fn": "Lend.priceOf(address)", "ir": _SPOT_SRC,
                    "via": "internal_call"}]),
        # a SEPARATE helper record for the SAME entrypoint carrying the TWAP read
        _rec("Lend.borrow(uint256)", f, "value-move",
             hops=[{"fn": "OracleLib.consult(address,uint32)",
                    "ir": "price0CumulativeLast", "via": "internal_call"}]),
    ])
    summary = _run(ws)
    assert summary["size_DIFF_survivors"] == 0
    assert _emitted_fns(ws) == []


# --------------------------------------------------------------------------
# 4: a HAIRCUT does NOT satisfy TWAP_XSOURCE (the Mango distinction).
# --------------------------------------------------------------------------
def test_haircut_does_not_remove_survivor(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Lend.sol")
    ws = _mk_ws(tmp_path, [
        _rec("Lend.borrow(uint256)", f, "value-move",
             hops=[{"fn": "Lend.priceOf(address)", "ir": _SPOT_SRC,
                    "via": "internal_call"}],
             # a collateral-factor haircut - NOT a manipulation-resistant source
             guard_exprs=["value = price * collateralFactor / 1e18"]),
    ])
    summary = _run(ws)
    assert summary["size_DIFF_survivors"] == 1, \
        "a haircut must NOT count as a TWAP/second-source cross-check"
    assert "borrow" in _emitted_fns(ws)


# --------------------------------------------------------------------------
# 5: a non-value-decision sink never enters SPOT_TO_VALUE.
# --------------------------------------------------------------------------
def test_config_write_sink_not_in_spot_to_value(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Admin.sol")
    ws = _mk_ws(tmp_path, [
        _rec("Admin.setPriceParam(uint256)", f, "state-write",
             sink_callee="Config.setMaxSwapValue",
             hops=[{"fn": "Admin.priceOf(address)", "ir": _SPOT_SRC,
                    "via": "internal_call"}]),
    ])
    summary = _run(ws)
    assert summary["size_SPOT_TO_VALUE"] == 0
    assert summary["size_DIFF_survivors"] == 0


# --------------------------------------------------------------------------
# 6: a cumulative-price read is NOT a spot source.
# --------------------------------------------------------------------------
def test_cumulative_read_is_not_spot(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Lend.sol")
    ws = _mk_ws(tmp_path, [
        _rec("Lend.borrow(uint256)", f, "value-move",
             hops=[{"fn": "Lend.twapOf(address)",
                    "ir": "price0CumulativeLast",  # cumulative, not spot
                    "via": "internal_call"}]),
    ])
    summary = _run(ws)
    assert summary["size_SPOT_TO_VALUE"] == 0
    assert summary["size_DIFF_survivors"] == 0


# --------------------------------------------------------------------------
# 7: vendored / out-of-workspace files never carry an obligation.
# --------------------------------------------------------------------------
def test_out_of_scope_file_no_obligation(tmp_path):
    vendored = "/tmp/vendor/node_modules/pkg/Lend.sol"
    ws = _mk_ws(tmp_path, [
        _rec("Lend.borrow(uint256)", vendored, "value-move",
             hops=[{"fn": "Lend.priceOf(address)", "ir": _SPOT_SRC,
                    "via": "internal_call"}]),
    ])
    summary = _run(ws)
    assert summary["size_DIFF_survivors"] == 0
    assert _emitted_fns(ws) == []


# --------------------------------------------------------------------------
# 8: a fully degraded substrate -> empty diff + warning; --fail-closed exits 3.
# --------------------------------------------------------------------------
def test_degraded_substrate_warns_and_fail_closed(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Lend.sol")
    ws = _mk_ws(tmp_path, [
        _rec("Lend.borrow(uint256)", f, "value-move", degraded=True),
    ])
    summary = _run(ws)
    assert summary["size_DIFF_survivors"] == 0
    assert any("DEGRADED" in w for w in summary["warnings"])
    rc = mod.run(["--workspace", str(ws), "--fail-closed"])
    assert rc == 3
