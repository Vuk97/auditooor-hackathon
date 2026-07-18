"""Regression tests for tools/atomic-sequence-economic-sequencer.py (LOGIC #4).

Proves the multi-tx/same-block economic-sequence PATH query over the owned
state-edge graph (state_coupling_edges + value_moving_functions shared-ledger
fields):
  1. a VALUE-conservation coupled cell carrying BOTH a source-role AND a
     spend-role value-mover fires an ordered (source -> cell -> spend) sequence;
  2. a cell with only a source (or only a spend) does NOT fire - the finding is a
     JOIN over two role-partitioned members, not a per-fn match;
  3. a FRESHNESS / config coupling (non-value cell) never enters the cell universe
     - the axelar cited-empty class;
  4. an atomicity guard (snapshot/commit/reentrancy) on the s..y path KILLS the
     sequence (reachability negative);
  5. a shared-ledger-field written by two value-movers is itself a produces->
     requires edge and can fire;
  6. an attacker-movable oracle read on the spend upgrades the template to
     borrow->pump->withdraw;
  7. absent both backends yields 0 sequences + a cited empty_reason, and
     --fail-closed exits 3.
"""
import importlib.util
import json
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "atomic-sequence-economic-sequencer.py"
_spec = importlib.util.spec_from_file_location("atomic_seq", _MOD)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _vmf_fn(fn, *, transfer_hit, transfer_ev=None, ledger=None, file="src/V.sol",
            line=10, lang="sol"):
    return {"function": fn, "file": file, "line": line, "language": lang,
            "transfer_hit": transfer_hit,
            "transfer_evidence": transfer_ev or [],
            "ledger_write_evidence": ledger or []}


def _edge(cell_a, cell_b, writers_a, writers_b, impact_class,
          guarded_readers=None, kind="cross-domain-conservation"):
    return {"schema": "state_coupling_edge.v1", "edge_id": cell_a + cell_b,
            "cell_a": cell_a, "cell_b": cell_b,
            "writers_a": writers_a, "writers_b": writers_b,
            "impact_class": impact_class, "kind": kind,
            "violators": [],
            "evidence": {"guarded_readers": guarded_readers or []}}


def _mk_ws(tmp_path, edges, vmf_fns, oracle=None):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    with (ws / ".auditooor" / "state_coupling_edges.jsonl").open("w") as fh:
        for e in edges:
            fh.write(json.dumps(e) + "\n")
    (ws / ".auditooor" / "value_moving_functions.json").write_text(
        json.dumps({"functions": vmf_fns}))
    if oracle is not None:
        with (ws / ".auditooor" / "oracle_reachability_hypotheses.jsonl").open("w") as fh:
            for o in oracle:
                fh.write(json.dumps(o) + "\n")
    return ws


# INBOUND / OUTBOUND transfer-evidence exemplars (real nuva/axelar shapes).
_IN = ["token.safeTransferFrom(msg.sender, address("]
_OUT = ["asset.safeTransfer(user, _amount);"]


def _run(ws):
    return mod.run(["--workspace", str(ws), "--json"])


def test_source_and_spend_on_value_cell_fires(tmp_path, capsys):
    ws = _mk_ws(
        tmp_path,
        [_edge("Shares", "external:share-marker", ["depositIn"], ["redeemOut"],
               "value-conservation-break")],
        [_vmf_fn("depositIn", transfer_hit=True, transfer_ev=_IN),
         _vmf_fn("redeemOut", transfer_hit=True, transfer_ev=_OUT)])
    out = _run(ws)
    assert out["n_sequences"] == 1
    ob = [json.loads(l) for l in
          (ws / ".auditooor" / "atomic_sequence_obligations.jsonl").read_text().splitlines()]
    assert ob[0]["source_function"] == "depositIn"
    assert ob[0]["spend_function"] == "redeemOut"
    # the finding is an ordered 3-step path, not a scalar
    steps = [s["role"] for s in ob[0]["sequence"]]
    assert steps == ["borrowed-source", "state-mutation", "spend"]


def test_only_source_does_not_fire(tmp_path):
    ws = _mk_ws(
        tmp_path,
        [_edge("Shares", "ext", ["depositIn"], ["alsoDepositIn"],
               "value-conservation-break")],
        [_vmf_fn("depositIn", transfer_hit=True, transfer_ev=_IN),
         _vmf_fn("alsoDepositIn", transfer_hit=True, transfer_ev=_IN)])
    out = _run(ws)
    assert out["n_sequences"] == 0
    assert "spend" in out["empty_reason"]


def test_freshness_cell_excluded(tmp_path):
    ws = _mk_ws(
        tmp_path,
        [_edge("usedSig", "external-clock", ["writeA"], ["writeB"],
               "stale-state-freshness-desync",
               kind="freshness-coupled-to-external-clock")],
        [_vmf_fn("writeA", transfer_hit=True, transfer_ev=_IN),
         _vmf_fn("writeB", transfer_hit=True, transfer_ev=_OUT)])
    out = _run(ws)
    # a freshness coupling is NOT a value cell -> never in the universe
    assert out["n_value_cells"] == 0
    assert out["n_sequences"] == 0
    assert "value" in out["empty_reason"].lower()


def test_atomicity_guard_kills_sequence(tmp_path):
    ws = _mk_ws(
        tmp_path,
        [_edge("Shares", "ext", ["depositIn"], ["redeemOut"],
               "value-conservation-break")],
        # the spend carries a snapshot ledger cell -> atomic composition broken
        [_vmf_fn("depositIn", transfer_hit=True, transfer_ev=_IN),
         _vmf_fn("redeemOut", transfer_hit=True, transfer_ev=_OUT,
                 ledger=["balanceSnapshot"])])
    out = _run(ws)
    assert out["n_sequences"] == 0
    assert "guard" in out["empty_reason"].lower()


def test_shared_ledger_field_edge_fires(tmp_path):
    # no state_coupling edge; the edge is the shared ledger field 'Pool'
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / ".auditooor" / "state_coupling_edges.jsonl").write_text("")
    (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps({
        "functions": [
            _vmf_fn("creditPool", transfer_hit=True, transfer_ev=_IN, ledger=["Pool"]),
            _vmf_fn("drainPool", transfer_hit=True, transfer_ev=_OUT, ledger=["Pool"]),
        ]}))
    out = _run(ws)
    assert out["n_sequences"] == 1
    assert out["cell_reports"][0]["origin"] == "shared-ledger-field"


def test_oracle_pump_upgrades_template(tmp_path):
    ws = _mk_ws(
        tmp_path,
        [_edge("Coll", "ext", ["borrowIn"], ["withdrawOut"],
               "value-conservation-break")],
        [_vmf_fn("borrowIn", transfer_hit=True, transfer_ev=_IN),
         _vmf_fn("withdrawOut", transfer_hit=True, transfer_ev=_OUT)],
        oracle=[{"consuming_fn": "withdrawOut"}])
    out = _run(ws)
    ob = json.loads((ws / ".auditooor" / "atomic_sequence_obligations.jsonl")
                    .read_text().splitlines()[0])
    assert ob["oracle_pump"] is True
    assert ob["attack_class"] == "flashloan-oracle-pump-withdraw"
    assert ob["sequence_family"] == "borrow->pump->withdraw"


def test_absent_backends_fail_closed(tmp_path):
    ws = tmp_path / "empty"
    (ws / ".auditooor").mkdir(parents=True)
    out = mod.run(["--workspace", str(ws), "--json"])
    assert out["n_sequences"] == 0
    assert "no owned state-edge backend" in out["empty_reason"]
    rc = mod.run(["--workspace", str(ws), "--fail-closed"])
    assert rc == 3
