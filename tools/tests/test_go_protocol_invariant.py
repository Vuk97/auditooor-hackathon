"""Regression tests for tools/go-protocol-invariant.py.

Proves the IBC / cross-chain protocol STATE-MACHINE invariant SET-DIFFERENCE query
(REQUIRED_PROTOCOL_INVARIANTS \\ ENFORCED_ON_PATH per handler) over the owned
dataflow backend, NOT a body regex for 'sequence'/'nonce':

  1. a protocol handler whose closure enforces ALL THREE families (monotonic
     sequence + source binding + once-only consume) is KEPT - NOT emitted;
  2. a protocol handler missing >=1 family is a SURVIVOR and IS emitted with the
     exact missing families;
  3. axis (a) - a family is a CLOSURE property: a once-only receipt check reached
     only through an N-hop helper IR (not the handler body) still credits the family;
  4. axis (c) - a family UNIONs across MULTIPLE path records for the same
     entrypoint: the sequence check in a SIBLING path still credits it;
  5. NON-VACUITY MUTATION: add the missing monotonic-sequence + once-only-consume
     enforcement to a survivor and it FLIPS to KEPT - proving the family predicates
     are load-bearing, not a tautology;
  6. a non-inbound entrypoint never populates the protocol-handler set even when it
     writes state;
  7. substrate_vacuous (no protocol handler reached) is N/A not a clean 0;
  8. a fully absent substrate warns and --fail-closed exits 3.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parents[1] / "go-protocol-invariant.py"
_spec = importlib.util.spec_from_file_location("go_protocol_invariant", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _rec(entry_fn, sink_kind, *, sink_callee="Proc", hops_ir=None,
         guard_exprs=None, lang="go", file="/ws/x/handler.go", line=10):
    return {
        "schema": "dataflow_path.v1",
        "language": lang,
        "direction": "backward",
        "degraded": False,
        "source": {"kind": "param", "fn": entry_fn, "var": "packet",
                   "file": file, "line": line},
        "sink": {"kind": sink_kind, "callee": sink_callee, "arg_pos": 0,
                 "fn": entry_fn, "file": file, "line": line + 5},
        "hops": [{"fn": "", "ir": ir} for ir in (hops_ir or [])],
        "guard_nodes": [{"expr": e} for e in (guard_exprs or [])],
        "unguarded": True,
    }


def _write(tmp, records):
    ad = tmp / ".auditooor"
    ad.mkdir(parents=True, exist_ok=True)
    p = ad / "dataflow_paths.jsonl"
    with p.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return p


FULL_HANDLER = "(github.com/x/ibc/transfer.Keeper).OnRecvPacket"
PARTIAL_HANDLER = "(github.com/x/axelarnet.Keeper).RouteMessage"
LOCAL_MSG = "(github.com/x/token.Keeper)._Msg_Mint_Handler"


def _run(tmp, **kw):
    argv = ["--workspace", str(tmp)]
    for k, v in kw.items():
        argv += ["--" + k.replace("_", "-")] + ([] if v is True else [str(v)])
    return mod.run(argv)


def _base_records():
    return [
        # KEPT: enforces all three families (seq via N-hop helper IR, source binding
        # via guard, once-only via sink-adjacent hop) - axis (a).
        _rec(FULL_HANDLER, "value-move", sink_callee="SendCoins",
             hops_ir=["t1 = GetNextSequenceRecv(ctx, port, chan)",
                      "t2 = SetPacketReceipt(ctx, port, chan, seq)"],
             guard_exprs=["GetChannel(port, chan)"]),
        # SURVIVOR: mints but enforces NOTHING (missing all three).
        _rec(PARTIAL_HANDLER, "mint", sink_callee="MintCoins",
             hops_ir=["t1 = GetBalance(addr)"]),
        # non-inbound local Msg handler - must NOT be in the protocol-handler set.
        _rec(LOCAL_MSG, "state-write", sink_callee="SetBalance"),
    ]


def test_kept_survivor_and_local_partition(tmp_path):
    _write(tmp_path, _base_records())
    s = _run(tmp_path, json=True)
    c = s["counts"]
    assert c["protocol_handlers"] == 2, c        # two inbound handlers, not LOCAL_MSG
    assert c["KEPT"] == 1, c
    assert c["survivors"] == 1, c
    assert c["required_invariants"] == 6, c       # 2 handlers * 3 families
    assert s["substrate_status"] == "survivors_present"
    surv = {x["fn"]: x for x in s["survivors"]}
    kept = {x["fn"] for x in s["kept"]}
    assert PARTIAL_HANDLER in surv
    assert FULL_HANDLER in kept
    assert LOCAL_MSG not in surv and LOCAL_MSG not in kept
    assert set(surv[PARTIAL_HANDLER]["missing"]) == {
        "MONOTONIC_SEQUENCE", "SOURCE_BINDING", "ONCE_ONLY_CONSUME"}
    rows = [json.loads(l) for l in
            (tmp_path / ".auditooor" / "go_protocol_invariant_obligations.jsonl")
            .read_text().splitlines() if l.strip()]
    assert len(rows) == 1
    ob = rows[0]
    assert ob["schema"] == "auditooor.go_protocol_invariant.v1"
    assert ob["function"] == "RouteMessage"
    assert ob["likely_severity"] == "critical"
    assert sorted(ob["missing_invariants"]) == [
        "MONOTONIC_SEQUENCE", "ONCE_ONLY_CONSUME", "SOURCE_BINDING"]
    assert ob["source_refs"] and "handler.go" in ob["source_refs"][0]


def test_partial_enforcement_reports_only_missing(tmp_path):
    # handler enforces source-binding only -> survivor missing the other two.
    _write(tmp_path, [
        _rec(PARTIAL_HANDLER, "mint", sink_callee="MintCoins",
             guard_exprs=["GetChannel(port, chan)"]),
    ])
    s = _run(tmp_path, json=True)
    assert s["counts"]["survivors"] == 1
    miss = set(s["survivors"][0]["missing"])
    assert miss == {"MONOTONIC_SEQUENCE", "ONCE_ONLY_CONSUME"}
    assert s["survivors"][0]["enforced"] == ["SOURCE_BINDING"]


def test_sibling_path_union_credits_family(tmp_path):
    # axis (c): the sequence check lives in a SIBLING path (a different sink record)
    # for the SAME entrypoint; it must still credit MONOTONIC_SEQUENCE.
    _write(tmp_path, [
        _rec(PARTIAL_HANDLER, "mint", sink_callee="MintCoins",
             hops_ir=["t2 = SetPacketReceipt(ctx, seq)"],
             guard_exprs=["GetChannel(port, chan)"]),
        _rec(PARTIAL_HANDLER, "state-write", sink_callee="SetSeq",
             hops_ir=["t9 = GetNextSequenceRecv(ctx, port, chan)"]),
    ])
    s = _run(tmp_path, json=True)
    # all three now enforced via union across the two sibling paths -> KEPT.
    assert s["counts"]["KEPT"] == 1, s["counts"]
    assert s["counts"]["survivors"] == 0


def test_non_vacuity_mutation_flip(tmp_path):
    """Add the missing monotonic-sequence + once-only-consume enforcement to a
    survivor's closure -> the survivor DISAPPEARS (flips to KEPT). Proves the family
    predicates are load-bearing, not a tautology."""
    before = [
        _rec(PARTIAL_HANDLER, "mint", sink_callee="MintCoins",
             guard_exprs=["GetChannel(port, chan)"]),   # only source-binding
    ]
    _write(tmp_path, before)
    s0 = _run(tmp_path, json=True)
    assert s0["counts"]["survivors"] == 1 and s0["counts"]["KEPT"] == 0

    after = [
        _rec(PARTIAL_HANDLER, "mint", sink_callee="MintCoins",
             hops_ir=["t1 = GetNextSequenceRecv(ctx, port, chan)",
                      "t2 = VerifyPacketReceiptAbsence(ctx, port, chan, seq)"],
             guard_exprs=["GetChannel(port, chan)"]),
    ]
    _write(tmp_path, after)
    s1 = _run(tmp_path, json=True)
    assert s1["counts"]["survivors"] == 0, s1["counts"]
    assert s1["counts"]["KEPT"] == 1, s1["counts"]


def test_substrate_vacuous_is_not_clean_zero(tmp_path):
    # rows exist but NO inbound protocol handler -> substrate_vacuous (N/A).
    _write(tmp_path, [_rec(LOCAL_MSG, "state-write", sink_callee="SetBalance")])
    s = _run(tmp_path, json=True)
    assert s["substrate_status"] == "substrate_vacuous"
    assert s["counts"]["protocol_handlers"] == 0
    assert s["counts"]["survivors"] == 0


def test_cited_empty_is_honest_clean_zero(tmp_path):
    # a protocol handler exists and enforces all three -> cited_empty clean 0.
    _write(tmp_path, [
        _rec(FULL_HANDLER, "value-move", sink_callee="SendCoins",
             hops_ir=["t1 = GetNextSequenceRecv(ctx)",
                      "t2 = SetPacketReceipt(ctx, seq)"],
             guard_exprs=["GetChannel(port, chan)"]),
    ])
    s = _run(tmp_path, json=True)
    assert s["substrate_status"] == "cited_empty"
    assert s["counts"]["protocol_handlers"] == 1
    assert s["counts"]["survivors"] == 0


def test_absent_substrate_fail_closed(tmp_path):
    (tmp_path / ".auditooor").mkdir(parents=True, exist_ok=True)
    s = _run(tmp_path, json=True)   # no dataflow file at all
    assert s["substrate_status"] == "substrate_absent"
    with pytest.raises(SystemExit) as ei:
        _run(tmp_path, json=True, fail_closed=True)
    assert ei.value.code == 3


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
