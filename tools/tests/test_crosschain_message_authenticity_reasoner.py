"""Regression tests for tools/crosschain-message-authenticity-reasoner.py.

Proves the Nomad/Wormhole cross-chain forgery SET-DIFFERENCE reasoning query over
the owned dataflow backend (ACT \\ VERIFIED), NOT a body regex:

  1. an inbound handler that acts on the payload (mint/value-move sink) AND whose
     closure reaches an authenticity node is KEPT - it is NOT emitted;
  2. an inbound handler that acts on the payload but reaches NO authenticity node
     is a SURVIVOR and IS emitted as a crosschain-message-forgery obligation;
  3. axis (a) - the authenticity binding is a CLOSURE property: a verifier reached
     only through an N-hop helper IR (not in the handler's own body) still KEEPs
     the handler - impossible for a same-body regex;
  4. axis (c) - the authenticity node UNIONs across MULTIPLE path records for the
     same entrypoint: the verifier in a SIBLING path (mint sink in another) still
     KEEPs the handler;
  5. NON-VACUITY MUTATION: neutralize the KEPT handler's single authenticity node
     (rename the verifier callee) and the handler FLIPS from KEPT to SURVIVOR -
     proving the auth predicate is load-bearing, not a tautology;
  6. a non-inbound entrypoint (a local Msg handler) never populates ACT even when
     it mints;
  7. a fully absent substrate yields an empty diff + a warning and --fail-closed
     exits 3.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_MOD_PATH = (Path(__file__).resolve().parents[1]
             / "crosschain-message-authenticity-reasoner.py")
_spec = importlib.util.spec_from_file_location("xchain_auth", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# --------------------------------------------------------------------------
# synthetic dataflow_paths.jsonl builder
# --------------------------------------------------------------------------
def _rec(entry_fn, sink_kind, *, sink_callee="Act", hops_ir=None,
         guard_exprs=None, lang="go", file="/ws/x/handler.go", line=10):
    """A backward dataflow_path.v1 record: entrypoint `entry_fn` reaches sink
    `sink_kind` (callee `sink_callee`), with the closure call-sites `hops_ir` and
    guard exprs `guard_exprs`."""
    return {
        "schema": "dataflow_path.v1",
        "language": lang,
        "direction": "backward",
        "degraded": False,
        "source": {"kind": "param", "fn": entry_fn, "var": "msg",
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


VERIFIER_HANDLER = "(github.com/axelar/x/axelarnet.Keeper).RouteMessage"
FORGERY_HANDLER = "(github.com/axelar/x/transfer.Keeper).OnRecvPacket"
LOCAL_MSG = "(github.com/axelar/x/token.Keeper)._Msg_Mint_Handler"


def _base_records():
    return [
        # KEPT: inbound handler mints AND its closure reaches a verified-membership
        # authenticity node (via an N-hop helper IR - axis (a)).
        _rec(VERIFIER_HANDLER, "mint", sink_callee="MintCoins",
             hops_ir=["t1 = VerifyMembership(proof, root, path)"]),
        # SURVIVOR: inbound handler mints, NO authenticity node anywhere in closure.
        _rec(FORGERY_HANDLER, "mint", sink_callee="MintCoins",
             hops_ir=["t1 = GetBalance(addr)"]),
        # non-inbound local Msg handler that mints - must NOT be in ACT.
        _rec(LOCAL_MSG, "mint", sink_callee="MintCoins"),
    ]


def _run(tmp, **kw):
    argv = ["--workspace", str(tmp)]
    for k, v in kw.items():
        argv += ["--" + k.replace("_", "-")] + ([] if v is True else [str(v)])
    return mod.run(argv)


def test_kept_survivor_and_local_partition(tmp_path):
    _write(tmp_path, _base_records())
    s = _run(tmp_path, json=True)
    c = s["counts"]
    assert c["ACT"] == 2, c            # only the two inbound handlers, not LOCAL_MSG
    assert c["VERIFIED_kept"] == 1, c
    assert c["survivors_ACT_minus_VERIFIED"] == 1, c
    surv_fns = {x["fn"] for x in s["survivors"]}
    kept_fns = {x["fn"] for x in s["kept"]}
    assert FORGERY_HANDLER in surv_fns
    assert VERIFIER_HANDLER in kept_fns
    assert LOCAL_MSG not in surv_fns and LOCAL_MSG not in kept_fns
    # emitted obligation carries the schema + citation + critical severity
    rows = [json.loads(l) for l in
            (tmp_path / ".auditooor" / "crosschain_forgery_obligations.jsonl")
            .read_text().splitlines() if l.strip()]
    assert len(rows) == 1
    ob = rows[0]
    assert ob["schema"] == "auditooor.crosschain_message_authenticity.v1"
    assert ob["function"] == "OnRecvPacket"
    assert ob["source_refs"] and "handler.go" in ob["source_refs"][0]
    assert ob["likely_severity"] == "critical"


def test_sibling_path_union_keeps_handler(tmp_path):
    """axis (c): the mint sink and the verifier live in TWO SEPARATE path records
    for the SAME entrypoint - the union still KEEPs it (a same-body regex cannot)."""
    records = [
        # path 1: the mint sink, no auth node here.
        _rec(VERIFIER_HANDLER, "mint", sink_callee="MintCoins",
             hops_ir=["t1 = GetBalance(addr)"]),
        # path 2 (sibling, same fn): reaches the authenticity verifier only.
        _rec(VERIFIER_HANDLER, "state-write", sink_callee="parseAndVerifyVM",
             hops_ir=["t2 = parseAndVerifyVM(vaa)"]),
        _rec(FORGERY_HANDLER, "mint", sink_callee="MintCoins"),
    ]
    _write(tmp_path, records)
    s = _run(tmp_path, json=True)
    assert s["counts"]["VERIFIED_kept"] == 1, s
    assert VERIFIER_HANDLER in {x["fn"] for x in s["kept"]}
    assert FORGERY_HANDLER in {x["fn"] for x in s["survivors"]}


def test_nonvacuity_mutation_flips_kept_to_survivor(tmp_path):
    """NON-VACUITY: neutralize the KEPT handler's ONLY authenticity node (rename
    the verifier callee to a benign helper). The auth predicate now fails on it,
    so the handler FLIPS KEPT->SURVIVOR. Proves the predicate is load-bearing."""
    base = _base_records()
    s0 = _run(tmp_path.__class__(str(_write(tmp_path, base).parent.parent)),
              json=True)
    assert s0["counts"]["survivors_ACT_minus_VERIFIED"] == 1

    # MUTANT: rename VerifyMembership -> readState (a non-authenticity helper).
    mutant = [
        _rec(VERIFIER_HANDLER, "mint", sink_callee="MintCoins",
             hops_ir=["t1 = readState(proof, root, path)"]),
        _rec(FORGERY_HANDLER, "mint", sink_callee="MintCoins",
             hops_ir=["t1 = GetBalance(addr)"]),
        _rec(LOCAL_MSG, "mint", sink_callee="MintCoins"),
    ]
    mtmp = tmp_path / "mut"
    _write(mtmp, mutant)
    sm = _run(mtmp, json=True)
    # the formerly-KEPT handler is now a survivor: 2 survivors, 0 kept.
    assert sm["counts"]["VERIFIED_kept"] == 0, sm
    assert sm["counts"]["survivors_ACT_minus_VERIFIED"] == 2, sm
    assert VERIFIER_HANDLER in {x["fn"] for x in sm["survivors"]}


def test_authenticity_pred_families():
    """The node predicate recognizes all four Nomad/Wormhole binding families and
    rejects a benign helper (so it is not a catch-all shape)."""
    assert mod.authenticity_pred("VerifyMembership")        # merkle/proof
    assert mod.authenticity_pred("parseAndVerifyVM")        # signature/quorum
    assert mod.authenticity_pred("SetPacketReceipt")        # replay/nonce
    assert mod.authenticity_pred("GetChainByName")          # source-chain binding
    assert not mod.authenticity_pred("GetBalance")
    assert not mod.authenticity_pred("readState")
    assert not mod.authenticity_pred("")


def test_absent_substrate_warns_and_fail_closed_exits_3(tmp_path):
    (tmp_path / ".auditooor").mkdir(parents=True, exist_ok=True)
    s = _run(tmp_path, json=True)
    assert s["counts"]["ACT"] == 0
    assert any("no dataflow_paths" in w or "empty" in w for w in s["warnings"]), s
    # CLI --fail-closed exits 3 on an absent substrate (subprocess: run() sys.exit)
    r = subprocess.run(
        [sys.executable, str(_MOD_PATH), "--workspace", str(tmp_path),
         "--fail-closed"], capture_output=True, text=True)
    assert r.returncode == 3, (r.returncode, r.stderr)
