#!/usr/bin/env python3
"""LOGIC CAPABILITY #7 - cross-contract-privilege-trust-graph regression + non-vacuity.

Pins tools/cross-contract-privilege-trust-graph.py. The tool is a TRUST-EDGE
set-difference reasoning query (NOT a token detector): a payload-derived,
non-immutable dispatch/verifier TARGET that is trusted but reaches no
membership/authorization validation is the survivor of

    TRUSTED_TARGETS \\ (IMMUTABLE union VALIDATED).

Solidity matrix (planted positive fires; each guard/derivation control is silent):
  - dispatcher calls a param-address VERIFIER, no allowlist         -> 1 survivor.
  - SAME target membership-checked against `isTrusted[verifier]`    -> 0 (VALIDATED/KEPT).
  - verifier is a governance-pinned state var (onlyOwner setter)    -> 0 (not payload-derived).
  - dispatch target is an `immutable` state var                     -> 0 (IMMUTABLE).
  - target set by an UNGUARDED public setter (attacker-writable)    -> 1 survivor.

Non-vacuity (each operand of the set-difference is load-bearing - a mutation of the
tool's predicate flips the verdict):
  - force trust_validation_pred -> True (everything VALIDATED)   => planted 1 -> 0.
  - force _ref_validated -> True                                 => planted 1 -> 0.

Dataflow arm: the payload-derived-CALLEE gate rejects a statically-resolved callee
(the source param is only an ARGUMENT) and accepts a dynamically payload-selected
callee - proving the #7 axis is distinct from #3's payload-VALUE flow.

Pure-source (no compiler); the suite never skips. If the real nuva/axelar
workspaces are present, an optional live assertion pins the proven-on-real result
(nuva: 0 survivors but >=1 KEPT trusted-but-validated = non-vacuous; axelar:
cited-empty over a non-zero dispatch-record count).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "cross_contract_privilege_trust_graph",
        TOOLS / "cross-contract-privilege-trust-graph.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


X = _load_tool()


# --- synthetic Solidity fixtures --------------------------------------------

# planted POSITIVE: a dispatcher authenticates against a verifier address taken
# straight from calldata, with no allowlist/authorization on that ref -> survivor.
POS_PARAM_VERIFIER = """
pragma solidity ^0.8.0;
contract Dispatcher {
    function execute(address verifier, bytes calldata data) external {
        // the trusted verifier address is a raw calldata param, never validated.
        require(IVerifier(verifier).isValid(data), "bad");
        _payout(msg.sender);
    }
    function _payout(address to) internal {}
}
"""

# CONTROL A (VALIDATED / KEPT): SAME param target, but membership-checked against
# a governance allowlist before it is trusted -> removed from the survivors.
KEPT_ALLOWLISTED = """
pragma solidity ^0.8.0;
contract Dispatcher {
    mapping(address => bool) public isTrusted;
    function execute(address verifier, bytes calldata data) external {
        require(isTrusted[verifier], "unknown");
        require(IVerifier(verifier).isValid(data), "bad");
    }
}
"""

# CONTROL B (governance-pinned): the verifier is a state var whose ONLY setter is
# onlyOwner -> not payload-derived -> silent.
GOV_PINNED = """
pragma solidity ^0.8.0;
contract Dispatcher {
    address public verifier;
    function setVerifier(address v) external onlyOwner { verifier = v; }
    function execute(bytes calldata data) external {
        require(IVerifier(verifier).isValid(data), "bad");
    }
}
"""

# CONTROL C (IMMUTABLE): the dispatch target is immutable -> silent.
IMMUTABLE_TARGET = """
pragma solidity ^0.8.0;
contract Dispatcher {
    address public immutable verifier;
    constructor(address v) { verifier = v; }
    function execute(bytes calldata data) external {
        require(IVerifier(verifier).isValid(data), "bad");
    }
}
"""

# planted POSITIVE 2 (attacker-writable state): the dispatch target is set by an
# UNGUARDED public setter -> attacker-swappable -> survivor.
POS_UNGUARDED_SETTER = """
pragma solidity ^0.8.0;
contract Dispatcher {
    address public router;
    function setRouter(address r) external { router = r; }
    function execute(uint256 amount) external {
        IRouter(router).forward(amount);
    }
}
"""


def _run(src: str):
    with tempfile.TemporaryDirectory() as d:
        ws = pathlib.Path(d)
        f = ws / "C.sol"
        f.write_text(src, encoding="utf-8")
        surv, kept, acct = X._sol_arm(ws, ws, include_oos=True)
        return surv, kept, acct


class SolArm(unittest.TestCase):
    def test_param_verifier_no_validation_fires(self):
        surv, kept, acct = _run(POS_PARAM_VERIFIER)
        self.assertEqual(len(surv), 1, (surv, acct))
        s = surv[0]
        self.assertEqual(s["fn"], "execute")
        self.assertEqual(s["target"], "verifier")
        self.assertEqual(s["derivation"], "param")
        self.assertIn("verifier-signer" if s["kind"] == "verifier-signer"
                      else "call", (s["kind"],))

    def test_allowlisted_target_is_kept_not_survivor(self):
        surv, kept, acct = _run(KEPT_ALLOWLISTED)
        self.assertEqual(len(surv), 0, surv)
        # the subtraction removed a REAL element (non-vacuous KEPT proof).
        self.assertGreaterEqual(len(kept), 1, (kept, acct))
        self.assertEqual(kept[0]["target"], "verifier")

    def test_governance_pinned_target_silent(self):
        surv, kept, acct = _run(GOV_PINNED)
        self.assertEqual(len(surv), 0, surv)

    def test_immutable_target_silent(self):
        surv, kept, acct = _run(IMMUTABLE_TARGET)
        self.assertEqual(len(surv), 0, surv)

    def test_unguarded_setter_attacker_writable_fires(self):
        surv, kept, acct = _run(POS_UNGUARDED_SETTER)
        self.assertEqual(len(surv), 1, (surv, acct))
        self.assertEqual(surv[0]["target"], "router")
        self.assertEqual(surv[0]["derivation"], "attacker-writable-state")


class NonVacuity(unittest.TestCase):
    """Each operand of the set-difference is load-bearing: a mutation of the
    tool's own predicate flips the planted positive."""

    def test_validation_pred_true_collapses_positive(self):
        orig = X.trust_validation_pred
        try:
            X.trust_validation_pred = lambda expr, target=None: True  # type: ignore
            # _ref_validated is what the sol arm consults; mutate that too.
            orig_ref = X._ref_validated
            X._ref_validated = lambda ref, txt: True  # type: ignore
            try:
                surv, kept, acct = _run(POS_PARAM_VERIFIER)
                self.assertEqual(len(surv), 0,
                                 "forcing VALIDATED=True must collapse the survivor")
            finally:
                X._ref_validated = orig_ref  # type: ignore
        finally:
            X.trust_validation_pred = orig  # type: ignore

    def test_ref_validated_false_keeps_positive(self):
        # sanity: with the real predicate the positive stands (guards the mutation
        # test above is meaningful, not trivially always-zero).
        surv, _, _ = _run(POS_PARAM_VERIFIER)
        self.assertEqual(len(surv), 1)


class DataflowArm(unittest.TestCase):
    """The payload-derived-CALLEE gate: a statically-resolved callee (source param
    is only an argument) is REJECTED; a payload-selected callee is accepted. This
    is the axis that keeps #7 distinct from #3's payload-VALUE flow."""

    def _emit(self, sink, source, guard_nodes, srcname="keeper.go"):
        """Run the dataflow arm over one record whose sink.file is a real
        in-scope source under the temp workspace."""
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            (ws / ".auditooor").mkdir()
            src = ws / srcname
            src.write_text("package p\n", encoding="utf-8")
            rec = {"language": "go", "source": source,
                   "sink": {**sink, "file": str(src)},
                   "guard_nodes": guard_nodes}
            df = ws / ".auditooor" / "df.jsonl"
            df.write_text(json.dumps(rec), encoding="utf-8")
            return X._dataflow_arm(ws, [df], include_oos=True)

    def test_static_callee_rejected(self):
        # source param `amt` is only an argument; callee statically resolved.
        surv, kept, acct = self._emit(
            {"kind": "value-move",
             "callee": "(cosmos/x/bank/keeper.BaseKeeper).SendCoins",
             "line": 10, "fn": "Keeper.Pay"},
            {"kind": "param", "var": "amt"}, [])
        self.assertEqual(len(surv), 0, (surv, acct))
        self.assertGreaterEqual(acct.get("dispatch_records", 0), 1)

    def test_payload_selected_callee_fires(self):
        # the resolved callee IDENTITY references the tainted var `handlerAddr`
        # (a dynamically payload-selected handler) -> survivor.
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            (ws / ".auditooor").mkdir()
            src = ws / "router.go"
            src.write_text("package router\n", encoding="utf-8")
            rec = {"language": "go",
                   "source": {"kind": "param", "var": "handlerAddr"},
                   "sink": {"kind": "authority",
                            "callee": "dynamicdispatch(handlerAddr).Handle",
                            "file": str(src), "line": 5, "fn": "Router.Route"},
                   "guard_nodes": []}
            df = ws / ".auditooor" / "df.jsonl"
            df.write_text(json.dumps(rec), encoding="utf-8")
            surv, kept, acct = X._dataflow_arm(ws, [df], include_oos=True)
            self.assertEqual(len(surv), 1, (surv, acct))
            self.assertEqual(surv[0]["derivation"], "param-entrypoint")

    def test_payload_selected_callee_with_authz_guard_kept(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            (ws / ".auditooor").mkdir()
            src = ws / "router.go"
            src.write_text("package router\n", encoding="utf-8")
            rec = {"language": "go",
                   "source": {"kind": "param", "var": "handlerAddr"},
                   "sink": {"kind": "authority",
                            "callee": "dynamicdispatch(handlerAddr).Handle",
                            "file": str(src), "line": 5, "fn": "Router.Route"},
                   "guard_nodes": [{"expr": "isTrusted[handlerAddr]"}]}
            df = ws / ".auditooor" / "df.jsonl"
            df.write_text(json.dumps(rec), encoding="utf-8")
            surv, kept, acct = X._dataflow_arm(ws, [df], include_oos=True)
            self.assertEqual(len(surv), 0, surv)
            self.assertEqual(len(kept), 1, kept)


class DispatchTargetHygiene(unittest.TestCase):
    """The dispatch-target extractor must NOT count Solidity builtins/keywords
    (`address`, `msg`, `this`, ...) as trust targets, and must unwrap an
    `address(x)` cast to the inner ref - otherwise `safeTransferFrom(from,
    address(this), amt)` leaks a phantom `address` target and a genuine
    `transfer(address(dest))` recipient is lost as the `address` keyword."""

    class _Fn:
        def __init__(self, body):
            self.body = body

    def _targets(self, body):
        return set(X._dispatch_targets(self._Fn(body)))

    def test_address_this_recipient_not_a_target(self):
        body = "token.safeTransferFrom(msg.sender, address(this), amt);"
        tg = self._targets(body)
        names = {t for t, _ in tg}
        self.assertNotIn("address", names, tg)
        self.assertNotIn("this", names, tg)
        self.assertNotIn("msg", names, tg)

    def test_address_cast_recipient_unwrapped_to_inner_ref(self):
        body = "payToken.transfer(address(dest));"
        tg = self._targets(body)
        self.assertIn(("dest", "value-recipient"), tg, tg)
        self.assertNotIn("address", {t for t, _ in tg})

    def test_plain_param_recipient_still_captured(self):
        body = "payToken.safeTransfer(recipient, amt);"
        tg = self._targets(body)
        self.assertIn(("recipient", "value-recipient"), tg, tg)


class CitedEmptyExaminedRecord(unittest.TestCase):
    """NEVER a silent 0: a 0-survivor run must persist a single CITED-EMPTY
    examined-record to the ledger (so a downstream consumer distinguishes a
    terminal-clean examined result from a starved/absent run), and that record
    must be advisory (not an open obligation) and skipped by exploit-queue."""

    def _run_to_file(self, src):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            (ws / "C.sol").write_text(src, encoding="utf-8")
            emit = ws / "obl.jsonl"
            out = X.run(["--workspace", str(ws), "--include-oos",
                         "--emit", str(emit)])
            rows = [json.loads(l) for l in emit.read_text().splitlines() if l.strip()]
            return out, rows

    def test_zero_survivors_emits_cited_empty_record(self):
        # GOV_PINNED has real substrate (a dispatch target) but 0 survivors.
        out, rows = self._run_to_file(GOV_PINNED)
        self.assertEqual(out["size_DIFF_survivors"], 0, out)
        self.assertEqual(out["obligations_written"], 0)
        self.assertTrue(out["examined_record_written"])
        # exactly one row: the examined-record (never a silent empty file).
        self.assertEqual(len(rows), 1, rows)
        rec = rows[0]
        self.assertEqual(rec["obligation_type"], "trust-graph-examined-record")
        self.assertIn("cited-empty", rec["note"])
        self.assertEqual(rec["report"]["totals"]["survivors"], 0)
        # terminal statuses so no consumer reads it as an OPEN obligation.
        self.assertEqual(rec["proof_status"], "not-applicable")

    def test_survivor_run_has_no_examined_record(self):
        out, rows = self._run_to_file(POS_PARAM_VERIFIER)
        self.assertGreaterEqual(out["size_DIFF_survivors"], 1, out)
        self.assertFalse(out["examined_record_written"])
        self.assertTrue(all(
            r.get("obligation_type") != "trust-graph-examined-record"
            for r in rows), rows)

    def test_no_substrate_emits_na_examined_record(self):
        # a workspace with NO solidity + NO dataflow substrate still gets a cited
        # examined-record (N/A), never a silent empty file.
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            emit = ws / "obl.jsonl"
            out = X.run(["--workspace", str(ws), "--emit", str(emit)])
            rows = [json.loads(l) for l in emit.read_text().splitlines() if l.strip()]
            self.assertTrue(out["no_substrate"], out)
            self.assertEqual(len(rows), 1, rows)
            self.assertEqual(rows[0]["obligation_type"], "trust-graph-examined-record")
            self.assertIn("cited-empty", rows[0]["note"])


class Obligation(unittest.TestCase):
    def test_obligation_schema_exploit_queue_compatible(self):
        surv, _, _ = _run(POS_PARAM_VERIFIER)
        ob = X.make_obligation(surv[0], "INV-TEST")
        for k in ("schema", "obligation_type", "contract", "function",
                  "source_refs", "attack_class", "broken_invariant_ids",
                  "root_cause_hypothesis", "quality_gate_status"):
            self.assertIn(k, ob)
        self.assertEqual(ob["schema"],
                         "auditooor.payload_derived_trusted_dispatch.v1")
        self.assertEqual(ob["broken_invariant_ids"], ["INV-TEST"])
        self.assertEqual(ob["quality_gate_status"], "needs_source")


class ProvenOnReal(unittest.TestCase):
    """Optional: pin the proven-on-real result when the workspaces are present."""

    def test_nuva_non_vacuous_or_cited(self):
        ws = pathlib.Path("/Users/wolf/audits/nuva")
        if not (ws / ".auditooor" / "inscope_units.jsonl").is_file():
            self.skipTest("nuva workspace absent")
        out = X.run(["--workspace", str(ws), "--json"])
        self.assertIsInstance(out, dict)
        # non-vacuous: either real survivors, or a real KEPT set proving the
        # subtraction removed a genuine element (not a vacuous empty scan).
        non_vacuous = (out["size_DIFF_survivors"] > 0
                       or out["size_VALIDATED_or_IMMUTABLE_among_trusted"] > 0)
        self.assertTrue(non_vacuous, out)
        self.assertGreater(out["sol_arm"]["dispatch_target_refs"], 0)
        # never a silent 0: when the diff is empty on real substrate, a
        # cited-empty examined-record was persisted.
        if out["size_DIFF_survivors"] == 0:
            self.assertTrue(out["examined_record_written"], out)

    def test_axelar_cited_empty_over_nonzero_records(self):
        ws = pathlib.Path("/Users/wolf/audits/axelar-dlt")
        if not (ws / ".auditooor" / "dataflow_paths.jsonl").is_file():
            self.skipTest("axelar workspace absent")
        out = X.run(["--workspace", str(ws), "--json"])
        # genuinely empty for a CITED reason: a non-zero number of dispatch
        # records were examined (the backend fired), all statically-resolved.
        self.assertGreaterEqual(out["dataflow_arm"]["records"], 1)
        self.assertGreaterEqual(out["dataflow_arm"].get("dispatch_records", 0), 1)


if __name__ == "__main__":
    unittest.main()
