#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered via agent-pathspec-register.py -->
"""Guard: unhunted-surface-adjudicate emits evidence-grounded terminal verdicts,
and the follow-through gate credits them ONLY when the evidence_ref is a real
file (anti-false-green).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / fname))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ADJ = _load("adj", "unhunted-surface-adjudicate.py")
GATE = _load("_unhunted_gate", "unhunted-surface-followthrough-gate.py")


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    (ws / "src" / "interfaces").mkdir(parents=True)
    (ws / "src" / "libraries").mkdir(parents=True)
    # interface file
    (ws / "src" / "interfaces" / "IFoo.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ninterface IFoo { function bar() external; }\n")
    # vendored library
    (ws / "src" / "libraries" / "SafeTransferLib.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\nlibrary SafeTransferLib { }\n")
    # in-scope source
    (ws / "src" / "Core.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract Core { function f() external {} }\n")
    # coverage report: 0 uncovered
    (ws / ".auditooor" / "coverage_report.json").write_text(
        json.dumps({"covered": 10, "uncovered": 0}))
    # fuzz artifact
    (ws / ".auditooor" / "deep-engine-findings").mkdir()
    (ws / ".auditooor" / "deep-engine-findings" / "X-CORE-SOLVENCY-fuzz.md").write_text("medusa 1.85M calls, 0 violations")
    return ws


def _queue(ws: Path, titles_ids):
    rows = [{"lead_id": lid, "title": t, "proof_status": "open"} for lid, t in titles_ids]
    (ws / ".auditooor" / "exploit_queue.json").write_text(json.dumps(rows))


# r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
class TestAdjudicate(unittest.TestCase):
    def test_classifier_per_class(self):
        """Unit-test the per-lead classifier across all evidence classes + the
        OPEN residual (no genuine basis -> no verdict)."""
        ws = _ws()
        cov = ws / ".auditooor" / "coverage_report.json"
        fuzz = ADJ._fuzz_artifact(ws)
        def cls(title):
            v = ADJ._adjudicate_lead({"id": "x", "title": title}, ws, cov, fuzz)
            return v["evidence_class"] if v else None
        self.assertEqual(cls("unhunted-surface target: IFoo.sol::bar"), "interface-declaration")
        self.assertEqual(cls("unhunted-surface target: SafeTransferLib.sol::safeTransfer"),
                         "vendored-trusted-library")
        # HONESTY (coverage-theater fix): an in-scope source surface is NOT
        # auto-refuted from source-unit coverage (uncovered==0) alone. With no
        # per-lead hunt verdict it stays OPEN (None / abandoned).
        self.assertIsNone(cls("unhunted-surface target: Core.sol::f"),
                          "coverage-only must NOT auto-refute an in-scope surface")
        self.assertEqual(cls("corpus-hunt-fuel: INV-X (accounting_conservation) @ f"),
                         "solvency-invariant-fuzzed-clean")
        # OPEN: no genuine basis -> None (stays abandoned)
        self.assertIsNone(cls("corpus-hunt-fuel: INV-Y (bridge_replay) @ setConsumed"))
        self.assertIsNone(cls("corpus-hunt-hacker-q: HQ-FLASH-LOAN @ relayIsRatified"))

    def test_inscope_first_party_oz_wrapper_not_vendored(self):
        """strata 2026-07-01 regression: a FIRST-PARTY in-scope contract that
        imports/extends OpenZeppelin must NOT be auto-closed as
        'vendored-trusted-library'. Importing a library is not vendoring it."""
        ws = _ws()
        # a first-party in-scope contract that WRAPS OpenZeppelin (like Strata's
        # AccessControlManager). Header mentions OZ; body imports @openzeppelin.
        acm = ws / "src" / "AccessControlManager.sol"
        acm.write_text(
            "// SPDX-License-Identifier: BSD-3-Clause\npragma solidity ^0.8.20;\n"
            'import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";\n'
            "/// @dev This contract is a wrapper of OpenZeppelin AccessControl extending it.\n"
            "contract AccessControlManager is AccessControl { function grantCall() public {} }\n")
        # mark it in-scope
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/AccessControlManager.sol", "function": "grantCall"}) + "\n")
        ADJ._INSCOPE_CACHE.clear(); ADJ._RESOLVE_PATH_CACHE.clear()
        # direct predicate: not vendored despite the OZ mention/import
        self.assertFalse(ADJ._is_vendored_file(acm, ws),
                         "in-scope first-party OZ-wrapper must not be vendored")
        self.assertTrue(ADJ._is_inscope_file(ws, acm))
        # end-to-end: the lead must NOT get the vendored-trusted-library verdict
        v = ADJ._adjudicate_lead(
            {"id": "x", "title": "unhunted-surface target: AccessControlManager.sol::grantCall"},
            ws, ws / ".auditooor" / "coverage_report.json", ADJ._fuzz_artifact(ws))
        cls = v["evidence_class"] if v else None
        self.assertNotEqual(cls, "vendored-trusted-library",
                            "in-scope first-party contract wrongly closed as vendored/OOS")

    def test_genuinely_vendored_still_detected(self):
        """The hardening must not blind us to a REAL inlined copy: a Solmate/Solady
        verbatim copy, or a file under a vendored path, is still vendored."""
        ws = _ws()
        # verbatim inlined copy carrying the original author tag (not in-scope)
        sol = ws / "src" / "utils" / "SafeCast.sol"
        sol.parent.mkdir(parents=True, exist_ok=True)
        sol.write_text("// SPDX-License-Identifier: MIT\n/// @author Solmate\n"
                       "library SafeCast { }\n")
        self.assertTrue(ADJ._is_vendored_file(sol, ws), "Solmate verbatim copy is vendored")
        # a copied OZ file carrying the real OZ copyright header is still vendored
        ozf = ws / "src" / "oz" / "Pausable.sol"
        ozf.parent.mkdir(parents=True, exist_ok=True)
        ozf.write_text("// SPDX-License-Identifier: MIT\n"
                       "// OpenZeppelin Contracts (last updated v5.0.0) (utils/Pausable.sol)\n"
                       "abstract contract Pausable { }\n")
        self.assertTrue(ADJ._is_vendored_file(ozf, ws), "verbatim OZ copy is vendored")

    def test_rubric_class_refuted_from_intact_doc_reproducible(self):
        """An unattempted-rubric-class lead is credited terminal from a REFUTED
        rubric-refutation doc (reproducible), and stays OPEN without it."""
        ws = _ws()
        lead = {"id": "r", "title": "unattempted-rubric-class target tier=critical ref=abc123"}
        cov = ws / ".auditooor" / "coverage_report.json"
        fuzz = ADJ._fuzz_artifact(ws)
        # no doc -> OPEN (honest fail)
        self.assertIsNone(ADJ._adjudicate_lead(lead, ws, cov, fuzz))
        # REFUTED doc covering the critical tier -> terminal exhaustive-hunt-no-instance
        (ws / ".auditooor" / "unhunted_rubric_class_refutation.md").write_text(
            "# refutation\nTerminal verdict: REFUTED. critical/medium/low all covered by "
            "exhaustive per-function + corpus + mutation-verified harness hunt.\n")
        v = ADJ._adjudicate_lead(lead, ws, cov, fuzz)
        self.assertIsNotNone(v)
        self.assertEqual(v["evidence_class"], "exhaustive-hunt-no-instance")
        # a tier the doc does NOT mention stays OPEN (false-green-safe)
        lead2 = {"id": "r2", "title": "unattempted-rubric-class target tier=high ref=z9"}
        self.assertIsNone(ADJ._adjudicate_lead(lead2, ws, cov, fuzz))

    def test_surface_markers_resolved_end_to_end(self):
        ws = _ws()
        _queue(ws, [
            ("L1", "unhunted-surface target: IFoo.sol::bar"),          # interface
            ("L2", "unhunted-surface target: SafeTransferLib.sol::safeTransfer"),  # vendored
            ("L3", "unhunted-surface target: Core.sol::f"),            # in-scope, coverage-only
        ])
        r = ADJ.adjudicate(ws)
        # HONESTY (coverage-theater fix): only the interface + vendored markers
        # have a genuine per-lead basis. The in-scope Core.sol::f surface has
        # coverage but NO per-lead hunt verdict, so it stays abandoned - the gate
        # honestly shows the undriven tail.
        self.assertEqual(r["resolved"], 2, r["by_class"])
        self.assertEqual(r["still_open"], 1)
        g = GATE.evaluate(str(ws))
        self.assertEqual(g["stats"]["resolved_by_ledger"], 2)
        self.assertEqual(g["stats"]["abandoned_count"], 1)
        self.assertEqual(g["verdict"], "fail-abandoned-surfaces")
        # the abandoned surface is the coverage-only in-scope one
        self.assertIn("Core.sol::f",
                      " | ".join(s["title"] for s in g["abandoned_surfaces"]))

    def test_covered_in_scope_requires_per_lead_hunt_verdict(self):
        """SPEC guard: 2 in-scope surfaces with coverage uncovered==0 but NO
        per-lead hunt verdict -> BOTH stay abandoned (not auto-refuted). A 3rd
        surface that a real hunt-source-refuted sidecar pairs to -> covered."""
        ws = _ws()  # coverage_report.json already has uncovered==0
        # in-scope source files for the three surfaces
        (ws / "src" / "Vault.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract Vault { function deposit() external {} }\n")
        (ws / "src" / "Router.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract Router { function swap() external {} }\n")
        # a genuine per-lead hunt verdict ONLY for Router.sol::swap
        (ws / ".auditooor" / "residual_hunt_verdicts.json").write_text(json.dumps([
            {"lead_id": "HQ-ROUTER", "function": "swap", "file_line": "src/Router.sol:1",
             "verdict": "refuted", "reason": "slippage-bounded; no value drain path"},
        ]))
        _queue(ws, [
            ("S1", "unhunted-surface target: Core.sol::f"),    # coverage-only -> abandoned
            ("S2", "unhunted-surface target: Vault.sol::deposit"),  # coverage-only -> abandoned
            ("S3", "unhunted-surface target: Router.sol::swap"),    # per-lead refuted -> covered
        ])
        r = ADJ.adjudicate(ws)
        # exactly one (Router/swap) is resolved via a genuine per-lead verdict
        self.assertEqual(r["resolved"], 1, r["by_class"])
        self.assertEqual(r["still_open"], 2)
        self.assertEqual(r["by_class"].get("covered-in-scope"), 1)
        g = GATE.evaluate(str(ws))
        self.assertEqual(g["stats"]["resolved_by_ledger"], 1)
        abandoned_titles = " | ".join(s["title"] for s in g["abandoned_surfaces"])
        self.assertIn("Core.sol::f", abandoned_titles)
        self.assertIn("Vault.sol::deposit", abandoned_titles)
        self.assertNotIn("Router.sol::swap", abandoned_titles)

    def test_shared_coverage_report_ref_rejected_by_gate(self):
        """SPEC guard: a ledger verdict whose evidence_ref is the SHARED
        coverage_report.json must NOT credit a lead (a single shared artifact
        cannot be N distinct terminal verdicts)."""
        ws = _ws()  # coverage_report.json exists
        _queue(ws, [("CV1", "unhunted-surface target: Core.sol::f")])
        # hand-write a ledger that (the OLD coverage-theater way) cites the
        # shared coverage_report.json as the terminal evidence_ref
        (ws / ".auditooor" / "unhunted_terminal_verdicts.json").write_text(json.dumps({
            "schema": "auditooor.unhunted_terminal_verdicts.v1",
            "verdicts": [{"lead_id": "CV1", "title": "unhunted-surface target: Core.sol::f",
                          "verdict": "refuted",
                          "evidence_ref": ".auditooor/coverage_report.json"}],
        }))
        g = GATE.evaluate(str(ws))
        self.assertEqual(g["stats"]["resolved_by_ledger"], 0,
                         "shared coverage_report.json must not credit a lead")
        self.assertEqual(g["stats"]["abandoned_count"], 1)

    def test_covered_basis_requires_zero_uncovered(self):
        ws = _ws()
        # flip coverage to a non-zero uncovered -> covered-in-scope basis gone
        (ws / ".auditooor" / "coverage_report.json").write_text(
            json.dumps({"covered": 10, "uncovered": 3}))
        _queue(ws, [("L3", "unhunted-surface target: Core.sol::f")])
        r = ADJ.adjudicate(ws)
        self.assertEqual(r["resolved"], 0, "covered credit must require 0 uncovered")
        self.assertEqual(r["still_open"], 1)

    def test_fabricated_ledger_ref_does_not_credit(self):
        """Anti-false-green: a ledger verdict whose evidence_ref is not a real
        file must NOT remove the lead from abandoned."""
        ws = _ws()
        _queue(ws, [("L9", "unhunted-surface target: Core.sol::f")])
        # hand-write a bogus ledger pointing at a non-existent file
        (ws / ".auditooor" / "unhunted_terminal_verdicts.json").write_text(json.dumps({
            "schema": "auditooor.unhunted_terminal_verdicts.v1",
            "verdicts": [{"lead_id": "L9", "title": "unhunted-surface target: Core.sol::f",
                          "verdict": "refuted", "evidence_ref": "does/not/exist.json"}],
        }))
        g = GATE.evaluate(str(ws))
        self.assertEqual(g["stats"]["resolved_by_ledger"], 0,
                         "a non-existent evidence_ref must not credit a lead")
        self.assertEqual(g["stats"]["abandoned_count"], 1)

    # r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
    def test_hunt_verdict_refutes_residual_lead(self):
        """A residual corpus-fuel/hacker-q lead is resolved when a focused-hunt
        residual_hunt_verdicts.json carries a `refuted` verdict that pairs to it
        (by id / function / class); a `candidate-finding` does NOT resolve it."""
        ws = _ws()
        (ws / ".auditooor" / "residual_hunt_verdicts.json").write_text(json.dumps([
            {"lead_id": "INV-ORD-EX-0002", "function": "setConsumed",
             "file_line": "src/Core.sol:1", "verdict": "refuted", "reason": "monotonic+auth"},
            {"lead_id": "HQ-X-OVERFLOW", "function": "mulDivUp",
             "file_line": "src/Core.sol:1", "verdict": "candidate-finding", "reason": "maybe"},
        ]))
        hunt = ADJ._load_hunt_verdicts(ws)
        # refuted lead pairs -> resolved
        v = ADJ._adjudicate_lead(
            {"id": "x", "title": "corpus-hunt-fuel: INV-ORD-EX-0002 (bridge_replay) @ setConsumed"},
            ws, None, None, hunt)
        self.assertIsNotNone(v)
        self.assertEqual(v["evidence_class"], "hunt-source-refuted")
        # candidate-finding lead stays OPEN (becomes a paste-ready lead, not hidden)
        v2 = ADJ._adjudicate_lead(
            {"id": "y", "title": "corpus-hunt-hacker-q: HQ-X-OVERFLOW (integer-overflow) @ mulDivUp"},
            ws, None, None, hunt)
        self.assertIsNone(v2, "a candidate-finding must NOT be auto-resolved")

    def test_covered_in_scope_cites_real_sidecar_not_shared_ledger(self):
        """A covered-in-scope verdict from a workflow-drill hunt sidecar must cite
        the ACTUAL sidecar file (a distinct on-disk per-surface ref the gate
        accepts), NOT the shared (often non-existent) residual_hunt_verdicts.json.
        near-intents 2026-06-26: 1045 verdicts were rejected by the gate because
        they cited the missing shared ledger."""
        ws = _ws()
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "Core.sol").write_text(
            "contract Core { function setConsumed() public {} }\n", encoding="utf-8")
        scd = ws / ".auditooor" / "hunt_findings_sidecars"
        scd.mkdir(parents=True, exist_ok=True)
        (scd / "hunt_b0001_setConsumed.json").write_text(json.dumps({
            "task_id": "ni-b0001-setConsumed",
            "function_anchor": {"file": "src/Core.sol", "fn": "setConsumed"},
            "result": {"verdict": "KILL", "applies_to_target": "no",
                       "file_line": "src/Core.sol:1", "reasoning": "monotonic+auth"},
        }), encoding="utf-8")
        hunt = ADJ._load_hunt_verdicts(ws)
        v = ADJ._adjudicate_lead(
            {"id": "x", "title": "corpus-hunt-fuel: INV-ORD-EX-0002 (bridge_replay) @ setConsumed"},
            ws, None, None, hunt)
        self.assertIsNotNone(v)
        # evidence_ref points at the real sidecar (exists), not the shared ledger
        self.assertTrue(v["evidence_ref"].endswith("hunt_b0001_setConsumed.json"))
        self.assertTrue((ws / v["evidence_ref"]).is_file())

    def test_eq_format_trailer_stripped(self):
        """A surface title with an equivalence-class trailer
        ("foo.rs | EQ-9261 | unknown") must resolve the bare file, not fold the
        trailer into the unit (near-intents: 164 EQ-format targets never resolved)."""
        ws = _ws()
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "consts.rs").write_text("pub const A: u8 = 1;\n", encoding="utf-8")
        v = ADJ._adjudicate_lead(
            {"id": "z", "title": "unhunted-surface target: consts.rs | EQ-9261 | unknown"},
            ws, None, None, [])
        self.assertIsNotNone(v)
        self.assertEqual(v["evidence_class"], "no-attack-surface-no-function")

    def test_top_level_schema_sidecar_ingested(self):
        """Early per-fn hunt sidecars use a TOP-LEVEL {file,line,function,verdict}
        schema with no nested result; the ingest must still read them (near-intents
        queue-3 wave: blstrs.rs etc. were KILLed but skipped)."""
        ws = _ws()
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "conv.rs").write_text("pub fn from() {}\n", encoding="utf-8")
        scd = ws / ".auditooor" / "hunt_findings_sidecars"
        scd.mkdir(parents=True, exist_ok=True)
        (scd / "hunt_qc0000_t06.json").write_text(json.dumps({
            "task_id": "qc0000_t06", "file": "src/conv.rs", "line": 5,
            "function": "from", "verdict": "KILL", "reasoning": "infallible compression",
        }), encoding="utf-8")
        hunt = ADJ._load_hunt_verdicts(ws)
        self.assertTrue(any(h.get("function") == "from"
                            and h.get("file_line", "").endswith("conv.rs:5") for h in hunt),
                        "top-level-schema sidecar must be ingested with a file_line")

    def test_top_level_combined_fileline_schema_sidecar_ingested(self):
        """SEI mimo/perfn hunt sidecars use a TOP-LEVEL schema with NO nested
        ``result`` and NO separate {file, line} pair either - the source cite is a
        single already-combined ``file_line`` string, e.g.
        hunt__CW1155ERC1155Pointer.sol__burn__4006959d__L141__I-na.json:
        {"file_line": "contracts/src/Foo.sol:141-157", "verdict": "NEGATIVE",
        "applies_to_target": "no", "function_anchor": {"file": ..., "fn": "burn"}}.
        Without the top-level-file_line fallback this silently failed the R76
        source-cite check and ~53% of SEI's hunt_findings_sidecars/*.json (2599/4935)
        never paired to their unhunted-surface marker (operator-caught 2026-07-06)."""
        ws = _ws()
        (ws / "contracts" / "src").mkdir(parents=True, exist_ok=True)
        (ws / "contracts" / "src" / "Foo.sol").write_text(
            "contract Foo { function burn() public {} }\n", encoding="utf-8")
        scd = ws / ".auditooor" / "hunt_findings_sidecars"
        scd.mkdir(parents=True, exist_ok=True)
        (scd / "hunt__Foo.sol__burn__deadbeef__L141__I-na.json").write_text(json.dumps({
            "unit": "Foo.sol::burn",
            "function_anchor": {"file": "contracts/src/Foo.sol", "fn": "burn"},
            "file_line": "contracts/src/Foo.sol:141-157",
            "applies_to_target": "no",
            "verdict": "NEGATIVE",
            "severity": "NA",
            "reasoning": "authority-gated; no unprivileged burn path.",
        }), encoding="utf-8")
        hunt = ADJ._load_hunt_verdicts(ws)
        matches = [h for h in hunt if h.get("function") == "burn"]
        self.assertTrue(matches, "combined-file_line-schema sidecar must be ingested")
        self.assertTrue(any(h.get("file_line", "").startswith("contracts/src/Foo.sol:141")
                            for h in matches))
        self.assertTrue(all(h.get("verdict") == "refuted" for h in matches))

    def test_prefer_non_test_copy_on_basename_collision(self):
        """When a basename exists in both a production and a test/e2e crate,
        _resolve_unit_file prefers the production copy (near-intents conversions.rs:
        0-fn production aggregator vs 4-fn e2e-tests helper)."""
        ws = _ws()
        (ws / "src" / "prod").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "e2e-tests" / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "prod" / "conversions.rs").write_text("pub enum E { A }\n", encoding="utf-8")
        (ws / "src" / "e2e-tests" / "src" / "conversions.rs").write_text("pub fn t() {}\n", encoding="utf-8")
        ADJ._RESOLVE_PATH_CACHE.clear()
        p = ADJ._resolve_unit_file(ws, "conversions.rs")
        self.assertIsNotNone(p)
        self.assertIn("prod", str(p))
        self.assertNotIn("e2e-tests", str(p))

    def test_file_only_no_function_target_is_terminal(self):
        """A file-only surface target over a zero-function data/const module is
        terminal (no per-fn attack surface), cited to the file itself."""
        ws = _ws()
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "consts.rs").write_text(
            "pub const A: u8 = 1;\npub const B: u8 = 2;\n", encoding="utf-8")
        v = ADJ._adjudicate_lead(
            {"id": "z", "title": "unhunted-surface target: consts.rs"}, ws, None, None, [])
        self.assertIsNotNone(v)
        self.assertEqual(v["evidence_class"], "no-attack-surface-no-function")
        self.assertTrue((ws / v["evidence_ref"]).is_file())

    def test_file_only_with_function_unhunted_stays_open(self):
        """A file-only target over a file WITH functions but NO matching hunt
        verdict must stay OPEN (no false-green)."""
        ws = _ws()
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "logic.rs").write_text(
            "pub fn transfer(a: u128) { do_it(a); }\n", encoding="utf-8")
        v = ADJ._adjudicate_lead(
            {"id": "z", "title": "unhunted-surface target: logic.rs"}, ws, None, None, [])
        self.assertIsNone(v, "a fn-bearing file with no hunt verdict must stay OPEN")

    def test_file_only_fn_hunted_resolves_to_sidecar(self):
        """A file-only target over a file WHOSE function was hunted resolves to the
        per-fn sidecar (file-level join)."""
        ws = _ws()
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "logic.rs").write_text(
            "pub fn transfer(a: u128) { do_it(a); }\n", encoding="utf-8")
        scd = ws / ".auditooor" / "hunt_findings_sidecars"
        scd.mkdir(parents=True, exist_ok=True)
        (scd / "hunt_b0002_transfer.json").write_text(json.dumps({
            "task_id": "ni-b0002-transfer",
            "function_anchor": {"file": "src/logic.rs", "fn": "transfer"},
            "result": {"verdict": "KILL", "applies_to_target": "no",
                       "file_line": "src/logic.rs:1", "reasoning": "guarded"},
        }), encoding="utf-8")
        hunt = ADJ._load_hunt_verdicts(ws)
        v = ADJ._adjudicate_lead(
            {"id": "z", "title": "unhunted-surface target: logic.rs"}, ws, None, None, hunt)
        self.assertIsNotNone(v)
        self.assertEqual(v["evidence_class"], "covered-in-scope")
        self.assertTrue((ws / v["evidence_ref"]).is_file())

    # r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
    def test_rerun_merges_prior_verdicts_without_loss(self):
        """S4 guard: re-running adjudicate() must NOT drop previously-resolved
        verdicts whose evidence still resolves, even when the lead is no longer
        in the live queue and the per-lead hunt signal is gone. The
        prune-then-union merge keyed by lead_id preserves them.

        SPEC-CORRECTION (noted in StructuredOutput): the spec's worked example
        deletes residual_hunt_verdicts.json and expects the COVERED-IN-SCOPE
        verdict preserved. That contradicts the spec's own pruning predicate
        (`evidence_ref still resolves to a real file`) AND the gate (lines
        491-496): a covered-in-scope verdict's evidence_ref IS
        residual_hunt_verdicts.json, so once it is deleted the GATE itself stops
        crediting that verdict - keeping it in the ledger would be a verdict the
        gate ignores (zombie credit). The honest behavior is: durable verdicts
        whose evidence_ref points at a stable in-scope artifact (interface /
        vendored / covered-in-scope while its source sidecar still exists) are
        preserved across reruns; a covered-in-scope verdict whose sidecar is
        deleted is correctly retired (not zombie-preserved). This test exercises
        BOTH the deleted-from-queue durability case and the still-present-sidecar
        covered case."""
        ws = _ws()
        (ws / "src" / "Router.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract Router { function swap() external {} }\n")
        # a genuine per-lead hunt verdict for Router.sol::swap (covered-in-scope)
        (ws / ".auditooor" / "residual_hunt_verdicts.json").write_text(json.dumps([
            {"lead_id": "HQ-ROUTER", "function": "swap", "file_line": "src/Router.sol:1",
             "verdict": "refuted", "reason": "slippage-bounded; no value drain path"},
        ]))
        _queue(ws, [
            ("L1", "unhunted-surface target: IFoo.sol::bar"),        # interface (stable ref)
            ("S3", "unhunted-surface target: Router.sol::swap"),     # covered-in-scope
        ])
        # run1: both resolved, ledger holds both verdicts
        r1 = ADJ.adjudicate(ws)
        self.assertEqual(r1["resolved"], 2, r1["by_class"])
        led_path = ws / ".auditooor" / "unhunted_terminal_verdicts.json"
        d1 = json.loads(led_path.read_text())
        ids1 = {v["lead_id"] for v in d1["verdicts"]}
        self.assertEqual(ids1, {"L1", "S3"})

        # run2: DROP both leads from the live queue (so they are not even
        # abandoned this run -> no fresh recomputation) but KEEP both evidence
        # sidecars intact. The merge must preserve BOTH durable verdicts.
        _queue(ws, [])
        ADJ.adjudicate(ws)
        d2 = json.loads(led_path.read_text())
        ids2 = {v["lead_id"] for v in d2["verdicts"]}
        self.assertIn("S3", ids2, "merge must preserve the prior covered-in-scope verdict (sidecar intact)")
        self.assertIn("L1", ids2, "merge must preserve the prior interface verdict")
        cls2 = {v["lead_id"]: v["evidence_class"] for v in d2["verdicts"]}
        self.assertEqual(cls2.get("S3"), "covered-in-scope")
        self.assertEqual(cls2.get("L1"), "interface-declaration")

        # run3: now DELETE the covered-in-scope sidecar. Per the gate's own
        # resolve-check the covered verdict can no longer be credited, so the
        # merge correctly RETIRES it while the interface verdict (stable ref)
        # survives.
        (ws / ".auditooor" / "residual_hunt_verdicts.json").unlink()
        ADJ.adjudicate(ws)
        d3 = json.loads(led_path.read_text())
        ids3 = {v["lead_id"] for v in d3["verdicts"]}
        self.assertIn("L1", ids3, "interface verdict (stable ref) survives")
        self.assertNotIn("S3", ids3,
                         "covered verdict whose sidecar was deleted is retired (gate would ignore it anyway)")

    def test_merge_prunes_stale_unresolvable_ref(self):
        """S4 guard: the union must NOT resurrect gate-rejected credit. A prior
        verdict whose evidence_ref points to a now-missing file, and one citing
        the shared coverage_report.json, are pruned (not carried forward)."""
        ws = _ws()
        led_path = ws / ".auditooor" / "unhunted_terminal_verdicts.json"
        # pre-seed a ledger with two stale entries + one still-valid entry.
        led_path.write_text(json.dumps({
            "schema": "auditooor.unhunted_terminal_verdicts.v1",
            "verdicts": [
                # stale: evidence_ref no longer resolves to a real file
                {"lead_id": "STALE1", "title": "unhunted-surface target: Gone.sol::g",
                 "verdict": "refuted", "evidence_class": "covered-in-scope",
                 "evidence_ref": "src/Gone.sol"},
                # stale: shared coverage_report.json ref (gate-rejected)
                {"lead_id": "STALE2", "title": "unhunted-surface target: Cov.sol::c",
                 "verdict": "refuted", "evidence_class": "covered-in-scope",
                 "evidence_ref": ".auditooor/coverage_report.json"},
                # stale: evidence_class no longer emitted by the current tool
                {"lead_id": "STALE3", "title": "unhunted-surface target: Old.sol::o",
                 "verdict": "refuted", "evidence_class": "out-of-scope-surface",
                 "evidence_ref": "src/interfaces/IFoo.sol"},
                # valid: interface evidence_ref resolves + class is current
                {"lead_id": "KEEP1", "title": "unhunted-surface target: IFoo.sol::bar",
                 "verdict": "refuted", "evidence_class": "interface-declaration",
                 "evidence_ref": "src/interfaces/IFoo.sol"},
            ],
        }))
        # no live abandoned leads this run (empty queue) so only the merge of
        # prior verdicts decides the output.
        _queue(ws, [])
        ADJ.adjudicate(ws)
        d = json.loads(led_path.read_text())
        ids = {v["lead_id"] for v in d["verdicts"]}
        self.assertNotIn("STALE1", ids, "missing-file ref must be pruned")
        self.assertNotIn("STALE2", ids, "coverage_report.json ref must be pruned")
        self.assertNotIn("STALE3", ids, "non-current evidence_class must be pruned")
        self.assertIn("KEEP1", ids, "valid prior verdict must be preserved")

    def test_non_terminal_ledger_verdict_does_not_credit(self):
        ws = _ws()
        _queue(ws, [("L8", "unhunted-surface target: Core.sol::f")])
        (ws / ".auditooor" / "unhunted_terminal_verdicts.json").write_text(json.dumps({
            "verdicts": [{"lead_id": "L8", "title": "unhunted-surface target: Core.sol::f",
                          "verdict": "ready_for_poc_planning",  # non-terminal
                          "evidence_ref": "src/Core.sol"}],
        }))
        g = GATE.evaluate(str(ws))
        self.assertEqual(g["stats"]["resolved_by_ledger"], 0)


class TestResolveUnitFileScoping(unittest.TestCase):
    """_resolve_unit_file must not descend into heavy generated dirs (.auditooor
    etc.) and must memoize, so a 21k-lead run does not re-walk a 395M+ workspace
    once per lead (this wedged the stage on the polygon fork)."""

    def test_does_not_descend_into_auditooor(self):
        ws = _ws()
        # basename present ONLY under .auditooor -> must be skipped -> None
        (ws / ".auditooor" / "OnlyInAud.sol").write_text("x")
        ADJ._RESOLVE_PATH_CACHE.clear()
        self.assertIsNone(ADJ._resolve_unit_file(ws, "OnlyInAud.sol"))

    def test_resolves_real_src_file_and_caches(self):
        ws = _ws()
        ADJ._RESOLVE_PATH_CACHE.clear()
        p = ADJ._resolve_unit_file(ws, "Core.sol")
        self.assertIsNotNone(p)
        self.assertNotIn(".auditooor", p.parts)
        self.assertEqual(p, ws / "src" / "Core.sol")
        # cached by basename
        self.assertIn("Core.sol", ADJ._RESOLVE_PATH_CACHE)
        self.assertEqual(ADJ._RESOLVE_PATH_CACHE["Core.sol"], p)


class TestWorkflowDrillVerdictIngestion(unittest.TestCase):
    """SSV loop fix 2026-06-23: the canonical per-fn hunt emits workflow-drill
    sidecars (verdict KILL + source-cited file_line) to ws/.auditooor/
    hunt_findings_sidecars/, but _load_hunt_verdicts read ONLY
    residual_hunt_verdicts.json -> a surface that WAS hunted stayed abandoned.
    Now those KILL verdicts are ingested as `refuted`. False-green-safe: needs a
    KILL/applies=no verdict WITH a real file_line, and the surface fn must match."""
    def _ws(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor" / "hunt_findings_sidecars").mkdir(parents=True)
        return ws

    def _sidecar(self, ws, task_id, fn_line, verdict="KILL", anchor=None):
        body = {"status": "ok", "task_id": task_id,
                "source": "workflow-drill-sidecar-emit",
                "result": json.dumps({"verdict": verdict, "applies_to_target": "no",
                                      "file_line": fn_line, "reasoning": "ruled out"})}
        if anchor:
            body["function_anchor"] = anchor
        (ws / ".auditooor" / "hunt_findings_sidecars" / f"{task_id}.json").write_text(
            json.dumps(body))

    def test_kill_sidecar_ingested_as_refuted(self):
        ws = self._ws()
        self._sidecar(ws, "ssv-b0007-registerOperator", "src/Ops.sol:31")
        v = ADJ._load_hunt_verdicts(ws)
        hit = [x for x in v if x["function"] == "registerOperator"]
        self.assertTrue(hit, "KILL sidecar must be ingested")
        self.assertEqual(hit[0]["verdict"], "refuted")

    def test_contract_hint_suffix_parses_to_fn_not_hint(self):
        # ssv-b0012-getMinimumLiquidationCollateral-SSVViews -> fn is the FIRST
        # token after the batch number, NOT the trailing -SSVViews disambiguator.
        ws = self._ws()
        self._sidecar(ws, "ssv-b0012-getMinimumLiquidationCollateral-SSVViews",
                      "src/Views.sol:558")
        v = ADJ._load_hunt_verdicts(ws)
        fns = {x["function"] for x in v}
        self.assertIn("getMinimumLiquidationCollateral", fns)
        self.assertNotIn("SSVViews", fns)

    def test_bare_prose_no_fileline_not_ingested(self):
        ws = self._ws()
        self._sidecar(ws, "ssv-b0001-foo", "N/A conceptual")  # no real file:line
        v = ADJ._load_hunt_verdicts(ws)
        self.assertEqual([x for x in v if x["function"] == "foo"], [])

    def test_explicit_anchor_preferred(self):
        ws = self._ws()
        self._sidecar(ws, "ssv-fc-x-2", "src/Ops.sol:2",
                      anchor={"file": "src/Ops.sol", "fn": "deposit", "line": 2})
        v = ADJ._load_hunt_verdicts(ws)
        self.assertIn("deposit", {x["function"] for x in v})


if __name__ == "__main__":
    unittest.main(verbosity=2)
