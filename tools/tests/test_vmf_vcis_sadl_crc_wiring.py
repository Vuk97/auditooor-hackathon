#!/usr/bin/env python3
"""Guard tests for the VMF/VCIS/SADL/CRC/SIDL/ORL wiring.

Six assertion groups (matching the task requirements):

  1. DAG-level: audit-deep.sh step list now includes the 6 tools
     (value-moving-functions, vcis, sadl, crc, share-inflation-lane,
     oracle-reachability-lane) - verified by grepping the source of
     audit-deep.sh for the step headers and tool invocations.

  2. Fold test: after auto-coverage-closer.run(), SADL, CRC, SIDL, and ORL
     hypotheses (seeded as .jsonl artifacts in <ws>/.auditooor/) appear in
     per_fn_hacker_questions.jsonl with verdict=needs-fuzz and correct
     attack_class values.

  3. No-auto-credit test (lanes_in_dag): wiring alone does NOT raise
     per_function_verified above 0 in mutation_verify_coverage.json, and does
     NOT flip any audit-honesty gate to pass when value-moving functions are
     present but no real fuzz+mutation run has occurred.

  4. VCIS registration test: after audit-deep Step 21b registers VCIS
     harnesses, mutation_verify_coverage.json contains a vcis_registration
     block with verdict=needs-fuzz entries and per_function_verified remains 0.

  5. SIDL-specific: Step 24 header + tool present in audit-deep.sh; SIDL
     hypotheses fold into corpus with verdict=needs-fuzz; no-auto-credit.

  6. ORL-specific: Step 25 header + tool present in audit-deep.sh; ORL
     hypotheses fold into corpus with verdict=needs-fuzz and
     attack_class=oracle-price-manipulation; no-auto-credit.

All tests are hermetic (tmpdir workspaces), no network, no real fuzz engines.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Repo root + tool loader
# ---------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parent.parent.parent  # tools/ -> repo root
_TOOLS = _REPO / "tools"

_AUDIT_DEEP_SH = _TOOLS / "audit-deep.sh"
_AUTO_COVERAGE_CLOSER = _TOOLS / "auto-coverage-closer.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Helper: minimal workspace builder
# ---------------------------------------------------------------------------
def _make_ws() -> Path:
    td = Path(tempfile.mkdtemp())
    (td / ".auditooor").mkdir()
    return td


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


# ---------------------------------------------------------------------------
# Test 1: DAG-level - audit-deep.sh contains Steps 20-23 for all 4 tools
# ---------------------------------------------------------------------------
class TestAuditDeepDAGIncludes4Tools(unittest.TestCase):

    def setUp(self):
        if not _AUDIT_DEEP_SH.is_file():
            self.skipTest("audit-deep.sh not found")
        self._src = _AUDIT_DEEP_SH.read_text(encoding="utf-8")

    def test_step20_vmf_header_present(self):
        self.assertIn("Step 20", self._src,
                      "audit-deep.sh must include Step 20 (VMF prereq)")

    def test_step20_vmf_tool_invoked(self):
        self.assertIn("value-moving-functions.py", self._src,
                      "audit-deep.sh must invoke value-moving-functions.py")

    def test_step21_vcis_header_present(self):
        self.assertIn("Step 21", self._src,
                      "audit-deep.sh must include Step 21 (VCIS)")

    def test_step21_vcis_tool_invoked(self):
        self.assertIn("value-conservation-invariant-synth.py", self._src,
                      "audit-deep.sh must invoke value-conservation-invariant-synth.py")

    def test_step22_sadl_header_present(self):
        self.assertIn("Step 22", self._src,
                      "audit-deep.sh must include Step 22 (SADL)")

    def test_step22_sadl_tool_invoked(self):
        self.assertIn("self-dealing-hypothesis-lane.py", self._src,
                      "audit-deep.sh must invoke self-dealing-hypothesis-lane.py")

    def test_step23_crc_header_present(self):
        self.assertIn("Step 23", self._src,
                      "audit-deep.sh must include Step 23 (CRC)")

    def test_step23_crc_tool_invoked(self):
        self.assertIn("callback-reentrancy-composition.py", self._src,
                      "audit-deep.sh must invoke callback-reentrancy-composition.py")

    def test_step20_before_step21(self):
        idx20 = self._src.find("Step 20")
        idx21 = self._src.find("Step 21")
        self.assertGreater(idx20, 0)
        self.assertGreater(idx21, idx20,
                           "Step 21 must come after Step 20 in audit-deep.sh")

    def test_step21_before_step22(self):
        idx21 = self._src.find("Step 21")
        idx22 = self._src.find("Step 22")
        self.assertGreater(idx22, idx21,
                           "Step 22 must come after Step 21 in audit-deep.sh")

    def test_step22_before_step23(self):
        idx22 = self._src.find("Step 22")
        idx23 = self._src.find("Step 23")
        self.assertGreater(idx23, idx22,
                           "Step 23 must come after Step 22 in audit-deep.sh")

    def test_step24_sidl_header_present(self):
        self.assertIn("Step 24", self._src,
                      "audit-deep.sh must include Step 24 (SIDL)")

    def test_step24_sidl_tool_invoked(self):
        self.assertIn("share-inflation-lane.py", self._src,
                      "audit-deep.sh must invoke share-inflation-lane.py")

    def test_step23_before_step24(self):
        idx23 = self._src.find("Step 23")
        idx24 = self._src.find("Step 24")
        self.assertGreater(idx24, idx23,
                           "Step 24 must come after Step 23 in audit-deep.sh")

    def test_step25_orl_header_present(self):
        self.assertIn("Step 25", self._src,
                      "audit-deep.sh must include Step 25 (ORL)")

    def test_step25_orl_tool_invoked(self):
        self.assertIn("oracle-reachability-lane.py", self._src,
                      "audit-deep.sh must invoke oracle-reachability-lane.py")

    def test_step24_before_step25(self):
        idx24 = self._src.find("Step 24")
        idx25 = self._src.find("Step 25")
        self.assertGreater(idx25, idx24,
                           "Step 25 must come after Step 24 in audit-deep.sh")

    def test_step26_rdl_header_present(self):
        self.assertIn("Step 26", self._src,
                      "audit-deep.sh must include Step 26 (RDL)")

    def test_step26_rdl_tool_invoked(self):
        self.assertIn("rounding-drain-lane.py", self._src,
                      "audit-deep.sh must invoke rounding-drain-lane.py")

    def test_step25_before_step26(self):
        idx25 = self._src.find("Step 25")
        idx26 = self._src.find("Step 26")
        self.assertGreater(idx26, idx25,
                           "Step 26 must come after Step 25 in audit-deep.sh")

    def test_go_advisory_lanes_auto_run_in_audit_deep(self):
        # The 9 wave-2 Go advisory lanes (G2/G4/G5/G6/G7/G8/G11/G12/G13) must be
        # AUTO-RUN in audit-deep with their AUDITOOR_G* envs set, else they are
        # built-but-dormant orphans that never fire in a real audit
        # (methodology_capability_must_be_wired_not_just_built).
        self.assertIn("go-detector-runner.py", self._src,
                      "audit-deep.sh must invoke go-detector-runner.py for advisory lanes")
        for env in ("AUDITOOR_G2_ATTACKER_DIVISOR_ZERO=1",
                    "AUDITOOR_G12_GOROUTINE_NO_RECOVER=1",
                    "AUDITOOR_G13_CTX_CANCELLATION_IGNORED_VERDICT=1"):
            self.assertIn(env, self._src,
                          f"audit-deep.sh must set {env} so the lane fires")

    def test_rust_advisory_lanes_auto_run_in_audit_deep(self):
        # The 6 wave-2 Rust advisory axes must be AUTO-RUN in audit-deep with their
        # AUDITOOR_RUST_*_AXIS envs set, else rust-detector-runner is an orphan (it is
        # not invoked anywhere else in the pipeline).
        self.assertIn("rust-detector-runner.py", self._src,
                      "audit-deep.sh must invoke rust-detector-runner.py for advisory axes")
        for env in ("AUDITOOR_RUST_OOB_AXIS=1",
                    "AUDITOOR_RUST_LOCKPOISON_AXIS=1",
                    "AUDITOOR_RUST_DROPSAFETY_AXIS=1"):
            self.assertIn(env, self._src,
                          f"audit-deep.sh must set {env} so the Rust axis fires")


# ---------------------------------------------------------------------------
# Test 2: Fold - SADL + CRC hypotheses appear in per_fn_hacker_questions.jsonl
#          with verdict=needs-fuzz after auto-coverage-closer.run()
# ---------------------------------------------------------------------------
class TestLaneHypothesesFoldedIntoCorpus(unittest.TestCase):

    def setUp(self):
        if not _AUTO_COVERAGE_CLOSER.is_file():
            self.skipTest("auto-coverage-closer.py not found")
        self._mod = _load_module("auto_coverage_closer_wiring_test",
                                 _AUTO_COVERAGE_CLOSER)

    def _make_sadl_record(self, fn="transfer", param_a="payer", param_b="receiver"):
        return {
            "workspace": "/tmp/ws",
            "file": "src/Vault.sol",
            "function": fn,
            "language": "sol",
            "param_a": param_a,
            "param_b": param_b,
            "collapse_expr": f"{param_a} == {param_b}",
            "note": "self-dealing collapse on payer/receiver",
            "attack_class": "self-dealing-identity-collapse",
            "source": "SADL",
            "verdict": "needs-fuzz",
            "vcis_oracle_hint": "balanceOf >= creditOf",
            "selftake_guard_note": "no guard on this pair",
        }

    def _make_crc_record(self, window="flashLoan", target="take"):
        return {
            "workspace": "/tmp/ws",
            "file": "src/Vault.sol",
            "function": window,
            "language": "sol",
            "window_line": 42,
            "callback_evidence": "onFlashLoan(",
            "guard_detected": False,
            "reentry_target_file": "src/Vault.sol",
            "reentry_target": target,
            "note": f"re-enter {target} from {window} callback",
            "attack_class": "reentrancy-into-settlement",
            "source": "CRC",
            "verdict": "needs-fuzz",
        }

    def test_sadl_hypotheses_folded_with_needs_fuzz(self):
        ws = _make_ws()
        sadl_path = ws / ".auditooor" / "self_dealing_hypotheses.jsonl"
        _write_jsonl(sadl_path, [self._make_sadl_record()])

        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-1")
        self.assertGreater(result["appended"], 0,
                           "at least one SADL record should be appended")

        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(corpus_path.is_file(), "per_fn_hacker_questions.jsonl must be created")

        records = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
        sadl_records = [r for r in records if r.get("source") == "SADL"]
        self.assertGreater(len(sadl_records), 0, "SADL records must appear in corpus")
        for r in sadl_records:
            self.assertEqual(r["verdict"], "needs-fuzz",
                             "SADL fold must carry verdict=needs-fuzz (no-auto-credit)")
            self.assertEqual(r["attack_class"], "self-dealing-identity-collapse")
            self.assertIn("[SADL]", r["question"])

    def test_crc_hypotheses_folded_with_needs_fuzz(self):
        ws = _make_ws()
        crc_path = ws / ".auditooor" / "callback_reentrancy_hypotheses.jsonl"
        _write_jsonl(crc_path, [self._make_crc_record()])

        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-2")
        self.assertGreater(result["appended"], 0)

        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        records = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
        crc_records = [r for r in records if r.get("source") == "CRC"]
        self.assertGreater(len(crc_records), 0, "CRC records must appear in corpus")
        for r in crc_records:
            self.assertEqual(r["verdict"], "needs-fuzz",
                             "CRC fold must carry verdict=needs-fuzz (no-auto-credit)")
            self.assertEqual(r["attack_class"], "reentrancy-into-settlement")
            self.assertIn("[CRC]", r["question"])

    def _make_sidl_record(self, fn="deposit", ac="share-inflation-donation"):
        return {
            "workspace": "/tmp/ws",
            "file": "src/Vault.sol",
            "function": fn,
            "language": "sol",
            "attack_class": ac,
            "note": "share inflation via donation",
            "source": "SIDL",
            "verdict": "needs-fuzz",
        }

    def test_sidl_hypotheses_folded_with_needs_fuzz(self):
        ws = _make_ws()
        sidl_path = ws / ".auditooor" / "share_inflation_hypotheses.jsonl"
        _write_jsonl(sidl_path, [self._make_sidl_record()])

        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-sidl-1")
        self.assertGreater(result["appended"], 0,
                           "at least one SIDL record should be appended")

        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(corpus_path.is_file(), "per_fn_hacker_questions.jsonl must be created")

        records = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
        sidl_records = [r for r in records if r.get("source") == "SIDL"]
        self.assertGreater(len(sidl_records), 0, "SIDL records must appear in corpus")
        for r in sidl_records:
            self.assertEqual(r["verdict"], "needs-fuzz",
                             "SIDL fold must carry verdict=needs-fuzz (no-auto-credit)")
            self.assertEqual(r["attack_class"], "share-inflation-donation")
            self.assertIn("[SIDL]", r["question"])

    def _make_orl_record(self, fn="swap", read_kind="cosmos-oracle-GetPrice"):
        return {
            "workspace": "/tmp/ws",
            "file": "src/Exchange.sol",
            "function": fn,
            "language": "sol",
            "read_kind": read_kind,
            "value_loss_path": "stale price drives under-valued swap output",
            "note": "oracle read unguarded",
            "attack_class": "oracle-price-manipulation",
            "source": "ORL",
            "verdict": "needs-fuzz",
        }

    def test_orl_hypotheses_folded_with_needs_fuzz(self):
        ws = _make_ws()
        orl_path = ws / ".auditooor" / "oracle_reachability_hypotheses.jsonl"
        _write_jsonl(orl_path, [self._make_orl_record()])

        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-orl-1")
        self.assertGreater(result["appended"], 0,
                           "at least one ORL record should be appended")

        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(corpus_path.is_file(), "per_fn_hacker_questions.jsonl must be created")

        records = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
        orl_records = [r for r in records if r.get("source") == "ORL"]
        self.assertGreater(len(orl_records), 0, "ORL records must appear in corpus")
        for r in orl_records:
            self.assertEqual(r["verdict"], "needs-fuzz",
                             "ORL fold must carry verdict=needs-fuzz (no-auto-credit)")
            self.assertEqual(r["attack_class"], "oracle-price-manipulation")
            self.assertIn("[ORL]", r["question"])

    def test_fold_skips_gracefully_when_no_jsonl_files(self):
        ws = _make_ws()
        # No lane-hypothesis files seeded -> every registered lane reports absent.
        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-3")
        self.assertEqual(result["appended"], 0)
        self.assertIn("skipped_files", result)
        # Future-proof: assert every CANONICAL lane label appears as absent rather
        # than hard-coding a count (the lane registry grows over time - RDL, MOL,
        # ACL-COV, IUL were added after this test's original count of 5, which is
        # what broke it). A new lane never breaks this; only removing one does.
        _skipped = " ".join(result["skipped_files"])
        for _label in ("SADL", "CRC", "SIDL", "ORL", "RDL"):
            self.assertIn(_label, _skipped,
                          f"canonical lane {_label} must report as absent (skipped)")
        self.assertGreaterEqual(len(result["skipped_files"]), 5)

    def test_fold_appends_not_overwrites_existing_corpus(self):
        ws = _make_ws()
        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        # Pre-existing record from arsenal pass.
        pre_existing = {
            "schema_version": "auditooor.per_fn_hacker_questions.v1",
            "workspace": "ws",
            "run_id": "r1",
            "unit_id": "foo",
            "source_path": "src/Foo.sol",
            "question": "Can foo overflow?",
        }
        _write_jsonl(corpus_path, [pre_existing])

        sadl_path = ws / ".auditooor" / "self_dealing_hypotheses.jsonl"
        _write_jsonl(sadl_path, [self._make_sadl_record()])

        self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-4")

        records = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
        # Pre-existing record must survive.
        pre = [r for r in records if r.get("unit_id") == "foo"]
        self.assertEqual(len(pre), 1, "pre-existing record must not be overwritten")
        # SADL record must be appended.
        sadl_recs = [r for r in records if r.get("source") == "SADL"]
        self.assertGreater(len(sadl_recs), 0)

    def _make_rdl_record(self, fn="accrueInterest", op="mulDivDown"):
        return {
            "workspace": "/tmp/ws",
            "file": "src/Vault.sol",
            "function": fn,
            "language": "sol",
            "rounding_op": f"{op}(units, fee, WAD)",
            "rounding_site": f"src/Vault.sol:~386",
            "direction": "DOWN",
            "direction_reason": f"{op} rounds down on intake/fee path - protocol under-collects.",
            "value_path": "intake",
            "conservation_invariant": "per-call drain <= 1 wei; cumulative N*1 must be bounded",
            "vcis_miss_reason": "VCIS solvency-floor tolerates 1-wei per-op drift",
            "attack_class": "rounding-drain",
            "source": "RDL",
            "verdict": "needs-fuzz",
        }

    def test_rdl_hypotheses_folded_with_needs_fuzz(self):
        ws = _make_ws()
        rdl_path = ws / ".auditooor" / "rounding_drain_hypotheses.jsonl"
        _write_jsonl(rdl_path, [self._make_rdl_record()])

        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-rdl-1")
        self.assertGreater(result["appended"], 0,
                           "at least one RDL record should be appended")

        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(corpus_path.is_file(), "per_fn_hacker_questions.jsonl must be created")

        records = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
        rdl_records = [r for r in records if r.get("source") == "RDL"]
        self.assertGreater(len(rdl_records), 0, "RDL records must appear in corpus")
        for r in rdl_records:
            self.assertEqual(r["verdict"], "needs-fuzz",
                             "RDL fold must carry verdict=needs-fuzz (no-auto-credit)")
            self.assertEqual(r["attack_class"], "rounding-drain")
            self.assertIn("[RDL]", r["question"])

    def _make_go_adv_record(self, fn="GetNAVPerShare", src="G2",
                            pid="go.cosmos.attacker_divisor_zero_unchecked",
                            ac="divide-by-zero-chain-halt"):
        # Mirrors the real go-detector-runner advisory record shape (G2 shown).
        return {
            "workspace": "/tmp/ws",
            "file": "src/vault/keeper/valuation.go",
            "line": 208,
            "function": fn,
            "divisor": "vault.TotalShares.Amount",
            "operator": "Quo",
            "snippet": "return tvv.Quo(vault.TotalShares.Amount), nil",
            "pattern_id": pid,
            "attack_class": ac,
            "source": src,
            "verdict": "needs-fuzz",
        }

    def test_go_advisory_hypotheses_folded_with_needs_fuzz(self):
        # G2 attacker-divisor is one of the 9 wave-2 Go advisory lanes wired in
        # audit-deep Step 5b. A folded record proves CREDITED (serving-join).
        ws = _make_ws()
        p = ws / ".auditooor" / "attacker_divisor_zero_hypotheses.jsonl"
        _write_jsonl(p, [self._make_go_adv_record()])

        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-goadv-1")
        self.assertGreater(result["appended"], 0,
                           "at least one GO-ADV record should be appended")

        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(corpus_path.is_file())
        records = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
        go_records = [r for r in records if r.get("source") == "GO-ADV"]
        self.assertGreater(len(go_records), 0, "GO-ADV records must appear in corpus")
        for r in go_records:
            self.assertEqual(r["verdict"], "needs-fuzz",
                             "GO-ADV fold must carry verdict=needs-fuzz (no-auto-credit)")
            self.assertEqual(r["attack_class"], "divide-by-zero-chain-halt")
            self.assertIn("[G2]", r["question"])

    def test_go_advisory_all_lane_files_registered(self):
        # Non-vacuity guard: EVERY registered Go advisory jsonl must be a fold
        # source. A dead-end jsonl = an uncredited orphan (the exact class this
        # wiring fixes). The floor (>=13, incl G9 decode-consumption) catches an
        # accidental lane removal; ``appended == len(rels)`` catches a dead-end.
        ws = _make_ws()
        rels = self._mod.GO_ADVISORY_HYPOTHESES_REL
        self.assertGreaterEqual(
            len(rels), 13, "the known Go advisory lane floor (incl G9)")
        for i, rel in enumerate(rels):
            _write_jsonl(ws / rel, [self._make_go_adv_record(fn=f"fn{i}", src=f"G{i}")])
        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-goadv-all")
        self.assertEqual(result["appended"], len(rels),
                         "all Go advisory lane files must fold into the hunt corpus "
                         "(no dead-end orphan)")

    def _make_rust_adv_record(self, fn="deserialize_header", axis="rust-OOB",
                              ac="untrusted_ingress_slice_oob_panic"):
        # Mirrors the real rust-detector-runner advisory record shape.
        return {
            "file": "src/net/decode.rs",
            "line": 88,
            "function": fn,
            "axis": axis,
            "attack_class": ac,
            "snippet": "let body = &buf[len..end];",
            "source": "rust-detector-runner.py:RU3",
            "verdict": "needs-fuzz",
        }

    def test_rust_advisory_hypotheses_folded_with_needs_fuzz(self):
        ws = _make_ws()
        p = ws / ".auditooor" / "rust_oob_hypotheses.jsonl"
        _write_jsonl(p, [self._make_rust_adv_record()])
        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-rustadv-1")
        self.assertGreater(result["appended"], 0,
                           "at least one RUST-ADV record should be appended")
        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        records = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
        rust_records = [r for r in records if r.get("source") == "RUST-ADV"]
        self.assertGreater(len(rust_records), 0, "RUST-ADV records must appear in corpus")
        for r in rust_records:
            self.assertEqual(r["verdict"], "needs-fuzz",
                             "RUST-ADV fold must carry verdict=needs-fuzz (no-auto-credit)")
            self.assertEqual(r["attack_class"], "untrusted_ingress_slice_oob_panic")
            self.assertIn("[RUST-ADV", r["question"])

    def test_rust_advisory_all_lane_files_registered(self):
        # Non-vacuity guard: EVERY registered Rust advisory jsonl must be a fold
        # source (a dead-end jsonl = an uncredited orphan). Floor (>=6) catches a
        # removal; ``appended == len(rels)`` catches a dead-end. (Pre-existing
        # stale count 6 vs the current 7 registered axes corrected in passing.)
        ws = _make_ws()
        rels = self._mod.RUST_ADVISORY_HYPOTHESES_REL
        self.assertGreaterEqual(
            len(rels), 6, "the known Rust advisory axis floor")
        for i, rel in enumerate(rels):
            _write_jsonl(ws / rel, [self._make_rust_adv_record(fn=f"fn{i}", axis=f"rust-ax{i}")])
        result = self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-rustadv-all")
        self.assertEqual(result["appended"], len(rels),
                         "all Rust advisory lane files must fold into the hunt corpus")

    def test_no_em_dash_in_folded_records(self):
        ws = _make_ws()
        sadl_path = ws / ".auditooor" / "self_dealing_hypotheses.jsonl"
        crc_path  = ws / ".auditooor" / "callback_reentrancy_hypotheses.jsonl"
        sidl_path = ws / ".auditooor" / "share_inflation_hypotheses.jsonl"
        orl_path  = ws / ".auditooor" / "oracle_reachability_hypotheses.jsonl"
        rdl_path  = ws / ".auditooor" / "rounding_drain_hypotheses.jsonl"
        _write_jsonl(sadl_path, [self._make_sadl_record()])
        _write_jsonl(crc_path,  [self._make_crc_record()])
        _write_jsonl(sidl_path, [self._make_sidl_record()])
        _write_jsonl(orl_path,  [self._make_orl_record()])
        _write_jsonl(rdl_path,  [self._make_rdl_record()])

        self._mod._fold_lane_hypotheses_into_corpus(ws, "run-test-5")

        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        raw = corpus_path.read_text(encoding="utf-8")
        self.assertNotIn("—", raw, "no em-dash (U+2014) in folded corpus")
        self.assertNotIn("–", raw, "no en-dash (U+2013) in folded corpus")


# ---------------------------------------------------------------------------
# Test 3 + 4: No-auto-credit + VCIS registration
# ---------------------------------------------------------------------------
class TestNoAutoCredit(unittest.TestCase):
    """Wiring alone must NOT raise per_function_verified above 0 and must NOT
    flip audit-honesty gates to pass.
    """

    def _simulate_step21b_registration(self, ws: Path, vcis_manifest: dict) -> dict:
        """Re-run the Step 21b inline Python from audit-deep.sh as a Python call
        so we can assert its output without running the full shell script."""
        mvc_path = ws / ".auditooor" / "mutation_verify_coverage.json"
        vcis_dir = ws / ".auditooor" / "vcis"
        vcis_dir.mkdir(parents=True, exist_ok=True)
        vcis_manifest_path = vcis_dir / "vcis_manifest.json"
        vcis_manifest_path.write_text(json.dumps(vcis_manifest), encoding="utf-8")

        # Replicate the Step 21b logic directly (same code as in audit-deep.sh).
        existing: dict = {}
        if mvc_path.is_file():
            try:
                existing = json.loads(mvc_path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        if not isinstance(existing, dict):
            existing = {}

        verdicts = vcis_manifest.get("verdicts", [])
        reg = existing.get("vcis_registration") or {}
        for v in verdicts:
            key = f"{v.get('file', '?')}::{v.get('function', '?')}"
            if key not in reg:
                reg[key] = {
                    "file": v.get("file"),
                    "function": v.get("function"),
                    "property_form": v.get("property_form"),
                    "harness_path": str(vcis_manifest_path.parent / "Properties_VCIS.sol"),
                    "verdict": "needs-fuzz",
                    "note": "registered by audit-deep Step 21b; run mutation-verify-coverage.py to earn genuine credit",
                }
        existing["vcis_registration"] = reg
        counts = existing.get("counts") or {}
        if "per_function_verified" not in counts:
            counts["per_function_verified"] = 0
        if "vcis_registered" not in counts:
            counts["vcis_registered"] = 0
        counts["vcis_registered"] = len(reg)
        existing["counts"] = counts
        existing.setdefault("schema", "auditooor.mutation_verify_coverage.v1")
        mvc_path.parent.mkdir(parents=True, exist_ok=True)
        mvc_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
        return existing

    def test_vcis_registration_does_not_increment_per_function_verified(self):
        ws = _make_ws()
        vcis_manifest = {
            "schema": "vcis_manifest.v1",
            "verdicts": [
                {"file": "src/Vault.sol", "function": "take",
                 "property_form": "solvency-floor", "verdict": "needs-fuzz"},
                {"file": "src/Vault.sol", "function": "flashLoan",
                 "property_form": "delta-conservation", "verdict": "needs-fuzz"},
            ],
        }
        mvc = self._simulate_step21b_registration(ws, vcis_manifest)

        # per_function_verified must remain 0.
        counts = mvc.get("counts", {})
        self.assertEqual(counts.get("per_function_verified", 0), 0,
                         "Step 21b must NOT set per_function_verified > 0 (no-auto-credit)")

    def test_vcis_registration_block_contains_needs_fuzz_entries(self):
        ws = _make_ws()
        vcis_manifest = {
            "schema": "vcis_manifest.v1",
            "verdicts": [
                {"file": "src/Vault.sol", "function": "take",
                 "property_form": "solvency-floor", "verdict": "needs-fuzz"},
            ],
        }
        mvc = self._simulate_step21b_registration(ws, vcis_manifest)
        reg = mvc.get("vcis_registration", {})
        self.assertGreater(len(reg), 0, "vcis_registration block must be populated")
        for key, entry in reg.items():
            self.assertEqual(entry["verdict"], "needs-fuzz",
                             f"entry {key} must carry verdict=needs-fuzz")

    def test_vcis_registration_sets_vcis_registered_count(self):
        ws = _make_ws()
        vcis_manifest = {
            "schema": "vcis_manifest.v1",
            "verdicts": [
                {"file": "src/A.sol", "function": "funcA",
                 "property_form": "solvency-floor", "verdict": "needs-fuzz"},
                {"file": "src/B.sol", "function": "funcB",
                 "property_form": "delta-conservation", "verdict": "needs-fuzz"},
            ],
        }
        mvc = self._simulate_step21b_registration(ws, vcis_manifest)
        counts = mvc.get("counts", {})
        self.assertEqual(counts.get("vcis_registered"), 2,
                         "vcis_registered count must equal number of verdicts registered")
        # per_function_verified still 0.
        self.assertEqual(counts.get("per_function_verified", 0), 0)

    def test_step21b_is_additive_does_not_clobber_existing_mvc(self):
        ws = _make_ws()
        # Pre-populate a real per_function_verified count (as if a real fuzz
        # run already happened before Step 21b runs for a fresh re-run).
        existing_mvc = {
            "schema": "auditooor.mutation_verify_coverage.v1",
            "counts": {"per_function_verified": 3, "vcis_registered": 0},
            "some_other_key": "preserved",
        }
        mvc_path = ws / ".auditooor" / "mutation_verify_coverage.json"
        mvc_path.write_text(json.dumps(existing_mvc), encoding="utf-8")

        vcis_manifest = {
            "schema": "vcis_manifest.v1",
            "verdicts": [
                {"file": "src/X.sol", "function": "funcX",
                 "property_form": "solvency-floor", "verdict": "needs-fuzz"},
            ],
        }
        mvc = self._simulate_step21b_registration(ws, vcis_manifest)

        # per_function_verified MUST NOT be decremented - the step is additive.
        counts = mvc.get("counts", {})
        self.assertEqual(counts.get("per_function_verified"), 3,
                         "Step 21b must not clobber an existing per_function_verified count")
        # Existing unrelated keys must survive.
        self.assertEqual(mvc.get("some_other_key"), "preserved")

    def test_sadl_fold_does_not_set_per_function_verified(self):
        """Folding SADL hypotheses into per_fn_hacker_questions.jsonl must not
        touch mutation_verify_coverage.json at all."""
        if not _AUTO_COVERAGE_CLOSER.is_file():
            self.skipTest("auto-coverage-closer.py not found")
        mod = _load_module("acc_no_auto_credit", _AUTO_COVERAGE_CLOSER)

        ws = _make_ws()
        mvc_path = ws / ".auditooor" / "mutation_verify_coverage.json"
        # Start with a known state.
        mvc_path.write_text(json.dumps({"counts": {"per_function_verified": 0}}), encoding="utf-8")

        sadl_path = ws / ".auditooor" / "self_dealing_hypotheses.jsonl"
        _write_jsonl(sadl_path, [
            {
                "workspace": str(ws), "file": "src/V.sol", "function": "transfer",
                "language": "sol", "param_a": "from", "param_b": "to",
                "collapse_expr": "from == to", "note": "identity collapse",
                "attack_class": "self-dealing-identity-collapse",
                "source": "SADL", "verdict": "needs-fuzz",
                "vcis_oracle_hint": "", "selftake_guard_note": "",
            }
        ])

        mod._fold_lane_hypotheses_into_corpus(ws, "r-test")

        mvc_after = json.loads(mvc_path.read_text(encoding="utf-8"))
        self.assertEqual(
            mvc_after.get("counts", {}).get("per_function_verified", 0), 0,
            "_fold_lane_hypotheses_into_corpus must NOT touch per_function_verified",
        )


# ---------------------------------------------------------------------------
# Test: hypotheses_folded_to_hunt_corpus - the fold is wired into run()
# ---------------------------------------------------------------------------
class TestLaneFoldWiredIntoRun(unittest.TestCase):
    """Verify that the result dict returned by auto-coverage-closer.run()
    includes the lane_hypothesis_fold key (confirming the fold is called)."""

    def setUp(self):
        if not _AUTO_COVERAGE_CLOSER.is_file():
            self.skipTest("auto-coverage-closer.py not found")
        self._mod = _load_module("acc_run_fold_test", _AUTO_COVERAGE_CLOSER)

    def test_run_result_includes_lane_hypothesis_fold_key(self):
        ws = _make_ws()
        # run() requires a valid workspace with some minimal structure.
        # Seed enough to prevent crashes in the coverage report path.
        result = self._mod.run(ws, max_iters=1)
        self.assertIn("lane_hypothesis_fold", result,
                      "run() result must include 'lane_hypothesis_fold' key "
                      "proving the fold is called even when no hypotheses exist")

    def test_run_folds_sadl_records_into_corpus_when_present(self):
        ws = _make_ws()
        sadl_path = ws / ".auditooor" / "self_dealing_hypotheses.jsonl"
        _write_jsonl(sadl_path, [
            {
                "workspace": str(ws), "file": "src/V.sol", "function": "settle",
                "language": "sol", "param_a": "buyer", "param_b": "seller",
                "collapse_expr": "buyer == seller", "note": "buyer-seller collapse",
                "attack_class": "self-dealing-identity-collapse",
                "source": "SADL", "verdict": "needs-fuzz",
                "vcis_oracle_hint": "", "selftake_guard_note": "",
            }
        ])
        result = self._mod.run(ws, max_iters=1)
        fold = result.get("lane_hypothesis_fold", {})
        self.assertGreater(fold.get("appended", 0), 0,
                           "SADL records must be appended to corpus when present")

        corpus_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        records = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
        sadl_recs = [r for r in records if r.get("source") == "SADL"]
        self.assertGreater(len(sadl_recs), 0)
        for r in sadl_recs:
            self.assertEqual(r["verdict"], "needs-fuzz")


class TestPipelineManifestRoutesAdvisoryIntoHunt(unittest.TestCase):
    """Manifest V2 must route grounded advisory outputs into hunt and verdict."""

    def setUp(self):
        manifest = json.loads((_TOOLS / "readme_runbook_steps.json").read_text(encoding="utf-8"))
        self.steps = manifest["steps"]
        self.by_id = {step["step_id"]: step for step in self.steps}
        self.contracts = {row["id"]: row for row in manifest["artifact_contracts"]}

    def test_corpus_driven_hunt_is_a_reasoning_step_before_hunt(self):
        step = self.by_id["step-4c"]
        self.assertEqual(step["phase"], "reasoning")
        self.assertEqual(step["execution_target"], ["make", "corpus-driven-hunt", "WS={workspace}", "EMIT_PROOF_QUEUE=1"])
        self.assertLess(step["run_sequence"], self.by_id["step-3"]["run_sequence"])

    def test_corpus_driven_hunt_consumes_reasoner_outputs_before_hunt(self):
        step = self.by_id["step-4c"]
        for upstream in (
            "step-2d-coupled-state",
            "step-2d-atomic-sequence",
            "step-2d-go-mustsucceed",
            "step-2d-rust-account-confusion",
            "step-2d-rust-arith-overflow",
        ):
            self.assertIn(upstream, step["depends_on"], upstream)
            self.assertLess(self.by_id[upstream]["run_sequence"], step["run_sequence"], upstream)
        self.assertIn("step-2d-oracle-reachability", self.by_id["step-2d-atomic-sequence"]["depends_on"])
        self.assertLess(
            self.by_id["step-2d-oracle-reachability"]["run_sequence"],
            self.by_id["step-2d-atomic-sequence"]["run_sequence"],
        )

    def test_fold_artifact_feeds_hunt_conversion_and_verdict(self):
        artifact = self.contracts["artifact.step-4c"]
        self.assertEqual(artifact["path"], ".auditooor/corpus_driven_hunt.json")
        self.assertEqual(
            artifact["consumer_step_ids"],
            ["step-2h-reasoner-regen", "step-3", "step-4e-exploit-conversion", "step-5"],
        )

    def test_named_lane_artifacts_route_into_grounding_hunt_and_verdict(self):
        for artifact_id in (
            "artifact.step-2d-coupled-state",
            "artifact.step-2d-atomic-sequence",
            "artifact.step-2d-go-mustsucceed",
            "artifact.step-2d-rust-account-confusion",
            "artifact.step-2d-rust-arith-overflow",
        ):
            consumers = self.contracts[artifact_id]["consumer_step_ids"]
            self.assertIn("step-4c", consumers, artifact_id)
            self.assertIn("step-3", consumers, artifact_id)
            self.assertIn("step-4e-exploit-conversion", consumers, artifact_id)
            self.assertIn("step-5", consumers, artifact_id)


if __name__ == "__main__":
    unittest.main()
