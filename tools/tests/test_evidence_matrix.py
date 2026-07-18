#!/usr/bin/env python3
"""PR 108 — Evidence matrix unit tests.

Fully offline. Construct mock `results` dicts and call
`build_evidence_matrix()` directly. No real gates / no subprocess calls.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGER_PATH = ROOT / "tools" / "submission-packager.py"


def _load_packager_module():
    spec = importlib.util.spec_from_file_location("submission_packager", PACKAGER_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


PKG = _load_packager_module()
build_evidence_matrix = PKG.build_evidence_matrix


def _semantic_replay_entry(**overrides) -> dict:
    entry = {
        "reference": "a_manifest.json",
        "status": "success",
        "block": 12345678,
        "fork_block": 12345677,
        "assertions": [{"id": "attacker-profit", "status": "PASS"}],
    }
    entry.update(overrides)
    return entry


def _base_results(
    *,
    dupe_risk: str = "LOW",
    fork_entries=None,
    fork_missing=None,
    live_status: str = "executed",
    pre_submit_output: str = "  ✅ 20. No historical rejection patterns matched\n",
) -> dict:
    return {
        "gates": {
            "variant": {"risk_level": dupe_risk},
            "pre_submit": {"rc": 0, "output": pre_submit_output},
        },
        "fork_replay": {
            "entries": fork_entries if fork_entries is not None else [],
            "missing": fork_missing or [],
            "malformed": [],
        },
        "live_proof": {"proof_status": live_status, "referenced_ids": []},
    }


def _draft_tmp(text: str) -> Path:
    tmp = Path(tempfile.mkstemp(suffix=".md")[1])
    tmp.write_text(text)
    return tmp


def _empty_ws() -> Path:
    return Path(tempfile.mkdtemp(prefix="evmx-ws-"))


class EvidenceMatrixTests(unittest.TestCase):

    # 1. High severity, all evidence present → READY ----------------------
    def test_high_all_present_ready(self):
        results = _base_results(
            fork_entries=[_semantic_replay_entry()],
            live_status="executed",
        )
        draft = _draft_tmp("# X\nSeverity: High\n")
        ws = _empty_ws()
        # Simulate a fuzz run directory.
        run_dir = ws / "fuzz_runs" / "2026-04-23T00-00-00"
        run_dir.mkdir(parents=True)
        (run_dir / "manifest.json").write_text('{"status":"ok"}')
        m = build_evidence_matrix(results, draft_path=draft, ws=ws, poc_found=True)
        self.assertEqual(m["summary"]["ready_verdict"], "READY")
        self.assertEqual(m["severity"], "HIGH")
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["forge_poc"]["status"], "PRESENT")
        self.assertEqual(rows["fork_replay"]["status"], "PRESENT")
        self.assertEqual(rows["live_proof"]["status"], "PRESENT")
        self.assertEqual(rows["dupe_check"]["risk"], "LOW")

    # 2. High severity missing fork_replay → BLOCKED ----------------------
    def test_high_missing_fork_replay_blocked(self):
        results = _base_results(
            fork_entries=[],
            fork_missing=["deltas/missing.json"],
            live_status="executed",
        )
        draft = _draft_tmp("# Y\n**Severity**: High\n")
        m = build_evidence_matrix(results, draft_path=draft, ws=_empty_ws(), poc_found=True)
        self.assertEqual(m["summary"]["ready_verdict"], "BLOCKED")
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["fork_replay"]["status"], "MISSING")

    # 3. HIGH dupe risk → DUPE_RISK regardless ----------------------------
    def test_high_dupe_risk_overrides(self):
        results = _base_results(
            dupe_risk="HIGH",
            fork_entries=[_semantic_replay_entry(reference="x_manifest.json")],
            live_status="executed",
        )
        draft = _draft_tmp("# Z\nSeverity: High\n")
        m = build_evidence_matrix(results, draft_path=draft, ws=_empty_ws(), poc_found=True)
        self.assertEqual(m["summary"]["ready_verdict"], "DUPE_RISK")
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["dupe_check"]["risk"], "HIGH")

    # 4. Source-only High draft with N/A fork replay → SOURCE_ONLY --------
    def test_source_only_high_draft(self):
        # A High+ draft that explicitly opts out of fork replay with a
        # source-only justification. We signal "N/A fork replay" by passing a
        # results dict that already contains a synthetic N/A entry — mirroring
        # the behaviour a future caller will have once source-only is a
        # first-class option. For the current heuristic, we confirm the
        # phrase detector fires and that passing an N/A-shaped fork_replay
        # entries list triggers SOURCE_ONLY.
        draft = _draft_tmp(
            "# SrcOnly\nSeverity: High\n\n"
            "source-only justification: this bug is detectable purely from source.\n"
        )
        self.assertTrue(PKG._draft_cites_source_only(draft))

        results = _base_results(fork_entries=[], live_status="executed")
        m = build_evidence_matrix(
            results, draft_path=draft, ws=_empty_ws(), poc_found=True,
            severity_override="HIGH",
        )
        self.assertEqual(m["summary"]["ready_verdict"], "SOURCE_ONLY")

    # 5. Medium draft with no fork replay → READY -------------------------
    def test_medium_no_fork_replay_ready(self):
        results = _base_results(
            fork_entries=[], live_status="executed",
        )
        draft = _draft_tmp("# M\nSeverity: Medium\n")
        m = build_evidence_matrix(results, draft_path=draft, ws=_empty_ws(), poc_found=True)
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["fork_replay"]["status"], "N/A")
        self.assertEqual(m["summary"]["ready_verdict"], "READY")

    # 6. Critical draft missing live proof → BLOCKED ----------------------
    def test_critical_missing_live_proof_blocked(self):
        results = _base_results(
            fork_entries=[_semantic_replay_entry(reference="m.json")],
            live_status="missing",
        )
        draft = _draft_tmp("# C\nSeverity: Critical\n")
        m = build_evidence_matrix(results, draft_path=draft, ws=_empty_ws(), poc_found=True)
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["live_proof"]["status"], "MISSING")
        self.assertEqual(m["summary"]["ready_verdict"], "BLOCKED")

    # 7. Codex PR-102 blocker 4: status="executed" must be accepted -------
    def test_fork_replay_status_executed_is_accepted(self):
        """fork-replay.sh emits status="executed" on success (not "success");
        build_evidence_matrix must treat it as a PRESENT entry."""
        results = _base_results(
            fork_entries=[_semantic_replay_entry(reference="m.json", status="executed")],
            live_status="executed",
        )
        draft = _draft_tmp("# X\nSeverity: High\n")
        ws = _empty_ws()
        run_dir = ws / "fuzz_runs" / "2026-04-23T00-00-00"
        run_dir.mkdir(parents=True)
        (run_dir / "manifest.json").write_text('{"status":"ok"}')
        m = build_evidence_matrix(results, draft_path=draft, ws=ws, poc_found=True)
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["fork_replay"]["status"], "PRESENT")
        self.assertEqual(m["summary"]["ready_verdict"], "READY")

    def test_fork_replay_status_uppercase_executed_is_accepted(self):
        """Status matching must be case-insensitive."""
        results = _base_results(
            fork_entries=[_semantic_replay_entry(reference="m.json", status="EXECUTED")],
            live_status="executed",
        )
        draft = _draft_tmp("# X\nSeverity: High\n")
        ws = _empty_ws()
        run_dir = ws / "fuzz_runs" / "2026-04-23T00-00-00"
        run_dir.mkdir(parents=True)
        (run_dir / "manifest.json").write_text('{"status":"ok"}')
        m = build_evidence_matrix(results, draft_path=draft, ws=ws, poc_found=True)
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["fork_replay"]["status"], "PRESENT")

    # 8. Codex PR-102 blocker 7: High+ source-only + no cite → N/A row + -
    #    SOURCE_ONLY verdict (previously impossible because row was PARTIAL)
    def test_high_source_only_no_cite_yields_source_only_verdict(self):
        results = _base_results(fork_entries=[], live_status="not-required")
        draft = _draft_tmp(
            "# SrcOnly\nSeverity: High\n\n"
            "Fork-replay not applicable — this is a source-only finding with\n"
            "no economic delta to measure. Proof is the Forge PoC below.\n"
        )
        m = build_evidence_matrix(
            results, draft_path=draft, ws=_empty_ws(), poc_found=True,
        )
        rows = {r["key"]: r for r in m["rows"]}
        # Row must be N/A (not PARTIAL), so the verdict logic can reach
        # SOURCE_ONLY without being short-circuited by BLOCKED.
        self.assertEqual(rows["fork_replay"]["status"], "N/A")
        self.assertEqual(m["summary"]["ready_verdict"], "SOURCE_ONLY")

    def test_high_no_cite_no_source_only_still_blocked(self):
        """Baseline: High+ with no cite AND no source-only phrase must NOT
        reach SOURCE_ONLY. It should block/partial as before."""
        results = _base_results(fork_entries=[], live_status="executed")
        draft = _draft_tmp("# Y\nSeverity: High\n\nBug happens.\n")
        m = build_evidence_matrix(
            results, draft_path=draft, ws=_empty_ws(), poc_found=True,
        )
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["fork_replay"]["status"], "PARTIAL")
        self.assertEqual(m["summary"]["ready_verdict"], "BLOCKED")

    def test_high_executed_replay_without_assertions_is_partial_and_blocked(self):
        results = _base_results(
            fork_entries=[{
                "reference": "m.json",
                "status": "executed",
                "block": 12345678,
                "fork_block": 12345677,
            }],
            live_status="executed",
        )
        draft = _draft_tmp("# X\nSeverity: High\n")
        ws = _empty_ws()
        run_dir = ws / "fuzz_runs" / "2026-04-23T00-00-00"
        run_dir.mkdir(parents=True)
        (run_dir / "manifest.json").write_text('{"status":"ok"}')
        m = build_evidence_matrix(results, draft_path=draft, ws=ws, poc_found=True)
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["fork_replay"]["status"], "PARTIAL")
        self.assertIn("assertions-missing", rows["fork_replay"]["notes"])
        self.assertEqual(m["summary"]["ready_verdict"], "BLOCKED")

    def test_high_source_only_without_poc_is_blocked(self):
        results = _base_results(fork_entries=[], live_status="not-required")
        draft = _draft_tmp(
            "# SrcOnly\nSeverity: High\n\n"
            "Source-only justification: proof is only in prose.\n"
        )
        m = build_evidence_matrix(
            results, draft_path=draft, ws=_empty_ws(), poc_found=False,
        )
        self.assertEqual(m["summary"]["ready_verdict"], "BLOCKED")

    def test_high_source_only_with_required_live_proof_missing_is_blocked(self):
        results = _base_results(fork_entries=[], live_status="missing")
        draft = _draft_tmp(
            "# SrcOnly\nSeverity: High\n\n"
            "Source-only justification: source proves this, but deployed role "
            "truth still depends on live proof.\n"
        )
        m = build_evidence_matrix(
            results, draft_path=draft, ws=_empty_ws(), poc_found=True,
        )
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(rows["live_proof"]["status"], "MISSING")
        self.assertEqual(m["summary"]["ready_verdict"], "BLOCKED")

    def test_recommended_severity_format_is_detected(self):
        draft = _draft_tmp("# Finding\n**Severity (RECOMMENDED)**: **High**\n")
        self.assertEqual(PKG._extract_severity_from_draft(draft), "HIGH")

    def test_rust_dlt_harness_counts_as_poc_evidence(self):
        ws = _empty_ws()
        harness_dir = ws / "poc-tests" / "fn7_evidence_runner"
        harness_dir.mkdir(parents=True)
        (harness_dir / "fn7_evidence_manifest.json").write_text('{"overall_status":"pass"}')
        (harness_dir / "FN7_EVIDENCE_MANIFEST.md").write_text("# Evidence\n")
        draft = _draft_tmp(
            "# FN7\n"
            "**Severity (RECOMMENDED)**: **High**\n\n"
            "Rust/DLT Engine API cargo test evidence lives at "
            "`poc-tests/fn7_evidence_runner/fn7_evidence_manifest.json`.\n"
            "Fork-replay not applicable — this is a source-only finding.\n"
        )
        evidence = PKG.find_poc_evidence_for_draft(draft, ws)
        self.assertTrue(evidence["present"])
        self.assertEqual(evidence["kind"], "rust_dlt_harness")
        results = _base_results(fork_entries=[], live_status="not-required")
        m = build_evidence_matrix(
            results,
            draft_path=draft,
            ws=ws,
            poc_found=False,
            poc_evidence=evidence,
        )
        rows = {r["key"]: r for r in m["rows"]}
        self.assertEqual(m["severity"], "HIGH")
        self.assertEqual(rows["forge_poc"]["status"], "PRESENT")
        self.assertEqual(rows["forge_poc"]["label"], "PoC / exploit harness")
        self.assertEqual(m["summary"]["ready_verdict"], "SOURCE_ONLY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
