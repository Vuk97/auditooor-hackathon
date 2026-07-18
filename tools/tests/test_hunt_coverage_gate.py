#!/usr/bin/env python3
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[]
"""Tests for tools/hunt-coverage-gate.py (G15.1).

Covers:
  - fail-empty-workspace (no source files)
  - fail-coverage-below-threshold lists uncovered + flags libraries
  - skip-log subtracts intentionally-skipped contracts -> pass
  - full coverage (all hit) -> pass
  - ok-rebuttal (visible line + HTML form)
  - audit-run-full last-result sidecar persistence and overwrite discipline
  - reuses workspace-coverage-heatmap internals (collect_hits / list_workspace_files)
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

gate = importlib.import_module("hunt-coverage-gate")  # type: ignore
TOOL = REPO_ROOT / "tools" / "hunt-coverage-gate.py"


class HuntCoverageGateTests(unittest.TestCase):
    def _emit_hits(self, hints: list[str]) -> None:
        """Write workflow sidecars whose file_path_hint covers given contracts.
        collect_hits globs DERIVED_ROOT/mimo_harness_<ws>*; we monkeypatch the
        heatmap module's AUDITOOOR_ROOT to point at our base via emitting into
        the real derived path is heavy, so instead we emit directly and
        repoint collect_hits' glob through the heatmap module."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_wch_for_test", REPO_ROOT / "tools" / "workspace-coverage-heatmap.py"
        )
        self.wch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.wch)
        # Point the heatmap's derived glob at our base.
        self.wch.AUDITOOOR_ROOT = self.base.parent
        ws_name = self.ws.name
        d = self.base.parent / "audit" / "corpus_tags" / "derived" / f"mimo_harness_{ws_name}_workflow"
        d.mkdir(parents=True, exist_ok=True)
        for i, hint in enumerate(hints):
            if "::" in hint:
                file_hint, fn_name = hint.split("::", 1)
            else:
                file_hint = hint
                fn_name = "add" if hint == "MathLib.sol" else "hit"
            inner = {"verdict": "CONFIRMED", "applies_to_target": "yes",
                     "confidence": "high", "file_line": f"src/{file_hint}:L1",
                     "code_excerpt": "", "severity_final": "Medium",
                     "reasoning": "", "file_path_hint": f"src/{file_hint}",
                     "workspace_path": str(self.ws)}
            sidecar = {"status": "ok", "task_id": f"t{i}", "workspace": ws_name,
                       "workspace_path": str(self.ws),
                       "function_anchor": {"file": f"src/{file_hint}", "fn": fn_name},
                       "result": json.dumps(inner)}
            (d / f"t{i}.json").write_text(json.dumps(sidecar), encoding="utf-8")

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        # Workspace with 5 contracts + 1 library.
        self.ws = Path(self.tmp.name) / "ws"
        (self.ws / "src").mkdir(parents=True, exist_ok=True)
        for f in ("A", "B", "C", "D", "E"):
            (self.ws / "src" / f"{f}.sol").write_text(
                f"contract {f} {{ function hit() external {{}} }}\n",
                encoding="utf-8",
            )
        (self.ws / "src" / "MathLib.sol").write_text(
            "library MathLib { function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; } }\n",
            encoding="utf-8",
        )
        # Sidecars live under a custom base so we can control hits.
        self.base = Path(self.tmp.name) / "derived"

        # Patch _load_strict_fn_coverage_module to return a pass-through for
        # all tests by default.  Tests that specifically exercise the FCC
        # reconciliation override this patch themselves.
        self._orig_load_fcc = gate._load_strict_fn_coverage_module

        class _PassFCC:
            @staticmethod
            def evaluate(_ws):
                return {
                    "verdict": "pass-fully-covered",
                    "reason": "test-passthrough",
                    "counts": {"total": 0, "real_attack": 0, "hollow": 0, "untouched": 0},
                    "functions": [],
                }

        gate._load_strict_fn_coverage_module = lambda: _PassFCC  # type: ignore

    def tearDown(self) -> None:
        gate._load_strict_fn_coverage_module = self._orig_load_fcc  # type: ignore
        self.tmp.cleanup()

    def _patch_gate_heatmap(self):
        """Make the gate load OUR heatmap module (with repointed root)."""
        orig = gate._load_heatmap
        gate._load_heatmap = lambda: self.wch  # type: ignore
        # And make workspace_to_path resolve to our ws dir directly.
        self.wch.workspace_to_path = lambda ws: self.ws  # type: ignore
        return orig

    def _restore_gate_heatmap(self, orig):
        gate._load_heatmap = orig  # type: ignore

    def test_empty_workspace(self) -> None:
        empty = Path(self.tmp.name) / "empty"
        empty.mkdir()
        r = gate.check(str(empty))
        self.assertEqual(r["verdict"], "fail-zero-coverage-denominator")
        self.assertEqual(r["total_units"], 0)
        self.assertIn("Bootstrap or mirror the target source first", r["reason"])
        self.assertIn("no enumerable source units", r["remediation"])

    def test_below_threshold_lists_uncovered_and_libraries(self) -> None:
        self._emit_hits(["A.sol"])  # only 1 of 6 covered
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.80)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-coverage-below-threshold")
        self.assertIn("MathLib.sol::add", r["libraries_uncovered"])
        self.assertEqual(r["total_contracts"], 6)
        self.assertEqual(r["total_units"], 6)
        self.assertEqual(r["coverage_basis"], "source-unit")
        self.assertEqual(r["covered"], 1)
        self.assertEqual(len(r["denominator_units"]), 6)
        self.assertIn("A.sol::hit", r["denominator_units"])
        self.assertFalse(r["coverage_report_exists"])
        self.assertFalse(r["coverage_report_generated_by_gate"])

    def test_live_denominator_missing_in_scope_units_fails(self) -> None:
        class FakeHeatmap:
            @staticmethod
            def workspace_to_path(_workspace: str) -> Path:
                return self.ws

            @staticmethod
            def build_coverage_report(_ws: Path, list_cap: int = -1) -> dict:
                return {
                    "coverage_basis": "source-unit",
                    "function_denominator_status": "complete",
                    "full_in_scope_function_denominator": True,
                    "total_units": 1,
                    "covered": 1,
                    "uncovered": 0,
                    "uncovered_units": [],
                    "denominator_units": ["A.sol::hit"],
                    "enumeration": {"languages": {".sol": 2}},
                    "source_freshness": {
                        "source_files_count": 2,
                        "source_files_sha256": "files",
                        "source_units_count": 1,
                        "source_units_sha256": "units",
                        "function_denominator_status": "complete",
                        "full_in_scope_function_denominator": True,
                        "denominator_sha256": "denom",
                    },
                }

            @staticmethod
            def enumerate_units(_ws: Path) -> tuple[list[str], dict]:
                return (
                    ["A.sol::hit", "B.sol::hit"],
                    {"languages": {".sol": 2}, "ambiguous_source_basenames": []},
                )

        orig = gate._load_heatmap
        gate._load_heatmap = lambda: FakeHeatmap  # type: ignore
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-denominator-missing-in-scope-units")
        self.assertEqual(r["live_total_units"], 2)
        self.assertEqual(r["reported_total_units"], 1)
        self.assertEqual(r["missing_denominator_units"], ["B.sol::hit"])
        self.assertEqual(r["denominator_units"], ["A.sol::hit", "B.sol::hit"])

    def test_stale_cached_denominator_fails_before_threshold(self) -> None:
        self._emit_hits(["A.sol"])
        orig = self._patch_gate_heatmap()
        try:
            live = self.wch.build_coverage_report(self.ws, list_cap=-1)
            stale = json.loads(json.dumps(live))
            stale["source_freshness"]["source_units_count"] = 0
            stale["source_freshness"]["denominator_sha256"] = "stale"
            (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            (self.ws / ".auditooor" / "coverage_report.json").write_text(
                json.dumps(stale),
                encoding="utf-8",
            )
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-stale-coverage-denominator")
        self.assertIn("source_freshness.source_units_count", r["mismatches"])
        self.assertIn("source_freshness.denominator_sha256", r["mismatches"])

    def test_legacy_cached_report_regenerates_and_continues(self) -> None:
        self._emit_hits(["A.sol"])
        orig = self._patch_gate_heatmap()
        try:
            live = self.wch.build_coverage_report(self.ws, list_cap=-1)
            legacy = json.loads(json.dumps(live))
            legacy.pop("source_freshness", None)
            legacy.pop("numerator_freshness", None)
            legacy.pop("denominator_disclosure", None)
            legacy.pop("function_denominator_status", None)
            legacy.pop("full_in_scope_function_denominator", None)
            report_path = self.ws / ".auditooor" / "coverage_report.json"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(legacy), encoding="utf-8")
            r = gate.check(str(self.ws), min_coverage=0.0)
            rewritten = json.loads(report_path.read_text(encoding="utf-8"))
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertTrue(r["coverage_report_generated_by_gate"])
        self.assertIsInstance(rewritten.get("source_freshness"), dict)
        self.assertIsInstance(rewritten.get("numerator_freshness"), dict)
        self.assertEqual(rewritten["total_units"], live["total_units"])
        self.assertFalse(rewritten["uncovered_units_truncated"])

    def test_cached_source_unit_only_denominator_fails_when_functions_expected(self) -> None:
        self._emit_hits(["A.sol"])
        orig = self._patch_gate_heatmap()
        try:
            live = self.wch.build_coverage_report(self.ws, list_cap=-1)
            stale = json.loads(json.dumps(live))
            stale["function_denominator_status"] = "source-unit-only"
            stale["full_in_scope_function_denominator"] = False
            stale["source_freshness"]["function_denominator_status"] = "source-unit-only"
            stale["source_freshness"]["full_in_scope_function_denominator"] = False
            (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            (self.ws / ".auditooor" / "coverage_report.json").write_text(
                json.dumps(stale),
                encoding="utf-8",
            )
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-stale-coverage-denominator")
        self.assertEqual(
            r["mismatches"]["coverage_report.function_denominator_status"],
            {"stored": "source-unit-only", "recomputed": "complete"},
        )

    def test_live_source_unit_only_denominator_fails_for_function_language(self) -> None:
        class FakeHeatmap:
            @staticmethod
            def workspace_to_path(_workspace: str) -> Path:
                return self.ws

            @staticmethod
            def build_coverage_report(_ws: Path, list_cap: int = -1) -> dict:
                return {
                    "coverage_basis": "source-unit",
                    "function_denominator_status": "source-unit-only",
                    "full_in_scope_function_denominator": False,
                    "function_level_extensions": [],
                    "source_unit_extensions": [".sol"],
                    "total_units": 1,
                    "covered": 1,
                    "uncovered": 0,
                    "uncovered_units": [],
                    "enumeration": {"languages": {".sol": 1}},
                    "source_freshness": {
                        "source_files_count": 1,
                        "source_files_sha256": "files",
                        "source_units_count": 1,
                        "source_units_sha256": "units",
                        "function_denominator_status": "source-unit-only",
                        "full_in_scope_function_denominator": False,
                        "denominator_sha256": "denom",
                    },
                }

        orig = gate._load_heatmap
        gate._load_heatmap = lambda: FakeHeatmap  # type: ignore
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-source-unit-only-denominator")
        self.assertEqual(r["function_denominator_status"], "source-unit-only")

    def test_skip_log_requires_reason(self) -> None:
        self._emit_hits(["A.sol"])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "hunt_coverage_skips.txt").write_text(
            "B.sol\nC.sol accepted-risk\n",
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.80)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-skip-without-reason")
        self.assertEqual(r["skip_log_missing_reasons"][0]["token"], "B.sol")
        self.assertEqual(r["skip_log_entries"][1]["reason"], "accepted-risk")

    def test_detector_only_unit_must_be_queued_or_scanned(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "detector_hits.json").write_text(
            json.dumps({"hits": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-detector-only-not-queued")
        self.assertEqual(r["detector_only_not_queued"], ["A.sol::hit"])
        self.assertEqual(r["queued_units"], [])
        self.assertEqual(r["scanned_units"], [])

    def test_detector_only_unit_with_skip_log_is_reviewed(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "detector_hits.json").write_text(
            json.dumps({"hits": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        (self.ws / ".auditooor" / "hunt_coverage_skips.txt").write_text(
            "A.sol::hit human-reviewed no finding candidate\n",
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertIn("A.sol::hit", r["detector_units"])
        self.assertIn("A.sol::hit", r["skip_logged_units"])
        self.assertNotIn("A.sol::hit", r.get("detector_only_not_queued", []))

    def test_detector_only_unit_with_exact_review_artifact_is_scanned(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "detector_action_graph.json").write_text(
            json.dumps({
                "detector_hit": {
                    "file_path": "src/A.sol:1",
                    "function": "hit",
                    "detector_slug": "example",
                }
            }),
            encoding="utf-8",
        )
        (self.ws / ".auditooor" / "a_source_review.json").write_text(
            json.dumps({
                "target": {
                    "name": "A.sol::hit",
                    "source_ref": "src/A.sol:1-2; writes through B.sol:1",
                },
                "finding_candidate": False,
                "verdict": "no finding candidate",
            }),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertIn("A.sol::hit", r["scanned_units"])
        self.assertNotIn("A.sol::hit", r.get("detector_only_not_queued", []))

    def test_pass_result_surfaces_skipped_hunt_artifacts(self) -> None:
        self._emit_hits(["A.sol"])
        ws_name = self.ws.name
        failed_dir = self.base.parent / "audit" / "corpus_tags" / "derived" / f"mimo_harness_{ws_name}_workflow"
        failed_dir.mkdir(parents=True, exist_ok=True)
        (failed_dir / "failed.json").write_text(
            json.dumps(
                {
                    "status": "rate-limited",
                    "workspace": ws_name,
                    "workspace_path": str(self.ws),
                    "function_anchor": {"file": "src/A.sol", "fn": "hit"},
                }
            ),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertEqual(r["skipped_coverage_count"], 1)
        self.assertEqual(r["skipped_coverage_reasons"], {"hunt_status_rate_limited": 1})
        self.assertEqual(r["skipped_coverage"][0]["file"], "src/A.sol")
        self.assertEqual(r["skipped_coverage"][0]["function"], "hit")

    def test_detector_function_snippet_does_not_expand_to_constructor(self) -> None:
        (self.ws / "src" / "Auth.sol").write_text(
            "contract Auth { constructor(address a) {} function setIsAuthorized() external {} }\n",
            encoding="utf-8",
        )
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "detector_action_graph.json").write_text(
            json.dumps({
                "action_graph": {
                    "nodes": [
                        {"source_refs": ["src/Auth.sol:1"]}
                    ]
                },
                "detector_hit": {
                    "file_path": "src/Auth.sol:1",
                    "detector_slug": "setters-with-no-access-control",
                    "snippet": "function setIsAuthorized() external {}",
                },
            }),
            encoding="utf-8",
        )
        (self.ws / ".auditooor" / "auth_review.json").write_text(
            json.dumps({
                "target": {
                    "name": "Auth.sol::setIsAuthorized",
                    "source_ref": "src/Auth.sol:1",
                },
                "finding_candidate": False,
            }),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertIn("Auth.sol::setIsAuthorized", r["detector_units"])
        self.assertNotIn("Auth.sol::constructor", r["detector_units"])

    def test_review_artifact_does_not_blanket_cover_cited_file(self) -> None:
        (self.ws / "src" / "Multi.sol").write_text(
            "contract Multi { function reviewed() external {} function unreviewed() external {} }\n",
            encoding="utf-8",
        )
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "detector_hits.json").write_text(
            json.dumps({
                "hits": [
                    {"file": "src/Multi.sol", "function": "reviewed"},
                    {"file": "src/Multi.sol", "function": "unreviewed"},
                ]
            }),
            encoding="utf-8",
        )
        (self.ws / ".auditooor" / "multi_review.json").write_text(
            json.dumps({
                "target": {
                    "name": "Multi.sol::reviewed",
                    "source_ref": "src/Multi.sol:1",
                },
                "source_citations": [
                    {"path": "src/Multi.sol", "lines": "1-1"},
                ],
            }),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-detector-only-not-queued")
        self.assertIn("Multi.sol::unreviewed", r["detector_only_not_queued"])
        self.assertNotIn("Multi.sol::reviewed", r["detector_only_not_queued"])

    def test_queued_unit_must_be_scanned(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-queued-not-scanned")
        self.assertEqual(r["queued_not_scanned"], ["A.sol::hit"])
        self.assertEqual(r["queued_units"], ["A.sol::hit"])
        self.assertEqual(r["scanned_units"], [])

    def test_unhunted_surface_queue_rows_are_not_exempt_from_queued_not_scanned(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({
                "queue": [
                    {
                        "source": "unhunted-surface",
                        "file": "src/A.sol",
                        "function": "hit",
                    }
                ]
            }),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-queued-not-scanned")
        self.assertEqual(r["queued_units"], ["A.sol::hit"])
        self.assertEqual(r["queued_units_strict"], ["A.sol::hit"])
        self.assertEqual(r["queued_not_scanned"], ["A.sol::hit"])
        self.assertEqual(r["scanned_units"], [])

    def test_strict_auto_seed_heal_rehydrates_missing_coverage_rows(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": []}),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=1.0, auto_seed_heal=True)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-queued-not-scanned")
        self.assertTrue(r["auto_seed_heal"]["attempted"])
        self.assertTrue(r["auto_seed_heal"]["applied"])
        self.assertGreater(r["auto_seed_heal"]["result"]["seed_rows_total"], 0)
        self.assertIn("A.sol::hit", r["queued_not_scanned"])
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.json").read_text(encoding="utf-8")
        )["queue"]
        self.assertTrue(any(row.get("source") == "unhunted-surface" for row in queue))

    def test_queued_unit_scanned_via_dot_auditooor_hunt_findings_sidecars_review_schema(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        sidecars = self.ws / ".auditooor" / "hunt_findings_sidecars"
        sidecars.mkdir(parents=True, exist_ok=True)
        (sidecars / "reviewed-evidence.json").write_text(
            json.dumps(
                {
                    "reviewed_units": ["A.sol::hit"],
                    "source_citations": [
                        {
                            "name": "A.sol::hit",
                            "source_ref": "src/A.sol:1-3; review note",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertIn("A.sol::hit", r["queued_units"])
        self.assertIn("A.sol::hit", r["scanned_units"])
        self.assertEqual(r.get("queued_not_scanned", []), [])

    def test_queued_unit_scanned_via_source_artifacts_review_schema(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        source_artifacts = self.ws / ".auditooor" / "source_artifacts" / "lane-z"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        (source_artifacts / "scan-artifact.json").write_text(
            json.dumps(
                {
                    "scanned_units": [
                        {
                            "source_unit": "A.sol::hit",
                            "source_ref": "src/A.sol:1",
                        }
                    ],
                    "source_citations": [
                        {
                            "unit": "A.sol::hit",
                            "path": "src/A.sol:1",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertIn("A.sol::hit", r["queued_units"])
        self.assertIn("A.sol::hit", r["scanned_units"])
        self.assertEqual(r.get("queued_not_scanned", []), [])

    def test_run_id_mode_ignores_stale_source_artifact(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        source_artifacts = self.ws / ".auditooor" / "source_artifacts" / "lane-z"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        (source_artifacts / "scan-artifact.json").write_text(
            json.dumps(
                {
                    "run_id": "auditrun-old",
                    "scanned_units": [
                        {
                            "source_unit": "A.sol::hit",
                            "source_ref": "src/A.sol:1",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(
                str(self.ws),
                min_coverage=0.0,
                run_id="auditrun-current",
            )
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-queued-not-scanned")
        self.assertEqual(r["scanned_units"], [])
        self.assertEqual(r["queued_not_scanned"], ["A.sol::hit"])

    def test_run_id_mode_accepts_current_source_artifact(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        source_artifacts = self.ws / ".auditooor" / "source_artifacts" / "lane-z"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        (source_artifacts / "scan-artifact.json").write_text(
            json.dumps(
                {
                    "run_id": "auditrun-current",
                    "scanned_units": [
                        {
                            "source_unit": "A.sol::hit",
                            "source_ref": "src/A.sol:1",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(
                str(self.ws),
                min_coverage=0.0,
                run_id="auditrun-current",
            )
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertEqual(r.get("queued_not_scanned", []), [])
        self.assertIn("A.sol::hit", r["scanned_units"])

    def test_queued_file_unit_scanned_via_source_artifacts_review_schema(self) -> None:
        # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
        # Item 3: .go is now FUNCTION-granular, so worker.go enumerates as
        # worker.go::Tick. The queue cites the function (file+function) and the
        # scan artifact cites the function-precise source_unit; a bare file
        # source_unit no longer blanket-credits the function (R80 honesty).
        ws = Path(self.tmp.name) / "go-ws"
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "worker.go").write_text(
            "package src\nfunc Tick() {}\n",
            encoding="utf-8",
        )
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [
                {"file": "worker.go", "function": "Tick",
                 "source": "unhunted-surface"}
            ]}),
            encoding="utf-8",
        )
        source_artifacts = ws / ".auditooor" / "source_artifacts" / "lane-z"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        (source_artifacts / "scan-artifact.json").write_text(
            json.dumps(
                {
                    "scanned_units": [
                        {
                            "source_unit": "worker.go::Tick",
                            "source_ref": "src/worker.go:2",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        r = gate.check(str(ws), min_coverage=0.0, auto_seed_heal=False)

        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertIn("worker.go::Tick", r["queued_units"])
        self.assertIn("worker.go::Tick", r["scanned_units"])
        self.assertEqual(r.get("queued_not_scanned", []), [])

    def test_source_artifact_prefers_relative_source_unit_when_ref_is_absolute(self) -> None:
        # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
        # Item 3: .go function-granular; queue + scan cite the function-precise
        # unit (src/one/worker.go::Tick) so the absolute-ref relativization still
        # reconciles to the correct path-qualified function unit.
        ws = Path(self.tmp.name) / "absolute-ref-ws"
        target = ws / "src" / "one" / "worker.go"
        sibling = ws / "src" / "two" / "worker.go"
        target.parent.mkdir(parents=True, exist_ok=True)
        sibling.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("package one\nfunc Tick() {}\n", encoding="utf-8")
        sibling.write_text("package two\nfunc Tick() {}\n", encoding="utf-8")
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [
                {"file": "src/one/worker.go", "function": "Tick",
                 "source": "unhunted-surface"}
            ]}),
            encoding="utf-8",
        )
        source_artifacts = ws / ".auditooor" / "source_artifacts"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        (source_artifacts / "scan-artifact.json").write_text(
            json.dumps(
                {
                    "scanned_units": [
                        {
                            "source_unit": "src/one/worker.go::Tick",
                            "source_ref": f"{target}:2",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        r = gate.check(str(ws), min_coverage=0.0, auto_seed_heal=False)

        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertIn("src/one/worker.go::Tick", r["queued_units"])
        self.assertIn("src/one/worker.go::Tick", r["scanned_units"])
        self.assertEqual(r.get("queued_not_scanned", []), [])

    def test_source_artifact_prefers_relative_function_unit_when_absolute_ref_is_ambiguous(self) -> None:
        ws = Path(self.tmp.name) / "absolute-ref-fn-ws"
        target = ws / "src" / "one" / "Worker.sol"
        sibling = ws / "src" / "two" / "Worker.sol"
        target.parent.mkdir(parents=True, exist_ok=True)
        sibling.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "pragma solidity ^0.8.0;\ncontract OneWorker { function tick() external {} }\n",
            encoding="utf-8",
        )
        sibling.write_text(
            "pragma solidity ^0.8.0;\ncontract TwoWorker { function tick() external {} }\n",
            encoding="utf-8",
        )
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps(
                {
                    "queue": [
                        {
                            "file": "src/one/Worker.sol",
                            "function": "tick",
                            "source": "unhunted-surface",
                        },
                        {
                            "file": "src/two/Worker.sol",
                            "function": "tick",
                            "source": "unhunted-surface",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        source_artifacts = ws / ".auditooor" / "source_artifacts"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        (source_artifacts / "scan-artifact.json").write_text(
            json.dumps(
                {
                    "scanned_units": [
                        {
                            "source_unit": "src/one/Worker.sol::tick",
                            "source_ref": f"{target}:2",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        r = gate.check(str(ws), min_coverage=0.0, auto_seed_heal=False)

        self.assertEqual(r["verdict"], "fail-queued-not-scanned")
        self.assertIn("src/one/Worker.sol::tick", r["scanned_units"])
        self.assertNotIn("src/two/Worker.sol::tick", r["scanned_units"])
        self.assertIn("src/two/Worker.sol::tick", r["queued_not_scanned"])

    def test_seed_source_mine_gate_flow_clears_queued_not_scanned(self) -> None:
        ws = Path(self.tmp.name) / "seed-source-mine-ws"
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    function withdraw() external {}\n"
            "}\n",
            encoding="utf-8",
        )
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "workspace-coverage-heatmap.py"),
                "--coverage-report",
                "--workspace-path",
                str(ws),
                "--uncovered-list-cap",
                "-1",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        seed_spec = importlib.util.spec_from_file_location(
            "_coverage_to_hunt_seed_flow_test",
            REPO_ROOT / "tools" / "coverage-to-hunt-seed.py",
        )
        seed_mod = importlib.util.module_from_spec(seed_spec)
        seed_spec.loader.exec_module(seed_mod)  # type: ignore[union-attr]
        miner_spec = importlib.util.spec_from_file_location(
            "_exploit_queue_source_miner_flow_test",
            REPO_ROOT / "tools" / "exploit-queue-source-miner.py",
        )
        miner_mod = importlib.util.module_from_spec(miner_spec)
        miner_spec.loader.exec_module(miner_mod)  # type: ignore[union-attr]

        seed = seed_mod.run(ws, rebuild=False, dry_run=False, queue_path_override=None)
        self.assertEqual(seed["seed_rows_total"], 1)

        mined = miner_mod.run(
            [
                "--workspace",
                str(ws),
                "--top-n",
                "5",
                "--include-open-unhunted",
                "--review-only",
                "--update-queue",
            ]
        )
        self.assertEqual(mined["review_only_scanned"], 1)

        r = gate.check(str(ws), min_coverage=1.0, auto_seed_heal=False)

        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertEqual(r.get("queued_not_scanned", []), [])

    def test_review_artifacts_close_threshold_uncovered_units_before_auto_seed(self) -> None:
        ws = Path(self.tmp.name) / "review-threshold-ws"
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        uncovered_units = ["B.sol::hit"]
        (ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps(
                {
                    "queue": [
                        {
                            "file": "B.sol",
                            "function": "hit",
                            "source": "unhunted-surface",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        source_artifacts = ws / ".auditooor" / "source_artifacts"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        for unit in uncovered_units:
            file_name, fn_name = unit.split("::", 1)
            (source_artifacts / f"{file_name}-{fn_name}.json").write_text(
                json.dumps(
                    {
                        "scanned_units": [
                            {
                                "source_unit": unit,
                                "source_ref": f"src/{file_name}:1",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

        class FakeHeatmap:
            @staticmethod
            def workspace_to_path(_workspace: str) -> Path:
                return ws

            @staticmethod
            def build_coverage_report(_ws: Path, list_cap: int = -1) -> dict:
                return {
                    "coverage_basis": "source-unit",
                    "function_denominator_status": "complete",
                    "full_in_scope_function_denominator": True,
                    "total_units": 2,
                    "covered": 1,
                    "uncovered": 1,
                    "uncovered_units": ["B.sol::hit"],
                    "denominator_units": ["A.sol::hit", "B.sol::hit"],
                    "enumeration": {"languages": {".sol": 2}},
                    "source_freshness": {
                        "source_files_count": 2,
                        "source_files_sha256": "files",
                        "source_units_count": 2,
                        "source_units_sha256": "units",
                        "function_denominator_status": "complete",
                        "full_in_scope_function_denominator": True,
                        "denominator_sha256": "denom",
                    },
                }

            @staticmethod
            def enumerate_units(_ws: Path) -> tuple[list[str], dict]:
                return (
                    ["A.sol::hit", "B.sol::hit"],
                    {"languages": {".sol": 2}, "ambiguous_source_basenames": []},
                )

        orig = gate._load_heatmap
        gate._load_heatmap = lambda: FakeHeatmap  # type: ignore
        try:
            r = gate.check(
                str(ws),
                min_coverage=1.0,
                auto_seed_heal=True,
            )
        finally:
            gate._load_heatmap = orig

        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertEqual(r["coverage_fraction"], 1.0)
        self.assertEqual(r["raw_coverage_fraction"], 0.5)
        self.assertEqual(r["review_scanned_uncovered_count"], 1)
        self.assertFalse(r["auto_seed_heal"]["attempted"])

    def test_source_artifacts_queue_like_json_does_not_count_as_scanned(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        source_artifacts = self.ws / ".auditooor" / "source_artifacts"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        (source_artifacts / "queue-echo.json").write_text(
            json.dumps({"queue": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-queued-not-scanned")
        self.assertEqual(r["queued_not_scanned"], ["A.sol::hit"])
        self.assertEqual(r["scanned_units"], [])

    def test_persist_cli_result_writes_last_gate_payload(self) -> None:
        persist_info = gate._persist_cli_result({
            "workspace_path": str(self.ws),
            "verdict": "fail-queued-not-scanned",
            "exit": 1,
            "queued_not_scanned": ["A.sol::hit"],
        }, workspace=str(self.ws), run_id="auditrun-test", strict=True, min_coverage=1.0)

        out = self.ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
        self.assertTrue(persist_info["written"])
        self.assertEqual(persist_info["path"], str(out))
        self.assertTrue(out.is_file())
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.g15_hunt_coverage_gate.v1")
        self.assertEqual(payload["gate"], "G15-HUNT-COVERAGE-GATE")
        self.assertEqual(payload["verdict"], "fail-queued-not-scanned")
        self.assertEqual(payload["queued_not_scanned"], ["A.sol::hit"])
        self.assertEqual(payload["run_id"], "auditrun-test")
        self.assertTrue(payload["strict"])
        self.assertEqual(payload["min_coverage"], 1.0)
        self.assertIn("generated_at_utc", payload)

    def test_persist_cli_result_without_run_id_preserves_existing_audit_run_sidecar(self) -> None:
        out = self.ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        original = {"verdict": "fail-old", "run_id": "auditrun-current"}
        out.write_text(json.dumps(original), encoding="utf-8")

        persist_info = gate._persist_cli_result({
            "workspace_path": str(self.ws),
            "verdict": "pass-coverage-met",
            "exit": 0,
        }, workspace=str(self.ws), run_id="", strict=False, min_coverage=1.0)

        self.assertFalse(persist_info["written"])
        self.assertEqual(persist_info["reason"], "missing_run_id")
        self.assertEqual(json.loads(out.read_text(encoding="utf-8")), original)

    def test_persist_cli_result_without_run_id_writes_when_no_sidecar_exists(self) -> None:
        # write-if-absent: the documented remediation `make hunt-coverage-gate
        # WS=<ws>` (no RUN_ID) must create the sidecar when none exists, so
        # audit-honesty-check stops reporting "coverage gate absent". The write
        # is tagged adhoc_run=True + run_id="cli-adhoc" so it is never mistaken
        # for a real audit-run-full result.
        out = self.ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
        self.assertFalse(out.exists())
        persist_info = gate._persist_cli_result({
            "workspace_path": str(self.ws),
            "verdict": "fail-queued-not-scanned",
            "exit": 1,
            "queued_not_scanned": ["A.sol::hit"],
        }, workspace=str(self.ws), run_id="", strict=False, min_coverage=1.0)

        self.assertTrue(persist_info["written"])
        self.assertTrue(out.is_file())
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["verdict"], "fail-queued-not-scanned")
        self.assertEqual(payload["run_id"], "cli-adhoc")
        self.assertTrue(payload["adhoc_run"])
        # A SECOND ad-hoc run REFRESHES the stale ad-hoc sidecar (re-running the
        # gate must reflect the latest measurement) - it does not freeze.
        again = gate._persist_cli_result({
            "workspace_path": str(self.ws),
            "verdict": "pass-coverage-met",
            "exit": 0,
        }, workspace=str(self.ws), run_id="", strict=False, min_coverage=1.0)
        self.assertTrue(again["written"])
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["verdict"],
                         "pass-coverage-met")

    def test_persist_cli_result_adhoc_does_not_clobber_real_run_sidecar(self) -> None:
        # The no-clobber invariant for a REAL run must still hold even now that
        # ad-hoc writes are allowed: a real-run sidecar (no adhoc_run flag) is
        # preserved when an ad-hoc (empty run_id) call arrives.
        out = self.ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        real = {"verdict": "pass-coverage-met", "run_id": "auditrun-real"}
        out.write_text(json.dumps(real), encoding="utf-8")
        info = gate._persist_cli_result({
            "workspace_path": str(self.ws),
            "verdict": "fail-queued-not-scanned",
            "exit": 1,
        }, workspace=str(self.ws), run_id="", strict=False, min_coverage=1.0)
        self.assertFalse(info["written"])
        self.assertEqual(info["reason"], "missing_run_id")
        self.assertEqual(json.loads(out.read_text(encoding="utf-8")), real)

    def test_cli_persists_rebuttal_pass_and_overwrites_old_sidecar(self) -> None:
        out = self.ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps({"verdict": "fail-old", "run_id": "auditrun-old"}),
            encoding="utf-8",
        )
        prompt = self.ws / "prompt.md"
        prompt.write_text("<!-- g15-rebuttal: operator-approved smoke -->\n", encoding="utf-8")

        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(self.ws),
                "--prompt-file",
                str(prompt),
                "--run-id",
                "auditrun-new",
                "--strict",
                "--json",
            ],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        emitted = json.loads(proc.stdout)
        persisted = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(emitted["verdict"], "ok-rebuttal")
        self.assertTrue(emitted["last_result_sidecar"]["written"])
        self.assertEqual(persisted["verdict"], "ok-rebuttal")
        self.assertEqual(persisted["run_id"], "auditrun-new")
        self.assertTrue(persisted["strict"])
        self.assertIn("generated_at_utc", persisted)

    def test_cli_without_run_id_preserves_existing_audit_run_sidecar(self) -> None:
        out = self.ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        original = {"verdict": "fail-old", "run_id": "auditrun-current"}
        out.write_text(json.dumps(original), encoding="utf-8")
        env = os.environ.copy()
        env.pop("AUDITOOOR_AUDIT_RUN_FULL_ID", None)

        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(self.ws),
                "--json",
            ],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertNotEqual(proc.stdout, "")
        emitted = json.loads(proc.stdout)
        self.assertFalse(emitted["last_result_sidecar"]["written"])
        self.assertEqual(emitted["last_result_sidecar"]["reason"], "missing_run_id")
        self.assertEqual(json.loads(out.read_text(encoding="utf-8")), original)

    def test_skip_log_subtracts(self) -> None:
        self._emit_hits(["A.sol"])  # 1 of 6 covered
        # Skip-log the other 5 -> all remaining uncovered logged -> pass.
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "hunt_coverage_skips.txt").write_text(
            "B.sol oos\nC.sol oos\nD.sol oos\nE.sol oos\nMathLib.sol library\n",
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.80)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertEqual(r["skip_logged_count"], 5)
        self.assertEqual(r["skip_logged_reasons"]["B.sol::hit"], "oos")
        self.assertEqual(r["skip_logged_reasons"]["MathLib.sol::add"], "library")

    def test_full_coverage(self) -> None:
        self._emit_hits(["A.sol", "B.sol", "C.sol", "D.sol", "E.sol", "MathLib.sol"])
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.80)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertEqual(r["covered"], 6)

    def test_function_precise_denominator_does_not_blanket_cover_sibling(self) -> None:
        (self.ws / "src" / "Multi.sol").write_text(
            "contract Multi { function covered() external {} function uncovered() external {} }\n",
            encoding="utf-8",
        )
        self._emit_hits([
            "A.sol", "B.sol", "C.sol", "D.sol", "E.sol", "MathLib.sol",
            "Multi.sol::covered",
        ])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{"file": "src/Multi.sol", "function": "covered"}]}),
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=1.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "fail-coverage-below-threshold")
        self.assertEqual(r["total_units"], 8)
        self.assertEqual(r["covered"], 7)
        self.assertIn("Multi.sol::uncovered", r["unlogged_uncovered"])
        self.assertNotIn("Multi.sol::covered", r["unlogged_uncovered"])

    def test_skip_log_accepts_exact_source_unit(self) -> None:
        (self.ws / "src" / "Multi.sol").write_text(
            "contract Multi { function covered() external {} function skipped() external {} }\n",
            encoding="utf-8",
        )
        self._emit_hits([
            "A.sol", "B.sol", "C.sol", "D.sol", "E.sol", "MathLib.sol",
            "Multi.sol::covered",
        ])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{"file": "src/Multi.sol", "function": "covered"}]}),
            encoding="utf-8",
        )
        (self.ws / ".auditooor" / "hunt_coverage_skips.txt").write_text(
            "Multi.sol::skipped oos\n",
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=1.0)
        finally:
            gate._load_heatmap = orig
        self.assertEqual(r["verdict"], "pass-coverage-met")
        self.assertEqual(r["skip_logged_count"], 1)

    def test_run_id_mode_requires_current_skip_log_entry(self) -> None:
        self._emit_hits([])
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({"queue": [{"file": "src/A.sol", "function": "hit"}]}),
            encoding="utf-8",
        )
        skip_log = self.ws / ".auditooor" / "hunt_coverage_skips.txt"
        skip_log.write_text(
            "A.sol::hit stale-review run_id=auditrun-old\n",
            encoding="utf-8",
        )
        orig = self._patch_gate_heatmap()
        try:
            stale = gate.check(
                str(self.ws),
                min_coverage=0.0,
                run_id="auditrun-current",
            )
            skip_log.write_text(
                "A.sol::hit current-review run_id=auditrun-current\n",
                encoding="utf-8",
            )
            current = gate.check(
                str(self.ws),
                min_coverage=0.0,
                run_id="auditrun-current",
            )
        finally:
            gate._load_heatmap = orig

        self.assertEqual(stale["verdict"], "fail-queued-not-scanned")
        self.assertEqual(stale["skip_logged_units"], [])
        self.assertEqual(stale["queued_not_scanned"], ["A.sol::hit"])
        self.assertEqual(current["verdict"], "pass-coverage-met")
        self.assertEqual(current["skip_logged_units"], ["A.sol::hit"])

    def test_rebuttal_line(self) -> None:
        r = gate.check(str(self.ws), rebuttal_text="g15-rebuttal: single-file repo")
        self.assertEqual(r["verdict"], "ok-rebuttal")

    def test_rebuttal_html(self) -> None:
        r = gate.check(str(self.ws), rebuttal_text="<!-- g15-rebuttal: operator-approved -->")
        self.assertEqual(r["verdict"], "ok-rebuttal")

    def test_rebuttal_oversized_ignored(self) -> None:
        # Oversized rebuttal ignored; with no hits it should still evaluate
        # coverage (and not short-circuit to ok-rebuttal).
        self._emit_hits([])
        orig = self._patch_gate_heatmap()
        try:
            r = gate.check(str(self.ws), min_coverage=0.80,
                           rebuttal_text="g15-rebuttal: " + ("x" * 250))
        finally:
            gate._load_heatmap = orig
        self.assertNotEqual(r["verdict"], "ok-rebuttal")

    # ------------------------------------------------------------------
    # Guard tests: strict function-coverage gate reconciliation (the fix
    # for the G15 false-pass bug where G15 "100% covered" contradicts
    # hundreds of hollow/untouched functions in function-coverage-completeness).
    # ------------------------------------------------------------------

    def _make_fake_fcc_module(self, verdict: str, hollow: int = 0, untouched: int = 0, total: int = 6) -> object:
        """Return a fake function-coverage-completeness module with a fixed evaluate()."""
        class FakeFCC:
            @staticmethod
            def evaluate(_ws):
                counts = {
                    "total": total,
                    "real_attack": total - hollow - untouched,
                    "hollow": hollow,
                    "untouched": untouched,
                }
                return {
                    "verdict": verdict,
                    "reason": f"fake fcc: {verdict}",
                    "counts": counts,
                    "functions": [],
                    "hollow_or_untouched": [],
                }
        return FakeFCC

    def test_strict_fn_coverage_disagrees_blocks_pass(self) -> None:
        # Bug guard: G15 token-coverage at 100% (all 6 units hit) but the
        # strict per-function gate says fail-functions-untouched-or-hollow.
        # G15 must NOT emit pass-coverage-met; it must emit
        # fail-strict-function-coverage-disagrees.
        self._emit_hits(["A.sol", "B.sol", "C.sol", "D.sol", "E.sol", "MathLib.sol"])
        orig_hm = self._patch_gate_heatmap()
        fake_fcc = self._make_fake_fcc_module(
            "fail-functions-untouched-or-hollow",
            hollow=50,
            untouched=86,
            total=136,
        )
        orig_fcc = gate._load_strict_fn_coverage_module
        gate._load_strict_fn_coverage_module = lambda: fake_fcc  # type: ignore
        try:
            r = gate.check(str(self.ws), min_coverage=0.80)
        finally:
            gate._load_heatmap = orig_hm
            gate._load_strict_fn_coverage_module = orig_fcc  # type: ignore
        self.assertEqual(r["verdict"], "fail-strict-function-coverage-disagrees",
                         f"expected fail, got {r['verdict']!r}; reason={r.get('reason')!r}")
        self.assertEqual(r["exit"], 1)
        self.assertEqual(r["strict_function_coverage_verdict"], "fail-functions-untouched-or-hollow")
        self.assertEqual(r["strict_function_coverage_hollow"], 50)
        self.assertEqual(r["strict_function_coverage_untouched"], 86)
        self.assertEqual(r["strict_function_coverage_total"], 136)

    def test_strict_fn_coverage_pass_allows_g15_pass(self) -> None:
        # When function-coverage-completeness passes, G15 should still emit
        # pass-coverage-met as before (no regression).
        self._emit_hits(["A.sol", "B.sol", "C.sol", "D.sol", "E.sol", "MathLib.sol"])
        orig_hm = self._patch_gate_heatmap()
        fake_fcc = self._make_fake_fcc_module(
            "pass-fully-covered",
            hollow=0,
            untouched=0,
            total=6,
        )
        orig_fcc = gate._load_strict_fn_coverage_module
        gate._load_strict_fn_coverage_module = lambda: fake_fcc  # type: ignore
        try:
            r = gate.check(str(self.ws), min_coverage=0.80)
        finally:
            gate._load_heatmap = orig_hm
            gate._load_strict_fn_coverage_module = orig_fcc  # type: ignore
        self.assertEqual(r["verdict"], "pass-coverage-met",
                         f"expected pass, got {r['verdict']!r}; reason={r.get('reason')!r}")
        self.assertEqual(r["exit"], 0)
        self.assertEqual(r["strict_function_coverage"]["verdict"], "pass-fully-covered")

    def test_strict_fn_coverage_absent_degrades_to_warn_pass(self) -> None:
        # When function-coverage-completeness.py is absent, G15 must NOT block
        # on tooling-absence; it degrades gracefully and still emits
        # pass-coverage-met (with a warn annotation).
        self._emit_hits(["A.sol", "B.sol", "C.sol", "D.sol", "E.sol", "MathLib.sol"])
        orig_hm = self._patch_gate_heatmap()
        orig_fcc = gate._load_strict_fn_coverage_module
        gate._load_strict_fn_coverage_module = lambda: None  # type: ignore
        try:
            r = gate.check(str(self.ws), min_coverage=0.80)
        finally:
            gate._load_heatmap = orig_hm
            gate._load_strict_fn_coverage_module = orig_fcc  # type: ignore
        self.assertEqual(r["verdict"], "pass-coverage-met",
                         f"expected pass on tooling-absence, got {r['verdict']!r}")
        self.assertIsNotNone(r["strict_function_coverage"]["warn"])

    def test_strict_fn_coverage_error_verdict_does_not_block(self) -> None:
        # Non-fail verdicts from function-coverage-completeness (error,
        # no-source, ok-rebuttal, etc.) must NOT block G15 pass.
        self._emit_hits(["A.sol", "B.sol", "C.sol", "D.sol", "E.sol", "MathLib.sol"])
        orig_hm = self._patch_gate_heatmap()
        try:
            for non_fail_verdict in ("error", "no-source", "pass-no-source", "ok-rebuttal", "unavailable"):
                fake_fcc = self._make_fake_fcc_module(non_fail_verdict, total=6)
                gate._load_strict_fn_coverage_module = lambda m=fake_fcc: m  # type: ignore
                r = gate.check(str(self.ws), min_coverage=0.80)
                self.assertEqual(
                    r["verdict"], "pass-coverage-met",
                    f"non-fail verdict {non_fail_verdict!r} must not block G15; got {r['verdict']!r}",
                )
        finally:
            gate._load_heatmap = orig_hm

    def test_strict_fn_coverage_zero_untouched_does_not_disagree(self) -> None:
        # When strict_uncovered == 0 (zero hollow + zero untouched), G15 passes.
        self._emit_hits(["A.sol", "B.sol", "C.sol", "D.sol", "E.sol", "MathLib.sol"])
        orig_hm = self._patch_gate_heatmap()
        # Simulate: FCC says pass-fully-covered with counts all real-attack.
        fake_fcc = self._make_fake_fcc_module("pass-fully-covered", hollow=0, untouched=0, total=6)
        orig_fcc = gate._load_strict_fn_coverage_module
        gate._load_strict_fn_coverage_module = lambda: fake_fcc  # type: ignore
        try:
            r = gate.check(str(self.ws), min_coverage=0.80)
        finally:
            gate._load_heatmap = orig_hm
            gate._load_strict_fn_coverage_module = orig_fcc  # type: ignore
        self.assertNotEqual(r["verdict"], "fail-strict-function-coverage-disagrees")
        self.assertEqual(r["verdict"], "pass-coverage-met")


if __name__ == "__main__":
    unittest.main()
