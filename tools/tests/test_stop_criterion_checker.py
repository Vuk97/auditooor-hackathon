#!/usr/bin/env python3
"""Tests for tools/stop-criterion-checker.py.

Covers:
  - R85 consecutive-FP check (6 consecutive FPs fire STOP)
  - R85 mixed TP/FP window does NOT fire
  - Window smaller than fp_window does NOT fire
  - Case-study frontmatter loading (_parse_frontmatter)
  - Workspace-class detection fallback
  - Paste-citation check (MISSING-CITATION fires on uncited slug)
  - CLI exit codes: 0 (CONTINUE), 1 (STOP/MISSING), 2 (UNKNOWN)
  - JSON output flag
  - Multiple surfaces: only the exhausted one fires
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "stop-criterion-checker.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("stop_criterion_checker", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {SCRIPT}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


checker = _load_checker()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_workspace(tmp: Path, attempts: list[dict] | None = None,
                    intake_text: str = "") -> Path:
    """Create a minimal workspace with .auditooor/ and optional attempt log."""
    ws = tmp / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    auditooor_dir = ws / ".auditooor"
    auditooor_dir.mkdir(exist_ok=True)

    if attempts is not None:
        (auditooor_dir / "finding_attempts.json").write_text(
            json.dumps(attempts), encoding="utf-8"
        )

    if intake_text:
        (ws / "INTAKE_BASELINE.md").write_text(intake_text, encoding="utf-8")

    return ws


def _make_case_study_dir(tmp: Path, studies: list[str]) -> Path:
    """Write case-study markdown files and return the dir."""
    cs_dir = tmp / "case_study"
    cs_dir.mkdir(parents=True, exist_ok=True)
    for i, body in enumerate(studies):
        (cs_dir / f"study_{i:02d}.md").write_text(body, encoding="utf-8")
    return cs_dir


def _run_main(argv: list[str]) -> int:
    return checker.main(argv)


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestParseFrontmatter(unittest.TestCase):
    def test_basic_scalars(self):
        md = textwrap.dedent("""\
            ---
            case_id: test-case
            class: lending
            severity_class: HIGH
            ---
            # body
        """)
        fm = checker._parse_frontmatter(md)
        self.assertEqual(fm["case_id"], "test-case")
        self.assertEqual(fm["class"], "lending")
        self.assertEqual(fm["severity_class"], "HIGH")

    def test_list_field(self):
        md = textwrap.dedent("""\
            ---
            case_id: list-case
            applicable_workspace_classes:
              - lending
              - vault
            ---
        """)
        fm = checker._parse_frontmatter(md)
        self.assertIn("lending", fm["applicable_workspace_classes"])
        self.assertIn("vault", fm["applicable_workspace_classes"])

    def test_block_scalar(self):
        md = textwrap.dedent("""\
            ---
            case_id: block-case
            stop_criterion: >
              6 consecutive FPs on a surface means it is exhausted.
              Pivot to specification-level analysis.
            ---
        """)
        fm = checker._parse_frontmatter(md)
        self.assertIn("exhausted", fm.get("stop_criterion", ""))

    def test_no_frontmatter(self):
        md = "# Just a heading\n\nSome text."
        fm = checker._parse_frontmatter(md)
        self.assertEqual(fm, {})

    def test_workflow_predicate_fields(self):
        md = textwrap.dedent("""\
            ---
            case_id: wp-case
            stop_criterion: 6 consecutive FPs fires STOP
            workflow_signature: scanner_triage_exhausted
            loop_back_phase: phase-5-cold-read
            ---
        """)
        fm = checker._parse_frontmatter(md)
        self.assertEqual(fm["stop_criterion"], "6 consecutive FPs fires STOP")
        self.assertEqual(fm["workflow_signature"], "scanner_triage_exhausted")
        self.assertEqual(fm["loop_back_phase"], "phase-5-cold-read")


class TestR85ConsecutiveFP(unittest.TestCase):
    def _make_attempts(self, verdicts: list[str], surface: str = "v2-exchange") -> list[dict]:
        return [
            {
                "timestamp": f"2026-04-{10 + i:02d}T12:00:00Z",
                "surface": surface,
                "tool": "slither",
                "candidate_id": f"R85-{chr(65 + i)}",
                "verdict": v,
            }
            for i, v in enumerate(verdicts)
        ]

    def test_six_fp_fires_stop(self):
        attempts = self._make_attempts(["FP"] * 6)
        triggers = checker._check_r85_consecutive_fp(attempts, fp_window=6)
        self.assertEqual(len(triggers), 1)
        self.assertEqual(triggers[0]["verdict"], "STOP")
        self.assertEqual(triggers[0]["surface"], "v2-exchange")
        self.assertEqual(triggers[0]["consecutive_fps"], 6)

    def test_five_fp_does_not_fire(self):
        attempts = self._make_attempts(["FP"] * 5)
        triggers = checker._check_r85_consecutive_fp(attempts, fp_window=6)
        self.assertEqual(triggers, [])

    def test_tp_in_window_resets(self):
        # Last 6 = TP + 5 FP → not all FP → no trigger
        attempts = self._make_attempts(["FP"] * 5 + ["TP"])
        triggers = checker._check_r85_consecutive_fp(attempts, fp_window=6)
        self.assertEqual(triggers, [])

    def test_tp_at_start_then_six_fp_fires(self):
        # 1 TP then 6 consecutive FP → window is last 6 = all FP → fires
        attempts = self._make_attempts(["TP"] + ["FP"] * 6)
        triggers = checker._check_r85_consecutive_fp(attempts, fp_window=6)
        self.assertEqual(len(triggers), 1)
        self.assertEqual(triggers[0]["verdict"], "STOP")

    def test_custom_window(self):
        attempts = self._make_attempts(["FP"] * 3)
        triggers = checker._check_r85_consecutive_fp(attempts, fp_window=3)
        self.assertEqual(len(triggers), 1)

    def test_multiple_surfaces_only_exhausted_fires(self):
        attempts_a = self._make_attempts(["FP"] * 6, surface="v2-exchange")
        attempts_b = self._make_attempts(["TP", "FP", "TP", "FP", "FP", "TP"],
                                          surface="vault")
        triggers = checker._check_r85_consecutive_fp(
            attempts_a + attempts_b, fp_window=6
        )
        self.assertEqual(len(triggers), 1)
        self.assertEqual(triggers[0]["surface"], "v2-exchange")

    def test_empty_attempts(self):
        triggers = checker._check_r85_consecutive_fp([], fp_window=6)
        self.assertEqual(triggers, [])


class TestWorkspaceClassDetection(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="scc-cls-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_detects_lending(self):
        ws = _make_workspace(self.tmp, intake_text="This morpho lending protocol uses borrow mechanics")
        cls = checker._detect_workspace_class(ws)
        self.assertEqual(cls, "lending")

    def test_detects_prediction_market(self):
        ws = _make_workspace(self.tmp, intake_text="Polymarket CTF exchange prediction market outcomes")
        cls = checker._detect_workspace_class(ws)
        self.assertEqual(cls, "prediction-market")

    def test_unknown_class(self):
        ws = _make_workspace(self.tmp, intake_text="")
        cls = checker._detect_workspace_class(ws)
        self.assertIsNone(cls)


class TestCaseStudyLoader(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="scc-cs-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _cs_body(self, case_id: str, classes: list[str],
                 stop_criterion: str = "", workflow_sig: str = "",
                 loop_back: str = "") -> str:
        lines = [
            "---",
            f"case_id: {case_id}",
            "applicable_workspace_classes:",
        ]
        for c in classes:
            lines.append(f"  - {c}")
        if stop_criterion:
            lines.append(f"stop_criterion: {stop_criterion}")
        if workflow_sig:
            lines.append(f"workflow_signature: {workflow_sig}")
        if loop_back:
            lines.append(f"loop_back_phase: {loop_back}")
        lines.append("---")
        lines.append("# body")
        return "\n".join(lines)

    def test_loads_matching_study(self):
        cs_dir = _make_case_study_dir(
            self.tmp,
            [self._cs_body("r85-test", ["lending", "vault"],
                           stop_criterion="6 consecutive FPs fire STOP")]
        )
        studies = checker._load_case_studies(cs_dir)
        matched = checker._match_case_studies(studies, "lending")
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["case_id"], "r85-test")

    def test_no_match_for_wrong_class(self):
        cs_dir = _make_case_study_dir(
            self.tmp,
            [self._cs_body("r85-test", ["bridge"])]
        )
        studies = checker._load_case_studies(cs_dir)
        matched = checker._match_case_studies(studies, "lending")
        self.assertEqual(matched, [])

    def test_workflow_methodology_always_matches(self):
        cs_dir = _make_case_study_dir(
            self.tmp,
            [self._cs_body("r88-test", ["workflow-methodology"],
                           stop_criterion="hard-stop on missing tools")]
        )
        studies = checker._load_case_studies(cs_dir)
        # workflow-methodology in applicable_workspace_classes → matches any class
        matched = checker._match_case_studies(studies, "lending")
        self.assertEqual(len(matched), 1)

    def test_workflow_predicates_emitted(self):
        cs_dir = _make_case_study_dir(
            self.tmp,
            [self._cs_body("r85-pred", ["lending"],
                           stop_criterion="6 FPs exhaust surface",
                           workflow_sig="scanner_triage_exhausted",
                           loop_back="phase-5-cold-read")]
        )
        studies = checker._load_case_studies(cs_dir)
        matched = checker._match_case_studies(studies, "lending")
        ws = _make_workspace(self.tmp)
        triggers = checker._check_workflow_predicates(matched, ws)
        self.assertEqual(len(triggers), 1)
        self.assertEqual(triggers[0]["workflow_signature"], "scanner_triage_exhausted")
        self.assertEqual(triggers[0]["loop_back_phase"], "phase-5-cold-read")
        self.assertEqual(triggers[0]["verdict"], "APPLICABLE")


class TestPasteCitationCheck(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="scc-paste-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_paste(self, body: str) -> Path:
        p = self.tmp / "paste.md"
        p.write_text(body, encoding="utf-8")
        return p

    def test_citation_present(self):
        paste = self._write_paste("# Finding\n\nSee r85-v2-exchange-surface-exhausted for context.\n")
        studies = [{"case_id": "r85-v2-exchange-surface-exhausted"}]
        missing = checker._check_paste_citations(paste, studies)
        self.assertEqual(missing, [])

    def test_citation_missing(self):
        paste = self._write_paste("# Finding\n\nNo case study reference here.\n")
        studies = [{"case_id": "r85-v2-exchange-surface-exhausted"}]
        missing = checker._check_paste_citations(paste, studies)
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["verdict"], "MISSING-CITATION")
        self.assertIn("r85-v2-exchange-surface-exhausted", missing[0]["message"])

    def test_missing_paste_file(self):
        studies = [{"case_id": "r85-test"}]
        missing = checker._check_paste_citations(
            self.tmp / "nonexistent.md", studies
        )
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["verdict"], "UNKNOWN")


class TestCLIExitCodes(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="scc-cli-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _empty_cs_dir(self) -> Path:
        cs = self.tmp / "cs_empty"
        cs.mkdir(exist_ok=True)
        return cs

    def test_continue_on_empty_workspace(self):
        ws = _make_workspace(self.tmp, attempts=[])
        rc = _run_main([
            "--workspace", str(ws),
            "--case-study-dir", str(self._empty_cs_dir()),
        ])
        self.assertEqual(rc, 0)

    def test_stop_on_six_consecutive_fp(self):
        attempts = [
            {"timestamp": f"2026-04-{10+i:02d}T12:00:00Z",
             "surface": "v2", "tool": "slither",
             "candidate_id": f"R-{i}", "verdict": "FP"}
            for i in range(6)
        ]
        ws = _make_workspace(self.tmp, attempts=attempts)
        rc = _run_main([
            "--workspace", str(ws),
            "--case-study-dir", str(self._empty_cs_dir()),
        ])
        self.assertEqual(rc, 1)

    def test_continue_on_five_fp(self):
        attempts = [
            {"timestamp": f"2026-04-{10+i:02d}T12:00:00Z",
             "surface": "v2", "tool": "slither",
             "candidate_id": f"R-{i}", "verdict": "FP"}
            for i in range(5)
        ]
        ws = _make_workspace(self.tmp, attempts=attempts)
        rc = _run_main([
            "--workspace", str(ws),
            "--case-study-dir", str(self._empty_cs_dir()),
        ])
        self.assertEqual(rc, 0)

    def test_json_flag_emits_valid_json(self):
        ws = _make_workspace(self.tmp, attempts=[])
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            _run_main([
                "--workspace", str(ws),
                "--case-study-dir", str(self._empty_cs_dir()),
                "--json",
            ])
        output = buf.getvalue()
        data = json.loads(output)
        self.assertIn("verdict", data)
        self.assertIn("triggers", data)

    def test_custom_fp_window(self):
        attempts = [
            {"timestamp": f"2026-04-{10+i:02d}T12:00:00Z",
             "surface": "v2", "tool": "slither",
             "candidate_id": f"R-{i}", "verdict": "FP"}
            for i in range(3)
        ]
        ws = _make_workspace(self.tmp, attempts=attempts)
        # fp_window=3 → should fire STOP
        rc = _run_main([
            "--workspace", str(ws),
            "--case-study-dir", str(self._empty_cs_dir()),
            "--fp-window", "3",
        ])
        self.assertEqual(rc, 1)

    def test_workspace_not_found_returns_3(self):
        rc = _run_main(["--workspace", "/tmp/scc-nonexistent-12345"])
        self.assertEqual(rc, 3)


class TestJSONLAttemptLog(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="scc-jsonl-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_jsonl_format_loaded(self):
        ws = self.tmp / "ws"
        ws.mkdir()
        ad = ws / ".auditooor"
        ad.mkdir()
        lines = [
            json.dumps({
                "timestamp": f"2026-04-{10+i:02d}T12:00:00Z",
                "surface": "v2",
                "tool": "slither",
                "candidate_id": f"X-{i}",
                "verdict": "FP",
            })
            for i in range(6)
        ]
        (ad / "finding_attempts.jsonl").write_text("\n".join(lines), encoding="utf-8")
        attempts = checker._load_attempts(ws)
        self.assertEqual(len(attempts), 6)
        triggers = checker._check_r85_consecutive_fp(attempts, fp_window=6)
        self.assertEqual(len(triggers), 1)
        self.assertEqual(triggers[0]["verdict"], "STOP")


class TestRealCaseStudyDir(unittest.TestCase):
    """Smoke-test against the real case_study/ directory in this repo."""

    def test_loads_real_case_studies(self):
        cs_dir = REPO / "case_study"
        if not cs_dir.is_dir():
            self.skipTest("case_study/ directory not found in repo")
        studies = checker._load_case_studies(cs_dir)
        self.assertGreater(len(studies), 0, "Expected at least 1 case study")
        # Every loaded study must have case_id
        for s in studies:
            self.assertIn("case_id", s, f"Missing case_id in {s.get('_source_file')}")

    def test_r85_case_study_has_workflow_predicates(self):
        cs_dir = REPO / "case_study"
        if not cs_dir.is_dir():
            self.skipTest("case_study/ directory not found in repo")
        studies = checker._load_case_studies(cs_dir)
        r85 = next((s for s in studies if s.get("case_id") == "r85-v2-exchange-surface-exhausted"), None)
        self.assertIsNotNone(r85, "R85 case study not found in case_study/")
        self.assertIn("stop_criterion", r85,
                      "R85 case study missing stop_criterion frontmatter field")
        self.assertIn("workflow_signature", r85,
                      "R85 case study missing workflow_signature frontmatter field")
        self.assertIn("loop_back_phase", r85,
                      "R85 case study missing loop_back_phase frontmatter field")


if __name__ == "__main__":
    unittest.main()
