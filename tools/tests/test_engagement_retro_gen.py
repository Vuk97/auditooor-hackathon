#!/usr/bin/env python3
"""PR #128 — hermetic fixture tests for tools/engagement-retro-gen.py.

Covers Fixtures A-G from docs/PLAN_ENGAGEMENT_RETRO_AUTOGEN.md:

    A. workspace with no cost_runs/   → est_cost_usd unknown, $/accepted NA
    B. workspace with populated cost_runs/ → est_cost_usd float, wording set
    C. workspace with all submissions pending → resolved counts unknown,
       NEVER 0
    D. workspace with mixed outcomes via operator OUTCOMES.md → concrete
       int counts, accept-rate computed, $/accepted computed
    E. structured-lessons workspace → extraction_method=structured, line provenance
    F. regex-fallback-only workspace → extraction_method=regex_fallback, advisory
    G. advisory outcomes.jsonl provenance → outcome carries
       "(advisory; partial/stale)" tag and is NOT promoted to ground truth

All hermetic — every fixture is built inside ``tempfile.TemporaryDirectory``.
No real cost-telemetry runs (they exercise the real summarize_workspace
against synthetic stage_*.json files we write ourselves). No live
reference/outcomes.jsonl reads — tests pass an in-test fixture path or
/dev/null.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "engagement-retro-gen.py"
COST_TELEMETRY_PATH = ROOT / "tools" / "cost-telemetry.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "engagement_retro_gen", MODULE_PATH
    )
    assert spec and spec.loader, f"could not load {MODULE_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


retro = _load_module()


# --------------------------------------------------------------------------- #
# Fixture-builder helpers
# --------------------------------------------------------------------------- #


def _write_submissions_md(ws: Path, n: int = 3) -> None:
    lines = ["# Submissions", ""]
    severities = ["High", "Medium", "Low", "High", "Critical"]
    for i in range(1, n + 1):
        sev = severities[(i - 1) % len(severities)]
        lines.append(f"## Draft {i} — Synthetic finding number {i} (test fixture)")
        lines.append("")
        lines.append("### Severity")
        lines.append(f"- → Severity: {sev}")
        lines.append("")
        lines.append("Body text for submission " + str(i) + ".")
        lines.append("")
    (ws / "SUBMISSIONS.md").write_text("\n".join(lines), encoding="utf-8")


def _write_cost_runs(ws: Path, *, model: str = "sonnet-4.5", cost: float = 0.50) -> None:
    run_dir = ws / "cost_runs" / "20260101T000000Z"
    run_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "stage": "scan",
        "started_at": "2026-01-01T00:00:00+00:00",
        "duration_s": 120.0,
        "est_tokens": {"input": 1000, "output": 500},
        "est_cost_usd": cost,
        "model": model,
        "cost_source": "rate-card",
    }
    (run_dir / "stage_scan.json").write_text(
        json.dumps(payload, sort_keys=True), encoding="utf-8"
    )
    payload2 = {
        "stage": "draft",
        "started_at": "2026-01-01T00:02:00+00:00",
        "duration_s": 60.0,
        "est_tokens": {"input": 500, "output": 200},
        "est_cost_usd": cost / 2,
        "model": model,
        "cost_source": "rate-card",
    }
    (run_dir / "stage_draft.json").write_text(
        json.dumps(payload2, sort_keys=True), encoding="utf-8"
    )


def _write_empty_advisory_outcomes(tmp_root: Path) -> Path:
    """Create an empty advisory outcomes file so tests are hermetic."""
    p = tmp_root / "outcomes.jsonl"
    p.write_text("", encoding="utf-8")
    return p


def _write_advisory_outcomes(tmp_root: Path, rows: list[dict[str, Any]]) -> Path:
    p = tmp_root / "outcomes.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# Fixture A: no cost_runs/
# --------------------------------------------------------------------------- #


class FixtureA_NoCostRuns(unittest.TestCase):
    """est_cost_usd value=='unknown' with reason mentioning 'no cost_runs',
    $/accepted=='NA', RETROSPECTIVE.md says 'cost telemetry: unavailable'."""

    def test_no_cost_runs_emits_unknown_never_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_submissions_md(ws, n=2)
            advisory = _write_empty_advisory_outcomes(Path(tmp))

            sidecar = retro.generate_retrospective(
                ws,
                cost_telemetry_path=COST_TELEMETRY_PATH,
                advisory_outcomes_path=advisory,
                write_files=True,
            )

            cost = sidecar["metrics"]["est_cost_usd"]
            self.assertEqual(cost["value"], "unknown")
            self.assertIsNotNone(cost["unknown_reason"])
            self.assertIn("cost_runs", cost["unknown_reason"])
            self.assertNotEqual(cost["value"], 0)
            self.assertNotEqual(cost["value"], 0.0)

            dpa = sidecar["metrics"]["dollars_per_accepted"]
            self.assertEqual(dpa["value"], "NA")
            self.assertIsNotNone(dpa["unknown_reason"])

            md = (ws / "RETROSPECTIVE.md").read_text()
            self.assertIn("cost telemetry: unavailable", md)


# --------------------------------------------------------------------------- #
# Fixture B: cost_runs/ populated
# --------------------------------------------------------------------------- #


class FixtureB_PopulatedCostRuns(unittest.TestCase):
    def test_populated_cost_runs_carries_est_wording(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_submissions_md(ws, n=2)
            _write_cost_runs(ws, cost=0.50)
            advisory = _write_empty_advisory_outcomes(Path(tmp))

            sidecar = retro.generate_retrospective(
                ws,
                cost_telemetry_path=COST_TELEMETRY_PATH,
                advisory_outcomes_path=advisory,
                write_files=True,
            )
            cost = sidecar["metrics"]["est_cost_usd"]
            self.assertIsInstance(cost["value"], float)
            self.assertAlmostEqual(cost["value"], 0.75, places=2)
            self.assertTrue(cost.get("advisory") is True)
            self.assertIn("est_cost_usd", cost.get("wording", ""))
            self.assertIn("advisory; not a bill", cost.get("wording", ""))
            # est_duration_s
            dur = sidecar["metrics"]["est_duration_s"]
            self.assertIsInstance(dur["value"], float)
            self.assertAlmostEqual(dur["value"], 180.0, places=1)
            self.assertTrue(dur.get("advisory") is True)


# --------------------------------------------------------------------------- #
# Fixture C: all submissions pending
# --------------------------------------------------------------------------- #


class FixtureC_AllPending(unittest.TestCase):
    def test_all_pending_emits_unknown_never_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_submissions_md(ws, n=3)
            # advisory rows that are pending — should NOT promote to resolved
            advisory_rows = [
                {"finding_id": "1", "outcome": "pending", "severity": "High"},
                {"finding_id": "2", "outcome": "pending", "severity": "Medium"},
                {"finding_id": "3", "outcome": "pending", "severity": "Low"},
            ]
            advisory = _write_advisory_outcomes(Path(tmp), advisory_rows)

            sidecar = retro.generate_retrospective(
                ws,
                cost_telemetry_path=COST_TELEMETRY_PATH,
                advisory_outcomes_path=advisory,
                write_files=False,
            )
            m = sidecar["metrics"]
            self.assertEqual(m["accepted_count"]["value"], "unknown")
            self.assertEqual(m["rejected_count"]["value"], "unknown")
            self.assertEqual(m["duplicate_count"]["value"], "unknown")
            self.assertEqual(m["accept_rate"]["value"], "unknown")
            self.assertEqual(m["dollars_per_accepted"]["value"], "NA")
            # NEVER 0/null/inf
            for key in (
                "accepted_count",
                "rejected_count",
                "duplicate_count",
                "accept_rate",
            ):
                self.assertNotEqual(m[key]["value"], 0)
                self.assertNotEqual(m[key]["value"], 0.0)
                self.assertIsNotNone(m[key]["value"])
            self.assertEqual(m["dollars_per_accepted"]["value"], "NA")


# --------------------------------------------------------------------------- #
# Fixture D: mixed outcomes via operator OUTCOMES.md
# --------------------------------------------------------------------------- #


class FixtureD_OperatorOutcomes(unittest.TestCase):
    def test_operator_ledger_drives_concrete_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_submissions_md(ws, n=4)
            _write_cost_runs(ws, cost=10.0)  # est_cost_usd ~ 15.0 total
            outcomes_md = (
                "# Operator Outcomes\n\n"
                "| id | outcome | paid_usd |\n"
                "|---|---|---|\n"
                "| 1 | accepted | 100 |\n"
                "| 2 | duplicate | 0 |\n"
                "| 3 | rejected | 0 |\n"
                "| 4 | pending |  |\n"
            )
            (ws / "OUTCOMES.md").write_text(outcomes_md, encoding="utf-8")
            advisory = _write_empty_advisory_outcomes(Path(tmp))

            sidecar = retro.generate_retrospective(
                ws,
                cost_telemetry_path=COST_TELEMETRY_PATH,
                advisory_outcomes_path=advisory,
                write_files=False,
            )
            m = sidecar["metrics"]
            self.assertEqual(m["accepted_count"]["value"], 1)
            self.assertEqual(m["rejected_count"]["value"], 1)
            self.assertEqual(m["duplicate_count"]["value"], 1)
            self.assertEqual(m["pending_count"]["value"], 1)
            # accept-rate: 1 / (1+1+1) = 0.333...
            self.assertAlmostEqual(
                float(m["accept_rate"]["value"]), 1 / 3, places=4
            )
            # provenance points to OUTCOMES.md
            self.assertIn("OUTCOMES.md", m["accepted_count"]["provenance"])
            # $/accepted is computed
            self.assertIsInstance(m["dollars_per_accepted"]["value"], float)
            # And per-submission outcome provenance points at OUTCOMES.md:N
            sub1 = next(s for s in sidecar["submissions"] if s["id"] == "1")
            self.assertEqual(sub1["outcome"]["value"], "accepted")
            self.assertIn("OUTCOMES.md", sub1["outcome"]["provenance"])
            self.assertEqual(sub1["paid_usd"]["value"], 100.0)


# --------------------------------------------------------------------------- #
# Fixture E: structured lessons
# --------------------------------------------------------------------------- #


class FixtureE_StructuredLessons(unittest.TestCase):
    def test_structured_lessons_extracted_with_line_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_submissions_md(ws, n=1)
            retro_md = (
                "# Engagement notes\n"
                "\n"
                "## Lessons\n"
                "\n"
                "- AP-26: do not ship mock-PoC contamination\n"
                "- FN-5: collapse adjacent-novelty into one anchor finding\n"
                "\n"
                "## Other section\n"
                "\n"
                "- this should NOT be captured\n"
            )
            (ws / "RETRO.md").write_text(retro_md, encoding="utf-8")
            advisory = _write_empty_advisory_outcomes(Path(tmp))

            sidecar = retro.generate_retrospective(
                ws,
                cost_telemetry_path=COST_TELEMETRY_PATH,
                advisory_outcomes_path=advisory,
                write_files=False,
            )
            lessons = sidecar["lessons"]
            self.assertGreaterEqual(len(lessons), 2)
            for L in lessons:
                self.assertEqual(L["extraction_method"], "structured")
                self.assertIn("RETRO.md", L["source_file"])
                self.assertGreater(L["source_line"], 0)
            ap_match = [L for L in lessons if L.get("anti_pattern_match") == "AP-26"]
            self.assertEqual(len(ap_match), 1)
            # "Other section" content not captured
            self.assertFalse(
                any("should NOT be captured" in L["text"] for L in lessons)
            )


# --------------------------------------------------------------------------- #
# Fixture F: regex-fallback-only
# --------------------------------------------------------------------------- #


class FixtureF_RegexFallback(unittest.TestCase):
    def test_regex_fallback_when_no_structured_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_submissions_md(ws, n=1)
            notes_md = (
                "# Random notes\n"
                "\n"
                "Some prose here.\n"
                "\n"
                "- bullet referencing AP-26 anti-pattern (mock-PoC contamination)\n"
                "- another non-AP bullet\n"
                "- bullet referencing FN-5 collapse\n"
            )
            (ws / "NOTES.md").write_text(notes_md, encoding="utf-8")
            advisory = _write_empty_advisory_outcomes(Path(tmp))

            sidecar = retro.generate_retrospective(
                ws,
                cost_telemetry_path=COST_TELEMETRY_PATH,
                advisory_outcomes_path=advisory,
                write_files=False,
            )
            lessons = sidecar["lessons"]
            self.assertGreaterEqual(len(lessons), 2)
            for L in lessons:
                self.assertEqual(L["extraction_method"], "regex_fallback")
                self.assertTrue(L.get("advisory") is True)
                self.assertIn("NOTES.md", L["source_file"])
            # AP-26 should be captured exactly
            ap_match = [L for L in lessons if L.get("anti_pattern_match") == "AP-26"]
            self.assertEqual(len(ap_match), 1)


# --------------------------------------------------------------------------- #
# Fixture G: advisory outcomes.jsonl provenance is preserved + not promoted
# --------------------------------------------------------------------------- #


class FixtureG_AdvisoryOutcomesProvenance(unittest.TestCase):
    def test_advisory_outcomes_tagged_and_not_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_submissions_md(ws, n=2)
            # Advisory rows ASSERT one accepted — but no operator ledger exists.
            # The retro tool MUST NOT promote this into accepted_count.
            advisory_rows = [
                {"finding_id": "1", "outcome": "accepted", "severity": "High"},
                {"finding_id": "2", "outcome": "pending", "severity": "Low"},
            ]
            advisory = _write_advisory_outcomes(Path(tmp), advisory_rows)

            sidecar = retro.generate_retrospective(
                ws,
                cost_telemetry_path=COST_TELEMETRY_PATH,
                advisory_outcomes_path=advisory,
                write_files=False,
            )
            # Per-submission outcome provenance carries advisory tag.
            sub1 = next(s for s in sidecar["submissions"] if s["id"] == "1")
            self.assertEqual(sub1["outcome"]["value"], "accepted")
            self.assertIn(
                "advisory; partial/stale", sub1["outcome"]["provenance"]
            )
            self.assertTrue(sub1["outcome"].get("advisory") is True)

            # CRITICAL: accepted_count must remain UNKNOWN — advisory rows do
            # not feed the resolved-outcome buckets.
            m = sidecar["metrics"]
            self.assertEqual(m["accepted_count"]["value"], "unknown")
            self.assertEqual(m["accept_rate"]["value"], "unknown")
            self.assertEqual(m["dollars_per_accepted"]["value"], "NA")

            # paid_usd remains unknown (no workspace ledger)
            self.assertEqual(sub1["paid_usd"]["value"], "unknown")


# --------------------------------------------------------------------------- #
# Bonus: schema invariants — no metric is 0/null/inf when it should be unknown
# --------------------------------------------------------------------------- #


class SchemaInvariants(unittest.TestCase):
    def test_metric_objects_obey_truth_discipline(self) -> None:
        """For an empty workspace, every metric is an object with the contract:
        value ∈ concrete | 'unknown' | 'NA'; provenance None iff value unknown/NA;
        unknown_reason non-null iff value unknown/NA."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_submissions_md(ws, n=0)  # writes only header
            advisory = _write_empty_advisory_outcomes(Path(tmp))
            sidecar = retro.generate_retrospective(
                ws,
                cost_telemetry_path=COST_TELEMETRY_PATH,
                advisory_outcomes_path=advisory,
                write_files=False,
            )
            for name, m in sidecar["metrics"].items():
                self.assertIsInstance(m, dict, f"{name} must be a dict")
                self.assertIn("value", m, name)
                self.assertIn("provenance", m, name)
                self.assertIn("unknown_reason", m, name)
                v = m["value"]
                if v in ("unknown", "NA"):
                    self.assertIsNone(m["provenance"], name)
                    self.assertIsNotNone(m["unknown_reason"], name)
                else:
                    self.assertIsNotNone(m["provenance"], name)
                    self.assertIsNone(m["unknown_reason"], name)
                # Never inf/null/0-as-stand-in for missing.
                self.assertIsNotNone(v, name)
                # If not concrete, must be one of these literal strings.
                if isinstance(v, str):
                    self.assertIn(v, ("unknown", "NA"), name)


if __name__ == "__main__":
    unittest.main()
