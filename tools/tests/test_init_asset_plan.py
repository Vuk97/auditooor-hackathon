from __future__ import annotations

import importlib.util
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "init-asset-plan.sh"
INTAKE = REPO / "tools" / "intake-baseline.py"


def _load_intake():
    spec = importlib.util.spec_from_file_location("intake_baseline", INTAKE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class InitAssetPlanTest(unittest.TestCase):
    def test_smart_contract_declared_in_scope_scaffolds_plan_with_correct_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text(
                "# Scope\n\n"
                "- Asset type: Smart Contract\n"
            )

            result = subprocess.run(
                ["bash", str(TOOL), str(ws)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            plan_file = ws / "ASSET_PLAN_Smart_Contract.md"
            self.assertTrue(plan_file.is_file())
            text = plan_file.read_text()
            # Heading line uses em dash + asset label
            self.assertIn("# Asset Coverage Plan — Smart Contract", text)
            # Required parser keys (key:value form, exactly as
            # tools/intake-baseline.py expects).
            self.assertRegex(text, r"(?m)^- Strategy:\s+TBD")
            self.assertRegex(text, r"(?m)^- Estimated hours:\s+0\s*$")
            self.assertRegex(text, r"(?m)^- Agent hour quota pct:\s+0\s*$")
            # Plan-status default is `missing`, NOT `ready` (operator must
            # promote explicitly after filling in real values).
            self.assertRegex(text, r"(?m)^- Plan status:\s+missing\s*$")
            # `## Roots` section must be present and parseable as a bullet
            # list per PR #120 lesson 3 — the absence of a bulleted Roots
            # section trips the malformed-roots branch in the parser.
            self.assertIn("## Roots", text)
            self.assertRegex(text, r"(?m)^- ")

    def test_existing_plan_file_is_refused_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text("- Asset: Smart Contract\n")
            existing = ws / "ASSET_PLAN_Smart_Contract.md"
            existing.write_text("# Operator hand-edited content — do not lose\n")

            result = subprocess.run(
                ["bash", str(TOOL), str(ws)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # Skip message printed
            self.assertIn("already exists", result.stdout)
            # Original content preserved
            self.assertEqual(
                existing.read_text(),
                "# Operator hand-edited content — do not lose\n",
            )

    def test_force_flag_overrides_existing_plan_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text("- Asset type: Smart Contract\n")
            existing = ws / "ASSET_PLAN_Smart_Contract.md"
            existing.write_text("# stale\n")

            result = subprocess.run(
                ["bash", str(TOOL), str(ws), "--force"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            text = existing.read_text()
            self.assertIn("# Asset Coverage Plan — Smart Contract", text)
            self.assertIn("Plan status: missing", text)
            self.assertNotIn("# stale", text)

    def test_multi_word_asset_label_renders_underscored_filename(self):
        """Blockchain/DLT must become ASSET_PLAN_Blockchain_DLT.md (slash and
        any other non-alnum characters collapse to a single underscore).
        Web/App must become ASSET_PLAN_Web_App.md. This matches the
        slug rule in tools/intake-baseline.py::_asset_slug()."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text(
                "# Scope\n\n"
                "Assets in scope: Smart Contract, Blockchain/DLT, Web/App\n"
            )

            result = subprocess.run(
                ["bash", str(TOOL), str(ws)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((ws / "ASSET_PLAN_Smart_Contract.md").is_file())
            self.assertTrue((ws / "ASSET_PLAN_Blockchain_DLT.md").is_file())
            self.assertTrue((ws / "ASSET_PLAN_Web_App.md").is_file())
            # Heading carries the original (slash-bearing) label, not the slug.
            bdl = (ws / "ASSET_PLAN_Blockchain_DLT.md").read_text()
            self.assertIn("# Asset Coverage Plan — Blockchain/DLT", bdl)
            web = (ws / "ASSET_PLAN_Web_App.md").read_text()
            self.assertIn("# Asset Coverage Plan — Web/App", web)

    def test_scaffolded_file_is_parseable_by_intake_baseline(self):
        """End-to-end: the scaffolded file must be parsed by
        tools/intake-baseline.py::_read_plan_file() without errors. The
        Roots section must be parseable per PR #120 lesson 3."""
        intake = _load_intake()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text("- Asset type: Smart Contract\n")

            result = subprocess.run(
                ["bash", str(TOOL), str(ws)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            parsed = intake._read_plan_file(ws, "ASSET_PLAN_Smart_Contract.md")

        self.assertIsNotNone(parsed)
        # Plan-status default is `missing` — not `ready` — so the parser will
        # correctly refuse to clear the asset-coverage gate until the operator
        # promotes it.
        self.assertEqual(parsed["plan_status"], "missing")
        # Estimated hours / quota parse to int 0.
        self.assertEqual(parsed.get("estimated_hours"), 0)
        self.assertEqual(parsed.get("agent_hour_quota_pct"), 0)
        # The bulleted Roots section parses (status != "missing"); the single
        # placeholder bullet under `## Roots` is captured.
        self.assertIn(
            parsed.get("roots_parse_status"), ("parsed", None)
        )

    def test_missing_scope_file_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            result = subprocess.run(
                ["bash", str(TOOL), str(ws)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("SCOPE.md", result.stdout + result.stderr)


class IntakeBaselineHintTest(unittest.TestCase):
    """The intake-baseline blocker emit must include the autofix hint when
    asset-plan-related blockers fire (I-02). Regression: previously operators
    had to read source to find the required structure."""

    def test_hint_appears_when_asset_plan_missing(self):
        intake = _load_intake()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text(
                "# Critical\n- Theft\n\n# High\n- Freeze\n"
            )
            (ws / "RUBRIC_COVERAGE.md").write_text(
                "# Rubric Coverage\n\n"
                "**Severity source files:**\n"
                "- `SEVERITY_SMART_CONTRACTS.md`\n\n"
                "| # | Example | Verdict | Evidence / Gap |\n"
                "|---|---|---|---|\n"
                "| C1 | Theft | 📋 NOT CHECKED | — |\n"
            )
            # No ASSET_PLAN_Smart_Contract.md → asset-coverage blocker fires.
            payload = intake.build_baseline(ws)

        blockers = payload["blockers"]
        # The plan-status blocker is present.
        self.assertTrue(
            any("Smart Contract" in b and "plan_status=" in b for b in blockers),
            f"missing plan_status blocker; got: {blockers}",
        )
        # The autofix hint is present.
        self.assertTrue(
            any("init-asset-plan.sh" in b for b in blockers),
            f"missing init-asset-plan.sh hint; got: {blockers}",
        )


if __name__ == "__main__":
    unittest.main()
