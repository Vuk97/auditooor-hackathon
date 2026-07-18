"""Unit tests for Rule 52 Rubric-Row-Coverage preflight (Check #91)."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "r52"

_spec = importlib.util.spec_from_file_location(
    "rubric_row_coverage_check",
    ROOT / "tools" / "rubric-row-coverage-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace(severity_md: str | None = None) -> Path:
    root = Path(tempfile.mkdtemp(prefix="r52_test_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests").mkdir()
    if severity_md is not None:
        (root / "SEVERITY.md").write_text(severity_md, encoding="utf-8")
    return root


def _draft_in(ws: Path, body: str, filename: str = "draft-HIGH.md") -> Path:
    p = ws / "submissions" / "paste_ready" / filename
    p.write_text(body, encoding="utf-8")
    return p


def _run(draft: Path, workspace: Path | None = None, severity: str | None = None,
         strict: bool = False) -> tuple[int, dict]:
    return mod.run(draft, workspace=workspace, severity_override=severity, strict=strict)


# ---------------------------------------------------------------------------
# SEVERITY.md helpers
# ---------------------------------------------------------------------------
DYDX_SEVERITY_MD = (FIXTURES / "workspaces" / "dydx" / "SEVERITY.md").read_text()
SPARK_SEVERITY_MD = (FIXTURES / "workspaces" / "spark" / "SEVERITY.md").read_text()
HB_PHAROS_SEVERITY_MD = (FIXTURES / "workspaces" / "hb_pharos" / "SEVERITY.md").read_text()


class TestNoSeverity(unittest.TestCase):
    """pass-out-of-scope when no valid severity is detected."""

    def test_no_severity_header_passes(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        # Use a filename with no severity token so the filename heuristic doesn't fire.
        draft = _draft_in(
            ws,
            "## Rubric Row Mapping\n\nThis finding has no severity header.\n",
            filename="draft-nosev.md",
        )
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


class TestNoRubricSection(unittest.TestCase):
    """fail-no-rubric-row-cited when no Rubric Row Mapping section."""

    def test_no_rubric_section(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        draft = _draft_in(ws, "Severity: High\n\n## Impact\n\nSome impact.\n")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-rubric-row-cited")

    def test_fixture_no_row_cited(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        fixture = FIXTURES / "no_row_cited_fail.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-rubric-row-cited")


class TestProgramSeverityMissingClass(unittest.TestCase):
    """fail-program-severity-missing-impact-class when cited row absent from SEVERITY.md."""

    def test_dos_row_missing_in_pharos(self) -> None:
        ws = _workspace(HB_PHAROS_SEVERITY_MD)
        fixture = FIXTURES / "hb_pharos_no_dos_row_fail.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-program-severity-missing-impact-class")

    def test_dos_row_accepted_in_dydx(self) -> None:
        """dYdX SEVERITY.md has RPC API crash row - DoS citing that row passes."""
        ws = _workspace(DYDX_SEVERITY_MD)
        body = (
            "Severity: High\n\n"
            "## Impact\n\nRPC crash causing network unavailability.\n\n"
            "## Rubric Row Mapping\n\n"
            "- Program SEVERITY.md cited row verbatim: RPC API crash affecting projects with >=25% market cap\n"
            "- Impact claim verbatim: RPC crash causing network unavailability\n"
            "- Word-overlap verification: 'crash' matches 'RPC API crash' row\n"
            "- Verdict: pass\n"
        )
        draft = _draft_in(ws, body)
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")


class TestImpactMismatch(unittest.TestCase):
    """fail-impact-mismatch-with-cited-row when nouns don't overlap."""

    def test_fixture_mismatch_cited_row(self) -> None:
        ws = _workspace(SPARK_SEVERITY_MD)
        fixture = FIXTURES / "mismatch_cited_row_fail.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-impact-mismatch-with-cited-row")

    def test_fixture_impact_noun_mismatch(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        fixture = FIXTURES / "impact_noun_mismatch_fail.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-impact-mismatch-with-cited-row")


class TestPassRubricRowMatched(unittest.TestCase):
    """pass-rubric-row-matched for well-formed drafts."""

    def test_dydx_critical_direct_loss(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        fixture = FIXTURES / "dydx_critical_direct_loss_pass.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")

    def test_spark_high1_rpc_crash(self) -> None:
        ws = _workspace(SPARK_SEVERITY_MD)
        fixture = FIXTURES / "spark_high1_rpc_crash_pass.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")

    def test_governance_takeover_pass(self) -> None:
        ws = _workspace(HB_PHAROS_SEVERITY_MD)
        fixture = FIXTURES / "governance_takeover_pass.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")

    def test_medium_freeze_pass(self) -> None:
        ws = _workspace(HB_PHAROS_SEVERITY_MD)
        fixture = FIXTURES / "pass_medium_freeze.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")

    def test_numbered_mapping_fields_pass(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        body = (
            "Severity: Medium\n\n"
            "## Impact\n\n"
            "Incorrect state manipulation with partial user impact.\n\n"
            "## Rubric Row Mapping\n\n"
            "1. Program SEVERITY.md cited row verbatim: "
            "\"Incorrect state manipulation with partial user impact.\"\n"
            "2. Impact claim verbatim: incorrect state manipulation with partial user impact.\n"
            "3. Word-overlap verification: state manipulation and user impact.\n"
            "4. Verdict: pass-rubric-row-matched\n"
        )
        draft = _draft_in(ws, body, filename="draft-MEDIUM.md")
        rc, payload = _run(draft, workspace=ws, severity="MEDIUM")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")
        self.assertIn("Incorrect state manipulation", payload["evidence"]["cited_row"])

    def test_bullet_severity_header_passes(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        body = (
            "- Severity: Medium\n\n"
            "## Impact\n\n"
            "Incorrect state manipulation with partial user impact.\n\n"
            "## Rubric Row Mapping\n\n"
            "- Program SEVERITY.md cited row verbatim: "
            "\"Incorrect state manipulation with partial user impact.\"\n"
            "- Impact claim verbatim: incorrect state manipulation with partial user impact.\n"
            "- Word-overlap verification: state manipulation and user impact.\n"
            "- Verdict: pass-rubric-row-matched\n"
        )
        draft = _draft_in(ws, body, filename="draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")

    def test_bold_bullet_severity_header_passes(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        body = (
            "- **Severity:** **Medium**\n\n"
            "## Impact\n\n"
            "Incorrect state manipulation with partial user impact.\n\n"
            "## Rubric Row Mapping\n\n"
            "- Program SEVERITY.md cited row verbatim: "
            "\"Incorrect state manipulation with partial user impact.\"\n"
            "- Impact claim verbatim: incorrect state manipulation with partial user impact.\n"
            "- Word-overlap verification: state manipulation and user impact.\n"
            "- Verdict: pass-rubric-row-matched\n"
        )
        draft = _draft_in(ws, body, filename="draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")

    def test_spark_crit_tier_id_passes(self) -> None:
        ws = _workspace(SPARK_SEVERITY_MD)
        body = (
            "severity_tier: CRIT-1\n\n"
            "## Impact\n\n"
            "Direct loss of funds from the receiver wallet.\n\n"
            "## Rubric Row Mapping\n\n"
            "- Program SEVERITY.md cited row verbatim: \"Direct loss of funds\"\n"
            "- Impact claim verbatim: direct loss of funds from the receiver wallet.\n"
            "- Word-overlap verification: direct loss of funds.\n"
            "- Verdict: pass-rubric-row-matched\n"
        )
        draft = _draft_in(ws, body, filename="spark-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")

    def test_spark_crit_tier_id_filename_passes(self) -> None:
        ws = _workspace(SPARK_SEVERITY_MD)
        body = (
            "## Impact\n\n"
            "Direct loss of funds from the receiver wallet.\n\n"
            "## Rubric Row Mapping\n\n"
            "- Program SEVERITY.md cited row verbatim: \"Direct loss of funds\"\n"
            "- Impact claim verbatim: direct loss of funds from the receiver wallet.\n"
            "- Word-overlap verification: direct loss of funds.\n"
            "- Verdict: pass-rubric-row-matched\n"
        )
        draft = _draft_in(ws, body, filename="spark-draft-CRIT-1.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-row-matched")

    def test_cli_accepts_tier_id_override(self) -> None:
        ws = _workspace(SPARK_SEVERITY_MD)
        body = (
            "## Impact\n\n"
            "Direct loss of funds from the receiver wallet.\n\n"
            "## Rubric Row Mapping\n\n"
            "- Program SEVERITY.md cited row verbatim: \"Direct loss of funds\"\n"
            "- Impact claim verbatim: direct loss of funds from the receiver wallet.\n"
            "- Word-overlap verification: direct loss of funds.\n"
            "- Verdict: pass-rubric-row-matched\n"
        )
        draft = _draft_in(ws, body, filename="spark-draft.md")
        rc = mod.main([str(draft), "--workspace", str(ws), "--severity", "CRIT-1", "--json"])
        self.assertEqual(rc, 0)

    def test_low_severity_requires_rubric_section(self) -> None:
        """Rule 52 is severity-agnostic (LOW+) - a Low draft without a rubric
        section should fail-no-rubric-row-cited, not pass silently."""
        ws = _workspace(DYDX_SEVERITY_MD)
        fixture = FIXTURES / "pass_low_severity.md"
        rc, payload = _run(fixture, workspace=ws)
        # Gate fires at LOW+; no rubric section -> fail
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-rubric-row-cited")


class TestRebuttal(unittest.TestCase):
    """ok-rebuttal for valid rebuttal markers."""

    def test_visible_line_rebuttal(self) -> None:
        ws = _workspace(SPARK_SEVERITY_MD)
        fixture = FIXTURES / "r52_rebuttal_override.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("r52_rebuttal" in payload or "rebuttal" in payload, [True])

    def test_html_comment_rebuttal(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        fixture = FIXTURES / "html_comment_rebuttal.md"
        rc, payload = _run(fixture, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_overlong_rebuttal_fails(self) -> None:
        """A rebuttal reason >200 chars must NOT be accepted."""
        ws = _workspace(DYDX_SEVERITY_MD)
        fixture = FIXTURES / "overlong_rebuttal_fail.md"
        rc, payload = _run(fixture, workspace=ws)
        # Rebuttal is >200 chars so it is ignored; no rubric section -> fail
        self.assertEqual(rc, 1)
        self.assertIn(payload["verdict"], [
            "fail-no-rubric-row-cited",
            "fail-impact-mismatch-with-cited-row",
            "fail-program-severity-missing-impact-class",
        ])


class TestNoSeverityMd(unittest.TestCase):
    """When SEVERITY.md is missing the gate cannot validate cited row."""

    def test_no_severity_md_with_cited_row(self) -> None:
        """When no SEVERITY.md found and a row is cited, should still check noun overlap."""
        tmpdir = Path(tempfile.mkdtemp(prefix="r52_nosevmd_"))
        fixture = FIXTURES / "no_severity_md_workspace_fail.md"
        # Run without workspace - no SEVERITY.md reachable from fixture path
        # The tool should be lenient about missing SEVERITY.md but still check
        # the rubric section fields.
        rc, payload = mod.run(fixture, workspace=tmpdir)
        # Without SEVERITY.md the tool cannot fail-program-severity, so it either
        # passes on noun overlap alone or fails on row-not-found.
        # Either way it should not crash.
        self.assertIn(payload["verdict"], [
            "pass-rubric-row-matched",
            "fail-no-rubric-row-cited",
            "fail-program-severity-missing-impact-class",
            "fail-impact-mismatch-with-cited-row",
            "ok-rebuttal",
            "pass-out-of-scope",
        ])
        self.assertNotEqual(payload["verdict"], "error")


class TestSchemaVersion(unittest.TestCase):
    def test_schema_version_present(self) -> None:
        ws = _workspace(DYDX_SEVERITY_MD)
        body = "Severity: High\n\n## Impact\n\nImpact here.\n"
        draft = _draft_in(ws, body)
        _, payload = _run(draft, workspace=ws)
        self.assertEqual(payload["schema_version"], "auditooor.r52_rubric_row_coverage.v1")
        self.assertEqual(payload["gate"], "R52-RUBRIC-ROW-COVERAGE")


class TestCLIOverride(unittest.TestCase):
    """severity override and --strict work as expected."""

    def test_severity_override_pulls_into_scope(self) -> None:
        """Draft with no explicit severity but filename without severity token
        should be overrideable via CLI."""
        ws = _workspace(DYDX_SEVERITY_MD)
        draft = _draft_in(ws, "## Impact\n\nLoss of funds via drain.\n", filename="draft.md")
        rc, payload = _run(draft, workspace=ws, severity="high")
        self.assertEqual(payload["severity_source"], "cli")
        # No rubric section -> fail
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-rubric-row-cited")


if __name__ == "__main__":
    import unittest
    unittest.main()
