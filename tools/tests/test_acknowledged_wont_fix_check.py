"""Unit tests for Rule 47 Acknowledged-Wont-Fix precheck (Check #94).

Covers all 6 verdict classes + edge cases for >= 12 total test cases.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "r47"

_spec = importlib.util.spec_from_file_location(
    "acknowledged_wont_fix_check",
    ROOT / "tools" / "acknowledged-wont-fix-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _run(
    draft: Path,
    *,
    workspace: Path | None = None,
    strict: bool = False,
    severity: str | None = None,
) -> tuple[int, dict]:
    return mod.run(draft, severity_override=severity, workspace=workspace, strict=strict)


def _make_workspace(
    *,
    security_md: str | None = None,
    prior_audit: str | None = None,
    known_issues: str | None = None,
) -> Path:
    """Create a temporary workspace with optional workspace documents."""
    root = Path(tempfile.mkdtemp(prefix="r47_ws_"))
    if security_md is not None:
        (root / "SECURITY.md").write_text(security_md, encoding="utf-8")
    if prior_audit is not None:
        pa_dir = root / "prior_audits"
        pa_dir.mkdir()
        (pa_dir / "prior_audit.txt").write_text(prior_audit, encoding="utf-8")
    if known_issues is not None:
        ref_dir = root / "reference" / "known_issues_catalogs"
        ref_dir.mkdir(parents=True)
        (ref_dir / "catalog.md").write_text(known_issues, encoding="utf-8")
    return root


def _make_source_workspace(comment: str, code: str = "function withdraw(uint256 amount) external { }\n") -> Path:
    root = _make_workspace()
    source = root / "src"
    source.mkdir()
    (source / "Vault.sol").write_text(f"{comment}\n{code}", encoding="utf-8")
    return root


class TestPassOutOfScope(unittest.TestCase):
    """LOW/MEDIUM severity drafts pass immediately without R47 firing."""

    def test_low_severity_fixture(self) -> None:
        draft = FIXTURES / "low_severity_pass.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")
        self.assertEqual(payload["severity"], "low")

    def test_medium_severity_fixture(self) -> None:
        """MEDIUM draft passes out-of-scope even when ack-scan section present."""
        draft = FIXTURES / "medium_severity_pass.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_no_severity_declared_passes(self) -> None:
        """Draft with no severity declared passes out-of-scope."""
        f = Path(tempfile.mktemp(suffix=".md"))
        f.write_text("# Some finding\n\nNo severity header.\n")
        try:
            rc, payload = _run(f)
            self.assertEqual(rc, 0)
            self.assertEqual(payload["verdict"], "pass-out-of-scope")
        finally:
            f.unlink(missing_ok=True)


class TestPassNoAcknowledgementFound(unittest.TestCase):
    """HIGH+ draft with scan section that found no acknowledgement."""

    def test_no_acknowledgement_fixture(self) -> None:
        draft = FIXTURES / "no_acknowledgement_pass.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-acknowledgement-found")

    def test_no_acknowledgement_with_workspace_scan(self) -> None:
        """HIGH draft with empty prior_audits workspace passes."""
        ws = _make_workspace()
        f = Path(tempfile.mktemp(suffix="-high.md"))
        f.write_text(
            "# Novel High finding\n\nSeverity: High\n\n"
            "## Acknowledgement Scan\n\n"
            "- Scan paths: prior_audits/, SECURITY.md\n"
            "- Acknowledgement found: no\n"
            "- Extension-distinct evidence: N/A\n"
            "- Verdict: pass\n",
            encoding="utf-8",
        )
        try:
            rc, payload = _run(f, workspace=ws)
            self.assertEqual(rc, 0)
            self.assertEqual(payload["verdict"], "pass-no-acknowledgement-found")
        finally:
            f.unlink(missing_ok=True)

    def test_security_relevant_source_comment_is_known_issue_evidence(self) -> None:
        ws = _make_source_workspace("// TODO: known issue, team aware; planned fix will wire access control")
        draft = FIXTURES / "no_acknowledgement_pass.md"
        try:
            rc, payload = _run(draft, workspace=ws)
            self.assertEqual(rc, 0)
            self.assertEqual(payload["evidence"]["source_comment_ack_count"], 1)
            hit = payload["evidence"]["workspace_ack_hits"][0]
            self.assertEqual(hit["evidence_class"], "known-issue/oos")
            self.assertTrue(hit["source_comment"])
        finally:
            import shutil
            shutil.rmtree(ws)

    def test_each_explicit_source_disposition_is_detected(self) -> None:
        for phrase in ("known issue", "team aware", "will wire", "planned fix", "accepted risk", "wont-fix"):
            with self.subTest(phrase=phrase):
                ws = _make_source_workspace(f"// {phrase}: withdraw authorization needs attention")
                try:
                    hits = mod._scan_source_comments_for_acknowledgements(ws)
                    self.assertEqual(len(hits), 1)
                finally:
                    import shutil
                    shutil.rmtree(ws)

    def test_generic_todo_and_unrelated_comment_are_ignored(self) -> None:
        for comment in ("// TODO: clean up this helper", "// known issue in documentation wording"):
            with self.subTest(comment=comment):
                ws = _make_source_workspace(comment, "function formatMessage(string memory text) pure external { }\n")
                try:
                    self.assertEqual(mod._scan_source_comments_for_acknowledgements(ws), [])
                finally:
                    import shutil
                    shutil.rmtree(ws)

    def test_workspace_extractor_returns_all_comments_for_agent_review(self) -> None:
        ws = _make_source_workspace(
            "// TODO: clean up this helper\n// Actual bytes stay hard-capped; per-IP rate limiting will be wired in front of this handler."
        )
        try:
            comments = mod._extract_source_comments(ws)
            texts = [row["text"] for row in comments]
            self.assertIn("TODO: clean up this helper", texts)
            self.assertIn(
                "Actual bytes stay hard-capped; per-IP rate limiting will be wired in front of this handler.",
                texts,
            )
            self.assertTrue(all(row["analysis_status"] == "pending" for row in comments))
        finally:
            import shutil
            shutil.rmtree(ws)

    def test_workspace_scan_never_claims_zero_security_comments(self) -> None:
        ws = _make_source_workspace("// will be wired in front of this handler")
        try:
            rc, payload = mod.scan_workspace_source_comments(ws)
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "pending-agent-analysis")
            self.assertEqual(payload["comment_count"], 1)
            self.assertEqual(payload["pending_count"], 1)
            self.assertNotIn("pass-no-security-aware-comments", payload["verdict"])
        finally:
            import shutil
            shutil.rmtree(ws)

    def test_workspace_scan_accepts_terminal_agent_disposition(self) -> None:
        ws = _make_source_workspace("// will be wired in front of this handler")
        try:
            comment = mod._extract_source_comments(ws)[0]
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            (audit_dir / "source_comment_analysis.json").write_text(
                __import__("json").dumps({
                    "schema_version": "auditooor.source_comment_analysis.v1",
                    "analyses": [{
                        "comment_id": comment["comment_id"],
                        "disposition": "planned-remediation-oos",
                        "rationale": "The comment records an intended control that is absent; new reports must treat it as team-aware scope evidence.",
                    }],
                }),
                encoding="utf-8",
            )
            rc, payload = mod.scan_workspace_source_comments(ws)
            self.assertEqual(rc, 0)
            self.assertEqual(payload["verdict"], "pass-comment-analysis-complete")
        finally:
            import shutil
            shutil.rmtree(ws)

    def test_workspace_scan_fails_closed_and_requests_refresh_for_stale_identity(self) -> None:
        ws = _make_source_workspace("// will be wired in front of this handler")
        try:
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            (audit_dir / "source_comment_analysis.json").write_text(
                json.dumps({
                    "schema_version": "auditooor.source_comment_analysis.v1",
                    "comment_count": 1,
                    "analyses": [{
                        "comment_id": "stale-comment-id",
                        "disposition": "ordinary-comment",
                        "rationale": "Old source snapshot.",
                    }],
                }),
                encoding="utf-8",
            )
            rc, payload = mod.scan_workspace_source_comments(ws)
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "refresh-required-source-comment-analysis")
            self.assertEqual(payload["analysis_status"], "refresh-required")
            self.assertEqual(payload["freshness"]["stale_analysis_ids"], ["stale-comment-id"])
            refresh = Path(payload["refresh_required_artifact"])
            refresh_payload = json.loads(refresh.read_text(encoding="utf-8"))
            self.assertEqual(refresh_payload["verdict"], "refresh-required")
            self.assertIn("semantic-review-source-comments.py", refresh_payload["required_action"])
        finally:
            import shutil
            shutil.rmtree(ws)

    def test_workspace_scan_refreshes_when_source_is_newer_than_analysis(self) -> None:
        ws = _make_source_workspace("// ordinary implementation note")
        try:
            comment = mod._extract_source_comments(ws)[0]
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            analysis = audit_dir / "source_comment_analysis.json"
            analysis.write_text(
                json.dumps({
                    "schema_version": "auditooor.source_comment_analysis.v1",
                    "comment_count": 1,
                    "analyses": [{
                        "comment_id": comment["comment_id"],
                        "disposition": "ordinary-comment",
                        "rationale": "Reviewed source context.",
                    }],
                }),
                encoding="utf-8",
            )
            source = Path(comment["source_file"])
            newer = analysis.stat().st_mtime_ns + 1_000_000_000
            os.utime(source, ns=(newer, newer))
            rc, payload = mod.scan_workspace_source_comments(ws)
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "refresh-required-source-comment-analysis")
            self.assertIn(
                "source files are newer than the source comment analysis artifact",
                payload["freshness"]["reasons"],
            )
        finally:
            import shutil
            shutil.rmtree(ws)

    def test_fixed_comment_requires_current_code_evidence(self) -> None:
        ws = _make_source_workspace("// fixed: rate limit is now enforced")
        try:
            comment = mod._extract_source_comments(ws)[0]
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            (audit_dir / "source_comment_analysis.json").write_text(
                __import__("json").dumps({
                    "schema_version": "auditooor.source_comment_analysis.v1",
                    "analyses": [{
                        "comment_id": comment["comment_id"],
                        "disposition": "claimed-fixed-verified",
                        "rationale": "The team claims the control is fixed.",
                    }],
                }),
                encoding="utf-8",
            )
            rc, payload = mod.scan_workspace_source_comments(ws)
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "review-required")
        finally:
            import shutil
            shutil.rmtree(ws)


class TestPassExtensionDistinct(unittest.TestCase):
    """HIGH+ drafts where ack found but extension-distinct evidence present."""

    def test_extension_distinct_fixture(self) -> None:
        draft = FIXTURES / "extension_distinct_pass.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-extension-distinct-from-acknowledgement")

    def test_extension_distinct_content_only_fixture(self) -> None:
        """Extension-distinct without explicit 'yes' marker but substantive content."""
        draft = FIXTURES / "extension_distinct_content_only_pass.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-extension-distinct-from-acknowledgement")


class TestPassOkRebuttal(unittest.TestCase):
    """Valid r47-rebuttal markers bypass the gate."""

    def test_rebuttal_line_form(self) -> None:
        draft = FIXTURES / "r47_rebuttal_override.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("rebuttal", payload)
        self.assertLessEqual(len(payload["rebuttal"]), 200)

    def test_html_comment_rebuttal(self) -> None:
        draft = FIXTURES / "html_comment_rebuttal_pass.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_overlong_rebuttal_is_ignored(self) -> None:
        """Rebuttal >200 chars is silently ignored; gate still fires."""
        draft = FIXTURES / "overlong_rebuttal_ignored_fail.md"
        rc, payload = _run(draft)
        # Rebuttal is >200 chars so it is ignored; no scan section -> fail
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-acknowledgement-scan-performed")


class TestFailAcknowledgedWithoutExtension(unittest.TestCase):
    """HIGH+ drafts that declare ack found but provide no extension-distinct evidence."""

    def test_dydx_pseudorand_vs_informal_q4(self) -> None:
        draft = FIXTURES / "dydx_pseudorand_vs_informal_q4_fail.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-acknowledged-without-extension-distinct")

    def test_spark_leadhd_vs_77043(self) -> None:
        draft = FIXTURES / "spark_leadhd_vs_77043_fail.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-acknowledged-without-extension-distinct")

    def test_hb_call_decompressor_vs_srl_610(self) -> None:
        draft = FIXTURES / "hb_call_decompressor_vs_srl_610_fail.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-acknowledged-without-extension-distinct")

    def test_ack_found_no_extension_field(self) -> None:
        """Ack found but extension-distinct sub-field entirely missing."""
        draft = FIXTURES / "ack_found_no_extension_field_fail.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-acknowledged-without-extension-distinct")


class TestFailNoScanPerformed(unittest.TestCase):
    """HIGH+ drafts missing the Acknowledgement Scan section entirely."""

    def test_no_scan_section_fixture(self) -> None:
        draft = FIXTURES / "no_scan_performed_fail.md"
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-acknowledgement-scan-performed")

    def test_high_draft_no_section_inline(self) -> None:
        """Inline HIGH draft with no scan section -> fail."""
        f = Path(tempfile.mktemp(suffix="-high.md"))
        f.write_text(
            "# Vault reentrancy leads to fund drain\n\n"
            "Severity: High\n\n"
            "## Summary\n\nReentrancy in vault.withdraw().\n\n"
            "## Root Cause\n\nvault.sol:88 calls external before update.\n",
            encoding="utf-8",
        )
        try:
            rc, payload = _run(f)
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "fail-no-acknowledgement-scan-performed")
        finally:
            f.unlink(missing_ok=True)


class TestErrorHandling(unittest.TestCase):
    """Error cases."""

    def test_nonexistent_draft(self) -> None:
        rc, payload = _run(Path("/nonexistent/path/draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")
        self.assertIn("error", payload)


class TestEnvExtension(unittest.TestCase):
    """Env hook AUDITOOOR_R47_ACK_PATTERNS extends acknowledgement detection."""

    def test_custom_ack_pattern(self) -> None:
        """Custom env pattern picked up by ack-scan logic."""
        f = Path(tempfile.mktemp(suffix="-high.md"))
        f.write_text(
            "# Protocol pause accepted HIGH finding\n\n"
            "Severity: High\n\n"
            "## Acknowledgement Scan\n\n"
            "- Scan paths: prior_audits/\n"
            "- Acknowledgement found: yes\n"
            "  > CUSTOM-MARK-001: protocol-pause risk accepted by team.\n"
            "- Extension-distinct evidence: none\n"
            "- Verdict: fail\n",
            encoding="utf-8",
        )
        try:
            prev = os.environ.get("AUDITOOOR_R47_ACK_PATTERNS", "")
            os.environ["AUDITOOOR_R47_ACK_PATTERNS"] = r"CUSTOM-MARK-\d+"
            rc, payload = _run(f)
            # Ack found + no extension-distinct content -> fail
            self.assertEqual(rc, 1)
            self.assertIn(
                payload["verdict"],
                {"fail-acknowledged-without-extension-distinct"},
            )
        finally:
            f.unlink(missing_ok=True)
            if prev:
                os.environ["AUDITOOOR_R47_ACK_PATTERNS"] = prev
            else:
                os.environ.pop("AUDITOOOR_R47_ACK_PATTERNS", None)


class TestSchemaVersion(unittest.TestCase):
    """Schema version field is always present in output."""

    def test_schema_version_present(self) -> None:
        draft = FIXTURES / "low_severity_pass.md"
        _, payload = _run(draft)
        self.assertEqual(payload["schema_version"], "auditooor.r47_acknowledged_wont_fix.v1")
        self.assertEqual(payload["gate"], "R47-ACKNOWLEDGED-WONT-FIX-PRECHECK")


if __name__ == "__main__":
    unittest.main()
