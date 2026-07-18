#!/usr/bin/env python3
"""test_duplicate_preflight_platforms.py — platform-specific Q1+Q2 mode tests.

Tests the --platform flag added in SCHEMA_VERSION v2 of duplicate-preflight-check.py.
Each test runs the script via subprocess with a tempdir containing a synthetic
draft + a synthetic prior report, asserting the JSON verdict.

Covered scenarios:
  1. Cantina  — same fix-commit, different cantina-asset → distinct_cross_asset
  2. Sherlock — same fix-commit, but draft has novel impact-class → distinct_by_uniqueness_escalation
  3. Code4rena (no --c4-judge-flag) — shared fix → manual_review_required
  4. Code4rena (with --c4-judge-flag) — shared fix → duplicate (same as immunefi)
  5. Private  — reads from explicit --prior-reports-dir, behaves like immunefi
  6. Immunefi default — backward-compat regression: same fix → duplicate
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

TOOL = (
    Path(__file__).resolve().parent.parent / "duplicate-preflight-check.py"
)

SHARED_FIX_SHA = "deadbeef1234"  # 12-char SHA that both drafts cite
SHARED_FILE = "src/transfer/claim.go"


def _make_prior(tmpdir: Path, *, cantina_asset: str | None = None, sherlock_impact: str | None = None) -> Path:
    """Write a synthetic prior report into tmpdir/submissions/paste_ready/."""
    d = tmpdir / "submissions" / "paste_ready"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "prior-report.md"
    lines = [
        "# Prior Finding",
        "",
        f"Fix reference: `{SHARED_FIX_SHA}`",
        f"Affected file: `{SHARED_FILE}:42`",
        "",
    ]
    if cantina_asset:
        lines.append(f"<!-- cantina-asset: {cantina_asset} -->")
    if sherlock_impact:
        lines.append(f"<!-- sherlock-impact: {sherlock_impact} -->")
    p.write_text("\n".join(lines))
    return p


def _run(
    draft_path: Path,
    workspace: Path,
    *,
    platform: str,
    extra_args: list[str] | None = None,
) -> dict:
    """Run the tool and return parsed JSON output."""
    cmd = [
        sys.executable,
        str(TOOL),
        str(draft_path),
        "--workspace", str(workspace),
        "--platform", platform,
        "--json",
    ]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"Tool did not emit valid JSON.\nstdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        ) from exc


class TestCantinaCrossAssetDistinct(unittest.TestCase):
    """Same fix-commit, DIFFERENT cantina-asset → verdict = distinct_cross_asset."""

    def test_different_asset_is_distinct(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_prior(ws, cantina_asset="chain-a (core)")

            draft = ws / "draft.md"
            draft.write_text(textwrap.dedent(f"""
                # New Finding
                Fix reference: `{SHARED_FIX_SHA}`
                Affected file: `{SHARED_FILE}:99`
                <!-- cantina-asset: chain-b (periphery) -->
            """))

            data = _run(draft, ws, platform="cantina")
            self.assertEqual(
                data["verdict"], "distinct_cross_asset",
                f"Expected distinct_cross_asset, got: {data['verdict']}\nfull: {data}",
            )
            # Confirm at least one entry was classified as DISTINCT_CROSS_ASSET
            verdicts = [d["verdict"] for d in data["duplicates"]]
            self.assertIn("DISTINCT_CROSS_ASSET", verdicts)


class TestSherlockUniquenessEscalation(unittest.TestCase):
    """Same fix-commit + novel impact-class → distinct_by_uniqueness_escalation."""

    def test_novel_impact_class_escalation(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_prior(ws, sherlock_impact="fund-freeze")

            draft = ws / "draft.md"
            draft.write_text(textwrap.dedent(f"""
                # New Finding
                Fix reference: `{SHARED_FIX_SHA}`
                Affected file: `{SHARED_FILE}:99`
                <!-- sherlock-impact: direct-theft -->
            """))

            data = _run(draft, ws, platform="sherlock")
            self.assertEqual(
                data["verdict"], "distinct_by_uniqueness_escalation",
                f"Expected distinct_by_uniqueness_escalation, got: {data['verdict']}\nfull: {data}",
            )
            # Confirm the novel impact is noted
            dupes = data["duplicates"]
            self.assertTrue(
                any("direct-theft" in d.get("sherlock_novel_impacts", []) for d in dupes),
                f"Expected 'direct-theft' in sherlock_novel_impacts. Dupe entries: {dupes}",
            )


class TestCode4renaNoJudgeFlag(unittest.TestCase):
    """Same fix-commit, no --c4-judge-flag → verdict = manual_review_required."""

    def test_no_judge_flag_routes_to_manual_review(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_prior(ws)

            draft = ws / "draft.md"
            draft.write_text(textwrap.dedent(f"""
                # New Finding
                Fix reference: `{SHARED_FIX_SHA}`
                Affected file: `{SHARED_FILE}:99`
            """))

            data = _run(draft, ws, platform="code4rena")
            self.assertEqual(
                data["verdict"], "manual_review_required",
                f"Expected manual_review_required, got: {data['verdict']}\nfull: {data}",
            )
            verdicts = [d["verdict"] for d in data["duplicates"]]
            self.assertIn("MANUAL_REVIEW_REQUIRED", verdicts)


class TestCode4renaWithJudgeFlag(unittest.TestCase):
    """Same fix-commit, with --c4-judge-flag → verdict = duplicate (same as immunefi)."""

    def test_judge_flag_treats_like_immunefi(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_prior(ws)

            draft = ws / "draft.md"
            draft.write_text(textwrap.dedent(f"""
                # New Finding
                Fix reference: `{SHARED_FIX_SHA}`
                Affected file: `{SHARED_FILE}:99`
            """))

            data = _run(draft, ws, platform="code4rena", extra_args=["--c4-judge-flag"])
            self.assertEqual(
                data["verdict"], "duplicate",
                f"Expected duplicate, got: {data['verdict']}\nfull: {data}",
            )
            verdicts = [d["verdict"] for d in data["duplicates"]]
            self.assertIn("DUPLICATE", verdicts)
            # Confirm c4_judge_flag is recorded in the dupe entry
            self.assertTrue(
                any(d.get("c4_judge_flag") is True for d in data["duplicates"]),
                "Expected c4_judge_flag=true in at least one dupe entry",
            )


class TestPrivatePlatform(unittest.TestCase):
    """Private platform reads from explicit --prior-reports-dir, otherwise behaves like immunefi."""

    def test_private_reads_prior_reports_dir(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # No submissions/ subdir in workspace — prior comes from --prior-reports-dir.
            prior_dir = ws / "external_priors"
            prior_dir.mkdir()
            prior_file = prior_dir / "external-finding.md"
            prior_file.write_text(textwrap.dedent(f"""
                # External Prior
                Fix reference: `{SHARED_FIX_SHA}`
                Affected file: `{SHARED_FILE}:10`
            """))

            draft = ws / "draft.md"
            draft.write_text(textwrap.dedent(f"""
                # New Finding
                Fix reference: `{SHARED_FIX_SHA}`
                Affected file: `{SHARED_FILE}:99`
            """))

            data = _run(
                draft, ws,
                platform="private",
                extra_args=["--prior-reports-dir", str(prior_dir)],
            )
            # Shared fix → duplicate (private behaves like immunefi)
            self.assertEqual(
                data["verdict"], "duplicate",
                f"Expected duplicate for private platform, got: {data['verdict']}\nfull: {data}",
            )
            self.assertTrue(
                any(d["prior_id"].startswith("external:") for d in data["duplicates"]),
                "Expected an external: prior_id in duplicates",
            )


class TestImmunefiDefaultBackwardCompat(unittest.TestCase):
    """Backward-compat regression: immunefi (default) same fix → duplicate."""

    def test_immunefi_default_same_fix_is_duplicate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_prior(ws)

            draft = ws / "draft.md"
            draft.write_text(textwrap.dedent(f"""
                # New Finding
                Fix reference: `{SHARED_FIX_SHA}`
                Affected file: `{SHARED_FILE}:99`
            """))

            # Run without --platform to exercise default.
            cmd = [
                sys.executable,
                str(TOOL),
                str(draft),
                "--workspace", str(ws),
                "--json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            data = json.loads(result.stdout)

            self.assertEqual(
                data["verdict"], "duplicate",
                f"Expected duplicate for immunefi default, got: {data['verdict']}\nfull: {data}",
            )
            self.assertEqual(data["platform"], "immunefi")


if __name__ == "__main__":
    unittest.main()
