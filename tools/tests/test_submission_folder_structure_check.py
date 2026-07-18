"""Unit tests for Rule 41 per-finding submission folder structure preflight.

<!-- r36-rebuttal: lane-CAPABILITY-GAP-36-R41-ARTIFACT-COMPLETENESS registered via tools/agent-pathspec-register.py in .auditooor/agent_pathspec.json -->
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "submission_folder_structure_check",
    ROOT / "tools" / "submission-folder-structure-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


SLUG = "hb-arbitrum-orbit-unconfirmed-node-HIGH"
ARTIFACT_EXTS = [
    ".md",
    ".md.hash",
    ".hackenproof-plain.txt",
    ".hackenproof-plain.json",
    ".hackenproof-plain.txt.hash",
    ".hardening.md",
    ".poc-transcript.txt",
]
POC_ZIP = "hb-arbitrum-orbit-unconfirmed-node-poc.zip"


class _Workspace:
    """tempfile-backed workspace with a submissions/ tree."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="r41_subfolder_"))
        self.submissions = self.root / "submissions"
        self.submissions.mkdir()

    def status(self, name: str) -> Path:
        path = self.submissions / name
        path.mkdir(exist_ok=True)
        return path

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def _write(path: Path, content: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _compliant_folder(status_dir: Path, slug: str) -> Path:
    """Create a fully-compliant per-finding folder under status_dir."""
    folder = status_dir / slug
    folder.mkdir()
    for ext in ARTIFACT_EXTS:
        _write(folder / f"{slug}{ext}")
    _write(folder / f"{slug.rsplit('-', 1)[0]}-poc.zip")
    return folder


def _flat_finding(status_dir: Path, slug: str) -> None:
    """Drop all artifacts flat in status_dir (the non-compliant layout)."""
    for ext in ARTIFACT_EXTS:
        _write(status_dir / f"{slug}{ext}")
    _write(status_dir / f"{slug.rsplit('-', 1)[0]}-poc.zip")


class TestCheckMode(unittest.TestCase):
    def setUp(self) -> None:
        self.ws = _Workspace()

    def tearDown(self) -> None:
        self.ws.cleanup()

    def test_compliant_tree_passes(self) -> None:
        _compliant_folder(self.ws.status("filed"), SLUG)
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")

    def test_empty_status_dir_passes(self) -> None:
        self.ws.status("staging")
        self.ws.status("filed")
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-empty")

    def test_flat_md_fails(self) -> None:
        _write(self.ws.status("staging") / f"{SLUG}.md")
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-flat-artifact")

    def test_flat_poc_zip_fails(self) -> None:
        _write(self.ws.status("filed") / POC_ZIP)
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-flat-artifact")

    def test_folder_name_mismatch_fails(self) -> None:
        # Folder named differently from the contained <slug>.md stem.
        bad = self.ws.status("filed") / "wrong-folder-name"
        bad.mkdir()
        _write(bad / f"{SLUG}.md")
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-folder-name-mismatch")

    def test_killed_folder_handled(self) -> None:
        killed_slug = "hb-hft-superapprove-unrestricted-KILLED"
        folder = self.ws.status("_killed") / killed_slug
        folder.mkdir()
        _write(folder / f"{killed_slug}.md")
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")

    def test_allowed_flat_files_do_not_fail(self) -> None:
        # README.md / SUBMISSIONS.md are status-dir bookkeeping, not artifacts.
        _write(self.ws.status("_oos_rejected") / "README.md")
        _compliant_folder(self.ws.status("filed"), SLUG)
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")

    def test_no_submissions_dir_passes_empty(self) -> None:
        rc, payload = mod.check(self.ws.root / "does-not-exist")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-empty")

    def test_paste_ready_dir_scanned_in_check_mode(self) -> None:
        # A compliant finding folder under paste_ready must be recognized.
        _compliant_folder(self.ws.status("paste_ready"), SLUG)
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")
        scanned = [s["status_dir"] for s in payload["status_dirs"]]
        self.assertIn("paste_ready", scanned)

    def test_flat_artifact_in_superseded_fails(self) -> None:
        _write(self.ws.status("superseded") / f"{SLUG}.md")
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-flat-artifact")

    def test_non_finding_subdir_with_no_md_is_ignored(self) -> None:
        # ready/poc-tests is a real layout - a dir with no .md is left alone.
        (self.ws.status("ready") / "poc-tests").mkdir()
        _compliant_folder(self.ws.status("ready"), SLUG)
        rc, payload = mod.check(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")


class TestFixMode(unittest.TestCase):
    def setUp(self) -> None:
        self.ws = _Workspace()

    def tearDown(self) -> None:
        self.ws.cleanup()

    def test_fix_reorganizes_flat_tree(self) -> None:
        status_dir = self.ws.status("filed")
        _flat_finding(status_dir, SLUG)
        rc, payload = mod.fix(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")
        self.assertTrue(payload["moves"])
        # After fix, every artifact lives inside the per-finding folder.
        folder = status_dir / SLUG
        self.assertTrue((folder / f"{SLUG}.md").is_file())
        self.assertTrue((folder / f"{SLUG}.hardening.md").is_file())
        self.assertTrue((folder / POC_ZIP).is_file())
        # The status dir holds only the finding folder now.
        flat = [p for p in status_dir.iterdir() if p.is_file()]
        self.assertEqual(flat, [])
        # And it now passes a check.
        rc2, payload2 = mod.check(self.ws.submissions)
        self.assertEqual(rc2, 0)
        self.assertEqual(payload2["verdict"], "pass-compliant")

    def test_fix_is_idempotent(self) -> None:
        status_dir = self.ws.status("filed")
        _flat_finding(status_dir, SLUG)
        mod.fix(self.ws.submissions)
        # Re-running --fix on an already-correct tree is a no-op.
        rc, payload = mod.fix(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")
        self.assertEqual(payload["moves"], [])

    def test_fix_longest_prefix_grouping(self) -> None:
        # Two findings whose slugs share a common prefix - the artifact must
        # go to the LONGEST-prefix-match slug.
        status_dir = self.ws.status("staging")
        short = "hb-orbit-node"
        longg = "hb-orbit-node-confirmed-HIGH"
        _write(status_dir / f"{short}.md")
        _write(status_dir / f"{longg}.md")
        _write(status_dir / f"{longg}.hardening.md")
        rc, payload = mod.fix(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertTrue((status_dir / longg / f"{longg}.hardening.md").is_file())
        self.assertFalse((status_dir / short / f"{longg}.hardening.md").exists())

    def test_fix_reorganizes_dotted_slug_roots_and_sidecars(self) -> None:
        status_dir = self.ws.status("staging")
        slug = "R89-Blue-consolidated.notes"
        _write(status_dir / f"{slug}.md")
        _write(status_dir / f"{slug}.md.bak")
        _write(status_dir / f"{slug}.hardening.md")
        _write(status_dir / f"{slug}.poc-transcript.txt")
        rc, payload = mod.fix(self.ws.submissions)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")
        folder = status_dir / slug
        self.assertTrue((folder / f"{slug}.md").is_file())
        self.assertTrue((folder / f"{slug}.md.bak").is_file())
        self.assertTrue((folder / f"{slug}.hardening.md").is_file())
        self.assertTrue((folder / f"{slug}.poc-transcript.txt").is_file())
        rc2, payload2 = mod.check(self.ws.submissions)
        self.assertEqual(rc2, 0)
        self.assertEqual(payload2["verdict"], "pass-compliant")


class TestDraftMode(unittest.TestCase):
    def setUp(self) -> None:
        self.ws = _Workspace()

    def tearDown(self) -> None:
        self.ws.cleanup()

    def test_draft_in_finding_folder_passes(self) -> None:
        folder = self.ws.status("filed") / SLUG
        folder.mkdir()
        draft = folder / f"{SLUG}.md"
        _write(draft)
        rc, payload = mod.check_draft(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")

    def test_flat_draft_fails(self) -> None:
        draft = self.ws.status("filed") / f"{SLUG}.md"
        _write(draft)
        rc, payload = mod.check_draft(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-draft-not-in-finding-folder")

    def test_draft_folder_name_mismatch_fails(self) -> None:
        folder = self.ws.status("filed") / "wrong-name"
        folder.mkdir()
        draft = folder / f"{SLUG}.md"
        _write(draft)
        rc, payload = mod.check_draft(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-draft-not-in-finding-folder")

    # ---- R41 (#85) escalation-variant draft co-residency -------------------
    def test_escalation_variant_draft_in_base_folder_passes(self) -> None:
        """FALSE-POSITIVE SUPPRESSED: an escalation variant co-resides in the
        base finding's folder. folder=<base>, draft=<base>-escalation.md, and
        the base <base>.md exists -> accept.
        """
        base = SLUG
        folder = self.ws.status("staging") / base
        folder.mkdir()
        _write(folder / f"{base}.md")  # base finding present
        variant = folder / f"{base}-escalation.md"
        _write(variant)
        rc, payload = mod.check_draft(variant)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")
        self.assertTrue(payload["observed"]["accepted_as_escalation_variant"])
        self.assertFalse(payload["observed"]["folder_name_matches_slug"])

    def test_variant_without_base_finding_still_fails(self) -> None:
        """CONTROL: prefix matches but the base <folder>.md is ABSENT -> the
        folder is a genuinely mis-named container, still a violation.
        """
        base = SLUG
        folder = self.ws.status("staging") / base
        folder.mkdir()
        # NO base {base}.md written - only the variant.
        variant = folder / f"{base}-escalation.md"
        _write(variant)
        rc, payload = mod.check_draft(variant)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-draft-not-in-finding-folder")
        self.assertFalse(payload["observed"]["accepted_as_escalation_variant"])

    def test_shared_prefix_without_separator_still_fails(self) -> None:
        """CONTROL: draft slug shares a leading substring with the folder but
        NOT the literal `<folder>-` separator (folder `hb-orbit`, draft
        `hb-orbitals.md`). Must NOT be accepted as a variant.
        """
        folder = self.ws.status("filed") / "hb-orbit"
        folder.mkdir()
        _write(folder / "hb-orbit.md")  # base present, but slug is not a variant
        stray = folder / "hb-orbitals.md"
        _write(stray)
        rc, payload = mod.check_draft(stray)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-draft-not-in-finding-folder")
        self.assertFalse(payload["observed"]["accepted_as_escalation_variant"])

    def test_draft_unrecognized_status_dir_fails(self) -> None:
        folder = self.ws.submissions / "unknown_status" / SLUG
        folder.mkdir(parents=True)
        draft = folder / f"{SLUG}.md"
        _write(draft)
        rc, payload = mod.check_draft(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-draft-not-in-finding-folder")

    def test_draft_missing_file_errors(self) -> None:
        rc, payload = mod.check_draft(self.ws.root / "nope.md")
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    def test_draft_in_paste_ready_finding_folder_passes(self) -> None:
        # Spark / L27 workflow uses submissions/paste_ready/<slug>/<slug>.md.
        folder = self.ws.status("paste_ready") / SLUG
        folder.mkdir()
        draft = folder / f"{SLUG}.md"
        _write(draft)
        rc, payload = mod.check_draft(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")

    def test_draft_in_held_and_superseded_dirs_pass(self) -> None:
        for status in ("held", "superseded"):
            folder = self.ws.status(status) / SLUG
            folder.mkdir()
            draft = folder / f"{SLUG}.md"
            _write(draft)
            rc, payload = mod.check_draft(draft)
            self.assertEqual(rc, 0, f"{status} not recognized")
            self.assertEqual(payload["verdict"], "pass-compliant")

    def test_env_hook_extends_status_dirs(self) -> None:
        # AUDITOOOR_R41_STATUS_DIRS extends the recognized status dir set.
        folder = self.ws.submissions / "custom_lane" / SLUG
        folder.mkdir(parents=True)
        draft = folder / f"{SLUG}.md"
        _write(draft)
        rc, payload = mod.check_draft(draft)
        self.assertEqual(rc, 1)  # unrecognized by default
        old = os.environ.get("AUDITOOOR_R41_STATUS_DIRS")
        os.environ["AUDITOOOR_R41_STATUS_DIRS"] = "custom_lane"
        try:
            rc, payload = mod.check_draft(draft)
        finally:
            if old is None:
                del os.environ["AUDITOOOR_R41_STATUS_DIRS"]
            else:
                os.environ["AUDITOOOR_R41_STATUS_DIRS"] = old
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")


class TestCLI(unittest.TestCase):
    def setUp(self) -> None:
        self.ws = _Workspace()

    def tearDown(self) -> None:
        self.ws.cleanup()

    def test_cli_workspace_check_compliant(self) -> None:
        _compliant_folder(self.ws.status("filed"), SLUG)
        rc = mod.main(["--workspace", str(self.ws.root), "--check", "--json"])
        self.assertEqual(rc, 0)

    def test_cli_workspace_check_flat_fails(self) -> None:
        _write(self.ws.status("staging") / f"{SLUG}.md")
        rc = mod.main(["--submissions-dir", str(self.ws.submissions), "--json"])
        self.assertEqual(rc, 1)

    def test_cli_no_target_errors(self) -> None:
        rc = mod.main(["--json"])
        self.assertEqual(rc, 2)

    def test_cli_draft_form(self) -> None:
        draft = self.ws.status("filed") / f"{SLUG}.md"
        _write(draft)
        rc = mod.main(["--draft", str(draft), "--json"])
        self.assertEqual(rc, 1)


# =============================================================================
# Gap #36: R41 artifact-completeness extension tests (added 2026-05-26).
# <!-- r36-rebuttal: lane-CAPABILITY-GAP-36-R41-ARTIFACT-COMPLETENESS -->
# =============================================================================
# Six mandatory test cases per the lane brief:
#   1. DRILL-9 paste-ready BEFORE poc-zip fix -> fail-artifact-missing
#   2. DRILL-9 paste-ready AFTER poc-zip fix -> pass-all-artifacts-present
#   3. Draft without executed-PoC marker -> pass-out-of-scope
#   4. Draft with rebuttal marker -> ok-rebuttal
#   5. DRILL-6 filed (Medium) -> pass-all-artifacts-present
#   6. Draft cites "PoC PASS" but missing only .poc-transcript.txt
#      -> fail-artifact-missing listing .poc-transcript.txt
# =============================================================================


DRILL9_SLUG = "smt-eth-branch-isempty-value-conflation"

DRILL9_DRAFT_BODY_POC_FIXTURE = """\
# Title: EthereumTrieDB.isEmpty value-slot conflation (audit-pin)

## Summary
Library-level decoder deviation from EIP-1186 + Ethereum yellow paper.
Demonstrated via 13/13 Foundry PoC PASS at the audit-pin source.

## PoC (V3-grade, Foundry, runs against audit-pin source)
```
cd src/solidity-merkle-trees && forge test --match-contract EthBranchIsEmptyTest -vv
```
Suite result: ok. 13 passed; 0 failed; 0 skipped; finished in 5.39ms

## Notes
- listed_impact_proven: true (13/13 Foundry tests PASS at the audit pin).
- harness-scaffold: PoC transcript at
  `poc-tests/smt-eth-branch-isempty/forge-test-transcript.txt`.
"""

NON_POC_DRAFT_BODY = """\
# Title: Source-only architectural finding

## Summary
This draft cites only source-level reasoning. No executed PoC is presented;
severity claim is bounded by source-only evidence.

## Recommendation
Add the missing validation.
"""


def _make_per_finding_folder(status_dir: Path, slug: str, body: str,
                             include_artifacts: list[str] | None = None) -> Path:
    """Build a per-finding folder for completeness-mode tests.

    include_artifacts: list of suffixes (relative to slug stem) to write.
    Each suffix may begin with `-` (e.g. `-poc.zip`) or `.` (e.g.
    `.poc-transcript.txt`). The .md is always written.
    """
    folder = status_dir / slug
    folder.mkdir(parents=True, exist_ok=True)
    _write(folder / f"{slug}.md", body)
    for suffix in include_artifacts or []:
        _write(folder / f"{slug}{suffix}", "x")
    return folder


class TestCompletenessExtension(unittest.TestCase):
    """Gap #36 R41 artifact-completeness check (--completeness flag)."""

    def setUp(self) -> None:
        self.ws = _Workspace()

    def tearDown(self) -> None:
        self.ws.cleanup()

    # ---- Case 1 ------------------------------------------------------------
    def test_drill9_before_fix_fails_missing_poc_zip_and_transcript(self) -> None:
        """DRILL-9 paste-ready BEFORE the poc-zip-fix.

        The operator caught the missing poc-zip + transcript. The check must
        return fail-artifact-missing and list BOTH suffixes as missing.
        """
        folder = _make_per_finding_folder(
            self.ws.status("paste_ready"),
            DRILL9_SLUG,
            DRILL9_DRAFT_BODY_POC_FIXTURE,
            include_artifacts=[
                ".md.hash",
                ".hackenproof-plain.txt",
                ".hackenproof-plain.txt.hash",
                ".hackenproof-plain.json",
            ],
        )
        draft = folder / f"{DRILL9_SLUG}.md"
        rc, payload = mod.check_completeness(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-artifact-missing")
        self.assertIn("-poc.zip", payload["missing_artifact_suffixes"])
        self.assertIn(".poc-transcript.txt", payload["missing_artifact_suffixes"])
        self.assertGreaterEqual(len(payload["poc_evidence_markers_hit"]), 1)

    # ---- Case 2 ------------------------------------------------------------
    def test_drill9_after_fix_passes_all_artifacts_present(self) -> None:
        """DRILL-9 paste-ready AFTER the poc-zip-fix (current live state)."""
        folder = _make_per_finding_folder(
            self.ws.status("filed"),
            DRILL9_SLUG,
            DRILL9_DRAFT_BODY_POC_FIXTURE,
            include_artifacts=[
                ".md.hash",
                ".hackenproof-plain.txt",
                ".hackenproof-plain.txt.hash",
                ".hackenproof-plain.json",
                "-poc.zip",
                ".poc-transcript.txt",
            ],
        )
        draft = folder / f"{DRILL9_SLUG}.md"
        rc, payload = mod.check_completeness(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-all-artifacts-present")
        self.assertEqual(payload["missing_artifact_suffixes"], [])

    # ---- Case 3 ------------------------------------------------------------
    def test_non_poc_draft_passes_out_of_scope(self) -> None:
        """Source-only draft (no executed-PoC trigger phrase) is OOS."""
        folder = _make_per_finding_folder(
            self.ws.status("staging"),
            "source-only-architectural-finding",
            NON_POC_DRAFT_BODY,
            include_artifacts=[".md.hash"],
        )
        draft = folder / "source-only-architectural-finding.md"
        rc, payload = mod.check_completeness(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")
        self.assertEqual(payload["poc_evidence_markers_hit"], [])

    # ---- Case 4 ------------------------------------------------------------
    def test_draft_with_rebuttal_passes_ok_rebuttal(self) -> None:
        """A draft with a valid `r41-completeness-rebuttal:` marker passes."""
        body = (
            DRILL9_DRAFT_BODY_POC_FIXTURE
            + "\n<!-- r41-completeness-rebuttal: PoC corpus archived separately for confidentiality; transcript embedded inline -->\n"
        )
        folder = _make_per_finding_folder(
            self.ws.status("paste_ready"),
            DRILL9_SLUG,
            body,
            include_artifacts=[".md.hash"],
        )
        draft = folder / f"{DRILL9_SLUG}.md"
        rc, payload = mod.check_completeness(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("PoC corpus", payload["rebuttal_reason"])

    # ---- Case 5 ------------------------------------------------------------
    def test_drill6_filed_medium_passes_all_artifacts_present(self) -> None:
        """DRILL-6 filed Medium analogue - hb-univ3-univ4 actual folder shape.

        The live workspace's hb-univ3-univ4-wrapper-refund-deployer-MEDIUM
        folder ships the poc-zip under the SHORTER base slug
        `hb-univ3-univ4-wrapper-refund-poc.zip` (severity tag dropped). The
        suffix-match design must accept that.
        """
        slug = "hb-univ3-univ4-wrapper-refund-deployer-MEDIUM"
        body = (
            "# hb-univ3-univ4-wrapper-refund-deployer-MEDIUM\n"
            "## PoC\n"
            "`forge test --match-contract WrapperRefundTest -vv`\n"
            "Suite result: ok. 4 passed; 0 failed; 0 skipped.\n"
        )
        folder = self.ws.status("filed") / slug
        folder.mkdir(parents=True, exist_ok=True)
        _write(folder / f"{slug}.md", body)
        for suffix in (
            ".md.hash",
            ".hackenproof-plain.txt",
            ".hackenproof-plain.txt.hash",
            ".hackenproof-plain.json",
            ".hardening.md",
            ".poc-transcript.txt",
        ):
            _write(folder / f"{slug}{suffix}", "x")
        _write(folder / "hb-univ3-univ4-wrapper-refund-poc.zip", "x")
        draft = folder / f"{slug}.md"
        rc, payload = mod.check_completeness(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-all-artifacts-present")
        self.assertEqual(payload["missing_artifact_suffixes"], [])

    # ---- Case 6 ------------------------------------------------------------
    def test_draft_missing_only_poc_transcript_fails_listing_it(self) -> None:
        """Draft cites `PoC PASS` but folder has -poc.zip and no transcript."""
        body = (
            "# Synthetic\n## Summary\nPoC PASS confirmed on audit-pin.\n"
            "Reference: poc-tests/synthetic/forge.log\n"
        )
        slug = "synthetic-poc-pass-only"
        folder = _make_per_finding_folder(
            self.ws.status("paste_ready"),
            slug,
            body,
            include_artifacts=[
                ".md.hash",
                "-poc.zip",
            ],
        )
        draft = folder / f"{slug}.md"
        rc, payload = mod.check_completeness(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-artifact-missing")
        self.assertEqual(payload["missing_artifact_suffixes"], [".poc-transcript.txt"])
        self.assertNotIn("-poc.zip", payload["missing_artifact_suffixes"])

    # ---- Sanity / wiring ---------------------------------------------------
    def test_completeness_flag_routes_in_main(self) -> None:
        """`--draft <X> --completeness --json` returns completeness verdict."""
        folder = _make_per_finding_folder(
            self.ws.status("paste_ready"),
            DRILL9_SLUG,
            DRILL9_DRAFT_BODY_POC_FIXTURE,
            include_artifacts=[".md.hash"],
        )
        draft = folder / f"{DRILL9_SLUG}.md"
        rc = mod.main(["--draft", str(draft), "--completeness", "--json"])
        self.assertEqual(rc, 1)

    def test_completeness_flag_off_preserves_legacy_draft_passthrough(self) -> None:
        """Default --draft form (no --completeness) still runs legacy R41."""
        folder = _make_per_finding_folder(
            self.ws.status("paste_ready"),
            DRILL9_SLUG,
            DRILL9_DRAFT_BODY_POC_FIXTURE,
            include_artifacts=[".md.hash"],
        )
        draft = folder / f"{DRILL9_SLUG}.md"
        rc, payload = mod.check_draft(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-compliant")

    def test_completeness_missing_draft_errors(self) -> None:
        """Missing draft path returns rc=2 / verdict=error."""
        rc, payload = mod.check_completeness(self.ws.root / "nope.md")
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


if __name__ == "__main__":
    unittest.main()
