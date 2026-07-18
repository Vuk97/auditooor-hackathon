"""Tests for tools/duplicate-preflight-check.py --self-skip-same-family flag.

Covers (per W2-CATCHUP-L4):
  1. Default behavior (no flag): paste_ready/foo.md vs staging/foo.md still
     flagged (regression guard for pre-submit-check.sh check #49 call site).
  2. --self-skip-same-family with matching family-id (filename prefix): skip,
     no duplicate flagged, FP eliminated.
  3. --self-skip-same-family with DIFFERENT family-ids: still flagged
     (the flag is not a blanket bypass).
  4. --self-skip-same-family with no family identifier on either side:
     fall back to old behavior (flag the duplicate as before).
  5. Bonus: matching paste_content_hash sidecar triggers same-family skip
     even without filename-prefix or frontmatter family-id.
  6. Bonus: matching frontmatter family_id: triggers skip across differing
     filenames.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "duplicate-preflight-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("duplicate_preflight_check", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["duplicate_preflight_check"] = module
    spec.loader.exec_module(module)
    return module


dpc = _load_module()


# Two drafts that share files + fix-refs → without the flag they collide.
DRAFT_BODY_TEMPLATE = """\
# {title}

Bug class: missing `validateTransferLeavesNotExitedToL1` guard in
`spark/proto/transfer.go:142` (call site `FinalizeTransfer(`).

The fix is in commit 0123456789abcdef and pull request #77043.

## Files

- `spark/proto/transfer.go:140-160`
- `spark/proto/claim.go:88`

## Recommended Fix

Wrap callers in `validateTransferLeavesNotExitedToL1`.
"""


def _write_draft(path: Path, title: str, frontmatter: str = "") -> None:
    body = DRAFT_BODY_TEMPLATE.format(title=title)
    if frontmatter:
        body = f"{frontmatter}\n\n{body}"
    path.write_text(body, encoding="utf-8")


def _run_cli(*args: str) -> tuple[int, dict]:
    """Invoke the tool as a subprocess; return (rc, parsed_json)."""
    cmd = [sys.executable, str(TOOL_PATH), *args, "--json"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = proc.stdout.strip()
    parsed: dict = {}
    if out:
        try:
            parsed = json.loads(out)
        except json.JSONDecodeError:
            parsed = {"_raw_stdout": out, "_stderr": proc.stderr}
    else:
        parsed = {"_raw_stdout": "", "_stderr": proc.stderr}
    return proc.returncode, parsed


class FamilyIdExtractionTests(unittest.TestCase):
    def test_filename_prefix_rg_n6_s1(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "RG-N6-S1-some-finding.md"
            p.write_text("# nothing here\n", encoding="utf-8")
            self.assertEqual(dpc._extract_family_id(p, p.read_text()), "rg-n6-s1")

    def test_filename_prefix_rg_01a(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "RG-01A-other-name.md"
            p.write_text("# x\n", encoding="utf-8")
            self.assertEqual(dpc._extract_family_id(p, p.read_text()), "rg-01a")

    def test_filename_prefix_lead_critical_name(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "LEAD-CMTBFT-FORK-LAG-something.md"
            p.write_text("# x\n", encoding="utf-8")
            self.assertEqual(
                dpc._extract_family_id(p, p.read_text()),
                "lead-cmtbft-fork-lag",
            )

    def test_frontmatter_family_id_overrides_filename(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "RG-99-misnamed.md"
            p.write_text(
                "---\nfamily_id: spark-finalize-leaf-status\n---\n# body",
                encoding="utf-8",
            )
            # Frontmatter wins over filename prefix.
            self.assertEqual(
                dpc._extract_family_id(p, p.read_text()),
                "spark-finalize-leaf-status",
            )

    def test_no_family_signal_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "random-name-no-prefix.md"
            p.write_text("just body, no prefix, no frontmatter", encoding="utf-8")
            self.assertIsNone(dpc._extract_family_id(p, p.read_text()))


class FixReferenceExtractionTests(unittest.TestCase):
    def test_audit_pin_sha_is_not_q2_fix_reference(self):
        text = (
            "audit-pin: 5ee9766351ef864856a309a971b13fdd98cae2c5\n"
            "The source commit under test is 0123456789abcdef.\n"
        )
        features = dpc._extract_features(text)
        self.assertEqual(features["fix_refs"], set())

    def test_fix_context_sha_and_pr_are_q2_references(self):
        text = (
            "Recommended Fix: apply commit 0123456789abcdef and PR #77043.\n"
            "This one fix closes both paths.\n"
        )
        features = dpc._extract_features(text)
        self.assertEqual(features["fix_refs"], {"sha:0123456789ab", "pr:#77043"})


class SelfSkipFlagTests(unittest.TestCase):
    """Integration tests via subprocess against a temp workspace."""

    def _setup_workspace(self, td: Path) -> tuple[Path, Path, Path]:
        ws = td / "ws"
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "submissions" / "staging").mkdir(parents=True)
        (ws / "submissions" / "packaged").mkdir(parents=True)
        (ws / "submissions" / "held").mkdir(parents=True)
        return ws, ws / "submissions" / "paste_ready", ws / "submissions" / "staging"

    def test_default_behavior_flags_self_collision(self):
        """No flag → paste_ready/foo and staging/foo collide as duplicate (FP)."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ws, pr_dir, stg_dir = self._setup_workspace(tdp)
            new = pr_dir / "RG-N6-S1-finding.md"
            sib = stg_dir / "RG-N6-S1-finding.md"
            _write_draft(new, "RG-N6-S1 paste-ready")
            _write_draft(sib, "RG-N6-S1 staging copy")
            rc, result = _run_cli(str(new), "--workspace", str(ws), "--strict")
            # Without --self-skip-same-family, sibling is flagged.
            self.assertEqual(result.get("verdict"), "duplicate", msg=result)
            self.assertEqual(rc, 1)
            self.assertGreaterEqual(len(result.get("duplicates", [])), 1)
            self.assertFalse(result.get("self_skip_same_family", False))

    def test_flag_skips_same_family_filename_prefix(self):
        """--self-skip-same-family + matching RG-N6-S1 prefix → no duplicate."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ws, pr_dir, stg_dir = self._setup_workspace(tdp)
            new = pr_dir / "RG-N6-S1-finding.md"
            sib = stg_dir / "RG-N6-S1-finding.md"
            _write_draft(new, "RG-N6-S1 paste-ready")
            _write_draft(sib, "RG-N6-S1 staging copy")
            rc, result = _run_cli(
                str(new),
                "--workspace", str(ws),
                "--strict",
                "--self-skip-same-family",
            )
            # When the only sibling is filtered out, no priors remain and
            # exit code is 2 (advisory "no priors"); when other priors remain
            # but none are duplicates, verdict is "distinct" / rc=0. Both are
            # acceptable success cases — the FP flag is gone.
            self.assertIn(
                result.get("verdict"),
                {"distinct", "no_priors_to_compare"},
                msg=result,
            )
            self.assertNotEqual(rc, 1)
            self.assertEqual(result.get("duplicates"), [])
            self.assertTrue(result.get("self_skip_same_family", False))
            skipped = result.get("self_skipped_priors", [])
            self.assertGreaterEqual(len(skipped), 1)
            # Signal should mention family_id=rg-n6-s1.
            self.assertIn("rg-n6-s1", (skipped[0].get("signal") or "").lower())

    def test_flag_does_not_skip_different_family_ids(self):
        """Different family-ids (RG-01 vs RG-02) → still flagged with shared fix."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ws, pr_dir, stg_dir = self._setup_workspace(tdp)
            new = pr_dir / "RG-01-finding.md"
            sib = stg_dir / "RG-02-different-family.md"
            _write_draft(new, "RG-01 paste-ready")
            _write_draft(sib, "RG-02 different family but shared files/fix")
            rc, result = _run_cli(
                str(new),
                "--workspace", str(ws),
                "--strict",
                "--self-skip-same-family",
            )
            # Different families → flag stands.
            self.assertEqual(result.get("verdict"), "duplicate", msg=result)
            self.assertEqual(rc, 1)
            self.assertEqual(result.get("self_skipped_priors"), [])

    def test_flag_with_no_family_id_falls_back_to_old_behavior(self):
        """Neither file has filename-prefix nor frontmatter → flag still fires."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ws, pr_dir, stg_dir = self._setup_workspace(tdp)
            new = pr_dir / "anonymous-finding.md"
            sib = stg_dir / "another-anon.md"
            _write_draft(new, "anon paste-ready")
            _write_draft(sib, "anon staging copy")
            rc, result = _run_cli(
                str(new),
                "--workspace", str(ws),
                "--strict",
                "--self-skip-same-family",
            )
            # No family-id signal on either side → fall back to old behavior.
            self.assertEqual(result.get("verdict"), "duplicate", msg=result)
            self.assertEqual(rc, 1)
            self.assertEqual(result.get("self_skipped_priors"), [])

    def test_flag_skips_on_matching_paste_hash_sidecar(self):
        """Same `.paste_hash` sidecar → same-family skip even without prefix."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ws, pr_dir, stg_dir = self._setup_workspace(tdp)
            new = pr_dir / "anonymous-paste.md"
            sib = stg_dir / "different-name.md"
            _write_draft(new, "anon paste-ready")
            _write_draft(sib, "anon staging copy")
            shared_hash = "deadbeefcafe1234567890abcdef0987"
            (new.with_suffix(new.suffix + ".paste_hash")).write_text(
                shared_hash, encoding="utf-8"
            )
            (sib.with_suffix(sib.suffix + ".paste_hash")).write_text(
                shared_hash, encoding="utf-8"
            )
            rc, result = _run_cli(
                str(new),
                "--workspace", str(ws),
                "--strict",
                "--self-skip-same-family",
            )
            self.assertIn(
                result.get("verdict"),
                {"distinct", "no_priors_to_compare"},
                msg=result,
            )
            self.assertNotEqual(rc, 1)
            skipped = result.get("self_skipped_priors", [])
            self.assertGreaterEqual(len(skipped), 1)
            self.assertIn("paste_content_hash", skipped[0].get("signal") or "")

    def test_flag_skips_on_matching_frontmatter_family_id(self):
        """Same `family_id:` in frontmatter → skip across differing filenames."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ws, pr_dir, stg_dir = self._setup_workspace(tdp)
            new = pr_dir / "alpha.md"
            sib = stg_dir / "beta.md"
            fm = "---\nfamily_id: spark-finalize-leaf-status\n---"
            _write_draft(new, "alpha paste-ready", frontmatter=fm)
            _write_draft(sib, "beta staging copy", frontmatter=fm)
            rc, result = _run_cli(
                str(new),
                "--workspace", str(ws),
                "--strict",
                "--self-skip-same-family",
            )
            self.assertIn(
                result.get("verdict"),
                {"distinct", "no_priors_to_compare"},
                msg=result,
            )
            self.assertNotEqual(rc, 1)
            skipped = result.get("self_skipped_priors", [])
            self.assertGreaterEqual(len(skipped), 1)
            self.assertIn(
                "spark-finalize-leaf-status",
                (skipped[0].get("signal") or "").lower(),
            )


class FiledLaneDupeTests(unittest.TestCase):
    """CAP-GAP-81: submissions/filed/ lane is scanned by default (regression)."""

    def _setup_workspace_with_filed(self, td: Path) -> Path:
        ws = td / "ws"
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "submissions" / "staging").mkdir(parents=True)
        (ws / "submissions" / "filed").mkdir(parents=True)
        return ws

    def test_filed_lane_dupe_detected(self):
        """Draft sharing files+fix-refs with a submissions/filed/ report -> duplicate."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ws = self._setup_workspace_with_filed(tdp)
            prior = ws / "submissions" / "filed" / "spark-lead-hd-filed.md"
            _write_draft(prior, "LEAD H-D (already filed)")
            new_draft = ws / "new-draft.md"
            _write_draft(new_draft, "LEAD H-D refile attempt")
            rc, result = _run_cli(str(new_draft), "--workspace", str(ws), "--strict")
            self.assertEqual(
                result.get("verdict"),
                "duplicate",
                msg=f"Expected duplicate from filed lane; got: {result}",
            )
            self.assertEqual(rc, 1)
            dupes = result.get("duplicates", [])
            self.assertGreaterEqual(len(dupes), 1)
            lanes = {d.get("prior_lane") or d.get("lane") for d in dupes}
            self.assertIn("filed", lanes, msg=f"filed lane not in dupes: {dupes}")

    def test_filed_lane_distinct_passes(self):
        """Draft with no overlap against filed reports -> distinct."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ws = self._setup_workspace_with_filed(tdp)
            prior = ws / "submissions" / "filed" / "unrelated-filed.md"
            prior.write_text(
                "# Unrelated\n\nFiles: other/thing.go:10\n"
                "Fix is in commit aaaaaaaabbbbbbbbcccccccc and PR #999.\n",
                encoding="utf-8",
            )
            new_draft = ws / "new-draft.md"
            _write_draft(new_draft, "Brand new finding - unrelated")
            rc, result = _run_cli(str(new_draft), "--workspace", str(ws))
            self.assertNotEqual(
                result.get("verdict"),
                "duplicate",
                msg=f"Should be distinct; got: {result}",
            )
            self.assertNotEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
