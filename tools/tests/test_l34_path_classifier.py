#!/usr/bin/env python3
"""Regression coverage for tools/l34-path-classifier.py.

Covers:
- 5-bucket classification (draft-file, tracker-file, workspace-ledger,
  lesson-anchor, out-of-scope)
- iter17 YYYYY anchor paths (SUBMISSIONS.md across spark/hyperbridge/polymarket)
- .hash sidecar inheritance
- backup-suffix tolerance (.bak / .backup-old / .bak-FOO)
- per-finding folder vs flat status-dir contents
- glob expansion
- JSON vs human-readable output shapes
- exit codes for empty input / zero-match glob
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "l34-path-classifier.py"


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(TOOL), *args]
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        check=False,
    )


def _classify_json(*paths: str) -> dict:
    proc = _run(*paths, "--json")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


class L34PathClassifierBucketTests(unittest.TestCase):
    """Verify each of the 5 buckets is produced for canonical inputs."""

    def test_tracker_file_at_submissions_root(self) -> None:
        payload = _classify_json("/tmp/ws/submissions/SUBMISSIONS.md")
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_tracker_file_inside_status_dir(self) -> None:
        payload = _classify_json("/tmp/ws/submissions/staging/SUBMISSIONS.md")
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_draft_file_inside_per_finding_folder(self) -> None:
        payload = _classify_json(
            "/tmp/ws/submissions/filed/hb-arbitrum-orbit-HIGH/"
            "hb-arbitrum-orbit-HIGH.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "draft-file")
        self.assertTrue(rec["requires_per_draft_op_auth"])

    def test_workspace_ledger(self) -> None:
        payload = _classify_json("/tmp/ws/.auditooor/commit_lifecycle_ledger.json")
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "workspace-ledger")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_lesson_anchor(self) -> None:
        payload = _classify_json(
            "/tmp/ws/submissions/_lessons-learned/lesson-2026-05-23.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_out_of_scope(self) -> None:
        payload = _classify_json("/Users/wolf/.zshrc")
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "out-of-scope")
        self.assertFalse(rec["requires_per_draft_op_auth"])


class L34PathClassifierIter17AnchorTests(unittest.TestCase):
    """Replay the iter17 YYYYY anchor paths verbatim.

    YYYYY auto-executed tracker edits to SUBMISSIONS.md in 3 workspaces;
    classifier MUST agree those edits were auto-executable (tracker-file +
    requires_per_draft_op_auth=false).
    """

    def test_polymarket_submissions_md(self) -> None:
        payload = _classify_json(
            "/Users/wolf/audits/polymarket/submissions/SUBMISSIONS.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_spark_submissions_md(self) -> None:
        payload = _classify_json(
            "/Users/wolf/audits/spark/submissions/SUBMISSIONS.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_hyperbridge_submissions_md(self) -> None:
        payload = _classify_json(
            "/Users/wolf/audits/hyperbridge/submissions/SUBMISSIONS.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_zshrc_out_of_scope(self) -> None:
        payload = _classify_json("/Users/wolf/.zshrc")
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "out-of-scope")


class L34PathClassifierEdgeCaseTests(unittest.TestCase):
    """Edge cases: sidecar files, backup suffixes, status-dir variants,
    deeper draft paths, unknown subdirs under submissions/."""

    def test_hash_sidecar_inherits_tracker_classification(self) -> None:
        payload = _classify_json("/tmp/ws/submissions/SUBMISSIONS.md.hash")
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")

    def test_hash_sidecar_inherits_draft_classification(self) -> None:
        payload = _classify_json(
            "/tmp/ws/submissions/filed/finding-slug/finding-slug.md.hash"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "draft-file")
        self.assertTrue(rec["requires_per_draft_op_auth"])

    def test_backup_suffix_routes_to_tracker(self) -> None:
        payload = _classify_json(
            "/tmp/ws/submissions/SUBMISSIONS.md.backup-old"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")

    def test_bak_FOO_suffix_routes_to_tracker(self) -> None:
        payload = _classify_json(
            "/tmp/ws/submissions/SUBMISSIONS.md.bak-R82"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")

    def test_killed_dir_is_lesson_anchor_per_cap_gap_96(self) -> None:
        # CAP-GAP-96 (2026-05-27): _killed/<slug>/<slug>.md is post-mortem
        # material, not active draft. Flipped from draft-file -> lesson-anchor.
        # r36-rebuttal: agent_pathspec.json lane-CAP-FIX-W13-l34-killed-bucket
        payload = _classify_json(
            "/tmp/ws/submissions/_killed/old-finding/old-finding.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_oos_rejected_dir_is_lesson_anchor_per_cap_gap_96(self) -> None:
        # CAP-GAP-96 (2026-05-27): _oos_rejected/<slug>/<slug>.md is
        # post-decision rationale, not active draft.
        # r36-rebuttal: tools/agent-pathspec-register.py declared this edit
        payload = _classify_json(
            "/tmp/ws/submissions/_oos_rejected/finding/finding.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_paste_ready_per_finding_folder(self) -> None:
        payload = _classify_json(
            "/tmp/ws/submissions/paste_ready/cantina-192/cantina-192.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "draft-file")

    def test_paste_ready_artifact_zip(self) -> None:
        payload = _classify_json(
            "/tmp/ws/submissions/paste_ready/cantina-192/cantina-192-poc.zip"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "draft-file")
        self.assertTrue(rec["requires_per_draft_op_auth"])

    def test_readme_at_status_dir_root_is_tracker(self) -> None:
        payload = _classify_json("/tmp/ws/submissions/filed/README.md")
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_unknown_dir_under_submissions_defaults_to_draft(self) -> None:
        # Defensive: if operator creates submissions/some_new_dir/finding.md
        # without updating DRAFT_STATUS_DIRS, classifier defaults to draft-file
        # (safer than auto-executable).
        payload = _classify_json(
            "/tmp/ws/submissions/some_new_dir/finding/finding.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "draft-file")
        self.assertTrue(rec["requires_per_draft_op_auth"])

    def test_flat_draft_at_submissions_root_defaults_to_draft(self) -> None:
        # Polymarket pre-R41 layout: legacy single-file drafts flat in
        # submissions/. Classifier treats as draft-file (auth required).
        payload = _classify_json(
            "/tmp/ws/submissions/D14-OrderStatus-uint248-overflow.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "draft-file")
        self.assertTrue(rec["requires_per_draft_op_auth"])

    def test_lesson_anchor_dir_alt_underscore(self) -> None:
        payload = _classify_json(
            "/tmp/ws/submissions/_lessons_learned/lesson.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")

    def test_workspace_ledger_nested(self) -> None:
        payload = _classify_json(
            "/tmp/ws/.auditooor/agent_recall_detector_queue.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "workspace-ledger")

    def test_workspace_ledger_subdir(self) -> None:
        payload = _classify_json(
            "/tmp/ws/.auditooor/snapshots/snapshot.json"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "workspace-ledger")

    def test_submissions_directory_itself_out_of_scope(self) -> None:
        payload = _classify_json("/tmp/ws/submissions/")
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "out-of-scope")

    def test_existing_directory_path_is_out_of_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "submissions" / "staging"
            path.mkdir(parents=True)
            payload = _classify_json(str(path))
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "out-of-scope")
        self.assertFalse(rec["requires_per_draft_op_auth"])


class L34PathClassifierIOTests(unittest.TestCase):
    """Verify CLI flags: --batch, --glob, --json, exit codes."""

    def test_batch_flag(self) -> None:
        proc = _run(
            "--batch",
            "/tmp/ws/submissions/SUBMISSIONS.md",
            "/tmp/ws/submissions/filed/slug/slug.md",
            "--json",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(len(payload["results"]), 2)
        self.assertEqual(payload["results"][0]["bucket"], "tracker-file")
        self.assertEqual(payload["results"][1]["bucket"], "draft-file")

    def test_glob_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "submissions").mkdir()
            (ws / "submissions" / "SUBMISSIONS.md").write_text("x", encoding="utf-8")
            (ws / "submissions" / "filed").mkdir()
            (ws / "submissions" / "filed" / "slug").mkdir()
            (ws / "submissions" / "filed" / "slug" / "slug.md").write_text(
                "x", encoding="utf-8"
            )
            proc = _run(
                "--glob",
                "submissions/**/*.md",
                "--workspace",
                str(ws),
                "--json",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["total"], 2)
            buckets = sorted(r["bucket"] for r in payload["results"])
            self.assertEqual(buckets, ["draft-file", "tracker-file"])

    def test_glob_zero_matches_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            proc = _run(
                "--glob",
                "no-match-pattern-*.md",
                "--workspace",
                td,
                "--json",
            )
            self.assertEqual(proc.returncode, 2)

    def test_no_paths_returns_1(self) -> None:
        proc = _run("--json")
        self.assertEqual(proc.returncode, 1)

    def test_schema_version_present(self) -> None:
        payload = _classify_json("/tmp/ws/submissions/SUBMISSIONS.md")
        self.assertEqual(payload["schema"], "auditooor.l34_path_classifier.v1")
        self.assertIn("tool_version", payload)

    def test_summary_counts_correct(self) -> None:
        payload = _classify_json(
            "/tmp/ws/submissions/SUBMISSIONS.md",
            "/tmp/ws/submissions/filed/slug/slug.md",
            "/tmp/ws/.auditooor/ledger.json",
            "/tmp/ws/submissions/_lessons-learned/lesson.md",
            "/etc/hosts",
        )
        s = payload["summary"]
        self.assertEqual(s["total"], 5)
        self.assertEqual(s["tracker_file"], 1)
        self.assertEqual(s["draft_file"], 1)
        self.assertEqual(s["workspace_ledger"], 1)
        self.assertEqual(s["lesson_anchor"], 1)
        self.assertEqual(s["out_of_scope"], 1)

    def test_human_readable_output_contains_AUTH_marker(self) -> None:
        proc = _run(
            "/tmp/ws/submissions/filed/slug/slug.md",
            "/tmp/ws/submissions/SUBMISSIONS.md",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("[AUTH]", proc.stdout)
        self.assertIn("[auto]", proc.stdout)

    def test_tilde_expansion(self) -> None:
        # ~/foo/submissions/SUBMISSIONS.md should expand to
        # $HOME/foo/submissions/SUBMISSIONS.md and classify as tracker-file
        # without needing the file to exist.
        payload = _classify_json("~/foo/submissions/SUBMISSIONS.md")
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")


class L34PathClassifierCapGap96Tests(unittest.TestCase):
    """CAP-GAP-96 (codified 2026-05-27): post-decision dirs route to
    lesson-anchor bucket (auto-executable), not draft-file.

    Anchor: Hyperbridge bandwidth-fot-over-credit kill + c4-solver kill
    (2026-05-27) both wanted to write in-folder DISPOSITION.md but were
    blocked because the prior classifier treated _killed/<slug>/<slug>.md as
    draft-file requiring per-draft op auth. Killed findings are post-mortem
    material, semantically equivalent to _lessons-learned/.

    r36-rebuttal: tools/agent-pathspec-register.py declared this edit
    """

    def test_killed_disposed_slug_md_is_lesson_anchor(self) -> None:
        # Case 1: _killed/<slug>/<slug>.md -> lesson-anchor, auth=false
        payload = _classify_json(
            "/tmp/ws/submissions/_killed/bandwidth-fot-salvage/"
            "bandwidth-fot-salvage.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_killed_disposition_md_is_lesson_anchor(self) -> None:
        # Case 2: _killed/<slug>/DISPOSITION.md -> lesson-anchor, auth=false
        payload = _classify_json(
            "/tmp/ws/submissions/_killed/bandwidth-fot-salvage/"
            "DISPOSITION.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_killed_kill_rationale_md_is_lesson_anchor(self) -> None:
        # Case 3: _killed/<slug>/KILL_RATIONALE.md -> lesson-anchor, auth=false
        payload = _classify_json(
            "/tmp/ws/submissions/_killed/c4-solver-controlled/"
            "KILL_RATIONALE.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_oos_rejected_slug_md_is_lesson_anchor(self) -> None:
        # Case 4: _oos_rejected/<slug>/<slug>.md -> lesson-anchor, auth=false
        payload = _classify_json(
            "/tmp/ws/submissions/_oos_rejected/finding-slug/finding-slug.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_superseded_underscore_slug_md_is_lesson_anchor(self) -> None:
        # Case 5a: _superseded/<slug>/<slug>.md -> lesson-anchor, auth=false
        payload = _classify_json(
            "/tmp/ws/submissions/_superseded/finding-slug/finding-slug.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_superseded_no_underscore_slug_md_is_lesson_anchor(self) -> None:
        # Case 5b: superseded/<slug>/<slug>.md (spark convention without
        # leading underscore) -> lesson-anchor, auth=false.
        payload = _classify_json(
            "/Users/wolf/audits/spark/submissions/superseded/"
            "spark-claim-path-leaf-status-guard-gap-CRITICAL/"
            "spark-claim-path-leaf-status-guard-gap-CRITICAL.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_regression_staging_slug_md_still_draft_file(self) -> None:
        # Case 6: regression - submissions/staging/<slug>/<slug>.md still
        # classifies as draft-file (auth required). CAP-GAP-96 must NOT
        # widen lesson-anchor to in-progress drafts.
        payload = _classify_json(
            "/tmp/ws/submissions/staging/active-finding/active-finding.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "draft-file")
        self.assertTrue(rec["requires_per_draft_op_auth"])

    def test_killed_md_hash_sidecar_inherits_lesson_anchor(self) -> None:
        # .md.hash sidecar inside _killed/ must inherit lesson-anchor
        # bucket from its parent .md file.
        payload = _classify_json(
            "/tmp/ws/submissions/_killed/finding/finding.md.hash"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_killed_poc_zip_artifact_is_lesson_anchor(self) -> None:
        # Pre-kill staging artifacts that survived into _killed/ subtree
        # (.poc.zip, .hardening.md, .hackenproof-plain.{txt,json}) are
        # post-decision artifacts and auto-executable.
        payload = _classify_json(
            "/tmp/ws/submissions/_killed/finding/finding-poc.zip"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_killed_flat_submissions_md_is_tracker(self) -> None:
        # Edge: SUBMISSIONS.md flat inside _killed/ (status-dir root) is a
        # tracker file, not a lesson anchor. Tracker-stem detection wins
        # over post-decision-dir routing for flat metadata.
        payload = _classify_json(
            "/tmp/ws/submissions/_killed/SUBMISSIONS.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "tracker-file")
        self.assertFalse(rec["requires_per_draft_op_auth"])

    def test_killed_flat_disposition_md_is_lesson_anchor(self) -> None:
        # Edge: flat DISPOSITION.md at _killed/ root (no slug subdir) is
        # still lesson-anchor since it's post-decision material.
        payload = _classify_json(
            "/tmp/ws/submissions/_killed/DISPOSITION.md"
        )
        rec = payload["results"][0]
        self.assertEqual(rec["bucket"], "lesson-anchor")
        self.assertFalse(rec["requires_per_draft_op_auth"])


if __name__ == "__main__":
    unittest.main()
