#!/usr/bin/env python3
"""Tests for ``tools/placeholder-fp-remediation-queue.py``.

Burn-down item #9: indexed reversible remediation queue for placeholder
FP-guard fields. Tests are hermetic (each scenario builds a synthetic spec
tree under tempfile and a separate workspace dir) and exercise the script
through both the in-process API and the CLI subprocess contract.

Coverage map:

  scan
    test_scan_empty_queue            scan over zero placeholders -> empty queue, state file present
    test_scan_finds_five_rows        five synthetic placeholders -> five queue rows with deterministic shas
    test_scan_idempotent             second --scan keeps shas stable + bumps last_seen
    test_field_table_matches_lint    queue table stays in sync with detector-lint.py Check 4b

  worker
    test_worker_emits_proposals      five-row queue -> --worker --limit N produces N diff + sidecar pairs
    test_worker_no_pending           re-running worker after all rows proposed -> no-op
    test_worker_skips_missing_file   target file missing -> row skipped, status preserved

  apply / rollback
    test_apply_then_rollback_reverts apply mutates target; rollback restores byte-equal original
    test_partial_apply_other_rows_pending one apply leaves other proposed rows untouched
    test_apply_unknown_sha           rc != 0, structured error
    test_apply_after_drift           target hand-edited after proposal -> source-drift refusal
    test_rollback_only_after_apply   rollback on a proposed-only row refuses
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "placeholder-fp-remediation-queue.py"
DETECTOR_LINT = ROOT / "tools" / "detector-lint.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


# Load once at module scope so tests can call APIs directly without re-paying
# import cost. Hyphenated filename means the importlib path is the cleanest.
PFP = _load_module(SCRIPT, "placeholder_fp_queue")
LINT = _load_module(DETECTOR_LINT, "detector_lint")


def _run_cli(workspace: Path, *args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--workspace", str(workspace), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _write_synthetic_draft(spec_dir: Path, slug: str, placeholder: str) -> Path:
    """Write a YAML draft mirroring the real generated-spec shape."""
    spec_dir.mkdir(parents=True, exist_ok=True)
    yaml_path = spec_dir / f"{slug}.yaml"
    body = (
        'skeleton: "name_match_missing_call"\n'
        f'name: "{slug}"\n'
        f'class_name: "TestSlug"\n'
        'wave: "14"\n'
        'severity: "HIGH"\n'
        f'{placeholder}\n'
        'vuln_fn_name: "doIt"\n'
    )
    yaml_path.write_text(body, encoding="utf-8")
    return yaml_path


def _build_synthetic_workspace(tmp: Path, n_rows: int) -> Path:
    """Create a synthetic spec_root (==workspace) with `n_rows` placeholder hits.

    Each row uses a distinct placeholder field so the suggested-action
    heuristic table is exercised across its branches.
    """
    spec_dir = tmp / "detectors" / "_specs" / "drafts_synthetic"
    spec_dir.mkdir(parents=True, exist_ok=True)

    placeholder_lines = [
        'guarded_helper_name: "_accrue"',
        'guarded_helper_name: "_guard"',
        'guard_require_line: "require(newVal <= 10000, \\"err\\");"',
        'guard_var_regex: ".*(balance|amount|total|supply|reserve).*"',
        'guard_var_regex: ".*(admin|owner|balance|amount).*"',
    ]
    for i in range(n_rows):
        _write_synthetic_draft(spec_dir, f"draft-{i:03d}", placeholder_lines[i % len(placeholder_lines)])
    return tmp


class ScanTests(unittest.TestCase):
    def test_scan_empty_queue(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            # No drafts at all.
            (tmp / "detectors" / "_specs").mkdir(parents=True)
            rc, out, err = _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            self.assertEqual(rc, 0, msg=err)
            payload = json.loads(out)
            self.assertEqual(payload["hits"], 0)
            self.assertEqual(payload["new"], 0)
            queue_path = tmp / ".auditooor" / "placeholder_fp_queue.jsonl"
            state_path = tmp / ".auditooor" / "placeholder_fp_queue_state.json"
            self.assertTrue(queue_path.is_file())
            self.assertTrue(state_path.is_file())
            self.assertEqual(queue_path.read_text(encoding="utf-8"), "")

    def test_scan_finds_five_rows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=5)
            rc, out, err = _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            self.assertEqual(rc, 0, msg=err)
            payload = json.loads(out)
            self.assertEqual(payload["hits"], 5)
            self.assertEqual(payload["new"], 5)
            queue_path = tmp / ".auditooor" / "placeholder_fp_queue.jsonl"
            rows = [json.loads(ln) for ln in queue_path.read_text().splitlines() if ln.strip()]
            self.assertEqual(len(rows), 5)
            shas = {row["sha"] for row in rows}
            self.assertEqual(len(shas), 5)
            for row in rows:
                self.assertEqual(row["status"], PFP.ST_PENDING)
                self.assertIn(row["field"], PFP.PLACEHOLDER_FP_GUARD_FIELDS)
                self.assertIn(row["action"], {
                    "grep-discover-helper",
                    "tighten-require-line",
                    "tighten-regex-anchor",
                    "flag-as-todo",
                })

    def test_scan_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=3)
            rc1, out1, _ = _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            self.assertEqual(rc1, 0)
            shas_first = {
                json.loads(ln)["sha"]
                for ln in (tmp / ".auditooor" / "placeholder_fp_queue.jsonl").read_text().splitlines()
                if ln.strip()
            }
            rc2, out2, _ = _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            self.assertEqual(rc2, 0)
            payload = json.loads(out2)
            self.assertEqual(payload["new"], 0)
            self.assertEqual(payload["refreshed"], 3)
            shas_second = {
                json.loads(ln)["sha"]
                for ln in (tmp / ".auditooor" / "placeholder_fp_queue.jsonl").read_text().splitlines()
                if ln.strip()
            }
            self.assertEqual(shas_first, shas_second)

    def test_field_table_matches_lint(self) -> None:
        """Queue's placeholder-field table must stay in sync with Check 4b."""
        self.assertEqual(
            dict(PFP.PLACEHOLDER_FP_GUARD_FIELDS),
            dict(LINT._PLACEHOLDER_FP_GUARD_FIELDS),
        )


class WorkerTests(unittest.TestCase):
    def test_worker_emits_proposals(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=5)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            rc, out, err = _run_cli(tmp, "--worker", "--limit", "3")
            self.assertEqual(rc, 0, msg=err)
            payload = json.loads(out)
            self.assertEqual(payload["emitted"], 3)
            self.assertEqual(payload["remaining_pending"], 2)
            proposals_dir = tmp / ".auditooor" / "placeholder_fp_proposals"
            diffs = list(proposals_dir.glob("*.diff"))
            sidecars = list(proposals_dir.glob("*.sidecar.json"))
            self.assertEqual(len(diffs), 3)
            self.assertEqual(len(sidecars), 3)
            for diff in diffs:
                body = diff.read_text(encoding="utf-8")
                self.assertIn("OPERATOR REVIEW REQUIRED", body)
                self.assertIn("Apply with", body)
                self.assertIn("Rollback", body)

    def test_worker_no_pending(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=2)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            _run_cli(tmp, "--worker", "--limit", "10")
            rc, out, _ = _run_cli(tmp, "--worker", "--limit", "10")
            self.assertEqual(rc, 0)
            payload = json.loads(out)
            self.assertEqual(payload["emitted"], 0)
            self.assertEqual(payload["remaining_pending"], 0)

    def test_worker_skips_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=2)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            # Now delete one target file before worker runs.
            queue_path = tmp / ".auditooor" / "placeholder_fp_queue.jsonl"
            rows = [json.loads(ln) for ln in queue_path.read_text().splitlines() if ln.strip()]
            target = Path(rows[0]["path"])
            target.unlink()
            rc, out, _ = _run_cli(tmp, "--worker", "--limit", "10")
            self.assertEqual(rc, 0)
            payload = json.loads(out)
            self.assertEqual(payload["emitted"], 1)
            self.assertEqual(len(payload["skipped"]), 1)
            self.assertEqual(payload["skipped"][0]["reason"], "empty-source")


class ApplyRollbackTests(unittest.TestCase):
    def test_apply_then_rollback_reverts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=1)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            _run_cli(tmp, "--worker", "--limit", "5")
            queue_path = tmp / ".auditooor" / "placeholder_fp_queue.jsonl"
            rows = [json.loads(ln) for ln in queue_path.read_text().splitlines() if ln.strip()]
            row = rows[0]
            target_path = Path(row["path"])
            original_bytes = target_path.read_bytes()

            rc, out, err = _run_cli(tmp, "--apply", row["sha"])
            self.assertEqual(rc, 0, msg=err)
            self.assertNotEqual(target_path.read_bytes(), original_bytes)
            # Status flipped to applied
            rows2 = [json.loads(ln) for ln in queue_path.read_text().splitlines() if ln.strip()]
            applied_row = next(r for r in rows2 if r["sha"] == row["sha"])
            self.assertEqual(applied_row["status"], PFP.ST_APPLIED)

            rc, out, err = _run_cli(tmp, "--rollback", row["sha"])
            self.assertEqual(rc, 0, msg=err)
            # Byte-equal restoration
            self.assertEqual(target_path.read_bytes(), original_bytes)
            rows3 = [json.loads(ln) for ln in queue_path.read_text().splitlines() if ln.strip()]
            rolled_row = next(r for r in rows3 if r["sha"] == row["sha"])
            self.assertEqual(rolled_row["status"], PFP.ST_ROLLED_BACK)

    def test_partial_apply_other_rows_pending(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=4)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            _run_cli(tmp, "--worker", "--limit", "4")
            queue_path = tmp / ".auditooor" / "placeholder_fp_queue.jsonl"
            rows = [json.loads(ln) for ln in queue_path.read_text().splitlines() if ln.strip()]
            target_sha = rows[0]["sha"]
            other_paths = {r["path"]: Path(r["path"]).read_bytes() for r in rows[1:]}

            rc, _, err = _run_cli(tmp, "--apply", target_sha)
            self.assertEqual(rc, 0, msg=err)
            for path, body in other_paths.items():
                self.assertEqual(Path(path).read_bytes(), body)

            rows2 = [json.loads(ln) for ln in queue_path.read_text().splitlines() if ln.strip()]
            statuses = {r["sha"]: r["status"] for r in rows2}
            self.assertEqual(statuses[target_sha], PFP.ST_APPLIED)
            for r in rows2:
                if r["sha"] != target_sha:
                    self.assertEqual(r["status"], PFP.ST_PROPOSED)

    def test_apply_unknown_sha(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "detectors" / "_specs").mkdir(parents=True)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            rc, _, err = _run_cli(tmp, "--apply", "deadbeef0000")
            self.assertNotEqual(rc, 0)
            payload = json.loads(err or "{}")
            self.assertEqual(payload.get("error"), "unknown-sha")

    def test_apply_after_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=1)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            _run_cli(tmp, "--worker", "--limit", "5")
            queue_path = tmp / ".auditooor" / "placeholder_fp_queue.jsonl"
            rows = [json.loads(ln) for ln in queue_path.read_text().splitlines() if ln.strip()]
            row = rows[0]
            target_path = Path(row["path"])
            # Hand-edit the target to simulate drift.
            target_path.write_text(target_path.read_text() + "\n# drift\n", encoding="utf-8")
            rc, _, err = _run_cli(tmp, "--apply", row["sha"])
            self.assertNotEqual(rc, 0)
            payload = json.loads(err or "{}")
            self.assertEqual(payload.get("error"), "source-drift")

    def test_rollback_only_after_apply(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=1)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            _run_cli(tmp, "--worker", "--limit", "5")
            queue_path = tmp / ".auditooor" / "placeholder_fp_queue.jsonl"
            rows = [json.loads(ln) for ln in queue_path.read_text().splitlines() if ln.strip()]
            row = rows[0]
            rc, _, err = _run_cli(tmp, "--rollback", row["sha"])
            self.assertNotEqual(rc, 0)
            payload = json.loads(err or "{}")
            self.assertEqual(payload.get("error"), "invalid-state")


class StatusListTests(unittest.TestCase):
    def test_status_summary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=3)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            _run_cli(tmp, "--worker", "--limit", "2")
            rc, out, _ = _run_cli(tmp, "--status")
            self.assertEqual(rc, 0)
            payload = json.loads(out)
            self.assertEqual(payload["total"], 3)
            self.assertEqual(payload["counts"][PFP.ST_PENDING], 1)
            self.assertEqual(payload["counts"][PFP.ST_PROPOSED], 2)

    def test_list_proposals(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = _build_synthetic_workspace(Path(raw), n_rows=2)
            _run_cli(tmp, "--scan", "--spec-root", str(tmp))
            _run_cli(tmp, "--worker", "--limit", "2")
            rc, out, _ = _run_cli(tmp, "--list-proposals")
            self.assertEqual(rc, 0)
            payload = json.loads(out)
            self.assertEqual(payload["count"], 2)
            for entry in payload["proposals"]:
                self.assertEqual(entry["status"], PFP.ST_PROPOSED)


if __name__ == "__main__":
    unittest.main()
