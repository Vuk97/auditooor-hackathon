"""Tests for universal-task-ledger-validate.py (PR #658 commit 1)."""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "universal-task-ledger-validate.py"


def _make_row(**overrides):
    """Builds a minimal valid universal_task_ledger.v1 row."""
    base = {
        "schema": "auditooor.universal_task_ledger.v1",
        "id": "TFILING_LIFECYCLE-20260509-cmtbft-fork-lag",
        "type": "filing_lifecycle",
        "title": "Blocksync verification gap in dYdX cometbft fork at audit-pin",
        "status": "in-progress",
        "owner_agent": "claude",
        "priority": "P0",
        "created_at": "2026-05-08T22:00:00Z",
        "last_touched": "2026-05-09T08:00:00Z",
    }
    base.update(overrides)
    return base


def _run(rows, *args):
    """Runs the validator against a temp JSONL file. Returns (returncode, stderr)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
        path = fh.name
    try:
        proc = subprocess.run(
            ["python3", str(TOOL), path, *args],
            capture_output=True,
            text=True,
        )
        return proc.returncode, proc.stderr
    finally:
        os.unlink(path)


class TestUniversalTaskLedgerValidator(unittest.TestCase):
    def test_minimal_valid_row(self):
        rc, err = _run([_make_row()])
        self.assertEqual(rc, 0, f"expected 0 (valid), got {rc}; stderr:\n{err}")

    def test_missing_required_field(self):
        row = _make_row()
        del row["id"]
        rc, err = _run([row])
        self.assertEqual(rc, 1, f"expected 1 (error), got {rc}; stderr:\n{err}")
        self.assertIn("missing required field", err)

    def test_bad_id_format(self):
        rc, err = _run([_make_row(id="invalid-id-format")])
        self.assertEqual(rc, 1)
        self.assertIn("id format invalid", err)

    def test_bad_type_enum(self):
        rc, err = _run([_make_row(type="not_a_real_type")])
        self.assertEqual(rc, 1)
        self.assertIn("type", err)
        self.assertIn("not in allowed enum", err)

    def test_bad_status_enum(self):
        rc, err = _run([_make_row(status="oh_no")])
        self.assertEqual(rc, 1)
        self.assertIn("status", err)

    def test_bad_owner_enum(self):
        rc, err = _run([_make_row(owner_agent="random_llm")])
        self.assertEqual(rc, 1)
        self.assertIn("owner_agent", err)

    def test_bad_priority_enum(self):
        rc, err = _run([_make_row(priority="P5")])
        self.assertEqual(rc, 1)
        self.assertIn("priority", err)

    def test_bad_iso_datetime(self):
        rc, err = _run([_make_row(created_at="May 8 2026")])
        self.assertEqual(rc, 1)
        self.assertIn("ISO-8601", err)

    def test_title_too_long(self):
        rc, err = _run([_make_row(title="x" * 200)])
        self.assertEqual(rc, 1)
        self.assertIn("title length", err)

    def test_title_too_short(self):
        rc, err = _run([_make_row(title="hi")])
        self.assertEqual(rc, 1)
        self.assertIn("title length", err)

    def test_substate_advisory_warning(self):
        # status_substate "wibble" not in TYPE_SUBSTATE_MAP for filing_lifecycle
        rc, err = _run([_make_row(status_substate="wibble")])
        self.assertEqual(rc, 0, "advisory only by default")
        self.assertIn("WARN", err)

    def test_substate_strict_error(self):
        rc, err = _run([_make_row(status_substate="wibble")], "--check-substate")
        self.assertEqual(rc, 1, "strict substate enforcement")
        self.assertIn("not in TYPE_SUBSTATE_MAP", err)

    def test_strict_mode_promotes_warnings(self):
        rc, err = _run([_make_row(status_substate="wibble")], "--strict")
        self.assertEqual(rc, 1, "strict promotes warnings to errors")

    def test_rules_cited_format_advisory(self):
        rc, err = _run([_make_row(rules_cited=["NotARule"])])
        self.assertEqual(rc, 0, "rules_cited format is advisory")
        self.assertIn("WARN", err)
        self.assertIn("rules_cited entry", err)

    def test_frames_applied_format_advisory(self):
        rc, err = _run([_make_row(frames_applied=["AMF-NotADigit"])])
        self.assertEqual(rc, 0)
        self.assertIn("frames_applied entry", err)

    def test_empty_jsonl_file_valid(self):
        rc, err = _run([])
        self.assertEqual(rc, 0)

    def test_comments_skipped(self):
        # Real validator skips lines starting with #
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as fh:
            fh.write("# this is a comment\n")
            fh.write(json.dumps(_make_row()) + "\n")
            path = fh.name
        try:
            proc = subprocess.run(
                ["python3", str(TOOL), path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0)
        finally:
            os.unlink(path)

    def test_print_schema(self):
        proc = subprocess.run(
            ["python3", str(TOOL), "--print-schema"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        schema = json.loads(proc.stdout)
        self.assertEqual(schema["$id"], "auditooor.universal_task_ledger.v1")

    def test_all_15_task_types_valid(self):
        types = [
            "klbq_burndown", "retro_audit", "corpus_mining", "detector_authoring",
            "cross_engagement_propagation", "in_engagement_hunt", "filing_lifecycle",
            "rule_codification", "triager_response", "tooling_ship", "pr_landing",
            "next_loop_priority", "commit_mining", "external_intel_intake", "regression_repro",
        ]
        for t in types:
            row = _make_row(type=t, id=f"T{t.upper()}-20260509-test-row")
            rc, err = _run([row])
            self.assertEqual(rc, 0, f"task type {t!r} should validate; stderr:\n{err}")


if __name__ == "__main__":
    unittest.main()
