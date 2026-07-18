"""Tests for tools/hot-function-hacker-question-receipt.py

Run:
    python3 -m unittest tools.tests.test_hot_function_hacker_question_receipt -v
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

# Make the repo root importable when run from repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import importlib.util as _ilu

def _load_tool():
    """Dynamically load the tool module (filename has hyphens)."""
    spec = _ilu.spec_from_file_location(
        "hot_function_receipt",
        _REPO_ROOT / "tools" / "hot-function-hacker-question-receipt.py",
    )
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_tool = _load_tool()

SCHEMA = _tool.SCHEMA

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _make_workspace():
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        yield ws


def _make_queue_row(
    lead_id: str = "lead-001",
    title: str = "Test candidate",
    severity: str = "high",
    attack_class: str = "",
) -> dict:
    row: dict = {
        "lead_id": lead_id,
        "title": title,
        "likely_severity": severity,
    }
    if attack_class:
        row["attack_class"] = attack_class
    return row


def _write_queue(ws: Path, rows: list) -> Path:
    path = ws / ".auditooor" / "exploit_queue.source_mined.json"
    payload = {"schema": "auditooor.exploit_queue.v1", "rows": rows}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run_build(ws: Path) -> int:
    return _tool.main(["--workspace", str(ws), "--build", "--no-md"])


def _run_check(ws: Path, strict: bool = False) -> int:
    args = ["--workspace", str(ws)]
    if strict:
        args.append("--strict")
    return _tool.main(args)


def _load_receipt(ws: Path) -> dict:
    path = ws / ".auditooor" / "hot_function_hacker_question_receipt.json"
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestBuildProducesValidReceipt(unittest.TestCase):
    """BUILD produces a schema-valid receipt with required top-level fields."""

    def test_schema_valid_receipt(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row()])
            rc = _run_build(ws)
            self.assertEqual(rc, 0)
            receipt = _load_receipt(ws)
            self.assertEqual(receipt["schema"], SCHEMA)
            for field in ("workspace", "generated_at", "source_queue_path",
                          "function_mindset_tool", "rows", "summary", "receipt_proof"):
                self.assertIn(field, receipt, f"missing field: {field}")

    def test_receipt_proof_is_valid(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row()])
            _run_build(ws)
            receipt = _load_receipt(ws)
            stored_proof = receipt["receipt_proof"]
            # Recompute: SHA-256 of canonical JSON without receipt_proof
            copy = {k: v for k, v in receipt.items() if k != "receipt_proof"}
            canonical = json.dumps(copy, indent=None, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(canonical.encode()).hexdigest()
            self.assertEqual(stored_proof, expected)

    def test_rows_have_required_fields(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row()])
            _run_build(ws)
            receipt = _load_receipt(ws)
            self.assertEqual(len(receipt["rows"]), 1)
            row = receipt["rows"][0]
            for field in ("candidate_id", "queue_row_ref", "source_artifact_refs",
                          "source_anchors", "hot_functions", "function_mindset",
                          "hacker_questions", "gate_blockers"):
                self.assertIn(field, row, f"missing row field: {field}")

    def test_summary_counts_correct(self):
        with _make_workspace() as ws:
            rows = [_make_queue_row(lead_id=f"lead-{i}") for i in range(3)]
            _write_queue(ws, rows)
            _run_build(ws)
            receipt = _load_receipt(ws)
            s = receipt["summary"]
            self.assertEqual(s["rows_seen"], 3)
            self.assertEqual(s["rows_receipted"], 3)


class TestCheckPasses(unittest.TestCase):
    """CHECK passes when all rows have receipts."""

    def test_check_passes_after_build(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row()])
            _run_build(ws)
            rc = _run_check(ws)
            self.assertEqual(rc, 0)

    def test_strict_check_passes_after_build(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row()])
            _run_build(ws)
            rc = _run_check(ws, strict=True)
            self.assertEqual(rc, 0)


class TestCheckFailsMissingReceipt(unittest.TestCase):
    """CHECK --strict fails when receipt file is absent."""

    def test_strict_fails_when_no_receipt_file(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row()])
            # No build - no receipt file
            rc = _run_check(ws, strict=True)
            self.assertNotEqual(rc, 0)

    def test_non_strict_warns_but_exits_zero_when_no_receipt(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row()])
            rc = _run_check(ws, strict=False)
            self.assertEqual(rc, 0)


class TestEmptyOrMissingQueue(unittest.TestCase):
    """Empty or missing source-mined queue is handled gracefully."""

    def test_no_queue_build_emits_empty_receipt(self):
        with _make_workspace() as ws:
            rc = _run_build(ws)
            self.assertEqual(rc, 0)
            receipt = _load_receipt(ws)
            self.assertEqual(receipt["rows"], [])
            self.assertTrue(receipt["summary"].get("no_source_mined_queue"))

    def test_no_queue_check_passes(self):
        with _make_workspace() as ws:
            rc = _run_check(ws, strict=True)
            # No queue = trivially pass (even strict)
            self.assertEqual(rc, 0)

    def test_empty_queue_list_build_ok(self):
        with _make_workspace() as ws:
            _write_queue(ws, [])
            rc = _run_build(ws)
            self.assertEqual(rc, 0)
            receipt = _load_receipt(ws)
            self.assertEqual(receipt["rows"], [])


class TestUnresolvedReasonPath(unittest.TestCase):
    """Rows with no anchor / function data carry typed unresolved_reason, not fabricated data."""

    def test_row_with_no_source_gets_blockers(self):
        with _make_workspace() as ws:
            # Minimal row - no source_anchors, no hot_functions, no attack_class
            _write_queue(ws, [{"lead_id": "bare-lead", "title": "Bare candidate", "likely_severity": "high"}])
            _run_build(ws)
            receipt = _load_receipt(ws)
            row = receipt["rows"][0]
            # Should have blockers for missing anchor and/or hot function
            blockers = row["gate_blockers"]
            self.assertIn("missing_source_anchor", blockers)
            self.assertIn("unresolved_hot_function", blockers)

    def test_row_with_attack_class_resolves_mindset(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row(attack_class="reentrancy")])
            _run_build(ws)
            receipt = _load_receipt(ws)
            row = receipt["rows"][0]
            mindset = row["function_mindset"]
            self.assertTrue(mindset.get("ranked_attack_classes"))
            self.assertNotIn("missing_function_mindset", row["gate_blockers"])

    def test_hacker_questions_synthesized_from_mindset(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row(attack_class="integer-overflow")])
            _run_build(ws)
            receipt = _load_receipt(ws)
            row = receipt["rows"][0]
            qs = row["hacker_questions"]
            self.assertTrue(len(qs) >= 1)
            # Every question must have prompt_text
            for q in qs:
                self.assertIn("prompt_text", q)
                self.assertTrue(q["prompt_text"])


class TestTerminalRowsExempt(unittest.TestCase):
    """Terminal / disproved / OOS queue rows are marked exempt."""

    def test_terminal_row_is_exempt(self):
        with _make_workspace() as ws:
            row = _make_queue_row()
            row["status"] = "dropped"
            _write_queue(ws, [row])
            _run_build(ws)
            receipt = _load_receipt(ws)
            rr = receipt["rows"][0]
            self.assertTrue(rr["is_terminal"])

    def test_strict_check_passes_when_only_terminal_rows_present(self):
        with _make_workspace() as ws:
            row = _make_queue_row()
            row["status"] = "oos"
            _write_queue(ws, [row])
            _run_build(ws)
            rc = _run_check(ws, strict=True)
            self.assertEqual(rc, 0)


class TestSchemaFieldsPresent(unittest.TestCase):
    """Spot-check schema field shapes and types."""

    def test_function_mindset_shape(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row(attack_class="access-control")])
            _run_build(ws)
            receipt = _load_receipt(ws)
            fm = receipt["rows"][0]["function_mindset"]
            self.assertIn("ranked_attack_classes", fm)
            self.assertIn("source", fm)
            self.assertIsInstance(fm["ranked_attack_classes"], list)

    def test_queue_row_ref_shape(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row(lead_id="l-001", severity="critical")])
            _run_build(ws)
            receipt = _load_receipt(ws)
            qr = receipt["rows"][0]["queue_row_ref"]
            self.assertEqual(qr["candidate_id"], "l-001")
            self.assertIn("likely_severity", qr)
            self.assertIn("attack_class", qr)

    def test_hacker_question_schema_field(self):
        with _make_workspace() as ws:
            _write_queue(ws, [_make_queue_row(attack_class="reentrancy")])
            _run_build(ws)
            receipt = _load_receipt(ws)
            qs = receipt["rows"][0]["hacker_questions"]
            for q in qs:
                self.assertEqual(q.get("schema"), "auditooor.hacker_question.v1")
                self.assertIn("question_id", q)


class TestMultipleRows(unittest.TestCase):
    """Multiple rows all get receipted; summary counts are accurate."""

    def test_five_rows_all_receipted(self):
        with _make_workspace() as ws:
            rows = [_make_queue_row(lead_id=f"lead-{i}", attack_class="reentrancy") for i in range(5)]
            _write_queue(ws, rows)
            _run_build(ws)
            receipt = _load_receipt(ws)
            self.assertEqual(len(receipt["rows"]), 5)
            s = receipt["summary"]
            self.assertEqual(s["rows_seen"], 5)
            self.assertEqual(s["rows_receipted"], 5)

    def test_mixed_terminal_and_live_rows(self):
        with _make_workspace() as ws:
            live = _make_queue_row(lead_id="live-1", attack_class="reentrancy")
            terminal = _make_queue_row(lead_id="dead-1")
            terminal["status"] = "dropped"
            _write_queue(ws, [live, terminal])
            _run_build(ws)
            receipt = _load_receipt(ws)
            self.assertEqual(receipt["summary"]["rows_terminal"], 1)

            # check: live row has a receipt entry, strict passes
            rc = _run_check(ws, strict=True)
            self.assertEqual(rc, 0)
