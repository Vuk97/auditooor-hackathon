"""test_provider_output_normalizer.py -- Unit tests for tools/provider-output-normalizer.py

HACKERMAN_V2 Slice 1 deliverable.

Coverage:
  - Each of the 8 normalized types is producible
  - Required fields present on every item
  - Malformed/empty provider result -> provider_failure
  - Idempotent append (no dup lines)
  - Schema field presence
  - CLI round-trip (json output)
  - Explicit type override
  - Token estimate auto-derivation
  - Local verification command auto-derivation
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "provider-output-normalizer.py"

REQUIRED_FIELDS = {
    "schema",
    "ts",
    "normalized_type",
    "disposition",
    "provider",
    "model",
    "task_type",
    "prompt_path",
    "output_path",
    "token_estimate",
    "local_verification_command",
    "local_verification_run",
    "raw_length",
    "dedup_key",
}

NORMALIZED_TYPES = {
    "verified_source_fact_pending_local_check",
    "candidate_detector_generalization",
    "candidate_fixture",
    "candidate_chain_edge",
    "candidate_poc_task",
    "kill_reason_pending_local_check",
    "duplicate_or_oos_risk",
    "provider_failure",
}

DISPOSITIONS = {"KEEP", "KILL", "DEFER", "SOURCE_NEEDED"}


def _import_module():
    spec = importlib.util.spec_from_file_location("provider_output_normalizer", str(TOOL))
    assert spec is not None and spec.loader is not None, f"Cannot load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


mod = _import_module()
normalize = mod.normalize
append_to_queue = mod.append_to_queue

_BASE = dict(
    provider="minimax",
    model="MiniMax-M2.7",
    task_type="adversarial-kill",
    prompt_path="/tmp/prompt.md",
    output_path="/tmp/output.txt",
)


class TestRequiredFields(unittest.TestCase):
    """Every normalize() call must return all required fields."""

    def _call(self, raw_text: str, **kwargs) -> dict:
        kw = dict(_BASE)
        kw.update(kwargs)
        return normalize(raw_text=raw_text, **kw)

    def test_required_fields_present_on_normal_output(self):
        item = self._call("file: contracts/Foo.sol\nline: 42\nfunction: transfer")
        missing = REQUIRED_FIELDS - set(item.keys())
        self.assertEqual(missing, set(), f"Missing fields: {missing}")

    def test_required_fields_present_on_empty_output(self):
        item = self._call("")
        missing = REQUIRED_FIELDS - set(item.keys())
        self.assertEqual(missing, set(), f"Missing fields on empty: {missing}")

    def test_disposition_is_valid(self):
        item = self._call("some text")
        self.assertIn(item["disposition"], DISPOSITIONS)

    def test_normalized_type_is_valid(self):
        item = self._call("some text")
        self.assertIn(item["normalized_type"], NORMALIZED_TYPES)

    def test_schema_version(self):
        item = self._call("x")
        self.assertEqual(item["schema"], "auditooor.provider_normalized_work_queue.v1")

    def test_local_verification_run_is_bool(self):
        item = self._call("x")
        self.assertIsInstance(item["local_verification_run"], bool)

    def test_raw_length_matches(self):
        text = "hello world"
        item = self._call(text)
        self.assertEqual(item["raw_length"], len(text))

    def test_token_estimate_auto(self):
        text = "x" * 400
        item = self._call(text)
        # ~400/4 = 100
        self.assertGreater(item["token_estimate"], 0)

    def test_token_estimate_explicit(self):
        item = self._call("x", token_estimate=9999)
        self.assertEqual(item["token_estimate"], 9999)

    def test_local_verification_run_explicit(self):
        item = self._call("x", local_verification_run=True)
        self.assertTrue(item["local_verification_run"])

    def test_local_verification_command_explicit(self):
        item = self._call("x", local_verification_command="grep foo /bar.sol")
        self.assertEqual(item["local_verification_command"], "grep foo /bar.sol")

    def test_dedup_key_present_and_nonempty(self):
        item = self._call("x")
        self.assertIsInstance(item["dedup_key"], str)
        self.assertGreater(len(item["dedup_key"]), 0)

    def test_dedup_key_stable(self):
        item1 = self._call("x")
        item2 = self._call("y")  # same output_path, same type
        # Both should produce the same dedup_key because output_path + type are the same
        # (type may differ based on content, so compare only if types match)
        if item1["normalized_type"] == item2["normalized_type"]:
            self.assertEqual(item1["dedup_key"], item2["dedup_key"])


class TestAllEightTypes(unittest.TestCase):
    """Each of the 8 normalized types must be producible."""

    def _call(self, raw_text: str, explicit_type=None) -> dict:
        return normalize(raw_text=raw_text, explicit_type=explicit_type, **_BASE)

    def test_provider_failure_from_empty(self):
        item = self._call("")
        self.assertEqual(item["normalized_type"], "provider_failure")
        self.assertEqual(item["disposition"], "KILL")

    def test_provider_failure_from_error_text(self):
        item = self._call('{"reason": "cannot-run: no-api-key", "provider": "minimax"}')
        self.assertEqual(item["normalized_type"], "provider_failure")

    def test_provider_failure_explicit(self):
        item = self._call("some text", explicit_type="provider_failure")
        self.assertEqual(item["normalized_type"], "provider_failure")
        self.assertEqual(item["disposition"], "KILL")

    def test_duplicate_or_oos_risk(self):
        item = self._call("This finding is a duplicate of issue #777 - already known.")
        self.assertEqual(item["normalized_type"], "duplicate_or_oos_risk")
        self.assertEqual(item["disposition"], "DEFER")

    def test_duplicate_or_oos_risk_explicit(self):
        item = self._call("x", explicit_type="duplicate_or_oos_risk")
        self.assertEqual(item["normalized_type"], "duplicate_or_oos_risk")
        self.assertEqual(item["disposition"], "DEFER")

    def test_kill_reason_pending_local_check(self):
        item = self._call("KILL: no direct path from the bug site to the claimed impact.")
        self.assertEqual(item["normalized_type"], "kill_reason_pending_local_check")
        self.assertEqual(item["disposition"], "KILL")

    def test_kill_reason_explicit(self):
        item = self._call("x", explicit_type="kill_reason_pending_local_check")
        self.assertEqual(item["normalized_type"], "kill_reason_pending_local_check")
        self.assertEqual(item["disposition"], "KILL")

    def test_candidate_poc_task(self):
        item = self._call("POC task: reproduce with the following harness plan...")
        self.assertEqual(item["normalized_type"], "candidate_poc_task")
        self.assertEqual(item["disposition"], "KEEP")

    def test_candidate_poc_task_explicit(self):
        item = self._call("x", explicit_type="candidate_poc_task")
        self.assertEqual(item["normalized_type"], "candidate_poc_task")

    def test_candidate_chain_edge(self):
        item = self._call("chain edge: requires first calling approve() before exploiting...")
        self.assertEqual(item["normalized_type"], "candidate_chain_edge")
        self.assertEqual(item["disposition"], "KEEP")

    def test_candidate_chain_edge_explicit(self):
        item = self._call("x", explicit_type="candidate_chain_edge")
        self.assertEqual(item["normalized_type"], "candidate_chain_edge")

    def test_candidate_fixture(self):
        item = self._call("Fixture: new fixture for the invariant check on withdraw().")
        self.assertEqual(item["normalized_type"], "candidate_fixture")
        self.assertEqual(item["disposition"], "KEEP")

    def test_candidate_fixture_explicit(self):
        item = self._call("x", explicit_type="candidate_fixture")
        self.assertEqual(item["normalized_type"], "candidate_fixture")

    def test_candidate_detector_generalization(self):
        item = self._call("Detector: new detector pattern for missing-reentrancy-guard class.")
        self.assertEqual(item["normalized_type"], "candidate_detector_generalization")
        self.assertEqual(item["disposition"], "KEEP")

    def test_candidate_detector_generalization_explicit(self):
        item = self._call("x", explicit_type="candidate_detector_generalization")
        self.assertEqual(item["normalized_type"], "candidate_detector_generalization")

    def test_verified_source_fact(self):
        item = self._call("file: contracts/Vault.sol\nline: 112\nfunction: _withdraw")
        self.assertEqual(item["normalized_type"], "verified_source_fact_pending_local_check")
        self.assertEqual(item["disposition"], "SOURCE_NEEDED")

    def test_verified_source_fact_explicit(self):
        item = self._call("x", explicit_type="verified_source_fact_pending_local_check")
        self.assertEqual(item["normalized_type"], "verified_source_fact_pending_local_check")


class TestMalformedAndEdgeCases(unittest.TestCase):
    """Malformed/empty input must map to provider_failure."""

    def _call(self, raw_text: str) -> dict:
        return normalize(raw_text=raw_text, **_BASE)

    def test_none_like_empty_string(self):
        item = self._call("")
        self.assertEqual(item["normalized_type"], "provider_failure")

    def test_whitespace_only(self):
        item = self._call("   \n\t\n  ")
        self.assertEqual(item["normalized_type"], "provider_failure")

    def test_http_error_text(self):
        item = self._call('{"reason": "http-401: unauthorized"}')
        self.assertEqual(item["normalized_type"], "provider_failure")

    def test_5xx_error_text(self):
        item = self._call('{"reason": "http-502: bad gateway"}')
        self.assertEqual(item["normalized_type"], "provider_failure")

    def test_transport_error_text(self):
        item = self._call('{"reason": "transport-error: connection refused"}')
        self.assertEqual(item["normalized_type"], "provider_failure")


class TestIdempotentAppend(unittest.TestCase):
    """Appending the same item twice must not produce duplicate lines."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._queue = pathlib.Path(self._tmpdir) / "test_queue.jsonl"

    def _item(self, output_path: str = "/tmp/out.txt") -> dict:
        return normalize(
            raw_text="KILL: no direct path found.",
            output_path=output_path,
            **{k: v for k, v in _BASE.items() if k != "output_path"},
        )

    def test_first_append_returns_true(self):
        item = self._item()
        result = append_to_queue(self._queue, item)
        self.assertTrue(result)

    def test_second_append_returns_false(self):
        item = self._item()
        append_to_queue(self._queue, item)
        result = append_to_queue(self._queue, item)
        self.assertFalse(result)

    def test_no_duplicate_lines_after_double_append(self):
        item = self._item()
        append_to_queue(self._queue, item)
        append_to_queue(self._queue, item)
        lines = [l for l in self._queue.read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)

    def test_different_output_path_is_not_dup(self):
        item_a = self._item("/tmp/out_a.txt")
        item_b = self._item("/tmp/out_b.txt")
        append_to_queue(self._queue, item_a)
        result = append_to_queue(self._queue, item_b)
        # item_b may or may not be dedup'd depending on normalized_type equality
        # but if dedup_keys differ, it MUST be appended
        if item_a["dedup_key"] != item_b["dedup_key"]:
            self.assertTrue(result)
            lines = [l for l in self._queue.read_text().splitlines() if l.strip()]
            self.assertEqual(len(lines), 2)

    def test_queue_file_created_on_first_append(self):
        self.assertFalse(self._queue.exists())
        item = self._item()
        append_to_queue(self._queue, item)
        self.assertTrue(self._queue.exists())

    def test_each_line_is_valid_json(self):
        for i in range(3):
            item = self._item(f"/tmp/out_{i}.txt")
            append_to_queue(self._queue, item)
        lines = [l for l in self._queue.read_text().splitlines() if l.strip()]
        for line in lines:
            obj = json.loads(line)
            self.assertIsInstance(obj, dict)

    def test_appended_item_has_all_required_fields(self):
        item = self._item()
        append_to_queue(self._queue, item)
        lines = [l for l in self._queue.read_text().splitlines() if l.strip()]
        obj = json.loads(lines[0])
        missing = REQUIRED_FIELDS - set(obj.keys())
        self.assertEqual(missing, set(), f"Missing from appended item: {missing}")


class TestCLIRoundTrip(unittest.TestCase):
    """CLI --json flag must produce valid JSON with all required fields."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def _run_cli(self, raw_content: str, **extra_args) -> dict:
        import io
        from unittest.mock import patch

        # Write raw content to a temp file
        raw_file = pathlib.Path(self._tmpdir) / "raw_output.txt"
        raw_file.write_text(raw_content, encoding="utf-8")

        argv = [
            "--provider", "minimax",
            "--model", "MiniMax-M2.7",
            "--task-type", "adversarial-kill",
            "--prompt-path", str(pathlib.Path(self._tmpdir) / "prompt.md"),
            "--output-path", str(raw_file),
            "--raw-file", str(raw_file),
            "--json",
        ]
        for k, v in extra_args.items():
            argv += [f"--{k.replace('_','-')}", str(v)]

        captured = io.StringIO()
        with patch("sys.stdout", captured):
            rc = mod.main(argv)

        self.assertEqual(rc, 0)
        return json.loads(captured.getvalue())

    def test_cli_json_output_has_required_fields(self):
        item = self._run_cli("file: Vault.sol\nline: 42")
        missing = REQUIRED_FIELDS - set(item.keys())
        self.assertEqual(missing, set(), f"CLI missing fields: {missing}")

    def test_cli_empty_input_gives_provider_failure(self):
        item = self._run_cli("")
        self.assertEqual(item["normalized_type"], "provider_failure")

    def test_cli_kill_text_gives_kill_type(self):
        item = self._run_cli("KILL: no direct path to impact found here.")
        self.assertEqual(item["normalized_type"], "kill_reason_pending_local_check")

    def test_cli_explicit_type_override(self):
        # Even though text says "kill:", explicit_type wins
        raw_file = pathlib.Path(self._tmpdir) / "raw2.txt"
        raw_file.write_text("KILL: something", encoding="utf-8")
        argv = [
            "--provider", "kimi",
            "--model", "kimi-for-coding",
            "--task-type", "source-extract",
            "--prompt-path", "/tmp/p.md",
            "--output-path", str(raw_file),
            "--raw-file", str(raw_file),
            "--explicit-type", "candidate_fixture",
            "--json",
        ]
        import io
        from unittest.mock import patch
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            rc = mod.main(argv)
        self.assertEqual(rc, 0)
        item = json.loads(captured.getvalue())
        self.assertEqual(item["normalized_type"], "candidate_fixture")

    def test_cli_append_queue_idempotent(self):
        queue_file = pathlib.Path(self._tmpdir) / "q.jsonl"
        raw_file = pathlib.Path(self._tmpdir) / "raw3.txt"
        raw_file.write_text("file: X.sol line: 10", encoding="utf-8")

        argv = [
            "--provider", "minimax",
            "--model", "MiniMax-M2.7",
            "--task-type", "adversarial-kill",
            "--prompt-path", "/tmp/p.md",
            "--output-path", str(raw_file),
            "--raw-file", str(raw_file),
            "--append-queue", str(queue_file),
        ]
        import io
        from unittest.mock import patch

        # Run twice
        for _ in range(2):
            with patch("sys.stdout", io.StringIO()):
                mod.main(argv)

        lines = [l for l in queue_file.read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1, "Idempotent append must not duplicate")

    def test_cli_token_estimate_explicit(self):
        item = self._run_cli("some text", token_estimate=1234)
        self.assertEqual(item["token_estimate"], 1234)


class TestSchemaFieldPresence(unittest.TestCase):
    """Schema and version fields must always be present and correct."""

    def test_schema_field(self):
        item = normalize(raw_text="x", **_BASE)
        self.assertIn("schema", item)
        self.assertTrue(item["schema"].startswith("auditooor.provider_normalized_work_queue"))

    def test_all_8_types_have_schema(self):
        # All 8 types are covered by TestAllEightTypes; verify the constant here via mod
        for ntype in mod.NORMALIZED_TYPES:
            item = normalize(raw_text="x", explicit_type=ntype, **_BASE)
            self.assertIn("schema", item)
            self.assertEqual(item["normalized_type"], ntype)

    def test_explicit_unknown_type_is_rejected_by_classify(self):
        # Invalid explicit_type falls back to heuristic classification
        # (the CLI --explicit-type is constrained by choices=, but normalize() is permissive)
        item = normalize(raw_text="x", explicit_type="totally_invalid_type", **_BASE)
        # Should still produce a valid type (heuristic fires)
        self.assertIn(item["normalized_type"], NORMALIZED_TYPES)

    def test_local_verification_command_nonempty(self):
        item = normalize(raw_text="x", **_BASE)
        self.assertIsInstance(item["local_verification_command"], str)
        self.assertGreater(len(item["local_verification_command"]), 0)


if __name__ == "__main__":
    unittest.main()
