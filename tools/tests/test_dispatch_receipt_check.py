"""Tests for tools/dispatch-receipt-check.py (B5 dispatch receipt enforcement).

Plan item B5 acceptance: task-dispatch lint and closeout fail High/Critical
worker packets that mention MCP/Hackerman but lack machine-readable receipts.

Test cases (>=7):
  1. No MCP mention at all -> pass with no_mcp_claim
  2. High packet mentioning MCP with no receipt -> FAIL
  3. Critical packet mentioning MCP with complete receipt -> PASS
  4. Packet with partial receipt missing args_hash -> FAIL (high)
  5. Low-severity packet mentioning MCP with no receipt -> WARN not FAIL
  6. Strict mode: High packet lacking receipt -> exit non-zero
  7. JSON output schema field presence
  8. File-not-found -> ERROR verdict (defensive)
  9. Medium packet mentioning vault with receipt missing artifact_path -> WARN (non-high)
  10. Fenced-block receipt (```json {...}```) -> PASS
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-receipt-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("dispatch_receipt_check", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mod = _load_module()

COMPLETE_RECEIPT_JSON = json.dumps({
    "context_pack_id": "auditooor.vault_context_pack.v1:resume:abcdef01",
    "context_pack_hash": "a" * 64,
    "callable": "vault_resume_context",
    "args_hash": "b" * 64,
    "artifact_path": "/tmp/test_artifact.json",
})

PARTIAL_RECEIPT_JSON_NO_ARGS_HASH = json.dumps({
    "context_pack_id": "auditooor.vault_context_pack.v1:resume:abcdef01",
    "context_pack_hash": "a" * 64,
    "callable": "vault_resume_context",
    # args_hash intentionally missing
    "artifact_path": "/tmp/test_artifact.json",
})

PARTIAL_RECEIPT_JSON_NO_ARTIFACT = json.dumps({
    "context_pack_id": "auditooor.vault_context_pack.v1:resume:abcdef01",
    "context_pack_hash": "a" * 64,
    "callable": "vault_resume_context",
    "args_hash": "b" * 64,
    # artifact_path intentionally missing
})


def _make_packet(
    severity: str,
    mcp_mention: bool,
    receipt_json: str = "",
    use_fenced: bool = False,
) -> str:
    """Build a synthetic worker packet string."""
    lines = [
        f"- Severity: `{severity}`",
        "",
        "## Task",
        "Hunt for reentrancy in the swap path.",
        "",
    ]
    if mcp_mention:
        lines += [
            "## MCP Recall",
            "Called vault_resume_context to load exploit context.",
            "Hackerman: yes, loaded hackerman cheat sheet.",
            "",
        ]
    if receipt_json:
        if use_fenced:
            lines += [
                "## MCP Receipt",
                "```json",
                receipt_json,
                "```",
                "",
            ]
        else:
            lines += [
                "## MCP Receipt",
                receipt_json,
                "",
            ]
    lines += [
        "## Acceptance",
        "- File a paste-ready draft at submissions/staging/.",
        "",
        "## Deliverable",
        "`submissions/staging/example-CRITICAL.md`",
    ]
    return "\n".join(lines)


class TestNoMcpMention(unittest.TestCase):
    """Case 1: No MCP mention -> pass with no_mcp_claim."""

    def test_no_mcp_mention_passes(self):
        text = _make_packet("high", mcp_mention=False)
        result = mod.check_packet_text(text, label="test_no_mcp.md", explicit_severity="high")
        self.assertEqual(result.verdict, mod.PASS)
        self.assertFalse(result.has_mcp_mention)
        self.assertIn("no_mcp_claim", result.message)

    def test_no_mcp_mention_low_severity_passes(self):
        text = "This is a low-severity hunt with no vault recalls.\n- Severity: low\n"
        result = mod.check_packet_text(text, label="low_no_mcp.md")
        self.assertEqual(result.verdict, mod.PASS)
        self.assertFalse(result.has_mcp_mention)


class TestHighCriticalMissingReceipt(unittest.TestCase):
    """Case 2: High/Critical packet mentioning MCP with no receipt -> FAIL."""

    def test_high_mcp_no_receipt_fails(self):
        text = _make_packet("high", mcp_mention=True, receipt_json="")
        result = mod.check_packet_text(text, label="high_no_receipt.md")
        self.assertEqual(result.verdict, mod.FAIL)
        self.assertTrue(result.has_mcp_mention)
        self.assertFalse(result.receipt_complete)
        self.assertTrue(result.is_high_critical)

    def test_critical_mcp_no_receipt_fails(self):
        text = _make_packet("critical", mcp_mention=True, receipt_json="")
        result = mod.check_packet_text(text, label="crit_no_receipt.md")
        self.assertEqual(result.verdict, mod.FAIL)
        self.assertTrue(result.is_high_critical)
        self.assertFalse(result.receipt_complete)


class TestCompleteReceiptPasses(unittest.TestCase):
    """Case 3: Critical packet with complete receipt block -> PASS."""

    def test_critical_with_complete_inline_json_receipt_passes(self):
        text = _make_packet("critical", mcp_mention=True, receipt_json=COMPLETE_RECEIPT_JSON)
        result = mod.check_packet_text(text, label="crit_complete.md")
        self.assertEqual(result.verdict, mod.PASS)
        self.assertTrue(result.has_mcp_mention)
        self.assertTrue(result.has_receipt)
        self.assertTrue(result.receipt_complete)
        self.assertEqual(result.missing_fields, [])

    def test_high_with_complete_inline_json_receipt_passes(self):
        text = _make_packet("high", mcp_mention=True, receipt_json=COMPLETE_RECEIPT_JSON)
        result = mod.check_packet_text(text, label="high_complete.md")
        self.assertEqual(result.verdict, mod.PASS)
        self.assertTrue(result.receipt_complete)


class TestPartialReceiptMissingArgsHash(unittest.TestCase):
    """Case 4: Partial receipt missing args_hash -> FAIL for High."""

    def test_high_partial_receipt_missing_args_hash_fails(self):
        text = _make_packet("high", mcp_mention=True, receipt_json=PARTIAL_RECEIPT_JSON_NO_ARGS_HASH)
        result = mod.check_packet_text(text, label="high_partial.md")
        self.assertEqual(result.verdict, mod.FAIL)
        self.assertTrue(result.has_receipt)
        self.assertFalse(result.receipt_complete)
        self.assertIn("args_hash", result.missing_fields)

    def test_critical_partial_receipt_missing_args_hash_fails(self):
        text = _make_packet("critical", mcp_mention=True, receipt_json=PARTIAL_RECEIPT_JSON_NO_ARGS_HASH)
        result = mod.check_packet_text(text, label="crit_partial.md")
        self.assertEqual(result.verdict, mod.FAIL)
        self.assertIn("args_hash", result.missing_fields)


class TestLowSeverityMcpNoReceiptWarns(unittest.TestCase):
    """Case 5: Low-severity packet mentioning MCP with no receipt -> WARN not FAIL."""

    def test_low_mcp_no_receipt_warns(self):
        text = _make_packet("low", mcp_mention=True, receipt_json="")
        result = mod.check_packet_text(text, label="low_no_receipt.md")
        self.assertEqual(result.verdict, mod.WARN)
        self.assertNotEqual(result.verdict, mod.FAIL)
        self.assertTrue(result.has_mcp_mention)
        self.assertFalse(result.is_high_critical)

    def test_medium_mcp_no_receipt_warns(self):
        text = _make_packet("medium", mcp_mention=True, receipt_json="")
        result = mod.check_packet_text(text, label="medium_no_receipt.md")
        self.assertEqual(result.verdict, mod.WARN)
        self.assertFalse(result.is_high_critical)


class TestStrictModeExitNonZero(unittest.TestCase):
    """Case 6: Strict mode - High packet lacking receipt -> exit non-zero."""

    def test_strict_mode_high_no_receipt_exits_one(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            packet_path = Path(tmpdir) / "high_packet.md"
            packet_path.write_text(
                _make_packet("high", mcp_mention=True, receipt_json=""),
                encoding="utf-8",
            )
            exit_code = mod.main([str(packet_path), "--strict"])
            self.assertEqual(exit_code, 1)

    def test_strict_mode_high_complete_receipt_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            packet_path = Path(tmpdir) / "high_complete.md"
            packet_path.write_text(
                _make_packet("high", mcp_mention=True, receipt_json=COMPLETE_RECEIPT_JSON),
                encoding="utf-8",
            )
            exit_code = mod.main([str(packet_path), "--strict"])
            self.assertEqual(exit_code, 0)

    def test_strict_mode_no_mcp_mention_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            packet_path = Path(tmpdir) / "no_mcp.md"
            packet_path.write_text(
                _make_packet("high", mcp_mention=False),
                encoding="utf-8",
            )
            exit_code = mod.main([str(packet_path), "--strict"])
            self.assertEqual(exit_code, 0)


class TestJsonSchemaFieldPresence(unittest.TestCase):
    """Case 7: JSON output has required schema fields."""

    def test_json_schema_fields_present(self):
        results = [mod.check_packet_text(
            _make_packet("high", mcp_mention=True, receipt_json=""),
            label="test.md",
        )]
        report = mod.build_json_report(results)
        # Top-level schema
        self.assertEqual(report["schema"], "auditooor.dispatch_receipt_check.v1")
        # Summary fields
        self.assertIn("summary", report)
        summary = report["summary"]
        for key in ("total", "pass", "warn", "fail", "error", "overall"):
            self.assertIn(key, summary, f"Missing summary key: {key}")
        # Results fields
        self.assertIn("results", report)
        self.assertEqual(len(report["results"]), 1)
        result_row = report["results"][0]
        for key in (
            "file", "verdict", "severity", "is_high_critical",
            "has_mcp_mention", "has_receipt", "receipt_complete",
            "missing_fields", "mcp_mention_sample", "receipt_source", "message",
        ):
            self.assertIn(key, result_row, f"Missing result key: {key}")

    def test_json_flag_outputs_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            packet_path = Path(tmpdir) / "test.md"
            packet_path.write_text(
                _make_packet("critical", mcp_mention=True, receipt_json=""),
                encoding="utf-8",
            )
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                mod.main([str(packet_path), "--json"])
            output = buf.getvalue()
            parsed = json.loads(output)
            self.assertEqual(parsed["schema"], "auditooor.dispatch_receipt_check.v1")
            self.assertIn("results", parsed)


class TestFileNotFound(unittest.TestCase):
    """Case 8: File not found -> ERROR verdict (defensive, no crash)."""

    def test_missing_file_returns_error_verdict(self):
        result = mod.check_packet_file(Path("/nonexistent/path/worker_packet.md"))
        self.assertEqual(result.verdict, mod.ERROR)
        self.assertIn("not found", result.message.lower())

    def test_missing_file_does_not_crash(self):
        # Should return ERROR gracefully without raising exceptions
        try:
            result = mod.check_packet_file(Path("/nonexistent/worker.md"))
        except Exception as exc:
            self.fail(f"check_packet_file raised unexpectedly: {exc}")
        self.assertEqual(result.verdict, mod.ERROR)


class TestFencedBlockReceipt(unittest.TestCase):
    """Case 10: Receipt in fenced code block -> PASS."""

    def test_fenced_json_receipt_passes(self):
        text = _make_packet(
            "critical", mcp_mention=True,
            receipt_json=COMPLETE_RECEIPT_JSON,
            use_fenced=True,
        )
        result = mod.check_packet_text(text, label="fenced_receipt.md")
        self.assertEqual(result.verdict, mod.PASS)
        self.assertTrue(result.receipt_complete)
        self.assertIn("fenced", result.receipt_source)

    def test_fenced_partial_receipt_still_fails_high(self):
        text = _make_packet(
            "high", mcp_mention=True,
            receipt_json=PARTIAL_RECEIPT_JSON_NO_ARTIFACT,
            use_fenced=True,
        )
        result = mod.check_packet_text(text, label="fenced_partial.md")
        self.assertEqual(result.verdict, mod.FAIL)
        self.assertIn("artifact_path", result.missing_fields)


class TestSidecarReceiptFile(unittest.TestCase):
    """Sidecar .receipt.json file next to packet is detected."""

    def test_sidecar_receipt_file_passes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            packet_path = Path(tmpdir) / "high_packet.md"
            packet_path.write_text(
                _make_packet("high", mcp_mention=True, receipt_json=""),
                encoding="utf-8",
            )
            # Write sidecar receipt
            sidecar = Path(tmpdir) / "high_packet.md.receipt.json"
            receipt_data = {
                "context_pack_id": "auditooor.vault_context_pack.v1:resume:test",
                "context_pack_hash": "c" * 64,
                "callable": "vault_resume_context",
                "args_hash": "d" * 64,
                "artifact_path": str(sidecar),
            }
            sidecar.write_text(json.dumps(receipt_data), encoding="utf-8")
            result = mod.check_packet_file(packet_path)
            self.assertEqual(result.verdict, mod.PASS)
            self.assertTrue(result.receipt_complete)


class TestSeverityDetection(unittest.TestCase):
    """Severity detection from packet body works correctly."""

    def test_explicit_severity_override(self):
        text = "vault_resume_context was called.\n- Severity: medium\n"
        result = mod.check_packet_text(text, explicit_severity="high")
        # Should use explicit override
        self.assertEqual(result.severity, "high")
        self.assertTrue(result.is_high_critical)

    def test_json_severity_field_detected(self):
        text = '{"severity": "Critical"}\nvault_resume_context was called.\n'
        result = mod.check_packet_text(text)
        self.assertEqual(result.severity, "critical")
        self.assertTrue(result.is_high_critical)

    def test_unknown_severity_no_mcp_passes(self):
        text = "No severity mentioned and no MCP either.\n"
        result = mod.check_packet_text(text)
        self.assertEqual(result.verdict, mod.PASS)
        self.assertEqual(result.severity, "unknown")


class TestMcpMentionVariants(unittest.TestCase):
    """Various forms of MCP mention are detected."""

    def test_vault_callable_detected(self):
        text = "- Severity: `high`\nCalled vault_exploit_context to get exploit list.\n"
        result = mod.check_packet_text(text)
        self.assertTrue(result.has_mcp_mention)

    def test_hackerman_detected(self):
        text = "- Severity: `high`\nHackerman cheat sheet loaded.\n"
        result = mod.check_packet_text(text)
        self.assertTrue(result.has_mcp_mention)

    def test_mcp_first_detected(self):
        text = "- Severity: `high`\nMCP-first recall block completed.\n"
        result = mod.check_packet_text(text)
        self.assertTrue(result.has_mcp_mention)

    def test_context_pack_id_mention_detected(self):
        # Mentioning context_pack_id in prose (without a full receipt) still flags MCP use
        text = "- Severity: `high`\ncontext_pack_id was recorded from the recall.\n"
        result = mod.check_packet_text(text)
        self.assertTrue(result.has_mcp_mention)
        # But no structured receipt -> FAIL for high
        self.assertEqual(result.verdict, mod.FAIL)


if __name__ == "__main__":
    unittest.main()
