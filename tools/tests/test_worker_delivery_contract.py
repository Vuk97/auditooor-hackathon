#!/usr/bin/env python3
"""Tests for tools/worker-delivery-contract.py (J4 worker-delivery contract)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "worker-delivery-contract.py"


def load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("worker_delivery_contract", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = load_module()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _complete_lesson_pack(context_pack_id: str = "ctx-abc123") -> dict:
    """Return a fully valid lesson pack dict."""
    return {
        "context_pack_id": context_pack_id,
        "context_pack_hash": "a" * 64,
        "selection_keys": {
            "target_domain": "defi-lending",
            "language": "Solidity",
            "function_shape": "unchecked-return",
            "attack_class": "theft",
            "severity_row": "Direct loss of funds",
            "platform_oos": "governance-takeover excluded",
        },
        "case_study_logic": ["Compound finance comptroller reentrancy case 2020"],
        "corpus_analogues": ["record-4419: flash-loan reentrancy in AAVE v2"],
        "hacker_questions": ["Can attacker re-enter before balance update?"],
        "triager_objections": ["Requires whitelist - is this admin-gated?"],
        "economic_viability_questions": ["Is profit > gas cost + flash-loan fee?"],
        "kill_rubrics": ["Drop if admin-only trigger. Drop if OOS by platform rules."],
    }


def _packet(severity: str = "High", lesson_pack: dict | None = None, no_reason: str = "") -> dict:
    """Build a minimal valid-looking worker packet dict."""
    pkt: dict = {
        "schema": "auditooor.v3_worker_packet.v1",
        "severity": severity,
        "packet_id": "test-packet",
        "title": "Test Worker Packet",
    }
    if lesson_pack is not None:
        pkt["lesson_pack"] = lesson_pack
    if no_reason:
        pkt["no_lesson_pack_reason"] = no_reason
    return pkt


def _write_packet(tmp_dir: Path, name: str, packet: dict) -> Path:
    p = tmp_dir / name
    p.write_text(json.dumps(packet, indent=2), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNonHighCriticalPacket(unittest.TestCase):
    """Non-High/Critical packet: lesson pack is advisory, result is warn not fail."""

    def test_low_severity_no_lesson_pack_warns_not_fails(self) -> None:
        pkt = _packet(severity="Low")
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.WARN)
        self.assertFalse(result["is_high_or_critical"])
        # Must NOT be FAIL
        fail_issues = [i for i in result["issues"] if i.get("level") == MOD.FAIL]
        self.assertEqual(fail_issues, [])

    def test_medium_severity_no_lesson_pack_warns_not_fails(self) -> None:
        pkt = _packet(severity="Medium")
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertIn(result["status"], (MOD.WARN, MOD.PASS))
        self.assertFalse(result["is_high_or_critical"])

    def test_low_severity_with_lesson_pack_passes(self) -> None:
        pkt = _packet(severity="Low", lesson_pack=_complete_lesson_pack())
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertIn(result["status"], (MOD.PASS, MOD.WARN))
        fail_issues = [i for i in result["issues"] if i.get("level") == MOD.FAIL]
        self.assertEqual(fail_issues, [])


class TestHighCriticalPacketNoLessonPack(unittest.TestCase):
    """High/Critical packet with no lesson pack and no NO_LESSON_PACK_REASON: must FAIL."""

    def test_high_no_lesson_pack_no_reason_fails(self) -> None:
        pkt = _packet(severity="High")
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.FAIL)
        self.assertTrue(result["is_high_or_critical"])
        codes = {i["code"] for i in result["issues"]}
        self.assertIn("missing_lesson_pack", codes)

    def test_critical_no_lesson_pack_no_reason_fails(self) -> None:
        pkt = _packet(severity="Critical")
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.FAIL)
        self.assertTrue(result["is_high_or_critical"])

    def test_full_tooling_claim_no_lesson_pack_fails(self) -> None:
        """Claims 'full tooling' but no lesson pack - hard fail."""
        pkt = _packet(severity="High")
        pkt["description"] = "This packet uses full tooling and corpus recall."
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.FAIL)
        # Message should mention full tooling
        msgs = " ".join(i.get("message", "") for i in result["issues"])
        self.assertIn("full tooling", msgs.lower())


class TestHighCriticalPacketWithCompleteLessonPack(unittest.TestCase):
    """High/Critical packet with a complete lesson pack: must PASS."""

    def test_high_complete_lesson_pack_passes(self) -> None:
        pkt = _packet(severity="High", lesson_pack=_complete_lesson_pack())
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.PASS)
        fail_issues = [i for i in result["issues"] if i.get("level") == MOD.FAIL]
        self.assertEqual(fail_issues, [])

    def test_critical_complete_lesson_pack_passes(self) -> None:
        pkt = _packet(severity="Critical", lesson_pack=_complete_lesson_pack())
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.PASS)


class TestNoLessonPackReason(unittest.TestCase):
    """High/Critical packet with NO_LESSON_PACK_REASON: must PASS."""

    def test_high_typed_no_reason_passes(self) -> None:
        reason = "NO_LESSON_PACK_REASON: no corpus records match this novel ZK verifier attack class"
        pkt = _packet(severity="High", no_reason=reason)
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.PASS)

    def test_critical_typed_no_reason_passes(self) -> None:
        reason = "NO_LESSON_PACK_REASON: early-stage research, no analogues in corpus yet"
        pkt = _packet(severity="Critical", no_reason=reason)
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.PASS)

    def test_empty_no_reason_prefix_fails(self) -> None:
        """NO_LESSON_PACK_REASON: with no trailing text is NOT a valid exemption."""
        reason = "NO_LESSON_PACK_REASON:"
        pkt = _packet(severity="High", no_reason=reason)
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.FAIL)

    def test_wrong_prefix_fails(self) -> None:
        """Wrong prefix doesn't qualify as a typed reason."""
        reason = "No lesson pack needed here"
        pkt = _packet(severity="High", no_reason=reason)
        result = MOD.check_packet(pkt, source_path="test.json")
        self.assertEqual(result["status"], MOD.FAIL)


class TestMissingOneSectionFails(unittest.TestCase):
    """High/Critical packet missing one required lesson-pack section must FAIL."""

    def _packet_missing_section(self, section: str) -> dict:
        lp = _complete_lesson_pack()
        del lp[section]
        return _packet(severity="High", lesson_pack=lp)

    def test_missing_case_study_logic_fails(self) -> None:
        result = MOD.check_packet(self._packet_missing_section("case_study_logic"))
        self.assertEqual(result["status"], MOD.FAIL)
        codes = {i["code"] for i in result["issues"]}
        self.assertIn("missing_content_sections", codes)

    def test_missing_corpus_analogues_fails(self) -> None:
        result = MOD.check_packet(self._packet_missing_section("corpus_analogues"))
        self.assertEqual(result["status"], MOD.FAIL)

    def test_missing_hacker_questions_fails(self) -> None:
        result = MOD.check_packet(self._packet_missing_section("hacker_questions"))
        self.assertEqual(result["status"], MOD.FAIL)

    def test_missing_triager_objections_fails(self) -> None:
        result = MOD.check_packet(self._packet_missing_section("triager_objections"))
        self.assertEqual(result["status"], MOD.FAIL)

    def test_missing_economic_viability_questions_fails(self) -> None:
        result = MOD.check_packet(self._packet_missing_section("economic_viability_questions"))
        self.assertEqual(result["status"], MOD.FAIL)

    def test_missing_kill_rubrics_fails(self) -> None:
        result = MOD.check_packet(self._packet_missing_section("kill_rubrics"))
        self.assertEqual(result["status"], MOD.FAIL)

    def test_missing_selection_key_fails(self) -> None:
        lp = _complete_lesson_pack()
        del lp["selection_keys"]["attack_class"]
        pkt = _packet(severity="High", lesson_pack=lp)
        result = MOD.check_packet(pkt)
        self.assertEqual(result["status"], MOD.FAIL)
        codes = {i["code"] for i in result["issues"]}
        self.assertIn("missing_selection_keys", codes)

    def test_missing_mcp_context_pack_id_fails(self) -> None:
        lp = _complete_lesson_pack()
        del lp["context_pack_id"]
        pkt = _packet(severity="High", lesson_pack=lp)
        result = MOD.check_packet(pkt)
        self.assertEqual(result["status"], MOD.FAIL)
        codes = {i["code"] for i in result["issues"]}
        self.assertIn("missing_mcp_receipt_fields", codes)

    def test_pending_only_content_section_fails(self) -> None:
        """A section whose only row is 'PENDING' is treated as missing."""
        lp = _complete_lesson_pack()
        lp["kill_rubrics"] = ["PENDING"]
        pkt = _packet(severity="High", lesson_pack=lp)
        result = MOD.check_packet(pkt)
        self.assertEqual(result["status"], MOD.FAIL)


class TestAssembleTemplate(unittest.TestCase):
    """--assemble mode: emits a valid template skeleton."""

    def test_assemble_returns_dict_with_all_sections(self) -> None:
        template = MOD.assemble_template(severity="High")
        self.assertEqual(template["schema"], MOD.SCHEMA)
        self.assertEqual(template["mode"], "template")
        self.assertEqual(template["severity"], "High")
        for section in MOD.REQUIRED_CONTENT_SECTIONS:
            self.assertIn(section, template, f"section {section!r} missing from template")
        for key in MOD.REQUIRED_SELECTION_KEYS:
            self.assertIn(key, template.get("selection_keys", {}),
                          f"selection key {key!r} missing from template")
        for field in MOD.REQUIRED_MCP_FIELDS:
            # Accept at top level or inside mcp_receipt
            in_top = field in template
            in_receipt = field in template.get("mcp_receipt", {})
            self.assertTrue(in_top or in_receipt, f"MCP field {field!r} missing from template")

    def test_assemble_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "lesson_pack_template.json"
            template = MOD.assemble_template(severity="Critical", out=out)
            self.assertTrue(out.is_file())
            written = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(written["severity"], "Critical")
            self.assertIn("template_hash", written)

    def test_assemble_template_has_pending_markers(self) -> None:
        template = MOD.assemble_template(severity="High")
        raw = json.dumps(template)
        self.assertIn("PENDING", raw)

    def test_assemble_cli_mode(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "--assemble", "--severity", "High", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["schema"], MOD.SCHEMA)
        self.assertEqual(data["mode"], "template")


class TestStrictMode(unittest.TestCase):
    """--strict mode: exit non-zero when High/Critical packet fails."""

    def test_strict_exits_nonzero_on_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkt_path = _write_packet(
                Path(tmp), "bad_packet.json",
                _packet(severity="High")  # no lesson pack, no reason
            )
            result = subprocess.run(
                [sys.executable, str(TOOL), str(pkt_path), "--strict"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1, msg=f"expected exit 1, got {result.returncode}\n{result.stdout}")

    def test_strict_exits_zero_on_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkt_path = _write_packet(
                Path(tmp), "good_packet.json",
                _packet(severity="High", lesson_pack=_complete_lesson_pack())
            )
            result = subprocess.run(
                [sys.executable, str(TOOL), str(pkt_path), "--strict"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, msg=f"expected exit 0, got {result.returncode}\n{result.stdout}")

    def test_strict_exits_zero_for_low_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkt_path = _write_packet(
                Path(tmp), "low_packet.json",
                _packet(severity="Low")  # no lesson pack - advisory only
            )
            result = subprocess.run(
                [sys.executable, str(TOOL), str(pkt_path), "--strict"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, msg=f"expected exit 0 for Low severity\n{result.stdout}")


class TestJsonSchemaOutput(unittest.TestCase):
    """--json mode: JSON report has required schema fields."""

    def test_json_report_has_schema_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkt_path = _write_packet(
                Path(tmp), "pkt.json",
                _packet(severity="High", lesson_pack=_complete_lesson_pack())
            )
            result = subprocess.run(
                [sys.executable, str(TOOL), str(pkt_path), "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data["schema"], MOD.SCHEMA)
            self.assertIn("overall_status", data)
            self.assertIn("summary", data)
            self.assertIn("results", data)
            self.assertIsInstance(data["results"], list)
            self.assertGreater(len(data["results"]), 0)

    def test_json_report_fail_schema_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkt_path = _write_packet(
                Path(tmp), "bad.json",
                _packet(severity="Critical")  # no lesson pack, no reason
            )
            result = subprocess.run(
                [sys.executable, str(TOOL), str(pkt_path), "--json"],
                capture_output=True,
                text=True,
            )
            data = json.loads(result.stdout)
            self.assertEqual(data["overall_status"], MOD.FAIL)
            self.assertTrue(data["summary"]["high_or_critical_fail"])
            result_item = data["results"][0]
            self.assertEqual(result_item["status"], MOD.FAIL)
            self.assertIn("issues", result_item)
            self.assertGreater(len(result_item["issues"]), 0)


class TestFileAndDirectoryHandling(unittest.TestCase):
    """Error handling for missing files and directories."""

    def test_missing_file_returns_error(self) -> None:
        results = MOD.check_path(Path("/nonexistent/path/packet.json"))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "error")

    def test_directory_with_packets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _write_packet(tmp_path, "a.json", _packet(severity="High", lesson_pack=_complete_lesson_pack()))
            _write_packet(tmp_path, "b.json", _packet(severity="Low"))
            results = MOD.check_path(tmp_path)
            self.assertEqual(len(results), 2)
            statuses = {r["status"] for r in results}
            # a.json should pass, b.json should warn (advisory)
            self.assertIn(MOD.PASS, statuses)

    def test_empty_directory_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            results = MOD.check_path(Path(tmp))
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "error")

    def test_invalid_json_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not-json{{{{", encoding="utf-8")
            results = MOD.check_path(bad)
            self.assertEqual(results[0]["status"], "error")


class TestLessonPackPersistence(unittest.TestCase):
    """Valid lesson packs are persisted to derived JSONL for MCP consumers."""

    def test_persist_valid_lesson_pack_to_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pkt_path = _write_packet(
                tmp_path,
                "good_packet.json",
                _packet(severity="High", lesson_pack=_complete_lesson_pack()),
            )
            out_dir = tmp_path / "derived"
            result = MOD.persist_valid_lesson_packs(
                pkt_path,
                workspace="/tmp/example-workspace",
                out_dir=out_dir,
            )
            self.assertEqual(result["persisted"], 1)
            outputs = result["outputs"]
            self.assertEqual(len(outputs), 1)
            out_path = Path(outputs[0]["path"])
            self.assertTrue(out_path.is_file())
            rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["schema"], "auditooor.lesson_pack_persistence.v1")
            self.assertEqual(rows[0]["workspace"], "example-workspace")

            again = MOD.persist_valid_lesson_packs(
                pkt_path,
                workspace="/tmp/example-workspace",
                out_dir=out_dir,
            )
            self.assertEqual(again["persisted"], 0)

    def test_invalid_lesson_pack_is_not_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bad_lesson_pack = _complete_lesson_pack()
            del bad_lesson_pack["selection_keys"]["attack_class"]
            pkt_path = _write_packet(
                tmp_path,
                "bad_packet.json",
                _packet(severity="High", lesson_pack=bad_lesson_pack),
            )
            out_dir = tmp_path / "derived"

            result = MOD.persist_valid_lesson_packs(
                pkt_path,
                workspace="/tmp/example-workspace",
                out_dir=out_dir,
            )

            self.assertEqual(result["persisted"], 0)
            self.assertEqual(result["skipped"], 1)
            self.assertFalse(list(out_dir.glob("lesson_pack_*.jsonl")))

    def test_cli_wires_lesson_pack_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pkt_path = _write_packet(
                tmp_path,
                "good_packet.json",
                _packet(severity="High", lesson_pack=_complete_lesson_pack()),
            )
            out_dir = tmp_path / "derived"

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(pkt_path),
                    "--json",
                    "--workspace",
                    "/tmp/example-workspace",
                    "--lesson-pack-out-dir",
                    str(out_dir),
                ],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["lesson_pack_persistence"]["persisted"], 1)
            outputs = report["lesson_pack_persistence"]["outputs"]
            self.assertEqual(len(outputs), 1)
            self.assertTrue(Path(outputs[0]["path"]).is_file())


class TestBuildReport(unittest.TestCase):
    """build_report aggregation."""

    def test_all_pass_gives_pass_overall(self) -> None:
        results = [
            {"status": MOD.PASS, "is_high_or_critical": True, "issues": []},
            {"status": MOD.PASS, "is_high_or_critical": False, "issues": []},
        ]
        report = MOD.build_report(results)
        self.assertEqual(report["overall_status"], MOD.PASS)
        self.assertFalse(report["summary"]["high_or_critical_fail"])

    def test_any_hc_fail_gives_fail_overall(self) -> None:
        results = [
            {"status": MOD.FAIL, "is_high_or_critical": True, "issues": [{"code": "x", "level": MOD.FAIL, "message": ""}]},
            {"status": MOD.PASS, "is_high_or_critical": False, "issues": []},
        ]
        report = MOD.build_report(results)
        self.assertEqual(report["overall_status"], MOD.FAIL)
        self.assertTrue(report["summary"]["high_or_critical_fail"])

    def test_warn_only_gives_warn_overall(self) -> None:
        results = [
            {"status": MOD.WARN, "is_high_or_critical": False, "issues": [{"code": "x", "level": MOD.WARN, "message": ""}]},
        ]
        report = MOD.build_report(results)
        self.assertEqual(report["overall_status"], MOD.WARN)
        self.assertFalse(report["summary"]["high_or_critical_fail"])


if __name__ == "__main__":
    unittest.main()
