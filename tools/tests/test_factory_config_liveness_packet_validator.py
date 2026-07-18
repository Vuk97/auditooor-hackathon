"""Tests for factory-config-liveness packet structural validation."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "factory-config-liveness-packet-validator.py"
PACKETS = REPO / "reference" / "dispatch-packets"


def _load_module():
    cache_key = "_test_factory_config_liveness_packet_validator"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    spec = importlib.util.spec_from_file_location(cache_key, TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[cache_key] = module
    spec.loader.exec_module(module)
    return module


class TestFactoryConfigLivenessPacketValidator(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()

    def test_extraction_example_is_structurally_valid(self) -> None:
        packet = PACKETS / "factory-config-liveness-extraction.example.md"
        data = self.mod.load_packet(packet)
        self.assertEqual(
            self.mod.validate_packet(data, "factory-config-liveness-extraction"),
            [],
        )

    def test_kill_example_is_structurally_valid(self) -> None:
        packet = PACKETS / "factory-config-liveness-kill.example.md"
        data = self.mod.load_packet(packet)
        self.assertEqual(
            self.mod.validate_packet(data, "factory-config-liveness-kill"),
            [],
        )

    def test_extraction_invalid_fixture_reports_line_and_shape_errors(self) -> None:
        packet = PACKETS / "factory-config-liveness-extraction.invalid.example.md"
        data = self.mod.load_packet(packet)
        errors = self.mod.validate_packet(data, "factory-config-liveness-extraction")
        joined = "\n".join(errors)
        self.assertIn("target_files[0] must include an exact file:line", joined)
        self.assertIn("missing required field: hypotheses", joined)
        self.assertIn("expected_output_shape missing candidate field: candidate_id", joined)

    def test_kill_invalid_fixture_reports_candidate_and_output_errors(self) -> None:
        packet = PACKETS / "factory-config-liveness-kill.invalid.example.md"
        data = self.mod.load_packet(packet)
        errors = self.mod.validate_packet(data, "factory-config-liveness-kill")
        joined = "\n".join(errors)
        self.assertIn("candidate_list[0].candidate_id must start with FCL-", joined)
        self.assertIn("candidate_list[0].source_files_and_lines[0] must include an exact file:line", joined)
        self.assertIn("truncation_flag must be complete or truncated", joined)
        self.assertIn("expected_output_shape missing kill field: required_next_check", joined)

    def test_cli_json_success_and_failure(self) -> None:
        ok = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--task-type",
                "factory-config-liveness-extraction",
                "--packet",
                str(PACKETS / "factory-config-liveness-extraction.example.md"),
                "--json",
            ],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertTrue(json.loads(ok.stdout)["ok"])

        bad = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--task-type",
                "factory-config-liveness-kill",
                "--packet",
                str(PACKETS / "factory-config-liveness-kill.invalid.example.md"),
                "--json",
            ],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(bad.returncode, 1)
        payload = json.loads(bad.stdout)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["advisory_only"])

    def test_rejects_malformed_yaml_packet(self) -> None:
        with TemporaryDirectory() as tmp:
            packet = Path(tmp) / "bad.md"
            packet.write_text("# Packet\n\nworkspace_path: [unterminated\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--task-type",
                    "factory-config-liveness-extraction",
                    "--packet",
                    str(packet),
                    "--json",
                ],
                check=False,
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("YAML parse failed", "\n".join(json.loads(result.stdout)["errors"]))


if __name__ == "__main__":
    unittest.main()
