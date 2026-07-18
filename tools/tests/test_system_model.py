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
SM_TOOL = ROOT / "tools" / "system-model.py"
GATE_TOOL = ROOT / "tools" / "system-model-dispatch-gate.py"
FIXTURE_WS = Path(__file__).resolve().parent / "fixtures" / "system_model"


def _load(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SM = _load("system_model", SM_TOOL)
GATE = _load("system_model_dispatch_gate", GATE_TOOL)

_SPEC_SECTIONS = (
    "components",
    "asset_value_flows",
    "trust_boundaries",
    "privileged_roles",
    "external_dependencies",
    "protocol_owned_defenses",
    "claimed_invariants",
    "state_machines",
)


class SystemModelExtractionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.model = SM.build_system_model(FIXTURE_WS)

    def test_schema_and_all_eight_spec_sections_present(self) -> None:
        self.assertEqual(self.model["schema"], "auditooor.system_model.v1")
        for section in _SPEC_SECTIONS:
            self.assertIn(section, self.model, f"missing spec section {section}")

    def test_components_extracted_from_solidity_and_rust(self) -> None:
        paths = {c["path"] for c in self.model["components"]}
        self.assertIn("Vault.sol", paths)
        self.assertIn("pallet/lib.rs", paths)
        langs = {c["language"] for c in self.model["components"]}
        self.assertEqual(langs, {"solidity", "rust"})

    def test_build_artifacts_excluded(self) -> None:
        paths = {c["path"] for c in self.model["components"]}
        self.assertNotIn("out/Compiled.sol", paths)
        for p in paths:
            self.assertNotIn("out/", p)

    def test_roles_extracted(self) -> None:
        roles = {r["role"] for r in self.model["privileged_roles"]}
        # modifier name, *_ROLE constant, and substrate origins all surface
        self.assertTrue(any("Guardian" in r for r in roles))
        self.assertTrue(any("ROLE" in r.upper() for r in roles))

    def test_external_calls_extracted(self) -> None:
        self.assertTrue(self.model["external_dependencies"])
        joined = json.dumps(self.model["external_dependencies"])
        # the `.call{` site in Vault.withdraw is detected
        self.assertIn("call", joined)

    def test_protocol_owned_defenses_extracted(self) -> None:
        families = {d["family"] for d in self.model["protocol_owned_defenses"]}
        # fixture has refund/pause/challenge (sol) + slash/finalize (rust)
        for fam in ("refund", "pause", "challenge", "slash", "finalize"):
            self.assertIn(fam, families, f"defense family {fam} not extracted")

    def test_state_machines_extracted(self) -> None:
        tokens = {s["state_token"] for s in self.model["state_machines"]}
        # enum names + bare Pending/Active/Finalized state words
        self.assertTrue(tokens & {"RequestStatus", "TransferState", "Pending", "Finalized"})

    def test_asset_flows_have_ingress_and_egress(self) -> None:
        flows = self.model["asset_value_flows"]
        self.assertTrue(flows["ingress_signal_paths"])
        self.assertTrue(flows["egress_signal_paths"])

    def test_reasoning_fields_carry_typed_review_placeholder(self) -> None:
        tb = self.model["trust_boundaries"]
        self.assertEqual(tb["status"], "needs_operator_or_agent_review")
        inv = self.model["claimed_invariants"]
        self.assertEqual(inv["status"], "needs_operator_or_agent_review")

    def test_artifact_is_marked_not_proof(self) -> None:
        self.assertFalse(self.model["extraction"]["is_proof"])
        self.assertTrue(self.model["extraction"]["mechanical_only"])


class L3ReadApiTest(unittest.TestCase):
    def test_protocol_owned_defenses_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(
                (FIXTURE_WS / "src" / "Vault.sol").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            # before write: read API returns []
            self.assertEqual(SM.read_protocol_owned_defenses(ws), [])
            rc = SM.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)
            # after write: round-trips the defense families
            defenses = SM.read_protocol_owned_defenses(ws)
            self.assertIn("refund", defenses)
            self.assertIn("pause", defenses)
            self.assertIn("challenge", defenses)
            # de-dup + stable
            self.assertEqual(len(defenses), len(set(defenses)))

    def test_read_api_returns_empty_for_missing_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(SM.read_protocol_owned_defenses(Path(tmp)), [])

    def test_load_system_model_rejects_wrong_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "system_model.json").write_text(
                json.dumps({"schema": "wrong.schema.v9"}), encoding="utf-8"
            )
            self.assertIsNone(SM.load_system_model(ws))


class SystemModelCliTest(unittest.TestCase):
    def test_cli_writes_json_and_md(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(
                (FIXTURE_WS / "src" / "Vault.sol").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(SM_TOOL), "--workspace", str(ws)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((ws / ".auditooor" / "system_model.json").is_file())
            self.assertTrue((ws / ".auditooor" / "system_model.md").is_file())
            md = (ws / ".auditooor" / "system_model.md").read_text(encoding="utf-8")
            self.assertIn("Protocol-Owned Defenses", md)

    def test_no_write_mode_does_not_create_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract X {}", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(SM_TOOL), "--workspace", str(ws), "--no-write", "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse((ws / ".auditooor").exists())


class DispatchGateTest(unittest.TestCase):
    def test_high_packet_without_slice_fails(self) -> None:
        verdict = GATE.evaluate_packet({"packet_id": "p1", "severity": "High"})
        self.assertEqual(verdict["verdict"], "fail")
        self.assertEqual(verdict["code"], "missing_system_model_slice")
        self.assertTrue(verdict["blocked"])

    def test_critical_packet_without_slice_fails(self) -> None:
        verdict = GATE.evaluate_packet({"packet_id": "p2", "severity": "Critical"})
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(verdict["blocked"])

    def test_high_packet_with_inline_slice_passes(self) -> None:
        verdict = GATE.evaluate_packet(
            {
                "packet_id": "p3",
                "severity": "High",
                "system_model_slice": {"protocol_owned_defenses": ["refund", "pause"]},
            }
        )
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["code"], "system_model_slice_present")
        self.assertFalse(verdict["blocked"])

    def test_high_packet_with_artifact_reference_passes(self) -> None:
        verdict = GATE.evaluate_packet(
            {
                "packet_id": "p4",
                "severity": "Critical",
                "source_files": ["src/Vault.sol", ".auditooor/system_model.json"],
            }
        )
        self.assertEqual(verdict["verdict"], "pass")
        self.assertFalse(verdict["blocked"])

    def test_high_packet_with_typed_reason_passes(self) -> None:
        verdict = GATE.evaluate_packet(
            {
                "packet_id": "p5",
                "severity": "High",
                "no_system_model_reason": "NO_SYSTEM_MODEL_REASON: single-file lib audit, no system to model",
            }
        )
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["code"], "typed_no_system_model_reason")
        self.assertFalse(verdict["blocked"])

    def test_bare_reason_without_prefix_does_not_pass(self) -> None:
        verdict = GATE.evaluate_packet(
            {
                "packet_id": "p6",
                "severity": "High",
                "no_system_model_reason": "no model needed",
            }
        )
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(verdict["blocked"])

    def test_empty_slice_does_not_pass(self) -> None:
        verdict = GATE.evaluate_packet(
            {"packet_id": "p7", "severity": "High", "system_model_slice": {}}
        )
        self.assertEqual(verdict["verdict"], "fail")

    def test_medium_packet_not_gated(self) -> None:
        verdict = GATE.evaluate_packet({"packet_id": "p8", "severity": "Medium"})
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["code"], "severity_not_high_critical")
        self.assertFalse(verdict["blocked"])

    def test_low_packet_not_gated(self) -> None:
        verdict = GATE.evaluate_packet({"packet_id": "p9", "severity": "Low"})
        self.assertEqual(verdict["verdict"], "pass")
        self.assertFalse(verdict["blocked"])

    def test_cli_strict_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fail_pkt = Path(tmp) / "fail.json"
            fail_pkt.write_text(json.dumps({"packet_id": "f", "severity": "High"}))
            proc = subprocess.run(
                [sys.executable, str(GATE_TOOL), "--packet", str(fail_pkt), "--strict"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

            pass_pkt = Path(tmp) / "pass.json"
            pass_pkt.write_text(
                json.dumps(
                    {
                        "packet_id": "p",
                        "severity": "High",
                        "system_model_slice": {"components": [{"name": "Vault"}]},
                    }
                )
            )
            proc = subprocess.run(
                [sys.executable, str(GATE_TOOL), "--packet", str(pass_pkt), "--strict"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
