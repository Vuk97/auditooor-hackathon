"""Tests for tools/fork-pinned-witness.py (auditooor.fork_pinned_witness.v1).

Covers:
1. Empty workspace (no exploit_queue) - degraded or no_proved_high_critical_rows
2. Proved High/Critical row with no witness - check mode flags it as missing_artifact
3. Proved High/Critical row with complete witness - passes
4. Strict mode exits non-zero when a proved row lacks a complete witness
5. EVM vs Cosmos/Solana witness equivalence (non_evm_proof_manifest accepted)
6. --scaffold template emission (template_unfilled=true, all required fields present)
7. JSON schema field presence in scaffold output
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "fork-pinned-witness.py"
SCHEMA = "auditooor.fork_pinned_witness.v1"


def _import_tool():
    spec = importlib.util.spec_from_file_location("fork_pinned_witness_test", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _proved_high_row(lead_id: str = "EQ-001") -> dict[str, object]:
    return {
        "lead_id": lead_id,
        "title": "Unauthorized withdrawal via reentrancy",
        "attack_class": "reentrancy",
        "likely_severity": "High",
        "proof_status": "proved",
        "blockers": [],
    }


def _proved_critical_row(lead_id: str = "EQ-002") -> dict[str, object]:
    return {
        "lead_id": lead_id,
        "title": "Direct fund drain",
        "attack_class": "access-control",
        "likely_severity": "Critical",
        "proof_status": "proved",
        "blockers": [],
    }


def _proved_cosmos_row(lead_id: str = "EQ-003") -> dict[str, object]:
    return {
        "lead_id": lead_id,
        "title": "Cosmos bank module overflow",
        "attack_class": "integer-overflow",
        "likely_severity": "High",
        "proof_status": "proved",
        "chain_type": "cosmos",
        "blockers": [],
    }


def _complete_evm_witness(row_id: str = "EQ-001") -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "row_id": row_id,
        "chain_type": "evm",
        "pinned_state": {
            "rpc_url": "https://mainnet.infura.io/v3/abc123",
            "block_number": 19500000,
        },
        "replay_command": "forge test --match-test testExploit --fork-url $RPC --fork-block-number 19500000 -vvv",
        "attacker_setup": "Attacker at 0xBEEF, funded with 1 ETH",
        "call_trace": "0xDEAD.attack() -> 0xVAULT.withdraw() -> 0xDEAD.receive() -> re-enter",
        "state_diff": {
            "before": "vault.balance = 100 ETH",
            "after": "vault.balance = 0 ETH",
        },
        "balance_deltas": "attacker: +99 ETH, vault: -100 ETH, gas: -1 ETH",
        "capital_accounting": {
            "gas_cost_gwei": "500000",
            "attacker_capital_required": "0.1 ETH",
            "attacker_profit": "99.9 ETH",
        },
        "negative_control": "forge test --match-test testExploitNoReentry: vault balance unchanged",
    }


def _complete_cosmos_witness(row_id: str = "EQ-003") -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "row_id": row_id,
        "chain_type": "cosmos",
        "non_evm_proof_manifest": {
            "chain_type": "cosmos",
            "snapshot_path": "/tmp/cosmos-snapshot/genesis.json",
            "replay_command": "go test ./poc/... -run TestBankOverflow -v",
        },
        "pinned_state": {
            "description": "Cosmos chain block 100000, audit-pin abc123",
            "snapshot_path": "/tmp/cosmos-snapshot/genesis.json",
            "block_number": "100000",
        },
        "replay_command": "go test ./poc/... -run TestBankOverflow -v",
        "attacker_setup": "Attacker account cosmos1attacker, 1000000uatom",
        "call_trace": "MsgSend -> bank.SendCoins -> overflow at uint64 boundary",
        "state_diff": {
            "before": "attacker: 1000000uatom, victim: 1000000uatom",
            "after": "attacker: 2000001uatom, victim: 0uatom",
        },
        "balance_deltas": "attacker: +1000001uatom, victim: -1000000uatom",
        "capital_accounting": {
            "fee_cost": "2000uatom",
            "attacker_capital_required": "1000000uatom",
            "attacker_profit": "1000001uatom",
        },
        "negative_control": "go test ./poc/... -run TestBankNormal: no overflow, balances correct",
    }


def _witness_path(ws: Path, row_id: str) -> Path:
    return ws / "witness_bundles" / row_id / "witness.json"


def _transcript_path(ws: Path, row_id: str) -> Path:
    return ws / "witness_bundles" / row_id / "replay_transcript.txt"


class TestForkPinnedWitness(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _import_tool()

    # ------------------------------------------------------------------
    # Case 1: Empty workspace (no exploit_queue)
    # ------------------------------------------------------------------
    def test_missing_workspace_returns_degraded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-missing-") as tmp:
            ws = Path(tmp) / "nonexistent-ws"
            payload = self.mod.build_check_payload(ws)

        self.assertEqual(payload["schema"], SCHEMA)
        self.assertTrue(payload["degraded"])
        self.assertEqual(payload["degraded_reason"], "workspace_missing")
        self.assertEqual(payload["rows"], [])
        self.assertTrue(payload["all_covered"])
        self.assertFalse(payload["strict_fail"])

    def test_empty_workspace_no_queue_no_proved_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-empty-") as tmp:
            ws = Path(tmp)
            # Workspace exists but has no .auditooor/exploit_queue.json
            payload = self.mod.build_check_payload(ws)

        self.assertFalse(payload["degraded"])
        self.assertTrue(payload.get("no_proved_high_critical_rows"))
        self.assertEqual(payload["rows"], [])
        self.assertTrue(payload["all_covered"])

    # ------------------------------------------------------------------
    # Case 2: Proved High/Critical row with no witness - must be flagged
    # ------------------------------------------------------------------
    def test_proved_high_row_missing_witness_flagged(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-missing-witness-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)
            _write_json(adir / "exploit_queue.json", [_proved_high_row("EQ-001")])

            payload = self.mod.build_check_payload(ws)

        self.assertFalse(payload["degraded"])
        self.assertFalse(payload.get("no_proved_high_critical_rows"))
        self.assertEqual(len(payload["rows"]), 1)
        row = payload["rows"][0]
        self.assertEqual(row["row_id"], "EQ-001")
        self.assertEqual(row["verdict"], "missing_artifact")
        self.assertFalse(payload["all_covered"])
        self.assertEqual(payload["summary"]["missing_witness"], 1)
        self.assertEqual(payload["summary"]["covered"], 0)

    # ------------------------------------------------------------------
    # Case 3: Proved High/Critical row with complete witness - passes
    # ------------------------------------------------------------------
    def test_proved_high_row_with_complete_witness_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-complete-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)
            _write_json(adir / "exploit_queue.json", [_proved_high_row("EQ-001")])

            wp = _witness_path(ws, "EQ-001")
            _write_json(wp, _complete_evm_witness("EQ-001"))

            tp = _transcript_path(ws, "EQ-001")
            tp.parent.mkdir(parents=True, exist_ok=True)
            tp.write_text("forge test output...\n[PASS] testExploit\n", encoding="utf-8")

            payload = self.mod.build_check_payload(ws)

        self.assertFalse(payload["degraded"])
        self.assertEqual(len(payload["rows"]), 1)
        row = payload["rows"][0]
        self.assertEqual(row["verdict"], "pass")
        self.assertTrue(payload["all_covered"])
        self.assertEqual(payload["summary"]["covered"], 1)
        self.assertEqual(payload["summary"]["missing_witness"], 0)

    # ------------------------------------------------------------------
    # Case 4: Strict mode exits non-zero when proved row lacks witness
    # ------------------------------------------------------------------
    def test_strict_mode_sets_strict_fail_when_witness_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-strict-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)
            _write_json(adir / "exploit_queue.json", [_proved_critical_row("EQ-002")])

            payload = self.mod.build_check_payload(ws, strict=True)

        self.assertTrue(payload["strict_fail"])
        self.assertFalse(payload["all_covered"])

    def test_strict_mode_does_not_fail_when_all_witnesses_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-strict-ok-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)
            _write_json(adir / "exploit_queue.json", [_proved_critical_row("EQ-002")])

            wp = _witness_path(ws, "EQ-002")
            _write_json(wp, _complete_evm_witness("EQ-002"))
            tp = _transcript_path(ws, "EQ-002")
            tp.parent.mkdir(parents=True, exist_ok=True)
            tp.write_text("run output\n", encoding="utf-8")

            payload = self.mod.build_check_payload(ws, strict=True)

        self.assertFalse(payload["strict_fail"])
        self.assertTrue(payload["all_covered"])

    # ------------------------------------------------------------------
    # Case 5: EVM vs Cosmos/Solana witness equivalence
    # ------------------------------------------------------------------
    def test_cosmos_row_accepts_non_evm_proof_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-cosmos-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)
            _write_json(adir / "exploit_queue.json", [_proved_cosmos_row("EQ-003")])

            wp = _witness_path(ws, "EQ-003")
            _write_json(wp, _complete_cosmos_witness("EQ-003"))
            tp = _transcript_path(ws, "EQ-003")
            tp.parent.mkdir(parents=True, exist_ok=True)
            tp.write_text("go test output\n--- PASS: TestBankOverflow\n", encoding="utf-8")

            payload = self.mod.build_check_payload(ws)

        self.assertEqual(len(payload["rows"]), 1)
        row = payload["rows"][0]
        self.assertTrue(row["non_evm"])
        self.assertEqual(row["verdict"], "pass")

    def test_cosmos_row_without_non_evm_manifest_is_flagged(self) -> None:
        """A Cosmos row with no non_evm_proof_manifest and placeholder pinned_state fails."""
        with tempfile.TemporaryDirectory(prefix="fpw-cosmos-fail-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)
            _write_json(adir / "exploit_queue.json", [_proved_cosmos_row("EQ-003")])

            # Witness missing non_evm_proof_manifest entirely
            incomplete = _complete_cosmos_witness("EQ-003")
            del incomplete["non_evm_proof_manifest"]
            incomplete["pinned_state"] = {"description": "PENDING", "snapshot_path": "TODO", "block_number": "TODO"}
            wp = _witness_path(ws, "EQ-003")
            _write_json(wp, incomplete)
            tp = _transcript_path(ws, "EQ-003")
            tp.parent.mkdir(parents=True, exist_ok=True)
            tp.write_text("output\n", encoding="utf-8")

            payload = self.mod.build_check_payload(ws)

        row = payload["rows"][0]
        self.assertNotEqual(row["verdict"], "pass")
        self.assertTrue(len(row["missing_fields"]) > 0)

    # ------------------------------------------------------------------
    # Case 6: --scaffold emits template_unfilled=True with all required fields
    # ------------------------------------------------------------------
    def test_scaffold_emits_template_with_all_required_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-scaffold-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)

            template = self.mod.scaffold_witness(ws, "EQ-NEW", non_evm=False)

        self.assertTrue(template.get("template_unfilled"))
        for field in self.mod.REQUIRED_FIELDS:
            self.assertIn(field, template, f"scaffold missing field: {field}")

    def test_scaffold_non_evm_emits_non_evm_proof_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-scaffold-nonevm-") as tmp:
            ws = Path(tmp)
            template = self.mod.scaffold_witness(ws, "EQ-COSMOS", non_evm=True)

        self.assertTrue(template.get("template_unfilled"))
        self.assertIn("non_evm_proof_manifest", template)
        manifest = template["non_evm_proof_manifest"]
        for sub in ("chain_type", "snapshot_path", "replay_command"):
            self.assertIn(sub, manifest, f"scaffold non_evm_proof_manifest missing: {sub}")

    def test_scaffold_file_written_to_witness_bundles_dir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-scaffold-file-") as tmp:
            ws = Path(tmp)
            self.mod.scaffold_witness(ws, "EQ-SCAFFOLD")
            wp = ws / "witness_bundles" / "EQ-SCAFFOLD" / "witness.json"
            self.assertTrue(wp.exists())
            raw = json.loads(wp.read_text())
            self.assertTrue(raw.get("template_unfilled"))

    # ------------------------------------------------------------------
    # Case 7: JSON schema field presence in payload
    # ------------------------------------------------------------------
    def test_check_payload_has_required_schema_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpw-schema-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)
            _write_json(adir / "exploit_queue.json", [_proved_high_row("EQ-001")])

            payload = self.mod.build_check_payload(ws)

        required_top_keys = [
            "schema", "workspace", "degraded", "rows",
            "all_covered", "strict_fail", "summary",
        ]
        for key in required_top_keys:
            self.assertIn(key, payload, f"payload missing key: {key}")

        self.assertEqual(payload["schema"], SCHEMA)

        summary = payload["summary"]
        for sk in ("proved_high_critical", "covered", "missing_witness"):
            self.assertIn(sk, summary, f"summary missing key: {sk}")

    def test_template_unfilled_witness_is_not_accepted_as_complete(self) -> None:
        """A scaffold template (template_unfilled=true) must NOT count as a complete witness."""
        with tempfile.TemporaryDirectory(prefix="fpw-template-check-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)
            _write_json(adir / "exploit_queue.json", [_proved_high_row("EQ-001")])

            # Write a template (unfilled) as the witness
            template = self.mod.scaffold_witness(ws, "EQ-001", non_evm=False)
            # Ensure template_unfilled is set
            self.assertTrue(template.get("template_unfilled"))

            # Write transcript so only witness quality matters
            tp = _transcript_path(ws, "EQ-001")
            tp.parent.mkdir(parents=True, exist_ok=True)
            tp.write_text("output\n", encoding="utf-8")

            payload = self.mod.build_check_payload(ws)

        row = payload["rows"][0]
        # A template_unfilled witness should be flagged as incomplete, not pass
        self.assertNotEqual(row["verdict"], "pass")

    def test_medium_severity_proved_row_is_not_checked(self) -> None:
        """Only High/Critical proved rows are checked. Medium is out of scope."""
        with tempfile.TemporaryDirectory(prefix="fpw-medium-") as tmp:
            ws = Path(tmp)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True)
            medium_row = {
                "lead_id": "EQ-MED",
                "title": "Medium severity finding",
                "attack_class": "griefing",
                "likely_severity": "Medium",
                "proof_status": "proved",
            }
            _write_json(adir / "exploit_queue.json", [medium_row])

            payload = self.mod.build_check_payload(ws)

        self.assertTrue(payload.get("no_proved_high_critical_rows"))
        self.assertEqual(payload["rows"], [])


if __name__ == "__main__":
    unittest.main()
