#!/usr/bin/env python3
"""Tests for tools/deep-counterexample-replay-scaffold.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "deep-counterexample-replay-scaffold.py"


def write_impact_contract(ws: Path, *, proven: bool = True) -> None:
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor" / "impact_contracts.json").write_text(
        json.dumps(
            {
                "contracts": [
                    {
                        "impact_contract_id": "impact-contract-vault-loss",
                        "selected_impact": "Direct loss of user funds",
                        "severity": "High",
                        "exact_impact_row": True,
                        "listed_impact_proven": proven,
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )


def record_payload(ws: Path, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "auditooor.deep_counterexample.v1",
        "workspace": str(ws),
        "engine": "halmos",
        "target_function": "Vault.withdraw",
        "expected_invariant": "shares decrease",
        "observed_violation": "shares unchanged",
        "input_sequence": "withdraw(1)",
        "replay_command": "halmos --contract Vault",
        "impact_contract_id": "impact-contract-vault-loss",
    }
    payload.update(overrides)
    return payload


class DeepCounterexampleReplayScaffoldTest(unittest.TestCase):
    def test_generates_skipped_forge_scaffold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_impact_contract(ws)
            record = ws / "deep_counterexamples" / "demo.deep_counterexample.v1.json"
            record.parent.mkdir()
            record.write_text(
                json.dumps(record_payload(ws))
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(record),
                    "--workspace",
                    str(ws),
                    "--print-path",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = Path(proc.stdout.strip())
            text = out.read_text(encoding="utf-8")
            handoff = json.loads((out.with_name(out.name + ".handoff.json")).read_text(encoding="utf-8"))
            self.assertTrue(text.startswith("// SPDX-License-Identifier: MIT"), text[:80])
            self.assertIn("contract DeepCounterexampleReplayScaffold is Test", text)
            self.assertIn("SCAFFOLD ONLY", text)
            self.assertIn("vm.skip(true)", text)
            self.assertIn("withdraw(1)", text)
            self.assertIn("HAS_SYNTHESIZED_CALLS = true", text)
            self.assertIn('abi.encodeWithSignature("withdraw(uint256)"', text)
            self.assertIn("make poc-execution-record", text)
            self.assertEqual(handoff["schema_version"], "auditooor.deep_counterexample_replay_handoff.v1")
            self.assertEqual(handoff["impact_contract"]["impact_contract_id"], "impact-contract-vault-loss")
            self.assertTrue(handoff["has_synthesized_calls"])
            self.assertEqual(handoff["synthesized_call_count"], 1)
            self.assertIn("remaining_tasks", handoff)
            self.assertIn("poc-execution-record", handoff["poc_execution_handoff"])

    def test_synthesizes_multiple_simple_call_steps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_impact_contract(ws)
            record = ws / "deep_counterexamples" / "demo.deep_counterexample.v1.json"
            record.parent.mkdir()
            record.write_text(
                json.dumps(
                    record_payload(
                        ws,
                        engine="medusa",
                        target_function="Vault.sequence",
                        expected_invariant="balance conserved",
                        observed_violation="balance increased",
                        input_sequence="\n".join(
                            [
                                "deposit(100)",
                                "withdraw(0x000000000000000000000000000000000000dEaD, 5, true)",
                            ]
                        ),
                        replay_command="medusa replay",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(record),
                    "--workspace",
                    str(ws),
                    "--print-path",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            text = Path(proc.stdout.strip()).read_text(encoding="utf-8")
            self.assertIn('abi.encodeWithSignature("deposit(uint256)", 100)', text)
            self.assertIn(
                'abi.encodeWithSignature("withdraw(address,uint256,bool)", address(0x000000000000000000000000000000000000dEaD), 5, true)',
                text,
            )
            self.assertIn("require(target != address(0)", text)
            handoff = json.loads((Path(proc.stdout.strip()).with_name(Path(proc.stdout.strip()).name + ".handoff.json")).read_text(encoding="utf-8"))
            self.assertEqual(handoff["synthesized_call_count"], 2)

    def test_synthesizes_numbered_and_foundry_style_trace_steps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_impact_contract(ws)
            record = ws / "deep_counterexamples" / "demo.deep_counterexample.v1.json"
            record.parent.mkdir()
            record.write_text(
                json.dumps(
                    record_payload(
                        ws,
                        target_function="Vault.trace",
                        expected_invariant="debt stays collateralized",
                        observed_violation="debt exceeds collateral",
                        input_sequence="\n".join(
                            [
                                "1) Vault::deposit(100)",
                                "[2] actor: Vault::borrow(0x000000000000000000000000000000000000dEaD, 7)",
                                "\u251c\u2500 Vault::repay(3)",
                            ]
                        ),
                        replay_command="halmos --function check_debt",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(record),
                    "--workspace",
                    str(ws),
                    "--print-path",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = Path(proc.stdout.strip())
            text = out.read_text(encoding="utf-8")
            handoff = json.loads((out.with_name(out.name + ".handoff.json")).read_text(encoding="utf-8"))
            self.assertIn('abi.encodeWithSignature("deposit(uint256)", 100)', text)
            self.assertIn(
                'abi.encodeWithSignature("borrow(address,uint256)", address(0x000000000000000000000000000000000000dEaD), 7)',
                text,
            )
            self.assertIn('abi.encodeWithSignature("repay(uint256)", 3)', text)
            self.assertEqual(handoff["synthesized_call_count"], 3)

    def test_rejects_wrong_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record = Path(tmp) / "bad.json"
            record.write_text('{"schema_version":"other"}\n', encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(record)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("expected schema_version", proc.stderr + proc.stdout)

    def test_missing_impact_contract_blocks_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            record = ws / "deep_counterexamples" / "demo.deep_counterexample.v1.json"
            out = ws / "poc-tests" / "blocked.t.sol"
            record.parent.mkdir()
            record.write_text(
                json.dumps(record_payload(ws, impact_contract_id=""))
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(record),
                    "--workspace",
                    str(ws),
                    "--out",
                    str(out),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("blocked_missing_impact_contract", proc.stderr + proc.stdout)
            self.assertFalse(out.exists())
            self.assertFalse(out.with_name(out.name + ".handoff.json").exists())


if __name__ == "__main__":
    unittest.main()
