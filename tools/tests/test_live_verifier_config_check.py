#!/usr/bin/env python3
"""Tests for tools/live-verifier-config-check.py (PR #546 Lane B).

Stdlib-only. No live RPC calls — the tool emits specs only.

Coverage:
  1. Verifier-shaped target in deployment_topology.json -> spec emitted.
  2. addresses.json fallback -> spec emitted (different source).
  3. Non-verifier targets are filtered out.
  4. EIP-1967 implementation/admin/beacon slots are present.
  5. Cross-validation RPC envs are recorded.
  6. Append semantics: existing rows are preserved.
  7. --strict exits 1 when no targets are found.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-verifier-config-check.py"


def _run(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestLiveVerifierConfigCheck(unittest.TestCase):
    def _make_workspace_topology(self, *, with_verifier: bool = True) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="lvc_ws_"))
        contracts = []
        if with_verifier:
            contracts.append(
                {
                    "contract": "DisputeGameFactory",
                    "status": "resolved",
                    "resolved_address": "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa",
                    "candidate_addresses": ["0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"],
                }
            )
        contracts.append(
            {
                "contract": "ERC20Token",
                "status": "resolved",
                "resolved_address": "0xBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb",
                "candidate_addresses": ["0xBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb"],
            }
        )
        (ws / "deployment_topology.json").write_text(
            json.dumps({"contracts": contracts}), encoding="utf-8"
        )
        return ws

    def test_verifier_target_emits_spec(self):
        ws = self._make_workspace_topology()
        proc = _run(["--workspace", str(ws), "--pinned-block", "0x123"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads((ws / "live_topology_checks.json").read_text())
        self.assertEqual(out["schema"], "auditooor.live_verifier_config_check.v1")
        # Only the verifier-shaped contract becomes a row.
        self.assertEqual(len(out["rows"]), 1)
        row = out["rows"][0]
        self.assertEqual(row["target_name"], "DisputeGameFactory")
        self.assertEqual(row["pinned_block"], "0x123")

    def test_addresses_json_fallback(self):
        ws = Path(tempfile.mkdtemp(prefix="lvc_addr_"))
        (ws / "addresses.json").write_text(
            json.dumps(
                {
                    "AnchorStateRegistry": "0x1111111111111111111111111111111111111111",
                    "RandomToken": "0x2222222222222222222222222222222222222222",
                }
            ),
            encoding="utf-8",
        )
        proc = _run(["--workspace", str(ws)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads((ws / "live_topology_checks.json").read_text())
        names = {row["target_name"] for row in out["rows"]}
        self.assertEqual(names, {"AnchorStateRegistry"})
        self.assertEqual(out["rows"][0]["address_source"], "addresses.json")

    def test_eip1967_slots_present(self):
        ws = self._make_workspace_topology()
        _run(["--workspace", str(ws)])
        out = json.loads((ws / "live_topology_checks.json").read_text())
        check_names = {c["name"] for c in out["rows"][0]["checks"]}
        self.assertEqual(
            check_names,
            {"implementation_slot", "admin_slot", "beacon_slot", "owner_call"},
        )
        # EIP-1967 implementation slot is the canonical hash.
        impl_check = next(
            c for c in out["rows"][0]["checks"] if c["name"] == "implementation_slot"
        )
        self.assertEqual(
            impl_check["slot"],
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        )

    def test_cross_validation_envs(self):
        ws = self._make_workspace_topology()
        _run(
            [
                "--workspace",
                str(ws),
                "--primary-rpc-env",
                "BASE_RPC_URL",
                "--cross-rpc-envs",
                "BASE_RPC_URL_BACKUP",
                "BASE_RPC_URL_QUICKNODE",
            ]
        )
        out = json.loads((ws / "live_topology_checks.json").read_text())
        row = out["rows"][0]
        self.assertEqual(row["primary_rpc_env"], "BASE_RPC_URL")
        self.assertEqual(
            row["cross_validate_rpc_envs"],
            ["BASE_RPC_URL_BACKUP", "BASE_RPC_URL_QUICKNODE"],
        )
        self.assertTrue(row["cross_validation_required"])

    def test_append_preserves_existing(self):
        ws = self._make_workspace_topology()
        # Pre-seed an existing row.
        (ws / "live_topology_checks.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_verifier_config_check.v1",
                    "rows": [
                        {
                            "schema": "auditooor.live_verifier_config_check.v1",
                            "target_address": "0xCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCc",
                            "pinned_block": "0xfeed",
                            "target_name": "Existing",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        _run(["--workspace", str(ws), "--pinned-block", "0xbeef"])
        out = json.loads((ws / "live_topology_checks.json").read_text())
        # Existing pre-seeded row kept + the new one added.
        self.assertEqual(len(out["rows"]), 2)
        names = {row["target_name"] for row in out["rows"]}
        self.assertEqual(names, {"Existing", "DisputeGameFactory"})

    def test_strict_no_targets(self):
        ws = self._make_workspace_topology(with_verifier=False)
        proc = _run(["--workspace", str(ws), "--strict"])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
