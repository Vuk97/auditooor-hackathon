#!/usr/bin/env python3
"""Regression tests for stale immutable hash-preimage scanner."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "stale-immutable-hash-preimage-scanner.py"


def _run(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCANNER), str(path), "--json"],
        capture_output=True,
        text=True,
    )


class StaleImmutableHashPreimageScannerTests(unittest.TestCase):
    def test_flags_verifier_immutable_absent_from_hash_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "AggregateVerifier.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract AggregateVerifier {
                        uint256 public immutable L2_CHAIN_ID;
                        bytes32 public immutable GAME_TYPE;

                        constructor(uint256 chainId, bytes32 gameType) {
                            L2_CHAIN_ID = chainId;
                            GAME_TYPE = gameType;
                        }

                        function verify(bytes memory journal) external view returns (bytes32) {
                            return keccak256(abi.encode(GAME_TYPE, journal));
                        }
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            names = {finding["immutable"] for finding in out["findings"]}
            self.assertIn("L2_CHAIN_ID", names, out)
            self.assertNotIn("GAME_TYPE", names, out)

    def test_does_not_flag_immutable_bound_into_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "AggregateVerifier.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract AggregateVerifier {
                        uint256 public immutable L2_CHAIN_ID;

                        constructor(uint256 chainId) {
                            L2_CHAIN_ID = chainId;
                        }

                        function verify(bytes memory journal) external view returns (bytes32) {
                            return keccak256(abi.encode(L2_CHAIN_ID, journal));
                        }
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["findings"], [], out)


if __name__ == "__main__":
    unittest.main()
