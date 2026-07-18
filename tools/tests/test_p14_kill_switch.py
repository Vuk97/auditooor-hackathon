#!/usr/bin/env python3
"""Lock test for P-14 one_way_kill_switch_no_recovery.

Source: Base-Azul engagement-3 FN-6 (Verifier.sol:39-47). ``bool public
nullified`` has an external ``nullify()`` that only writes ``nullified =
true`` and no ``unNullify() / reset / recover`` path anywhere in the
contract.

Hard-negative: counter-fixture declares ``bool public nullified`` but
also exposes ``function unNullify()`` that writes ``nullified = false``.
The scanner must NOT flag that file.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "one-way-kill-switch-scanner.py"


def _run(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCANNER), str(path), "--json"],
        capture_output=True,
        text=True,
    )


class P14OneWayKillSwitchTests(unittest.TestCase):
    def test_flags_nullified_bool_without_recovery(self) -> None:
        """Verifier.nullified shape — must flag."""
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "Verifier.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract Verifier {
                        bool public nullified;
                        address public owner;

                        constructor() {
                            owner = msg.sender;
                        }

                        function nullify() external {
                            require(msg.sender == owner, "!owner");
                            nullified = true;
                        }

                        function verify(bytes calldata) external view returns (bool) {
                            require(!nullified, "dead");
                            return true;
                        }
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            names = {f["variable"] for f in out["findings"]}
            self.assertIn("nullified", names, out)
            self.assertEqual(
                out["findings"][0]["pattern"],
                "one_way_kill_switch_no_recovery",
            )

    def test_does_not_flag_bool_with_recovery_path(self) -> None:
        """Counter-fixture: unNullify() restores the flag."""
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "Verifier.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract Verifier {
                        bool public nullified;
                        address public owner;

                        constructor() { owner = msg.sender; }

                        function nullify() external {
                            require(msg.sender == owner, "!owner");
                            nullified = true;
                        }

                        function unNullify() external {
                            require(msg.sender == owner, "!owner");
                            nullified = false;
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

    def test_sibling_contract_does_not_suppress(self) -> None:
        """Codex review #1 regression: a sibling contract in the same .sol
        whose name accidentally matches the recovery-function regex (e.g.
        ``OtherAdmin.unNullified()``) MUST NOT suppress a finding on a
        genuinely vulnerable contract (``Verifier.nullified``). Recovery
        detection has to be scoped to the enclosing contract body.
        """
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "Mixed.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract Verifier {
                        bool public nullified;
                        function nullify() external { nullified = true; }
                        function verify() external view { require(!nullified); }
                    }
                    contract OtherAdmin {
                        function unNullified() external {}
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            # Verifier must be flagged; OtherAdmin must NOT be flagged.
            verifier_hits = [
                f for f in out["findings"] if f.get("contract") == "Verifier"
            ]
            other_hits = [
                f for f in out["findings"] if f.get("contract") == "OtherAdmin"
            ]
            self.assertEqual(len(verifier_hits), 1, out)
            self.assertEqual(verifier_hits[0]["variable"], "nullified")
            self.assertEqual(other_hits, [], out)

    def test_hard_negative_bool_never_assigned_true_is_not_flagged(self) -> None:
        """Hard-negative: a bool public declaration never written to true
        (e.g. a view-only getter that other contracts set through a proxy
        not visible in this file) must not produce a finding. This keeps
        the scanner from devolving into 'any bool public is a kill switch'.
        """
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "Config.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract Config {
                        bool public paused;
                        uint256 public maxSupply;

                        function setMaxSupply(uint256 n) external {
                            maxSupply = n;
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
