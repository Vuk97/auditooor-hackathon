from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "ccia.py"


class CciaSourceRootTest(unittest.TestCase):
    def test_default_src_falls_back_to_external_contracts_src(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            src = ws / "external" / "contracts" / "src"
            src.mkdir(parents=True)
            (src / "Vault.sol").write_text(
                textwrap.dedent(
                    """
                    pragma solidity ^0.8.20;

                    contract Vault {
                        uint256 public total;

                        function deposit() external payable {
                            total += msg.value;
                        }
                    }
                    """
                ).strip()
                + "\n"
            )
            out = ws / "ccia.json"

            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(ws), "--src", "src", "--json", "--out", str(out)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("external/contracts/src", proc.stdout)
            data = json.loads(out.read_text())
            self.assertIn("Vault", data["ccia"]["contracts"])

    def test_hardhat_monorepo_packages_layout_resolves_without_metadata(self) -> None:
        """PR #120 lesson 2 — HH-style external/contracts/packages/<pkg>/contracts/
        layouts must resolve without operator-supplied workspace metadata.
        Regression: The Graph workspace previously deadlocked CCIA + mine-prioritize."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            pkg_a = ws / "external" / "contracts" / "packages" / "horizon" / "contracts"
            pkg_b = ws / "external" / "contracts" / "packages" / "issuance" / "contracts"
            pkg_a.mkdir(parents=True)
            pkg_b.mkdir(parents=True)
            (pkg_a / "Staking.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Staking { uint256 public total; }\n"
            )
            (pkg_b / "Allocator.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Allocator { uint256 public rate; }\n"
            )
            out = ws / "ccia.json"

            # No --src flag, no .auditooor.json. resolve_source_root() must
            # fall through COMMON_SOURCE_ROOTS to `external/contracts/packages`
            # and find_sol_files() recurses into both packages.
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(ws), "--json", "--out", str(out)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            data = json.loads(out.read_text())
            self.assertIn("Staking", data["ccia"]["contracts"])
            self.assertIn("Allocator", data["ccia"]["contracts"])

    def test_single_src_layout_still_wins(self) -> None:
        """Backward-compat: classic <ws>/src/Foo.sol layout must still resolve
        first when present (so single-package workspaces don't regress)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "Wins.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Wins { uint256 public x; }\n"
            )
            # Also create a packages/ tree to make sure src/ wins ordering.
            (ws / "packages" / "alt" / "contracts").mkdir(parents=True)
            (ws / "packages" / "alt" / "contracts" / "Loses.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Loses { uint256 public y; }\n"
            )
            out = ws / "ccia.json"

            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(ws), "--json", "--out", str(out)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn(f"{ws}/src", proc.stdout)
            data = json.loads(out.read_text())
            self.assertIn("Wins", data["ccia"]["contracts"])

    def test_workspace_metadata_source_roots_are_respected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            src = ws / "custom" / "solidity"
            src.mkdir(parents=True)
            (ws / "workspace.json").write_text(json.dumps({"source_roots": ["custom/solidity"]}))
            (src / "Router.sol").write_text(
                textwrap.dedent(
                    """
                    pragma solidity ^0.8.20;

                    contract Router {
                        address public owner;

                        function setOwner(address next) external {
                            owner = next;
                        }
                    }
                    """
                ).strip()
                + "\n"
            )
            out = ws / "ccia.json"

            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(ws), "--json", "--out", str(out)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("custom/solidity", proc.stdout)
            data = json.loads(out.read_text())
            self.assertIn("Router", data["ccia"]["contracts"])


if __name__ == "__main__":
    unittest.main()
