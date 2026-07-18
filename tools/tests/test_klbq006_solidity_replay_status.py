from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "klbq006-solidity-replay-status.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("klbq006_solidity_replay_status", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


MOD = _load_module()


class Klbq006SolidityReplayStatusTest(unittest.TestCase):
    def test_consumes_terminal_boundary_commands_and_stays_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "re-nft-smart-contracts"
            repo.mkdir()
            self.assertEqual(_git(repo, "init").returncode, 0)
            self.assertEqual(_git(repo, "config", "user.email", "tests@example.com").returncode, 0)
            self.assertEqual(_git(repo, "config", "user.name", "Tests").returncode, 0)

            _write(
                repo / "src" / "policies" / "Guard.sol",
                "\n".join(
                    [
                        "contract Guard {",
                        "  function _checkTransaction(address from, address to, bytes memory data) private view {",
                        "    bytes4 selector;",
                        "    if (selector == gnosis_safe_set_guard_selector) {",
                        "      revert Errors.GuardPolicy_UnauthorizedSelector(selector);",
                        "    }",
                        "  }",
                        "  function checkTransaction() external {}",
                        "}",
                    ]
                )
                + "\n",
            )
            _write(
                repo / "src" / "policies" / "Factory.sol",
                "contract Factory { address fallbackHandler; function setup() external {} }\n",
            )
            _write(
                repo / "src" / "libraries" / "RentalConstants.sol",
                "bytes4 constant gnosis_safe_set_guard_selector = 0xe19a9dd9;\n",
            )
            _write(
                repo / "test" / "unit" / "Guard" / "CheckTransaction.t.sol",
                "contract GuardCheckTransactionTest { function test_OtherSelector() public {} }\n",
            )
            self.assertEqual(_git(repo, "add", ".").returncode, 0)
            self.assertEqual(_git(repo, "commit", "-m", "initial vulnerable snapshot").returncode, 0)
            pinned_ref = _git(repo, "rev-parse", "HEAD").stdout.strip()

            _write(
                repo / "src" / "policies" / "Guard.sol",
                "\n".join(
                    [
                        "contract Guard {",
                        "  function _checkTransaction(address from, address to, bytes memory data) private view {",
                        "    bytes4 selector;",
                        "    if (selector == gnosis_safe_set_fallback_handler_selector) {",
                        "      revert Errors.GuardPolicy_UnauthorizedSelector(gnosis_safe_set_fallback_handler_selector);",
                        "    }",
                        "  }",
                        "  function checkTransaction() external {}",
                        "}",
                    ]
                )
                + "\n",
            )
            _write(
                repo / "src" / "libraries" / "RentalConstants.sol",
                "\n".join(
                    [
                        "// bytes4(keccak256(\"setFallbackHandler(address)\"))",
                        "bytes4 constant gnosis_safe_set_fallback_handler_selector = 0xf08a0323;",
                    ]
                )
                + "\n",
            )
            _write(
                repo / "test" / "unit" / "Guard" / "CheckTransaction.t.sol",
                "\n".join(
                    [
                        "contract GuardCheckTransactionTest {",
                        "  function test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler() public {}",
                        "}",
                    ]
                )
                + "\n",
            )
            _write(
                repo / "test" / "integration" / "prevented-exploits" / "SetCustomFallbackHandler.t.sol",
                "contract SetCustomFallbackHandlerTest {}\n",
            )
            self.assertEqual(_git(repo, "add", ".").returncode, 0)
            self.assertEqual(_git(repo, "commit", "-m", "fixed head anchor").returncode, 0)

            with tempfile.TemporaryDirectory() as ws:
                root = Path(ws)
                reports = root / "reports"
                reports.mkdir()
                boundary_path = reports / "klbq_006_terminal_boundary_2026-05-05.json"
                anchors_path = reports / "klbq_006_real_source_anchors_2026-05-05.json"
                _write_json(
                    boundary_path,
                    {
                        "schema": "auditooor.klbq_006_terminal_boundary.v1",
                        "limitation_id": "KLBQ-006",
                        "finding_id": "30522",
                        "source_root": str(repo),
                        "pinned_ref": pinned_ref,
                        "exact_next_commands": [
                            "python3 tools/klbq006-terminal-boundary.py --renft-root /tmp/re-nft",
                            f"git -C {repo} show --no-patch --format='%H %cI %s' {pinned_ref}",
                            (
                                f"git -C {repo} grep -n "
                                "\"setFallbackHandler\\|fallbackHandler\\|checkTransaction\\|f08a0323\" "
                                f"{pinned_ref} -- \"*.sol\""
                            ),
                            (
                                f"git -C {repo} grep -n "
                                "\"setFallbackHandler\\|fallbackHandler\\|checkTransaction\\|f08a0323\" "
                                "HEAD -- \"*.sol\""
                            ),
                            f"python3 tools/rust-detect.py {repo} --only r94_loop_safe_fallback_handler_setter_missing_address_guard --log /tmp/klbq006_r94.log",
                            f"python3 tools/rust-detect.py {repo} --only setfallbackhandler_bypass_hijacks_rented_erc721_1155 --log /tmp/klbq006_sibling.log",
                            f"forge test --root {repo} --match-path test/unit/Guard/CheckTransaction.t.sol --match-test test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler -vvv",
                        ],
                    },
                )
                _write_json(
                    anchors_path,
                    {
                        "finding_id": "30522",
                        "classification": {
                            "exact_finding_github_blob_anchors": "absent",
                            "exact_renft_source_root": "present",
                            "real_source_anchors": "present",
                        },
                    },
                )

                report = MOD.build_report(boundary_path=boundary_path, anchors_path=anchors_path)

        self.assertEqual(report["status"], "source_aware_replay_commands_consumed_fail_closed")
        self.assertFalse(report["verification_claim_allowed"])
        self.assertFalse(report["promotion_ready"])
        self.assertTrue(report["replay_gate"]["fail_closed"])
        self.assertTrue(report["citation_status"]["exact_citation_absent"])
        self.assertFalse(report["replay_gate"]["executable_foundry_proof_present"])
        self.assertEqual(
            report["source_aware_pinned_probe"]["classification"],
            "source_aware_guard_boundary_missing_direct_setfallbackhandler_revert",
        )
        records = report["command_consumption"]["commands"]
        self.assertEqual(records[0]["status"], "imported_from_terminal_boundary")
        self.assertEqual(records[1]["status"], "passed")
        self.assertEqual(records[2]["status"], "passed")
        self.assertEqual(records[3]["status"], "passed")
        self.assertEqual(records[4]["status"], "imported_from_terminal_boundary")
        self.assertEqual(records[5]["status"], "imported_from_terminal_boundary")
        self.assertEqual(records[6]["status"], "not_executed_fail_closed")
        self.assertIn("HEAD anchor test", records[6]["note"])
        self.assertTrue(any("citation is still absent" in blocker for blocker in report["remaining_blockers"]))
        self.assertEqual(
            report["source_citation_acquisition"]["state"],
            "blocked_pending_exact_30522_source_citation",
        )
        self.assertIn(str(repo), report["source_citation_acquisition"]["exact_next_commands"][0])
        self.assertEqual(
            report["exact_next_command"],
            report["source_citation_acquisition"]["exact_next_commands"][0],
        )
        self.assertEqual(
            report["exact_proof_command"],
            f"forge test --root {repo} --match-path test/unit/Guard/CheckTransaction.t.sol --match-test test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler -vvv",
        )

    def test_execute_foundry_records_dependency_blocker_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            missing_repo = root / "re-nft-smart-contracts"
            (missing_repo / "lib" / "forge-std").mkdir(parents=True)
            _write(
                missing_repo / ".gitmodules",
                "\n".join(
                    [
                        '[submodule "lib/forge-std"]',
                        "\tpath = lib/forge-std",
                        "\turl = https://github.com/foundry-rs/forge-std",
                    ]
                )
                + "\n",
            )
            boundary_path = root / "reports" / "klbq_006_terminal_boundary_2026-05-05.json"
            anchors_path = root / "reports" / "klbq_006_real_source_anchors_2026-05-05.json"
            command = (
                f"forge test --root {missing_repo} "
                "--match-path test/unit/Guard/CheckTransaction.t.sol "
                "--match-test test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler -vvv"
            )
            _write_json(
                boundary_path,
                {
                    "schema": "auditooor.klbq_006_terminal_boundary.v1",
                    "limitation_id": "KLBQ-006",
                    "finding_id": "30522",
                    "source_root": str(missing_repo),
                    "pinned_ref": "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291",
                    "exact_next_commands": [command],
                },
            )
            _write_json(
                anchors_path,
                {
                    "finding_id": "30522",
                    "classification": {
                        "exact_finding_github_blob_anchors": "absent",
                        "exact_renft_source_root": "present",
                        "real_source_anchors": "present",
                    },
                },
            )

            forge_failure = subprocess.CompletedProcess(
                args=command.split(),
                returncode=1,
                stdout=(
                    "Missing dependencies found. Installing now...\n"
                    "Cloning into '/tmp/re-nft/lib/Solady'...\n"
                    "fatal: unable to access 'https://github.com/Vectorized/Solady/': "
                    "Could not resolve host: github.com\n"
                ),
                stderr=(
                    '2026-05-05T22:59:19Z ERROR foundry_compilers_artifacts_solc::sources: '
                    'error="/tmp/re-nft/lib/forge-std/src/Test.sol": No such file or directory (os error 2)\n'
                    'ParserError: Source "lib/safe-contracts/contracts/common/Enum.sol" not found: File not found.\n'
                ),
            )
            with mock.patch.object(MOD.shutil, "which", return_value="/usr/local/bin/forge"):
                with mock.patch.object(MOD, "_run_argv", return_value=forge_failure):
                    report = MOD.build_report(
                        boundary_path=boundary_path,
                        anchors_path=anchors_path,
                        execute_foundry=True,
                    )

        record = report["command_consumption"]["commands"][0]
        blocker = record["execution_blocker"]
        self.assertEqual(record["status"], "foundry_dependency_blocked_fail_closed")
        self.assertTrue(record["executed"])
        self.assertTrue(blocker["dependency_install_attempted"])
        self.assertTrue(blocker["network_resolution_failure"])
        self.assertEqual(blocker["missing_import_count"], 1)
        self.assertEqual(blocker["missing_source_file_count"], 1)
        self.assertEqual(blocker["unblock_command"], f"git -C {missing_repo} submodule update --init --recursive")
        self.assertEqual(blocker["rerun_exact_proof_command"], command)
        self.assertTrue(report["replay_gate"]["fail_closed"])
        self.assertTrue(report["replay_gate"]["foundry_anchor_test_executed"])
        self.assertTrue(report["replay_gate"]["foundry_execution_blocked"])
        self.assertFalse(report["replay_gate"]["executable_foundry_proof_present"])
        dependency_unblock = report["foundry_dependency_unblock"]
        self.assertEqual(dependency_unblock["state"], "blocked_uninitialized_or_empty_submodules")
        self.assertEqual(dependency_unblock["declared_submodule_count"], 1)
        self.assertEqual(dependency_unblock["uninitialized_or_empty_submodule_count"], 1)
        self.assertTrue(dependency_unblock["network_resolution_failure_observed"])
        self.assertTrue(dependency_unblock["offline_fallback_requires_exact_submodule_commits"])
        self.assertIn(
            f"git -C {missing_repo.resolve()} submodule status --recursive",
            dependency_unblock["offline_fallback_commands"],
        )
        self.assertEqual(
            report["exact_next_command"],
            report["source_citation_acquisition"]["exact_next_commands"][0],
        )
        self.assertEqual(
            report["dependency_next_command"],
            dependency_unblock["network_unblock_command"],
        )
        self.assertEqual(report["exact_proof_command"], command)
        self.assertTrue(any("did not reach proof execution" in blocker_text for blocker_text in report["remaining_blockers"]))
        self.assertTrue(any("dependency unblock path is still blocked" in blocker_text for blocker_text in report["remaining_blockers"]))

    def test_exact_citation_present_allows_proof_command_as_next_action(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            repo = root / "re-nft-smart-contracts"
            repo.mkdir()
            boundary_path = root / "reports" / "klbq_006_terminal_boundary_2026-05-05.json"
            anchors_path = root / "reports" / "klbq_006_real_source_anchors_2026-05-05.json"
            command = (
                f"forge test --root {repo} "
                "--match-path test/unit/Guard/CheckTransaction.t.sol "
                "--match-test test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler -vvv"
            )
            _write_json(
                boundary_path,
                {
                    "schema": "auditooor.klbq_006_terminal_boundary.v1",
                    "limitation_id": "KLBQ-006",
                    "finding_id": "30522",
                    "source_root": str(repo),
                    "pinned_ref": "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291",
                    "exact_next_commands": [command],
                },
            )
            _write_json(
                anchors_path,
                {
                    "finding_id": "30522",
                    "classification": {
                        "exact_finding_github_blob_anchors": "present",
                        "exact_renft_source_root": "present",
                        "real_source_anchors": "present",
                    },
                },
            )

            report = MOD.build_report(boundary_path=boundary_path, anchors_path=anchors_path)

        self.assertEqual(report["source_citation_acquisition"]["state"], "exact_30522_citation_present")
        self.assertEqual(report["exact_next_command"], command)
        self.assertEqual(report["exact_proof_command"], command)

    def test_reuses_recorded_foundry_blocker_without_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            repo = root / "re-nft-smart-contracts"
            (repo / "lib" / "forge-std").mkdir(parents=True)
            _write(
                repo / ".gitmodules",
                "\n".join(
                    [
                        '[submodule "lib/forge-std"]',
                        "\tpath = lib/forge-std",
                        "\turl = https://github.com/foundry-rs/forge-std",
                    ]
                )
                + "\n",
            )
            boundary_path = root / "reports" / "klbq_006_terminal_boundary_2026-05-05.json"
            anchors_path = root / "reports" / "klbq_006_real_source_anchors_2026-05-05.json"
            command = (
                f"forge test --root {repo} "
                "--match-path test/unit/Guard/CheckTransaction.t.sol "
                "--match-test test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler -vvv"
            )
            _write_json(
                boundary_path,
                {
                    "schema": "auditooor.klbq_006_terminal_boundary.v1",
                    "limitation_id": "KLBQ-006",
                    "finding_id": "30522",
                    "source_root": str(repo),
                    "pinned_ref": "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291",
                    "exact_next_commands": [command],
                },
            )
            _write_json(
                anchors_path,
                {
                    "finding_id": "30522",
                    "classification": {
                        "exact_finding_github_blob_anchors": "absent",
                        "exact_renft_source_root": "present",
                        "real_source_anchors": "present",
                    },
                },
            )
            previous_report = {
                "command_consumption": {
                    "commands": [
                        {
                            "command": command,
                            "kind": "foundry_anchor_test",
                            "executed": True,
                            "exit_code": 1,
                            "status": "foundry_dependency_blocked_fail_closed",
                            "checks": [],
                            "execution_blocker": {
                                "state": "blocked_missing_foundry_dependencies",
                                "network_resolution_failure": True,
                                "failed_submodule_urls": ["https://github.com/foundry-rs/forge-std/"],
                                "unblock_command": f"git -C {repo} submodule update --init --recursive",
                                "rerun_exact_proof_command": command,
                            },
                        }
                    ]
                }
            }

            with mock.patch.object(MOD, "_record_foundry_command", side_effect=AssertionError("forge rerun attempted")):
                report = MOD.build_report(
                    boundary_path=boundary_path,
                    anchors_path=anchors_path,
                    previous_report=previous_report,
                )

        record = report["command_consumption"]["commands"][0]
        self.assertTrue(record["reused_existing_execution_record"])
        self.assertEqual(record["status"], "foundry_dependency_blocked_fail_closed")
        self.assertEqual(
            report["exact_next_command"],
            report["source_citation_acquisition"]["exact_next_commands"][0],
        )
        self.assertEqual(
            report["dependency_next_command"],
            report["foundry_dependency_unblock"]["network_unblock_command"],
        )


if __name__ == "__main__":
    unittest.main()
