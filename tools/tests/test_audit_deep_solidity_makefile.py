#!/usr/bin/env python3
"""Regression tests for Solidity audit-deep Makefile routing."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent.parent
MAKEFILE = REPO / "Makefile"
STERILE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
EXPECTED_STEPS = [
    "workspace-detection",
    "hackerman-brief",
    "slither-resilient",
    "regex-detectors-solidity",
    "aderyn-solidity",
    "semgrep-solidity",
    "wave14-slither-ast",
    "changelog-source-drift-miner",
    "reverted-guard-mine",
    "mine-solidity-fork-patterns",
    "composition-fixtures",
    "per-function-invariant-gen",
    "halmos-runner",
    "echidna-campaign",
    "medusa-fuzz",
    "deep-engine-output-parse",
    "foundry-invariant-runner",
    "universal-fp-runner",
]


class TestAuditDeepSolidityMakefile(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("make"):
            raise unittest.SkipTest("make not on PATH")
        if not shutil.which("python3"):
            raise unittest.SkipTest("python3 not on PATH")
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")

    def setUp(self) -> None:
        self.sandbox = Path(tempfile.mkdtemp(prefix="audit_deep_solidity_"))
        self.ws = self.sandbox / "audits" / "solidity-ws"
        (self.ws / "src").mkdir(parents=True)
        (self.ws / "src" / "Token.sol").write_text(
            "pragma solidity ^0.8.20;\ncontract Token { function ping() external pure returns (uint256) { return 1; } }\n",
            encoding="utf-8",
        )
        (self.ws / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.sandbox, ignore_errors=True)

    def _env(self, path: str | None = None) -> dict[str, str]:
        env = os.environ.copy()
        env["HOME"] = str(self.sandbox)
        env["PATH"] = path or STERILE_PATH
        # W5-D1: a truly sterile environment also has no provisioned
        # deep-engine binaries; point the resolver at an empty dir so the
        # offline-skip assertions are deterministic regardless of whether
        # the local worktree ran `make deep-engines-provision`.
        empty_bin = self.sandbox / "w5d1-empty-deep-bin"
        empty_bin.mkdir(exist_ok=True)
        env["AUDITOOOR_DEEP_BIN_DIR"] = str(empty_bin)
        env["AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE"] = "1"
        env["AUDITOOOR_AUDIT_DEEP_ROUTE_ONLY"] = "1"
        env["AUDIT_COMMIT_MINING_SKIP"] = "1"
        return env

    def _run_make(
        self,
        target: str,
        *extra: str,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["make", target, f"WS={self.ws}", *extra],
            cwd=REPO,
            env=env or self._env(),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _manifest(self) -> dict:
        path = self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json"
        self.assertTrue(path.is_file(), f"missing Solidity deep manifest at {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_executable(self, path: Path, body: str) -> None:
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _prepare_nested_hardhat_project(self) -> tuple[Path, Path]:
        (self.ws / "foundry.toml").unlink()
        nested = self.ws / "src" / "contracts" / "nested-hardhat"
        (nested / "contracts").mkdir(parents=True)
        (nested / "hardhat.config.js").write_text("module.exports = {};\n", encoding="utf-8")
        (nested / "echidna.yaml").write_text("testLimit: 100\n", encoding="utf-8")
        contract = nested / "contracts" / "EchidnaTest.sol"
        contract.write_text("pragma solidity ^0.8.20;\ncontract EchidnaTest {}\n", encoding="utf-8")
        return nested, contract

    def test_audit_deep_solidity_target_emits_offline_safe_artifacts(self) -> None:
        proc = self._run_make("audit-deep-solidity")
        self.assertEqual(
            proc.returncode,
            0,
            f"make audit-deep-solidity failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )

        out_dir = self.ws / ".auditooor" / "solidity-deep-audit"
        self.assertTrue(out_dir.is_dir())
        manifest = self._manifest()
        self.assertEqual(manifest["schema"], "auditooor.solidity_deep_audit.v1")
        self.assertTrue(manifest["detection"]["foundry"])
        self.assertTrue(manifest["detection"]["src_solidity"])
        self.assertTrue(manifest["detection"]["is_solidity_workspace"])
        self.assertIn("contract_scope", manifest)
        self.assertIsNone(manifest["contract_scope"])

        tools = [row["tool"] for row in manifest["artifacts"]]
        self.assertEqual(tools, EXPECTED_STEPS)
        for step in EXPECTED_STEPS:
            artifact = out_dir / f"{step}.json"
            self.assertTrue(artifact.is_file(), f"missing step artifact for {step}")
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.solidity_deep_audit.step.v1")
            self.assertIn("run_id", payload)
            self.assertIn(payload["status"], {"ok", "skipped", "blocked"})

        for offline_step in ["slither-resilient", "halmos-runner", "echidna-campaign", "medusa-fuzz", "foundry-invariant-runner"]:
            payload = json.loads((out_dir / f"{offline_step}.json").read_text(encoding="utf-8"))
            self.assertIn(
                payload["status"],
                {"skipped", "blocked"},
                f"{offline_step} should not require a real external engine in sterile PATH",
            )

    def test_audit_deep_solidity_contract_file_relative_scopes_commands(self) -> None:
        nested, contract = self._prepare_nested_hardhat_project()
        nested_resolved = nested.resolve()
        contract_rel = contract.relative_to(self.ws).as_posix()

        proc = self._run_make("audit-deep-solidity", f"CONTRACT_FILE={contract_rel}")
        self.assertEqual(
            proc.returncode,
            0,
            f"make audit-deep-solidity failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )

        out_dir = self.ws / ".auditooor" / "solidity-deep-audit"
        manifest = self._manifest()
        self.assertEqual(
            manifest["contract_scope"],
            {
                "contract_file": contract_rel,
                "contract_name": "EchidnaTest",
                "project_root": str(nested_resolved),
            },
        )

        hackerman_step = json.loads((out_dir / "hackerman-brief.json").read_text(encoding="utf-8"))
        self.assertIn(f"FILES={contract_rel}", hackerman_step["command"])
        self.assertNotIn(".sol,", hackerman_step["command"])

        halmos_step = json.loads((out_dir / "halmos-runner.json").read_text(encoding="utf-8"))
        self.assertIn(f"run_in_project {nested_resolved}", halmos_step["command"])
        echidna_step = json.loads((out_dir / "echidna-campaign.json").read_text(encoding="utf-8"))
        self.assertIn(f"run_in_project {nested_resolved}", echidna_step["command"])
        medusa_step = json.loads((out_dir / "medusa-fuzz.json").read_text(encoding="utf-8"))
        self.assertIn(f"run_in_project {nested_resolved}", medusa_step["command"])
        foundry_step = json.loads((out_dir / "foundry-invariant-runner.json").read_text(encoding="utf-8"))
        self.assertIn(f"run_in_project {nested_resolved}", foundry_step["command"])

    def test_audit_deep_solidity_contract_file_absolute_scopes_commands(self) -> None:
        nested, contract = self._prepare_nested_hardhat_project()
        nested_resolved = nested.resolve()
        ws_resolved = self.ws.resolve()
        contract_rel = contract.relative_to(self.ws).as_posix()
        contract_abs = str(contract.resolve())

        proc = self._run_make("audit-deep-solidity", f"CONTRACT_FILE={contract_abs}")
        self.assertEqual(
            proc.returncode,
            0,
            f"make audit-deep-solidity failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )

        out_dir = self.ws / ".auditooor" / "solidity-deep-audit"
        manifest = self._manifest()
        self.assertEqual(manifest["contract_scope"]["contract_file"], contract_rel)
        self.assertEqual(manifest["contract_scope"]["project_root"], str(nested_resolved))

        hackerman_step = json.loads((out_dir / "hackerman-brief.json").read_text(encoding="utf-8"))
        self.assertIn(f"FILES={contract_rel}", hackerman_step["command"])
        self.assertIn(f"WS={self.ws}", hackerman_step["command"])

    def test_audit_deep_solidity_contract_file_outside_workspace_is_rejected(self) -> None:
        outside = self.sandbox / "outside" / "Detached.sol"
        outside.parent.mkdir(parents=True, exist_ok=True)
        outside.write_text("pragma solidity ^0.8.20;\ncontract Detached {}\n", encoding="utf-8")

        proc = self._run_make("audit-deep-solidity", f"CONTRACT_FILE={outside}")
        self.assertNotEqual(proc.returncode, 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        self.assertIn("CONTRACT_FILE must be inside workspace", proc.stderr)
        self.assertFalse(
            (self.ws / ".auditooor" / "solidity-deep-audit" / "manifest.json").exists(),
            "outside-workspace contract file should not produce a manifest",
        )

    def test_audit_deep_routes_solidity_workspace_to_solidity_target(self) -> None:
        proc = self._run_make(
            "audit-deep",
            "AUDIT_DEEP_SKIP_AUDIT_PREREQ=1",
            "AUDIT_DEEP_ALLOW_STALE_AUDIT_PREREQ=1",
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"make audit-deep routing failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        self.assertIn("Solidity workspace detected; routing to audit-deep-solidity", proc.stdout)
        manifest = self._manifest()
        self.assertEqual([row["tool"] for row in manifest["artifacts"]], EXPECTED_STEPS)

    def test_nested_hardhat_project_root_drives_engine_args(self) -> None:
        nested, _ = self._prepare_nested_hardhat_project()
        nested_resolved = nested.resolve()

        fake_bin = self.sandbox / "bin"
        fake_bin.mkdir()
        halmos_tripwire = self.sandbox / "halmos-invoked.txt"

        self._write_executable(
            fake_bin / "echidna",
            """
            #!/usr/bin/env bash
            case "${1:-}" in
              --version|-v|version) echo "fake-echidna 0.0-test"; exit 0 ;;
            esac
            echo "cwd=$(pwd) args=$* private_key=${PRIVATE_KEY:-missing}"
            exit 0
            """,
        )
        self._write_executable(
            fake_bin / "medusa",
            """
            #!/usr/bin/env bash
            case "${1:-}" in
              --version|-v|version) echo "fake-medusa 0.0-test"; exit 0 ;;
            esac
            echo "cwd=$(pwd) args=$*"
            exit 0
            """,
        )
        self._write_executable(
            fake_bin / "halmos",
            f"""
            #!/usr/bin/env bash
            case "${{1:-}}" in
              --version|-v|version) echo "fake-halmos 0.0-test"; exit 0 ;;
            esac
            echo invoked > "{halmos_tripwire}"
            echo "cwd=$(pwd) args=$*"
            exit 0
            """,
        )

        env = self._env(path=os.pathsep.join([str(fake_bin), STERILE_PATH]))
        env["AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE_RUN_DEEP_ENGINES"] = "1"
        env.pop("PRIVATE_KEY", None)
        proc = self._run_make("audit-deep-solidity", env=env)
        self.assertEqual(
            proc.returncode,
            0,
            f"make audit-deep-solidity failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )

        out_dir = self.ws / ".auditooor" / "solidity-deep-audit"
        manifest = self._manifest()
        self.assertTrue(manifest["detection"]["hardhat"])
        self.assertFalse(manifest["detection"]["foundry"])

        echidna_step = json.loads((out_dir / "echidna-campaign.json").read_text(encoding="utf-8"))
        self.assertEqual(echidna_step["status"], "ok")
        self.assertIn(f"run_in_project {nested}", echidna_step["command"])
        self.assertIn(". --config echidna.yaml --contract EchidnaTest", echidna_step["command"])

        medusa_step = json.loads((out_dir / "medusa-fuzz.json").read_text(encoding="utf-8"))
        self.assertEqual(medusa_step["status"], "ok")
        self.assertIn(f"run_in_project {nested}", medusa_step["command"])
        self.assertIn("fuzz --compilation-target . --target-contracts EchidnaTest", medusa_step["command"])

        halmos_step = json.loads((out_dir / "halmos-runner.json").read_text(encoding="utf-8"))
        self.assertEqual(halmos_step["status"], "skipped")
        self.assertIn("incompatible_project_type", halmos_step["reason"])
        self.assertIn(f"run_in_project {nested}", halmos_step["command"])

        echidna_artifact = json.loads((self.ws / ".auditooor" / "echidna" / "artifact.json").read_text(encoding="utf-8"))
        self.assertEqual(
            echidna_artifact["args"],
            [".", "--config", "echidna.yaml", "--contract", "EchidnaTest"],
        )
        self.assertIn(f"cwd={nested}", echidna_artifact["stdout"])
        self.assertIn("args=. --config echidna.yaml --contract EchidnaTest", echidna_artifact["stdout"])
        self.assertIn(
            "private_key=0x59c6995e998f97a5a0044966f094538880e6e10f2e0f5b8680f7abf9e6e3e8e0",
            echidna_artifact["stdout"],
        )

        medusa_artifact = json.loads((self.ws / ".auditooor" / "medusa" / "artifact.json").read_text(encoding="utf-8"))
        self.assertEqual(
            medusa_artifact["args"],
            ["fuzz", "--compilation-target", ".", "--target-contracts", "EchidnaTest"],
        )
        self.assertIn(f"cwd={nested}", medusa_artifact["stdout"])
        self.assertIn("args=fuzz --compilation-target . --target-contracts EchidnaTest", medusa_artifact["stdout"])

        self.assertFalse((self.ws / ".auditooor" / "halmos" / "artifact.json").exists())
        self.assertFalse(halmos_tripwire.exists(), "halmos should be skipped for Hardhat-only project roots")

    def test_engine_harness_root_under_poc_tests_drives_engine_args(self) -> None:
        harness = self.ws / "poc-tests" / "morpho-engine-harness"
        (harness / "src").mkdir(parents=True)
        (harness / "test").mkdir()
        (harness / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
        (harness / "echidna.yaml").write_text("testMode: property\ntestLimit: 10\n", encoding="utf-8")
        (harness / "src" / "EngineHarness.sol").write_text(
            "pragma solidity ^0.8.20;\ncontract EngineHarness { function invariant_harnessRoot() public pure {} }\n",
            encoding="utf-8",
        )
        (harness / "test" / "EngineHarness_FuzzProps.sol").write_text(
            "pragma solidity ^0.8.20;\ncontract EngineHarness_FuzzProps { function echidna_harnessRoot() public pure returns (bool) { return true; } }\n",
            encoding="utf-8",
        )

        fake_bin = self.sandbox / "bin"
        fake_bin.mkdir()
        self._write_executable(
            fake_bin / "echidna",
            """
            #!/usr/bin/env bash
            case "${1:-}" in
              --version|-v|version) echo "fake-echidna 0.0-test"; exit 0 ;;
            esac
            echo "cwd=$(pwd) args=$*"
            exit 0
            """,
        )
        self._write_executable(
            fake_bin / "medusa",
            """
            #!/usr/bin/env bash
            case "${1:-}" in
              --version|-v|version) echo "fake-medusa 0.0-test"; exit 0 ;;
            esac
            echo "cwd=$(pwd) args=$*"
            exit 0
            """,
        )
        self._write_executable(
            fake_bin / "halmos",
            """
            #!/usr/bin/env bash
            case "${1:-}" in
              --version|-v|version) echo "fake-halmos 0.0-test"; exit 0 ;;
            esac
            echo "cwd=$(pwd) args=$*"
            exit 0
            """,
        )
        self._write_executable(
            fake_bin / "forge",
            """
            #!/usr/bin/env bash
            case "${1:-}" in
              --version|-V|version) echo "fake-forge 0.0-test"; exit 0 ;;
            esac
            echo "cwd=$(pwd) args=$*"
            exit 0
            """,
        )

        env = self._env(path=os.pathsep.join([str(fake_bin), STERILE_PATH]))
        env["AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE_RUN_DEEP_ENGINES"] = "1"
        proc = self._run_make("audit-deep-solidity", env=env)
        self.assertEqual(
            proc.returncode,
            0,
            f"make audit-deep-solidity failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )

        out_dir = self.ws / ".auditooor" / "solidity-deep-audit"
        manifest = self._manifest()
        self.assertTrue(manifest["detection"]["foundry"])

        for step in ["halmos-runner", "echidna-campaign", "medusa-fuzz", "foundry-invariant-runner"]:
            payload = json.loads((out_dir / f"{step}.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "ok", f"{step} stdout:\n{payload['stdout_tail']}\nstderr:\n{payload['stderr_tail']}")
            self.assertIn(f"run_in_project {harness}", payload["command"])

        echidna_artifact = json.loads((self.ws / ".auditooor" / "echidna" / "artifact.json").read_text(encoding="utf-8"))
        self.assertEqual(
            echidna_artifact["args"],
            [".", "--config", "echidna.yaml", "--contract", "EngineHarness_FuzzProps"],
        )
        medusa_artifact = json.loads((self.ws / ".auditooor" / "medusa" / "artifact.json").read_text(encoding="utf-8"))
        self.assertEqual(
            medusa_artifact["args"],
            ["fuzz", "--compilation-target", ".", "--target-contracts", "EngineHarness_FuzzProps"],
        )
        foundry_stdout = (out_dir / "foundry-invariant-runner.stdout.log").read_text(encoding="utf-8")
        self.assertIn(f"cwd={harness}", foundry_stdout)
        self.assertIn("args=test --match-test invariant|Invariant -vvv", foundry_stdout)

    def test_all_harness_target_is_opt_in_and_isolates_artifacts(self) -> None:
        harnesses: list[Path] = []
        for name in ["alpha-engine-harness", "beta-engine-harness"]:
            harness = self.ws / "poc-tests" / name
            harnesses.append(harness)
            (harness / "src").mkdir(parents=True)
            (harness / "test").mkdir()
            contract_name = name.split("-")[0].title() + "_FuzzProps"
            (harness / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
            (harness / "echidna.yaml").write_text("testMode: property\ntestLimit: 10\n", encoding="utf-8")
            (harness / "src" / "Harness.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Harness { function invariant_ok() public pure {} }\n",
                encoding="utf-8",
            )
            (harness / "test" / f"{contract_name}.sol").write_text(
                f"pragma solidity ^0.8.20;\ncontract {contract_name} {{ function echidna_ok() public pure returns (bool) {{ return true; }} }}\n",
                encoding="utf-8",
            )

        fake_bin = self.sandbox / "bin"
        fake_bin.mkdir()
        for tool in ["echidna", "medusa", "halmos", "forge"]:
            version_flag = "--version|-v|version" if tool != "forge" else "--version|-V|version"
            self._write_executable(
                fake_bin / tool,
                f"""
                #!/usr/bin/env bash
                case "${{1:-}}" in
                  {version_flag}) echo "fake-{tool} 0.0-test"; exit 0 ;;
                esac
                echo "cwd=$(pwd) args=$* artifact_root=${{AUDITOOOR_DEEP_ARTIFACT_ROOT:-missing}}"
                exit 0
                """,
            )

        env = self._env(path=os.pathsep.join([str(fake_bin), STERILE_PATH]))
        env["AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE_RUN_DEEP_ENGINES"] = "1"
        default_proc = self._run_make("audit-deep-solidity", env=env)
        self.assertEqual(default_proc.returncode, 0, default_proc.stderr)
        self.assertFalse((self.ws / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json").exists())

        all_proc = self._run_make("audit-deep-solidity-all-harnesses", env=env)
        self.assertEqual(
            all_proc.returncode,
            0,
            f"make audit-deep-solidity-all-harnesses failed\nstdout:\n{all_proc.stdout}\nstderr:\n{all_proc.stderr}",
        )

        aggregate = json.loads(
            (self.ws / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(aggregate["schema"], "auditooor.solidity_deep_all_harnesses.v1")
        self.assertEqual(aggregate["expected_harness_count"], 2)
        self.assertEqual(aggregate["executed_harness_count"], 2)
        self.assertEqual(aggregate["status"], "ok")
        self.assertEqual([row["slug"] for row in aggregate["harnesses"]], ["alpha-engine-harness", "beta-engine-harness"])

        for harness in harnesses:
            slug = harness.name
            manifest = self.ws / ".auditooor" / "solidity-deep-audit" / "by-harness" / slug / "manifest.json"
            self.assertTrue(manifest.is_file(), f"missing per-harness manifest for {slug}")
            for engine in ["halmos", "echidna", "medusa"]:
                artifact = self.ws / ".auditooor" / "deep-engine-runs" / "by-harness" / slug / engine / "artifact.json"
                self.assertTrue(artifact.is_file(), f"missing isolated {engine} artifact for {slug}")
                payload = json.loads(artifact.read_text(encoding="utf-8"))
                self.assertIn(f"deep-engine-runs/by-harness/{slug}", payload["artifact_dir"])


if __name__ == "__main__":
    unittest.main()
