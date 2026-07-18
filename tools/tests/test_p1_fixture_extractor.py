#!/usr/bin/env python3
"""Hermetic tests for tools/p1-fixture-extractor.py."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "p1-fixture-extractor.py"


VULN_FIXTURE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DemoVuln {
    uint256 public value;
    function setValue(uint256 x) external {
        value = x;
    }
}
"""


CLEAN_FIXTURE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DemoClean {
    address public owner;
    uint256 public value;
    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }
    function setValue(uint256 x) external onlyOwner {
        value = x;
    }
}
"""


def _load_tool():
    spec = importlib.util.spec_from_file_location("p1_fixture_extractor_test_subject", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _norm_sol(text: str) -> str:
    return "\n".join(line.strip() for line in text.strip().splitlines() if line.strip())


class P1FixtureExtractorTest(unittest.TestCase):
    def _write_common_files(self, tmp_path: Path) -> dict[str, Path]:
        dsl_dir = tmp_path / "dsl"
        dsl_dir.mkdir()
        (dsl_dir / "demo-setter-no-auth.yaml").write_text(
            textwrap.dedent(
                """\
                pattern: demo-setter-no-auth
                source: demo-source-contract
                severity: HIGH
                confidence: MEDIUM
                match:
                  - function.kind: external_or_public
                  - function.name_matches: setValue
                fixtures:
                  vuln: detectors/test_fixtures/demo_setter_no_auth_vulnerable.sol
                  clean: detectors/test_fixtures/demo_setter_no_auth_clean.sol
                help: "demo"
                """
            ),
            encoding="utf-8",
        )

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "DemoSource.sol").write_text(
            textwrap.dedent(
                """\
                // demo-source-contract
                pragma solidity ^0.8.20;
                contract DemoSource {
                    uint256 public value;
                    function setValue(uint256 x) external { value = x; }
                }
                """
            ),
            encoding="utf-8",
        )

        mock_dispatcher = tmp_path / "mock_dispatcher.py"
        mock_dispatcher.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "prompt = open(sys.argv[-1]).read()\n"
            "if 'Adversarially review' in prompt:\n"
            "    print('APPROVE')\n"
            "else:\n"
            "    print('VULN fixture')\n"
            "    print('```solidity')\n"
            f"    print({VULN_FIXTURE!r})\n"
            "    print('```')\n"
            "    print('CLEAN fixture')\n"
            "    print('```solidity')\n"
            f"    print({CLEAN_FIXTURE!r})\n"
            "    print('```')\n",
            encoding="utf-8",
        )
        mock_dispatcher.chmod(0o755)

        mock_runner = tmp_path / "mock_runner.py"
        mock_runner.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "assert '--tier=ALL' in sys.argv, sys.argv\n"
            "name = pathlib.Path(sys.argv[1]).name\n"
            "print('total hits: 0' if '_clean' in name else 'total hits: 1')\n",
            encoding="utf-8",
        )
        mock_runner.chmod(0o755)

        run_tests = tmp_path / "run_tests.sh"
        run_tests.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                run_test() { :; }
                run_clean_test() { :; }
                echo
                TOTAL=$(wc -l < "$STAGE" | tr -d ' ')
                echo "[staged] $TOTAL"
                """
            ),
            encoding="utf-8",
        )

        return {
            "dsl_dir": dsl_dir,
            "workspace": workspace,
            "mock_dispatcher": mock_dispatcher,
            "mock_runner": mock_runner,
            "run_tests": run_tests,
            "fixture_dir": tmp_path / "fixtures",
        }

    def _run(self, args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        clean_env = {
            key: val for key, val in os.environ.items()
            if key not in {
                "AUDITOOOR_LLM_NETWORK_CONSENT",
                "ADVERSARIAL_LIVE_CONSENT",
                "AUDITOOOR_P1_FIXTURE_MOCK_DISPATCHER",
            }
        }
        if env:
            clean_env.update(env)
        return subprocess.run(
            [sys.executable, str(TOOL), *args],
            cwd=str(ROOT),
            env=clean_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_mock_dispatcher_extracts_and_smoke_fires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._write_common_files(Path(tmp))
            proc = self._run([
                "--pattern", "demo-setter-no-auth",
                "--workspace", str(paths["workspace"]),
                "--dsl-dir", str(paths["dsl_dir"]),
                "--mock-dispatcher", str(paths["mock_dispatcher"]),
                "--runner", str(paths["mock_runner"]),
                "--skip-solc",
                "--no-minimax-review",
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "ok")
            self.assertTrue(Path(payload["vuln"]).is_file())
            self.assertTrue(Path(payload["clean"]).is_file())

    def test_existing_fixture_reextracts_equivalent_with_mock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._write_common_files(Path(tmp))
            proc = self._run([
                "--pattern", "demo-setter-no-auth",
                "--workspace", str(paths["workspace"]),
                "--dsl-dir", str(paths["dsl_dir"]),
                "--source-file", "DemoSource.sol",
                "--mock-dispatcher", str(paths["mock_dispatcher"]),
                "--runner", str(paths["mock_runner"]),
                "--skip-solc",
                "--no-minimax-review",
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(_norm_sol(Path(payload["vuln"]).read_text()), _norm_sol(VULN_FIXTURE))
            self.assertEqual(_norm_sol(Path(payload["clean"]).read_text()), _norm_sol(CLEAN_FIXTURE))

    def test_unlocatable_source_fails_structured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._write_common_files(Path(tmp))
            (paths["workspace"] / "DemoSource.sol").unlink()
            proc = self._run([
                "--pattern", "demo-setter-no-auth",
                "--workspace", str(paths["workspace"]),
                "--dsl-dir", str(paths["dsl_dir"]),
                "--mock-dispatcher", str(paths["mock_dispatcher"]),
                "--runner", str(paths["mock_runner"]),
                "--skip-solc",
                "--no-minimax-review",
            ])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("cannot-run: source-unlocatable", proc.stderr)

    def test_missing_consent_without_mock_fails_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._write_common_files(Path(tmp))
            proc = self._run([
                "--pattern", "demo-setter-no-auth",
                "--workspace", str(paths["workspace"]),
                "--dsl-dir", str(paths["dsl_dir"]),
                "--dispatcher", str(paths["mock_dispatcher"]),
                "--runner", str(paths["mock_runner"]),
                "--skip-solc",
                "--no-minimax-review",
            ])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("cannot-run: no-consent", proc.stderr)

    def test_default_runner_missing_detector_argument_fails_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._write_common_files(Path(tmp))
            proc = self._run([
                "--pattern", "demo-setter-no-auth",
                "--workspace", str(paths["workspace"]),
                "--dsl-dir", str(paths["dsl_dir"]),
                "--dispatcher", str(paths["mock_dispatcher"]),
                "--skip-solc",
                "--no-minimax-review",
            ], env={"AUDITOOOR_LLM_NETWORK_CONSENT": "1"})
            self.assertEqual(proc.returncode, 2)
            self.assertIn("cannot-run: missing-detector-argument", proc.stderr)

    def test_accept_writes_canonical_fixture_dir_and_live_run_tests_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._write_common_files(Path(tmp))
            proc = self._run([
                "--pattern", "demo-setter-no-auth",
                "--workspace", str(paths["workspace"]),
                "--dsl-dir", str(paths["dsl_dir"]),
                "--source-file", "DemoSource.sol",
                "--mock-dispatcher", str(paths["mock_dispatcher"]),
                "--runner", str(paths["mock_runner"]),
                "--fixture-dir", str(paths["fixture_dir"]),
                "--run-tests", str(paths["run_tests"]),
                "--skip-solc",
                "--accept",
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((paths["fixture_dir"] / "demo_setter_no_auth_vulnerable.sol").is_file())
            self.assertTrue((paths["fixture_dir"] / "demo_setter_no_auth_clean.sol").is_file())
            run_tests = paths["run_tests"].read_text()
            rows_idx = run_tests.index("run_test")
            total_idx = run_tests.index("TOTAL=$(wc -l")
            self.assertLess(rows_idx, total_idx, "rows must be staged before execution block")
            self.assertIn("demo_setter_no_auth_vulnerable.sol", run_tests)
            self.assertIn("demo_setter_no_auth_clean.sol", run_tests)

    def test_marker_style_response_parses(self) -> None:
        tool = _load_tool()
        vuln, clean = tool.parse_fixtures(
            f"=== VULN ===\n{VULN_FIXTURE}\n=== CLEAN ===\n{CLEAN_FIXTURE}\n"
        )
        self.assertIn("DemoVuln", vuln)
        self.assertIn("DemoClean", clean)

    def test_repair_generated_solidity_renames_state_function_collisions(self) -> None:
        tool = _load_tool()
        repaired = tool.repair_generated_solidity(
            textwrap.dedent(
                """\
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.20;
                contract Demo {
                    uint256 internal burn;
                    function burn() internal returns (bool) {
                        return burn > 0;
                    }
                }
                """
            )
        )
        self.assertIn("uint256 internal burnState;", repaired)
        self.assertIn("function burn() internal returns (bool)", repaired)
        self.assertIn("return burnState > 0;", repaired)

    def test_repair_generated_solidity_removes_view_from_mutating_helper_calls(self) -> None:
        tool = _load_tool()
        repaired = tool.repair_generated_solidity(
            textwrap.dedent(
                """\
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.20;
                contract Demo {
                    uint256 internal balance;
                    function _accrue() internal { balance += 1; }
                    function activePool() internal view returns (bool) {
                        _accrue();
                        return balance > 0;
                    }
                }
                """
            )
        )
        self.assertIn("function activePool() internal returns (bool)", repaired)
        self.assertNotIn("function activePool() internal view returns (bool)", repaired)

    def test_repair_generated_solidity_renames_parameter_function_collisions(self) -> None:
        tool = _load_tool()
        repaired = tool.repair_generated_solidity(
            textwrap.dedent(
                """\
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.20;
                contract Demo {
                    function maxIterations() internal returns (bool) { return true; }
                    function borrowLogic(uint256 maxIterations) external {
                        if (maxIterations()) {
                            uint256 copy = maxIterations;
                        }
                    }
                }
                """
            )
        )
        self.assertIn("uint256 maxIterationsArg", repaired)
        self.assertIn("maxIterations()", repaired)
        self.assertIn("uint256 copy = maxIterationsArg;", repaired)
        self.assertNotIn("uint256 copy = maxIterations;", repaired)

    def test_repair_generated_solidity_renames_legacy_constructor_like_helper(self) -> None:
        tool = _load_tool()
        repaired = tool.repair_generated_solidity(
            textwrap.dedent(
                """\
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.20;
                contract StEtherAdapter {
                    function StEtherAdapter() internal returns (bool) {
                        return true;
                    }
                    function check() external returns (bool) {
                        return StEtherAdapter();
                    }
                }
                """
            )
        )
        self.assertIn("contract StEtherAdapter", repaired)
        self.assertIn("function _StEtherAdapterHelper() internal returns (bool)", repaired)
        self.assertIn("return _StEtherAdapterHelper();", repaired)
        self.assertNotIn("function StEtherAdapter() internal", repaired)


if __name__ == "__main__":
    unittest.main()
