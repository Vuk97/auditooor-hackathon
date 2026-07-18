#!/usr/bin/env python3
"""Hermetic tests for tools/p1-extraction-queue-runner.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "p1-extraction-queue-runner.py"


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


class P1ExtractionQueueRunnerTest(unittest.TestCase):
    def _write_fixture_env(self, root: Path) -> dict[str, Path]:
        dsl_dir = root / "dsl"
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
                """
            ),
            encoding="utf-8",
        )
        workspace = root / "workspace"
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
        mock_dispatcher = root / "mock_dispatcher.py"
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
        mock_runner = root / "mock_runner.py"
        mock_runner.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "name = pathlib.Path(sys.argv[1]).name\n"
            "print('total hits: 0' if '_clean' in name else 'total hits: 1')\n",
            encoding="utf-8",
        )
        mock_runner.chmod(0o755)
        queue = root / "queue.json"
        queue.write_text(
            json.dumps(
                [
                    {
                        "pattern": "demo-setter-no-auth",
                        "source": "demo-source-contract",
                        "source_status": "archive-found",
                        "argv": [
                            "python3",
                            "tools/p1-fixture-extractor.py",
                            "--pattern",
                            "demo-setter-no-auth",
                            "--workspace",
                            str(workspace),
                            "--source-file",
                            str(workspace / "DemoSource.sol"),
                            "--strict-smoke-fire",
                        ],
                    }
                ]
            ),
            encoding="utf-8",
        )
        return {
            "dsl_dir": dsl_dir,
            "queue": queue,
            "mock_dispatcher": mock_dispatcher,
            "mock_runner": mock_runner,
        }

    def test_dry_run_records_safe_argv_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._write_fixture_env(Path(tmp))
            out = Path(tmp) / "manifest.json"
            out_md = Path(tmp) / "report.md"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--queue",
                    str(paths["queue"]),
                    "--out",
                    str(out),
                    "--out-md",
                    str(out_md),
                    "--dry-run",
                    "--limit",
                    "1",
                ],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(manifest["result_counts"], {"dry_run": 1})
            self.assertIn("p1-fixture-extractor.py", " ".join(manifest["results"][0]["argv"]))
            report = out_md.read_text(encoding="utf-8")
            self.assertIn("P1 Extraction Execution Report", report)
            self.assertIn("demo-setter-no-auth", report)

    def test_mock_queue_row_executes_and_captures_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._write_fixture_env(Path(tmp))
            out = Path(tmp) / "manifest.json"
            out_md = Path(tmp) / "report.md"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--queue",
                    str(paths["queue"]),
                    "--out",
                    str(out),
                    "--out-md",
                    str(out_md),
                    "--mock-dispatcher",
                    str(paths["mock_dispatcher"]),
                    "--runner",
                    str(paths["mock_runner"]),
                    "--dsl-dir",
                    str(paths["dsl_dir"]),
                    "--skip-solc",
                    "--no-minimax-review",
                    "--limit",
                    "1",
                ],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(manifest["result_counts"], {"ok": 1})
            row = manifest["results"][0]
            self.assertTrue(Path(row["stdout_path"]).is_file())
            payload = json.loads(Path(row["stdout_path"]).read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "ok")
            self.assertIn("stdout:", out_md.read_text(encoding="utf-8"))

    def test_rejects_queue_rows_that_do_not_target_extractor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue = Path(tmp) / "bad_queue.json"
            queue.write_text(json.dumps([{"pattern": "bad", "argv": ["python3", "evil.py"]}]), encoding="utf-8")
            out = Path(tmp) / "manifest.json"
            out_md = Path(tmp) / "report.md"
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--queue", str(queue), "--out", str(out), "--out-md", str(out_md)],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            manifest = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(manifest["result_counts"], {"invalid_queue_row": 1})
            self.assertIn("invalid_queue_row", out_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
