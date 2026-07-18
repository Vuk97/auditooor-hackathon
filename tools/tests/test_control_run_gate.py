from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.control.run_gate import SCHEMA, build_run_gate_plan, execute_run_gate


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class ControlRunGateTests(unittest.TestCase):
    def test_dry_run_command_construction_uses_candidate_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "audit"
            repo = root / "repo"
            ws.mkdir()
            repo.mkdir()
            candidate = ws / ".auditooor" / "control" / "candidates" / "amp-zero.json"
            _write(candidate, json.dumps({"id": "amp-zero", "title": "Amp zero"}))

            manifest = build_run_gate_plan(ws, candidate_file=candidate, cwd=repo)

        self.assertEqual(manifest["schema"], SCHEMA)
        self.assertTrue(manifest["dry_run"])
        self.assertFalse(manifest["would_execute"])
        self.assertEqual(manifest["candidate_id"], "amp-zero")
        self.assertEqual(manifest["candidate_path"], str(candidate.resolve()))
        self.assertEqual(manifest["blocked_reasons"], [])
        self.assertEqual(
            manifest["argv"][:6],
            [
                "python3",
                "tools/upstream-equivalent-gate.py",
                "--workspace",
                str(ws.resolve()),
                "--candidate",
                str(candidate.resolve()),
            ],
        )
        self.assertIn("--candidate-id", manifest["argv"])
        self.assertIn("--out-json", manifest["argv"])
        self.assertIn("tools/upstream-equivalent-gate.py", manifest["command_text"])
        self.assertEqual(len(manifest["command_hash"]), 64)
        self.assertIn("upstream_equivalent_gate.json", manifest["gate_artifact_paths"]["out_json"])
        self.assertIn("promotion-review evidence only", manifest["proof_boundary"])

    def test_missing_candidate_file_blocks_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "audit"
            repo = Path(td) / "repo"
            ws.mkdir()
            repo.mkdir()
            missing = ws / ".auditooor" / "control" / "candidates" / "missing.json"

            manifest = build_run_gate_plan(ws, candidate_file=missing, candidate_id="missing", cwd=repo)

        self.assertEqual(manifest["candidate_id"], "missing")
        self.assertEqual(manifest["candidate_path"], str(missing.resolve()))
        self.assertIn("candidate_file_missing", manifest["blocked_reasons"])
        self.assertTrue(manifest["dry_run"])
        self.assertFalse(manifest["would_execute"])

    def test_candidate_id_lookup_uses_normalized_candidate_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "audit"
            repo = root / "repo"
            ws.mkdir()
            repo.mkdir()
            candidate = ws / ".auditooor" / "control" / "candidates" / "oracle-lag.json"
            _write(candidate, json.dumps({"id": "oracle-lag", "title": "Oracle lag"}))
            report = ws / ".auditooor" / "control" / "candidates_report.json"
            _write(
                report,
                json.dumps(
                    {
                        "schema": "auditooor.control.candidates.v1",
                        "candidates": [
                            {
                                "id": "oracle-lag",
                                "title": "Oracle lag",
                                "status": "candidate",
                                "source_paths": ["src/Oracle.sol", str(candidate)],
                            }
                        ],
                    }
                ),
            )

            manifest = build_run_gate_plan(
                ws,
                candidate_id="oracle-lag",
                candidate_report=report,
                cwd=repo,
            )

        self.assertEqual(manifest["candidate_id"], "oracle-lag")
        self.assertEqual(manifest["candidate_path"], str(candidate.resolve()))
        self.assertEqual(manifest["candidate_source"], "candidate_report")
        self.assertEqual(manifest["blocked_reasons"], [])
        self.assertIn(str(candidate.resolve()), manifest["argv"])

    def test_build_plan_is_safe_no_execution_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "audit"
            repo = root / "repo"
            ws.mkdir()
            repo.mkdir()
            candidate = ws / ".auditooor" / "control" / "candidates" / "amp-zero.json"
            marker = ws / "SHOULD_NOT_EXIST"
            fake_gate = repo / "tools" / "upstream-equivalent-gate.py"
            _write(candidate, json.dumps({"id": "amp-zero"}))
            _write(
                fake_gate,
                "\n".join(
                    [
                        "#!/usr/bin/env python3",
                        "from pathlib import Path",
                        f"Path({str(marker)!r}).write_text('executed')",
                    ]
                )
                + "\n",
            )

            manifest = build_run_gate_plan(ws, candidate_file=candidate, cwd=repo)

            self.assertTrue(manifest["dry_run"])
            self.assertFalse(manifest["would_execute"])
            self.assertFalse(marker.exists())
            self.assertFalse(Path(manifest["gate_artifact_paths"]["stdout"]).exists())
            self.assertFalse(Path(manifest["gate_artifact_paths"]["stderr"]).exists())

    def test_explicit_execution_captures_stdout_stderr_and_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "audit"
            repo = root / "repo"
            ws.mkdir()
            repo.mkdir()
            candidate = ws / ".auditooor" / "control" / "candidates" / "amp-zero.json"
            fake_gate = repo / "tools" / "upstream-equivalent-gate.py"
            _write(candidate, json.dumps({"id": "amp-zero"}))
            _write(
                fake_gate,
                "\n".join(
                    [
                        "#!/usr/bin/env python3",
                        "import argparse, json, sys",
                        "parser = argparse.ArgumentParser()",
                        "parser.add_argument('--workspace')",
                        "parser.add_argument('--candidate')",
                        "parser.add_argument('--candidate-id')",
                        "parser.add_argument('--out-json')",
                        "args = parser.parse_args()",
                        "print('stdout ok')",
                        "print('stderr ok', file=sys.stderr)",
                        "with open(args.out_json, 'w', encoding='utf-8') as fh:",
                        "    json.dump({'verdict': 'passed'}, fh)",
                    ]
                )
                + "\n",
            )
            manifest = build_run_gate_plan(ws, candidate_file=candidate, cwd=repo)

            executed = execute_run_gate(manifest)

            self.assertFalse(executed["dry_run"])
            self.assertTrue(executed["would_execute"])
            self.assertEqual(executed["execution"]["status"], "succeeded")
            self.assertEqual(executed["gate_verdict"]["status"], "passed")
            self.assertEqual(Path(executed["execution"]["stdout_path"]).read_text(encoding="utf-8"), "stdout ok\n")
            self.assertEqual(Path(executed["execution"]["stderr_path"]).read_text(encoding="utf-8"), "stderr ok\n")
            self.assertTrue(Path(executed["execution"]["run_manifest_path"]).is_file())


if __name__ == "__main__":
    unittest.main()
