#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-provider-result.py"


class ZkBugsProviderResultTest(unittest.TestCase):
    def test_records_blocked_result_from_fenced_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brief = root / "brief.md"
            kimi = root / "kimi.out"
            minimax = root / "minimax.out"
            out = root / "result.json"
            out_md = root / "result.md"
            brief.write_text("# Brief\n", encoding="utf-8")
            kimi.write_text('```json\n{"verdict":"CANDIDATE"}\n```\n', encoding="utf-8")
            minimax.write_text(
                '```json\n{"verdict":"BLOCKER","blocker":"missing fixture",'
                '"codex_required_evidence":["vuln fixture","clean fixture"]}\n```\n',
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--brief",
                    str(brief),
                    "--kimi-output",
                    str(kimi),
                    "--minimax-output",
                    str(minimax),
                    "--out",
                    str(out),
                    "--out-md",
                    str(out_md),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["kimi_verdict"], "CANDIDATE")
            self.assertEqual(payload["minimax_verdict"], "BLOCKER")
            self.assertEqual(payload["promotion_status"], "blocked_by_minimax")
            self.assertIn("missing fixture", out_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
