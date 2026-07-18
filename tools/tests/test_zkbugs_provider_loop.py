#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-provider-loop.py"


class ZkBugsProviderLoopTest(unittest.TestCase):
    def test_dry_run_writes_manifest_without_live_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brief = root / "brief.md"
            kimi_prompt = root / "001_demo.kimi.md"
            minimax_template = root / "001_demo.minimax.template.md"
            queue = root / "queue.json"
            out = root / "out"
            brief.write_text("# Brief\n", encoding="utf-8")
            kimi_prompt.write_text("kimi prompt", encoding="utf-8")
            minimax_template.write_text("<PASTE_KIMI_JSON_HERE>", encoding="utf-8")
            queue.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "index": 1,
                                "brief": str(brief),
                                "kimi_prompt": str(kimi_prompt),
                                "minimax_prompt_template": str(minimax_template),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--queue",
                    str(queue),
                    "--out-dir",
                    str(out),
                    "--limit",
                    "1",
                    "--dry-run",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "zkbugs_provider_loop.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["summary"], {"ok": 1})
            row = manifest["rows"][0]
            self.assertEqual(row["kimi"]["command"][2:4], ["--provider", "kimi"])
            self.assertEqual(row["minimax"]["command"][2:4], ["--provider", "minimax"])
            self.assertEqual(row["record"]["status"], "dry-run")

    def test_fake_dispatch_records_provider_result_and_skips_existing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brief = root / "brief.md"
            kimi_prompt = root / "001_demo.kimi.md"
            minimax_template = root / "001_demo.minimax.template.md"
            queue = root / "queue.json"
            out = root / "out"
            fake_dispatch = root / "fake_dispatch.py"
            brief.write_text("# Brief\n", encoding="utf-8")
            kimi_prompt.write_text("kimi prompt", encoding="utf-8")
            minimax_template.write_text("Kimi: <PASTE_KIMI_JSON_HERE>", encoding="utf-8")
            queue.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "index": 1,
                                "brief": str(brief),
                                "kimi_prompt": str(kimi_prompt),
                                "minimax_prompt_template": str(minimax_template),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            fake_dispatch.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import argparse
                    import os
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--provider")
                    parser.add_argument("--prompt-file")
                    parser.add_argument("--max-tokens")
                    parser.add_argument("--timeout")
                    parser.add_argument("--audit-dir")
                    args = parser.parse_args()
                    env_provider = os.environ.get("AUDITOOOR_LLM_PROVIDER")
                    if env_provider != args.provider:
                        raise SystemExit(f"provider env mismatch: {env_provider} != {args.provider}")
                    if args.provider == "kimi":
                        print('```json\\n{"verdict":"CANDIDATE"}\\n```')
                    else:
                        print('```json\\n{"verdict":"KEEP_FOR_CODEX","codex_required_evidence":["fixture"]}\\n```')
                    """
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--queue",
                    str(queue),
                    "--out-dir",
                    str(out),
                    "--dispatch-tool",
                    str(fake_dispatch),
                    "--limit",
                    "1",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                    "AUDITOOOR_LLM_PROVIDER": "kimi",
                },
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(next((out / "final").glob("*.provider-result.json")).read_text(encoding="utf-8"))
            self.assertEqual(result["promotion_status"], "candidate_needs_codex_evidence")

            second = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--queue",
                    str(queue),
                    "--out-dir",
                    str(out),
                    "--dispatch-tool",
                    str(fake_dispatch),
                    "--limit",
                    "1",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"AUDITOOOR_LLM_NETWORK_CONSENT": "1"},
                check=False,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            manifest = json.loads((out / "zkbugs_provider_loop.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["summary"], {"skipped-existing-result": 1})

    def test_operator_live_consent_flag_is_passed_to_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brief = root / "brief.md"
            kimi_prompt = root / "001_demo.kimi.md"
            minimax_template = root / "001_demo.minimax.template.md"
            queue = root / "queue.json"
            out = root / "out"
            fake_dispatch = root / "fake_dispatch.py"
            brief.write_text("# Brief\n", encoding="utf-8")
            kimi_prompt.write_text("kimi prompt", encoding="utf-8")
            minimax_template.write_text("Kimi: <PASTE_KIMI_JSON_HERE>", encoding="utf-8")
            queue.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "index": 1,
                                "brief": str(brief),
                                "kimi_prompt": str(kimi_prompt),
                                "minimax_prompt_template": str(minimax_template),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            fake_dispatch.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import argparse
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--provider")
                    parser.add_argument("--prompt-file")
                    parser.add_argument("--max-tokens")
                    parser.add_argument("--timeout")
                    parser.add_argument("--audit-dir")
                    parser.add_argument("--operator-live-network-consent", action="store_true")
                    args = parser.parse_args()
                    if not args.operator_live_network_consent:
                        raise SystemExit("missing explicit operator consent flag")
                    if args.provider == "kimi":
                        print('```json\\n{"verdict":"CANDIDATE"}\\n```')
                    else:
                        print('```json\\n{"verdict":"KEEP_FOR_CODEX","codex_required_evidence":["fixture"]}\\n```')
                    """
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--queue",
                    str(queue),
                    "--out-dir",
                    str(out),
                    "--dispatch-tool",
                    str(fake_dispatch),
                    "--limit",
                    "1",
                    "--operator-live-network-consent",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={},
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "zkbugs_provider_loop.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["summary"], {"ok": 1})
            self.assertIn(
                "--operator-live-network-consent",
                manifest["rows"][0]["kimi"]["command"],
            )
            self.assertIn(
                "--operator-live-network-consent",
                manifest["rows"][0]["minimax"]["command"],
            )

    def test_zero_byte_provider_output_is_not_reused_on_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brief = root / "brief.md"
            kimi_prompt = root / "001_demo.kimi.md"
            minimax_template = root / "001_demo.minimax.template.md"
            queue = root / "queue.json"
            out = root / "out"
            fake_dispatch = root / "fake_dispatch.py"
            brief.write_text("# Brief\n", encoding="utf-8")
            kimi_prompt.write_text("kimi prompt", encoding="utf-8")
            minimax_template.write_text("Kimi: <PASTE_KIMI_JSON_HERE>", encoding="utf-8")
            queue.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "index": 1,
                                "brief": str(brief),
                                "kimi_prompt": str(kimi_prompt),
                                "minimax_prompt_template": str(minimax_template),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (out / "kimi").mkdir(parents=True)
            (out / "kimi" / "001_001_demo.kimi.out.json").write_text("", encoding="utf-8")
            fake_dispatch.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import argparse
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--provider")
                    parser.add_argument("--prompt-file")
                    parser.add_argument("--max-tokens")
                    parser.add_argument("--timeout")
                    parser.add_argument("--audit-dir")
                    args = parser.parse_args()
                    if args.provider == "kimi":
                        print('```json\\n{"verdict":"CANDIDATE"}\\n```')
                    else:
                        print('```json\\n{"verdict":"BLOCKER","blocker":"killed"}\\n```')
                    """
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--queue",
                    str(queue),
                    "--out-dir",
                    str(out),
                    "--dispatch-tool",
                    str(fake_dispatch),
                    "--limit",
                    "1",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"AUDITOOOR_LLM_NETWORK_CONSENT": "1"},
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            kimi_out = out / "kimi" / "001_001_demo.kimi.out.json"
            self.assertGreater(kimi_out.stat().st_size, 0)
            manifest = json.loads((out / "zkbugs_provider_loop.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["summary"], {"ok": 1})


if __name__ == "__main__":
    unittest.main()
