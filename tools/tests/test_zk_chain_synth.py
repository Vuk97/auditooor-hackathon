# <!-- r36-rebuttal: ZK-CHAIN-SYNTH lane; file declared in .auditooor/agent_pathspec.json -->
"""tests/test_zk_chain_synth.py - Unit tests for zk-chain-synth.py

Cases:
  1. no ZK soundness gaps -> status=no-gaps, chains_synthesized=0, no write.
  2. gaps from zk_hunt_queue.jsonl -> dry-run collects gaps + builds prompt,
     status=dry-run, no LLM call, no report written.
  3. gaps + --mock-llm -> report written to <ws>/.auditooor/zk_chain_synthesis_<date>.json
     with mock narrative (no network).
  4. de-dup: same gap id across zk_candidates_*.jsonl and zk_hunt_queue.jsonl
     collapses to a single gap.
  5. prompt content: build_synthesis_prompt enumerates every gap id + the JSON
     output contract.
  6. zk_candidates_*.jsonl precedence: most-recent candidates file is read.

LLM dispatch is mocked via --mock-llm (llm-dispatch --mock); no real network.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "zk-chain-synth.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("zk_chain_synth", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


zcs = _load_module()


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


class TestZkChainSynth(unittest.TestCase):
    def _ws(self, tmp: str) -> Path:
        ws = Path(tmp) / "ws"
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        return ws

    def test_no_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            report = zcs.run(ws, dry_run=False, mock_llm=True)
            self.assertEqual(report["status"], "no-gaps")
            self.assertEqual(report["gap_count"], 0)
            self.assertEqual(report["chains_synthesized"], 0)
            # No report file written.
            self.assertEqual(list((ws / ".auditooor").glob("zk_chain_synthesis_*.json")), [])

    def test_dry_run_collects_from_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            _write_jsonl(
                ws / ".auditooor" / "zk_hunt_queue.jsonl",
                [
                    {"finding_id": "15007", "bug_class": "missing-databus-constraint",
                     "fn": "verify_databus", "file_line": "src/verifier.rs:42",
                     "code_excerpt": "// no databus eq"},
                    {"finding_id": "18736", "bug_class": "partial-masking",
                     "fn": "mask_witness", "file_line": "src/mask.rs:88"},
                ],
            )
            report = zcs.run(ws, dry_run=True, now="2026-05-29T00:00:00Z")
            self.assertEqual(report["status"], "dry-run")
            self.assertEqual(report["gap_count"], 2)
            self.assertIn("15007", report["gap_ids"])
            self.assertIn("18736", report["gap_ids"])
            self.assertTrue(report["narrative"].get("dry_run"))
            # dry-run does not write.
            self.assertEqual(list((ws / ".auditooor").glob("zk_chain_synthesis_*.json")), [])

    def test_mock_llm_writes_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            _write_jsonl(
                ws / ".auditooor" / "zk_hunt_queue.jsonl",
                [
                    {"finding_id": "16623", "bug_class": "challenge-gen-gap",
                     "fn": "gen_challenge", "file_line": "src/fs.rs:12"},
                ],
            )
            env = {**os.environ, "MIMO_API_KEY": "dummy",
                   "MIMO_BASE_URL": "https://example.invalid",
                   "AUDITOOOR_LLM_NETWORK_CONSENT": "1"}
            with mock.patch.dict(os.environ, env, clear=True):
                report = zcs.run(ws, dry_run=False, now="2026-05-29T00:00:00Z", mock_llm=True)
            self.assertEqual(report["status"], "complete")
            self.assertEqual(report["gap_count"], 1)
            self.assertEqual(report["chains_synthesized"], 1)
            out = ws / ".auditooor" / "zk_chain_synthesis_2026-05-29.json"
            self.assertTrue(out.is_file())
            on_disk = json.loads(out.read_text())
            self.assertEqual(on_disk["schema"], "auditooor.zk_chain_synthesis_report.v1")
            # mock-mode narrative is non-JSON model text -> captured as raw.
            self.assertIn("raw", report["narrative"])

    def test_dedup_across_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            _write_jsonl(
                ws / ".auditooor" / "zk_candidates_2026-05-28T10-00-00Z.jsonl",
                [{"finding_id": "15007", "bug_class": "missing-databus-constraint",
                  "fn": "verify_databus", "file_line": "src/verifier.rs:42"}],
            )
            _write_jsonl(
                ws / ".auditooor" / "zk_hunt_queue.jsonl",
                [{"finding_id": "15007", "bug_class": "missing-databus-constraint",
                  "fn": "verify_databus", "file_line": "src/verifier.rs:42"}],
            )
            gaps = zcs.collect_soundness_gaps(ws)
            self.assertEqual(len(gaps), 1)
            self.assertEqual(gaps[0]["gap_id"], "15007")

    def test_prompt_enumerates_gaps(self):
        gaps = [
            {"gap_id": "15007", "bug_class": "missing-databus-constraint", "fn": "a",
             "file_line": "x:1", "code_excerpt": "", "soundness_invariant": "INV-DB", "note": ""},
            {"gap_id": "18736", "bug_class": "partial-masking", "fn": "b",
             "file_line": "y:2", "code_excerpt": "", "soundness_invariant": "", "note": "n"},
        ]
        prompt = zcs.build_synthesis_prompt("aztec", gaps)
        self.assertIn("15007", prompt)
        self.assertIn("18736", prompt)
        self.assertIn("composes", prompt)
        self.assertIn("soundness_invariant_broken", prompt)
        self.assertIn("forged-proof-acceptance", prompt)

    def test_candidates_precedence_most_recent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            _write_jsonl(
                ws / ".auditooor" / "zk_candidates_2026-05-27T10-00-00Z.jsonl",
                [{"finding_id": "OLD-1", "bug_class": "old", "fn": "o", "file_line": "o:1"}],
            )
            _write_jsonl(
                ws / ".auditooor" / "zk_candidates_2026-05-28T10-00-00Z.jsonl",
                [{"finding_id": "NEW-1", "bug_class": "new", "fn": "n", "file_line": "n:1"}],
            )
            gaps = zcs.collect_soundness_gaps(ws)
            ids = [g["gap_id"] for g in gaps]
            self.assertIn("NEW-1", ids)
            self.assertNotIn("OLD-1", ids)


if __name__ == "__main__":
    unittest.main()
