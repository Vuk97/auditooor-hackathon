#!/usr/bin/env python3
"""Tests for tools/cross-lane-correlate.py."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "cross-lane-correlate.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("cross_lane_correlate_test_subject", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class CrossLaneCorrelateTests(unittest.TestCase):
    def _write_candidate(
        self,
        root: Path,
        *,
        name: str,
        lane: str,
        files: list[str],
    ) -> None:
        (root / f"{name}.json").write_text(json.dumps({
            "schema_version": "deep_candidate.v1",
            "lane": lane,
            "candidate_id": name,
            "files": files,
            "claim": "claim",
            "trigger": "trigger",
            "impact": "impact",
            "reproduction": "repro",
            "confidence": "low",
            "promotion_status": "investigate",
        }))

    def test_joins_three_candidates_by_same_file(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            candidates = ws / "deep_candidates"
            candidates.mkdir()
            self._write_candidate(candidates, name="math-1", lane="math", files=["src/Vault.sol:42"])
            self._write_candidate(candidates, name="fuzz-1", lane="fuzz", files=["src/Vault.sol"])
            self._write_candidate(candidates, name="source-1", lane="source_mine", files=["./src/Vault.sol"])
            self._write_candidate(candidates, name="crypto-1", lane="crypto", files=["src/Verifier.sol"])

            payload = tool.build_payload(ws)

            self.assertEqual(payload["candidate_count"], 4)
            self.assertEqual(payload["correlation_count"], 1)
            corr = payload["correlations"][0]
            self.assertEqual(corr["file"], "src/Vault.sol")
            self.assertEqual(corr["lanes"], ["fuzz", "math", "source_mine"])
            self.assertEqual(corr["candidate_count"], 3)

    def test_empty_workspace_is_friendly(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            out_json = ws / ".audit_logs" / "cross_lane_correlations.json"
            out_md = ws / ".audit_logs" / "cross_lane_correlations.md"
            payload = tool.build_payload(ws)
            tool.write_payload(payload, out_json=out_json, out_md=out_md)

            self.assertEqual(payload["correlations"], [])
            self.assertIn("No cross-lane", out_md.read_text())
            self.assertEqual(json.loads(out_json.read_text())["correlation_count"], 0)


if __name__ == "__main__":
    unittest.main()
