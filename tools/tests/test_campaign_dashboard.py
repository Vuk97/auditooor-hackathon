#!/usr/bin/env python3
"""Tests for tools/campaign-dashboard.py."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "campaign-dashboard.py"


def _load_dashboard():
    spec = importlib.util.spec_from_file_location("campaign_dashboard_test_subject", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class CampaignDashboardTests(unittest.TestCase):
    def test_empty_corpus_writes_friendly_dashboard(self) -> None:
        tool = _load_dashboard()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_json = root / "dashboard.json"
            out_md = root / "dashboard.md"
            payload = tool.build_dashboard(
                audits_dir=root / "no-audits",
                dispatch_log=root / "missing-dispatch.jsonl",
                submission_log=root / "missing-submissions.jsonl",
            )
            tool.write_outputs(payload, out_json=out_json, out_md=out_md)

            self.assertEqual(payload["schema_version"], "auditooor.campaign_dashboard.v1")
            self.assertEqual(payload["rows"], [])
            self.assertIn("No campaign data found", out_md.read_text())
            self.assertEqual(json.loads(out_json.read_text())["rows"], [])

    def test_synthetic_workspace_aggregates_detector_outcome(self) -> None:
        tool = _load_dashboard()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "audits" / "demo"
            campaign = ws / ".auditooor" / "campaigns" / "src-001"
            campaign.mkdir(parents=True)
            (campaign / "summary.json").write_text(json.dumps({
                "campaign_id": "src-001",
                "lane": "source_mine",
                "survivors": [],
                "rejections": [],
            }))

            deep_dir = ws / "deep_candidates"
            deep_dir.mkdir(parents=True)
            (deep_dir / "source_mine_001.json").write_text(json.dumps({
                "schema_version": "deep_candidate.v1",
                "lane": "source_mine",
                "candidate_id": "cand-1",
                "confidence": "medium",
                "promotion_status": "investigate",
                "lane_payload": {"tool": "detector-alpha"},
            }))

            dispatch_log = root / "dispatch.jsonl"
            dispatch_log.write_text(json.dumps({
                "schema_version": "campaign-dispatch.v1",
                "campaign_id": "src-001",
                "lane": "source_mine",
                "provider": "kimi",
                "model": "kimi-for-coding",
                "tokens_used": 12,
                "outcome": "ok",
            }) + "\n")

            submission_log = root / "submissions.jsonl"
            submission_log.write_text(json.dumps({
                "schema_version": "campaign-submission.v1",
                "finding_id": "F-1",
                "workspace": str(ws),
                "candidate_id": "cand-1",
                "source_campaign_id": "src-001",
                "fuzz_campaign_id": None,
                "symbolic_campaign_id": None,
                "deep_campaign_id": None,
                "triager_outcome": "accepted",
                "scope_verdict": "in-scope",
                "confidence_at_submission": "high",
            }) + "\n")

            payload = tool.build_dashboard(
                audits_dir=root / "audits",
                dispatch_log=dispatch_log,
                submission_log=submission_log,
            )
            rows = {row["detector"]: row for row in payload["rows"]}
            self.assertIn("detector-alpha", rows)
            row = rows["detector-alpha"]
            self.assertEqual(row["candidates_emitted"], 1)
            self.assertEqual(row["survivors"], 1)
            self.assertEqual(row["submissions"], 1)
            self.assertEqual(row["accepted"], 1)
            self.assertEqual(row["confidence_drift"], 0.4)

    def test_sort_order_is_submissions_then_survivors_then_detector(self) -> None:
        tool = _load_dashboard()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "audits" / "demo"
            deep_dir = ws / "deep_candidates"
            deep_dir.mkdir(parents=True)
            docs = [
                ("a", "det-b", "investigate"),
                ("b", "det-a", "investigate"),
                ("c", "det-c", "hold"),
            ]
            for cid, det, promo in docs:
                (deep_dir / f"{cid}.json").write_text(json.dumps({
                    "schema_version": "deep_candidate.v1",
                    "lane": "source_mine",
                    "candidate_id": cid,
                    "confidence": "low",
                    "promotion_status": promo,
                    "lane_payload": {"tool": det},
                }))
            sub_log = root / "subs.jsonl"
            sub_log.write_text(json.dumps({
                "schema_version": "campaign-submission.v1",
                "finding_id": "F-a",
                "candidate_id": "b",
                "triager_outcome": "pending",
            }) + "\n")
            payload = tool.build_dashboard(
                audits_dir=root / "audits",
                dispatch_log=root / "dispatch.jsonl",
                submission_log=sub_log,
            )
            self.assertEqual(
                [row["detector"] for row in payload["rows"]],
                ["det-a", "det-b", "det-c"],
            )


if __name__ == "__main__":
    unittest.main()
