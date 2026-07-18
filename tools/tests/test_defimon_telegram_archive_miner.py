"""Tests for tools/defimon-telegram-archive-miner.py."""

# r36-rebuttal: registered to lane DEFIMON-TG-BACKFILL in .auditooor/agent_pathspec.json

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MINER_PATH = REPO_ROOT / "tools" / "defimon-telegram-archive-miner.py"
FIXTURE_PATH = (
    REPO_ROOT / "tools" / "tests" / "fixtures" / "defimon_telegram_sample_page.html"
)


def _load_miner():
    spec = importlib.util.spec_from_file_location(
        "defimon_telegram_archive_miner", MINER_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["defimon_telegram_archive_miner"] = mod
    spec.loader.exec_module(mod)
    return mod


class ClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.miner = _load_miner()

    def test_skip_empty_post(self) -> None:
        post = {"post_id": 1, "datetime": "", "text": ""}
        cls = self.miner.classify_post(post)
        self.assertEqual(cls["verdict"], "skip")
        self.assertEqual(cls["reason"], "empty-or-trivial")

    def test_skip_return_request_post(self) -> None:
        # The return-request boilerplate fires the SKIP keyword path.
        post = {
            "post_id": 100,
            "datetime": "2026-05-01T00:00:00+00:00",
            "text": (
                "Onchain message: To the Renegade exploiter, please return "
                "the funds. White hat reward of 10%. You have 24 hours to "
                "contact us. Legal warning otherwise."
            ),
        }
        cls = self.miner.classify_post(post)
        self.assertEqual(cls["verdict"], "skip")
        self.assertEqual(cls["reason"], "negotiation-or-monitoring")

    def test_skip_unpause_alert(self) -> None:
        post = {
            "post_id": 101,
            "datetime": "",
            "text": "Kelp DAO LRTOracle is now unpaused. Monitoring resumed.",
        }
        cls = self.miner.classify_post(post)
        self.assertEqual(cls["verdict"], "skip")
        self.assertEqual(cls["reason"], "negotiation-or-monitoring")

    def test_skip_small_mev(self) -> None:
        post = {
            "post_id": 102,
            "datetime": "",
            "text": "Small MEV sandwich detected: $200 profit on Uniswap V3.",
        }
        cls = self.miner.classify_post(post)
        self.assertEqual(cls["verdict"], "skip")
        self.assertEqual(cls["reason"], "small-mev")

    def test_keep_renegade_initialize_incident(self) -> None:
        post = {
            "post_id": 3003,
            "datetime": "2026-05-12T10:00:00+00:00",
            "text": (
                "Renegade incident summary: a dangling public initialize() "
                "entrypoint was left after a Stylus proxy upgrade. An attacker "
                "exploited the unprotected initializer to drain funds. Loss "
                "of about $209K. Project: renegade.fi proxy 0x"
                "1234567890abcdef1234567890abcdef12345678."
            ),
        }
        cls = self.miner.classify_post(post)
        self.assertEqual(cls["verdict"], "keep")
        self.assertEqual(cls["attack_class"], "unprotected-initializer")
        self.assertGreaterEqual(cls["amount_usd"] or 0.0, 200_000.0)
        # 209K is between $25K and $250K -> medium tier
        self.assertEqual(cls["severity_heuristic"], "medium")
        self.assertIn("renegade", cls["target_hint"])

    def test_keep_transit_callbytes_incident(self) -> None:
        post = {
            "post_id": 3018,
            "datetime": "",
            "text": (
                "Transit.finance was hacked for about $1.8M. The "
                "TransitMixSwapBridge callBytes(bytes) function forwards "
                "attacker calldata to itself, enabling a crafted "
                "USDT.transferFrom call to drain victim approvals. "
                "Contract 0xabcdef1234567890abcdef1234567890abcdef12."
            ),
        }
        cls = self.miner.classify_post(post)
        self.assertEqual(cls["verdict"], "keep")
        self.assertEqual(cls["attack_class"], "router-self-call-arbitrary-target")
        # $1.8M -> critical
        self.assertEqual(cls["severity_heuristic"], "critical")

    def test_severity_thresholds(self) -> None:
        # $30K -> medium
        post_med = {
            "post_id": 200,
            "datetime": "",
            "text": "Project Foo was exploited for $30K via reentrancy attack.",
        }
        self.assertEqual(
            self.miner.classify_post(post_med)["severity_heuristic"], "medium"
        )
        # $500K -> high
        post_high = {
            "post_id": 201,
            "datetime": "",
            "text": "Project Bar drained for $500K via oracle manipulation.",
        }
        self.assertEqual(
            self.miner.classify_post(post_high)["severity_heuristic"], "high"
        )
        # $5M -> critical
        post_crit = {
            "post_id": 202,
            "datetime": "",
            "text": "Project Baz hacked for $5M via flash loan price manipulation.",
        }
        self.assertEqual(
            self.miner.classify_post(post_crit)["severity_heuristic"], "critical"
        )


class SlugAndYamlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.miner = _load_miner()

    def test_slug_format(self) -> None:
        slug = self.miner.build_slug(3018, "Transit.Finance")
        self.assertEqual(slug, "defimon-tg-3018-transit-finance")

    def test_record_id(self) -> None:
        rid = self.miner.build_record_id(3018, "Transit.Finance")
        self.assertEqual(rid, "defimon-telegram:3018:transit-finance")

    def test_record_yaml_schema(self) -> None:
        post = {
            "post_id": 3003,
            "datetime": "2026-05-12T10:00:00+00:00",
            "text": "Renegade exploited via unprotected initialize() for $209K.",
        }
        cls = self.miner.classify_post(post)
        yaml_text = self.miner.render_record_yaml(
            post=post, classification=cls, dedup_hits=[]
        )
        self.assertIn("schema_version: auditooor.hackerman_record.v1.1", yaml_text)
        self.assertIn("verification_tier: tier-2-verified-public-archive", yaml_text)
        self.assertIn("source_url:", yaml_text)
        self.assertIn("https://t.me/defimon_alerts/3003", yaml_text)
        # r36-rebuttal: test file registered under DEFIMON-TG-BACKFILL pathspec
        self.assertIn("2026-05-12", yaml_text)
        self.assertIn("attack_class:", yaml_text)
        self.assertIn("fix_commit_refs: []", yaml_text)


class PageParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.miner = _load_miner()
        cls.body = FIXTURE_PATH.read_text(encoding="utf-8")

    def test_fixture_exists(self) -> None:
        self.assertTrue(FIXTURE_PATH.exists(), f"Missing fixture {FIXTURE_PATH}")

    def test_parse_page_yields_posts(self) -> None:
        page = self.miner.parse_page(self.body)
        self.assertGreaterEqual(len(page["posts"]), 4)
        ids = {p["post_id"] for p in page["posts"]}
        # Fixture explicitly contains these 5 post ids (3003 synthetic + the
        # 4 cached real posts: 3025, 3034, 3037, 3038)
        for expected in (3003, 3025, 3034, 3037, 3038):
            self.assertIn(expected, ids, f"Expected post {expected} in fixture")

    def test_parse_page_extracts_text(self) -> None:
        page = self.miner.parse_page(self.body)
        by_id = {p["post_id"]: p for p in page["posts"]}
        renegade = by_id[3003]
        self.assertIn("renegade", renegade["text"].lower())
        self.assertIn("initialize", renegade["text"].lower())
        # datetime extracted
        self.assertTrue(renegade["datetime"].startswith("2026-05-12"))

    def test_parse_page_detects_older_cursor(self) -> None:
        page = self.miner.parse_page(self.body)
        self.assertEqual(page["older_cursor"], 3025)

    def test_end_to_end_classify(self) -> None:
        page = self.miner.parse_page(self.body)
        kept = []
        for post in page["posts"]:
            cls = self.miner.classify_post(post)
            if cls["verdict"] == "keep":
                kept.append((post["post_id"], cls))
        kept_ids = {pid for pid, _ in kept}
        # Renegade synthetic = keep; LunarBase 3038 (MEV-bot with $20K) keep
        # if mechanics_signals >= 2 (it has WETH/USDC pool addresses).
        self.assertIn(3003, kept_ids)


class CursorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.miner = _load_miner()

    def test_cursor_written(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cursor_path = Path(td) / "cursor.json"
            self.miner.update_cursor(
                cursor_path, oldest=2900, newest=3045, dry_run=False
            )
            data = json.loads(cursor_path.read_text(encoding="utf-8"))
            self.assertEqual(data["channel"], "defimon_alerts")
            self.assertEqual(data["oldest_post_id_mined"], 2900)
            self.assertEqual(data["newest_post_id_mined"], 3045)
            self.assertIn("last_run_utc", data)

    def test_cursor_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cursor_path = Path(td) / "cursor.json"
            self.miner.update_cursor(
                cursor_path, oldest=2900, newest=3045, dry_run=True
            )
            self.assertFalse(cursor_path.exists())


if __name__ == "__main__":
    unittest.main()
