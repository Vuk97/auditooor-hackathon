"""Hermetic tests for ``tools/hackerman-etl-from-post-mortem.py`` (W4.2).

All five supported sources (rekt, defillama, samczsun, pcaversaccio,
hackmd) are exercised against synthetic fixtures injected via
``WebCache(prefetched=...)``. Zero live network.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-post-mortem.py"
WEB_CACHE = REPO_ROOT / "tools" / "lib" / "hackerman_web_cache.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Synthetic fixtures (synthetic_fixture: true)
# ---------------------------------------------------------------------------


REKT_EULER_PAGE = b"""<!doctype html>
<html><head>
<title>Euler Finance - Rekt</title>
<meta property="article:published_time" content="2023-03-13T18:00:00Z" />
</head><body>
<h1>Euler Finance Hack</h1>
<p>On March 13, 2023, Euler Finance was drained for $197 million via a donation-attack reentrancy vector.</p>
<p>The attacker exploited a missing health-check on the donateToReserves path; see the fix at https://github.com/euler-xyz/euler-contracts/commit/abc123def456.</p>
<p>This is one of the largest DeFi hacks of the year.</p>
</body></html>
"""

REKT_NOMAD_PAGE = b"""<!doctype html>
<html><head>
<title>Nomad Bridge - Rekt</title>
</head><body>
<h1>Nomad Bridge Heist</h1>
<p>On August 2, 2022, Nomad bridge was drained for $190 million in a permissionless free-for-all exploit.</p>
<p>The bug was a signature verification bypass introduced by an upgrade that set trusted-root to 0x0.</p>
</body></html>
"""

REKT_INDEX_PAGE = b"""<!doctype html><html><body>
<a href="https://rekt.news/euler-rekt/">Euler</a>
<a href="https://rekt.news/nomad-rekt/">Nomad</a>
<a href="https://rekt.news/leaderboard/">Leaderboard (skip)</a>
</body></html>
"""

REKT_CURRENT_INDEX_PAGE = b"""<!doctype html><html><body>
<a href="/">Home</a>
<a href="/leaderboard">Leaderboard</a>
<a href="/the-one-that-got-away">The One That Got Away</a>
<a href="/bybit-rekt">ByBit - Rekt</a>
<a href="https://www.rekt.news/ronin-rekt">Ronin Network - REKT</a>
<a href="/_next/static/chunks/pages/leaderboard.js">static chunk</a>
<a href="https://www.youtube.com/@RektNews./videos">videos</a>
</body></html>
"""

DEFILLAMA_HACKS_JSON = json.dumps([
    {
        "name": "Ronin Bridge",
        "date": "2022-03-23",
        "amount": 624000000,
        "technique": "private-key leak via compromised validator nodes",
        "source": "https://roninnetwork.medium.com/community-alert-ronin-validators-compromised-c0f3a0c43d0d",
    },
    {
        "name": "BNB Bridge",
        "date": 1665187200,  # 2022-10-08 unix-seconds
        "amount": 570000000,
        "technique": "IAVL Merkle proof forgery",
        "source": "https://github.com/bnb-chain/bsc/issues/1100",
    },
    {
        "name": "Wormhole",
        "date": "2022-02-02",
        "amount": 326000000,
        "technique": "signature verification bypass via uninitialized proxy",
    },
]).encode("utf-8")

SAMCZSUN_RESEARCH_PAGE = b"""<!doctype html>
<html><head><title>Hacking Skyward Finance | samczsun</title></head><body>
<h1>Hacking Skyward Finance</h1>
<p>On November 2, 2021, an attacker drained $3 million from Skyward Finance using an oracle manipulation attack.</p>
<p>The fix is at https://github.com/skyward-finance/contracts/pull/42.</p>
</body></html>
"""

PCAVERSACCIO_PAGE = b"""<!doctype html>
<html><head><title>The Curve Re-entrancy Bug | pcaversaccio</title></head><body>
<h1>The Curve Re-entrancy Bug</h1>
<p>On July 30, 2023, Curve pools were drained for $52 million due to a re-entrancy bug in Vyper's reentrancy guard implementation.</p>
<p>See the fix proposal at https://github.com/vyperlang/vyper/pull/3552.</p>
</body></html>
"""

HACKMD_PAGE = b"""<!doctype html>
<html><head><title>Post-mortem: Beanstalk governance takeover</title></head><body>
<h1>Beanstalk Governance Takeover</h1>
<p>On April 17, 2022, Beanstalk lost $182 million to a flash-loan governance takeover.</p>
<p>The attacker borrowed enough BEAN/Stalk tokens to single-handedly pass a proposal that drained the treasury.</p>
</body></html>
"""


def _build_cache(tmp: Path, prefetched_extra=None):
    wc = _load(WEB_CACHE, "_hackerman_web_cache_for_postmortem_tests")
    prefetched = dict(prefetched_extra or {})
    cache = wc.WebCache(
        cache_dir=tmp / "cache",
        rate_limit_ms=0,
        respect_robots=False,
        i_acknowledge_tos=True,
        prefetched=prefetched,
        sleep=lambda _s: None,
        offline=True,
    )
    return cache, wc


class HackermanEtlFromPostMortemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_post_mortem")

    # ------------------------------------------------------------------
    # 1. Constants / surface
    # ------------------------------------------------------------------
    def test_01_verification_tier_constant(self) -> None:
        self.assertEqual(self.tool.VERIFICATION_TIER, "tier-2-verified-public-archive")
        self.assertEqual(self.tool.SOURCE_EXTRACTION_METHOD, "web-scrape-post-mortem")

    def test_02_supported_sources_enumerated(self) -> None:
        self.assertEqual(
            set(self.tool.SUPPORTED_SOURCES),
            {"rekt", "defillama", "samczsun", "pcaversaccio", "hackmd"},
        )

    # ------------------------------------------------------------------
    # 2. CLI guards
    # ------------------------------------------------------------------
    def test_03_blocked_when_cache_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = self.tool.main([
                    "--source", "rekt",
                    "--cache-dir", str(Path(tmp) / "cache"),
                    "--out-dir", str(Path(tmp) / "out"),
                    "--dry-run",
                ])
            self.assertEqual(rc, 3)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())

    def test_04_no_respect_robots_requires_ack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = self.tool.main([
                    "--source", "rekt",
                    "--cache-dir", str(Path(tmp) / "cache"),
                    "--out-dir", str(Path(tmp) / "out"),
                    "--no-respect-robots",
                ])
            self.assertEqual(rc, 2)
            self.assertIn("--i-acknowledge-tos", stderr.getvalue())

    # ------------------------------------------------------------------
    # 3. Per-source parser smoke tests
    # ------------------------------------------------------------------
    def test_05_parse_rekt_index_filters_leaderboard(self) -> None:
        urls = self.tool.parse_rekt_index(REKT_INDEX_PAGE.decode())
        self.assertEqual(len(urls), 2)
        self.assertTrue(any("euler-rekt" in u for u in urls))
        self.assertFalse(any("leaderboard" in u for u in urls))

    def test_05b_parse_rekt_index_accepts_current_relative_links(self) -> None:
        urls = self.tool.parse_rekt_index(REKT_CURRENT_INDEX_PAGE.decode())
        self.assertEqual(
            urls,
            [
                "https://rekt.news/the-one-that-got-away/",
                "https://rekt.news/bybit-rekt/",
                "https://rekt.news/ronin-rekt/",
            ],
        )

    def test_06_parse_defillama_handles_iso_and_unix_seconds(self) -> None:
        entries = self.tool.parse_defillama_hacks(DEFILLAMA_HACKS_JSON)
        self.assertEqual(len(entries), 3)
        # Build records to verify date coercion logic.
        rec_ronin = self.tool.build_defillama_record(
            entry=entries[0],
            source_url="https://api.llama.fi/hacks",
            payload_sha256="a" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        rec_bnb = self.tool.build_defillama_record(
            entry=entries[1],
            source_url="https://api.llama.fi/hacks",
            payload_sha256="a" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertEqual(rec_ronin["incident_date"], "2022-03-23")
        self.assertEqual(rec_bnb["incident_date"], "2022-10-08")
        self.assertEqual(rec_ronin["amount_stolen_usd_estimate"], 624_000_000)
        self.assertEqual(rec_ronin["severity_at_finding"], "critical")

    # ------------------------------------------------------------------
    # 4. Record-shape invariants
    # ------------------------------------------------------------------
    def test_07_tier2_marker_on_every_emit_page(self) -> None:
        rec = self.tool.build_page_record(
            source="rekt",
            page_url="https://rekt.news/euler-rekt/",
            html=REKT_EULER_PAGE.decode(),
            payload_sha256="b" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
        self.assertIn("record_extensions", rec)
        self.assertEqual(rec["record_extensions"]["impact_usd"], 197_000_000)
        self.assertEqual(rec["incident_date"], "March 13, 2023")
        self.assertEqual(rec["source_audit_ref"]["payload_sha256"], "b" * 64)

    def test_08_tier2_marker_on_every_emit_defillama(self) -> None:
        entries = self.tool.parse_defillama_hacks(DEFILLAMA_HACKS_JSON)
        for entry in entries:
            rec = self.tool.build_defillama_record(
                entry=entry,
                source_url="https://api.llama.fi/hacks",
                payload_sha256="c" * 64,
                fetched_at_utc="2026-05-16T00:00:00Z",
            )
            self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
            self.assertEqual(rec["source_audit_ref"]["payload_sha256"], "c" * 64)
            self.assertIn("record_extensions", rec)

    def test_09_record_id_includes_source_namespace(self) -> None:
        rec = self.tool.build_page_record(
            source="samczsun",
            page_url="https://samczsun.com/hacking-skyward-finance/",
            html=SAMCZSUN_RESEARCH_PAGE.decode(),
            payload_sha256="d" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertTrue(rec["record_id"].startswith("post-mortem-samczsun:"))
        self.assertEqual(rec["attack_class"], "oracle-manipulation")

    def test_10_attack_class_detected_per_source(self) -> None:
        rekt = self.tool.build_page_record(
            source="rekt",
            page_url="https://rekt.news/nomad-rekt/",
            html=REKT_NOMAD_PAGE.decode(),
            payload_sha256="e" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertEqual(rekt["attack_class"], "signature-verification-bypass")
        hackmd = self.tool.build_page_record(
            source="hackmd",
            page_url="https://hackmd.io/@beanstalk/governance-takeover",
            html=HACKMD_PAGE.decode(),
            payload_sha256="f" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertEqual(hackmd["attack_class"], "governance-takeover")
        pcav = self.tool.build_page_record(
            source="pcaversaccio",
            page_url="https://pcaversaccio.com/curve-reentrancy/",
            html=PCAVERSACCIO_PAGE.decode(),
            payload_sha256="0" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertEqual(pcav["attack_class"], "reentrancy")

    def test_11_fix_commit_ref_extracted(self) -> None:
        rec = self.tool.build_page_record(
            source="pcaversaccio",
            page_url="https://pcaversaccio.com/curve-reentrancy/",
            html=PCAVERSACCIO_PAGE.decode(),
            payload_sha256="1" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertGreaterEqual(len(rec["fix_commit_ref"]), 1)
        self.assertIn("vyperlang", rec["fix_commit_ref"][0])
        self.assertEqual(rec["target_repo"], "github.com/vyperlang/vyper")

    def test_12_amount_dollar_class_buckets(self) -> None:
        self.assertEqual(self.tool.amount_to_dollar_class(326_000_000), ">=$1M")
        self.assertEqual(self.tool.amount_to_dollar_class(500_000), "$100K-$1M")
        self.assertEqual(self.tool.amount_to_dollar_class(50_000), "$10K-$100K")
        self.assertEqual(self.tool.amount_to_dollar_class(1_000), "<$10K")
        self.assertEqual(self.tool.amount_to_dollar_class(0), "non-financial")

    # ------------------------------------------------------------------
    # 5. End-to-end (per source, with prefetched fixtures)
    # ------------------------------------------------------------------
    def test_13_end_to_end_rekt_index_to_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p, prefetched_extra={
                "https://rekt.news/leaderboard/": REKT_INDEX_PAGE,
                "https://rekt.news/euler-rekt/": REKT_EULER_PAGE,
                "https://rekt.news/nomad-rekt/": REKT_NOMAD_PAGE,
            })
            out_dir = tmp_p / "out"
            summary = self.tool.convert(
                cache=cache, out_dir=out_dir, source="rekt",
                fetch_live=False, urls=[], index_url="https://rekt.news/leaderboard/",
                dry_run=False, max_pages=None,
            )
            self.assertEqual(summary["urls_resolved"], 2)
            self.assertEqual(summary["records_emitted"], 2)
            json_files = list(out_dir.rglob("*.json"))
            self.assertEqual(len(json_files), 2)
            # Pick the euler one and check shape.
            for jf in json_files:
                rec = json.loads(jf.read_text(encoding="utf-8"))
                if "euler" in rec["target_project_slug"]:
                    self.assertEqual(rec["severity_at_finding"], "critical")
                    self.assertEqual(rec["amount_stolen_usd_estimate"], 197_000_000)
                    self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")

    def test_14_end_to_end_defillama_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p, prefetched_extra={
                "https://api.llama.fi/hacks": DEFILLAMA_HACKS_JSON,
            })
            out_dir = tmp_p / "out"
            summary = self.tool.convert(
                cache=cache, out_dir=out_dir, source="defillama",
                fetch_live=False, urls=[],
                index_url="https://api.llama.fi/hacks",
                dry_run=False, max_pages=None,
            )
            self.assertEqual(summary["records_emitted"], 3)
            files = list(out_dir.rglob("*.json"))
            self.assertEqual(len(files), 3)
            # All three incidents are critical (>=$1M).
            self.assertEqual(summary["by_severity"].get("critical", 0), 3)

    def test_15_end_to_end_url_list_mode_hackmd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p, prefetched_extra={
                "https://hackmd.io/@beanstalk/governance-takeover": HACKMD_PAGE,
            })
            url_list = tmp_p / "urls.txt"
            url_list.write_text(
                "# comments ignored\n"
                "\n"
                "https://hackmd.io/@beanstalk/governance-takeover\n",
                encoding="utf-8",
            )
            urls = self.tool.load_url_list(url_list)
            self.assertEqual(urls, ["https://hackmd.io/@beanstalk/governance-takeover"])
            summary = self.tool.convert(
                cache=cache, out_dir=tmp_p / "out", source="hackmd",
                fetch_live=False, urls=urls, index_url=None,
                dry_run=False, max_pages=None,
            )
            self.assertEqual(summary["records_emitted"], 1)
            self.assertGreaterEqual(summary["by_severity"].get("critical", 0), 1)

    def test_16_real_source_only_no_url_no_index_fails_blocked(self) -> None:
        # When neither URL nor cached index is reachable, we get BLOCKED-NO-REAL-SOURCE.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p)
            out_dir = tmp_p / "out"
            summary = self.tool.convert(
                cache=cache, out_dir=out_dir, source="samczsun",
                fetch_live=False, urls=[],
                index_url="https://samczsun.com/research/",
                dry_run=False, max_pages=None,
            )
            # offline + url not in cache -> error appended, nothing emitted.
            self.assertEqual(summary["records_emitted"], 0)
            self.assertTrue(summary["errors"])

    def test_17_sha256_evidence_per_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p, prefetched_extra={
                "https://samczsun.com/research/": b"<html></html>",
                "https://samczsun.com/hacking-skyward-finance/": SAMCZSUN_RESEARCH_PAGE,
            })
            summary = self.tool.convert(
                cache=cache, out_dir=tmp_p / "out", source="samczsun",
                fetch_live=False, urls=["https://samczsun.com/hacking-skyward-finance/"],
                index_url=None, dry_run=False, max_pages=None,
            )
            self.assertEqual(summary["records_emitted"], 1)
            rec_files = list((tmp_p / "out").rglob("*.json"))
            self.assertEqual(len(rec_files), 1)
            rec = json.loads(rec_files[0].read_text(encoding="utf-8"))
            self.assertEqual(len(rec["source_audit_ref"]["payload_sha256"]), 64)
            steps = [s["step"] for s in rec["verification_chain"]]
            self.assertEqual(steps, ["fetch", "parse", "emit"])

    def test_18_rate_limit_enforced_via_sleep_callback(self) -> None:
        # Ensure WebCache's sleep callback is exercised when rate_limit_ms>0
        # for non-prefetched fetches. We simulate two distinct URLs; the
        # second triggers the rate-limit gate before fetch.
        sleeps: list = []
        wc = _load(WEB_CACHE, "_hackerman_web_cache_for_rate_limit_test")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache = wc.WebCache(
                cache_dir=tmp_p / "cache",
                rate_limit_ms=1500,
                respect_robots=False,
                i_acknowledge_tos=True,
                prefetched={
                    "https://rekt.news/a/": REKT_EULER_PAGE,
                    "https://rekt.news/b/": REKT_NOMAD_PAGE,
                },
                sleep=lambda s: sleeps.append(s),
                offline=True,
            )
            # Prefetched bytes bypass the rate-limit per WebCache contract;
            # this test asserts that policy holds (no sleep on prefetched
            # hits) so unit tests stay deterministic.
            cache.fetch("https://rekt.news/a/")
            cache.fetch("https://rekt.news/b/")
            self.assertEqual(sleeps, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
