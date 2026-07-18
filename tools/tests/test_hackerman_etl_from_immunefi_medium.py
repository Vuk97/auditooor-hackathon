"""Hermetic tests for ``tools/hackerman-etl-from-immunefi-medium.py``.

Synthetic Atom-feed + Medium-post HTML fixtures injected via
``WebCache(prefetched=...)``; no live network calls.
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
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-immunefi-medium.py"
WEB_CACHE = REPO_ROOT / "tools" / "lib" / "hackerman_web_cache.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ATOM_FEED = b"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>Immunefi</title>
<entry>
  <title>Wormhole Uninitialized Proxy Bugfix Review</title>
  <link href="https://medium.com/immunefi/wormhole-uninitialized-proxy-bugfix-review-90250c41a43a"/>
</entry>
<entry>
  <title>Curve Re-entrancy Postmortem</title>
  <link href="https://medium.com/immunefi/curve-reentrancy-postmortem-aabbccddeeff"/>
</entry>
</feed>
"""

WORMHOLE_POST = b"""<!doctype html>
<html><head><title>Wormhole Uninitialized Proxy Bugfix Review</title>
<script type="application/ld+json">{
  "@type": "NewsArticle",
  "headline": "Wormhole Uninitialized Proxy Bugfix Review",
  "datePublished": "2022-02-15T10:00:00Z",
  "author": {"name": "Immunefi Team"},
  "articleBody": "On February 3, 2022, Wormhole experienced a $326 million exploit. The attacker used a signature verification bypass via an uninitialized proxy. The fix was deployed at https://github.com/wormhole-foundation/wormhole/pull/745 and the patch commit is https://github.com/wormhole-foundation/wormhole/commit/abc123def456."
}</script>
</head>
<body>
<h1>Wormhole Uninitialized Proxy Bugfix Review</h1>
<h2>Wormhole</h2>
<p>On February 3, 2022, Wormhole experienced a $326 million exploit.</p>
<p>The attacker used a signature verification bypass via an uninitialized proxy.</p>
<p>The fix was deployed at https://github.com/wormhole-foundation/wormhole/pull/745</p>
</body></html>
"""

CURVE_POST = b"""<!doctype html>
<html><head><title>Curve Re-entrancy Postmortem</title>
<script type="application/ld+json">{
  "@type": "BlogPosting",
  "headline": "Curve Re-entrancy Postmortem",
  "datePublished": "2023-07-30T08:00:00Z",
  "articleBody": "On July 30 2023, Curve pools were drained for $52 million via a reentrancy bug in Vyper's reentrancy guard."
}</script>
</head><body>
<h1>Curve Re-entrancy Postmortem</h1>
<h2>Curve</h2>
<p>On July 30 2023, Curve pools were drained for $52 million via a reentrancy bug.</p>
</body></html>
"""


def _build_cache(tmp: Path):
    wc = _load(WEB_CACHE, "_hackerman_web_cache_for_medium_tests")
    prefetched = {
        "https://medium.com/feed/immunefi": ATOM_FEED,
        "https://medium.com/immunefi/wormhole-uninitialized-proxy-bugfix-review-90250c41a43a": WORMHOLE_POST,
        "https://medium.com/immunefi/curve-reentrancy-postmortem-aabbccddeeff": CURVE_POST,
    }
    cache = wc.WebCache(
        cache_dir=tmp / "cache",
        rate_limit_ms=0,
        respect_robots=False,
        i_acknowledge_tos=True,
        prefetched=prefetched,
        sleep=lambda _s: None,
    )
    return cache, wc


class HackermanEtlImmunefiMediumTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_immunefi_medium")

    def test_verification_tier_constant(self) -> None:
        self.assertEqual(self.tool.VERIFICATION_TIER, "tier-2-verified-public-archive")
        self.assertEqual(self.tool.SOURCE_EXTRACTION_METHOD, "web-scrape-medium-jsonld")

    def test_default_rate_limit_2000ms(self) -> None:
        self.assertEqual(self.tool.DEFAULT_RATE_LIMIT_MS, 2000)

    def test_blocked_when_cache_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = self.tool.main([
                    "--cache-dir", str(Path(tmp) / "cache"),
                    "--out-dir", str(Path(tmp) / "out"),
                    "--dry-run",
                ])
            self.assertEqual(rc, 3)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())

    def test_parse_atom_feed(self) -> None:
        urls = self.tool.parse_feed(ATOM_FEED.decode())
        self.assertEqual(len(urls), 2)
        self.assertIn("wormhole", urls[0])

    def test_extract_jsonld(self) -> None:
        blocks = self.tool.extract_jsonld(WORMHOLE_POST.decode())
        self.assertTrue(blocks)
        self.assertEqual(blocks[0]["@type"], "NewsArticle")

    def test_extract_amount_stolen(self) -> None:
        paragraphs = ["On February 3, 2022, Wormhole experienced a $326 million exploit."]
        amount, conf, _literal = self.tool.extract_amount_stolen(paragraphs)
        self.assertEqual(amount, 326_000_000)
        self.assertEqual(conf, "medium")

    def test_extract_attack_class_signature_bypass(self) -> None:
        klass = self.tool.extract_attack_class(WORMHOLE_POST.decode())
        self.assertEqual(klass, "signature-verification-bypass")

    def test_extract_attack_class_reentrancy(self) -> None:
        klass = self.tool.extract_attack_class(CURVE_POST.decode())
        self.assertEqual(klass, "reentrancy")

    def test_extract_fix_commit_refs(self) -> None:
        refs = self.tool.extract_fix_commit_refs(WORMHOLE_POST.decode())
        # one PR + one commit referenced.
        self.assertGreaterEqual(len(refs), 1)
        joined = " ".join(refs)
        self.assertIn("wormhole-foundation/wormhole", joined)

    def test_severity_from_amount(self) -> None:
        self.assertEqual(self.tool.severity_from_amount(326_000_000), "critical")
        self.assertEqual(self.tool.severity_from_amount(500_000), "high")
        self.assertEqual(self.tool.severity_from_amount(10_000), "medium")
        self.assertEqual(self.tool.severity_from_amount(0), "info")

    def test_end_to_end_offline_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p)
            out_dir = tmp_p / "out"
            summary = self.tool.convert(
                cache=cache, out_dir=out_dir, fetch_live=False,
                max_posts=None, dry_run=False,
            )
            self.assertEqual(summary["posts_discovered"], 2)
            self.assertEqual(summary["records_emitted"], 2)
            json_files = list(out_dir.rglob("*.json"))
            yaml_files = list(out_dir.rglob("*.yaml"))
            self.assertEqual(len(json_files), 2)
            self.assertEqual(len(yaml_files), 2)
            wormhole = None
            for jf in json_files:
                rec = json.loads(jf.read_text(encoding="utf-8"))
                if "wormhole" in rec["target_project_slug"].lower():
                    wormhole = rec
                    break
            self.assertIsNotNone(wormhole)
            self.assertEqual(wormhole["severity_at_finding"], "critical")
            self.assertEqual(wormhole["amount_stolen_usd_estimate"], 326_000_000)
            self.assertEqual(wormhole["verification_tier"], "tier-2-verified-public-archive")
            steps = [s["step"] for s in wormhole["verification_chain"]]
            self.assertEqual(steps, ["fetch", "parse", "emit"])

    def test_jsonld_schema_drift_logged(self) -> None:
        no_jsonld_html = b"""<html><head><title>X</title></head><body><p>$1 million stolen.</p></body></html>"""
        rec = self.tool.build_record(
            post_url="https://medium.com/immunefi/x",
            html=no_jsonld_html.decode(),
            payload_sha256="c" * 64,
            fetched_at_utc="2026-05-16T12:00:00Z",
        )
        self.assertIn("articleBody", rec["jsonld_schema_drift"])
        self.assertIn("headline", rec["jsonld_schema_drift"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
