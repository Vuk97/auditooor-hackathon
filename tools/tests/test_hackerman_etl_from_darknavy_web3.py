from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hackerman-etl-from-darknavy-web3.py"


ARCHIVE_HTML = b"""<!doctype html><html><body>
<a href="/web3/exploits/bridge-eth-tbtc-usdc-drain/">Bridge Incident</a>
<a href="/web3/page/2/">Next page</a>
<a href="/category/web3/">Category</a>
<a href="https://example.com/offsite">Offsite</a>
<a href="/web3/exploits/bridge-eth-tbtc-usdc-drain/#comments">Duplicate</a>
</body></html>
"""


ARTICLE_HTML = """<!doctype html><html><head>
<title>Ethereum Bridge BTC Import/Proof Path Trace-Attributed Unauthorized Payout | DARKNAVY</title>
<meta property="article:published_time" content="2026-05-17T00:00:00+00:00">
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "BlogPosting",
  "headline": "Ethereum Bridge BTC Import/Proof Path Trace-Attributed Unauthorized Payout",
  "datePublished": "2026-05-17T00:00:00Z",
  "articleBody": "On Ethereum block 25118335 at 2026-05-17T23:55:23Z, attacker EOA called bridge dispatcher 0x71518580f36feceffe0721f06ba4703218cd7f63 and drained bridge-held assets. Exact losses were 1,625.36688649 ETH, 103.56766017 tBTC, and 147,658.836798 USDC. Root Cause: proveImports(bytes) accepted attacker supplied import material before processTransactions(bytes,uint256) executed payouts."
}
</script>
</head><body>
<div class="post-meta deepsea-article-post-meta">2026-05-17&nbsp;·&nbsp;Loss: ≥$147.7K&nbsp;·&nbsp;Logic Error</div>
<article><p>On Ethereum block <code>25118335</code>, attacker EOA called bridge dispatcher.</p>
<h2>Root Cause</h2><p>proveImports(bytes) accepted attacker supplied import material.</p>
<h2>Evidence</h2><a href="https://etherscan.io/tx/0x6990f01720f57fc515d0e976a0c4f8157e0a9529194c4c15d190e98d087eb321">tx</a></article>
</body></html>
""".encode()


def _load_tool():
    spec = importlib.util.spec_from_file_location("_darknavy_web3_etl", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class DarknavyWeb3EtlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_constants(self) -> None:
        self.assertEqual(self.tool.VERIFICATION_TIER, "tier-2-verified-public-archive")
        self.assertEqual(self.tool.SOURCE_EXTRACTION_METHOD, "web-scrape-darknavy-web3")

    def test_archive_parser_accepts_real_web3_exploit_links(self) -> None:
        urls = self.tool.extract_archive_article_links(ARCHIVE_HTML.decode(), base_url="https://www.darknavy.org/web3/")
        self.assertEqual(
            urls,
            ["https://www.darknavy.org/web3/exploits/bridge-eth-tbtc-usdc-drain/"],
        )

    def test_page_range_guard(self) -> None:
        with self.assertRaises(ValueError):
            self.tool._archive_page_urls(1, 9)

    def test_build_record_has_quality_gate_fields(self) -> None:
        record = self.tool.build_darknavy_record(
            page_url="https://www.darknavy.org/web3/exploits/bridge-eth-tbtc-usdc-drain/",
            html_text=ARTICLE_HTML.decode(),
            payload_sha256="a" * 64,
            fetched_at_utc="2026-05-20T00:00:00Z",
        )
        self.assertEqual(record["verification_tier"], "tier-2-verified-public-archive")
        self.assertEqual(record["record_source_url"], "https://www.darknavy.org/web3/exploits/bridge-eth-tbtc-usdc-drain/")
        self.assertEqual(record["source_audit_ref"]["payload_sha256"], "a" * 64)
        self.assertEqual(record["report_date"], "2026-05-17")
        self.assertEqual(record["chain_or_language"], "Ethereum")
        self.assertEqual(record["attack_class"], "bridge-proof-domain-bypass")
        self.assertGreaterEqual(record["amount_stolen_usd_estimate"], 147_000)
        self.assertTrue(record["source_anchors"])
        self.assertTrue(record["detector_hypotheses"])
        self.assertEqual([step["step"] for step in record["verification_chain"]], ["fetch", "parse", "emit"])

    def test_convert_prefetched_archive_and_article_emits_json_and_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            article_url = "https://www.darknavy.org/web3/exploits/bridge-eth-tbtc-usdc-drain/"
            cache = self.tool._WC.WebCache(
                cache_dir=root / "cache",
                rate_limit_ms=0,
                respect_robots=True,
                prefetched={
                    "https://www.darknavy.org/web3/": ARCHIVE_HTML,
                    article_url: ARTICLE_HTML,
                },
                offline=True,
            )
            summary = self.tool.convert(
                cache=cache,
                out_dir=root / "out",
                fetch_live=False,
                dry_run=False,
                start_page=1,
                end_page=1,
            )
            self.assertEqual(summary["records_emitted"], 1)
            self.assertEqual(summary["article_urls_resolved"], 1)
            self.assertEqual(len(summary["files"]), 2)
            self.assertTrue(Path(summary["files"][0]).exists())
            self.assertTrue(Path(summary["files"][1]).exists())

    def test_dry_run_writes_no_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            article_url = "https://www.darknavy.org/web3/exploits/bridge-eth-tbtc-usdc-drain/"
            cache = self.tool._WC.WebCache(
                cache_dir=root / "cache",
                rate_limit_ms=0,
                respect_robots=True,
                prefetched={
                    "https://www.darknavy.org/web3/": ARCHIVE_HTML,
                    article_url: ARTICLE_HTML,
                },
                offline=True,
            )
            summary = self.tool.convert(
                cache=cache,
                out_dir=root / "out",
                fetch_live=False,
                dry_run=True,
                start_page=1,
                end_page=1,
            )
            self.assertEqual(summary["records_emitted"], 1)
            self.assertEqual(summary["files"], [])

    def test_cli_empty_cache_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = self.tool.main([
                    "--cache-dir",
                    str(Path(tmp) / "cache"),
                    "--out-dir",
                    str(Path(tmp) / "out"),
                    "--max-pages",
                    "1",
                    "--json-summary",
                ])
            self.assertEqual(rc, 3)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["records_emitted"], 0)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
