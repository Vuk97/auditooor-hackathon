"""Hermetic tests for ``tools/hackerman-etl-from-audit-firm-blog.py`` (W4.4).

All seven supported sources (tob, spearbit, openzeppelin, chainsecurity,
halborn, certik, cyfrin) are exercised against synthetic fixtures
injected via ``WebCache(prefetched=...)``. Zero live network.

Each fixture is marked ``synthetic_fixture: true`` in the prose so it
cannot be mistaken for a real scraped record.
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
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-audit-firm-blog.py"
WEB_CACHE = REPO_ROOT / "tools" / "lib" / "hackerman_web_cache.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Synthetic fixtures (synthetic_fixture: true).
# Each fixture is a contrived per-source blog post with enough HTML
# scaffolding to exercise the meta-tag + body parsers. None of these
# fixtures are scraped from the live web; they exist only to drive the
# extractor.
# ---------------------------------------------------------------------------


TOB_PAGE = b"""<!doctype html>
<html><head>
<title>Symbolic execution for fun and profit | Trail of Bits Blog</title>
<meta property="article:published_time" content="2024-03-10T09:00:00Z" />
<meta name="author" content="Alice Tobsen" />
<meta name="description" content="A deep dive into symbolic execution and formal verification for EVM bytecode." />
<meta name="keywords" content="symbolic-execution,formal-verification,ethereum,smt" />
</head><body>
<h1>Symbolic execution for fun and profit</h1>
<p>Published March 10, 2024. We dig into formal verification of Aave's
flash-loan code path; an SMT solver finds a precision-loss bug.</p>
<p>The fix landed at https://github.com/aave/aave-v3-core/pull/812.</p>
<p>This is a synthetic_fixture: true post.</p>
</body></html>
"""

TOB_INDEX_PAGE = b"""<!doctype html><html><body>
<a href="https://blog.trailofbits.com/2024/03/10/symbolic-execution/">Symbolic execution</a>
<a href="https://blog.trailofbits.com/2024/04/01/another-post/">Another post</a>
<a href="https://blog.trailofbits.com/category/all/">Category (skip)</a>
<a href="https://blog.trailofbits.com/tag/evm/">Tag (skip)</a>
</body></html>
"""

SPEARBIT_PAGE = b"""<!doctype html>
<html><head>
<title>Reentrancy in Curve pools - Spearbit</title>
<meta property="article:published_time" content="2023-07-30T12:00:00Z" />
<meta name="author" content="Bob Spear" />
<meta name="description" content="A reentrancy bug in Vyper's reentrancy-guard implementation drained Curve pools." />
</head><body>
<h1>Reentrancy in Curve pools</h1>
<p>By Bob Spear. On July 30, 2023, multiple Curve pools had
$52 million drained due to a re-entrancy bug.</p>
<p>The fix proposal is at https://github.com/vyperlang/vyper/pull/3552.</p>
<p>synthetic_fixture: true.</p>
</body></html>
"""

OZ_PAGE = b"""<!doctype html>
<html><head>
<title>Access control patterns for upgradeable contracts | OpenZeppelin Blog</title>
<meta property="article:published_time" content="2024-01-15" />
<meta name="author" content="Carol OZ" />
<meta name="description" content="Best practices for access control in upgradeable proxy contracts; covers governance takeover risks." />
</head><body>
<h1>Access control patterns for upgradeable contracts</h1>
<p>Published 2024-01-15. We discuss governance-takeover vectors in
upgradeable proxies; an access-control bypass via uninitialized proxy
is the canonical anti-pattern.</p>
<p>synthetic_fixture: true.</p>
</body></html>
"""

CHAINSEC_PAGE = b"""<!doctype html>
<html><head>
<title>Oracle manipulation in Compound v2 - ChainSecurity</title>
<meta property="article:published_time" content="2023-11-22T00:00:00Z" />
<meta name="author" content="Dave Chain" />
</head><body>
<h1>Oracle manipulation in Compound v2</h1>
<p>By Dave Chain. In November 2023, an oracle manipulation attack
drained $5 million from Compound v2 markets.</p>
<p>synthetic_fixture: true.</p>
</body></html>
"""

HALBORN_PAGE = b"""<!doctype html>
<html><head>
<title>Bridge message replay attacks explained | Halborn</title>
<meta property="article:published_time" content="2023-08-05" />
<meta name="author" content="Eve Halborn" />
<meta name="description" content="Cross-chain replay vulnerabilities in bridge contracts and how to defend." />
</head><body>
<h1>Bridge message replay attacks explained</h1>
<p>By Eve Halborn. Bridge-message-replay is a critical bug class
affecting Nomad, Wormhole, and Ronin bridges.</p>
<p>synthetic_fixture: true.</p>
</body></html>
"""

CERTIK_PAGE = b"""<!doctype html>
<html><head>
<title>DoS via unbounded loops in Solana programs | CertiK Research</title>
<meta property="article:published_time" content="2024-02-10" />
<meta name="author" content="Frank Certik" />
</head><body>
<h1>DoS via unbounded loops in Solana programs</h1>
<p>Published February 10, 2024. Denial of service via unbounded loops
in Solana programs is a high severity finding.</p>
<p>synthetic_fixture: true.</p>
</body></html>
"""

CYFRIN_PAGE = b"""<!doctype html>
<html><head>
<title>Writing invariant tests with Foundry - Cyfrin Blog</title>
<meta property="article:published_time" content="2024-04-01T10:00:00Z" />
<meta name="author" content="Grace Cyfrin" />
<meta name="description" content="A practical guide to invariant testing and Foundry fuzz campaigns for DeFi protocols." />
</head><body>
<h1>Writing invariant tests with Foundry</h1>
<p>By Grace Cyfrin. Invariant test driven development with Foundry
fuzz and Echidna is the gold standard for DeFi protocols like Uniswap
and Aave.</p>
<p>The example code is at https://github.com/cyfrin/foundry-invariants/commit/deadbeef1234.</p>
<p>synthetic_fixture: true.</p>
</body></html>
"""


PER_SOURCE_FIXTURES = {
    "tob":           ("https://blog.trailofbits.com/2024/03/10/symbolic-execution/", TOB_PAGE),
    "spearbit":      ("https://blog.spearbit.com/curve-reentrancy/", SPEARBIT_PAGE),
    "openzeppelin":  ("https://blog.openzeppelin.com/access-control-patterns/", OZ_PAGE),
    "chainsecurity": ("https://www.chainsecurity.com/blog/compound-oracle/", CHAINSEC_PAGE),
    "halborn":       ("https://www.halborn.com/blog/bridge-replay/", HALBORN_PAGE),
    "certik":        ("https://www.certik.com/resources/solana-dos/", CERTIK_PAGE),
    "cyfrin":        ("https://www.cyfrin.io/blog/foundry-invariants/", CYFRIN_PAGE),
}


def _build_cache(tmp: Path, prefetched_extra=None):
    wc = _load(WEB_CACHE, "_hackerman_web_cache_for_audit_firm_blog_tests")
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


class HackermanEtlFromAuditFirmBlogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_audit_firm_blog")

    # ------------------------------------------------------------------
    # 1. Constants / surface
    # ------------------------------------------------------------------
    def test_01_verification_tier_constant(self) -> None:
        self.assertEqual(self.tool.VERIFICATION_TIER, "tier-2-verified-public-archive")
        self.assertEqual(self.tool.SOURCE_EXTRACTION_METHOD, "web-scrape-audit-firm-blog")

    def test_02_supported_sources_enumerated(self) -> None:
        self.assertEqual(
            set(self.tool.SUPPORTED_SOURCES),
            {"tob", "spearbit", "openzeppelin", "chainsecurity", "halborn", "certik", "cyfrin"},
        )
        self.assertEqual(len(self.tool.SUPPORTED_SOURCES), 7)

    # ------------------------------------------------------------------
    # 2. CLI guards
    # ------------------------------------------------------------------
    def test_03_blocked_when_cache_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = self.tool.main([
                    "--source", "tob",
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
                    "--source", "spearbit",
                    "--cache-dir", str(Path(tmp) / "cache"),
                    "--out-dir", str(Path(tmp) / "out"),
                    "--no-respect-robots",
                ])
            self.assertEqual(rc, 2)
            self.assertIn("--i-acknowledge-tos", stderr.getvalue())

    def test_05_url_list_missing_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = self.tool.main([
                    "--source", "tob",
                    "--cache-dir", str(Path(tmp) / "cache"),
                    "--out-dir", str(Path(tmp) / "out"),
                    "--url-list", str(Path(tmp) / "nope.txt"),
                ])
            self.assertEqual(rc, 2)
            self.assertIn("--url-list path missing", stderr.getvalue())

    # ------------------------------------------------------------------
    # 3. Per-source parser smoke tests (7 sources)
    # ------------------------------------------------------------------
    def test_06_parse_tob_record_shape(self) -> None:
        url, html = PER_SOURCE_FIXTURES["tob"]
        rec = self.tool.build_blog_record(
            source="tob",
            page_url=url,
            html=html.decode(),
            payload_sha256="a" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
        self.assertTrue(rec["record_id"].startswith("blog-tob-"))
        self.assertEqual(rec["author"], "Alice Tobsen")
        self.assertEqual(rec["published_date"], "2024-03-10")
        # ATTACK_CLASS_KEYWORDS is first-match-wins priority order; the
        # body mentions "flash-loan" which is ranked above
        # "formal-verification", so flash-loan wins.
        self.assertEqual(rec["attack_class"], "flash-loan")
        self.assertIn("aave", rec["affected_protocols"])
        # source-url is mirrored at top-level (per spec) AND in source_audit_ref.
        self.assertEqual(rec["record_source_url"], url)
        self.assertEqual(rec["source_audit_ref"]["url"], url)

    def test_07_parse_spearbit_record_shape(self) -> None:
        url, html = PER_SOURCE_FIXTURES["spearbit"]
        rec = self.tool.build_blog_record(
            source="spearbit",
            page_url=url,
            html=html.decode(),
            payload_sha256="b" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertTrue(rec["record_id"].startswith("blog-spearbit-"))
        self.assertEqual(rec["attack_class"], "reentrancy")
        self.assertIn("curve", rec["affected_protocols"])
        self.assertEqual(rec["target_repo"], "github.com/vyperlang/vyper")
        # severity heuristic: "$52 million" stolen text triggers critical.
        self.assertEqual(rec["severity_estimate"], "critical")
        self.assertGreaterEqual(len(rec["fix_commit_ref"]), 1)

    def test_08_parse_openzeppelin_record_shape(self) -> None:
        url, html = PER_SOURCE_FIXTURES["openzeppelin"]
        rec = self.tool.build_blog_record(
            source="openzeppelin",
            page_url=url,
            html=html.decode(),
            payload_sha256="c" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertTrue(rec["record_id"].startswith("blog-openzeppelin-"))
        # ATTACK_CLASS_KEYWORDS is first-match-wins priority order. The
        # body mentions an "uninitialized proxy" which is ranked above
        # "access-control" / "governance-takeover", so
        # signature-verification-bypass wins.
        self.assertIn(rec["attack_class"],
                      {"signature-verification-bypass",
                       "access-control-bypass", "governance-takeover"})
        self.assertEqual(rec["author"], "Carol OZ")

    def test_09_parse_chainsecurity_record_shape(self) -> None:
        url, html = PER_SOURCE_FIXTURES["chainsecurity"]
        rec = self.tool.build_blog_record(
            source="chainsecurity",
            page_url=url,
            html=html.decode(),
            payload_sha256="d" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertEqual(rec["attack_class"], "oracle-manipulation")
        self.assertIn("compound", rec["affected_protocols"])

    def test_10_parse_halborn_record_shape(self) -> None:
        url, html = PER_SOURCE_FIXTURES["halborn"]
        rec = self.tool.build_blog_record(
            source="halborn",
            page_url=url,
            html=html.decode(),
            payload_sha256="e" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertEqual(rec["attack_class"], "bridge-message-replay")
        # nomad / wormhole / ronin all mentioned in body.
        protos = set(rec["affected_protocols"])
        self.assertTrue({"nomad", "wormhole", "ronin"}.issubset(protos))

    def test_11_parse_certik_record_shape(self) -> None:
        url, html = PER_SOURCE_FIXTURES["certik"]
        rec = self.tool.build_blog_record(
            source="certik",
            page_url=url,
            html=html.decode(),
            payload_sha256="f" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        self.assertEqual(rec["attack_class"], "dos")
        self.assertIn("solana", rec["affected_protocols"])
        self.assertEqual(rec["severity_estimate"], "high")

    def test_12_parse_cyfrin_record_shape(self) -> None:
        url, html = PER_SOURCE_FIXTURES["cyfrin"]
        rec = self.tool.build_blog_record(
            source="cyfrin",
            page_url=url,
            html=html.decode(),
            payload_sha256="0" * 64,
            fetched_at_utc="2026-05-16T00:00:00Z",
        )
        # invariant-testing fires before fuzzing-technique in regex order.
        self.assertIn(rec["attack_class"], {"invariant-testing", "fuzzing-technique"})
        self.assertEqual(rec["author"], "Grace Cyfrin")
        protos = set(rec["affected_protocols"])
        self.assertIn("uniswap", protos)
        self.assertIn("aave", protos)

    # ------------------------------------------------------------------
    # 4. SHA256 evidence + verification chain on every emit
    # ------------------------------------------------------------------
    def test_13_sha256_evidence_on_every_source(self) -> None:
        for source, (url, html) in PER_SOURCE_FIXTURES.items():
            rec = self.tool.build_blog_record(
                source=source,
                page_url=url,
                html=html.decode(),
                payload_sha256="9" * 64,
                fetched_at_utc="2026-05-16T00:00:00Z",
            )
            self.assertEqual(len(rec["source_audit_ref"]["payload_sha256"]), 64,
                             f"missing sha256 for source={source}")
            steps = [s["step"] for s in rec["verification_chain"]]
            self.assertEqual(steps, ["fetch", "parse", "emit"],
                             f"bad verification_chain for source={source}")

    def test_14_tier2_on_every_source(self) -> None:
        for source, (url, html) in PER_SOURCE_FIXTURES.items():
            rec = self.tool.build_blog_record(
                source=source,
                page_url=url,
                html=html.decode(),
                payload_sha256="8" * 64,
                fetched_at_utc="2026-05-16T00:00:00Z",
            )
            self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive",
                             f"wrong tier for source={source}")
            self.assertIn("record_extensions", rec)
            self.assertIn("published_at", rec["record_extensions"])
            self.assertIn("author", rec["record_extensions"])
            self.assertIn("affected_protocols", rec["record_extensions"])

    # ------------------------------------------------------------------
    # 5. Index-page anchor extraction
    # ------------------------------------------------------------------
    def test_15_parse_index_anchors_tob_filters_tag_category(self) -> None:
        urls = self.tool.parse_index_anchors(TOB_INDEX_PAGE.decode(), source="tob")
        self.assertEqual(len(urls), 2)
        self.assertTrue(any("symbolic-execution" in u for u in urls))
        self.assertFalse(any("/tag/" in u for u in urls))
        self.assertFalse(any("/category/" in u for u in urls))

    # ------------------------------------------------------------------
    # 6. End-to-end via convert() for one source
    # ------------------------------------------------------------------
    def test_16_end_to_end_tob_url_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            url, html = PER_SOURCE_FIXTURES["tob"]
            cache, _wc = _build_cache(tmp_p, prefetched_extra={url: html})
            summary = self.tool.convert(
                cache=cache, out_dir=tmp_p / "out", source="tob",
                fetch_live=False, urls=[url], index_url=None,
                dry_run=False, max_pages=None,
            )
            self.assertEqual(summary["records_emitted"], 1)
            files = list((tmp_p / "out").rglob("*.json"))
            self.assertEqual(len(files), 1)
            rec = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
            self.assertTrue(rec["record_id"].startswith("blog-tob-"))
            yaml_files = list((tmp_p / "out").rglob("*.yaml"))
            self.assertEqual(len(yaml_files), 1)
            self.assertIn("verification_tier: tier-2-verified-public-archive",
                          yaml_files[0].read_text(encoding="utf-8"))

    def test_17_end_to_end_index_walk_tob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            index = "https://blog.trailofbits.com/"
            url_a = "https://blog.trailofbits.com/2024/03/10/symbolic-execution/"
            url_b = "https://blog.trailofbits.com/2024/04/01/another-post/"
            cache, _wc = _build_cache(tmp_p, prefetched_extra={
                index: TOB_INDEX_PAGE,
                url_a: TOB_PAGE,
                url_b: TOB_PAGE,  # synthetic dup to verify dedup-by-url + emit
            })
            summary = self.tool.convert(
                cache=cache, out_dir=tmp_p / "out", source="tob",
                fetch_live=False, urls=[], index_url=index,
                dry_run=False, max_pages=None,
            )
            self.assertEqual(summary["urls_resolved"], 2)
            self.assertEqual(summary["records_emitted"], 2)

    def test_18_real_source_only_no_url_no_index_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p)
            summary = self.tool.convert(
                cache=cache, out_dir=tmp_p / "out", source="halborn",
                fetch_live=False, urls=[],
                index_url="https://www.halborn.com/blog",
                dry_run=False, max_pages=None,
            )
            self.assertEqual(summary["records_emitted"], 0)
            self.assertTrue(summary["errors"])

    def test_19_dry_run_emits_zero_files_but_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            url, html = PER_SOURCE_FIXTURES["cyfrin"]
            cache, _wc = _build_cache(tmp_p, prefetched_extra={url: html})
            summary = self.tool.convert(
                cache=cache, out_dir=tmp_p / "out", source="cyfrin",
                fetch_live=False, urls=[url], index_url=None,
                dry_run=True, max_pages=None,
            )
            self.assertEqual(summary["records_emitted"], 1)
            files = list((tmp_p / "out").rglob("*.json"))
            self.assertEqual(len(files), 0)

    # ------------------------------------------------------------------
    # 7. Rate-limit + robots policy
    # ------------------------------------------------------------------
    def test_20_rate_limit_not_invoked_on_prefetched(self) -> None:
        sleeps: list = []
        wc = _load(WEB_CACHE, "_hackerman_web_cache_for_w44_rate_limit")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache = wc.WebCache(
                cache_dir=tmp_p / "cache",
                rate_limit_ms=1500,
                respect_robots=False,
                i_acknowledge_tos=True,
                prefetched={
                    "https://blog.trailofbits.com/a/": TOB_PAGE,
                    "https://blog.trailofbits.com/b/": TOB_PAGE,
                },
                sleep=lambda s: sleeps.append(s),
                offline=True,
            )
            cache.fetch("https://blog.trailofbits.com/a/")
            cache.fetch("https://blog.trailofbits.com/b/")
            # Prefetched bytes bypass rate-limit (sibling W4.2 invariant).
            self.assertEqual(sleeps, [])

    def test_21_robots_disallowed_url_raises(self) -> None:
        wc = _load(WEB_CACHE, "_hackerman_web_cache_for_w44_robots")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            # Robots.txt that disallows everything under /blog/.
            robots = b"User-agent: *\nDisallow: /blog/\n"
            cache = wc.WebCache(
                cache_dir=tmp_p / "cache",
                rate_limit_ms=0,
                respect_robots=True,
                i_acknowledge_tos=False,
                prefetched={
                    "https://blog.trailofbits.com/robots.txt": robots,
                },
                # No prefetched body for the disallowed URL; cache will
                # consult robots.txt first and raise.
                sleep=lambda _s: None,
                offline=False,  # robots decision is the policy gate
                fetcher=lambda _u, _t: (b"", 200, "text/plain"),
            )
            with self.assertRaises(wc.RobotsDisallowedError):
                cache.fetch("https://blog.trailofbits.com/blog/disallowed/")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
