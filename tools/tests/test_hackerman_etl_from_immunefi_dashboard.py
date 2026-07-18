"""Hermetic tests for ``tools/hackerman-etl-from-immunefi-dashboard.py``.

No live network calls. Synthetic HTML fixtures are injected into the
shared ``WebCache`` via the ``prefetched={url: bytes}`` constructor
keyword. The miner reads the cache; tests assert on the emitted record
shape, severity row enumeration, asset-class enumeration, and
verification-tier propagation.
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
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-immunefi-dashboard.py"
WEB_CACHE = REPO_ROOT / "tools" / "lib" / "hackerman_web_cache.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


EXPLORE_INDEX_HTML = b"""<!doctype html>
<html><head><title>Immunefi Explore</title></head><body>
<a href="/bug-bounty/compound-v3/">Compound V3</a>
<a href="/bug-bounty/polygon-zkevm/">Polygon zkEVM</a>
<a href="/bug-bounty/wormhole/">Wormhole</a>
</body></html>
"""

BOUNTY_COMPOUND_HTML = b"""<!doctype html>
<html><head><title>Compound V3 Bounty</title></head><body>
<h1>Compound V3</h1>
<div class="bounty">
<span class="status">active</span>
<p>Status: active. Asset: Smart Contract.</p>
<table>
<tr><td>Critical</td><td>Up to $1,000,000</td></tr>
<tr><td>High</td><td>Up to $250,000</td></tr>
<tr><td>Medium</td><td>Up to $25,000</td></tr>
<tr><td>Low</td><td>Up to $5,000</td></tr>
</table>
<h2>Impacts in scope</h2>
<ul>
<li>Direct theft of user funds</li>
<li>Permanent freezing of funds</li>
<li>Smart contract DoS</li>
</ul>
<p>Repository: <a href="https://github.com/compound-finance/comet">github.com/compound-finance/comet</a></p>
<p>$1,500,000 paid out across 12 reports.</p>
</div>
</body></html>
"""

BOUNTY_POLYGON_HTML = b"""<!doctype html>
<html><head><title>Polygon zkEVM</title></head><body>
<h1>Polygon zkEVM</h1>
<p>Status: paused</p>
<table>
<tr><td>Critical</td><td>$500,000</td></tr>
<tr><td>High</td><td>$100,000</td></tr>
</table>
<h2>Impacts</h2>
<ul>
<li>Permanent freezing of funds</li>
<li>Theft of unclaimed user rewards</li>
</ul>
<p>Repo: https://github.com/0xPolygonHermez/zkevm-node</p>
</body></html>
"""

BOUNTY_WORMHOLE_HTML = b"""<!doctype html>
<html><head><title>Wormhole</title></head><body>
<h1>Wormhole</h1>
<p>Status: ended</p>
<table>
<tr><td>Critical</td><td>$2,500,000</td></tr>
</table>
<h2>Impacts</h2>
<ul>
<li>Signature verification bypass leading to direct theft of user funds</li>
</ul>
<p>Repo: https://github.com/wormhole-foundation/wormhole</p>
</body></html>
"""


def _build_cache(tmp: Path, *, with_index: bool = True):
    wc = _load(WEB_CACHE, "_hackerman_web_cache_for_dashboard_tests")
    prefetched = {}
    if with_index:
        prefetched["https://immunefi.com/explore/"] = EXPLORE_INDEX_HTML
    prefetched.update({
        "https://immunefi.com/bug-bounty/compound-v3/": BOUNTY_COMPOUND_HTML,
        "https://immunefi.com/bug-bounty/polygon-zkevm/": BOUNTY_POLYGON_HTML,
        "https://immunefi.com/bug-bounty/wormhole/": BOUNTY_WORMHOLE_HTML,
    })
    cache = wc.WebCache(
        cache_dir=tmp / "cache",
        rate_limit_ms=0,
        respect_robots=False,
        i_acknowledge_tos=True,
        prefetched=prefetched,
        sleep=lambda _s: None,
    )
    return cache, wc


class HackermanEtlImmunefiDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_immunefi_dashboard")

    # ------------------------------------------------------------------
    # 1. CLI gate: --no-respect-robots requires --i-acknowledge-tos.
    # ------------------------------------------------------------------
    def test_cli_robots_co_occurrence_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = self.tool.main([
                    "--cache-dir", str(Path(tmp) / "cache"),
                    "--out-dir", str(Path(tmp) / "out"),
                    "--no-respect-robots",
                    "--dry-run",
                ])
            self.assertEqual(rc, 2)
            self.assertIn("--i-acknowledge-tos", stderr.getvalue())

    # ------------------------------------------------------------------
    # 2. BLOCKED-NO-REAL-SOURCE on empty cache + no fetch.
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # 3. Default rate-limit is 1500 ms.
    # ------------------------------------------------------------------
    def test_default_rate_limit_is_1500ms(self) -> None:
        self.assertEqual(self.tool.DEFAULT_RATE_LIMIT_MS, 1500)

    # ------------------------------------------------------------------
    # 4. Verification tier is tier-2-verified-public-archive.
    # ------------------------------------------------------------------
    def test_verification_tier_constant(self) -> None:
        self.assertEqual(self.tool.VERIFICATION_TIER, "tier-2-verified-public-archive")
        self.assertEqual(self.tool.SOURCE_EXTRACTION_METHOD, "web-scrape-static-html")

    # ------------------------------------------------------------------
    # 5. Bounty slugs extracted from explore index.
    # ------------------------------------------------------------------
    def test_extract_bounty_slugs(self) -> None:
        slugs = self.tool.extract_bounty_slugs(EXPLORE_INDEX_HTML.decode())
        self.assertEqual(slugs, ["compound-v3", "polygon-zkevm", "wormhole"])

    # ------------------------------------------------------------------
    # 6. Severity row extraction (Compound: 4 tiers).
    # ------------------------------------------------------------------
    def test_extract_severity_rows_compound(self) -> None:
        rows = self.tool.extract_severity_rows(BOUNTY_COMPOUND_HTML.decode())
        sevs = [r["severity"] for r in rows]
        self.assertEqual(sevs, ["critical", "high", "medium", "low"])
        self.assertEqual(rows[0]["ceiling_usd"], 1_000_000)
        self.assertEqual(rows[0]["ceiling_dollar_class"], ">=$1M")

    # ------------------------------------------------------------------
    # 7. Asset class extraction.
    # ------------------------------------------------------------------
    def test_extract_asset_classes_smart_contract(self) -> None:
        classes = self.tool.extract_asset_classes(BOUNTY_COMPOUND_HTML.decode())
        self.assertIn("smart-contract", classes)

    # ------------------------------------------------------------------
    # 8. Per-bounty record build cardinality (severity x asset_class).
    # ------------------------------------------------------------------
    def test_build_records_for_bounty_cardinality(self) -> None:
        records = self.tool.build_records_for_bounty(
            slug="compound-v3",
            page_url="https://immunefi.com/bug-bounty/compound-v3/",
            html=BOUNTY_COMPOUND_HTML.decode(),
            payload_sha256="a" * 64,
            fetched_at_utc="2026-05-16T12:00:00Z",
        )
        # 4 severity rows x 1 asset class = 4 records.
        self.assertEqual(len(records), 4)
        for r in records:
            self.assertEqual(r["verification_tier"], "tier-2-verified-public-archive")
            self.assertEqual(r["source_extraction_method"], "web-scrape-static-html")
            self.assertIn("payload_sha256", r["source_audit_ref"])
            self.assertEqual(r["source_audit_ref"]["payload_sha256"], "a" * 64)

    # ------------------------------------------------------------------
    # 9. record_id includes the payload sha256 (uniqueness across pages).
    # ------------------------------------------------------------------
    def test_record_id_uniqueness(self) -> None:
        r1 = self.tool.build_records_for_bounty(
            slug="x", page_url="https://immunefi.com/bug-bounty/x/",
            html=BOUNTY_COMPOUND_HTML.decode(), payload_sha256="a" * 64,
            fetched_at_utc="2026-05-16T12:00:00Z",
        )[0]
        r2 = self.tool.build_records_for_bounty(
            slug="x", page_url="https://immunefi.com/bug-bounty/x/",
            html=BOUNTY_COMPOUND_HTML.decode(), payload_sha256="b" * 64,
            fetched_at_utc="2026-05-16T12:00:00Z",
        )[0]
        self.assertNotEqual(r1["record_id"], r2["record_id"])

    # ------------------------------------------------------------------
    # 10. End-to-end with offline cache: emits >=1 record per bounty.
    # ------------------------------------------------------------------
    def test_end_to_end_offline_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p)
            out_dir = tmp_p / "out"
            summary = self.tool.convert(
                cache=cache,
                out_dir=out_dir,
                fetch_live=False,
                max_pages=None,
                dry_run=False,
            )
            self.assertEqual(summary["bounties_discovered"], 3)
            self.assertGreaterEqual(summary["records_emitted"], 6)
            # Files exist on disk.
            json_files = list(out_dir.rglob("*.json"))
            yaml_files = list(out_dir.rglob("*.yaml"))
            self.assertEqual(len(json_files), summary["records_emitted"])
            self.assertEqual(len(yaml_files), summary["records_emitted"])

    # ------------------------------------------------------------------
    # 11. Emitted records carry the verification_chain triplet (fetch/parse/emit).
    # ------------------------------------------------------------------
    def test_verification_chain_triplet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p)
            out_dir = tmp_p / "out"
            self.tool.convert(
                cache=cache, out_dir=out_dir, fetch_live=False,
                max_pages=None, dry_run=False,
            )
            json_files = list(out_dir.rglob("*.json"))
            self.assertTrue(json_files)
            first = json.loads(json_files[0].read_text(encoding="utf-8"))
            steps = [s["step"] for s in first["verification_chain"]]
            self.assertEqual(steps, ["fetch", "parse", "emit"])
            for s in first["verification_chain"]:
                self.assertEqual(len(s["proof"]), 64)  # sha256 hex

    # ------------------------------------------------------------------
    # 12. Max-pages caps the bounty discovery list.
    # ------------------------------------------------------------------
    def test_max_pages_caps_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            cache, _wc = _build_cache(tmp_p)
            summary = self.tool.convert(
                cache=cache, out_dir=tmp_p / "out", fetch_live=False,
                max_pages=1, dry_run=True,
            )
            self.assertEqual(summary["bounties_discovered"], 1)

    # ------------------------------------------------------------------
    # 13. target_repo is extracted from the bounty page GitHub link.
    # ------------------------------------------------------------------
    def test_target_repo_extraction(self) -> None:
        repo = self.tool.extract_target_repo(BOUNTY_COMPOUND_HTML.decode())
        self.assertEqual(repo, "github.com/compound-finance/comet")

    # ------------------------------------------------------------------
    # 14. bounty_status extraction.
    # ------------------------------------------------------------------
    def test_bounty_status_extraction(self) -> None:
        self.assertEqual(
            self.tool.extract_bounty_status(BOUNTY_COMPOUND_HTML.decode()), "active"
        )
        self.assertEqual(
            self.tool.extract_bounty_status(BOUNTY_POLYGON_HTML.decode()), "paused"
        )
        self.assertEqual(
            self.tool.extract_bounty_status(BOUNTY_WORMHOLE_HTML.decode()), "ended"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
