"""Tests for defimon-staleness-check.py BLOCKED_NO_LIVE_SOURCE path (I2 spec).

All tests are offline-safe: no network calls, no external APIs.
The corpus_registry.json is loaded from the real repo root for registry-aware tests;
synthetic registry dicts are used for staleness-computation tests.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


DSC = _load_module("_defimon_staleness_check", REPO_ROOT / "tools" / "defimon-staleness-check.py")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _synthetic_registry(last_mined: str | None = "2026-05-20T19:05:59Z", ttl_days: int = 30) -> dict:
    return {
        "extended_corpora": [
            {
                "slug": "defimon",
                "source": "https://t.me/s/defimon_alerts + https://defimon.xyz/blog",
                "staleness": {
                    "last_mined": last_mined,
                    "ttl_days": ttl_days,
                    "status": "fresh" if last_mined else "never_mined",
                },
                "produces": "test records",
            }
        ]
    }


# ---------------------------------------------------------------------------
# Case 1: build_blocked_status returns required shape
# ---------------------------------------------------------------------------

class TestBlockedStatusShape(unittest.TestCase):
    def test_blocked_status_schema(self):
        """build_blocked_status returns the expected schema and status."""
        entry = {"slug": "defimon", "source": "https://t.me/s/defimon_alerts"}
        staleness = {"is_stale": True, "status": "stale", "last_mined": "2026-05-20T19:05:59Z"}
        blocked = DSC.build_blocked_status(entry, staleness)
        self.assertEqual(blocked["status"], "BLOCKED_NO_LIVE_SOURCE")
        self.assertEqual(blocked["schema"], "auditooor.defimon_blocked_status.v1")
        self.assertEqual(blocked["source_id"], "defimon_delta_blocked_no_live_source")
        self.assertEqual(blocked["slug"], "defimon")

    def test_blocked_status_evidence_has_checked_sources(self):
        """blocked_evidence.sources_checked has at least 2 entries with api_available=False."""
        blocked = DSC.build_blocked_status(None, None)
        evidence = blocked["blocked_evidence"]
        sources = evidence["sources_checked"]
        self.assertGreaterEqual(len(sources), 2)
        for src in sources:
            self.assertFalse(src["api_available"], f"source {src['url']} must report api_available=False")
            self.assertIn("reason", src)
            self.assertIn("type", src)

    def test_blocked_status_has_unblock_path(self):
        """blocked_evidence.unblock_path describes how to lift the block."""
        blocked = DSC.build_blocked_status(None, None)
        unblock = blocked["blocked_evidence"]["unblock_path"]
        self.assertIsInstance(unblock, str)
        self.assertGreater(len(unblock), 20)

    def test_blocked_status_no_network_performed(self):
        """BLOCKED_NO_LIVE_SOURCE always reports network_performed=False."""
        blocked = DSC.build_blocked_status(None, None)
        self.assertFalse(blocked["network_performed"])

    def test_blocked_status_has_generated_at(self):
        """BLOCKED_NO_LIVE_SOURCE record has a generated_at ISO timestamp."""
        blocked = DSC.build_blocked_status(None, None)
        self.assertIn("generated_at", blocked)
        self.assertIn("T", blocked["generated_at"])  # ISO datetime sanity


# ---------------------------------------------------------------------------
# Case 2: --blocked-status CLI flag
# ---------------------------------------------------------------------------

class TestBlockedStatusCLI(unittest.TestCase):
    def test_cli_blocked_status_emits_json(self):
        """--blocked-status --json emits a valid BLOCKED_NO_LIVE_SOURCE JSON record."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            registry_path.write_text(
                json.dumps(_synthetic_registry()), encoding="utf-8"
            )
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = DSC.run([
                    "--registry", str(registry_path),
                    "--blocked-status",
                    "--json",
                ])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["status"], "BLOCKED_NO_LIVE_SOURCE")
            self.assertEqual(out["source_id"], "defimon_delta_blocked_no_live_source")
            self.assertFalse(out["network_performed"])

    def test_cli_blocked_status_exit_zero(self):
        """--blocked-status exits 0 (not a hard error; just reporting the block)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            registry_path.write_text(json.dumps(_synthetic_registry()), encoding="utf-8")
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = DSC.run(["--registry", str(registry_path), "--blocked-status"])
            self.assertEqual(rc, 0)

    def test_cli_blocked_status_does_not_call_network(self):
        """--blocked-status must not trigger any network call."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            registry_path.write_text(json.dumps(_synthetic_registry()), encoding="utf-8")
            import urllib.request
            network_calls = []

            def _fake_urlopen(*a, **kw):
                network_calls.append(True)
                raise AssertionError("network called in --blocked-status mode")

            buf = io.StringIO()
            with mock.patch("sys.stdout", buf), mock.patch.object(urllib.request, "urlopen", _fake_urlopen):
                DSC.run(["--registry", str(registry_path), "--blocked-status", "--json"])
            self.assertEqual(network_calls, [])


# ---------------------------------------------------------------------------
# Case 3: --remine emits BLOCKED_NO_LIVE_SOURCE
# ---------------------------------------------------------------------------

class TestRemineBlockedPath(unittest.TestCase):
    def test_remine_returns_blocked_exit_code(self):
        """--remine (no --dry-run) emits BLOCKED_NO_LIVE_SOURCE and exits 2 (blocked)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            # Make it stale (last_mined 2 years ago)
            reg = _synthetic_registry("2024-01-01T00:00:00Z", ttl_days=1)
            registry_path.write_text(json.dumps(reg), encoding="utf-8")
            buf = io.StringIO()
            err_buf = io.StringIO()
            with mock.patch("sys.stdout", buf), mock.patch("sys.stderr", err_buf):
                rc = DSC.run([
                    "--registry", str(registry_path),
                    "--remine",
                    # no --dry-run: triggers actual BLOCKED path, exits 2
                ])
            # Exit 2 = blocked (distinct from 0=ok, 1=stale-no-remine, 2=blocked-no-live-source)
            self.assertEqual(rc, 2)

    def test_remine_dry_run_returns_zero(self):
        """--remine --dry-run exits 0 (dry-run path always exits 0)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            reg = _synthetic_registry("2024-01-01T00:00:00Z", ttl_days=1)
            registry_path.write_text(json.dumps(reg), encoding="utf-8")
            buf = io.StringIO()
            err_buf = io.StringIO()
            with mock.patch("sys.stdout", buf), mock.patch("sys.stderr", err_buf):
                rc = DSC.run([
                    "--registry", str(registry_path),
                    "--remine",
                    "--dry-run",
                ])
            # Dry-run exits 0: no registry mutation, just prints blocked status
            self.assertEqual(rc, 0)

    def test_remine_dry_run_does_not_update_registry(self):
        """--remine --dry-run never mutates the registry file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            reg = _synthetic_registry("2024-01-01T00:00:00Z", ttl_days=1)
            original_text = json.dumps(reg)
            registry_path.write_text(original_text, encoding="utf-8")
            buf = io.StringIO()
            err_buf = io.StringIO()
            with mock.patch("sys.stdout", buf), mock.patch("sys.stderr", err_buf):
                DSC.run(["--registry", str(registry_path), "--remine", "--dry-run"])
            # File content must be identical
            self.assertEqual(registry_path.read_text(encoding="utf-8"), original_text)

    def test_remine_no_dry_run_does_not_update_registry(self):
        """--remine without --dry-run also does NOT update registry (no mine was performed)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            reg = _synthetic_registry("2024-01-01T00:00:00Z", ttl_days=1)
            original_text = json.dumps(reg)
            registry_path.write_text(original_text, encoding="utf-8")
            buf = io.StringIO()
            err_buf = io.StringIO()
            with mock.patch("sys.stdout", buf), mock.patch("sys.stderr", err_buf):
                DSC.run(["--registry", str(registry_path), "--remine"])
            # Confirmed: registry unchanged because BLOCKED_NO_LIVE_SOURCE path does not mine
            self.assertEqual(registry_path.read_text(encoding="utf-8"), original_text)


# ---------------------------------------------------------------------------
# Case 4: Staleness computation
# ---------------------------------------------------------------------------

class TestStalenessComputation(unittest.TestCase):
    def test_fresh_when_recently_mined(self):
        """Entry mined today -> is_stale=False, status='fresh'."""
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        last_mined = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = {"staleness": {"last_mined": last_mined, "ttl_days": 30}}
        report = DSC._compute_staleness(entry, None)
        self.assertFalse(report["is_stale"])
        self.assertEqual(report["status"], "fresh")

    def test_stale_when_old(self):
        """Entry mined 60 days ago with TTL=30 -> is_stale=True."""
        entry = {"staleness": {"last_mined": "2024-01-01T00:00:00Z", "ttl_days": 30}}
        report = DSC._compute_staleness(entry, None)
        self.assertTrue(report["is_stale"])
        self.assertEqual(report["status"], "stale")

    def test_never_mined(self):
        """Entry with no last_mined -> status='never_mined', is_stale=True."""
        entry = {"staleness": {"ttl_days": 30}}
        report = DSC._compute_staleness(entry, None)
        self.assertTrue(report["is_stale"])
        self.assertEqual(report["status"], "never_mined")

    def test_json_flag_emits_staleness_report(self):
        """--json flag prints the staleness report dict."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            registry_path.write_text(json.dumps(_synthetic_registry()), encoding="utf-8")
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                DSC.run(["--registry", str(registry_path), "--json"])
            out = json.loads(buf.getvalue())
            self.assertIn("slug", out)
            self.assertIn("is_stale", out)


# ---------------------------------------------------------------------------
# Case 5: Live-source preflight stays bounded and non-scraping
# ---------------------------------------------------------------------------

class _FakeHTTPResponse:
    def __init__(self, status: int, content_type: str, body: bytes = b"") -> None:
        self.status = status
        self.headers = {"content-type": content_type}
        self._body = body
        self.read_limits: list[int] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getcode(self):
        return self.status

    def read(self, limit: int = -1):
        self.read_limits.append(limit)
        if limit is None or limit < 0:
            return self._body
        return self._body[:limit]


class TestLivePreflight(unittest.TestCase):
    def test_live_preflight_reports_blocked_when_only_html_and_404s(self):
        """Preflight reports no machine source when public pages are HTML and feeds are absent."""

        def fake_urlopen(request, timeout=None):
            url = request.full_url
            if url in {"https://t.me/s/defimon_alerts", "https://defimon.xyz/blog"}:
                return _FakeHTTPResponse(
                    200,
                    "text/html; charset=utf-8",
                    b"<html><head></head><body>public html</body></html>",
                )
            return _FakeHTTPResponse(404, "text/html; charset=utf-8", b"<html>not found</html>")

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            out = DSC.build_live_preflight(timeout=1, max_bytes=1024)

        self.assertEqual(out["schema"], "auditooor.defimon_live_preflight.v1")
        self.assertEqual(out["status"], "BLOCKED_NO_MACHINE_SOURCE")
        self.assertTrue(out["network_performed"])
        self.assertFalse(out["secret_required"])
        self.assertFalse(out["safe_miner_available"])
        self.assertEqual(out["candidate_machine_sources"], [])
        self.assertEqual(len(out["sources_checked"]), 6)
        self.assertIn("does not scrape", out["automation_boundary"])

    def test_live_preflight_detects_machine_content_type_candidate(self):
        """A reachable RSS/JSON endpoint is surfaced as a candidate, not auto-promoted."""

        def fake_urlopen(request, timeout=None):
            url = request.full_url
            if url == "https://defimon.xyz/rss.xml":
                return _FakeHTTPResponse(200, "application/rss+xml", b"<rss></rss>")
            return _FakeHTTPResponse(404, "text/html; charset=utf-8", b"")

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            out = DSC.build_live_preflight(timeout=1, max_bytes=1024)

        self.assertEqual(out["status"], "MACHINE_SOURCE_CANDIDATE_FOUND")
        self.assertTrue(out["safe_miner_available"])
        self.assertEqual(out["candidate_machine_sources"][0]["url"], "https://defimon.xyz/rss.xml")
        self.assertEqual(out["next_action"], "review_candidate_machine_source_before_miner")

    def test_live_preflight_detects_html_alternate_link_candidate(self):
        """Only durable alternate machine-source links are parsed from HTML."""
        html = (
            b'<html><head><link rel="alternate" type="application/json" '
            b'href="/blog/feed.json" title="JSON feed"></head></html>'
        )

        def fake_urlopen(request, timeout=None):
            if request.full_url == "https://defimon.xyz/blog":
                return _FakeHTTPResponse(200, "text/html; charset=utf-8", html)
            return _FakeHTTPResponse(404, "text/html; charset=utf-8", b"")

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            out = DSC.build_live_preflight(timeout=1, max_bytes=1024)

        self.assertEqual(out["status"], "MACHINE_SOURCE_CANDIDATE_FOUND")
        self.assertEqual(out["candidate_machine_sources"][0]["url"], "/blog/feed.json")
        self.assertEqual(out["candidate_machine_sources"][0]["reason"], "html alternate link")

    def test_live_preflight_detects_nextjs_ssg_blog_json_candidate(self):
        """Next.js blog index JSON is detected as a bounded machine-source candidate."""
        build_id = "kkTestBuild123"
        build_url = f"https://defimon.xyz/_next/static/{build_id}/_buildManifest.js"
        ssg_url = f"https://defimon.xyz/_next/static/{build_id}/_ssgManifest.js"
        index_url = f"https://defimon.xyz/_next/data/{build_id}/blog.json"

        build_manifest = b'{"pages":{"\\/blog":[], "/blog/[slug]":[]}}'
        ssg_manifest = b'{"routes":["/","/blog","/blog/[slug]"]}'
        blog_html = (
            f"<html><head><script src=\"/_next/static/{build_id}/_buildManifest.js\"></script></head></html>"
        ).encode("utf-8")

        def fake_urlopen(request, timeout=None):
            url = request.full_url
            if url == "https://defimon.xyz/blog":
                return _FakeHTTPResponse(200, "text/html; charset=utf-8", blog_html)
            if url == build_url:
                return _FakeHTTPResponse(200, "application/javascript; charset=utf-8", build_manifest)
            if url == ssg_url:
                return _FakeHTTPResponse(200, "application/javascript; charset=utf-8", ssg_manifest)
            if url == index_url:
                return _FakeHTTPResponse(200, "application/json; charset=utf-8", b"{\"posts\":[]}")
            return _FakeHTTPResponse(404, "text/html; charset=utf-8", b"")

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            out = DSC.build_live_preflight(timeout=1, max_bytes=1024)

        self.assertEqual(out["status"], "MACHINE_SOURCE_CANDIDATE_FOUND")
        self.assertTrue(out["safe_miner_available"])
        self.assertEqual(len(out["sources_checked"]), 9)
        candidates = out["candidate_machine_sources"]
        self.assertEqual(candidates[0]["url"], index_url)
        self.assertEqual(candidates[0]["reason"], "nextjs_ssg_blog_json_candidate")
        self.assertEqual(candidates[0]["build_id"], build_id)
        self.assertEqual(candidates[0]["discovered_from"], "https://defimon.xyz/blog")

    def test_live_preflight_nextjs_route_detection_requires_exact_blog_route(self):
        """The /blog/[slug] route alone must not satisfy the /blog route check."""
        build_id = "kkTestBuild123"
        build_url = f"https://defimon.xyz/_next/static/{build_id}/_buildManifest.js"
        ssg_url = f"https://defimon.xyz/_next/static/{build_id}/_ssgManifest.js"
        index_url = f"https://defimon.xyz/_next/data/{build_id}/blog.json"
        blog_html = (
            f"<html><head><script src=\"/_next/static/{build_id}/_buildManifest.js\"></script></head></html>"
        ).encode("utf-8")

        def fake_urlopen(request, timeout=None):
            url = request.full_url
            if url == "https://defimon.xyz/blog":
                return _FakeHTTPResponse(200, "text/html; charset=utf-8", blog_html)
            if url in {build_url, ssg_url}:
                return _FakeHTTPResponse(200, "application/javascript; charset=utf-8", b'{"routes":["/blog/[slug]"]}')
            if url == index_url:
                return _FakeHTTPResponse(200, "application/json; charset=utf-8", b"{\"posts\":[]}")
            return _FakeHTTPResponse(404, "text/html; charset=utf-8", b"")

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            out = DSC.build_live_preflight(timeout=1, max_bytes=1024)

        self.assertEqual(out["status"], "MACHINE_SOURCE_CANDIDATE_FOUND")
        machine_candidates = [
            candidate
            for candidate in out["candidate_machine_sources"]
            if candidate["reason"] == "nextjs_ssg_blog_json_candidate"
        ]
        self.assertEqual(machine_candidates, [])

    def test_live_preflight_honors_max_bytes_read_limit(self):
        """Each request reads max_bytes + 1 and reports only max_bytes stored bytes."""
        response = _FakeHTTPResponse(200, "text/html; charset=utf-8", b"x" * 100)

        with mock.patch("urllib.request.urlopen", return_value=response):
            out = DSC.build_live_preflight(timeout=1, max_bytes=5)

        self.assertEqual(response.read_limits, [6] * 6)
        self.assertTrue(all(row["bytes_read"] == 5 for row in out["sources_checked"]))

    def test_live_preflight_rejects_nonpositive_bounds(self):
        """Direct preflight calls reject bounds that would break bounded reads."""
        with self.assertRaisesRegex(ValueError, "--max-bytes"):
            DSC.build_live_preflight(timeout=1, max_bytes=0)
        with self.assertRaisesRegex(ValueError, "--timeout-seconds"):
            DSC.build_live_preflight(timeout=0, max_bytes=1024)

    def test_cli_live_preflight_emits_json(self):
        """--live-preflight emits parseable JSON and remains explicit opt-in network mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            registry_path.write_text(json.dumps(_synthetic_registry()), encoding="utf-8")

            def fake_urlopen(request, timeout=None):
                return _FakeHTTPResponse(404, "text/html; charset=utf-8", b"")

            buf = io.StringIO()
            with mock.patch("sys.stdout", buf), mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                rc = DSC.run([
                    "--registry", str(registry_path),
                    "--live-preflight",
                    "--timeout-seconds", "1",
                    "--max-bytes", "256",
                ])

        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["schema"], "auditooor.defimon_live_preflight.v1")
        self.assertEqual(out["max_bytes_per_url"], 256)

    def test_cli_live_preflight_rejects_invalid_bounds_without_traceback(self):
        """Invalid CLI bounds exit predictably instead of reaching urllib."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = Path(tmpdir) / "corpus_registry.json"
            registry_path.write_text(json.dumps(_synthetic_registry()), encoding="utf-8")

            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr), mock.patch("urllib.request.urlopen") as urlopen:
                rc = DSC.run([
                    "--registry", str(registry_path),
                    "--live-preflight",
                    "--timeout-seconds", "-1",
                ])

        self.assertEqual(rc, 2)
        self.assertIn("--timeout-seconds must be greater than 0", stderr.getvalue())
        urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# Case 6: Live corpus_registry.json integration
# ---------------------------------------------------------------------------

class TestRealRegistry(unittest.TestCase):
    """Use the real corpus_registry.json to confirm the defimon entry shape."""

    def test_real_registry_defimon_entry_exists(self):
        """The real corpus_registry.json contains a 'defimon' slug."""
        real_registry = REPO_ROOT / "reference" / "corpus_registry.json"
        if not real_registry.exists():
            self.skipTest("corpus_registry.json not found")
        reg = json.loads(real_registry.read_text(encoding="utf-8"))
        entry = next(
            (e for e in reg.get("extended_corpora", []) if e.get("slug") == "defimon"),
            None,
        )
        self.assertIsNotNone(entry, "defimon slug must be present in corpus_registry.json")

    def test_real_registry_defimon_blocked_status_runs(self):
        """--blocked-status succeeds against the real registry."""
        real_registry = REPO_ROOT / "reference" / "corpus_registry.json"
        if not real_registry.exists():
            self.skipTest("corpus_registry.json not found")
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = DSC.run(["--registry", str(real_registry), "--blocked-status", "--json"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["status"], "BLOCKED_NO_LIVE_SOURCE")


if __name__ == "__main__":
    unittest.main()
