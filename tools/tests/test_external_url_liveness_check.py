"""Tests for tools/external-url-liveness-check.py (Rule 54, Check #101).

Covers all verdict branches with mocked HTTP probes:
  pass-no-external-urls
  pass-all-urls-live
  ok-rebuttal
  fail-dead-url-cited
  fail-network-validation-failed-strict
  error

Plus the real-world MMMMM anchor (Hyperbridge OP dispute draft) dead-URL
fixture. URL extraction edge cases (trailing punctuation, schemes to skip,
localhost) are also covered.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "external_url_liveness_check",
    ROOT / "tools" / "external-url-liveness-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

check = mod.check
SCHEMA_VERSION = mod.SCHEMA_VERSION
GATE = mod.GATE
_extract_urls = mod._extract_urls
_should_skip = mod._should_skip
_classify = mod._classify

FIXTURES = Path(__file__).parent / "fixtures" / "r54"


# ---------------------------------------------------------------------------
# Mock probe registry
# ---------------------------------------------------------------------------
DEAD_404_URL = "https://gist.github.com/Vuk97/9d055289dd81f2d48ad192580b7aa7fb"
LIVE_GIST_URL = "https://gist.github.com/Vuk97/3904db90824e1a3b990bfee1e9b684c0"
LIVE_PR_URL = "https://github.com/Vuk97/auditooor/pull/659"


def make_probe_fn(responses: dict[str, dict]):
    """Build a mock probe function from a URL -> response dict.

    Default behaviour for un-listed URLs: return status=200, method=HEAD.
    """
    def _probe(url: str, timeout: float, method: str = "HEAD") -> dict:
        if url in responses:
            return responses[url]
        # Unknown URL defaults to live
        return {"status": 200, "method": method, "error": None}
    return _probe


# Pre-built probe functions used by multiple tests
PROBE_ALL_LIVE = make_probe_fn({})

PROBE_DEAD_404 = make_probe_fn({
    DEAD_404_URL: {"status": 404, "method": "HEAD", "error": "HTTP 404"},
})

PROBE_DEAD_410 = make_probe_fn({
    "https://docs.example.com/removed-page": {
        "status": 410, "method": "HEAD", "error": "HTTP 410",
    },
})

PROBE_DEAD_503 = make_probe_fn({
    "https://service.example.com/down": {
        "status": 503, "method": "HEAD", "error": "HTTP 503",
    },
})

PROBE_MIXED = make_probe_fn({
    DEAD_404_URL: {"status": 404, "method": "HEAD", "error": "HTTP 404"},
    LIVE_PR_URL: {"status": 200, "method": "HEAD", "error": None},
    "https://docs.example.com/ok": {"status": 200, "method": "HEAD", "error": None},
})

PROBE_NETWORK_FAILURE = make_probe_fn({
    "https://flaky-host.example.invalid/path/to/poc": {
        "status": None, "method": "HEAD", "error": "timeout",
    },
})

PROBE_AMBIGUOUS_403 = make_probe_fn({
    "https://etherscan.io/address/0xdeadbeef": {
        "status": 403, "method": "HEAD", "error": "HTTP 403",
    },
})


def _run(filename: str, **kwargs) -> dict:
    """Run check against fixture with PROBE_ALL_LIVE default override."""
    if "probe_fn" not in kwargs:
        kwargs["probe_fn"] = PROBE_ALL_LIVE
    return check(FIXTURES / filename, **kwargs)


# ---------------------------------------------------------------------------
# pass-no-external-urls
# ---------------------------------------------------------------------------
class TestNoExternalUrls(unittest.TestCase):

    def test_draft_with_no_urls_passes(self) -> None:
        r = _run("no_urls.md")
        self.assertEqual(r["verdict"], "pass-no-external-urls")
        self.assertEqual(r["gate"], GATE)
        self.assertEqual(r["schema"], SCHEMA_VERSION)
        self.assertEqual(r["total_urls_extracted"], 0)

    def test_localhost_only_passes(self) -> None:
        # Localhost is in skip-list, treated as no external URLs
        r = _run("skipped_localhost.md")
        # Localhost is skipped (extracted but not probed); since no other URL
        # exists, total_urls_extracted >= 1 but counts.probed == 0.
        # The current implementation routes to pass-all-urls-live with
        # 0 probed if any URL was extracted; assert that path.
        self.assertIn(r["verdict"], ("pass-no-external-urls", "pass-all-urls-live"))
        # If pass-all-urls-live, ensure 0 dead.
        if r["verdict"] == "pass-all-urls-live":
            self.assertEqual(r["counts"]["dead"], 0)


# ---------------------------------------------------------------------------
# pass-all-urls-live
# ---------------------------------------------------------------------------
class TestAllLive(unittest.TestCase):

    def test_all_live_urls_pass(self) -> None:
        r = _run("all_live_urls.md", probe_fn=PROBE_ALL_LIVE)
        self.assertEqual(r["verdict"], "pass-all-urls-live")
        self.assertGreaterEqual(r["counts"]["live"], 1)
        self.assertEqual(r["counts"]["dead"], 0)

    def test_ambiguous_403_treated_as_live(self) -> None:
        r = _run("ambiguous_403_url.md", probe_fn=PROBE_AMBIGUOUS_403)
        self.assertEqual(r["verdict"], "pass-all-urls-live")
        self.assertGreaterEqual(r["counts"]["ambiguous"], 1)
        self.assertEqual(r["counts"]["dead"], 0)


# ---------------------------------------------------------------------------
# fail-dead-url-cited
# ---------------------------------------------------------------------------
class TestDeadUrlCited(unittest.TestCase):

    def test_dead_404_fails(self) -> None:
        r = _run("dead_url_404.md", probe_fn=PROBE_DEAD_404)
        self.assertEqual(r["verdict"], "fail-dead-url-cited")
        self.assertEqual(r["counts"]["dead"], 1)
        self.assertEqual(r["dead_urls"][0]["status"], 404)
        self.assertIn(DEAD_404_URL, r["dead_urls"][0]["url"])

    def test_dead_410_fails(self) -> None:
        r = _run("dead_url_410.md", probe_fn=PROBE_DEAD_410)
        self.assertEqual(r["verdict"], "fail-dead-url-cited")
        self.assertEqual(r["dead_urls"][0]["status"], 410)

    def test_dead_503_fails(self) -> None:
        r = _run("dead_url_503.md", probe_fn=PROBE_DEAD_503)
        self.assertEqual(r["verdict"], "fail-dead-url-cited")
        self.assertEqual(r["dead_urls"][0]["status"], 503)

    def test_mixed_dead_and_live_fails(self) -> None:
        r = _run("mixed_dead_and_live.md", probe_fn=PROBE_MIXED)
        self.assertEqual(r["verdict"], "fail-dead-url-cited")
        # At least 2 live + 1 dead in fixture
        self.assertGreaterEqual(r["counts"]["live"], 2)
        self.assertEqual(r["counts"]["dead"], 1)


# ---------------------------------------------------------------------------
# ok-rebuttal
# ---------------------------------------------------------------------------
class TestRebuttal(unittest.TestCase):

    def test_html_rebuttal_accepted(self) -> None:
        # Rebuttal short-circuits before probing
        r = _run("r54_rebuttal_override.md", probe_fn=PROBE_DEAD_404)
        self.assertEqual(r["verdict"], "ok-rebuttal")
        self.assertIn("r54-rebuttal accepted", r["reason"])

    def test_inline_rebuttal_accepted(self) -> None:
        r = _run("r54_rebuttal_inline.md", probe_fn=PROBE_DEAD_404)
        self.assertEqual(r["verdict"], "ok-rebuttal")

    def test_empty_rebuttal_does_not_silence(self) -> None:
        r = _run("r54_rebuttal_empty.md", probe_fn=PROBE_DEAD_404)
        # Empty rebuttal reason should NOT be accepted; gate falls through to fail.
        self.assertEqual(r["verdict"], "fail-dead-url-cited")


# ---------------------------------------------------------------------------
# network failure (warn vs strict)
# ---------------------------------------------------------------------------
class TestNetworkFailure(unittest.TestCase):

    def test_network_failure_warn_only_default(self) -> None:
        # Without --strict, network failure -> still pass-all-urls-live
        # (no dead URLs, no failures escalated).
        r = _run("network_failure_url.md", probe_fn=PROBE_NETWORK_FAILURE)
        self.assertEqual(r["verdict"], "pass-all-urls-live")
        self.assertGreaterEqual(r["counts"]["network_failures"], 1)

    def test_network_failure_strict_promotes_to_fail(self) -> None:
        r = _run(
            "network_failure_url.md",
            probe_fn=PROBE_NETWORK_FAILURE,
            strict=True,
        )
        self.assertEqual(r["verdict"], "fail-network-validation-failed-strict")
        self.assertIn("flaky-host", r["network_failures"][0]["url"])


# ---------------------------------------------------------------------------
# error / nonexistent file
# ---------------------------------------------------------------------------
class TestError(unittest.TestCase):

    def test_nonexistent_file_returns_error(self) -> None:
        r = check(Path("/nonexistent/path/draft.md"))
        self.assertEqual(r["verdict"], "error")
        self.assertEqual(r["gate"], GATE)


# ---------------------------------------------------------------------------
# URL extraction helpers
# ---------------------------------------------------------------------------
class TestUrlExtraction(unittest.TestCase):

    def test_trailing_period_stripped(self) -> None:
        text = "See https://example.com/page. End."
        urls = _extract_urls(text)
        self.assertEqual(urls, ["https://example.com/page"])

    def test_trailing_paren_stripped_via_regex_stop(self) -> None:
        text = "Link [foo](https://example.com/page) end"
        urls = _extract_urls(text)
        self.assertEqual(urls, ["https://example.com/page"])

    def test_deduplication(self) -> None:
        text = "https://example.com/a and https://example.com/a again"
        urls = _extract_urls(text)
        self.assertEqual(urls, ["https://example.com/a"])

    def test_multiple_urls_preserved_in_order(self) -> None:
        text = """
        https://github.com/foo/bar
        https://gist.github.com/baz/0xabc
        https://docs.example.com/x
        """
        urls = _extract_urls(text)
        self.assertEqual(len(urls), 3)
        self.assertIn("https://github.com/foo/bar", urls)

    def test_no_urls_returns_empty(self) -> None:
        urls = _extract_urls("plain text with no urls at all")
        self.assertEqual(urls, [])

    def test_mailto_not_extracted(self) -> None:
        # _URL_RE only matches http(s); mailto: is naturally excluded.
        text = "mailto:foo@bar.com and https://real.example.com"
        urls = _extract_urls(text)
        self.assertEqual(urls, ["https://real.example.com"])

    def test_trailing_punctuation_fixture(self) -> None:
        # Real fixture file form
        r = _run("url_with_trailing_punct.md", probe_fn=PROBE_DEAD_404)
        # The URL with trailing period must still be probed correctly
        # (no protocol confusion).
        self.assertEqual(r["verdict"], "fail-dead-url-cited")
        # The cleaned URL should be the 9d055289 dead-URL (no trailing period)
        self.assertEqual(r["dead_urls"][0]["url"], DEAD_404_URL)


# ---------------------------------------------------------------------------
# Should-skip logic
# ---------------------------------------------------------------------------
class TestShouldSkip(unittest.TestCase):

    def test_localhost_skipped(self) -> None:
        skip, reason = _should_skip("http://localhost:8080/x")
        self.assertTrue(skip)
        self.assertIn("host", (reason or "").lower())

    def test_127_skipped(self) -> None:
        skip, _ = _should_skip("http://127.0.0.1/x")
        self.assertTrue(skip)

    def test_private_192_168_skipped(self) -> None:
        skip, _ = _should_skip("http://192.168.1.1/x")
        self.assertTrue(skip)

    def test_example_com_skipped(self) -> None:
        # example.com is in the skip-list (RFC-defined test domain)
        skip, _ = _should_skip("https://example.com/x")
        self.assertTrue(skip)

    def test_real_host_not_skipped(self) -> None:
        skip, _ = _should_skip("https://github.com/foo/bar")
        self.assertFalse(skip)

    def test_mailto_scheme_skipped(self) -> None:
        skip, _ = _should_skip("mailto:foo@bar.com")
        self.assertTrue(skip)


# ---------------------------------------------------------------------------
# Status classification
# ---------------------------------------------------------------------------
class TestClassify(unittest.TestCase):

    def test_200_live(self) -> None:
        self.assertEqual(_classify(200), "live")

    def test_301_live(self) -> None:
        self.assertEqual(_classify(301), "live")

    def test_404_dead(self) -> None:
        self.assertEqual(_classify(404), "dead")

    def test_410_dead(self) -> None:
        self.assertEqual(_classify(410), "dead")

    def test_500_dead(self) -> None:
        self.assertEqual(_classify(500), "dead")

    def test_503_dead(self) -> None:
        self.assertEqual(_classify(503), "dead")

    def test_403_ambiguous(self) -> None:
        self.assertEqual(_classify(403), "ambiguous")

    def test_401_ambiguous(self) -> None:
        self.assertEqual(_classify(401), "ambiguous")

    def test_429_ambiguous(self) -> None:
        self.assertEqual(_classify(429), "ambiguous")

    def test_none_unknown(self) -> None:
        self.assertEqual(_classify(None), "unknown")


# ---------------------------------------------------------------------------
# JSON output schema validity
# ---------------------------------------------------------------------------
class TestJsonOutput(unittest.TestCase):

    def test_pass_no_urls_has_schema_version(self) -> None:
        r = _run("no_urls.md")
        self.assertEqual(r["schema"], SCHEMA_VERSION)
        self.assertEqual(r["gate"], GATE)
        self.assertIn("verdict", r)
        self.assertIn("reason", r)

    def test_fail_dead_url_has_dead_urls_array(self) -> None:
        r = _run("dead_url_404.md", probe_fn=PROBE_DEAD_404)
        self.assertIn("dead_urls", r)
        self.assertIsInstance(r["dead_urls"], list)
        first = r["dead_urls"][0]
        self.assertIn("url", first)
        self.assertIn("status", first)
        self.assertEqual(first["classification"], "dead")

    def test_counts_block_present(self) -> None:
        r = _run("all_live_urls.md", probe_fn=PROBE_ALL_LIVE)
        self.assertIn("counts", r)
        for key in ("live", "dead", "ambiguous", "network_failures", "skipped", "probed"):
            self.assertIn(key, r["counts"])


# ---------------------------------------------------------------------------
# Real-world MMMMM anchor: Hyperbridge OP dispute dead-URL archive
# ---------------------------------------------------------------------------
class TestMMMMMAnchor(unittest.TestCase):
    """Live-dogfood test against the actual archived dead-URL Hyperbridge
    dispute draft (read-only, L34-compliant)."""

    DEAD_URL_ARCHIVE = Path(
        "/Users/wolf/audits/hyperbridge/submissions/_lessons-learned/"
        "hb-optimism-l2oracle-dispute-v2-SHORT-DEAD-URL-2026-05-23.md"
    )

    LIVE_URL_DRAFT = Path(
        "/Users/wolf/audits/hyperbridge/submissions/staging/"
        "hb-optimism-l2oracle-dispute-v2-SHORT/"
        "hb-optimism-l2oracle-dispute-v2-SHORT.md"
    )

    def test_dead_archive_must_fail_with_mocked_probe(self) -> None:
        """Use mocked 404 probe to confirm the dead-URL archive triggers fail.

        Test only runs if the archive file exists (it does as of 2026-05-23).
        """
        if not self.DEAD_URL_ARCHIVE.exists():
            self.skipTest("Hyperbridge dead-URL archive not present in env")
        probe = make_probe_fn({
            DEAD_404_URL: {"status": 404, "method": "HEAD", "error": "HTTP 404"},
        })
        r = check(self.DEAD_URL_ARCHIVE, probe_fn=probe)
        self.assertEqual(r["verdict"], "fail-dead-url-cited")
        self.assertGreaterEqual(r["counts"]["dead"], 1)
        # Verify the actual dead URL is the 9d055289 gist
        dead_urls_str = [d["url"] for d in r["dead_urls"]]
        self.assertTrue(
            any("9d055289" in u for u in dead_urls_str),
            msg=f"Expected 9d055289 dead-URL in {dead_urls_str}",
        )

    def test_live_draft_passes_with_mocked_probe(self) -> None:
        """The fixed draft should pass with the live-URL gist."""
        if not self.LIVE_URL_DRAFT.exists():
            self.skipTest("Hyperbridge fixed draft not present in env")
        probe = make_probe_fn({
            # Everything 200
        })
        r = check(self.LIVE_URL_DRAFT, probe_fn=probe)
        # The fixed draft has a live URL; verdict should be pass-all-urls-live
        # OR ok-rebuttal if a rebuttal marker is present.
        self.assertIn(r["verdict"], ("pass-all-urls-live", "ok-rebuttal"))


if __name__ == "__main__":
    unittest.main()
