"""Hermetic tests for ``tools/lib/hackerman_web_cache.py``.

No live network. ``WebCache`` is constructed with a ``prefetched`` dict
that maps URL -> bytes; the fetcher stub is never called for the
synthetic-cache path.
"""
from __future__ import annotations

import gzip
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import List, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_CACHE = REPO_ROOT / "tools" / "lib" / "hackerman_web_cache.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class HackermanWebCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.wc = _load(WEB_CACHE, "_hackerman_web_cache_tests")

    def test_url_to_sha256_deterministic(self) -> None:
        a = self.wc.url_to_sha256("https://example.com/x")
        b = self.wc.url_to_sha256("https://example.com/x")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_compute_payload_sha256_matches(self) -> None:
        payload = b"hello world"
        self.assertEqual(len(self.wc.compute_payload_sha256(payload)), 64)

    def test_prefetched_fetch_writes_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = self.wc.WebCache(
                cache_dir=Path(tmp),
                respect_robots=False,
                i_acknowledge_tos=True,
                prefetched={"https://x/": b"<html>test</html>"},
                sleep=lambda _s: None,
            )
            result = cache.fetch("https://x/")
            self.assertFalse(result.from_cache)
            self.assertEqual(result.payload, b"<html>test</html>")
            page, meta = cache.cached_paths("https://x/")
            self.assertTrue(page.exists())
            self.assertTrue(meta.exists())
            metadata = json.loads(meta.read_text(encoding="utf-8"))
            self.assertEqual(metadata["payload_sha256"], result.payload_sha256)

    def test_cache_hit_avoids_fetcher(self) -> None:
        calls: List[str] = []

        def stub_fetcher(url: str, _t: int) -> Tuple[bytes, int, str]:
            calls.append(url)
            return b"NETWORK", 200, "text/html"

        with tempfile.TemporaryDirectory() as tmp:
            cache = self.wc.WebCache(
                cache_dir=Path(tmp), respect_robots=False, i_acknowledge_tos=True,
                prefetched={"https://x/": b"<html>x</html>"},
                fetcher=stub_fetcher, sleep=lambda _s: None,
            )
            cache.fetch("https://x/")
            # Second fetch should be served from disk cache, NOT the fetcher.
            r2 = cache.fetch("https://x/")
            self.assertTrue(r2.from_cache)
            self.assertEqual(calls, [])  # fetcher never invoked

    def test_robots_disallowed_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            robots_body = b"User-agent: *\nDisallow: /private/\n"
            cache = self.wc.WebCache(
                cache_dir=Path(tmp), respect_robots=True,
                prefetched={"https://immunefi.com/robots.txt": robots_body},
                sleep=lambda _s: None,
            )
            with self.assertRaises(self.wc.RobotsDisallowedError):
                cache.fetch("https://immunefi.com/private/secret")

    def test_robots_allowed_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            robots_body = b"User-agent: *\nAllow: /\n"
            cache = self.wc.WebCache(
                cache_dir=Path(tmp), respect_robots=True,
                prefetched={
                    "https://immunefi.com/robots.txt": robots_body,
                    "https://immunefi.com/explore/": b"<html>OK</html>",
                },
                sleep=lambda _s: None,
            )
            result = cache.fetch("https://immunefi.com/explore/")
            self.assertEqual(result.payload, b"<html>OK</html>")

    def test_rate_limit_invokes_sleep(self) -> None:
        sleeps: List[float] = []

        def stub_fetcher(_url: str, _t: int) -> Tuple[bytes, int, str]:
            return b"x", 200, "text/html"

        with tempfile.TemporaryDirectory() as tmp:
            cache = self.wc.WebCache(
                cache_dir=Path(tmp), respect_robots=False, i_acknowledge_tos=True,
                rate_limit_ms=1500, fetcher=stub_fetcher,
                sleep=lambda s: sleeps.append(s),
            )
            cache.fetch("https://a/")  # first; no sleep (last_fetch_at==0)
            cache.fetch("https://b/")  # second; should sleep
            self.assertTrue(sleeps)
            # The first sleep is the rate-limit between fetch 1 and fetch 2.
            self.assertGreater(sleeps[0], 0.0)

    def test_payload_sha256_in_meta_matches_disk(self) -> None:
        payload = b"<html>abc</html>"
        with tempfile.TemporaryDirectory() as tmp:
            cache = self.wc.WebCache(
                cache_dir=Path(tmp), respect_robots=False, i_acknowledge_tos=True,
                prefetched={"https://x/": payload}, sleep=lambda _s: None,
            )
            r = cache.fetch("https://x/")
            page, _ = cache.cached_paths("https://x/")
            with gzip.open(page, "rb") as fh:
                disk = fh.read()
            self.assertEqual(disk, payload)
            self.assertEqual(r.payload_sha256, self.wc.compute_payload_sha256(payload))

    def test_iter_cached_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = self.wc.WebCache(
                cache_dir=Path(tmp), respect_robots=False, i_acknowledge_tos=True,
                prefetched={
                    "https://a/": b"<a/>",
                    "https://b/": b"<b/>",
                },
                sleep=lambda _s: None,
            )
            cache.fetch("https://a/")
            cache.fetch("https://b/")
            seen = sorted([r.url for r in cache.iter_cached()])
            self.assertEqual(seen, ["https://a/", "https://b/"])

    def test_robots_decision_helper(self) -> None:
        decision = self.wc.robots_decision(
            "User-agent: *\nDisallow: /no/\n",
            url="https://h/no/x",
        )
        self.assertFalse(decision["allowed"])
        decision2 = self.wc.robots_decision(
            "User-agent: *\nDisallow: /no/\n",
            url="https://h/yes/x",
        )
        self.assertTrue(decision2["allowed"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
