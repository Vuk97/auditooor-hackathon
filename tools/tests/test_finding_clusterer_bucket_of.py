#!/usr/bin/env python3
"""Offline tests for tools/finding-clusterer.py `bucket_of()`.

Covers the PR #481 follow-up fix: when a finding's text matches multiple
keywords, the classifier must pick the LONGEST (most specific) matching
keyword instead of the first-declared one. Tie-break is alphabetical on
bucket name for determinism.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "finding-clusterer.py"


def _load_clusterer_module():
    """Import finding-clusterer.py as a module despite the hyphen in its name."""
    spec = importlib.util.spec_from_file_location("finding_clusterer", TOOL)
    assert spec and spec.loader, "finding-clusterer.py missing"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CLUSTERER = _load_clusterer_module()


def _finding(text: str) -> dict:
    """Build a minimal finding dict whose haystack is exactly `text`."""
    return {"title": text, "tags": [], "content": ""}


class BucketOfLongestKeywordTests(unittest.TestCase):
    """`bucket_of()` must pick the longest matching keyword, not the first."""

    def test_long_keyword_wins_over_short_in_different_bucket(self):
        """A finding mentioning both a short and a longer (more specific) keyword
        from a different bucket should be classified into the LONGER-keyword's
        bucket.

        BUCKETS contains:
          - "reentrancy" -> ["reentran", ...]            (short: 8 chars)
          - "bridge-layerzero" -> ["cross-chain", ...]   (long: 11 chars)

        A finding mentioning both "reentran" and "cross-chain" should land in
        bridge-layerzero (longest keyword wins), not in reentrancy (declared
        first). With the old first-match-wins logic, this returned
        "reentrancy".
        """
        text = "cross-chain reentrancy on bridge"
        bucket = CLUSTERER.bucket_of(_finding(text))
        self.assertEqual(
            bucket,
            "bridge-layerzero",
            f"expected 'bridge-layerzero' (longer keyword 'cross-chain' wins) but got {bucket!r}",
        )

    def test_only_short_keyword_present_picks_short_bucket(self):
        """When ONLY the short keyword is present, the classifier should still
        pick that bucket. Sanity check: the longest-wins rule must not break
        single-match cases.
        """
        text = "classic reentrancy via callback"
        bucket = CLUSTERER.bucket_of(_finding(text))
        self.assertEqual(bucket, "reentrancy")

    def test_tie_on_keyword_length_breaks_alphabetically_on_bucket(self):
        """When two matching keywords have the SAME length, tie-break must be
        alphabetical on bucket name (deterministic).

        We construct a finding whose haystack contains two same-length
        keywords from two different buckets:
          - "oracle"  (6 chars) -> bucket "oracle-manipulation"
          - "permit"  (6 chars) -> bucket "erc20-token"

        Alphabetical tie-break: "erc20-token" < "oracle-manipulation".
        """
        text = "oracle permit interaction"
        bucket = CLUSTERER.bucket_of(_finding(text))
        # Both keywords match; both have length 6. Alphabetical first wins.
        self.assertEqual(
            bucket,
            "erc20-token",
            f"expected alphabetical tie-break to 'erc20-token' but got {bucket!r}",
        )

    def test_no_keyword_match_returns_unclassified(self):
        """Findings whose haystack contains no bucket keyword fall into
        the 'unclassified' default bucket.
        """
        text = "totally unrelated finding text with nothing notable"
        bucket = CLUSTERER.bucket_of(_finding(text))
        self.assertEqual(bucket, "unclassified")

    def test_empty_finding_returns_unclassified(self):
        """An empty finding (no title/tags/content) classifies as unclassified."""
        bucket = CLUSTERER.bucket_of({})
        self.assertEqual(bucket, "unclassified")


if __name__ == "__main__":
    unittest.main()
