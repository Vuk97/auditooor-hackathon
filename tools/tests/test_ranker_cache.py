#!/usr/bin/env python3
"""test_ranker_cache.py — Wave-8 module-level tag/rule cache tests.

Assertions:
  1. First load_tags() call populates cache (mtime > 0, cache not None).
  2. Second load_tags() call returns the identical list object (cache hit,
     no re-read from disk).
  3. File mtime change triggers cache refresh (new data replaces old cache).
  4. RANKER_CACHE_DISABLED=1 bypasses the cache entirely (always re-reads).
  5. Concurrent rank() calls do not crash (basic thread-safety smoke test).
  6. Cache survives across multiple rank() calls in the same process
     (module-level globals persist, not cleared between calls).
  7. load_rules() cache populates on first call; hit on second call.
  8. load_bug_class_to_ac_map() cache populates and hits.
  9. load_cross_lang_map() cache populates and hits.

context_pack_id: auditooor.vault_context_pack.v1:resume:0f215322f432e859
context_pack_hash: 0f215322f432e85958d7066d789a969fde5a36155a57b8d5f3d2bc5d62a677ea
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# Wave-8 fix: sibling test test_ranker_per_family_recency may set
# RANKER_CACHE_DISABLED=1 globally via os.environ.setdefault. Pop here at
# module import AND in setUpModule (which runs after all module imports)
# to ensure cache tests run against the live cache code path regardless
# of test-module import order.
os.environ.pop("RANKER_CACHE_DISABLED", None)


def setUpModule():
    """Run after all test modules have been imported. Defends against
    sibling-test env-var pollution from `os.environ.setdefault` at their
    import time (e.g. test_ranker_per_family_recency.py)."""
    os.environ.pop("RANKER_CACHE_DISABLED", None)


REPO_ROOT = Path(__file__).resolve().parents[2]
RANKER_PATH = REPO_ROOT / "tools" / "ranker.py"

# Disable prediction-log writes during tests.
os.environ.setdefault("RANKER_PREDICTION_LOG_DISABLED", "1")


def _load_ranker(key: str = "_ranker_cache_test"):
    """Load ranker.py in-process with sys.modules pre-registration."""
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, str(RANKER_PATH))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot create spec for {RANKER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


def _reset_tag_cache(mod):
    """Reset only the tag cache globals so the next load_tags() is a miss."""
    mod._TAG_CACHE = None
    mod._TAG_CACHE_MTIME = 0.0
    mod._TAG_CACHE_DIR = None


def _reset_all_caches(mod):
    """Reset all four caches to simulate a fresh process load."""
    mod._TAG_CACHE = None
    mod._TAG_CACHE_MTIME = 0.0
    mod._TAG_CACHE_DIR = None
    mod._RULES_CACHE = None
    mod._RULES_CACHE_MTIME = 0.0
    mod._RULES_CACHE_PATH = None
    mod._BUG_CLASS_MAP_CACHE = None
    mod._BUG_CLASS_MAP_CACHE_MTIME = 0.0
    mod._BUG_CLASS_MAP_CACHE_PATH = None
    mod._CROSS_LANG_MAP_CACHE = None
    mod._CROSS_LANG_MAP_CACHE_MTIME = 0.0
    mod._CROSS_LANG_MAP_CACHE_PATH = None


class TestTagCachePopulation(unittest.TestCase):
    """Assertion 1: first call populates cache (mtime > 0, cache not None)."""

    def setUp(self):
        # Wave-8 fix: ensure cache is enabled (sibling test may set it)
        os.environ.pop("RANKER_CACHE_DISABLED", None)
        self.mod = _load_ranker("_ranker_cache_pop_test")
        _reset_tag_cache(self.mod)
        # Ensure cache is clear
        self.assertIsNone(self.mod._TAG_CACHE)
        self.assertEqual(self.mod._TAG_CACHE_MTIME, 0.0)

    def test_first_call_populates_cache(self):
        tags_dir = REPO_ROOT / "audit" / "corpus_tags" / "tags"
        if not tags_dir.exists():
            self.skipTest("corpus_tags/tags directory not found")
        # First call — cache miss
        result = self.mod.load_tags(tags_dir)
        self.assertIsNotNone(self.mod._TAG_CACHE, "cache must be set after first call")
        self.assertGreater(self.mod._TAG_CACHE_MTIME, 0.0, "cache mtime must be > 0 after first call")
        self.assertIsInstance(result, list, "load_tags must return a list")


class TestTagCacheHit(unittest.TestCase):
    """Assertion 2: second call returns the same list object (no re-read)."""

    def setUp(self):
        self.mod = _load_ranker("_ranker_cache_hit_test")
        _reset_tag_cache(self.mod)

    def test_second_call_is_cache_hit(self):
        tags_dir = REPO_ROOT / "audit" / "corpus_tags" / "tags"
        if not tags_dir.exists():
            self.skipTest("corpus_tags/tags directory not found")
        first = self.mod.load_tags(tags_dir)
        second = self.mod.load_tags(tags_dir)
        self.assertIs(
            first,
            second,
            "second load_tags() call must return the identical list object (cache hit)",
        )


class TestTagCacheInvalidation(unittest.TestCase):
    """Assertion 3: mtime change triggers cache refresh."""

    def test_mtime_change_causes_refresh(self):
        mod = _load_ranker("_ranker_cache_invalidation_test")
        tags_dir = REPO_ROOT / "audit" / "corpus_tags" / "tags"
        if not tags_dir.exists():
            self.skipTest("corpus_tags/tags directory not found")

        _reset_tag_cache(mod)
        first = mod.load_tags(tags_dir)
        saved_cache = mod._TAG_CACHE

        # Force a cache miss by rolling the mtime back in the module global
        # (simulating that a file was written since the last load).
        mod._TAG_CACHE_MTIME = 0.0  # any future mtime will exceed 0.0

        second = mod.load_tags(tags_dir)
        # The cache was re-built; it may or may not be the same *object* (depends
        # on whether any file actually changed), but the refresh path must have
        # been taken (the old _TAG_CACHE should have been replaced).
        self.assertIsNotNone(second)
        # The cache object should have been rebuilt (new list allocated).
        self.assertIsNot(
            saved_cache,
            mod._TAG_CACHE,
            "after mtime rollback, cache must have been rebuilt (new object)",
        )


class TestCacheDisabledEnvVar(unittest.TestCase):
    """Assertion 4: RANKER_CACHE_DISABLED=1 bypasses cache on every call."""

    def test_cache_disabled_always_reloads(self):
        mod = _load_ranker("_ranker_cache_disabled_test")
        tags_dir = REPO_ROOT / "audit" / "corpus_tags" / "tags"
        if not tags_dir.exists():
            self.skipTest("corpus_tags/tags directory not found")

        _reset_tag_cache(mod)
        old_env = os.environ.get("RANKER_CACHE_DISABLED")
        try:
            os.environ["RANKER_CACHE_DISABLED"] = "1"
            first = mod.load_tags(tags_dir)
            second = mod.load_tags(tags_dir)
            # With cache disabled, each call returns a fresh list object.
            self.assertIsNot(
                first,
                second,
                "RANKER_CACHE_DISABLED=1 must force fresh disk reads (different list objects)",
            )
            # Module-level cache globals must remain unpopulated.
            self.assertIsNone(
                mod._TAG_CACHE,
                "RANKER_CACHE_DISABLED=1 must not populate module-level cache",
            )
        finally:
            if old_env is None:
                os.environ.pop("RANKER_CACHE_DISABLED", None)
            else:
                os.environ["RANKER_CACHE_DISABLED"] = old_env


class TestConcurrentRankCalls(unittest.TestCase):
    """Assertion 5: concurrent rank() calls do not crash."""

    def test_concurrent_rank_calls_no_crash(self):
        mod = _load_ranker("_ranker_cache_concurrent_test")
        _reset_all_caches(mod)

        errors: list[Exception] = []
        results: list[object] = []
        lock = threading.Lock()

        def _worker(i: int):
            try:
                r = mod.rank(
                    target_repo="dydxprotocol/v4-chain",
                    file_path="protocol/x/affiliates/keeper/msg_server.go",
                    function_signature=(
                        f"func (k Keeper) TestFn{i}(ctx context.Context) error"
                    ),
                    top_n=3,
                    min_confidence=0.0,
                )
                with lock:
                    results.append(r)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        self.assertEqual(
            errors,
            [],
            f"concurrent rank() calls must not raise; got errors: {errors}",
        )
        self.assertEqual(
            len(results),
            8,
            "all 8 concurrent rank() calls must return a result",
        )


class TestCacheSurvivesMultipleRankCalls(unittest.TestCase):
    """Assertion 6: cache survives across multiple rank() calls in same process."""

    def test_cache_not_cleared_between_calls(self):
        mod = _load_ranker("_ranker_cache_persist_test")
        _reset_all_caches(mod)

        for i in range(5):
            mod.rank(
                target_repo="dydxprotocol/v4-chain",
                file_path="protocol/x/affiliates/keeper/msg_server.go",
                function_signature=f"func (k Keeper) Fn{i}(ctx context.Context) error",
                top_n=3,
                min_confidence=0.0,
            )

        # After 5 calls, cache must be populated (not reset to None between calls).
        tags_dir = REPO_ROOT / "audit" / "corpus_tags" / "tags"
        if tags_dir.exists():
            self.assertIsNotNone(
                mod._TAG_CACHE,
                "tag cache must remain populated across multiple rank() calls",
            )
            self.assertGreater(
                mod._TAG_CACHE_MTIME,
                0.0,
                "tag cache mtime must remain > 0 after multiple rank() calls",
            )


class TestRulesCachePopulationAndHit(unittest.TestCase):
    """Assertion 7: load_rules() cache populates on first call; hit on second."""

    def test_rules_cache_populate_and_hit(self):
        mod = _load_ranker("_ranker_rules_cache_test")
        mod._RULES_CACHE = None
        mod._RULES_CACHE_MTIME = 0.0
        mod._RULES_CACHE_PATH = None

        rules_path = REPO_ROOT / "audit" / "ranker_rules.yaml"
        if not rules_path.exists():
            self.skipTest("audit/ranker_rules.yaml not found")

        first = mod.load_rules(rules_path)
        self.assertIsNotNone(mod._RULES_CACHE, "rules cache must be set after first call")
        self.assertGreater(mod._RULES_CACHE_MTIME, 0.0)

        second = mod.load_rules(rules_path)
        self.assertIs(first, second, "second load_rules() must return cached list object")


class TestBugClassMapCachePopulationAndHit(unittest.TestCase):
    """Assertion 8: load_bug_class_to_ac_map() cache populates and hits."""

    def test_bug_class_map_cache_populate_and_hit(self):
        mod = _load_ranker("_ranker_bcmap_cache_test")
        mod._BUG_CLASS_MAP_CACHE = None
        mod._BUG_CLASS_MAP_CACHE_MTIME = 0.0
        mod._BUG_CLASS_MAP_CACHE_PATH = None

        map_path = REPO_ROOT / "audit" / "bug_class_to_attack_classes_map.yaml"
        if not map_path.exists():
            self.skipTest("audit/bug_class_to_attack_classes_map.yaml not found")

        first = mod.load_bug_class_to_ac_map(map_path)
        self.assertIsNotNone(mod._BUG_CLASS_MAP_CACHE, "bug-class map cache must be set after first call")
        self.assertGreater(mod._BUG_CLASS_MAP_CACHE_MTIME, 0.0)

        second = mod.load_bug_class_to_ac_map(map_path)
        self.assertIs(first, second, "second load_bug_class_to_ac_map() must return cached dict object")


class TestCrossLangMapCachePopulationAndHit(unittest.TestCase):
    """Assertion 9: load_cross_lang_map() cache populates and hits."""

    def test_cross_lang_map_cache_populate_and_hit(self):
        mod = _load_ranker("_ranker_xlang_cache_test")
        mod._CROSS_LANG_MAP_CACHE = None
        mod._CROSS_LANG_MAP_CACHE_MTIME = 0.0
        mod._CROSS_LANG_MAP_CACHE_PATH = None

        map_path = REPO_ROOT / "reference" / "cross_lang_detector_map.yaml"
        if not map_path.exists():
            self.skipTest("reference/cross_lang_detector_map.yaml not found")

        first = mod.load_cross_lang_map(map_path)
        self.assertIsNotNone(mod._CROSS_LANG_MAP_CACHE, "cross-lang map cache must be set after first call")
        self.assertGreater(mod._CROSS_LANG_MAP_CACHE_MTIME, 0.0)

        second = mod.load_cross_lang_map(map_path)
        self.assertIs(first, second, "second load_cross_lang_map() must return cached dict object")


if __name__ == "__main__":
    unittest.main()
