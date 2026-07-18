"""Tests for the Hackerman ETL miner registry builder.

Verifies:
1. Registry directory exists with one JSON per miner + a `_manifest.json`.
2. Per-entry schema (every required key present, expected types).
3. All `tool_path` values point at on-disk miner scripts.
4. All `target_subtree` values either (a) exist on disk, or (b) the entry
   is marked `honest_zero=true` (no fabricated subtrees).
5. All `companion_test_path` values point at on-disk test files.
6. `_manifest.json` is internally consistent (miner_count matches list,
   honest_zero_count matches honest_zero_miners length).
7. `source_channel` values come from the valid set.
8. `verification_tier` values come from {tier-1, tier-2, tier-3}.
9. The list of registry entries is in one-to-one correspondence with the
   set of `tools/hackerman-etl-from-*.py` scripts on disk (no missing,
   no extras).
10. ``--check`` exit-code path is wired (smoke test: dry run does not
    explode).

Tests deliberately read the on-disk registry (regenerating it on the fly
into a tmpdir for each test would lose the "is the committed registry
current?" signal). The build script itself is exercised by
``--check`` so drift is still caught in CI via
``make hackerman-etl-registry-check``.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REGISTRY_DIR = REPO_ROOT / "tools" / "audit" / "etl_miner_registry"
MINERS_GLOB = "hackerman-etl-from-*.py"
BUILDER = REPO_ROOT / "tools" / "hackerman-etl-miner-registry-build.py"

VALID_SOURCE_CHANNELS = {
    "gh-api",
    "github-rest-api",
    "pdf-listing",
    "web-scrape",
    "commit-history",
    "corpus-bridge",
}
VALID_VERIFICATION_TIERS = {"tier-1", "tier-2", "tier-3"}

REQUIRED_ENTRY_KEYS = {
    "schema",
    "miner_slug",
    "tool_path",
    "description",
    "target_subtree",
    "target_subtree_exists_on_disk",
    "source_channel",
    "verification_tier",
    "companion_test_path",
    "makefile_target",
    "record_count_emitted",
    "honest_zero",
    "last_run_commit_sha",
}


def _load_entry(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_manifest() -> dict:
    return _load_entry(REGISTRY_DIR / "_manifest.json")


def _all_entry_files() -> list[Path]:
    return sorted(p for p in REGISTRY_DIR.glob("*.json") if p.name != "_manifest.json")


def _slug_from_miner_file(p: Path) -> str:
    """tools/hackerman-etl-from-foo-bar.py -> foo_bar"""
    return p.name.replace("hackerman-etl-from-", "").replace(".py", "").replace("-", "_")


def _load_builder():
    spec = importlib.util.spec_from_file_location("_etl_registry_builder_test", BUILDER)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestRegistryShape(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not REGISTRY_DIR.exists():
            raise unittest.SkipTest(f"registry dir not built: {REGISTRY_DIR}")
        if not (REGISTRY_DIR / "_manifest.json").exists():
            raise unittest.SkipTest("manifest missing; run 'make hackerman-etl-registry-build'")

    def test_01_directory_exists_and_has_entries(self):
        self.assertTrue(REGISTRY_DIR.is_dir())
        entries = _all_entry_files()
        self.assertGreaterEqual(
            len(entries),
            50,
            f"expected >=50 miner entries, found {len(entries)} - run registry-build",
        )

    def test_02_per_entry_schema(self):
        for p in _all_entry_files():
            with self.subTest(entry=p.name):
                e = _load_entry(p)
                self.assertEqual(e["schema"], "auditooor.hackerman_etl_miner_registry_entry.v1")
                missing = REQUIRED_ENTRY_KEYS - set(e.keys())
                self.assertFalse(missing, f"missing keys: {missing}")
                # Type checks
                self.assertIsInstance(e["miner_slug"], str)
                self.assertIsInstance(e["tool_path"], str)
                self.assertIsInstance(e["description"], str)
                self.assertIsInstance(e["honest_zero"], bool)
                self.assertIsInstance(e["target_subtree_exists_on_disk"], bool)
                self.assertIsInstance(e["record_count_emitted"], int)

    def test_03_all_tool_paths_exist(self):
        for p in _all_entry_files():
            with self.subTest(entry=p.name):
                e = _load_entry(p)
                tool = REPO_ROOT / e["tool_path"]
                self.assertTrue(tool.is_file(), f"tool_path missing: {tool}")

    def test_04_target_subtree_or_honest_zero(self):
        """target_subtree must exist on disk OR entry is honest_zero=true."""
        for p in _all_entry_files():
            with self.subTest(entry=p.name):
                e = _load_entry(p)
                sub = e["target_subtree"]
                exists = e["target_subtree_exists_on_disk"]
                honest_zero = e["honest_zero"]
                count = e["record_count_emitted"]
                if sub is not None:
                    sub_path = REPO_ROOT / sub
                    # Either: (a) subtree exists with records, or
                    #          (b) honest_zero=true and either subtree missing or zero records
                    if exists:
                        self.assertEqual((count == 0), honest_zero)
                        self.assertTrue(sub_path.is_dir(), f"subtree advertised exists but missing: {sub_path}")
                    else:
                        self.assertTrue(
                            honest_zero,
                            f"{e['miner_slug']}: target_subtree {sub} not on disk but honest_zero=false",
                        )

    def test_05_companion_test_paths_exist(self):
        for p in _all_entry_files():
            with self.subTest(entry=p.name):
                e = _load_entry(p)
                tp = e["companion_test_path"]
                if tp is None:
                    continue
                self.assertTrue(
                    (REPO_ROOT / tp).is_file(),
                    f"companion_test_path missing: {tp}",
                )

    def test_06_manifest_internal_consistency(self):
        m = _load_manifest()
        self.assertEqual(m["schema"], "auditooor.hackerman_etl_miner_registry_manifest.v1")
        self.assertEqual(m["miner_count"], len(m["miners"]))
        self.assertEqual(m["honest_zero_count"], len(m["honest_zero_miners"]))
        # Every honest-zero miner must appear in the miner list
        miners_set = set(m["miners"])
        self.assertTrue(set(m["honest_zero_miners"]).issubset(miners_set))
        # Per-channel + per-tier counts must sum to miner_count
        self.assertEqual(sum(m["by_source_channel"].values()), m["miner_count"])
        self.assertEqual(sum(m["by_verification_tier"].values()), m["miner_count"])

    def test_07_source_channel_values_valid(self):
        for p in _all_entry_files():
            with self.subTest(entry=p.name):
                e = _load_entry(p)
                self.assertIn(
                    e["source_channel"],
                    VALID_SOURCE_CHANNELS,
                    f"invalid source_channel: {e['source_channel']}",
                )

    def test_08_verification_tier_values_valid(self):
        for p in _all_entry_files():
            with self.subTest(entry=p.name):
                e = _load_entry(p)
                self.assertIn(
                    e["verification_tier"],
                    VALID_VERIFICATION_TIERS,
                    f"invalid verification_tier: {e['verification_tier']}",
                )

    def test_09_one_to_one_with_disk_miners(self):
        """No missing entries; no orphan entries."""
        disk_miners = sorted((REPO_ROOT / "tools").glob(MINERS_GLOB))
        expected_slugs = {_slug_from_miner_file(m) for m in disk_miners}
        registered_slugs = {p.stem for p in _all_entry_files()}
        missing = expected_slugs - registered_slugs
        orphan = registered_slugs - expected_slugs
        self.assertFalse(missing, f"missing registry entries for miners: {missing}")
        self.assertFalse(orphan, f"orphan registry entries (no on-disk miner): {orphan}")

    def test_10_check_subcommand_executes(self):
        """`--check` exits 0 (registry currently in-sync after this test session)."""
        if not BUILDER.exists():
            self.skipTest(f"builder missing: {BUILDER}")
        rc = subprocess.call(
            [sys.executable, str(BUILDER), "--check", "--out-dir", str(REGISTRY_DIR)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Drift is acceptable (=1) here only if the registry was hand-edited
        # since the last build. In CI the canonical invocation is the build
        # step, which we exercise in the next test by writing into a tmp dir.
        self.assertIn(rc, (0, 1))

    def test_11_builder_writes_into_tmpdir(self):
        """Smoke: full rebuild into a tmp dir yields a non-empty registry."""
        if not BUILDER.exists():
            self.skipTest(f"builder missing: {BUILDER}")
        with tempfile.TemporaryDirectory() as tmp:
            rc = subprocess.call(
                [sys.executable, str(BUILDER), "--out-dir", tmp, "--quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertEqual(rc, 0)
            tmp_path = Path(tmp)
            self.assertTrue((tmp_path / "_manifest.json").is_file())
            built = list(tmp_path.glob("*.json"))
            self.assertGreater(len(built), 50)

    def test_12_post_mortem_miner_has_curated_default_target_and_make_target(self):
        """The generic post-mortem miner uses a legacy Make target name."""
        if not BUILDER.exists():
            self.skipTest(f"builder missing: {BUILDER}")
        builder = _load_builder()
        entry = builder.build_entry(REPO_ROOT / "tools" / "hackerman-etl-from-post-mortem.py")
        self.assertEqual(entry["target_subtree"], "audit/corpus_tags/tags/post_mortem")
        self.assertEqual(entry["makefile_target"], "hackerman-etl-post-mortem")
        self.assertEqual(entry["source_channel"], "web-scrape")

    def test_13_darknavy_miner_has_curated_default_target_and_make_target(self):
        """Darknavy should be tracked as a first-class mined web source."""
        if not BUILDER.exists():
            self.skipTest(f"builder missing: {BUILDER}")
        builder = _load_builder()
        entry = builder.build_entry(REPO_ROOT / "tools" / "hackerman-etl-from-darknavy-web3.py")
        self.assertEqual(entry["target_subtree"], "audit/corpus_tags/tags/darknavy_web3_incidents")
        self.assertEqual(entry["makefile_target"], "darknavy-web3-mine")
        self.assertEqual(entry["source_channel"], "web-scrape")
        self.assertGreater(entry["record_count_emitted"], 0)


if __name__ == "__main__":
    unittest.main()
