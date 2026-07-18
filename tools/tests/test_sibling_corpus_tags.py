"""
test_sibling_corpus_tags.py
Wave-8 deliverable: 4+ assertions verifying the sibling-corpus tag growth
produced by the cosmos-sdk-fork + morpho-family mining pass (2026-05-11).
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"
SCHEMA_TOOL = REPO_ROOT / "tools" / "verdict-tag-schema.py"


class TestSiblingCorpusTagsExist(unittest.TestCase):
    """Assertion 1: At least 20 new sibling-repo tags exist."""

    def test_at_least_20_sibling_tags_exist(self):
        sibling_tags = list(TAGS_DIR.glob("sibling_*.yaml"))
        self.assertGreaterEqual(
            len(sibling_tags),
            20,
            f"Expected >= 20 sibling tags under {TAGS_DIR}, found {len(sibling_tags)}: "
            f"{[p.name for p in sibling_tags]}",
        )


class TestSiblingTagsSchemaValid(unittest.TestCase):
    """Assertion 2: All new sibling tags validate against schema v2."""

    def test_all_sibling_tags_pass_schema(self):
        sibling_tags = list(TAGS_DIR.glob("sibling_*.yaml"))
        self.assertGreater(len(sibling_tags), 0, "No sibling_*.yaml files found")

        result = subprocess.run(
            [sys.executable, str(SCHEMA_TOOL), "--validate-dir", str(TAGS_DIR), "--quiet"],
            capture_output=True,
            text=True,
        )
        # Parse results: look for FAIL lines that match sibling_ tags
        failures = [
            line for line in result.stdout.splitlines()
            if line.startswith("FAIL") and "sibling_" in line
        ]
        self.assertEqual(
            failures,
            [],
            f"Schema validation failures on sibling tags:\n" + "\n".join(failures),
        )


class TestByTargetRepoIndexHasSiblingRepos(unittest.TestCase):
    """Assertion 3: by_target_repo index includes sibling cosmos-sdk-fork or morpho repos."""

    EXPECTED_REPOS = {
        "osmosis-labs/osmosis",
        "cosmos/cosmos-sdk",
        "penumbra-zone/penumbra",
        "morpho-org/morpho-blue",
    }

    def _load_index_keys(self) -> set:
        index_path = INDEX_DIR / "by_target_repo.jsonl"
        if not index_path.exists():
            return set()
        keys = set()
        with open(index_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    keys.add(row.get("key", ""))
                except json.JSONDecodeError:
                    pass
        return keys

    def test_by_target_repo_has_osmosis_or_cosmos_sdk(self):
        keys = self._load_index_keys()
        found = self.EXPECTED_REPOS & keys
        self.assertGreater(
            len(found),
            0,
            f"Expected at least one of {self.EXPECTED_REPOS} in by_target_repo.jsonl, "
            f"found: {sorted(keys)[:20]}...",
        )

    def test_osmosis_labs_osmosis_in_index(self):
        keys = self._load_index_keys()
        self.assertIn(
            "osmosis-labs/osmosis",
            keys,
            "osmosis-labs/osmosis not found in by_target_repo.jsonl",
        )

    def test_morpho_blue_in_index(self):
        keys = self._load_index_keys()
        self.assertIn(
            "morpho-org/morpho-blue",
            keys,
            "morpho-org/morpho-blue not found in by_target_repo.jsonl",
        )


class TestSiblingTagsHaveDiverseTargets(unittest.TestCase):
    """Assertion 4: Sibling tags span at least 4 distinct target repos."""

    def test_at_least_4_distinct_target_repos(self):
        sibling_tags = list(TAGS_DIR.glob("sibling_*.yaml"))
        self.assertGreater(len(sibling_tags), 0, "No sibling_*.yaml files found")

        import yaml  # type: ignore
        repos = set()
        for tag_path in sibling_tags:
            try:
                with open(tag_path) as f:
                    data = yaml.safe_load(f)
                repo = data.get("target_repo", "")
                if repo:
                    repos.add(repo)
            except Exception:
                pass

        self.assertGreaterEqual(
            len(repos),
            4,
            f"Expected >= 4 distinct target_repos in sibling tags, found {len(repos)}: {sorted(repos)}",
        )


class TestSiblingTagsCoverCosmosSDKForkFamily(unittest.TestCase):
    """Assertion 5 (bonus): At least one sibling tag targets osmosis-labs/osmosis
    AND at least one targets a Tendermint-family chain (penumbra-zone/penumbra)."""

    def _get_target_repos(self) -> set:
        import yaml
        repos = set()
        for tag_path in TAGS_DIR.glob("sibling_*.yaml"):
            try:
                with open(tag_path) as f:
                    data = yaml.safe_load(f)
                repos.add(data.get("target_repo", ""))
            except Exception:
                pass
        return repos

    def test_osmosis_and_penumbra_both_present(self):
        repos = self._get_target_repos()
        self.assertIn("osmosis-labs/osmosis", repos, "osmosis-labs/osmosis missing from sibling tags")
        self.assertIn("penumbra-zone/penumbra", repos, "penumbra-zone/penumbra missing from sibling tags")


if __name__ == "__main__":
    unittest.main()
