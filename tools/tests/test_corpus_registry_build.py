"""Tests for tools/corpus-registry-build.py."""
from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest

# Allow running from repo root or directly
import importlib.util
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_TOOLS = _HERE.parent
_SCRIPT = _TOOLS / "corpus-registry-build.py"

spec = importlib.util.spec_from_file_location("corpus_registry_build", _SCRIPT)
_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)

build_registry = _mod.build_registry
SLUG_TO_TOPIC = _mod.SLUG_TO_TOPIC
PREFIX = _mod.PREFIX


def _make_mock_corpus(base: pathlib.Path, slug: str, num_files: int = 3) -> pathlib.Path:
    """Create a mock corpus directory with num_files dummy .yaml files."""
    corpus_dir = base / f"patterns.dsl.r94_solodit_{slug}"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    for i in range(num_files):
        (corpus_dir / f"finding-{i:03d}.yaml").write_text(
            f"# mock finding {i} for {slug}\n", encoding="utf-8"
        )
    return corpus_dir


class TestCorpusRegistryBuild(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ref_dir = pathlib.Path(self._tmp.name) / "reference"
        self.ref_dir.mkdir()
        self.out_path = self.ref_dir / "corpus_registry.json"

    def tearDown(self):
        self._tmp.cleanup()

    # ------------------------------------------------------------------ #
    # Schema fields
    # ------------------------------------------------------------------ #

    def test_schema_fields_present(self):
        _make_mock_corpus(self.ref_dir, "reentrancy", num_files=2)
        build_registry(self.ref_dir, self.out_path)
        data = json.loads(self.out_path.read_text())

        self.assertEqual(data["schema"], "auditooor.corpus_registry.v1")
        self.assertIn("generated_at", data)
        self.assertIn("corpora", data)
        self.assertIsInstance(data["corpora"], list)

    def test_corpus_entry_fields(self):
        _make_mock_corpus(self.ref_dir, "oracle", num_files=5)
        build_registry(self.ref_dir, self.out_path)
        data = json.loads(self.out_path.read_text())

        self.assertEqual(len(data["corpora"]), 1)
        entry = data["corpora"][0]
        for field in ("slug", "path", "file_count", "size_bytes", "newest_mtime", "topic"):
            self.assertIn(field, entry, f"missing field: {field}")

        self.assertEqual(entry["slug"], "oracle")
        self.assertEqual(entry["file_count"], 5)
        self.assertGreater(entry["size_bytes"], 0)
        self.assertIsNotNone(entry["newest_mtime"])
        # ISO-8601 UTC: YYYY-MM-DDTHH:MM:SSZ
        self.assertRegex(entry["newest_mtime"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(entry["topic"], "Oracle Manipulation")

    def test_path_is_relative_to_repo_root(self):
        _make_mock_corpus(self.ref_dir, "amm", num_files=1)
        build_registry(self.ref_dir, self.out_path)
        data = json.loads(self.out_path.read_text())
        entry = data["corpora"][0]
        # path should be relative (not absolute)
        self.assertFalse(pathlib.Path(entry["path"]).is_absolute(),
                         f"expected relative path, got: {entry['path']}")

    # ------------------------------------------------------------------ #
    # Sorting
    # ------------------------------------------------------------------ #

    def test_sorted_by_slug(self):
        for slug in ("zk", "amm", "bridge", "reentrancy"):
            _make_mock_corpus(self.ref_dir, slug, num_files=1)
        build_registry(self.ref_dir, self.out_path)
        data = json.loads(self.out_path.read_text())
        slugs = [e["slug"] for e in data["corpora"]]
        self.assertEqual(slugs, sorted(slugs))

    # ------------------------------------------------------------------ #
    # Determinism
    # ------------------------------------------------------------------ #

    def test_determinism_rerun_identical_content(self):
        for slug in ("proxy", "staking", "mev"):
            _make_mock_corpus(self.ref_dir, slug, num_files=4)

        build_registry(self.ref_dir, self.out_path)
        first_run = self.out_path.read_bytes()

        # Overwrite with a second run
        build_registry(self.ref_dir, self.out_path)
        second_run = self.out_path.read_bytes()

        # Content must be identical except for generated_at timestamp.
        # Compare corpora list directly (the part that must be stable).
        data1 = json.loads(first_run)
        data2 = json.loads(second_run)
        self.assertEqual(data1["schema"], data2["schema"])
        self.assertEqual(data1["corpora"], data2["corpora"])

    # ------------------------------------------------------------------ #
    # Unknown slug fallback topic
    # ------------------------------------------------------------------ #

    def test_unknown_slug_title_cased(self):
        _make_mock_corpus(self.ref_dir, "my_novel_topic", num_files=1)
        build_registry(self.ref_dir, self.out_path)
        data = json.loads(self.out_path.read_text())
        entry = data["corpora"][0]
        self.assertEqual(entry["topic"], "My Novel Topic")

    # ------------------------------------------------------------------ #
    # Non-corpus dirs are ignored
    # ------------------------------------------------------------------ #

    def test_non_corpus_dirs_ignored(self):
        _make_mock_corpus(self.ref_dir, "reentrancy", num_files=2)
        # A directory that doesn't match the prefix should be ignored
        other = self.ref_dir / "some_other_dir"
        other.mkdir()
        (other / "file.txt").write_text("noise\n")
        build_registry(self.ref_dir, self.out_path)
        data = json.loads(self.out_path.read_text())
        self.assertEqual(len(data["corpora"]), 1)
        self.assertEqual(data["corpora"][0]["slug"], "reentrancy")

    # ------------------------------------------------------------------ #
    # Empty corpus dir
    # ------------------------------------------------------------------ #

    def test_empty_corpus_dir(self):
        _make_mock_corpus(self.ref_dir, "flashloan", num_files=0)
        build_registry(self.ref_dir, self.out_path)
        data = json.loads(self.out_path.read_text())
        entry = data["corpora"][0]
        self.assertEqual(entry["file_count"], 0)
        self.assertEqual(entry["size_bytes"], 0)
        self.assertIsNone(entry["newest_mtime"])

    # ------------------------------------------------------------------ #
    # Multiple corpora count
    # ------------------------------------------------------------------ #

    def test_multiple_corpora_count(self):
        slugs = ["aa", "bridge", "cairo", "erc4626", "zk"]
        for slug in slugs:
            _make_mock_corpus(self.ref_dir, slug, num_files=2)
        count = build_registry(self.ref_dir, self.out_path)
        self.assertEqual(count, len(slugs))
        data = json.loads(self.out_path.read_text())
        self.assertEqual(len(data["corpora"]), len(slugs))

    # ------------------------------------------------------------------ #
    # Output file has trailing newline + valid JSON
    # ------------------------------------------------------------------ #

    def test_trailing_newline(self):
        _make_mock_corpus(self.ref_dir, "sigreplay", num_files=1)
        build_registry(self.ref_dir, self.out_path)
        raw = self.out_path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"), "output JSON must end with newline")

    def test_output_is_valid_json(self):
        _make_mock_corpus(self.ref_dir, "stablecoin", num_files=3)
        build_registry(self.ref_dir, self.out_path)
        # Should not raise
        json.loads(self.out_path.read_text())


if __name__ == "__main__":
    unittest.main()
