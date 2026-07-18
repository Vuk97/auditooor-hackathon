from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman_query_common.py"


def _load_tool():
    name = "_hackerman_query_common_corpus_walker"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("record_id: synthetic\n", encoding="utf-8")


class CorpusRecordWalkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tags_dir = Path(self.tmp.name) / "tags"
        self.tags_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _relative_paths(self, *, include_excluded: bool = False) -> list[str]:
        return [
            row.relative_path
            for row in self.tool.iter_corpus_record_paths(
                self.tags_dir,
                include_excluded=include_excluded,
            )
        ]

    def test_flat_yaml_records_are_walked_recursively(self) -> None:
        _touch(self.tags_dir / "flat.yaml")
        _touch(self.tags_dir / "nested_flat" / "inside.yml")

        self.assertEqual(
            self._relative_paths(),
            ["flat.yaml", "nested_flat/inside.yml"],
        )

    def test_nested_record_yaml_is_walked(self) -> None:
        _touch(self.tags_dir / "contest_platform_findings" / "finding-1" / "record.yaml")

        self.assertEqual(
            self._relative_paths(),
            ["contest_platform_findings/finding-1/record.yaml"],
        )

    def test_json_only_record_json_is_walked(self) -> None:
        _touch(self.tags_dir / "move_aptos_sui" / "finding-1" / "record.json")

        self.assertEqual(
            self._relative_paths(),
            ["move_aptos_sui/finding-1/record.json"],
        )

    def test_record_yaml_is_canonical_when_json_sibling_exists(self) -> None:
        record_dir = self.tags_dir / "dual_form" / "finding-1"
        _touch(record_dir / "record.yaml")
        _touch(record_dir / "record.json")

        self.assertEqual(
            self._relative_paths(),
            ["dual_form/finding-1/record.yaml"],
        )

    def test_relative_path_is_stable_from_tags_dir(self) -> None:
        record_path = self.tags_dir / "deep" / "year" / "finding-1" / "record.yaml"
        _touch(record_path)
        row = list(self.tool.iter_corpus_record_paths(self.tags_dir))[0]

        self.assertEqual(row.path, record_path)
        self.assertEqual(row.relative_path, "deep/year/finding-1/record.yaml")

    def test_excluded_subtrees_are_skipped_by_default(self) -> None:
        _touch(self.tags_dir / "kept" / "finding-1" / "record.yaml")
        _touch(self.tags_dir / "_deprecated" / "old" / "record.yaml")
        _touch(self.tags_dir / "_QUARANTINE_FABRICATED_CVE" / "fake" / "record.json")

        self.assertEqual(
            self._relative_paths(),
            ["kept/finding-1/record.yaml"],
        )
        self.assertEqual(
            self._relative_paths(include_excluded=True),
            [
                "_deprecated/old/record.yaml",
                "kept/finding-1/record.yaml",
                "_QUARANTINE_FABRICATED_CVE/fake/record.json",
            ],
        )

    def test_recursive_content_fingerprint_uses_canonical_walker(self) -> None:
        _touch(self.tags_dir / "flat.yaml")
        _touch(self.tags_dir / "nested" / "finding-1" / "record.yaml")
        _touch(self.tags_dir / "json_only" / "finding-2" / "record.json")

        _flat_fingerprint, flat_count = self.tool.corpus_content_fingerprint(self.tags_dir)
        _recursive_fingerprint, recursive_count = self.tool.corpus_content_fingerprint(
            self.tags_dir,
            recursive=True,
        )

        self.assertEqual(flat_count, 1)
        self.assertEqual(recursive_count, 3)


if __name__ == "__main__":
    unittest.main()
