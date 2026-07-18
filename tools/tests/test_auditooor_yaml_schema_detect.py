"""Tests for tools.auditooor-yaml-schema-detect.

Wave-2 PR-A (PR #728) capability-gap #3. All fixtures are tagged
``synthetic_fixture: true`` per the disciplined-fixtures rule. No real corpus
records are mutated or written.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest


_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOL_PATH = os.path.normpath(os.path.join(_THIS_DIR, "..", "auditooor-yaml-schema-detect.py"))


def _load_tool():
    spec = importlib.util.spec_from_file_location("auditooor_yaml_schema_detect", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()


def _write(tmpdir: str, name: str, body: str) -> str:
    path = os.path.join(tmpdir, name)
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(name) else None
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


class DetectFromDocTests(unittest.TestCase):
    """Pure-function unit tests on detect_schema_from_doc."""

    def test_explicit_schema_version_wins(self):
        doc = {"schema_version": "auditooor.hackerman_record.v1.1", "record_id": "x"}
        family, evidence = TOOL.detect_schema_from_doc(doc)
        self.assertEqual(family, "auditooor.hackerman_record.v1.1")
        self.assertIn("schema_version=", evidence)

    def test_dsl_pattern_heuristic(self):
        doc = {
            "verdict_id": "dsl_pattern/x",
            "extraction_provenance": "dsl_pattern_synthesis",
            "synthetic_fixture": True,
        }
        family, evidence = TOOL.detect_schema_from_doc(doc)
        self.assertEqual(family, TOOL.KNOWN_DSL_PATTERN)
        self.assertIn("verdict_id", evidence)

    def test_legacy_hackerman_v1_heuristic(self):
        # No schema_version field; legacy v1 records should be detected.
        doc = {
            "record_id": "abc",
            "record_tier": "tier-1",
            "attack_class": "reentrancy",
            "synthetic_fixture": True,
        }
        family, _ = TOOL.detect_schema_from_doc(doc)
        self.assertEqual(family, TOOL.KNOWN_HACKERMAN_V1)

    def test_skill_state_workspace_heuristic(self):
        doc = {
            "version": 1,
            "workspace": "thegraph",
            "last_scan": {"date": None, "hit_count": 0},
            "adversarial_reads": [],
            "synthetic_fixture": True,
        }
        family, _ = TOOL.detect_schema_from_doc(doc)
        self.assertEqual(family, TOOL.KNOWN_SKILL_STATE_V1)

    def test_unknown_when_no_signals(self):
        doc = {"foo": "bar", "baz": [1, 2, 3], "synthetic_fixture": True}
        family, _ = TOOL.detect_schema_from_doc(doc)
        self.assertEqual(family, TOOL.UNKNOWN)

    def test_empty_document(self):
        family, _ = TOOL.detect_schema_from_doc(None)
        self.assertEqual(family, TOOL.EMPTY_DOCUMENT)

    def test_non_mapping_top_level(self):
        family, _ = TOOL.detect_schema_from_doc([1, 2, 3])
        self.assertEqual(family, TOOL.UNKNOWN)

    def test_ci_workflow_heuristic(self):
        # PyYAML parses bare ``on:`` as Python True; the detector accepts
        # either spelling.
        doc = {
            "name": "ci",
            True: ["push", "pull_request"],
            "jobs": {"build": {"runs-on": "ubuntu-latest"}},
            "synthetic_fixture": True,
        }
        family, _ = TOOL.detect_schema_from_doc(doc)
        self.assertEqual(family, TOOL.NON_AUDITOOOR_CI_WORKFLOW)


class CliFileModeTests(unittest.TestCase):
    """Tests for the ``--file`` CLI path."""

    def test_single_file_explicit_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                "rec.yaml",
                "schema_version: auditooor.hackerman_record.v1.1\n"
                "record_id: 'syn-1'\n"
                "synthetic_fixture: true\n",
            )
            buf = io.StringIO()
            saved = sys.stdout
            sys.stdout = buf
            try:
                rc = TOOL.main(["--file", path, "--json"])
            finally:
                sys.stdout = saved
            self.assertEqual(rc, 0)
            doc = json.loads(buf.getvalue())
            self.assertEqual(doc["detected_schema"], "auditooor.hackerman_record.v1.1")

    def test_single_file_heuristic_dsl_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                "syn.yaml",
                "verdict_id: 'dsl_pattern/test'\n"
                "extraction_provenance: dsl_pattern_synthesis\n"
                "synthetic_fixture: true\n",
            )
            rc = TOOL.main(["--file", path])
            self.assertEqual(rc, 0)

    def test_invalid_yaml_handled_without_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "bad.yaml", "::: this is :::: not yaml :::\n")
            buf = io.StringIO()
            saved = sys.stdout
            sys.stdout = buf
            try:
                rc = TOOL.main(["--file", path, "--json"])
            finally:
                sys.stdout = saved
            # Without --strict, parse errors do not fail the process.
            self.assertEqual(rc, 0)
            doc = json.loads(buf.getvalue())
            self.assertEqual(doc["detected_schema"], TOOL.PARSE_ERROR)

    def test_strict_unknown_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                "unk.yaml",
                "foo: bar\nbaz: 123\nsynthetic_fixture: true\n",
            )
            buf = io.StringIO()
            saved = sys.stdout
            sys.stdout = buf
            try:
                rc = TOOL.main(["--file", path, "--strict", "--json"])
            finally:
                sys.stdout = saved
            self.assertEqual(rc, 1)


class CliDirModeTests(unittest.TestCase):
    """Tests for the ``--dir`` CLI path."""

    def test_dir_walk_mixed_schemas(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(
                tmp,
                "v11.yaml",
                "schema_version: auditooor.hackerman_record.v1.1\n"
                "record_id: 'syn-2'\n"
                "synthetic_fixture: true\n",
            )
            _write(
                tmp,
                "dsl.yaml",
                "verdict_id: 'dsl_pattern/y'\n"
                "extraction_provenance: dsl_pattern_synthesis\n"
                "synthetic_fixture: true\n",
            )
            _write(
                tmp,
                "skill.yaml",
                "version: 1\n"
                "workspace: testws\n"
                "last_scan:\n  date: null\n  hit_count: 0\n"
                "adversarial_reads: []\n"
                "synthetic_fixture: true\n",
            )
            _write(tmp, "u.yaml", "foo: 1\nbar: 2\nsynthetic_fixture: true\n")
            buf = io.StringIO()
            saved = sys.stdout
            sys.stdout = buf
            try:
                rc = TOOL.main(["--dir", tmp, "--json"])
            finally:
                sys.stdout = saved
            self.assertEqual(rc, 0)
            pack = json.loads(buf.getvalue())
            self.assertEqual(pack["schema_version"], TOOL.SCHEMA_VERSION_TAG)
            self.assertEqual(pack["files_scanned"], 4)
            dist = pack["schema_distribution"]
            self.assertEqual(dist.get("auditooor.hackerman_record.v1.1"), 1)
            self.assertEqual(dist.get(TOOL.KNOWN_DSL_PATTERN), 1)
            self.assertEqual(dist.get(TOOL.KNOWN_SKILL_STATE_V1), 1)
            self.assertEqual(dist.get(TOOL.UNKNOWN), 1)
            self.assertEqual(len(pack["unknown_files"]), 1)

    def test_dir_strict_fails_on_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "unk.yaml", "alpha: beta\nsynthetic_fixture: true\n")
            buf = io.StringIO()
            saved = sys.stdout
            sys.stdout = buf
            try:
                rc = TOOL.main(["--dir", tmp, "--strict", "--json"])
            finally:
                sys.stdout = saved
            self.assertEqual(rc, 1)

    def test_dir_detects_dual_form_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "rec")
            with open(base + ".yaml", "w", encoding="utf-8") as fh:
                fh.write(
                    "schema_version: auditooor.hackerman_record.v1.1\n"
                    "record_id: 'syn-3'\n"
                    "synthetic_fixture: true\n"
                )
            with open(base + ".json", "w", encoding="utf-8") as fh:
                fh.write('{"schema_version": "auditooor.hackerman_record.v1.1"}\n')
            buf = io.StringIO()
            saved = sys.stdout
            sys.stdout = buf
            try:
                rc = TOOL.main(["--dir", tmp, "--json"])
            finally:
                sys.stdout = saved
            self.assertEqual(rc, 0)
            pack = json.loads(buf.getvalue())
            self.assertEqual(len(pack["dual_form_pairs"]), 1)


if __name__ == "__main__":
    unittest.main()
