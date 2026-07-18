#!/usr/bin/env python3
"""Tests for ``tools/run-detector.py`` (Wave O-B — Gap #2 closure).

Coverage
--------
1. ``test_known_detector_ids_in_registry``        — all expected IDs present.
2. ``test_unknown_detector_raises``               — ValueError on bad ID.
3. ``test_row_to_hit_normalisation``              — dataclass row → canonical hit shape.
4. ``test_build_output_schema``                   — output doc has all required keys.
5. ``test_build_output_schema_version``           — schema_version == auditooor.detector_run.v1.
6. ``test_cli_missing_workspace_exits_2``         — missing WS exits 2.
7. ``test_cli_unknown_detector_exits_2``          — unknown detector exits 2.
8. ``test_cli_stdout_json_shape``                 — smoke: real detector, real workspace,
                                                    stdout JSON has schema_version + hit_count.
9. ``test_cli_output_file``                       — --output writes file, file is valid JSON.
10. ``test_cli_list_detectors``                   — --list-detectors exits 0 and prints IDs.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools" / "run-detector.py"

# Real workspace used in smoke tests (matches Wave L-1 fixture)
BASE_AZUL_WS = Path(os.environ.get("BASE_AZUL_WS", "~/audits/base-azul")).expanduser()

EXPECTED_IDS = {
    "rust-discarded-verify-bool-scan",
    "rust-decode-bomb-scan",
    "rust-from-u8-panic-on-untrusted-input-scan",
    "rust-non-exact-decode-trailing-bytes-scan",
    "rust-existence-only-cache-gate-scan",
    "rust-hardfork-precompile-address-mismatch-scan",
    "rust-host-length-cast-unbounded-alloc-scan",
    "rust-numeric-overflow-underflow-scan",
    "rust-option-iter-misclassifier-scan",
    "base-rust-swival-shape-scan",
    "rust-cache-miss-policy-scanner",
}


def _load_runner():
    """Dynamically import tools/run-detector.py as a module."""
    spec = importlib.util.spec_from_file_location("run_detector", RUNNER)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.mod = _load_runner()

    def test_known_detector_ids_in_registry(self):
        registry = self.mod.DETECTOR_REGISTRY
        for did in EXPECTED_IDS:
            self.assertIn(did, registry, f"Missing detector ID: {did}")

    def test_unknown_detector_raises(self):
        with self.assertRaises(ValueError):
            self.mod.load_detector_module("not-a-real-detector-id")


class TestRowToHit(unittest.TestCase):
    def setUp(self):
        self.mod = _load_runner()

    def _hit(self, row):
        return self.mod._row_to_hit(row, Path("/fake/workspace"))

    def test_row_to_hit_normalisation(self):
        """Dataclass with file/line/snippet/extra fields normalises correctly."""

        @dataclass
        class FakeRow:
            file: str
            line: int
            snippet: str
            pattern_id: str
            confidence: str

        row = FakeRow(
            file="src/foo.rs",
            line=42,
            snippet="    let x = verify_proof()?;",
            pattern_id="discarded_verify_bool",
            confidence="high",
        )
        hit = self._hit(row)
        self.assertEqual(hit["file"], "src/foo.rs")
        self.assertEqual(hit["line"], 42)
        self.assertIn("verify_proof", hit["snippet"])
        # Extra fields land in metadata
        self.assertIn("pattern_id", hit["metadata"])
        self.assertEqual(hit["metadata"]["pattern_id"], "discarded_verify_bool")


class TestBuildOutput(unittest.TestCase):
    def setUp(self):
        self.mod = _load_runner()

    def test_build_output_schema(self):
        doc = self.mod.build_output("rust-decode-bomb-scan", Path("/ws"), [])
        for key in ("schema_version", "detector_id", "workspace", "ran_at", "hits", "hit_count"):
            self.assertIn(key, doc)

    def test_build_output_schema_version(self):
        doc = self.mod.build_output("rust-decode-bomb-scan", Path("/ws"), [])
        self.assertEqual(doc["schema_version"], "auditooor.detector_run.v1")

    def test_build_output_hit_count_matches_hits(self):
        fake_hits = [
            {"file": "a.rs", "line": 1, "snippet": "x", "metadata": {}},
            {"file": "b.rs", "line": 2, "snippet": "y", "metadata": {}},
        ]
        doc = self.mod.build_output("rust-decode-bomb-scan", Path("/ws"), fake_hits)
        self.assertEqual(doc["hit_count"], 2)
        self.assertEqual(len(doc["hits"]), 2)


class TestCLI(unittest.TestCase):
    """End-to-end CLI tests via subprocess."""

    def _run(self, args, *, cwd=None):
        return subprocess.run(
            [sys.executable, str(RUNNER)] + args,
            capture_output=True,
            text=True,
            cwd=cwd or str(ROOT),
        )

    def test_cli_missing_workspace_exits_2(self):
        result = self._run(["--workspace", "/nonexistent/ws", "--detector", "rust-decode-bomb-scan"])
        self.assertEqual(result.returncode, 2)

    def test_cli_unknown_detector_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run(["--workspace", tmp, "--detector", "not-a-real-detector"])
        self.assertEqual(result.returncode, 2)

    @unittest.skipUnless(BASE_AZUL_WS.is_dir(), "BASE_AZUL_WS not available")
    def test_cli_stdout_json_shape(self):
        """Smoke: run rust-discarded-verify-bool-scan against base-azul, check shape."""
        result = self._run([
            "--workspace", str(BASE_AZUL_WS),
            "--detector", "rust-discarded-verify-bool-scan",
        ])
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["schema_version"], "auditooor.detector_run.v1")
        self.assertIn("hit_count", doc)
        self.assertIsInstance(doc["hits"], list)
        self.assertGreater(doc["hit_count"], 0, "Expected >0 hits on base-azul workspace")

    @unittest.skipUnless(BASE_AZUL_WS.is_dir(), "BASE_AZUL_WS not available")
    def test_cli_output_file(self):
        """--output writes a valid JSON file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        try:
            result = self._run([
                "--workspace", str(BASE_AZUL_WS),
                "--detector", "rust-discarded-verify-bool-scan",
                "--output", out_path,
            ])
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            doc = json.loads(Path(out_path).read_text())
            self.assertEqual(doc["schema_version"], "auditooor.detector_run.v1")
            self.assertIn("hit_count", doc)
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_cli_list_detectors(self):
        result = self._run(["--list-detectors", "--workspace", "/unused", "--detector", "x"])
        # --list-detectors should exit 0 regardless of other args
        self.assertEqual(result.returncode, 0)
        lines = result.stdout.strip().splitlines()
        self.assertIn("rust-discarded-verify-bool-scan", lines)
        self.assertIn("rust-decode-bomb-scan", lines)


if __name__ == "__main__":
    unittest.main()
