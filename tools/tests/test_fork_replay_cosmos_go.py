#!/usr/bin/env python3
"""Unit tests for tools/fork-replay-cosmos-go.py (stdlib-only)."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path


# ---------------------------------------------------------------------------
# Import the module under test without relying on __main__ guard
# ---------------------------------------------------------------------------

def _load_module():
    spec = importlib.util.spec_from_file_location(
        "fork_replay_cosmos_go",
        Path(__file__).parent.parent / "fork-replay-cosmos-go.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mod = _load_module()
SCHEMA = _mod.SCHEMA
detect_cosmos_go_shape = _mod.detect_cosmos_go_shape
run = _mod.run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ws(**files: str) -> tempfile.TemporaryDirectory:
    """Create a temp workspace with the given relative-path → content mapping."""
    tmp = tempfile.mkdtemp(prefix="frcg_test_")
    root = Path(tmp)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNoCosmosShape(unittest.TestCase):
    """On a workspace with no go.mod / app/app.go, CLI exits 0 + skips."""

    def test_no_shape_exits_0(self):
        tmp = _make_ws(**{"README.md": "hello"})
        ws = Path(tmp)
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            rc = run(workspace=ws, finding_id="TEST", hermetic=True, dry_run=False)
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)

    def test_no_shape_prints_skip_message(self):
        tmp = _make_ws(**{"contracts/Foo.sol": "// solidity"})
        ws = Path(tmp)
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            run(workspace=ws, finding_id="TEST", hermetic=True, dry_run=False)
        finally:
            sys.stdout = old_stdout
        self.assertIn("no Cosmos/Go shape detected", captured.getvalue())

    def test_no_shape_writes_nothing(self):
        tmp = _make_ws(**{"src/main.rs": "fn main() {}"})
        ws = Path(tmp)
        run(workspace=ws, finding_id="TEST", hermetic=True, dry_run=False)
        self.assertFalse((ws / "fork_replay").exists())


class TestCosmosShapeDetected(unittest.TestCase):
    """On a workspace with go.mod + app/app.go, hermetic run writes a JSON packet."""

    def _build_cosmos_ws(self) -> Path:
        tmp = _make_ws(**{
            "go.mod": "module github.com/example/chain\n\ngo 1.21\n",
            "app/app.go": "package app\n",
        })
        return Path(tmp)

    def test_hermetic_writes_packet(self):
        ws = self._build_cosmos_ws()
        rc = run(workspace=ws, finding_id="FN1", hermetic=True, dry_run=False)
        self.assertEqual(rc, 0)
        candidates = list((ws / "fork_replay").glob("cosmos_go_*.json"))
        self.assertEqual(len(candidates), 1, f"Expected 1 packet, found: {candidates}")

    def test_packet_has_correct_schema(self):
        ws = self._build_cosmos_ws()
        run(workspace=ws, finding_id="FN1", hermetic=True, dry_run=False)
        packet_path = next((ws / "fork_replay").glob("cosmos_go_*.json"))
        with packet_path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["schema"], SCHEMA)

    def test_packet_contains_detected_shape(self):
        ws = self._build_cosmos_ws()
        run(workspace=ws, finding_id="FN1", hermetic=True, dry_run=False)
        packet_path = next((ws / "fork_replay").glob("cosmos_go_*.json"))
        with packet_path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("go.mod", data["detected_shape"])

    def test_packet_finding_id_in_filename(self):
        ws = self._build_cosmos_ws()
        run(workspace=ws, finding_id="MYID", hermetic=True, dry_run=False)
        candidates = list((ws / "fork_replay").glob("cosmos_go_MYID_*.json"))
        self.assertEqual(len(candidates), 1)


class TestDryRun(unittest.TestCase):
    """--dry-run writes nothing but exits 0."""

    def test_dry_run_exits_0(self):
        tmp = _make_ws(**{
            "go.mod": "module github.com/example/chain\n",
            "app/app.go": "package app\n",
        })
        ws = Path(tmp)
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            rc = run(workspace=ws, finding_id="DR", hermetic=True, dry_run=True)
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)

    def test_dry_run_writes_nothing(self):
        tmp = _make_ws(**{
            "go.mod": "module github.com/example/chain\n",
            "app/app.go": "package app\n",
        })
        ws = Path(tmp)
        run(workspace=ws, finding_id="DR", hermetic=True, dry_run=True)
        self.assertFalse((ws / "fork_replay").exists())

    def test_dry_run_prints_plan(self):
        tmp = _make_ws(**{
            "go.mod": "module github.com/example/chain\n",
        })
        ws = Path(tmp)
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            run(workspace=ws, finding_id="DR", hermetic=False, dry_run=True)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        self.assertIn("DRY-RUN", output)


if __name__ == "__main__":
    unittest.main()
