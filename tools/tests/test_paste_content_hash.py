"""Tests for tools/paste_content_hash.py — L29-Filing Check C standalone tool."""

from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "paste_content_hash.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("paste_content_hash", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["paste_content_hash"] = module
    spec.loader.exec_module(module)
    return module


pch = _load_module()


class RecordVerifyTests(unittest.TestCase):
    def test_record_writes_hash_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste = Path(td) / "p.md"
            paste.write_text("# hello\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = pch.record(paste)
            self.assertEqual(rc, 0)
            hp = paste.with_suffix(paste.suffix + ".hash")
            self.assertTrue(hp.is_file())
            self.assertEqual(len(hp.read_text(encoding="utf-8").strip()), 64)

    def test_verify_passes_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste = Path(td) / "p.md"
            paste.write_text("# hello\n", encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(pch.record(paste), 0)
                self.assertEqual(pch.verify(paste), 0)

    def test_verify_fails_on_edit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste = Path(td) / "p.md"
            paste.write_text("# v1\n", encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(pch.record(paste), 0)
            paste.write_text("# v2\n", encoding="utf-8")
            err = io.StringIO()
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                rc = pch.verify(paste)
            self.assertEqual(rc, 1)
            self.assertIn("mismatch", err.getvalue())

    def test_verify_fails_when_hash_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste = Path(td) / "p.md"
            paste.write_text("# x\n", encoding="utf-8")
            err = io.StringIO()
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                rc = pch.verify(paste)
            self.assertEqual(rc, 1)
            self.assertIn("no recorded hash", err.getvalue())

    def test_record_missing_paste_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste = Path(td) / "missing.md"
            err = io.StringIO()
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                rc = pch.record(paste)
            self.assertEqual(rc, 2)

    def test_compute_sha256_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste = Path(td) / "p.md"
            paste.write_text("identical content\n", encoding="utf-8")
            d1 = pch.compute_sha256(paste)
            d2 = pch.compute_sha256(paste)
            self.assertEqual(d1, d2)
            self.assertEqual(len(d1), 64)


if __name__ == "__main__":
    unittest.main()
