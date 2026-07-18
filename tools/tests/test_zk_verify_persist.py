#!/usr/bin/env python3
"""Tests for tools/zk-verify-persist.py."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "zk-verify-persist.py"


def _load():
    spec = importlib.util.spec_from_file_location("zk_verify_persist_test_mod", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkVerifyPersistTest(unittest.TestCase):
    def test_empty_queue_is_current_empty_snapshot_not_error(self) -> None:
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            queue = ws / ".auditooor" / "zk_hunt_queue.jsonl"
            queue.parent.mkdir(parents=True)
            queue.write_text("", encoding="utf-8")

            result = mod.process_queue(ws, queue, persist=False, dry_run=False)

            self.assertEqual(result["verdict"], "pass-empty-queue")
            self.assertEqual(result["total"], 0)
            candidates = list((ws / ".auditooor").glob("zk_candidates_*.jsonl"))
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
