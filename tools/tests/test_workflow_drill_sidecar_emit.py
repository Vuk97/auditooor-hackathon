#!/usr/bin/env python3
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[]
"""Tests for tools/workflow-drill-sidecar-emit.py (G14.1).

Covers:
  - emitted file round-trips through the 3 canonical readers:
      triage-kill-promoter.parse_mimo_sidecar
      r76-hallucination-guard.scan_mimo_dir
      workspace-coverage-heatmap.collect_hits (shape)
  - CONFIRMED with a fake (non-grepable / conceptual) excerpt downgrades to MAYBE
  - result is a JSON STRING (not a dict)
  - KILL verdict emits and is parsed by the kill-promoter
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

emit = importlib.import_module("workflow-drill-sidecar-emit")  # type: ignore


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class WorkflowSidecarEmitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name) / "derived"
        # A fake workspace with a known excerpt so R76 grep can confirm it.
        self.ws = Path(self.tmp.name) / "ws"
        (self.ws / "src").mkdir(parents=True, exist_ok=True)
        self.excerpt = "let amount = balance.checked_sub(fee).unwrap();"
        (self.ws / "src" / "lib.rs").write_text(
            f"fn f() {{\n    {self.excerpt}\n}}\n", encoding="utf-8"
        )
        self.r76 = _load("_r76", "tools/r76-hallucination-guard.py").check_candidate

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _emit(self, **rec):
        od = emit.out_dir_for(str(self.ws), self.base)
        path, downgraded = emit.emit_one(rec, od, r76_check=self.r76)
        return path, downgraded

    def test_result_is_json_string(self) -> None:
        path, _ = self._emit(
            workspace=str(self.ws), task_id="t1", verdict="CONFIRMED",
            applies_to_target="yes", confidence="high",
            file_line="src/lib.rs:L2", code_excerpt=self.excerpt,
            severity="Medium", reasoning="underflow", file_path_hint="src/lib.rs",
        )
        d = json.loads(path.read_text())
        self.assertEqual(d["status"], "ok")
        self.assertIsInstance(d["result"], str)
        inner = json.loads(d["result"])
        self.assertEqual(inner["verdict"], "CONFIRMED")
        self.assertEqual(inner["file_path_hint"], "src/lib.rs")

    def test_roundtrip_kill_promoter(self) -> None:
        path, _ = self._emit(
            workspace=str(self.ws), task_id="kill1", verdict="KILL",
            applies_to_target="no", confidence="low",
            file_line="src/lib.rs:L2", code_excerpt=self.excerpt,
            severity="Low", reasoning="false positive", file_path_hint="src/lib.rs",
        )
        tkp = _load("_tkp", "tools/triage-kill-promoter.py")
        rec = tkp.parse_mimo_sidecar(path)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["kill_verdict"], "KILL")

    def test_roundtrip_heatmap_collect(self) -> None:
        # collect_hits globs DERIVED_ROOT/mimo_harness_<ws>*; emit under a
        # custom base and check the parsing shape directly.
        path, _ = self._emit(
            workspace=str(self.ws), task_id="h1", verdict="CONFIRMED",
            applies_to_target="yes", confidence="high",
            file_line="src/lib.rs:L2", code_excerpt=self.excerpt,
            severity="Medium", reasoning="x", file_path_hint="src/lib.rs",
        )
        d = json.loads(path.read_text())
        self.assertEqual(d["status"], "ok")
        body = d["result"].strip().strip("`").lstrip("json").strip()
        j = json.loads(body)
        hint = j.get("file_path_hint", "")
        self.assertEqual(hint.split("/")[-1], "lib.rs")

    def test_roundtrip_r76_scan_clean(self) -> None:
        # A real-excerpt CONFIRMED sidecar should NOT be flagged by r76 scan.
        path, downgraded = self._emit(
            workspace=str(self.ws), task_id="r1", verdict="CONFIRMED",
            applies_to_target="yes", confidence="high",
            file_line="src/lib.rs:L2", code_excerpt=self.excerpt,
            severity="Medium", reasoning="x", file_path_hint="src/lib.rs",
        )
        self.assertFalse(downgraded)
        r76 = _load("_r76b", "tools/r76-hallucination-guard.py")
        fails = r76.scan_mimo_dir(path.parent, self.ws)
        flagged_ids = [f.get("task_id") for f in fails]
        self.assertNotIn("r1", flagged_ids)

    def test_confirmed_conceptual_file_line_downgrades(self) -> None:
        path, downgraded = self._emit(
            workspace=str(self.ws), task_id="hall1", verdict="CONFIRMED",
            applies_to_target="yes", confidence="high",
            file_line="N/A conceptual pattern",
            code_excerpt="keccak256(abi.encodePacked(x))",
            severity="High", reasoning="hash", file_path_hint="src/lib.rs",
        )
        self.assertTrue(downgraded)
        inner = json.loads(json.loads(path.read_text())["result"])
        self.assertEqual(inner["verdict"], "MAYBE")
        self.assertEqual(inner["applies_to_target"], "maybe")
        self.assertIn("R76-downgrade", inner["reasoning"])

    def test_confirmed_fake_excerpt_downgrades(self) -> None:
        # file_line is fine but the excerpt does not exist in the workspace.
        path, downgraded = self._emit(
            workspace=str(self.ws), task_id="hall2", verdict="CONFIRMED",
            applies_to_target="yes", confidence="high",
            file_line="src/lib.rs:L2",
            code_excerpt="this exact line does not appear anywhere in the source tree at all",
            severity="High", reasoning="synthetic", file_path_hint="src/lib.rs",
        )
        self.assertTrue(downgraded)
        inner = json.loads(json.loads(path.read_text())["result"])
        self.assertEqual(inner["verdict"], "MAYBE")

    def test_function_anchor_emitted_top_level_and_inner(self) -> None:
        # PER-FN subject anchor must land at the TOP LEVEL of the sidecar (where
        # function-coverage-completeness reads outer.get("function_anchor")) AND
        # inside the result payload. Carries file + fn + (function alias) + int line.
        path, _ = self._emit(
            workspace=str(self.ws), task_id="anc1", verdict="KILL",
            applies_to_target="no", confidence="high", file_line="src/lib.rs:L2",
            code_excerpt=self.excerpt, severity="", reasoning="ruled out",
            file_path_hint="src/lib.rs",
            function_anchor={"file": "src/lib.rs", "fn": "transfer", "line": "2"},
        )
        sc = json.loads(path.read_text())
        self.assertEqual(sc.get("function_anchor"),
                         {"file": "src/lib.rs", "fn": "transfer",
                          "function": "transfer", "line": 2})
        inner = json.loads(sc["result"])
        self.assertEqual(inner["function_anchor"]["fn"], "transfer")

    def test_no_anchor_absent_when_not_provided(self) -> None:
        path, _ = self._emit(
            workspace=str(self.ws), task_id="anc2", verdict="KILL",
            applies_to_target="no", confidence="high", file_line="src/lib.rs:L2",
            code_excerpt=self.excerpt, severity="", reasoning="x",
            file_path_hint="src/lib.rs",
        )
        self.assertNotIn("function_anchor", json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
