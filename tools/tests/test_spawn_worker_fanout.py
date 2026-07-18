#!/usr/bin/env python3
"""test_spawn_worker_fanout.py

Regression for the fan-out helper (operator-caught 2026-07-03): a worklist of N
INDEPENDENT units must expand to N lanes, each with a DISTINCT output sidecar
(the anti-clobber invariant that lets the lanes run concurrently), field
substitution, axis filtering, and honest --max overflow (NOT silent drop).

Uses --dry-run so spawn-worker.sh is never invoked (no lane registration / git).
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "spawn-worker-fanout.py"


def _run(args: list[str]):
    return subprocess.run([sys.executable, str(_TOOL), *args],
                          capture_output=True, text=True)


class TestSpawnWorkerFanout(unittest.TestCase):
    def _setup(self, tmp: Path, rows: list[dict]):
        ws = tmp / "ws"
        (ws / ".auditooor").mkdir(parents=True)
        wl = ws / ".auditooor" / "worklist.jsonl"
        wl.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        tmpl = tmp / "tmpl.md"
        tmpl.write_text(
            "cell {{UNIT_INDEX}} mechanism={{FIELD:mechanism}} write to {{OUTPUT_SIDECAR}}\n"
            "full unit: {{UNIT_JSON}}\n", encoding="utf-8")
        return ws, wl, tmpl

    def test_n_units_expand_to_n_distinct_lanes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = [{"axis": "mechanism", "mechanism": f"m{i}"} for i in range(3)]
            ws, wl, tmpl = self._setup(tmp, rows)
            r = _run(["--worklist", str(wl), "--lane-type", "hunt", "--severity", "HIGH",
                      "--workspace", str(ws), "--lane-prefix", "t", "--prompt-template", str(tmpl),
                      "--tmp-dir", str(tmp), "--dry-run"])
            self.assertEqual(r.returncode, 0, r.stderr)
            prompts = [l for l in r.stdout.splitlines() if l.strip()]
            self.assertEqual(len(prompts), 3, f"expected 3 per-unit prompts: {prompts}")
            # DISTINCT output sidecars + correct field substitution per unit
            sidecars = set()
            for i, p in enumerate(prompts):
                body = Path(p).read_text()
                self.assertIn(f"mechanism=m{i}", body)
                # extract the OUTPUT_SIDECAR path token
                for tok in body.split():
                    if tok.endswith(f"t_{i}.json"):
                        sidecars.add(tok)
            self.assertEqual(len(sidecars), 3, f"sidecars must be distinct per unit: {sidecars}")
            # manifest written with 3 rows
            man = ws / ".auditooor" / "fanout_t_manifest.jsonl"
            self.assertTrue(man.is_file())
            self.assertEqual(len([l for l in man.read_text().splitlines() if l.strip()]), 3)

    def test_axis_filter_selects_subset(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = [{"axis": "mechanism", "mechanism": "a"},
                    {"axis": "function", "function": "f"},
                    {"axis": "mechanism", "mechanism": "b"}]
            ws, wl, tmpl = self._setup(tmp, rows)
            r = _run(["--worklist", str(wl), "--lane-type", "hunt", "--severity", "HIGH",
                      "--workspace", str(ws), "--lane-prefix", "t", "--prompt-template", str(tmpl),
                      "--tmp-dir", str(tmp), "--filter-axis", "mechanism", "--dry-run"])
            self.assertEqual(r.returncode, 0, r.stderr)
            prompts = [l for l in r.stdout.splitlines() if l.strip()]
            self.assertEqual(len(prompts), 2, "only the 2 mechanism rows should fan out")

    def test_max_overflow_is_reported_not_silent(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = [{"axis": "mechanism", "mechanism": f"m{i}"} for i in range(5)]
            ws, wl, tmpl = self._setup(tmp, rows)
            r = _run(["--worklist", str(wl), "--lane-type", "hunt", "--severity", "HIGH",
                      "--workspace", str(ws), "--lane-prefix", "t", "--prompt-template", str(tmpl),
                      "--tmp-dir", str(tmp), "--max", "2", "--dry-run"])
            self.assertEqual(r.returncode, 0, r.stderr)
            prompts = [l for l in r.stdout.splitlines() if l.strip()]
            self.assertEqual(len(prompts), 2, "only --max lanes dispatched")
            self.assertIn("overflow=3", r.stderr)
            self.assertIn("NOT silently covered", r.stderr)

    def test_extractor_strips_durable_brief_prefix(self):
        # regression: spawn-worker prints `[spawn-worker] durable_brief=/path/_enriched.md`
        # and a bare `/tmp/spawn_worker_..._enriched.md`; the extractor must return a
        # CLEAN path, never the `[spawn-worker] durable_brief=` line verbatim.
        import importlib.util
        spec = importlib.util.spec_from_file_location("swf", _TOOL)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        out = ("[spawn-worker] durable_brief=/ws/.auditooor/dispatch_briefs/lane-0_enriched.md\n"
               "/tmp/spawn_worker_lane-0_123_enriched.md\n")
        got = mod._extract_enriched_path(out)
        self.assertEqual(got, "/tmp/spawn_worker_lane-0_123_enriched.md",
                         f"must prefer the clean bare path, got: {got!r}")
        # durable-only fallback: still returns a clean path (no `key=` wrapper)
        got2 = mod._extract_enriched_path(
            "[spawn-worker] durable_brief=/ws/.auditooor/dispatch_briefs/lane-0_enriched.md\n")
        self.assertEqual(got2, "/ws/.auditooor/dispatch_briefs/lane-0_enriched.md")
        self.assertFalse(got2.startswith("["), "must not return the prefixed line")

    def test_empty_worklist_is_clean_noop(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws, wl, tmpl = self._setup(tmp, [])
            r = _run(["--worklist", str(wl), "--lane-type", "hunt", "--severity", "HIGH",
                      "--workspace", str(ws), "--lane-prefix", "t", "--prompt-template", str(tmpl),
                      "--tmp-dir", str(tmp), "--dry-run"])
            self.assertEqual(r.returncode, 0)
            self.assertIn("worklist empty", r.stderr)


if __name__ == "__main__":
    unittest.main()
