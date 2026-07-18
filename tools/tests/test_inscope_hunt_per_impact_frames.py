# <!-- r36-rebuttal: lane substrate-per-impact-frames registered via agent-pathspec-register.py -->
"""Brick 2 regression: the OPT-IN --per-impact-frames flag on inscope-hunt-batch-builder.py.

Guarantees:
 (a) WITHOUT the flag, task generation is byte-identical to legacy (backward-compat HARD).
 (b) WITH the flag, each per-function task expands into one task per in-scope IMPACT FRAME
     for the unit's language, each impact-tagged with a distinct task_id + focusing prompt.
 (c) impact frames are derived from the SHARED mechanism-library seed (R47 reuse), filtered
     to the ws language (solidity vs go differ by chain-halt).
"""
import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"


def _load():
    spec = importlib.util.spec_from_file_location("inscope_hunt_batch_builder_pif", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["inscope_hunt_batch_builder_pif"] = m
    spec.loader.exec_module(m)
    return m


class PerImpactFramesTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir(parents=True)
        (self.ws / "a.sol").write_text(
            "contract A {\n  function f() public { uint x = 1; }\n}\n", encoding="utf-8")
        (self.ws / "b.go").write_text("package b\nfunc G() int {\n  return 1\n}\n", encoding="utf-8")
        cov = {"functions": [
            {"name": "f", "file": "a.sol", "line": 2, "lang": "sol", "classification": "untouched"},
            {"name": "G", "file": "b.go", "line": 2, "lang": "go", "classification": "untouched"},
        ]}
        (self.ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            json.dumps(cov), encoding="utf-8")
        # a second manifest for build_tasks (inscope_units) backward-compat check
        units = [
            {"file": "a.sol", "function": "f", "lang": "solidity", "file_line": "a.sol:2"},
            {"file": "b.go", "function": "", "lang": "go", "file_line": "b.go:2"},
        ]
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps(u) for u in units), encoding="utf-8")

    # ---- (a) BACKWARD-COMPAT: no flag == legacy, byte-identical ------------
    def _strip_volatile(self, tasks):
        """task_id is a content-hash; compare everything else + the anchor identity."""
        out = []
        for t in tasks:
            c = copy.deepcopy(t)
            c.pop("task_id", None)
            out.append(c)
        return out

    def test_no_flag_per_function_is_byte_identical_to_legacy(self):
        legacy, _ = self.m.build_tasks_per_function(self.ws, None, False, None, False,
                                                    embed_source=True)
        flag_off, _ = self.m.build_tasks_per_function(self.ws, None, False, None, False,
                                                      embed_source=True, per_impact_frames=False)
        self.assertEqual(self._strip_volatile(legacy), self._strip_volatile(flag_off))
        # and no impact field leaks in the default path
        self.assertTrue(all("impact" not in t for t in flag_off))

    def test_no_flag_build_tasks_is_byte_identical_to_legacy(self):
        legacy, _ = self.m.build_tasks(self.ws, None, False, None, False, embed_source=False)
        flag_off, _ = self.m.build_tasks(self.ws, None, False, None, False, embed_source=False,
                                         per_impact_frames=False)
        self.assertEqual(self._strip_volatile(legacy), self._strip_volatile(flag_off))
        self.assertTrue(all("impact" not in t for t in flag_off))

    # ---- (b) FLAG ON: N functions x M impacts, each impact-tagged ----------
    def test_flag_on_expands_each_function_per_impact_frame(self):
        on, _ = self.m.build_tasks_per_function(self.ws, None, False, None, False,
                                                embed_source=True, per_impact_frames=True)
        sol_impacts = set(self.m._inscope_impacts_for_lang("sol"))
        go_impacts = set(self.m._inscope_impacts_for_lang("go"))
        self.assertTrue(sol_impacts, "solidity must derive >=1 impact frame")
        self.assertTrue(go_impacts, "go must derive >=1 impact frame")
        # go carries chain-halt; solidity does not (language-specific derivation)
        self.assertIn("chain-halt", go_impacts)
        self.assertNotIn("chain-halt", sol_impacts)
        # exactly len(sol_impacts)+len(go_impacts) tasks
        self.assertEqual(len(on), len(sol_impacts) + len(go_impacts))
        # every task is impact-tagged with a distinct task_id
        self.assertTrue(all(t.get("impact") for t in on))
        self.assertEqual(len({t["task_id"] for t in on}), len(on))
        # frames per fn match the derived set
        f_frames = {t["impact"] for t in on if t["function_anchor"]["fn"] == "f"}
        g_frames = {t["impact"] for t in on if t["function_anchor"]["fn"] == "G"}
        self.assertEqual(f_frames, sol_impacts)
        self.assertEqual(g_frames, go_impacts)

    def test_flag_on_prompt_hunts_one_impact_deeply(self):
        on, _ = self.m.build_tasks_per_function(self.ws, None, False, None, False,
                                                embed_source=True, per_impact_frames=True)
        t = next(x for x in on if x["function_anchor"]["fn"] == "f")
        self.assertTrue(t["prompt"].startswith("IMPACT FRAME"))
        self.assertIn(t["impact"], t["prompt"])
        # the base per-function prompt is still present (SEVERITY rubric anchor)
        self.assertIn("IMPACT CLASSES", t["prompt"])

    def test_task_id_folds_impact_so_frames_are_distinct(self):
        base = {"function_anchor": {"file": "x/a.sol", "fn": "f", "start_line": 2}}
        no_imp = self.m._stable_task_id(dict(base))
        theft = self.m._stable_task_id({**base, "impact": "direct-theft"})
        freeze = self.m._stable_task_id({**base, "impact": "permanent-freeze"})
        self.assertNotEqual(theft, freeze)
        self.assertNotEqual(theft, no_imp)   # frame folds into the id
        # legacy (no impact) id is stable/unchanged
        self.assertEqual(no_imp, self.m._stable_task_id(dict(base)))


class PerImpactFramesEnvWiringTest(unittest.TestCase):
    """Orphan-fix regression: the --per-impact-frames flag on inscope-hunt-batch-builder.py
    was DEAD (make hunt-batch-bodypack, Makefile:3805, never passed it; no README/runbook did).
    The fix env-gates the argparse DEFAULT on the SAME PER_IMPACT_FRAMES knob that already
    gates the live sibling path (per-fn-mimo-batch-gen.py:948), default ON, so the plane now
    fires automatically through `make hunt-batch-bodypack` (which invokes --per-function) and
    is not skippable, while PER_IMPACT_FRAMES=0 restores byte-identical-legacy.
    """

    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir(parents=True)
        (self.ws / "a.sol").write_text(
            "contract A {\n  function f() public { uint x = 1; }\n}\n", encoding="utf-8")
        cov = {"functions": [
            {"name": "f", "file": "a.sol", "line": 2, "lang": "sol", "classification": "untouched"},
        ]}
        (self.ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            json.dumps(cov), encoding="utf-8")
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "a.sol", "function": "f", "lang": "solidity",
                        "file_line": "a.sol:2"}), encoding="utf-8")
        self._saved_env = os.environ.get("PER_IMPACT_FRAMES")

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("PER_IMPACT_FRAMES", None)
        else:
            os.environ["PER_IMPACT_FRAMES"] = self._saved_env

    def _run_cli(self, env_val, extra_args=()):
        if env_val is None:
            os.environ.pop("PER_IMPACT_FRAMES", None)
        else:
            os.environ["PER_IMPACT_FRAMES"] = env_val
        out = self.ws / ".auditooor" / "hunt_batch_bodypack.jsonl"
        # EXACT flags that Makefile:3805 (hunt-batch-bodypack) passes, plus nothing else -
        # so this proves the DEFAULT wiring the make target relies on.
        rc = self.m.main([
            "--workspace", str(self.ws),
            "--per-function", "--with-pack-intel",
            "--out", str(out),
        ] + list(extra_args))
        self.assertEqual(rc, 0)
        return [json.loads(l) for l in out.read_text().splitlines() if l.strip()]

    def test_env_default_on_makefile_flags_emit_frames(self):
        # No env, exactly the make hunt-batch-bodypack flags -> frames MUST be emitted
        # (the dead path is now live).
        tasks = self._run_cli(env_val=None)
        sol_impacts = set(self.m._inscope_impacts_for_lang("sol"))
        self.assertTrue(sol_impacts)
        self.assertEqual(len(tasks), len(sol_impacts))
        self.assertTrue(all(t.get("impact") for t in tasks))

    def test_env_opt_out_restores_legacy_frameless(self):
        tasks = self._run_cli(env_val="0")
        self.assertEqual(len(tasks), 1)               # one per-function task, no expansion
        self.assertTrue(all("impact" not in t for t in tasks))

    def test_explicit_flag_forces_on_over_env_opt_out(self):
        tasks = self._run_cli(env_val="0", extra_args=["--per-impact-frames"])
        self.assertTrue(all(t.get("impact") for t in tasks))
        self.assertGreater(len(tasks), 1)

    def test_explicit_no_flag_forces_off_over_env_on(self):
        tasks = self._run_cli(env_val="1", extra_args=["--no-per-impact-frames"])
        self.assertEqual(len(tasks), 1)
        self.assertTrue(all("impact" not in t for t in tasks))


if __name__ == "__main__":
    unittest.main(verbosity=2)
