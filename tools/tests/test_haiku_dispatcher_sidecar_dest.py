#!/usr/bin/env python3
"""Regression: haiku-fanout-dispatcher writes the per-task 'write sidecar to'
path into the WORKSPACE gate-scanned dir (`<ws>/.auditooor/hunt_findings_sidecars/`),
NOT the tmp prompt output_dir.

near-intents 2026-06-26: the batch template pointed the creditable sidecar at
`{output_dir}/{task_id}.json` where output_dir was a /tmp prompt dir. 80 genuine
wave-A sidecars landed there, outside the hunt-coverage-gate's scan roots, and
credited 0 units until hand-copied into the workspace. The dispatcher must use the
task's own workspace_path so future waves land where the gate reads.
"""
import importlib.util
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "haiku-fanout-dispatcher.py"
_spec = importlib.util.spec_from_file_location("hfd", _TOOL)
hfd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hfd)


class SidecarDestTest(unittest.TestCase):
    def test_sidecar_dest_is_workspace_dir_and_function_named(self):
        tasks = [{
            "task_id": "inscope_hunt_00000",
            "workspace": "near-intents",
            "workspace_path": "/Users/wolf/audits/near-intents",
            "source_question_id": "q",
            "function_anchor": {"file": "/x/lib.rs", "fn": "get_bridged_token"},
            "prompt": "do the thing",
        }]
        prompt = hfd.build_agent_prompt(tasks, Path("/tmp/some_prompt_dir"), 0, "sonnet", "")
        # function-identity slug (base + fn + path-hash) under the workspace dir
        self.assertIn(
            "/Users/wolf/audits/near-intents/.auditooor/hunt_findings_sidecars/"
            "hunt__lib.rs__get_bridged_token__",
            prompt,
            "sidecar dest must be the workspace dir, named by function identity",
        )
        # NOT named by the sequential task_id (which collides across waves)
        self.assertNotIn("hunt_findings_sidecars/inscope_hunt_00000.json", prompt)
        self.assertNotIn("/tmp/some_prompt_dir/", prompt)

    def test_same_basename_same_fn_different_dir_no_collision(self):
        # several `lib.rs::new` across crates must NOT collapse to one slug
        ws = "/ws"
        t1 = [{"task_id": "a", "workspace_path": ws,
               "function_anchor": {"file": "/ws/src/mock-token/src/lib.rs", "fn": "new"},
               "prompt": "x"}]
        t2 = [{"task_id": "b", "workspace_path": ws,
               "function_anchor": {"file": "/ws/src/threshold-sigs/src/lib.rs", "fn": "new"},
               "prompt": "x"}]
        import re
        p1 = hfd.build_agent_prompt(t1, Path("/tmp/o"), 0, "sonnet", "")
        p2 = hfd.build_agent_prompt(t2, Path("/tmp/o"), 0, "sonnet", "")
        f1 = re.search(r"hunt__lib.rs__new__[0-9a-f]{8}\.json", p1).group(0)
        f2 = re.search(r"hunt__lib.rs__new__[0-9a-f]{8}\.json", p2).group(0)
        self.assertNotEqual(f1, f2, "different dirs must yield different sidecar files")

    def test_same_function_same_path_stable_slug(self):
        # re-hunt of the SAME function (same path) -> same file -> correct overwrite
        ws = "/ws"
        t = [{"task_id": "x", "workspace_path": ws,
              "function_anchor": {"file": "/ws/src/a/lib.rs", "fn": "foo"}, "prompt": "x"}]
        import re
        p1 = hfd.build_agent_prompt(t, Path("/tmp/o"), 0, "sonnet", "")
        p2 = hfd.build_agent_prompt(t, Path("/tmp/o"), 1, "sonnet", "")
        f1 = re.search(r"hunt__lib.rs__foo__[0-9a-f]{8}\.json", p1).group(0)
        f2 = re.search(r"hunt__lib.rs__foo__[0-9a-f]{8}\.json", p2).group(0)
        self.assertEqual(f1, f2)

    def test_same_task_id_different_function_no_collision(self):
        # the core regression: wave N+1 reuses task_id 00000 for a DIFFERENT fn.
        # the two sidecar filenames must differ so no overwrite occurs.
        ws = "/Users/wolf/audits/near-intents"
        waveB = [{
            "task_id": "inscope_hunt_00010", "workspace_path": ws,
            "function_anchor": {"file": "/a/lib.rs", "fn": "get_bridged_token"},
            "prompt": "x",
        }]
        waveFC = [{
            "task_id": "inscope_hunt_00010", "workspace_path": ws,
            "function_anchor": {"file": "/b/attestation.rs", "fn": "verify_dcap_quote"},
            "prompt": "x",
        }]
        pB = hfd.build_agent_prompt(waveB, Path("/tmp/o"), 0, "sonnet", "")
        pFC = hfd.build_agent_prompt(waveFC, Path("/tmp/o"), 0, "sonnet", "")
        self.assertIn("hunt__lib.rs__get_bridged_token__", pB)
        self.assertIn("hunt__attestation.rs__verify_dcap_quote__", pFC)
        # the two destinations are distinct -> wave FC cannot clobber wave B
        self.assertNotIn("hunt__lib.rs__get_bridged_token__", pFC)

    def test_same_file_same_name_different_line_no_collision(self):
        # overloaded/multi-impl same-name fns in the SAME file (participants() on two
        # structs) must get distinct sidecars via the line suffix.
        ws = "/ws"
        t1 = [{"task_id": "a", "workspace_path": ws,
               "function_anchor": {"file": "/ws/src/thresholds.rs", "fn": "participants", "start_line": 189},
               "prompt": "x"}]
        t2 = [{"task_id": "b", "workspace_path": ws,
               "function_anchor": {"file": "/ws/src/thresholds.rs", "fn": "participants", "start_line": 263},
               "prompt": "x"}]
        import re
        p1 = hfd.build_agent_prompt(t1, Path("/tmp/o"), 0, "sonnet", "")
        p2 = hfd.build_agent_prompt(t2, Path("/tmp/o"), 0, "sonnet", "")
        f1 = re.search(r"hunt__thresholds.rs__participants__[0-9a-f]{8}__L189\.json", p1)
        f2 = re.search(r"hunt__thresholds.rs__participants__[0-9a-f]{8}__L263\.json", p2)
        self.assertIsNotNone(f1)
        self.assertIsNotNone(f2)
        self.assertNotEqual(f1.group(0), f2.group(0))

    def test_falls_back_to_taskid_without_anchor(self):
        tasks = [{"task_id": "t1", "workspace_path": "/ws", "prompt": "x"}]
        prompt = hfd.build_agent_prompt(tasks, Path("/tmp/out"), 0, "sonnet", "")
        self.assertIn("/ws/.auditooor/hunt_findings_sidecars/t1.json", prompt)

    def test_falls_back_to_output_dir_without_workspace_path(self):
        tasks = [{"task_id": "t1", "workspace": "?", "prompt": "x"}]
        prompt = hfd.build_agent_prompt(tasks, Path("/tmp/out"), 0, "sonnet", "")
        self.assertIn("/tmp/out/t1.json", prompt)

    def test_prompt_requires_atomic_cli_writes_and_exact_task_identity(self):
        task = [{
            "task_id": "task-identity-001",
            "workspace": "demo",
            "workspace_path": "/tmp/ws",
            "source_question_id": "q-1",
            "function_anchor": {},
            "prompt": "Inspect the cited source.",
        }]
        prompt = hfd.build_agent_prompt(task, Path("/tmp/out"), 0, "sonnet", "")
        self.assertIn("MUST exactly equal the task id", prompt)
        self.assertIn("writes a temporary file", prompt)
        self.assertIn("Never use `apply_patch` to edit JSON", prompt)
        self.assertIn('"task_id": "<from task definition>"', prompt)


if __name__ == "__main__":
    unittest.main()
