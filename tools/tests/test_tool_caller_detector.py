"""Unit tests for tools/tool-caller-detector.py (WF-10 false-positive fix).

Each test builds an ephemeral repo-like tree (Makefile + tools/) under a
tempdir, drops caller-surface fixtures, and asserts the detector returns
the expected verdict + caller-count-by-surface.

The detector is invoked via subprocess so the test matches the runtime
exit-code contract that pre-commit-check / Make targets rely on.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "tool-caller-detector.py"


def _run(args: list[str], *, root: Path | None = None) -> tuple[int, str, str]:
    """Invoke the detector with explicit --root, returning (rc, stdout, stderr)."""
    cmd = [sys.executable, str(TOOL)] + args
    if root is not None and "--root" not in args:
        cmd.extend(["--root", str(root)])
    r = subprocess.run(cmd, capture_output=True, text=True, env={
        **os.environ,
        # Default scheduled-tasks dir to a non-existent path so the test
        # is hermetic - individual tests can override via --scheduled-tasks-dir.
        "AUDITOOOR_TOOL_CALLER_SCHEDULED_TASKS_DIR":
            os.environ.get("AUDITOOOR_TOOL_CALLER_SCHEDULED_TASKS_DIR",
                          str(Path("/nonexistent/scheduled-tasks-for-test"))),
        "AUDITOOOR_TOOL_CALLER_AUDITS_DIR":
            os.environ.get("AUDITOOOR_TOOL_CALLER_AUDITS_DIR",
                          str(Path("/nonexistent/audits-for-test"))),
    })
    return r.returncode, r.stdout, r.stderr


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _make_repo(prefix: str = "tcd_") -> Path:
    """Create a minimal repo-like tree with Makefile + tools/."""
    repo = Path(tempfile.mkdtemp(prefix=prefix))
    _write(repo / "Makefile", "# empty\n")
    (repo / "tools").mkdir()
    return repo


class ToolCallerDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = _make_repo()
        # Add a no-op tool we exercise as the subject.
        _write(self.repo / "tools" / "my-tool.py", "# subject\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.repo, ignore_errors=True)

    # --- Surface 1: Makefile -------------------------------------------------

    def test_surface_makefile_hit(self) -> None:
        _write(self.repo / "Makefile",
               "subj:\n\tpython3 tools/my-tool.py --x 1\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertTrue(data["verdict"].startswith("wired-"))
        self.assertEqual(data["caller_count_by_surface"]["makefile"], 1)
        self.assertEqual(data["caller_count"], 1)

    # --- Surface 2: pre-submit-check.sh + tools/*.sh ------------------------

    def test_surface_pre_submit_check_hit(self) -> None:
        _write(self.repo / "tools" / "pre-submit-check.sh",
               "#!/bin/bash\npython3 tools/my-tool.py\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(
            data["caller_count_by_surface"]["pre_submit_check_and_sh_wrappers"], 1)

    def test_surface_tools_sh_wrapper_hit(self) -> None:
        _write(self.repo / "tools" / "wrap.sh",
               "#!/bin/bash\nexec python3 tools/my-tool.py \"$@\"\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(
            data["caller_count_by_surface"]["pre_submit_check_and_sh_wrappers"], 1)

    # --- Surface 3: engage.py -----------------------------------------------

    def test_surface_engage_py_hit(self) -> None:
        _write(self.repo / "tools" / "engage.py",
               "# stage chain\n"
               "MY = HERE / 'my-tool.py'\n"
               "def stage_my(ws):\n"
               "    subprocess.run([sys.executable, MY])\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        # Two lines mention the tool.
        self.assertEqual(data["caller_count_by_surface"]["engage_py"], 1)
        # tools_py surface MUST NOT double-count engage.py.
        self.assertEqual(
            data["caller_count_by_surface"]["tools_py_subprocess_or_import"], 0)

    # --- Surface 4: pre-iter-check.sh ---------------------------------------

    def test_surface_pre_iter_check_sh_hit(self) -> None:
        _write(self.repo / "tools" / "pre-iter-check.sh",
               "#!/bin/bash\n"
               "if [ -f tools/my-tool.py ]; then python3 tools/my-tool.py; fi\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        # pre-iter-check.sh hit; pre-submit/wrappers surface must NOT also
        # count the same file (separate surfaces).
        self.assertGreaterEqual(
            data["caller_count_by_surface"]["pre_iter_check_sh"], 1)
        self.assertEqual(
            data["caller_count_by_surface"]["pre_submit_check_and_sh_wrappers"], 0)

    # --- Surface 5: audit-deep.sh + audit-deep-*.sh -------------------------

    def test_surface_audit_deep_sh_hit(self) -> None:
        _write(self.repo / "tools" / "audit-deep.sh",
               "#!/bin/bash\npython3 tools/my-tool.py\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(data["caller_count_by_surface"]["audit_deep_sh"], 1)
        # And the generic sh surface should NOT also count it.
        self.assertEqual(
            data["caller_count_by_surface"]["pre_submit_check_and_sh_wrappers"], 0)

    # --- Surface 6: agent_briefs/*.md ---------------------------------------

    def test_surface_agent_briefs_md_hit(self) -> None:
        _write(self.repo / "agent_briefs" / "lane.md",
               "Run `python3 tools/my-tool.py --x 1` to ship.\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(data["caller_count_by_surface"]["agent_briefs_md"], 1)

    # --- Surface 7: docs/*.md -----------------------------------------------

    def test_surface_docs_md_hit(self) -> None:
        _write(self.repo / "docs" / "TOOLS.md",
               "| `my-tool.py` | does X | weekly |\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(data["caller_count_by_surface"]["docs_md"], 1)

    def test_surface_docs_archive_excluded_when_requested(self) -> None:
        _write(self.repo / "docs" / "archive" / "old.md",
               "Old reference to my-tool.py\n")
        _write(self.repo / "docs" / "live.md",
               "Live reference to my-tool.py\n")
        rc, out, err = _run(
            ["my-tool.py", "--json", "--exclude-archive"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        # archive doc should be filtered; live doc remains.
        self.assertEqual(data["caller_count_by_surface"]["docs_md"], 1)
        for c in data["callers"]:
            self.assertNotIn("/archive/", c["file"])

    # --- Surface 8: scheduled-tasks SKILL.md -------------------------------

    def test_surface_scheduled_tasks_skill_md_hit(self) -> None:
        sched_dir = self.repo / "_sched"
        _write(sched_dir / "task-a" / "SKILL.md",
               "Hourly: run `python3 tools/my-tool.py`\n")
        rc, out, err = _run(
            ["my-tool.py", "--json", "--scheduled-tasks-dir", str(sched_dir)],
            root=self.repo,
        )
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(
            data["caller_count_by_surface"]["scheduled_tasks_skill_md"], 1)

    # --- Surface 9: tools/*.py subprocess/import ----------------------------

    def test_surface_tools_py_subprocess_hit(self) -> None:
        _write(self.repo / "tools" / "other.py",
               "import subprocess\n"
               "subprocess.run([sys.executable, 'tools/my-tool.py'])\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(
            data["caller_count_by_surface"]["tools_py_subprocess_or_import"], 1)

    def test_surface_tools_py_importlib_hit(self) -> None:
        _write(self.repo / "tools" / "other.py",
               "import importlib\n"
               "m = importlib.import_module('tools.my_tool')\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(
            data["caller_count_by_surface"]["tools_py_subprocess_or_import"], 1)

    # --- Multi-surface composition ------------------------------------------

    def test_multi_surface_tool_counts_distinctly(self) -> None:
        # Same tool wired in 3 different surfaces.
        _write(self.repo / "Makefile", "x:\n\tpython3 tools/my-tool.py\n")
        _write(self.repo / "tools" / "audit-deep.sh",
               "python3 tools/my-tool.py\n")
        _write(self.repo / "agent_briefs" / "lane.md",
               "`tools/my-tool.py` is canonical.\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(data["caller_count_by_surface"]["makefile"], 1)
        self.assertEqual(data["caller_count_by_surface"]["audit_deep_sh"], 1)
        self.assertEqual(data["caller_count_by_surface"]["agent_briefs_md"], 1)
        # Verdict should reflect 3 wired surfaces.
        self.assertEqual(data["verdict"], "wired-in-3-surfaces")
        self.assertEqual(data["caller_count"], 3)

    # --- Self-test-only filtering -------------------------------------------

    def test_self_test_only_caller_is_dead(self) -> None:
        # Dedicated test file references the tool but nothing else does.
        _write(self.repo / "tools" / "tests" / "test_my_tool.py",
               "from tools.my_tool import x\n"
               "# under test: tools/my-tool.py\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        # No callers (test is filtered by default).
        self.assertEqual(rc, 1, msg=err)
        data = json.loads(out)
        self.assertEqual(data["verdict"], "dead-no-caller")
        self.assertEqual(data["caller_count"], 0)

    def test_self_test_only_caller_visible_with_include_test(self) -> None:
        _write(self.repo / "tools" / "tests" / "test_my_tool.py",
               "from tools.my_tool import x\n"
               "# under test: tools/my-tool.py\n")
        rc, out, err = _run(
            ["my-tool.py", "--json", "--include-test"], root=self.repo)
        self.assertEqual(rc, 1, msg=err)  # still dead (only self-test caller)
        data = json.loads(out)
        self.assertEqual(data["verdict"], "dead-only-self-test-caller")
        self.assertGreaterEqual(data["caller_count"], 1)
        # Self/test filter classifies surviving callers.
        for c in data["callers"]:
            self.assertTrue(c["is_test"])

    # --- dead-no-caller -----------------------------------------------------

    def test_dead_no_caller(self) -> None:
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        # Brand-new repo with empty Makefile and no callers.
        self.assertEqual(rc, 1, msg=err)
        data = json.loads(out)
        self.assertEqual(data["verdict"], "dead-no-caller")
        self.assertEqual(data["caller_count"], 0)
        # Every surface counted zero.
        for s, n in data["caller_count_by_surface"].items():
            self.assertEqual(n, 0, msg=f"surface {s} had {n} hits")

    # --- Boundary discipline: must not match inside other identifiers ------

    def test_no_substring_match_inside_other_identifier(self) -> None:
        # "not-my-tool.py" must NOT match "my-tool.py".
        _write(self.repo / "Makefile", "x:\n\tpython3 tools/not-my-tool.py\n")
        # Create the bogus tool file too so the grep target is realistic.
        _write(self.repo / "tools" / "not-my-tool.py", "# bogus\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 1, msg=err)
        data = json.loads(out)
        self.assertEqual(data["verdict"], "dead-no-caller")
        self.assertEqual(data["caller_count_by_surface"]["makefile"], 0)

    # --- Batch mode ---------------------------------------------------------

    def test_batch_mode_emits_per_tool_records(self) -> None:
        _write(self.repo / "Makefile", "x:\n\tpython3 tools/my-tool.py\n")
        # second tool dead
        _write(self.repo / "tools" / "dead.py", "# dead\n")
        batch = self.repo / "batch.txt"
        _write(batch, "my-tool.py\ndead.py\n# comment\n\n")
        rc, out, err = _run(
            ["--batch", str(batch), "--json"], root=self.repo)
        # Batch exit: dead.py is dead -> exit 1.
        self.assertEqual(rc, 1, msg=err)
        data = json.loads(out)
        self.assertEqual(data["count"], 2)
        verdicts = {r["tool_basename"]: r["verdict"] for r in data["results"]}
        self.assertTrue(verdicts["my-tool.py"].startswith("wired-"))
        self.assertEqual(verdicts["dead.py"], "dead-no-caller")

    def test_batch_mode_ndjson_when_not_json(self) -> None:
        _write(self.repo / "Makefile", "x:\n\tpython3 tools/my-tool.py\n")
        batch = self.repo / "batch.txt"
        _write(batch, "my-tool.py\n")
        rc, out, err = _run(["--batch", str(batch)], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        # NDJSON: one valid JSON object on the first line.
        first = out.splitlines()[0]
        obj = json.loads(first)
        self.assertEqual(obj["tool_basename"], "my-tool.py")

    # --- Surface 3 vs 9 mutual exclusion ------------------------------------

    def test_engage_py_does_not_appear_in_tools_py_surface(self) -> None:
        # If engage.py mentions the tool, ONLY the engage_py surface counts.
        # The tools_py surface filters out engage.py by name.
        _write(self.repo / "tools" / "engage.py",
               "from tools.my_tool import doit\n"
               "subprocess.run(['python3', 'tools/my-tool.py'])\n")
        rc, out, err = _run(["my-tool.py", "--json"], root=self.repo)
        self.assertEqual(rc, 0, msg=err)
        data = json.loads(out)
        self.assertGreater(data["caller_count_by_surface"]["engage_py"], 0)
        self.assertEqual(
            data["caller_count_by_surface"]["tools_py_subprocess_or_import"], 0)

    # --- Exit code contract -------------------------------------------------

    def test_exit_code_wired(self) -> None:
        _write(self.repo / "Makefile", "x:\n\tpython3 tools/my-tool.py\n")
        rc, _, _ = _run(["my-tool.py"], root=self.repo)
        self.assertEqual(rc, 0)

    def test_exit_code_dead(self) -> None:
        rc, _, _ = _run(["my-tool.py"], root=self.repo)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
