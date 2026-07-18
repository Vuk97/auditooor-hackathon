"""Guard: hunt-scoped Makefile recipe wires the anchor-lead -> hunt-task pipeline.

WHY: tools/anchor-lead-to-hunt-task.py was proven standalone (real strata round-trip)
but nothing in hunt-scoped ever invoked it, so <ws>/.auditooor/anchor_hunt_tasks.jsonl
sat unread. commit-anchor-lead-emit.py (the upstream producer of anchor_leads.jsonl)
was ALSO never invoked anywhere in the Makefile. This test guards that both are now
wired into the hunt-scoped recipe body, in the correct order (emit before to-hunt-task),
both non-fatal (advisory - must never block the scoped-hunt recipe), and that the
recipe still parses cleanly under `make -n` (dry-run, no real execution).

Asserts on the recipe BLOCK (target line to next top-level target), not the whole
file, so an unrelated mention elsewhere in the Makefile cannot mask a regression -
matches the convention in tools/tests/test_makefile_batch2_wiring.py.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = REPO / "Makefile"


def _recipe_block(text: str, target: str) -> str:
    """Return the recipe body for `target:` up to (not including) the next
    top-level (non-indented) target line. Mirrors test_makefile_batch2_wiring.py."""
    lines = text.splitlines()
    out: list[str] = []
    capturing = False
    for ln in lines:
        if ln.startswith(f"{target}:"):
            capturing = True
            out.append(ln)
            continue
        if capturing:
            if ln and not ln.startswith(("\t", " ")) and re.match(r"^[A-Za-z0-9_.-]+:", ln):
                break
            out.append(ln)
    return "\n".join(out)


class TestAnchorHuntMakefileWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")
        cls.text = MAKEFILE.read_text(encoding="utf-8")
        cls.block = _recipe_block(cls.text, "hunt-scoped hunt-haiku")

    def test_recipe_found(self) -> None:
        self.assertTrue(self.block, "hunt-scoped hunt-haiku recipe not found in Makefile")

    def test_commit_anchor_lead_emit_invoked(self) -> None:
        self.assertIn(
            "tools/commit-anchor-lead-emit.py", self.block,
            "hunt-scoped must invoke commit-anchor-lead-emit.py so anchor_leads.jsonl "
            "is (re)generated before the downstream consumer runs",
        )
        self.assertIn("--workspace", self.block)

    def test_anchor_lead_to_hunt_task_invoked(self) -> None:
        self.assertIn(
            "tools/anchor-lead-to-hunt-task.py", self.block,
            "hunt-scoped must invoke anchor-lead-to-hunt-task.py - the previously "
            "orphaned downstream consumer of anchor_leads.jsonl",
        )

    def test_emit_runs_before_to_hunt_task(self) -> None:
        emit_idx = self.block.find("tools/commit-anchor-lead-emit.py")
        task_idx = self.block.find("tools/anchor-lead-to-hunt-task.py")
        self.assertGreater(emit_idx, -1)
        self.assertGreater(task_idx, -1)
        self.assertLess(
            emit_idx, task_idx,
            "commit-anchor-lead-emit.py must run BEFORE anchor-lead-to-hunt-task.py "
            "(the emitter produces anchor_leads.jsonl, which the hunt-task builder reads)",
        )

    def test_both_invocations_are_non_fatal(self) -> None:
        for line in self.block.splitlines():
            if "tools/commit-anchor-lead-emit.py" in line or "tools/anchor-lead-to-hunt-task.py" in line:
                self.assertIn(
                    "||", line,
                    f"invocation must be non-fatal (echo-warn-and-continue on failure): {line!r}",
                )
                self.assertNotIn(
                    "exit 1", line.split("||", 1)[1] if "||" in line else "",
                    f"non-fatal fallback must not exit non-zero: {line!r}",
                )

    def test_summary_line_reports_task_count_and_path(self) -> None:
        self.assertIn(
            "anchor_hunt_tasks.jsonl", self.block,
            "recipe must echo the anchor_hunt_tasks.jsonl path so an operator/loop "
            "sees the artifact instead of it being silently generated",
        )
        self.assertIn(
            "spawn-worker.sh", self.block,
            "the summary line must point at spawn-worker.sh as the dispatch mechanism",
        )
        self.assertRegex(
            self.block, r"anchor hunt task\(s\) written to",
            "recipe must print a one-line N-tasks-written summary",
        )

    def test_hunt_haiku_alias_shares_the_same_wiring(self) -> None:
        # hunt-scoped and hunt-haiku are a combined target (`hunt-scoped hunt-haiku:`)
        # sharing one recipe body, so the alias must carry the same wiring.
        self.assertRegex(self.text, re.compile(r"^hunt-scoped hunt-haiku:\s*$", re.MULTILINE))


class TestAnchorHuntMakefileDryRun(unittest.TestCase):
    """`make -n` (dry-run) proves the recipe still PARSES with zero errors after
    the new lines were added - a real GNU Make syntax check, not just a string grep."""

    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("make"):
            raise unittest.SkipTest("make not on PATH")
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")

    def setUp(self) -> None:
        self.ws = Path(tempfile.mkdtemp(prefix="anchor_hunt_makefile_dryrun_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.ws, ignore_errors=True)

    def _dry_run(self, target: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["make", "-n", target, f"WS={self.ws}"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_hunt_scoped_dry_run_parses_and_shows_both_new_invocations(self) -> None:
        proc = self._dry_run("hunt-scoped")
        self.assertEqual(
            proc.returncode, 0,
            f"make -n hunt-scoped failed to parse\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        self.assertIn("tools/commit-anchor-lead-emit.py", proc.stdout)
        self.assertIn("tools/anchor-lead-to-hunt-task.py", proc.stdout)
        emit_pos = proc.stdout.find("tools/commit-anchor-lead-emit.py")
        task_pos = proc.stdout.find("tools/anchor-lead-to-hunt-task.py")
        self.assertLess(emit_pos, task_pos)

    def test_hunt_haiku_alias_dry_run_parses(self) -> None:
        proc = self._dry_run("hunt-haiku")
        self.assertEqual(
            proc.returncode, 0,
            f"make -n hunt-haiku failed to parse\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        self.assertIn("tools/anchor-lead-to-hunt-task.py", proc.stdout)


if __name__ == "__main__":
    unittest.main()
