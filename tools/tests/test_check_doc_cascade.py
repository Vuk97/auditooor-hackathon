#!/usr/bin/env python3
"""Regression tests for ``tools/check-doc-cascade.py``.

The tool flags stale README/docs/reference entries when a tool/script
changes. It must:

  * NOT auto-edit any doc.
  * Detect doc-vs-tool drift in three flavours:
      a) flag drift (doc cites ``--foo`` not in argparse).
      b) artifact-path drift (doc cites a tool output the source no
         longer mentions and the file no longer exists).
      c) line-citation drift (doc cites ``foo.py:L9999`` past EOF).
  * Emit ``REVIEW`` (advisory, exit 0) for ambiguous prose mentions.
  * Emit ``OK`` for docs that don't mention a changed tool at all.
  * Be conservative on flag attribution: bare prose mentions and
    multi-tool lines must NOT raise STALE.

These tests run hermetically against a synthetic mini-repo built in a
``tempfile.TemporaryDirectory``. No git, no network, stdlib only.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "check-doc-cascade.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("check_doc_cascade", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_repo(
    tmp: Path,
    *,
    tool_src: str,
    docs: dict[str, str],
    readme: str | None = None,
    tool_name: str = "demo.py",
) -> Path:
    """Build a synthetic repo at ``tmp`` with one tool and the given docs."""
    (tmp / "tools").mkdir(parents=True, exist_ok=True)
    (tmp / "tools" / tool_name).write_text(tool_src)
    (tmp / "docs").mkdir(parents=True, exist_ok=True)
    for rel, body in docs.items():
        target = tmp / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    if readme is not None:
        (tmp / "README.md").write_text(readme)
    return tmp


def _run_check(repo: Path, *tool_paths: str) -> dict:
    """Invoke check() directly via the loaded module — fast and isolated."""
    mod = _load_module()
    return mod.check(
        repo=repo,
        base="origin/main",
        working_tree=False,
        explicit_tools=list(tool_paths),
    )


class CheckDocCascadeTest(unittest.TestCase):
    def test_tool_exists(self) -> None:
        self.assertTrue(TOOL.is_file(), f"tool missing at {TOOL}")

    def test_help_runs(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--working-tree", proc.stdout)
        self.assertIn("--json", proc.stdout)

    def test_no_changed_tools_is_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src="import sys\n", docs={})
            result = _run_check(tmp)
        self.assertEqual(result["counts"], {"OK": 0, "STALE": 0, "REVIEW": 0})
        self.assertEqual(result["changed_tools"], [])

    def test_doc_with_no_mention_is_silent(self) -> None:
        """A doc that doesn't mention the changed tool produces 0 findings."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(
                tmp,
                tool_src="import argparse\np=argparse.ArgumentParser()\np.add_argument('--foo')\n",
                docs={"docs/UNRELATED.md": "This doc talks about something else.\n"},
            )
            result = _run_check(tmp, "tools/demo.py")
        self.assertEqual(result["counts"]["STALE"], 0)
        self.assertEqual(result["counts"]["REVIEW"], 0)

    def test_flag_drift_in_invocation_is_stale(self) -> None:
        """A doc that runs ``python3 tools/demo.py --gone`` for a removed
        flag is STALE."""
        tool_src = textwrap.dedent("""\
            import argparse
            p = argparse.ArgumentParser()
            p.add_argument("--keep")
            p.parse_args()
        """)
        doc_body = textwrap.dedent("""\
            # Demo doc

            Run it like:

                python3 tools/demo.py --gone

            That should now work.
        """)
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/DEMO.md": doc_body})
            result = _run_check(tmp, "tools/demo.py")
        stale = [f for f in result["findings"] if f["verdict"] == "STALE"]
        self.assertEqual(len(stale), 1, f"unexpected findings: {result['findings']}")
        self.assertIn("--gone", stale[0]["evidence"][0])
        self.assertEqual(result["counts"]["STALE"], 1)

    def test_flag_drift_only_in_prose_mention_is_review_not_stale(self) -> None:
        """If the doc mentions ``demo.py`` only as bare prose (no
        invocation form like ``python3 tools/demo.py``), unknown flags
        on the same line are NOT STALE — only REVIEW."""
        tool_src = textwrap.dedent("""\
            import argparse
            p = argparse.ArgumentParser()
            p.add_argument("--keep")
        """)
        doc_body = textwrap.dedent("""\
            Lesson: `demo.py --gone src` was hardcoded; later updated.
        """)
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/LESSON.md": doc_body})
            result = _run_check(tmp, "tools/demo.py")
        self.assertEqual(result["counts"]["STALE"], 0, result["findings"])
        self.assertEqual(result["counts"]["REVIEW"], 1)

    def test_flag_drift_skipped_when_other_tool_on_same_line(self) -> None:
        """Multi-tool lines must not attribute the foreign flag to our
        tool. ``demo.py ... git fetch --all`` should NOT raise STALE
        for ``--all`` on demo.py."""
        tool_src = textwrap.dedent("""\
            import argparse
            p = argparse.ArgumentParser()
            p.add_argument("--keep")
        """)
        # Mention demo.py + another tool basename on same line.
        doc_body = (
            "Run `python3 tools/demo.py --keep` and then `helper.py --all` later.\n"
        )
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/MULTI.md": doc_body})
            result = _run_check(tmp, "tools/demo.py")
        self.assertEqual(result["counts"]["STALE"], 0, result["findings"])

    def test_known_flag_in_invocation_is_review_only(self) -> None:
        """A doc that runs the tool with a flag that DOES still exist
        should land in REVIEW, never STALE."""
        tool_src = textwrap.dedent("""\
            import argparse
            p = argparse.ArgumentParser()
            p.add_argument("--keep")
        """)
        doc_body = "    python3 tools/demo.py --keep\n"
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/DEMO.md": doc_body})
            result = _run_check(tmp, "tools/demo.py")
        self.assertEqual(result["counts"]["STALE"], 0)
        self.assertEqual(result["counts"]["REVIEW"], 1)

    def test_line_citation_past_eof_is_stale(self) -> None:
        """``demo.py:L9999`` for a 10-line file is STALE."""
        tool_src = "print('hi')\n" * 10  # 10 lines
        doc_body = "See tools/demo.py:L9999 for context.\n"
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/CITE.md": doc_body})
            result = _run_check(tmp, "tools/demo.py")
        self.assertEqual(result["counts"]["STALE"], 1, result["findings"])
        ev = result["findings"][0]["evidence"]
        self.assertTrue(any("L9999" in e for e in ev))

    def test_artifact_path_missing_is_stale(self) -> None:
        """Doc cites an artifact ``docs/OLD_REPORT.md`` that the tool
        no longer produces and that doesn't exist on disk → STALE."""
        # Tool source mentions only the *new* artifact path. The doc
        # still cites the *old* path. The old file does not exist on
        # disk → STALE.
        tool_src = 'OUT = "docs/NEW_REPORT.md"\n'
        doc_body = (
            "Reading `python3 tools/demo.py` writes `docs/OLD_REPORT.md`.\n"
        )
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/DEMO.md": doc_body})
            # docs/OLD_REPORT.md must NOT exist on disk for STALE to fire.
            result = _run_check(tmp, "tools/demo.py")
        stale_evidence = [
            ev
            for f in result["findings"]
            if f["verdict"] == "STALE"
            for ev in f["evidence"]
        ]
        self.assertTrue(
            any("OLD_REPORT.md" in e for e in stale_evidence),
            f"expected OLD_REPORT.md STALE, got: {result['findings']}",
        )

    def test_artifact_path_present_on_disk_is_not_stale(self) -> None:
        """If the cited artifact still exists on disk, do NOT raise
        STALE — the file may legitimately exist as a checked-in
        snapshot or a peer tool's output."""
        tool_src = 'OUT = "docs/NEW_REPORT.md"\n'
        doc_body = (
            "Reading `python3 tools/demo.py` writes `docs/OLD_REPORT.md`.\n"
        )
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/DEMO.md": doc_body})
            # Make OLD_REPORT.md actually exist — must NOT be STALE.
            (tmp / "docs" / "OLD_REPORT.md").write_text("snapshot\n")
            result = _run_check(tmp, "tools/demo.py")
        self.assertEqual(result["counts"]["STALE"], 0, result["findings"])

    def test_no_doc_mutation(self) -> None:
        """The tool must NEVER edit doc files — only flag them."""
        tool_src = "import argparse\np=argparse.ArgumentParser()\np.add_argument('--gone')\n"
        doc_body = "    python3 tools/demo.py --gone\n"
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/DEMO.md": doc_body})
            doc = tmp / "docs" / "DEMO.md"
            before = doc.read_text()
            _run_check(tmp, "tools/demo.py")
            after = doc.read_text()
        self.assertEqual(before, after, "tool must not edit docs")

    def test_json_output_is_valid_and_has_counts(self) -> None:
        """``--json`` produces structured output."""
        tool_src = "import argparse\np=argparse.ArgumentParser()\np.add_argument('--ok')\n"
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/X.md": "no mention\n"})
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--repo", str(tmp), "--tool", "tools/demo.py", "--json"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIn("counts", payload)
        self.assertEqual(payload["changed_tools"], ["tools/demo.py"])
        self.assertEqual(payload["counts"]["STALE"], 0)

    def test_exit_code_is_one_on_stale(self) -> None:
        """Subprocess exit code must be 1 when STALE > 0."""
        tool_src = "import argparse\np=argparse.ArgumentParser()\np.add_argument('--keep')\n"
        doc_body = "    python3 tools/demo.py --gone\n"
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _build_repo(tmp, tool_src=tool_src, docs={"docs/X.md": doc_body})
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--repo", str(tmp), "--tool", "tools/demo.py"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("STALE", proc.stdout)


if __name__ == "__main__":
    unittest.main()
