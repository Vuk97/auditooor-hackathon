"""Gap #57 (formerly Gap #52 in ENFORCEMENT-COMPLETENESS-AUDIT numbering):
NotebookEdit was not classified by the universal classifier dispatch
table, so notebook cell writes could silently land L34-protected drafts.

Verifies the universal classifier:
  - dispatches NotebookEdit through _classify_edit_or_write (so a draft
    notebook_path inherits L34 just like Edit/Write/MultiEdit).
  - scans the cell.source body for Gap #56 shell-write shapes and emits
    NotebookEdit<draft-file-write-via-cell> with L34 when the cell body
    would write to a draft path.

Spec: reports/v3_iter_2026-05-26_enforcement_audit/lane_ENFORCEMENT_COMPLETENESS_AUDIT/results.md
Lane: lane-GAP-FIX-3-C

r36-rebuttal: lane-GAP-FIX-3-C tools/agent-pathspec-register.py declared 5 files at lane start
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
CLASSIFIER = os.path.join(REPO_ROOT, "tools", "hooks", "auditooor-universal-action-classifier.py")


def run_classifier(payload: dict) -> dict:
    proc = subprocess.run(
        [sys.executable, CLASSIFIER],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"classifier exited {proc.returncode}; stderr={proc.stderr!r}"
        )
    return json.loads(proc.stdout)


class TestGap57NotebookEditDispatch(unittest.TestCase):
    """NotebookEdit dispatches through _classify_edit_or_write."""

    def test_notebookedit_on_draft_notebook_path_requires_l34(self) -> None:
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/Users/wolf/audits/spark/submissions/paste_ready/foo/foo.ipynb",
            },
        })
        self.assertEqual(out["tool_name"], "NotebookEdit")
        self.assertEqual(out["action_signature"], "NotebookEdit<submissions-draft-file>")
        self.assertEqual(out["filepath_class"], "draft-file")
        self.assertIn("L34", out["required_rule_citations"])

    def test_notebookedit_on_tools_py_path_requires_r36(self) -> None:
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/Users/wolf/auditooor-mcp/tools/foo.ipynb",
            },
        })
        # tools/* but not .py -> tools-non-py (R36 only applies to .py).
        # The dispatch is now alive (no longer <allow-by-default>).
        self.assertEqual(out["tool_name"], "NotebookEdit")
        self.assertNotIn("allow-by-default", out["action_signature"])

    def test_notebookedit_on_docs_path_is_allow(self) -> None:
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/Users/wolf/auditooor-mcp/docs/FOO.ipynb",
            },
        })
        self.assertEqual(out["filepath_class"], "docs")
        self.assertEqual(out["required_rule_citations"], [])

    def test_notebookedit_on_out_of_tree_path_is_allow(self) -> None:
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/Users/wolf/Downloads/notebook.ipynb",
            },
        })
        self.assertEqual(out["filepath_class"], "cwd-out-of-tree")
        self.assertEqual(out["required_rule_citations"], [])


class TestGap57NotebookEditCellSourceScan(unittest.TestCase):
    """NotebookEdit cell.source body is scanned for Gap #56 shell-write
    shapes targeting draft paths. Cell-level draft writes fire
    NotebookEdit<draft-file-write-via-cell>.
    """

    def test_cell_python_open_write_to_draft(self) -> None:
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/tmp/scratch.ipynb",
                "cell": {
                    "cell_type": "code",
                    "source": "open('/Users/wolf/audits/spark/submissions/filed/y/y.md','w').write('x')",
                },
            },
        })
        self.assertEqual(out["action_signature"], "NotebookEdit<draft-file-write-via-cell>")
        self.assertIn("L34", out["required_rule_citations"])
        self.assertEqual(out["filepath_class"], "draft-file")
        self.assertEqual(out["context_signals"]["cell_draft_write_shape"], "naked-python-open")

    def test_cell_pathlib_write_text_to_draft(self) -> None:
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/tmp/scratch.ipynb",
                "cell": {
                    "source": (
                        "from pathlib import Path\n"
                        "Path('/Users/wolf/audits/spark/submissions/filed/y/y.md').write_text('x')\n"
                    ),
                },
            },
        })
        self.assertEqual(out["action_signature"], "NotebookEdit<draft-file-write-via-cell>")
        self.assertIn("L34", out["required_rule_citations"])

    def test_cell_source_as_list_is_supported(self) -> None:
        # Jupyter cells sometimes carry source as a list of strings.
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/tmp/scratch.ipynb",
                "cell": {
                    "source": [
                        "import os\n",
                        "Path('/Users/wolf/audits/spark/submissions/filed/y/y.md').write_text('x')\n",
                    ],
                },
            },
        })
        self.assertEqual(out["action_signature"], "NotebookEdit<draft-file-write-via-cell>")

    def test_cell_shell_magic_redirect_to_draft(self) -> None:
        # IPython cells can run shell via `!` prefix; the body itself is
        # still a shell command shape.
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/tmp/scratch.ipynb",
                "cell": {
                    "source": "!echo 'malicious' >> /Users/wolf/audits/spark/submissions/filed/y/y.md",
                },
            },
        })
        self.assertEqual(out["action_signature"], "NotebookEdit<draft-file-write-via-cell>")
        self.assertIn("L34", out["required_rule_citations"])

    def test_cell_with_new_source_field(self) -> None:
        # Anthropic NotebookEdit harness sometimes passes `new_source`
        # directly at the top level of tool_input.
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/tmp/scratch.ipynb",
                "new_source": "!echo z >> /Users/wolf/audits/spark/submissions/filed/y/y.md",
            },
        })
        self.assertEqual(out["action_signature"], "NotebookEdit<draft-file-write-via-cell>")

    def test_benign_cell_against_non_draft_notebook_is_allow(self) -> None:
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/Users/wolf/Downloads/scratch.ipynb",
                "cell": {
                    "source": "import pandas as pd\nprint('hello')\n",
                },
            },
        })
        self.assertNotIn("L34", out["required_rule_citations"])
        self.assertEqual(out["filepath_class"], "cwd-out-of-tree")

    def test_cell_writing_to_non_draft_path_does_not_fire_l34(self) -> None:
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/Users/wolf/Downloads/scratch.ipynb",
                "cell": {
                    "source": "open('/tmp/scratch.md','w').write('x')",
                },
            },
        })
        self.assertNotEqual(out["action_signature"], "NotebookEdit<draft-file-write-via-cell>")

    def test_cell_writing_to_tracker_md_is_allow(self) -> None:
        # SUBMISSIONS.md is tracker-file bucket per L34 v2.
        out = run_classifier({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/tmp/scratch.ipynb",
                "cell": {
                    "source": "open('/Users/wolf/audits/spark/submissions/SUBMISSIONS.md','a').write('row\\n')",
                },
            },
        })
        # Cell body does not match _matches_bash_draft_write because the
        # path is not under a draft status dir.
        self.assertNotEqual(out["action_signature"], "NotebookEdit<draft-file-write-via-cell>")


class TestGap57BackwardCompatibility(unittest.TestCase):
    """Regression: Edit/Write/MultiEdit dispatch is unchanged."""

    def test_edit_draft_file_still_requires_l34(self) -> None:
        out = run_classifier({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/Users/wolf/audits/spark/submissions/filed/foo/foo.md",
                "old_string": "x", "new_string": "y",
            },
        })
        self.assertEqual(out["action_signature"], "Edit<submissions-draft-file>")
        self.assertIn("L34", out["required_rule_citations"])

    def test_write_tools_py_still_requires_r36(self) -> None:
        out = run_classifier({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/Users/wolf/auditooor-mcp/tools/foo.py",
                "content": "print('hi')\n",
            },
        })
        self.assertEqual(out["action_signature"], "Write<tools-py>")
        self.assertIn("R36", out["required_rule_citations"])


if __name__ == "__main__":
    unittest.main()
