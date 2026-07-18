"""Gap #56 (formerly Gap #51 in ENFORCEMENT-COMPLETENESS-AUDIT numbering):
Bash command-body draft-file write bypass.

Verifies the universal classifier emits
``Bash<draft-file-write-via-shell>`` with required citation L34 for every
known shell-write shape targeting a draft path, AND does NOT misfire on
read-only operations against the same paths.

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


def bash_cmd(command: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


class TestGap56BashShellWriteShapes(unittest.TestCase):
    """Each shape from Gap #56 fix sketch fires L34 with a distinct shape tag."""

    def test_echo_redirect_to_draft(self) -> None:
        out = run_classifier(bash_cmd(
            "echo 'malicious' >> /Users/wolf/audits/dydx/submissions/filed/cantina-018/cantina-018.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertIn("L34", out["required_rule_citations"])
        self.assertTrue(out["exception_marker_required"])
        self.assertEqual(out["context_signals"]["shell_draft_write_shape"], "redirect")

    def test_echo_single_redirect_overwrite(self) -> None:
        out = run_classifier(bash_cmd(
            "echo 'fresh' > /Users/wolf/audits/spark/submissions/staging/foo/foo.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertEqual(out["context_signals"]["shell_draft_write_shape"], "redirect")

    def test_cat_heredoc_to_draft(self) -> None:
        cmd = (
            "cat <<'EOF' > /Users/wolf/audits/hyperbridge/submissions/paste_ready/h/h.md\n"
            "body content\n"
            "EOF\n"
        )
        out = run_classifier(bash_cmd(cmd))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertIn("L34", out["required_rule_citations"])

    def test_tee_append_to_draft(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x | tee -a /Users/wolf/audits/spark/submissions/staging/bar/bar.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertEqual(out["context_signals"]["shell_draft_write_shape"], "tee")

    def test_tee_overwrite_to_draft(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x | tee /Users/wolf/audits/spark/submissions/staging/bar/bar.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_sed_in_place_to_draft(self) -> None:
        out = run_classifier(bash_cmd(
            "sed -i '' 's/old/new/' /Users/wolf/audits/spark/submissions/filed/baz/baz.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertEqual(out["context_signals"]["shell_draft_write_shape"], "sed-inplace")

    def test_sed_in_place_no_suffix(self) -> None:
        out = run_classifier(bash_cmd(
            "sed -i s/x/y/ /Users/wolf/audits/spark/submissions/filed/baz/baz.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_awk_in_place_to_draft(self) -> None:
        out = run_classifier(bash_cmd(
            "awk -i inplace '/foo/{print}' /Users/wolf/audits/spark/submissions/filed/qux/qux.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertEqual(out["context_signals"]["shell_draft_write_shape"], "awk-inplace")

    def test_perl_in_place_to_draft(self) -> None:
        out = run_classifier(bash_cmd(
            "perl -i -pe 's/old/new/' /Users/wolf/audits/spark/submissions/filed/x/x.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertEqual(out["context_signals"]["shell_draft_write_shape"], "perl-inplace")

    def test_perl_in_place_with_backup(self) -> None:
        out = run_classifier(bash_cmd(
            "perl -i.bak -pe 's/old/new/' /Users/wolf/audits/spark/submissions/filed/x/x.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_cp_to_draft_destination(self) -> None:
        out = run_classifier(bash_cmd(
            "cp /tmp/x.md /Users/wolf/audits/spark/submissions/filed/y/y.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertEqual(out["context_signals"]["shell_draft_write_shape"], "cp-mv-dest")

    def test_mv_to_draft_destination(self) -> None:
        out = run_classifier(bash_cmd(
            "mv /tmp/x.md /Users/wolf/audits/spark/submissions/filed/z/z.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertEqual(out["context_signals"]["shell_draft_write_shape"], "cp-mv-dest")

    def test_inline_python_open_write_draft(self) -> None:
        out = run_classifier(bash_cmd(
            "python3 -c \"open('/Users/wolf/audits/spark/submissions/paste_ready/p/p.md','w').write('x')\""
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertEqual(out["context_signals"]["shell_draft_write_shape"], "inline-interp")

    def test_inline_node_fs_writeFileSync_draft(self) -> None:
        out = run_classifier(bash_cmd(
            "node -e \"require('fs').writeFileSync('/Users/wolf/audits/spark/submissions/staging/n/n.md','x')\""
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_inline_python_pathlib_write_text(self) -> None:
        out = run_classifier(bash_cmd(
            "python3 -c \"from pathlib import Path; Path('/Users/wolf/audits/spark/submissions/staging/n/n.md').write_text('x')\""
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    # --- override marker / non-write false-positive guards ------------

    def test_l34_rebuttal_html_marker_in_command_satisfies_hook(self) -> None:
        # The classifier itself still fires the signature (the *enforcement
        # hook* is what consumes the rebuttal marker). This test pins the
        # classifier behavior: signature is emitted; the hook then resolves
        # the rebuttal. We just verify the signature stays consistent so
        # the hook has a deterministic input.
        out = run_classifier(bash_cmd(
            "echo '<!-- l34-rebuttal: operator-authorised batch fix #foo -->' >> "
            "/Users/wolf/audits/spark/submissions/filed/bar/bar.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")
        self.assertIn("L34", out["required_rule_citations"])

    def test_plain_cat_read_is_not_matched(self) -> None:
        out = run_classifier(bash_cmd(
            "cat /Users/wolf/audits/spark/submissions/filed/x/x.md"
        ))
        self.assertNotEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_grep_against_draft_is_not_matched(self) -> None:
        out = run_classifier(bash_cmd(
            "grep TODO /Users/wolf/audits/spark/submissions/filed/x/x.md"
        ))
        self.assertNotEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_redirect_to_non_draft_is_not_matched(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x >> /tmp/scratch.md"
        ))
        self.assertNotEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_redirect_to_tracker_md_is_not_matched(self) -> None:
        # SUBMISSIONS.md / README.md at submissions root are tracker-file
        # bucket per L34 v2 (auto-executable, no L34 auth required).
        # The Bash shell-write classifier should also pass this through.
        out = run_classifier(bash_cmd(
            "echo '- new row' >> /Users/wolf/audits/spark/submissions/SUBMISSIONS.md"
        ))
        self.assertNotEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_redirect_to_lessons_learned_is_not_matched(self) -> None:
        # lesson-anchor bucket; also auto-executable.
        out = run_classifier(bash_cmd(
            "echo '- lesson' >> /Users/wolf/audits/spark/submissions/_lessons-learned/lesson.md"
        ))
        self.assertNotEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_redirect_to_workspace_ledger_is_not_matched(self) -> None:
        # workspace-ledger bucket; also auto-executable.
        out = run_classifier(bash_cmd(
            "echo '{}' > /Users/wolf/audits/spark/.auditooor/state.json"
        ))
        self.assertNotEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_make_audit_command_is_not_matched(self) -> None:
        # `make audit WS=...` does not produce a draft write itself.
        out = run_classifier(bash_cmd("make audit WS=/Users/wolf/audits/spark"))
        self.assertNotEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    # --- extreme-gap precedence ---------------------------------------

    def test_extreme_gap_takes_precedence_over_gap56(self) -> None:
        # `git commit --no-verify` is Gap 1 (NEVER-SKIP-HOOKS) which runs
        # BEFORE Gap #56 in classifier dispatch. Even if the commit body
        # mentions a draft path, the Gap 1 signature should still fire.
        out = run_classifier(bash_cmd(
            "git commit --no-verify -m 'edit submissions/filed/foo/foo.md'"
        ))
        self.assertEqual(out["action_signature"], "Bash<git-no-verify>")

    def test_raw_git_reset_hard_takes_precedence_over_gap56(self) -> None:
        # Gap 6 (R55-FOREGROUND) wins even if the command body contains a
        # draft path reference.
        out = run_classifier(bash_cmd(
            "git reset --hard HEAD~1 # touches submissions/filed/foo/foo.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<git-reset-hard-raw>")


class TestGap56DraftPathVariants(unittest.TestCase):
    """Each draft status directory is recognised."""

    def test_paste_ready_status_dir(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x >> /Users/wolf/audits/h/submissions/paste_ready/y/y.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_staging_status_dir(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x >> /Users/wolf/audits/h/submissions/staging/y/y.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_filed_status_dir(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x >> /Users/wolf/audits/h/submissions/filed/y/y.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_held_status_dir(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x >> /Users/wolf/audits/h/submissions/held/y/y.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_killed_status_dir(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x >> /Users/wolf/audits/h/submissions/_killed/y/y.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_oos_rejected_status_dir(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x >> /Users/wolf/audits/h/submissions/_oos_rejected/y/y.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_packaged_status_dir(self) -> None:
        out = run_classifier(bash_cmd(
            "echo x >> /Users/wolf/audits/h/submissions/packaged/y/y.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")

    def test_workspace_relative_path_is_matched(self) -> None:
        # `cd <workspace> && echo x >> submissions/filed/y/y.md` is a
        # common idiom that the classifier should still catch.
        out = run_classifier(bash_cmd(
            "echo x >> submissions/filed/y/y.md"
        ))
        self.assertEqual(out["action_signature"], "Bash<draft-file-write-via-shell>")


if __name__ == "__main__":
    unittest.main()
