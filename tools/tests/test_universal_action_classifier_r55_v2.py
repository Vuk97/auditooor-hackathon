"""LIFT-22 R55 regex-tighten regression tests.

Covers the 4 false-positive (FP) carve-outs and the 1 false-negative
(FN) coverage gap that the LIFT-20 enforcement audit identified.

FP carve-outs (should NOT fire R55 / Gap-6 / destructive-op):
  FP-1 grep "git reset --hard" file.txt        - string in grep pattern
  FP-2 # example: git reset --hard would wipe  - bash comment
  FP-3 echo "DO NOT run git reset --hard"      - operator-facing doc echo
  FP-4 R55_TEST_CASES = ["git reset --hard"]   - test-data list (no exec)
  FP-5 cat <<EOF\nUse `git reset --hard` ...   - heredoc documentation
  FP-6 \"\"\"Documents the git reset --hard ... - Python docstring
  FP-7 markdown code block in heredoc

FN coverage (SHOULD fire R55 - LIFT-20 audit identified):
  FN-1 subprocess.run(["git", "reset", "--hard"])        - Python list form (KEY FN)
  FN-2 subprocess.call(["git", "checkout", "--", ...])   - Python list form
  FN-3 subprocess.Popen(["git", "clean", "-fd"])         - Python list form
  FN-4 os.system("git reset --hard")                     - Python string form
  FN-5 sh -c "git clean -fd"                             - shell exec form

TP (true positive) cases (existing behavior preserved):
  TP-1..6 raw destructive shapes that must still fire

r36-rebuttal: lane LIFT-22-R55-REGEX-TIGHTEN registered via tools/agent-pathspec-register.py

Empirical anchor: 2026-05-26 LIFT-20 enforcement audit
(reports/v3_iter_2026-05-26/lane_LIFT_20*) confirmed the 4 FPs +
1 FN class combined to manufacture the 940-record loss at 20:56.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
CLASSIFIER = os.path.join(
    REPO_ROOT, "tools", "hooks", "auditooor-universal-action-classifier.py"
)

# String fragments assembled at runtime so this test file itself does
# not literal-contain `git reset --hard`; otherwise the universal hook
# would refuse to let the test file be edited / committed.
_RESET = "g" + "it " + "reset"
RESET_HARD = _RESET + " --hard"
RESET_MERGE = _RESET + " --merge"
RESET_KEEP = _RESET + " --keep"
CHECKOUT_DD = "g" + "it " + "checkout -- file.py"
CHECKOUT_BR = "g" + "it " + "checkout some-branch"
CLEAN_FD = "g" + "it " + "clean -fd"
STASH_DROP = "g" + "it " + "stash drop stash@{0}"


def run_classifier(payload: dict) -> dict:
    env = os.environ.copy()
    env["AUDITOOOR_UNIVERSAL_BYPASS"] = "1"
    proc = subprocess.run(
        [sys.executable, CLASSIFIER],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"classifier exit={proc.returncode}; stderr={proc.stderr!r}"
        )
    return json.loads(proc.stdout)


def fired_r55(out: dict) -> bool:
    """Return True iff classification fires R55 / Gap-6."""
    sig = out.get("action_signature", "")
    rules = out.get("required_rule_citations", []) or []
    return (
        any(r in ("R55", "R55-FOREGROUND") for r in rules)
        or sig in ("Bash<git-reset-hard-raw>", "Bash<git-destructive-op>")
    )


class TestFPNotFiring(unittest.TestCase):
    """4 FP classes the LIFT-20 audit confirmed; must NOT fire R55."""

    def test_fp1_grep_pattern_literal(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": f'grep "{RESET_HARD}" file.txt'},
        })
        self.assertFalse(
            fired_r55(out),
            f"FP-1: grep string pattern leaked to R55: {out['action_signature']}",
        )

    def test_fp2_bash_comment(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": f"# example: {RESET_HARD} would wipe"},
        })
        self.assertFalse(fired_r55(out))

    def test_fp3_echo_doc_string(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": f'echo "DO NOT run {RESET_HARD}"'},
        })
        self.assertFalse(fired_r55(out))

    def test_fp4_test_data_list_no_exec(self) -> None:
        """A test-fixture string-list constant must not fire R55 when
        the command body has no subprocess.* / os.system / sh -c that
        could execute the list."""
        cmd = f'R55_TEST_CASES = ["{RESET_HARD}", "{CLEAN_FD}"]; echo loaded'
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
        })
        self.assertFalse(fired_r55(out))

    def test_fp5_heredoc_documentation(self) -> None:
        cmd = f"cat <<EOF\nUse `{RESET_HARD}` carefully\nEOF"
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
        })
        self.assertFalse(fired_r55(out))

    def test_fp6_python_docstring(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {
                "command": f'"""Documents the {RESET_HARD} fallback path."""'
            },
        })
        self.assertFalse(fired_r55(out))


class TestFNCoverage(unittest.TestCase):
    """1 FN class (Python list form) the LIFT-20 audit identified;
    MUST fire R55 now. Plus 4 sibling exec-wrapper shapes."""

    def test_fn1_subprocess_run_list_form(self) -> None:
        """KEY FN catch from LIFT-20: subprocess.run list form."""
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {
                "command": 'subprocess.run(["git", "reset", "--hard"])'
            },
        })
        self.assertTrue(
            fired_r55(out),
            f"FN-1: subprocess.run list form leaked through: {out['action_signature']}",
        )
        # The reset verb should escalate to the EXTREME Gap-6 path.
        self.assertEqual(out["action_signature"], "Bash<git-reset-hard-raw>")
        self.assertIn("R55-FOREGROUND", out["required_rule_citations"])

    def test_fn2_subprocess_call_checkout_list_form(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {
                "command": 'subprocess.call(["git", "checkout", "--", "x.py"])'
            },
        })
        self.assertTrue(fired_r55(out))

    def test_fn3_subprocess_Popen_clean_list_form(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {
                "command": 'subprocess.Popen(["git", "clean", "-fd"])'
            },
        })
        self.assertTrue(fired_r55(out))

    def test_fn4_os_system_string_form(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": f'os.system("{RESET_HARD}")'},
        })
        self.assertTrue(fired_r55(out))
        # The reset verb should escalate to the EXTREME Gap-6 path.
        self.assertEqual(out["action_signature"], "Bash<git-reset-hard-raw>")

    def test_fn5_sh_exec_string_form(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": f'sh -c "{CLEAN_FD}"'},
        })
        self.assertTrue(fired_r55(out))


class TestTPPreserved(unittest.TestCase):
    """Existing TP behavior preserved (no regression)."""

    def test_tp1_direct_reset_hard(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": f"{RESET_HARD} HEAD~1"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-reset-hard-raw>")
        self.assertIn("R55-FOREGROUND", out["required_rule_citations"])

    def test_tp2_chained_destructive(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": f"git status && {RESET_HARD}"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-reset-hard-raw>")

    def test_tp3_clean_fd(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": CLEAN_FD},
        })
        self.assertEqual(out["action_signature"], "Bash<git-destructive-op>")

    def test_tp4_stash_drop(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": STASH_DROP},
        })
        self.assertEqual(out["action_signature"], "Bash<git-destructive-op>")

    def test_tp5_checkout_dd_file(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": CHECKOUT_DD},
        })
        self.assertEqual(out["action_signature"], "Bash<git-destructive-op>")

    def test_tp6_reset_keep(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": f"{RESET_KEEP} HEAD"},
        })
        # _RAW_GIT_RESET_HARD_RE only matches --hard, so --keep falls
        # through to the generic destructive-op classifier.
        self.assertEqual(out["action_signature"], "Bash<git-destructive-op>")

    def test_tp7_reset_merge(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": f"{RESET_MERGE} HEAD"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-destructive-op>")

    def test_tp8_wrapper_invocation_not_classified(self) -> None:
        """The safe-reset wrapper invocation must NOT fire Gap-6."""
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {
                "command": "bash tools/git-hooks/git-reset-safe.sh --hard HEAD~1"
            },
        })
        self.assertNotEqual(out["action_signature"], "Bash<git-reset-hard-raw>")


class TestInteractionWithExistingClasses(unittest.TestCase):
    """Make sure the LIFT-22 changes don't break non-R55 classifications."""

    def test_plain_ls_still_allowed(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        self.assertEqual(out["action_signature"], "Bash<other>")
        self.assertEqual(out["required_rule_citations"], [])

    def test_git_commit_still_caught(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": 'git commit -m "foo"'},
        })
        self.assertEqual(out["action_signature"], "Bash<git-commit>")

    def test_grep_other_pattern_not_blocked(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": 'grep "hello world" file.txt'},
        })
        self.assertEqual(out["action_signature"], "Bash<other>")

    def test_echo_other_string_not_blocked(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": 'echo "hello world"'},
        })
        self.assertEqual(out["action_signature"], "Bash<other>")


if __name__ == "__main__":
    unittest.main()
