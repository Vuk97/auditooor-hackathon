"""Tests for tools/hooks/auditooor-universal-action-classifier.py.

Covers the 7 seed action classes the classifier ships with:

  1. Bash<git-commit>
  2. Bash<git-push>
  3. Bash<git-destructive-op>
  4. Bash<make-audit-or-hunt> (techupgrade-tagged)
  5. Edit<submissions-draft-file>
  6. Write<tools-py>
  7. Agent<severity-decision-context>
  8. Agent<drill-class-lane>

Plus fall-through cases (unrelated dev work, plain Read, etc).
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


class TestBashClassification(unittest.TestCase):
    def test_git_commit_requires_context_pack(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git commit -m 'foo'"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-commit>")
        self.assertIn("context-pack-id", out["required_rule_citations"])
        self.assertTrue(out["exception_marker_required"])

    def test_git_push_requires_mcp_token(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git push origin main"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-push>")
        self.assertIn("mcp-session-token", out["required_rule_citations"])

    def test_git_reset_hard_blocks_via_r55(self) -> None:
        # r36-rebuttal: agent_pathspec.json declares this test file; tools/agent-pathspec-register.py registered at lane start
        # Phase 1 Tier-A Gap 6 supersedes the legacy generic destructive-op
        # signature for raw `git reset --hard` (more specific DENY message).
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git reset --hard HEAD~1"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-reset-hard-raw>")
        self.assertIn("R55-FOREGROUND", out["required_rule_citations"])

    def test_git_clean_fd_blocks_via_r55(self) -> None:
        # `git clean -fd` is not one of the 6 Tier-A EXTREME gaps; falls
        # through to the generic destructive-op classifier.
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git clean -fd"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-destructive-op>")

    def test_git_push_force_blocks_via_r55(self) -> None:
        # Phase 1 Tier-A Gap 2 supersedes the legacy generic destructive-op
        # signature for force-push-to-main (more specific DENY message).
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git push origin main --force"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-force-push-main>")
        self.assertIn("NEVER-FORCE-PUSH-MAIN", out["required_rule_citations"])

    def test_make_audit_tagged_techupgrade(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "make audit WS=/Users/wolf/audits/hyperbridge"},
        })
        self.assertEqual(out["action_signature"], "Bash<make-audit-or-hunt>")
        self.assertEqual(out["required_rule_citations"], [])
        self.assertTrue(out["techupgrades"], "expected techupgrade entry")

    def test_plain_ls_is_allow_by_default(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        self.assertEqual(out["action_signature"], "Bash<other>")
        self.assertEqual(out["required_rule_citations"], [])


class TestEditWriteClassification(unittest.TestCase):
    def test_edit_draft_file_requires_l34(self) -> None:
        out = run_classifier({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/Users/wolf/audits/hyperbridge/submissions/paste_ready/foo/foo.md",
                "old_string": "x",
                "new_string": "y",
            },
        })
        self.assertEqual(out["action_signature"], "Edit<submissions-draft-file>")
        self.assertEqual(out["filepath_class"], "draft-file")
        self.assertIn("L34", out["required_rule_citations"])
        self.assertTrue(out["exception_marker_required"])

    def test_write_tools_py_requires_r36(self) -> None:
        out = run_classifier({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/Users/wolf/auditooor-mcp/tools/foo.py",
                "content": "print('hi')\n",
            },
        })
        self.assertEqual(out["action_signature"], "Write<tools-py>")
        self.assertEqual(out["filepath_class"], "tools-py")
        self.assertIn("R36", out["required_rule_citations"])

    def test_edit_submissions_md_tracker_is_allow(self) -> None:
        out = run_classifier({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/Users/wolf/audits/spark/submissions/SUBMISSIONS.md",
                "old_string": "x", "new_string": "y",
            },
        })
        self.assertEqual(out["filepath_class"], "tracker-file")
        self.assertEqual(out["required_rule_citations"], [])

    def test_edit_workspace_ledger_is_allow(self) -> None:
        out = run_classifier({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/Users/wolf/audits/spark/.auditooor/state.json",
                "old_string": "x", "new_string": "y",
            },
        })
        self.assertEqual(out["filepath_class"], "workspace-ledger")
        self.assertEqual(out["required_rule_citations"], [])

    def test_edit_lesson_anchor_is_allow(self) -> None:
        out = run_classifier({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/Users/wolf/audits/spark/submissions/_lessons-learned/lesson.md",
                "old_string": "x", "new_string": "y",
            },
        })
        self.assertEqual(out["filepath_class"], "lesson-anchor")

    def test_write_docs_is_allow_by_default(self) -> None:
        out = run_classifier({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/Users/wolf/auditooor-mcp/docs/FOO.md",
                "content": "x",
            },
        })
        self.assertEqual(out["filepath_class"], "docs")
        self.assertEqual(out["required_rule_citations"], [])

    def test_write_cwd_out_of_tree_is_allow(self) -> None:
        out = run_classifier({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/Users/wolf/Downloads/GTO_WEBSITE/foo.js",
                "content": "x",
            },
        })
        self.assertEqual(out["filepath_class"], "cwd-out-of-tree")
        self.assertEqual(out["required_rule_citations"], [])


class TestAgentClassification(unittest.TestCase):
    def test_agent_severity_decision_requires_r14(self) -> None:
        out = run_classifier({
            "tool_name": "Agent",
            "tool_input": {
                "prompt": "Lane: SEVERITY-ESCALATION for dydx finding. Decide on severity upgrade.",
            },
        })
        self.assertEqual(out["action_signature"], "Agent<severity-decision-context>")
        self.assertIn("R14", out["required_rule_citations"])

    def test_agent_drill_lane_requires_hacker_mcp(self) -> None:
        out = run_classifier({
            "tool_name": "Agent",
            "tool_input": {
                "prompt": "DRILL-7 lane for hyperbridge: hunt for novel vectors.",
            },
        })
        self.assertEqual(out["action_signature"], "Agent<drill-class-lane>")
        self.assertIn("hacker-mcp-suite", out["required_rule_citations"])

    def test_agent_audit_dispatch_no_severity_no_drill_is_allow(self) -> None:
        out = run_classifier({
            "tool_name": "Agent",
            "tool_input": {"prompt": "Lane: documentation cleanup for /audits/spark"},
        })
        # Audit-workspace touched but no severity/drill -> allow-by-default
        self.assertEqual(out["action_signature"], "Agent<audit-workspace-dispatch>")
        self.assertEqual(out["required_rule_citations"], [])

    def test_agent_non_audit_is_allow(self) -> None:
        out = run_classifier({
            "tool_name": "Agent",
            "tool_input": {"prompt": "Refactor unrelated React component"},
        })
        self.assertEqual(out["action_signature"], "Agent<non-audit-dispatch>")
        self.assertEqual(out["required_rule_citations"], [])


# r36-rebuttal: test file declared in agent_pathspec.json lane ENFORCEMENT-PHASE-1-TIER-A; registered via tools/agent-pathspec-register.py at lane start
class TestPhase1TierAExtremeGaps(unittest.TestCase):
    """Phase 1 Tier-A EXTREME-gap classification tests (6 gaps).

    Each gap is verified with the classifier alone (pattern detection).
    Override-marker / env-var behavior is verified by the sibling shell
    test harness (test_auditooor_universal_rule_enforce.sh) because the
    classifier itself does NOT consume env vars; the shell hook does.

    Spec: reports/v3_iter_2026-05-26/lane_ENFORCEMENT_AUDIT/phase1_extension_recommendations.md
    """

    # --- Gap 1: --no-verify -------------------------------------------
    def test_gap1_no_verify_classified(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git commit --no-verify -m foo"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-no-verify>")
        self.assertIn("NEVER-SKIP-HOOKS", out["required_rule_citations"])
        self.assertEqual(out["context_signals"]["extreme_gap"], "gap1-no-verify")

    def test_gap1_no_verify_on_push_also_caught(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git push --no-verify origin feat"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-no-verify>")

    # --- Gap 2: force push to main/master/HEAD ------------------------
    def test_gap2_force_push_main_classified(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git push -f origin main"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-force-push-main>")
        self.assertIn("NEVER-FORCE-PUSH-MAIN", out["required_rule_citations"])
        self.assertEqual(out["context_signals"]["extreme_gap"], "gap2-force-push-main")

    def test_gap2_force_push_master_caught(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git push --force origin master"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-force-push-main>")

    def test_gap2_force_push_feature_branch_NOT_gap2(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git push -f origin my-feature-branch"},
        })
        self.assertNotEqual(out["action_signature"], "Bash<git-force-push-main>")

    # --- Gap 3: git config WRITE --------------------------------------
    def test_gap3_git_config_global_write_classified(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git config --global user.email foo@bar.com"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-config-write>")
        self.assertIn("NEVER-GIT-CONFIG-CHANGE", out["required_rule_citations"])
        self.assertEqual(out["context_signals"]["extreme_gap"], "gap3-git-config-write")

    def test_gap3_git_config_local_unset_caught(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git config --local --unset core.editor"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-config-write>")

    def test_gap3_git_config_get_is_NOT_classified(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git config --get user.email"},
        })
        self.assertNotEqual(out["action_signature"], "Bash<git-config-write>")

    def test_gap3_git_config_list_is_NOT_classified(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git config --list"},
        })
        self.assertNotEqual(out["action_signature"], "Bash<git-config-write>")

    # --- Gap 4: gh gist delete ----------------------------------------
    def test_gap4_gist_delete_classified(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "gh gist delete abc123def"},
        })
        self.assertEqual(out["action_signature"], "Bash<gh-gist-delete>")
        self.assertIn("NEVER-DELETE-GISTS", out["required_rule_citations"])
        self.assertEqual(out["context_signals"]["extreme_gap"], "gap4-gist-delete")

    def test_gap4_gist_list_is_NOT_classified(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "gh gist list --limit 10"},
        })
        self.assertNotEqual(out["action_signature"], "Bash<gh-gist-delete>")

    # --- Gap 5: incrementNonce ----------------------------------------
    def test_gap5_incrementNonce_classified(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "cast send 0xDEAD incrementNonce()"},
        })
        self.assertEqual(out["action_signature"], "Bash<incrementNonce>")
        self.assertIn("NEVER-INCREMENTNONCE", out["required_rule_citations"])
        self.assertEqual(out["context_signals"]["extreme_gap"], "gap5-incrementNonce")

    def test_gap5_polymarket_cli_incrementNonce_caught(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "polymarket-cli send incrementNonce"},
        })
        self.assertEqual(out["action_signature"], "Bash<incrementNonce>")

    # --- Gap 6: raw git reset --hard NOT via wrapper ------------------
    def test_gap6_raw_git_reset_hard_classified(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git reset --hard HEAD~3"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-reset-hard-raw>")
        self.assertIn("R55-FOREGROUND", out["required_rule_citations"])
        self.assertEqual(out["context_signals"]["extreme_gap"], "gap6-git-reset-hard-raw")

    def test_gap6_wrapper_invocation_NOT_classified_as_raw(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "bash tools/git-hooks/git-reset-safe.sh --hard HEAD~3"},
        })
        self.assertNotEqual(out["action_signature"], "Bash<git-reset-hard-raw>")

    # --- Cross-gap ordering / specificity -----------------------------
    def test_extreme_gap_takes_precedence_over_generic_destructive_op(self) -> None:
        out = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git commit --no-verify -m fast"},
        })
        self.assertEqual(out["action_signature"], "Bash<git-no-verify>")
        out2 = run_classifier({
            "tool_name": "Bash",
            "tool_input": {"command": "git push --force origin main"},
        })
        self.assertEqual(out2["action_signature"], "Bash<git-force-push-main>")


class TestReadAndFallthrough(unittest.TestCase):
    def test_read_is_never_blocked(self) -> None:
        out = run_classifier({
            "tool_name": "Read",
            "tool_input": {"file_path": "/Users/wolf/audits/hyperbridge/submissions/paste_ready/foo/foo.md"},
        })
        self.assertEqual(out["tool_name"], "Read")
        self.assertEqual(out["required_rule_citations"], [])

    def test_unknown_tool_is_allow_by_default(self) -> None:
        out = run_classifier({
            "tool_name": "Glob",
            "tool_input": {"pattern": "**/*.md"},
        })
        self.assertIn("allow-by-default", out["action_signature"])

    def test_empty_stdin_is_handled(self) -> None:
        proc = subprocess.run(
            [sys.executable, CLASSIFIER],
            input="",
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(out["action_signature"], "<empty-payload>")

    def test_malformed_json_is_fail_open(self) -> None:
        proc = subprocess.run(
            [sys.executable, CLASSIFIER],
            input="not-json{{",
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(out["action_signature"], "<parse-error>")


if __name__ == "__main__":
    unittest.main()
