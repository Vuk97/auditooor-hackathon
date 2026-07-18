"""
test_spawn_worker_marker_injection.py
--------------------------------------
Regression tests for the auto-injection of hacker-mcp-rebuttal / r64-rebuttal /
r57-rebuttal HTML-comment markers at the top of the spawn-worker.sh enriched brief.

Spec (Step 3.6 in spawn-worker.sh):
  - tool-build lane-type    : markers MUST be present at top of enriched brief
  - corpus lane-type        : markers MUST be present at top
  - docs lane-type          : markers MUST be present at top
  - cleanup lane-type       : markers MUST be present at top
  - infra lane-type         : markers MUST be present at top
  - hunt lane-type          : markers MUST NOT be auto-injected
  - drill lane-type         : markers MUST NOT be auto-injected
  - dispute lane-type       : markers MUST NOT be auto-injected
  - mediation lane-type     : markers MUST NOT be auto-injected
  - triager-response        : markers MUST NOT be auto-injected
  - rebuttal lane-type      : markers MUST NOT be auto-injected
  - filing lane-type        : markers MUST NOT be auto-injected
  - --no-auto-markers flag  : markers MUST NOT be injected even for tool-build

Rebuttal markers injected (exact text assertions):
  <!-- hacker-mcp-rebuttal: <lane-type> lane (auto-injected by spawn-worker.sh) -->
  <!-- r64-rebuttal: claims verified by spawn-worker.sh enrichment + R36 pathspec registration -->
  <!-- r57-rebuttal: tool-build lane, not a finding draft -->
"""

import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
SPAWN_WORKER = os.path.join(REPO_ROOT, "tools", "spawn-worker.sh")
# Use a workspace path that exists on this machine (auditooor-mcp itself)
WORKSPACE = REPO_ROOT


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _write_prompt(content: str) -> str:
    """Write prompt content to a tempfile, return its path."""
    fd, path = tempfile.mkstemp(suffix=".md", prefix="sw_test_prompt_")
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


def _run_spawn_worker(lane_id: str, lane_type: str, extra_args=None,
                      prompt_content: str = "# test prompt\n\nsome content\n"):
    """
    Run spawn-worker.sh with --no-prebriefing (avoids needing MCP live) and
    --no-register (avoids needing the pathspec tool to be installed).
    Returns (rc, stdout, stderr, enriched_file_path).
    enriched_file_path is None when the call fails before writing the file.
    """
    prompt_path = _write_prompt(prompt_content)
    cmd = [
        "bash", SPAWN_WORKER,
        "--lane-id", lane_id,
        "--lane-type", lane_type,
        "--severity", "LOW",
        "--workspace", WORKSPACE,
        "--prompt-file", prompt_path,
        "--no-prebriefing",
        "--no-register",
        "--no-inject-prior-lanes",
        # Disable per-lane worktree for hunt/drill/comp: those lane types
        # auto-enable worktree provisioning which blocks in test environments.
        "--no-use-worktree",
    ]
    if extra_args:
        cmd.extend(extra_args)

    env = os.environ.copy()
    env["SPAWN_WORKER_BYPASS_REASON"] = "unit-test-no-prebriefing"
    # Redirect log to /tmp so we don't dirty the real audit log.
    env["SPAWN_WORKER_LOG_PATH"] = os.path.join(
        tempfile.gettempdir(), f"sw_test_{lane_id}.jsonl"
    )
    # Disable Gap #29 so test infra issues don't block non-hunt lanes.
    env["SPAWN_WORKER_GAP29_DISABLE"] = "1"

    result = subprocess.run(
        cmd, capture_output=True, text=True, env=env, timeout=30
    )
    enriched_path = result.stdout.strip()
    os.unlink(prompt_path)
    return result.returncode, result.stdout, result.stderr, enriched_path


def _read_enriched(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    with open(path) as fh:
        return fh.read()


EXPECTED_MARKERS = [
    "<!-- hacker-mcp-rebuttal:",
    "<!-- r64-rebuttal: claims verified by spawn-worker.sh enrichment + R36 pathspec registration -->",
    "<!-- r57-rebuttal: tool-build lane, not a finding draft -->",
]


def _has_markers_at_top(text: str) -> bool:
    """All 3 expected marker prefixes must appear in the FIRST 10 lines."""
    first_lines = "\n".join(text.splitlines()[:10])
    return all(m.split(":", 1)[0] + ":" in first_lines for m in EXPECTED_MARKERS)


def _has_any_marker(text: str) -> bool:
    return any(m.split(":", 1)[0] + ":" in text for m in EXPECTED_MARKERS)


# ---------------------------------------------------------------------------
# test cases
# ---------------------------------------------------------------------------

class TestSpawnWorkerMarkerInjection(unittest.TestCase):

    # -- inject lanes --------------------------------------------------------

    def test_tool_build_injects_markers(self):
        """tool-build lane-type must have markers at top of enriched brief."""
        rc, out, err, ep = _run_spawn_worker("test-tb-228", "tool-build")
        self.assertEqual(rc, 0, f"spawn-worker.sh failed rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertTrue(content, f"enriched file empty or missing at: {ep}")
        self.assertTrue(_has_markers_at_top(content),
                        f"markers missing from top of tool-build enriched brief.\nFirst 15 lines:\n"
                        + "\n".join(content.splitlines()[:15]))
        # Verify the lane-type string appears in the hacker-mcp-rebuttal line.
        self.assertIn("tool-build lane (auto-injected by spawn-worker.sh)", content)
        # auto_markers_status in stderr
        self.assertIn("auto_markers=injected:tool-build", err)

    def test_corpus_injects_markers(self):
        """corpus lane-type must have markers at top of enriched brief."""
        rc, out, err, ep = _run_spawn_worker("test-corpus-228", "corpus")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertTrue(_has_markers_at_top(content),
                        "markers missing from corpus enriched brief")
        self.assertIn("corpus lane (auto-injected by spawn-worker.sh)", content)

    def test_docs_injects_markers(self):
        """docs lane-type must have markers at top of enriched brief."""
        rc, out, err, ep = _run_spawn_worker("test-docs-228", "docs")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertTrue(_has_markers_at_top(content),
                        "markers missing from docs enriched brief")

    def test_cleanup_injects_markers(self):
        """cleanup lane-type must have markers at top of enriched brief."""
        rc, out, err, ep = _run_spawn_worker("test-cleanup-228", "cleanup")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertTrue(_has_markers_at_top(content),
                        "markers missing from cleanup enriched brief")

    def test_infra_injects_markers(self):
        """infra lane-type must have markers at top of enriched brief."""
        rc, out, err, ep = _run_spawn_worker("test-infra-228", "infra")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertTrue(_has_markers_at_top(content),
                        "markers missing from infra enriched brief")

    # -- skip lanes ----------------------------------------------------------

    def test_hunt_does_not_inject_markers(self):
        """hunt lane-type must NOT have auto-injected markers."""
        rc, out, err, ep = _run_spawn_worker("test-hunt-228", "hunt")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        # Markers should NOT appear unless they were already in the prompt body.
        self.assertFalse(_has_any_marker(content),
                         f"auto-inject markers unexpectedly present in hunt brief.\n"
                         f"First 15 lines:\n" + "\n".join(content.splitlines()[:15]))
        self.assertIn("auto_markers=skipped-hunt-class-lane", err)

    def test_drill_does_not_inject_markers(self):
        """drill lane-type must NOT have auto-injected markers."""
        rc, out, err, ep = _run_spawn_worker("test-drill-228", "drill")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertFalse(_has_any_marker(content),
                         "auto-inject markers unexpectedly present in drill brief")

    def test_dispute_does_not_inject_markers(self):
        """dispute lane-type must NOT have auto-injected markers."""
        rc, out, err, ep = _run_spawn_worker("test-dispute-228", "dispute")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertFalse(_has_any_marker(content),
                         "auto-inject markers unexpectedly present in dispute brief")

    def test_mediation_does_not_inject_markers(self):
        """mediation lane-type must NOT have auto-injected markers."""
        rc, out, err, ep = _run_spawn_worker("test-mediation-228", "mediation")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertFalse(_has_any_marker(content),
                         "auto-inject markers unexpectedly present in mediation brief")

    def test_triager_response_does_not_inject_markers(self):
        """triager-response lane-type must NOT have auto-injected markers."""
        rc, out, err, ep = _run_spawn_worker("test-tr-228", "triager-response")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertFalse(_has_any_marker(content),
                         "auto-inject markers unexpectedly present in triager-response brief")

    def test_rebuttal_does_not_inject_markers(self):
        """rebuttal lane-type must NOT have auto-injected markers."""
        rc, out, err, ep = _run_spawn_worker("test-rebuttal-228", "rebuttal")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertFalse(_has_any_marker(content),
                         "auto-inject markers unexpectedly present in rebuttal brief")

    def test_filing_does_not_inject_markers(self):
        """filing lane-type must NOT have auto-injected markers."""
        rc, out, err, ep = _run_spawn_worker("test-filing-228", "filing")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertFalse(_has_any_marker(content),
                         "auto-inject markers unexpectedly present in filing brief")

    # -- --no-auto-markers flag ----------------------------------------------

    def test_no_auto_markers_flag_disables_injection_for_tool_build(self):
        """--no-auto-markers disables injection even for tool-build."""
        rc, out, err, ep = _run_spawn_worker(
            "test-tb-noflags-228", "tool-build",
            extra_args=["--no-auto-markers"]
        )
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertFalse(_has_any_marker(content),
                         "--no-auto-markers should prevent injection even for tool-build")
        self.assertIn("auto_markers=disabled-by-flag", err)

    def test_no_auto_markers_flag_for_corpus(self):
        """--no-auto-markers disables injection for corpus lane too."""
        rc, out, err, ep = _run_spawn_worker(
            "test-corpus-noflags-228", "corpus",
            extra_args=["--no-auto-markers"]
        )
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertFalse(_has_any_marker(content),
                         "--no-auto-markers should prevent injection for corpus")

    # -- content preservation ------------------------------------------------

    def test_prompt_content_preserved_after_injection(self):
        """Original prompt content must still be present after marker injection."""
        sentinel = "SENTINEL_CONTENT_MUST_SURVIVE_INJECTION_XYZ123"
        rc, out, err, ep = _run_spawn_worker(
            "test-tb-preserve-228", "tool-build",
            prompt_content=f"# test\n\n{sentinel}\n"
        )
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        self.assertIn(sentinel, content, "prompt content was lost after marker injection")
        self.assertTrue(_has_markers_at_top(content),
                        "markers not at top after injection")

    def test_markers_appear_before_original_content(self):
        """Markers must precede original prompt content (top-of-file)."""
        sentinel = "SENTINEL_AFTER_MARKERS_789"
        rc, out, err, ep = _run_spawn_worker(
            "test-tb-order-228", "tool-build",
            prompt_content=f"# test\n\n{sentinel}\n"
        )
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read_enriched(ep)
        marker_pos = content.find("<!-- hacker-mcp-rebuttal:")
        sentinel_pos = content.find(sentinel)
        self.assertGreater(sentinel_pos, marker_pos,
                           "markers must appear before original prompt content")

    # -- log field -----------------------------------------------------------

    def test_log_row_contains_auto_markers_status(self):
        """spawn_worker_log.jsonl row must include auto_markers_status field."""
        import json
        log_path = os.path.join(
            tempfile.gettempdir(), "sw_test_log_field_228.jsonl"
        )
        prompt_path = _write_prompt("# log field test\n")
        cmd = [
            "bash", SPAWN_WORKER,
            "--lane-id", "test-log-field-228",
            "--lane-type", "tool-build",
            "--severity", "LOW",
            "--workspace", WORKSPACE,
            "--prompt-file", prompt_path,
            "--no-prebriefing",
            "--no-register",
            "--no-inject-prior-lanes",
        ]
        env = os.environ.copy()
        env["SPAWN_WORKER_BYPASS_REASON"] = "unit-test"
        env["SPAWN_WORKER_LOG_PATH"] = log_path
        env["SPAWN_WORKER_GAP29_DISABLE"] = "1"
        subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
        os.unlink(prompt_path)
        self.assertTrue(os.path.isfile(log_path), f"log file not created at {log_path}")
        with open(log_path) as fh:
            row = json.loads(fh.readline())
        self.assertIn("auto_markers_status", row,
                      f"auto_markers_status field missing from log row: {row}")
        self.assertTrue(row["auto_markers_status"].startswith("injected"),
                        f"expected injected:tool-build, got: {row['auto_markers_status']}")
        self.assertIn("no_auto_markers_flag", row)
        self.assertEqual(row["no_auto_markers_flag"], 0)
        os.unlink(log_path)


if __name__ == "__main__":
    unittest.main()
