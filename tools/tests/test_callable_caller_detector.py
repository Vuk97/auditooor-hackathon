"""Unit tests for tools/callable-caller-detector.py (WF10-CALLABLE-COVERAGE-AUDIT lane).

Each test builds an ephemeral repo-like tree (Makefile + tools/) under a
tempdir, drops caller-surface fixtures + an mcp_call_log, and asserts the
detector returns the expected verdict + caller-count-by-surface.

The detector is invoked via subprocess so the test matches the runtime
exit-code contract that pre-commit-check / Make targets rely on.

Empirical anchor:
  WF-10 reported 53 of 94 MCP callables as "silent" using only an
  mcp_call_log invocation tally. The 9-surface check this detector
  applies should flip most of those 53 from "delete" to either
  "wired-not-yet-invoked" (real subprocess wiring exists) or
  "unwired-but-cited" (doc references but no real wiring).
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
TOOL = ROOT / "tools" / "callable-caller-detector.py"


def _run(args: list[str], *, root: Path | None = None) -> tuple[int, str, str]:
    """Invoke the detector with explicit --root, returning (rc, stdout, stderr)."""
    cmd = [sys.executable, str(TOOL)] + args
    if root is not None and "--root" not in args:
        cmd.extend(["--root", str(root)])
    r = subprocess.run(cmd, capture_output=True, text=True, env={
        **os.environ,
        "AUDITOOOR_CALLABLE_CALLER_SCHEDULED_TASKS_DIR":
            os.environ.get("AUDITOOOR_CALLABLE_CALLER_SCHEDULED_TASKS_DIR",
                          str(Path("/nonexistent/scheduled-tasks-for-test"))),
        "AUDITOOOR_CALLABLE_CALLER_AUDITS_DIR":
            os.environ.get("AUDITOOOR_CALLABLE_CALLER_AUDITS_DIR",
                          str(Path("/nonexistent/audits-for-test"))),
    })
    return r.returncode, r.stdout, r.stderr


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _make_repo(td: Path, *,
               makefile_terms: list[str] | None = None,
               presubmit_terms: list[str] | None = None,
               engage_terms: list[str] | None = None,
               agent_brief_terms: list[str] | None = None,
               docs_terms: list[str] | None = None,
               tools_py_terms: list[str] | None = None,
               server_registered: list[str] | None = None,
               call_log_entries: list[str] | None = None,
               ) -> Path:
    """Build an ephemeral repo at ``td`` with the requested per-surface terms.

    Returns the repo root path.
    """
    (td / "tools").mkdir(parents=True, exist_ok=True)
    (td / "tools" / "tests").mkdir(parents=True, exist_ok=True)
    (td / "docs").mkdir(parents=True, exist_ok=True)
    (td / "agent_briefs").mkdir(parents=True, exist_ok=True)
    (td / ".auditooor").mkdir(parents=True, exist_ok=True)

    # Always create a baseline Makefile (without target callable refs).
    base_make = "# test makefile\nhello:\n\t@echo hi\n"
    if makefile_terms:
        for t in makefile_terms:
            base_make += f"\nhelper-{abs(hash(t))%1000}:\n\tpython3 tools/vault-mcp-server.py --call {t}\n"
    _write(td / "Makefile", base_make)

    # Always create vault-mcp-server.py - it's needed for the registry surface.
    server_lines = [
        "#!/usr/bin/env python3",
        '"""mock vault server for tests."""',
        "TOOL_SCHEMAS = [",
    ]
    for name in (server_registered or []):
        server_lines.append(f'    {{"name": "{name}", "description": "mock"}},')
    server_lines.append("]")
    server_lines.append("def main(): pass")
    _write(td / "tools" / "vault-mcp-server.py", "\n".join(server_lines) + "\n")

    if presubmit_terms:
        body = "#!/bin/bash\n"
        for t in presubmit_terms:
            body += f'python3 tools/vault-mcp-server.py --call {t} --args "{{}}"\n'
        _write(td / "tools" / "pre-submit-check.sh", body)

    if engage_terms:
        body = '#!/usr/bin/env python3\nimport subprocess\n'
        for t in engage_terms:
            body += f'subprocess.run(["python3", "tools/vault-mcp-server.py", "--call", "{t}"])\n'
        _write(td / "tools" / "engage.py", body)

    if agent_brief_terms:
        for i, t in enumerate(agent_brief_terms):
            _write(td / "agent_briefs" / f"brief_{i}.md",
                   f"## Agent brief\nInvoke `python3 tools/vault-mcp-server.py --call {t}` here.\n")

    if docs_terms:
        for i, t in enumerate(docs_terms):
            _write(td / "docs" / f"doc_{i}.md",
                   f"# Doc\nThe `{t}` callable does X.\n")

    if tools_py_terms:
        for i, t in enumerate(tools_py_terms):
            _write(td / "tools" / f"caller_{i}.py",
                   f'import subprocess\nsubprocess.run(["python3", "tools/vault-mcp-server.py", "--call", "{t}"])\n')

    # Create mcp_call_log.jsonl with the given invocations.
    log_lines = []
    for name in (call_log_entries or []):
        log_lines.append(json.dumps({"callable": name, "ts": "2026-05-23T00:00:00Z"}))
    _write(td / ".auditooor" / "mcp_call_log.jsonl",
           "\n".join(log_lines) + ("\n" if log_lines else ""))

    return td


class CallableCallerDetectorTests(unittest.TestCase):
    """Test the WF10-callable-coverage-audit detector across 9+1 surfaces."""

    def test_01_live_frequent_threshold(self):
        """>=10 invocations -> live-frequent verdict, exit 0."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_resume_context"],
                              call_log_entries=["vault_resume_context"] * 15)
            rc, out, err = _run(["vault_resume_context", "--json"], root=root)
            self.assertEqual(rc, 0, msg=err)
            data = json.loads(out)
            self.assertEqual(data["verdict"], "live-frequent")
            self.assertEqual(data["invocation_count"], 15)

    def test_02_live_low_volume_range(self):
        """1-9 invocations -> live-low-volume verdict, exit 0."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_corpus_mining_state"],
                              call_log_entries=["vault_corpus_mining_state"] * 3)
            rc, out, err = _run(["vault_corpus_mining_state", "--json"], root=root)
            self.assertEqual(rc, 0, msg=err)
            data = json.loads(out)
            self.assertEqual(data["verdict"], "live-low-volume")
            self.assertEqual(data["invocation_count"], 3)

    def test_03_wired_not_yet_invoked_subprocess(self):
        """0 invocations + subprocess wire -> wired-not-yet-invoked, exit 0."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_zk_template_lookup"],
                              tools_py_terms=["vault_zk_template_lookup"],
                              call_log_entries=[])
            rc, out, err = _run(["vault_zk_template_lookup", "--json"], root=root)
            self.assertEqual(rc, 0, msg=err)
            data = json.loads(out)
            self.assertEqual(data["verdict"], "wired-not-yet-invoked")
            self.assertEqual(data["invocation_count"], 0)
            self.assertGreater(data["surface_count"], 0)

    def test_04_wired_not_yet_invoked_makefile(self):
        """0 invocations + Makefile wire -> wired-not-yet-invoked, exit 0."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_attack_class_taxonomy"],
                              makefile_terms=["vault_attack_class_taxonomy"],
                              call_log_entries=[])
            rc, out, err = _run(["vault_attack_class_taxonomy", "--json"], root=root)
            self.assertEqual(rc, 0, msg=err)
            data = json.loads(out)
            self.assertEqual(data["verdict"], "wired-not-yet-invoked")
            self.assertIn("makefile", data["surfaces_wired_in"])

    def test_05_unwired_but_cited_docs_only(self):
        """0 invocations + docs ref only -> unwired-but-cited, exit 1."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_fp_precision_report"],
                              docs_terms=["vault_fp_precision_report"],
                              call_log_entries=[])
            rc, out, err = _run(["vault_fp_precision_report", "--json"], root=root)
            self.assertEqual(rc, 1, msg=err)
            data = json.loads(out)
            self.assertEqual(data["verdict"], "unwired-but-cited")
            self.assertEqual(data["surface_count"], 0)
            self.assertIn("docs_md", data["surfaces_wired_in"])

    def test_06_dead_no_caller(self):
        """0 invocations + 0 surface refs -> dead-no-caller, exit 1.

        Even a callable registered in the server with no wiring anywhere
        is dead because the registry self-ref is not counted as wiring.
        """
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_ghost_callable"],
                              call_log_entries=[])
            rc, out, err = _run(["vault_ghost_callable", "--json"], root=root)
            self.assertEqual(rc, 1, msg=err)
            data = json.loads(out)
            self.assertEqual(data["verdict"], "dead-no-caller")
            self.assertEqual(data["surface_count"], 0)

    def test_07_json_output_shape(self):
        """JSON output contains all required schema fields."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_resume_context"],
                              tools_py_terms=["vault_resume_context"],
                              call_log_entries=["vault_resume_context"] * 5)
            rc, out, err = _run(["vault_resume_context", "--json"], root=root)
            self.assertEqual(rc, 0, msg=err)
            data = json.loads(out)
            for key in ("schema", "callable", "verdict", "invocation_count",
                        "surfaces_wired_in", "surface_count", "callers",
                        "caller_count_by_surface", "scope", "root",
                        "surfaces_searched", "registered_in_server",
                        "timestamp_utc"):
                self.assertIn(key, data, f"missing key: {key}")
            self.assertEqual(data["schema"], "auditooor.callable_caller_detector.v1")
            self.assertEqual(data["callable"], "vault_resume_context")

    def test_08_normalize_callable_name(self):
        """Accepts both `resume_context` and `vault_resume_context`."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_resume_context"],
                              call_log_entries=["vault_resume_context"] * 12)
            # Without `vault_` prefix.
            rc, out, _ = _run(["resume_context", "--json"], root=root)
            self.assertEqual(rc, 0)
            data = json.loads(out)
            self.assertEqual(data["callable"], "vault_resume_context")

    def test_09_boundary_check_no_partial_match(self):
        """`vault_X` should NOT match `vault_X_v2`."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_X_v2"],
                              tools_py_terms=["vault_X_v2"],
                              call_log_entries=[])
            # Now probe for `vault_X` (NOT `vault_X_v2`).
            rc, out, _ = _run(["vault_X", "--json"], root=root)
            data = json.loads(out)
            # No wires + no invocations + no docs = dead-no-caller.
            self.assertEqual(data["verdict"], "dead-no-caller")
            self.assertEqual(data["surface_count"], 0)

    def test_10_all_flag_emits_each_callable_once(self):
        """--all enumerates every TOOL_SCHEMAS name without duplicates."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=[
                                  "vault_a", "vault_b", "vault_c",
                              ],
                              call_log_entries=[])
            rc, out, err = _run(["--all", "--ndjson"], root=root)
            lines = [l for l in out.splitlines() if l.strip()]
            self.assertEqual(len(lines), 3, msg=f"out={out!r} err={err!r}")
            names = sorted(json.loads(l)["callable"] for l in lines)
            self.assertEqual(names, ["vault_a", "vault_b", "vault_c"])

    def test_11_batch_mode(self):
        """--batch reads one callable per line, emits one record per line."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_x", "vault_y"],
                              call_log_entries=["vault_x"] * 11)
            batch = Path(td) / "callables.txt"
            batch.write_text("vault_x\nvault_y\n# a comment\n\n")
            rc, out, err = _run(["--batch", str(batch), "--ndjson"], root=root)
            lines = [l for l in out.splitlines() if l.strip()]
            self.assertEqual(len(lines), 2, msg=f"out={out!r} err={err!r}")
            verdicts = sorted(json.loads(l)["verdict"] for l in lines)
            self.assertEqual(verdicts, ["dead-no-caller", "live-frequent"])

    def test_12_env_hook_call_log_override(self):
        """AUDITOOOR_CALLABLE_CALLER_CALL_LOG env hook resolves correctly."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_x"],
                              call_log_entries=[])
            # Custom call log with 7 invocations of vault_x.
            custom_log = Path(td) / "custom_log.jsonl"
            custom_log.write_text(
                "\n".join(json.dumps({"callable": "vault_x"}) for _ in range(7)) + "\n"
            )
            env = os.environ.copy()
            env["AUDITOOOR_CALLABLE_CALLER_CALL_LOG"] = str(custom_log)
            env["AUDITOOOR_CALLABLE_CALLER_SCHEDULED_TASKS_DIR"] = "/nonexistent"
            env["AUDITOOOR_CALLABLE_CALLER_AUDITS_DIR"] = "/nonexistent"
            r = subprocess.run(
                [sys.executable, str(TOOL), "vault_x", "--root", str(root), "--json"],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(r.returncode, 0, msg=r.stderr)
            data = json.loads(r.stdout)
            self.assertEqual(data["verdict"], "live-low-volume")
            self.assertEqual(data["invocation_count"], 7)

    def test_13_registry_self_ref_not_counted_as_wiring(self):
        """A callable in TOOL_SCHEMAS but nowhere else has surface_count=0."""
        with tempfile.TemporaryDirectory() as td:
            root = _make_repo(Path(td),
                              server_registered=["vault_phantom"],
                              call_log_entries=[])
            rc, out, _ = _run(["vault_phantom", "--json"], root=root)
            data = json.loads(out)
            # Registry surface counts a hit but doesn't push surface_count.
            self.assertIn("registry_self_ref", data["surfaces_wired_in"])
            self.assertEqual(data["surface_count"], 0)
            self.assertEqual(data["verdict"], "dead-no-caller")
            self.assertTrue(data["registered_in_server"])

    def test_14_live_dogfood_against_canonical_server(self):
        """Smoke test: vault_resume_context against real /Users/wolf/auditooor-mcp.

        This is the live dogfood that proves the detector reports the
        canonical live callable as live (>=10 invocations on the canonical
        call log).
        """
        canonical = Path("/Users/wolf/auditooor-mcp")
        if not (canonical / "tools" / "vault-mcp-server.py").is_file():
            self.skipTest("canonical worktree not present on this host")
        log = canonical / ".auditooor" / "mcp_call_log.jsonl"
        if not log.is_file():
            self.skipTest("canonical call log not present on this host")
        env = os.environ.copy()
        env["AUDITOOOR_CALLABLE_CALLER_CALL_LOG"] = str(log)
        env["AUDITOOOR_CALLABLE_CALLER_SCHEDULED_TASKS_DIR"] = \
            str(Path.home() / ".claude" / "scheduled-tasks")
        r = subprocess.run(
            [sys.executable, str(TOOL),
             "vault_resume_context",
             "--root", str(canonical),
             "--json"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["verdict"], "live-frequent")
        self.assertGreaterEqual(data["invocation_count"], 10)


if __name__ == "__main__":
    unittest.main()
