"""Gap #76 tests: Codex CLI wrapper pre-write + pre-subagent-spawn gates.

Gap #76 (2026-05-26) extends `auditooor-codex-wrapper.sh` with two new gates
on top of the existing Gap #72 pre-submit-check chain:

1. Pre-write gate (L34 v2 path classifier) for `apply` against draft files.
   Refuses when target classifies as `draft-file` without per-draft op-auth.
   Bypass: CODEX_NO_PREWRITE_CHECK=1, L34_DRAFT_AUTHORIZED=<slug>, or in-draft
   `<!-- l34-rebuttal: ... -->` marker.

2. Pre-subagent-spawn gate (R64 prompt-claim verifier) on exec/e/review/
   resume/fork/cloud subcommands. Codex spawning a sub-agent with a prompt
   is the equivalent of Claude Code's Agent/Task dispatch. R64 verifies every
   factual claim against the canonical-inventory snapshot.
   Bypass: CODEX_NO_SUBAGENT_CHECK=1, AUDITOOOR_R64_REBUTTAL=<reason>, or
   in-prompt `<!-- r64-rebuttal: ... -->` marker.

Tests use:
 - A fake `codex` binary (`AUDITOOOR_REAL_CODEX=...`) so we can assert
   whether the wrapper exec'd through or rejected.
 - A fresh `.auditooor/last_mcp_recall.json` sentinel so the Wave-6 E-2
   freshness gate passes (we are not testing freshness here).
 - A valid MCP session token so the existing token gate passes (we are
   not testing the token gate here either).
 - `CODEX_NO_PREWRITE_CHECK` / `CODEX_NO_SUBAGENT_CHECK` env vars only when
   the test specifically targets the bypass codepath.
 - `AUDITOOOR_NO_PRESUBMIT_CHECK=1` to short-circuit the unrelated Gap #72
   chain (we cover that separately).
"""
# r36-rebuttal: lane-GAP-76-CODEX-PARITY pathspec registered via tools/agent-pathspec-register.py
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
CODEX_WRAPPER = REPO / "tools" / "auditooor-codex-wrapper.sh"
TOKEN_TOOL = REPO / "tools" / "auditooor_mcp_token.py"
L34_TOOL = REPO / "tools" / "l34-path-classifier.py"
R64_TOOL = REPO / "tools" / "r64-prompt-claim-verifier.py"


def _issue_token(workspace, scope="write", ttl=14400):
    proc = subprocess.run(
        ["python3", str(TOKEN_TOOL), "issue",
         "--workspace", workspace, "--scope", scope, "--ttl", str(ttl), "--no-log"],
        capture_output=True, text=True,
        env={**os.environ, "AUDITOOOR_MCP_SECRET": "test-shim-secret-32-bytes-content"},
    )
    return proc.stdout.strip()


def _write_fresh_recall(workspace: str) -> None:
    sentinel_dir = pathlib.Path(workspace) / ".auditooor"
    sentinel_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "context_pack_id": "test.pack.v1:gap76:compat",
        "context_pack_hash": "gap76_compat_hash",
        "workspace_path": workspace,
        "recall_ts": time.time(),
        "recall_iso": "2026-05-26T12:00:00Z",
        "owner_tool": "TEST_GAP76",
    }
    (sentinel_dir / "last_mcp_recall.json").write_text(json.dumps(data, indent=2))


def _make_fake_codex(tmp_dir):
    """Fake codex that records its args and exits 0."""
    fake = pathlib.Path(tmp_dir) / "fake-codex"
    marker = pathlib.Path(tmp_dir) / "fake-codex-called"
    fake.write_text(f'''#!/usr/bin/env bash
echo "FAKE-CODEX: $@" > "{marker}"
echo "fake codex called with: $@"
exit 0
''')
    fake.chmod(0o755)
    return str(fake), marker


class _Gap76TestBase(unittest.TestCase):
    """Shared setUp: workspace + fake codex + token + fresh recall + Gap #72 bypass."""

    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = "test-shim-secret-32-bytes-content"
        self.tmp = tempfile.mkdtemp(prefix="gap76-")
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)
        self.fake_bin, self.marker = _make_fake_codex(self.tmp)
        _write_fresh_recall(self.tmp)
        self.token = _issue_token(self.tmp, scope="write")
        self.env = {
            **os.environ,
            "AUDITOOOR_MCP_SECRET": "test-shim-secret-32-bytes-content",
            "AUDITOOOR_REAL_CODEX": self.fake_bin,
            "AUDITOOOR_WORKSPACE": str(pathlib.Path(self.tmp).resolve()),
            "AUDITOOOR_WS_ROOT": str(pathlib.Path(self.tmp).resolve()),
            "AUDITOOOR_MCP_SESSION_TOKEN": self.token,
            "AUDITOOOR_MCP_REQUIRED": "1",
            # Gap #72 is tested separately; bypass here so its log path is
            # not entangled with the Gap #76 gates we exercise.
            "AUDITOOOR_NO_PRESUBMIT_CHECK": "1",
            # Wave-6 E-2 freshness is tested separately.
            "AUDITOOOR_NO_FINALIZATION_CHECK": "1",
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_draft(self, slug, status="staging", content=None):
        """Create submissions/<status>/<slug>/<slug>.md."""
        ws = pathlib.Path(self.tmp)
        folder = ws / "submissions" / status / slug
        folder.mkdir(parents=True, exist_ok=True)
        draft = folder / f"{slug}.md"
        body = content if content is not None else f"# {slug}\n\nDraft body for {slug}.\n"
        draft.write_text(body)
        return draft


class TestBashSyntax(unittest.TestCase):
    def test_wrapper_bash_syntax(self):
        proc = subprocess.run(
            ["bash", "-n", str(CODEX_WRAPPER)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, f"bash -n failed:\n{proc.stderr}")


class TestPreWriteGate(_Gap76TestBase):
    """Gap #76 pre-write gate (L34 v2): apply against draft files."""

    def test_apply_to_draft_file_without_auth_refused(self):
        draft = self._make_draft("test-finding-MEDIUM", status="staging")
        rel = draft.relative_to(self.tmp)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "apply", str(rel)],
            capture_output=True, text=True, env=self.env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1,
                         f"expected reject; stdout={proc.stdout} stderr={proc.stderr}")
        self.assertIn("REJECTED (Gap #76 / L34)", proc.stderr)
        self.assertFalse(self.marker.is_file(),
                         "fake codex should NOT have been called when refused")
        # Log written
        log = pathlib.Path(self.tmp) / ".auditooor" / "codex_prewrite_gate.jsonl"
        self.assertTrue(log.is_file(), "Gap #76 pre-write gate log should exist")
        line = log.read_text().strip().splitlines()[-1]
        rec = json.loads(line)
        self.assertEqual(rec["verdict"], "fail-l34-draft-without-auth")
        self.assertEqual(rec["bucket"], "draft-file")

    def test_apply_to_draft_with_l34_rebuttal_marker_allowed(self):
        draft = self._make_draft(
            "rebuttal-finding-MEDIUM",
            content="# rebuttal-finding\n\n<!-- l34-rebuttal: operator-approved-edit -->\n\nbody\n",
        )
        rel = draft.relative_to(self.tmp)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "apply", str(rel)],
            capture_output=True, text=True, env=self.env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"expected pass with l34-rebuttal; stderr={proc.stderr}")
        self.assertIn("l34-rebuttal marker", proc.stderr)
        self.assertTrue(self.marker.is_file(), "fake codex SHOULD have been called")

    def test_apply_to_draft_with_l34_draft_authorized_env_allowed(self):
        slug = "auth-finding-HIGH"
        draft = self._make_draft(slug)
        rel = draft.relative_to(self.tmp)
        env = {**self.env, "L34_DRAFT_AUTHORIZED": slug}
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "apply", str(rel)],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"expected pass with L34_DRAFT_AUTHORIZED; stderr={proc.stderr}")
        self.assertIn("L34_DRAFT_AUTHORIZED", proc.stderr)
        self.assertTrue(self.marker.is_file())

    def test_apply_to_tracker_file_auto_executable(self):
        ws = pathlib.Path(self.tmp)
        tracker = ws / "submissions" / "SUBMISSIONS.md"
        tracker.parent.mkdir(parents=True, exist_ok=True)
        tracker.write_text("# Submissions\n\n| id | title | status |\n|---|---|---|\n")
        rel = tracker.relative_to(self.tmp)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "apply", str(rel)],
            capture_output=True, text=True, env=self.env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"tracker-file should auto-pass; stderr={proc.stderr}")
        self.assertTrue(self.marker.is_file())
        # Log shows pass-auto-executable
        log = pathlib.Path(self.tmp) / ".auditooor" / "codex_prewrite_gate.jsonl"
        if log.is_file():
            lines = [json.loads(ln) for ln in log.read_text().strip().splitlines() if ln]
            self.assertTrue(any(r.get("verdict") == "pass-auto-executable" for r in lines),
                            f"expected pass-auto-executable record, got: {lines}")

    def test_apply_to_draft_with_bypass_env_allowed_and_logged(self):
        draft = self._make_draft("bypass-finding-MEDIUM")
        rel = draft.relative_to(self.tmp)
        env = {**self.env, "CODEX_NO_PREWRITE_CHECK": "1"}
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "apply", str(rel)],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"expected pass with bypass; stderr={proc.stderr}")
        self.assertIn("Gap #76 BYPASS (pre-write)", proc.stderr)
        self.assertTrue(self.marker.is_file())
        log = pathlib.Path(self.tmp) / ".auditooor" / "codex_prewrite_gate.jsonl"
        self.assertTrue(log.is_file())
        rec = json.loads(log.read_text().strip().splitlines()[-1])
        self.assertEqual(rec["verdict"], "bypass-env")
        self.assertEqual(rec["reason"], "CODEX_NO_PREWRITE_CHECK=1")


class TestPreSubagentSpawnGate(_Gap76TestBase):
    """Gap #76 pre-subagent-spawn gate (R64): exec/review/resume/fork/cloud."""

    def test_exec_with_unverified_tool_path_refused(self):
        env = {**self.env, "CODEX_NO_PREWRITE_CHECK": "1"}  # focus this test
        # Inline prompt cites a fabricated tool path that R64 should fail.
        prompt = "Run tools/this-tool-does-not-exist-anywhere.py to drive analysis."
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "exec", prompt],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1,
                         f"expected reject; stdout={proc.stdout} stderr={proc.stderr}")
        self.assertIn("REJECTED (Gap #76 / R64)", proc.stderr)
        self.assertFalse(self.marker.is_file(),
                         "fake codex should NOT have been called when refused")
        log = pathlib.Path(self.tmp) / ".auditooor" / "codex_subagent_spawn_gate.jsonl"
        self.assertTrue(log.is_file())
        rec = json.loads(log.read_text().strip().splitlines()[-1])
        self.assertEqual(rec["verdict"], "fail-codex-subagent-unverified-claim")

    def test_exec_with_verified_prompt_passes(self):
        # Prompt with no fabricated claims; uses only a known MCP callable name.
        prompt = "Investigate using vault_resume_context for memory grounding."
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "exec", prompt],
            capture_output=True, text=True, env=self.env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"expected pass; stderr={proc.stderr}")
        self.assertTrue(self.marker.is_file(),
                        "fake codex SHOULD have been called")

    def test_exec_with_r64_rebuttal_marker_in_prompt_allowed(self):
        prompt = (
            "<!-- r64-rebuttal: operator-pre-verified -->\n"
            "Use tools/some-fake-tool.py for the lane."
        )
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "exec", prompt],
            capture_output=True, text=True, env=self.env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"expected pass with marker; stderr={proc.stderr}")
        self.assertIn("r64-rebuttal marker in prompt", proc.stderr)
        self.assertTrue(self.marker.is_file())

    def test_exec_with_auditooor_r64_rebuttal_env_allowed(self):
        prompt = "Use tools/another-fake-tool.py to drive."
        env = {**self.env, "AUDITOOOR_R64_REBUTTAL": "test-suite-fixture"}
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "exec", prompt],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"expected pass with env rebuttal; stderr={proc.stderr}")
        self.assertIn("AUDITOOOR_R64_REBUTTAL set", proc.stderr)
        self.assertTrue(self.marker.is_file())

    def test_subagent_with_bypass_env_allowed_and_logged(self):
        prompt = "Use tools/some-fake-tool.py for the lane."
        env = {**self.env, "CODEX_NO_SUBAGENT_CHECK": "1"}
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "exec", prompt],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"expected pass with bypass; stderr={proc.stderr}")
        self.assertIn("Gap #76 BYPASS (pre-subagent-spawn)", proc.stderr)
        self.assertTrue(self.marker.is_file())
        log = pathlib.Path(self.tmp) / ".auditooor" / "codex_subagent_spawn_gate.jsonl"
        self.assertTrue(log.is_file())
        rec = json.loads(log.read_text().strip().splitlines()[-1])
        self.assertEqual(rec["verdict"], "bypass-env")
        self.assertEqual(rec["reason"], "CODEX_NO_SUBAGENT_CHECK=1")

    def test_resume_with_unverified_prompt_refused(self):
        # `codex resume` is also a sub-agent-spawn surface; same gate applies.
        env = {**self.env, "CODEX_NO_PREWRITE_CHECK": "1"}
        prompt = "Continue using tools/not-a-real-tool-anywhere.py to finish."
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "resume", prompt],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1,
                         f"expected reject; stderr={proc.stderr}")
        self.assertIn("REJECTED (Gap #76 / R64)", proc.stderr)

    def test_review_with_verified_prompt_passes(self):
        prompt = "Review this PR using vault_resume_context for grounding."
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "review", prompt],
            capture_output=True, text=True, env=self.env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"expected pass; stderr={proc.stderr}")
        self.assertTrue(self.marker.is_file())

    def test_exec_injects_meta1_block_into_prompt(self):
        prompt = "<!-- r64-rebuttal: fixture -->\nRun a focused lane."
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "exec", prompt],
            capture_output=True, text=True, env=self.env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        marker_text = self.marker.read_text()
        self.assertIn("BEGIN dispatch-agent-with-prebriefing META-1 block", marker_text)
        self.assertIn("Section 15c", marker_text)
        log = pathlib.Path(self.tmp) / ".auditooor" / "codex_subagent_spawn_gate.jsonl"
        rows = [json.loads(ln) for ln in log.read_text().splitlines() if ln]
        self.assertTrue(any(r.get("verdict") == "pass-meta1-injected" for r in rows))

    def test_exec_meta1_injection_bypass_keeps_original_prompt(self):
        prompt = "<!-- r64-rebuttal: fixture -->\nRun a focused lane."
        env = {**self.env, "CODEX_NO_META1_INJECT": "1"}
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "exec", prompt],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        marker_text = self.marker.read_text()
        self.assertNotIn("BEGIN dispatch-agent-with-prebriefing META-1 block", marker_text)
        self.assertIn("Run a focused lane.", marker_text)


class TestExistingFunctionalityNotBroken(_Gap76TestBase):
    """Sanity: Gap #76 must not break the existing exec/run/submit/apply path."""

    def test_passthrough_list_still_works(self):
        # `list` is not gated; should pass through regardless.
        env = {**self.env}
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "list"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"list should pass-through; stderr={proc.stderr}")
        self.assertTrue(self.marker.is_file())
        self.assertIn("list", self.marker.read_text())

    def test_submit_no_draft_args_still_works(self):
        # `submit` with no detectable draft path should pass through (the
        # Gap #72 pre-submit-check scans for draft regex; if none found,
        # the wrapper continues to the token gate which we satisfy).
        env = {**self.env}
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "submit", "something-non-draft.txt"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"submit (no draft) should pass; stderr={proc.stderr}")
        self.assertTrue(self.marker.is_file())

    def test_apply_to_out_of_scope_path_still_works(self):
        # apply against a path outside submissions/ should not trigger L34
        # (classifier short-circuits on non-submission paths in our wrapper).
        env = {**self.env}
        out_of_scope = pathlib.Path(self.tmp) / "src" / "foo.py"
        out_of_scope.parent.mkdir(parents=True, exist_ok=True)
        out_of_scope.write_text("print('hi')\n")
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "apply", str(out_of_scope.relative_to(self.tmp))],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0,
                         f"out-of-scope apply should pass; stderr={proc.stderr}")
        self.assertTrue(self.marker.is_file())


class TestP9CodexParity(_Gap76TestBase):
    """P9 hook propagation parity: make gating and apply corpus refresh."""

    def _make_fake_refresh_hook(self):
        hook = pathlib.Path(self.tmp) / "fake-corpus-refresh-hook.sh"
        marker = pathlib.Path(self.tmp) / "fake-corpus-refresh-payload.json"
        hook.write_text(f"""#!/usr/bin/env bash
cat > "{marker}"
exit 0
""")
        hook.chmod(0o755)
        return hook, marker

    def test_make_audit_target_is_gated_without_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "make", "audit"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stderr)
        self.assertFalse(self.marker.is_file())

    def test_make_non_audit_target_stays_passthrough(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "make", "docs-check"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(self.marker.is_file())
        self.assertIn("make docs-check", self.marker.read_text())

    def test_apply_corpus_path_invokes_refresh_hook_after_success(self):
        target = pathlib.Path(self.tmp) / "audit" / "corpus_tags" / "derived" / "fixture.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{}\n")
        hook, hook_marker = self._make_fake_refresh_hook()
        env = {
            **self.env,
            "AUDITOOOR_CODEX_CORPUS_REFRESH_HOOK": str(hook),
        }
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "apply", str(target.relative_to(self.tmp))],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(hook_marker.is_file(), "refresh hook should receive a payload")
        payload = json.loads(hook_marker.read_text())
        self.assertEqual(payload["tool_name"], "Bash")
        self.assertIn("audit/corpus_tags/derived/fixture.json", payload["tool_input"]["command"])
        log = pathlib.Path(self.tmp) / ".auditooor" / "codex_corpus_refresh_gate.jsonl"
        rows = [json.loads(ln) for ln in log.read_text().splitlines() if ln]
        self.assertTrue(any(r.get("verdict") == "refresh-hook-invoked" for r in rows))


class TestVerifierJsonShape(unittest.TestCase):
    """Sanity: the wrapper's JSON parsing matches the verifiers' actual shapes.

    Regression guard: if l34-path-classifier.py renames `results` -> `records`
    or r64-prompt-claim-verifier.py renames `overall_verdict` -> something
    else, these tests catch the drift early.
    """

    def test_l34_classifier_emits_results_key(self):
        proc = subprocess.run(
            ["python3", str(L34_TOOL), "/foo/submissions/staging/x/x.md", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        doc = json.loads(proc.stdout)
        self.assertIn("results", doc, "L34 classifier must emit `results` key")
        self.assertEqual(doc["results"][0]["bucket"], "draft-file")

    def test_r64_verifier_emits_overall_verdict_key(self):
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
            fh.write("Use vault_resume_context for grounding.\n")
            tmp = fh.name
        try:
            proc = subprocess.run(
                ["python3", str(R64_TOOL), tmp, "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0)
            doc = json.loads(proc.stdout)
            self.assertIn("overall_verdict", doc,
                          "R64 verifier must emit `overall_verdict` key")
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main()
