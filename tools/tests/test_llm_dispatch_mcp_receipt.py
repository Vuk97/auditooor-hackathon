"""Tests for --require-mcp-receipt flag in llm-dispatch.py (PR #658 deferred item #1)."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
DISPATCH = REPO / "tools" / "llm-dispatch.py"
TOKEN_TOOL = REPO / "tools" / "auditooor_mcp_token.py"
MEMORY_CONTEXT_LOAD = REPO / "tools" / "memory-context-load.py"


def _make_dummy_prompt():
    """Returns a path to a tempfile with a benign prompt body."""
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False)
    fh.write("# test prompt\n\nbenign text\n")
    fh.close()
    return fh.name


def _issue_token(workspace, scope="write"):
    proc = subprocess.run(
        ["python3", str(TOKEN_TOOL), "issue",
         "--workspace", workspace, "--scope", scope, "--no-log"],
        capture_output=True, text=True,
        env={**os.environ, "AUDITOOOR_MCP_SECRET": "test-dispatch-secret-32-bytes-len"},
    )
    return proc.stdout.strip()


def _load_memory_context_module():
    spec = importlib.util.spec_from_file_location("memory_context_load_test", MEMORY_CONTEXT_LOAD)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_valid_receipt(workspace: str) -> None:
    mem = _load_memory_context_module()
    ws = pathlib.Path(workspace)
    auditooor = ws / ".auditooor"
    pack_dir = auditooor / "memory_context_packs"
    pack_dir.mkdir(parents=True, exist_ok=True)

    generated_at = mem.utc_now()
    req_doc = {
        "schema": mem.REQ_SCHEMA,
        "workspace": ws.name,
        "workspace_path": str(ws),
        "generated_at": generated_at,
        "workspace_facts": {},
        "requirements": [
            {
                "requirement_id": "resume",
                "context_kind": "resume",
                "tool": "vault_resume_context",
                "args": {},
                "fresh_after_refs": [],
            }
        ],
    }
    req_path = mem.requirements_path(ws)
    req_path.parent.mkdir(parents=True, exist_ok=True)
    req_path.write_text(json.dumps(req_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    pack = {
        "schema": "auditooor.vault_context_pack.v1",
        "kind": "resume",
        "source_refs": [],
    }
    pack_hash = mem.expected_pack_hash(pack)
    pack["context_pack_hash"] = pack_hash
    pack["context_pack_id"] = f"auditooor.vault_context_pack.v1:resume:{pack_hash[:16]}"
    pack_path = pack_dir / "resume.json"
    pack_path.write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    receipt = {
        "schema": mem.RECEIPT_SCHEMA,
        "workspace": ws.name,
        "workspace_path": str(ws),
        "generated_at": generated_at,
        "requirements_path": str(req_path),
        "requirements_hash": mem.sha256_file(req_path),
        "loaded_contexts": [
            {
                "requirement_id": "resume",
                "context_kind": "resume",
                "tool": "vault_resume_context",
                "args_hash": mem.sha256_text(mem.canonical_json({})),
                "context_pack_id": pack["context_pack_id"],
                "context_pack_hash": pack_hash,
                "pack_path": str(pack_path),
                "source_refs": [],
                "loaded_at": generated_at,
            }
        ],
        "missing_contexts": [],
        "summary": {
            "required_count": 1,
            "loaded_count": 1,
            "missing_count": 0,
            "stale_count": 0,
            "strict_ready": True,
        },
    }
    receipt["receipt_proof"] = mem.expected_receipt_proof(receipt)
    mem.receipt_path(ws).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class TestRequireMcpReceiptFlag(unittest.TestCase):
    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = "test-dispatch-secret-32-bytes-len"
        self.tmp = tempfile.mkdtemp()
        self.prompt = _make_dummy_prompt()
        # Base env: no consent, no token
        self.base_env = {**os.environ}
        self.base_env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        # Don't set AUDITOOOR_LLM_NETWORK_CONSENT — we'll get cannot-run for
        # different reasons depending on flag. We test ONLY the receipt gate.

    def tearDown(self):
        os.environ.pop("AUDITOOOR_MCP_SECRET", None)
        os.unlink(self.prompt)

    def test_require_mcp_receipt_missing_token_fails_with_rc3(self):
        env = {**self.base_env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["python3", str(DISPATCH),
             "--prompt-file", self.prompt,
             "--provider", "anthropic",
             "--require-mcp-receipt"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 3, f"expected 3 (mcp-receipt-missing); stderr:\n{proc.stderr}")
        self.assertIn("mcp-receipt-missing", proc.stdout + proc.stderr)
        self.assertIn("--scope write", proc.stdout + proc.stderr)

    def test_require_mcp_receipt_invalid_token_fails_with_rc3(self):
        env = {**self.base_env, "AUDITOOOR_MCP_SESSION_TOKEN": "garbage.invalid.token"}
        proc = subprocess.run(
            ["python3", str(DISPATCH),
             "--prompt-file", self.prompt,
             "--provider", "anthropic",
             "--require-mcp-receipt"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertIn("mcp-receipt-invalid", proc.stdout + proc.stderr)

    def test_valid_token_without_workspace_receipt_fails_with_rc3(self):
        token = _issue_token(self.tmp, scope="write")
        env = {**self.base_env, "AUDITOOOR_MCP_SESSION_TOKEN": token}
        proc = subprocess.run(
            ["python3", str(DISPATCH),
             "--prompt-file", self.prompt,
             "--provider", "anthropic",
             "--require-mcp-receipt"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertIn("mcp-receipt-incomplete", proc.stdout + proc.stderr)
        self.assertIn("next_command", proc.stdout + proc.stderr)

    def test_require_mcp_receipt_with_valid_token_and_receipt_proceeds(self):
        # Issue valid token
        token = _issue_token(self.tmp, scope="write")
        _write_valid_receipt(self.tmp)
        env = {**self.base_env, "AUDITOOOR_MCP_SESSION_TOKEN": token}
        proc = subprocess.run(
            ["python3", str(DISPATCH),
             "--prompt-file", self.prompt,
             "--provider", "anthropic",
             "--require-mcp-receipt"],
            capture_output=True, text=True, env=env,
        )
        # rc=3 would be receipt failure. Other failures (network consent
        # missing, etc.) yield different non-zero codes. We just verify
        # rc != 3 since the token is valid.
        self.assertNotEqual(proc.returncode, 3,
                            f"valid token should not trigger mcp-receipt-missing; stderr:\n{proc.stderr}")

    def test_no_require_flag_skips_receipt_check(self):
        env = {**self.base_env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        # WITHOUT --require-mcp-receipt, no token check
        proc = subprocess.run(
            ["python3", str(DISPATCH),
             "--prompt-file", self.prompt,
             "--provider", "anthropic"],
            capture_output=True, text=True, env=env,
        )
        # Should NOT be rc=3 (no mcp gate without flag)
        self.assertNotEqual(proc.returncode, 3)
        self.assertNotIn("mcp-receipt", proc.stdout + proc.stderr)

    def test_token_with_wrong_scope_rejected(self):
        # Issue token with read-only scope; --require-mcp-receipt requires write
        token = _issue_token(self.tmp, scope="read")
        env = {**self.base_env, "AUDITOOOR_MCP_SESSION_TOKEN": token}
        proc = subprocess.run(
            ["python3", str(DISPATCH),
             "--prompt-file", self.prompt,
             "--provider", "anthropic",
             "--require-mcp-receipt"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertIn("scope", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
