"""Gap #44 / R36-compliant resilience test for Layer-1 MCP callables.

For each of 10 known workspaces (hyperbridge, near, spark, dydx, sei,
morpho, polymarket, thegraph, base-azul, auditooor-mcp), invoke the 4 Layer-1
callables that were observed degraded by HUNT-HB-1-CORE / HUNT-SMT-1:

  - vault_resume_context
  - vault_knowledge_gap_context
  - vault_harness_context
  - vault_outcome_context

After the Gap #44 hardening:
  * No invocation may return a bare error-only envelope.
  * Every emit MUST include `schema`, `context_pack_id`, and a top-level
    `context_pack_hash` of 64 hex chars (Gap #47 canonicalization).
  * A workspace's ledger may be invalid; the callable MUST still emit
    an empty-but-valid honest-degraded pack with the `degraded` marker
    and a `next_action` hint.
  * Workspaces that DO NOT exist are tolerated by passing `workspace_path`
    that points at the repo root (the callables resolve repo-relative
    refs independently of the workspace_path argument). The test still
    asserts that invocation does not raise and the emit is valid.

The test does not require the auditooor-mcp workspace path to exist as a
sibling of the audits/ tree - we use the repo_root itself as the
auditooor-mcp workspace probe target (matches the operational pattern).

R36 pathspec compliance: tests/test_vault_mcp_callable_resilience.py is
declared in the GAP-FIX-2-44 lane (.auditooor/agent_pathspec.json via
tools/agent-pathspec-register.py).
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


WORKSPACES = [
    Path("/Users/wolf/audits/hyperbridge"),
    Path("/Users/wolf/audits/near"),
    Path("/Users/wolf/audits/spark"),
    Path("/Users/wolf/audits/dydx"),
    Path("/Users/wolf/audits/sei"),
    Path("/Users/wolf/audits/morpho"),
    Path("/Users/wolf/audits/polymarket"),
    Path("/Users/wolf/audits/thegraph"),
    Path("/Users/wolf/audits/base-azul"),
    REPO_ROOT,  # "auditooor-mcp" workspace = the repo itself.
]


LAYER_1_CALLABLES = [
    "vault_resume_context",
    "vault_knowledge_gap_context",
    "vault_harness_context",
    "vault_outcome_context",
]


HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_resilience_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _invoke(callable_name: str, workspace_path: Path) -> dict:
    """Subprocess invocation so we exercise the same code path as the live
    CLI (matches how operators / lanes call the server)."""
    proc = subprocess.run(
        [
            sys.executable,
            str(MODULE_PATH),
            "--call",
            callable_name,
            "--args",
            json.dumps({"workspace_path": str(workspace_path), "limit": 2}),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_ROOT),
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"{callable_name} on {workspace_path} exited rc={proc.returncode}: "
            f"stderr={proc.stderr[:300]}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"{callable_name} on {workspace_path} produced invalid JSON: {exc}; "
            f"stdout[:300]={proc.stdout[:300]}"
        )


class TestLayer1CallableResilience(unittest.TestCase):
    """Each test asserts no bare error envelope for any workspace x callable
    combination, and every emit is a recognizable schema envelope with
    top-level canonical context_pack_id / context_pack_hash."""

    maxDiff = None

    def _assert_canonical_envelope(self, callable_name: str, workspace: Path, payload: dict) -> None:
        # Gap #47: top-level hash field MUST be present and well-formed.
        self.assertIn(
            "context_pack_hash",
            payload,
            f"{callable_name}@{workspace.name}: missing top-level context_pack_hash",
        )
        h = payload.get("context_pack_hash")
        self.assertIsInstance(
            h, str, f"{callable_name}@{workspace.name}: context_pack_hash not str"
        )
        self.assertTrue(
            HEX64.match(h),
            f"{callable_name}@{workspace.name}: context_pack_hash not 64-hex: {h!r}",
        )
        # Gap #44: schema + context_pack_id MUST be present even on degraded.
        self.assertIn(
            "schema",
            payload,
            f"{callable_name}@{workspace.name}: missing schema field (Gap #44)",
        )
        self.assertIn(
            "context_pack_id",
            payload,
            f"{callable_name}@{workspace.name}: missing context_pack_id (Gap #44)",
        )
        pid = payload.get("context_pack_id")
        self.assertIsInstance(
            pid, str, f"{callable_name}@{workspace.name}: context_pack_id not str"
        )
        # ID encodes the schema + first 16 hex chars of hash (server convention).
        self.assertIn(
            h[:16],
            pid,
            f"{callable_name}@{workspace.name}: id does not embed hash prefix",
        )

    def _assert_no_bare_error(self, callable_name: str, workspace: Path, payload: dict) -> None:
        """A bare error envelope is one that has only error/message/path fields
        and no schema/context_pack_id/context_pack_hash. After Gap #44, this
        shape is no longer allowed."""
        is_bare_error = (
            "error" in payload
            and "schema" not in payload
            and "context_pack_id" not in payload
            and "context_pack_hash" not in payload
        )
        self.assertFalse(
            is_bare_error,
            f"{callable_name}@{workspace.name}: bare error envelope no longer "
            f"allowed (Gap #44). payload keys: {list(payload.keys())[:15]}",
        )

    def test_no_callable_returns_bare_error_envelope(self):
        """For each workspace x callable combination, the emit MUST not be a
        bare error dict; it MUST carry schema + context_pack_id + hash."""
        failures: list[str] = []
        for ws in WORKSPACES:
            for cb in LAYER_1_CALLABLES:
                payload = _invoke(cb, ws)
                # Two-way check:
                try:
                    self._assert_no_bare_error(cb, ws, payload)
                    self._assert_canonical_envelope(cb, ws, payload)
                except AssertionError as exc:
                    failures.append(str(exc))
        if failures:
            self.fail(
                f"{len(failures)} workspace x callable combo(s) failed "
                f"resilience check:\n" + "\n".join(failures[:20])
            )

    def test_degraded_emit_includes_next_action_hint(self):
        """When a callable returns degraded (validation failed), the pack MUST
        carry a `next_action` hint pointing at the remediation path. Probe the
        repo root specifically because reports/knowledge_gaps.jsonl and
        reports/harness_failures.jsonl are known to fail validation here."""
        for cb in ("vault_knowledge_gap_context", "vault_harness_context"):
            payload = _invoke(cb, REPO_ROOT)
            if payload.get("degraded"):
                self.assertIn(
                    "next_action",
                    payload,
                    f"{cb}: degraded pack missing next_action hint",
                )
                self.assertIn(
                    "memory-context-load.py",
                    payload.get("next_action", ""),
                    f"{cb}: next_action does not reference the canonical "
                    f"refresh tool",
                )

    def test_callable_emits_token_estimate_or_skips_gracefully(self):
        """Resilience for downstream telemetry: token_estimate should be
        present in harness / knowledge_gap packs (used by memory-context-load
        for pack validation)."""
        for cb in ("vault_knowledge_gap_context", "vault_harness_context"):
            payload = _invoke(cb, REPO_ROOT)
            self.assertIn(
                "token_estimate",
                payload,
                f"{cb}: missing token_estimate field after Gap #44 fix",
            )


class TestModuleLoadParity(unittest.TestCase):
    """Quick parity check that the in-process load returns equivalent shape."""

    def test_in_process_invocation_matches_subprocess_shape(self):
        module = _load_module()
        # In-process: requires VaultQuery construction.
        vault = REPO_ROOT / "obsidian-vault"
        if not vault.is_dir():
            self.skipTest(f"obsidian-vault not present at {vault}")
        q = module.VaultQuery(vault, REPO_ROOT)
        for cb in LAYER_1_CALLABLES:
            result = getattr(q, cb)()
            self.assertIsInstance(result, dict, f"{cb}: not dict")
            self.assertIn(
                "context_pack_hash",
                result,
                f"{cb}: in-process emit missing context_pack_hash",
            )


if __name__ == "__main__":
    unittest.main()
