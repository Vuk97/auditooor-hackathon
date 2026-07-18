"""Gap #47 hash-canonical test for hacker / Layer-1 MCP callables.

After the Gap #44 / Gap #47 hardening sweep, the following Layer-1
callables MUST emit a top-level `context_pack_hash` field of 64 hex
chars, in EVERY emit shape:

  - vault_resume_context
  - vault_knowledge_gap_context
  - vault_harness_context
  - vault_outcome_context

The hash MUST NOT live nested inside `pack_payload`, `summary`,
`metadata`, or any other sub-dict. Downstream tooling (memory-context-
load.py, pr-hygiene-check, workpack-validator) reads
`pack["context_pack_hash"]` as a top-level field. Drift between
callables surfaced by HUNT-SMT-1 left some pack envelopes emitting
the hash under nested keys; this test locks the canonical top-level
location.

Probes both the live in-process callable (VaultQuery) and the
subprocess CLI invocation. Both code paths MUST agree.

R36 pathspec compliance: GAP-FIX-2-47 in .auditooor/agent_pathspec.json
via tools/agent-pathspec-register.py.
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
HEX64 = re.compile(r"^[0-9a-f]{64}$")


CANONICAL_HASH_CALLABLES = [
    "vault_resume_context",
    "vault_knowledge_gap_context",
    "vault_harness_context",
    "vault_outcome_context",
]


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_hash_canonical_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _subprocess_invoke(callable_name: str, ws: Path) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            str(MODULE_PATH),
            "--call",
            callable_name,
            "--args",
            json.dumps({"workspace_path": str(ws), "limit": 2}),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_ROOT),
    )
    if proc.returncode != 0:
        raise AssertionError(f"{callable_name} exited rc={proc.returncode}: {proc.stderr[:300]}")
    return json.loads(proc.stdout)


class TestHashCanonicalLocation(unittest.TestCase):
    """The top-level `context_pack_hash` field is the canonical location;
    nested hashes in pack_payload / metadata / summary are NOT acceptable."""

    maxDiff = None

    def test_top_level_hash_is_present_and_well_formed(self):
        """Every Layer-1 callable on the repo workspace MUST emit a top-level
        context_pack_hash that is 64 hex chars."""
        failures: list[str] = []
        for cb in CANONICAL_HASH_CALLABLES:
            payload = _subprocess_invoke(cb, REPO_ROOT)
            h = payload.get("context_pack_hash")
            if not isinstance(h, str):
                failures.append(f"{cb}: context_pack_hash absent or not str ({type(h).__name__})")
                continue
            if not HEX64.match(h):
                failures.append(f"{cb}: hash not 64-hex: {h!r}")
        if failures:
            self.fail("hash-canonical failures:\n" + "\n".join(failures))

    def test_hash_is_not_smuggled_into_nested_sub_dicts(self):
        """A pack MUST NOT carry the hash exclusively under nested fields like
        `pack_payload`, `summary`, `metadata`, or `validation`. The top-level
        is the authority; nested mirror copies are acceptable only if the
        top-level is also present."""
        for cb in CANONICAL_HASH_CALLABLES:
            payload = _subprocess_invoke(cb, REPO_ROOT)
            top = payload.get("context_pack_hash")
            self.assertIsNotNone(
                top, f"{cb}: top-level context_pack_hash missing"
            )
            for nested_key in ("pack_payload", "metadata", "validation"):
                sub = payload.get(nested_key)
                if isinstance(sub, dict) and "context_pack_hash" in sub:
                    self.assertEqual(
                        sub["context_pack_hash"],
                        top,
                        f"{cb}.{nested_key}.context_pack_hash diverges from top-level",
                    )

    def test_pack_id_embeds_first_16_chars_of_hash(self):
        """The context_pack_id MUST encode the schema + first 16 hex chars of
        the hash (server convention; memory-context-load.py validates this)."""
        for cb in CANONICAL_HASH_CALLABLES:
            payload = _subprocess_invoke(cb, REPO_ROOT)
            pid = payload.get("context_pack_id")
            phash = payload.get("context_pack_hash")
            self.assertIsInstance(pid, str, f"{cb}: pack_id not str")
            self.assertIsInstance(phash, str, f"{cb}: pack_hash not str")
            self.assertIn(
                phash[:16],
                pid,
                f"{cb}: pack_id ({pid!r}) does not embed hash prefix "
                f"({phash[:16]!r})",
            )

    def test_in_process_invocation_top_level_hash(self):
        """The in-process path must agree with the subprocess path on
        top-level hash location."""
        vault = REPO_ROOT / "obsidian-vault"
        if not vault.is_dir():
            self.skipTest(f"obsidian-vault not present at {vault}")
        q = vault_mcp_server.VaultQuery(vault, REPO_ROOT)
        for cb in CANONICAL_HASH_CALLABLES:
            result = getattr(q, cb)()
            self.assertIsInstance(result, dict, f"{cb}: in-process result not dict")
            h = result.get("context_pack_hash")
            self.assertIsInstance(
                h, str, f"{cb}: in-process emit missing top-level context_pack_hash"
            )
            self.assertTrue(
                HEX64.match(h), f"{cb}: in-process hash not 64-hex: {h!r}"
            )

    def test_top_level_id_and_hash_present_on_all_workspaces(self):
        """Cross-workspace assertion: even when ledgers contain unsafe refs,
        the top-level hash field MUST be present and well-formed."""
        for ws_name in (
            "hyperbridge",
            "spark",
            "dydx",
            "sei",
            "morpho",
            "polymarket",
            "thegraph",
            "base-azul",
        ):
            ws = Path("/Users/wolf/audits") / ws_name
            if not ws.is_dir():
                continue
            for cb in CANONICAL_HASH_CALLABLES:
                payload = _subprocess_invoke(cb, ws)
                self.assertIn(
                    "context_pack_hash",
                    payload,
                    f"{ws_name}/{cb}: top-level hash missing",
                )
                self.assertIn(
                    "context_pack_id",
                    payload,
                    f"{ws_name}/{cb}: top-level id missing",
                )
                h = payload.get("context_pack_hash")
                self.assertTrue(
                    isinstance(h, str) and HEX64.match(h),
                    f"{ws_name}/{cb}: hash malformed: {h!r}",
                )


if __name__ == "__main__":
    unittest.main()
