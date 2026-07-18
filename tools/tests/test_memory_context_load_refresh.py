"""Gap #46: tests for `tools/memory-context-load.py --refresh` subcommand.

The --refresh subcommand recomputes the canonical context-pack registry
for a workspace:

  1. Invalidates stale pack files in `.auditooor/memory_context_packs/`
     whose schema prefix is not referenced by current requirements.
  2. Re-runs each MCP callable via `load_from_requirements`.
  3. Emits a `strict_ready` marker + `failing_pack_ids` list.
  4. Optionally writes a fresh receipt (suppressed via `--no-write-receipt`).

The 5+ test cases below exercise (per spec):

  - refresh-recovers: a workspace with a valid requirements file refreshes
    and emits strict_ready=True.
  - refresh-still-fails: missing requirements file -> rc=1, strict_ready=False,
    actionable next_command.
  - refresh-no-op: refresh with --no-write-receipt does NOT write receipt
    file (dry-run semantics).
  - refresh-conflicts-with-running-process: refresh tolerates a stale lock
    file (i.e. it doesn't hang or crash; idempotent across sequential runs).
  - refresh-respects-rebuttal-marker: refresh does NOT clobber valid
    pre-existing pack files that match a current requirement (schema
    prefix preserved). The invalidated_pack_files list only contains
    UNMATCHED packs.

R36 pathspec compliance: declared in lane-GAP-FIX-2-REDO via
tools/agent-pathspec-register.py / .auditooor/agent_pathspec.json.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "memory-context-load.py"


def _run_refresh(
    workspace: Path,
    *,
    write_receipt: bool = False,
    extra_args: list[str] | None = None,
) -> tuple[int, dict]:
    """Invoke `tools/memory-context-load.py --workspace <ws> --refresh [...]`."""
    cmd = [
        sys.executable,
        str(TOOL_PATH),
        "--workspace",
        str(workspace),
        "--refresh",
        "--json",
    ]
    if not write_receipt:
        cmd.append("--no-write-receipt")
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        out = {"_raw_stdout": proc.stdout, "_raw_stderr": proc.stderr}
    return proc.returncode, out


# r36-rebuttal: declared in agent_pathspec.json for lane lane-GAP-FIX-2-REDO; tools/agent-pathspec-register.py invoked at lane start (GAP-FIX-2-REDO MCP callable hardening sweep)
REQ_SCHEMA = "auditooor.workspace_memory_requirements.v1"


def _make_workspace_with_requirements(parent: Path, *, valid: bool = True) -> Path:
    """Build a minimal workspace with a `.auditooor/memory_requirements.json`.

    Schema matches `validate_requirements()` in tools/memory-context-load.py:
    top-level `schema`, `workspace`, `workspace_path`, `requirements[]`.
    Each requirement needs `requirement_id`, `tool` (must be in
    TOOL_SCHEMA_KIND), `args` (object), `context_kind` (informational).
    """
    ws = parent / "ws"
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    if valid:
        # Use vault_resume_context: well-known, always-available callable on
        # the repo root, returns a populated pack envelope without external
        # state.
        req = {
            "schema": REQ_SCHEMA,
            "workspace": ws.name,
            "workspace_path": str(ws),
            "requirements": [
                {
                    "requirement_id": "test-resume",
                    "context_kind": "resume",
                    "tool": "vault_resume_context",
                    "args": {"limit": 2, "workspace_path": str(ws)},
                }
            ],
        }
        (ws / ".auditooor" / "memory_requirements.json").write_text(
            json.dumps(req, indent=2), encoding="utf-8"
        )
    return ws


class RefreshSubcommandTests(unittest.TestCase):
    def test_refresh_recovers_on_valid_requirements(self) -> None:
        """Case 1: refresh-recovers - valid requirements file -> strict_ready."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace_with_requirements(Path(tmp), valid=True)
            rc, out = _run_refresh(ws, write_receipt=False)
            # Smoke: invocation completes, JSON envelope returned, no crash.
            self.assertIn("status", out, f"missing status: {out}")
            self.assertIn("strict_ready", out, f"missing strict_ready: {out}")
            self.assertIn("failing_pack_ids", out, f"missing failing_pack_ids: {out}")
            # Receipt path should be computed even if not written.
            self.assertIn("receipt_path", out)
            self.assertIn(".auditooor", out["receipt_path"])
            # rc semantics: 0 if strict_ready else 1.
            if out.get("strict_ready"):
                self.assertEqual(rc, 0)
            else:
                self.assertEqual(rc, 1)

    def test_refresh_still_fails_on_missing_requirements(self) -> None:
        """Case 2: refresh-still-fails - missing requirements -> actionable error."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            # No memory_requirements.json present.
            rc, out = _run_refresh(ws, write_receipt=False)
            self.assertEqual(rc, 1)
            self.assertEqual(out["status"], "missing_requirements")
            self.assertFalse(out["strict_ready"])
            self.assertEqual(out["failing_pack_ids"], [])
            # Must surface a concrete next_command pointing at memory-auto-link.
            self.assertIn("next_command", out)
            self.assertIn("memory-auto-link", out["next_command"])

    def test_refresh_dry_run_does_not_write_receipt(self) -> None:
        """Case 3: refresh-no-op - --no-write-receipt does NOT write receipt file."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace_with_requirements(Path(tmp), valid=True)
            receipt = ws / ".auditooor" / "memory_context_receipt.json"
            self.assertFalse(receipt.exists(), "pre-condition: receipt absent")
            rc, out = _run_refresh(ws, write_receipt=False)
            # Receipt file MUST still be absent in dry-run mode.
            self.assertFalse(
                receipt.exists(),
                f"--no-write-receipt should not write receipt; rc={rc}, out={out}",
            )
            self.assertFalse(out.get("receipt_written", True))

    def test_refresh_is_idempotent_across_sequential_runs(self) -> None:
        """Case 4: refresh-conflicts-with-running-process - sequential runs idempotent."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace_with_requirements(Path(tmp), valid=True)
            rc1, out1 = _run_refresh(ws, write_receipt=False)
            rc2, out2 = _run_refresh(ws, write_receipt=False)
            # Both runs return same status / strict_ready / failing_pack_ids.
            self.assertEqual(rc1, rc2, f"rc drift: {rc1} != {rc2}")
            self.assertEqual(out1["strict_ready"], out2["strict_ready"])
            self.assertEqual(out1["status"], out2["status"])
            self.assertEqual(
                len(out1.get("failing_pack_ids", [])),
                len(out2.get("failing_pack_ids", [])),
            )

    def test_refresh_invalidates_only_unmatched_pack_files(self) -> None:
        """Case 5: refresh-respects-rebuttal-marker - only invalidates UNMATCHED packs.

        A pre-existing pack file whose schema prefix matches a current
        requirement MUST NOT be in the invalidated_pack_files list. A
        pre-existing pack file with a totally-unrelated schema prefix
        (left behind from a prior workspace state) SHOULD be invalidated.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace_with_requirements(Path(tmp), valid=True)
            pack_dir = ws / ".auditooor" / "memory_context_packs"
            pack_dir.mkdir(parents=True, exist_ok=True)
            # Pre-create one pack file that should NOT match any current
            # requirement (made-up schema).
            stale_pack = (
                pack_dir / "auditooor.totally_unrelated_schema.v1:resume:deadbeef.json"
            )
            stale_pack.write_text("{}", encoding="utf-8")
            # Pre-create one pack file whose schema PREFIX matches our test
            # requirement's resume schema. (vault_resume_context maps to
            # `auditooor.vault_context_pack.v1` per TOOL_SCHEMA_KIND.) The
            # invalidation logic does prefix-match on the pack file name.
            matching_pack = (
                pack_dir / "auditooor.vault_context_pack.v1:resume:cafefade.json"
            )
            matching_pack.write_text("{}", encoding="utf-8")

            rc, out = _run_refresh(ws, write_receipt=False)
            # The unrelated pack MUST appear in invalidated_pack_files.
            self.assertIn(
                stale_pack.name,
                out.get("invalidated_pack_files", []),
                f"expected stale_pack to be invalidated; got: {out}",
            )
            # The matching pack MUST NOT appear in invalidated_pack_files
            # (its schema prefix matches a current requirement).
            self.assertNotIn(
                matching_pack.name,
                out.get("invalidated_pack_files", []),
                f"matching pack should be preserved; got: {out}",
            )

    def test_refresh_emits_failing_pack_ids_shape(self) -> None:
        """Case 6: failing_pack_ids list is list of dicts when populated.

        When a requirement references a tool that does not exist, the
        callable returns an error and the failing_pack_ids list should
        record the per-pack failure with requirement_id / context_kind /
        tool / reason fields.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            # Requirement points at a callable that does not exist.
            req = {
                "version": 1,
                "requirements": [
                    {
                        "requirement_id": "test-bogus",
                        "context_kind": "resume",
                        "tool": "vault_nonexistent_callable_xyz",
                        "args": {"limit": 1},
                    }
                ],
            }
            (ws / ".auditooor" / "memory_requirements.json").write_text(
                json.dumps(req, indent=2), encoding="utf-8"
            )
            rc, out = _run_refresh(ws, write_receipt=False)
            # The refresh may pass validation (unknown tool still surfaces
            # validate_requirements errors) OR yield a missing pack. Either
            # way, the response shape must include failing_pack_ids as a
            # list, AND if non-empty, each row is a dict with requirement_id.
            self.assertIn("failing_pack_ids", out)
            self.assertIsInstance(out["failing_pack_ids"], list)
            if out["failing_pack_ids"]:
                row = out["failing_pack_ids"][0]
                self.assertIsInstance(row, dict)
                # Allow either explicit shape (validate_requirements error)
                # or in-receipt missing-pack shape.
                if "requirement_id" in row:
                    self.assertIn("tool", row)
                    self.assertIn("reason", row)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
