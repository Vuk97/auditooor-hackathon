#!/usr/bin/env python3
# r36-rebuttal: lane-GAP-FIX-3-B (this test file declared in agent_pathspec.json)
"""Tests for Gap #54 universal-hook bypass-env propagation audit logging.

Gap #54 (codified 2026-05-26): SESSION-GAP-HUNT found 61 bypass-env
STRING references in session transcripts but 0 bypass-env HOOK LOG
entries — confirming the AUDITOOOR_UNIVERSAL_BYPASS env var was not
propagated to the hook subprocess. The fix adds:

  1. Explicit JSONL audit logging to
     `.auditooor/universal_hook_audit.jsonl` when bypass IS set
     (event=bypass-env, bypass=true).

  2. Inverse diagnostic logging when the bypass env name is REFERENCED
     in the action context but NOT exported to the hook subprocess
     (event=bypass-name-referenced-but-not-set, bypass=false).

  3. No audit row when neither set nor referenced (clean baseline).

Schema: auditooor.gap54_universal_hook_audit.v1
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HOOK_PATH = _REPO_ROOT / "tools" / "hooks" / "auditooor-universal-rule-enforce.sh"


def _run_hook(payload: dict, extra_env: dict[str, str] | None = None,
              tmp_repo_root: Path | None = None) -> tuple[int, str]:
    """Run the universal hook with a temporary REPO_ROOT for log isolation.

    Note: the hook hard-codes REPO_ROOT to /Users/wolf/auditooor-mcp at the
    top of the script. Rather than fighting that, we run the hook in the
    REAL repo and inspect/clean the real audit log files between tests.
    """
    env = os.environ.copy()
    # Always start with a clean bypass-env to avoid leaking between tests.
    env.pop("AUDITOOOR_UNIVERSAL_BYPASS", None)
    if extra_env:
        env.update(extra_env)
    payload_json = json.dumps(payload)
    proc = subprocess.run(
        [str(_HOOK_PATH)],
        input=payload_json, capture_output=True, text=True, env=env,
        check=False,
    )
    return proc.returncode, proc.stdout


def _read_audit_log(audit_log: Path) -> list[dict]:
    if not audit_log.exists():
        return []
    rows: list[dict] = []
    for line in audit_log.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


class _Gap54AuditLogIsolation(unittest.TestCase):
    """Each test starts with an empty .auditooor/universal_hook_audit.jsonl."""

    AUDIT_LOG = _REPO_ROOT / ".auditooor" / "universal_hook_audit.jsonl"

    def setUp(self):
        # Preserve any pre-existing log content, then start fresh.
        if self.AUDIT_LOG.exists():
            self._backup = self.AUDIT_LOG.read_text(encoding="utf-8")
            self.AUDIT_LOG.unlink()
        else:
            self._backup = None
        self.AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        # Restore baseline so production audit log is not disturbed.
        if self.AUDIT_LOG.exists():
            self.AUDIT_LOG.unlink()
        if self._backup is not None:
            self.AUDIT_LOG.write_text(self._backup, encoding="utf-8")

    def _rows(self) -> list[dict]:
        return _read_audit_log(self.AUDIT_LOG)


class TestGap54BypassEnvSet(_Gap54AuditLogIsolation):
    """When AUDITOOOR_UNIVERSAL_BYPASS=1 is exported to the hook, a
    `bypass-env` row must be appended to the audit log AND the hook
    must exit 0 with no stdout (allow)."""

    def test_bypass_env_exported_logs_and_allows(self):
        rc, stdout = _run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "echo hi"}},
            extra_env={"AUDITOOOR_UNIVERSAL_BYPASS": "1"},
        )
        self.assertEqual(rc, 0)
        # Hook should not emit a deny JSON on bypass.
        self.assertEqual(stdout.strip(), "")
        rows = self._rows()
        self.assertTrue(rows, "expected at least one audit row")
        # Find the bypass-env row.
        bypass_rows = [r for r in rows if r.get("event") == "bypass-env"]
        self.assertEqual(len(bypass_rows), 1)
        row = bypass_rows[0]
        self.assertTrue(row.get("bypass"))
        self.assertEqual(
            row.get("bypass_env_name"), "AUDITOOOR_UNIVERSAL_BYPASS",
        )
        self.assertTrue(row.get("bypass_env_value_present"))
        self.assertEqual(
            row.get("schema"), "auditooor.gap54_universal_hook_audit.v1",
        )

    def test_bypass_env_set_to_non_one_does_not_trigger(self):
        """Only the exact value '1' triggers bypass."""
        rc, stdout = _run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "echo hi"}},
            extra_env={"AUDITOOOR_UNIVERSAL_BYPASS": "true"},
        )
        # Hook continues to classifier; result depends on classifier.
        # We only assert no bypass-env audit row was emitted.
        rows = self._rows()
        bypass_rows = [r for r in rows if r.get("event") == "bypass-env"]
        self.assertEqual(len(bypass_rows), 0)


class TestGap54BypassReferencedButNotSet(_Gap54AuditLogIsolation):
    """When the bypass env NAME appears in the action context but the
    env var is NOT exported, emit a propagation-failure diagnostic row."""

    def test_command_mentions_bypass_name_but_env_not_set(self):
        rc, _ = _run_hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "AUDITOOOR_UNIVERSAL_BYPASS=1 some-command "
                        "(this is the string-only reference)"
                    ),
                },
            },
        )
        rows = self._rows()
        diag_rows = [
            r for r in rows
            if r.get("event") == "bypass-name-referenced-but-not-set"
        ]
        self.assertEqual(len(diag_rows), 1)
        row = diag_rows[0]
        self.assertFalse(row.get("bypass"))
        self.assertFalse(row.get("bypass_env_value_present"))
        self.assertIn(
            "AUDITOOOR_UNIVERSAL_BYPASS",
            row.get("reason", ""),
        )

    def test_no_reference_and_no_export_emits_no_audit_row(self):
        """Baseline: clean action does not pollute the audit log."""
        rc, _ = _run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "ls -la /tmp"}},
        )
        rows = self._rows()
        # No bypass-env, no bypass-name-referenced-but-not-set.
        bypass_rows = [
            r for r in rows
            if r.get("event") in (
                "bypass-env",
                "bypass-name-referenced-but-not-set",
            )
        ]
        self.assertEqual(len(bypass_rows), 0)


class TestGap54AuditLogShape(_Gap54AuditLogIsolation):
    """Audit log rows must conform to the
    auditooor.gap54_universal_hook_audit.v1 schema."""

    def test_audit_row_schema_fields_present(self):
        _run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "x"}},
            extra_env={"AUDITOOOR_UNIVERSAL_BYPASS": "1"},
        )
        rows = self._rows()
        self.assertTrue(rows)
        for r in rows:
            for required in (
                "ts", "event", "bypass", "bypass_env_name",
                "bypass_env_value_present", "reason", "hook", "schema",
            ):
                self.assertIn(required, r, f"missing key: {required}")
            self.assertEqual(
                r["schema"], "auditooor.gap54_universal_hook_audit.v1",
            )
            self.assertEqual(
                r["hook"], "auditooor-universal-rule-enforce.sh",
            )

    def test_bypass_set_and_referenced_emits_only_bypass_row(self):
        """When the env IS exported AND the body mentions the name,
        only the bypass-env path fires (early exit at line 99)."""
        _run_hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "echo $AUDITOOOR_UNIVERSAL_BYPASS"
                    ),
                },
            },
            extra_env={"AUDITOOOR_UNIVERSAL_BYPASS": "1"},
        )
        rows = self._rows()
        bypass = [r for r in rows if r.get("event") == "bypass-env"]
        diag = [
            r for r in rows
            if r.get("event") == "bypass-name-referenced-but-not-set"
        ]
        self.assertEqual(len(bypass), 1)
        self.assertEqual(
            len(diag), 0,
            "diagnostic must not fire when bypass IS actually exported",
        )


if __name__ == "__main__":
    unittest.main()
