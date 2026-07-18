#!/usr/bin/env python3
"""Tests for tools/audit/session-memory-carry.py (W4.12 cross-session carry)."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "audit" / "session-memory-carry.py"
_spec = importlib.util.spec_from_file_location("session_memory_carry", _TOOL)
smc = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(smc)


def _make_workspace(root: Path) -> Path:
    """Build a synthetic workspace with one of each delta class."""
    ws = root / "synthetic-ws"
    (ws / ".auditooor" / "gate-status").mkdir(parents=True)
    (ws / "agent_outputs").mkdir()
    (ws / "scope_review").mkdir()

    # NEGATIVE verdict — name + body marker both present.
    (ws / "agent_outputs" / "lane_x_negative_verdict.md").write_text(
        "# Lane X\nVERDICT: DROPPED-OOS-DOS-CLASS — generic DoS, no in-scope impact.\n",
        encoding="utf-8",
    )
    # A file with a NEGATIVE name but no body marker — must be skipped.
    (ws / "agent_outputs" / "lane_y_verdict.md").write_text(
        "# Lane Y\nStill in progress, building PoC.\n", encoding="utf-8"
    )
    # Dropped / deferred lanes.
    (ws / ".auditooor" / "deferred_l17_lanes.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "lanes": [
                    {"lane_id": "LANE-DEFERRED-1", "status": "deferred-structural-blocker"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws / ".auditooor" / "gate-status" / "foo_DROPPED_bar.gate-status.json").write_text(
        "{}", encoding="utf-8"
    )
    # Harness delta.
    (ws / ".auditooor" / "commit_lifecycle_ledger.json").write_text(
        json.dumps(
            {
                "commits": [
                    {"kind": "harness", "title": "Add Check #99 gate", "sha": "abc123"},
                    {"kind": "finding", "title": "not a harness delta", "sha": "def456"},
                ]
            }
        ),
        encoding="utf-8",
    )
    # Lane cooldown.
    (ws / ".auditooor" / "lane_cooldown_state.json").write_text(
        json.dumps(
            {"cooldowns": [{"lane_id": "LANE-COOLED", "cooldown_until": "2026-06-01"}]}
        ),
        encoding="utf-8",
    )
    return ws


class TestCollectors(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = _make_workspace(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_negative_verdicts_require_name_and_body(self) -> None:
        neg = smc.collect_negative_verdicts(self.ws)
        lanes = {n["lane"] for n in neg}
        self.assertIn("lane_x_negative_verdict", lanes)
        # lane_y has a NEGATIVE name but no DROP/NEGATIVE body marker.
        self.assertNotIn("lane_y_verdict", lanes)
        self.assertEqual(neg[0]["verdict_marker"], "DROPPED-OOS-DOS-CLASS")

    def test_dropped_lanes_from_both_sources(self) -> None:
        dropped = smc.collect_dropped_lanes(self.ws)
        ids = {d["lane_id"] for d in dropped}
        self.assertIn("LANE-DEFERRED-1", ids)
        self.assertTrue(any("DROPPED" in i for i in ids))

    def test_harness_deltas_filter_by_kind(self) -> None:
        harness = smc.collect_harness_deltas(self.ws)
        self.assertEqual(len(harness), 1)
        self.assertEqual(harness[0]["summary"], "Add Check #99 gate")
        self.assertEqual(harness[0]["sha"], "abc123")

    def test_lane_cooldowns(self) -> None:
        cd = smc.collect_lane_cooldowns(self.ws)
        self.assertEqual(len(cd), 1)
        self.assertEqual(cd[0]["lane_id"], "LANE-COOLED")
        self.assertEqual(cd[0]["cooldown_until"], "2026-06-01")


class TestArtifact(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = _make_workspace(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_artifact_schema_and_summary(self) -> None:
        art = smc.build_artifact(self.ws)
        self.assertEqual(art["schema"], "auditooor.session_memory_carry.v1")
        self.assertEqual(art["workspace"], "synthetic-ws")
        self.assertEqual(art["summary"]["negative_verdicts"], 1)
        self.assertEqual(art["summary"]["dropped_lanes"], 2)
        self.assertEqual(art["summary"]["harness_deltas"], 1)
        self.assertEqual(art["summary"]["lane_cooldowns"], 1)

    def test_content_hash_is_idempotent(self) -> None:
        """Re-running on an unchanged workspace yields the same content_hash."""
        a1 = smc.build_artifact(self.ws)
        a2 = smc.build_artifact(self.ws)
        self.assertEqual(a1["content_hash"], a2["content_hash"])

    def test_write_outputs_emits_artifact_and_vault_note(self) -> None:
        vault = Path(self._tmp.name) / "vault"
        art = smc.build_artifact(self.ws)
        written = smc.write_outputs(art, self.ws, vault, dry_run=False)
        # Workspace artifact exists and round-trips.
        ap = Path(written["workspace_artifact"])
        self.assertTrue(ap.is_file())
        reloaded = json.loads(ap.read_text())
        self.assertEqual(reloaded["content_hash"], art["content_hash"])
        # Vault note exists at session-memory/<slug>.md and carries the marker.
        np = Path(written["vault_note"])
        self.assertTrue(np.is_file())
        self.assertEqual(written["vault_note_relpath"], "session-memory/synthetic-ws.md")
        note_text = np.read_text()
        self.assertIn("Session Memory Carry", note_text)
        self.assertIn("DROPPED-OOS-DOS-CLASS", note_text)
        self.assertIn("session-memory/carry", note_text)  # frontmatter tag

    def test_dry_run_writes_nothing(self) -> None:
        vault = Path(self._tmp.name) / "vault-dry"
        art = smc.build_artifact(self.ws)
        written = smc.write_outputs(art, self.ws, vault, dry_run=True)
        self.assertFalse(Path(written["workspace_artifact"]).exists())
        self.assertFalse(Path(written["vault_note"]).exists())


class TestCLI(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = _make_workspace(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_cli_json_mode(self) -> None:
        vault = Path(self._tmp.name) / "vault"
        rc = smc.main(
            ["--workspace", str(self.ws), "--vault-dir", str(vault), "--json"]
        )
        self.assertEqual(rc, 0)

    def test_cli_missing_workspace_errors(self) -> None:
        rc = smc.main(["--workspace", str(self.ws / "nonexistent")])
        self.assertEqual(rc, 2)

    def test_cli_requires_workspace_or_sync_flag(self) -> None:
        rc = smc.main([])
        self.assertEqual(rc, 2)


class TestVaultIntegration(unittest.TestCase):
    """W4.12 wiring: the vault-sync section + resume-pack path resolution."""

    def test_section_registered_in_vault_sync(self) -> None:
        sync_tool = (
            Path(__file__).resolve().parents[1] / "obsidian-vault-sync.py"
        )
        spec = importlib.util.spec_from_file_location("ovsync", sync_tool)
        mod = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)
        self.assertIn("session-memory", mod.SECTION_SOURCES)
        self.assertIn("session-memory", mod.SESSION_MEMORY_SECTIONS)
        # The section command routes to the carry tool.
        cmd = mod._section_command("session-memory", Path("/tmp/v"))
        self.assertTrue(any("session-memory-carry.py" in c for c in cmd))
        self.assertIn("--sync-all-workspaces", cmd)


if __name__ == "__main__":
    unittest.main()
