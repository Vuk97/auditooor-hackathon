"""Tests for VaultQuery.vault_lane_cooldown_check callable (W2-B-5).

Verifies:
  1. Happy path: state with 3 cooldowns returns 3 lanes.
  2. Empty cooldowns: returns 0 lanes (graceful empty envelope).
  3. Missing state file: returns graceful empty envelope without crash.
  4. lane_id filter: returns only the requested lane row.
  5. iter_age computation: cooldown at iter 8, current iter 14 → iter_age=6,
     staleness_class="stale_5+_iters".
  6. context_pack_id and context_pack_hash present in all outputs.
  7. stale_10+_iters class for age >= 10.
  8. CLI dispatch: subprocess.run exits 0 and returns valid JSON.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
SCHEMA_PREFIX = "auditooor.vault_lane_cooldown_check.v1"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_state(iteration: int, cooldowns: dict) -> dict:
    """Return a minimal spark_hunt_loop_state.json payload."""
    return {
        "iteration": iteration,
        "lane_cooldowns": cooldowns,
    }


def _write_state(path: Path, iteration: int, cooldowns: dict) -> None:
    path.write_text(json.dumps(_make_state(iteration, cooldowns)), encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestVaultLaneCooldownCheck(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-vlcc-test-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        # Workspace with .auditooor subdir
        self.workspace = self.root / "audits" / "test-ws"
        (self.workspace / ".auditooor").mkdir(parents=True)
        self.state_file = self.workspace / ".auditooor" / "spark_hunt_loop_state.json"
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    # ------------------------------------------------------------------
    # Test 1: Happy path — 3 cooldowns → 3 lanes returned
    # ------------------------------------------------------------------

    def test_happy_path_three_cooldowns(self):
        """State with 3 cooldowns returns 3 lane objects, all fields present."""
        cooldowns = {
            "H1-rerun": {
                "since_iter": 8,
                "reason": "iter8 EMPTY: covered by prior dupe. Re-run when audit-pin advances.",
                "trigger_state": {"audit_pin_sha": "abc123"},
            },
            "H3-mining": {
                "since_iter": 10,
                "reason": "iter10 NEGATIVE: 0 new hits. Re-run when Rust patterns count changes.",
                "trigger_state": {"rust_patterns_count": "baseline"},
            },
            "H6-bridge": {
                "since_iter": 12,
                "reason": "iter12 DROP: bridge-state-bloat classified DROP class-b.",
                "trigger_state": {},
            },
        }
        _write_state(self.state_file, iteration=14, cooldowns=cooldowns)

        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
        )

        self.assertEqual(result.get("total_cooldowns"), 3)
        self.assertEqual(len(result.get("lanes", [])), 3)
        self.assertEqual(result.get("current_iter"), 14)
        self.assertEqual(result.get("verdict"), "active-cooldown")
        self.assertEqual(result.get("state_file_status"), "present")
        self.assertFalse(result.get("degraded"))
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertEqual(result.get("schema"), SCHEMA_PREFIX)
        self.assertEqual(result.get("kind"), "lane_cooldown")

        lane_ids = {lane["lane_id"] for lane in result["lanes"]}
        self.assertEqual(lane_ids, {"H1-rerun", "H3-mining", "H6-bridge"})

        for lane in result["lanes"]:
            self.assertIn("lane_id", lane)
            self.assertIn("since_iter", lane)
            self.assertIn("reason", lane)
            self.assertIn("trigger_state_summary", lane)
            self.assertIn("current_iter", lane)
            self.assertIn("iter_age", lane)
            self.assertIn("staleness_class", lane)

    # ------------------------------------------------------------------
    # Test 2: Empty cooldowns → 0 lanes
    # ------------------------------------------------------------------

    def test_empty_cooldowns_returns_zero_lanes(self):
        """State with empty lane_cooldowns returns 0 lanes without error."""
        _write_state(self.state_file, iteration=5, cooldowns={})

        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
        )

        self.assertEqual(result.get("total_cooldowns"), 0)
        self.assertEqual(result.get("lanes"), [])
        self.assertEqual(result.get("current_iter"), 5)
        self.assertEqual(result.get("verdict"), "pass-no-active-cooldowns")
        self.assertEqual(result.get("state_file_status"), "present")
        self.assertFalse(result.get("degraded"))
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertNotIn("error", result)

    # ------------------------------------------------------------------
    # Test 3: Missing state file → graceful empty envelope, no crash
    # ------------------------------------------------------------------

    def test_missing_state_file_graceful_empty(self):
        """Missing state is cooldown-clear, not an MCP error."""
        # Do NOT create self.state_file
        self.assertFalse(self.state_file.exists())

        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
        )

        self.assertEqual(result.get("total_cooldowns"), 0)
        self.assertEqual(result.get("lanes"), [])
        self.assertEqual(result.get("current_iter"), 0)
        self.assertEqual(result.get("verdict"), "pass-no-cooldown-ledger")
        self.assertEqual(result.get("state_file_status"), "absent")
        self.assertFalse(result.get("degraded"))
        self.assertNotIn("error", result)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_workspace_alias_scopes_missing_state_as_no_ledger(self):
        """workspace alias is scoped like workspace_path, including no-ledger verdict."""
        alias_workspace = self.root / "audits" / "alias-ws"
        (alias_workspace / ".auditooor").mkdir(parents=True)

        synth_root = self.root / "synthetic-worktrees"
        synth_ws = synth_root / "synth-host-alias"
        (synth_ws / ".auditooor").mkdir(parents=True)
        _write_state(
            synth_ws / ".auditooor" / "spark_hunt_loop_state.json",
            iteration=99,
            cooldowns={
                "SHOULD-NOT-LEAK": {
                    "since_iter": 1,
                    "reason": "alias leak guard",
                    "trigger_state": {},
                },
            },
        )

        env_patch = {
            "AUDITOOOR_ALLOW_WORKTREE_GLOB_FALLBACK": "1",
            "AUDITOOOR_WORKTREE_GLOB_ROOT": str(synth_root),
        }
        with mock.patch.dict(os.environ, env_patch, clear=False):
            result = self.vault.vault_lane_cooldown_check(
                workspace=str(alias_workspace),
                lane_id="PHASE_A_SMOKE",
            )

        self.assertEqual(result.get("workspace_path"), str(alias_workspace))
        self.assertEqual(result.get("total_cooldowns"), 0)
        self.assertEqual(result.get("lanes"), [])
        self.assertEqual(result.get("verdict"), "pass-no-cooldown-ledger")
        self.assertEqual(result.get("state_file_status"), "absent")
        self.assertFalse(result.get("degraded"))
        self.assertNotIn("error", result)
        joined = "\n".join(result.get("state_file_path_searched", []))
        self.assertIn(str(alias_workspace.resolve()), joined)
        self.assertNotIn("SHOULD-NOT-LEAK", json.dumps(result))

    # ------------------------------------------------------------------
    # Test 4: lane_id filter returns only the requested lane
    # ------------------------------------------------------------------

    def test_lane_id_filter_returns_single_lane(self):
        """When lane_id is given, only that lane's row is returned."""
        cooldowns = {
            "H1-rerun": {
                "since_iter": 8,
                "reason": "iter8 EMPTY: claim-path covered. Re-run when pin advances.",
                "trigger_state": {"audit_pin_sha": "e8311d"},
            },
            "H3-mining": {
                "since_iter": 10,
                "reason": "iter10 NEGATIVE. Re-run when Rust patterns change.",
                "trigger_state": {"rust_patterns_count": "baseline"},
            },
            "H8-frost": {
                "since_iter": 11,
                "reason": "iter11 DROP: FROST library OOS for this engagement.",
                "trigger_state": {},
            },
        }
        _write_state(self.state_file, iteration=14, cooldowns=cooldowns)

        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
            lane_id="H3-mining",
        )

        # total_cooldowns reflects the full state, lanes[] only the filtered one
        self.assertEqual(result.get("total_cooldowns"), 3)
        lanes = result.get("lanes", [])
        self.assertEqual(len(lanes), 1)
        self.assertEqual(lanes[0]["lane_id"], "H3-mining")
        self.assertEqual(lanes[0]["since_iter"], 10)

    def test_lane_id_filter_missing_lane_is_success_verdict(self):
        """A missing lane_id in a present ledger is not an MCP error."""
        cooldowns = {
            "H1-rerun": {
                "since_iter": 8,
                "reason": "iter8 EMPTY. Re-run when pin advances.",
                "trigger_state": {"audit_pin_sha": "e8311d"},
            },
        }
        _write_state(self.state_file, iteration=14, cooldowns=cooldowns)

        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
            lane_id="not-cooled",
        )

        self.assertEqual(result.get("total_cooldowns"), 1)
        self.assertEqual(result.get("lanes"), [])
        self.assertEqual(result.get("verdict"), "pass-lane-not-cooled")
        self.assertEqual(result.get("state_file_status"), "present")
        self.assertFalse(result.get("degraded"))
        self.assertNotIn("error", result)

    # ------------------------------------------------------------------
    # Test 5: iter_age computation and staleness_class
    # ------------------------------------------------------------------

    def test_iter_age_and_staleness_class_stale_5(self):
        """cooldown at iter 8, current iter 14 → iter_age=6, staleness_class='stale_5+_iters'."""
        cooldowns = {
            "H1-rerun": {
                "since_iter": 8,
                "reason": "iter8 EMPTY. Re-run when audit-pin advances.",
                "trigger_state": {"audit_pin_sha": "abc"},
            },
        }
        _write_state(self.state_file, iteration=14, cooldowns=cooldowns)

        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
            lane_id="H1-rerun",
        )

        lanes = result.get("lanes", [])
        self.assertEqual(len(lanes), 1)
        lane = lanes[0]
        self.assertEqual(lane["iter_age"], 6)
        self.assertEqual(lane["staleness_class"], "stale_5+_iters")
        self.assertEqual(lane["current_iter"], 14)
        self.assertEqual(lane["since_iter"], 8)

    # ------------------------------------------------------------------
    # Test 6: context_pack_id and context_pack_hash always present
    # ------------------------------------------------------------------

    def test_context_pack_fields_always_present(self):
        """context_pack_id and context_pack_hash are in every response."""
        # With state file
        _write_state(self.state_file, iteration=3, cooldowns={"H9": {"since_iter": 1, "reason": "x", "trigger_state": {}}})
        result_with = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
        )
        self.assertIn("context_pack_id", result_with)
        self.assertIn("context_pack_hash", result_with)
        self.assertTrue(result_with["context_pack_id"].startswith(f"{SCHEMA_PREFIX}:lane_cooldown:"))

        # Without state file
        self.state_file.unlink()
        result_without = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
        )
        self.assertIn("context_pack_id", result_without)
        self.assertIn("context_pack_hash", result_without)
        self.assertTrue(result_without["context_pack_id"].startswith(f"{SCHEMA_PREFIX}:lane_cooldown:"))

    # ------------------------------------------------------------------
    # Test 7: stale_10+_iters class for age >= 10
    # ------------------------------------------------------------------

    def test_staleness_class_stale_10_plus(self):
        """Lane cooled at iter 3 with current iter 14 → iter_age=11, staleness_class='stale_10+_iters'."""
        cooldowns = {
            "H5-old": {
                "since_iter": 3,
                "reason": "iter3 DROP: insufficient signal.",
                "trigger_state": {},
            },
        }
        _write_state(self.state_file, iteration=14, cooldowns=cooldowns)

        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
            lane_id="H5-old",
        )

        lanes = result.get("lanes", [])
        self.assertEqual(len(lanes), 1)
        self.assertEqual(lanes[0]["iter_age"], 11)
        self.assertEqual(lanes[0]["staleness_class"], "stale_10+_iters")

    # ------------------------------------------------------------------
    # Test 8: CLI dispatch
    # ------------------------------------------------------------------

    def test_cli_dispatch_exits_zero_and_valid_json(self):
        """CLI --call vault_lane_cooldown_check exits 0 and returns valid JSON."""
        _write_state(
            self.state_file,
            iteration=7,
            cooldowns={
                "H2-test": {
                    "since_iter": 5,
                    "reason": "iter5 EMPTY.",
                    "trigger_state": {},
                }
            },
        )
        args_json = json.dumps({
            "workspace_path": str(self.workspace),
            "state_file": str(self.state_file),
        })
        proc = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--repo-root", str(self.root),
                "--call", "vault_lane_cooldown_check",
                "--args", args_json,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"CLI exited non-zero: {proc.stderr[:300]}")
        parsed = json.loads(proc.stdout)
        self.assertIn("context_pack_id", parsed)
        self.assertTrue(
            parsed["context_pack_id"].startswith(f"{SCHEMA_PREFIX}:lane_cooldown:"),
            f"Unexpected prefix: {parsed['context_pack_id']}",
        )
        self.assertEqual(parsed.get("total_cooldowns"), 1)
        self.assertEqual(len(parsed.get("lanes", [])), 1)

    # ------------------------------------------------------------------
    # Test 9: Hermetic default - worktree glob fallback is OFF without env var
    # ------------------------------------------------------------------

    def test_worktree_glob_fallback_disabled_by_default(self):
        """Without AUDITOOOR_ALLOW_WORKTREE_GLOB_FALLBACK=1 and no workspace_path,
        the glob fallback must NOT fire even if a synthetic worktree-glob-root
        contains valid state files. synthetic_fixture: true.
        """
        # Synthetic worktree-glob-root with 2 cooldowns
        synth_root = self.root / "synthetic-worktrees"
        synth_ws = synth_root / "synthetic-ws-a"
        (synth_ws / ".auditooor").mkdir(parents=True)
        _write_state(
            synth_ws / ".auditooor" / "spark_hunt_loop_state.json",
            iteration=99,
            cooldowns={
                "SYNTH-L1": {"since_iter": 90, "reason": "synthetic", "trigger_state": {}},
                "SYNTH-L2": {"since_iter": 91, "reason": "synthetic", "trigger_state": {}},
            },
        )

        # Env: glob root pointed at synthetic, but fallback NOT enabled.
        # Also clear workspace_path to ensure we are testing the "no explicit
        # workspace" branch (the hermetic guard relies on BOTH conditions).
        env_patch = {
            "AUDITOOOR_WORKTREE_GLOB_ROOT": str(synth_root),
        }
        # Make sure the allow flag is NOT set
        with mock.patch.dict(os.environ, env_patch, clear=False):
            os.environ.pop("AUDITOOOR_ALLOW_WORKTREE_GLOB_FALLBACK", None)
            result = self.vault.vault_lane_cooldown_check(
                workspace_path="",  # explicitly empty -> falls into default branch
            )

        # Because the allow flag is off, glob must not have fired.
        # The default workspace (~/audits/spark) almost certainly has no state
        # file in test environments, so we expect empty + error.
        self.assertEqual(result.get("total_cooldowns"), 0)
        self.assertEqual(result.get("lanes"), [])
        # Importantly, none of the synthetic lane ids should leak
        lane_ids = {lane.get("lane_id") for lane in result.get("lanes", [])}
        self.assertNotIn("SYNTH-L1", lane_ids)
        self.assertNotIn("SYNTH-L2", lane_ids)

    # ------------------------------------------------------------------
    # Test 10: Opt-in glob fallback via env var enables cross-worktree
    # ------------------------------------------------------------------

    def test_worktree_glob_fallback_enabled_by_env_var(self):
        """With AUDITOOOR_ALLOW_WORKTREE_GLOB_FALLBACK=1 set AND no explicit
        workspace_path, the glob fallback finds state files in the configured
        glob root. synthetic_fixture: true.
        """
        # Build a synthetic glob root with one worktree that has a state file
        # containing 20+ cooldowns (mirroring the original concurrent-agent
        # leakage scenario).
        synth_root = self.root / "synthetic-worktrees"
        synth_ws = synth_root / "synth-host-a"
        (synth_ws / ".auditooor").mkdir(parents=True)
        cooldowns = {
            f"SYNTH-LANE-{i:02d}": {
                "since_iter": 50 + i,
                "reason": f"synthetic cooldown #{i}",
                "trigger_state": {"synthetic_fixture": True},
            }
            for i in range(20)
        }
        _write_state(
            synth_ws / ".auditooor" / "spark_hunt_loop_state.json",
            iteration=99,
            cooldowns=cooldowns,
        )

        env_patch = {
            "AUDITOOOR_ALLOW_WORKTREE_GLOB_FALLBACK": "1",
            "AUDITOOOR_WORKTREE_GLOB_ROOT": str(synth_root),
        }
        with mock.patch.dict(os.environ, env_patch, clear=False):
            result = self.vault.vault_lane_cooldown_check(
                workspace_path="",  # explicitly empty -> default branch
            )

        # The 20-cooldown synthetic state file must have been discovered.
        self.assertEqual(result.get("total_cooldowns"), 20)
        self.assertEqual(len(result.get("lanes", [])), 20)
        lane_ids = {lane["lane_id"] for lane in result["lanes"]}
        self.assertIn("SYNTH-LANE-00", lane_ids)
        self.assertIn("SYNTH-LANE-19", lane_ids)

    # ------------------------------------------------------------------
    # Test 11: Explicit workspace_path always suppresses glob fallback
    # ------------------------------------------------------------------

    def test_explicit_workspace_path_suppresses_glob_even_when_env_set(self):
        """Even when AUDITOOOR_ALLOW_WORKTREE_GLOB_FALLBACK=1 is set, an
        explicit workspace_path argument must scope the search to that
        workspace and refuse to fall through to the host glob.
        synthetic_fixture: true.
        """
        # Populate a synthetic glob root that WOULD leak if reached
        synth_root = self.root / "synthetic-worktrees"
        synth_ws = synth_root / "synth-host-b"
        (synth_ws / ".auditooor").mkdir(parents=True)
        _write_state(
            synth_ws / ".auditooor" / "spark_hunt_loop_state.json",
            iteration=99,
            cooldowns={
                "SHOULD-NOT-LEAK": {"since_iter": 1, "reason": "leak guard", "trigger_state": {}},
            },
        )

        env_patch = {
            "AUDITOOOR_ALLOW_WORKTREE_GLOB_FALLBACK": "1",
            "AUDITOOOR_WORKTREE_GLOB_ROOT": str(synth_root),
        }
        # self.workspace has no state file (test 3 fixture pattern)
        self.assertFalse(self.state_file.exists())

        with mock.patch.dict(os.environ, env_patch, clear=False):
            result = self.vault.vault_lane_cooldown_check(
                workspace_path=str(self.workspace),  # explicit -> suppresses glob
            )

        # No leakage from synthetic glob root
        self.assertEqual(result.get("total_cooldowns"), 0)
        self.assertEqual(result.get("lanes"), [])
        lane_ids = {lane.get("lane_id") for lane in result.get("lanes", [])}
        self.assertNotIn("SHOULD-NOT-LEAK", lane_ids)

    # ------------------------------------------------------------------
    # Test: vault_lane_cooldown_check appears in TOOL_SCHEMAS
    # ------------------------------------------------------------------

    def test_callable_in_tool_schemas(self):
        """vault_lane_cooldown_check must appear in TOOL_SCHEMAS list."""
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_lane_cooldown_check", names)


if __name__ == "__main__":
    unittest.main()
