"""Tests for Phase-0 roadmap coordination MCP callables."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


ROADMAP_FIXTURE = """# Consolidated Roadmap for Codex - test

## PHASE 0 - MCP enforcement callable

### 0.1 Build `vault_active_roadmap` MCP callable

### 0.2 Build `vault_known_dead_ends` MCP callable

### 0.3 Update `~/.claude/CLAUDE.md` Layer-1 sequence

### 0.4 Atomic state file

## PHASE I - Plumbing

### I.1 Wire pillar callables into vault_dispatch_brief_skeleton
**Owner**: CLAUDE | **Effort**: small

### I.3 Multi-MEMORY_PATH in tools/obsidian-vault-sync.py
**Owner**: either | **Effort**: medium

## PHASE II - New Capabilities

### II.1 SMIV-FDASR-WIRE
**Owner**: CODEX

### II.5 Predicate library domain coverage
**Owner**: CODEX

### II.2 DNS
**Owner**: CLAUDE

### II.3 AHDH
**Owner**: CLAUDE

### II.4 PFORPD
**Owner**: CLAUDE

## PHASE III - Continue master plan

### III.1 Phase B Gate #1
"""


class VaultActiveRoadmapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-active-roadmap-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.roadmap_path = self.root / "roadmap.md"
        self.state_path = self.root / "state.json"
        self.roadmap_path.write_text(ROADMAP_FIXTURE, encoding="utf-8")
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _args(self, **extra):
        base = {
            "side": "codex",
            "roadmap_path": str(self.roadmap_path),
            "state_path": str(self.state_path),
        }
        base.update(extra)
        return base

    def test_preview_creates_state_and_returns_phase0_first(self) -> None:
        result = self.vault.vault_active_roadmap(**self._args(claim=False))

        self.assertEqual(result["schema"], "auditooor.vault_active_roadmap.v1")
        self.assertEqual(result["next_item_id"], "PHASE-0.1")
        self.assertTrue(result["dependencies_met"])
        self.assertFalse(result["claim"])
        self.assertTrue(self.state_path.exists())
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertIn("PHASE-0.1", state["items"])
        self.assertEqual(state["items"]["PHASE-0.1"]["status"], "PLANNED")

    def test_claim_hides_lane_from_other_side_and_result_releases(self) -> None:
        claimed = self.vault.vault_active_roadmap(**self._args(claim=True, item_id="PHASE-0.1"))

        token = claimed["claim_token"]
        self.assertTrue(token)
        self.assertIsNotNone(token)
        self.assertEqual(claimed["mutation"]["reason"], "claim_recorded")
        self.assertEqual(claimed["next_item"]["display_status"], "IN-FLIGHT-BY-codex")

        claude = self.vault.vault_active_roadmap(
            side="claude",
            roadmap_path=str(self.roadmap_path),
            state_path=str(self.state_path),
            claim=False,
            item_id="PHASE-0.1",
        )
        self.assertEqual(claude["next_item_id"], "PHASE-0.1")
        self.assertEqual(claude["next_item"]["display_status"], "IN-FLIGHT-BY-codex")
        self.assertEqual(claude["next_item"]["claim_token"], token)

    def test_result_write_rejects_wrong_claim_token_and_preserves_in_flight_state(self) -> None:
        claimed = self.vault.vault_active_roadmap(**self._args(claim=True, item_id="PHASE-0.1"))
        token = claimed["claim_token"]

        rejected = self.vault.vault_active_roadmap(
            **self._args(
                item_id="PHASE-0.1",
                claim_token="bogus-token",
                result_status="LANDED",
            )
        )

        self.assertEqual(rejected["mutation"]["reason"], "claim_token_mismatch")
        self.assertFalse(rejected["mutation"]["accepted"])
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        row = state["items"]["PHASE-0.1"]
        self.assertEqual(row["status"], "IN-FLIGHT")
        self.assertEqual(row["claim_token"], claimed["claim_token"])
        self.assertEqual(row["owner"], "codex")

        landed = self.vault.vault_active_roadmap(
            **self._args(
                claim=False,
                item_id="PHASE-0.1",
                claim_token=token,
                result_status="LANDED",
            )
        )
        self.assertEqual(landed["mutation"]["reason"], "result_recorded")
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["items"]["PHASE-0.1"]["status"], "LANDED")
        self.assertIsNone(state["items"]["PHASE-0.1"]["claim_token"])

    def test_dependencies_block_phase_i_until_phase0_landed(self) -> None:
        blocked = self.vault.vault_active_roadmap(**self._args(claim=True, item_id="PHASE-I.3"))

        self.assertFalse(blocked["mutation"]["accepted"])
        self.assertEqual(blocked["mutation"]["reason"], "dependencies_not_met")
        self.assertFalse(blocked["next_item"]["dependencies_met"])
        self.assertIn("PHASE-0.1", blocked["next_item"]["missing_dependencies"])

    def test_owner_labels_are_advisory_codex_can_claim_claude_lanes(self) -> None:
        for item_id in ("PHASE-0.1", "PHASE-0.2", "PHASE-0.3", "PHASE-0.4"):
            claimed = self.vault.vault_active_roadmap(**self._args(claim=True, item_id=item_id))
            self.vault.vault_active_roadmap(
                **self._args(
                    item_id=item_id,
                    claim_token=claimed["claim_token"],
                    result_status="LANDED",
                )
            )

        preview = self.vault.vault_active_roadmap(**self._args(claim=False))
        self.assertEqual(preview["next_item_id"], "PHASE-I.1")
        self.assertEqual(preview["next_item"]["preferred_owner"], "claude")
        self.assertIn("Preferred owner (advisory): claude", preview["lane_brief_template"])
        self.assertIn("Codex may claim and execute every lane", preview["lane_brief_template"])

        claimed = self.vault.vault_active_roadmap(**self._args(claim=True, item_id="PHASE-I.1"))
        self.assertEqual(claimed["mutation"]["reason"], "claim_recorded")
        self.assertEqual(claimed["next_item"]["display_status"], "IN-FLIGHT-BY-codex")

    def test_phase_ii5_sorts_before_dns_ahdh_pforpd(self) -> None:
        for item_id in ("PHASE-0.1", "PHASE-0.2", "PHASE-0.3", "PHASE-0.4"):
            claimed = self.vault.vault_active_roadmap(**self._args(claim=True, item_id=item_id))
            self.vault.vault_active_roadmap(
                **self._args(
                    item_id=item_id,
                    claim_token=claimed["claim_token"],
                    result_status="LANDED",
                )
            )
        for item_id in ("PHASE-I.1", "PHASE-I.3", "PHASE-II.1"):
            claimed = self.vault.vault_active_roadmap(**self._args(claim=True, item_id=item_id))
            self.vault.vault_active_roadmap(
                **self._args(
                    item_id=item_id,
                    claim_token=claimed["claim_token"],
                    result_status="LANDED",
                )
            )

        preview = self.vault.vault_active_roadmap(**self._args(claim=False))

        self.assertEqual(preview["next_item_id"], "PHASE-II.5")
        catalog_ids = [
            item["item_id"]
            for item in self.vault._active_roadmap_catalog(self.roadmap_path)
        ]
        self.assertLess(
            catalog_ids.index("PHASE-II.5"),
            catalog_ids.index("PHASE-II.2"),
        )

    def test_phase_ii6_subitems_are_included_and_ordered(self) -> None:
        roadmap_path = self.root / "roadmap_ii6.md"
        roadmap_path.write_text(
            """# Consolidated Roadmap for Codex - test

## PHASE II - New Capabilities

### II.5 Predicate library domain coverage (CAP-021 generalized, priority before II.2-II.4)
**Owner**: CODEX

### II.6 Predicate naming-overshoot fix (slither IR + LLM gate + cross-language AST)
**Owner**: CODEX | **Effort**: 5-7 days / 3 sub-items | **Source**: `reports/v3_iter_2026-05-24/PREDICATE_NAMING_OVERSHOOT_FIX_PLAN.md`

1. **II.6.A WIRE** (1-2 days, highest leverage): wire `tools/slither_predicates.py` IR predicates into `P1_INVARIANT_PREDICATES` in `tools/live-target-intelligence-report.py`, with the current regex/name heuristics retained as fallback for non-Solidity or missing-Slither contexts.
2. **II.6.C LLM 2-stage semantic gate** (1 day): add a `tools/llm-dispatch.py` backed gate so topical matches are LLM-verified as `SEMANTIC-MATCH`, retained topical, or marked false-positive, with default cost capped around $1/report and cached by code+predicate hash.
3. **II.6.B Cross-language AST s-expression queries** (3-4 days): add `Language.query()` s-expression support to `tools/ast-engine.py` for Rust/Go/Move structural predicates, so non-Solidity bridge/cosmos/substrate/move targets can match structure rather than identifier names.

### II.7 Enforcement fix plan (active hard-block wiring)
**Owner**: CODEX
""",
            encoding="utf-8",
        )

        catalog = self.vault._active_roadmap_catalog(roadmap_path)
        item_ids = [item["item_id"] for item in catalog]

        self.assertEqual(
            item_ids,
            [
                "PHASE-II.5",
                "PHASE-II.6",
                "PHASE-II.6.A",
                "PHASE-II.6.C",
                "PHASE-II.6.B",
                "PHASE-II.7",
            ],
        )
        self.assertEqual(catalog[2]["preferred_owner"], "codex")
        self.assertEqual(catalog[2]["phase_title"], "New Capabilities")
        self.assertEqual(catalog[3]["title"], "LLM 2-stage semantic gate")
        self.assertEqual(catalog[4]["title"], "Cross-language AST s-expression queries")

    def test_state_merge_preserves_plan_derived_subitems(self) -> None:
        self.state_path.write_text(
            json.dumps(
                {
                    "schema": "auditooor.consolidated_roadmap_state.v1",
                    "iter": "2026-05-24",
                    "updated_at": "2026-05-25T00:00:00Z",
                    "items": {
                        "PHASE-II.6.A": {
                            "status": "PARTIAL",
                            "owner": "codex",
                            "claim_token": "subitem-token",
                            "claimed_at": "2026-05-25T00:00:00Z",
                            "expires_at": "2026-05-26T00:00:00Z",
                            "result": None,
                            "result_summary": "Fine-grained state row from plan audit.",
                            "result_remember": None,
                            "completed_at": None,
                            "completed_by": None,
                        }
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        self.vault.vault_active_roadmap(**self._args(claim=False))

        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertIn("PHASE-0.1", state["items"])
        self.assertIn("PHASE-II.6.A", state["items"])
        self.assertEqual(state["items"]["PHASE-II.6.A"]["status"], "PARTIAL")
        self.assertEqual(state["items"]["PHASE-II.6.A"]["claim_token"], "subitem-token")

    def test_known_dead_ends_filters_query(self) -> None:
        dead_ends = self.root / "known_dead_ends.jsonl"
        row = {
            "schema": "auditooor.known_dead_end.v1",
            "workspace": "hyperbridge",
            "attack_class": "template-noise",
            "candidate_pattern": "top-n source verification null",
            "reason": "Repeated V2/V3/V5 source reads produced no actionable finding.",
            "verification_tier": "tier-2-verified-public-archive",
        }
        dead_ends.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")

        result = self.vault.vault_known_dead_ends(
            workspace="hyperbridge",
            candidate_pattern="source verification",
            dead_ends_path=str(dead_ends),
        )

        self.assertEqual(result["schema"], "auditooor.vault_known_dead_ends.v1")
        self.assertFalse(result["degraded"])
        self.assertEqual(result["returned_count"], 1)
        self.assertEqual(result["dead_ends"][0]["workspace"], "hyperbridge")

    def test_tool_schemas_and_cli_dispatch(self) -> None:
        names = {tool["name"] for tool in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_active_roadmap", names)
        self.assertIn("vault_known_dead_ends", names)

        proc = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--repo-root",
                str(self.root),
                "--vault-dir",
                str(self.vault_dir),
                "--call",
                "vault_active_roadmap",
                "--args",
                json.dumps(
                    {
                        "side": "codex",
                        "roadmap_path": str(self.roadmap_path),
                        "state_path": str(self.state_path),
                    }
                ),
            ],
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.vault_active_roadmap.v1")
        self.assertIn("context_pack_id", payload)

    # ------------------------------------------------------------------
    # Fix 1: ad-hoc item_id claim token issuance (PHASE-II.11.1 pattern)
    # ------------------------------------------------------------------

    def test_fix1_adhoc_item_id_claim_returns_non_null_token(self) -> None:
        """claim:true with a well-formed item_id not in the catalog MD should
        return a non-null claim_token with mutation.accepted=true."""
        result = self.vault.vault_active_roadmap(
            **self._args(claim=True, item_id="PHASE-II.11.1-CLAIM-TOKEN-FIX")
        )
        self.assertTrue(result["mutation"]["accepted"], result["mutation"])
        self.assertEqual(result["mutation"]["reason"], "claim_recorded")
        self.assertIsNotNone(result["claim_token"])
        self.assertGreater(len(result["claim_token"]), 8)
        self.assertIsNotNone(result["expires_at"])
        # State file must record the ad-hoc item
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertIn("PHASE-II.11.1-CLAIM-TOKEN-FIX", state["items"])
        self.assertEqual(state["items"]["PHASE-II.11.1-CLAIM-TOKEN-FIX"]["status"], "IN-FLIGHT")

    def test_fix1_adhoc_item_second_claim_returns_in_flight(self) -> None:
        """Claiming an ad-hoc item twice (different callers) - second call should
        return in_flight_by:first-claimant, not issue a second token."""
        first = self.vault.vault_active_roadmap(
            **self._args(claim=True, item_id="PHASE-II.11.6-META-FIX", side="codex")
        )
        self.assertTrue(first["mutation"]["accepted"])
        first_token = first["claim_token"]

        second = self.vault.vault_active_roadmap(
            **self._args(claim=True, item_id="PHASE-II.11.6-META-FIX", side="claude")
        )
        self.assertFalse(second["mutation"]["accepted"])
        self.assertIn("in_flight_by", second["mutation"]["reason"])
        # Token visible to the second caller should be the first token
        self.assertEqual(second["next_item"]["claim_token"], first_token)

    def test_fix1_adhoc_item_release_with_valid_token(self) -> None:
        """claim:false + valid claim_token + result_status=LANDED releases the
        ad-hoc item atomically."""
        claimed = self.vault.vault_active_roadmap(
            **self._args(claim=True, item_id="PHASE-II.11.2-RELEASE-FIX")
        )
        token = claimed["claim_token"]
        self.assertIsNotNone(token)

        released = self.vault.vault_active_roadmap(
            **self._args(
                item_id="PHASE-II.11.2-RELEASE-FIX",
                claim_token=token,
                result_status="LANDED",
                result_summary="Release flow verified for ad-hoc lane",
            )
        )
        self.assertTrue(released["mutation"]["accepted"], released["mutation"])
        self.assertEqual(released["mutation"]["reason"], "result_recorded")
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        row = state["items"]["PHASE-II.11.2-RELEASE-FIX"]
        self.assertEqual(row["status"], "LANDED")
        self.assertIsNone(row["claim_token"])
        self.assertIsNone(row["owner"])

    def test_fix1_expired_adhoc_claim_auto_releases(self) -> None:
        """An ad-hoc item whose claim has already expired in the state file
        should be auto-released on the next call, allowing a new claim.
        (TTL min is 60s, so we write an expired entry directly rather than
        sleeping for 61 seconds.)"""
        import datetime as _datetime

        item_id = "PHASE-II.11.3-TTL-FIX"
        # Write a state file with an already-expired claim for the ad-hoc item
        past = _datetime.datetime.now(_datetime.timezone.utc) - _datetime.timedelta(seconds=120)
        self.state_path.write_text(
            json.dumps(
                {
                    "schema": "auditooor.consolidated_roadmap_state.v1",
                    "iter": "2026-05-24",
                    "updated_at": past.isoformat().replace("+00:00", "Z"),
                    "items": {
                        item_id: {
                            "status": "IN-FLIGHT",
                            "owner": "codex",
                            "claim_token": "expired-token-xyz",
                            "claimed_at": (past - _datetime.timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
                            "expires_at": past.isoformat().replace("+00:00", "Z"),
                            "result": None,
                            "result_summary": None,
                            "result_remember": None,
                            "completed_at": None,
                            "completed_by": None,
                        }
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        # Calling with claim=True should auto-expire the stale entry and issue
        # a fresh token.
        reclaimed = self.vault.vault_active_roadmap(
            **self._args(claim=True, item_id=item_id)
        )
        self.assertTrue(reclaimed["mutation"]["accepted"], reclaimed["mutation"])
        self.assertEqual(reclaimed["mutation"]["reason"], "claim_recorded")
        self.assertIsNotNone(reclaimed["claim_token"])
        # Must be a different token from the expired one
        self.assertNotEqual(reclaimed["claim_token"], "expired-token-xyz")

    def test_fix1_invalid_claim_token_rejected(self) -> None:
        """Supplying a bogus claim_token to result_status=LANDED must return
        claim_token_mismatch and leave the item IN-FLIGHT."""
        claimed = self.vault.vault_active_roadmap(
            **self._args(claim=True, item_id="PHASE-II.11.4-BADTOKEN-FIX")
        )
        self.assertTrue(claimed["mutation"]["accepted"])

        bad = self.vault.vault_active_roadmap(
            **self._args(
                item_id="PHASE-II.11.4-BADTOKEN-FIX",
                claim_token="not-the-real-token-0000000000",
                result_status="LANDED",
            )
        )
        self.assertFalse(bad["mutation"]["accepted"])
        self.assertEqual(bad["mutation"]["reason"], "claim_token_mismatch")
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["items"]["PHASE-II.11.4-BADTOKEN-FIX"]["status"], "IN-FLIGHT")

    # ------------------------------------------------------------------
    # Fix 6: next_item returns title + description from MD parse
    # ------------------------------------------------------------------

    def test_fix6_next_item_returns_description_field(self) -> None:
        """next_item response must include a non-empty 'description' field
        extracted from the first prose paragraph in the roadmap MD."""
        roadmap_with_desc = self.root / "roadmap_desc.md"
        roadmap_with_desc.write_text(
            """# Consolidated Roadmap

## PHASE 0 - MCP enforcement callable

### 0.1 Build `vault_active_roadmap` MCP callable

This is the first-paragraph description sentence for testing purposes.
It should appear in the description field of the next_item response.

**Owner**: either

### 0.2 Build `vault_known_dead_ends` MCP callable

Second item has a different description here.
""",
            encoding="utf-8",
        )
        result = self.vault.vault_active_roadmap(
            side="codex",
            roadmap_path=str(roadmap_with_desc),
            state_path=str(self.state_path),
            claim=False,
        )
        ni = result.get("next_item", {})
        self.assertIn("description", ni, "next_item must have a 'description' key")
        desc = ni["description"]
        self.assertIsNotNone(desc)
        # The description must contain the first-paragraph text
        self.assertIn("first-paragraph description sentence", desc)
        # Must not be empty
        self.assertGreater(len(desc.strip()), 0)


if __name__ == "__main__":
    unittest.main()
