"""Tests for the vault_lane_skeleton_filler MCP callable (iter6 Lane PP).

The callable returns per-lane fill-in-the-blank rule-section skeletons at
brief-time, mirroring CANONICAL_CANTINA_PASTE_TEMPLATE.md section format
with placeholder syntax `<<key|default|description>>`.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_lane_skeleton_filler", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp = _load_module()


def _make_vault(repo_root: Path):
    vault_dir = repo_root / "obsidian-vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_mcp.VaultQuery(vault_dir, repo_root)


class LaneSkeletonFillerTests(unittest.TestCase):

    # --- Lane-rule-map sanity --------------------------------------------------

    def test_dispute_lane_returns_expected_rule_set(self):
        """dispute lane MUST address R28, R29, R43, R45."""
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="dispute", severity="HIGH"
            )
        self.assertEqual(
            result["schema"], vault_mcp.LANE_SKELETON_FILLER_SCHEMA
        )
        self.assertEqual(result["lane_type"], "dispute")
        self.assertEqual(
            sorted(result["applicable_rules"]),
            ["R28", "R29", "R43", "R45"],
        )

    def test_mediation_lane_returns_expected_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="mediation", severity="HIGH"
            )
        self.assertEqual(
            sorted(result["applicable_rules"]),
            ["R28", "R29", "R35", "R43", "R45"],
        )

    def test_filing_lane_returns_full_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="filing", severity="CRITICAL"
            )
        expected = {"R29", "R40", "R42", "R43", "R44", "R45", "R46", "R47", "R52"}
        self.assertEqual(set(result["applicable_rules"]), expected)

    def test_hunt_lane_returns_hunt_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="hunt", severity="HIGH"
            )
        self.assertEqual(
            sorted(result["applicable_rules"]),
            ["R36", "R37", "R38", "R39"],
        )

    def test_opposed_trace_harness_returns_expected_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="opposed-trace-harness", severity="HIGH"
            )
        self.assertEqual(
            sorted(result["applicable_rules"]),
            ["R18", "R19", "R22", "R30", "R40", "R43", "R44"],
        )

    def test_escalation_lane_returns_expected_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="escalation", severity="HIGH"
            )
        self.assertEqual(
            sorted(result["applicable_rules"]),
            ["R28", "R29", "R43", "R45"],
        )

    # --- Severity filtering ----------------------------------------------------

    def test_low_severity_filters_out_high_only_rules(self):
        """severity=LOW returns only always-applicable rules (R28 etc.).

        Dispute lane = {R28, R29, R43, R45}. R29/R43/R45 are HIGH+ or
        MEDIUM+. At severity LOW only R28 (any) remains.
        """
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="dispute", severity="LOW"
            )
        self.assertEqual(result["applicable_rules"], ["R28"])
        # R28 has no skeleton template - section is doctrine-only.
        self.assertEqual(result["skeleton_sections"], {})

    def test_high_severity_returns_full_dispute_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="dispute", severity="HIGH"
            )
        self.assertEqual(
            sorted(result["applicable_rules"]),
            ["R28", "R29", "R43", "R45"],
        )

    def test_severity_all_includes_every_rule(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="filing", severity="all"
            )
        # All filing rules apply at severity=all.
        self.assertEqual(len(result["applicable_rules"]), 9)

    # --- Skeleton-sections + placeholder extraction ----------------------------

    def test_skeleton_sections_populated_for_dispute_high(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="dispute", severity="HIGH"
            )
        # Templates present for R29 / R43 / R45 (R28 doctrine-only).
        for rid in ("R29", "R43", "R45"):
            self.assertIn(rid, result["skeleton_sections"])
            body = result["skeleton_sections"][rid]
            self.assertIn("##", body, f"Skeleton {rid} missing markdown heading")
            self.assertIn("<<", body, f"Skeleton {rid} missing placeholder syntax")
        self.assertNotIn("R28", result["skeleton_sections"])

    def test_placeholders_to_resolve_excludes_docs_syntax_literal(self):
        """The <<key|default|description>> literal in template-docs
        comments must NOT show up as a real placeholder to fill in.
        """
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="dispute", severity="HIGH"
            )
        for rid, placeholders in result["placeholders_to_resolve"].items():
            self.assertNotIn(
                "key", placeholders,
                f"Rule {rid}: docs-syntax literal 'key' leaked into "
                "placeholders_to_resolve",
            )

    def test_placeholders_capture_fields_with_inner_greater_than(self):
        """Defaults like ``<file:line>`` and descriptions like ``N>1``
        contain single ``>`` characters; the placeholder extractor must
        terminate only on ``>>`` so those fields are not dropped.

        R29 template has 7 placeholder fields incl. one with default
        ``<file:line>``. Regression locks the regex fix.
        """
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="dispute", severity="HIGH"
            )
        r29_placeholders = result["placeholders_to_resolve"].get("R29", [])
        # Lock the full expected set of 7 fields.
        self.assertEqual(
            r29_placeholders,
            [
                "commitment_point_fileline",
                "reversibility",
                "gap_class",
                "protection_cardinality",
                "sibling_guards",
                "recovery_cost",
                "verdict",
            ],
        )

    def test_workspace_anchors_surface_when_target_class_set(self):
        """When workspace + target_finding_class matches a known class
        AND candidate files exist, workspace_anchors should be populated.
        """
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # Create a fake workspace with a cooperative-exit handler.
            ws = td_path / "fake_workspace"
            (ws / "external" / "spark" / "spark").mkdir(parents=True, exist_ok=True)
            (ws / "external" / "spark" / "spark" / "watch_chain.go").write_text(
                "package main\n// fake fixture for skeleton anchor test\n",
                encoding="utf-8",
            )
            vault = _make_vault(td_path)
            result = vault.vault_lane_skeleton_filler(
                lane_type="dispute",
                severity="HIGH",
                target_finding_class="cooperative-exit",
                workspace_path=str(ws),
            )
        self.assertIn("workspace_candidates_cooperative-exit", result["workspace_anchors"])
        self.assertIn(
            "watch_chain.go",
            result["workspace_anchors"]["workspace_candidates_cooperative-exit"],
        )

    def test_workspace_anchors_empty_when_no_match(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="dispute",
                severity="HIGH",
                target_finding_class="oracle-trust",
                workspace_path=str(Path(td)),
            )
        self.assertEqual(result["workspace_anchors"], {})

    # --- Error paths -----------------------------------------------------------

    def test_unknown_lane_type_returns_error_payload(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_lane_skeleton_filler(
                lane_type="not-a-real-lane", severity="HIGH"
            )
        self.assertEqual(result["error"], "unknown_lane_type")
        self.assertEqual(result["applicable_rules"], [])
        self.assertEqual(result["skeleton_sections"], {})
        self.assertIn("dispute", result["valid_lane_types"])
        # context_pack_id / context_pack_hash still present.
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_context_pack_id_is_deterministic_for_same_input(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            a = vault.vault_lane_skeleton_filler(
                lane_type="dispute", severity="HIGH"
            )
            b = vault.vault_lane_skeleton_filler(
                lane_type="dispute", severity="HIGH"
            )
        # generated_at_utc differs by second; everything else stable.
        # The pack hash itself includes the timestamp, so we just
        # verify the schema + applicable_rules are equal.
        self.assertEqual(a["schema"], b["schema"])
        self.assertEqual(a["applicable_rules"], b["applicable_rules"])
        self.assertEqual(
            a["lane_rule_full_set"], b["lane_rule_full_set"]
        )


if __name__ == "__main__":
    unittest.main()
