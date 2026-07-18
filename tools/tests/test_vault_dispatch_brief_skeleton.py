"""Tests for the vault_dispatch_brief_skeleton MCP callable
(iter14 Lane LLLL).

The callable composes vault_codified_rules_digest + vault_lane_skeleton_filler
+ vault_resume_context + the dispatch pillar callables + workspace SEVERITY.md
parser + originality / busywork / pre-submit-preview heuristics into a single
payload. It MUST:

  * always return the mandated top-level fields
  * key off lane_type to produce the expected rule set (delegates to
    LANE_SKELETON_FILLER_LANE_MAP)
  * keyword-map free-form lane_ids (``dispute-cantina-192``,
    ``H1-coop-exit``) to canonical lane_types
  * resolve severity 'auto' -> HIGH
  * pull workspace context when a valid path is given; degrade
    gracefully (no errors, empty workspace-specific fields) when path
    is missing or invalid
  * compose without raising even when sub-callables fail
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
        "vault_mcp_server_dispatch_brief_skeleton", MODULE_PATH
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


REQUIRED_TOP_LEVEL_FIELDS = [
    "context_pack_id",
    "context_pack_hash",
    "lane_specific_rules",
    "skeleton_sections",
    "recall_summary",
    "rubric_excerpt",
    "originality_anchors",
    "pillar_context",
    "routine_violation_warnings",
    "busywork_refusals",
    "pre_submit_preview",
    "usage_note",
]


class DispatchBriefSkeletonTests(unittest.TestCase):

    # --- 1. Schema + composition -----------------------------------------

    def test_payload_contains_all_mandated_fields(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="dispute", severity="HIGH"
            )
        for field in REQUIRED_TOP_LEVEL_FIELDS:
            self.assertIn(field, result, f"missing top-level field: {field}")
        self.assertEqual(
            result["schema"], vault_mcp.DISPATCH_BRIEF_SKELETON_SCHEMA
        )
        self.assertEqual(result["kind"], "dispatch_brief_skeleton")

    def test_context_pack_id_format(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="filing", severity="HIGH"
            )
        self.assertTrue(
            result["context_pack_id"].startswith(
                f"{vault_mcp.DISPATCH_BRIEF_SKELETON_SCHEMA}:dispatch_brief:"
            )
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)  # sha256 hex

    # --- 2. Per-lane rule sets -------------------------------------------

    def test_dispute_lane_returns_dispute_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="dispute", severity="HIGH"
            )
        # dispute set = {R28, R29, R43, R45}
        self.assertEqual(
            sorted(result["lane_specific_rules"]),
            ["R28", "R29", "R43", "R45"],
        )

    def test_filing_lane_returns_filing_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="filing", severity="HIGH"
            )
        expected = {"R29", "R40", "R42", "R43", "R44", "R45", "R46", "R47", "R52"}
        self.assertEqual(set(result["lane_specific_rules"]), expected)

    def test_mediation_lane_returns_mediation_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="mediation", severity="HIGH"
            )
        self.assertEqual(
            sorted(result["lane_specific_rules"]),
            ["R28", "R29", "R35", "R43", "R45"],
        )

    def test_hunt_lane_returns_hunt_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="hunt", severity="HIGH"
            )
        self.assertEqual(
            sorted(result["lane_specific_rules"]),
            ["R36", "R37", "R38", "R39"],
        )

    def test_opposed_trace_lane_returns_opposed_trace_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="opposed-trace-harness", severity="HIGH"
            )
        self.assertEqual(
            sorted(result["lane_specific_rules"]),
            ["R18", "R19", "R22", "R30", "R40", "R43", "R44"],
        )

    def test_escalation_lane_returns_escalation_rule_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="escalation", severity="HIGH"
            )
        self.assertEqual(
            sorted(result["lane_specific_rules"]),
            ["R28", "R29", "R43", "R45"],
        )

    # --- 3. Severity filtering -------------------------------------------

    def test_severity_low_returns_only_always_applicable_rules(self):
        """LOW filters out HIGH-min rules. Filing rule set under LOW
        keeps R41/R52 (any) and drops R40+ which require MEDIUM+."""
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="filing", severity="LOW"
            )
        for rid in result["lane_specific_rules"]:
            # Every rule returned must apply at LOW (its min_severity
            # is "any") - verify against the underlying map.
            min_sev = vault_mcp.LANE_SKELETON_FILLER_RULE_MIN_SEVERITY.get(
                rid, "any"
            )
            self.assertEqual(min_sev, "any", f"{rid} should not be in LOW result")

    def test_severity_critical_returns_comprehensive_set(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="filing", severity="CRITICAL"
            )
        # CRITICAL ⊇ HIGH ⊇ MEDIUM ⊇ LOW for this lane.
        self.assertGreaterEqual(
            len(result["lane_specific_rules"]),
            len(
                vault.vault_dispatch_brief_skeleton(
                    lane_type="filing", severity="LOW"
                )["lane_specific_rules"]
            ),
        )

    def test_severity_auto_resolves_to_high(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result_auto = vault.vault_dispatch_brief_skeleton(
                lane_type="dispute", severity="auto"
            )
            result_high = vault.vault_dispatch_brief_skeleton(
                lane_type="dispute", severity="HIGH"
            )
        self.assertEqual(result_auto["severity"], "HIGH")
        self.assertEqual(
            sorted(result_auto["lane_specific_rules"]),
            sorted(result_high["lane_specific_rules"]),
        )

    # --- 4. Free-form lane_id keyword mapping ----------------------------

    def test_free_form_lane_id_dispute_cantina_192(self):
        """`dispute-cantina-192` keyword-maps to ``dispute``."""
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="dispute-cantina-192", severity="HIGH"
            )
        self.assertEqual(result["lane_type"], "dispute")
        self.assertEqual(result["lane_type_raw"], "dispute-cantina-192")
        self.assertEqual(
            sorted(result["lane_specific_rules"]),
            ["R28", "R29", "R43", "R45"],
        )

    def test_free_form_lane_id_hunt_keyword(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="H1-coop-exit", severity="HIGH"
            )
        self.assertEqual(result["lane_type"], "hunt")

    def test_free_form_lane_id_escalation_keyword_before_dispute(self):
        """Escalation keyword takes precedence over dispute (escalation
        is the more specific subtype)."""
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="refile-walk-back", severity="HIGH"
            )
        self.assertEqual(result["lane_type"], "escalation")

    # --- 5. Workspace path handling --------------------------------------

    def test_missing_workspace_path_gracefully_degrades(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="filing", severity="HIGH"
            )
        # All workspace-specific fields exist but are empty.
        self.assertFalse(result["workspace_resolved"])
        self.assertEqual(result["rubric_excerpt"]["rows"], [])
        self.assertFalse(result["rubric_excerpt"]["parsed"])
        self.assertEqual(result["originality_anchors"], [])
        # recall_summary is still a string (may say "no recall ...").
        self.assertIsInstance(result["recall_summary"], str)

    def test_invalid_workspace_path_does_not_raise(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="filing",
                severity="HIGH",
                workspace_path="/nonexistent/path/zzz",
            )
        self.assertFalse(result["workspace_resolved"])
        # Still returns all 10 fields.
        for field in REQUIRED_TOP_LEVEL_FIELDS:
            self.assertIn(field, result)

    def test_workspace_severity_md_parsed(self):
        """SEVERITY.md in a workspace is parsed into rubric_excerpt rows."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # Build a minimal workspace with a SEVERITY.md.
            ws = tdp / "ws"
            ws.mkdir()
            (ws / "SEVERITY.md").write_text(
                "# Severity rubric\n\n"
                "### Critical (Blockchain/DLT)\n\n"
                "| ID | Listed-impact sentence (verbatim) | Reward |\n"
                "|---|---|---|\n"
                "| CRIT-1 | Direct loss of funds | 10% of funds-at-risk |\n\n"
                "### High (Blockchain/DLT)\n\n"
                "| ID | Listed-impact sentence (verbatim) | Reward |\n"
                "|---|---|---|\n"
                "| HIGH-1 | RPC API crash affecting projects | USD 25,000 flat |\n",
                encoding="utf-8",
            )
            vault = _make_vault(tdp)
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="filing",
                severity="HIGH",
                workspace_path=str(ws),
            )
        self.assertTrue(result["workspace_resolved"])
        self.assertTrue(result["rubric_excerpt"]["parsed"])
        # severity=HIGH filters to HIGH-tier rows only.
        rows = result["rubric_excerpt"]["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["rubric_id"], "HIGH-1")
        self.assertEqual(rows[0]["tier"], "HIGH")

    # --- 6. Skeleton sections + busywork + routine ------------------------

    def test_skeleton_sections_are_markdown_strings(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="dispute", severity="HIGH"
            )
        # dispute lane should have skeleton entries for R29, R43, R45
        # (R28 is doctrine-only, no template).
        self.assertIn("R29", result["skeleton_sections"])
        self.assertIn("R43", result["skeleton_sections"])
        self.assertIn("R45", result["skeleton_sections"])
        # NOT in skeleton (doctrine-only):
        self.assertNotIn("R28", result["skeleton_sections"])
        for body in result["skeleton_sections"].values():
            self.assertIsInstance(body, str)
            self.assertGreater(len(body), 0)

    def test_busywork_refusals_list_present(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="dispute", severity="HIGH"
            )
        ids = [r["refusal_id"] for r in result["busywork_refusals"]]
        self.assertIn("JJ-1", ids)
        self.assertIn("JJ-2", ids)
        self.assertIn("QQQ-1", ids)
        self.assertIn("QQQ-2", ids)
        self.assertIn("QQQ-3", ids)

    def test_routine_violation_warnings_top_5(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="dispute", severity="HIGH"
            )
        self.assertLessEqual(len(result["routine_violation_warnings"]), 5)
        # Each row carries rule_id + remediation + override marker.
        for row in result["routine_violation_warnings"]:
            self.assertIn("rule_id", row)
            self.assertIn("remediation", row)
            self.assertIn("override_marker", row)

    # --- 7. Pre-submit preview --------------------------------------------

    def test_pre_submit_preview_lists_filing_lane_checks(self):
        """Filing lane includes R40/R42 which map to checks #84/#88/#89."""
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="filing", severity="HIGH"
            )
        check_numbers = {p["check_number"] for p in result["pre_submit_preview"]}
        rule_ids = {p["rule_id"] for p in result["pre_submit_preview"]}
        self.assertIn(84, check_numbers)  # R40
        self.assertIn(88, check_numbers)  # R42
        self.assertIn("R40", rule_ids)
        self.assertIn("R42", rule_ids)

    # --- 8. Composition_sources block ------------------------------------

    def test_composition_sources_block_present(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="dispute", severity="HIGH"
            )
        cs = result["composition_sources"]
        # codified + skeleton always composed; recall packs may be
        # empty pack_ids when no workspace.
        self.assertIn("codified_rules_digest_pack_id", cs)
        self.assertIn("lane_skeleton_filler_pack_id", cs)
        self.assertIn("invariant_library_pack_id", cs)
        self.assertIn("live_target_report_pack_id", cs)
        self.assertIn("anti_pattern_corpus_pack_id", cs)
        self.assertTrue(cs["codified_rules_digest_pack_id"].startswith(
            "auditooor.vault_codified_rules_digest.v1:"
        ))
        self.assertTrue(cs["lane_skeleton_filler_pack_id"].startswith(
            "auditooor.vault_lane_skeleton_filler.v1:"
        ))
        self.assertTrue(cs["invariant_library_pack_id"].startswith(
            "auditooor.vault_invariant_library.v1:"
        ))
        self.assertTrue(cs["live_target_report_pack_id"].startswith(
            "auditooor.vault_live_target_report.v1:"
        ))
        self.assertTrue(cs["anti_pattern_corpus_pack_id"].startswith(
            "auditooor.vault_anti_pattern_corpus.v1:"
        ))

    def test_pillar_context_contains_bounded_pack_summaries(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="hunt", severity="HIGH"
            )
        pillar_context = result["pillar_context"]
        self.assertTrue(pillar_context["bounded"])
        self.assertEqual(pillar_context["limit_per_pillar"], 5)
        self.assertEqual(
            set(pillar_context["packs"]),
            {"invariant_library", "live_target_report", "anti_pattern_corpus"},
        )
        self.assertEqual(
            pillar_context["pack_ids"]["invariant_library"],
            pillar_context["packs"]["invariant_library"]["context_pack_id"],
        )
        self.assertIn(
            "reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md",
            pillar_context["source_refs"],
        )
        for pack in pillar_context["packs"].values():
            self.assertIn("callable", pack)
            self.assertIn("context_pack_id", pack)
            self.assertIn("context_pack_hash", pack)
            self.assertIn("degraded", pack)
            self.assertIn("source_refs", pack)

    def test_pillar_subcall_failure_degrades_without_raising(self):
        with tempfile.TemporaryDirectory() as td:
            vault = _make_vault(Path(td))

            def _raise_invariant(**_kwargs):
                raise RuntimeError("forced invariant failure")

            vault.vault_invariant_library = _raise_invariant
            result = vault.vault_dispatch_brief_skeleton(
                lane_type="hunt", severity="HIGH"
            )
        pack = result["pillar_context"]["packs"]["invariant_library"]
        self.assertTrue(pack["degraded"])
        self.assertEqual(
            pack["context_pack_id"],
            "auditooor.vault_invariant_library.v1:unavailable",
        )
        self.assertIn("call_failed", pack["reason"])
        self.assertEqual(
            result["composition_sources"]["invariant_library_pack_id"],
            "auditooor.vault_invariant_library.v1:unavailable",
        )


if __name__ == "__main__":
    unittest.main()
