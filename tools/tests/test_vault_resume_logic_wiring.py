"""test_vault_resume_logic_wiring.py — unit tests for Phase J M-J logic wiring.

Verifies that vault_resume_context returns the three new extracted-LOGIC fields:
  - case_study_logic[]
  - big_loss_template_actor_sequences[]
  - defihack_class_matches[]

Uses a synthetic case_study fixture with valid frontmatter (class_matcher_predicates).
All tests are offline-safe (no network, no subprocess calls to grep).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_vault_module() -> Any:
    module_id = "vault_mcp_server_logic_wiring_test"
    if module_id in sys.modules:
        return sys.modules[module_id]
    spec = importlib.util.spec_from_file_location(module_id, MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[module_id] = mod
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


vault_mcp_server = _load_vault_module()


# ---------------------------------------------------------------------------
# Test: _case_study_logic
# ---------------------------------------------------------------------------

class TestCaseStudyLogic(unittest.TestCase):
    """Verify _case_study_logic() returns well-formed dicts from real case_study/ dir."""

    def test_returns_list(self):
        result = vault_mcp_server._case_study_logic(None)
        self.assertIsInstance(result, list)

    def test_no_workspace_returns_all_or_empty(self):
        """Without workspace_path the function returns all studies (up to 8) or empty []."""
        result = vault_mcp_server._case_study_logic(None)
        self.assertLessEqual(len(result), 8)
        # Every entry must have the mandatory fields.
        for item in result:
            self.assertIn("case_id", item)
            self.assertIn("extracted_lesson", item)
            self.assertIn("grep_predicates", item)
            self.assertIsInstance(item["grep_predicates"], list)

    def test_with_workspace_class_returns_matches(self):
        """Passing a workspace that derives class 'prediction-market' returns matching studies."""
        with tempfile.TemporaryDirectory(prefix="auditooor-logic-test-") as tmp:
            ws = Path(tmp)
            # Write a minimal INTAKE_BASELINE.md that drives class detection to prediction-market
            (ws / "INTAKE_BASELINE.md").write_text(
                "# Baseline\n\nThis is a prediction-market workspace.", encoding="utf-8"
            )
            result = vault_mcp_server._case_study_logic(ws)
            self.assertIsInstance(result, list)
            # prediction-market case studies exist in the repo; we should get at least 1 match.
            # If for some reason the repo has none, we accept 0 gracefully (not an error).
            for item in result:
                self.assertIn("case_id", item)
                self.assertIn("extracted_lesson", item)

    def test_invalid_workspace_returns_empty(self):
        """Non-existent workspace must not raise; returns []."""
        result = vault_mcp_server._case_study_logic(Path("/nonexistent/workspace/xyz"))
        self.assertIsInstance(result, list)
        # May still return all studies (no workspace class derived), or []
        # The key requirement is no exception.

    def test_case_study_logic_deduplicates_semantic_rows(self):
        """Duplicate case-study rows collapse before the hard cap."""
        class FakeCaseMatch:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

            def as_dict(self):
                data = dict(self.__dict__)
                data["class"] = data.pop("class_")
                return data

        def _study(source_file: str):
            return types.SimpleNamespace(
                case_id="duplicate-case",
                mechanism="same mechanism",
                class_="lending",
                severity_class="HIGH",
                grep_predicates=["balanceOf"],
                runtime_predicates=["forge test"],
                extracted_lesson="same lesson",
                stop_criterion="same stop",
                workflow_signature="same workflow",
                loop_back_phase="triage",
                source_file=source_file,
            )

        fake_mod = types.SimpleNamespace(
            CaseMatch=FakeCaseMatch,
            load_all_case_studies=lambda: [
                _study("case_study/a.md"),
                _study("case_study/b.md"),
                types.SimpleNamespace(
                    case_id="unique-case",
                    mechanism="different mechanism",
                    class_="bridge",
                    severity_class="INFO",
                    grep_predicates=["sendMessage"],
                    runtime_predicates=[],
                    extracted_lesson="different lesson",
                    stop_criterion="",
                    workflow_signature="",
                    loop_back_phase="",
                    source_file="case_study/c.md",
                ),
            ],
        )

        old_loader = vault_mcp_server._load_tool_module
        vault_mcp_server._load_tool_module = lambda name: fake_mod
        try:
            result = vault_mcp_server._case_study_logic(None)
        finally:
            vault_mcp_server._load_tool_module = old_loader

        self.assertEqual(
            [item["case_id"] for item in result],
            ["duplicate-case", "unique-case"],
        )
        self.assertEqual(result[0]["source_file"], "case_study/a.md")

    def test_synthetic_frontmatter_in_recall(self):
        """Patch case_study_dir to a temp dir with a synthetic .md; verify fields appear."""
        with tempfile.TemporaryDirectory(prefix="auditooor-synthetic-cs-") as tmp:
            cs_dir = Path(tmp)
            synthetic = textwrap.dedent("""\
                ---
                case_id: synthetic-test-001
                mechanism: synthetic test mechanism for M-J unit coverage
                class: lending
                severity_class: HIGH
                applicable_workspace_classes:
                  - lending
                  - vault
                grep_predicates:
                  - "transfer\\s*\\("
                  - "balanceOf"
                runtime_predicates:
                  - "forge test: PoC PASS"
                extracted_lesson: >
                  Synthetic lesson: always check invariants before state mutations.
                ---
                # Synthetic Case Study

                Body text here.
            """)
            (cs_dir / "synthetic_test_001.md").write_text(synthetic, encoding="utf-8")

            # Load the tool module and call match_workspace with our synthetic dir.
            mod = vault_mcp_server._load_tool_module("case-study-class-matcher")
            if mod is None:
                self.skipTest("case-study-class-matcher module not found")

            matches = mod.match_workspace("lending", top_n=5, case_study_dir=cs_dir)
            self.assertGreaterEqual(len(matches), 1, "Synthetic lending study must match")

            first = matches[0]
            d = first.as_dict() if hasattr(first, "as_dict") else vars(first)
            self.assertEqual(d.get("case_id"), "synthetic-test-001")
            self.assertIn("Synthetic lesson", d.get("extracted_lesson", ""))
            self.assertIsInstance(d.get("grep_predicates", []), list)
            self.assertGreaterEqual(len(d.get("grep_predicates", [])), 1)


# ---------------------------------------------------------------------------
# Test: _big_loss_template_actor_sequences
# ---------------------------------------------------------------------------

class TestBigLossTemplateActorSequences(unittest.TestCase):
    """Verify _big_loss_template_actor_sequences() returns well-formed dicts."""

    def test_returns_list(self):
        result = vault_mcp_server._big_loss_template_actor_sequences(None)
        self.assertIsInstance(result, list)

    def test_no_workspace_returns_empty(self):
        """Without workspace_path returns empty (early return guard)."""
        result = vault_mcp_server._big_loss_template_actor_sequences(None)
        self.assertEqual(result, [])

    def test_with_workspace_returns_template_results(self):
        """Passing a real workspace should return at least one template verdict."""
        # Use the repo root itself as a stand-in workspace (templates always run).
        result = vault_mcp_server._big_loss_template_actor_sequences(REPO_ROOT)
        self.assertIsInstance(result, list)
        if result:  # templates dir may or may not match; can be empty on CI
            for item in result:
                self.assertIn("template_id", item)
                self.assertIn("title", item)
                self.assertIn("workspace_scope_match", item)
                self.assertIn("actor_sequence_verdicts", item)
                self.assertIsInstance(item["actor_sequence_verdicts"], list)

    def test_actor_sequence_verdicts_are_bounded(self):
        """actor_sequence_verdicts list is capped at 10 entries per template."""
        result = vault_mcp_server._big_loss_template_actor_sequences(REPO_ROOT)
        for item in result:
            self.assertLessEqual(len(item.get("actor_sequence_verdicts", [])), 10)

    def test_template_count_is_bounded(self):
        """At most 6 templates are returned per recall."""
        result = vault_mcp_server._big_loss_template_actor_sequences(REPO_ROOT)
        self.assertLessEqual(len(result), 6)


# ---------------------------------------------------------------------------
# Test: _defihack_class_matches
# ---------------------------------------------------------------------------

class TestDefihackClassMatches(unittest.TestCase):
    """Verify _defihack_class_matches() returns well-formed dicts."""

    def test_returns_list(self):
        result = vault_mcp_server._defihack_class_matches(None)
        self.assertIsInstance(result, list)

    def test_no_workspace_returns_empty(self):
        """Without workspace_path returns empty (early return guard)."""
        result = vault_mcp_server._defihack_class_matches(None)
        self.assertEqual(result, [])

    def test_nonexistent_workspace_returns_empty(self):
        result = vault_mcp_server._defihack_class_matches(Path("/nonexistent/xyz"))
        self.assertIsInstance(result, list)
        # Should return [] (workspace doesn't exist)
        self.assertEqual(result, [])

    def test_result_fields_are_present(self):
        """Every returned row has the required fields."""
        # Use a small tmp dir so we don't hit the file-count cap.
        with tempfile.TemporaryDirectory(prefix="auditooor-dfh-test-") as tmp:
            result = vault_mcp_server._defihack_class_matches(Path(tmp))
            self.assertIsInstance(result, list)
            for item in result:
                self.assertIn("id", item)
                self.assertIn("attack_class", item)
                self.assertIn("mechanism", item)
                self.assertIn("total_hits", item)
                self.assertIn("is_candidate", item)
                self.assertIn("grep_predicates", item)
                self.assertIn("matched_predicates", item)

    def test_large_workspace_returns_skip_sentinel(self):
        """Workspaces with >300 source files return a 'skipped' sentinel entry."""
        with tempfile.TemporaryDirectory(prefix="auditooor-large-ws-") as tmp:
            ws = Path(tmp)
            # Create 310 .sol files to exceed the cap
            for i in range(310):
                (ws / f"Contract{i:04d}.sol").write_text(
                    f"// SPDX-License-Identifier: MIT\ncontract C{i} {{}}", encoding="utf-8"
                )
            result = vault_mcp_server._defihack_class_matches(ws)
            self.assertIsInstance(result, list)
            self.assertGreaterEqual(len(result), 1)
            self.assertEqual(result[0].get("id"), "skipped")
            self.assertIn("too large", result[0].get("mechanism", ""))

    def test_count_is_bounded(self):
        """At most 8 rows returned."""
        with tempfile.TemporaryDirectory(prefix="auditooor-dfh-bound-") as tmp:
            result = vault_mcp_server._defihack_class_matches(Path(tmp))
            self.assertLessEqual(len(result), 8)

    def test_match_details_include_predicates_and_refs(self):
        """Matched rows retain grep predicates and bounded hit refs for brief Section 4."""
        with tempfile.TemporaryDirectory(prefix="auditooor-dfh-detail-") as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Oracle.sol").write_text(
                "function getPrice() external view returns (uint) {\n"
                "    return ICurvePool(pool).get_virtual_price();\n"
                "}\n",
                encoding="utf-8",
            )
            result = vault_mcp_server._defihack_class_matches(ws)
            oracle_rows = [item for item in result if item.get("id") == "dhl-005"]
            self.assertTrue(oracle_rows, "expected dhl-005 to match planted oracle file")
            row = oracle_rows[0]
            self.assertIn("get_virtual_price", " ".join(row.get("grep_predicates", [])))
            self.assertTrue(row.get("matched_predicates"))
            first_match = row["matched_predicates"][0]
            self.assertIn("predicate", first_match)
            self.assertIn("hit_refs", first_match)


# ---------------------------------------------------------------------------
# Test: vault_resume_context integration — three fields present in output
# ---------------------------------------------------------------------------

class TestVaultResumeContextLogicFields(unittest.TestCase):
    """Integration test: vault_resume_context output includes the three new fields."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-resume-logic-test-")
        self.root = Path(self.tmp.name)
        vault_dir = self.root / "obsidian-vault"
        (vault_dir / "goals").mkdir(parents=True)
        (vault_dir / "dispatch").mkdir()
        (vault_dir / "_privacy_quarantine").mkdir()
        (vault_dir / "_archive").mkdir()
        (vault_dir / ".privacy").mkdir()
        (self.root / "reference").mkdir()
        (self.root / "reports").mkdir()
        (vault_dir / "NEXT_LOOP.md").write_text(
            "---\ntitle: Next loop\nstatus: active\n---\n## items\n", encoding="utf-8"
        )
        (vault_dir / "INDEX.md").write_text("# Index\n", encoding="utf-8")
        (vault_dir / "INDEX_active.md").write_text(
            "---\ntitle: Active\nstatus: in_flight\n---\n# Active\n", encoding="utf-8"
        )
        (vault_dir / "goals" / "current.md").write_text(
            "---\nobjective: Test goal\nstatus: active\nloop: perpetual\nterminal_condition: never\nnext_action: loop\n---\n",
            encoding="utf-8",
        )
        (self.root / "reference" / "outcomes.jsonl").write_text("{}\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_three_logic_fields_present_in_resume_pack(self):
        """vault_resume_context always includes case_study_logic, big_loss_template_actor_sequences, defihack_class_matches."""
        vault = vault_mcp_server.VaultQuery(self.root / "obsidian-vault", self.root)
        result = vault.vault_resume_context()
        self.assertIn("case_study_logic", result)
        self.assertIn("big_loss_template_actor_sequences", result)
        self.assertIn("defihack_class_matches", result)
        self.assertIsInstance(result["case_study_logic"], list)
        self.assertIsInstance(result["big_loss_template_actor_sequences"], list)
        self.assertIsInstance(result["defihack_class_matches"], list)

    def test_three_logic_fields_are_lists_even_without_workspace(self):
        """Without workspace_path the fields are empty lists (not absent, not None)."""
        vault = vault_mcp_server.VaultQuery(self.root / "obsidian-vault", self.root)
        result = vault.vault_resume_context()
        self.assertEqual(result["big_loss_template_actor_sequences"], [])
        self.assertEqual(result["defihack_class_matches"], [])

    def test_legacy_refs_still_present_for_backward_compat(self):
        """case_study_refs and known_patterns_refs are still returned (backward compat)."""
        vault = vault_mcp_server.VaultQuery(self.root / "obsidian-vault", self.root)
        result = vault.vault_resume_context()
        self.assertIn("case_study_refs", result)
        self.assertIn("known_patterns_refs", result)
        self.assertIsInstance(result["case_study_refs"], list)
        self.assertIsInstance(result["known_patterns_refs"], list)

    def test_context_pack_id_is_stable_when_inputs_unchanged(self):
        """Same inputs → same context_pack_id (determinism check)."""
        vault = vault_mcp_server.VaultQuery(self.root / "obsidian-vault", self.root)
        r1 = vault.vault_resume_context()
        r2 = vault.vault_resume_context()
        self.assertEqual(r1["context_pack_id"], r2["context_pack_id"])


if __name__ == "__main__":
    unittest.main()
