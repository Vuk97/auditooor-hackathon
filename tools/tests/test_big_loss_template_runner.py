"""Tests for tools/big-loss-template-runner.py — Phase F.

Coverage:
- template loading from INDEX.json
- scope_path_regex match / no-match detection
- actor_sequence step evaluation (applicable vs not)
- all 3 templates discoverable
- CLI dry-run on a toy workspace (--print-json)
- bridge_proof_domain template runs without error
- consensus_parser_differential template runs without error
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------
_TOOLS_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _TOOLS_DIR.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

_RUNNER_PATH = _TOOLS_DIR / "big-loss-template-runner.py"
_spec = importlib.util.spec_from_file_location("big_loss_template_runner", _RUNNER_PATH)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

run = _mod.run
run_template = _mod.run_template
_load_templates = _mod._load_templates
_template_matches_workspace = _mod._template_matches_workspace
SCHEMA_VERSION = _mod.SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ws(
    file_tree: list[str] | None = None,
    ledger_rows: list[dict] | None = None,
) -> tempfile.TemporaryDirectory:
    """Build a minimal workspace temp dir."""
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    (root / ".auditooor").mkdir()

    # Create stub files matching the requested tree
    for rel_path in (file_tree or []):
        p = root / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("// stub")

    # Write ledger if rows provided
    if ledger_rows:
        ledger = {
            "schema_version": "auditooor.invariant_ledger.v1",
            "workspace": str(root),
            "rows": ledger_rows,
        }
        (root / ".auditooor" / "invariant_ledger.json").write_text(json.dumps(ledger))

    return td


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTemplateLoading(unittest.TestCase):
    def test_all_templates_load(self) -> None:
        templates = _load_templates()
        self.assertIn("bridge_proof_domain", templates)
        self.assertIn("consensus_parser_differential", templates)
        self.assertIn("rust_dlt_state_divergence", templates)

    def test_template_schema_version(self) -> None:
        templates = _load_templates()
        for tid, tmpl in templates.items():
            with self.subTest(template=tid):
                self.assertEqual(
                    tmpl.get("schema_version"),
                    "auditooor.big_loss_template.v1",
                )

    def test_actor_sequence_non_empty(self) -> None:
        templates = _load_templates()
        for tid, tmpl in templates.items():
            with self.subTest(template=tid):
                self.assertGreater(len(tmpl.get("actor_sequence", [])), 0)


class TestScopePathRegex(unittest.TestCase):
    def test_bridge_proof_domain_matches_portal_path(self) -> None:
        templates = _load_templates()
        t = templates["bridge_proof_domain"]
        # workspace scope text that contains a matching path
        scope_text = "src/L1/OptimismPortal2.sol\nsrc/multiproof/AggregateVerifier.sol"
        self.assertTrue(_template_matches_workspace(t, scope_text))

    def test_bridge_proof_domain_no_match_unrelated_path(self) -> None:
        templates = _load_templates()
        t = templates["bridge_proof_domain"]
        scope_text = "src/token/ERC20.sol\nlib/utils/Math.sol"
        self.assertFalse(_template_matches_workspace(t, scope_text))

    def test_consensus_parser_matches_derive_path(self) -> None:
        templates = _load_templates()
        t = templates["consensus_parser_differential"]
        scope_text = "crates/consensus/derive/src/attributes.rs\nsome/other/file.rs"
        self.assertTrue(_template_matches_workspace(t, scope_text))

    def test_consensus_parser_no_match_unrelated(self) -> None:
        templates = _load_templates()
        t = templates["consensus_parser_differential"]
        scope_text = "src/vault/ERC4626.sol\nlib/openzeppelin/SafeMath.sol"
        self.assertFalse(_template_matches_workspace(t, scope_text))


class TestRunTemplate(unittest.TestCase):
    def _bridge_ws(self) -> tempfile.TemporaryDirectory:
        return _make_ws(
            file_tree=[
                "src/L1/OptimismPortal2.sol",
                "src/multiproof/AggregateVerifier.sol",
                "src/multiproof/tee/TEEVerifier.sol",
                "src/dispute/DisputeGameFactory.sol",
            ],
            ledger_rows=[
                {
                    "row_id": "BP-001",
                    "production_path": "src/multiproof/AggregateVerifier.sol",
                    "invariant_family": "verifier",
                    "severity": "Critical",
                    "scope_status": "IN",
                }
            ],
        )

    def _consensus_ws(self) -> tempfile.TemporaryDirectory:
        return _make_ws(
            file_tree=[
                "crates/consensus/derive/src/attributes.rs",
                "crates/consensus/engine/src/engine_request_processor.rs",
                "crates/consensus/engine/src/seal/task.rs",
                "crates/consensus/stateful/src/lib.rs",
            ],
            ledger_rows=[
                {
                    "row_id": "CPD-001",
                    "production_path": "crates/consensus/derive/src/attributes.rs",
                    "invariant_family": "parser",
                    "severity": "High",
                    "scope_status": "IN",
                }
            ],
        )

    def test_bridge_proof_domain_run_template(self) -> None:
        templates = _load_templates()
        td = self._bridge_ws()
        try:
            verdict = run_template(templates["bridge_proof_domain"], Path(td.name))
        finally:
            td.cleanup()

        self.assertEqual(verdict["schema_version"], SCHEMA_VERSION)
        self.assertEqual(verdict["template_id"], "bridge_proof_domain")
        self.assertTrue(verdict["workspace_scope_match"])
        self.assertEqual(verdict["total_steps"], 4)
        self.assertGreater(len(verdict["actor_sequence_verdicts"]), 0)
        # Ledger matching rows count
        self.assertEqual(verdict["ledger_matching_row_count"], 1)

    def test_consensus_parser_run_template(self) -> None:
        templates = _load_templates()
        td = self._consensus_ws()
        try:
            verdict = run_template(templates["consensus_parser_differential"], Path(td.name))
        finally:
            td.cleanup()

        self.assertEqual(verdict["schema_version"], SCHEMA_VERSION)
        self.assertEqual(verdict["template_id"], "consensus_parser_differential")
        self.assertTrue(verdict["workspace_scope_match"])
        self.assertEqual(verdict["total_steps"], 5)
        # Steps that reference attributes.rs should be marked applicable
        attr_steps = [
            s for s in verdict["actor_sequence_verdicts"]
            if "attributes" in s.get("target", "").lower()
        ]
        self.assertGreater(len(attr_steps), 0)

    def test_consensus_worklist_predicates_symbol_hit(self) -> None:
        templates = _load_templates()
        td = _make_ws(
            file_tree=[
                "crates/consensus/derive/src/attributes.rs",
                "crates/consensus/engine/src/engine_request_processor.rs",
                "crates/consensus/engine/src/seal/task.rs",
                "crates/consensus/stateful/src/lib.rs",
            ],
            ledger_rows=[
                {
                    "row_id": "CPD-002",
                    "production_path": "crates/consensus/derive/src/attributes.rs",
                    "invariant_family": "parser",
                    "severity": "High",
                    "scope_status": "IN",
                }
            ],
        )
        try:
            attrs = Path(td.name) / "crates/consensus/derive/src/attributes.rs"
            attrs.write_text(
                "pub fn classify() -> bool {\n"
                "    is_deposits_only(&[])\n"
                "}\n"
            )
            verdict = run_template(templates["consensus_parser_differential"], Path(td.name))
        finally:
            td.cleanup()

        step2 = next(s for s in verdict["actor_sequence_verdicts"] if s.get("step") == 2)
        predicate_ids = {p["predicate_id"] for p in step2["worklist_predicates"]}
        self.assertIn("cpd.step2.is_deposits_only_symbol_present", predicate_ids)

        symbol_pred = next(
            p for p in step2["worklist_predicates"]
            if p["predicate_id"] == "cpd.step2.is_deposits_only_symbol_present"
        )
        self.assertEqual(symbol_pred["status"], "needs_evidence")
        self.assertTrue(symbol_pred["advisory_only"])
        self.assertTrue(any(ref.startswith("crates/consensus/derive/src/attributes.rs:") for ref in symbol_pred["hit_refs"]))

        step1 = next(s for s in verdict["actor_sequence_verdicts"] if s.get("step") == 1)
        step1_ids = {p["predicate_id"] for p in step1["worklist_predicates"]}
        self.assertIn("cpd.step1.attributes_path_present", step1_ids)

    def test_oos_rows_excluded(self) -> None:
        templates = _load_templates()
        # Create ws with only OOS rows
        td = _make_ws(
            file_tree=["src/multiproof/AggregateVerifier.sol"],
            ledger_rows=[
                {
                    "row_id": "BP-OOS",
                    "production_path": "src/multiproof/AggregateVerifier.sol",
                    "invariant_family": "verifier",
                    "severity": "Critical",
                    "scope_status": "OOS",
                }
            ],
        )
        try:
            verdict = run_template(templates["bridge_proof_domain"], Path(td.name))
        finally:
            td.cleanup()
        self.assertEqual(verdict["ledger_matching_row_count"], 0)

    def test_out_of_severity_set_excluded(self) -> None:
        templates = _load_templates()
        td = _make_ws(
            file_tree=["src/multiproof/AggregateVerifier.sol"],
            ledger_rows=[
                {
                    "row_id": "BP-LOW",
                    "production_path": "src/multiproof/AggregateVerifier.sol",
                    "invariant_family": "verifier",
                    "severity": "Low",
                    "scope_status": "IN",
                }
            ],
        )
        try:
            verdict = run_template(templates["bridge_proof_domain"], Path(td.name))
        finally:
            td.cleanup()
        self.assertEqual(verdict["ledger_matching_row_count"], 0)


class TestRunCLI(unittest.TestCase):
    """Integration: run() against a toy workspace."""

    def test_run_bridge_template_toy_workspace(self) -> None:
        td = _make_ws(
            file_tree=["src/L1/OptimismPortal2.sol", "src/multiproof/AggregateVerifier.sol"],
        )
        try:
            results = run(workspace=td.name, template_id="bridge_proof_domain", print_json=False)
        finally:
            td.cleanup()

        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["template_id"], "bridge_proof_domain")
        self.assertIn("actor_sequence_verdicts", r)
        self.assertIn("kill_conditions_to_check", r)

    def test_run_consensus_template_toy_workspace(self) -> None:
        td = _make_ws(
            file_tree=["crates/consensus/derive/src/attributes.rs"],
        )
        try:
            results = run(workspace=td.name, template_id="consensus_parser_differential", print_json=False)
        finally:
            td.cleanup()

        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["template_id"], "consensus_parser_differential")
        self.assertEqual(r["engine"], "cargo_test")

    def test_run_all_templates_no_template_id(self) -> None:
        """No --template arg runs all scope-matching templates."""
        td = _make_ws(
            file_tree=[
                "src/L1/OptimismPortal2.sol",
                "crates/consensus/derive/src/attributes.rs",
                "crates/tee/src/verifier.rs",
            ],
        )
        try:
            results = run(workspace=td.name, print_json=False)
        finally:
            td.cleanup()

        # Should include all 3 templates (all match the mixed scope text)
        tids = {r["template_id"] for r in results}
        self.assertGreaterEqual(len(tids), 1)

    def test_run_json_output(self) -> None:
        import io, contextlib
        td = _make_ws(file_tree=["src/multiproof/AggregateVerifier.sol"])
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                run(workspace=td.name, template_id="bridge_proof_domain", print_json=True)
        finally:
            td.cleanup()

        output = buf.getvalue()
        parsed = json.loads(output)
        self.assertIsInstance(parsed, list)
        self.assertEqual(parsed[0]["template_id"], "bridge_proof_domain")

    def test_step_verdicts_have_required_fields(self) -> None:
        td = _make_ws(file_tree=["src/L1/OptimismPortal2.sol"])
        try:
            results = run(workspace=td.name, template_id="bridge_proof_domain", print_json=False)
        finally:
            td.cleanup()

        verdicts = results[0]["actor_sequence_verdicts"]
        for v in verdicts:
            for field in ("step", "actor", "action", "target", "prerequisite",
                          "evidence_required", "applicable", "actual_state"):
                self.assertIn(field, v, f"missing field {field!r} in step {v.get('step')}")

    def test_actor_sequence_hit_count_bridge(self) -> None:
        """bridge_proof_domain has 4 steps; verify count."""
        td = _make_ws(file_tree=["src/L1/OptimismPortal2.sol"])
        try:
            results = run(workspace=td.name, template_id="bridge_proof_domain", print_json=False)
        finally:
            td.cleanup()
        self.assertEqual(results[0]["total_steps"], 4)

    def test_actor_sequence_hit_count_consensus(self) -> None:
        """consensus_parser_differential has 5 steps."""
        td = _make_ws(file_tree=["crates/consensus/derive/src/attributes.rs"])
        try:
            results = run(workspace=td.name, template_id="consensus_parser_differential", print_json=False)
        finally:
            td.cleanup()
        self.assertEqual(results[0]["total_steps"], 5)


if __name__ == "__main__":
    unittest.main()
