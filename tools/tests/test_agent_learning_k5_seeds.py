"""Tests for agent-learning-k5-seeds.py - Lane K5 backfill seed tool.

Verifies:
  1. All 6 required terminal kinds are emitted.
  2. Every row carries K3a fields (proposition / evidence_polarity /
     primary_for / reuse_action / promotion_class / is_primary_signal /
     can_promote_to_proof).
  3. Every row carries source_refs (non-empty list).
  4. The proof_artifact seed references a real PoC path and has
     is_primary_signal=True, source_has_local_proof=True,
     provider_only=False.
  5. NO_ACTION rows carry a rationale field.
  6. The inline _validate_rows check passes (0 errors).
  7. Output JSONL is gate-compatible (agent-learning-gate passes on a
     synthetic workspace built from the seed rows as the ledger).
  8. Rows emitted to a temp file are valid JSONL (one dict per line).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SEED_TOOL = REPO_ROOT / "tools" / "agent-learning-k5-seeds.py"
GATE_TOOL = REPO_ROOT / "tools" / "agent-learning-gate.py"


def load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


seeds_mod = load_module(SEED_TOOL, "agent_learning_k5_seeds")
gate_mod = load_module(GATE_TOOL, "agent_learning_gate")

REQUIRED_TERMINAL_KINDS = {
    "typed_lesson",
    "proof_artifact",
    "kill_reason",
    "triager_objection",
    "hacker_question",
    "no_action",
}

K3A_FIELDS = (
    "proposition",
    "evidence_polarity",
    "primary_for",
    "reuse_action",
    "promotion_class",
    "is_primary_signal",
    "can_promote_to_proof",
)


class TestK5Seeds(unittest.TestCase):

    def setUp(self):
        self.rows = seeds_mod.build_seeds("2026-05-22T00:00:00+00:00")

    def _kinds(self) -> set[str]:
        return {str(r.get("terminal_kind") or "").lower() for r in self.rows}

    # ------------------------------------------------------------------
    # 1. All 6 terminal kinds present
    # ------------------------------------------------------------------

    def test_all_six_terminal_kinds_covered(self):
        kinds = self._kinds()
        missing = REQUIRED_TERMINAL_KINDS - kinds
        self.assertEqual(
            missing,
            set(),
            f"Missing terminal kinds: {sorted(missing)}; found: {sorted(kinds)}",
        )

    def test_typed_lesson_present(self):
        self.assertIn("typed_lesson", self._kinds())

    def test_proof_artifact_present(self):
        self.assertIn("proof_artifact", self._kinds())

    def test_kill_reason_present(self):
        self.assertIn("kill_reason", self._kinds())

    def test_triager_objection_present(self):
        self.assertIn("triager_objection", self._kinds())

    def test_hacker_question_present(self):
        self.assertIn("hacker_question", self._kinds())

    def test_no_action_present(self):
        self.assertIn("no_action", self._kinds())

    # ------------------------------------------------------------------
    # 2. K3a fields present on every row
    # ------------------------------------------------------------------

    def test_every_row_has_k3a_fields(self):
        for row in self.rows:
            aid = row.get("artifact_id", "<unknown>")
            for field in K3A_FIELDS:
                self.assertIn(field, row, f"Row {aid!r} missing K3a field {field!r}")
                if isinstance(row[field], str):
                    self.assertTrue(
                        row[field].strip() or field in ("promotion_class",),
                        f"Row {aid!r} has empty K3a string field {field!r}",
                    )

    # ------------------------------------------------------------------
    # 3. Every row has source_refs (non-empty list)
    # ------------------------------------------------------------------

    def test_every_row_has_source_refs(self):
        for row in self.rows:
            aid = row.get("artifact_id", "<unknown>")
            refs = row.get("source_refs")
            self.assertIsInstance(refs, list, f"Row {aid!r}: source_refs not a list")
            self.assertTrue(refs, f"Row {aid!r}: source_refs is empty")

    # ------------------------------------------------------------------
    # 4. proof_artifact seed has correct K3 flags + cites real PoC
    # ------------------------------------------------------------------

    def test_proof_artifact_row_k3_flags(self):
        proof_rows = [r for r in self.rows if r.get("terminal_kind") == "proof_artifact"]
        self.assertTrue(proof_rows, "No proof_artifact row found")
        for row in proof_rows:
            aid = row.get("artifact_id", "<unknown>")
            self.assertTrue(row.get("is_primary_signal"), f"{aid}: is_primary_signal must be True")
            self.assertTrue(row.get("source_has_local_proof"), f"{aid}: source_has_local_proof must be True")
            self.assertFalse(row.get("provider_only"), f"{aid}: provider_only must be False")
            self.assertEqual(row.get("promotion_class"), "primary_promoted", f"{aid}: promotion_class must be primary_promoted")
            self.assertTrue(row.get("can_promote_to_proof"), f"{aid}: can_promote_to_proof must be True")

    def test_proof_artifact_cites_real_poc(self):
        """The proof_artifact seed must reference the NUVA ExpDec PoC path."""
        proof_rows = [r for r in self.rows if r.get("terminal_kind") == "proof_artifact"]
        self.assertTrue(proof_rows, "No proof_artifact row found")
        row = proof_rows[0]
        refs = row.get("source_refs") or []
        poc_refs = [r for r in refs if "poc" in r.lower() and "expdec" in r.lower()]
        self.assertTrue(
            poc_refs,
            f"proof_artifact seed must cite the NUVA ExpDec PoC; got source_refs={refs}",
        )

    def test_proof_artifact_not_fabricated(self):
        """Confirm the proof_artifact row cites a real engagement (nuva) not a stub."""
        proof_rows = [r for r in self.rows if r.get("terminal_kind") == "proof_artifact"]
        row = proof_rows[0]
        self.assertEqual(row.get("engagement"), "nuva", "proof_artifact must reference nuva engagement")
        refs = str(row.get("source_refs") or "")
        self.assertIn("expdec_chain_halt", refs, "proof_artifact source_refs must mention expdec_chain_halt PoC file")

    # ------------------------------------------------------------------
    # 5. NO_ACTION rows have a rationale
    # ------------------------------------------------------------------

    def test_no_action_rows_have_rationale(self):
        no_action_rows = [r for r in self.rows if str(r.get("terminal_kind") or "").lower() == "no_action"]
        self.assertTrue(no_action_rows, "No no_action rows found")
        for row in no_action_rows:
            aid = row.get("artifact_id", "<unknown>")
            rationale = str(row.get("rationale") or "").strip()
            self.assertTrue(rationale, f"NO_ACTION row {aid!r} has empty rationale")

    # ------------------------------------------------------------------
    # 6. Inline _validate_rows passes (0 errors)
    # ------------------------------------------------------------------

    def test_inline_validate_rows_passes(self):
        errors = seeds_mod._validate_rows(self.rows)
        self.assertEqual(
            errors,
            [],
            f"_validate_rows returned {len(errors)} error(s):\n" + "\n".join(errors),
        )

    # ------------------------------------------------------------------
    # 7. Gate-compatible: agent-learning-gate passes on a synthetic workspace
    #    using the seed rows as the learning ledger (no miner report present).
    # ------------------------------------------------------------------

    def test_gate_passes_on_seed_rows_as_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            # Write seeds as learning_ledger.jsonl at a gate-candidate path
            ledger_path = workspace / "learning_ledger.jsonl"
            with ledger_path.open("w", encoding="utf-8") as fh:
                for row in self.rows:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
            result = gate_mod.evaluate(workspace)
            # No miner report - gate should be pass or warn (no fail)
            # The ledger rows themselves must not produce promotion escapes or
            # scope violations (blockers that fire without a report).
            blockers = result.get("blockers") or []
            hard_fails = [b for b in blockers if b.get("code") not in (
                "missing_agent_artifact_report",
            )]
            self.assertEqual(
                hard_fails,
                [],
                f"Gate returned hard blockers on K5 seed ledger:\n"
                + json.dumps(hard_fails, indent=2),
            )
            # No promotion escapes
            self.assertEqual(
                result.get("ledger_promotion_escape_count", 0),
                0,
                "K5 seeds must not trigger ledger promotion escapes",
            )
            # No scope violations
            self.assertEqual(
                result.get("terminal_scope_violation_count", 0),
                0,
                "K5 seeds must not trigger terminal scope violations",
            )
            # No reuse_action violations
            self.assertEqual(
                result.get("reuse_action_violation_count", 0),
                0,
                "K5 seeds must not trigger reuse_action violations",
            )

    # ------------------------------------------------------------------
    # 8. Output JSONL is valid (one dict per line)
    # ------------------------------------------------------------------

    def test_emit_produces_valid_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "test_k5.jsonl"
            seeds_mod.emit(self.rows, out)
            self.assertTrue(out.is_file(), "emit() must create output file")
            lines = out.read_text(encoding="utf-8").splitlines()
            non_empty = [l for l in lines if l.strip()]
            self.assertEqual(len(non_empty), len(self.rows), "Expected one JSONL line per row")
            for i, line in enumerate(non_empty):
                parsed = json.loads(line)
                self.assertIsInstance(parsed, dict, f"Line {i} is not a JSON object")
                self.assertIn("artifact_id", parsed, f"Line {i} missing artifact_id")

    # ------------------------------------------------------------------
    # Bonus: all artifact_ids are unique
    # ------------------------------------------------------------------

    def test_artifact_ids_unique(self):
        ids = [str(r.get("artifact_id") or "") for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate artifact_ids: {ids}")

    # ------------------------------------------------------------------
    # Bonus: engagement coverage - all 8 named K5 engagements present
    # ------------------------------------------------------------------

    def test_k5_engagement_coverage(self):
        required_engagements = {
            "mezo", "nuva", "dydx", "the-graph",
            "polymarket", "revert-v4", "reserve", "spark",
        }
        seen = {str(r.get("engagement") or "") for r in self.rows}
        missing = required_engagements - seen
        self.assertEqual(
            missing,
            set(),
            f"Missing K5 named engagements: {sorted(missing)}; found: {sorted(seen)}",
        )


if __name__ == "__main__":
    unittest.main()
