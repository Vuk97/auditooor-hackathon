from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "zero-day-freeze-compiler.py"
SPEC = importlib.util.spec_from_file_location("zero_day_freeze_compiler", TOOL)
COMPILER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = COMPILER
SPEC.loader.exec_module(COMPILER)


class ZeroDayFreezeCompilerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ws = Path(self.tmp.name) / "ws"
        self.aud = self.ws / ".auditooor"
        self.receipts = self.aud / "pipeline" / "receipts"
        self.ws.mkdir(parents=True)
        self.artifacts = {
            "artifact.step-0d-awareness": ".auditooor/awareness_ledger.json",
            "artifact.r": ".auditooor/r.jsonl",
            "artifact.step-4c-hunt-report": ".auditooor/corpus_driven_hunt.json",
            "artifact.step-4c": ".auditooor/zero_day_fuel_step-4c.jsonl",
            "artifact.step-2g-novelty-flywheel": ".auditooor/novelty/burndown_feed.jsonl",
        }
        self.manifest = {
            "schema": COMPILER.PIPELINE_MANIFEST_SCHEMA,
            "steps": [
                {"step_id": "step-0d", "phase": "intake", "class": "mechanical", "depends_on": []},
                {"step_id": "step-r", "phase": "reasoning", "class": "reasoning", "depends_on": ["step-0d"]},
                {"step_id": "step-4c", "phase": "reasoning", "class": "orchestration", "depends_on": ["step-r"]},
                {"step_id": "step-2g-novelty-flywheel", "phase": "reasoning", "class": "orchestration", "depends_on": ["step-r"]},
                {"step_id": "step-2h-reasoner-regen", "phase": "reasoning", "class": "orchestration", "depends_on": ["step-r", "step-4c", "step-2g-novelty-flywheel"]},
            ],
            "artifact_contracts": [
                {"id": key, "path": value} for key, value in self.artifacts.items()
            ],
            "reasoner_registry": [
                {"id": "r", "step_id": "step-r", "ledger_artifact": "artifact.r"},
            ],
            "reasoner_routes": [{
                "reasoner_id": "r",
                "step_id": "step-r",
                "ledger_artifact": "artifact.r",
                "producer_step_id": "step-r",
                "consumer_step_ids": ["q", "p", "x", "z"],
                "queue_step_id": "q",
                "question_step_id": "p",
                "proof_step_id": "x",
                "resolution_step_id": "z",
            }],
        }
        self.manifest_path = self.ws / "manifest.json"
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.baseline = {field: "a" * 64 for field in COMPILER.PROVENANCE_FIELDS}
        self.baseline["manifest_sha256"] = COMPILER.digest(self.manifest)
        self.inventory_rows = [
            {"unit_id": "unit-a", "file": "src/Vault.sol", "function": "withdraw", "source_refs": ["src/Vault.sol:9"]},
            {"unit_id": "unit-b", "file": "src/Vault.sol", "function": "deposit", "source_refs": ["src/Vault.sol:3"]},
        ]

    def write_jsonl(self, rel: str | Path, rows: list[dict]) -> Path:
        path = self.ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return path

    def receipt(
        self,
        step: str,
        artifact: str | None = None,
        path: Path | None = None,
        *,
        outputs: list[tuple[str, Path]] | None = None,
    ) -> dict:
        if outputs is None:
            assert artifact is not None and path is not None
            outputs = [(artifact, path)]
        row = {
            "schema": COMPILER.PIPELINE_RECEIPT_SCHEMA,
            **self.baseline,
            "step_id": step,
            "status": "succeeded",
            "output_artifacts": [
                {
                    "artifact_contract": contract,
                    "path": str(output_path.relative_to(self.ws)),
                    "sha256": COMPILER.path_sha256(output_path),
                }
                for contract, output_path in outputs
            ],
        }
        row["receipt_id"] = COMPILER.receipt_digest(row)
        row["self_hash"] = row["receipt_id"]
        return row

    def obligation_row(self, source_ref: str = "src/Vault.sol:9") -> dict:
        return {
            "producer_step_id": "step-r",
            "target_unit": "Vault.withdraw",
            "asset_invariant": "assets conserved",
            "violation_relation": "debit omitted",
            "actor_model": "permissionless attacker",
            "impact_class": "loss of funds",
            "source_refs": [source_ref],
            "file": "src/Vault.sol",
            "function": "withdraw",
            "broken_invariant_ids": ["INV-WITHDRAW-DEBIT"],
        }

    def empty_row(self, *, units: list[str] | None = None, axes: list[str] | None = None) -> dict:
        return {
            "schema": COMPILER.EMPTY_LEDGER_SCHEMA,
            "reasoner_step_id": "step-r",
            "producer_step_id": "step-r",
            "source_grounded_explanation": "Examined every applicable source unit and question axis.",
            "source_refs": ["src/Vault.sol:3", "src/Vault.sol:9"],
            "applicable_inventory_unit_ids": units if units is not None else ["unit-a", "unit-b"],
            "examined_axes": axes if axes is not None else list(COMPILER.AXES),
        }

    def coverage_row(self, *, units: list[str] | None = None) -> dict:
        covered = units if units is not None else ["unit-a", "unit-b"]
        return {
            "schema": COMPILER.COVERAGE_LEDGER_SCHEMA,
            "reasoner_step_id": "step-r",
            "producer_step_id": "step-r",
            "source_grounded_explanation": "Examined every applicable source unit across all question axes.",
            "source_refs": ["src/Vault.sol:3", "src/Vault.sol:9"],
            "applicable_inventory_unit_ids": covered,
            "examined_inventory_unit_ids": covered,
            "examined_axes": list(COMPILER.AXES),
        }

    def expected_link(self, row: dict, reasoner_receipt: dict, ledger_path: Path) -> tuple[str, str]:
        logical = COMPILER.normalized_fields(row)
        obligation_id = "zdo_" + COMPILER.digest(logical)
        revision_base = {field: self.baseline[field] for field in COMPILER.PROVENANCE_FIELDS}
        revision_base["all_substrate_and_producer_receipt_ids"] = sorted([
            self.awareness_receipt["receipt_id"],
            reasoner_receipt["receipt_id"],
        ])
        revision_base["manifest_sha256"] = COMPILER.digest(self.manifest)
        revision_context = {
            **revision_base,
            "obligation_id": obligation_id,
            "producer_receipt_id": reasoner_receipt["receipt_id"],
            "ledger_sha256": COMPILER.path_sha256(ledger_path),
            "source_row_sha256": COMPILER.digest(row),
        }
        return obligation_id, "zdr_" + COMPILER.digest(revision_context)

    def fuel_row(self, step: str, kind: str, link: tuple[str, str], question: str) -> dict:
        return {
            "schema": COMPILER.FUEL_SCHEMA,
            "fuel_kind": kind,
            "producer_step_id": step,
            "obligation_id": link[0],
            "revision_id": link[1],
            "source_refs": ["src/Vault.sol:9"],
            "asset_invariant": "assets conserved",
            "impact_class": "loss of funds",
            "question": question,
        }

    def build(
        self,
        *,
        reasoner_rows: list[dict] | None = None,
        linked_fuel: bool = False,
        corpus_rows: list[dict] | None = None,
        corpus_eligible: int | None = None,
        novelty_rows: list[dict] | None = None,
        awareness_candidates: list[dict] | None = None,
    ) -> None:
        rows = reasoner_rows if reasoner_rows is not None else [self.obligation_row()]
        self.write_jsonl(COMPILER.INVENTORY_RELATIVE, self.inventory_rows)
        awareness_path = self.ws / self.artifacts["artifact.step-0d-awareness"]
        awareness_path.parent.mkdir(parents=True, exist_ok=True)
        awareness_path.write_text(json.dumps({
            "schema": COMPILER.AWARENESS_LEDGER_SCHEMA,
            "audit_pin": "pin-1",
            "validation_errors": [],
            "fail_closed": False,
            "candidates": awareness_candidates or [],
        }), encoding="utf-8")
        self.awareness_receipt = self.receipt("step-0d", "artifact.step-0d-awareness", awareness_path)
        ledger_rows = rows
        if not (len(rows) == 1 and rows[0].get("schema") == COMPILER.EMPTY_LEDGER_SCHEMA):
            ledger_rows = [self.coverage_row(), *rows]
        reasoner_path = self.write_jsonl(self.artifacts["artifact.r"], ledger_rows)
        reasoner_receipt = self.receipt("step-r", "artifact.r", reasoner_path)
        if linked_fuel:
            link = self.expected_link(rows[0], reasoner_receipt, reasoner_path)
            corpus_rows = [self.fuel_row("step-4c", "corpus_hacker_question", link, "Can withdrawal omit its debit?")]
            novelty_rows = [self.fuel_row("step-2g-novelty-flywheel", "novelty_flywheel", link, "Is this invariant violation novel?")]
        corpus_rows = corpus_rows if corpus_rows is not None else []
        novelty_rows = novelty_rows if novelty_rows is not None else []
        corpus_path = self.write_jsonl(self.artifacts["artifact.step-4c"], corpus_rows)
        report_path = self.ws / self.artifacts["artifact.step-4c-hunt-report"]
        self.report_path = report_path
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps({
            "schema": "auditooor.corpus_driven_hunt.v1",
            "eligible": corpus_eligible if corpus_eligible is not None else (1 if corpus_rows else 0),
            "hacker_questions": [],
            "hypotheses": [],
            "zero_day_fuel": {"path": str(corpus_path), "rows": len(corpus_rows)},
        }), encoding="utf-8")
        novelty_path = self.write_jsonl(
            self.artifacts["artifact.step-2g-novelty-flywheel"], novelty_rows
        )
        receipts = {
            "step-0d": self.awareness_receipt,
            "step-r": reasoner_receipt,
            "step-4c": self.receipt(
                "step-4c",
                outputs=[
                    ("artifact.step-4c-hunt-report", report_path),
                    ("artifact.step-4c", corpus_path),
                ],
            ),
            "step-2g-novelty-flywheel": self.receipt(
                "step-2g-novelty-flywheel",
                "artifact.step-2g-novelty-flywheel",
                novelty_path,
            ),
        }
        for step_id, row in receipts.items():
            output = self.receipts / step_id / "attempt-1.json"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(row), encoding="utf-8")
        state_steps = {
            step_id: {
                "current_receipt_id": row["receipt_id"],
                "current_output_artifacts": row["output_artifacts"],
            }
            for step_id, row in receipts.items()
        }
        state_steps["step-2h-reasoner-regen"] = {
            "current_receipt_id": None,
            "current_output_artifacts": [],
        }
        state = {
            "schema": COMPILER.PIPELINE_STATE_SCHEMA,
            **self.baseline,
            "manifest_sha256": COMPILER.digest(self.manifest),
            "steps": state_steps,
        }
        self.state_path = self.aud / "pipeline" / "state.json"
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

    def compile(self) -> dict:
        return COMPILER.compile_freeze(
            self.ws,
            self.manifest_path,
            self.state_path,
            self.receipts,
            self.aud / "zero_day_bus",
        )

    def read_jsonl(self, name: str) -> list[dict]:
        path = self.aud / "zero_day_bus" / name
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def test_registry_selects_reasoner_and_excludes_orchestration(self) -> None:
        self.build(linked_fuel=True)
        receipt = self.compile()
        self.assertEqual(receipt["reasoner_count"], 1)
        self.assertEqual(receipt["obligation_count"], 1)
        obligation = self.read_jsonl("obligations.jsonl")[0]
        self.assertEqual(obligation["producer_step_id"], "step-r")
        self.assertNotIn("step-4c", receipt["reasoner_receipt_ids"])

    def test_linked_fuel_is_preserved_in_every_axis_and_receipt(self) -> None:
        self.build(linked_fuel=True)
        first = self.compile()
        questions = self.read_jsonl("questions.jsonl")
        self.assertEqual({row["axis"] for row in questions}, set(COMPILER.AXES))
        self.assertTrue(all(len(row["fuel_refs"]) == 2 for row in questions))
        payloads = [fuel["payload"]["question"] for fuel in questions[0]["fuel_refs"]]
        self.assertEqual(sorted(payloads), [
            "Can withdrawal omit its debit?",
            "Is this invariant violation novel?",
        ])
        self.assertEqual(first["fuel_row_count"], 2)
        self.assertEqual(first["fuel_counts"], {
            "step-2g-novelty-flywheel": 1,
            "step-4c": 1,
        })
        self.assertEqual(
            set(first["fuel_artifact_sha256"]),
            {"step-4c", "step-2g-novelty-flywheel"},
        )
        self.assertEqual(len(first["source_scope_severity_rules_fingerprint"]), 64)
        self.assertEqual(first, self.compile())

    def test_empty_step4c_fuel_requires_an_exhaustive_empty_hunt_report(self) -> None:
        self.build(corpus_eligible=1)
        with self.assertRaisesRegex(COMPILER.FreezeError, "step4c_empty_fuel_without_exhaustive_empty_report"):
            self.compile()

    def test_step4c_report_must_attest_the_exact_jsonl_fuel(self) -> None:
        self.build(linked_fuel=True)
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["zero_day_fuel"]["rows"] = 99
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(COMPILER.FreezeError, "artifact_hash_mismatch:step-4c:artifact.step-4c-hunt-report"):
            self.compile()

    def test_pre_freeze_identity_map_matches_freeze_identity_without_fuel_receipts(self) -> None:
        self.build()
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        for step_id in ("step-4c", "step-2g-novelty-flywheel"):
            del state["steps"][step_id]
            receipt_dir = self.receipts / step_id
            for path in receipt_dir.glob("*"):
                path.unlink()
            receipt_dir.rmdir()
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        output = self.aud / "zero_day_identity_map.jsonl"
        receipt = COMPILER.compile_identity_map(
            self.ws, self.manifest_path, self.state_path, self.receipts, output
        )
        rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line]
        reasoner_path = self.ws / self.artifacts["artifact.r"]
        reasoner_receipt = json.loads((self.receipts / "step-r" / "attempt-1.json").read_text())
        expected_obligation, expected_revision = self.expected_link(
            self.obligation_row(), reasoner_receipt, reasoner_path
        )
        self.assertEqual(receipt["identity_count"], 3)
        self.assertEqual(rows[0]["obligation_id"], expected_obligation)
        self.assertEqual(rows[0]["revision_id"], expected_revision)
        self.assertIn(
            "reasoner:step-r:" + COMPILER.digest(self.obligation_row()),
            {row["identity_key"] for row in rows},
        )
        self.assertEqual(
            {row["identity_key"] for row in rows if row["identity_key"].startswith("corpus_")},
            {
                "corpus_hypothesis:INV-WITHDRAW-DEBIT:withdraw",
                "corpus_hacker_question:INV-WITHDRAW-DEBIT:withdraw",
            },
        )
        with self.assertRaisesRegex(COMPILER.FreezeError, "missing_current_receipt:step-2g-novelty-flywheel"):
            self.compile()

    def test_pre_freeze_identity_map_rejects_missing_reasoner_receipt(self) -> None:
        self.build()
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        state["steps"]["step-r"]["current_receipt_id"] = "0" * 64
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaisesRegex(COMPILER.FreezeError, "missing_current_receipt:step-r"):
            COMPILER.compile_identity_map(
                self.ws, self.manifest_path, self.state_path, self.receipts,
                self.aud / "zero_day_identity_map.jsonl",
            )

    def test_identity_map_and_full_freeze_share_exact_ids(self) -> None:
        self.build(linked_fuel=True)
        output = self.aud / "zero_day_identity_map.jsonl"
        self.assertEqual(COMPILER.main([
            "--workspace", str(self.ws), "--manifest", str(self.manifest_path),
            "--write-identity-map", "--json",
        ]), 0)
        identity_row = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
        self.compile()
        obligation = self.read_jsonl("obligations.jsonl")[0]
        self.assertEqual(
            (identity_row["obligation_id"], identity_row["revision_id"]),
            (obligation["obligation_id"], obligation["revision_id"]),
        )

    def test_unlinked_or_untyped_step4c_and_flywheel_fuel_fails(self) -> None:
        bad_link = ("zdo_" + "0" * 64, "zdr_" + "1" * 64)
        cases = (
            {
                "corpus_rows": [self.fuel_row("step-4c", "corpus_hacker_question", bad_link, "bad")],
                "novelty_rows": [],
                "error": "unlinked_fuel:step-4c",
            },
            {
                "corpus_rows": [],
                "novelty_rows": [self.fuel_row("step-2g-novelty-flywheel", "novelty_flywheel", bad_link, "bad")],
                "error": "unlinked_fuel:step-2g-novelty-flywheel",
            },
            {
                "corpus_rows": [{"question_id": "raw", "question": "bypass"}],
                "novelty_rows": [],
                "error": "untyped_unlinked_fuel:step-4c",
            },
        )
        for case in cases:
            with self.subTest(case=case["error"]):
                self.build(corpus_rows=case["corpus_rows"], novelty_rows=case["novelty_rows"])
                with self.assertRaisesRegex(COMPILER.FreezeError, case["error"]):
                    self.compile()

    def test_global_examined_empty_requires_every_unit_and_all_axes(self) -> None:
        self.build(reasoner_rows=[self.empty_row(units=["unit-a"])])
        with self.assertRaisesRegex(COMPILER.FreezeError, "starved_empty_inventory_unit:unit-b"):
            self.compile()
        self.build(reasoner_rows=[self.empty_row(axes=list(COMPILER.AXES[:-1]))])
        with self.assertRaisesRegex(COMPILER.FreezeError, "malformed_examined_empty"):
            self.compile()
        self.build(reasoner_rows=[self.empty_row()])
        receipt = self.compile()
        proofs = self.read_jsonl("examined_empty.jsonl")
        self.assertEqual(receipt["obligation_count"], 0)
        self.assertEqual(receipt["examined_empty_count"], 2)
        self.assertEqual({row["inventory_unit_id"] for row in proofs}, {"unit-a", "unit-b"})
        self.assertTrue(all(row["schema"] == COMPILER.EMPTY_SCHEMA for row in proofs))
        self.assertTrue(all(row["examined_axes"] == list(COMPILER.AXES) for row in proofs))

    def test_positive_reasoner_coverage_requires_exact_examined_inventory(self) -> None:
        row = self.coverage_row()
        self.assertTrue(COMPILER.coverage_row(row, "step-r", "receipt-r"))
        row["examined_inventory_unit_ids"] = ["unit-a"]
        self.assertFalse(COMPILER.coverage_row(row, "step-r", "receipt-r"))

    def test_reviewed_awareness_binding_excludes_only_the_exact_obligation(self) -> None:
        logical = COMPILER.normalized_fields(self.obligation_row())
        candidate = {
            "candidate_id": "awareness-1",
            "terminal": True,
            "novelty_blocked": True,
            "state": "team_aware",
            "source_ids": ["issue-1"],
            "obligation_logical": logical,
        }
        self.build(awareness_candidates=[candidate])
        receipt = self.compile()
        self.assertEqual(receipt["obligation_count"], 0)
        self.assertEqual(receipt["awareness_exclusion_count"], 1)
        rows = self.read_jsonl("awareness_exclusions.jsonl")
        self.assertEqual(rows[0]["candidate_id"], "awareness-1")
        self.assertEqual(rows[0]["obligation_id"], "zdo_" + COMPILER.digest(logical))

    def test_unbound_team_aware_candidate_blocks_freeze_instead_of_guessing(self) -> None:
        self.build(awareness_candidates=[{
            "candidate_id": "awareness-unbound",
            "terminal": True,
            "novelty_blocked": True,
            "state": "team_aware",
            "source_ids": ["issue-1"],
        }])
        with self.assertRaisesRegex(COMPILER.FreezeError, "awareness_obligation_binding_missing"):
            self.compile()

    def test_revision_staleness_hash_binding_and_conflict(self) -> None:
        self.build()
        self.compile()
        first = self.read_jsonl("obligations.jsonl")[0]
        self.baseline["source_snapshot_sha256"] = "b" * 64
        self.build()
        self.compile()
        second = self.read_jsonl("obligations.jsonl")[0]
        self.assertEqual(first["obligation_id"], second["obligation_id"])
        self.assertNotEqual(first["revision_id"], second["revision_id"])
        state = json.loads(self.state_path.read_text())
        state["source_snapshot_sha256"] = "c" * 64
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaisesRegex(COMPILER.FreezeError, "receipt_provenance_mismatch"):
            self.compile()

        self.build()
        (self.ws / self.artifacts["artifact.r"]).write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(COMPILER.FreezeError, "artifact_hash_mismatch"):
            self.compile()

        self.build(reasoner_rows=[self.obligation_row(), self.obligation_row("src/Vault.sol:10")])
        with self.assertRaisesRegex(COMPILER.FreezeError, "conflicting_duplicate_logical_row"):
            self.compile()


if __name__ == "__main__":
    unittest.main()
