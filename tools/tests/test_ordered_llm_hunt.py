#!/usr/bin/env python3
"""Hermetic coverage for the frozen-bus Step 3 hunt runner."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "ordered-llm-hunt.py"
SPEC = importlib.util.spec_from_file_location("ordered_llm_hunt_test", TOOL)
assert SPEC and SPEC.loader
HUNT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HUNT
SPEC.loader.exec_module(HUNT)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def write_jsonl(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
                    encoding="utf-8")


class FakeRunner:
    def __init__(self, *, skip_task: str | None = None):
        self.skip_task = skip_task
        self.calls: list[list[str]] = []

    def __call__(self, argv, cwd, environment, timeout):
        self.calls.append(list(argv))
        output = Path(argv[argv.index("--output-last-message") + 1])
        if output.stem != self.skip_task:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps({
                "applies_to_target": "no",
                "confidence": "high",
                "candidate_finding": "source-cited rule out",
                "file_line": "src/A.sol:1",
                "code_excerpt": "contract A {}",
                "severity_estimate": "NA",
                "rubric_row_cited": "NA",
                "dupe_check": "none",
                "falsification_attempt": "reviewed source",
                "notes": "nonterminal hunt evidence",
            }), encoding="utf-8")
        return HUNT.CommandResult(0)


class MismatchedExcerptRunner(FakeRunner):
    def __call__(self, argv, cwd, environment, timeout):
        output = Path(argv[argv.index("--output-last-message") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({
            "applies_to_target": "maybe",
            "confidence": "medium",
            "candidate_finding": "unverified candidate",
            "file_line": "src/A.sol:1",
            "code_excerpt": "function unrelated() external { drain(); }",
            "severity_estimate": "unknown",
            "rubric_row_cited": "unknown",
            "dupe_check": "pending",
            "falsification_attempt": "not terminal",
            "notes": "nonterminal hunt evidence",
        }), encoding="utf-8")
        return HUNT.CommandResult(0)


class OrderedLlmHuntTest(unittest.TestCase):
    def make_workspace(self, root: Path, *, obligation_count: int = 1,
                       axes: tuple[str, ...] = HUNT.AXES, inventory_count: int = 1,
                       global_empty_proof: bool = False, with_bus: bool = True) -> tuple[Path, list[dict], list[dict]]:
        ws = root / "ws"
        (ws / "src").mkdir(parents=True)
        (ws / "src" / "A.sol").write_text("contract A {}\n", encoding="utf-8")
        (ws / "SCOPE.md").write_text("scope\n", encoding="utf-8")
        (ws / "SEVERITY.md").write_text("severity\n", encoding="utf-8")
        write_json(ws / ".auditooor" / "program_rules.json", {"rules": ["x"]})
        inventory = [{"unit_id": "src/A.sol::f:1", "file": "src/A.sol", "function": "f", "start_line": 1}]
        write_jsonl(ws / ".auditooor" / "inscope_units.jsonl", inventory[:inventory_count])
        write_json(ws / ".auditooor" / "attestations" / "step-0f.json", {
            "available_tier": "local",
            "backend_verified_by": "operator",
            "provider": "codex",
            "model": "gpt-test",
            "dispatch_route": "codex-cli",
            "verification_command": "codex --version",
            "verification_result": "pass",
        })
        obligations: list[dict] = []
        questions: list[dict] = []
        producer_receipt_id = "a" * 64
        for number in range(obligation_count):
            logical = {
                "target_unit": f"src/A.sol::f:{number}",
                "asset_invariant": "assets conserved",
                "violation_relation": f"candidate relation {number}",
                "actor_model": "permissionless attacker",
                "impact_class": "loss of funds",
            }
            obligation_id = "zdo_" + HUNT._stable_hash(logical)
            fingerprint = HUNT._stable_hash({"revision": number})
            revision_id = "zdr_" + fingerprint
            obligation = {
                "schema": HUNT.OBLIGATION_SCHEMA,
                "obligation_id": obligation_id,
                "revision_id": revision_id,
                "producer_step_id": "step-r",
                "reasoner_id": "r",
                "producer_receipt_id": producer_receipt_id,
                "logical": logical,
                "source_row_sha256": HUNT._stable_hash({"row": number}),
                "source_refs": ["src/A.sol:1"],
                "proof_task_kind": "executable_falsification",
                "required_positive_assertions": [],
                "required_negative_controls": [],
                "input_fingerprint": fingerprint,
                "fuel_ids": [],
            }
            obligations.append(obligation)
            question_fingerprint = HUNT._stable_hash({
                "obligation_input_fingerprint": fingerprint,
                "fuel_source_row_sha256": [],
            })
            for axis in axes:
                body = {
                    "obligation_id": obligation_id,
                    "revision_id": revision_id,
                    "axis": axis,
                    "input_fingerprint": question_fingerprint,
                }
                questions.append({
                    "schema": HUNT.QUESTION_SCHEMA,
                    "question_id": "zdq_" + HUNT._stable_hash(body),
                    "parent_ids": [obligation_id, revision_id],
                    "axis": axis,
                    "required_evidence": ["source_citation", "local_or_chain_evidence",
                                          "non_provider_terminal_verdict"],
                    "proof_route": f"Examine {axis}.",
                    "fuel_refs": [],
                    "input_fingerprint": question_fingerprint,
                })
        if with_bus:
            self.write_bus(ws, obligations, questions, producer_receipt_id,
                           include_global_proof=global_empty_proof)
        return ws, obligations, questions

    def write_bus(self, ws: Path, obligations: list[dict], questions: list[dict],
                  producer_receipt_id: str, *, include_global_proof: bool = False) -> None:
        bus = ws / ".auditooor" / "zero_day_bus"
        obligations_path = bus / "obligations.jsonl"
        questions_path = bus / "questions.jsonl"
        empty_path = bus / "examined_empty.jsonl"
        write_jsonl(obligations_path, obligations)
        write_jsonl(questions_path, questions)
        current = HUNT._current_inputs(ws)
        provenance = {field: "b" * 64 for field in HUNT.PROVENANCE_HASH_FIELDS}
        provenance.update({
            "source_snapshot_sha256": current["source_snapshot_sha256"],
            "scope_sha256": current["scope_sha256"],
            "severity_sha256": current["severity_sha256"],
            "program_rules_sha256": current["program_rules_sha256"],
        })
        combined = HUNT._stable_hash({
            "source_snapshot_sha256": current["source_snapshot_sha256"],
            "scope_sha256": current["scope_sha256"],
            "severity_sha256": current["severity_sha256"],
            "program_rules_sha256": current["program_rules_sha256"],
        })
        input_fingerprint = HUNT._stable_hash({
            "manifest_sha256": provenance["manifest_sha256"],
            "state_sha256": "c" * 64,
            "producer_receipt_ids": [producer_receipt_id],
            "reasoner_receipt_ids": [producer_receipt_id],
            "fuel_artifact_hashes": {},
            "fuel_rows_sha256": HUNT._stable_hash([]),
            "inventory_sha256": current["inventory_sha256"],
            "source_scope_severity_rules_fingerprint": combined,
            "pipeline_tooling_sha256": provenance["pipeline_tooling_sha256"],
        })
        empty_rows = []
        if include_global_proof:
            for unit_id in current["unit_ids"]:
                body = {
                    "inventory_unit_id": unit_id,
                    "examined_axes": list(HUNT.AXES),
                    "reasoner_step_ids": ["step-r"],
                    "reasoner_receipt_ids": [producer_receipt_id],
                    "source_refs": ["src/A.sol:1"],
                    "input_fingerprint": input_fingerprint,
                }
                empty_rows.append({"schema": HUNT.EMPTY_SCHEMA,
                                   "empty_proof_id": "zde_" + HUNT._stable_hash(body), **body})
        write_jsonl(empty_path, empty_rows)
        receipt = {
            "schema": HUNT.BUS_RECEIPT_SCHEMA,
            "manifest_sha256": provenance["manifest_sha256"],
            "state_sha256": "c" * 64,
            "provenance": provenance,
            "producer_receipt_ids": [producer_receipt_id],
            "reasoner_receipt_ids": [producer_receipt_id],
            "reasoner_count": 1,
            "obligation_count": len(obligations),
            "question_count": len(questions),
            "examined_empty_count": len(empty_rows),
            "empty_explanations": {},
            "inventory_count": len(current["unit_ids"]),
            "inventory_sha256": current["inventory_sha256"],
            "fuel_artifact_sha256": {},
            "fuel_counts": {},
            "fuel_row_count": 0,
            "fuel_rows_sha256": HUNT._stable_hash([]),
            "source_scope_severity_rules_fingerprint": combined,
            "obligations_sha256": HUNT._sha256_file(obligations_path),
            "questions_sha256": HUNT._sha256_file(questions_path),
            "examined_empty_sha256": HUNT._sha256_file(empty_path),
            "input_fingerprint": input_fingerprint,
        }
        receipt["receipt_id"] = HUNT._stable_hash(receipt)
        write_json(bus / "freeze_receipt.json", receipt)

    def test_dispatches_every_typed_question_and_top_n_only_orders(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ws, _obligations, questions = self.make_workspace(Path(temporary))
            runner = FakeRunner()
            manifest = HUNT.run_ordered_hunt(ws, top_n=1, runner=runner)
            self.assertEqual("completed", manifest["status"])
            self.assertEqual(len(HUNT.AXES), manifest["all_typed_questions_denominator"])
            self.assertEqual(1, manifest["scheduled_priority_count"])
            self.assertEqual(len(HUNT.AXES), manifest["dispatched_count"])
            self.assertEqual(len(HUNT.AXES), manifest["completed_count"])
            self.assertEqual(len(questions), len(runner.calls))
            self.assertTrue(all(call[0:3] == ["codex", "exec", "--full-auto"] for call in runner.calls))
            self.assertEqual({question["question_id"] for question in questions},
                             {task["question_id"] for task in manifest["tasks"]})
            self.assertTrue(all(task["terminal"] is False for task in manifest["tasks"]))

    def test_provider_excerpt_must_match_the_claimed_source_window(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ws, _obligations, _questions = self.make_workspace(Path(temporary))
            with self.assertRaisesRegex(HUNT.HuntError, "provider_result_code_excerpt_source_mismatch"):
                HUNT.run_ordered_hunt(ws, runner=MismatchedExcerptRunner())
            manifest = json.loads((ws / ".auditooor" / "ordered_hunt" / "manifest.json").read_text())
            self.assertEqual("failed", manifest["status"])
            self.assertEqual(0, manifest["completed_count"])

    def test_current_hunt_validator_rejects_tampered_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ws, _obligations, _questions = self.make_workspace(Path(temporary))
            manifest = HUNT.run_ordered_hunt(ws, runner=FakeRunner())
            validated = HUNT.validate_current_ordered_hunt(ws)
            self.assertEqual(manifest["bus_receipt_id"], validated["bus"]["receipt"]["receipt_id"])
            task = manifest["tasks"][0]
            sidecar_path = Path(task["sidecar_path"])
            sidecar_path = sidecar_path if sidecar_path.is_absolute() else ws / sidecar_path
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
            sidecar["axis"] = "tampered"
            sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
            with self.assertRaisesRegex(HUNT.HuntError, "ordered_hunt_sidecar_hash_mismatch"):
                HUNT.validate_current_ordered_hunt(ws)

    def test_partial_q0_q8_axis_set_fails_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ws, _obligations, _questions = self.make_workspace(
                Path(temporary), axes=HUNT.AXES[:-1],
            )
            runner = FakeRunner()
            with self.assertRaisesRegex(HUNT.HuntError, "zero_day_question_axis_set_incomplete"):
                HUNT.run_ordered_hunt(ws, runner=runner)
            self.assertEqual([], runner.calls)

    def test_question_parent_must_match_exact_obligation_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ws, _obligations, questions = self.make_workspace(Path(temporary))
            question = questions[0]
            question["parent_ids"] = [question["parent_ids"][0], "zdr_" + "f" * 64]
            body = {
                "obligation_id": question["parent_ids"][0],
                "revision_id": question["parent_ids"][1],
                "axis": question["axis"],
                "input_fingerprint": question["input_fingerprint"],
            }
            question["question_id"] = "zdq_" + HUNT._stable_hash(body)
            bus = ws / ".auditooor" / "zero_day_bus"
            write_jsonl(bus / "questions.jsonl", questions)
            receipt = json.loads((bus / "freeze_receipt.json").read_text())
            receipt["questions_sha256"] = HUNT._sha256_file(bus / "questions.jsonl")
            receipt.pop("receipt_id")
            receipt["receipt_id"] = HUNT._stable_hash(receipt)
            write_json(bus / "freeze_receipt.json", receipt)
            runner = FakeRunner()
            with self.assertRaisesRegex(HUNT.HuntError, "zero_day_question_parent_missing"):
                HUNT.run_ordered_hunt(ws, runner=runner)
            self.assertEqual([], runner.calls)

    def test_legacy_reasoner_and_hunt_inputs_cannot_earn_credit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ws, _obligations, _questions = self.make_workspace(Path(temporary), with_bus=False)
            write_jsonl(ws / ".auditooor" / "reasoner_regen_receipts.jsonl",
                        [{"ledger": "old.jsonl", "rc": 0}])
            write_json(ws / ".auditooor" / "corpus_driven_hunt.json", {"hacker_questions": [{"id": "old"}]})
            write_jsonl(ws / ".auditooor" / "novelty" / "burndown_feed.jsonl", [{"id": "old"}])
            write_json(ws / ".auditooor" / "hunt_findings_sidecars" / "old.json", {"status": "ok"})
            runner = FakeRunner()
            with self.assertRaisesRegex(HUNT.HuntError, "missing_zero_day_bus_receipt"):
                HUNT.run_ordered_hunt(ws, runner=runner)
            self.assertEqual([], runner.calls)

    def test_zero_questions_never_silently_green(self) -> None:
        for inventory_count in (0, 1):
            with self.subTest(inventory_count=inventory_count), tempfile.TemporaryDirectory() as temporary:
                ws, _obligations, _questions = self.make_workspace(
                    Path(temporary), obligation_count=0, inventory_count=inventory_count,
                )
                runner = FakeRunner()
                with self.assertRaisesRegex(HUNT.HuntError,
                                            "no_applicable_inventory_units|examined_empty_unit_coverage_mismatch"):
                    HUNT.run_ordered_hunt(ws, runner=runner)
                self.assertEqual([], runner.calls)

    def test_typed_global_examined_empty_proof_is_required_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ws, _obligations, _questions = self.make_workspace(
                Path(temporary), obligation_count=0, global_empty_proof=True,
            )
            manifest = HUNT.run_ordered_hunt(ws, runner=FakeRunner())
            self.assertEqual("completed-examined-empty", manifest["status"])
            self.assertEqual(1, len(manifest["examined_empty_proofs"]))
            self.assertEqual(list(HUNT.AXES), manifest["examined_empty_proofs"][0]["examined_axes"])

    def test_partial_provider_capture_fails_without_denominator_credit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ws, _obligations, questions = self.make_workspace(Path(temporary))
            runner = FakeRunner(skip_task=questions[-1]["question_id"])
            with self.assertRaisesRegex(HUNT.HuntError, "provider_sidecar_missing"):
                HUNT.run_ordered_hunt(ws, runner=runner)
            manifest = json.loads((ws / ".auditooor" / "ordered_hunt" / "manifest.json").read_text())
            self.assertEqual("failed", manifest["status"])
            self.assertEqual(len(HUNT.AXES), manifest["all_typed_questions_denominator"])
            self.assertLess(manifest["completed_count"], manifest["all_typed_questions_denominator"])

    def test_current_source_or_policy_change_invalidates_frozen_bus(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ws, _obligations, _questions = self.make_workspace(Path(temporary))
            (ws / "SCOPE.md").write_text("changed scope\n", encoding="utf-8")
            runner = FakeRunner()
            with self.assertRaisesRegex(HUNT.HuntError, "zero_day_bus_current_fingerprint_mismatch"):
                HUNT.run_ordered_hunt(ws, runner=runner)
            self.assertEqual([], runner.calls)


if __name__ == "__main__":
    unittest.main()
