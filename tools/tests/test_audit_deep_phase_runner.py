#!/usr/bin/env python3
"""Hermetic tests for strict audit-deep phase ownership and contracts."""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit-deep-phase-runner.py"
spec = importlib.util.spec_from_file_location("strict_phase_runner", TOOL)
runner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(runner)


class Completed:
    def __init__(self, rc: int = 0, stdout: str = "", stderr: str = "", timed_out: bool = False) -> None:
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


class StrictPhaseRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.ws = self.root / "ws"
        (self.ws / ".auditooor").mkdir(parents=True)
        self._set_language("solidity")
        (self.ws / "SCOPE.md").write_text("All canonical inventory sources are in scope.\n", encoding="utf-8")
        (self.ws / "SEVERITY.md").write_text("High: loss of in-scope assets.\n", encoding="utf-8")
        self._write(".auditooor/program_rules.json", {"rules": ["No admin compromise"]})

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    def _set_language(self, language: str) -> None:
        definitions = {
            "solidity": ("src/Vault.sol", "contract Vault {}\n", "solidity"),
            "go": ("src/vault.go", "package vault\n", "go"),
            "rust": ("src/lib.rs", "pub fn deposit() {}\n", "rust"),
            "javascript": ("src/vault.js", "function deposit() {}\n", "javascript"),
            "typescript": ("src/vault.ts", "function deposit() {}\n", "typescript"),
            "vyper": ("src/Vault.vy", "@external\ndef deposit(): pass\n", "vyper"),
            "oscript": ("src/agent.oscript", "{bounce_fees: {base: 10000}}\n", "oscript"),
        }
        rel, body, declared = definitions[language]
        src = self.ws / rel
        if (self.ws / "src").exists():
            shutil.rmtree(self.ws / "src")
        src.parent.mkdir(parents=True)
        src.write_text(body, encoding="utf-8")
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": rel, "lang": declared, "function": "deposit"}) + "\n",
            encoding="utf-8",
        )

    def _zero_day_and_ordered_hunt(self) -> None:
        aud = self.ws / ".auditooor"
        ordered = runner._load_repo_module("_audit_deep_ordered_hunt", "tools/ordered-llm-hunt.py")
        current = ordered._current_inputs(self.ws)
        producer_id = "c" * 64
        logical = {
            "target_unit": "src/Vault.sol:deposit",
            "asset_invariant": "vault assets are conserved",
            "violation_relation": "assets leave without equivalent debit",
            "actor_model": "untrusted public caller",
            "impact_class": "loss of funds",
        }
        input_fingerprint = "d" * 64
        obligation = {
            "schema": ordered.OBLIGATION_SCHEMA,
            "obligation_id": "zdo_" + ordered._stable_hash(logical),
            "revision_id": "zdr_" + input_fingerprint,
            "producer_receipt_id": producer_id,
            "source_row_sha256": "6" * 64,
            "source_refs": ["src/Vault.sol:1"],
            "logical": logical,
            "fuel_ids": [],
            "input_fingerprint": input_fingerprint,
        }
        questions = []
        question_input_fingerprint = ordered._stable_hash({
            "obligation_input_fingerprint": input_fingerprint,
            "fuel_source_row_sha256": [],
        })
        for axis in ordered.AXES:
            body = {
                "obligation_id": obligation["obligation_id"],
                "revision_id": obligation["revision_id"],
                "axis": axis,
                "input_fingerprint": question_input_fingerprint,
            }
            questions.append({
                "schema": ordered.QUESTION_SCHEMA,
                "question_id": "zdq_" + ordered._stable_hash(body),
                "parent_ids": [obligation["obligation_id"], obligation["revision_id"]],
                "axis": axis,
                "required_evidence": ["source_citation", "local_or_chain_evidence", "non_provider_terminal_verdict"],
                "proof_route": "source review",
                "fuel_refs": [],
                "input_fingerprint": question_input_fingerprint,
            })
        bus = aud / "zero_day_bus"
        bus.mkdir(exist_ok=True)
        obligations_path = bus / "obligations.jsonl"
        questions_path = bus / "questions.jsonl"
        examined_empty_path = bus / "examined_empty.jsonl"
        obligations_path.write_text(json.dumps(obligation, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        questions_path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in questions), encoding="utf-8")
        examined_empty_path.write_text("", encoding="utf-8")
        provenance = {
            "manifest_sha256": "1" * 64,
            "workspace_identity_sha256": "2" * 64,
            "source_snapshot_sha256": current["source_snapshot_sha256"],
            "scope_sha256": current["scope_sha256"],
            "severity_sha256": current["severity_sha256"],
            "targets_sha256": "3" * 64,
            "program_rules_sha256": current["program_rules_sha256"],
            "pipeline_tooling_sha256": "4" * 64,
        }
        source_binding = ordered._stable_hash({
            "source_snapshot_sha256": current["source_snapshot_sha256"],
            "scope_sha256": current["scope_sha256"],
            "severity_sha256": current["severity_sha256"],
            "program_rules_sha256": current["program_rules_sha256"],
        })
        fuel_rows_sha256 = ordered._stable_hash([])
        freeze_input = ordered._stable_hash({
            "manifest_sha256": provenance["manifest_sha256"],
            "state_sha256": "5" * 64,
            "producer_receipt_ids": [producer_id],
            "reasoner_receipt_ids": [producer_id],
            "fuel_artifact_hashes": {},
            "fuel_rows_sha256": fuel_rows_sha256,
            "inventory_sha256": current["inventory_sha256"],
            "source_scope_severity_rules_fingerprint": source_binding,
            "pipeline_tooling_sha256": provenance["pipeline_tooling_sha256"],
        })
        freeze = {
            "schema": ordered.BUS_RECEIPT_SCHEMA,
            "manifest_sha256": provenance["manifest_sha256"],
            "state_sha256": "5" * 64,
            "provenance": provenance,
            "producer_receipt_ids": [producer_id],
            "reasoner_receipt_ids": [producer_id],
            "reasoner_count": 1,
            "obligation_count": 1,
            "question_count": len(questions),
            "examined_empty_count": 0,
            "empty_explanations": {},
            "inventory_count": len(current["unit_ids"]),
            "inventory_sha256": current["inventory_sha256"],
            "fuel_artifact_sha256": {},
            "fuel_counts": {},
            "fuel_row_count": 0,
            "fuel_rows_sha256": fuel_rows_sha256,
            "source_scope_severity_rules_fingerprint": source_binding,
            "obligations_sha256": runner._sha256_bytes(obligations_path.read_bytes()),
            "questions_sha256": runner._sha256_bytes(questions_path.read_bytes()),
            "examined_empty_sha256": runner._sha256_bytes(examined_empty_path.read_bytes()),
            "input_fingerprint": freeze_input,
        }
        freeze["receipt_id"] = ordered._stable_hash(freeze)
        freeze_path = bus / "freeze_receipt.json"
        freeze_path.write_text(json.dumps(freeze, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

        hunt = aud / "ordered_hunt"
        sidecars = hunt / "sidecars"
        sidecars.mkdir(parents=True)
        tasks = []
        for question in questions:
            sidecar_path = sidecars / f"{question['question_id']}.json"
            prompt_sha256 = ordered._stable_hash({"prompt": question["question_id"]})
            command_sha256 = ordered._stable_hash({"command": question["question_id"]})
            sidecar = {
                "schema": ordered.SIDECAR_SCHEMA,
                "task_id": question["question_id"],
                "question_id": question["question_id"],
                "parent_ids": question["parent_ids"],
                "axis": question["axis"],
                "input_fingerprint": input_fingerprint,
                "status": "captured",
                "terminal": False,
                "evidence_class": "nonterminal-hunt-evidence",
                "provider": "fixture-provider",
                "model": "fixture-model",
                "prompt_sha256": prompt_sha256,
                "command_sha256": command_sha256,
            }
            sidecar_path.write_text(json.dumps(sidecar, sort_keys=True), encoding="utf-8")
            tasks.append({
                "task_id": question["question_id"],
                "question_id": question["question_id"],
                "parent_ids": question["parent_ids"],
                "axis": question["axis"],
                "provider": "fixture-provider",
                "model": "fixture-model",
                "terminal": False,
                "evidence_class": "nonterminal-hunt-evidence",
                "prompt_sha256": prompt_sha256,
                "command_sha256": command_sha256,
                "sidecar_path": sidecar_path.relative_to(self.ws).as_posix(),
                "sidecar_sha256": runner._sha256_bytes(sidecar_path.read_bytes()),
            })
        question_ids = [row["question_id"] for row in questions]
        manifest = {
            "schema": ordered.SCHEMA,
            "workspace": str(self.ws),
            "status": "completed",
            "errors": [],
            "tasks": tasks,
            "bus_receipt_id": freeze["receipt_id"],
            "bus_input_fingerprint": freeze["input_fingerprint"],
            "bus_fingerprints": {
                "freeze_receipt_sha256": runner._sha256_bytes(freeze_path.read_bytes()),
                "obligations_sha256": freeze["obligations_sha256"],
                "questions_sha256": freeze["questions_sha256"],
                "examined_empty_sha256": freeze["examined_empty_sha256"],
            },
            "current_fingerprints": {
                "inventory_sha256": current["inventory_sha256"],
                "source_snapshot_sha256": current["source_snapshot_sha256"],
                "scope_sha256": current["scope_sha256"],
                "severity_sha256": current["severity_sha256"],
                "program_rules_sha256": current["program_rules_sha256"],
            },
            "all_typed_questions_denominator": len(questions),
            "dispatched_count": len(questions),
            "completed_count": len(questions),
            "reconciliation": {
                "expected_task_ids": question_ids,
                "completed_task_ids": question_ids,
                "missing_task_ids": [],
            },
        }
        manifest_path = hunt / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        (hunt / "receipt.json").write_text(json.dumps({
            "schema": ordered.RECEIPT_SCHEMA,
            "manifest_sha256": runner._sha256_bytes(manifest_path.read_bytes()),
            "status": "completed",
            "terminal_evidence": False,
            "all_typed_questions_denominator": len(questions),
            "dispatched_count": len(questions),
            "completed_count": len(questions),
        }, sort_keys=True), encoding="utf-8")

    def _drive_inputs(self, *, worklist: bool = True, grounded: bool = True) -> None:
        self._zero_day_and_ordered_hunt()
        aud = self.ws / ".auditooor"
        (aud / "depth_certificate.json").write_text(json.dumps({"schema": "auditooor.depth_certificate.v1", "verdict": "depth-audited"}), encoding="utf-8")
        rows = []
        markdown = ["# Invariant Ledger\n\n"]
        for index in range(1, 6):
            invariant_id = f"I-{index}"
            row = {
                "id": invariant_id, "scope_asset": "vault",
                "invariant_family": "asset_conservation",
                "statement": f"Invariant {index} conserves assets",
                "source_citations": [], "attacker_capability": "public caller",
                "trusted_boundary": "operator keys remain honest",
                "oos_boundary": "admin compromise excluded",
                "production_path": "src/Vault.sol:1",
                "harness_target": "test/Vault.t.sol",
                "required_engine": "forge", "negative_test": "unauthorized mint",
                "status": "missing_harness", "artifacts": [], "owner": "human",
            }
            rows.append(row)
            heading = "I-WRONG" if not grounded and index == 1 else invariant_id
            markdown.extend([
                f"## {heading}\n\n", "- scope_asset: vault\n",
                "- invariant_family: asset_conservation\n",
                f"- statement: Invariant {index} conserves assets\n",
                "- source_citations:\n", "- attacker_capability: public caller\n",
                "- trusted_boundary: operator keys remain honest\n",
                "- oos_boundary: admin compromise excluded\n",
                "- production_path: src/Vault.sol:1\n",
                "- harness_target: test/Vault.t.sol\n",
                "- required_engine: forge\n", "- negative_test: unauthorized mint\n",
                "- status: missing_harness\n", "- artifacts:\n", "- owner: human\n\n",
            ])
        ledger = {"schema_version": "auditooor.invariant_ledger.v1", "rows": rows}
        (aud / "invariant_ledger.json").write_text(json.dumps(ledger), encoding="utf-8")
        (self.ws / "INVARIANT_LEDGER.md").write_text("".join(markdown), encoding="utf-8")
        attest = aud / "attestations"
        attest.mkdir(exist_ok=True)
        (attest / "step-4b.json").write_text(json.dumps({
            "completed_at": "2026-07-17T00:00:00Z", "attested_by": "operator",
            "summary": "reviewed", "invariant_count": 5, "invariant_ids": [f"I-{index}" for index in range(1, 6)],
            "harness_file_paths": ["test/Vault.t.sol"],
            "economic_properties_summary": "Assets are conserved.",
        }), encoding="utf-8")
        if worklist:
            source = json.loads((aud / "inscope_units.jsonl").read_text())
            (aud / "fuzz_targets.jsonl").write_text(json.dumps({
                "schema_version": "auditooor.fuzz_target_worklist.v1",
                "asset_path": source["file"], "functions": ["deposit"],
                "needs_campaign": True, "verdict": "campaign-pending",
            }) + "\n", encoding="utf-8")

    def _write(self, rel: str, value: object) -> None:
        path = self.ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, str):
            path.write_text(value, encoding="utf-8")
        else:
            path.write_text(json.dumps(value), encoding="utf-8")

    def _default_fake(self, *, warning_tool: str | None = None, timeout_tool: str | None = None):
        def call(argv, **_kwargs):
            tool = argv[1] if len(argv) > 1 else argv[0]
            if timeout_tool and timeout_tool in tool:
                return Completed(timed_out=True)
            stdout = ""
            if tool == "tools/regex-detectors-orchestrator.py":
                self._write(".auditooor/strict_audit_deep/engine/solidity-regex.json", {
                    "schema": "auditooor.regex_detectors_solidity.v1", "status": "ok",
                    "runner_returncode": 0, "files_scanned": 1, "detectors_loaded": 2,
                })
                self._write(".auditooor/strict_audit_deep/engine/solidity-regex.findings.jsonl", "")
            elif tool == "tools/go-detector-runner.py":
                self._write(".auditooor/go_findings.json", {"schema_version": 1, "go_files_scanned": 1, "patterns": {}, "totals": {"hits": 0, "files": 0}})
            elif tool == "tools/rust-source-graph.py":
                self._write(".auditooor/strict_audit_deep/engine/rust-source-graph.json", {"_meta": {"schema_version": "auditooor.rust_source_graph.v1", "crate_count": 1}, "crate": {"files_scanned": 1}})
            elif tool == "tools/rust-cross-crate-graph.py":
                self._write(".auditooor/strict_audit_deep/engine/rust-cross-crate-graph.json", {"_meta": {"schema_version": "auditooor.rust_cross_crate_graph.v1", "crate_count": 1}, "crates": {"crate": {}}, "edges": []})
            elif tool == "tools/js-oscript-value-moving-surface.py":
                self._write(".auditooor/strict_audit_deep/engine/js-oscript-value-surface.json", {"tool": "js-oscript-value-moving-surface", "verdict": "no-findings", "surface": [], "findings": [], "exempt_files": []})
            elif tool == "tools/depth-probe-runner.py":
                self._write(".auditooor/depth_probes/batch_000.jsonl", json.dumps({"guard_id": "G-1", "file_line": "src/Vault.sol:1", "code_excerpt": "contract Vault", "gap_found": False, "why_no_gap_or_exploit": "Vault line 1 enforces the concrete access predicate", "probe_source": "depth-probe-runner"}) + "\n")
                stdout = json.dumps({"schema": "auditooor.depth_probe_runner.v1", "verdict": "all-batches-ok", "packets_read": 1, "batches_failed": 0, "probes_emitted": 1, "live_fallback_to_agent_batches": None})
            elif tool == "tools/function-coverage-completeness.py":
                self._write(".auditooor/function_coverage_completeness.json", {"schema": "auditooor.function_coverage_completeness.v1", "verdict": "pass-fully-covered", "counts": {"total": 1, "hollow": 0, "untouched": 0}})
                stdout = "{}"
            elif tool == "tools/depth-probe-ingest.py":
                self._write(".auditooor/negative_space_gaps.jsonl", json.dumps({"guard_id": "G-1"}) + "\n")
                stdout = json.dumps({"schema": "auditooor.depth_probe_ingest.v1", "verdict": "ingested-genuine", "probes_read": 1, "r76_fail": 0, "bulk_template_detected": False, "genuine": 1, "ingested": 1})
            elif tool == "tools/depth-certificate-build.py":
                self._write(".auditooor/depth_certificate.json", {"schema": "auditooor.depth_certificate.v1", "verdict": "depth-audited"})
            elif tool == "harness-scaffold":
                self._write(".auditooor/harness_plans.json", {"plans": ["deposit"]})
                self._write(".auditooor/harness_binding_manifest.json", {"schema": "auditooor.harness_binding_manifest.v0", "row_count": 1, "ready_count": 1, "blocked_count": 0, "executable_command_count": 1, "rows": [{}]})
            elif tool == "tools/fuzz-runner.sh":
                self._write(".auditooor/strict_audit_deep/drive/solidity-fuzz/manifest.json", {"status": "pass"})
            elif tool == "tools/per-function-invariant-gen.py":
                language = argv[argv.index("--lang") + 1]
                self._write(f".auditooor/strict_audit_deep/drive/{language}-harnesses/manifest.json", {"schema": "auditooor.per_function_invariant_gen.v1", "language": language, "function_count": 1, "sentinel_count": 0, "non_sentinel_count": 1, "functions": [{}]})
            elif tool == "tools/go-dynamic-engine-runner.sh":
                self._write(".auditooor/strict_audit_deep/drive/go-fuzz/manifest.json", {"status": "pass"})
            elif tool == "tools/rust-proptest-engine-runner.sh":
                self._write(".auditooor/strict_audit_deep/drive/rust-fuzz/manifest.json", {"status": "pass"})
            stderr = "WARN injected" if warning_tool and warning_tool in tool else ""
            return Completed(stdout=stdout, stderr=stderr)
        return call

    def _receipt(self, mode: str) -> dict:
        return json.loads((self.ws / ".auditooor" / "strict_audit_deep" / f"{mode}_receipt.json").read_text())

    def test_default_registry_preflight_and_phase_ownership(self) -> None:
        registry = runner._default_registry()
        runner.preflight_registry(registry, ROOT)
        engine_argv = " ".join(part for command in registry["engine-substrates"] for part in command["argv"])
        self.assertNotIn("dataflow", engine_argv)
        self.assertNotIn("state-coupling", engine_argv)
        self.assertNotIn("semantic-graph", engine_argv)
        self.assertEqual(
            {command["id"] for command in registry["engine-substrates"]},
            {"solidity-semantic-engine", "go-semantic-engine", "rust-semantic-engine"},
        )
        mutation = next(command for command in registry["depth-probe"] if command["id"] == "per-function-mutation")
        self.assertIn("--check", mutation["argv"])
        self.assertNotIn("--strict", next(command for command in registry["drive"] if command["id"] == "go-campaign")["argv"])

    def test_shape_only_engine_row_cannot_satisfy_semantic_backend(self) -> None:
        registry = runner._default_registry()
        registry["engine-substrates"] = [{
            "id": "shape-only", "role": "semantic-engine", "evidence_tier": "lexical/shape-only",
            "languages": ["solidity"],
            "argv": ["python3", "tools/regex-detectors-orchestrator.py", "--workspace", "{workspace}"],
        }]
        path = self.root / "shape-registry.json"
        path.write_text(json.dumps(registry), encoding="utf-8")
        calls = []

        def never_run(argv, **_kwargs):
            calls.append(argv)
            return Completed()

        self.assertEqual(runner.run_phase(self.ws, "engine-substrates", path, runner=never_run), 1)
        error = self._receipt("engine-substrates")["error"]
        self.assertIn("cannot satisfy semantic-engine", error)
        self.assertIn("lexical/shape-only", error)
        self.assertEqual(calls, [])

    def test_semantic_label_cannot_wrap_shape_output_contract(self) -> None:
        registry = runner._default_registry()
        registry["engine-substrates"] = [{
            "id": "shape-overclaim", "role": "semantic-engine",
            "evidence_tier": "semantic/compiler-backed", "languages": ["solidity"],
            "argv": ["python3", "tools/regex-detectors-orchestrator.py", "--workspace", "{workspace}"],
            "outputs": [{"path": ".auditooor/shape.json", "kind": "json", "contract": "solidity-regex"}],
        }]
        path = self.root / "shape-overclaim-registry.json"
        path.write_text(json.dumps(registry), encoding="utf-8")
        self.assertEqual(runner.run_phase(self.ws, "engine-substrates", path, runner=self._default_fake()), 1)
        self.assertIn("no strict semantic engine output contract", self._receipt("engine-substrates")["error"])

    def test_present_typescript_and_vyper_fail_without_backend(self) -> None:
        for language in ("typescript", "vyper"):
            self._set_language(language)
            self.assertEqual(runner.run_phase(self.ws, "engine-substrates", runner=self._default_fake()), 1)
            error = self._receipt("engine-substrates")["error"]
            self.assertIn(language, error)
            self.assertIn("engine_substrate_route", error)

    def test_oscript_enumerator_does_not_count_as_engine_coverage(self) -> None:
        self._set_language("oscript")
        self.assertEqual(runner.run_phase(self.ws, "engine-substrates", runner=self._default_fake()), 1)
        receipt = self._receipt("engine-substrates")
        error = receipt["error"]
        self.assertIn("oscript", error)
        self.assertIn("engine_substrate_route", error)
        self.assertFalse(receipt["inputs"]["language_capability_query"]["ok"])

    def test_depth_probe_rejects_unsupported_javascript_mutation_route(self) -> None:
        self._set_language("javascript")
        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=self._default_fake()), 1)
        error = self._receipt("depth-probe")["error"]
        self.assertIn("unsupported applicable language 'javascript'", error)
        self.assertIn("function-mutation", error)

    def test_depth_probe_requires_terminal_live_reports_and_has_no_final_screens(self) -> None:
        self._zero_day_and_ordered_hunt()
        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=self._default_fake()), 0)
        receipt = self._receipt("depth-probe")
        self.assertEqual(receipt["status"], "passed")
        self.assertNotIn("campaign", {row["role"] for row in receipt["commands"]})
        mutation = next(row for row in receipt["commands"] if row["id"] == "per-function-mutation")
        self.assertIn("--check", mutation["argv"])

    def test_depth_probe_rejects_stub_rows_and_nonterminal_ingest(self) -> None:
        self._zero_day_and_ordered_hunt()
        fake = self._default_fake()

        def stubbed(argv, **kwargs):
            result = fake(argv, **kwargs)
            if len(argv) > 1 and argv[1] == "tools/depth-probe-runner.py":
                self._write(".auditooor/depth_probes/batch_000.jsonl", json.dumps({"guard_id": "G-1", "file_line": "src/Vault.sol:1", "code_excerpt": "contract Vault", "gap_found": False, "why_no_gap_or_exploit": "dry-run stub", "probe_source": "depth-probe-runner-dry-run"}) + "\n")
            return result

        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=stubbed), 1)
        self.assertIn("stub", self._receipt("depth-probe")["error"])

    def test_depth_ingest_rejects_any_rejected_or_uningested_rows(self) -> None:
        self._zero_day_and_ordered_hunt()
        fake = self._default_fake()

        def partial(argv, **kwargs):
            result = fake(argv, **kwargs)
            if len(argv) > 1 and argv[1] == "tools/depth-probe-ingest.py":
                result.stdout = json.dumps({"schema": "auditooor.depth_probe_ingest.v1", "verdict": "ingested-genuine", "probes_read": 2, "r76_fail": 1, "bulk_template_detected": False, "genuine": 1, "ingested": 1})
            return result

        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=partial), 1)
        self.assertIn("rejected", self._receipt("depth-probe")["error"])

    def test_directory_hash_is_recursive_and_sized(self) -> None:
        directory = self.ws / ".auditooor" / "tree"
        (directory / "nested").mkdir(parents=True)
        (directory / "a.txt").write_text("a", encoding="utf-8")
        (directory / "nested" / "b.txt").write_text("bb", encoding="utf-8")
        first = runner._path_summary(directory, self.ws)
        self.assertEqual(first["size"], 3)
        self.assertEqual(first["file_count"], 2)
        self.assertNotEqual(first["sha256"], "directory")
        expected_rows = [
            {"path": "a.txt", "sha256": runner._sha256_bytes(b"a"), "size": 1},
            {"path": "nested/b.txt", "sha256": runner._sha256_bytes(b"bb"), "size": 2},
        ]
        self.assertEqual(first["sha256"], runner._sha256_bytes(runner._canonical_json(expected_rows)))
        (directory / "nested" / "b.txt").write_text("bc", encoding="utf-8")
        self.assertNotEqual(first["sha256"], runner._path_summary(directory, self.ws)["sha256"])

    def test_applicable_na_row_does_not_satisfy_backend_role(self) -> None:
        registry = {mode: [] for mode in runner.MODES}
        registry["engine-substrates"] = [{
            "id": "fake-na", "role": "semantic-engine", "evidence_tier": "semantic/compiler-backed",
            "languages": ["solidity"], "not_applicable": True, "reason": "backend absent",
        }]
        self._write(".auditooor/language_backend_receipts.jsonl", json.dumps({
            "schema": "auditooor.language_backend_receipt.v1", "language": "solidity",
            "backend": "slither", "confidence": "semantic-ssa", "status": "pass", "degraded": False,
        }) + "\n")
        path = self.root / "registry.json"
        path.write_text(json.dumps(registry), encoding="utf-8")
        self.assertEqual(runner.run_phase(self.ws, "engine-substrates", path, runner=self._default_fake()), 1)
        self.assertIn("no semantic/compiler-backed production backend registered", self._receipt("engine-substrates")["error"])

    def test_engine_capability_reads_the_strict_dataflow_receipt_location(self) -> None:
        self._write(".auditooor/language_backend_receipts/dataflow.jsonl", json.dumps({
            "schema": "auditooor.language_backend_receipt.v1", "language": "solidity",
            "backend": "slither", "confidence": "semantic-ssa", "status": "pass", "degraded": False,
        }) + "\n")
        rows, summaries = runner._language_backend_evidence(self.ws)
        self.assertEqual(1, len(rows))
        self.assertEqual("slither", rows[0]["backend"])
        self.assertEqual([".auditooor/language_backend_receipts/dataflow.jsonl"], [row["path"] for row in summaries])

    def test_default_engine_registry_materializes_current_semantic_substrate(self) -> None:
        engine = runner._load_repo_module(
            "test_semantic_engine_adapter", "tools/semantic-engine-substrate.py"
        )
        files, source_set_sha256 = engine._inventory(self.ws, "solidity")
        record = engine.DATAFLOW.new_path(
            "semantic-path", "solidity", "backward", "slither.analyses.data_dependency",
            {"kind": "param", "fn": "deposit", "var": "amount", "file": "src/Vault.sol", "line": 1},
            {"kind": "transfer", "callee": "transfer", "arg_pos": 0, "fn": "deposit", "file": "src/Vault.sol", "line": 1}, [],
        )
        self._write(".auditooor/dataflow_paths.jsonl", json.dumps(record) + "\n")
        self._write(".auditooor/language_backend_receipts/dataflow.jsonl", json.dumps({
            "schema": "auditooor.language_backend_receipt.v1", "language": "solidity",
            "backend": "slither", "confidence": "semantic-ssa", "status": "pass",
            "degraded": False, "source_set_sha256": source_set_sha256,
            "inventory_unit_count": len(files), "examined_empty": False,
            "execution": {
                "argv": ["slither", "src/Vault.sol"], "executable": "slither", "returncode": 0,
                "command_sha256": "1" * 64, "stdout_sha256": "2" * 64,
                "stderr_sha256": "3" * 64, "artifact_sha256": engine._record_digest([record]),
                "artifact_kind": "slither-semantic-rows",
            },
        }) + "\n")
        self.assertEqual(0, runner.run_phase(self.ws, "engine-substrates"))
        receipt = self._receipt("engine-substrates")
        self.assertEqual("passed", receipt["status"])
        self.assertEqual("solidity-semantic-engine", receipt["commands"][0]["id"])
        artifact = self.ws / ".auditooor/strict_audit_deep/engine-substrates/solidity.json"
        self.assertEqual("passed", json.loads(artifact.read_text())["status"])

    def test_stale_declared_output_cannot_receive_credit(self) -> None:
        self._zero_day_and_ordered_hunt()
        self._write(".auditooor/depth_probes/batch_000.jsonl", json.dumps({"guard_id": "G-1"}) + "\n")

        def no_output(_argv, **_kwargs):
            return Completed(stdout=json.dumps({
                "schema": "auditooor.depth_probe_runner.v1", "verdict": "all-batches-ok",
                "packets_read": 1, "batches_failed": 0, "probes_emitted": 1,
                "live_fallback_to_agent_batches": None,
            }))

        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=no_output), 1)
        self.assertIn("did not refresh", self._receipt("depth-probe")["error"])

    def test_legacy_reasoner_and_hunt_inputs_are_rejected(self) -> None:
        self._write(".auditooor/reasoner_regen_receipts.jsonl", json.dumps({"ledger": "x", "rc": 0}) + "\n")
        self._write(".auditooor/hunt_findings_sidecars/result.json", {})
        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=self._default_fake()), 1)
        error = self._receipt("depth-probe")["error"]
        self.assertIn("zero-day bus validation failed", error)
        self.assertIn("freeze_receipt", error)
        self.assertNotIn(str(self.ws), json.dumps(self._receipt("depth-probe"), sort_keys=True))

    def test_ordered_hunt_rejects_incomplete_denominator(self) -> None:
        self._zero_day_and_ordered_hunt()
        manifest_path = self.ws / ".auditooor" / "ordered_hunt" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["completed_count"] -= 1
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=self._default_fake()), 1)
        self.assertIn("full typed question denominator", self._receipt("depth-probe")["error"])

    def test_zero_day_bus_hash_tamper_is_rejected(self) -> None:
        self._zero_day_and_ordered_hunt()
        path = self.ws / ".auditooor" / "zero_day_bus" / "obligations.jsonl"
        path.write_text(path.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")
        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=self._default_fake()), 1)
        self.assertIn("zero_day_obligations_hash_mismatch", self._receipt("depth-probe")["error"])

    def test_drive_rejects_machine_ledger_not_grounded_to_manual_ledger(self) -> None:
        self._drive_inputs(grounded=False)
        self.assertEqual(runner.run_phase(self.ws, "drive", runner=self._default_fake()), 1)
        self.assertIn("not grounded", self._receipt("drive")["error"])

    def test_drive_executes_real_harness_and_campaign_roles(self) -> None:
        self._drive_inputs()
        self.assertEqual(runner.run_phase(self.ws, "drive", runner=self._default_fake()), 0)
        receipt = self._receipt("drive")
        applicable = [row for row in receipt["commands"] if row["classification"] == "applicable"]
        self.assertEqual({row["role"] for row in applicable}, {"harness-author", "campaign"})
        self.assertIn("harness-binding", {artifact.get("contract") for artifact in receipt["artifacts"]})
        self.assertIn("campaign", {artifact.get("validator") for artifact in receipt["artifacts"]})

    def test_drive_rejects_blocked_harness_binding(self) -> None:
        self._drive_inputs()
        fake = self._default_fake()

        def blocked(argv, **kwargs):
            result = fake(argv, **kwargs)
            if len(argv) > 1 and argv[1] == "harness-scaffold":
                self._write(".auditooor/harness_binding_manifest.json", {"schema": "auditooor.harness_binding_manifest.v0", "row_count": 1, "ready_count": 0, "blocked_count": 1, "executable_command_count": 0, "rows": [{}]})
            return result

        self.assertEqual(runner.run_phase(self.ws, "drive", runner=blocked), 1)
        self.assertIn("blocked or non-executable", self._receipt("drive")["error"])

    def test_drive_rejects_ungrounded_worklist_row(self) -> None:
        self._drive_inputs()
        self._write(".auditooor/fuzz_targets.jsonl", json.dumps({"schema_version": "auditooor.fuzz_target_worklist.v1", "asset_path": "src/Other.sol", "functions": ["deposit"], "needs_campaign": True, "verdict": "campaign-pending"}) + "\n")
        self.assertEqual(runner.run_phase(self.ws, "drive", runner=self._default_fake()), 1)
        self.assertIn("ungrounded fuzz worklist", self._receipt("drive")["error"])

    def test_drive_empty_worklist_requires_typed_no_value_moving_proof(self) -> None:
        self._drive_inputs(worklist=False)
        self.assertEqual(runner.run_phase(self.ws, "drive", runner=self._default_fake()), 1)
        self.assertIn("value_moving_functions", self._receipt("drive")["error"])
        self._write(".auditooor/value_moving_functions.json", {"function_count": 0, "functions": []})
        self.assertEqual(runner.run_phase(self.ws, "drive", runner=self._default_fake()), 0)
        receipt = self._receipt("drive")
        disposition = receipt["inputs"]["empty_worklist_disposition"]
        self.assertEqual(disposition["schema"], runner.EMPTY_WORKLIST_SCHEMA)
        self.assertEqual(disposition["value_moving_in_scope_count"], 0)
        self.assertTrue(all(row["classification"] == "not_required" for row in receipt["commands"] if row["classification"] != "not_applicable"))

    def test_missing_backend_fails_even_with_empty_worklist_disposition(self) -> None:
        self._set_language("javascript")
        self._drive_inputs(worklist=False)
        self._write(".auditooor/value_moving_functions.json", {"function_count": 0, "functions": []})
        self.assertEqual(runner.run_phase(self.ws, "drive", runner=self._default_fake()), 1)
        self.assertIn("unsupported applicable language 'javascript'", self._receipt("drive")["error"])

    def test_receipt_is_portable_and_hashes_inputs_outputs(self) -> None:
        self._zero_day_and_ordered_hunt()
        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=self._default_fake()), 0)
        receipt = self._receipt("depth-probe")
        serialized = json.dumps(receipt, sort_keys=True)
        self.assertEqual(receipt["workspace"], ".")
        self.assertNotIn(str(self.ws), serialized)
        self.assertIn("sha256", receipt["inputs"]["canonical_inventory"])
        command = next(row for row in receipt["commands"] if row["classification"] == "applicable")
        self.assertIn("stdout", command)
        self.assertIn("stderr", command)
        self.assertIn("{workspace}", " ".join(command["argv"]))
        self.assertIn("size", receipt["artifacts"][0])

    def test_warning_and_timeout_are_terminal(self) -> None:
        self._zero_day_and_ordered_hunt()
        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=self._default_fake(warning_tool="depth-probe-runner")), 1)
        self.assertIn("warning", self._receipt("depth-probe")["error"])
        self.assertEqual(runner.run_phase(self.ws, "depth-probe", runner=self._default_fake(timeout_tool="depth-probe-runner")), 1)
        self.assertIn("timed out", self._receipt("depth-probe")["error"])

    def test_structured_empty_warnings_do_not_fail_a_command(self) -> None:
        self.assertFalse(runner._command_output_has_warning('{"warnings": []}', ""))
        self.assertFalse(runner._command_output_has_warning('{"warning": null}', ""))
        self.assertTrue(runner._command_output_has_warning('{"warnings": ["needs review"]}', ""))
        self.assertTrue(runner._command_output_has_warning('{"status": "warning"}', ""))
        self.assertTrue(runner._command_output_has_warning("", "WARN injected"))
        self.assertFalse(runner._command_output_has_warning("candidate contains warning text", ""))


if __name__ == "__main__":
    unittest.main()
