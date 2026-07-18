#!/usr/bin/env python3
# <!-- r36-rebuttal: lane L-README-CONFORMANCE-GATE registered via agent-pathspec-register.py -->
"""Guard tests for tools/readme-conformance-check.py - the fail-closed README
runbook conformance gate (wired into audit-done-guard so no required runbook
step can be silently bypassed in a status/done claim).

Pins:
  - a missing required step is RED -> conformance_pass=False (fail-closed);
  - satisfying the artifact + attestation flips it GREEN;
  - a waiver with a non-empty reason flips RED -> waived (operator escape);
  - a waiver with a BLANK reason is REJECTED (stays RED) - no empty-waiver bypass;
  - a step whose language_filter excludes the workspace is n/a (not RED).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "readme-conformance-check.py"
_PIPELINE_MACHINE = _TOOL.parent / "pipeline-state-machine.py"
_PIPELINE_EXECUTOR = _TOOL.parent / "pipeline-executor.py"
_CANONICAL_MANIFEST = _TOOL.parent / "readme_runbook_steps.json"
_BASELINES = {
    "workspace_identity_sha256": "1" * 64,
    "source_snapshot_sha256": "2" * 64,
    "scope_sha256": "3" * 64,
    "severity_sha256": "4" * 64,
    "targets_sha256": "5" * 64,
    "program_rules_sha256": "6" * 64,
    "pipeline_tooling_sha256": "7" * 64,
}


def _load():
    spec = importlib.util.spec_from_file_location("readme_conformance_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["readme_conformance_check"] = m
    spec.loader.exec_module(m)
    return m


def _load_machine():
    spec = importlib.util.spec_from_file_location("pipeline_state_machine_for_readme_tests", _PIPELINE_MACHINE)
    m = importlib.util.module_from_spec(spec)
    sys.modules["pipeline_state_machine_for_readme_tests"] = m
    spec.loader.exec_module(m)
    return m


def _load_executor():
    spec = importlib.util.spec_from_file_location("pipeline_executor_for_readme_tests", _PIPELINE_EXECUTOR)
    m = importlib.util.module_from_spec(spec)
    sys.modules["pipeline_executor_for_readme_tests"] = m
    spec.loader.exec_module(m)
    return m


def _write_inventory(ws: Path, *languages: str):
    ext = {
        "go": ".go",
        "solidity": ".sol",
        "rust": ".rs",
        "javascript": ".js",
        "typescript": ".ts",
        "vyper": ".vy",
    }
    rows = []
    for index, language in enumerate(languages or ("go",), start=1):
        rel = f"src/source_{index}{ext.get(language, '.txt')}"
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"// {language}\n", encoding="utf-8")
        rows.append({"file": rel, "lang": language})
    path = ws / ".auditooor" / "inscope_units.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _normalize_depends_on(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _make_v2_manifest(base_manifest: dict, machine_module, *, directory_contract_ids: set[str] | None = None) -> dict:
    _ = (base_manifest, machine_module)
    directory_contract_ids = directory_contract_ids or set()
    steps = []
    for idx in range(69):
        step_id = f"step-{idx:02d}"
        steps.append({
            "step_id": step_id,
            "order_index": idx,
            "run_sequence": idx,
            "phase": "reasoning" if idx == 34 else "drive",
            "required": True,
            "execution_target": ["python3", "tools/pipeline-manifest-validate.py", "--manifest", "{workspace}/manifest.json"],
            "applicability_probe": "probe.always",
            "depends_on": [f"step-{idx - 1:02d}"] if idx > 0 else [],
            "consumes": [f"artifact-{idx - 1:02d}"] if idx > 0 else [],
            "produces": [f"artifact-{idx:02d}"],
            "validators": ["noop"],
            "invalidates": [f"step-{idx + 1:02d}"] if idx == 10 else [],
            "terminal_output": idx == 68,
        })
    artifact_contracts = [
        {
            "id": f"artifact-{idx:02d}",
            "path": (
                f".auditooor/test/artifact-{idx:02d}"
                if f"artifact-{idx:02d}" in directory_contract_ids
                else f".auditooor/test/artifact-{idx:02d}.json"
            ),
            "kind": "directory" if f"artifact-{idx:02d}" in directory_contract_ids else "file",
            "validators": ["directory_exists"] if f"artifact-{idx:02d}" in directory_contract_ids else ["file_exists"],
            "producer_step_ids": [f"step-{idx:02d}"],
            "consumer_step_ids": [f"step-{idx + 1:02d}"] if idx < 68 else [],
            "terminal": idx == 68,
        }
        for idx in range(69)
    ]
    return {
        "schema": "auditooor.pipeline_manifest.v2",
        "expected_step_count": 69,
        "steps": steps,
        "execution_target_registry": [
            {"step_id": step["step_id"], "argv": list(step["execution_target"])}
            for step in steps
        ],
        "execution_placeholders": [{"id": "workspace", "token": "{workspace}", "source": "executor.workspace_root"}],
        "environment_passthrough": ["PIPELINE_FORCE", "PIPELINE_STRICT"],
        "applicability_probes": [{"id": "probe.always", "kind": "always"}],
        "validators": [
            {"id": "noop", "kind": "noop"},
            {"id": "file_exists", "kind": "file_exists"},
            {"id": "directory_exists", "kind": "directory_exists"},
        ],
        "legacy_artifact_check_types": [{"id": "file_exists"}],
        "legacy_artifact_checks": [{"step_id": "step-00", "check_type": "file_exists"}],
        "artifact_contracts": artifact_contracts,
        "reasoner_registry": [{"id": "reasoner.synthetic", "step_id": "step-34", "ledger_artifact": "artifact-34"}],
        "reasoner_routes": [{
            "reasoner_id": "reasoner.synthetic",
            "step_id": "step-34",
            "ledger_artifact": "artifact-34",
            "producer_step_id": "step-34",
            "consumer_step_ids": ["step-35"],
            "queue_step_id": "step-35",
            "question_step_id": "step-35",
            "proof_step_id": "step-35",
            "resolution_step_id": "step-35",
        }],
    }


def _write_manifest(path: Path, manifest: dict):
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_strict_state(ws: Path, machine_module, strict_manifest: dict):
    ws = ws.resolve()
    executor = _load_executor()
    state = machine_module.initialize_state(strict_manifest, run_id="run-fixture", **_BASELINES)
    contracts = executor._artifact_contracts(strict_manifest, ws)
    for step in sorted(strict_manifest["steps"], key=lambda item: item["run_sequence"]):
        applicability = machine_module._applicability.evaluate_probe(strict_manifest, step["applicability_probe"], ws)
        token = machine_module.start_step(state, strict_manifest, step["step_id"])
        status = "succeeded" if applicability["result"] else "not_applicable"
        input_artifacts = [] if status == "not_applicable" else [
            row for dep in step["depends_on"] for row in state["steps"][dep]["current_output_artifacts"]
        ]
        output_artifacts = []
        if status != "not_applicable":
            contract = contracts[step["produces"][0]]
            out = contract["path"]
            out.parent.mkdir(parents=True, exist_ok=True)
            if contract["kind"] == "directory":
                out.mkdir(parents=True, exist_ok=True)
                (out / "payload.json").write_text(
                    json.dumps({"step_id": step["step_id"], "attempt": state["steps"][step["step_id"]]["attempt"]}),
                    encoding="utf-8",
                )
            else:
                out.write_text(
                    json.dumps({"step_id": step["step_id"], "attempt": state["steps"][step["step_id"]]["attempt"]}),
                    encoding="utf-8",
                )
            row, diagnostics = executor._artifact_row(contract, ws)
            assert row is not None and not diagnostics
            output_artifacts = [row]
        receipt = machine_module._receipt.build_receipt(
            run_id=state["run_id"],
            manifest_sha256=state["manifest_sha256"],
            workspace_identity_sha256=state["workspace_identity_sha256"],
            source_snapshot_sha256=state["source_snapshot_sha256"],
            scope_sha256=state["scope_sha256"],
            severity_sha256=state["severity_sha256"],
                targets_sha256=state["targets_sha256"],
                program_rules_sha256=state["program_rules_sha256"],
                pipeline_tooling_sha256=state["pipeline_tooling_sha256"],
                step_id=step["step_id"],
            order_index=step["order_index"],
            attempt=state["steps"][step["step_id"]]["attempt"],
            step_token=token,
            status=status,
            applicability_probe_id=applicability["probe_id"],
            applicability_inputs=applicability["canonical_inputs"],
            applicability_result=applicability["result"],
            argv=step["execution_target"],
            selected_environment={"LANG": "C"},
            started_at="2026-07-17T10:00:00+00:00",
            finished_at="2026-07-17T10:00:01+00:00",
            exit_code=0,
            upstream_receipt_ids=sorted(
                state["steps"][dep]["current_receipt_id"] for dep in step["depends_on"]
            ),
            input_artifacts=input_artifacts,
            output_artifacts=output_artifacts,
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            tool_versions={"pipeline": "2"},
            toolchain_versions={"python": "3"},
        )
        machine_module.accept_receipt(state, strict_manifest, receipt, workspace=ws)
        receipt_path = ws / ".auditooor" / "pipeline" / "receipts" / step["step_id"] / f"attempt-{receipt['attempt']}.json"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    state_path = ws / ".auditooor" / "pipeline" / "state.json"
    machine_module.write_state(state_path, state)
    return state_path, state


_MANIFEST = {
    "_schema_version": "test.v1",
    "waiver_file": ".auditooor/readme_step_waivers.txt",
    "steps": [
        {
            "step_id": "t-mech", "label": "mech step", "class": "mechanical",
            "required": True, "language_filter": None,
            "how_to_verify_done": {
                "artifact_checks": [{"type": "file_exists", "path": "MARKER.md"}],
                "attestation_required": False,
            },
        },
        {
            "step_id": "t-manual", "label": "manual step", "class": "manual-judgment",
            "required": True, "language_filter": None,
            "how_to_verify_done": {
                "artifact_checks": [],
                "attestation_required": True,
                "attestation_path": ".auditooor/attestations/t-manual.json",
            },
        },
        {
            "step_id": "t-solonly", "label": "sol-only step", "class": "conditional-mechanical",
            "required": True, "language_filter": ["solidity", "evm"],
            "how_to_verify_done": {
                "artifact_checks": [{"type": "file_exists", "path": "NEVER.md"}],
                "attestation_required": False,
            },
        },
    ],
}


class ReadmeConformanceGateTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.machine = _load_machine()
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True, exist_ok=True)
        # make it a Go workspace so the sol-only step is n/a (not RED)
        (self.tmp / "main.go").write_text("package main\nfunc main(){}\n", encoding="utf-8")
        _write_inventory(self.tmp, "go")
        self.manifest = self.tmp / "manifest.json"
        self.manifest.write_text(json.dumps(_MANIFEST), encoding="utf-8")

    def _eval(self):
        return self.m.evaluate(self.tmp, self.manifest)

    def _v2_manifest_path(self, base_manifest: dict | None = None, *, name: str = "strict-v2-manifest.json") -> Path:
        manifest = _make_v2_manifest(base_manifest or json.loads(_CANONICAL_MANIFEST.read_text(encoding="utf-8")), self.machine)
        path = self.tmp / name
        _write_manifest(path, manifest)
        return path

    def _attest(self):
        d = self.tmp / ".auditooor" / "attestations"
        d.mkdir(parents=True, exist_ok=True)
        (d / "t-manual.json").write_text(json.dumps({
            "completed_at": "2026-06-15T00:00:00Z", "attested_by": "operator",
            "summary": "authored + verified per the runbook step"}), encoding="utf-8")

    def test_missing_required_steps_are_red_and_fail_closed(self):
        r = self._eval()
        self.assertFalse(r["conformance_pass"], "missing required steps must fail-closed")
        red = set(r.get("red_step_ids", []))
        self.assertIn("t-mech", red)
        self.assertIn("t-manual", red)
        # sol-only step is n/a on a Go workspace -> NOT red
        self.assertNotIn("t-solonly", red, "language-filtered step must be n/a, not RED")

    def test_satisfying_artifact_and_attestation_passes(self):
        (self.tmp / "MARKER.md").write_text("done\n", encoding="utf-8")
        self._attest()
        r = self._eval()
        self.assertTrue(r["conformance_pass"], f"all required steps satisfied should pass: {r.get('red_step_ids')}")

    def test_attestation_missing_required_field_is_red(self):
        """False-green guard: an attestation missing completed_at/summary is rejected."""
        (self.tmp / "MARKER.md").write_text("done\n", encoding="utf-8")
        d = self.tmp / ".auditooor" / "attestations"; d.mkdir(parents=True, exist_ok=True)
        (d / "t-manual.json").write_text(json.dumps({"attested_by": "op"}), encoding="utf-8")
        r = self._eval()
        self.assertFalse(r["conformance_pass"], "incomplete attestation must NOT pass")
        self.assertIn("t-manual", set(r.get("red_step_ids", [])))

    def test_waiver_with_reason_flips_red_to_waived(self):
        (self.tmp / "MARKER.md").write_text("done\n", encoding="utf-8")  # satisfy t-mech
        (self.tmp / ".auditooor" / "readme_step_waivers.txt").write_text(
            "waive: t-manual: operator accepts no attestation for this engagement\n", encoding="utf-8")
        r = self._eval()
        self.assertTrue(r["conformance_pass"], f"a reasoned waiver should pass: {r.get('red_step_ids')}")

    def test_strict_non_v2_manifest_is_rejected(self):
        (self.tmp / "MARKER.md").write_text("done\n", encoding="utf-8")
        (self.tmp / ".auditooor" / "readme_step_waivers.txt").write_text(
            "waive: t-manual: operator accepts no attestation\n", encoding="utf-8")
        r = self.m.evaluate(self.tmp, self.manifest, strict=True)
        self.assertFalse(r["conformance_pass"])
        self.assertTrue(any(g.startswith("readme-conformance-manifest:") for g in r["fail_gates"]))

    def test_language_marker_after_2000_files_is_detected(self):
        for i in range(2001):
            (self.tmp / f"{i:04d}.txt").write_text("x\n", encoding="utf-8")
        (self.tmp / "late.sol").write_text("contract C {}\n", encoding="utf-8")
        languages = self.m._detect_languages(self.tmp)
        self.assertIn("solidity", languages)
        self.assertIn("evm", languages)

    def test_js_oscript_and_solidity_are_detected_together(self):
        for name in ("app.js", "agent.oscript", "Contract.sol"):
            (self.tmp / name).write_text("x\n", encoding="utf-8")
        languages = self.m._detect_languages(self.tmp)
        self.assertTrue({"js", "javascript", "oscript", "solidity", "evm"}.issubset(languages))

    def test_interim_c_cpp_java_extensions_are_detected(self):
        for name in ("a.c", "a.h", "a.cc", "a.cpp", "a.cxx", "a.hpp", "A.java"):
            (self.tmp / name).write_text("x\n", encoding="utf-8")
        languages = self.m._detect_languages(self.tmp)
        self.assertTrue({"c", "cpp", "java"}.issubset(languages))

    def test_generic_first_party_directories_are_not_pruned(self):
        markers = {
            "external": "x.java",
            "deps": "x.cpp",
            "gen": "x.c",
            "generated": "x.h",
        }
        for directory, name in markers.items():
            path = self.tmp / directory
            path.mkdir()
            (path / name).write_text("x\n", encoding="utf-8")
        languages = self.m._detect_languages(self.tmp)
        self.assertTrue({"c", "cpp", "java"}.issubset(languages))

    def test_required_false_red_still_blocks_conformance(self):
        manifest = {
            "steps": [{
                "step_id": "advisory-red", "required": False,
                "how_to_verify_done": {
                    "artifact_checks": [{"type": "file_exists", "path": "MISSING"}],
                    "attestation_required": False,
                },
            }],
        }
        path = self.tmp / "required-false.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        r = self.m.evaluate(self.tmp, path)
        self.assertFalse(r["conformance_pass"])
        self.assertIn("advisory-red", r["red_step_ids"])

    def test_unknown_artifact_check_blocks_conformance(self):
        manifest = {
            "steps": [{
                "step_id": "unknown-check", "required": True,
                "how_to_verify_done": {
                    "artifact_checks": [{"type": "future_check"}],
                    "attestation_required": False,
                },
            }],
        }
        path = self.tmp / "unknown-check.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        r = self.m.evaluate(self.tmp, path)
        self.assertFalse(r["conformance_pass"])
        self.assertTrue(any("unknown artifact check type" in f for f in r["steps"][0]["failures"]))

    def test_blank_reason_waiver_is_rejected(self):
        (self.tmp / "MARKER.md").write_text("done\n", encoding="utf-8")
        (self.tmp / ".auditooor" / "readme_step_waivers.txt").write_text(
            "waive: t-manual:   \n", encoding="utf-8")  # blank reason
        r = self._eval()
        self.assertFalse(r["conformance_pass"], "a blank-reason waiver must NOT bypass (fail-closed)")
        self.assertIn("t-manual", set(r.get("red_step_ids", [])))

    def test_step_1c_required_flips_conformance_when_dark(self):
        """LOAD-BEARING flip (strata 2026-06-30): step-1c (the def-use dataflow slice)
        was mislabeled advisory (required:false) and silently went dark. It is now
        required:true / load-bearing - so on every supported-language workspace with
        its artifact ABSENT it MUST be a red required step (FIRE-CHECK)."""
        canonical = _TOOL.parent / "readme_runbook_steps.json"
        man = json.loads(canonical.read_text(encoding="utf-8"))
        ids = [s["step_id"] for s in man["steps"]]
        self.assertIn("step-1c", ids, "step-1c must be present in the canonical manifest")
        step = next(s for s in man["steps"] if s["step_id"] == "step-1c")
        self.assertTrue(step["required"], "step-1c is now REQUIRED / load-bearing (required:true)")
        self.assertIsNone(step["language_filter"])
        checks = step["how_to_verify_done"]["artifact_checks"]
        self.assertEqual(checks[0]["type"], "file_nonempty_by_language")
        self.assertEqual(checks[0]["paths_by_language"]["oscript"], ".auditooor/oscript_ast_substrate.jsonl")
        self.assertIn(".auditooor/dataflow_paths.jsonl", checks[0]["default_paths"])
        # Solidity workspace, dataflow_paths.jsonl ABSENT -> now a RED required step.
        sol_ws = Path(tempfile.mkdtemp())
        (sol_ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (sol_ws / "C.sol").write_text("contract C { function f() public {} }\n", encoding="utf-8")
        r = self.m.evaluate(sol_ws, canonical)
        red = set(r.get("red_step_ids", []))
        self.assertIn("step-1c", red,
                      "load-bearing step-1c MUST flip conformance red when its artifact is dark")
        # Go is also an applicable semantic dataflow arm, so darkness remains red.
        go_ws = Path(tempfile.mkdtemp())
        (go_ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (go_ws / "main.go").write_text("package main\nfunc main(){}\n", encoding="utf-8")
        r2 = self.m.evaluate(go_ws, canonical)
        s1c = next((s for s in r2["steps"] if s["step_id"] == "step-1c"), None)
        self.assertIsNotNone(s1c)
        self.assertEqual(s1c["status"], "red")

    def test_step_1c_oscript_receipt_cannot_cross_credit_semantic_languages(self):
        canonical = _TOOL.parent / "readme_runbook_steps.json"
        step = next(item for item in json.loads(canonical.read_text(encoding="utf-8"))["steps"]
                    if item["step_id"] == "step-1c")
        checks = step["how_to_verify_done"]["artifact_checks"]
        workspace = Path(tempfile.mkdtemp())
        audit_dir = workspace / ".auditooor"
        audit_dir.mkdir()
        audit_dir.joinpath("oscript_ast_substrate.jsonl").write_text("syntactic receipt\n", encoding="utf-8")
        ok, failures = self.m._run_artifact_checks(workspace, checks, {"solidity"})
        self.assertFalse(ok)
        self.assertTrue(any("dataflow_paths.jsonl" in failure for failure in failures))
        audit_dir.joinpath("dataflow_paths.jsonl").write_text("semantic path\n", encoding="utf-8")
        ok, failures = self.m._run_artifact_checks(workspace, checks, {"oscript"})
        self.assertTrue(ok, failures)
        audit_dir.joinpath("dataflow_paths.jsonl").unlink()
        ok, failures = self.m._run_artifact_checks(workspace, checks, {"solidity", "oscript"})
        self.assertFalse(ok)
        self.assertTrue(any("(solidity)" in failure for failure in failures))

    def test_file_min_data_rows_distinguishes_stub_from_populated(self):
        # Regression: a byte-nonempty all-comment stub (e.g. bootstrap targets.tsv)
        # must FAIL file_min_data_rows; a file with >=1 real data row must PASS.
        # Guards the step-0d targets.tsv prerequisite that step-1 make audit needs.
        chk = [{"type": "file_min_data_rows", "path": "targets.tsv",
                "min_rows": 1, "comment_prefix": "#"}]
        stub = self.tmp / "targets.tsv"
        stub.write_text("# header\n# Example: https://github.com/o/r.git\n\n", encoding="utf-8")
        ok, fails = self.m._run_artifact_checks(self.tmp, chk)
        self.assertFalse(ok, "all-comment stub must fail file_min_data_rows")
        self.assertTrue(any("file_min_data_rows" in f for f in fails))
        stub.write_text("# header\nhttps://github.com/o/r.git\tabc\tr\n", encoding="utf-8")
        ok2, _ = self.m._run_artifact_checks(self.tmp, chk)
        self.assertTrue(ok2, "a real data row must pass file_min_data_rows")

    def test_go_mvc_sidecar_verified_credits_mutation_verified_go_harness(self):
        # Regression (SEI 2026-07-04): a Go/Cosmos L1 has no medusa/echidna
        # equivalent, so its step-2c campaign evidence is a mutation-verified
        # go-test economic-invariant sidecar - NOT a chimera dir + fuzz receipt.
        # go_mvc_sidecar_verified must PASS on a genuine sidecar and FAIL when the
        # evidence is missing / not mutation-verified / zero mutants killed.
        scdir = self.tmp / ".auditooor" / "mvc_sidecar"
        scdir.mkdir(parents=True, exist_ok=True)
        chk = [{"type": "go_mvc_sidecar_verified",
                "dir": ".auditooor/mvc_sidecar", "min_mutants": 1}]

        # No sidecar file yet -> FAIL.
        ok, fails = self.m._run_artifact_checks(self.tmp, chk)
        self.assertFalse(ok, "empty sidecar dir must fail")
        self.assertTrue(any("go_mvc_sidecar_verified" in f for f in fails))

        # A genuine mutation-verified Go sidecar -> PASS.
        good = {
            "lang": "go", "baseline_result": "PASS",
            "mutation_verified": True, "mutants_killed": 1,
        }
        (scdir / "go_econ.json").write_text(json.dumps(good), encoding="utf-8")
        ok2, _ = self.m._run_artifact_checks(self.tmp, chk)
        self.assertTrue(ok2, "a mutation-verified go sidecar must be credited")

        # mutation_verified false -> FAIL (no vacuous credit).
        (scdir / "go_econ.json").write_text(
            json.dumps({**good, "mutation_verified": False}), encoding="utf-8")
        ok3, _ = self.m._run_artifact_checks(self.tmp, chk)
        self.assertFalse(ok3, "non-mutation-verified sidecar must NOT be credited")

        # mutants_killed 0 -> FAIL.
        (scdir / "go_econ.json").write_text(
            json.dumps({**good, "mutants_killed": 0}), encoding="utf-8")
        ok4, _ = self.m._run_artifact_checks(self.tmp, chk)
        self.assertFalse(ok4, "a sidecar that killed 0 mutants must NOT be credited")

        # baseline FAIL -> FAIL.
        (scdir / "go_econ.json").write_text(
            json.dumps({**good, "baseline_result": "FAIL"}), encoding="utf-8")
        ok5, _ = self.m._run_artifact_checks(self.tmp, chk)
        self.assertFalse(ok5, "a sidecar with a failing baseline must NOT be credited")

        # non-go lang -> FAIL (this arm is the Go/Cosmos arm only).
        (scdir / "go_econ.json").write_text(
            json.dumps({**good, "lang": "solidity"}), encoding="utf-8")
        ok6, _ = self.m._run_artifact_checks(self.tmp, chk)
        self.assertFalse(ok6, "a non-go sidecar must NOT satisfy the go arm")

    def test_any_of_passes_when_either_alternative_satisfied(self):
        # Regression: any_of models peer evidence alternatives (EVM campaign
        # cluster OR Go mutation-verified sidecar) without weakening either arm.
        evm_group = [
            {"type": "dir_exists", "path": "chimera_harnesses"},
            {"type": "file_exists_any", "paths": [".auditooor/fuzz_campaign_receipt.json"]},
        ]
        go_group = [
            {"type": "go_mvc_sidecar_verified", "dir": ".auditooor/mvc_sidecar", "min_mutants": 1},
        ]
        chk = [{"type": "any_of", "groups": [evm_group, go_group]}]

        # Neither arm satisfied -> FAIL, and the message enumerates both alts.
        ok, fails = self.m._run_artifact_checks(self.tmp, chk)
        self.assertFalse(ok, "no alternative satisfied -> fail")
        self.assertTrue(any("any_of FAIL" in f for f in fails))
        self.assertTrue(any("alt 0" in f and "alt 1" in f for f in fails),
                        "the failure must enumerate every unmet alternative")

        # Satisfy ONLY the Go arm -> PASS (the SEI case).
        scdir = self.tmp / ".auditooor" / "mvc_sidecar"
        scdir.mkdir(parents=True, exist_ok=True)
        (scdir / "go_econ.json").write_text(json.dumps({
            "lang": "go", "baseline_result": "PASS",
            "mutation_verified": True, "mutants_killed": 1,
        }), encoding="utf-8")
        ok2, _ = self.m._run_artifact_checks(self.tmp, chk)
        self.assertTrue(ok2, "the Go sidecar alternative alone must satisfy any_of")

        # Satisfy ONLY the EVM arm (fresh ws) -> PASS (no regression to the EVM path).
        evm_ws = Path(tempfile.mkdtemp())
        (evm_ws / "chimera_harnesses").mkdir(parents=True, exist_ok=True)
        (evm_ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (evm_ws / ".auditooor" / "fuzz_campaign_receipt.json").write_text("{}", encoding="utf-8")
        ok3, _ = self.m._run_artifact_checks(evm_ws, chk)
        self.assertTrue(ok3, "the EVM campaign alternative alone must still satisfy any_of")

    def test_step_2c_manifest_accepts_go_sidecar_arm(self):
        # Pin the canonical manifest wiring: step-2c's campaign-evidence arm is an
        # any_of(EVM cluster | Go mvc_sidecar), so a Go workspace with a verified
        # sidecar passes the ARTIFACT arm (attestation remains a separate step).
        canonical = _TOOL.parent / "readme_runbook_steps.json"
        man = json.loads(canonical.read_text(encoding="utf-8"))
        step = next(s for s in man["steps"] if s["step_id"] == "step-2c")
        checks = step["how_to_verify_done"]["artifact_checks"]
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["type"], "any_of")
        types_in_groups = {c["type"] for grp in checks[0]["groups"] for c in grp}
        self.assertIn("go_mvc_sidecar_verified", types_in_groups)
        self.assertIn("dir_exists", types_in_groups)  # EVM arm preserved

        # Go ws + verified sidecar -> the artifact arm passes (only attestation red).
        go_ws = Path(tempfile.mkdtemp())
        sc = go_ws / ".auditooor" / "mvc_sidecar"
        sc.mkdir(parents=True, exist_ok=True)
        (go_ws / "x.go").write_text("package x\n", encoding="utf-8")
        (sc / "go_econ.json").write_text(json.dumps({
            "lang": "go", "baseline_result": "PASS",
            "mutation_verified": True, "mutants_killed": 1,
        }), encoding="utf-8")
        art_ok, art_fails = self.m._run_artifact_checks(
            go_ws, checks + step["how_to_verify_done"].get("condition_checks", []))
        self.assertTrue(art_ok, f"go sidecar must satisfy step-2c artifact arm: {art_fails}")

    def test_strict_canonical_manifest_requires_state_not_filesystem_artifacts(self):
        base_manifest = {
            "steps": [{
                "step_id": "strict-step", "required": True,
                "language_filter": None,
                "how_to_verify_done": {
                    "artifact_checks": [{"type": "file_exists", "path": "MARKER.md"}],
                    "attestation_required": True,
                    "attestation_path": ".auditooor/attestations/strict-step.json",
                },
            }],
        }
        path = self._v2_manifest_path(base_manifest, name="strict-single-step-v2.json")
        (self.tmp / "MARKER.md").write_text("done\n", encoding="utf-8")
        d = self.tmp / ".auditooor" / "attestations"
        d.mkdir(parents=True, exist_ok=True)
        (d / "strict-step.json").write_text(json.dumps({
            "completed_at": "2026-07-17T00:00:00Z",
            "attested_by": "operator",
            "summary": "filesystem only",
        }), encoding="utf-8")
        dev = self.m.evaluate(self.tmp, path, strict=False)
        self.assertTrue(dev["conformance_pass"], dev)
        strict = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(strict["conformance_pass"])
        self.assertTrue(any(
            g.startswith("readme-conformance-state:") or g.startswith("readme-conformance-manifest:")
            for g in strict["fail_gates"]
        ))

    def test_strict_canonical_manifest_fails_when_state_absent(self):
        path = self._v2_manifest_path()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        result = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(result["conformance_pass"])
        self.assertIn("readme-conformance-state:state_file_missing", result["fail_gates"])
        applicable = [
            step["step_id"] for step in manifest["steps"]
            if step.get("applicability_probe") == "probe.always"
        ]
        self.assertTrue(set(applicable).issubset(set(result["red_step_ids"])))

    def test_strict_canonical_manifest_fails_when_state_malformed(self):
        path = self._v2_manifest_path()
        state_path = self.tmp / ".auditooor" / "pipeline" / "state.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text("{not-json\n", encoding="utf-8")
        result = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(result["conformance_pass"])
        self.assertTrue(any(g.startswith("readme-conformance-state:state_file_unreadable:") for g in result["fail_gates"]))

    def test_strict_canonical_manifest_fails_when_state_self_hash_is_forged(self):
        path = self._v2_manifest_path()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        state_path, state = _build_strict_state(self.tmp, self.machine, manifest)
        state["state_self_hash"] = "f" * 64
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(result["conformance_pass"])
        self.assertIn("readme-conformance-state:state_self_hash_mismatch", result["fail_gates"])

    def test_strict_canonical_manifest_fails_on_wrong_manifest_hash(self):
        path = self._v2_manifest_path()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        state_path, state = _build_strict_state(self.tmp, self.machine, manifest)
        state["manifest_sha256"] = "0" * 64
        self.machine.write_state(state_path, self.machine._seal(state))
        result = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(result["conformance_pass"])
        self.assertIn("readme-conformance-closeout:manifest_sha256_mismatch", result["fail_gates"])

    def test_strict_canonical_manifest_fails_on_68_of_69_state(self):
        path = self._v2_manifest_path()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        state_path, state = _build_strict_state(self.tmp, self.machine, manifest)
        state["steps"].pop("step-05")
        self.machine.write_state(state_path, self.machine._seal(state))
        result = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(result["conformance_pass"])
        self.assertIn("readme-conformance-state:state_step_count_mismatch", result["fail_gates"])

    def test_strict_canonical_manifest_fails_on_invalidated_suffix(self):
        path = self._v2_manifest_path()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        state_path, state = _build_strict_state(self.tmp, self.machine, manifest)
        self.machine.invalidate_step(state, manifest, "step-68", reason="test invalidation")
        self.machine.write_state(state_path, state)
        result = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(result["conformance_pass"])
        self.assertIn("step-68", result["red_step_ids"])
        self.assertIn("readme-conformance-closeout:closeout_non_success_terminal_state", result["fail_gates"])

    def test_strict_canonical_manifest_fails_when_current_receipt_archive_is_missing(self):
        path = self._v2_manifest_path()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        state_path, state = _build_strict_state(self.tmp, self.machine, manifest)
        _ = state_path
        receipt_path = self.tmp / ".auditooor" / "pipeline" / "receipts" / "step-00" / "attempt-1.json"
        receipt_path.unlink()
        result = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(result["conformance_pass"])
        self.assertTrue(any(g.startswith("readme-conformance-receipt:step-00:receipt_archive_missing:") for g in result["fail_gates"]))

    def test_strict_canonical_manifest_fails_when_current_output_changes_on_disk(self):
        path = self._v2_manifest_path()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        _state_path, _state = _build_strict_state(self.tmp, self.machine, manifest)
        output_path = self.tmp / ".auditooor" / "test" / "artifact-00.json"
        output_path.write_text('{"tampered":true}\n', encoding="utf-8")
        result = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(result["conformance_pass"])
        self.assertTrue(any(g.startswith("readme-conformance-receipt:step-00:receipt_output_artifact_sha256_mismatch:") for g in result["fail_gates"]))

    def test_strict_canonical_manifest_detects_changed_directory_output(self):
        manifest = _make_v2_manifest({}, self.machine, directory_contract_ids={"artifact-00"})
        path = self.tmp / "strict-v2-directory-manifest.json"
        _write_manifest(path, manifest)
        _state_path, _state = _build_strict_state(self.tmp, self.machine, manifest)
        dir_path = self.tmp / ".auditooor" / "test" / "artifact-00"
        (dir_path / "late.txt").write_text("mutated\n", encoding="utf-8")
        result = self.m.evaluate(self.tmp, path, strict=True)
        self.assertFalse(result["conformance_pass"])
        self.assertTrue(any(g.startswith("readme-conformance-receipt:step-00:receipt_output_artifact_sha256_mismatch:") for g in result["fail_gates"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
