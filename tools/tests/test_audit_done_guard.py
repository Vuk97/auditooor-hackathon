#!/usr/bin/env python3
# <!-- r36-rebuttal: lane L37-AUDIT-DONE-GUARD registered via agent-pathspec-register.py -->
"""Guard: audit-done-guard is the mechanical DONE judge.

DONE requires a FRESH pass-audit-complete (STRICT) marker AND
paste-ready-or-nothing. Verifies the not-done reasons (missing marker, non-pass
verdict, stale pass, pass-but-no-paste-ready) and the done happy path.
"""
import importlib.util
import json
import sys
import tempfile
import time
import unittest
import contextlib
from unittest.mock import patch
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_READ_ME = _TOOLS / "readme-conformance-check.py"
_PIPELINE_MACHINE = _TOOLS / "pipeline-state-machine.py"
_PIPELINE_EXECUTOR = _TOOLS / "pipeline-executor.py"
_CANONICAL_MANIFEST = _TOOLS / "readme_runbook_steps.json"
_BASELINES = {
    "workspace_identity_sha256": "1" * 64,
    "source_snapshot_sha256": "2" * 64,
    "scope_sha256": "3" * 64,
    "severity_sha256": "4" * 64,
    "targets_sha256": "5" * 64,
    "program_rules_sha256": "6" * 64,
    "pipeline_tooling_sha256": "7" * 64,
}
spec = importlib.util.spec_from_file_location("adg", str(_TOOLS / "audit-done-guard.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["adg"] = m
spec.loader.exec_module(m)


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    return ws


def _marker(ws: Path, verdict: str, strict=True):
    (ws / ".auditooor" / "audit_completion.json").write_text(
        json.dumps({"verdict": verdict, "strict": strict}), encoding="utf-8")


def _write_inventory(ws: Path, *languages: str):
    path = ws / ".auditooor" / "inscope_units.jsonl"
    ext = {"go": ".go", "solidity": ".sol", "rust": ".rs"}
    rows = []
    for index, language in enumerate(languages or ("go",), start=1):
        rel = f"src/source_{index}{ext.get(language, '.txt')}"
        target = ws / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"// {language}\n", encoding="utf-8")
        rows.append({"file": rel, "lang": language})
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _normalize_depends_on(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _make_v2_manifest(machine) -> dict:
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
            "path": f".auditooor/test/artifact-{idx:02d}.json",
            "kind": "file",
            "validators": ["file_exists"],
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


def _build_strict_state(ws: Path, strict_manifest: dict):
    ws = ws.resolve()
    machine = _load_module("pipeline_state_machine_for_done_guard", _PIPELINE_MACHINE)
    executor = _load_module("pipeline_executor_for_done_guard", _PIPELINE_EXECUTOR)
    state = machine.initialize_state(strict_manifest, run_id="run-fixture", **_BASELINES)
    contracts = executor._artifact_contracts(strict_manifest, ws)
    for step in sorted(strict_manifest["steps"], key=lambda item: item["run_sequence"]):
        applicability = machine._applicability.evaluate_probe(strict_manifest, step["applicability_probe"], ws)
        token = machine.start_step(state, strict_manifest, step["step_id"])
        status = "succeeded" if applicability["result"] else "not_applicable"
        input_artifacts = [] if status == "not_applicable" else [
            row for dep in step["depends_on"] for row in state["steps"][dep]["current_output_artifacts"]
        ]
        output_artifacts = []
        if status != "not_applicable":
            contract = contracts[step["produces"][0]]
            out = contract["path"]
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps({"step_id": step["step_id"]}), encoding="utf-8")
            row, diagnostics = executor._artifact_row(contract, ws)
            assert row is not None and not diagnostics
            output_artifacts = [row]
        receipt = machine._receipt.build_receipt(
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
        machine.accept_receipt(state, strict_manifest, receipt, workspace=ws)
        receipt_path = ws / ".auditooor" / "pipeline" / "receipts" / step["step_id"] / f"attempt-{receipt['attempt']}.json"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path = ws / ".auditooor" / "pipeline" / "state.json"
    machine.write_state(path, state)
    return machine, strict_manifest, path, state


def _conformance_pass():
    """Isolate guard tests from the canonical runbook artifact inventory."""
    original = importlib.util.spec_from_file_location

    def spec(name, location, *args, **kwargs):
        loaded = original(name, location, *args, **kwargs)
        if name == "_rcc_done" and loaded is not None and loaded.loader is not None:
            execute = loaded.loader.exec_module

            def execute_with_pass(module):
                execute(module)
                module.evaluate = lambda ws, strict=False: {
                    "conformance_pass": True, "red_step_ids": [], "steps": [],
                }

            loaded.loader.exec_module = execute_with_pass
        if name == "_rac_done" and loaded is not None and loaded.loader is not None:
            execute = loaded.loader.exec_module

            def execute_with_attestation_pass(module):
                execute(module)
                module.verify = lambda ws, *args, **kwargs: {
                    "attestation_pass": True, "failures": [], "failed_step_ids": [],
                }

            loaded.loader.exec_module = execute_with_attestation_pass
        return loaded

    return patch("importlib.util.spec_from_file_location", side_effect=spec)


@contextlib.contextmanager
def _honest_zero_pass():
    original = importlib.util.spec_from_file_location

    def spec(name, location, *args, **kwargs):
        loaded = original(name, location, *args, **kwargs)
        if name == "_hzv_done" and loaded is not None and loaded.loader is not None:
            execute = loaded.loader.exec_module

            def execute_with_pass(module):
                execute(module)
                module.verify = lambda ws, ttl_hours=6: {"ok": True, "reason": "fixture"}

            loaded.loader.exec_module = execute_with_pass
        return loaded

    with patch("importlib.util.spec_from_file_location", side_effect=spec):
        yield


def _waive_terminal_axes(ws: Path):
    (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
        "l37-rebuttal: coverage-map: not under test\n"
        "l37-rebuttal: rubric-coverage: not under test\n",
        encoding="utf-8",
    )


@contextlib.contextmanager
def _strict_manifest_eval(manifest_path: Path):
    original = importlib.util.spec_from_file_location

    def spec(name, location, *args, **kwargs):
        loaded = original(name, location, *args, **kwargs)
        if name == "_rcc_done" and loaded is not None and loaded.loader is not None:
            execute = loaded.loader.exec_module

            def execute_with_manifest(module):
                execute(module)
                real_evaluate = module.evaluate
                module.evaluate = lambda ws, strict=False: real_evaluate(ws, manifest_path, strict=strict)

            loaded.loader.exec_module = execute_with_manifest
        return loaded

    with patch("importlib.util.spec_from_file_location", side_effect=spec):
        yield


class TestAuditDoneGuard(unittest.TestCase):
    def test_no_marker_not_done(self):
        r = m.evaluate(_ws())
        self.assertFalse(r["done"])
        self.assertIn("no audit-complete marker", r["reason"])

    def test_non_pass_verdict_not_done(self):
        ws = _ws(); _marker(ws, "fail-hunt-incomplete")
        r = m.evaluate(ws)
        self.assertFalse(r["done"])
        self.assertIn("NOT pass-audit-complete", r["reason"])

    # r36-rebuttal: lane FIX-HONEST-ZERO-VERIFY registered in .auditooor/agent_pathspec.json
    def test_pass_but_no_paste_ready_not_done(self):
        ws = _ws(); _marker(ws, "pass-audit-complete")
        r = m.evaluate(ws)  # fresh pass but no paste_ready + no verifiable honest-0
        self.assertFalse(r["done"])
        self.assertIn("honest-0 is NOT verifiable", r["reason"])

    def test_stale_pass_not_done(self):
        ws = _ws(); _marker(ws, "pass-audit-complete")
        mk = ws / ".auditooor" / "audit_completion.json"
        # force the marker mtime to 10h ago
        old = time.time() - 10 * 3600
        import os
        os.utime(mk, (old, old))
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "submissions" / "paste_ready" / "f.md").write_text("x")
        r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"])
        self.assertIn("STALE", r["reason"])

    def test_done_happy_path(self):
        ws = _ws(); _marker(ws, "pass-audit-complete")
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "submissions" / "paste_ready" / "f.md").write_text("a finding")
        (ws / ".auditooor" / "skipped_test_markers.jsonl").write_text("", encoding="utf-8")
        _waive_terminal_axes(ws)
        with _conformance_pass():
            r = m.evaluate(ws, ttl_hours=6)
        self.assertTrue(r["done"], r["reason"])

    # r36-rebuttal: lane FIX-HONEST-ZERO-VERIFY registered in .auditooor/agent_pathspec.json
    def test_hand_written_honest_zero_does_NOT_pass(self):
        # A hand-written honest_zero.json with no real evidence must NOT satisfy
        # paste-ready-or-nothing: the guard recomputes the honest-0 via
        # honest-zero-verify, which fails on missing deep evidence.
        ws = _ws(); _marker(ws, "pass-audit-complete")
        (ws / ".auditooor" / "honest_zero.json").write_text(json.dumps({"all_gates_green": True}))
        r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"])
        self.assertIn("honest-0 is NOT verifiable", r["reason"])

    def test_done_via_verified_honest_zero(self):
        # A workspace whose honest-0 RECOMPUTES genuine (real deep evidence,
        # unhunted clean, nothing fileable) is DONE.
        ws = _ws(); _marker(ws, "pass-audit-complete")
        a = ws / ".auditooor"
        (a / "deep-engine-findings").mkdir()
        (a / "deep-engine-findings" / "CORE-SOLVENCY-fuzz.md").write_text("x" * 400)
        (a / "mutation_verify_coverage.json").write_text(json.dumps(
            {"counts": {"cross_function_verified": 5, "per_function_verified": 0}}))
        (a / "coverage_report.json").write_text(json.dumps({"covered": 10, "uncovered": 0}))
        (a / "skipped_test_markers.jsonl").write_text("", encoding="utf-8")
        _waive_terminal_axes(ws)
        with _conformance_pass(), _honest_zero_pass():
            r = m.evaluate(ws, ttl_hours=6)
        self.assertTrue(r["done"], r["reason"])

    def test_conformance_evaluation_exception_blocks_done(self):
        ws = _ws(); _marker(ws, "pass-audit-complete")
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "submissions" / "paste_ready" / "f.md").write_text("a finding")
        original = importlib.util.spec_from_file_location

        def broken_spec(name, location, *args, **kwargs):
            loaded = original(name, location, *args, **kwargs)
            if name == "_rcc_done":
                raise RuntimeError("test conformance evaluation failure")
            return loaded

        with patch("importlib.util.spec_from_file_location", side_effect=broken_spec):
            r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"])
        self.assertTrue(any(g.startswith("readme-conformance-engine-error:") for g in r["fail_gates"]))

    def test_missing_pipeline_state_blocks_done_even_with_fresh_marker_and_paste_ready(self):
        ws = _ws(); _marker(ws, "pass-audit-complete")
        _write_inventory(ws, "go")
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "submissions" / "paste_ready" / "f.md").write_text("a finding")
        manifest = _make_v2_manifest(_load_module("pipeline_state_machine_for_done_guard_manifest", _PIPELINE_MACHINE))
        manifest_path = ws / "strict-v2-manifest.json"
        _write_manifest(manifest_path, manifest)
        _waive_terminal_axes(ws)
        with _strict_manifest_eval(manifest_path):
            r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"])
        self.assertIn("readme-conformance-state:state_file_missing", r["fail_gates"])

    def test_invalidated_pipeline_state_blocks_done(self):
        ws = _ws(); _marker(ws, "pass-audit-complete")
        _write_inventory(ws, "go")
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "submissions" / "paste_ready" / "f.md").write_text("a finding")
        _waive_terminal_axes(ws)
        machine_for_manifest = _load_module("pipeline_state_machine_for_done_guard_manifest_2", _PIPELINE_MACHINE)
        strict_manifest = _make_v2_manifest(machine_for_manifest)
        manifest_path = ws / "strict-v2-manifest.json"
        _write_manifest(manifest_path, strict_manifest)
        machine, strict_manifest, state_path, state = _build_strict_state(ws, strict_manifest)
        machine.invalidate_step(state, strict_manifest, "step-68", reason="test invalidation")
        machine.write_state(state_path, state)
        with _strict_manifest_eval(manifest_path):
            r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"])
        self.assertIn("readme-conformance-closeout:closeout_non_success_terminal_state", r["fail_gates"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
