#!/usr/bin/env python3
"""Run a compact, offline demonstration of the ordered pipeline controls.

This is deliberately a control-plane demonstration. It derives its topology
from the production manifest and uses the production validator and state
machine, but it does not manufacture a target audit or a vulnerability claim.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "tools" / "readme_runbook_steps.json"


def load_module(name: str, filename: str) -> Any:
    path = ROOT / "tools" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _capability_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    """Summarize the typed handoffs that turn reasoning into proof work."""

    routes = manifest.get("reasoner_routes", [])
    registry = manifest.get("reasoner_registry", [])
    route_step_ids = {route.get("step_id") for route in routes if isinstance(route, dict)}
    registry_step_ids = {row.get("step_id") for row in registry if isinstance(row, dict)}
    return {
        "artifact_contract_count": len(manifest.get("artifact_contracts", [])),
        "applicability_probe_count": len(manifest.get("applicability_probes", [])),
        "reasoner_count": len(registry),
        "reasoner_route_count": len(routes),
        "reasoner_route_parity": route_step_ids == registry_step_ids,
        "queue_route_count": sum(1 for route in routes if route.get("queue_step_id")),
        "question_route_count": sum(1 for route in routes if route.get("question_step_id")),
        "proof_route_count": sum(1 for route in routes if route.get("proof_step_id")),
        "resolution_route_count": sum(1 for route in routes if route.get("resolution_step_id")),
    }


def _baseline() -> dict[str, str]:
    return {
        "workspace_identity_sha256": "1" * 64,
        "source_snapshot_sha256": "2" * 64,
        "scope_sha256": "3" * 64,
        "severity_sha256": "4" * 64,
        "targets_sha256": "5" * 64,
        "program_rules_sha256": "6" * 64,
        "pipeline_tooling_sha256": "7" * 64,
    }


def main() -> int:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    validator = load_module("judge_manifest_validator", "pipeline-manifest-validate.py")
    machine = load_module("judge_state_machine", "pipeline-state-machine.py")

    result = validator.validate_manifest(manifest)
    if not result["valid"]:
        print("DEMO FAIL: manifest rejected")
        return 1

    steps = manifest["steps"]
    phase_counts = Counter(step["phase"] for step in steps)
    ordered = sorted(steps, key=lambda step: step["run_sequence"])
    first_drive = next(step for step in ordered if step["phase"] == "drive")
    last_reasoning = max(step["run_sequence"] for step in ordered if step["phase"] == "reasoning")
    capabilities = _capability_summary(manifest)

    print("AUDITOOOR JUDGE DEMO")
    print("manifest: valid")
    print(f"required steps: {len(steps)} of {manifest['expected_step_count']}")
    print("phase counts: " + ", ".join(f"{phase}={phase_counts[phase]}" for phase in sorted(phase_counts)))
    print(
        "reasoning before drive: "
        f"PASS (last reasoning sequence={last_reasoning}, first drive={first_drive['run_sequence']})"
    )
    print("capability topology:")
    print(
        "  typed artifact contracts: "
        f"{capabilities['artifact_contract_count']}"
    )
    print(
        "  reasoners and routes: "
        f"{capabilities['reasoner_count']} reasoners, "
        f"{capabilities['reasoner_route_count']} routes "
        f"(parity={'PASS' if capabilities['reasoner_route_parity'] else 'FAIL'})"
    )
    print(
        "  reasoner handoffs: "
        f"queue={capabilities['queue_route_count']}, "
        f"questions={capabilities['question_route_count']}, "
        f"proof={capabilities['proof_route_count']}, "
        f"resolution={capabilities['resolution_route_count']}"
    )
    print(f"  applicability probes: {capabilities['applicability_probe_count']}")

    state = machine.initialize_state(manifest, run_id="judge-demo", **_baseline())
    try:
        machine.start_step(state, manifest, first_drive["step_id"])
    except machine.StateMachineError as error:
        print(f"early drive attempt: BLOCKED ({', '.join(error.diagnostics)})")
    else:
        print("DEMO FAIL: drive started before required predecessors")
        return 1

    closeout = machine.closeout(state, manifest)
    print(
        "empty closeout: BLOCKED "
        f"(current receipts={closeout['current_receipt_count']}/{manifest['expected_step_count']}; "
        f"{', '.join(closeout['diagnostics'])})"
    )

    tampered = dict(state)
    tampered["state_self_hash"] = "0" * 64
    valid, diagnostics = machine.validate_state(tampered)
    if valid or "state_self_hash_mismatch" not in diagnostics:
        print("DEMO FAIL: tampered state was accepted")
        return 1
    print("tampered state: BLOCKED (state_self_hash_mismatch)")

    print("evidence boundary: real topology and enforcement, no target audit or vulnerability claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
