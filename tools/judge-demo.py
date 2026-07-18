#!/usr/bin/env python3
"""Run a compact, offline demonstration of the ordered pipeline controls."""

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

    print("AUDITOOOR JUDGE DEMO")
    print("manifest: valid")
    print(f"required steps: {len(steps)} of {manifest['expected_step_count']}")
    print("phase counts: " + ", ".join(f"{phase}={phase_counts[phase]}" for phase in sorted(phase_counts)))
    print(
        "reasoning before drive: "
        f"PASS (last reasoning sequence={last_reasoning}, first drive={first_drive['run_sequence']})"
    )

    baseline = {
        "workspace_identity_sha256": "1" * 64,
        "source_snapshot_sha256": "2" * 64,
        "scope_sha256": "3" * 64,
        "severity_sha256": "4" * 64,
        "targets_sha256": "5" * 64,
        "program_rules_sha256": "6" * 64,
        "pipeline_tooling_sha256": "7" * 64,
    }
    state = machine.initialize_state(manifest, run_id="judge-demo", **baseline)
    try:
        machine.start_step(state, manifest, first_drive["step_id"])
    except machine.StateMachineError as error:
        print(f"early drive attempt: BLOCKED ({', '.join(error.diagnostics)})")
    else:
        print("DEMO FAIL: drive started before required predecessors")
        return 1

    print("evidence boundary: this demonstrates control-plane enforcement only; no target was audited")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
