#!/usr/bin/env python3
"""Require a reviewed, pin-bound awareness ledger at canonical intake Step 0d."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
LEDGER_SCHEMA = "auditooor.awareness_ledger.v1"
DEFAULT_MANIFEST = Path(".auditooor") / "awareness_evidence_manifest.json"
DEFAULT_DISCOVERY = Path(".auditooor") / "awareness_source_discovery.json"
DEFAULT_OUTPUT = Path(".auditooor") / "awareness_ledger.json"


def _load_awareness_module() -> Any:
    path = REPO_ROOT / "tools" / "awareness-ledger.py"
    spec = importlib.util.spec_from_file_location("prior_history_awareness_ledger", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("awareness_ledger_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


def _load_inventory_module() -> Any:
    path = REPO_ROOT / "tools" / "awareness-source-inventory.py"
    spec = importlib.util.spec_from_file_location("prior_history_awareness_inventory", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("awareness_source_inventory_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


def build_awareness_ledger(
    workspace: Path,
    manifest_path: Path,
    output_path: Path,
    *,
    discovery_path: Path | None = None,
    expected_pin: str | None = None,
) -> dict[str, Any]:
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("awareness_evidence_manifest_missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("awareness_evidence_manifest_malformed") from exc
    if not isinstance(manifest, dict):
        raise ValueError("awareness_evidence_manifest_not_object")
    pin = str(manifest.get("audit_pin", "")).strip()
    discovery = discovery_path or workspace / DEFAULT_DISCOVERY
    if not discovery.is_file() or discovery.is_symlink():
        raise ValueError("awareness_source_discovery_missing")
    try:
        inventory = _load_inventory_module()
        expected_sources = inventory.compile_expected_sources(
            inventory.load_discovery(discovery), pin
        )
    except Exception as exc:
        raise ValueError(f"awareness_source_discovery_invalid:{exc}") from exc
    declared = manifest.get("expected_sources")
    if declared is not None:
        if not isinstance(declared, list):
            raise ValueError("awareness_manifest_inventory_mismatch")
        try:
            normalized_declared = sorted(
                [{
                    "source_id": str(row["source_id"]),
                    "source_kind": str(row["source_kind"]),
                    "source_ref": str(row["source_ref"]),
                    "pin_binding": str(row["pin_binding"]),
                } for row in declared if isinstance(row, dict)],
                key=lambda row: row["source_id"],
            )
        except KeyError as exc:
            raise ValueError("awareness_manifest_inventory_mismatch") from exc
        if len(normalized_declared) != len(declared) or normalized_declared != expected_sources:
            raise ValueError("awareness_manifest_inventory_mismatch")
    manifest = dict(manifest)
    manifest["expected_sources"] = expected_sources
    ledger = _load_awareness_module().build_ledger(manifest)
    validation_errors = _load_awareness_module().validate_ledger(ledger)
    if validation_errors:
        raise ValueError("awareness_ledger_incomplete")
    if expected_pin is not None and ledger.get("audit_pin") != expected_pin:
        raise ValueError("awareness_ledger_attestation_pin_mismatch")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(ledger, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return ledger


def run(workspace: Path, manifest_path: Path, output_path: Path, *, discovery_path: Path | None = None, verify_attestation: bool = True) -> dict[str, Any]:
    expected_pin: str | None = None
    if verify_attestation:
        check = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "readme-attestation-check.py"),
                "--verify",
                "--ws",
                str(workspace),
                "--step",
                "step-0d",
                "--json",
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if check.returncode != 0:
            raise ValueError("step_0d_attestation_failed")
        attestation_path = workspace / ".auditooor" / "attestations" / "step-0d.json"
        try:
            attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("step_0d_attestation_malformed") from exc
        expected_pin = str(attestation.get("pinned_commit", "")).strip()
        if not expected_pin:
            raise ValueError("step_0d_attestation_pin_missing")
    if discovery_path is None:
        try:
            manifest_value = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("awareness_evidence_manifest_malformed") from exc
        audit_pin = str(manifest_value.get("audit_pin", "")).strip() if isinstance(manifest_value, dict) else ""
        if not audit_pin or (expected_pin is not None and audit_pin != expected_pin):
            raise ValueError("awareness_source_discovery_pin_mismatch")
        bootstrap = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "step-0d-awareness-bootstrap.py"), "--workspace", str(workspace), "--audit-pin", audit_pin],
            cwd=REPO_ROOT, text=True, capture_output=True, check=False,
        )
        if bootstrap.returncode:
            raise ValueError("awareness_source_discovery_producer_failed")
    ledger = build_awareness_ledger(workspace, manifest_path, output_path, discovery_path=discovery_path, expected_pin=expected_pin)
    return {
        "schema": "auditooor.prior_history_awareness_gate.v1",
        "workspace": str(workspace),
        "awareness_ledger": str(output_path),
        "candidate_count": len(ledger.get("candidates", [])),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--discovery", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    manifest = args.manifest or workspace / DEFAULT_MANIFEST
    output = args.output or workspace / DEFAULT_OUTPUT
    try:
        result = run(workspace, manifest, output, discovery_path=args.discovery)
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
