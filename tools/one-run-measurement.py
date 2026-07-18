#!/usr/bin/env python3
"""Record and compare provenance-compatible audit capability measurements.

This tool does not run detectors or reinterpret outcome data.  It binds already
produced recall, mutation, conversion, outcome, and timing artifacts to one
held-out case set, then permits deltas only for identical provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "auditooor.one_run_measurement.v1"
MANIFEST_SCHEMA = "auditooor.external_recall_samples.v1"
ALLOWED_KINDS = frozenset({"recall", "mutation", "conversion", "outcomes", "timing"})


class MeasurementError(ValueError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MeasurementError(f"measurement_input_unreadable:{path}") from exc


def _input_spec(value: str) -> tuple[str, Path]:
    kind, sep, raw_path = value.partition("=")
    if not sep or kind not in ALLOWED_KINDS or not raw_path:
        raise MeasurementError("measurement_input_spec_invalid")
    return kind, Path(raw_path).expanduser().resolve()


def _case_set(manifest_path: Path) -> dict[str, Any]:
    manifest = _read(manifest_path)
    if not isinstance(manifest, Mapping) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise MeasurementError("measurement_case_manifest_invalid")
    samples = manifest.get("samples")
    if not isinstance(samples, list):
        raise MeasurementError("measurement_case_manifest_samples_invalid")
    ids = []
    for sample in samples:
        if not isinstance(sample, Mapping) or not str(sample.get("id") or "").strip():
            raise MeasurementError("measurement_case_manifest_sample_invalid")
        ids.append(str(sample["id"]).strip())
    if len(ids) != len(set(ids)):
        raise MeasurementError("measurement_case_manifest_duplicate_id")
    return {
        "manifest_schema": MANIFEST_SCHEMA,
        "manifest_path": str(manifest_path),
        "manifest_digest": _digest(manifest),
        "case_ids": sorted(ids),
    }


def build_record(
    manifest_path: Path,
    *,
    repo_revision: str,
    config: Mapping[str, Any],
    tool_versions: Mapping[str, Any],
    inputs: Mapping[str, Path],
    run_id: str,
) -> dict[str, Any]:
    if not repo_revision or not run_id:
        raise MeasurementError("measurement_run_identity_missing")
    if set(inputs) - ALLOWED_KINDS:
        raise MeasurementError("measurement_input_kind_invalid")
    input_rows = []
    measurements: dict[str, Any] = {}
    for kind, path in sorted(inputs.items()):
        payload = _read(path)
        if not isinstance(payload, Mapping) or not str(payload.get("schema") or "").strip():
            raise MeasurementError(f"measurement_input_schema_missing:{kind}")
        # Preserve producer output verbatim under a named measurement. This is
        # intentionally not a second scoring vocabulary.
        measurements[kind] = payload
        input_rows.append({"kind": kind, "schema": payload["schema"], "path": str(path), "digest": _digest(payload)})
    return {
        "schema": SCHEMA,
        "run": {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "toolchain": {"repo_revision": repo_revision, "tool_versions": dict(tool_versions), "config_digest": _digest(config)},
            "case_set": _case_set(manifest_path),
        },
        "inputs": input_rows,
        "measurements": measurements,
    }


def compare(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    if baseline.get("schema") != SCHEMA or candidate.get("schema") != SCHEMA:
        raise MeasurementError("measurement_comparison_schema_invalid")
    left = baseline.get("run") if isinstance(baseline.get("run"), Mapping) else {}
    right = candidate.get("run") if isinstance(candidate.get("run"), Mapping) else {}
    keys = (
        ("case_set.manifest_digest", left.get("case_set", {}).get("manifest_digest"), right.get("case_set", {}).get("manifest_digest")),
        ("case_set.case_ids", left.get("case_set", {}).get("case_ids"), right.get("case_set", {}).get("case_ids")),
        ("toolchain.repo_revision", left.get("toolchain", {}).get("repo_revision"), right.get("toolchain", {}).get("repo_revision")),
        ("toolchain.tool_versions", left.get("toolchain", {}).get("tool_versions"), right.get("toolchain", {}).get("tool_versions")),
        ("toolchain.config_digest", left.get("toolchain", {}).get("config_digest"), right.get("toolchain", {}).get("config_digest")),
    )
    mismatch = [name for name, before, after in keys if before != after]
    if mismatch:
        return {"schema": SCHEMA, "comparable": False, "reasons": mismatch}
    return {"schema": SCHEMA, "comparable": True, "baseline_run_id": left.get("run_id"), "candidate_run_id": right.get("run_id"), "baseline_measurements": baseline.get("measurements", {}), "candidate_measurements": candidate.get("measurements", {})}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--repo-revision")
    parser.add_argument("--config-json", default="{}")
    parser.add_argument("--tool-versions-json", default="{}")
    parser.add_argument("--input", action="append", default=[])
    parser.add_argument("--run-id")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("BASELINE", "CANDIDATE"))
    args = parser.parse_args()
    try:
        if args.compare:
            result = compare(_read(args.compare[0]), _read(args.compare[1]))
        else:
            if not all((args.manifest, args.repo_revision, args.run_id, args.out)):
                raise MeasurementError("measurement_record_arguments_missing")
            config = json.loads(args.config_json)
            versions = json.loads(args.tool_versions_json)
            if not isinstance(config, Mapping) or not isinstance(versions, Mapping):
                raise MeasurementError("measurement_toolchain_json_invalid")
            inputs = dict(_input_spec(value) for value in args.input)
            result = build_record(args.manifest.resolve(), repo_revision=args.repo_revision, config=config, tool_versions=versions, inputs=inputs, run_id=args.run_id)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except (MeasurementError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
