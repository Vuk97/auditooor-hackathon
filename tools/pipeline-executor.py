#!/usr/bin/env python3
"""Execute one ordered Pipeline V2 manifest step with receipt-backed state."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
PIPELINE_RELATIVE = Path(".auditooor") / "pipeline"
PLACEHOLDER_RE = re.compile(r"\{[^{}]+\}")
NONTERMINAL_OUTPUT_RE = re.compile(r"\b(?:warn(?:ing)?|advisory(?:-only|[- ]first)?)\b", re.IGNORECASE)
KNOWN_ARTIFACT_VALIDATORS = frozenset(
    {"noop", "file_exists", "directory_exists", "file_nonempty", "json", "awareness_ledger"}
)
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SECRET_ENVIRONMENT_TOKENS = frozenset({"API_KEY", "PASSWORD", "PRIVATE_KEY", "SECRET", "TOKEN"})
CANONICAL_PIPELINE_TOOLS = (
    "tools/pipeline-executor.py",
    "tools/pipeline-manifest-validate.py",
    "tools/pipeline-state-machine.py",
    "tools/pipeline-receipt.py",
    "tools/pipeline-applicability.py",
    "tools/awareness-ledger.py",
    "tools/prior-history-awareness-gate.py",
)


def _load_module(name: str, filename: str) -> Any:
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


_validator = _load_module("_pipeline_executor_manifest", "pipeline-manifest-validate.py")
_machine = _load_module("_pipeline_executor_state", "pipeline-state-machine.py")
_receipt = _load_module("_pipeline_executor_receipt", "pipeline-receipt.py")
_applicability = _load_module("_pipeline_executor_applicability", "pipeline-applicability.py")
_awareness = _load_module("_pipeline_executor_awareness", "awareness-ledger.py")


class ExecutorError(ValueError):
    """Stable, sorted error diagnostics for fail-closed executor decisions."""

    def __init__(self, *diagnostics: str):
        self.diagnostics = tuple(sorted({str(item) for item in diagnostics if str(item)}))
        super().__init__(", ".join(self.diagnostics))


class JsonArgumentParser(argparse.ArgumentParser):
    """Keep automation-facing argument failures in the JSON diagnostic channel."""

    def error(self, message: str) -> None:
        raise ExecutorError(f"argument_error:{message}")


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def _json(value: Mapping[str, Any]) -> None:
    print(json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _directory_metadata(root: Path) -> tuple[str, int]:
    """Hash a directory by sorted relative file metadata, never mtime or inode."""

    if not root.is_dir() or root.is_symlink():
        return _receipt.stable_hash({"missing": root.name}), 0
    rows: list[dict[str, Any]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink()):
        rows.append({"path": path.relative_to(root).as_posix(), "sha256": _sha256_file(path), "size": path.stat().st_size})
    return _receipt.stable_hash(rows), sum(row["size"] for row in rows)


def _tree_hash(root: Path) -> str:
    return _directory_metadata(root)[0]


def _path_hash(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        return _receipt.stable_hash({"missing": path.name})
    return _sha256_file(path)


def _inventory_source_snapshot(root: Path) -> str | None:
    inventory_path = root / ".auditooor" / "inscope_units.jsonl"
    if not inventory_path.is_file():
        return None
    try:
        raw = inventory_path.read_bytes()
        rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutorError("source_inventory_malformed") from exc
    if not rows:
        raise ExecutorError("source_inventory_empty")
    sources: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        relative = row.get("file") if isinstance(row, dict) else None
        if not isinstance(relative, str) or not relative.strip():
            raise ExecutorError(f"source_inventory_invalid_row:{index}")
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ExecutorError(f"source_inventory_outside_workspace:{index}") from exc
        if not candidate.is_file() or candidate.is_symlink():
            raise ExecutorError(f"source_inventory_source_missing:{index}")
        sources.append({"path": candidate.relative_to(root).as_posix(), "sha256": _sha256_file(candidate), "size": candidate.stat().st_size})
    return _receipt.stable_hash({"mode": "inscope_inventory", "inventory_sha256": _sha256_bytes(raw), "sources": sorted(sources, key=lambda item: item["path"])})


def _registry_source_snapshot(root: Path) -> str:
    targets_path = root / "targets.tsv"
    roots: list[Path] = []
    if targets_path.is_file():
        for line in targets_path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) >= 3 and fields[2].strip():
                candidate = (root / "src" / fields[2].strip()).resolve()
                if candidate.is_dir() and not candidate.is_symlink():
                    roots.append(candidate)
    if not roots and (root / "src").is_dir():
        roots.append(root / "src")
    rows: list[dict[str, Any]] = []
    for source_root in sorted(set(roots)):
        for path in sorted(item for item in source_root.rglob("*") if item.is_file() and not item.is_symlink()):
            rows.append({"path": path.relative_to(root).as_posix(), "sha256": _sha256_file(path), "size": path.stat().st_size})
    return _receipt.stable_hash({"mode": "canonical_registry", "roots": [item.relative_to(root).as_posix() for item in sorted(set(roots))], "sources": rows})


def _source_snapshot(root: Path) -> str:
    """Use the authoritative in-scope inventory, otherwise canonical target roots."""

    return _inventory_source_snapshot(root) or _registry_source_snapshot(root)


def current_baselines(workspace: str | Path) -> dict[str, str]:
    """Return immutable state baselines without hashing executor-owned receipts."""

    root = Path(workspace).expanduser().resolve()
    if not root.is_dir():
        raise ExecutorError("workspace_missing")
    return {
        "workspace_identity_sha256": _receipt.stable_hash({"workspace": str(root)}),
        "source_snapshot_sha256": _source_snapshot(root),
        "scope_sha256": _path_hash(root / "SCOPE.md"),
        "severity_sha256": _path_hash(root / "SEVERITY.md"),
        "targets_sha256": _path_hash(root / "targets.tsv"),
        "program_rules_sha256": _path_hash(root / ".auditooor" / "program_rules.json"),
    }


def _load_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path).expanduser().resolve()
    result = _validator.validate_manifest_file(manifest_path)
    if not isinstance(result, dict) or not isinstance(result.get("valid"), bool) or not isinstance(result.get("diagnostics"), list):
        raise ExecutorError("manifest_validator_malformed_result")
    if not result["valid"]:
        codes = [item.get("code") for item in result["diagnostics"] if isinstance(item, dict) and isinstance(item.get("code"), str)]
        raise ExecutorError("manifest_invalid", *[f"manifest_{code}" for code in codes])
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExecutorError("manifest_load_error") from exc
    if not isinstance(raw, dict):
        raise ExecutorError("manifest_not_object")
    return raw


def _make_target_definition(makefile: Path, target: str) -> str:
    try:
        lines = makefile.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ExecutorError("pipeline_tooling_makefile_missing") from exc
    start = next((index for index, line in enumerate(lines) if re.match(rf"^{re.escape(target)}\s*:(?:\s|$)", line)), None)
    if start is None:
        raise ExecutorError(f"pipeline_tooling_make_target_missing:{target}")
    body = [lines[start]]
    for line in lines[start + 1 :]:
        if line and not line[0].isspace() and re.match(r"^[A-Za-z0-9_.%/-]+\s*:(?:\s|$)", line):
            break
        body.append(line)
    return "\n".join(body) + "\n"


def _pipeline_tooling_hash(manifest: Mapping[str, Any]) -> str:
    """Bind credit to the executor stack and manifest-declared repo entrypoints."""

    paths = set(CANONICAL_PIPELINE_TOOLS)
    make_targets: set[str] = set()
    for step in manifest.get("steps", []):
        target = step.get("execution_target") if isinstance(step, dict) else None
        if not isinstance(target, list) or len(target) < 2:
            continue
        executable, entrypoint = target[0], target[1]
        if executable in {"python3", "bash"} and isinstance(entrypoint, str) and entrypoint.startswith("tools/"):
            paths.add(entrypoint)
        elif executable == "make" and isinstance(entrypoint, str):
            make_targets.add(entrypoint)
    rows: list[dict[str, Any]] = []
    for relative in sorted(paths):
        path = (REPO_ROOT / relative).resolve()
        try:
            path.relative_to(REPO_ROOT)
        except ValueError as exc:
            raise ExecutorError(f"pipeline_tooling_path_outside_repo:{relative}") from exc
        if not path.is_file() or path.is_symlink():
            raise ExecutorError(f"pipeline_tooling_source_missing:{relative}")
        rows.append({"kind": "file", "path": relative, "sha256": _sha256_file(path), "size": path.stat().st_size})
    makefile = REPO_ROOT / "Makefile"
    for target in sorted(make_targets):
        definition = _make_target_definition(makefile, target).encode("utf-8")
        rows.append({"kind": "make_target", "path": f"Makefile:{target}", "sha256": _sha256_bytes(definition), "size": len(definition)})
    return _receipt.stable_hash(rows)


def _pipeline_dir(workspace: Path) -> Path:
    return workspace / PIPELINE_RELATIVE


def _default_state_path(workspace: Path) -> Path:
    return _pipeline_dir(workspace) / "state.json"


def _run_id(manifest: Mapping[str, Any], baselines: Mapping[str, str]) -> str:
    return "pipeline-" + _receipt.stable_hash({"manifest": _canonical(manifest), "baselines": _canonical(baselines)})[:24]


def _archive_active_run(
    state_path: Path,
    state: Mapping[str, Any],
    diagnostics: Sequence[str],
    manifest: Mapping[str, Any],
    baselines: Mapping[str, str],
) -> Path:
    archive_root = state_path.parent / "archive"
    stem = f"{state['run_id']}-{state['state_self_hash'][:16]}"
    archive_path = archive_root / stem
    suffix = 0
    while archive_path.exists():
        suffix += 1
        archive_path = archive_root / f"{stem}-{suffix:02d}"
    archive_path.mkdir(parents=True)
    record = {
        "schema": "auditooor.pipeline_run_archive.v1",
        "archived_run_id": state["run_id"],
        "archived_state_self_hash": state["state_self_hash"],
        "diagnostics": sorted(set(diagnostics)),
        "new_baselines": _canonical(baselines),
        "new_manifest_sha256": _receipt.stable_hash(_canonical(manifest)),
        "new_pipeline_tooling_sha256": manifest.get("_pipeline_tooling_sha256"),
    }
    (archive_path / "archive_record.json").write_text(
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    for name in ("receipts", "logs", "tokens", "attempt-output-baselines"):
        source = state_path.parent / name
        if source.exists():
            os.replace(source, archive_path / name)
    os.replace(state_path, archive_path / state_path.name)
    return archive_path


def _read_or_initialize_state(
    manifest: Mapping[str, Any], workspace: Path, state_path: Path, baselines: Mapping[str, str]
) -> tuple[dict[str, Any], bool, dict[str, Any]]:
    state, errors = _machine.read_state(state_path)
    if state is None:
        if errors == ["state_file_missing"]:
            return _machine.initialize_state(manifest, run_id=_run_id(manifest, baselines), **baselines), True, {
                "rotated": False,
                "diagnostics": [],
                "archive_path": None,
            }
        raise ExecutorError("state_invalid", *errors)
    mismatch_diagnostics = [
        f"{field}_mismatch"
        for field, value in baselines.items()
        if state.get(field) != value
    ]
    if state.get("manifest_sha256") != _receipt.stable_hash(_canonical(manifest)):
        mismatch_diagnostics.append("manifest_sha256_mismatch")
    try:
        _machine.resume_state(state, manifest, run_id=state["run_id"], **baselines)
    except _machine.StateMachineError as exc:
        all_diagnostics = sorted(set([*mismatch_diagnostics, *exc.diagnostics]))
        archive_path = _archive_active_run(state_path, state, all_diagnostics, manifest, baselines)
        replacement = _machine.initialize_state(manifest, run_id=_run_id(manifest, baselines), **baselines)
        _machine.write_state(state_path, replacement)
        return replacement, True, {
            "rotated": True,
            "diagnostics": [f"run_rotated:{item}" for item in all_diagnostics],
            "archive_path": str(archive_path),
        }
    return state, False, {"rotated": False, "diagnostics": [], "archive_path": None}


def _next_step(manifest: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any] | None:
    for step in sorted(manifest["steps"], key=lambda item: item["run_sequence"]):
        status = state["steps"][step["step_id"]]["state"]
        if status not in {"succeeded", "not_applicable"}:
            return step
    return None


def _expand_workspace(value: str, workspace: Path) -> str:
    expanded = value.replace("{workspace}", str(workspace))
    if PLACEHOLDER_RE.search(expanded):
        raise ExecutorError("undeclared_placeholder")
    return expanded


def expand_argv(argv: Sequence[Any], workspace: str | Path) -> list[str]:
    """Expand only literal ``{workspace}`` placeholders without shell parsing."""

    root = Path(workspace).expanduser().resolve()
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ExecutorError("invalid_execution_target")
    result: list[str] = []
    for value in argv:
        if not isinstance(value, str) or not value:
            raise ExecutorError("invalid_execution_target")
        result.append(_expand_workspace(value, root))
    return result


def _execution_manifest(manifest: Mapping[str, Any], workspace: Path) -> dict[str, Any]:
    """Bind state and receipts to the exact expanded argv that will execute."""

    expanded = json.loads(json.dumps(_canonical(manifest)))
    expanded["_pipeline_tooling_sha256"] = _pipeline_tooling_hash(manifest)
    for step in expanded.get("steps", []):
        if not isinstance(step, dict):
            raise ExecutorError("invalid_execution_target")
        step["execution_target"] = expand_argv(step.get("execution_target"), workspace)
    return expanded


def _execution_environment(manifest: Mapping[str, Any]) -> dict[str, str]:
    declared = manifest.get("environment_passthrough", [])
    if not isinstance(declared, list) or any(not isinstance(name, str) or not ENVIRONMENT_NAME_RE.fullmatch(name) for name in declared):
        raise ExecutorError("environment_passthrough_malformed")
    if len(set(declared)) != len(declared):
        raise ExecutorError("environment_passthrough_duplicate")
    if any(any(token in name for token in SECRET_ENVIRONMENT_TOKENS) for name in declared):
        raise ExecutorError("environment_passthrough_secret_forbidden")
    selected = {"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", ""), "PYTHONUTF8": "1"}
    for name in sorted(declared):
        if name in os.environ:
            selected[name] = os.environ[name]
    return selected


def _artifact_contracts(manifest: Mapping[str, Any], workspace: Path) -> dict[str, dict[str, Any]]:
    """Normalize top-level artifact contracts in one compatibility boundary."""

    raw = manifest.get("artifact_contracts", [])
    if not isinstance(raw, list):
        raise ExecutorError("artifact_contracts_malformed")
    result: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(raw):
        if not isinstance(row, dict):
            raise ExecutorError(f"artifact_contract_{index}_malformed")
        contract_id = row.get("id", row.get("artifact_contract"))
        path_value = row.get("path")
        kind = row.get("kind", "file")
        validators = row.get("validators", [])
        freshness_policy = row.get("freshness_policy", "must_refresh")
        if not isinstance(contract_id, str) or not contract_id.strip() or not isinstance(path_value, str) or not path_value:
            raise ExecutorError(f"artifact_contract_{index}_malformed")
        if (
            contract_id in result
            or kind not in {"file", "directory"}
            or freshness_policy not in {"must_refresh", "validate_existing"}
            or not isinstance(validators, list)
            or any(not isinstance(item, str) or not item for item in validators)
        ):
            raise ExecutorError(f"artifact_contract_{index}_malformed")
        try:
            expanded = Path(_expand_workspace(path_value, workspace)).expanduser()
        except ExecutorError:
            raise ExecutorError(f"artifact_contract_{index}_placeholder") from None
        target = (workspace / expanded).resolve() if not expanded.is_absolute() else expanded.resolve()
        try:
            target.relative_to(workspace)
        except ValueError as exc:
            raise ExecutorError(f"artifact_contract_{index}_outside_workspace") from exc
        result[contract_id] = {
            "id": contract_id,
            "path": target,
            "kind": kind,
            "validators": list(validators),
            "freshness_policy": freshness_policy,
        }
    return result


def _freshness_marker(contract: Mapping[str, Any]) -> dict[str, Any]:
    path = contract["path"]
    expected_kind = contract["kind"]
    exists = path.is_file() if expected_kind == "file" else path.is_dir()
    if not exists or path.is_symlink():
        return {"exists": False}
    paths = [path] if expected_kind == "file" else sorted(item for item in path.rglob("*") if item.is_file() and not item.is_symlink())
    rows: list[dict[str, Any]] = []
    for item in paths:
        stat = item.stat()
        rows.append(
            {
                "path": item.name if expected_kind == "file" else item.relative_to(path).as_posix(),
                "sha256": _sha256_file(item),
                "size": stat.st_size,
                "inode": stat.st_ino,
                "mtime_ns": stat.st_mtime_ns,
                "ctime_ns": stat.st_ctime_ns,
            }
        )
    return {"exists": True, "kind": expected_kind, "rows": rows}


def _archive_attempt_outputs(
    state_path: Path,
    step: Mapping[str, Any],
    attempt: int,
    contracts: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    snapshots: dict[str, dict[str, Any]] = {}
    archive_root = state_path.parent / "attempt-output-baselines" / step["step_id"] / f"attempt-{attempt}"
    for contract_id in step["produces"]:
        contract = contracts.get(contract_id)
        if contract is None:
            continue
        marker = _freshness_marker(contract)
        snapshots[contract_id] = marker
        if not marker["exists"]:
            continue
        contract_dir = archive_root / _receipt.stable_hash(contract_id)[:16]
        contract_dir.mkdir(parents=True, exist_ok=True)
        source = contract["path"]
        destination = contract_dir / "artifact"
        if contract["kind"] == "file":
            shutil.copy2(source, destination)
        else:
            shutil.copytree(source, destination, symlinks=True)
        (contract_dir / "metadata.json").write_text(
            json.dumps(
                {"artifact_contract": contract_id, "path": str(source), "freshness_marker": marker},
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return snapshots


def _output_freshness_errors(
    step: Mapping[str, Any],
    contracts: Mapping[str, Mapping[str, Any]],
    before: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for contract_id in step["produces"]:
        contract = contracts.get(contract_id)
        if contract is None:
            continue
        policy = contract["freshness_policy"]
        if policy == "validate_existing":
            step_class = step.get("class", "")
            verification = step.get("how_to_verify_done")
            if (
                step.get("phase") != "intake"
                or not isinstance(step_class, str)
                or not step_class.startswith("manual")
                or not isinstance(verification, dict)
                or verification.get("attestation_required") is not True
            ):
                errors.append(f"validate_existing_not_manual_intake:{contract_id}")
            continue
        prior = before.get(contract_id, {"exists": False})
        current = _freshness_marker(contract)
        if not current["exists"]:
            errors.append(f"output_not_produced:{contract_id}")
        elif prior.get("exists") and current == prior:
            errors.append(f"output_not_refreshed:{contract_id}")
    return sorted(set(errors))


def _validate_artifact(contract: Mapping[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    path = contract["path"]
    diagnostics: list[str] = []
    expected_kind = contract["kind"]
    exists = path.is_file() if expected_kind == "file" else path.is_dir()
    if not exists or path.is_symlink():
        diagnostics.append(f"artifact_missing:{contract['id']}")
        return None, diagnostics
    results: list[dict[str, str]] = []
    for validator_id in contract["validators"]:
        if validator_id not in KNOWN_ARTIFACT_VALIDATORS:
            diagnostics.append(f"unknown_artifact_validator:{validator_id}")
            results.append({"validator_id": validator_id, "status": "failed"})
            continue
        passed = validator_id == "noop"
        if validator_id == "file_exists":
            passed = expected_kind == "file" and path.is_file()
        elif validator_id == "directory_exists":
            passed = expected_kind == "directory" and path.is_dir()
        elif validator_id == "file_nonempty":
            passed = path.stat().st_size > 0 if expected_kind == "file" else any(path.iterdir())
        elif validator_id == "json":
            try:
                if expected_kind != "file":
                    raise IsADirectoryError(path)
                json.loads(path.read_text(encoding="utf-8"))
                passed = True
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                passed = False
        elif validator_id == "awareness_ledger":
            try:
                if expected_kind != "file":
                    raise IsADirectoryError(path)
                ledger = json.loads(path.read_text(encoding="utf-8"))
                passed = not _awareness.validate_ledger(ledger)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                passed = False
        if not passed:
            diagnostics.append(f"artifact_validator_failed:{contract['id']}:{validator_id}")
        results.append({"validator_id": validator_id, "status": "succeeded" if passed else "failed"})
    sha256, size = (_sha256_file(path), path.stat().st_size) if expected_kind == "file" else _directory_metadata(path)
    return {
        "artifact_contract": contract["id"],
        "path": path.name,
        "sha256": sha256,
        "size": size,
        "semantic_validator_results": results,
    }, diagnostics


def _artifact_row(contract: Mapping[str, Any], workspace: Path) -> tuple[dict[str, Any] | None, list[str]]:
    row, diagnostics = _validate_artifact(contract)
    if row is not None:
        row["path"] = contract["path"].relative_to(workspace).as_posix()
    return row, diagnostics


def _input_artifact_staleness_errors(
    inputs: Sequence[Mapping[str, Any]], contracts: Mapping[str, Mapping[str, Any]], workspace: Path
) -> list[str]:
    """Reject a consumer when a credited input changed during its command."""

    errors: list[str] = []
    for input_row in inputs:
        contract_id = input_row["artifact_contract"]
        contract = contracts.get(contract_id)
        actual, diagnostics = _artifact_row(contract, workspace) if contract is not None else (None, ["missing"])
        if diagnostics or actual is None or any(actual.get(field) != input_row.get(field) for field in ("artifact_contract", "path", "sha256", "size")):
            errors.append(f"input_artifact_stale_on_disk:{contract_id}")
    return sorted(set(errors))


def _verify_current_outputs(state: Mapping[str, Any], contracts: Mapping[str, Mapping[str, Any]], workspace: Path) -> list[str]:
    errors: list[str] = []
    for entry in state["steps"].values():
        if entry.get("state") not in {"succeeded", "not_applicable"}:
            continue
        for row in entry.get("current_output_artifacts", []):
            contract = contracts.get(row.get("artifact_contract"))
            if contract is None:
                errors.append(f"stale_output_unknown_contract:{row.get('artifact_contract', '')}")
                continue
            actual, diagnostics = _artifact_row(contract, workspace)
            if diagnostics or actual is None:
                errors.extend(f"stale_output:{item}" for item in diagnostics or [contract["id"]])
                continue
            if any(actual.get(field) != row.get(field) for field in ("artifact_contract", "path", "sha256", "size")):
                errors.append(f"stale_output_hash_mismatch:{contract['id']}")
    return sorted(set(errors))


def _stale_output_producers(
    state: Mapping[str, Any], manifest: Mapping[str, Any], contracts: Mapping[str, Mapping[str, Any]], workspace: Path
) -> list[tuple[str, str]]:
    stale: list[tuple[str, str]] = []
    step_by_id = {step["step_id"]: step for step in manifest["steps"]}
    for step_id, entry in state["steps"].items():
        if entry.get("state") not in {"succeeded", "not_applicable"}:
            continue
        for row in entry.get("current_output_artifacts", []):
            contract_id = row.get("artifact_contract")
            contract = contracts.get(contract_id)
            if contract is None:
                stale.append((step_id, str(contract_id)))
                continue
            actual, diagnostics = _artifact_row(contract, workspace)
            if diagnostics or actual is None or any(actual.get(field) != row.get(field) for field in ("artifact_contract", "path", "sha256", "size")):
                stale.append((step_id, str(contract_id)))
    return sorted(set(stale), key=lambda item: (step_by_id[item[0]]["run_sequence"], item[1]))


def _timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _token_path(state_path: Path, step_id: str, attempt: int) -> Path:
    return state_path.parent / "tokens" / f"{step_id}.attempt-{attempt}.token"


def _write_token(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n", encoding="ascii")
    path.chmod(0o600)


def _receipt_path(state_path: Path, step_id: str, attempt: int) -> Path:
    return state_path.parent / "receipts" / step_id / f"attempt-{attempt}.json"


def _log_path(state_path: Path, step_id: str, attempt: int, stream: str) -> Path:
    return state_path.parent / "logs" / step_id / f"attempt-{attempt}.{stream}"


def _build_and_accept(
    *, state: dict[str, Any], manifest: Mapping[str, Any], workspace: Path, state_path: Path, step: Mapping[str, Any], token: str,
    applicability: Mapping[str, Any] | None, status: str, started_at: str, finished_at: str, exit_code: int, stdout: bytes, stderr: bytes,
    contracts: Mapping[str, Mapping[str, Any]], argv: Sequence[str], selected_environment: Mapping[str, str], extra_diagnostics: Sequence[str] = (),
    applicability_error_diagnostics: Sequence[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    entry = state["steps"][step["step_id"]]
    errors = list(extra_diagnostics)
    inputs = []
    all_steps = {item["step_id"]: item for item in manifest["steps"]}
    ancestor_ids: set[str] = set()
    queue = list(step["depends_on"])
    while queue:
        ancestor = queue.pop()
        if ancestor in ancestor_ids:
            continue
        ancestor_ids.add(ancestor)
        queue.extend(all_steps[ancestor]["depends_on"])
    ordered_ancestors = sorted(ancestor_ids, key=lambda item: all_steps[item]["run_sequence"], reverse=True)
    for contract_id in step["consumes"]:
        found = next(
            (row for ancestor in ordered_ancestors for row in state["steps"][ancestor]["current_output_artifacts"] if row["artifact_contract"] == contract_id),
            None,
        )
        if found is None:
            errors.append(f"input_artifact_missing:{contract_id}")
        else:
            inputs.append(found)
    errors.extend(_input_artifact_staleness_errors(inputs, contracts, workspace))
    outputs = []
    if status == "succeeded":
        for contract_id in step["produces"]:
            contract = contracts.get(contract_id)
            if contract is None:
                errors.append(f"artifact_contract_missing:{contract_id}")
                continue
            row, artifact_errors = _artifact_row(contract, workspace)
            if row is not None:
                outputs.append(row)
            errors.extend(artifact_errors)
    applicable = bool(applicability is not None and applicability["result"])
    final_status = "not_applicable" if not applicable and not errors and applicability_error_diagnostics is None else ("failed" if errors or status == "failed" or applicability_error_diagnostics is not None else "succeeded")
    if final_status == "not_applicable":
        inputs, outputs = [], []
    diagnostic_bytes = "".join(f"{item}\n" for item in sorted(set(errors))).encode("utf-8")
    stderr = stderr + diagnostic_bytes
    for stream, content in (("stdout", stdout), ("stderr", stderr)):
        log_path = _log_path(state_path, step["step_id"], entry["attempt"], stream)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_bytes(content)
    receipt = _receipt.build_receipt(
        run_id=state["run_id"],
        **{field: state[field] for field in _receipt.PROVENANCE_FIELDS},
        step_id=step["step_id"], order_index=step["order_index"], attempt=entry["attempt"], step_token=token,
        status=final_status,
        applicability_probe_id=step["applicability_probe"] if applicability is None else applicability["probe_id"],
        applicability_inputs={} if applicability is None else applicability["canonical_inputs"],
        applicability_result=False if applicability is None else applicability["result"],
        applicability_error_diagnostics=applicability_error_diagnostics,
        argv=argv,
        selected_environment=selected_environment,
        started_at=started_at, finished_at=finished_at, exit_code=0 if final_status in {"succeeded", "not_applicable"} else exit_code or 1,
        upstream_receipt_ids=[state["steps"][item]["current_receipt_id"] for item in step["depends_on"]],
        input_artifacts=inputs, output_artifacts=outputs if final_status != "not_applicable" else [],
        stdout_sha256=_sha256_bytes(stdout), stderr_sha256=_sha256_bytes(stderr),
        tool_versions={
            "pipeline_executor": "1",
            "pipeline_tooling_sha256": str(manifest.get("_pipeline_tooling_sha256", "")),
        },
        toolchain_versions={"python": sys.version.split()[0]},
    )
    _receipt.write_receipt(_receipt_path(state_path, step["step_id"], entry["attempt"]), receipt)
    _machine.accept_receipt(state, manifest, receipt, workspace=workspace)
    _machine.write_state(state_path, state)
    _token_path(state_path, step["step_id"], entry["attempt"]).unlink(missing_ok=True)
    return receipt, sorted(set(errors))


def _fail_expected(
    state: dict[str, Any], manifest: Mapping[str, Any], workspace: Path, state_path: Path, step: Mapping[str, Any], contracts: Mapping[str, Mapping[str, Any]],
    selected_environment: Mapping[str, str], diagnostics: Sequence[str]
) -> dict[str, Any]:
    token = _machine.start_step(state, manifest, step["step_id"])
    _write_token(_token_path(state_path, step["step_id"], state["steps"][step["step_id"]]["attempt"]), token)
    applicability: Mapping[str, Any] | None
    applicability_errors: Sequence[str] | None = None
    try:
        applicability = _applicability.evaluate_probe(manifest, step["applicability_probe"], workspace)
    except _applicability.ApplicabilityError as exc:
        applicability = None
        applicability_errors = exc.diagnostics
    receipt, errors = _build_and_accept(
        state=state, manifest=manifest, workspace=workspace, state_path=state_path, step=step, token=token, applicability=applicability,
        status="failed", started_at=_timestamp(), finished_at=_timestamp(), exit_code=1, stdout=b"", stderr=b"", contracts=contracts,
        argv=step["execution_target"], selected_environment=selected_environment,
        extra_diagnostics=[*diagnostics, *(applicability_errors or [])],
        applicability_error_diagnostics=applicability_errors,
    )
    return {"receipt": receipt, "diagnostics": errors}


def run_step(*, manifest_path: str | Path, workspace: str | Path, step_id: str, state_path: str | Path | None = None) -> dict[str, Any]:
    """Execute exactly the current next step, or record a blocking failed receipt."""

    root = Path(workspace).expanduser().resolve()
    selected_state_path = Path(state_path).expanduser().resolve() if state_path else _default_state_path(root)
    template_manifest = _load_manifest(manifest_path)
    manifest = _execution_manifest(template_manifest, root)
    selected_environment = _execution_environment(template_manifest)
    baselines = current_baselines(root)
    baselines["pipeline_tooling_sha256"] = manifest["_pipeline_tooling_sha256"]
    state, initialized, recovery = _read_or_initialize_state(manifest, root, selected_state_path, baselines)
    try:
        contracts = _artifact_contracts(manifest, root)
    except ExecutorError as exc:
        expected = _next_step(manifest, state)
        if expected is None:
            return {
                "ok": False,
                "operation": "run-step",
                "diagnostics": list(exc.diagnostics),
                "state_path": str(selected_state_path),
                "step_id": step_id,
            }
        result = _fail_expected(state, manifest, root, selected_state_path, expected, {}, selected_environment, exc.diagnostics)
        return {"ok": False, "operation": "run-step", "diagnostics": sorted(set([*exc.diagnostics, *result["diagnostics"]])), "receipt_id": result["receipt"]["receipt_id"], "state_path": str(selected_state_path), "step_id": expected["step_id"], "initialized": initialized}
    stale_producers = _stale_output_producers(state, manifest, contracts, root)
    if stale_producers:
        producer_id, contract_id = stale_producers[0]
        _machine.invalidate_step(state, manifest, producer_id, reason=f"credited_output_changed:{contract_id}")
        _machine.write_state(selected_state_path, state)
        rerun = run_step(manifest_path=manifest_path, workspace=root, state_path=selected_state_path, step_id=producer_id)
        rerun["diagnostics"] = sorted(set([f"credited_output_invalidated:{producer_id}:{contract_id}", *rerun["diagnostics"]]))
        rerun["invalidated_producer"] = producer_id
        return rerun
    expected = _next_step(manifest, state)
    if expected is None:
        closeout = _machine.closeout(state, manifest)
        return {"ok": closeout["valid"], "operation": "run-step", "diagnostics": closeout["diagnostics"], "state_path": str(selected_state_path), "step_id": step_id}
    entry = state["steps"][expected["step_id"]]
    if entry["state"] == "running":
        token_file = _token_path(selected_state_path, expected["step_id"], entry["attempt"])
        try:
            token = token_file.read_text(encoding="ascii").strip()
        except OSError:
            return {"ok": False, "operation": "run-step", "diagnostics": ["interrupted_running_step_token_missing"], "state_path": str(selected_state_path), "step_id": expected["step_id"]}
        if _receipt.stable_hash(token) != entry["active_token_sha256"]:
            return {"ok": False, "operation": "run-step", "diagnostics": ["interrupted_running_step_token_mismatch"], "state_path": str(selected_state_path), "step_id": expected["step_id"]}
        try:
            applicability = _applicability.evaluate_probe(manifest, expected["applicability_probe"], root)
        except _applicability.ApplicabilityError as exc:
            receipt, errors = _build_and_accept(
                state=state, manifest=manifest, workspace=root, state_path=selected_state_path, step=expected, token=token,
                applicability=None, status="failed", started_at=_timestamp(), finished_at=_timestamp(), exit_code=1,
                stdout=b"", stderr=b"", contracts=contracts, argv=expected["execution_target"], selected_environment=selected_environment,
                extra_diagnostics=["applicability_probe_error", *exc.diagnostics], applicability_error_diagnostics=exc.diagnostics,
            )
            return {"ok": False, "operation": "run-step", "diagnostics": errors, "receipt_id": receipt["receipt_id"], "state_path": str(selected_state_path), "step_id": expected["step_id"], "status": receipt["status"]}
        receipt, errors = _build_and_accept(
            state=state, manifest=manifest, workspace=root, state_path=selected_state_path, step=expected, token=token, applicability=applicability,
            status="failed", started_at=_timestamp(), finished_at=_timestamp(), exit_code=1, stdout=b"", stderr=b"", contracts=contracts,
            argv=expected["execution_target"], selected_environment=selected_environment,
            extra_diagnostics=["interrupted_running_step", *recovery["diagnostics"]],
        )
        return {"ok": False, "operation": "run-step", "diagnostics": errors, "receipt_id": receipt["receipt_id"], "state_path": str(selected_state_path), "step_id": expected["step_id"], "status": receipt["status"], "initialized": initialized}
    blocking: list[str] = []
    requested_step_id = expected["step_id"] if recovery["rotated"] else step_id
    if requested_step_id != expected["step_id"]:
        blocking.append(f"out_of_order_request:expected={expected['step_id']}:requested={requested_step_id}")
    if blocking:
        result = _fail_expected(state, manifest, root, selected_state_path, expected, contracts, selected_environment, blocking)
        return {"ok": False, "operation": "run-step", "diagnostics": sorted(set(blocking + result["diagnostics"])), "receipt_id": result["receipt"]["receipt_id"], "state_path": str(selected_state_path), "step_id": expected["step_id"], "initialized": initialized}
    try:
        applicability = _applicability.evaluate_probe(manifest, expected["applicability_probe"], root)
    except _applicability.ApplicabilityError as exc:
        token = _machine.start_step(state, manifest, expected["step_id"])
        attempt = state["steps"][expected["step_id"]]["attempt"]
        _write_token(_token_path(selected_state_path, expected["step_id"], attempt), token)
        _machine.write_state(selected_state_path, state)
        receipt, errors = _build_and_accept(
            state=state, manifest=manifest, workspace=root, state_path=selected_state_path, step=expected, token=token,
            applicability=None, status="failed", started_at=_timestamp(), finished_at=_timestamp(), exit_code=1,
            stdout=b"", stderr=b"", contracts=contracts, argv=expected["execution_target"], selected_environment=selected_environment,
            extra_diagnostics=["applicability_probe_error", *exc.diagnostics], applicability_error_diagnostics=exc.diagnostics,
        )
        return {"ok": False, "operation": "run-step", "diagnostics": errors, "receipt_id": receipt["receipt_id"], "state_path": str(selected_state_path), "step_id": expected["step_id"], "status": receipt["status"], "initialized": initialized}
    token = _machine.start_step(state, manifest, expected["step_id"])
    attempt = state["steps"][expected["step_id"]]["attempt"]
    token_path = _token_path(selected_state_path, expected["step_id"], attempt)
    _write_token(token_path, token)
    _machine.write_state(selected_state_path, state)
    output_snapshots = _archive_attempt_outputs(selected_state_path, expected, attempt, contracts) if applicability["result"] else {}
    started_at = _timestamp()
    stdout = b""
    stderr = b""
    exit_code = 1
    errors: list[str] = []
    if applicability["result"]:
        try:
            argv = expected["execution_target"]
            completed = subprocess.run(argv, cwd=REPO_ROOT, env=dict(selected_environment), capture_output=True, check=False)
            stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
            if exit_code != 0:
                errors.append(f"command_exit_nonzero:{exit_code}")
            if NONTERMINAL_OUTPUT_RE.search(stdout.decode("utf-8", errors="replace")) or NONTERMINAL_OUTPUT_RE.search(stderr.decode("utf-8", errors="replace")):
                errors.append("command_emitted_nonterminal_warning_or_advisory")
        except (OSError, ExecutorError) as exc:
            errors.append("command_execution_error")
            stderr = (str(exc) + "\n").encode("utf-8", errors="replace")
            exit_code = 127
        if not errors:
            errors.extend(_output_freshness_errors(expected, contracts, output_snapshots))
    receipt, receipt_errors = _build_and_accept(
        state=state, manifest=manifest, workspace=root, state_path=selected_state_path, step=expected, token=token, applicability=applicability,
        status="failed" if errors else "succeeded", started_at=started_at, finished_at=_timestamp(), exit_code=exit_code,
        stdout=stdout, stderr=stderr, contracts=contracts, argv=expected["execution_target"], selected_environment=selected_environment, extra_diagnostics=errors,
    )
    ok = receipt["status"] in {"succeeded", "not_applicable"}
    result = {
        "ok": ok,
        "operation": "run-step",
        "diagnostics": sorted(set([*recovery["diagnostics"], *receipt_errors])),
        "receipt_id": receipt["receipt_id"],
        "state_path": str(selected_state_path),
        "step_id": expected["step_id"],
        "status": receipt["status"],
        "initialized": initialized,
        "rotated": recovery["rotated"],
    }
    if recovery["archive_path"] is not None:
        result["archive_path"] = recovery["archive_path"]
    return result


def run_all(*, manifest_path: str | Path, workspace: str | Path, state_path: str | Path | None = None) -> dict[str, Any]:
    """Resume deterministically and stop at the first non-successful receipt."""

    completed: list[str] = []
    recovery_diagnostics: list[str] = []
    archives: list[str] = []
    while True:
        root = Path(workspace).expanduser().resolve()
        manifest = _execution_manifest(_load_manifest(manifest_path), root)
        path = Path(state_path).expanduser().resolve() if state_path else _default_state_path(root)
        baselines = current_baselines(root)
        baselines["pipeline_tooling_sha256"] = manifest["_pipeline_tooling_sha256"]
        state, _, recovery = _read_or_initialize_state(manifest, root, path, baselines)
        recovery_diagnostics.extend(recovery["diagnostics"])
        if recovery["archive_path"] is not None:
            archives.append(recovery["archive_path"])
        next_step = _next_step(manifest, state)
        if next_step is None:
            closeout = _machine.closeout(state, manifest)
            return {"ok": closeout["valid"], "operation": "run-all", "diagnostics": sorted(set([*recovery_diagnostics, *closeout["diagnostics"]])), "completed_steps": completed, "state_path": str(path), "closeout": closeout, "archives": archives}
        result = run_step(manifest_path=manifest_path, workspace=root, state_path=path, step_id=next_step["step_id"])
        completed.append(result["step_id"])
        if not result["ok"]:
            return {"ok": False, "operation": "run-all", "diagnostics": sorted(set([*recovery_diagnostics, *result["diagnostics"]])), "completed_steps": completed, "state_path": str(path), "failed_step_id": result["step_id"], "archives": archives}


def main(argv: Sequence[str] | None = None) -> int:
    parser = JsonArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--state", type=Path)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    run_step_parser = subparsers.add_parser("run-step")
    run_step_parser.add_argument("--step-id", required=True)
    subparsers.add_parser("run-all")
    try:
        args = parser.parse_args(argv)
        result = run_step(manifest_path=args.manifest, workspace=args.workspace, state_path=args.state, step_id=args.step_id) if args.operation == "run-step" else run_all(manifest_path=args.manifest, workspace=args.workspace, state_path=args.state)
        _json(result)
        return 0 if result["ok"] else 1
    except ExecutorError as exc:
        _json({"ok": False, "operation": getattr(locals().get("args"), "operation", None), "diagnostics": list(exc.diagnostics)})
        return 1
    except Exception as exc:  # Fail closed while keeping the CLI diagnostics JSON-only.
        _json({"ok": False, "operation": getattr(locals().get("args"), "operation", None), "diagnostics": ["executor_internal_error", type(exc).__name__]})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
