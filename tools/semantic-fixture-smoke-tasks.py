#!/usr/bin/env python3
"""Build fixture smoke task manifests and ingest detector smoke results.

This is the execution handoff between semantic scanner inventory rows and the
semantic fixture smoke gate. It does not run arbitrary shell commands and it
does not promote findings. It gives detector owners a bounded task manifest and
can normalize externally produced smoke JSON into the paths that
semantic-fixture-smoke-gate already checks.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.semantic_fixture_smoke_tasks.v1"
ADVISORY_POSTURE = {
    "coverage_claim": "none_fixture_smoke_task_manifest_only",
    "advisory_only": True,
    "promotion_allowed": False,
    "severity": "none",
    "selected_impact": "",
    "submission_posture": "NOT_SUBMIT_READY",
    "impact_contract_required": True,
}
SMOKE_REQUIRED_TYPES = {
    "detector_rewrite_with_fixture_pair",
    "fixture_pair_before_detector_rewrite",
}
PASS_STATUSES = {
    "pass",
    "passed",
    "ok",
    "success",
    "clean",
    "smoke_pass",
    "passed_vulnerable_clean_smoke",
}
MATERIALIZATION_SCHEMA_VERSION = "auditooor.semantic_fixture_materialization.v1"
FIXTURE_CORPUS_DIRS = (
    Path("detectors/test_fixtures"),
    Path("detectors/wave14_broken"),
)
DEPENDENCY_CANNOT_RUN_STATE = "terminal_cannot_run_dependency_preflight"
EXTRACTION_FAILED_STATE = "terminal_extraction_failed"
PROOF_OF_LIFE_SCRIPTS = (
    Path("detectors/python_wave1/test_fixtures/test_detectors.sh"),
    Path("detectors/go_wave1/test_fixtures/test_detectors.sh"),
)
_PROOF_OF_LIFE_CACHE: dict[str, list[str]] = {}
_SLITHER_PYTHON_CACHE: str | None = None
_DETECTOR_ARGUMENT_CACHE: dict[str, set[str]] = {}


def _load_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[semantic-fixture-smoke-tasks] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[semantic-fixture-smoke-tasks] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-fixture-smoke-tasks] expected object JSON for {label}: {path}")
    return payload


def _resolve_workspace_path(workspace: Path, raw: Any) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path)
    return str((workspace / path).resolve())


def _relativize(workspace: Path, path: str) -> str:
    if not path:
        return ""
    try:
        return str(Path(path).resolve().relative_to(workspace))
    except ValueError:
        return path


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _first_int(payload: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        if key not in payload:
            continue
        try:
            return int(payload.get(key) or 0)
        except (TypeError, ValueError):
            return None
    return None


def _nested_hit(payload: dict[str, Any], fixture_key: str) -> int | None:
    row = payload.get(fixture_key)
    if not isinstance(row, dict):
        return None
    return _first_int(row, ("hits", "hit_count", "match_count", "matches", "findings"))


def _smoke_hits(payload: dict[str, Any]) -> tuple[int | None, int | None]:
    positive = _first_int(payload, ("positive_hits", "vulnerable_hits", "vuln_hits", "positive_match_count"))
    clean = _first_int(payload, ("clean_hits", "negative_hits", "clean_match_count"))
    if positive is not None or clean is not None:
        return positive, clean

    for key in ("fixtures", "results"):
        rows = payload.get(key)
        if not isinstance(rows, dict):
            continue
        positive = _nested_hit(rows, "positive")
        if positive is None:
            positive = _nested_hit(rows, "vulnerable")
        clean = _nested_hit(rows, "clean")
        if clean is None:
            clean = _nested_hit(rows, "negative")
        if positive is not None or clean is not None:
            return positive, clean
    return None, None


def _status_ok(payload: dict[str, Any]) -> bool:
    status = str(payload.get("status") or payload.get("result") or "").strip().lower()
    return not status or status in PASS_STATUSES


def _smoke_command(payload: dict[str, Any]) -> str:
    command = str(payload.get("command") or payload.get("smoke_command") or "").strip()
    if command:
        return command
    positive_command = str(payload.get("positive_command") or "").strip()
    clean_command = str(payload.get("clean_command") or "").strip()
    if positive_command or clean_command:
        return " ; ".join(part for part in (positive_command, clean_command) if part)
    return ""


def _fixture_manifest_path(smoke_path: str) -> str:
    if not smoke_path:
        return ""
    path = Path(smoke_path)
    if path.name.endswith("_smoke.json"):
        return str(path.with_name(path.name.replace("_smoke.json", "_manifest.json")))
    return str(path.with_name(f"{path.stem}_manifest.json"))


def _read_fixture_manifest(path: str) -> tuple[bool, dict[str, Any]]:
    if not path:
        return False, {}
    manifest_path = Path(path)
    if not manifest_path.is_file():
        return False, {}
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, {}
    if not isinstance(payload, dict):
        return False, {}
    status = str(payload.get("materialization_status") or "")
    has_command = bool(payload.get("shell_command") or payload.get("argv"))
    has_import = bool(payload.get("imported_existing_fixture_pair") or payload.get("existing_fixture_pair"))
    terminal = status in {
        "exact_extraction_command_ready",
        "existing_fixture_pair_manifested",
        "imported_existing_fixture_pair",
    } or has_command or has_import
    return terminal, payload


def _read_extraction_failure(fixture_manifest_path: str) -> dict[str, Any]:
    if not fixture_manifest_path:
        return {}
    failure_path = Path(fixture_manifest_path).with_name("extraction_failure.json")
    if not failure_path.is_file():
        return {}
    try:
        payload = json.loads(failure_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "path": str(failure_path),
            "reason": "unreadable_extraction_failure",
            "detail": "extraction_failure.json exists but could not be parsed",
        }
    if not isinstance(payload, dict):
        return {
            "path": str(failure_path),
            "reason": "invalid_extraction_failure",
            "detail": "extraction_failure.json is not an object",
        }
    payload["path"] = str(failure_path)
    return payload


def _consent_granted() -> bool:
    return (
        os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1"
        or os.environ.get("ADVERSARIAL_LIVE_CONSENT") == "1"
        or bool(os.environ.get("AUDITOOOR_P1_FIXTURE_MOCK_DISPATCHER"))
    )


def _python_candidates() -> list[str]:
    candidates: list[str] = []
    env_python = os.environ.get("AUDITOOOR_PYTHON_SLITHER")
    if env_python:
        candidates.append(env_python)
    candidates.append(sys.executable)
    for name in ("python3", "python3.14", "python3.13", "python3.12", "python3.11"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def _python_imports_module(python_bin: str, module: str) -> bool:
    try:
        proc = subprocess.run(
            [
                python_bin,
                "-c",
                f"import importlib.util; raise SystemExit(0 if importlib.util.find_spec({module!r}) else 1)",
            ],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _slither_python() -> str:
    global _SLITHER_PYTHON_CACHE
    if _SLITHER_PYTHON_CACHE is not None:
        return _SLITHER_PYTHON_CACHE
    for python_bin in _python_candidates():
        if _python_imports_module(python_bin, "slither"):
            _SLITHER_PYTHON_CACHE = python_bin
            return _SLITHER_PYTHON_CACHE
    _SLITHER_PYTHON_CACHE = ""
    return _SLITHER_PYTHON_CACHE


def _slither_available() -> bool:
    return bool(_slither_python())


def _proof_of_life_failures(workspace: Path) -> list[str]:
    cache_key = str(workspace)
    if cache_key in _PROOF_OF_LIFE_CACHE:
        return _PROOF_OF_LIFE_CACHE[cache_key]
    failures: list[str] = []
    for rel in PROOF_OF_LIFE_SCRIPTS:
        script = workspace / rel
        if not script.is_file():
            continue
        proc = subprocess.run(
            ["bash", str(script)],
            cwd=str(workspace),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=30,
        )
        if proc.returncode != 0:
            failures.append(f"{rel}: rc={proc.returncode}: {proc.stdout[-500:].strip()}")
    _PROOF_OF_LIFE_CACHE[cache_key] = failures
    return failures


def _arg_value(parts: list[str], name: str) -> str:
    prefix = f"{name}="
    for idx, part in enumerate(parts):
        if part == name and idx + 1 < len(parts):
            return parts[idx + 1]
        if part.startswith(prefix):
            return part.split("=", 1)[1]
    return ""


def _slug_to_argument(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _slug_to_python_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _path_binding_candidates(workspace: Path, raw_path: str) -> set[str]:
    value = str(raw_path or "").strip()
    if not value:
        return set()
    path = Path(value).expanduser()
    candidates = {value.replace("\\", "/"), path.name, path.stem}
    if path.parent.name:
        candidates.add(path.parent.name)
    try:
        resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
        candidates.add(str(resolved).replace("\\", "/"))
        try:
            candidates.add(str(resolved.relative_to(workspace)).replace("\\", "/"))
        except ValueError:
            pass
    except (OSError, RuntimeError):
        pass
    return {candidate for candidate in candidates if candidate}


def _command_mentions_any(command: str, candidates: set[str]) -> bool:
    if not command or not candidates:
        return False
    raw_command = command.replace("\\", "/").lower()
    slug_command = _slug_to_argument(command)
    ident_command = _slug_to_python_identifier(command)
    for candidate in candidates:
        value = str(candidate or "").strip()
        if not value:
            continue
        raw_value = value.replace("\\", "/").lower()
        slug_value = _slug_to_argument(value)
        ident_value = _slug_to_python_identifier(value)
        if raw_value and raw_value in raw_command:
            return True
        if slug_value and slug_value in slug_command:
            return True
        if ident_value and ident_value in ident_command:
            return True
    return False


def _row_command_binding_candidates(workspace: Path, row: dict[str, Any]) -> set[str]:
    fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
    candidates: set[str] = set()
    for value in (
        row.get("suggested_detector_slug"),
        row.get("detector_slug"),
        row.get("candidate_detector_family"),
        fixture_task.get("detector_slug"),
    ):
        text = str(value or "").strip()
        if text:
            candidates.add(text)
            candidates.add(_slug_to_argument(text))
            candidates.add(_slug_to_python_identifier(text))
    for key in ("positive_fixture_path", "clean_fixture_path"):
        candidates.update(_path_binding_candidates(workspace, str(fixture_task.get(key) or "")))
    return {candidate for candidate in candidates if candidate}


def _record_command_binds_to_row(workspace: Path, row: dict[str, Any], payload: dict[str, Any]) -> bool:
    return _command_mentions_any(_smoke_command(payload), _row_command_binding_candidates(workspace, row))


def _pattern_name_from_source(source_component: str) -> str:
    name = Path(source_component).name
    return name[:-5] if name.endswith(".yaml") else Path(source_component).stem


def _infer_detector_argument(fixture_manifest: dict[str, Any]) -> dict[str, Any]:
    parts = [str(part) for part in (fixture_manifest.get("argv") or [])]
    if not parts and fixture_manifest.get("shell_command"):
        try:
            parts = shlex.split(str(fixture_manifest.get("shell_command") or ""))
        except ValueError:
            parts = []
    pattern = _arg_value(parts, "--pattern")
    if pattern:
        return {"argument": pattern, "source": "manifest_argv_pattern", "confidence": "high"}
    source_pattern_path = str(fixture_manifest.get("source_pattern_path") or "")
    if source_pattern_path:
        return {
            "argument": _pattern_name_from_source(source_pattern_path),
            "source": "manifest_source_pattern_path",
            "confidence": "high",
        }
    source_component = str(fixture_manifest.get("source_component") or "")
    if source_component:
        return {
            "argument": _pattern_name_from_source(source_component),
            "source": "manifest_source_component",
            "confidence": "medium",
        }
    detector_slug = str(fixture_manifest.get("detector_slug") or "")
    if detector_slug:
        return {
            "argument": _slug_to_argument(detector_slug),
            "source": "manifest_detector_slug",
            "confidence": "medium",
        }
    return {"argument": "", "source": "unavailable", "confidence": "none"}


def _detector_arguments(workspace: Path) -> set[str]:
    cache_key = str(workspace)
    if cache_key in _DETECTOR_ARGUMENT_CACHE:
        return _DETECTOR_ARGUMENT_CACHE[cache_key]
    detectors_dir = workspace / "detectors"
    if not detectors_dir.is_dir():
        _DETECTOR_ARGUMENT_CACHE[cache_key] = set()
        return _DETECTOR_ARGUMENT_CACHE[cache_key]
    arguments: set[str] = set()
    for py_file in sorted(detectors_dir.glob("*.py")) + sorted(detectors_dir.glob("wave*/*.py")):
        if py_file.name.startswith("_") or py_file.name == "run_custom.py":
            continue
        try:
            text = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        arguments.update(re.findall(r"\bARGUMENT\s*=\s*['\"]([^'\"]+)['\"]", text))
    _DETECTOR_ARGUMENT_CACHE[cache_key] = arguments
    return arguments


def _detector_argument_available(workspace: Path, argument: str) -> bool:
    if not argument:
        return True
    return argument in _detector_arguments(workspace)


def _detector_availability_preflight(workspace: Path, fixture_manifest: dict[str, Any]) -> dict[str, Any]:
    parts = [str(part) for part in (fixture_manifest.get("argv") or [])]
    if not parts and fixture_manifest.get("shell_command"):
        try:
            parts = shlex.split(str(fixture_manifest.get("shell_command") or ""))
        except ValueError:
            parts = []
    command = " ".join(parts) + " " + str(fixture_manifest.get("shell_command") or "")
    if "p1-fixture-extractor.py" not in command:
        return {"ok": True, "argument": "", "inference": {}, "blocker": ""}
    runner = _arg_value(parts, "--runner")
    uses_default_runner = not runner or Path(runner).name == "run_custom.py"
    if not uses_default_runner:
        return {"ok": True, "argument": "", "inference": {}, "blocker": ""}
    inference = _infer_detector_argument(fixture_manifest)
    argument = str(inference.get("argument") or "")
    if not _detector_argument_available(workspace, argument):
        detail = argument or "<missing --pattern>"
        source = str(inference.get("source") or "unavailable")
        return {
            "ok": False,
            "argument": argument,
            "inference": inference,
            "blocker": f"cannot-run: detector argument inferred from {source} but unavailable for smoke-fire: {detail}",
        }
    return {"ok": True, "argument": argument, "inference": inference, "blocker": ""}


def _detector_availability_blocker(workspace: Path, fixture_manifest: dict[str, Any]) -> str:
    return str(_detector_availability_preflight(workspace, fixture_manifest).get("blocker") or "")


def _dependency_preflight(workspace: Path, fixture_manifest: dict[str, Any]) -> dict[str, Any]:
    if not fixture_manifest:
        return {"ok": True, "blocker_categories": [], "blockers": []}
    command = " ".join(str(part) for part in fixture_manifest.get("argv") or [])
    command += " " + str(fixture_manifest.get("shell_command") or "")
    if "p1-fixture-extractor.py" not in command:
        return {"ok": True, "blocker_categories": [], "blockers": []}

    categories: list[str] = []
    blockers: list[str] = []
    if "--mock-dispatcher" not in command and not _consent_granted():
        categories.append("missing_llm_network_consent")
        blockers.append(
            "cannot-run: missing AUDITOOOR_LLM_NETWORK_CONSENT=1 for live fixture extraction"
        )
    uses_default_runner = "--runner" not in command or "run_custom.py" in command
    if uses_default_runner and not _slither_available():
        categories.append("missing_slither_analyzer")
        blockers.append("cannot-run: slither-analyzer import is unavailable; no auto-install attempted")
    detector_preflight = _detector_availability_preflight(workspace, fixture_manifest)
    if detector_preflight["blocker"]:
        categories.append("missing_detector_argument")
        blockers.append(str(detector_preflight["blocker"]))
    proof_failures = _proof_of_life_failures(workspace)
    if proof_failures:
        categories.append("proof_of_life_detector_failure")
        blockers.extend(f"cannot-run: proof_of_life detector preflight failed: {item}" for item in proof_failures)
    return {
        "ok": not blockers,
        "blocker_categories": categories,
        "blockers": blockers,
        "slither_python": _slither_python(),
        "detector_argument_inference": detector_preflight,
    }


def _existing_fixture_pair(workspace: Path, detector_slug: str) -> dict[str, str]:
    names = {
        detector_slug,
        detector_slug.replace("_", "-"),
        detector_slug.replace("-", "_"),
    }
    for corpus_dir in FIXTURE_CORPUS_DIRS:
        root = workspace / corpus_dir
        if not root.is_dir():
            continue
        files = list(root.iterdir())
        for name in names:
            positive = [
                path for path in files
                if path.is_file()
                and path.stem in {f"{name}_vulnerable", f"{name}_vuln", f"{name}_positive"}
            ]
            clean = [
                path for path in files
                if path.is_file()
                and path.stem in {f"{name}_clean", f"{name}_negative"}
            ]
            if positive and clean:
                return {
                    "positive": str(positive[0].resolve()),
                    "clean": str(clean[0].resolve()),
                    "corpus_dir": str(root.resolve()),
                }
    return {}


def _materialization_manifest(workspace: Path, row: dict[str, Any]) -> dict[str, Any]:
    fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
    detector_slug = str(row.get("suggested_detector_slug") or row.get("candidate_detector_family") or "semantic_detector")
    source_component = str(row.get("source_component") or "")
    pattern = _pattern_name_from_source(source_component)
    source_path = Path(source_component)
    if not source_path.is_absolute():
        source_path = workspace / source_path
    dsl_dir = source_path.parent if source_path.name.endswith(".yaml") else workspace
    target_fixture_dir = Path(_resolve_workspace_path(workspace, Path(str(fixture_task.get("positive_fixture_path") or "")).parent))
    existing_pair = _existing_fixture_pair(workspace, detector_slug)
    argv = [
        "python3",
        "tools/p1-fixture-extractor.py",
        "--pattern",
        pattern,
        "--workspace",
        str(workspace),
        "--source-file",
        str(source_path),
        "--dsl-dir",
        str(dsl_dir),
        "--fixture-dir",
        str(target_fixture_dir),
        "--strict-smoke-fire",
        "--smoke-tier",
        "ALL",
    ]
    status = "existing_fixture_pair_manifested" if existing_pair else "exact_extraction_command_ready"
    return {
        "schema": MATERIALIZATION_SCHEMA_VERSION,
        "queue_id": row.get("queue_id", ""),
        "inventory_id": row.get("inventory_id", ""),
        "fixture_id": fixture_task.get("fixture_id", ""),
        "detector_slug": detector_slug,
        "source_component": source_component,
        "source_pattern_path": str(source_path),
        "positive_fixture_path": _resolve_workspace_path(workspace, fixture_task.get("positive_fixture_path")),
        "clean_fixture_path": _resolve_workspace_path(workspace, fixture_task.get("clean_fixture_path")),
        "smoke_record_path": _resolve_workspace_path(workspace, fixture_task.get("smoke_record_path")),
        "materialization_status": status,
        "existing_fixture_pair": existing_pair,
        "imported_existing_fixture_pair": False,
        "argv": argv,
        "shell_command": " ".join(shlex.quote(part) for part in argv),
        "terminal_fixture_evidence": True,
        "evidence_class": "fixture_manifest_or_exact_extraction_command_only",
        "operator_note": "Run the extraction command and require vulnerable>=1, clean==0 smoke before promotion.",
        **ADVISORY_POSTURE,
    }


def _maybe_materialize_fixture_manifest(workspace: Path, row: dict[str, Any], smoke_path: str, *, enabled: bool) -> str:
    manifest_path = _fixture_manifest_path(smoke_path)
    if not enabled or not manifest_path:
        return manifest_path
    path = Path(manifest_path)
    if path.is_file():
        return manifest_path
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _materialization_manifest(workspace, row)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def _assess_smoke_payload(payload: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
    blockers: list[str] = []
    positive_hits, clean_hits = _smoke_hits(payload)
    if positive_hits is None:
        blockers.append("positive/vulnerable hit count missing")
    elif positive_hits < 1:
        blockers.append("positive/vulnerable fixture produced zero hits")
    if clean_hits is None:
        blockers.append("clean hit count missing")
    elif clean_hits != 0:
        blockers.append("clean fixture produced detector hits")
    if not _status_ok(payload):
        blockers.append("smoke record status is not pass/ok/success")
    command = _smoke_command(payload)
    if not command:
        blockers.append("smoke command missing")
    return not blockers, blockers, {
        "positive_hits": positive_hits,
        "clean_hits": clean_hits,
        "status": payload.get("status", payload.get("result", "")),
        "command": command,
    }


def _read_smoke_file(
    path: str,
    *,
    workspace: Path | None = None,
    row: dict[str, Any] | None = None,
) -> tuple[bool, list[str], dict[str, Any], dict[str, Any]]:
    if not path:
        return False, ["smoke record path missing"], {}, {}
    smoke_path = Path(path)
    if not smoke_path.is_file():
        return False, [f"smoke record missing: {path}"], {}, {}
    try:
        payload = json.loads(smoke_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"smoke record unreadable: {exc}"], {}, {}
    if not isinstance(payload, dict):
        return False, ["smoke record is not object JSON"], {}, {}
    ok, blockers, summary = _assess_smoke_payload(payload)
    if workspace is not None and row is not None and _smoke_command(payload):
        if not _record_command_binds_to_row(workspace, row, payload):
            blockers.append("smoke command does not bind to queued detector or fixtures")
            ok = False
    return ok, blockers, summary, payload


def _iter_smoke_results(paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw in paths:
        path = raw.expanduser().resolve()
        candidates = sorted(path.rglob("*.json")) if path.is_dir() else [path]
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                records.append({"path": str(candidate), "payload": payload})
    return records


def _match_tokens(row: dict[str, Any]) -> set[str]:
    fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
    tokens = {
        str(row.get("queue_id") or ""),
        str(row.get("inventory_id") or ""),
        str(row.get("suggested_detector_slug") or ""),
        str(row.get("candidate_detector_family") or ""),
        str(fixture_task.get("fixture_id") or ""),
    }
    for key in ("positive_fixture_path", "clean_fixture_path", "smoke_record_path"):
        value = str(fixture_task.get(key) or "")
        if value:
            tokens.add(value)
            tokens.add(Path(value).name)
            tokens.add(Path(value).stem)
    return {_slug(token) for token in tokens if _slug(token)}


def _record_tokens(record: dict[str, Any]) -> set[str]:
    payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
    tokens = {str(record.get("path") or ""), Path(str(record.get("path") or "")).name}
    for key in (
        "queue_id",
        "inventory_id",
        "fixture_id",
        "detector_slug",
        "suggested_detector_slug",
        "candidate_detector_family",
        "positive_fixture_path",
        "clean_fixture_path",
        "smoke_record_path",
    ):
        value = str(payload.get(key) or "")
        if value:
            tokens.add(value)
            tokens.add(Path(value).name)
            tokens.add(Path(value).stem)
    return {_slug(token) for token in tokens if _slug(token)}


def _record_identity_conflicts(workspace: Path, row: dict[str, Any], payload: dict[str, Any]) -> list[str]:
    fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
    conflicts: list[str] = []

    for key, expected in (
        ("queue_id", row.get("queue_id")),
        ("inventory_id", row.get("inventory_id")),
        ("fixture_id", fixture_task.get("fixture_id")),
        ("candidate_detector_family", row.get("candidate_detector_family")),
        ("source_component", row.get("source_component")),
    ):
        observed = str(payload.get(key) or "").strip()
        expected_value = str(expected or "").strip()
        if observed and expected_value and observed != expected_value:
            conflicts.append(key)

    expected_slug = str(row.get("suggested_detector_slug") or "").strip()
    for key in ("detector_slug", "suggested_detector_slug"):
        observed = str(payload.get(key) or "").strip()
        if observed and expected_slug and observed != expected_slug:
            conflicts.append(key)

    for key in ("positive_fixture_path", "clean_fixture_path", "smoke_record_path"):
        observed = str(payload.get(key) or "").strip()
        expected = _resolve_workspace_path(workspace, fixture_task.get(key))
        if observed and expected and _resolve_workspace_path(workspace, observed) != expected:
            conflicts.append(key)

    for observed_key, expected_key in (
        ("positive_fixture", "positive_fixture_path"),
        ("vulnerable_fixture", "positive_fixture_path"),
        ("clean_fixture", "clean_fixture_path"),
        ("negative_fixture", "clean_fixture_path"),
    ):
        observed = str(payload.get(observed_key) or "").strip()
        expected = _resolve_workspace_path(workspace, fixture_task.get(expected_key))
        if observed and expected and _resolve_workspace_path(workspace, observed) != expected:
            conflicts.append(observed_key)

    return conflicts


def _record_identity_matches(workspace: Path, row: dict[str, Any], payload: dict[str, Any]) -> list[str]:
    fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
    matches: list[str] = []
    for key, expected in (
        ("queue_id", row.get("queue_id")),
        ("inventory_id", row.get("inventory_id")),
        ("fixture_id", fixture_task.get("fixture_id")),
    ):
        observed = str(payload.get(key) or "").strip()
        expected_value = str(expected or "").strip()
        if observed and expected_value and observed == expected_value:
            matches.append(key)
    for key in ("positive_fixture_path", "clean_fixture_path", "smoke_record_path"):
        observed = str(payload.get(key) or "").strip()
        expected = _resolve_workspace_path(workspace, fixture_task.get(key))
        if observed and expected and _resolve_workspace_path(workspace, observed) == expected:
            matches.append(key)
    for observed_key, expected_key in (
        ("positive_fixture", "positive_fixture_path"),
        ("vulnerable_fixture", "positive_fixture_path"),
        ("clean_fixture", "clean_fixture_path"),
        ("negative_fixture", "clean_fixture_path"),
    ):
        observed = str(payload.get(observed_key) or "").strip()
        expected = _resolve_workspace_path(workspace, fixture_task.get(expected_key))
        if observed and expected and _resolve_workspace_path(workspace, observed) == expected:
            matches.append(observed_key)
    return matches


def _best_ingest_match(workspace: Path, row: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any] | None:
    row_tokens = _match_tokens(row)
    best: tuple[int, dict[str, Any]] | None = None
    for record in records:
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        if _record_identity_conflicts(workspace, row, payload):
            continue
        identity_matches = _record_identity_matches(workspace, row, payload)
        if not identity_matches:
            continue
        if not _record_command_binds_to_row(workspace, row, payload):
            continue
        overlap = row_tokens.intersection(_record_tokens(record))
        score = len(overlap)
        if str(payload.get("queue_id") or "") == str(row.get("queue_id") or ""):
            score += 10
        if str(payload.get("inventory_id") or "") == str(row.get("inventory_id") or ""):
            score += 8
        fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
        if str(payload.get("fixture_id") or "") == str(fixture_task.get("fixture_id") or ""):
            score += 6
        if score and (best is None or score > best[0]):
            best = (score, record)
    return best[1] if best else None


def _normalize_smoke_record(row: dict[str, Any], source_path: str, payload: dict[str, Any]) -> dict[str, Any]:
    fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
    ok, blockers, summary = _assess_smoke_payload(payload)
    return {
        "schema": "auditooor.semantic_fixture_smoke_record.v1",
        "source_smoke_result": source_path,
        "queue_id": row.get("queue_id", ""),
        "inventory_id": row.get("inventory_id", ""),
        "fixture_id": fixture_task.get("fixture_id", ""),
        "detector_slug": row.get("suggested_detector_slug", ""),
        "status": "pass" if ok else "failed_ingested_smoke",
        "command": summary.get("command", ""),
        "positive_hits": summary.get("positive_hits"),
        "clean_hits": summary.get("clean_hits"),
        "ingestion_blockers": blockers,
        "raw_status": payload.get("status", payload.get("result", "")),
        **ADVISORY_POSTURE,
    }


def _gate_row_matches_task_row(
    workspace: Path,
    row: dict[str, Any],
    gate_row: dict[str, Any],
    *,
    positive_path: str,
    clean_path: str,
    smoke_path: str,
) -> bool:
    detector_slug = str(row.get("suggested_detector_slug") or "").strip()
    if not detector_slug or detector_slug != str(gate_row.get("suggested_detector_slug") or "").strip():
        return False
    for key in ("inventory_id", "source_component", "candidate_detector_family"):
        observed = str(gate_row.get(key) or "").strip()
        expected = str(row.get(key) or "").strip()
        if observed and expected and observed != expected:
            return False
    fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
    observed_fixture_id = str(gate_row.get("fixture_id") or gate_row.get("fixture_task_id") or "").strip()
    expected_fixture_id = str(fixture_task.get("fixture_id") or "").strip()
    if observed_fixture_id and expected_fixture_id and observed_fixture_id != expected_fixture_id:
        return False
    for key, current_path in (
        ("positive_fixture_path", positive_path),
        ("clean_fixture_path", clean_path),
        ("smoke_record_path", smoke_path),
    ):
        if not current_path:
            return False
        if _resolve_workspace_path(workspace, gate_row.get(key)) != current_path:
            return False
    if not smoke_path or not Path(smoke_path).is_file():
        return False
    return True


def _gate_index(gate: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("queue_id") or ""): row
        for row in (gate.get("rows") or [])
        if isinstance(row, dict) and str(row.get("queue_id") or "")
    }


def _task_row(
    workspace: Path,
    row: dict[str, Any],
    gate_rows: dict[str, dict[str, Any]],
    ingest_records: list[dict[str, Any]],
    *,
    write_ingested: bool,
    materialize_manifests: bool,
) -> dict[str, Any]:
    fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
    task_type = str(row.get("task_type") or "")
    smoke_required = task_type in SMOKE_REQUIRED_TYPES or bool(fixture_task)
    positive_path = _resolve_workspace_path(workspace, fixture_task.get("positive_fixture_path"))
    clean_path = _resolve_workspace_path(workspace, fixture_task.get("clean_fixture_path"))
    smoke_path = _resolve_workspace_path(workspace, fixture_task.get("smoke_record_path"))
    blockers: list[str] = []
    existing_smoke_summary: dict[str, Any] = {}
    ingested_smoke_summary: dict[str, Any] = {}
    ingested_record_path = ""
    fixture_manifest_path = _maybe_materialize_fixture_manifest(
        workspace,
        row,
        smoke_path,
        enabled=materialize_manifests and smoke_required,
    )
    fixture_manifest_terminal, fixture_manifest = _read_fixture_manifest(fixture_manifest_path)
    dependency_preflight = _dependency_preflight(workspace, fixture_manifest)
    extraction_failure = _read_extraction_failure(fixture_manifest_path)

    if not smoke_required:
        terminal_state = "not_applicable_source_review_or_coverage"
    elif extraction_failure:
        detail = str(extraction_failure.get("detail") or "").strip()
        if len(detail) > 500:
            detail = detail[:500].rstrip() + "..."
        blockers.append(
            "terminal extraction failed: "
            + str(extraction_failure.get("reason") or "extraction_failed")
            + (f": {detail}" if detail else "")
        )
        blockers.extend(dependency_preflight["blockers"])
        terminal_state = EXTRACTION_FAILED_STATE
    elif not dependency_preflight["ok"]:
        blockers.extend(dependency_preflight["blockers"])
        terminal_state = DEPENDENCY_CANNOT_RUN_STATE
    else:
        if not positive_path or not Path(positive_path).is_file():
            blockers.append("positive fixture missing")
        if not clean_path or not Path(clean_path).is_file():
            blockers.append("clean fixture missing")

        smoke_ok, smoke_blockers, existing_smoke_summary, _ = _read_smoke_file(
            smoke_path,
            workspace=workspace,
            row=row,
        )
        if not smoke_ok:
            matched = _best_ingest_match(workspace, row, ingest_records)
            if matched:
                source_path = str(matched.get("path") or "")
                payload = matched.get("payload") if isinstance(matched.get("payload"), dict) else {}
                normalized = _normalize_smoke_record(row, source_path, payload)
                ingest_ok = not normalized["ingestion_blockers"]
                ingested_smoke_summary = {
                    "source_smoke_result": source_path,
                    "positive_hits": normalized.get("positive_hits"),
                    "clean_hits": normalized.get("clean_hits"),
                    "status": normalized.get("status"),
                    "command": normalized.get("command"),
                    "ingestion_blockers": normalized.get("ingestion_blockers", []),
                }
                if smoke_path and write_ingested:
                    target = Path(smoke_path)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    ingested_record_path = smoke_path
                if ingest_ok:
                    smoke_ok = True
                    smoke_blockers = []
                    existing_smoke_summary = ingested_smoke_summary
                else:
                    smoke_blockers = list(normalized["ingestion_blockers"])

        if not smoke_ok:
            blockers.extend(smoke_blockers)
        if blockers:
            terminal_state = "blocked_missing_fixture_or_smoke"
        else:
            terminal_state = "terminal_clean_positive_fixture_smoke"

    gate_row = gate_rows.get(str(row.get("queue_id") or ""), {})
    gate_row_matches = _gate_row_matches_task_row(
        workspace,
        row,
        gate_row,
        positive_path=positive_path,
        clean_path=clean_path,
        smoke_path=smoke_path,
    )
    if (
        gate_row.get("status") == "fixture_smoke_passed"
        and gate_row_matches
        and terminal_state.startswith("blocked")
    ):
        terminal_state = "terminal_clean_positive_fixture_smoke"
        blockers = []

    return {
        "queue_id": row.get("queue_id", ""),
        "inventory_id": row.get("inventory_id", ""),
        "task_type": task_type,
        "source_component": row.get("source_component", ""),
        "candidate_detector_family": row.get("candidate_detector_family", ""),
        "suggested_detector_slug": row.get("suggested_detector_slug", ""),
        "smoke_required": smoke_required,
        "terminal_state": terminal_state,
        "positive_fixture_path": positive_path,
        "clean_fixture_path": clean_path,
        "smoke_record_path": smoke_path,
        "fixture_manifest_path": fixture_manifest_path,
        "relative_positive_fixture_path": _relativize(workspace, positive_path),
        "relative_clean_fixture_path": _relativize(workspace, clean_path),
        "relative_smoke_record_path": _relativize(workspace, smoke_path),
        "relative_fixture_manifest_path": _relativize(workspace, fixture_manifest_path),
        "fixture_manifest_terminal": fixture_manifest_terminal,
        "fixture_manifest_status": fixture_manifest.get("materialization_status", ""),
        "fixture_manifest_shell_command": fixture_manifest.get("shell_command", ""),
        "extraction_failure_path": extraction_failure.get("path", ""),
        "extraction_failure_reason": extraction_failure.get("reason", ""),
        "existing_fixture_pair": fixture_manifest.get("existing_fixture_pair", {}),
        "dependency_preflight": dependency_preflight,
        "cannot_run_reason": (
            ",".join(dependency_preflight["blocker_categories"])
            if terminal_state == DEPENDENCY_CANNOT_RUN_STATE else ""
        ),
        "existing_gate_status": gate_row.get("status", ""),
        "existing_smoke_summary": existing_smoke_summary,
        "ingested_smoke_summary": ingested_smoke_summary,
        "ingested_record_path": ingested_record_path,
        "blockers": blockers,
        "next_command": (
            "rerun semantic-fixture-smoke-gate to consume ingested terminal clean/positive smoke"
            if terminal_state == "terminal_clean_positive_fixture_smoke"
            else "repair generated fixtures or detector availability, then rerun extraction; require solc plus vulnerable>=1 and clean=0 smoke"
            if terminal_state == EXTRACTION_FAILED_STATE
            else "resolve dependency preflight blockers, then rerun the exact fixture extraction command"
            if terminal_state == DEPENDENCY_CANNOT_RUN_STATE
            else "create missing fixtures or ingest detector smoke JSON with positive_hits>=1 and clean_hits=0"
        ),
        **ADVISORY_POSTURE,
    }


def build_manifest(
    workspace: Path,
    inventory: dict[str, Any],
    gate: dict[str, Any],
    ingest_records: list[dict[str, Any]],
    *,
    limit: int,
    write_ingested: bool,
    materialize_manifests: bool,
) -> dict[str, Any]:
    queue = inventory.get("detector_fixture_task_queue")
    if not isinstance(queue, list):
        queue = []
    gate_rows = _gate_index(gate)
    rows = [
        _task_row(
            workspace,
            row,
            gate_rows,
            ingest_records,
            write_ingested=write_ingested,
            materialize_manifests=materialize_manifests,
        )
        for row in queue[: max(0, limit)]
        if isinstance(row, dict)
    ]
    terminal = [row for row in rows if row["terminal_state"] == "terminal_clean_positive_fixture_smoke"]
    smoke_required = [row for row in rows if row.get("smoke_required")]
    cannot_run = [row for row in smoke_required if row["terminal_state"] == DEPENDENCY_CANNOT_RUN_STATE]
    extraction_failed = [row for row in smoke_required if row["terminal_state"] == EXTRACTION_FAILED_STATE]
    blocked = [row for row in smoke_required if row["terminal_state"].startswith("blocked")]
    fixture_manifest_rows = [row for row in smoke_required if row.get("fixture_manifest_terminal")]
    extraction_command_rows = [row for row in fixture_manifest_rows if row.get("fixture_manifest_shell_command")]
    existing_pair_rows = [row for row in fixture_manifest_rows if row.get("existing_fixture_pair")]
    status_counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("terminal_state") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    precision_accounting = {
        "accounting_mode": "fixture_smoke_precision_accounting_only",
        "precision_claim": "not_computed_fixture_smoke_only",
        "processed_count": len(rows),
        "smoke_required_count": len(smoke_required),
        "terminal_clean_positive_count": len(terminal),
        "blocked_missing_fixture_or_smoke_count": len(blocked),
        "terminal_cannot_run_count": len(cannot_run),
        "terminal_extraction_failed_count": len(extraction_failed),
        "runnable_fixture_blocked_count": len(blocked),
        "not_applicable_count": sum(
            1 for row in rows if row.get("terminal_state") == "not_applicable_source_review_or_coverage"
        ),
        "ingested_record_count": sum(1 for row in rows if row.get("ingested_record_path")),
        "terminal_fixture_manifest_count": len(fixture_manifest_rows),
        "exact_extraction_command_count": len(extraction_command_rows),
        "existing_fixture_pair_manifest_count": len(existing_pair_rows),
        "promotion_allowed": False,
        "severity": "none",
    }
    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "limit": limit,
        "queue_item_count": len(queue),
        "processed_count": len(rows),
        "smoke_required_count": len(smoke_required),
        "terminal_clean_positive_count": len(terminal),
        "blocking_count": len(blocked),
        "terminal_cannot_run_count": len(cannot_run),
        "terminal_extraction_failed_count": len(extraction_failed),
        "runnable_fixture_blocked_count": len(blocked),
        "terminal_fixture_manifest_count": len(fixture_manifest_rows),
        "exact_extraction_command_count": len(extraction_command_rows),
        "existing_fixture_pair_manifest_count": len(existing_pair_rows),
        "ingest_source_count": len(ingest_records),
        "ingested_record_count": precision_accounting["ingested_record_count"],
        "status_counts": status_counts,
        "detector_precision_accounting": precision_accounting,
        "rows": rows,
        "next_actions": [
            "Run semantic-scanner-inventory first when the queue is empty or stale.",
            f"Use this manifest to assign up to {limit} detector fixture smoke tasks when the queue contains that many rows.",
            "Ingest detector smoke JSON, then rerun semantic-fixture-smoke-gate for terminal gate evidence.",
            "Keep exact impact proof, severity, and submission readiness in separate gates.",
        ],
        **ADVISORY_POSTURE,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Semantic Fixture Smoke Tasks",
        "",
        "Bounded detector fixture smoke execution handoff for semantic scanner inventory rows.",
        "Rows here are task/evidence accounting only; they do not prove impact or submission readiness.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- processed rows: {payload['processed_count']}",
        f"- smoke-required rows: {payload['smoke_required_count']}",
        f"- terminal clean/positive rows: {payload['terminal_clean_positive_count']}",
        f"- terminal fixture manifests/extraction commands: {payload['terminal_fixture_manifest_count']}",
        f"- blocking rows: {payload['blocking_count']}",
        f"- terminal cannot-run rows: {payload.get('terminal_cannot_run_count', 0)}",
        f"- terminal extraction-failed rows: {payload.get('terminal_extraction_failed_count', 0)}",
        f"- ingested smoke records: {payload['ingested_record_count']}",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Status Counts",
        "",
    ]
    for status, count in sorted((payload.get("status_counts") or {}).items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend([
        "",
        "## Rows",
        "",
        "| Queue | Type | Terminal State | Source | Detector | Fixture Manifest | Smoke Record | Blockers |",
        "|---|---|---|---|---|---|---|---|",
    ])
    for row in payload.get("rows", []):
        blockers = "; ".join(row.get("blockers") or [])
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} |".format(
            row.get("queue_id", ""),
            row.get("task_type", ""),
            row.get("terminal_state", ""),
            row.get("source_component", ""),
            row.get("suggested_detector_slug", ""),
            row.get("relative_fixture_manifest_path", ""),
            row.get("relative_smoke_record_path", ""),
            blockers or "_none_",
        ))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--gate", type=Path)
    parser.add_argument("--smoke-results", type=Path, action="append", default=[])
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--no-write-ingested", action="store_true", help="Only report matched smoke JSON; do not write normalized smoke records")
    parser.add_argument("--materialize-manifests", action="store_true", help="Write per-row fixture materialization manifests with exact extraction commands")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when any smoke-required row remains blocked")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[semantic-fixture-smoke-tasks] workspace not found: {workspace}", file=sys.stderr)
        return 2
    inventory_path = (args.inventory or workspace / ".auditooor" / "semantic_scanner_inventory.json").expanduser().resolve()
    gate_path = (args.gate or workspace / ".auditooor" / "semantic_fixture_smoke_gate.json").expanduser().resolve()
    inventory = _load_json(inventory_path, "semantic scanner inventory")
    gate = _load_json(gate_path, "semantic fixture smoke gate", required=False)
    ingest_records = _iter_smoke_results(args.smoke_results)
    payload = build_manifest(
        workspace,
        inventory,
        gate,
        ingest_records,
        limit=args.limit,
        write_ingested=not args.no_write_ingested,
        materialize_manifests=args.materialize_manifests,
    )
    payload["source_artifacts"] = {
        "semantic_scanner_inventory": str(inventory_path),
        "semantic_fixture_smoke_gate": str(gate_path) if gate_path.is_file() else "",
        "smoke_results": [str(path.expanduser().resolve()) for path in args.smoke_results],
    }

    out_json = args.out_json or workspace / ".auditooor" / "semantic_fixture_smoke_tasks.json"
    out_md = args.out_md or workspace / ".auditooor" / "semantic_fixture_smoke_tasks.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[semantic-fixture-smoke-tasks] OK processed={payload['processed_count']} "
        f"terminal={payload['terminal_clean_positive_count']} blocked={payload['blocking_count']} json={out_json}",
        file=sys.stderr,
    )
    return 1 if args.strict and (
        payload["blocking_count"]
        or payload["terminal_cannot_run_count"]
        or payload["terminal_extraction_failed_count"]
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
