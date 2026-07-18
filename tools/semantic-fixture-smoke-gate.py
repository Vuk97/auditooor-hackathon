#!/usr/bin/env python3
"""Gate semantic scanner fixture tasks on paired fixtures and smoke output.

The semantic scanner inventory is intentionally advisory: it queues detector
rewrite and fixture-first work, but it must not be treated as detector proof.
This tool consumes that queue and checks the mechanical promotion blocker:
detector/fixture rows need both vulnerable and clean fixtures plus a smoke
record showing vulnerable hits and clean silence.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import shutil
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.semantic_fixture_smoke_gate.v1"
ADVISORY_POSTURE = {
    "coverage_claim": "none_fixture_smoke_gate_only",
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
DEPENDENCY_CANNOT_RUN_STATUS = "terminal_cannot_run_dependency_preflight"
EXTRACTION_FAILED_STATUS = "terminal_extraction_failed"
PROOF_OF_LIFE_SCRIPTS = (
    Path("detectors/python_wave1/test_fixtures/test_detectors.sh"),
    Path("detectors/go_wave1/test_fixtures/test_detectors.sh"),
)
_PROOF_OF_LIFE_CACHE: dict[str, list[str]] = {}
_SLITHER_PYTHON_CACHE: str | None = None
_DETECTOR_ARGUMENT_CACHE: dict[str, set[str]] = {}


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"[semantic-fixture-smoke-gate] missing {label}: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[semantic-fixture-smoke-gate] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-fixture-smoke-gate] expected object JSON for {label}: {path}")
    return payload


def _resolve_workspace_path(workspace: Path, raw: Any) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path)
    return str((workspace / path).resolve())


def _first_int(payload: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        if key in payload:
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

    fixtures = payload.get("fixtures")
    if isinstance(fixtures, dict):
        positive = _nested_hit(fixtures, "positive")
        if positive is None:
            positive = _nested_hit(fixtures, "vulnerable")
        clean = _nested_hit(fixtures, "clean")
        if clean is None:
            clean = _nested_hit(fixtures, "negative")
        if positive is not None or clean is not None:
            return positive, clean

    results = payload.get("results")
    if isinstance(results, dict):
        positive = _nested_hit(results, "positive")
        if positive is None:
            positive = _nested_hit(results, "vulnerable")
        clean = _nested_hit(results, "clean")
        if clean is None:
            clean = _nested_hit(results, "negative")
    return positive, clean


def _smoke_status_ok(payload: dict[str, Any]) -> bool:
    status = str(payload.get("status") or payload.get("result") or "").strip().lower()
    if not status:
        return True
    return status in {
        "pass",
        "passed",
        "ok",
        "success",
        "clean",
        "smoke_pass",
        "passed_vulnerable_clean_smoke",
    }


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


def _assess_fixture_manifest(path: str) -> tuple[bool, dict[str, Any]]:
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
    return terminal, {
        "status": status,
        "shell_command": payload.get("shell_command", ""),
        "argv": payload.get("argv", []),
        "existing_fixture_pair": payload.get("existing_fixture_pair", {}),
        "imported_existing_fixture_pair": bool(payload.get("imported_existing_fixture_pair")),
        "evidence_class": payload.get("evidence_class", ""),
        "detector_slug": payload.get("detector_slug", ""),
        "source_component": payload.get("source_component", ""),
        "source_pattern_path": payload.get("source_pattern_path", ""),
    }


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


def _pattern_name_from_source(source_component: str) -> str:
    name = Path(source_component).name
    return name[:-5] if name.endswith(".yaml") else Path(source_component).stem


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


def _observed_fixture_refs(payload: dict[str, Any], *keys: str) -> list[str]:
    refs: list[str] = []
    for key in keys:
        value = str(payload.get(key) or "").strip()
        if value:
            refs.append(value)
    return refs


def _fixture_ref_matches_expected(workspace: Path, smoke_path: Path, raw_ref: str, expected_path: str) -> bool:
    if not raw_ref or not expected_path:
        return True
    expected = Path(expected_path).expanduser()
    try:
        expected_resolved = expected.resolve() if expected.is_absolute() else (workspace / expected).resolve()
    except (OSError, RuntimeError):
        expected_resolved = None
    raw = Path(raw_ref).expanduser()
    candidates = [raw] if raw.is_absolute() else [workspace / raw, smoke_path.parent / raw]
    if expected_resolved is not None:
        for candidate in candidates:
            try:
                if candidate.resolve() == expected_resolved:
                    return True
            except (OSError, RuntimeError):
                continue
    expected_text = expected_path.replace("\\", "/").strip().lower()
    observed_text = raw_ref.replace("\\", "/").strip().lower()
    return bool(expected_text and observed_text and observed_text == expected_text)


def _smoke_binding_expectations(
    workspace: Path,
    row: dict[str, Any],
    fixture_task: dict[str, Any],
    smoke_path: str,
    positive_path: str,
    clean_path: str,
) -> dict[str, Any]:
    slug_candidates: set[str] = set()
    for value in (
        row.get("suggested_detector_slug"),
        row.get("detector_slug"),
        fixture_task.get("detector_slug"),
    ):
        slug = _slug_to_python_identifier(str(value or ""))
        if slug:
            slug_candidates.add(slug)
    for path in (smoke_path, positive_path, clean_path):
        if path:
            parent_slug = _slug_to_python_identifier(Path(path).parent.name)
            if parent_slug:
                slug_candidates.add(parent_slug)

    pattern_candidates = {_slug_to_argument(slug) for slug in slug_candidates if slug}
    source_component = str(row.get("source_component") or "").strip()
    source_name = Path(source_component).name.lower()
    if source_name.endswith(".yaml") or source_name.endswith(".yml"):
        source_pattern = _slug_to_argument(_pattern_name_from_source(source_component))
        if source_pattern:
            pattern_candidates.add(source_pattern)

    detector_path_candidates: set[str] = set()
    for raw in (fixture_task.get("detector_path"), row.get("detector_path")):
        value = str(raw or "").strip()
        if not value:
            continue
        path = Path(value).expanduser()
        if path.is_absolute():
            detector_path_candidates.add(str(path))
        else:
            detector_path_candidates.add(str((workspace / path).resolve()))
            detector_path_candidates.add(value)

    positive_fixture_candidates = _path_binding_candidates(workspace, positive_path)
    clean_fixture_candidates = _path_binding_candidates(workspace, clean_path)
    command_binding_candidates = set(pattern_candidates)
    command_binding_candidates.update(slug_candidates)
    command_binding_candidates.update(positive_fixture_candidates)
    command_binding_candidates.update(clean_fixture_candidates)
    for detector_path in detector_path_candidates:
        command_binding_candidates.update(_path_binding_candidates(workspace, detector_path))

    return {
        "workspace": str(workspace),
        "positive_fixture_path": positive_path,
        "clean_fixture_path": clean_path,
        "pattern_candidates": sorted(pattern_candidates),
        "detector_slug_candidates": sorted(slug_candidates),
        "detector_path_candidates": sorted(detector_path_candidates),
        "positive_fixture_candidates": sorted(positive_fixture_candidates),
        "clean_fixture_candidates": sorted(clean_fixture_candidates),
        "command_binding_candidates": sorted(command_binding_candidates),
        "binding_required": bool(pattern_candidates or slug_candidates or detector_path_candidates),
    }


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


def _assess_smoke_record(path: str, expected_binding: dict[str, Any] | None = None) -> tuple[bool, list[str], dict[str, Any]]:
    blockers: list[str] = []
    expected_binding = expected_binding or {}
    if not path:
        return False, ["smoke record path missing"], {}
    smoke_path = Path(path)
    if not smoke_path.is_file():
        return False, [f"smoke record missing: {path}"], {}
    try:
        payload = json.loads(smoke_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"smoke record unreadable: {exc}"], {}
    if not isinstance(payload, dict):
        return False, ["smoke record is not object JSON"], {}

    positive_hits, clean_hits = _smoke_hits(payload)
    if positive_hits is None:
        blockers.append("positive/vulnerable hit count missing")
    elif positive_hits < 1:
        blockers.append("positive/vulnerable fixture produced zero hits")
    if clean_hits is None:
        blockers.append("clean hit count missing")
    elif clean_hits != 0:
        blockers.append("clean fixture produced detector hits")
    if not _smoke_status_ok(payload):
        blockers.append("smoke record status is not pass/ok/success")
    command = _smoke_command(payload)
    if not command:
        blockers.append("smoke command missing")

    workspace = Path(str(expected_binding.get("workspace") or ".")).expanduser()
    if command and expected_binding.get("command_binding_candidates"):
        command_candidates = {
            str(value)
            for value in expected_binding.get("command_binding_candidates") or []
            if str(value).strip()
        }
        if not _command_mentions_any(command, command_candidates):
            blockers.append("smoke command does not bind to queued detector or fixtures")

    for label, expected_path, keys in (
        (
            "positive",
            str(expected_binding.get("positive_fixture_path") or ""),
            (
                "positive_fixture",
                "positive_fixture_path",
                "vulnerable_fixture",
                "vulnerable_fixture_path",
            ),
        ),
        (
            "clean",
            str(expected_binding.get("clean_fixture_path") or ""),
            (
                "clean_fixture",
                "clean_fixture_path",
                "negative_fixture",
                "negative_fixture_path",
            ),
        ),
    ):
        for observed_fixture in _observed_fixture_refs(payload, *keys):
            if not _fixture_ref_matches_expected(workspace, smoke_path, observed_fixture, expected_path):
                blockers.append(
                    f"smoke {label} fixture conflicts with queued fixture: observed={observed_fixture}"
                )

    observed_pattern = str(payload.get("pattern") or payload.get("detector_pattern") or "").strip()
    observed_detector_slug = str(payload.get("detector_slug") or "").strip()
    observed_detector_path = str(payload.get("detector_path") or "").strip()
    expected_patterns = {
        _slug_to_argument(str(value))
        for value in expected_binding.get("pattern_candidates") or []
        if str(value).strip()
    }
    expected_slugs = {
        _slug_to_python_identifier(str(value))
        for value in expected_binding.get("detector_slug_candidates") or []
        if str(value).strip()
    }
    expected_detector_paths = {
        str(value).strip()
        for value in expected_binding.get("detector_path_candidates") or []
        if str(value).strip()
    }
    binding_required = bool(expected_binding.get("binding_required"))
    if binding_required and not (observed_pattern or observed_detector_slug or observed_detector_path):
        blockers.append("smoke metadata missing detector binding fields (pattern/detector_slug/detector_path)")

    if observed_pattern and expected_patterns:
        if _slug_to_argument(observed_pattern) not in expected_patterns:
            blockers.append(
                f"smoke pattern conflicts with queued detector context: observed={observed_pattern}"
            )
    if observed_detector_slug and expected_slugs:
        if _slug_to_python_identifier(observed_detector_slug) not in expected_slugs:
            blockers.append(
                f"smoke detector_slug conflicts with queued detector context: observed={observed_detector_slug}"
            )
    if observed_detector_path:
        observed_path = Path(observed_detector_path).expanduser()
        observed_basename_slug = _slug_to_python_identifier(observed_path.stem)
        if expected_detector_paths:
            resolved_observed_path = (
                str(observed_path.resolve())
                if observed_path.is_absolute() else str((smoke_path.parent / observed_path).resolve())
            )
            if (
                observed_detector_path not in expected_detector_paths
                and resolved_observed_path not in expected_detector_paths
            ):
                blockers.append(
                    f"smoke detector_path conflicts with queued detector context: observed={observed_detector_path}"
                )
        elif expected_slugs and observed_basename_slug and observed_basename_slug not in expected_slugs:
            blockers.append(
                f"smoke detector_path conflicts with queued detector context: observed={observed_detector_path}"
            )

    return not blockers, blockers, {
        "positive_hits": positive_hits,
        "clean_hits": clean_hits,
        "status": payload.get("status", payload.get("result", "")),
        "command": command,
        "pattern": observed_pattern,
        "detector_slug": observed_detector_slug,
        "detector_path": observed_detector_path,
    }


def _assess_row(workspace: Path, row: dict[str, Any]) -> dict[str, Any]:
    task_type = str(row.get("task_type") or "")
    fixture_task = row.get("fixture_task") if isinstance(row.get("fixture_task"), dict) else {}
    smoke_required = task_type in SMOKE_REQUIRED_TYPES or bool(fixture_task)
    positive_path = _resolve_workspace_path(workspace, fixture_task.get("positive_fixture_path"))
    clean_path = _resolve_workspace_path(workspace, fixture_task.get("clean_fixture_path"))
    smoke_path = _resolve_workspace_path(workspace, fixture_task.get("smoke_record_path"))
    smoke_binding = _smoke_binding_expectations(
        workspace,
        row,
        fixture_task,
        smoke_path,
        positive_path,
        clean_path,
    )
    fixture_manifest_path = _fixture_manifest_path(smoke_path)
    fixture_manifest_terminal, fixture_manifest_summary = _assess_fixture_manifest(fixture_manifest_path)
    dependency_preflight = _dependency_preflight(workspace, fixture_manifest_summary)
    extraction_failure = _read_extraction_failure(fixture_manifest_path)
    blockers: list[str] = []

    if not smoke_required:
        status = "not_applicable_source_review_or_coverage"
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
        status = EXTRACTION_FAILED_STATUS
    elif not dependency_preflight["ok"]:
        blockers.extend(dependency_preflight["blockers"])
        status = DEPENDENCY_CANNOT_RUN_STATUS
    else:
        if not positive_path:
            blockers.append("positive fixture path missing")
        elif not Path(positive_path).is_file():
            blockers.append(f"positive fixture missing: {positive_path}")
        if not clean_path:
            blockers.append("clean fixture path missing")
        elif not Path(clean_path).is_file():
            blockers.append(f"clean fixture missing: {clean_path}")
        smoke_ok, smoke_blockers, smoke_summary = _assess_smoke_record(smoke_path, smoke_binding)
        blockers.extend(smoke_blockers)
        status = "fixture_smoke_passed" if not blockers and smoke_ok else "blocked_missing_fixture_or_smoke"

    result = {
        "queue_id": row.get("queue_id", ""),
        "inventory_id": row.get("inventory_id", ""),
        "task_type": task_type,
        "source_component": row.get("source_component", ""),
        "candidate_detector_family": row.get("candidate_detector_family", ""),
        "suggested_detector_slug": row.get("suggested_detector_slug", ""),
        "smoke_required": smoke_required,
        "status": status,
        "positive_fixture_path": positive_path,
        "clean_fixture_path": clean_path,
        "smoke_record_path": smoke_path,
        "fixture_manifest_path": fixture_manifest_path,
        "fixture_manifest_terminal": fixture_manifest_terminal,
        "fixture_manifest_summary": fixture_manifest_summary,
        "extraction_failure_path": extraction_failure.get("path", ""),
        "extraction_failure_reason": extraction_failure.get("reason", ""),
        "dependency_preflight": dependency_preflight,
        "cannot_run_reason": (
            ",".join(dependency_preflight["blocker_categories"])
            if status == DEPENDENCY_CANNOT_RUN_STATUS else ""
        ),
        "blockers": blockers,
        "next_command": (
            "resolve dependency preflight blockers, then rerun fixture extraction/smoke"
            if status == DEPENDENCY_CANNOT_RUN_STATUS
            else "repair generated fixtures or detector availability, then rerun extraction; require solc plus vulnerable>=1 and clean=0 smoke"
            if status == EXTRACTION_FAILED_STATUS
            else
            "create paired vulnerable/clean fixtures and a smoke JSON with positive_hits>=1, clean_hits=0, and command"
            if blockers
            else "preserve smoke record with detector fixture review"
        ),
        **ADVISORY_POSTURE,
    }
    if smoke_required:
        _, _, smoke_summary = _assess_smoke_record(smoke_path, smoke_binding)
        result["smoke_summary"] = smoke_summary
    return result


def build_gate(workspace: Path, inventory: dict[str, Any], *, limit: int = 50) -> dict[str, Any]:
    queue = inventory.get("detector_fixture_task_queue")
    if not isinstance(queue, list):
        queue = []
    rows = [
        _assess_row(workspace, row)
        for row in queue[: max(0, limit)]
        if isinstance(row, dict)
    ]
    smoke_required = [row for row in rows if row.get("smoke_required")]
    passed = [row for row in smoke_required if row.get("status") == "fixture_smoke_passed"]
    cannot_run = [row for row in smoke_required if row.get("status") == DEPENDENCY_CANNOT_RUN_STATUS]
    extraction_failed = [row for row in smoke_required if row.get("status") == EXTRACTION_FAILED_STATUS]
    runnable_blocked = [row for row in smoke_required if row.get("status") == "blocked_missing_fixture_or_smoke"]
    blocked = runnable_blocked
    fixture_manifest_rows = [row for row in smoke_required if row.get("fixture_manifest_terminal")]
    extraction_command_rows = [
        row for row in fixture_manifest_rows
        if (row.get("fixture_manifest_summary") or {}).get("shell_command")
    ]
    existing_pair_rows = [
        row for row in fixture_manifest_rows
        if (row.get("fixture_manifest_summary") or {}).get("existing_fixture_pair")
    ]
    status_counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "source_artifact": str(workspace / ".auditooor" / "semantic_scanner_inventory.json"),
        "limit": limit,
        "queue_item_count": len(queue),
        "processed_count": len(rows),
        "smoke_required_count": len(smoke_required),
        "smoke_passed_count": len(passed),
        "blocking_count": len(blocked),
        "terminal_cannot_run_count": len(cannot_run),
        "terminal_extraction_failed_count": len(extraction_failed),
        "runnable_fixture_blocked_count": len(runnable_blocked),
        "terminal_fixture_manifest_count": len(fixture_manifest_rows),
        "exact_extraction_command_count": len(extraction_command_rows),
        "existing_fixture_pair_manifest_count": len(existing_pair_rows),
        "gate_passed": len(blocked) == 0 and len(cannot_run) == 0 and len(extraction_failed) == 0,
        "status_counts": status_counts,
        "rows": rows,
        "next_actions": [
            "Run semantic-scanner-inventory first when the queue is empty or stale.",
            "For detector/fixture rows, add vulnerable and clean fixtures before detector promotion.",
            "Capture smoke JSON with positive_hits >= 1, clean_hits == 0, and the exact smoke command.",
            "Keep exact impact proof and submission readiness in separate gates; this tool only checks fixture smoke.",
        ],
        **ADVISORY_POSTURE,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Semantic Fixture Smoke Gate",
        "",
        "Fixture-first gate for semantic scanner inventory rows.",
        "Passing this gate means queued detector rows have paired fixture smoke only; it does not prove impact or submission readiness.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- processed rows: {payload['processed_count']}",
        f"- smoke-required rows: {payload['smoke_required_count']}",
        f"- smoke-passed rows: {payload['smoke_passed_count']}",
        f"- terminal fixture manifests/extraction commands: {payload['terminal_fixture_manifest_count']}",
        f"- blocking rows: {payload['blocking_count']}",
        f"- terminal cannot-run rows: {payload.get('terminal_cannot_run_count', 0)}",
        f"- terminal extraction-failed rows: {payload.get('terminal_extraction_failed_count', 0)}",
        f"- gate passed: `{str(payload['gate_passed']).lower()}`",
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
        "| Queue | Type | Status | Source | Detector | Blockers |",
        "|---|---|---|---|---|---|",
    ])
    for row in payload.get("rows", []):
        blockers = "; ".join(row.get("blockers") or [])
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | {} |".format(
            row.get("queue_id", ""),
            row.get("task_type", ""),
            row.get("status", ""),
            row.get("source_component", ""),
            row.get("suggested_detector_slug", ""),
            blockers or "_none_",
        ))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--strict", action="store_true", help="Exit 1 when any smoke-required row is blocked")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[semantic-fixture-smoke-gate] workspace not found: {workspace}", file=sys.stderr)
        return 2
    inventory_path = (args.inventory or workspace / ".auditooor" / "semantic_scanner_inventory.json").expanduser().resolve()
    inventory = _load_json(inventory_path, "semantic scanner inventory")
    payload = build_gate(workspace, inventory, limit=args.limit)
    payload["source_artifact"] = str(inventory_path)

    out_json = args.out_json or workspace / ".auditooor" / "semantic_fixture_smoke_gate.json"
    out_md = args.out_md or workspace / ".auditooor" / "semantic_fixture_smoke_gate.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[semantic-fixture-smoke-gate] OK processed={payload['processed_count']} "
        f"blocked={payload['blocking_count']} json={out_json}",
        file=sys.stderr,
    )
    return 1 if args.strict and not payload["gate_passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
