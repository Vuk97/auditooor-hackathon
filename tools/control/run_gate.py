"""Dry-run planner and explicit runner for candidate gate review.

``auditooorctl run-gate`` uses this module to build deterministic local
manifests by default.  Execution is intentionally separate and explicit via
``--execute`` / ``execute_run_gate`` so gate failures remain fail-closed and
never imply exploit proof, submission readiness, or remote automation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex
import subprocess
from typing import Any, Mapping, Sequence

from .candidates import discover_candidates
from .run_manifest import build_run_manifest, write_run_manifest
from .runner import command_hash


SCHEMA = "auditooor.control.run_gate.v1"
DEFAULT_GATE_SCRIPT = "tools/upstream-equivalent-gate.py"
DEFAULT_ARTIFACT_DIR = ".auditooor/control/run_gate"
PROOF_BOUNDARY = (
    "Run-gate output is local promotion-review evidence only; it does not "
    "prove exploit impact, approve severity, file a report, push code, open a "
    "PR, merge, or invoke GitHub Actions."
)


def build_run_gate_plan(
    workspace: str | Path,
    *,
    candidate_file: str | Path | None = None,
    candidate_id: str | None = None,
    candidate_report: str | Path | Mapping[str, Any] | None = None,
    cwd: str | Path | None = None,
    gate_script: str | Path = DEFAULT_GATE_SCRIPT,
    out_dir: str | Path | None = None,
    python: str = "python3",
) -> dict[str, Any]:
    """Return a dry-run manifest for one upstream-equivalent gate command.

    ``candidate_file`` is preferred when supplied.  Otherwise ``candidate_id``
    is resolved from a normalized candidate report or the workspace candidate
    registry.  This function never executes the planned command and never
    writes artifacts.
    """

    ws = Path(workspace).expanduser().resolve()
    run_cwd = Path(cwd).expanduser().resolve() if cwd is not None else _repo_root()
    blocked: list[str] = []

    candidate = _resolve_candidate(
        ws,
        candidate_file=candidate_file,
        candidate_id=candidate_id,
        candidate_report=candidate_report,
        cwd=run_cwd,
    )
    blocked.extend(candidate["blocked_reasons"])
    cid = candidate["candidate_id"]
    candidate_path = candidate["candidate_path"]

    artifacts = _artifact_paths(ws, cid, out_dir=out_dir)
    script_text = _script_command_path(gate_script, run_cwd)
    argv = [
        python,
        script_text,
        "--workspace",
        str(ws),
        "--candidate",
        candidate_path,
        "--candidate-id",
        cid,
        "--out-json",
        artifacts["out_json"],
    ]
    command_text = _command_text(argv)

    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "cwd": str(run_cwd),
        "candidate_id": cid,
        "candidate_path": candidate_path,
        "candidate_source": candidate["candidate_source"],
        "gate_script": str(_resolve_script_path(gate_script, run_cwd)),
        "command_hash": command_hash(command_text, cwd=run_cwd, workspace=ws),
        "command_text": command_text,
        "argv": argv,
        "command": {
            "text": command_text,
            "argv": argv,
        },
        "dry_run": True,
        "would_execute": False,
        "gate_artifact_paths": artifacts,
        "proof_boundary": PROOF_BOUNDARY,
        "blocked_reasons": _stable_unique(blocked),
    }


def write_run_gate_manifest(path: str | Path, manifest: Mapping[str, Any]) -> Path:
    """Persist a run-gate manifest as deterministic JSON."""

    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(manifest), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out.resolve()


def execute_run_gate(
    manifest_or_workspace: Mapping[str, Any] | str | Path,
    *,
    candidate_file: str | Path | None = None,
    candidate_id: str | None = None,
    candidate_report: str | Path | Mapping[str, Any] | None = None,
    cwd: str | Path | None = None,
    gate_script: str | Path = DEFAULT_GATE_SCRIPT,
    out_dir: str | Path | None = None,
    python: str = "python3",
    timeout: int | float | None = None,
) -> dict[str, Any]:
    """Execute a run-gate manifest only when this function is called.

    The function runs without ``shell=True``, captures stdout/stderr to the
    planned artifact paths, and writes a normalized run manifest where possible.
    Existing dry-run blockers fail closed before subprocess execution.
    """

    if isinstance(manifest_or_workspace, Mapping):
        plan = dict(manifest_or_workspace)
    else:
        plan = build_run_gate_plan(
            manifest_or_workspace,
            candidate_file=candidate_file,
            candidate_id=candidate_id,
            candidate_report=candidate_report,
            cwd=cwd,
            gate_script=gate_script,
            out_dir=out_dir,
            python=python,
        )

    execution_blockers = _execution_blockers(plan)
    if execution_blockers:
        return _blocked_execution(plan, execution_blockers)

    artifacts = _artifact_mapping(plan)
    _ensure_parent_dirs(artifacts.values())
    started_at = _utc_now()
    proc = subprocess.run(
        [str(part) for part in plan.get("argv") or []],
        cwd=str(plan.get("cwd") or Path.cwd()),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    finished_at = _utc_now()

    stdout_path = Path(artifacts["stdout"])
    stderr_path = Path(artifacts["stderr"])
    stdout_path.write_text(proc.stdout or "", encoding="utf-8")
    stderr_path.write_text(proc.stderr or "", encoding="utf-8")

    gate_payload = _read_json(Path(artifacts["out_json"]))
    verdict = _normalize_verdict(gate_payload, exit_code=proc.returncode)
    completed = {
        "returncode": proc.returncode,
        "started_at": started_at,
        "finished_at": finished_at,
        "stdout_path": artifacts["stdout"],
        "stderr_path": artifacts["stderr"],
        "artifacts": [artifacts["out_json"]],
        "proof_counted": False,
    }
    run_manifest = build_run_manifest(
        plan.get("argv") or [],
        cwd=str(plan.get("cwd") or Path.cwd()),
        workspace=str(plan.get("workspace") or ""),
        completed=completed,
        blocked_reasons=[] if proc.returncode == 0 else [f"gate_exit_{proc.returncode}"],
    )
    write_run_manifest(artifacts["run_manifest"], run_manifest)

    result = dict(plan)
    result.update(
        {
            "dry_run": False,
            "would_execute": True,
            "blocked_reasons": [],
            "execution": {
                "status": run_manifest["status"],
                "exit_code": proc.returncode,
                "started_at": started_at,
                "finished_at": finished_at,
                "stdout_path": artifacts["stdout"],
                "stderr_path": artifacts["stderr"],
                "run_manifest_path": artifacts["run_manifest"],
                "run_manifest": run_manifest,
            },
            "gate_verdict": verdict,
        }
    )
    return result


def _resolve_candidate(
    workspace: Path,
    *,
    candidate_file: str | Path | None,
    candidate_id: str | None,
    candidate_report: str | Path | Mapping[str, Any] | None,
    cwd: Path,
) -> dict[str, Any]:
    blocked: list[str] = []
    if candidate_file is not None:
        path = _resolve_path(candidate_file, workspace=workspace, cwd=cwd)
        if not path.is_file():
            blocked.append("candidate_file_missing")
        cid = _candidate_id_from_file(path) or _clean_id(candidate_id) or _slug(path.stem)
        return {
            "candidate_id": cid,
            "candidate_path": str(path),
            "candidate_source": "candidate_file",
            "blocked_reasons": blocked,
        }

    cid = _clean_id(candidate_id)
    if not cid:
        return {
            "candidate_id": "candidate",
            "candidate_path": "",
            "candidate_source": "unresolved",
            "blocked_reasons": ["candidate_id_or_file_required"],
        }

    row = _lookup_candidate_row(workspace, cid, candidate_report)
    if row is None:
        return {
            "candidate_id": cid,
            "candidate_path": "",
            "candidate_source": "candidate_id",
            "blocked_reasons": ["candidate_id_not_found"],
        }

    path_text = _candidate_path_from_row(row, workspace=workspace, cwd=cwd)
    if not path_text:
        blocked.append("candidate_path_missing")
        path = None
    else:
        path = Path(path_text)
        if not path.is_file():
            blocked.append("candidate_file_missing")

    return {
        "candidate_id": _clean_id(row.get("id") or row.get("candidate_id") or cid),
        "candidate_path": str(path) if path is not None else "",
        "candidate_source": "candidate_report" if candidate_report is not None else "workspace_registry",
        "blocked_reasons": blocked,
    }


def _lookup_candidate_row(
    workspace: Path,
    candidate_id: str,
    candidate_report: str | Path | Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if candidate_report is not None:
        payload = _load_candidate_report(candidate_report)
        for row in _candidate_rows_from_payload(payload):
            if _candidate_id_matches(row, candidate_id):
                return row
        return None

    for candidate in discover_candidates(workspace):
        if _candidate_id_matches(candidate.to_dict(), candidate_id):
            return candidate.to_dict()
    return None


def _load_candidate_report(candidate_report: str | Path | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(candidate_report, Mapping):
        return candidate_report
    path = Path(candidate_report).expanduser()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def _candidate_rows_from_payload(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("candidates")
    if raw is None:
        raw = payload.get("rows")
    if raw is None and isinstance(payload.get("state"), Mapping):
        raw = payload["state"].get("candidates")
    if raw is None and _looks_like_candidate_row(payload):
        raw = [payload]
    if not isinstance(raw, list):
        return []
    return [dict(row) for row in raw if isinstance(row, Mapping)]


def _candidate_id_matches(row: Mapping[str, Any], candidate_id: str) -> bool:
    wanted = _slug(candidate_id)
    aliases = {
        _slug(str(row.get("id") or "")),
        _slug(str(row.get("candidate_id") or "")),
        _slug(str(row.get("slug") or "")),
    }
    return wanted in aliases


def _candidate_path_from_row(row: Mapping[str, Any], *, workspace: Path, cwd: Path) -> str:
    direct_keys = (
        "candidate_path",
        "path",
        "file",
        "draft_path",
        "draft",
        "artifact_path",
    )
    for key in direct_keys:
        value = _string(row.get(key))
        if value:
            return str(_resolve_path(value, workspace=workspace, cwd=cwd))

    sources = _string_list(row.get("source_paths") or row.get("files") or row.get("sources"))
    preferred = _preferred_candidate_source(sources, workspace=workspace, cwd=cwd)
    return str(preferred) if preferred is not None else ""


def _preferred_candidate_source(sources: Sequence[str], *, workspace: Path, cwd: Path) -> Path | None:
    resolved = [_resolve_path(source, workspace=workspace, cwd=cwd) for source in sources if _strip_line_suffix(source)]
    existing = [path for path in resolved if path.is_file()]
    if not resolved:
        return None
    for paths in (existing, resolved):
        for path in paths:
            text = path.as_posix()
            if ".auditooor/control/candidates/" in text:
                return path
        for path in paths:
            text = path.as_posix()
            if "/submissions/" in text and path.suffix == ".md":
                return path
        for path in paths:
            if path.suffix.lower() in {".json", ".yaml", ".yml", ".md"}:
                return path
    return existing[0] if existing else resolved[0]


def _resolve_path(path: str | Path, *, workspace: Path, cwd: Path) -> Path:
    text = _strip_line_suffix(str(path))
    raw = Path(text).expanduser()
    if raw.is_absolute():
        return raw.resolve()
    ws_path = (workspace / raw).resolve()
    if ws_path.exists() or str(raw).startswith((".auditooor/", "submissions/", "poc_execution/")):
        return ws_path
    return (cwd / raw).resolve()


def _candidate_id_from_file(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, Mapping):
        return ""
    return _clean_id(payload.get("id") or payload.get("candidate_id") or payload.get("slug"))


def _artifact_paths(workspace: Path, candidate_id: str, *, out_dir: str | Path | None) -> dict[str, str]:
    root = _resolve_artifact_dir(workspace, out_dir)
    safe_id = _slug(candidate_id)
    gate_dir = root / safe_id
    return {
        "out_json": str(gate_dir / "upstream_equivalent_gate.json"),
        "stdout": str(gate_dir / "stdout.log"),
        "stderr": str(gate_dir / "stderr.log"),
        "run_manifest": str(gate_dir / "run_manifest.json"),
    }


def _resolve_artifact_dir(workspace: Path, out_dir: str | Path | None) -> Path:
    if out_dir is None:
        return workspace / DEFAULT_ARTIFACT_DIR
    raw = Path(out_dir).expanduser()
    return raw.resolve() if raw.is_absolute() else (workspace / raw).resolve()


def _execution_blockers(plan: Mapping[str, Any]) -> list[str]:
    blockers = _string_list(plan.get("blocked_reasons"))
    candidate_path = Path(_string(plan.get("candidate_path")))
    if not candidate_path.is_file():
        blockers.append("candidate_file_missing")
    script_path = Path(_string(plan.get("gate_script")))
    if not script_path.is_file():
        blockers.append("gate_script_missing")
    if not plan.get("argv"):
        blockers.append("command_argv_missing")
    return _stable_unique(blockers)


def _blocked_execution(plan: Mapping[str, Any], blockers: Sequence[str]) -> dict[str, Any]:
    result = dict(plan)
    artifacts = _artifact_mapping(plan)
    run_manifest = build_run_manifest(
        plan.get("argv") or [],
        cwd=str(plan.get("cwd") or Path.cwd()),
        workspace=str(plan.get("workspace") or ""),
        status="blocked",
        stdout_path=artifacts.get("stdout"),
        stderr_path=artifacts.get("stderr"),
        artifacts=[artifacts.get("out_json", "")],
        proof_counted=False,
        blocked_reasons=blockers,
    )
    result.update(
        {
            "dry_run": False,
            "would_execute": False,
            "blocked_reasons": _stable_unique(blockers),
            "execution": {
                "status": "blocked",
                "exit_code": None,
                "stdout_path": artifacts.get("stdout"),
                "stderr_path": artifacts.get("stderr"),
                "run_manifest_path": artifacts.get("run_manifest"),
                "run_manifest": run_manifest,
            },
            "gate_verdict": {
                "status": "blocked",
                "raw": "",
                "source": "wrapper_blocker",
                "proof_counted": False,
            },
        }
    )
    return result


def _artifact_mapping(plan: Mapping[str, Any]) -> dict[str, str]:
    artifacts = plan.get("gate_artifact_paths")
    if not isinstance(artifacts, Mapping):
        artifacts = {}
    return {
        "out_json": _string(artifacts.get("out_json")),
        "stdout": _string(artifacts.get("stdout")),
        "stderr": _string(artifacts.get("stderr")),
        "run_manifest": _string(artifacts.get("run_manifest")),
    }


def _normalize_verdict(payload: Any, *, exit_code: int) -> dict[str, Any]:
    raw = ""
    source = "returncode"
    if isinstance(payload, Mapping):
        source = "gate_artifact"
        raw = _string(
            payload.get("verdict")
            or payload.get("gate_verdict")
            or payload.get("status")
            or payload.get("result")
            or payload.get("decision")
        )
        if not raw and _int(payload.get("blocking_count")) > 0:
            raw = "blocked"
    normalized = _normalize_status(raw, exit_code=exit_code)
    return {
        "status": normalized,
        "raw": raw,
        "source": source,
        "proof_counted": False,
    }


def _normalize_status(raw: str, *, exit_code: int) -> str:
    value = raw.strip().lower().replace("-", "_")
    if value in {"pass", "passed", "ok", "success", "succeeded", "clean", "ready"}:
        return "passed"
    if value in {"blocked", "fail_closed", "needs_work", "not_ready"}:
        return "blocked"
    if value in {"fail", "failed", "failure", "error"}:
        return "failed"
    if value in {"warn", "warning", "partial"}:
        return "warning"
    if exit_code == 0:
        return "completed_unknown"
    return "failed"


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _ensure_parent_dirs(paths: Sequence[str]) -> None:
    for path in paths:
        if not path:
            continue
        Path(path).parent.mkdir(parents=True, exist_ok=True)


def _resolve_script_path(script: str | Path, cwd: Path) -> Path:
    path = Path(script).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (cwd / path).resolve()


def _script_command_path(script: str | Path, cwd: Path) -> str:
    path = Path(script).expanduser()
    if path.is_absolute():
        return str(path.resolve())
    try:
        return path.as_posix()
    except ValueError:
        return str(_resolve_script_path(script, cwd))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _command_text(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in argv)


def _looks_like_candidate_row(payload: Mapping[str, Any]) -> bool:
    return any(key in payload for key in ("id", "candidate_id", "slug", "title", "claim"))


def _clean_id(value: Any) -> str:
    text = _string(value)
    return text or ""


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _string_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (str, Path)):
        text = str(raw).strip()
        return [text] if text else []
    if isinstance(raw, Sequence):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []


def _strip_line_suffix(value: str) -> str:
    text = value.strip()
    match = re.match(r"^(.+?):\d+(?::\d+)?$", text)
    return match.group(1) if match else text


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-")
    return slug or "candidate"


def _stable_unique(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = [
    "DEFAULT_ARTIFACT_DIR",
    "DEFAULT_GATE_SCRIPT",
    "PROOF_BOUNDARY",
    "SCHEMA",
    "build_run_gate_plan",
    "execute_run_gate",
    "write_run_gate_manifest",
]
