#!/usr/bin/env python3
"""Discover and execute real Obyte AA testkit suites without semantic over-credit.

The runner is a phase-3 execution adapter.  It only runs workspace-local npm
test scripts in projects that declare and have an installed ``aa-testkit``.
Its receipt is runtime evidence for a named suite, never a source-semantic,
reasoner, depth, or fuzzing receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence


SCHEMA = "auditooor.oscript_aa_testkit_execution.v1"
MAX_DISCOVERY_DEPTH = 5


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relative(root: Path, value: Path) -> str:
    try:
        return value.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError("project outside workspace") from exc


def _load_package(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid package.json: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"invalid package.json object: {path}")
    return value


def _declares_testkit(package: dict[str, Any]) -> bool:
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        values = package.get(field, {})
        if isinstance(values, dict) and "aa-testkit" in values:
            return True
    return False


def _test_files(project: Path) -> list[dict[str, str]]:
    rows = []
    for path in sorted(project.rglob("*.test.oscript.js")):
        if "node_modules" in path.parts or not path.is_file() or path.is_symlink():
            continue
        raw = path.read_bytes()
        rows.append({"path": path.relative_to(project).as_posix(), "sha256": _sha256(raw)})
    return rows


def discover(workspace: str | Path) -> list[dict[str, Any]]:
    """Return deterministic AA testkit project descriptors below ``src/``."""

    root = Path(workspace).expanduser().resolve()
    source_root = root / "src"
    if not source_root.is_dir():
        raise ValueError("workspace src missing")
    rows: list[dict[str, Any]] = []
    for package_path in sorted(source_root.rglob("package.json")):
        relative_parts = package_path.relative_to(source_root).parts
        if "node_modules" in package_path.parts or len(relative_parts) > MAX_DISCOVERY_DEPTH:
            continue
        project = package_path.parent
        package = _load_package(package_path)
        if not _declares_testkit(package):
            continue
        scripts = package.get("scripts", {})
        test_script = scripts.get("test") if isinstance(scripts, dict) else None
        installed = (project / "node_modules" / "aa-testkit").is_dir()
        rows.append(
            {
                "project": _safe_relative(root, project),
                "package_sha256": _sha256(package_path.read_bytes()),
                "test_command": ["npm", "run", "test"],
                "test_script": test_script if isinstance(test_script, str) else "",
                "aa_testkit_installed": installed,
                "test_files": _test_files(project),
                "status": "ready" if installed and isinstance(test_script, str) and test_script.strip() else "blocked",
            }
        )
    return rows


def _select_project(workspace: Path, rows: list[dict[str, Any]], project: str | None) -> list[dict[str, Any]]:
    if project is None:
        return rows
    requested = _safe_relative(workspace, workspace / project)
    selected = [row for row in rows if row["project"] == requested]
    if not selected:
        raise ValueError("aa-testkit project not discovered")
    return selected


def execute(
    workspace: str | Path,
    *,
    project: str | None = None,
    timeout_seconds: int = 300,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, Any]]:
    """Run selected ready suites and return typed runtime-only receipts."""

    root = Path(workspace).expanduser().resolve()
    if timeout_seconds <= 0:
        raise ValueError("timeout must be positive")
    selected = _select_project(root, discover(root), project)
    if not selected:
        raise ValueError("no aa-testkit projects discovered")
    if shutil.which("npm") is None:
        raise RuntimeError("npm unavailable")
    receipts: list[dict[str, Any]] = []
    for descriptor in selected:
        project_root = root / descriptor["project"]
        if descriptor["status"] != "ready":
            raise RuntimeError(f"aa-testkit project not runnable: {descriptor['project']}")
        try:
            result = runner(
                descriptor["test_command"], cwd=project_root, capture_output=True,
                text=True, timeout=timeout_seconds, check=False,
            )
            stdout, stderr, exit_code = result.stdout or "", result.stderr or "", result.returncode
            status = "passed" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", "replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", "replace")
            exit_code, status = None, "timed_out"
        receipts.append(
            {
                "schema": SCHEMA,
                "language": "oscript",
                "backend": "aa-testkit",
                "evidence_tier": "runtime-execution",
                "project": descriptor["project"],
                "package_sha256": descriptor["package_sha256"],
                "command": descriptor["test_command"],
                "timeout_seconds": timeout_seconds,
                "test_files": descriptor["test_files"],
                "status": status,
                "exit_code": exit_code,
                "stdout_sha256": _sha256(str(stdout).encode("utf-8")),
                "stderr_sha256": _sha256(str(stderr).encode("utf-8")),
                "credit": {
                    "runtime_execution": status == "passed",
                    "semantic_engine": False,
                    "reasoner": False,
                    "depth": False,
                    "fuzz": False,
                },
            }
        )
    return receipts


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--project", help="workspace-relative AA project path")
    parser.add_argument("--execute", action="store_true", help="run npm test instead of discovery only")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.execute:
            payload: dict[str, Any] = {"receipts": execute(args.workspace, project=args.project, timeout_seconds=args.timeout_seconds)}
        else:
            rows = _select_project(args.workspace.resolve(), discover(args.workspace), args.project)
            payload = {"schema": "auditooor.oscript_aa_testkit_discovery.v1", "projects": rows}
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        if args.execute and any(row.get("status") != "passed" for row in payload["receipts"]):
            return 1
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
