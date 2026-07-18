#!/usr/bin/env python3
"""Safely borrow an audit asset, insert a test, run commands, and revert.

This runner is intentionally narrow: it mutates exactly one target path inside
an already-clean git worktree, captures command output outside that asset, then
restores that one path and verifies the asset is clean again.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.audit_asset_test_runner.v1"
MANIFEST_NAME = "audit_asset_test_runner_manifest.json"


class RunnerError(Exception):
    """Expected fail-closed runner error."""


def run_process(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def git(asset: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return run_process(["git", "-C", str(asset), *args])


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def now_unix() -> int:
    return int(time.time())


def status_entries(asset: Path) -> list[str]:
    proc = git(asset, ["status", "--porcelain=v1", "--untracked-files=all"])
    if proc.returncode != 0:
        raise RunnerError(f"git status failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return [line for line in proc.stdout.splitlines() if line.strip()]


def require_clean(asset: Path, label: str) -> list[str]:
    entries = status_entries(asset)
    if entries:
        raise RunnerError(f"{label} git status is dirty: {entries}")
    return entries


def git_root(asset: Path) -> Path:
    proc = git(asset, ["rev-parse", "--show-toplevel"])
    if proc.returncode != 0:
        raise RunnerError(f"asset is not a git repository: {asset}")
    return Path(proc.stdout.strip()).resolve()


def is_tracked(asset: Path, target_rel: str) -> bool:
    proc = git(asset, ["ls-files", "--error-unmatch", "--", target_rel])
    return proc.returncode == 0


def safe_relative_target(asset: Path, target: str) -> tuple[str, Path]:
    raw = Path(target)
    if raw.is_absolute():
        raise RunnerError("--target must be relative to --asset")
    if not target.strip() or raw == Path("."):
        raise RunnerError("--target must name a file path")
    if any(part == ".." for part in raw.parts):
        raise RunnerError("--target may not contain '..'")
    target_path = (asset / raw).resolve()
    try:
        target_path.relative_to(asset)
    except ValueError as exc:
        raise RunnerError("--target resolves outside --asset") from exc
    return raw.as_posix(), target_path


def path_is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def base_manifest(
    *,
    asset: Path,
    source: Path,
    target_rel: str,
    target_path: Path,
    capture_dir: Path,
    commands: list[str],
    execute: bool,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "generated_at_unix": now_unix(),
        "asset": str(asset),
        "source_test_file": str(source),
        "target": target_rel,
        "target_path": str(target_path),
        "capture_dir": str(capture_dir),
        "mode": "execute" if execute else "dry_run",
        "status": "initializing",
        "commands": [
            {
                "index": index,
                "command": command,
                "status": "planned",
                "returncode": None,
            }
            for index, command in enumerate(commands, start=1)
        ],
        "pre_status": None,
        "post_status": None,
        "target_existed_before": None,
        "target_tracked_before": None,
        "restoration": {
            "attempted": False,
            "method": None,
            "status": "not_started",
            "final_clean": None,
        },
    }


def validate_common(
    *,
    asset: Path,
    source: Path,
    target_path: Path,
    capture_dir: Path,
    execute: bool,
) -> Path:
    if not asset.exists() or not asset.is_dir():
        raise RunnerError(f"--asset is not a directory: {asset}")
    root = git_root(asset)
    if root != asset:
        raise RunnerError(f"--asset must be the git worktree root; got {asset}, root is {root}")
    if not source.exists() or not source.is_file():
        raise RunnerError(f"--insert is not a file: {source}")
    if target_path.exists() and target_path.is_dir():
        raise RunnerError(f"--target is a directory: {target_path}")
    if not target_path.parent.exists():
        raise RunnerError(f"--target parent does not exist: {target_path.parent}")
    if execute and path_is_inside(capture_dir, asset):
        raise RunnerError("--capture must be outside --asset in execute mode")
    return root


def run_shell_command(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def restore_target(asset: Path, target_rel: str, target_path: Path, target_tracked_before: bool) -> dict[str, Any]:
    restoration: dict[str, Any] = {
        "attempted": True,
        "method": "git_restore" if target_tracked_before else "unlink_new_file",
        "status": "started",
        "final_clean": False,
    }
    if target_tracked_before:
        proc = git(asset, ["restore", "--worktree", "--staged", "--", target_rel])
        restoration["restore_returncode"] = proc.returncode
        restoration["restore_stdout"] = proc.stdout
        restoration["restore_stderr"] = proc.stderr
        if proc.returncode != 0:
            restoration["status"] = "restore_failed"
            restoration["final_status_entries"] = status_entries(asset)
            return restoration
    elif target_path.exists():
        target_path.unlink()

    final_entries = status_entries(asset)
    restoration["final_status_entries"] = final_entries
    restoration["final_clean"] = not final_entries
    restoration["status"] = "clean" if not final_entries else "dirty_after_restore"
    return restoration


def execute_run(manifest: dict[str, Any], *, asset: Path, source: Path, target_rel: str, target_path: Path, capture_dir: Path) -> int:
    root = validate_common(asset=asset, source=source, target_path=target_path, capture_dir=capture_dir, execute=True)
    manifest["asset_git_root"] = str(root)
    manifest["pre_status"] = require_clean(asset, "pre-run")

    target_existed_before = target_path.exists()
    target_tracked_before = is_tracked(asset, target_rel)
    manifest["target_existed_before"] = target_existed_before
    manifest["target_tracked_before"] = target_tracked_before
    if target_existed_before and not target_tracked_before:
        raise RunnerError("--target exists but is not tracked; refusing to overwrite an untracked/ignored file")

    capture_dir.mkdir(parents=True, exist_ok=True)
    target_touched = False
    failed = False
    try:
        shutil.copyfile(source, target_path)
        target_touched = True
        for command_row in manifest["commands"]:
            command = str(command_row["command"])
            index = int(command_row["index"])
            stdout_path = capture_dir / f"command-{index:03d}.stdout.log"
            stderr_path = capture_dir / f"command-{index:03d}.stderr.log"
            started = time.monotonic()
            proc = run_shell_command(command, asset)
            duration = time.monotonic() - started
            stdout_path.write_text(proc.stdout, encoding="utf-8")
            stderr_path.write_text(proc.stderr, encoding="utf-8")
            command_row.update(
                {
                    "status": "passed" if proc.returncode == 0 else "failed",
                    "returncode": proc.returncode,
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                    "duration_seconds": round(duration, 3),
                }
            )
            if proc.returncode != 0:
                failed = True
                break
        for command_row in manifest["commands"]:
            if command_row["status"] == "planned":
                command_row["status"] = "skipped_after_failure"
    finally:
        if target_touched:
            manifest["restoration"] = restore_target(asset, target_rel, target_path, target_tracked_before)
        else:
            manifest["restoration"] = {
                "attempted": False,
                "method": None,
                "status": "not_needed",
                "final_clean": not status_entries(asset),
                "final_status_entries": status_entries(asset),
            }
        manifest["post_status"] = status_entries(asset)

    final_clean = bool(manifest["restoration"].get("final_clean"))
    if not final_clean:
        manifest["status"] = "dirty_after_restore"
        return 1
    if failed:
        manifest["status"] = "command_failed_reverted"
        return 1
    manifest["status"] = "passed_reverted"
    return 0


def dry_run(manifest: dict[str, Any], *, asset: Path, source: Path, target_path: Path, capture_dir: Path) -> int:
    root = validate_common(asset=asset, source=source, target_path=target_path, capture_dir=capture_dir, execute=False)
    manifest["asset_git_root"] = str(root)
    manifest["pre_status"] = status_entries(asset)
    manifest["target_existed_before"] = target_path.exists()
    manifest["target_tracked_before"] = is_tracked(asset, str(manifest["target"]))
    manifest["post_status"] = manifest["pre_status"]
    manifest["status"] = "dry_run"
    manifest["restoration"] = {
        "attempted": False,
        "method": None,
        "status": "not_needed",
        "final_clean": not manifest["post_status"],
        "final_status_entries": manifest["post_status"],
    }
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely insert an audit-asset test file, run commands, capture logs, and revert.",
    )
    parser.add_argument("--asset", required=True, help="Path to the borrowed audit asset git worktree root")
    parser.add_argument("--insert", required=True, help="Source test file to copy into the asset")
    parser.add_argument("--target", required=True, help="Relative target path inside --asset")
    parser.add_argument("--command", action="append", required=True, help="Shell command to run from --asset; repeatable")
    parser.add_argument("--capture", required=True, help="Directory for manifest and stdout/stderr logs")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Validate and write a plan without mutating the asset")
    mode.add_argument("--execute", action="store_true", help="Actually copy, run, capture, and revert")
    return parser


def run(args: argparse.Namespace) -> int:
    asset = Path(args.asset).expanduser().resolve()
    source = Path(args.insert).expanduser().resolve()
    capture_dir = Path(args.capture).expanduser().resolve()
    execute = bool(args.execute)
    target_rel, target_path = safe_relative_target(asset, args.target)
    manifest = base_manifest(
        asset=asset,
        source=source,
        target_rel=target_rel,
        target_path=target_path,
        capture_dir=capture_dir,
        commands=list(args.command or []),
        execute=execute,
    )
    manifest_path = capture_dir / MANIFEST_NAME
    exit_code = 1
    try:
        if execute:
            exit_code = execute_run(
                manifest,
                asset=asset,
                source=source,
                target_rel=target_rel,
                target_path=target_path,
                capture_dir=capture_dir,
            )
        else:
            exit_code = dry_run(manifest, asset=asset, source=source, target_path=target_path, capture_dir=capture_dir)
    except RunnerError as exc:
        manifest["status"] = "blocked"
        manifest["error"] = str(exc)
        try:
            manifest["post_status"] = status_entries(asset)
        except RunnerError:
            pass
        exit_code = 1
    finally:
        write_json(manifest_path, manifest)
    print(f"[audit-asset-test-runner] manifest: {manifest_path}")
    print(f"[audit-asset-test-runner] status: {manifest['status']}")
    if manifest.get("error"):
        print(f"[audit-asset-test-runner] error: {manifest['error']}", file=sys.stderr)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
