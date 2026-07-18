#!/usr/bin/env python3
"""Launch local Codex workers only after a real CLI/model preflight.

The PR560 watchdog sometimes starts shell workers from a user config that is
valid for the desktop app but invalid for the installed local Codex CLI.  This
wrapper fails before writing a running manifest, or falls back to the CLI's
known-good default runtime with ``--ignore-user-config``.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_MODEL_PROBE_PROMPT = "Reply exactly: CODEX_WORKER_PREFLIGHT_OK"
MODEL_FAILURE_PATTERNS = (
    "requires a newer version of Codex",
    "not supported when using Codex with a ChatGPT account",
    "Unknown model",
    "invalid_request_error",
)


@dataclass(frozen=True)
class WorkerSpec:
    lane: str
    prompt: Path


@dataclass(frozen=True)
class CodexRuntime:
    command: list[str]
    exec_options: list[str]
    mode: str
    model: str | None
    ignored_user_config: bool
    preflight_stdout: str
    preflight_stderr: str


def load_prompt_lint_module():
    lint_path = Path(__file__).resolve().with_name("agent-dispatch-prompt-lint.py")
    spec = importlib.util.spec_from_file_location("agent_dispatch_prompt_lint_for_codex_worker", lint_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load prompt lint tool: {lint_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_worker_specs(prompt_paths: Iterable[str]) -> list[WorkerSpec]:
    specs: list[WorkerSpec] = []
    for raw in prompt_paths:
        prompt = Path(raw).expanduser().resolve()
        match = re.search(r"worker_([a-z]{2})", prompt.name, re.IGNORECASE)
        lane = match.group(1).upper() if match else prompt.stem.upper()
        specs.append(WorkerSpec(lane=lane, prompt=prompt))
    return specs


def load_prompt_dir(prompt_dir: Path, lanes: str) -> list[WorkerSpec]:
    specs: list[WorkerSpec] = []
    for lane in [item.strip().lower() for item in lanes.split(",") if item.strip()]:
        matches = sorted(prompt_dir.glob(f"worker_{lane}*.md"))
        if len(matches) != 1:
            raise SystemExit(
                f"expected exactly one prompt for lane {lane.upper()} in {prompt_dir}, found {len(matches)}"
            )
        specs.append(WorkerSpec(lane=lane.upper(), prompt=matches[0].resolve()))
    return specs


def codex_version(codex_bin: str) -> str:
    proc = subprocess.run(
        [codex_bin, "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    return (proc.stdout or proc.stderr).strip()


def configured_model(config_path: Path) -> str | None:
    if not config_path.exists():
        return None
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'(?m)^\s*model\s*=\s*"([^"]+)"\s*$', text)
    return match.group(1) if match else None


def has_failed_turn(stdout: str, stderr: str) -> tuple[bool, str]:
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") in {"turn.failed", "error"}:
            return True, str(event.get("error") or event.get("message") or "codex turn failed")
    for needle in MODEL_FAILURE_PATTERNS:
        if needle in stderr:
            return True, needle
    return False, ""


def run_probe(
    command: list[str],
    exec_options: list[str],
    prompt: str,
    timeout: int,
    *,
    cwd: Path | None = None,
) -> tuple[bool, str, str, str]:
    proc = subprocess.run(
        [*command, "exec", *exec_options, "--json", "--ephemeral", prompt],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        cwd=cwd,
    )
    failed, reason = has_failed_turn(proc.stdout, proc.stderr)
    if proc.returncode != 0 and not failed:
        failed = True
        reason = f"codex exited {proc.returncode}"
    return (not failed), reason, proc.stdout, proc.stderr


def resolve_runtime(
    *,
    codex_bin: str,
    workspace: Path,
    requested_model: str | None,
    config_path: Path,
    probe_timeout: int,
    skip_model_probe: bool,
) -> CodexRuntime:
    # Current Codex CLI removed the legacy `-a never` approval flag.  Use the
    # stable explicit non-interactive bypass flag so preflight and launched
    # workers exercise the same command surface.
    base = [
        codex_bin,
        "--dangerously-bypass-approvals-and-sandbox",
        "-C",
        str(workspace),
    ]
    model = requested_model if requested_model != "auto" else configured_model(config_path)

    candidates: list[tuple[list[str], list[str], str, str | None, bool]] = []
    if model:
        candidates.append(([*base, "-m", model], [], "requested_or_configured_model", model, False))
    candidates.append((base, ["--ignore-user-config"], "ignore_user_config_default_model", None, True))

    failures: list[dict[str, str | None]] = []
    for command, exec_options, mode, candidate_model, ignored in candidates:
        if skip_model_probe:
            return CodexRuntime(command, exec_options, mode, candidate_model, ignored, "", "")
        ok, reason, stdout, stderr = run_probe(
            command,
            exec_options,
            DEFAULT_MODEL_PROBE_PROMPT,
            probe_timeout,
            cwd=workspace,
        )
        if ok:
            return CodexRuntime(command, exec_options, mode, candidate_model, ignored, stdout, stderr)
        failures.append({"mode": mode, "model": candidate_model, "reason": reason})

    raise SystemExit(json.dumps({"error": "codex_worker_preflight_failed", "failures": failures}, indent=2))


def lint_worker_prompts(
    specs: list[WorkerSpec],
    workspace: Path,
    out_dir: Path,
    *,
    strict: bool,
) -> dict[str, dict[str, Any]]:
    lint = load_prompt_lint_module()
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: dict[str, dict[str, Any]] = {}
    failures: list[dict[str, Any]] = []
    for spec in specs:
        if not spec.prompt.exists():
            raise SystemExit(f"missing prompt file: {spec.prompt}")
        text = spec.prompt.read_text(encoding="utf-8")
        results = lint.lint(text, workspace=workspace)
        fail_rows = [row for row in results if row.status == lint.FAIL]
        warn_rows = [row for row in results if row.status == lint.WARN]
        report = out_dir / f"worker_{spec.lane.lower()}_prompt_lint.json"
        payload = {
            "schema": "auditooor.codex_worker_prompt_lint.v1",
            "generated_at": utc_now(),
            "lane": spec.lane,
            "prompt": str(spec.prompt),
            "workspace": str(workspace),
            "strict": strict,
            "pass_count": sum(1 for row in results if row.status == lint.PASS),
            "warn_count": len(warn_rows),
            "fail_count": len(fail_rows),
            "results": [
                {
                    "rule": row.rule,
                    "status": row.status,
                    "message": row.message,
                    "matched_phrase": row.matched_phrase,
                }
                for row in results
            ],
        }
        report.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rows[spec.lane] = {
            "report": str(report),
            "status": "fail" if fail_rows else "pass",
            "fail_count": len(fail_rows),
            "warn_count": len(warn_rows),
        }
        if fail_rows:
            failures.append({"lane": spec.lane, "prompt": str(spec.prompt), "report": str(report), "fail_count": len(fail_rows)})
    if strict and failures:
        raise SystemExit(json.dumps({"error": "codex_worker_prompt_lint_failed", "failures": failures}, indent=2))
    return rows


def launch_workers(
    runtime: CodexRuntime,
    specs: list[WorkerSpec],
    workspace: Path,
    out_dir: Path,
    manifest: Path,
    startup_grace: int,
    dry_run: bool,
    prompt_lint: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    processes: list[tuple[subprocess.Popen[str], dict[str, Any]]] = []
    started_at = utc_now()

    for spec in specs:
        if not spec.prompt.exists():
            raise SystemExit(f"missing prompt file: {spec.prompt}")
        log = out_dir / f"worker_{spec.lane.lower()}_codex.log"
        err = out_dir / f"worker_{spec.lane.lower()}_codex.err"
        row: dict[str, Any] = {
            "lane": spec.lane,
            "prompt": str(spec.prompt),
            "log": str(log),
            "err": str(err),
            "started_at": started_at,
            "status": "dry_run" if dry_run else "starting",
            "runtime_mode": runtime.mode,
            "model": runtime.model or "codex_cli_default",
            "ignored_user_config": runtime.ignored_user_config,
        }
        if prompt_lint and spec.lane in prompt_lint:
            row["prompt_lint"] = prompt_lint[spec.lane]
        rows.append(row)
        if dry_run:
            continue
        with spec.prompt.open("r", encoding="utf-8") as prompt_in, log.open("w", encoding="utf-8") as log_out, err.open(
            "w", encoding="utf-8"
        ) as err_out:
            proc = subprocess.Popen(
                [*runtime.command, "exec", *runtime.exec_options, "--json"],
                cwd=workspace,
                stdin=prompt_in,
                stdout=log_out,
                stderr=err_out,
                text=True,
                start_new_session=True,
            )
        row["pid"] = proc.pid
        processes.append((proc, row))

    if not dry_run:
        deadline = time.time() + startup_grace
        while time.time() < deadline:
            failed = [(proc, row) for proc, row in processes if proc.poll() is not None]
            if failed:
                for proc, row in processes:
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGTERM)
                    row["status"] = "startup_failed" if proc.poll() is not None else "terminated_after_peer_startup_failure"
                    row["exit_code"] = proc.poll()
                payload = manifest_payload(runtime, rows, workspace, startup_ok=False)
                write_manifest(manifest, payload)
                raise SystemExit(1)
            time.sleep(0.5)
        for _proc, row in processes:
            row["status"] = "running"
            row["startup_grace_passed_sec"] = startup_grace

    payload = manifest_payload(runtime, rows, workspace, startup_ok=not dry_run)
    write_manifest(manifest, payload)
    return payload


def manifest_payload(runtime: CodexRuntime, rows: list[dict[str, Any]], workspace: Path, startup_ok: bool) -> dict[str, Any]:
    launch_mode = "dry_run" if all(row.get("status") == "dry_run" for row in rows) else "spawn"
    return {
        "schema": "auditooor.codex_worker_manifest.v2",
        "generated_at": utc_now(),
        "workspace": str(workspace),
        "launch_mode": launch_mode,
        "preflight_ok": True,
        "startup_ok": startup_ok,
        "runtime": {
            "mode": runtime.mode,
            "model": runtime.model or "codex_cli_default",
            "ignored_user_config": runtime.ignored_user_config,
        },
        "workers": rows,
    }


def write_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--prompt", action="append", default=[], help="Worker prompt file. Repeatable.")
    parser.add_argument("--prompt-dir", default="")
    parser.add_argument("--lanes", default="", help="Comma-separated lane names used with --prompt-dir.")
    parser.add_argument("--manifest", default="")
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--codex-bin", default=shutil.which("codex") or "codex")
    parser.add_argument("--model", default=os.environ.get("CODEX_WORKER_MODEL", "auto"))
    parser.add_argument("--config-path", default=str(Path.home() / ".codex" / "config.toml"))
    parser.add_argument("--probe-timeout", type=int, default=45)
    parser.add_argument("--startup-grace", type=int, default=20)
    parser.add_argument("--skip-model-probe", action="store_true")
    parser.add_argument("--skip-prompt-lint", action="store_true", help="Bypass strict agent-dispatch-prompt-lint gate.")
    parser.add_argument("--dry-run", action="store_true", help="Run preflight and write manifest, but do not spawn workers.")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else workspace / ".auditooor" / "agent_runs"
    manifest = (
        Path(args.manifest).expanduser().resolve()
        if args.manifest
        else out_dir / f"codex_worker_manifest_{int(time.time())}.json"
    )

    specs = parse_worker_specs(args.prompt)
    if args.prompt_dir or args.lanes:
        if not args.prompt_dir or not args.lanes:
            raise SystemExit("--prompt-dir and --lanes must be provided together")
        specs.extend(load_prompt_dir(Path(args.prompt_dir).expanduser().resolve(), args.lanes))
    if not specs:
        raise SystemExit("provide at least one --prompt, or --prompt-dir with --lanes")

    prompt_lint = lint_worker_prompts(
        specs,
        workspace,
        out_dir,
        strict=not args.skip_prompt_lint,
    )
    runtime = resolve_runtime(
        codex_bin=args.codex_bin,
        workspace=workspace,
        requested_model=args.model,
        config_path=Path(args.config_path).expanduser(),
        probe_timeout=args.probe_timeout,
        skip_model_probe=args.skip_model_probe,
    )
    payload = launch_workers(
        runtime,
        specs,
        workspace,
        out_dir,
        manifest,
        startup_grace=args.startup_grace,
        dry_run=args.dry_run,
        prompt_lint=prompt_lint,
    )
    payload["codex_version"] = codex_version(args.codex_bin)
    write_manifest(manifest, payload)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[codex-worker-launcher] manifest={manifest} mode={runtime.mode} workers={len(specs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
