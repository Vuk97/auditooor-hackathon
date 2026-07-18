#!/usr/bin/env python3
"""Run a resumable Kimi -> Minimax zkBugs provider farming loop.

This is the live-call companion to ``zkbugs-brief-queue.py``. It intentionally
does not promote detectors or PoCs; it only turns queued briefs into durable
provider triage artifacts. Codex still owns the final evidence gate.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_QUEUE = ROOT / ".audit_logs" / "zkbugs_farming" / "provider_queue" / "zkbugs_provider_queue.json"
DEFAULT_OUT_DIR = ROOT / ".audit_logs" / "zkbugs_farming" / "provider_results"
DEFAULT_DISPATCH_TOOL = ROOT / "tools" / "llm-dispatch.py"
DEFAULT_RESULT_TOOL = ROOT / "tools" / "zkbugs-provider-result.py"


def _usable_output(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _row_slug(row: dict[str, Any]) -> str:
    index = int(row.get("index", 0))
    prompt = Path(str(row["kimi_prompt"]))
    return f"{index:03d}_{prompt.name.removesuffix('.kimi.md')}"


def _run_dispatch(
    *,
    dispatch_tool: Path,
    provider: str,
    prompt_file: Path,
    output_file: Path,
    stderr_file: Path,
    audit_dir: Path,
    max_tokens: int,
    timeout: int,
    dry_run: bool,
    operator_live_network_consent: bool,
) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(dispatch_tool),
        "--provider",
        provider,
        "--prompt-file",
        str(prompt_file),
        "--max-tokens",
        str(max_tokens),
        "--timeout",
        str(timeout),
        "--audit-dir",
        str(audit_dir),
    ]
    if operator_live_network_consent:
        cmd.append("--operator-live-network-consent")
    if dry_run:
        return {"status": "dry-run", "command": cmd}
    output_file.parent.mkdir(parents=True, exist_ok=True)
    stderr_file.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    # llm-dispatch honors AUDITOOOR_LLM_PROVIDER over --provider. Force the
    # phase provider so sourced operator env cannot turn Minimax kill-passes
    # back into Kimi calls.
    env["AUDITOOOR_LLM_PROVIDER"] = provider
    with output_file.open("w", encoding="utf-8") as out, stderr_file.open("w", encoding="utf-8") as err:
        proc = subprocess.run(cmd, stdout=out, stderr=err, text=True, check=False, env=env)
    return {"status": "ok" if proc.returncode == 0 else "failed", "returncode": proc.returncode, "command": cmd}


def _materialize_minimax_prompt(template: Path, kimi_output: Path, out_path: Path) -> None:
    prompt = template.read_text(encoding="utf-8").replace(
        "<PASTE_KIMI_JSON_HERE>",
        kimi_output.read_text(encoding="utf-8"),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(prompt, encoding="utf-8")


def _record_result(
    *,
    result_tool: Path,
    brief: Path,
    kimi_output: Path,
    minimax_output: Path,
    out_json: Path,
    out_md: Path,
    dry_run: bool,
) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(result_tool),
        "--brief",
        str(brief),
        "--kimi-output",
        str(kimi_output),
        "--minimax-output",
        str(minimax_output),
        "--out",
        str(out_json),
        "--out-md",
        str(out_md),
    ]
    if dry_run:
        return {"status": "dry-run", "command": cmd}
    out_json.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        return {"status": "failed", "returncode": proc.returncode, "stderr": proc.stderr, "command": cmd}
    return {"status": "ok", "returncode": proc.returncode, "command": cmd}


def run_loop(args: argparse.Namespace) -> dict[str, Any]:
    queue = _load_json(args.queue)
    rows = queue.get("rows", [])
    if not isinstance(rows, list):
        raise ValueError(f"queue rows must be a list in {args.queue}")

    selected = [row for row in rows if isinstance(row, dict)]
    if args.start_index > 1:
        selected = [row for row in selected if int(row.get("index", 0)) >= args.start_index]
    if args.limit > 0:
        selected = selected[: args.limit]

    out_dir = args.out_dir
    kimi_dir = out_dir / "kimi"
    minimax_prompt_dir = out_dir / "minimax_prompts"
    minimax_dir = out_dir / "minimax"
    final_dir = out_dir / "final"
    audit_dir = out_dir / "audit"
    rows_out: list[dict[str, Any]] = []

    for row in selected:
        slug = _row_slug(row)
        kimi_prompt = Path(str(row["kimi_prompt"]))
        minimax_template = Path(str(row["minimax_prompt_template"]))
        brief = Path(str(row["brief"]))
        kimi_output = kimi_dir / f"{slug}.kimi.out.json"
        kimi_stderr = kimi_dir / f"{slug}.kimi.stderr"
        minimax_prompt = minimax_prompt_dir / f"{slug}.minimax.md"
        minimax_output = minimax_dir / f"{slug}.minimax.out.json"
        minimax_stderr = minimax_dir / f"{slug}.minimax.stderr"
        result_json = final_dir / f"{slug}.provider-result.json"
        result_md = final_dir / f"{slug}.provider-result.md"

        row_result: dict[str, Any] = {
            "index": row.get("index"),
            "brief": str(brief),
            "slug": slug,
            "status": "pending",
            "kimi_output": str(kimi_output),
            "minimax_output": str(minimax_output),
            "provider_result": str(result_json),
        }

        if args.skip_existing and result_json.is_file():
            row_result["status"] = "skipped-existing-result"
            rows_out.append(row_result)
            continue

        if args.skip_existing and _usable_output(kimi_output):
            kimi_result = {"status": "skipped-existing-output"}
        else:
            kimi_result = _run_dispatch(
                dispatch_tool=args.dispatch_tool,
                provider="kimi",
                prompt_file=kimi_prompt,
                output_file=kimi_output,
                stderr_file=kimi_stderr,
                audit_dir=audit_dir,
                max_tokens=args.kimi_max_tokens,
                timeout=args.timeout,
                dry_run=args.dry_run,
                operator_live_network_consent=args.operator_live_network_consent,
            )
        row_result["kimi"] = kimi_result
        if kimi_result["status"] not in {"ok", "skipped-existing-output", "dry-run"}:
            row_result["status"] = "kimi-failed"
            rows_out.append(row_result)
            continue

        if not args.dry_run:
            _materialize_minimax_prompt(minimax_template, kimi_output, minimax_prompt)
        else:
            row_result["minimax_prompt"] = str(minimax_prompt)

        if args.skip_existing and _usable_output(minimax_output):
            minimax_result = {"status": "skipped-existing-output"}
        else:
            minimax_result = _run_dispatch(
                dispatch_tool=args.dispatch_tool,
                provider="minimax",
                prompt_file=minimax_prompt,
                output_file=minimax_output,
                stderr_file=minimax_stderr,
                audit_dir=audit_dir,
                max_tokens=args.minimax_max_tokens,
                timeout=args.timeout,
                dry_run=args.dry_run,
                operator_live_network_consent=args.operator_live_network_consent,
            )
        row_result["minimax"] = minimax_result
        if minimax_result["status"] not in {"ok", "skipped-existing-output", "dry-run"}:
            row_result["status"] = "minimax-failed"
            rows_out.append(row_result)
            continue

        record_result = _record_result(
            result_tool=args.result_tool,
            brief=brief,
            kimi_output=kimi_output,
            minimax_output=minimax_output,
            out_json=result_json,
            out_md=result_md,
            dry_run=args.dry_run,
        )
        row_result["record"] = record_result
        row_result["status"] = "ok" if record_result["status"] in {"ok", "dry-run"} else "record-failed"
        rows_out.append(row_result)

    summary: dict[str, int] = {}
    for row in rows_out:
        status = str(row.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "queue": str(args.queue),
        "out_dir": str(out_dir),
        "dry_run": bool(args.dry_run),
        "summary": dict(sorted(summary.items())),
        "rows": rows_out,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "zkbugs_provider_loop.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--dispatch-tool", type=Path, default=DEFAULT_DISPATCH_TOOL)
    parser.add_argument("--result-tool", type=Path, default=DEFAULT_RESULT_TOOL)
    parser.add_argument("--limit", type=int, default=0, help="Rows to process; 0 means all remaining")
    parser.add_argument("--start-index", type=int, default=1)
    parser.add_argument("--kimi-max-tokens", type=int, default=4000)
    parser.add_argument("--minimax-max-tokens", type=int, default=3000)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--no-skip-existing", dest="skip_existing", action="store_false")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument(
        "--operator-live-network-consent",
        action="store_true",
        help=(
            "Explicit operator consent for this live provider loop to make "
            "outbound LLM provider network calls. Passed through to "
            "llm-dispatch.py so each dispatch audit record carries the "
            "command-local consent source."
        ),
    )
    parser.set_defaults(skip_existing=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.queue.is_file():
        raise SystemExit(f"[zkbugs-provider-loop] missing queue manifest: {args.queue}")
    has_env_consent = os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1"
    if not args.dry_run and not (has_env_consent or args.operator_live_network_consent):
        raise SystemExit(
            "[zkbugs-provider-loop] pass --operator-live-network-consent or "
            "set AUDITOOOR_LLM_NETWORK_CONSENT=1 before live provider dispatch"
        )
    manifest = run_loop(args)
    if args.print_json:
        print(json.dumps({"summary": manifest["summary"], "out_dir": manifest["out_dir"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
