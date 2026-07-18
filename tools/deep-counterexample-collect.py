#!/usr/bin/env python3
"""Collect fuzz/symbolic runner counterexamples into deep_counterexample.v1.

The existing runners already emit manifests. This collector is the safe bridge:
it converts ``status=counterexample`` manifests into the shared schema, while
keeping them advisory unless the operator supplies a generated Forge replay
test path.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RECORDER = ROOT / "tools" / "deep-counterexample-record.py"
QUEUE_BUILDER = ROOT / "tools" / "deep-counterexample-queue.py"


def slug(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9_.-]+", "-", value)
    return value.strip("-") or "counterexample"


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def iter_manifests(workspace: Path) -> list[Path]:
    return sorted(workspace.glob("fuzz_runs/**/manifest.json")) + sorted(
        workspace.glob("symbolic_runs/**/manifest.json")
    )


def engine_for(manifest: dict[str, Any], path: Path) -> str:
    raw = str(manifest.get("engine") or "")
    if raw in {"medusa", "echidna"}:
        return raw
    if raw in {"halmos", "kontrol"}:
        return raw
    if "fuzz_runs" in path.parts:
        return "forge-fuzz"
    return "halmos"


def target_for(manifest: dict[str, Any], path: Path) -> str:
    contract = str(manifest.get("contract") or manifest.get("test_contract") or "").strip()
    angle = str(manifest.get("angle") or "").strip()
    if contract and angle:
        return f"{contract}.{angle}"
    if contract:
        return contract
    return path.parent.name


def input_sequence_for(manifest_path: Path, ce_path: str) -> str:
    if not ce_path:
        return ""
    path = Path(ce_path)
    if not path.is_absolute():
        path = manifest_path.parent / path
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ce_path
    return text or ce_path


def collect_one(workspace: Path, manifest_path: Path, out_dir: Path, forge_test: str) -> dict[str, Any] | None:
    manifest = load_json(manifest_path)
    if not manifest or manifest.get("status") != "counterexample":
        return None
    engine = engine_for(manifest, manifest_path)
    target = target_for(manifest, manifest_path)
    ce_path = str(manifest.get("counterexample_path") or "")
    input_sequence = input_sequence_for(manifest_path, ce_path)
    command = str(manifest.get("command") or "")
    replay_command = command if forge_test else ""
    impossible = "" if forge_test else "runner produced a counterexample trace, but no generated Forge replay test path was supplied"
    out_json = out_dir / f"{slug(engine + '-' + target + '-' + manifest_path.parent.name)}.deep_counterexample.v1.json"
    argv = [
        sys.executable,
        str(RECORDER),
        "--workspace",
        str(workspace),
        "--engine",
        engine,
        "--target-function",
        target,
        "--expected-invariant",
        f"{engine} property run should not produce a counterexample",
        "--observed-violation",
        f"{manifest_path} reported status=counterexample; trace={ce_path or 'not recorded'}",
        "--input-sequence",
        input_sequence,
        "--out-json",
        str(out_json),
    ]
    if forge_test:
        argv.extend(["--replay-command", replay_command or f"forge test --match-path {forge_test}"])
        argv.extend(["--generated-forge-test-path", forge_test])
    else:
        argv.extend(["--replay-impossible-reason", impossible])
    subprocess.run(argv, check=True)
    return load_json(out_json)


def refresh_execution_queue(workspace: Path) -> dict[str, Any] | None:
    subprocess.run(
        [
            sys.executable,
            str(QUEUE_BUILDER),
            "--workspace",
            str(workspace),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    queue_path = workspace / "deep_counterexamples" / "execution_queue.json"
    data = load_json(queue_path)
    return data if isinstance(data, dict) else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument(
        "--generated-forge-test-path",
        default="",
        help="Optional replay test path. Without this, collected records stay advisory.",
    )
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[deep-counterexample-collect] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    out_dir = args.out_dir.expanduser().resolve() if args.out_dir else ws / "deep_counterexamples"
    out_dir.mkdir(parents=True, exist_ok=True)
    records = [
        record
        for path in iter_manifests(ws)
        for record in [collect_one(ws, path, out_dir, args.generated_forge_test_path)]
        if record
    ]
    payload = {
        "schema_version": "auditooor.deep_counterexample_collect.v1",
        "workspace": str(ws),
        "manifest_count": len(iter_manifests(ws)),
        "counterexample_count": len(records),
        "records": records,
    }
    default_deep_dir = ws / "deep_counterexamples"
    if out_dir == default_deep_dir:
        queue_payload = refresh_execution_queue(ws)
        payload["queue_refresh"] = {
            "status": "ok" if queue_payload else "missing_queue_payload",
            "execution_queue_path": str(default_deep_dir / "execution_queue.json"),
            "execution_queue_md_path": str(default_deep_dir / "execution_queue.md"),
            "queued_record_count": int(queue_payload.get("record_count", 0)) if isinstance(queue_payload, dict) else 0,
        }
    else:
        payload["queue_refresh"] = {
            "status": "skipped",
            "reason": "non_default_out_dir",
            "execution_queue_path": str(default_deep_dir / "execution_queue.json"),
        }
    (out_dir / "collection_manifest.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[deep-counterexample-collect] OK counterexamples={len(records)} out={out_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
