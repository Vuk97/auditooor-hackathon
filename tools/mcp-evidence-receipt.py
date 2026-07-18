#!/usr/bin/env python3
"""Build or validate auditooor.mcp_evidence_receipt.v1 sidecars."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from lib.mcp_evidence_receipt import (  # noqa: E402
    build_receipt,
    file_sha256,
    validate_receipt_file,
)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Build an MCP evidence receipt")
    build.add_argument("--workspace", type=Path, required=True)
    build.add_argument("--callable", required=True)
    build.add_argument("--context-pack-id", required=True)
    build.add_argument("--context-pack-hash", required=True)
    build.add_argument("--consumer-packet-hash", required=True)
    build.add_argument("--output-artifact", type=Path, required=True)
    build.add_argument("--required-call", action="append", default=[])
    build.add_argument("--source-file", action="append", default=[])
    build.add_argument("--args-json", default="{}")
    build.add_argument("--out", type=Path, default=None)

    check = sub.add_parser("validate", help="Validate an MCP evidence receipt")
    check.add_argument("receipt", type=Path)
    check.add_argument("--workspace", type=Path, default=None)
    check.add_argument("--consumer-packet-hash", default=None)
    check.add_argument("--required-call", action="append", default=[])
    check.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def _source_rows(paths: Sequence[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for value in paths:
        path = Path(value).expanduser()
        if path.is_file():
            rows.append({"path": value, "sha256": file_sha256(path)})
    return rows


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "build":
        try:
            args_payload = json.loads(args.args_json)
        except json.JSONDecodeError as exc:
            print(f"invalid --args-json: {exc}", file=sys.stderr)
            return 2
        try:
            artifact_hash = file_sha256(args.output_artifact.expanduser())
        except OSError as exc:
            print(f"cannot hash --output-artifact: {exc}", file=sys.stderr)
            return 2
        receipt = build_receipt(
            callable_name=args.callable,
            workspace=args.workspace,
            context_pack_id=args.context_pack_id,
            context_pack_hash=args.context_pack_hash,
            consumer_packet_hash=args.consumer_packet_hash,
            output_artifact_hash=artifact_hash,
            source_file_hashes=_source_rows(args.source_file),
            required_call_set=args.required_call,
            args=args_payload,
        )
        payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(payload, encoding="utf-8")
        else:
            print(payload, end="")
        return 0

    ok, errors, receipt = validate_receipt_file(
        args.receipt.expanduser(),
        workspace=args.workspace,
        consumer_packet_hash=args.consumer_packet_hash,
        required_call_set=args.required_call,
    )
    if args.json:
        print(json.dumps({"ok": ok, "errors": errors, "receipt": receipt}, indent=2, sort_keys=True))
    elif ok:
        print("mcp-evidence-receipt: ok")
    else:
        print("mcp-evidence-receipt: invalid: " + ", ".join(errors), file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

