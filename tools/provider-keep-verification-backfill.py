#!/usr/bin/env python3
"""Create bounded local verification backfill packets for provider KEEP rows.

The tool is intentionally offline-only: it reads local JSON/JSONL/text
artifacts and emits JSON/Markdown work packets. It never executes suggested
commands and never performs network access.

Usage:
    python3 tools/provider-keep-verification-backfill.py \
        --input-json reports/provider_fanout_discipline.json --out-json out.json
    python3 tools/provider-keep-verification-backfill.py \
        --workspace /path/to/ws --scan-workspace --out-json out.json --out-md out.md
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA = "auditooor.provider_keep_verification_backfill.v1"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LIMIT = 50

KEEP_VERDICTS: tuple[str, ...] = (
    "KEEP_FOR_LOCAL_VERIFICATION",
    "KEEP",
    '"verdict": "KEEP"',
    '"verdict":"KEEP"',
    '"verdict": "keep"',
    '"verdict":"keep"',
)

LOCAL_VERIFICATION_SIGNALS: tuple[str, ...] = (
    "rg ",
    "ripgrep",
    "grep ",
    "forge test",
    "go test",
    "python3 -m pytest",
    "python -m pytest",
    "source_ref",
    "source-ref",
    "test_pass",
    "PASS:",
    "test-harness",
    "harness",
    "fixture",
    "local_verification_required",
    "minimum_followup_check",
    "local_checks_required",
    "rg_cmd",
    "smoke_check",
)

SOURCE_PATH_RE = re.compile(
    r"\b(?:tools|docs|reference|audit|audits|agent_outputs|detectors|reports)/[A-Za-z0-9_./:@+-]+"
)
CODE_TOKEN_RE = re.compile(r"`([^`\n]{3,120})`|['\"]([A-Za-z_][A-Za-z0-9_:.()-]{3,120})['\"]")
KEEP_GAP_RE = re.compile(
    r"gap:keep-missing-local-verification:\s+(?P<output_file>.+?)\s+"
    r"\(task_type=(?P<task_type>[^,]+),\s+ts=(?P<ts>[^)]+)\)"
)


def _utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read_text(path: Path, limit: int = 40000) -> str:
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _unique(values: Iterable[Any], *, limit: int = 8) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None or isinstance(value, bool):
            continue
        text = re.sub(r"\s+", " ", str(value)).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _has_keep(text: str) -> bool:
    if any(token in text for token in KEEP_VERDICTS):
        return True
    return False


def _has_local_verification(text: str) -> bool:
    return any(signal in text for signal in LOCAL_VERIFICATION_SIGNALS)


def _guess_provider(path_or_row: str | dict[str, Any]) -> str:
    if isinstance(path_or_row, dict):
        for key in ("provider", "llm_provider", "model_provider"):
            value = path_or_row.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        text = " ".join(str(path_or_row.get(k) or "") for k in ("provider_output_path", "output_file", "path"))
    else:
        text = path_or_row
    low = text.lower()
    if "kimi" in low:
        return "kimi"
    if "minimax" in low:
        return "minimax"
    if "claude" in low or "anthropic" in low:
        return "anthropic"
    return "unknown"


def _task_type(row: dict[str, Any]) -> str:
    for key in ("task_type", "template", "template_id", "task", "route"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def _source_file(row: dict[str, Any]) -> str:
    for key in ("source_file", "output_file", "provider_output_path", "path", "file"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _text_excerpt(text: str, limit: int = 240) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _candidate_patterns(text: str, row: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    values.extend(re.findall(r"`([^`\n]{3,120})`", text))
    for key in ("candidate_id", "claim_id", "finding_id", "detector", "symbol", "function"):
        if row.get(key):
            values.append(row[key])
    for match in CODE_TOKEN_RE.finditer(text):
        value = match.group(1) or match.group(2)
        if value not in {"candidate_id", "verdict", "reason", "notes", "summary"}:
            values.append(value)
    values.extend(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{5,}\b", text[:2500]))
    return _unique((value for value in values if 3 <= len(str(value)) <= 120), limit=4)


def _source_hints(text: str, row: dict[str, Any], source_file: str) -> list[str]:
    hints: list[Any] = []
    for key in ("source_file", "file_path", "path", "output_file", "provider_output_path"):
        if row.get(key):
            hints.append(row[key])
    hints.extend(SOURCE_PATH_RE.findall(text))
    if source_file:
        hints.append(source_file)
    return _unique(hints, limit=6)


def _suggested_local_commands(text: str, row: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    patterns = _candidate_patterns(text, row)
    hints = _source_hints(text, row, source_file)
    pattern = patterns[0] if patterns else "KEEP_FOR_LOCAL_VERIFICATION"
    source_target = hints[0] if hints else "<workspace-local-source-path>"
    return [
        {
            "kind": "rg",
            "command": f"rg -n {shlex.quote(pattern)} {shlex.quote(source_target)}",
            "placeholder_only": True,
            "executes": False,
            "purpose": "Find local source references for the provider KEEP claim.",
        },
        {
            "kind": "source",
            "command": f"source-inspect {shlex.quote(source_file or '<provider-output-file>')}",
            "placeholder_only": True,
            "executes": False,
            "purpose": "Inspect the provider artifact and any cited local source files.",
        },
        {
            "kind": "test",
            "command": "test-placeholder <targeted-local-regression-or-harness>",
            "placeholder_only": True,
            "executes": False,
            "purpose": "Add or run a focused local regression after source evidence exists.",
        },
    ]


def _missing_reason(
    source_file: str,
    text: str,
    row: dict[str, Any],
    *,
    from_discipline_report: bool,
) -> str:
    explicit = row.get("missing_verification_reason") or row.get("reason")
    if isinstance(explicit, str) and explicit.startswith("keep"):
        return explicit
    if not source_file:
        return "missing_provider_output_path"
    if not text and not from_discipline_report:
        return "provider_output_file_missing_or_unreadable"
    if _has_keep(text) and not _has_local_verification(text):
        return "keep_without_local_verification_signal"
    if from_discipline_report:
        return "discipline_check_reported_keep_missing_local_verification"
    return "unknown_missing_local_verification"


def _packet_from_row(
    row: dict[str, Any],
    ordinal: int,
    workspace: Path,
    *,
    source_report: str,
    from_discipline_report: bool = False,
) -> dict[str, Any]:
    source_file = _source_file(row)
    source_path = Path(source_file).expanduser() if source_file else None
    if source_path is not None and not source_path.is_absolute():
        source_path = workspace / source_path
    text = _read_text(source_path) if source_path is not None else ""
    provider = _guess_provider(row if row.get("provider") else source_file)
    task_type = _task_type(row)
    reason = _missing_reason(source_file, text, row, from_discipline_report=from_discipline_report)
    return {
        "packet_id": f"KEEP-BACKFILL-{ordinal:03d}",
        "source_file": source_file,
        "dispatch_audit": row.get("dispatch_audit") or row.get("dispatch_audit_path") or "",
        "provider": provider,
        "model": row.get("model") or "",
        "task_type": task_type,
        "task_id": row.get("task_id") or row.get("template_id") or row.get("prompt_sha256") or "",
        "missing_verification_reason": reason,
        "suggested_local_commands": _suggested_local_commands(text, row, source_file),
        "evidence": {
            "keep_signal": bool(_has_keep(text) or from_discipline_report),
            "local_verification_signal": bool(_has_local_verification(text)),
            "excerpt": _text_excerpt(text),
        },
        "source_report": source_report,
        "packet_status": "pending_local_verification_backfill",
        "advisory_only": True,
        "offline_only": True,
        "network_allowed": False,
        "shell_executed": False,
        "promotion_authority": False,
    }


def _discipline_examples(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    candidates: list[Any] = []
    sub = payload.get("sub_results")
    if isinstance(sub, dict):
        keep = sub.get("keep_local_verification")
        if isinstance(keep, dict):
            candidates.append(keep.get("keep_missing_verification_examples"))
    candidates.append(payload.get("keep_missing_verification_examples"))
    candidates.append(payload.get("rows"))

    rows: list[dict[str, Any]] = []
    for candidate in candidates:
        if isinstance(candidate, list):
            rows.extend(item for item in candidate if isinstance(item, dict))

    keep_result = sub.get("keep_local_verification") if isinstance(sub, dict) else None
    gaps = keep_result.get("gaps") if isinstance(keep_result, dict) else payload.get("gaps")
    if isinstance(gaps, list):
        for gap in gaps:
            if not isinstance(gap, str):
                continue
            match = KEEP_GAP_RE.search(gap)
            if not match:
                continue
            output_file = match.group("output_file").strip()
            task_type = match.group("task_type").strip().strip("'\"")
            ts = match.group("ts").strip().strip("'\"")
            rows.append(
                {
                    "output_file": output_file,
                    "task_type": task_type,
                    "template_id": task_type,
                    "ts": ts,
                    "provider": _guess_provider(output_file),
                }
            )
    return rows


def _scan_workspace_rows(workspace: Path, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for audit_path in sorted(workspace.rglob("dispatch_audit.jsonl")):
        for audit_row in _load_jsonl(audit_path):
            status = str(audit_row.get("status") or "")
            if status and status != "DISPATCHED":
                continue
            output = audit_row.get("provider_output_path") or audit_row.get("output_file")
            if not isinstance(output, str) or not output.strip():
                continue
            output_path = Path(output).expanduser()
            if not output_path.is_absolute():
                output_path = workspace / output_path
            text = _read_text(output_path)
            if not _has_keep(text) or _has_local_verification(text):
                continue
            row = dict(audit_row)
            row["output_file"] = str(output_path)
            row["dispatch_audit"] = str(audit_path)
            row.setdefault("provider", _guess_provider(row))
            rows.append(row)
            if len(rows) >= limit:
                return rows
    return rows


def _dedupe_rows(rows: Iterable[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (
            _source_file(row),
            str(row.get("dispatch_audit") or row.get("dispatch_audit_path") or ""),
            _task_type(row),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
        if len(out) >= limit:
            break
    return out


def build_backfill(
    *,
    workspace: Path = ROOT,
    input_json: Path | None = None,
    scan_workspace: bool = False,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    ws = workspace.expanduser().resolve()
    rows: list[dict[str, Any]]
    source_mode: str
    source_report = ""

    if input_json is not None:
        payload = _load_json(input_json)
        rows = _discipline_examples(payload)
        source_mode = "input_json"
        source_report = str(input_json)
        from_report = True
    else:
        rows = _scan_workspace_rows(ws, limit)
        source_mode = "workspace_scan" if scan_workspace else "workspace_scan_default"
        source_report = str(ws)
        from_report = False

    bounded_rows = _dedupe_rows(rows, limit)
    packets = [
        _packet_from_row(
            row,
            index,
            ws,
            source_report=source_report,
            from_discipline_report=from_report,
        )
        for index, row in enumerate(bounded_rows, start=1)
    ]
    by_provider = Counter(packet["provider"] for packet in packets)
    by_task_type = Counter(packet["task_type"] for packet in packets)
    by_reason = Counter(packet["missing_verification_reason"] for packet in packets)
    return {
        "schema": SCHEMA,
        "generated_at_utc": _utcnow(),
        "workspace": str(ws),
        "source_mode": source_mode,
        "source_report": source_report,
        "offline_only": True,
        "network_allowed": False,
        "shell_executed": False,
        "advisory_only": True,
        "limit": limit,
        "summary": {
            "packet_count": len(packets),
            "by_provider": dict(sorted(by_provider.items())),
            "by_task_type": dict(sorted(by_task_type.items())),
            "by_missing_verification_reason": dict(sorted(by_reason.items())),
        },
        "packets": packets,
        "status": "packets_ready" if packets else "empty_no_keep_rows_missing_local_verification",
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Provider KEEP Verification Backfill",
        "",
        "Offline advisory packets for KEEP verdicts that still need local verification.",
        "",
        f"- source mode: `{payload['source_mode']}`",
        f"- packet count: `{payload['summary']['packet_count']}`",
        f"- shell executed: `{payload['shell_executed']}`",
        f"- network allowed: `{payload['network_allowed']}`",
        "",
        "| Packet | Source file | Provider | Task type | Missing reason | Suggested rg |",
        "|---|---|---|---|---|---|",
    ]
    for packet in payload["packets"]:
        rg_cmd = next(
            (cmd["command"] for cmd in packet["suggested_local_commands"] if cmd.get("kind") == "rg"),
            "",
        )
        values = [
            packet["packet_id"],
            packet["source_file"],
            packet["provider"],
            packet["task_type"],
            packet["missing_verification_reason"],
            rg_cmd,
        ]
        escaped = [str(value).replace("|", "\\|") for value in values]
        lines.append(
            f"| `{escaped[0]}` | `{escaped[1]}` | `{escaped[2]}` | `{escaped[3]}` | "
            f"`{escaped[4]}` | `{escaped[5]}` |"
        )
    lines.append("")
    return "\n".join(lines)


def write_outputs(payload: dict[str, Any], out_json: Path | None, out_md: Path | None) -> None:
    if out_json is not None:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if out_md is not None:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_markdown(payload), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--input-json", type=Path, default=None)
    parser.add_argument("--scan-workspace", action="store_true")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--out-md", type=Path, default=None)
    parser.add_argument("--print-json", "--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    limit = max(1, args.limit)
    payload = build_backfill(
        workspace=args.workspace,
        input_json=args.input_json,
        scan_workspace=args.scan_workspace,
        limit=limit,
    )
    write_outputs(payload, args.out_json, args.out_md)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
