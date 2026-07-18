#!/usr/bin/env python3
"""Append-only lane verdict bus.

The bus is intentionally small and file-backed:

  <workspace>/.auditooor/lane_verdict_bus/<lane-id>.jsonl
  <workspace>/.auditooor/lane_verdict_bus/aggregated.json

`append` writes one JSON object per line to a per-lane file. The write path
uses an exclusive file lock, O_APPEND, and a single os.write call so concurrent
appenders cannot clobber each other or interleave records.

CLI:
  python3 tools/lane-verdict-bus.py append --workspace <ws> --lane-id <id> \
    --candidate-id <id> --attack-class <class> --verdict DROPPED
  python3 tools/lane-verdict-bus.py read --workspace <ws> [--lane-id <id>]
  python3 tools/lane-verdict-bus.py aggregate --workspace <ws>
  python3 tools/lane-verdict-bus.py consult --workspace <ws> \
    [--candidate-id <id>] [--attack-class <class>] \
    [--filter verdict=DROPPED] [--limit N]
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback for importability.
    fcntl = None  # type: ignore[assignment]


RECORD_SCHEMA_VERSION = "auditooor.lane_verdict.v1"
APPEND_SCHEMA_VERSION = "auditooor.lane_verdict_bus.append.v1"
READ_SCHEMA_VERSION = "auditooor.lane_verdict_bus.read.v1"
AGGREGATE_SCHEMA_VERSION = "auditooor.lane_verdict_bus.aggregate.v1"
CONSULT_SCHEMA_VERSION = "auditooor.lane_verdict_bus.consult.v1"
BUS_REL = Path(".auditooor") / "lane_verdict_bus"
AGGREGATED_NAME = "aggregated.json"
LANE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
ALLOWED_RECORD_FIELDS = {
    "schema_version",
    "record_id",
    "timestamp",
    "lane_id",
    "sequence",
    "candidate_id",
    "attack_class",
    "verdict",
    "summary",
    "details",
    "evidence_refs",
    "metadata",
}


class BusError(RuntimeError):
    """Raised for user-facing bus errors."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def bus_dir(workspace: Path) -> Path:
    return workspace.expanduser() / BUS_REL


def validate_lane_id(lane_id: str) -> None:
    if not LANE_ID_RE.match(lane_id):
        raise BusError(
            "lane_id must match "
            f"{LANE_ID_RE.pattern!r}; path separators are not allowed"
        )


def lane_file(workspace: Path, lane_id: str) -> Path:
    validate_lane_id(lane_id)
    return bus_dir(workspace) / f"{lane_id}.jsonl"


def _normalise_verdict(verdict: str) -> str:
    text = verdict.strip().replace("-", "_").replace(" ", "_").upper()
    if not text:
        raise BusError("verdict must be non-empty")
    return text


def _parse_json_value(value: str) -> dict[str, Any]:
    if value.startswith("@"):
        path = Path(value[1:]).expanduser()
        try:
            value = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise BusError(f"cannot read record JSON file {path}: {exc}") from exc
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise BusError(f"invalid record JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BusError("record JSON must decode to an object")
    return data


def _parse_key_value(items: Sequence[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise BusError(f"expected key=value item, got {item!r}")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise BusError(f"empty key in key=value item {item!r}")
        out[key] = value
    return out


def _record_digest(record: Mapping[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def validate_record(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    required = (
        "schema_version",
        "record_id",
        "timestamp",
        "lane_id",
        "sequence",
        "candidate_id",
        "attack_class",
        "verdict",
    )
    for field in required:
        if field not in record:
            errors.append(f"missing required field {field!r}")
    if record.get("schema_version") != RECORD_SCHEMA_VERSION:
        errors.append(
            "schema_version must be "
            f"{RECORD_SCHEMA_VERSION!r}, got {record.get('schema_version')!r}"
        )
    lane_id = record.get("lane_id")
    if not isinstance(lane_id, str) or not LANE_ID_RE.match(lane_id):
        errors.append("lane_id must be a safe non-empty string")
    sequence = record.get("sequence")
    if not isinstance(sequence, int) or sequence < 1:
        errors.append("sequence must be a positive integer")
    for field in ("record_id", "timestamp", "candidate_id", "attack_class", "verdict"):
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} must be a non-empty string")
    evidence_refs = record.get("evidence_refs")
    if evidence_refs is not None and (
        not isinstance(evidence_refs, list)
        or not all(isinstance(item, str) for item in evidence_refs)
    ):
        errors.append("evidence_refs must be an array of strings")
    metadata = record.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        errors.append("metadata must be an object")
    return errors


@contextlib.contextmanager
def _locked_append_file(path: Path) -> Iterator[int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_all_from_fd(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _records_from_bytes(raw: bytes, path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not raw:
        return records
    for lineno, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BusError(f"{path}:{lineno}: invalid JSONL record: {exc}") from exc
        if not isinstance(record, dict):
            raise BusError(f"{path}:{lineno}: record must be a JSON object")
        records.append(record)
    return records


def _max_sequence_from_records(records: Iterable[Mapping[str, Any]]) -> int:
    max_sequence = 0
    for record in records:
        if isinstance(record.get("sequence"), int):
            max_sequence = max(max_sequence, int(record["sequence"]))
    return max_sequence


def _metadata_verdict_hash(record: Mapping[str, Any]) -> str:
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping):
        return ""
    value = metadata.get("verdict_hash")
    return str(value).strip() if value is not None else ""


def _is_duplicate_verdict(
    existing: Mapping[str, Any],
    *,
    lane_id: str,
    candidate_id: str,
    verdict_hash: str,
) -> bool:
    return (
        verdict_hash != ""
        and existing.get("lane_id") == lane_id
        and existing.get("candidate_id") == candidate_id
        and _metadata_verdict_hash(existing) == verdict_hash
    )


def build_record(
    *,
    lane_id: str,
    sequence: int,
    candidate_id: str | None,
    attack_class: str | None,
    verdict: str | None,
    summary: str = "",
    details: str = "",
    evidence_refs: Sequence[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    base: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    validate_lane_id(lane_id)
    record: dict[str, Any] = {
        key: value for key, value in dict(base or {}).items()
        if key in ALLOWED_RECORD_FIELDS
    }
    record["schema_version"] = RECORD_SCHEMA_VERSION
    record["lane_id"] = lane_id
    record["sequence"] = sequence
    record.setdefault("timestamp", utc_now())
    record["candidate_id"] = str(candidate_id or record.get("candidate_id") or "unknown").strip()
    record["attack_class"] = str(attack_class or record.get("attack_class") or "unknown").strip()
    record["verdict"] = _normalise_verdict(str(verdict or record.get("verdict") or "UNKNOWN"))
    if summary:
        record["summary"] = summary
    else:
        record.setdefault("summary", "")
    if details:
        record["details"] = details
    else:
        record.setdefault("details", "")
    refs = list(evidence_refs or record.get("evidence_refs") or [])
    record["evidence_refs"] = [str(item) for item in refs]
    merged_metadata: dict[str, Any] = {}
    prior_metadata = record.get("metadata")
    if isinstance(prior_metadata, dict):
        merged_metadata.update(prior_metadata)
    if metadata:
        merged_metadata.update(metadata)
    record["metadata"] = merged_metadata
    record.setdefault("record_id", "")
    if not str(record["record_id"]).strip():
        digest_input = dict(record)
        digest_input.pop("record_id", None)
        record["record_id"] = "lv-" + _record_digest(digest_input)
    errors = validate_record(record)
    if errors:
        raise BusError("; ".join(errors))
    return record


def append_record(
    workspace: Path,
    *,
    lane_id: str,
    candidate_id: str | None,
    attack_class: str | None,
    verdict: str | None,
    summary: str = "",
    details: str = "",
    evidence_refs: Sequence[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    base: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], Path, str]:
    path = lane_file(workspace, lane_id)
    with _locked_append_file(path) as fd:
        existing_records = _records_from_bytes(_read_all_from_fd(fd), path)
        candidate = str(candidate_id or (base or {}).get("candidate_id") or "unknown").strip()
        verdict_hash = ""
        if metadata:
            value = metadata.get("verdict_hash")
            verdict_hash = str(value).strip() if value is not None else ""
        for existing in existing_records:
            if _is_duplicate_verdict(
                existing,
                lane_id=lane_id,
                candidate_id=candidate,
                verdict_hash=verdict_hash,
            ):
                return dict(existing), path, "duplicate"
        max_sequence = _max_sequence_from_records(existing_records)
        record = build_record(
            lane_id=lane_id,
            sequence=max_sequence + 1,
            candidate_id=candidate_id,
            attack_class=attack_class,
            verdict=verdict,
            summary=summary,
            details=details,
            evidence_refs=evidence_refs,
            metadata=metadata,
            base=base,
        )
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    return record, path, "appended"


def _lane_files(workspace: Path, lane_id: str | None = None) -> list[Path]:
    root = bus_dir(workspace)
    if lane_id:
        return [lane_file(workspace, lane_id)] if lane_file(workspace, lane_id).exists() else []
    if not root.is_dir():
        return []
    return sorted(
        (
            path for path in root.glob("*.jsonl")
            if path.is_file() and path.name != AGGREGATED_NAME
        ),
        key=lambda path: path.name,
    )


def _read_lane_path(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BusError(f"cannot read {path}: {exc}") from exc
    for lineno, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BusError(f"{path}:{lineno}: invalid JSONL record: {exc}") from exc
        if not isinstance(data, dict):
            raise BusError(f"{path}:{lineno}: record must be a JSON object")
        errors = validate_record(data)
        if errors:
            raise BusError(f"{path}:{lineno}: invalid record: {'; '.join(errors)}")
        records.append(data)
    return records


def read_records(workspace: Path, lane_id: str | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in _lane_files(workspace, lane_id=lane_id):
        records.extend(_read_lane_path(path))
    return sorted(records, key=_record_sort_key)


def _record_sort_key(record: Mapping[str, Any]) -> tuple[str, int, str, str, str]:
    return (
        str(record.get("lane_id") or ""),
        int(record.get("sequence") or 0),
        str(record.get("timestamp") or ""),
        str(record.get("candidate_id") or ""),
        str(record.get("record_id") or ""),
    )


def aggregate_records(workspace: Path) -> dict[str, Any]:
    records = read_records(workspace)
    lanes = []
    for lane_id in sorted({str(record["lane_id"]) for record in records}):
        lane_records = [record for record in records if record["lane_id"] == lane_id]
        lanes.append({
            "lane_id": lane_id,
            "record_count": len(lane_records),
            "latest_sequence": max(int(record["sequence"]) for record in lane_records),
        })
    by_candidate = Counter(str(record["candidate_id"]) for record in records)
    by_attack_class = Counter(str(record["attack_class"]) for record in records)
    by_verdict = Counter(str(record["verdict"]) for record in records)
    return {
        "schema_version": AGGREGATE_SCHEMA_VERSION,
        "generated_at": "not-recorded-for-idempotence",
        "workspace": str(workspace.expanduser()),
        "bus_dir": str(bus_dir(workspace)),
        "bus_empty": len(records) == 0,
        "lane_count": len(lanes),
        "record_count": len(records),
        "lanes": lanes,
        "by_candidate": dict(sorted(by_candidate.items())),
        "by_attack_class": dict(sorted(by_attack_class.items())),
        "by_verdict": dict(sorted(by_verdict.items())),
        "records": records,
    }


def write_aggregate_snapshot(workspace: Path) -> tuple[dict[str, Any], Path]:
    payload = aggregate_records(workspace)
    root = bus_dir(workspace)
    root.mkdir(parents=True, exist_ok=True)
    path = root / AGGREGATED_NAME
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return payload, path


def _get_field(record: Mapping[str, Any], key: str) -> Any:
    current: Any = record
    for part in key.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def filter_records(
    records: Iterable[dict[str, Any]],
    *,
    candidate_id: str | None = None,
    attack_class: str | None = None,
    filters: Mapping[str, str] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    if limit is not None and limit < 0:
        raise BusError("limit must be >= 0")
    if limit == 0:
        return []
    out: list[dict[str, Any]] = []
    for record in records:
        if candidate_id is not None and record.get("candidate_id") != candidate_id:
            continue
        if attack_class is not None and record.get("attack_class") != attack_class:
            continue
        matched = True
        for key, value in (filters or {}).items():
            if str(_get_field(record, key)) != value:
                matched = False
                break
        if not matched:
            continue
        out.append(record)
        if limit is not None and len(out) >= limit:
            break
    return out


def _emit(payload: Mapping[str, Any], *, pretty: bool = False) -> None:
    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(json.dumps(payload, sort_keys=True))


def cmd_append(args: argparse.Namespace) -> int:
    base = _parse_json_value(args.record_json) if args.record_json else None
    metadata = _parse_key_value(args.metadata)
    record, path, classification = append_record(
        Path(args.workspace),
        lane_id=args.lane_id,
        candidate_id=args.candidate_id,
        attack_class=args.attack_class,
        verdict=args.verdict,
        summary=args.summary,
        details=args.details,
        evidence_refs=args.evidence_ref,
        metadata=metadata,
        base=base,
    )
    _emit({
        "schema_version": APPEND_SCHEMA_VERSION,
        "classification": classification,
        "path": str(path),
        "record": record,
    }, pretty=args.pretty)
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    records = read_records(Path(args.workspace), lane_id=args.lane_id)
    lanes = sorted({str(record["lane_id"]) for record in records})
    _emit({
        "schema_version": READ_SCHEMA_VERSION,
        "classification": "read",
        "workspace": str(Path(args.workspace).expanduser()),
        "bus_empty": len(records) == 0,
        "lane_count": len(lanes),
        "record_count": len(records),
        "lanes": lanes,
        "records": records,
    }, pretty=args.pretty)
    return 0


def cmd_aggregate(args: argparse.Namespace) -> int:
    if args.no_write:
        payload = aggregate_records(Path(args.workspace))
        path = bus_dir(Path(args.workspace)) / AGGREGATED_NAME
    else:
        payload, path = write_aggregate_snapshot(Path(args.workspace))
    out = dict(payload)
    out["classification"] = "aggregated"
    out["path"] = str(path)
    _emit(out, pretty=args.pretty)
    return 0


def cmd_consult(args: argparse.Namespace) -> int:
    filters = _parse_key_value(args.filter)
    records = read_records(Path(args.workspace))
    matches = filter_records(
        records,
        candidate_id=args.candidate_id,
        attack_class=args.attack_class,
        filters=filters,
        limit=args.limit,
    )
    _emit({
        "schema_version": CONSULT_SCHEMA_VERSION,
        "classification": "empty-bus" if not records else "consulted",
        "workspace": str(Path(args.workspace).expanduser()),
        "bus_empty": len(records) == 0,
        "query": {
            "candidate_id": args.candidate_id,
            "attack_class": args.attack_class,
            "filters": dict(sorted(filters.items())),
            "limit": args.limit,
        },
        "total_record_count": len(records),
        "match_count": len(matches),
        "records": matches,
    }, pretty=args.pretty)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lane-verdict-bus",
        description="Append, read, aggregate, and consult lane verdict records.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--workspace", required=True, help="Workspace root.")
        p.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
        p.add_argument("--json", action="store_true", help="Accepted for CLI parity; output is always JSON.")

    pa = sub.add_parser("append", help="Append one verdict record to a per-lane JSONL file.")
    add_common(pa)
    pa.add_argument("--lane-id", required=True)
    pa.add_argument("--candidate-id")
    pa.add_argument("--attack-class")
    pa.add_argument("--verdict")
    pa.add_argument("--summary", default="")
    pa.add_argument("--details", default="")
    pa.add_argument("--evidence-ref", action="append", default=[])
    pa.add_argument("--metadata", action="append", default=[], help="Additional metadata as key=value.")
    pa.add_argument("--record-json", help="Base record JSON object or @path.")
    pa.set_defaults(func=cmd_append)

    pr = sub.add_parser("read", help="Read per-lane records.")
    add_common(pr)
    pr.add_argument("--lane-id")
    pr.set_defaults(func=cmd_read)

    pg = sub.add_parser("aggregate", help="Write deterministic aggregated.json snapshot.")
    add_common(pg)
    pg.add_argument("--no-write", action="store_true", help="Build snapshot payload without writing aggregated.json.")
    pg.set_defaults(func=cmd_aggregate)

    pc = sub.add_parser("consult", help="Query the bus across all per-lane records.")
    add_common(pc)
    pc.add_argument("--candidate-id")
    pc.add_argument("--attack-class")
    pc.add_argument("--filter", action="append", default=[], help="Filter as key=value, e.g. verdict=DROPPED.")
    pc.add_argument("--limit", type=int)
    pc.set_defaults(func=cmd_consult)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except BusError as exc:
        _emit({
            "schema_version": "auditooor.lane_verdict_bus.error.v1",
            "classification": "error",
            "error": str(exc),
        }, pretty=getattr(args, "pretty", False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
