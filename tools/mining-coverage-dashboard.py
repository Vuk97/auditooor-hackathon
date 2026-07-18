#!/usr/bin/env python3
"""Offline mining coverage dashboard for source corpora.

Summarizes local coverage for registry-driven external intelligence sources,
``reference/corpus_mined`` notes, known Solodit/Pashov corpus outputs, and
agent-artifact mining reports when present. This is intentionally read-only and
offline: it never fetches network sources and only inspects local sidecars,
cursors, record trees, and bounded report JSON.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # pragma: no cover - exercised implicitly when PyYAML is available.
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


SCHEMA_VERSION = "auditooor.mining_coverage_dashboard.v1"
DEFAULT_STALE_DAYS = 30.0

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXTERNAL_SOURCES = ROOT / "reference" / "external_intel_sources.yaml"
DEFAULT_CORPUS_MINED = ROOT / "reference" / "corpus_mined"
DEFAULT_TAGS_DIR = ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_JSON = ROOT / ".auditooor" / "mining_coverage_dashboard.json"
DEFAULT_MD = ROOT / "docs" / "MINING_COVERAGE_DASHBOARD.md"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return _to_aware(datetime.fromisoformat(text))
    except ValueError:
        return None


def _file_mtime(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


def _newest_mtime(paths: list[Path]) -> datetime | None:
    newest: datetime | None = None
    for path in paths:
        mt = _file_mtime(path)
        if mt is not None and (newest is None or mt > newest):
            newest = mt
    return newest


def _age_days(dt: datetime | None, now: datetime) -> float | None:
    if dt is None:
        return None
    return round((now - _to_aware(dt)).total_seconds() / 86400, 2)


def _parse_ttl_days(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return DEFAULT_STALE_DAYS
    text = value.strip().lower()
    if not text:
        return DEFAULT_STALE_DAYS
    try:
        if text.endswith("h"):
            return float(text[:-1]) / 24.0
        if text.endswith("d"):
            return float(text[:-1])
        return float(text)
    except ValueError:
        return DEFAULT_STALE_DAYS


def _rel_or_abs(path_text: str | None, root: Path) -> Path | None:
    if not path_text:
        return None
    path = Path(path_text)
    if path.is_absolute():
        return path
    return root / path


def _glob_paths(pattern_text: str, root: Path) -> list[Path]:
    if not pattern_text:
        return []
    pattern = str(_rel_or_abs(pattern_text, root) or pattern_text)
    return sorted(path for path in Path("/").glob(pattern.lstrip("/")) if path.exists())


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    if yaml is not None:
        try:
            loaded = yaml.safe_load(text)
            return loaded if isinstance(loaded, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    return _minimal_external_sources_parse(text)


def _minimal_external_sources_parse(text: str) -> dict[str, Any]:
    """Tiny fallback parser for source_id/name/status rows.

    Real registry parsing uses PyYAML. This fallback keeps the tool degraded but
    useful in stdlib-only environments.
    """
    sources: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("- source_id:"):
            if current:
                sources.append(current)
            current = {"source_id": line.split(":", 1)[1].strip().strip("'\"")}
        elif current is not None and ":" in line and not line.startswith("- "):
            key, val = line.split(":", 1)
            if key in {"name", "ttl", "status", "backlog_reason", "output_subtree"}:
                current[key] = val.strip().strip("'\"")
    if current:
        sources.append(current)
    return {"sources": sources}


def _count_files(directory: Path, patterns: tuple[str, ...]) -> int:
    if not directory.exists() or not directory.is_dir():
        return 0
    total = 0
    for pattern in patterns:
        total += sum(1 for path in directory.rglob(pattern) if path.is_file())
    return total


def _record_count(directory: Path) -> int:
    if not directory.exists() or not directory.is_dir():
        return 0
    records: set[str] = set()
    for pattern in ("record.json", "record.yaml", "record.yml", "*.json", "*.yaml", "*.yml"):
        iterator = directory.rglob(pattern) if pattern.startswith("record.") else directory.glob(pattern)
        for path in iterator:
            if not path.is_file():
                continue
            records.add(_record_identity(path) or path.as_posix())

    # Source-specific miners such as DarkNavy emit one JSON/YAML pair per
    # incident using names like high-<hash>.yaml rather than record.yaml. Count
    # those nested records by record_id without double-counting their mirror.
    for pattern in ("*.json", "*.yaml", "*.yml"):
        for path in directory.rglob(pattern):
            if not path.is_file():
                continue
            identity = _record_identity(path)
            if identity:
                records.add(identity)
    return len(records)


def _record_identity(path: Path) -> str | None:
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
        elif suffix in {".yaml", ".yml"} and yaml is not None:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        else:
            return None
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(data, dict):
        return None
    record_id = data.get("record_id")
    if isinstance(record_id, str) and record_id.strip():
        return record_id.strip()
    return None


def _newest_file_in(directory: Path, patterns: tuple[str, ...]) -> datetime | None:
    if not directory.exists() or not directory.is_dir():
        return None
    files: list[Path] = []
    for pattern in patterns:
        files.extend(path for path in directory.rglob(pattern) if path.is_file())
    return _newest_mtime(files)


def _local_reference_signal(source_id: str, root: Path) -> tuple[int, datetime | None]:
    """Count established local pattern outputs for legacy source families."""
    ref = root / "reference"
    if not ref.exists():
        return 0, None

    source_lower = source_id.lower()
    files: list[Path] = []
    if "solodit" in source_lower:
        for entry in ref.iterdir():
            if entry.is_dir() and "solodit" in entry.name.lower():
                files.extend(path for path in entry.rglob("*.yaml") if path.is_file())
    elif "pashov" in source_lower:
        patterns_dsl = ref / "patterns.dsl"
        if patterns_dsl.exists():
            files.extend(path for path in patterns_dsl.glob("*pashov*.yaml") if path.is_file())
        pashov_dir = ref / "patterns.dsl.r75_mined_pashov"
        if pashov_dir.exists():
            files.extend(path for path in pashov_dir.rglob("*.yaml") if path.is_file())
    elif "defihacklabs" in source_lower:
        catalog = ref / "corpus_mined" / "defihacklabs_catalog.md"
        if catalog.exists():
            files.append(catalog)
        patterns_dsl = ref / "patterns.dsl"
        if patterns_dsl.exists():
            files.extend(path for path in patterns_dsl.glob("dh-*.yaml") if path.is_file())
    elif "defimon" in source_lower:
        for entry in ref.iterdir():
            if entry.is_dir() and "defimon" in entry.name.lower():
                files.extend(path for path in entry.rglob("*.yaml") if path.is_file())

    unique = sorted(set(files))
    return len(unique), _newest_mtime(unique)


def _source_refs(source: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    raw_refs = source.get("source_refs")
    if isinstance(raw_refs, list):
        refs.extend(str(ref) for ref in raw_refs if str(ref).strip())
    raw_source = source.get("url_or_api")
    if isinstance(raw_source, str) and raw_source.strip() and not raw_source.startswith("BLOCKED_"):
        refs.append(raw_source)
    elif isinstance(raw_source, list):
        refs.extend(str(ref) for ref in raw_source if str(ref).strip())
    return sorted(dict.fromkeys(refs))


def _source_obligations(source: dict[str, Any]) -> list[dict[str, Any]]:
    obligations = source.get("source_obligations")
    if not isinstance(obligations, list):
        return []
    return [item for item in obligations if isinstance(item, dict)]


def _queue_metadata(source: dict[str, Any], root: Path) -> dict[str, Any] | None:
    refs = _source_refs(source)
    if not refs:
        return None
    miner = source.get("miner") if isinstance(source.get("miner"), dict) else {}
    target = miner.get("makefile_target")
    if isinstance(target, str) and target.strip():
        queue_target = f"make {target.strip()}"
    else:
        tool_path = _rel_or_abs(miner.get("tool_path"), root)
        queue_target = f"python3 {tool_path.relative_to(root)}" if tool_path and tool_path.exists() else None
    return {
        "status": "queued",
        "source_refs": refs,
        "queue_target": queue_target,
        "next_action": "Run or extend the registered miner against these source refs before promoting new typed records.",
    }


def _cursor_timestamp(cursor_path: Path | None, field: str | None) -> tuple[datetime | None, Any]:
    if cursor_path is None or not cursor_path.exists():
        return None, None
    payload = _read_json(cursor_path)
    cursor_value = payload.get(field) if field else None
    for key in ("updated_at", "last_mined_at", "generated_at", "timestamp_utc", "refreshed_at"):
        parsed = _parse_iso(payload.get(key))
        if parsed is not None:
            return parsed, cursor_value
    mt = _file_mtime(cursor_path)
    return mt, cursor_value


def _cursor_signal(cursor: dict[str, Any], root: Path) -> tuple[datetime | None, Any, Path | None, list[Path]]:
    primary = _rel_or_abs(cursor.get("path"), root)
    paths: list[Path] = [primary] if primary is not None else []
    raw_alternates = cursor.get("alternate_paths")
    if isinstance(raw_alternates, list):
        for raw in raw_alternates:
            alt = _rel_or_abs(str(raw), root)
            if alt is not None:
                paths.append(alt)
    best_dt: datetime | None = None
    best_value: Any = None
    values: list[Any] = []
    for path in paths:
        dt, value = _cursor_timestamp(path, cursor.get("field"))
        if value is not None:
            values.append(value)
        if dt is not None and (best_dt is None or dt > best_dt):
            best_dt = dt
            best_value = value
    if best_value is None and primary is not None:
        _, best_value = _cursor_timestamp(primary, cursor.get("field"))
    numeric_values = [value for value in values if isinstance(value, (int, float))]
    if numeric_values:
        best_value = max(numeric_values)
    return best_dt, best_value, primary, paths


def _output_paths_for_source(source: dict[str, Any], promotion: dict[str, Any], root: Path, tags_dir: Path) -> list[Path]:
    output_paths: list[Path] = []
    output_text = source.get("output_subtree") or promotion.get("corpus_subtree")
    raw_globs = source.get("output_subtree_globs")
    if isinstance(output_text, str) and output_text.strip():
        output_path = _rel_or_abs(output_text, root)
        if output_path is not None and not output_path.exists():
            leaf = Path(output_text).name
            candidate = tags_dir / leaf
            if candidate.exists():
                output_path = candidate
        if output_path is not None and (output_path.exists() or not raw_globs):
            output_paths.append(output_path)
    if isinstance(raw_globs, list):
        for raw in raw_globs:
            output_paths.extend(_glob_paths(str(raw), root))
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in output_paths:
        if path not in seen:
            unique.append(path)
            seen.add(path)
    return unique


def _classify_status(
    *,
    explicit_status: str | None,
    mode: str | None,
    last_seen: datetime | None,
    output_exists: bool,
    mined_count: int,
    ttl_days: float,
    now: datetime,
) -> tuple[str, str]:
    status_text = (explicit_status or "").strip()
    status_lower = status_text.lower()
    mode_lower = (mode or "").lower()
    if "blocked" in status_lower:
        return "backlog", f"registry status is {status_text}"
    if "backlog" in status_lower:
        return "backlog", f"registry status is {status_text}"
    if "backlog" in mode_lower or "blocked" in mode_lower:
        return "backlog", f"registry miner mode is {mode}"
    if last_seen is None and not output_exists and mined_count == 0:
        return "missing", "no local cursor or mined output found"
    if last_seen is None:
        return "stale", "local output exists but no freshness timestamp was found"
    age = _age_days(last_seen, now)
    if age is not None and age > ttl_days:
        return "stale", f"last local refresh is {age:.2f} days old; ttl is {ttl_days:.2f} days"
    return "fresh", "local freshness is within ttl"


def _source_row(source: dict[str, Any], root: Path, tags_dir: Path, now: datetime) -> dict[str, Any]:
    source_id = str(source.get("source_id") or "unknown_source")
    miner = source.get("miner") if isinstance(source.get("miner"), dict) else {}
    cursor = source.get("cursor") if isinstance(source.get("cursor"), dict) else {}
    promotion = source.get("promotion_target") if isinstance(source.get("promotion_target"), dict) else {}
    network = source.get("network_requirement") if isinstance(source.get("network_requirement"), dict) else {}

    tool_path = _rel_or_abs(miner.get("tool_path"), root)
    cursor_dt, cursor_value, cursor_path, cursor_paths = _cursor_signal(cursor, root)
    output_paths = _output_paths_for_source(source, promotion, root, tags_dir)

    mined_records = sum(_record_count(path) for path in output_paths)
    mined_files = sum(_count_files(path, ("*.json", "*.yaml", "*.yml", "*.md")) for path in output_paths)
    output_dt = max(
        (
            dt
            for dt in (
                _newest_file_in(path, ("record.json", "record.yaml", "record.yml", "*.json", "*.yaml", "*.yml", "*.md"))
                for path in output_paths
            )
            if dt is not None
        ),
        default=None,
    )
    local_pattern_count, local_pattern_dt = _local_reference_signal(source_id, root)
    mined_files += local_pattern_count
    last_seen = max(
        (dt for dt in (cursor_dt, output_dt, local_pattern_dt) if dt is not None),
        default=None,
    )
    ttl_days = _parse_ttl_days(source.get("ttl"))
    status, reason = _classify_status(
        explicit_status=source.get("status"),
        mode=miner.get("mode"),
        last_seen=last_seen,
        output_exists=any(path.exists() for path in output_paths),
        mined_count=mined_records or mined_files,
        ttl_days=ttl_days,
        now=now,
    )
    preserve_backlog = str(source.get("status") or "").strip().lower() == "backlog"
    queue_meta = _queue_metadata(source, root) if status in {"stale", "backlog"} and not preserve_backlog else None
    if queue_meta is not None:
        original_status = status
        status = "queued"
        reason = (
            f"{original_status} source queued with explicit source refs; "
            f"previous reason: {source.get('backlog_reason') or reason}"
        )

    source_obligations = _source_obligations(source)
    row = {
        "source_id": source_id,
        "name": source.get("name") or source_id,
        "source_kind": "external_intel_registry",
        "status": status,
        "reason": source.get("backlog_reason") if status != "queued" and source.get("backlog_reason") else reason,
        "ttl_days": ttl_days,
        "last_mined_at": last_seen.isoformat() if last_seen else None,
        "age_days": _age_days(last_seen, now),
        "network_required": bool(network.get("required")),
        "miner_tool": str(tool_path) if tool_path else None,
        "miner_tool_exists": bool(tool_path and tool_path.exists()),
        "cursor_path": str(cursor_path) if cursor_path else None,
        "cursor_exists": bool(cursor_path and cursor_path.exists()),
        "cursor_paths": [str(path) for path in cursor_paths],
        "cursor_value": cursor_value,
        "output_path": str(output_paths[0]) if output_paths else None,
        "output_paths": [str(path) for path in output_paths],
        "output_exists": any(path.exists() for path in output_paths),
        "mined_record_count": mined_records,
        "mined_file_count": mined_files,
        "local_pattern_file_count": local_pattern_count,
        "source_obligations": source_obligations,
        "source_obligation_count": len(source_obligations),
    }
    if queue_meta is not None:
        row.update(queue_meta)
        row["reason"] = reason
    return row


def _local_corpus_mined_row(corpus_mined: Path, now: datetime) -> dict[str, Any]:
    md_count = _count_files(corpus_mined, ("*.md",))
    newest = _newest_file_in(corpus_mined, ("*.md",))
    ttl_days = DEFAULT_STALE_DAYS
    if not corpus_mined.exists():
        status, reason = "missing", "reference/corpus_mined directory is absent"
    elif newest is None:
        status, reason = "missing", "reference/corpus_mined has no markdown slices"
    else:
        age = _age_days(newest, now)
        status = "stale" if age is not None and age > ttl_days else "fresh"
        reason = "local corpus_mined markdown inventory"
    return {
        "source_id": "reference_corpus_mined",
        "name": "reference/corpus_mined local slices",
        "source_kind": "local_corpus_mined",
        "status": status,
        "reason": reason,
        "ttl_days": ttl_days,
        "last_mined_at": newest.isoformat() if newest else None,
        "age_days": _age_days(newest, now),
        "network_required": False,
        "miner_tool": None,
        "miner_tool_exists": None,
        "cursor_path": None,
        "cursor_exists": None,
        "cursor_value": None,
        "output_path": str(corpus_mined),
        "output_exists": corpus_mined.exists(),
        "mined_record_count": 0,
        "mined_file_count": md_count,
    }


def _agent_report_row(report_path: Path, root: Path, now: datetime) -> dict[str, Any]:
    exists = report_path.exists()
    payload = _read_json(report_path) if exists else {}
    generated = _parse_iso(payload.get("generated_at") or payload.get("timestamp_utc"))
    last_seen = generated or _file_mtime(report_path)
    total_artifacts = payload.get("total_artifacts")
    if not isinstance(total_artifacts, int):
        artifacts = payload.get("artifacts")
        total_artifacts = len(artifacts) if isinstance(artifacts, list) else 0
    ttl_days = 14.0
    if not exists:
        status, reason = "missing", "agent-artifact mining report is absent"
    else:
        age = _age_days(last_seen, now)
        status = "stale" if age is not None and age > ttl_days else "fresh"
        reason = "agent-artifact mining report present"
    return {
        "source_id": "agent_artifact_mining_report",
        "name": "agent-artifact mining report",
        "source_kind": "agent_artifact_mining",
        "status": status,
        "reason": reason,
        "ttl_days": ttl_days,
        "last_mined_at": last_seen.isoformat() if last_seen else None,
        "age_days": _age_days(last_seen, now),
        "network_required": False,
        "miner_tool": str(root / "tools" / "agent-artifact-miner.py"),
        "miner_tool_exists": (root / "tools" / "agent-artifact-miner.py").exists(),
        "cursor_path": None,
        "cursor_exists": None,
        "cursor_value": None,
        "output_path": str(report_path),
        "output_exists": exists,
        "mined_record_count": int(total_artifacts),
        "mined_file_count": 1 if exists else 0,
        "artifact_type_counts": payload.get("artifact_type_counts") if isinstance(payload.get("artifact_type_counts"), dict) else {},
    }


def _default_agent_reports(root: Path) -> list[Path]:
    return [
        root / "agent_artifact_mining_report.json",
        root / ".auditooor" / "agent_artifact_mining_report.json",
    ]


def build_dashboard(
    *,
    root: Path = ROOT,
    external_sources_path: Path = DEFAULT_EXTERNAL_SOURCES,
    corpus_mined_path: Path = DEFAULT_CORPUS_MINED,
    tags_dir: Path = DEFAULT_TAGS_DIR,
    agent_reports: list[Path] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the read-only coverage dashboard payload."""
    now = _to_aware(now or _utc_now())
    root = root.resolve()
    external_sources_path = external_sources_path if external_sources_path.is_absolute() else root / external_sources_path
    corpus_mined_path = corpus_mined_path if corpus_mined_path.is_absolute() else root / corpus_mined_path
    tags_dir = tags_dir if tags_dir.is_absolute() else root / tags_dir

    rows: list[dict[str, Any]] = []
    registry = _load_yaml(external_sources_path)
    sources = registry.get("sources")
    if isinstance(sources, list):
        for source in sources:
            if isinstance(source, dict):
                rows.append(_source_row(source, root, tags_dir, now))

    rows.append(_local_corpus_mined_row(corpus_mined_path, now))

    report_paths = agent_reports or _default_agent_reports(root)
    seen_reports: set[Path] = set()
    for report in report_paths:
        report_path = report if report.is_absolute() else root / report
        if report_path in seen_reports:
            continue
        seen_reports.add(report_path)
        if report_path.exists():
            rows.append(_agent_report_row(report_path, root, now))
    if not any(row["source_kind"] == "agent_artifact_mining" for row in rows):
        rows.append(_agent_report_row(_default_agent_reports(root)[0], root, now))

    stale_rows = [row for row in rows if row["status"] == "stale"]
    missing_rows = [row for row in rows if row["status"] == "missing"]
    backlog_rows = [row for row in rows if row["status"] == "backlog"]
    queued_rows = [row for row in rows if row["status"] == "queued"]
    summary = {
        "total_sources": len(rows),
        "fresh": sum(1 for row in rows if row["status"] == "fresh"),
        "stale": len(stale_rows),
        "missing": len(missing_rows),
        "backlog": len(backlog_rows),
        "queued": len(queued_rows),
    }

    return {
        "schema": SCHEMA_VERSION,
        "generated_at": now.isoformat(),
        "root": str(root),
        "registry_path": str(external_sources_path),
        "summary": summary,
        "rows": rows,
        "stale_rows": stale_rows,
        "missing_rows": missing_rows,
        "backlog_rows": backlog_rows,
        "queued_rows": queued_rows,
    }


def _fmt_date(value: Any) -> str:
    if not value:
        return "never"
    return str(value)[:10]


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Mining Coverage Dashboard",
        "",
        f"Generated: {payload.get('generated_at', 'unknown')}",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|---|---:|",
    ]
    summary = payload.get("summary", {})
    for key in ("total_sources", "fresh", "queued", "stale", "missing", "backlog"):
        lines.append(f"| {key} | {summary.get(key, 0)} |")

    lines += [
        "",
        "## Coverage Rows",
        "",
        "| Source | Kind | Status | Last local mine | Records | Files | Reason |",
        "|---|---|---|---:|---:|---:|---|",
    ]
    for row in payload.get("rows", []):
        lines.append(
            "| {source} | {kind} | {status} | {last} | {records} | {files} | {reason} |".format(
                source=row.get("source_id", ""),
                kind=row.get("source_kind", ""),
                status=row.get("status", ""),
                last=_fmt_date(row.get("last_mined_at")),
                records=row.get("mined_record_count", 0),
                files=row.get("mined_file_count", 0),
                reason=str(row.get("reason", "")).replace("|", "\\|"),
            )
        )

    for title, key in (
        ("Stale Rows", "stale_rows"),
        ("Missing Rows", "missing_rows"),
        ("Backlog Rows", "backlog_rows"),
        ("Queued Rows", "queued_rows"),
    ):
        lines += ["", f"## {title}", ""]
        rows = payload.get(key, [])
        if not rows:
            lines.append("- none")
        for row in rows:
            lines.append(f"- `{row.get('source_id')}`: {row.get('reason')}")
            if row.get("source_obligation_count"):
                lines.append(f"  - source obligations: {row.get('source_obligation_count')}")
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline source-corpus mining coverage dashboard")
    parser.add_argument("--root", default=str(ROOT), help="Repository root")
    parser.add_argument("--external-sources", default=None, help="Path to external_intel_sources.yaml")
    parser.add_argument("--corpus-mined", default=None, help="Path to reference/corpus_mined")
    parser.add_argument("--tags-dir", default=None, help="Path to audit/corpus_tags/tags")
    parser.add_argument("--agent-report", action="append", default=[], help="Agent artifact mining report path; repeatable")
    parser.add_argument("--out-json", default=str(DEFAULT_JSON), help="JSON output path")
    parser.add_argument("--out-md", default=str(DEFAULT_MD), help="Markdown output path")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    parser.add_argument("--markdown", action="store_true", help="Print Markdown to stdout")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).resolve()
    external_sources = Path(args.external_sources) if args.external_sources else root / "reference" / "external_intel_sources.yaml"
    corpus_mined = Path(args.corpus_mined) if args.corpus_mined else root / "reference" / "corpus_mined"
    tags_dir = Path(args.tags_dir) if args.tags_dir else root / "audit" / "corpus_tags" / "tags"
    agent_reports = [Path(p) for p in args.agent_report] if args.agent_report else None

    payload = build_dashboard(
        root=root,
        external_sources_path=external_sources,
        corpus_mined_path=corpus_mined,
        tags_dir=tags_dir,
        agent_reports=agent_reports,
    )

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")

    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=False) + "\n")
    elif args.markdown:
        sys.stdout.write(render_markdown(payload))
    elif not args.quiet:
        summary = payload["summary"]
        print(
            "mining-coverage-dashboard: "
            f"{summary['total_sources']} sources "
            f"({summary['fresh']} fresh, {summary['stale']} stale, "
            f"{summary['missing']} missing, {summary['backlog']} backlog)"
        )
        print(f"  json -> {out_json}")
        print(f"  md   -> {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
