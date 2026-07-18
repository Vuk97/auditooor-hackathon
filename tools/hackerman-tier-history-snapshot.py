#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - corpus tier-distribution snapshotter.

Walks the corpus tree under ``audit/corpus_tags/tags/``, computes the
``verification_tier`` distribution across the three record shapes
(``record.yaml``, ``record.json``-only, flat ``<name>.yaml``), and emits a
deterministic JSON snapshot to
``audit/wave1_snapshots/tier_history/<YYYY-MM-DDTHH-MM-SSZ>.json``.

Also maintains a rolling manifest at
``audit/wave1_snapshots/tier_history/_manifest.json`` listing every snapshot
ever taken (filename + timestamp + total_records + tier counts), so the
operator can ``cat`` it to see growth over time without rescanning every
snapshot file.

Idempotency: same-second invocations skip duplicate snapshot files but still
exit 0 with a ``skipped: true`` verdict so cron/loop callers don't bail.

Read-only against the corpus tree. Writes only under
``audit/wave1_snapshots/tier_history/``.

CLI:

    python3 tools/hackerman-tier-history-snapshot.py
    python3 tools/hackerman-tier-history-snapshot.py --json   # parse-friendly verdict
    python3 tools/hackerman-tier-history-snapshot.py --list   # show last N snapshots
    python3 tools/hackerman-tier-history-snapshot.py --tags-dir <path> --out-dir <path>
    python3 tools/hackerman-tier-history-snapshot.py --generated-at 2026-05-16T22:00:00Z

Wired into Makefile as:
    make hackerman-tier-history-snapshot
    make hackerman-tier-history-list
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - optional pyyaml.
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "wave1_snapshots" / "tier_history"
SCHEMA = "auditooor.hackerman_tier_history_snapshot.v1"
MANIFEST_SCHEMA = "auditooor.hackerman_tier_history_manifest.v1"
MANIFEST_NAME = "_manifest.json"
HACKERMAN_V1_SCHEMA = "auditooor.hackerman_record.v1"

VERIFICATION_TIER_TAG_RE = re.compile(r"^verification_tier:tier-([1-5])-[a-z0-9-]+$")
TIER_ORDER = ("tier-1", "tier-2", "tier-3", "tier-4", "tier-5", "no-tier")
DEFAULT_LIST_LIMIT = 10


# ---------------------------------------------------------------------------
# Loader helpers (mirrors hackerman-corpus-stats.py - kept fallback-friendly).
# ---------------------------------------------------------------------------


def _yaml_load(text: str) -> dict[str, Any]:
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    out: dict[str, Any] = {}
    in_function_shape = False
    current_list_key: str | None = None
    shape_tags: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("function_shape:"):
            in_function_shape = True
            current_list_key = None
            continue
        if in_function_shape and line.startswith("  ") and not line.startswith("    "):
            current_subkey = line.strip().rstrip(":")
            current_list_key = "shape_tags" if current_subkey == "shape_tags" else None
            continue
        if in_function_shape and current_list_key == "shape_tags" and line.startswith("    - "):
            shape_tags.append(line[6:].strip().strip("\"'"))
            continue
        if not line.startswith(" "):
            in_function_shape = False
            current_list_key = None
            if ":" in line:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip().strip("\"'")
    if shape_tags:
        out["function_shape"] = {"shape_tags": shape_tags}
    return out


def _load_record(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if path.suffix == ".json":
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return _yaml_load(text)


def _extract_verification_tier(record: dict[str, Any] | None) -> int | None:
    if not isinstance(record, dict):
        return None
    shape = record.get("function_shape")
    if not isinstance(shape, dict):
        return None
    tags = shape.get("shape_tags")
    if not isinstance(tags, list):
        return None
    for tag in tags:
        text = str(tag or "").strip()
        m = VERIFICATION_TIER_TAG_RE.match(text)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return None


def _is_hackerman_v1(record: dict[str, Any]) -> bool:
    return str(record.get("schema_version") or "").strip() == HACKERMAN_V1_SCHEMA


# ---------------------------------------------------------------------------
# Walker - matches hackerman-corpus-stats.py exactly so tier counts agree.
# ---------------------------------------------------------------------------


def _walk_records(tags_dir: Path) -> Iterable[tuple[Path, dict[str, Any], str]]:
    seen_dirs: set[Path] = set()
    for path in sorted(tags_dir.rglob("record.yaml")):
        seen_dirs.add(path.parent)
        rec = _load_record(path)
        if rec:
            yield path, rec, "record.yaml"
    for path in sorted(tags_dir.rglob("record.json")):
        if path.parent in seen_dirs:
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec, "record.json"
    for path in sorted(tags_dir.rglob("*.yaml")):
        if path.name == "record.yaml":
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec, "flat.yaml"


# ---------------------------------------------------------------------------
# Tier distribution computation.
# ---------------------------------------------------------------------------


def build_tier_distribution(tags_dir: Path) -> dict[str, Any]:
    """Walk the corpus and compute deterministic tier-distribution payload.

    Returns a dict with stable key order; tier counts sorted by TIER_ORDER.
    """
    tier_counts: Counter[str] = Counter()
    tier_counts_hackerman_v1: Counter[str] = Counter()
    shape_counts: Counter[str] = Counter()
    total_records = 0
    total_hackerman_v1 = 0

    for _path, rec, shape in _walk_records(tags_dir):
        total_records += 1
        shape_counts[shape] += 1
        tier = _extract_verification_tier(rec)
        key = f"tier-{tier}" if isinstance(tier, int) else "no-tier"
        tier_counts[key] += 1
        if _is_hackerman_v1(rec):
            total_hackerman_v1 += 1
            tier_counts_hackerman_v1[key] += 1

    def _ordered(counter: Counter[str]) -> dict[str, int]:
        # Canonical tier order: tier-1..tier-5 then no-tier. Drop unseen keys
        # (no zero-padding) so the JSON snapshot only carries observed tiers.
        out: dict[str, int] = {}
        for tier_key in TIER_ORDER:
            if tier_key in counter:
                out[tier_key] = int(counter[tier_key])
        # Surface any unexpected key (defensive - shouldn't happen given regex).
        for k, v in sorted(counter.items()):
            if k not in out:
                out[k] = int(v)
        return out

    return {
        "total_records": total_records,
        "total_hackerman_v1_records": total_hackerman_v1,
        "tier_counts": _ordered(tier_counts),
        "tier_counts_hackerman_v1": _ordered(tier_counts_hackerman_v1),
        "shape_counts": {k: int(v) for k, v in sorted(shape_counts.items())},
    }


# ---------------------------------------------------------------------------
# Snapshot file naming + manifest maintenance.
# ---------------------------------------------------------------------------

# Timestamp slug must be filesystem-safe ("-" instead of ":") AND parse back
# into the canonical ISO-8601 Z form for the manifest.
_TS_FS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z$")
_TS_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _resolve_generated_at(raw: str | None) -> str:
    """Return a canonical ISO-8601 Z timestamp string.

    Accepts either ``YYYY-MM-DDTHH:MM:SSZ`` (ISO) or ``YYYY-MM-DDTHH-MM-SSZ``
    (filesystem-slug); normalises to the ISO form.
    """
    if raw is None:
        # Use UTC; truncate sub-second precision for determinism.
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        return now.strftime("%Y-%m-%dT%H:%M:%SZ")
    s = raw.strip()
    if _TS_ISO_RE.match(s):
        return s
    if _TS_FS_RE.match(s):
        # Convert HH-MM-SS back to HH:MM:SS for the date portion.
        date_part, _, tail = s.partition("T")
        hh, mm, ss = tail.rstrip("Z").split("-")
        return f"{date_part}T{hh}:{mm}:{ss}Z"
    raise ValueError(
        f"--generated-at must be ISO YYYY-MM-DDTHH:MM:SSZ or slug "
        f"YYYY-MM-DDTHH-MM-SSZ; got {raw!r}"
    )


def _iso_to_fs_slug(iso_ts: str) -> str:
    """``2026-05-16T22:00:00Z`` -> ``2026-05-16T22-00-00Z``."""
    date_part, _, tail = iso_ts.partition("T")
    hh, mm, ss = tail.rstrip("Z").split(":")
    return f"{date_part}T{hh}-{mm}-{ss}Z"


def snapshot_filename_for(generated_at_iso: str) -> str:
    return f"{_iso_to_fs_slug(generated_at_iso)}.json"


def _serialise_payload(payload: dict[str, Any]) -> str:
    """Serialise a snapshot payload preserving canonical TIER_ORDER inside
    ``stats.tier_counts`` / ``stats.tier_counts_hackerman_v1``.

    Top-level keys + non-tier sub-dicts are sorted alphabetically for
    deterministic diffs.
    """
    stats = payload.get("stats", {}) or {}
    ordered_stats: dict[str, Any] = {}
    for k in sorted(stats.keys()):
        ordered_stats[k] = stats[k]
    # Tier-count dicts: re-order by TIER_ORDER (entries we observed).
    for key in ("tier_counts", "tier_counts_hackerman_v1"):
        if key in ordered_stats and isinstance(ordered_stats[key], dict):
            src = ordered_stats[key]
            reordered: dict[str, int] = {}
            for tier_key in TIER_ORDER:
                if tier_key in src:
                    reordered[tier_key] = int(src[tier_key])
            for k2 in sorted(src.keys()):
                if k2 not in reordered:
                    reordered[k2] = int(src[k2])
            ordered_stats[key] = reordered
    out_payload = {k: payload[k] for k in sorted(payload.keys()) if k != "stats"}
    out_payload["stats"] = ordered_stats
    # Re-sort top-level so "stats" lands alphabetically.
    final = {k: out_payload[k] for k in sorted(out_payload.keys())}
    return json.dumps(final, indent=2) + "\n"


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    if not manifest_path.exists():
        return {"schema": MANIFEST_SCHEMA, "snapshots": []}
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema": MANIFEST_SCHEMA, "snapshots": []}
    if not isinstance(data, dict):
        return {"schema": MANIFEST_SCHEMA, "snapshots": []}
    snaps = data.get("snapshots")
    if not isinstance(snaps, list):
        snaps = []
    return {"schema": MANIFEST_SCHEMA, "snapshots": snaps}


def _manifest_entry(filename: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": filename,
        "generated_at": payload["generated_at"],
        "total_records": payload["stats"]["total_records"],
        "total_hackerman_v1_records": payload["stats"]["total_hackerman_v1_records"],
        "tier_counts": payload["stats"]["tier_counts"],
    }


def _update_manifest(manifest_path: Path, entry: dict[str, Any]) -> dict[str, Any]:
    """Append entry to manifest, dedup by filename, keep entries sorted by
    generated_at asc so growth-over-time reads are linear."""
    manifest = _load_manifest(manifest_path)
    snaps = [s for s in manifest["snapshots"] if s.get("filename") != entry["filename"]]
    snaps.append(entry)
    snaps.sort(key=lambda s: (str(s.get("generated_at", "")), str(s.get("filename", ""))))
    manifest["snapshots"] = snaps
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


# ---------------------------------------------------------------------------
# Top-level snapshot orchestrator.
# ---------------------------------------------------------------------------


def take_snapshot(
    tags_dir: Path,
    out_dir: Path,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Walk corpus, write snapshot file (idempotent on same-second), and
    update the manifest.

    Returns a verdict dict with ``filename``, ``path``, ``skipped`` (bool),
    ``snapshot_count_after`` (int), ``payload`` (snapshot dict).
    """
    iso_ts = _resolve_generated_at(generated_at)
    filename = snapshot_filename_for(iso_ts)
    out_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = out_dir / filename
    manifest_path = out_dir / MANIFEST_NAME

    stats = build_tier_distribution(tags_dir)
    payload = {
        "schema": SCHEMA,
        "generated_at": iso_ts,
        "tags_dir": str(tags_dir),
        "stats": stats,
    }

    skipped = False
    if snapshot_path.exists():
        # Idempotency: same-second invocation, do NOT overwrite. Still update
        # the manifest entry (its tier_counts may have drifted if the on-disk
        # file was hand-edited; we keep the existing file authoritative).
        try:
            existing = json.loads(snapshot_path.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                payload = existing
                skipped = True
        except (OSError, json.JSONDecodeError):
            # Corrupt existing file - overwrite with fresh payload.
            snapshot_path.write_text(
                _serialise_payload(payload),
                encoding="utf-8",
            )
    else:
        snapshot_path.write_text(
            _serialise_payload(payload),
            encoding="utf-8",
        )

    manifest = _update_manifest(manifest_path, _manifest_entry(filename, payload))

    return {
        "filename": filename,
        "path": str(snapshot_path),
        "skipped": skipped,
        "snapshot_count_after": len(manifest["snapshots"]),
        "manifest_path": str(manifest_path),
        "payload": payload,
    }


def list_snapshots(out_dir: Path, limit: int = DEFAULT_LIST_LIMIT) -> list[dict[str, Any]]:
    """Return last ``limit`` snapshot entries from the manifest (newest first)."""
    manifest_path = out_dir / MANIFEST_NAME
    manifest = _load_manifest(manifest_path)
    snaps = list(manifest["snapshots"])
    snaps.sort(key=lambda s: (str(s.get("generated_at", "")), str(s.get("filename", ""))), reverse=True)
    return snaps[: max(0, int(limit))]


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _format_list_human(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "(no snapshots yet)"
    lines = []
    header = f"{'generated_at':<22} {'total':>8} {'v1':>8}  tiers"
    lines.append(header)
    lines.append("-" * len(header))
    for e in entries:
        tier_counts = e.get("tier_counts", {}) or {}
        ordered_keys = [k for k in TIER_ORDER if k in tier_counts]
        ordered_keys += [k for k in sorted(tier_counts.keys()) if k not in ordered_keys]
        tier_repr = ", ".join(f"{k}={tier_counts[k]}" for k in ordered_keys)
        lines.append(
            f"{e.get('generated_at',''):<22} "
            f"{int(e.get('total_records', 0)):>8} "
            f"{int(e.get('total_hackerman_v1_records', 0)):>8}  "
            f"{tier_repr}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Snapshot the hackerman corpus tier distribution to a "
        "versioned JSON file (PR #726 Wave-1)."
    )
    p.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help=f"Path to the corpus tags dir (default: {DEFAULT_TAGS_DIR}).",
    )
    p.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help=f"Snapshot output dir (default: {DEFAULT_OUT_DIR}).",
    )
    p.add_argument(
        "--generated-at",
        default=os.environ.get("AUDITOOOR_TIER_HISTORY_GENERATED_AT"),
        help="Pin the snapshot timestamp (ISO YYYY-MM-DDTHH:MM:SSZ). Default = UTC now.",
    )
    p.add_argument("--json", action="store_true", help="Emit verdict as JSON.")
    p.add_argument(
        "--list",
        action="store_true",
        help="List last N snapshots from the manifest (default 10); does NOT take a new snapshot.",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIST_LIMIT,
        help=f"With --list, how many entries to show (default {DEFAULT_LIST_LIMIT}).",
    )
    args = p.parse_args(argv)

    tags_dir = Path(args.tags_dir)
    out_dir = Path(args.out_dir)

    if args.list:
        entries = list_snapshots(out_dir, args.limit)
        if args.json:
            print(json.dumps({"schema": MANIFEST_SCHEMA, "snapshots": entries}, indent=2, sort_keys=True))
        else:
            print(_format_list_human(entries))
        return 0

    if not tags_dir.is_dir():
        msg = f"tags-dir does not exist or is not a directory: {tags_dir}"
        if args.json:
            print(json.dumps({"verdict": "error", "error": msg}, sort_keys=True))
        else:
            print(f"ERROR: {msg}", file=sys.stderr)
        return 2

    verdict = take_snapshot(tags_dir, out_dir, generated_at=args.generated_at)
    if args.json:
        # Drop full payload from the JSON verdict to keep stdout small; the
        # snapshot file already has it.
        compact = {k: v for k, v in verdict.items() if k != "payload"}
        compact["verdict"] = "skipped" if verdict["skipped"] else "ok"
        compact["total_records"] = verdict["payload"]["stats"]["total_records"]
        compact["tier_counts"] = verdict["payload"]["stats"]["tier_counts"]
        print(json.dumps(compact, indent=2, sort_keys=True))
    else:
        status = "SKIPPED (idempotent same-second)" if verdict["skipped"] else "WROTE"
        stats = verdict["payload"]["stats"]
        print(f"{status}: {verdict['path']}")
        print(f"  total_records         = {stats['total_records']}")
        print(f"  total_hackerman_v1    = {stats['total_hackerman_v1_records']}")
        print(f"  tier_counts           = {stats['tier_counts']}")
        print(f"  snapshot_count_after  = {verdict['snapshot_count_after']}")
        print(f"  manifest              = {verdict['manifest_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
