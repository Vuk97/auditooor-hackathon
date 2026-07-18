#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - corpus baseline-freeze tool.

Snapshots a deterministic SHA256 fingerprint of the entire hackerman corpus
plus aggregate stats (total records, verification-tier distribution, per-
top-level-subtree record counts) into a single JSON file. The frozen
fingerprint is the Wave-1 baseline used for Wave-2 diff comparisons: any
record content change OR path change will move the SHA.

Default output:
    audit/wave1_snapshots/baseline_freeze/2026-05-16-wave1-final.json

The freeze JSON has shape::

    {
      "schema": "auditooor.hackerman_baseline_freeze.v1",
      "generated_at": "2026-05-16T00:00:00Z",
      "tags_dir": "<abspath>",
      "baseline_label": "2026-05-16-wave1-final",
      "corpus_sha256": "<64-hex>",
      "stats": {
        "total_records": 34842,
        "tier_distribution": {"tier-1": ..., "tier-2": ..., ..., "no-tier": ...},
        "shape_counts": {"record.yaml": ..., "record.json": ..., "flat.yaml": ...},
        "subtree_record_counts": {
          "lending_protocols": 1234,
          "audit_firm_public_reports": 567,
          ...
        }
      },
      "input_count": <int>  # number of record files that fed the SHA
    }

The SHA is computed deterministically over the sorted list of
``record.{yaml,json}`` files (alphabetic by relative path, content +
path inline-fed). Flat ``*.yaml`` records also participate when they are
the only shape in their directory (matches hackerman walker semantics).

Idempotency: re-running with the same ``--out-path`` (or default name)
overwrites the freeze file. Same-content rewrites are byte-identical.
Use ``--check`` to assert an existing freeze matches the live corpus
without rewriting.

Read-only against the corpus tree. Writes only under
``audit/wave1_snapshots/baseline_freeze/``.

CLI:

    python3 tools/hackerman-baseline-freeze.py
    python3 tools/hackerman-baseline-freeze.py --json
    python3 tools/hackerman-baseline-freeze.py --check
    python3 tools/hackerman-baseline-freeze.py --tags-dir <path> --out-path <path>
    python3 tools/hackerman-baseline-freeze.py --baseline-label 2026-05-16-wave1-final

Wired into Makefile as::

    make hackerman-baseline-freeze
    make hackerman-baseline-freeze JSON=1
    make hackerman-baseline-freeze CHECK=1
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
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
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "wave1_snapshots" / "baseline_freeze"
DEFAULT_BASELINE_LABEL = "2026-05-16-wave1-final"
SCHEMA = "auditooor.hackerman_baseline_freeze.v1"
HACKERMAN_V1_SCHEMA = "auditooor.hackerman_record.v1"

VERIFICATION_TIER_TAG_RE = re.compile(r"^verification_tier:tier-([1-5])-[a-z0-9-]+$")
TIER_ORDER = ("tier-1", "tier-2", "tier-3", "tier-4", "tier-5", "no-tier")


# ---------------------------------------------------------------------------
# Loader helpers (mirrors hackerman-tier-history-snapshot.py exactly so the
# baseline-freeze counts agree with sibling tools).
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


# ---------------------------------------------------------------------------
# Walker (matches hackerman-tier-history-snapshot.py).
# Returns (path, relpath, shape) in deterministic alphabetic order over the
# union of record.yaml + record.json (json-only when no sibling yaml) + flat
# yaml. ``relpath`` is the path relative to ``tags_dir`` (POSIX style) so the
# SHA is independent of where the tags-dir lives on disk.
# ---------------------------------------------------------------------------


def _walk_records(tags_dir: Path) -> Iterable[tuple[Path, str, str]]:
    seen_dirs: set[Path] = set()
    # Pass 1: record.yaml
    yaml_paths = sorted(tags_dir.rglob("record.yaml"))
    json_paths = sorted(tags_dir.rglob("record.json"))
    flat_paths = sorted(
        p for p in tags_dir.rglob("*.yaml") if p.name != "record.yaml"
    )
    # Determine seen_dirs from yaml first so json fallback works.
    for path in yaml_paths:
        seen_dirs.add(path.parent)
    # Merge all into a single alphabetic stream by relpath for deterministic
    # SHA input order, but tag shape per source list.
    by_relpath: dict[str, tuple[Path, str]] = {}
    for path in yaml_paths:
        rel = path.relative_to(tags_dir).as_posix()
        by_relpath[rel] = (path, "record.yaml")
    for path in json_paths:
        if path.parent in seen_dirs:
            continue
        rel = path.relative_to(tags_dir).as_posix()
        by_relpath[rel] = (path, "record.json")
    for path in flat_paths:
        rel = path.relative_to(tags_dir).as_posix()
        by_relpath[rel] = (path, "flat.yaml")
    for rel in sorted(by_relpath.keys()):
        path, shape = by_relpath[rel]
        yield path, rel, shape


# ---------------------------------------------------------------------------
# Core: deterministic SHA256 + stats aggregation.
# ---------------------------------------------------------------------------


def _subtree_key(rel: str) -> str:
    """Top-level subtree name for ``rel``; ``<root>`` if file sits directly
    under tags-dir (no subdir)."""
    parts = rel.split("/", 1)
    if len(parts) == 1:
        return "<root>"
    return parts[0]


def compute_baseline(tags_dir: Path) -> dict[str, Any]:
    """Walk the corpus, compute the deterministic SHA256 + aggregate stats.

    The SHA is fed with a per-record block of the form::

        b"<relpath>\\n<content-bytes>\\n--RECORD-SEP--\\n"

    Records are emitted in sorted-relpath order so the SHA is stable
    independent of disk-walk order. Content is read as raw bytes (no text
    normalisation) so any byte-level change flips the SHA.

    Returns a dict::

        {
          "corpus_sha256": "<64-hex>",
          "input_count": <int>,
          "stats": {
            "total_records": <int>,
            "tier_distribution": {...},
            "shape_counts": {...},
            "subtree_record_counts": {...},
          },
        }
    """
    sha = hashlib.sha256()
    input_count = 0
    tier_counts: Counter[str] = Counter()
    shape_counts: Counter[str] = Counter()
    subtree_counts: Counter[str] = Counter()

    for path, rel, shape in _walk_records(tags_dir):
        # Hash both the relpath (so path-renames flip SHA) and the raw bytes
        # (so content edits flip SHA). Use NUL-free separators.
        try:
            content_bytes = path.read_bytes()
        except OSError:
            content_bytes = b""
        sha.update(rel.encode("utf-8"))
        sha.update(b"\n")
        sha.update(content_bytes)
        sha.update(b"\n--RECORD-SEP--\n")
        input_count += 1
        shape_counts[shape] += 1
        subtree_counts[_subtree_key(rel)] += 1
        # Tier-distribution requires parsing; reuse existing loader.
        rec = _load_record(path)
        tier = _extract_verification_tier(rec)
        key = f"tier-{tier}" if isinstance(tier, int) else "no-tier"
        tier_counts[key] += 1

    def _ordered_tiers(counter: Counter[str]) -> dict[str, int]:
        out: dict[str, int] = {}
        for tier_key in TIER_ORDER:
            if tier_key in counter:
                out[tier_key] = int(counter[tier_key])
        for k, v in sorted(counter.items()):
            if k not in out:
                out[k] = int(v)
        return out

    stats = {
        "total_records": input_count,
        "tier_distribution": _ordered_tiers(tier_counts),
        "shape_counts": {k: int(v) for k, v in sorted(shape_counts.items())},
        "subtree_record_counts": {k: int(v) for k, v in sorted(subtree_counts.items())},
    }
    return {
        "corpus_sha256": sha.hexdigest(),
        "input_count": input_count,
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# Freeze file writer / verifier.
# ---------------------------------------------------------------------------


_TS_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _resolve_generated_at(raw: str | None) -> str:
    if raw is None:
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        return now.strftime("%Y-%m-%dT%H:%M:%SZ")
    s = raw.strip()
    if _TS_ISO_RE.match(s):
        return s
    raise ValueError(
        f"--generated-at must be ISO YYYY-MM-DDTHH:MM:SSZ; got {raw!r}"
    )


def _serialise_freeze(payload: dict[str, Any]) -> str:
    """Serialise the freeze JSON with deterministic key ordering.

    Top-level keys sorted alphabetically; nested ``stats.tier_distribution``
    preserves TIER_ORDER; other nested dicts alphabetised.
    """
    out: dict[str, Any] = {k: payload[k] for k in sorted(payload.keys())}
    stats = out.get("stats")
    if isinstance(stats, dict):
        ordered_stats: dict[str, Any] = {k: stats[k] for k in sorted(stats.keys())}
        td = ordered_stats.get("tier_distribution")
        if isinstance(td, dict):
            reordered: dict[str, int] = {}
            for tier_key in TIER_ORDER:
                if tier_key in td:
                    reordered[tier_key] = int(td[tier_key])
            for k2 in sorted(td.keys()):
                if k2 not in reordered:
                    reordered[k2] = int(td[k2])
            ordered_stats["tier_distribution"] = reordered
        out["stats"] = ordered_stats
    return json.dumps(out, indent=2) + "\n"


def freeze_baseline(
    tags_dir: Path,
    out_path: Path,
    baseline_label: str = DEFAULT_BASELINE_LABEL,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Compute baseline + write freeze JSON to ``out_path``.

    Returns the in-memory payload (also written to disk).
    """
    iso_ts = _resolve_generated_at(generated_at)
    core = compute_baseline(tags_dir)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": iso_ts,
        "baseline_label": baseline_label,
        "tags_dir": str(tags_dir),
        "corpus_sha256": core["corpus_sha256"],
        "input_count": core["input_count"],
        "stats": core["stats"],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_serialise_freeze(payload), encoding="utf-8")
    return payload


def verify_baseline(tags_dir: Path, out_path: Path) -> dict[str, Any]:
    """Re-compute the baseline and compare against an existing freeze file.

    Returns a verdict dict with keys ``match`` (bool), ``expected_sha``,
    ``observed_sha``, ``expected_total``, ``observed_total``, and
    ``freeze_path``. Does not write any files.
    """
    if not out_path.exists():
        return {
            "match": False,
            "error": f"freeze file not found: {out_path}",
            "freeze_path": str(out_path),
        }
    try:
        existing = json.loads(out_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "match": False,
            "error": f"freeze file unreadable: {exc}",
            "freeze_path": str(out_path),
        }
    core = compute_baseline(tags_dir)
    expected_sha = str(existing.get("corpus_sha256", ""))
    expected_total = int(((existing.get("stats") or {}).get("total_records") or 0))
    observed_sha = core["corpus_sha256"]
    observed_total = int(core["stats"]["total_records"])
    return {
        "match": expected_sha == observed_sha and expected_total == observed_total,
        "expected_sha": expected_sha,
        "observed_sha": observed_sha,
        "expected_total": expected_total,
        "observed_total": observed_total,
        "freeze_path": str(out_path),
    }


def default_out_path(out_dir: Path, baseline_label: str) -> Path:
    return out_dir / f"{baseline_label}.json"


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _format_human(payload: dict[str, Any]) -> str:
    stats = payload.get("stats") or {}
    tier = stats.get("tier_distribution") or {}
    subtrees = stats.get("subtree_record_counts") or {}
    lines = []
    lines.append(f"baseline_label    = {payload.get('baseline_label')}")
    lines.append(f"generated_at      = {payload.get('generated_at')}")
    lines.append(f"tags_dir          = {payload.get('tags_dir')}")
    lines.append(f"corpus_sha256     = {payload.get('corpus_sha256')}")
    lines.append(f"total_records     = {stats.get('total_records')}")
    lines.append(f"tier_distribution = {tier}")
    lines.append(f"subtree_count     = {len(subtrees)} top-level dirs")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Freeze a baseline snapshot of the hackerman corpus "
        "(deterministic SHA256 + record counts + tier distribution + "
        "per-subtree counts) for Wave-2 diff comparison (PR #726 Wave-1)."
    )
    p.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help=f"Path to corpus tags dir (default: {DEFAULT_TAGS_DIR}).",
    )
    p.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help=f"Output dir for freeze JSON (default: {DEFAULT_OUT_DIR}).",
    )
    p.add_argument(
        "--out-path",
        default=None,
        help="Explicit freeze file path. Default: <out-dir>/<baseline-label>.json.",
    )
    p.add_argument(
        "--baseline-label",
        default=DEFAULT_BASELINE_LABEL,
        help=f"Baseline label (default: {DEFAULT_BASELINE_LABEL}).",
    )
    p.add_argument(
        "--generated-at",
        default=os.environ.get("AUDITOOOR_BASELINE_FREEZE_GENERATED_AT"),
        help="Pin freeze timestamp (ISO YYYY-MM-DDTHH:MM:SSZ). Default = UTC now.",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="Verify mode: re-compute and compare against existing freeze; do NOT write.",
    )
    p.add_argument("--json", action="store_true", help="Emit verdict as JSON.")
    args = p.parse_args(argv)

    tags_dir = Path(args.tags_dir)
    out_dir = Path(args.out_dir)
    out_path = (
        Path(args.out_path)
        if args.out_path
        else default_out_path(out_dir, args.baseline_label)
    )

    if not tags_dir.is_dir():
        msg = f"tags-dir does not exist or is not a directory: {tags_dir}"
        if args.json:
            print(json.dumps({"verdict": "error", "error": msg}, sort_keys=True))
        else:
            print(f"ERROR: {msg}", file=sys.stderr)
        return 2

    if args.check:
        verdict = verify_baseline(tags_dir, out_path)
        if args.json:
            envelope = dict(verdict)
            envelope["verdict"] = "match" if verdict.get("match") else "mismatch"
            print(json.dumps(envelope, indent=2, sort_keys=True))
        else:
            if verdict.get("match"):
                print(f"MATCH: {verdict['observed_sha']} ({verdict['observed_total']} records)")
                print(f"  freeze_path = {verdict['freeze_path']}")
            elif "error" in verdict:
                print(f"ERROR: {verdict['error']}", file=sys.stderr)
            else:
                print(
                    f"MISMATCH: expected={verdict['expected_sha']} "
                    f"({verdict['expected_total']}) "
                    f"observed={verdict['observed_sha']} "
                    f"({verdict['observed_total']})",
                    file=sys.stderr,
                )
                print(f"  freeze_path = {verdict['freeze_path']}", file=sys.stderr)
        return 0 if verdict.get("match") else 1

    payload = freeze_baseline(
        tags_dir,
        out_path,
        baseline_label=args.baseline_label,
        generated_at=args.generated_at,
    )
    if args.json:
        compact = {
            "verdict": "ok",
            "freeze_path": str(out_path),
            "corpus_sha256": payload["corpus_sha256"],
            "total_records": payload["stats"]["total_records"],
            "tier_distribution": payload["stats"]["tier_distribution"],
            "subtree_count": len(payload["stats"]["subtree_record_counts"]),
            "baseline_label": payload["baseline_label"],
            "generated_at": payload["generated_at"],
        }
        print(json.dumps(compact, indent=2, sort_keys=True))
    else:
        print(f"WROTE: {out_path}")
        print(_format_human(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
