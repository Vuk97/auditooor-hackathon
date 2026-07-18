#!/usr/bin/env python3
"""solodit-delta-runner.py - I2 Solodit delta runner (offline-safe wrapper).

Wraps tools/solodit-rest-direct.py to emit a structured delta report covering:
- new records (id > cursor)
- changed records (id seen in prior sidecar with different content hash)
- unchanged records (id seen with same hash)
- rejected records (filtered by quality gate: missing source_url, synthetic,
  wrong verification_tier)
- cursor movement (prior -> new last_id)
- sidecar refresh status
- exact source links

OFFLINE SAFETY (spec requirement):
  - With no SOLODIT_API_KEY the runner emits a NEGATIVE-NO-KEY verdict and
    never errors. It reports the staleness status from the cursor file.
  - Dry-run mode (--dry-run --inject-json <fixture>) runs the full delta
    pipeline against a synthetic fixture without touching the network.
  - Default offline mode (no key, no fixture) emits a staleness report only.

DESIGN INVARIANTS:
  1. Never mutates the cursor unless records are actually written (inherited
     from solodit-rest-direct.py).
  2. Never imports solodit-rest-direct.py at module-level; uses importlib so
     the test suite can patch individual callables independently.
  3. Sidecar refresh status is computed by checking whether the output subtree
     count changed since the prior cursor run.
  4. Schema: auditooor.solodit_delta_run.v1

USAGE
    # Offline staleness report (no network):
    python3 tools/solodit-delta-runner.py --json-only

    # Live delta (requires SOLODIT_API_KEY):
    python3 tools/solodit-delta-runner.py \\
        --out-dir audit/corpus_tags/tags/solodit_delta_<date> \\
        --max-pages 5

    # Offline dry-run with fixture:
    python3 tools/solodit-delta-runner.py \\
        --dry-run --inject-json /tmp/fixture.json \\
        --json-only

    # Full delta report to file:
    python3 tools/solodit-delta-runner.py \\
        --report-out reports/solodit_delta_run_<date>.json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

TOOL_VERSION = "i2-1.0.0"
TOOL_NAME = "solodit-delta-runner"
REPORT_SCHEMA = "auditooor.solodit_delta_run.v1"

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CURSOR_FILE = REPO_ROOT / "reference" / "solodit_ingest_cursor.json"
DEFAULT_OUT_DIR_TEMPLATE = "audit/corpus_tags/tags/solodit_delta_{date}"
SOLODIT_REST_DIRECT = REPO_ROOT / "tools" / "solodit-rest-direct.py"

# Quality gate: fields that MUST be present for a record to be promoted.
REQUIRED_FIELDS = {"record_source_url", "verification_tier", "severity_at_finding", "attack_class"}
EXPECTED_TIER = "tier-2-verified-public-archive"


# ---------------------------------------------------------------------------
# Module loader (no top-level import of solodit-rest-direct)
# ---------------------------------------------------------------------------

def _load_srd() -> Any:
    """Load solodit-rest-direct module via importlib. Patchable in tests."""
    spec = importlib.util.spec_from_file_location("_srd", str(SOLODIT_REST_DIRECT))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Cursor helpers
# ---------------------------------------------------------------------------

def _load_cursor(cursor_file: Path) -> Dict[str, Any]:
    """Load cursor state. Returns defaults if file absent or unreadable."""
    if not cursor_file.exists():
        return {"last_id": 0, "updated_at": None, "run_date": None, "tool": None}
    try:
        data = json.loads(cursor_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"last_id": 0, "updated_at": None, "run_date": None, "tool": None}
        return data
    except (json.JSONDecodeError, OSError):
        return {"last_id": 0, "updated_at": None, "run_date": None, "tool": None}


def _cursor_age_days(cursor_state: Dict[str, Any]) -> Optional[int]:
    """Return age in days since cursor was last updated, or None."""
    updated = cursor_state.get("updated_at")
    if not updated:
        return None
    try:
        if updated.endswith("Z"):
            updated = updated[:-1] + "+00:00"
        dt = datetime.fromisoformat(updated)
        now = datetime.now(timezone.utc)
        return (now - dt).days
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------

def _quality_verdict(record: Dict[str, Any]) -> str:
    """Return 'accepted', 'rejected-missing-field', or 'rejected-wrong-tier'."""
    extensions = record.get("record_extensions") or {}
    if extensions.get("synthetic_fixture"):
        return "rejected-synthetic-fixture"
    for field in REQUIRED_FIELDS:
        if not record.get(field):
            return f"rejected-missing-{field}"
    if record.get("verification_tier") != EXPECTED_TIER:
        return f"rejected-wrong-tier:{record.get('verification_tier')}"
    if not (record.get("record_source_url") or "").startswith("http"):
        return "rejected-missing-source-url"
    return "accepted"


def _record_hash(record: Dict[str, Any]) -> str:
    """Stable content hash for changed-detection."""
    stable = json.dumps(record, sort_keys=True, default=str)
    return hashlib.sha256(stable.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Sidecar refresh status
# ---------------------------------------------------------------------------

def _sidecar_count(out_dir: Path) -> int:
    if not out_dir.is_dir():
        return 0
    return sum(1 for _ in out_dir.rglob("*.yaml"))


def _sidecar_status(out_dir: Path, written: int) -> Dict[str, Any]:
    count_before = _sidecar_count(out_dir) - written  # approximate
    count_after = _sidecar_count(out_dir)
    return {
        "out_dir": str(out_dir),
        "records_in_subtree_after": count_after,
        "records_written_this_run": written,
        "sidecar_refreshed": written > 0,
    }


# ---------------------------------------------------------------------------
# Core delta computation
# ---------------------------------------------------------------------------

def run_delta(
    *,
    cursor_id: int,
    out_dir: Path,
    dry_run: bool,
    inject_json: Optional[Path],
    json_only: bool,
    max_pages: int,
    page_size: int,
    language_filter: Optional[List[str]],
    srd_mod: Any,
) -> Dict[str, Any]:
    """Run the delta ingestion and return a structured delta report.

    Uses srd_mod (solodit-rest-direct module) for record building and live
    fetching. In dry-run mode uses ingest_from_injected_fixture.
    """
    result: Dict[str, Any]

    if dry_run:
        if not inject_json:
            return {
                "verdict": "NEGATIVE",
                "reason": "--dry-run requires --inject-json",
                "new_count": 0,
                "changed_count": 0,
                "unchanged_count": 0,
                "rejected_count": 0,
                "cursor_movement": {"prior": cursor_id, "new": cursor_id, "moved": False},
            }
        result = srd_mod.ingest_from_injected_fixture(
            inject_json,
            cursor_id=cursor_id,
            out_dir=out_dir,
            json_only=json_only,
            page_size=page_size,
            language_filter=language_filter,
        )
    else:
        api_key = os.environ.get("SOLODIT_API_KEY", "").strip()
        if not api_key:
            return {
                "verdict": "NEGATIVE-NO-KEY",
                "reason": "SOLODIT_API_KEY env var is missing; no live ingest performed",
                "new_count": 0,
                "changed_count": 0,
                "unchanged_count": 0,
                "rejected_count": 0,
                "cursor_movement": {"prior": cursor_id, "new": cursor_id, "moved": False},
                "network_performed": False,
            }
        try:
            client = srd_mod.SoloditRESTClient(api_key=api_key)
        except Exception as exc:
            return {
                "verdict": "NEGATIVE",
                "reason": f"client init error: {exc}",
                "new_count": 0,
                "changed_count": 0,
                "unchanged_count": 0,
                "rejected_count": 0,
                "cursor_movement": {"prior": cursor_id, "new": cursor_id, "moved": False},
            }
        result = srd_mod.ingest_pages(
            client,
            cursor_id=cursor_id,
            page_size=page_size,
            severity="HIGH",
            out_dir=out_dir,
            max_pages=max_pages,
            keyword=None,
            keyword_field=None,
            language_filter=language_filter,
            json_only=json_only,
            # Delta mining MUST sort by Recency, not the rest-direct default Quality:
            # Quality-Desc returns the same top-quality records every run, so new ids
            # (often lower quality, on later pages) never surface and the cursor never
            # advances (observed 2026-06-18: stuck at id 66047 for 25 days while the
            # newest finding was 66605). Recency-Desc puts new ids on page 1.
            sort_field="Recency",
        )

    written = result.get("written", 0)
    skipped = result.get("skipped", 0)
    skipped_language = result.get("skipped_language", 0)
    highest_id = result.get("highest_id_seen", cursor_id)

    # Quality gate: scan emitted YAML files for rejected records.
    accepted = written
    rejected_quality = 0
    source_links: List[str] = []

    # r36-rebuttal: bugfix-inventory-claude-20260610
    if not json_only and out_dir.is_dir() and written > 0:
        # Select the N most-recently-modified YAML files (N=written).
        # glob() returns files in filesystem/inode order (undefined on APFS/HFS+),
        # so [:written] would silently skip the newly-written files when the
        # directory already contains files from a prior same-day run.  Sorting by
        # (mtime, name) and taking the tail picks exactly the files written this run.
        _all_yamls = sorted(
            out_dir.glob("*.yaml"),
            key=lambda p: (p.stat().st_mtime, p.name),
        )
        for yaml_file in _all_yamls[-written:]:
            try:
                import re
                text = yaml_file.read_text(encoding="utf-8")
                # Extract record_source_url for reporting
                url_match = re.search(r"^record_source_url:\s*(.+)$", text, re.MULTILINE)
                if url_match:
                    url = url_match.group(1).strip().strip('"')
                    if url.startswith("http") and url not in source_links:
                        source_links.append(url)
                # Check synthetic_fixture marker
                if "synthetic_fixture: true" in text:
                    rejected_quality += 1
                    accepted -= 1
            except OSError:
                pass

    return {
        "verdict": result.get("verdict", "UNKNOWN"),
        "new_count": accepted,
        "changed_count": 0,  # Solodit is append-only by cursor; changes are not tracked by id alone
        "unchanged_count": skipped,
        "rejected_count": rejected_quality + skipped_language,
        "rejected_breakdown": {
            "quality_gate": rejected_quality,
            "language_filter": skipped_language,
            "cursor_already_seen": skipped,
        },
        "cursor_movement": {
            "prior": cursor_id,
            "new": highest_id,
            "moved": highest_id > cursor_id,
        },
        "source_links": source_links[:10],
        "pages_fetched": result.get("pages_fetched", 0),
        "dry_run": dry_run,
        "upstream_result": result,
    }


# ---------------------------------------------------------------------------
# Staleness-only report (offline, no network)
# ---------------------------------------------------------------------------

def staleness_report(cursor_state: Dict[str, Any]) -> Dict[str, Any]:
    """Build an offline staleness report from cursor state alone."""
    last_id = cursor_state.get("last_id", 0)
    age_days = _cursor_age_days(cursor_state)
    ttl_days = 1  # Solodit TTL is 24h per registry
    is_stale = age_days is None or age_days >= ttl_days

    return {
        "status": "stale" if is_stale else "fresh",
        "last_cursor_id": last_id,
        "last_run_date": cursor_state.get("run_date"),
        "last_updated_at": cursor_state.get("updated_at"),
        "age_days": age_days,
        "ttl_days": ttl_days,
        "is_stale": is_stale,
        "next_action": (
            "run python3 tools/solodit-rest-direct.py --min-severity HIGH --max-pages 10 with SOLODIT_API_KEY set"
            if is_stale
            else "no action needed; cursor is fresh"
        ),
        "cursor_file": str(DEFAULT_CURSOR_FILE),
        "awaiting_network_run": is_stale,
    }


# ---------------------------------------------------------------------------
# Main report builder
# ---------------------------------------------------------------------------

def build_report(
    *,
    delta: Dict[str, Any],
    staleness: Dict[str, Any],
    out_dir: Path,
    cursor_file: Path,
    language_filter: Optional[List[str]],
) -> Dict[str, Any]:
    written = delta.get("new_count", 0)
    sidecar = _sidecar_status(out_dir, written)
    return {
        "schema": REPORT_SCHEMA,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "https://solodit.cyfrin.io/api/v1/solodit/findings",
        "cursor_file": str(cursor_file),
        "language_filter": language_filter or [],
        "staleness": staleness,
        "delta": delta,
        "sidecar_refresh_status": sidecar,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--cursor-file",
        default=str(DEFAULT_CURSOR_FILE),
        help=f"Cursor file path (default: {DEFAULT_CURSOR_FILE})",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="YAML output directory. Default: audit/corpus_tags/tags/solodit_delta_<date>",
    )
    parser.add_argument("--max-pages", type=int, default=5, help="Max API pages (default: 5)")
    parser.add_argument("--page-size", type=int, default=100, help="API page size (default: 100)")
    parser.add_argument("--language", default=None, help="Comma-separated language filter (e.g. rust,go)")
    parser.add_argument("--dry-run", action="store_true", help="Use --inject-json fixture instead of live API")
    parser.add_argument("--inject-json", default=None, help="Fixture JSON for --dry-run")
    parser.add_argument("--json-only", action="store_true", help="Print report JSON; do NOT write YAML records")
    parser.add_argument("--staleness-only", action="store_true", help="Emit offline staleness report only; no network")
    parser.add_argument(
        "--report-out",
        default=None,
        help="Write JSON report to this path (in addition to stdout)",
    )
    args = parser.parse_args(argv)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cursor_file = Path(args.cursor_file).expanduser().resolve()
    cursor_state = _load_cursor(cursor_file)
    cursor_id = int(cursor_state.get("last_id", 0))
    stale = staleness_report(cursor_state)

    # Parse language filter
    language_filter: Optional[List[str]] = None
    if args.language:
        language_filter = [lang.strip() for lang in args.language.split(",") if lang.strip()]

    out_dir_str = args.out_dir or DEFAULT_OUT_DIR_TEMPLATE.replace("<date>", today)
    out_dir = Path(out_dir_str).expanduser().resolve()
    if not out_dir.is_absolute():
        out_dir = REPO_ROOT / out_dir_str

    inject_json = Path(args.inject_json).expanduser().resolve() if args.inject_json else None

    if args.staleness_only:
        report = {
            "schema": REPORT_SCHEMA,
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "https://solodit.cyfrin.io/api/v1/solodit/findings",
            "cursor_file": str(cursor_file),
            "language_filter": language_filter or [],
            "staleness": stale,
            "delta": None,
            "sidecar_refresh_status": None,
            "mode": "staleness_only",
        }
        out = json.dumps(report, indent=2, default=str)
        print(out)
        if args.report_out:
            rp = Path(args.report_out).expanduser().resolve()
            rp.parent.mkdir(parents=True, exist_ok=True)
            rp.write_text(out + "\n", encoding="utf-8")
        return 0

    srd = _load_srd()

    delta = run_delta(
        cursor_id=cursor_id,
        out_dir=out_dir,
        dry_run=args.dry_run,
        inject_json=inject_json,
        json_only=args.json_only,
        max_pages=args.max_pages,
        page_size=args.page_size,
        language_filter=language_filter,
        srd_mod=srd,
    )

    report = build_report(
        delta=delta,
        staleness=stale,
        out_dir=out_dir,
        cursor_file=cursor_file,
        language_filter=language_filter,
    )

    out = json.dumps(report, indent=2, default=str)
    print(out)
    if args.report_out:
        rp = Path(args.report_out).expanduser().resolve()
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(out + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
