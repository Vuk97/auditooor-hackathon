#!/usr/bin/env python3
"""deep-crawler-staleness-check.py — Audit memory-deep-crawler section freshness.

Walks the canonical SECTION list defined in `tools/memory-deep-crawler.py`
(`ALL_SECTIONS`), correlates each section against its on-disk vault output
directory + the cached `last_sync` timestamp recorded in the vault's
`.deep_sync.json`, and emits a structured staleness audit:

  reports/deep_crawler_staleness_<YYYY-MM-DD>.json

Schema: `auditooor.deep_crawler_staleness.v1`

Per-section rows include:
  - section name
  - vault output dir (absolute string)
  - last_sync_iso (ISO-8601, UTC) sourced from `.deep_sync.json` when present
    or the most-recent `.md` file mtime under the section dir as a fallback
  - age_days (float, days since last_sync)
  - refresh_cadence_recommendation: one of {daily, weekly, on-event}
  - status: fresh | stale | stale-hard | missing
  - notes (string, optional)

Exit codes (also exposed as JSON `summary.exit_code`):
  0  — all sections fresh OR --advisory mode (default)
  1  — at least one section stale (>14d) AND --strict was supplied

The default mode is advisory (exit 0) so the gate can be wired into CI without
breaking unrelated builds.  Operators flip `STRICT=1` (or `--strict`) to make
the gate fail-closed.

Stdlib-only.  No external deps.

Cross-link: docs/next-loop/deep_crawler_staleness_audit_2026-05-07.md
Lane: T2-DEEP-CRAWLER-SECTIONS (master perpetual queue)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VAULT = Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault")
FALLBACK_VAULT = REPO_ROOT / "obsidian-vault"

SCHEMA = "auditooor.deep_crawler_staleness.v1"

# Mirror of tools/memory-deep-crawler.py:ALL_SECTIONS plus per-section vault
# subdirectory + recommended refresh cadence.  Cadence reasoning recorded in
# docs/next-loop/deep_crawler_staleness_audit_2026-05-07.md.
SECTION_REGISTRY: dict[str, dict[str, str]] = {
    "claude-memory": {
        "vault_subdir": "external-memory/claude",
        "cadence": "daily",
        "rationale": "claude-memory mutates every session; daily refresh keeps "
                     "operator-context aligned with most-recent rules.",
    },
    "codex-memory": {
        "vault_subdir": "external-memory/codex",
        "cadence": "daily",
        "rationale": "codex-memory mutates whenever Codex runs (multiple times "
                     "per day in active engagement); daily refresh required.",
    },
    "routines": {
        "vault_subdir": "routines",
        "cadence": "weekly",
        "rationale": "Routines change infrequently (only when scheduled tasks "
                     "added/removed); weekly refresh sufficient.",
    },
    "commits": {
        "vault_subdir": "commits",
        "cadence": "on-event",
        "rationale": "Commits append-only; refreshed when HEAD advances. "
                     "On-event cadence (post-push hook).",
    },
    "prs": {
        "vault_subdir": "prs",
        "cadence": "daily",
        "rationale": "PR state (status, comments, reviews) drifts daily during "
                     "active reviews; daily refresh keeps vault aligned.",
    },
    "tools-api": {
        "vault_subdir": "tools-api",
        "cadence": "weekly",
        "rationale": "Tool inventory changes when new tools land in tools/; "
                     "weekly is fine outside of major refactors.",
    },
    "make-targets": {
        "vault_subdir": "make-targets",
        "cadence": "weekly",
        "rationale": "Make targets only churn when Makefile edited; weekly "
                     "captures realistic edit cadence.",
    },
    "workspaces": {
        "vault_subdir": "workspaces",
        "cadence": "on-event",
        "rationale": "Per-workspace notes refresh when workspace mutates; "
                     "on-event triggered by audit-closeout.",
    },
    "errors": {
        "vault_subdir": "errors",
        "cadence": "daily",
        "rationale": "Error logs accumulate fast in active engagement; daily "
                     "refresh keeps error-aggregation notes current.",
    },
}

DEFAULT_STALE_DAYS = 14
DEFAULT_HARD_STALE_DAYS = 30


def _load_deep_sync(vault_dir: Path) -> dict[str, Any]:
    """Load `.deep_sync.json` if present; return empty dict on missing."""
    path = vault_dir / ".deep_sync.json"
    if not path.exists():
        return {}
    try:
        with path.open() as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _newest_mtime(directory: Path) -> float:
    """Return the newest mtime of any *.md file under `directory`, or 0.0."""
    if not directory.exists() or not directory.is_dir():
        return 0.0
    newest = 0.0
    for child in directory.rglob("*.md"):
        try:
            m = child.stat().st_mtime
        except OSError:
            continue
        if m > newest:
            newest = m
    return newest


def _resolve_section_timestamp(
    section: str,
    sync_state: dict[str, Any],
    vault_dir: Path,
    subdir: str,
) -> tuple[float, str]:
    """Resolve last-sync timestamp for a section.

    Returns (epoch_seconds, source) where `source` is one of
    {deep_sync_json, mtime_fallback, missing}.
    """
    # Workspaces are recorded as "workspaces/<name>" — aggregate by max.
    if section == "workspaces":
        ts = 0.0
        for k, v in sync_state.items():
            if k.startswith("workspaces/") and isinstance(v, (int, float)):
                if v > ts:
                    ts = float(v)
        if ts > 0:
            return ts, "deep_sync_json"
    elif section == "errors":
        ts = 0.0
        for k, v in sync_state.items():
            if k.startswith("errors/") and isinstance(v, (int, float)):
                if v > ts:
                    ts = float(v)
        if ts > 0:
            return ts, "deep_sync_json"
    else:
        v = sync_state.get(section)
        if isinstance(v, (int, float)):
            return float(v), "deep_sync_json"

    # Fallback: most-recent .md mtime under the section subdir.
    section_dir = vault_dir / subdir
    mtime = _newest_mtime(section_dir)
    if mtime > 0:
        return mtime, "mtime_fallback"
    return 0.0, "missing"


def _classify(age_days: float, stale_days: int, hard_stale_days: int) -> str:
    if age_days == float("inf"):
        return "missing"
    if age_days > hard_stale_days:
        return "stale-hard"
    if age_days > stale_days:
        return "stale"
    return "fresh"


def audit_sections(
    vault_dir: Path,
    *,
    now_epoch: float | None = None,
    stale_days: int = DEFAULT_STALE_DAYS,
    hard_stale_days: int = DEFAULT_HARD_STALE_DAYS,
) -> dict[str, Any]:
    """Run the staleness audit and return the structured report dict."""
    if now_epoch is None:
        now_epoch = _dt.datetime.now(tz=_dt.timezone.utc).timestamp()
    sync_state = _load_deep_sync(vault_dir)

    sections: list[dict[str, Any]] = []
    fresh = stale = stale_hard = missing = 0

    for name, meta in SECTION_REGISTRY.items():
        subdir = meta["vault_subdir"]
        cadence = meta["cadence"]
        rationale = meta["rationale"]

        ts, source = _resolve_section_timestamp(name, sync_state, vault_dir, subdir)

        if ts <= 0:
            age_days = float("inf")
            last_sync_iso = None
        else:
            age_seconds = max(0.0, now_epoch - ts)
            age_days = age_seconds / 86400.0
            last_sync_iso = (
                _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )

        status = _classify(age_days, stale_days, hard_stale_days)
        if status == "fresh":
            fresh += 1
        elif status == "stale":
            stale += 1
        elif status == "stale-hard":
            stale_hard += 1
        else:
            missing += 1

        sections.append({
            "section": name,
            "vault_subdir": subdir,
            "vault_path": str((vault_dir / subdir).resolve()),
            "last_sync_iso": last_sync_iso,
            "last_sync_source": source,
            "age_days": (
                None if age_days == float("inf")
                else round(age_days, 3)
            ),
            "status": status,
            "refresh_cadence_recommendation": cadence,
            "rationale": rationale,
        })

    summary = {
        "schema": SCHEMA,
        "generated_at": (
            _dt.datetime.fromtimestamp(now_epoch, tz=_dt.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "vault_dir": str(vault_dir.resolve()),
        "stale_days_threshold": stale_days,
        "hard_stale_days_threshold": hard_stale_days,
        "section_count": len(sections),
        "fresh_count": fresh,
        "stale_count": stale,
        "stale_hard_count": stale_hard,
        "missing_count": missing,
        "any_stale": (stale + stale_hard + missing) > 0,
    }

    return {
        "schema": SCHEMA,
        "summary": summary,
        "sections": sections,
    }


def _resolve_default_vault() -> Path:
    if DEFAULT_VAULT.exists():
        return DEFAULT_VAULT
    return FALLBACK_VAULT


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vault-dir", default=None,
                    help="Vault dir (defaults to live vault, then repo-local).")
    ap.add_argument("--out", default=None,
                    help="Output JSON path. Defaults to reports/deep_crawler_staleness_<DATE>.json")
    ap.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS,
                    help=f"Soft stale threshold (default: {DEFAULT_STALE_DAYS})")
    ap.add_argument("--hard-stale-days", type=int, default=DEFAULT_HARD_STALE_DAYS,
                    help=f"Hard stale threshold (default: {DEFAULT_HARD_STALE_DAYS})")
    ap.add_argument("--strict", action="store_true",
                    help="Fail (exit 1) when any section is stale or missing.")
    ap.add_argument("--print", dest="print_summary", action="store_true",
                    help="Print human-readable summary alongside JSON write.")
    args = ap.parse_args(argv)

    vault_dir = Path(args.vault_dir) if args.vault_dir else _resolve_default_vault()
    if not vault_dir.exists():
        sys.stderr.write(f"deep-crawler-staleness-check: vault dir not found: {vault_dir}\n")
        return 2

    report = audit_sections(
        vault_dir,
        stale_days=args.stale_days,
        hard_stale_days=args.hard_stale_days,
    )

    if args.out:
        out_path = Path(args.out)
    else:
        today = _dt.date.today().isoformat()
        out_path = REPO_ROOT / "reports" / f"deep_crawler_staleness_{today}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with tmp.open("w") as fh:
        json.dump(report, fh, indent=2, sort_keys=False)
        fh.write("\n")
    tmp.replace(out_path)

    summary = report["summary"]
    if args.print_summary:
        print(f"[deep-crawler-staleness-check] vault={summary['vault_dir']}")
        print(f"  fresh={summary['fresh_count']} stale={summary['stale_count']} "
              f"stale-hard={summary['stale_hard_count']} missing={summary['missing_count']}")
        for sec in report["sections"]:
            age = sec["age_days"]
            age_s = f"{age:.1f}d" if age is not None else "missing"
            print(f"    {sec['section']:<14} {sec['status']:<10} {age_s:>8}  cadence={sec['refresh_cadence_recommendation']}")
        print(f"  report: {out_path}")

    # Exit code policy
    strict = args.strict or os.environ.get("STRICT") == "1"
    if strict and summary["any_stale"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
