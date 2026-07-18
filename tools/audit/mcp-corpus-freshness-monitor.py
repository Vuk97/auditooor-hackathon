#!/usr/bin/env python3
"""mcp-corpus-freshness-monitor.py — per-MCP-callable corpus freshness monitor.

LANE W4.14. The vault MCP server (`tools/vault-mcp-server.py`) serves cached
audit knowledge. Each corpus segment is produced by an ETL miner registered in
`tools/audit/etl_miner_registry/<slug>.json`. Those segments drift stale over
time; a session that relies on MCP recall without knowing a segment's age can
trust outdated knowledge.

Sibling tooling:
  * `tools/deep-crawler-staleness-check.py` — audits the 9 memory-deep-crawler
    *vault* sections (claude-memory, prs, ...) at a 14d soft threshold.
  * MCP callable `vault_corpus_freshness` — per-record corpus-tag slice age,
    filtered by attack_class / target_repo (hot/warm/cool/stale bands).

This monitor fills the remaining gap: a *per-corpus-segment / per-miner* report
that tells a session, for every ETL-backed segment, how fresh its backing data
is and which upstream source it should be re-pulled from.

Freshness model
---------------
For each ETL miner registry entry the monitor computes two age signals and
takes the WORST (oldest) of them:

  1. registry-commit age: `git log -1 --format=%cI <last_run_commit_sha>` — the
     commit timestamp of the commit that last ran the miner. This is the
     authoritative "when was this segment last mined" anchor.
  2. record-mtime age: newest *.json / *.yaml mtime under the miner's
     `target_subtree`. A fallback when the registry SHA is unresolvable
     (shallow clone, pruned object) and a cross-check otherwise.

Age (days) -> verdict:
  FRESH  age <= soft threshold (default 14d)
  AGING  soft < age <= hard threshold (default 30d)
  STALE  age > hard threshold, OR no age resolvable

`honest_zero` miners (registry says the miner legitimately emits zero records)
are reported with verdict `FRESH` and note `honest-zero` — there is nothing to
go stale, but the row is still surfaced for completeness.

Upstream re-pull mapping
------------------------
Each registry entry carries a `source_channel`. The monitor maps the channel to
the concrete upstream a re-mine should target:

  gh-api / github-rest-api -> `gh api` (GitHub Advisory / repo commits)
  corpus-bridge            -> internal corpus bridge re-run (`make` ETL target)
  commit-history           -> `git log` over the tracked upstream repo
  pdf-listing              -> re-extract audit-firm PDF listings
  <unknown>                -> inspect registry entry `tool_path`

The `makefile_target` from the registry is surfaced verbatim as the exact
re-mine command.

Output
------
  reports/mcp_corpus_freshness_<YYYY-MM-DD>.json   (schema below)
  + optional human-readable table on --print

Schema: `auditooor.mcp_corpus_freshness.v1`

Exit codes (also in JSON `summary.exit_code`):
  0  advisory mode (default), or all segments FRESH
  1  >=1 segment STALE/AGING AND --strict (or STRICT=1)

Stdlib-only. No network calls — git is read-only and local.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = REPO_ROOT / "tools" / "audit" / "etl_miner_registry"

SCHEMA = "auditooor.mcp_corpus_freshness.v1"

DEFAULT_SOFT_DAYS = 14
DEFAULT_HARD_DAYS = 30

# source_channel -> (upstream label, re-pull guidance).
SOURCE_CHANNEL_UPSTREAM: dict[str, dict[str, str]] = {
    "gh-api": {
        "upstream": "GitHub Advisory API / repo commits",
        "repull": "gh api (GHSA advisories + repo commit history)",
    },
    "github-rest-api": {
        "upstream": "GitHub REST API",
        "repull": "gh api repos/<owner>/<repo>/commits",
    },
    "corpus-bridge": {
        "upstream": "internal corpus bridge (audit/corpus_tags + Solodit feed)",
        "repull": "re-run the miner's makefile target (corpus-bridge ETL)",
    },
    "commit-history": {
        "upstream": "tracked upstream repo git history",
        "repull": "git log over the upstream repo, re-run commit-history miner",
    },
    "pdf-listing": {
        "upstream": "audit-firm public PDF report listings",
        "repull": "re-extract audit-firm PDF listings, re-run miner",
    },
}

# MCP callables whose answers are backed by the ETL corpus segments. Surfaced
# in the report so a session can see which recall path a stale segment poisons.
# Not exhaustive — the corpus is shared, but these are the primary consumers.
CORPUS_BACKED_CALLABLES: tuple[str, ...] = (
    "vault_corpus_search",
    "vault_corpus_freshness",
    "vault_corpus_lineage",
    "vault_corpus_subtree_summary",
    "vault_external_corpus_search",
    "vault_attack_class_evidence",
    "vault_bug_family_heatmap",
    "vault_function_shape_attack_evidence",
    "vault_language_patterns",
    "vault_cross_language_pattern_lift",
)


def _git_commit_iso(repo_root: Path, sha: str) -> str | None:
    """Return the committer ISO-8601 date for `sha`, or None if unresolvable."""
    if not sha or len(sha) < 7:
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), "log", "-1", "--format=%cI", sha],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    line = out.stdout.strip()
    return line or None


def _newest_record_mtime(directory: Path) -> float:
    """Newest mtime of any *.json / *.yaml record under `directory`, or 0.0."""
    if not directory.exists() or not directory.is_dir():
        return 0.0
    newest = 0.0
    for pattern in ("*.json", "*.yaml", "*.yml"):
        for child in directory.rglob(pattern):
            try:
                m = child.stat().st_mtime
            except OSError:
                continue
            if m > newest:
                newest = m
    return newest


def _iso_to_epoch(iso: str) -> float | None:
    try:
        cleaned = iso.strip().replace("Z", "+00:00")
        dt = _dt.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt.timestamp()
    except (TypeError, ValueError):
        return None


def _epoch_to_iso(epoch: float) -> str:
    return (
        _dt.datetime.fromtimestamp(epoch, tz=_dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _classify(age_days: float | None, soft: int, hard: int) -> str:
    if age_days is None:
        return "STALE"
    if age_days > hard:
        return "STALE"
    if age_days > soft:
        return "AGING"
    return "FRESH"


def _load_registry_entries(registry_dir: Path) -> list[dict[str, Any]]:
    """Load every `<slug>.json` in the registry dir except `_manifest.json`."""
    entries: list[dict[str, Any]] = []
    if not registry_dir.is_dir():
        return entries
    for path in sorted(registry_dir.glob("*.json")):
        if path.name == "_manifest.json":
            continue
        try:
            with path.open() as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            data["_registry_file"] = str(path)
            entries.append(data)
    return entries


def audit_segments(
    *,
    repo_root: Path = REPO_ROOT,
    registry_dir: Path = REGISTRY_DIR,
    now_epoch: float | None = None,
    soft_days: int = DEFAULT_SOFT_DAYS,
    hard_days: int = DEFAULT_HARD_DAYS,
) -> dict[str, Any]:
    """Run the per-segment freshness audit and return the structured report."""
    if now_epoch is None:
        now_epoch = _dt.datetime.now(tz=_dt.timezone.utc).timestamp()

    entries = _load_registry_entries(registry_dir)
    segments: list[dict[str, Any]] = []
    fresh = aging = stale = 0

    for entry in entries:
        slug = str(entry.get("miner_slug") or Path(entry.get("_registry_file", "")).stem)
        honest_zero = bool(entry.get("honest_zero", False))
        channel = str(entry.get("source_channel") or "unknown")
        sha = str(entry.get("last_run_commit_sha") or "")
        makefile_target = str(entry.get("makefile_target") or "")
        tool_path = str(entry.get("tool_path") or "")
        subtree_rel = str(entry.get("target_subtree") or "")
        record_count = entry.get("record_count_emitted")

        # Signal 1: registry-commit age.
        commit_iso = _git_commit_iso(repo_root, sha)
        commit_epoch = _iso_to_epoch(commit_iso) if commit_iso else None

        # Signal 2: newest record mtime under the target subtree.
        subtree_dir = (repo_root / subtree_rel) if subtree_rel else None
        mtime_epoch = (
            _newest_record_mtime(subtree_dir)
            if subtree_dir is not None
            else 0.0
        )

        candidate_epochs = [e for e in (commit_epoch, mtime_epoch) if e and e > 0]
        if candidate_epochs:
            # Worst (oldest) wins — the segment is only as fresh as its
            # oldest freshness signal.
            anchor_epoch = min(candidate_epochs)
            age_days: float | None = round(
                max(0.0, now_epoch - anchor_epoch) / 86400.0, 3
            )
            last_refresh_iso = _epoch_to_iso(anchor_epoch)
        else:
            anchor_epoch = None
            age_days = None
            last_refresh_iso = None

        verdict = _classify(age_days, soft_days, hard_days)

        notes: list[str] = []
        if honest_zero:
            # Nothing can go stale in an intentionally-empty segment.
            verdict = "FRESH"
            notes.append("honest-zero")
        if commit_epoch is None and sha:
            notes.append("registry-sha-unresolvable (shallow clone?)")
        if not subtree_rel or (subtree_dir is not None and not subtree_dir.exists()):
            notes.append("target-subtree-missing-on-disk")

        if verdict == "FRESH":
            fresh += 1
        elif verdict == "AGING":
            aging += 1
        else:
            stale += 1

        upstream = SOURCE_CHANNEL_UPSTREAM.get(
            channel,
            {"upstream": f"unknown (inspect {tool_path or 'registry entry'})",
             "repull": f"inspect registry tool_path: {tool_path or '?'}"},
        )

        segments.append({
            "miner_slug": slug,
            "source_channel": channel,
            "honest_zero": honest_zero,
            "record_count_emitted": record_count,
            "last_run_commit_sha": sha,
            "registry_commit_iso": commit_iso,
            "newest_record_iso": (
                _epoch_to_iso(mtime_epoch) if mtime_epoch > 0 else None
            ),
            "last_refresh_iso": last_refresh_iso,
            "age_days": age_days,
            "verdict": verdict,
            "target_subtree": subtree_rel,
            "upstream_source": upstream["upstream"],
            "repull_guidance": upstream["repull"],
            "repull_command": (
                f"make {makefile_target}" if makefile_target else tool_path
            ),
            "notes": "; ".join(notes),
        })

    summary = {
        "schema": SCHEMA,
        "generated_at": _epoch_to_iso(now_epoch),
        "repo_root": str(repo_root),
        "registry_dir": str(registry_dir),
        "soft_days_threshold": soft_days,
        "hard_days_threshold": hard_days,
        "segment_count": len(segments),
        "fresh_count": fresh,
        "aging_count": aging,
        "stale_count": stale,
        "any_stale": (stale + aging) > 0,
        "corpus_backed_callables": list(CORPUS_BACKED_CALLABLES),
    }

    return {
        "schema": SCHEMA,
        "summary": summary,
        "segments": segments,
    }


def _print_report(report: dict[str, Any], out_path: Path) -> None:
    summary = report["summary"]
    print(f"[mcp-corpus-freshness-monitor] registry={summary['registry_dir']}")
    print(
        f"  segments={summary['segment_count']} "
        f"FRESH={summary['fresh_count']} "
        f"AGING={summary['aging_count']} "
        f"STALE={summary['stale_count']} "
        f"(soft={summary['soft_days_threshold']}d hard={summary['hard_days_threshold']}d)"
    )
    # Worst-first ordering for operator triage.
    rank = {"STALE": 0, "AGING": 1, "FRESH": 2}
    rows = sorted(
        report["segments"],
        key=lambda s: (rank.get(s["verdict"], 9), -(s["age_days"] or 0.0)),
    )
    for seg in rows:
        age = seg["age_days"]
        age_s = f"{age:.1f}d" if age is not None else "no-age"
        print(
            f"    {seg['miner_slug']:<28} {seg['verdict']:<6} {age_s:>9}  "
            f"channel={seg['source_channel']:<16} "
            f"repull={seg['repull_command']}"
        )
        if seg["notes"]:
            print(f"      note: {seg['notes']}")
    print(f"  report: {out_path}")
    print(
        "  corpus-backed MCP callables affected by stale segments: "
        + ", ".join(summary["corpus_backed_callables"])
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--repo-root", default=None,
                    help="Repo root (defaults to the auditooor repo this tool lives in).")
    ap.add_argument("--registry-dir", default=None,
                    help="ETL miner registry dir (defaults to tools/audit/etl_miner_registry).")
    ap.add_argument("--out", default=None,
                    help="Output JSON path. Defaults to reports/mcp_corpus_freshness_<DATE>.json")
    ap.add_argument("--soft-days", type=int, default=DEFAULT_SOFT_DAYS,
                    help=f"Soft (AGING) threshold in days (default: {DEFAULT_SOFT_DAYS})")
    ap.add_argument("--hard-days", type=int, default=DEFAULT_HARD_DAYS,
                    help=f"Hard (STALE) threshold in days (default: {DEFAULT_HARD_DAYS})")
    ap.add_argument("--strict", action="store_true",
                    help="Exit 1 when any segment is AGING or STALE.")
    ap.add_argument("--print", dest="print_summary", action="store_true",
                    help="Print a human-readable table alongside the JSON write.")
    args = ap.parse_args(argv)

    repo_root = Path(args.repo_root).resolve() if args.repo_root else REPO_ROOT
    registry_dir = (
        Path(args.registry_dir).resolve() if args.registry_dir
        else (repo_root / "tools" / "audit" / "etl_miner_registry")
    )
    if not registry_dir.is_dir():
        sys.stderr.write(
            f"mcp-corpus-freshness-monitor: registry dir not found: {registry_dir}\n"
        )
        return 2

    report = audit_segments(
        repo_root=repo_root,
        registry_dir=registry_dir,
        soft_days=args.soft_days,
        hard_days=args.hard_days,
    )

    if args.out:
        out_path = Path(args.out)
    else:
        today = _dt.date.today().isoformat()
        out_path = repo_root / "reports" / f"mcp_corpus_freshness_{today}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with tmp.open("w") as fh:
        json.dump(report, fh, indent=2, sort_keys=False)
        fh.write("\n")
    tmp.replace(out_path)

    report["summary"]["report_path"] = str(out_path)

    if args.print_summary:
        _print_report(report, out_path)

    strict = args.strict or os.environ.get("STRICT") == "1"
    exit_code = 1 if (strict and report["summary"]["any_stale"]) else 0
    report["summary"]["exit_code"] = exit_code
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
