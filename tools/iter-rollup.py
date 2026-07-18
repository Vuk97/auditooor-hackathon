#!/usr/bin/env python3
"""iter-rollup.py - cross-iter hunt index emitter.

Walks ``reports/v3_iter_*`` (and the ``_iter<N>`` / ``_phase_*`` variants)
under the workspace root and emits a consolidated index. The goal is to
give the operator a single "all hunts ever" view rather than having to
ls and read 60+ MB of report folders by hand.

Lane verdicts and fileable findings are parsed from each lane's
``results.md`` using a small set of conservative heuristics; commit SHAs
are looked up via ``git log --grep=<lane_name>`` when not embedded.

Emits Markdown by default to ``reports/ITER_INDEX.md`` (overwritten on
each run). ``--format json`` is also supported for downstream consumers.

Schema (JSON mode): ``auditooor.iter_rollup.v1``.

Usage::

    python3 tools/iter-rollup.py --since 60d --emit reports/ITER_INDEX.md
    python3 tools/iter-rollup.py --format json
    python3 tools/iter-rollup.py --workspace /Users/wolf/audits/hyperbridge
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = "auditooor.iter_rollup.v1"

REPO = Path(__file__).resolve().parent.parent

# Folder-name patterns. We accept the canonical ``v3_iter_YYYY-MM-DD``
# form and the ``_iter<N>`` / ``_phase_*`` variants that the V3 iter
# orchestrator emits.
ITER_FOLDER_RE = re.compile(
    r"^v3_iter_(?P<date>\d{4}-\d{2}-\d{2})(?P<suffix>(?:_iter\d+|_phase[\w-]*|))$"
)

LANE_FOLDER_PREFIX = "lane_"

# Verdict extraction. Lanes use a few shapes:
#   - "## VERDICT: DROP - foo"
#   - "## VERDICT" (header alone, body has free-form text)
#   - "- verdict: AUDIT-DEEP-MOSTLY-NOMINAL"
#   - "## Lane verdict\n\nPOSITIVE: ..." (header then prose)
VERDICT_INLINE_RE = re.compile(
    r"^##\s*(?:Lane\s+)?VERDICT(?:\s+SUMMARY)?[: ]+(?P<verdict>[^\n]+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
VERDICT_KV_RE = re.compile(
    r"^[-*]?\s*verdict\s*[:=]\s*(?P<verdict>[^\n]+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
VERDICT_HEADER_BODY_RE = re.compile(
    r"^##\s*(?:Lane\s+)?VERDICT\s*$\s*\n+(?P<body>[^\n]+)",
    re.MULTILINE | re.IGNORECASE,
)

# A POSITIVE verdict + a "Draft path" / "Submission draft" / "submissions/<status>"
# reference == a fileable finding produced by the lane.
POSITIVE_TOKENS = (
    "positive",
    "fileable",
    "novel",
    "ship",
    "fired",
    "confirmed",
    "valid",
)

DROP_TOKENS = (
    "drop",
    "no-novel",
    "skipped",
    "negative",
    "killed",
    "false-positive",
    "noop",
)

# Match draft / submission paths. We accept both the per-finding-folder
# layout (R41) and the legacy flat ``submissions/<status>/<slug>.md``.
DRAFT_PATH_RE = re.compile(
    r"(submissions/(?:staging|paste_ready|filed|packaged|ready|held|superseded|_killed|_oos_rejected)/[A-Za-z0-9._/-]+\.md)"
)

# Workspace hints. Lanes either declare it explicitly or just write
# "/Users/wolf/audits/<project>/..." paths.
WORKSPACE_DECL_RE = re.compile(
    r"^\s*[-*]?\s*(?:workspace|workspace-under-test)\s*[:=]\s*(?P<ws>[^\n]+)$",
    re.MULTILINE | re.IGNORECASE,
)
WORKSPACE_PATH_RE = re.compile(r"/Users/[^/]+/audits/(?P<ws>[a-zA-Z0-9_-]+)")

# Commit SHA hint embedded in results.md ("commit: abcdef1234").
COMMIT_INLINE_RE = re.compile(
    r"^\s*[-*]?\s*commit(?:\s+sha)?\s*[:=]\s*(?P<sha>[0-9a-f]{7,40})\s*$",
    re.MULTILINE | re.IGNORECASE,
)


@dataclass
class LaneRecord:
    iter_folder: str
    iter_date: str
    iter_variant: str  # "", "iter12", "phase_a", ...
    lane_name: str
    lane_dir: str
    results_md_path: str
    verdict: str
    verdict_class: str  # POSITIVE / DROP / NEUTRAL / UNKNOWN
    workspace: str
    fileable_draft_paths: list[str] = field(default_factory=list)
    commit_sha: str = ""
    results_md_size_bytes: int = 0

    @property
    def is_fileable(self) -> bool:
        return bool(self.fileable_draft_paths) and self.verdict_class == "POSITIVE"


@dataclass
class IterSummary:
    iter_folder: str
    iter_date: str
    iter_variant: str
    lane_count: int
    fileable_count: int
    verdict_counter: Counter
    lanes: list[LaneRecord] = field(default_factory=list)


def _classify_verdict(verdict_text: str) -> str:
    if not verdict_text:
        return "UNKNOWN"
    lower = verdict_text.lower()
    # DROP tokens are checked FIRST so that "DROP - no novel surface" classifies
    # as DROP (it contains "novel" which is also a POSITIVE token).
    for tok in DROP_TOKENS:
        if tok in lower:
            return "DROP"
    for tok in POSITIVE_TOKENS:
        if tok in lower:
            return "POSITIVE"
    if lower.strip() in {"noop", "nominal", "ok", "complete", "done"}:
        return "NEUTRAL"
    return "NEUTRAL"


def _extract_verdict(body: str) -> str:
    """Best-effort verdict extraction; returns "" if none found."""
    m = VERDICT_INLINE_RE.search(body)
    if m and m.group("verdict").strip():
        return m.group("verdict").strip()
    m = VERDICT_HEADER_BODY_RE.search(body)
    if m and m.group("body").strip():
        return m.group("body").strip().lstrip("- ").strip()
    m = VERDICT_KV_RE.search(body)
    if m and m.group("verdict").strip():
        return m.group("verdict").strip()
    return ""


def _extract_workspace(body: str, default: str = "") -> str:
    m = WORKSPACE_DECL_RE.search(body)
    if m:
        return m.group("ws").strip().strip("`'\"")
    m = WORKSPACE_PATH_RE.search(body)
    if m:
        return f"audits/{m.group('ws')}"
    return default


def _extract_fileable_drafts(body: str) -> list[str]:
    matches = DRAFT_PATH_RE.findall(body)
    # De-duplicate while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for m in matches:
        if m in seen:
            continue
        seen.add(m)
        ordered.append(m)
    return ordered


def _extract_commit_sha(body: str) -> str:
    m = COMMIT_INLINE_RE.search(body)
    if m:
        return m.group("sha").lower()[:12]
    return ""


def _git_log_commit_for_lane(repo: Path, lane_name: str) -> str:
    try:
        out = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "log",
                "--all",
                "--grep",
                lane_name,
                "--format=%H",
                "-n",
                "1",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        sha = (out.stdout or "").strip().splitlines()[0:1]
        if sha:
            return sha[0][:12]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return ""


def _parse_iter_folder(name: str) -> tuple[str, str] | None:
    m = ITER_FOLDER_RE.match(name)
    if not m:
        return None
    variant = m.group("suffix") or ""
    variant = variant.lstrip("_")  # "iter12" or "phase_a" or ""
    return m.group("date"), variant


def _within_window(iter_date: str, since_days: int) -> bool:
    if since_days <= 0:
        return True
    try:
        d = datetime.strptime(iter_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
    return d >= cutoff


def discover_lanes(
    reports_root: Path,
    *,
    since_days: int = 60,
    workspace_filter: str = "",
    git_lookup: bool = True,
) -> list[LaneRecord]:
    records: list[LaneRecord] = []
    if not reports_root.is_dir():
        return records
    for iter_dir in sorted(reports_root.iterdir()):
        if not iter_dir.is_dir():
            continue
        parsed = _parse_iter_folder(iter_dir.name)
        if parsed is None:
            continue
        iter_date, iter_variant = parsed
        if not _within_window(iter_date, since_days):
            continue
        for lane_dir in sorted(iter_dir.iterdir()):
            if not lane_dir.is_dir() or not lane_dir.name.startswith(LANE_FOLDER_PREFIX):
                continue
            results_md = lane_dir / "results.md"
            if not results_md.is_file():
                continue
            try:
                body = results_md.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            verdict_text = _extract_verdict(body)
            verdict_class = _classify_verdict(verdict_text)
            workspace = _extract_workspace(body)
            if workspace_filter and workspace_filter not in workspace:
                continue
            drafts = _extract_fileable_drafts(body)
            commit_sha = _extract_commit_sha(body)
            if not commit_sha and git_lookup:
                commit_sha = _git_log_commit_for_lane(REPO, lane_dir.name)
            rec = LaneRecord(
                iter_folder=iter_dir.name,
                iter_date=iter_date,
                iter_variant=iter_variant,
                lane_name=lane_dir.name[len(LANE_FOLDER_PREFIX) :],
                lane_dir=str(lane_dir.relative_to(reports_root.parent)),
                results_md_path=str(results_md.relative_to(reports_root.parent)),
                verdict=verdict_text or "(no verdict line found)",
                verdict_class=verdict_class,
                workspace=workspace,
                fileable_draft_paths=drafts,
                commit_sha=commit_sha,
                results_md_size_bytes=results_md.stat().st_size,
            )
            records.append(rec)
    return records


def summarize_by_iter(records: Iterable[LaneRecord]) -> list[IterSummary]:
    grouped: dict[str, list[LaneRecord]] = {}
    for r in records:
        grouped.setdefault(r.iter_folder, []).append(r)
    summaries: list[IterSummary] = []
    for folder, lanes in grouped.items():
        verdict_counter: Counter = Counter(l.verdict_class for l in lanes)
        first = lanes[0]
        summaries.append(
            IterSummary(
                iter_folder=folder,
                iter_date=first.iter_date,
                iter_variant=first.iter_variant,
                lane_count=len(lanes),
                fileable_count=sum(1 for l in lanes if l.is_fileable),
                verdict_counter=verdict_counter,
                lanes=sorted(lanes, key=lambda l: l.lane_name),
            )
        )
    summaries.sort(key=lambda s: (s.iter_date, s.iter_variant, s.iter_folder), reverse=True)
    return summaries


def _truncate(s: str, n: int) -> str:
    s = s.replace("|", "\\|").replace("\n", " ")
    if len(s) > n:
        return s[: n - 3] + "..."
    return s


def render_markdown(
    summaries: list[IterSummary],
    *,
    since_days: int,
    workspace_filter: str,
    generated_at: str,
) -> str:
    lines: list[str] = []
    lines.append("# Cross-iter hunt index")
    lines.append("")
    lines.append(f"Generated: `{generated_at}` (UTC)")
    lines.append("")
    lines.append(
        "Auto-emitted by `tools/iter-rollup.py` (schema "
        f"`{SCHEMA_VERSION}`). Regenerate via `make iter-rollup`."
    )
    lines.append("")
    scope = []
    scope.append(f"since={since_days}d")
    if workspace_filter:
        scope.append(f"workspace_filter={workspace_filter}")
    lines.append("Scope: " + ", ".join(scope))
    lines.append("")
    total_lanes = sum(s.lane_count for s in summaries)
    total_fileable = sum(s.fileable_count for s in summaries)
    lines.append(
        f"**Totals**: {len(summaries)} iter-folder(s), "
        f"{total_lanes} lane(s), {total_fileable} fileable finding(s)."
    )
    lines.append("")

    lines.append("## Per-iter overview")
    lines.append("")
    lines.append("| Iter folder | Date | Variant | Lanes | Fileable | Verdict mix |")
    lines.append("|---|---|---|---|---|---|")
    for s in summaries:
        mix = ", ".join(f"{k}:{v}" for k, v in sorted(s.verdict_counter.items()))
        lines.append(
            f"| `{s.iter_folder}` | {s.iter_date} | {s.iter_variant or '-'} | "
            f"{s.lane_count} | {s.fileable_count} | {mix or '-'} |"
        )
    lines.append("")

    lines.append("## Per-lane detail")
    lines.append("")
    for s in summaries:
        lines.append(f"### {s.iter_folder}")
        lines.append("")
        lines.append("| Lane | Verdict | Class | Workspace | Commit | Fileable |")
        lines.append("|---|---|---|---|---|---|")
        for l in s.lanes:
            fileable_cell = "yes" if l.is_fileable else "-"
            commit_cell = f"`{l.commit_sha}`" if l.commit_sha else "-"
            lines.append(
                f"| `{l.lane_name}` | {_truncate(l.verdict, 80)} | {l.verdict_class} | "
                f"{l.workspace or '-'} | {commit_cell} | {fileable_cell} |"
            )
        lines.append("")

    lines.append("## Fileable findings across iters")
    lines.append("")
    fileable_lanes = [l for s in summaries for l in s.lanes if l.is_fileable]
    if not fileable_lanes:
        lines.append("_None detected in the current window._")
    else:
        lines.append("| Iter | Lane | Workspace | Commit | Draft path(s) |")
        lines.append("|---|---|---|---|---|")
        for l in fileable_lanes:
            drafts_cell = "<br>".join(f"`{p}`" for p in l.fileable_draft_paths) or "-"
            commit_cell = f"`{l.commit_sha}`" if l.commit_sha else "-"
            lines.append(
                f"| `{l.iter_folder}` | `{l.lane_name}` | "
                f"{l.workspace or '-'} | {commit_cell} | {drafts_cell} |"
            )
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(summaries: list[IterSummary], *, since_days: int, workspace_filter: str, generated_at: str) -> str:
    payload = {
        "schema": SCHEMA_VERSION,
        "generated_at": generated_at,
        "since_days": since_days,
        "workspace_filter": workspace_filter,
        "totals": {
            "iter_folders": len(summaries),
            "lanes": sum(s.lane_count for s in summaries),
            "fileable": sum(s.fileable_count for s in summaries),
        },
        "iters": [
            {
                "iter_folder": s.iter_folder,
                "iter_date": s.iter_date,
                "iter_variant": s.iter_variant,
                "lane_count": s.lane_count,
                "fileable_count": s.fileable_count,
                "verdict_counter": dict(s.verdict_counter),
                "lanes": [asdict(l) for l in s.lanes],
            }
            for s in summaries
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _parse_since(value: str) -> int:
    """Accept "60d", "30d", "0" (== all), or raw integer day count."""
    v = value.strip().lower()
    if not v:
        return 60
    if v.endswith("d"):
        v = v[:-1]
    try:
        return max(0, int(v))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid --since value: {value!r}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cross-iter hunt index emitter.")
    parser.add_argument(
        "--reports-root",
        default=str(REPO / "reports"),
        help="reports/ root to walk (default: <repo>/reports)",
    )
    parser.add_argument(
        "--since",
        type=_parse_since,
        default=_parse_since("60d"),
        help="Look back window in days (e.g. 60d, 30d, 0 for all). Default: 60d.",
    )
    parser.add_argument(
        "--workspace",
        default="",
        help="Filter lanes to those whose workspace substring matches.",
    )
    parser.add_argument(
        "--format",
        choices=("md", "json"),
        default="md",
        help="Output format (default: md).",
    )
    parser.add_argument(
        "--emit",
        default="",
        help="Path to write output (default: stdout unless --format md, in which case reports/ITER_INDEX.md).",
    )
    parser.add_argument(
        "--no-git-lookup",
        action="store_true",
        help="Skip git log lookup for commit SHAs (faster, less complete).",
    )
    args = parser.parse_args(argv)

    reports_root = Path(args.reports_root)
    records = discover_lanes(
        reports_root,
        since_days=args.since,
        workspace_filter=args.workspace,
        git_lookup=not args.no_git_lookup,
    )
    summaries = summarize_by_iter(records)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.format == "json":
        out = render_json(
            summaries,
            since_days=args.since,
            workspace_filter=args.workspace,
            generated_at=generated_at,
        )
    else:
        out = render_markdown(
            summaries,
            since_days=args.since,
            workspace_filter=args.workspace,
            generated_at=generated_at,
        )

    if args.emit:
        emit_path = Path(args.emit)
    elif args.format == "md":
        emit_path = REPO / "reports" / "ITER_INDEX.md"
    else:
        emit_path = None

    if emit_path is None:
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
    else:
        emit_path.parent.mkdir(parents=True, exist_ok=True)
        emit_path.write_text(out, encoding="utf-8")
        print(f"[iter-rollup] wrote {emit_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
