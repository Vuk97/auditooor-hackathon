#!/usr/bin/env python3
"""wave3-cluster-to-hacker-brief - convert engage_report clusters to Hacker Briefs.

Reads ``<ws>/engage_report.md`` (produced by ``make audit WS=<ws>``) and emits
per-cluster Hacker Brief markdown (or JSON) that downstream agent dispatch can
consume via the ``vault_hacker_brief_for_lane`` MCP callable.

The brief is STRUCTURAL only.  It enumerates the cluster shape, the file:line
references the detectors fired on, a precondition / action / impact template,
a severity-rubric candidate row, a PoC-shape sketch, an originality angle
prompt, and Rule 30 production-profile scaffold hints.  It does NOT propose
specific findings or exploits.

PRIOR_CONCERNS.md is checked: if the cluster name (or one of its detector ids)
matches a prior acknowledge-by-design entry, the brief is BLOCKED with a
diagnostic instead of emitted.  Use ``--allow-blocked`` to override (for
debugging).

DISPATCH PRIORITY (LANE W5-H2): in ``--all`` batch mode the cluster order is,
by default, the order the parser produced them in.  Pass ``--priority-json``
pointing at an ``auditooor.bug_class_priority.v1`` envelope (the output of
``tools/audit/bug-class-prioritizer.py``) and the clusters are re-ordered so
that the cluster whose attack class ranks highest in the prioritizer's ranked
list is briefed FIRST.  This makes the 11-agent dispatch hunt the
highest-priority attack classes before the long tail, instead of being blind
to the W4.13 ranking.  Each brief's run-summary row carries the resolved
``priority_rank`` so the operator can see WHY a cluster sorted where it did.

Usage:
    python3 tools/wave3-cluster-to-hacker-brief.py --workspace <ws> \\
            --cluster <cluster-name> [--format markdown|json] [--out-dir DIR]
    python3 tools/wave3-cluster-to-hacker-brief.py --workspace <ws> --all
    python3 tools/wave3-cluster-to-hacker-brief.py --workspace <ws> --all \\
            --priority-json <ws>/bug_class_priority.json

Schema (auditooor.wave3_hacker_brief.v1):
    cluster_name, hits[], precondition, action, impact,
    severity_rubric_candidate, poc_shape, originality_angle,
    rule30_scaffold_notes, blocked, block_reason.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA = "auditooor.wave3_hacker_brief.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Engage report loader (delegates to tools/engage-report-parser.py).
# ---------------------------------------------------------------------------


def _load_engage_parser():
    """Dynamically import tools/engage-report-parser.py (hyphenated name)."""
    tool_path = REPO_ROOT / "tools" / "engage-report-parser.py"
    spec = importlib.util.spec_from_file_location("engage_report_parser", str(tool_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load engage-report-parser from {tool_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_engage_report(report_path: Path) -> Dict[str, Any]:
    """Parse engage_report.md via the canonical engage-report-parser tool."""
    mod = _load_engage_parser()
    return mod.parse_engage_report(report_path)


# ---------------------------------------------------------------------------
# PRIOR_CONCERNS.md probe.
# ---------------------------------------------------------------------------


ACK_MARKERS = (
    "acknowledged-by-design",
    "acknowledged by design",
    "ack-by-design",
    "by-design",
    "intentional",
    "wontfix",
    "won't fix",
    "out of scope",
    "out-of-scope",
    "informational only",
)


def probe_prior_concerns(
    prior_concerns_path: Path,
    cluster_name: str,
    detector_ids: List[str],
) -> Tuple[bool, str]:
    """Return (blocked, reason).  Blocked if a PRIOR_CONCERNS row matches."""
    if not prior_concerns_path.exists():
        return False, ""

    try:
        text = prior_concerns_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False, ""

    needles: List[str] = []
    if cluster_name:
        needles.append(cluster_name.lower())
    for det in detector_ids:
        if det:
            needles.append(det.lower())

    lines = text.splitlines()
    for idx, raw_line in enumerate(lines):
        lo = raw_line.lower()
        if not any(ack in lo for ack in ACK_MARKERS):
            continue
        block = "\n".join(lines[idx : idx + 3]).lower()
        for needle in needles:
            if needle and needle in block:
                snippet = raw_line.strip()[:200]
                return (
                    True,
                    f"PRIOR_CONCERNS row matches cluster/detector (ack-by-design): {snippet}",
                )
    return False, ""


# ---------------------------------------------------------------------------
# Severity-rubric mapping.
# ---------------------------------------------------------------------------


def severity_rubric_candidate(severity: str) -> str:
    """Translate detector severity to a structural rubric-row hint.

    This is a HINT for the agent to verify against the engagement's actual
    SEVERITY.md.  It does not assert filability.
    """
    s = (severity or "").upper().strip()
    if s == "CRITICAL":
        return (
            "Candidate: Critical rubric row (e.g. 'Direct loss of funds', "
            "'Permanent freezing of funds (fix requires hardfork)'). "
            "Verify against engagement SEVERITY.md and confirm verbatim match "
            "before drafting at Critical."
        )
    if s == "HIGH":
        return (
            "Candidate: High rubric row (e.g. 'RPC API crash affecting "
            ">=25% of market cap', 'Significant theft / freeze of funds'). "
            "Verify against engagement SEVERITY.md."
        )
    if s == "MEDIUM":
        return (
            "Candidate: Medium rubric row (state inconsistency, "
            "griefing, conditional fund-loss). Many engagements have NO "
            "Medium tier (e.g. Spark Immunefi); verify against engagement "
            "SEVERITY.md verbatim before drafting."
        )
    if s == "LOW":
        return (
            "Candidate: Low / Informational. Often detector telemetry only. "
            "Build evidence to a rubric-verbatim higher tier OR drop."
        )
    return (
        "Candidate: severity unclassified; map detector hit to engagement "
        "SEVERITY.md verbatim before drafting."
    )


# ---------------------------------------------------------------------------
# Dispatch priority (LANE W5-H2): consume the W4.13 bug-class prioritizer.
# ---------------------------------------------------------------------------


PRIORITY_SCHEMA = "auditooor.bug_class_priority.v1"


def load_priority_ranking(priority_json_path: Path) -> Dict[str, int]:
    """Load a bug-class-prioritizer envelope -> {attack_class: rank}.

    The prioritizer (tools/audit/bug-class-prioritizer.py) emits an
    ``auditooor.bug_class_priority.v1`` envelope whose ``ranked_attack_classes``
    list is already sorted best-first, each row carrying ``attack_class`` and
    ``rank`` (1 = highest priority).  This returns a flat lookup so the brief
    generator can sort clusters without re-implementing the scoring.

    A missing / malformed file returns an empty map (callers fall back to the
    parser's native cluster order, so a bad priority file degrades gracefully
    rather than crashing the dispatch).
    """
    if not priority_json_path.exists():
        return {}
    try:
        env = json.loads(priority_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(env, dict):
        return {}
    ranking: Dict[str, int] = {}
    for row in env.get("ranked_attack_classes", []) or []:
        if not isinstance(row, dict):
            continue
        cls = row.get("attack_class")
        rank = row.get("rank")
        if isinstance(cls, str) and isinstance(rank, int):
            # keep the best (lowest) rank if a class appears twice
            if cls not in ranking or rank < ranking[cls]:
                ranking[cls] = rank
    return ranking


def cluster_priority_rank(
    cluster: Dict[str, Any],
    ranking: Dict[str, int],
) -> int:
    """Resolve a cluster's dispatch rank from the prioritizer ranking.

    A cluster maps onto an attack class via its cluster name and the detector
    ids that fired in it.  The best (lowest) rank of any match wins, so a
    cluster touching a high-priority class is briefed first even if it also
    touches lower-priority classes.  Clusters with no match get a sentinel
    rank that sorts them after every ranked cluster but preserves their
    relative parser order.
    """
    if not ranking:
        return 0
    candidates = []
    cname = cluster.get("cluster_name") or cluster.get("name") or ""
    if cname:
        candidates.append(str(cname))
    for h in cluster.get("hits", []) or []:
        det = h.get("detector_id") or h.get("detector")
        if det:
            candidates.append(str(det))
    best = None
    for key in candidates:
        if key in ranking:
            r = ranking[key]
            best = r if best is None else min(best, r)
    # sentinel: unmatched clusters sort after the last ranked class.
    return best if best is not None else (max(ranking.values()) + 1)


def order_clusters_by_priority(
    clusters: List[Dict[str, Any]],
    ranking: Dict[str, int],
) -> List[Dict[str, Any]]:
    """Stable-sort clusters by prioritizer rank (rank 1 first).

    When ``ranking`` is empty the parser's native order is returned unchanged.
    The sort is stable, so clusters that share a rank (or are all unmatched)
    keep their original relative order - deterministic for tests and dispatch.
    """
    if not ranking:
        return list(clusters)
    decorated = [
        (cluster_priority_rank(c, ranking), idx, c)
        for idx, c in enumerate(clusters)
    ]
    decorated.sort(key=lambda t: (t[0], t[1]))
    return [c for _, _, c in decorated]


# ---------------------------------------------------------------------------
# Brief templates (structural, not finding-specific).
# ---------------------------------------------------------------------------


def precondition_template(cluster_name: str, hits: List[Dict[str, Any]]) -> str:
    n_hits = len(hits)
    distinct_files = sorted({h.get("file_path", "") for h in hits if h.get("file_path")})
    return (
        f"Detector cluster `{cluster_name}` fired on {n_hits} site(s) across "
        f"{len(distinct_files)} distinct file(s). The attacker reaches one of "
        "these call sites through normal protocol entry points. Identify which "
        "external entry points (public/external functions, RPC endpoints, "
        "message handlers, ABCI transactions) route to the cluster site, and "
        "what call-sequence or state-pre-state the attacker must arrange to "
        "make the detector pattern fire at runtime."
    )


def action_template(cluster_name: str) -> str:
    return (
        "Construct a call sequence that drives execution into the cluster "
        "site under attacker-controlled inputs. The detector flagged a "
        "structural pattern; the action step turns that pattern into a "
        "concrete payload (inputs, state pre-conditions, sender identity)."
    )


def impact_template(cluster_name: str, severity: str) -> str:
    return (
        "Impact follows from the detector class. Enumerate the concrete "
        "asset / invariant / liveness property the cluster site protects, "
        "and demonstrate a measurable violation under attacker-controlled "
        "inputs (balance delta, state-transition violation, halted-block, "
        "AppHash divergence, etc.). Map the demonstrated violation to a "
        f"rubric row verbatim (severity hint: {severity})."
    )


def poc_shape_template(cluster_name: str, hits: List[Dict[str, Any]]) -> str:
    file_hint = ""
    if hits:
        f = hits[0].get("file_path", "")
        ln = hits[0].get("line", 0)
        if f:
            file_hint = f" (first site: `{f}:{ln}`)"
    return (
        f"Sketch a PoC against the cluster site{file_hint}. "
        "If the engagement is Solidity, write a Foundry test that calls the "
        "external entry-point with attacker inputs and asserts the violated "
        "invariant via `assertEq` / `assertLt` against a victim balance / "
        "protocol-state field. If the engagement is Go/cosmos-sdk, prefer a "
        "node-level harness (BaseApp.FinalizeBlock or BroadcastTxSync) so the "
        "PoC traverses the full ante / handler chain (Rule 25 / Rule 26). "
        "If the engagement is Rust/Anchor, use program-test against a real "
        "ledger fork."
    )


def originality_angle_template(cluster_name: str, detector_ids: List[str]) -> str:
    return (
        "Before drafting, cross-check the cluster against:\n"
        "  (1) prior Cantina / Code4rena / Sherlock / Immunefi reports on the same target;\n"
        "  (2) audit firm PDFs in `audit/corpus_tags/tags/firm-*-audits/` for the same bug class;\n"
        "  (3) the upstream / sibling repo's commit log around the audit-pin (Tier-6 backward mining);\n"
        "  (4) the workspace's own `submissions/{paste_ready,staging,held,superseded}/` for prior filings;\n"
        f"  (5) detector ids that fired: {', '.join(detector_ids) if detector_ids else '(none)'}."
    )


def rule30_scaffold_template(severity: str) -> str:
    sev = (severity or "").upper()
    if sev in ("CRITICAL", "HIGH"):
        return (
            "Rule 30 (production-profile PoC) applies for HIGH/CRITICAL: "
            "use a real persistent backend (goleveldb / pebble / rocksdb) "
            "instead of MemDB; avoid timing / fault shims around DB primitives; "
            "no reflection writes to private runtime fields; multi-validator "
            "demonstration for network-level liveness claims; disclose the "
            "bug-fires-at threshold against documented validator hardware. "
            "Run `python3 tools/production-profile-preflight-check.py <draft.md>` "
            "before promoting to paste_ready/."
        )
    return (
        "Rule 30 (production-profile PoC) is not mandated at this severity "
        "hint, but if the bug class shifts upward during evidence build, "
        "rerun the preflight before promoting."
    )


# ---------------------------------------------------------------------------
# Brief rendering (markdown + json).
# ---------------------------------------------------------------------------


def build_brief(
    cluster: Dict[str, Any],
    workspace: str,
    blocked: bool = False,
    block_reason: str = "",
) -> Dict[str, Any]:
    """Build the structured brief record."""
    cluster_name = cluster.get("cluster_name", "")
    hits = cluster.get("hits", []) or []
    detector_ids = sorted({h.get("detector_id", "") for h in hits if h.get("detector_id")})
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}
    severity = ""
    for h in hits:
        s = (h.get("severity") or "").upper()
        if sev_rank.get(s, 0) > sev_rank.get(severity, 0):
            severity = s

    record: Dict[str, Any] = {
        "schema": SCHEMA,
        "workspace": workspace,
        "cluster_name": cluster_name,
        "hit_count": len(hits),
        "detector_ids": detector_ids,
        "dominant_severity": severity,
        "hits": hits,
        "precondition": precondition_template(cluster_name, hits),
        "action": action_template(cluster_name),
        "impact": impact_template(cluster_name, severity),
        "severity_rubric_candidate": severity_rubric_candidate(severity),
        "poc_shape": poc_shape_template(cluster_name, hits),
        "originality_angle": originality_angle_template(cluster_name, detector_ids),
        "rule30_scaffold_notes": rule30_scaffold_template(severity),
        "blocked": blocked,
        "block_reason": block_reason,
    }
    return record


def render_markdown(record: Dict[str, Any]) -> str:
    """Render the brief as a Hacker Brief markdown document."""
    lines: List[str] = []
    cluster_name = record["cluster_name"]
    lines.append(f"# Hacker Brief: {cluster_name}")
    lines.append("")
    if record.get("blocked"):
        lines.append("> **BLOCKED** - this cluster matches a PRIOR_CONCERNS")
        lines.append("> acknowledge-by-design row. Do not draft a finding from it.")
        lines.append(f">")
        lines.append(f"> Reason: {record.get('block_reason', '')}")
        lines.append("")
    lines.append("## Cluster summary")
    lines.append("")
    lines.append(f"- Cluster name: `{cluster_name}`")
    lines.append(f"- Workspace: `{record.get('workspace', '')}`")
    lines.append(f"- Hit count: {record['hit_count']}")
    lines.append(f"- Dominant severity (detector hint): {record['dominant_severity'] or '(unknown)'}")
    det_ids = record.get("detector_ids", [])
    if det_ids:
        lines.append(f"- Detectors fired: {', '.join(f'`{d}`' for d in det_ids)}")
    lines.append("")
    lines.append("## Affected sites")
    lines.append("")
    hits = record.get("hits", []) or []
    if not hits:
        lines.append("- (no parseable hits)")
    else:
        for h in hits:
            sev = h.get("severity", "")
            det = h.get("detector_id", "")
            fp = h.get("file_path", "")
            ln = h.get("line", 0)
            snip = h.get("snippet", "")
            row = f"- [{sev}] `{det}` - `{fp}:{ln}`"
            if snip:
                row += f"  snippet: `{snip}`"
            lines.append(row)
    lines.append("")
    lines.append("## Precondition")
    lines.append("")
    lines.append(record["precondition"])
    lines.append("")
    lines.append("## Action")
    lines.append("")
    lines.append(record["action"])
    lines.append("")
    lines.append("## Impact")
    lines.append("")
    lines.append(record["impact"])
    lines.append("")
    lines.append("## Severity rubric candidate")
    lines.append("")
    lines.append(record["severity_rubric_candidate"])
    lines.append("")
    lines.append("## PoC shape")
    lines.append("")
    lines.append(record["poc_shape"])
    lines.append("")
    lines.append("## Originality angle")
    lines.append("")
    lines.append(record["originality_angle"])
    lines.append("")
    lines.append("## Rule 30 scaffold notes")
    lines.append("")
    lines.append(record["rule30_scaffold_notes"])
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"_schema: {SCHEMA}_")
    lines.append(
        "_This brief is structural only. It does not propose a specific "
        "finding or exploit. The agent must build evidence and verify the "
        "rubric-verbatim match before drafting at any severity._"
    )
    lines.append("")
    return "\n".join(lines)


def safe_slug(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", name).strip("-")
    return s or "cluster"


def write_brief(
    record: Dict[str, Any],
    out_dir: Path,
    fmt: str,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = safe_slug(record["cluster_name"])
    if fmt == "json":
        out_path = out_dir / f"hacker-brief-{slug}.json"
        out_path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    else:
        out_path = out_dir / f"hacker-brief-{slug}.md"
        out_path.write_text(render_markdown(record), encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------


def process_workspace(
    workspace: Path,
    cluster_name: Optional[str],
    out_dir: Path,
    fmt: str,
    process_all: bool,
    allow_blocked: bool,
    priority_json: Optional[Path] = None,
) -> Dict[str, Any]:
    report_path = workspace / "engage_report.md"
    parsed = parse_engage_report(report_path)
    if not parsed.get("clusters"):
        return {
            "ok": False,
            "error": "no clusters in engage_report.md (or file missing)",
            "engage_report_path": str(report_path),
            "parse_ok": parsed.get("parse_ok", False),
            "briefs": [],
        }

    prior_concerns_path = workspace / "PRIOR_CONCERNS.md"

    # LANE W5-H2: consume the W4.13 bug-class prioritizer when --priority-json
    # is given.  Default path <ws>/bug_class_priority.json is auto-detected so
    # a workspace that produced one gets priority dispatch with no extra flag.
    if priority_json is None:
        default_priority = workspace / "bug_class_priority.json"
        if default_priority.exists():
            priority_json = default_priority
    ranking: Dict[str, int] = (
        load_priority_ranking(priority_json) if priority_json else {}
    )
    priority_applied = bool(ranking)

    targets: List[Dict[str, Any]]
    if process_all:
        targets = order_clusters_by_priority(parsed["clusters"], ranking)
    else:
        if not cluster_name:
            return {
                "ok": False,
                "error": "either --cluster <name> or --all is required",
                "briefs": [],
            }
        targets = [c for c in parsed["clusters"] if c.get("cluster_name") == cluster_name]
        if not targets:
            return {
                "ok": False,
                "error": f"cluster not found: {cluster_name}",
                "available_clusters": [c.get("cluster_name") for c in parsed["clusters"]],
                "briefs": [],
            }

    briefs: List[Dict[str, Any]] = []
    for dispatch_order, cluster in enumerate(targets, start=1):
        cname = cluster.get("cluster_name", "")
        det_ids = sorted({
            h.get("detector_id", "") for h in (cluster.get("hits") or []) if h.get("detector_id")
        })
        # LANE W5-H2: resolved dispatch rank from the prioritizer.  When no
        # priority file was loaded, priority_rank stays None and dispatch_order
        # is just the parser's native order.
        priority_rank = (
            cluster_priority_rank(cluster, ranking) if priority_applied else None
        )
        blocked, reason = probe_prior_concerns(prior_concerns_path, cname, det_ids)
        if blocked and not allow_blocked:
            briefs.append({
                "cluster_name": cname,
                "blocked": True,
                "block_reason": reason,
                "written_to": None,
                "dispatch_order": dispatch_order,
                "priority_rank": priority_rank,
            })
            continue

        record = build_brief(cluster, str(workspace), blocked=blocked, block_reason=reason)
        out_path = write_brief(record, out_dir, fmt)
        briefs.append({
            "cluster_name": cname,
            "blocked": blocked,
            "block_reason": reason,
            "written_to": str(out_path),
            "dispatch_order": dispatch_order,
            "priority_rank": priority_rank,
        })

    return {
        "ok": True,
        "workspace": str(workspace),
        "engage_report_path": str(report_path),
        "format": fmt,
        "out_dir": str(out_dir),
        "priority_applied": priority_applied,
        "priority_json": str(priority_json) if priority_json else None,
        "briefs": briefs,
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--workspace", required=True, help="Path to the workspace directory")
    p.add_argument("--cluster", default=None, help="Cluster name to emit a brief for")
    p.add_argument("--all", action="store_true", help="Process every cluster in engage_report.md")
    p.add_argument("--out-dir", default=None, help="Output directory (default <ws>/hacker_briefs/)")
    p.add_argument("--format", choices=("markdown", "json"), default="markdown")
    p.add_argument(
        "--allow-blocked",
        action="store_true",
        help="Emit briefs even when PRIOR_CONCERNS flags the cluster as acknowledge-by-design (debug)",
    )
    p.add_argument(
        "--priority-json",
        default=None,
        help=(
            "Path to an auditooor.bug_class_priority.v1 envelope "
            "(tools/audit/bug-class-prioritizer.py output). In --all mode the "
            "clusters are dispatched highest-priority attack class first. "
            "Defaults to <ws>/bug_class_priority.json if that file exists."
        ),
    )
    p.add_argument("--json", action="store_true", help="Emit the run-summary as JSON to stdout")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        print(f"error: workspace not found: {workspace}", file=sys.stderr)
        return 2
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else workspace / "hacker_briefs"

    if not args.all and not args.cluster:
        print("error: --cluster <name> or --all is required", file=sys.stderr)
        return 2

    priority_json = (
        Path(args.priority_json).expanduser().resolve()
        if args.priority_json
        else None
    )

    result = process_workspace(
        workspace=workspace,
        cluster_name=args.cluster,
        out_dir=out_dir,
        fmt=args.format,
        process_all=bool(args.all),
        allow_blocked=bool(args.allow_blocked),
        priority_json=priority_json,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if not result.get("ok"):
            print(f"error: {result.get('error')}", file=sys.stderr)
            avail = result.get("available_clusters")
            if avail:
                print("available clusters:", file=sys.stderr)
                for c in avail:
                    print(f"  - {c}", file=sys.stderr)
            return 1
        print(f"workspace: {result['workspace']}")
        print(f"out-dir:   {result['out_dir']}")
        print(f"format:    {result['format']}")
        if result.get("priority_applied"):
            print(f"priority:  W4.13 ranking applied ({result.get('priority_json')})")
        else:
            print("priority:  none (parser-native cluster order)")
        print(f"briefs:    {len(result['briefs'])}")
        for b in result["briefs"]:
            tag = "BLOCKED" if b.get("blocked") else "WRITTEN"
            rank = b.get("priority_rank")
            rank_s = f" [rank {rank}]" if rank is not None else ""
            order = b.get("dispatch_order")
            order_s = f"#{order} " if order is not None else ""
            print(
                f"  {order_s}[{tag}]{rank_s} {b['cluster_name']} -> "
                f"{b.get('written_to') or '(none)'}"
            )
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
