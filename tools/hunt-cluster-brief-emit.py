#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""hunt-cluster-brief-emit.py - step 5: per-cluster dispatch briefs.

For every in-scope cluster enumerated from ``<WS>/SCOPE.md``, emit a
dispatch brief under ``<WS>/.auditooor/hunt_cluster_briefs/<cluster>.md``.
Every brief embeds two load-bearing blocks:

  1. The CANONICAL HUNT DEFINITION (a hunt is the full pipeline; a
     shallow/partial/repeated pass is rejected by hunt-completeness-check).
  2. The DEDUP-FIRST directive + a digest of ``hunt_skip_set.json`` so the
     worker SKIPS already-filed / killed / dead-ended candidates BEFORE
     deriving anything.

Deterministic, stdlib-only, offline-safe. Reuses the SCOPE.md cluster
parser shape used by hunt-completeness-check so the cluster set is
consistent across the two gates.

CLI
---
    python3 tools/hunt-cluster-brief-emit.py <workspace> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

SCHEMA = "auditooor.l36_cluster_brief_emit.v1"
GATE = "L36-CLUSTER-BRIEF-EMIT"

_IN_SCOPE_SECTION_RE = re.compile(
    r"^(?:scope|in[- ]scope\b.*|assets? classes?|assets? in[- ]scope\b.*|"
    r"smart contracts? in[- ]scope\b.*|github targets?)$",
    re.IGNORECASE,
)
_OOS_SECTION_RE = re.compile(
    r"\b(?:out[- ]of[- ]scope|oos|assumptions?|target|protocol summary)\b",
    re.IGNORECASE,
)
_TITLE_SCOPE_RE = re.compile(r"\bscope\b", re.IGNORECASE)


def _is_cluster_section(heading: str) -> bool:
    norm = re.sub(r"\s+", " ", heading.strip().lower())
    if not norm or _OOS_SECTION_RE.search(norm):
        return False
    return bool(_IN_SCOPE_SECTION_RE.match(norm))


def _is_title_scope_heading(heading: str, level: int) -> bool:
    return level == 1 and bool(_TITLE_SCOPE_RE.search(heading))


def _clean_cluster_name(value: str) -> str:
    name = re.split(r"\s+[-:(]", value.strip())[0].strip()
    return name.replace("`", "").strip()

CANONICAL_HUNT_DEFINITION = (
    "A hunt is the FULL pipeline (dedup-first + deep clone + Tier-6 "
    "bidirectional mining + audit-deep + all-cluster coverage + artifact "
    "mining). FIRST consult <ws>/.auditooor/hunt_skip_set.json and SKIP "
    "anything already filed/killed/dead-ended. A shallow/partial/repeated "
    "pass is NOT a hunt and is rejected by hunt-completeness-check."
)


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def _parse_scope_clusters(ws: Path) -> list[str]:
    scope = ws / "SCOPE.md"
    txt = _read_text(scope)
    if not txt:
        return []
    clusters: list[str] = []
    saw_heading = False
    active_section = True
    for raw in txt.splitlines():
        line = raw.strip()
        heading = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if heading:
            saw_heading = True
            active_section = (
                _is_title_scope_heading(heading.group(2), len(heading.group(1)))
                or _is_cluster_section(heading.group(2))
            )
            continue
        if saw_heading and not active_section:
            continue
        m = re.match(r"^[-*+]\s+(.+)$", line)
        if m:
            name = _clean_cluster_name(m.group(1))
            if name and len(name) <= 120:
                clusters.append(name)
            continue
        if line.startswith("|") and "|" in line[1:]:
            cells = [c.strip() for c in line.strip("|").split("|")]
            if cells and not all(set(c) <= set("-: ") for c in cells if c):
                first = cells[0].strip("`").strip()
                if first and first.lower() not in (
                    "component", "cluster", "scope", "repo", "asset", "category"
                ):
                    clusters.append(first)
    seen = set()
    out = []
    for c in clusters:
        key = c.lower()
        if key and key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "cluster"


def _load_skip_set(ws: Path) -> dict:
    p = ws / ".auditooor" / "hunt_skip_set.json"
    txt = _read_text(p)
    if not txt:
        return {}
    try:
        d = json.loads(txt)
        return d if isinstance(d, dict) else {}
    except (ValueError, json.JSONDecodeError):
        return {}


def _skip_set_digest(skip_set: dict, limit: int = 25) -> list[str]:
    entries = skip_set.get("entries", []) if isinstance(skip_set, dict) else []
    out: list[str] = []
    for e in entries[:limit]:
        if not isinstance(e, dict):
            continue
        slug = e.get("slug", "")
        verdict = e.get("verdict", "")
        fl = e.get("file_line", "")
        rc = e.get("root_cause", "")
        bits = [b for b in (slug, verdict, fl) if b]
        line = " | ".join(bits)
        if rc and rc not in line:
            line = f"{line} - {rc[:80]}" if line else rc[:80]
        if line:
            out.append(line)
    return out


def _brief_body(cluster: str, ws: Path, skip_set: dict) -> str:
    counts = skip_set.get("source_counts", {}) if isinstance(skip_set, dict) else {}
    total = counts.get("total_after_dedup", 0)
    digest = _skip_set_digest(skip_set)
    lines = [
        f"# Hunt cluster brief: {cluster}",
        "",
        f"_Workspace: {ws}_",
        "",
        "## Canonical hunt definition (READ FIRST)",
        "",
        CANONICAL_HUNT_DEFINITION,
        "",
        "## DEDUP-FIRST directive (MANDATORY)",
        "",
        (f"Consult `<ws>/.auditooor/hunt_skip_set.json` "
         f"({total} known entries). SKIP any candidate whose slug / "
         "root-cause / file:line matches an entry below. Re-deriving a "
         "known dead-end or re-filing a prior finding is a wasted-cycle "
         "defect that hunt-completeness-check and the loop-finalization "
         "gate will surface."),
        "",
        "### Skip-set digest (already filed/killed/dead-ended)",
        "",
    ]
    if digest:
        for d in digest:
            lines.append(f"- {d}")
        if total > len(digest):
            lines.append(f"- ... ({total - len(digest)} more in hunt_skip_set.json)")
    else:
        lines.append("- (skip-set empty - fresh engagement; nothing to skip yet)")
    lines += [
        "",
        f"## Cluster scope: {cluster}",
        "",
        (f"Drill the `{cluster}` in-scope surface to completeness. Emit "
         "every candidate via `tools/workflow-drill-sidecar-emit.py` so "
         "coverage counts it, and log intentional skips in "
         "`<ws>/.auditooor/hunt_coverage_skips.txt`."),
        "",
    ]
    return "\n".join(lines) + "\n"


def run(ws: Path) -> dict:
    clusters = _parse_scope_clusters(ws)
    skip_set = _load_skip_set(ws)
    out_dir = ws / ".auditooor" / "hunt_cluster_briefs"
    written: list[str] = []
    if not clusters:
        return {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "pass-no-clusters",
            "reason": "SCOPE.md absent or enumerates 0 clusters; no briefs emitted",
            "briefs": [],
        }
    out_dir.mkdir(parents=True, exist_ok=True)
    for cluster in clusters:
        slug = _slugify(cluster)
        path = out_dir / f"{slug}.md"
        path.write_text(_brief_body(cluster, ws, skip_set), encoding="utf-8")
        written.append(str(path))
    return {
        "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
        "verdict": "pass-briefs-emitted",
        "reason": f"emitted {len(written)} per-cluster brief(s) with skip-set + canonical-hunt-def embedded",
        "briefs": written,
        "skip_set_entries": (skip_set.get("source_counts", {}) or {}).get("total_after_dedup", 0),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hunt-cluster-brief-emit.py", description=__doc__)
    p.add_argument("workspace")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not _exists(ws) or not ws.is_dir():
        payload = {"schema": SCHEMA, "gate": GATE, "workspace": str(ws),
                   "verdict": "error", "reason": "workspace not found"}
        print(json.dumps(payload, indent=2) if args.json else f"[{GATE}] verdict=error")
        return 2

    result = run(ws)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{GATE}] verdict={result['verdict']} - {result['reason']}")
        for b in result.get("briefs", []):
            print(f"  brief: {b}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
