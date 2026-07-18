#!/usr/bin/env python3
"""Walk the protocol-similarity graph and propose bug-class transfers.

Given a target workspace, consult the similarity graph emitted by
``protocol-similarity-graph.py``, find each high-similarity neighbor in another
workspace or the contest cache, and surface the bug classes that landed in
those neighbors. The output is a markdown checklist for the audit-kickoff
review.

Bug-class signal sources, in priority order:

1. ``known_vuln_hits`` from each neighbor node (contract name matched a
   ``patterns.dsl`` regex).
2. ``FINDINGS.md`` text in the neighbor workspace — specifically headings
   that introduce a candidate finding.

We do not invent suggestions. If no neighbor has any of the above, the tool
emits an honest "graph too sparse for this workspace" line so the operator
knows the gap is in the data, not a workflow miss.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GRAPH = REPO_ROOT / "reports" / "protocol_similarity_graph.json"
DEFAULT_AUDITS_ROOT = Path.home() / "audits"

DEFAULT_THRESHOLD = 0.50
DEFAULT_MAX_SUGGESTIONS = 25
DEFAULT_MAX_NEIGHBORS_PER_NODE = 5

FINDING_HEADING_RE = re.compile(
    r"^#{2,4}\s+(?:Candidate\s+|#)?(?:FN[-\s]*\d+|[A-Z]\d+|F\d+|FN\d+|\d+\.)?\s*[\-\—:]?\s*"
    r"(?P<title>[^\n]+)$",
    re.MULTILINE,
)
SECTION_FINDING_RE = re.compile(
    r"^###?\s+(?:#?\w+[\s\-—]+)?(?P<title>.{8,160})$",
    re.MULTILINE,
)

# Coarse bug-class keywords used to bucket free-form titles.
BUG_CLASS_KEYWORDS = [
    ("reentrancy",        ["reentrancy", "reenter", "cei "]),
    ("oracle-manipulation", ["oracle", "twap", "chainlink", "stale price", "price manipul"]),
    ("rounding-direction", ["round", "rounding", "off-by-one", "off by one", "favor", "shares-up", "shares-down"]),
    ("first-deposit-inflation", ["first deposit", "inflation attack", "share inflation", "donation attack", "vault donation"]),
    ("share-asset-mispricing", ["share", "asset", "convertto", "preview", "pps", "price-per-share"]),
    ("erc4626-conformance", ["erc-4626", "erc4626", "4626"]),
    ("flash-loan-bypass",  ["flash loan", "flashloan"]),
    ("signature-replay",   ["replay", "ecdsa", "permit", "signature"]),
    ("nonce-bypass",       ["nonce"]),
    ("slippage-bypass",    ["slippage", "min amount out", "amountout", "min-out"]),
    ("access-control",     ["access control", "owner", "role", "auth", "only"]),
    ("delegatecall-misuse", ["delegatecall"]),
    ("storage-collision",  ["storage collision", "storage layout", "storage slot"]),
    ("upgrade-init",       ["initializ", "upgrade", "proxy"]),
    ("liquidation-grief",  ["liquidat"]),
    ("gas-grief-dos",      ["dos", "denial of service", "grief", "out-of-gas"]),
    ("front-run",          ["front-run", "frontrun", "sandwich", "mev"]),
    ("bridge-finality",    ["bridge", "finality", "withdraw", "deposit"]),
    ("withdraw-griefing",  ["withdraw", "queue", "redeem"]),
    ("rebase-rounding",    ["rebase", "elastic", "rebasing"]),
    ("missing-event",      ["missing event", "event emission"]),
]


def load_graph(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def neighbors_of_workspace(
    graph: dict[str, Any],
    workspace_label: str,
    threshold: float,
    max_per_node: int,
) -> dict[str, list[dict[str, Any]]]:
    """Return ``{node_id_in_target -> [neighbor_edge, ...]}`` for the workspace.

    Only edges that cross workspace boundaries are kept (we want
    cross-protocol transfer, not same-protocol echoes).
    """
    nodes_by_id = {n["id"]: n for n in graph["nodes"]}
    target_ids = {n["id"] for n in graph["nodes"] if n["workspace"] == workspace_label}
    if not target_ids:
        return {}
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in graph["edges"]:
        if e["weight"] < threshold:
            continue
        a, b = e["src"], e["dst"]
        if a in target_ids and b not in target_ids:
            tgt, neigh = a, b
        elif b in target_ids and a not in target_ids:
            tgt, neigh = b, a
        else:
            continue
        out[tgt].append({
            "neighbor_id": neigh,
            "neighbor_node": nodes_by_id[neigh],
            "weight": e["weight"],
            "top_factor": e["top_factor"],
            "breakdown": e["breakdown"],
        })
    # Sort and truncate.
    for tgt, lst in out.items():
        lst.sort(key=lambda x: x["weight"], reverse=True)
        out[tgt] = lst[:max_per_node]
    return out


def harvest_findings_md(workspace_dir: Path) -> list[dict[str, Any]]:
    """Pull candidate-finding lines from FINDINGS.md (best-effort)."""
    out: list[dict[str, Any]] = []
    candidates = [
        workspace_dir / "FINDINGS.md",
        workspace_dir / "audit" / "FINDINGS.md",
    ]
    for fp in candidates:
        if not fp.exists():
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in SECTION_FINDING_RE.finditer(text):
            title = m.group("title").strip().rstrip(":")
            # Strip leading hash-id artifacts.
            title = re.sub(r"^#?[A-Z]?\d+(?:\.\w+)?\s*[\-—:]?\s*", "", title).strip()
            if len(title) < 8:
                continue
            # Skip template / boilerplate placeholders.
            lower = title.lower()
            if any(skip in lower for skip in (
                "template", "<id>", "<one-line", "candidate, eligible",
                "iter ", "round ", "wave ", "register", "all candidates",
            )):
                continue
            out.append({"title": title, "source": str(fp)})
    return out


def classify_bug(text: str) -> list[str]:
    classes = []
    lower = text.lower()
    for cls, keys in BUG_CLASS_KEYWORDS:
        for k in keys:
            if k in lower:
                classes.append(cls)
                break
    return classes


def find_workspace_label(audits_root: Path, ws_path: Path, graph: dict[str, Any]) -> str | None:
    """Return the workspace label as it appears in the graph (e.g. ``audits/morpho``)."""
    try:
        rel = ws_path.resolve().relative_to(audits_root.resolve())
    except ValueError:
        return None
    label = f"audits/{rel.parts[0]}"
    if any(n["workspace"] == label for n in graph["nodes"]):
        return label
    return None


def build_suggestions(
    graph: dict[str, Any],
    target_label: str,
    audits_root: Path,
    threshold: float,
    max_neighbors: int,
    max_suggestions: int,
) -> dict[str, Any]:
    nodes_by_id = {n["id"]: n for n in graph["nodes"]}
    neighbors = neighbors_of_workspace(graph, target_label, threshold, max_neighbors)

    # Cache FINDINGS.md by workspace.
    findings_by_ws: dict[str, list[dict[str, Any]]] = {}

    suggestions: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()

    # Cross-WS neighbor transfer.
    for tgt_id, edges in neighbors.items():
        tgt = nodes_by_id[tgt_id]
        for edge in edges:
            n = edge["neighbor_node"]
            ws = n["workspace"]
            # 1) Pattern-DSL matches on the neighbor.
            for hit in n.get("known_vuln_hits", []):
                key = (tgt["display"], f'pattern:{hit["pattern_id"]}')
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                suggestions.append({
                    "target_file": tgt["display"],
                    "target_contracts": tgt["contracts"][:5],
                    "neighbor_file": n["display"],
                    "neighbor_workspace": ws,
                    "edge_weight": edge["weight"],
                    "top_factor": edge["top_factor"],
                    "evidence": "patterns.dsl name match",
                    "bug_signal": f"pattern: {hit['pattern_id']}",
                    "matched_contract": hit["contract"],
                    "bug_classes": classify_bug(hit["pattern_id"].replace("-", " ")),
                })
            # 2) FINDINGS.md titles in the neighbor workspace.
            ws_dir = audits_root / ws.split("/", 1)[1] if ws.startswith("audits/") else None
            if ws_dir is None or not ws_dir.exists():
                continue
            if ws not in findings_by_ws:
                findings_by_ws[ws] = harvest_findings_md(ws_dir)
            for fdg in findings_by_ws[ws][:30]:   # cap per neighbor WS to keep output focused
                title = fdg["title"]
                key = (tgt["display"], f'finding:{ws}:{title[:80]}')
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                classes = classify_bug(title)
                if not classes:
                    continue   # no recognizable bug class; skip rather than emit boilerplate
                suggestions.append({
                    "target_file": tgt["display"],
                    "target_contracts": tgt["contracts"][:5],
                    "neighbor_file": n["display"],
                    "neighbor_workspace": ws,
                    "edge_weight": edge["weight"],
                    "top_factor": edge["top_factor"],
                    "evidence": f"FINDINGS.md ({ws})",
                    "bug_signal": title,
                    "bug_classes": classes,
                })

    # Sort: pattern hits first (more reliable), then by weight, then alphabetic.
    def key(s: dict[str, Any]) -> tuple:
        is_pattern = 0 if s["evidence"].startswith("patterns.dsl") else 1
        return (is_pattern, -s["edge_weight"], s["target_file"])
    suggestions.sort(key=key)

    return {
        "workspace": target_label,
        "graph_path": str(DEFAULT_GRAPH),
        "threshold": threshold,
        "neighbor_files_with_signals": len(neighbors),
        "suggestion_count": len(suggestions),
        "suggestions": suggestions[:max_suggestions],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    ws = report["workspace"]
    lines.append(f"# Cross-protocol bug-transfer suggestions — `{ws}`")
    lines.append("")
    lines.append(f"- Graph: `{report['graph_path']}`")
    lines.append(f"- Edge weight threshold: ≥ `{report['threshold']:.2f}`")
    lines.append(f"- Files with cross-WS neighbors: `{report['neighbor_files_with_signals']}`")
    lines.append(f"- Total suggestions: `{report['suggestion_count']}`")
    lines.append("")

    if not report["suggestions"]:
        lines.append("> **Graph too sparse — no cross-protocol bug transfer signal yet.**")
        lines.append(">")
        lines.append("> Either no high-similarity cross-workspace neighbors exist for any file in")
        lines.append("> this workspace, or the neighbors that do exist have no recorded findings or")
        lines.append("> pattern-DSL hits. This will improve as the contest_cache grows (§J GitHub")
        lines.append("> fix-commit mining) and as more workspaces accrue FINDINGS.md entries.")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Prioritized review areas")
    lines.append("")
    lines.append("Sorted: pattern-DSL hits first, then by neighbor edge weight.")
    lines.append("")

    # Group by target file.
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in report["suggestions"]:
        by_target[s["target_file"]].append(s)

    for tgt, items in by_target.items():
        first = items[0]
        contracts = ", ".join(first["target_contracts"]) if first["target_contracts"] else "(none)"
        lines.append(f"### `{tgt}`")
        lines.append("")
        lines.append(f"Contracts: `{contracts}`")
        lines.append("")
        for s in items:
            classes = (
                "`" + "`, `".join(sorted(set(s["bug_classes"]))) + "`"
                if s["bug_classes"]
                else "_(no class match)_"
            )
            lines.append(
                f"- [ ] **{classes}** — neighbor `{s['neighbor_file']}` "
                f"(`{s['neighbor_workspace']}`, w=`{s['edge_weight']:.2f}`, "
                f"top=`{s['top_factor']}`)"
            )
            lines.append(f"      Signal ({s['evidence']}): {s['bug_signal']}")
            if s.get("matched_contract"):
                lines.append(f"      Matched contract: `{s['matched_contract']}`")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("**Methodology.** Suggestions come from the cross-protocol similarity graph")
    lines.append("(`tools/protocol-similarity-graph.py`). For each in-scope file we walk")
    lines.append("its high-similarity neighbors in OTHER workspaces / contest_cache and")
    lines.append("surface either (a) `patterns.dsl` matches that fired on the neighbor")
    lines.append("contract name, or (b) recognizable bug-class keywords in the neighbor")
    lines.append("workspace's `FINDINGS.md`. We do not synthesize bugs that have no neighbor")
    lines.append("evidence; if this list is empty the graph is honestly too sparse.")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Cross-protocol bug-transfer suggestions")
    p.add_argument("--workspace", required=True,
                   help="Target workspace path (e.g. ~/audits/base-azul/)")
    p.add_argument("--graph", default=str(DEFAULT_GRAPH),
                   help="Similarity graph JSON")
    p.add_argument("--audits-root", default=str(DEFAULT_AUDITS_ROOT),
                   help="Root for ~/audits/<workspace>/ scopes")
    p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                   help="Minimum neighbor edge weight (default: %(default)s)")
    p.add_argument("--max-neighbors", type=int, default=DEFAULT_MAX_NEIGHBORS_PER_NODE,
                   help="Max neighbors considered per target node (default: %(default)s)")
    p.add_argument("--max-suggestions", type=int, default=DEFAULT_MAX_SUGGESTIONS,
                   help="Cap suggestions emitted (default: %(default)s)")
    p.add_argument("--suggestions-out", default=None,
                   help="Output markdown file (default: <workspace>/cross_protocol_transfer_suggestions.md)")
    p.add_argument("--json-out", default=None,
                   help="Optional sidecar JSON path")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    graph_path = Path(args.graph)
    if not graph_path.exists():
        print(f"[transfer] graph not found: {graph_path}", file=sys.stderr)
        print(
            "[transfer] run: python3 tools/protocol-similarity-graph.py --emit-graph "
            f"{graph_path}",
            file=sys.stderr,
        )
        return 2
    graph = load_graph(graph_path)
    audits_root = Path(args.audits_root).expanduser()
    ws_path = Path(args.workspace).expanduser()
    label = find_workspace_label(audits_root, ws_path, graph)
    if label is None:
        print(
            f"[transfer] workspace {ws_path} not found in graph; "
            f"available workspaces: {sorted({n['workspace'] for n in graph['nodes']})}",
            file=sys.stderr,
        )
        return 3

    report = build_suggestions(
        graph=graph,
        target_label=label,
        audits_root=audits_root,
        threshold=args.threshold,
        max_neighbors=args.max_neighbors,
        max_suggestions=args.max_suggestions,
    )

    out_path = (
        Path(args.suggestions_out)
        if args.suggestions_out
        else ws_path / "cross_protocol_transfer_suggestions.md"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_markdown(report))
    print(f"[transfer] {report['suggestion_count']} suggestions -> {out_path}", file=sys.stderr)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
