#!/usr/bin/env python3
"""vault-frame-extractor — cluster L2 case studies, draft L3 frame skeletons.

Phase D backfill (Lane 11) of MCP harness review (PR #658) commit 9.

Walks existing L2 case-study sources in priority order:
  1. r-rounds/          — 30+ round retrospectives (highest anchor density)
  2. engagement-retros/ — per-engagement retrospective summaries
  3. case_study/        — curated case studies
  4. findings/          — raw finding notes
  5. rollups/           — rollup summaries

Clusters by root_cause_class. For each cluster size >= 2, drafts a
candidate AMF-NNN.yaml skeleton in reference/attacker_frames/_drafts/
for operator review.

Does NOT auto-promote. Per Worker A's anti-over-codification constraint:
  - Active set capped at 50 (currently 7 hand-curated + drafts in _drafts/)
  - Admission requires ≥3 anchors from ≥2 distinct engagements
  - This tool surfaces candidates only; operator decides

Usage:
    tools/vault-frame-extractor.py                 # default scan + draft
    tools/vault-frame-extractor.py --dry-run       # show candidates, don't write
    tools/vault-frame-extractor.py --vault-dir P   # override vault location
    tools/vault-frame-extractor.py --json          # machine-readable
    tools/vault-frame-extractor.py --source r-rounds          # single-source scan
    tools/vault-frame-extractor.py --source-priority reverse  # override list order
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from datetime import datetime, timezone

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_VAULTS = [
    pathlib.Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault"),
    REPO / "obsidian-vault",
]
DRAFT_DIR = REPO / "reference" / "attacker_frames" / "_drafts"
FRAMES_DIR = REPO / "reference" / "attacker_frames"

# Source patterns (paths within vault to scan for L2 content).
# ORDER IS SIGNIFICANT: r-rounds first so their root_cause_class assignments
# win when the same anchor appears in multiple sources (first-match semantics
# in the clustering loop).  engagement-retros second, then case_study, findings,
# rollups.
L2_SOURCES = [
    "r-rounds/**/*.md",
    "engagement-retros/**/*.md",
    "case_study/**/*.md",
    "findings/**/*.md",
    "rollups/**/*.md",
]

# Symbolic names for each source (used by --source filter flag)
_SOURCE_NAMES = {
    "r-rounds": "r-rounds/**/*.md",
    "engagement-retros": "engagement-retros/**/*.md",
    "case_study": "case_study/**/*.md",
    "findings": "findings/**/*.md",
    "rollups": "rollups/**/*.md",
}

# Bug-class extraction heuristic — first match wins
BUG_CLASS_PATTERNS = [
    (r"\bmissing[- ](guard|validation|modifier|check)\b", "missing_validation"),
    (r"\b(reentran|callback)\b", "reentrancy"),
    (r"\boracle[- ](manipul|stale|prec)\b", "oracle_manipulation"),
    (r"\b(ordering|sequence|toctou|race)\b", "ordering_bug"),
    (r"\b(panic|nil[- ]point|crash)\b", "panic_class"),
    (r"\b(asymmetr|sender.recv|claim.final|deposit.withdraw)\b", "asymmetric_path"),
    (r"\b(fork[- ]lag|upstream[- ]div|silent[- ]fix)\b", "upstream_divergence"),
    (r"\b(consensus|rollout|partial[- ]deploy)\b", "consensus_bug"),
    (r"\b(reverted|removed|disabled)[- ](guard|check|protection)\b", "reverted_protection"),
    (r"\b(prior[- ]audit|ack|acknowledg)\b", "acked_not_fixed"),
    (r"\b(off[- ]chain|trust[- ]boundary|operator[- ]controlled)\b", "trust_boundary"),
    (r"\b(real[- ]component|mock|preconditi)\b", "over_claim_critical"),
]


def _resolve_vault():
    for v in DEFAULT_VAULTS:
        if v.is_dir():
            return v
    return None


def _classify_bug_class(text):
    """Returns first matching bug class or 'unknown'."""
    text_l = text.lower()
    for pattern, class_name in BUG_CLASS_PATTERNS:
        if re.search(pattern, text_l):
            return class_name
    return "unknown"


def _extract_engagement(path):
    """Heuristic: extract engagement slug from path."""
    p = pathlib.Path(path)
    parts = p.parts
    for part in parts:
        if part in ("spark", "dydx", "base-azul", "morpho", "centrifuge-v3",
                    "polymarket", "snowbridge", "thegraph", "monetrix",
                    "revert-stableswap-hooks", "litecoin"):
            return part
    return None


def scan_l2_sources(vault_dir, source_filter=None, source_priority="list"):
    """Walk L2 sources in priority order, classify each note's bug-class.

    Args:
        vault_dir: pathlib.Path to the vault root.
        source_filter: optional str — one of the keys in _SOURCE_NAMES.  When
            provided, only that source glob is scanned.  Useful for targeted
            testing and incremental runs.
        source_priority: "list" (default) respects L2_SOURCES order so earlier
            sources' root_cause_class assignments win; "reverse" inverts the
            order (later sources win); any other value is treated as "list".

    Returns:
        dict mapping bug_class -> list of {path, engagement, title, source}.
        Within each bug_class list, anchors appear in scan order (source
        priority is expressed by list position, not by a separate field).
    """
    # Build the effective source list
    if source_filter is not None:
        if source_filter not in _SOURCE_NAMES:
            raise ValueError(
                f"Unknown source filter {source_filter!r}. "
                f"Valid values: {sorted(_SOURCE_NAMES)}"
            )
        effective_sources = [_SOURCE_NAMES[source_filter]]
    else:
        effective_sources = list(L2_SOURCES)

    if source_priority == "reverse":
        effective_sources = list(reversed(effective_sources))

    # Track seen paths so a file matched by multiple globs is only counted once,
    # with the priority of the FIRST glob that matched it.
    seen_paths: set = set()
    clusters: dict = {}  # bug_class -> [{path, engagement, title, source}]

    for pattern in effective_sources:
        # Derive a short source label from the pattern (e.g. "r-rounds")
        source_label = pattern.split("/")[0]
        for f in sorted(vault_dir.glob(pattern)):
            if f in seen_paths:
                continue
            seen_paths.add(f)
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            if len(text) < 200:  # skip empty / tiny notes
                continue
            bug_class = _classify_bug_class(text)
            if bug_class == "unknown":
                continue
            engagement = _extract_engagement(f)
            # First # heading or filename
            title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
            title = title_match.group(1).strip() if title_match else f.stem
            clusters.setdefault(bug_class, []).append({
                "path": str(f.relative_to(vault_dir)),
                "engagement": engagement,
                "title": title[:100],
                "source": source_label,
            })
    return clusters


def existing_frames():
    """Returns set of (frame_id, bug_class) tuples from existing AMF YAMLs."""
    out = set()
    if not FRAMES_DIR.is_dir():
        return out
    try:
        import yaml
    except ImportError:
        # Lite parser — extract frame_id and bug_class via regex
        for f in FRAMES_DIR.glob("AMF-*.yaml"):
            text = f.read_text()
            fid_m = re.search(r"^frame_id:\s*(\S+)", text, re.MULTILINE)
            bc_m = re.search(r"^bug_class:\s*(\S+)", text, re.MULTILINE)
            if fid_m and bc_m:
                out.add((fid_m.group(1), bc_m.group(1)))
        return out
    for f in FRAMES_DIR.glob("AMF-*.yaml"):
        try:
            data = yaml.safe_load(f.read_text())
            out.add((data.get("frame_id"), data.get("bug_class")))
        except Exception:
            continue
    return out


def find_next_frame_id():
    """Returns next available AMF-NNN."""
    existing = existing_frames()
    drafted = set()
    if DRAFT_DIR.is_dir():
        for f in DRAFT_DIR.glob("AMF-*.yaml"):
            drafted.add(f.stem)
    used_ids = {fid for fid, _ in existing if fid} | drafted
    n = 1
    while f"AMF-{n:03d}" in used_ids:
        n += 1
    return f"AMF-{n:03d}"


def draft_frame_for_cluster(bug_class, members):
    """Generate a frame skeleton for operator review."""
    engagements = sorted(set(m["engagement"] for m in members if m["engagement"]))
    frame_id = find_next_frame_id()
    title = f"Auto-extracted candidate for {bug_class}"
    anchors = [m["path"] for m in members[:5]]
    return frame_id, {
        "schema": "auditooor.attacker_mental_frame.v1",
        "frame_id": frame_id,
        "title": title,
        "version": 0,  # 0 = draft, not yet curated
        "status": "quarantined",  # operator must promote to active
        "bug_class": bug_class,
        "protocol_class": engagements,
        "attacker_question": f"AUTO-DRAFT — operator: write the attacker reasoning for {bug_class} class.",
        "preconditions": [f"Cluster has {len(members)} anchors across {len(engagements)} engagements"],
        "mental_steps": [
            {"id": 1, "do": "AUTO-DRAFT — operator: replace with concrete steps."},
            {"id": 2, "do": "AUTO-DRAFT — operator: see corpus_anchors below."},
            {"id": 3, "do": "AUTO-DRAFT — operator: counter-examples are the highest-value field."},
        ],
        "counter_examples": ["AUTO-DRAFT — operator: list cases where frame would over-fire."],
        "existing_corpus_anchors": anchors,
        "trigger_keywords": [bug_class.replace("_", "-")],
        "auto_extracted": True,
        "auto_extracted_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }


def write_draft(frame_id, payload, dry_run=False):
    """Write draft YAML. Returns path."""
    DRAFT_DIR.mkdir(parents=True, exist_ok=True)
    path = DRAFT_DIR / f"{frame_id}.yaml"
    if dry_run:
        return path, False
    # Simple YAML emit (no PyYAML required)
    lines = [
        f"schema: {payload['schema']}",
        f"frame_id: {payload['frame_id']}",
        f"title: {payload['title']}",
        f"version: {payload['version']}",
        f"status: {payload['status']}",
        f"bug_class: {payload['bug_class']}",
        "protocol_class:",
    ]
    for pc in payload["protocol_class"]:
        lines.append(f"  - {pc}")
    lines.extend([
        f"attacker_question: |",
        f"  {payload['attacker_question']}",
        "preconditions:",
    ])
    for p in payload["preconditions"]:
        lines.append(f"  - {p}")
    lines.append("mental_steps:")
    for step in payload["mental_steps"]:
        lines.append(f"  - id: {step['id']}")
        lines.append(f"    do: {step['do']}")
    lines.append("counter_examples:")
    for ce in payload["counter_examples"]:
        lines.append(f"  - {ce}")
    lines.append("existing_corpus_anchors:")
    for a in payload["existing_corpus_anchors"]:
        lines.append(f"  - {a}")
    lines.append("trigger_keywords:")
    for k in payload["trigger_keywords"]:
        lines.append(f"  - {k}")
    lines.append(f"auto_extracted: true")
    lines.append(f"auto_extracted_at: {payload['auto_extracted_at']}")
    path.write_text("\n".join(lines) + "\n")
    return path, True


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--vault-dir", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--min-cluster-size", type=int, default=2,
                        help="minimum anchors required to draft a frame (default 2)")
    parser.add_argument(
        "--source",
        default=None,
        choices=sorted(_SOURCE_NAMES.keys()),
        metavar="SOURCE",
        help=(
            "Scan only one L2 source. Valid values: "
            + ", ".join(sorted(_SOURCE_NAMES.keys()))
            + ". Default: scan all sources in priority order."
        ),
    )
    parser.add_argument(
        "--source-priority",
        default="list",
        choices=["list", "reverse"],
        help=(
            "list (default): scan L2_SOURCES in declared order so earlier "
            "sources win. reverse: invert list order."
        ),
    )
    args = parser.parse_args()

    vault = pathlib.Path(args.vault_dir) if args.vault_dir else _resolve_vault()
    if not vault or not vault.is_dir():
        print(f"[vault-frame-extractor] vault dir not found", file=sys.stderr)
        return 1

    clusters = scan_l2_sources(
        vault,
        source_filter=args.source,
        source_priority=args.source_priority,
    )
    existing = existing_frames()
    existing_classes = {bc for _, bc in existing}

    candidates = []
    drafted = []
    for bug_class, members in sorted(clusters.items()):
        if len(members) < args.min_cluster_size:
            continue
        if bug_class in existing_classes:
            # Don't re-draft what's already curated
            continue
        engagements = set(m["engagement"] for m in members if m["engagement"])
        candidates.append({
            "bug_class": bug_class,
            "n_anchors": len(members),
            "engagements": sorted(engagements),
            "examples": [m["path"] for m in members[:3]],
        })
        if not args.dry_run:
            frame_id, payload = draft_frame_for_cluster(bug_class, members)
            path, written = write_draft(frame_id, payload, dry_run=args.dry_run)
            if written:
                drafted.append({"frame_id": frame_id, "path": str(path), "bug_class": bug_class})

    summary = {
        "schema": "auditooor.vault_frame_extractor.v1",
        "vault_scanned": str(vault),
        "n_clusters_total": len(clusters),
        "n_existing_curated_classes": len(existing_classes),
        "n_candidates_above_min_size": len(candidates),
        "n_drafted": len(drafted),
        "candidates": candidates[:10],
        "drafted": drafted,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[vault-frame-extractor] scanned {summary['n_clusters_total']} clusters")
        print(f"[vault-frame-extractor] existing curated: {sorted(existing_classes)}")
        print(f"[vault-frame-extractor] candidates (>={args.min_cluster_size} anchors, novel class): {len(candidates)}")
        for c in candidates[:5]:
            print(f"  - {c['bug_class']}: {c['n_anchors']} anchors across engagements {c['engagements']}")
        print(f"[vault-frame-extractor] drafted: {len(drafted)}")
        for d in drafted[:5]:
            print(f"  - {d['frame_id']} ({d['bug_class']}) -> {d['path']}")
        print()
        print("[vault-frame-extractor] Drafts in reference/attacker_frames/_drafts/")
        print("[vault-frame-extractor] Operator: review each draft, fill in attacker_question + mental_steps,")
        print("[vault-frame-extractor]           then promote to reference/attacker_frames/ when ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
