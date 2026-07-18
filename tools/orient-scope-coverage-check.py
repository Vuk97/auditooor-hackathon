#!/usr/bin/env python3
"""ORIENT-phase scope-coverage check (Capability Gap 24 fix, 2026-05-25).

# Capability Gap 24 (2026-05-25): this tool emits no corpus record (R37 N/A).

TRIGGER: Run BEFORE the ORIENT prefilter / drill dispatch on a workspace
whose SCOPE.md enumerates >=2 in-scope assets. Verifies that the ORIENT
phase's `drill_candidates[]` covers EVERY in-scope asset, not just the
largest / highest-priority one. Catches the scope-coverage gap where
ORIENT correctly lists assets in its scope-mapping table but the
candidate-selection step silently skips one or more in-scope assets,
leaving them entirely unaudited.

Empirical anchor: 2026-05-25 hyperbridge full-hunt - SCOPE.md lists 2
in-scope assets (Hyperbridge bridge tree + Solidity Merkle Trees stand-
alone repo). The ORIENT output `hunt_orient.json` enumerated 8
drill_candidates; ALL 8 targeted files under `src/hyperbridge/...` and
ZERO targeted files under `src/solidity-merkle-trees/...`. The merkle
library appeared only in the secondary `fuzz_targets[]` list, which is
NOT consumed by the per-candidate drill dispatch. Operator caught the
gap manually before any drill lanes spawned for the merkle library.

Inputs:
  --orient   path to hunt_orient.json (drill_candidates[] consumed)
  --workspace path to workspace root containing SCOPE.md and src/<asset>/
  [--json]   emit machine-readable JSON instead of human text
  [--strict] also fail on warn-partial-coverage verdicts

Verdicts (per asset):
  covered    - >=1 drill_candidate cites a file under the asset's local_path.
  uncovered  - 0 drill_candidates cite files under local_path AND
               local_path contains >=1 source file (.sol / .rs / .go / .ts /
               .move / .cairo). This is the fail mode.
  empty      - local_path missing OR contains 0 recognized source files.
               Warn-grade, not fail (the asset directory may not yet be
               fetched).

Top-level verdicts:
  pass-full-coverage      - every in-scope asset is `covered`.
  pass-empty-only         - all uncovered are `empty` (warn-grade pass).
  warn-partial-coverage   - >=1 `empty` asset present, none `uncovered`.
                            Or 0 in-scope assets parsed (SCOPE.md shape
                            unrecognized).
  fail-asset-uncovered    - >=1 asset is `uncovered` (the real fail).
  error                   - input shape rejected / required file missing.

Override marker: not codified at the rule level (this is an
informational gate, not an R-rule). The standalone wrapper
`tools/orient-pipeline.sh` decides whether to refuse-to-proceed based
on the verdict.

Schema: auditooor.orient_scope_coverage_check.v1
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

SCHEMA = "auditooor.orient_scope_coverage_check.v1"

# Recognized source-file extensions for "asset has code" detection.
SOURCE_EXTS = (".sol", ".rs", ".go", ".ts", ".tsx", ".move", ".cairo", ".vy")

# SCOPE.md asset block: a "### <name>" header followed by metadata lines.
# We parse minimal fields: asset name, Repository URL, Local path after fetch.
ASSET_HEADER_RE = re.compile(r"^###\s+(?P<name>.+?)\s*$", re.MULTILINE)
REPOSITORY_RE = re.compile(r"^\s*-\s*Repository:\s*(?P<url>.+?)\s*$", re.MULTILINE)
LOCAL_PATH_RE = re.compile(
    r"^\s*-\s*Local path after fetch:\s*`?(?P<path>[^`\n]+?)`?\s*$",
    re.MULTILINE,
)

# Section bounds: only parse the "## In-Scope Assets" block.
IN_SCOPE_HEADER_RE = re.compile(
    r"^##\s+In-Scope Assets\s*$", re.MULTILINE
)
NEXT_TOP_LEVEL_HEADER_RE = re.compile(r"^##\s+", re.MULTILINE)


def _read_scope_md(workspace: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (scope_md_content, scope_md_path) or (None, None)."""
    path = os.path.join(workspace, "SCOPE.md")
    if not os.path.isfile(path):
        return None, None
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read(), path


def parse_scope_assets(scope_md_content: str) -> List[Dict[str, str]]:
    """Parse SCOPE.md's '## In-Scope Assets' section and return asset rows.

    Each row: {name, repository, local_path}. Asset rows without a
    local_path are skipped (they cannot be coverage-checked).
    """
    assets: List[Dict[str, str]] = []
    if not scope_md_content:
        return assets
    in_scope_match = IN_SCOPE_HEADER_RE.search(scope_md_content)
    if not in_scope_match:
        return assets
    section_start = in_scope_match.end()
    rest = scope_md_content[section_start:]
    # Find the next "## " header to bound the section.
    next_top = NEXT_TOP_LEVEL_HEADER_RE.search(rest)
    section_end = next_top.start() if next_top else len(rest)
    section_text = rest[:section_end]

    # Walk asset headers within the section.
    header_matches = list(ASSET_HEADER_RE.finditer(section_text))
    for idx, hm in enumerate(header_matches):
        name = hm.group("name").strip()
        block_start = hm.end()
        block_end = header_matches[idx + 1].start() if idx + 1 < len(header_matches) else len(section_text)
        block = section_text[block_start:block_end]
        repo_m = REPOSITORY_RE.search(block)
        path_m = LOCAL_PATH_RE.search(block)
        if not path_m:
            # Asset row without a local path - cannot coverage-check.
            continue
        local_path = path_m.group("path").strip()
        # Strip optional surrounding backticks left by the markdown parser.
        if local_path.startswith("`") and local_path.endswith("`"):
            local_path = local_path[1:-1].strip()
        assets.append({
            "name": name,
            "repository": repo_m.group("url").strip() if repo_m else "",
            "local_path": local_path,
        })
    return assets


def parse_drill_candidate_files(orient_json: Dict) -> List[str]:
    """Return the flat list of source files cited across all drill_candidates."""
    out: List[str] = []
    candidates = orient_json.get("drill_candidates", [])
    if not isinstance(candidates, list):
        return out
    for cand in candidates:
        if not isinstance(cand, dict):
            continue
        # Two known shapes: {files: [...]} or {file: "..."}.
        files = cand.get("files")
        if isinstance(files, list):
            for f in files:
                if isinstance(f, str) and f.strip():
                    out.append(f.strip())
        single_file = cand.get("file")
        if isinstance(single_file, str) and single_file.strip():
            out.append(single_file.strip())
    return out


def _normalize_for_match(path: str) -> str:
    """Drop a leading './' or 'src/' so we can match against trailing path stubs."""
    p = path.lstrip("./")
    return p


def _candidate_matches_asset(candidate_file: str, asset_local_path: str) -> bool:
    """True if the candidate file path is under the asset's local_path.

    Heuristic: match by trailing-token containment. drill_candidates may
    cite paths as `hyperbridge/evm/src/...` (asset-tree-rooted) or
    `modules/pallets/.../src/...` (sub-tree). The asset's local_path is
    typically `src/<asset-slug>`. We extract the asset-slug terminal
    component and check if it appears as a top-level token in the
    candidate path.
    """
    if not candidate_file or not asset_local_path:
        return False
    cand = _normalize_for_match(candidate_file)
    local = _normalize_for_match(asset_local_path)
    # Asset-slug is the last component of local_path (e.g. "hyperbridge"
    # or "solidity-merkle-trees").
    asset_slug = local.rstrip("/").split("/")[-1]
    if not asset_slug:
        return False
    # Tokenize candidate path on '/'; check if asset-slug appears as a
    # path component prefix (matches both 'hyperbridge/evm/src/...' and
    # 'src/hyperbridge/...').
    tokens = cand.split("/")
    return asset_slug in tokens


def count_source_files(asset_local_path: str, workspace: str) -> int:
    """Return # of source files under <workspace>/<asset_local_path>/."""
    full = os.path.join(workspace, asset_local_path)
    if not os.path.isdir(full):
        return 0
    count = 0
    for root, _dirs, files in os.walk(full):
        # Skip common vendored / build directories.
        rel = os.path.relpath(root, full)
        skip_segments = {"node_modules", "target", "build", ".git", "out", "cache", "lib"}
        if any(seg in rel.split(os.sep) for seg in skip_segments):
            continue
        for fn in files:
            if fn.endswith(SOURCE_EXTS):
                count += 1
                if count >= 1:
                    # Early-exit: we only need to know "any source file present".
                    # But continue counting so the report can include the value
                    # up to a reasonable cap (avoid scanning huge trees).
                    if count > 2000:
                        return count
    return count


def classify_assets(
    assets: List[Dict[str, str]],
    candidate_files: List[str],
    workspace: str,
) -> List[Dict]:
    """Per-asset classification: covered / uncovered / empty."""
    rows = []
    for asset in assets:
        local_path = asset["local_path"]
        source_file_count = count_source_files(local_path, workspace)
        matching_cands = [
            cf for cf in candidate_files
            if _candidate_matches_asset(cf, local_path)
        ]
        if matching_cands:
            status = "covered"
        elif source_file_count == 0:
            status = "empty"
        else:
            status = "uncovered"
        rows.append({
            "name": asset["name"],
            "repository": asset["repository"],
            "local_path": local_path,
            "source_file_count": source_file_count,
            "matching_drill_candidate_count": len(matching_cands),
            "matching_drill_candidate_samples": matching_cands[:3],
            "status": status,
        })
    return rows


def aggregate_verdict(asset_rows: List[Dict]) -> str:
    if not asset_rows:
        return "warn-partial-coverage"
    statuses = {r["status"] for r in asset_rows}
    if "uncovered" in statuses:
        return "fail-asset-uncovered"
    if "empty" in statuses and "covered" not in statuses:
        return "pass-empty-only"
    if "empty" in statuses:
        return "warn-partial-coverage"
    return "pass-full-coverage"


def build_report(
    orient_path: str,
    workspace: str,
    orient_json: Dict,
    scope_md_path: Optional[str],
    asset_rows: List[Dict],
    candidate_files: List[str],
) -> Dict:
    top_verdict = aggregate_verdict(asset_rows)
    assets_covered = [r["name"] for r in asset_rows if r["status"] == "covered"]
    assets_uncovered = [r["name"] for r in asset_rows if r["status"] == "uncovered"]
    assets_empty = [r["name"] for r in asset_rows if r["status"] == "empty"]
    return {
        "schema": SCHEMA,
        "inputs": {
            "orient": orient_path,
            "workspace": workspace,
            "scope_md": scope_md_path,
        },
        "drill_candidate_file_count": len(candidate_files),
        "drill_candidate_file_samples": candidate_files[:6],
        "assets_in_scope": [r["name"] for r in asset_rows],
        "assets_covered": assets_covered,
        "assets_uncovered": assets_uncovered,
        "assets_empty": assets_empty,
        "asset_rows": asset_rows,
        "top_verdict": top_verdict,
    }


def render_human(report: Dict) -> str:
    lines = []
    lines.append(f"ORIENT scope-coverage check  ({report['schema']})")
    lines.append(f"  orient:     {report['inputs']['orient']}")
    lines.append(f"  workspace:  {report['inputs']['workspace']}")
    lines.append(f"  scope_md:   {report['inputs']['scope_md']}")
    lines.append(f"  drill_candidate_file_count: {report['drill_candidate_file_count']}")
    lines.append("")
    lines.append("Per-asset coverage:")
    for row in report["asset_rows"]:
        lines.append(
            f"  [{row['status']:9s}] {row['name']!r}  local_path={row['local_path']!r} "
            f"source_files={row['source_file_count']} matched_candidates={row['matching_drill_candidate_count']}"
        )
    lines.append("")
    lines.append(f"TOP VERDICT: {report['top_verdict']}")
    if report["assets_uncovered"]:
        lines.append("")
        lines.append("UNCOVERED in-scope assets (ORIENT did not emit ANY drill_candidate for these):")
        for name in report["assets_uncovered"]:
            lines.append(f"  - {name}")
        lines.append(
            "ACTION: re-run ORIENT (or extend hunt_orient.json) to add drill_candidates "
            "targeting the uncovered assets BEFORE dispatching drill lanes."
        )
    if report["assets_empty"]:
        lines.append("")
        lines.append(
            "EMPTY in-scope assets (local_path missing or no source files - workspace "
            "may not be fully fetched):"
        )
        for name in report["assets_empty"]:
            lines.append(f"  - {name}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "ORIENT-phase scope-coverage check: verify drill_candidates[] "
            "covers every in-scope asset declared in SCOPE.md."
        ),
    )
    parser.add_argument("--orient", required=True, help="Path to hunt_orient.json")
    parser.add_argument(
        "--workspace",
        required=True,
        help="Workspace root containing SCOPE.md and src/<asset>/ trees",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human text")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Also exit non-zero on warn-partial-coverage verdicts",
    )
    args = parser.parse_args(argv)

    if not os.path.isfile(args.orient):
        err = {
            "schema": SCHEMA,
            "error": "orient_file_missing",
            "orient": args.orient,
            "top_verdict": "error",
        }
        if args.json:
            print(json.dumps(err, indent=2, sort_keys=True))
        else:
            print(f"ERROR: orient file not found: {args.orient}", file=sys.stderr)
        return 2

    try:
        with open(args.orient, "r", encoding="utf-8") as fh:
            orient_json = json.load(fh)
    except json.JSONDecodeError as exc:
        err = {
            "schema": SCHEMA,
            "error": "orient_json_decode_failed",
            "orient": args.orient,
            "detail": str(exc),
            "top_verdict": "error",
        }
        if args.json:
            print(json.dumps(err, indent=2, sort_keys=True))
        else:
            print(f"ERROR: failed to decode orient JSON: {exc}", file=sys.stderr)
        return 2

    scope_md_content, scope_md_path = _read_scope_md(args.workspace)
    if scope_md_content is None:
        err = {
            "schema": SCHEMA,
            "error": "scope_md_missing",
            "workspace": args.workspace,
            "top_verdict": "error",
        }
        if args.json:
            print(json.dumps(err, indent=2, sort_keys=True))
        else:
            print(f"ERROR: SCOPE.md not found at {args.workspace}/SCOPE.md", file=sys.stderr)
        return 2

    assets = parse_scope_assets(scope_md_content)
    candidate_files = parse_drill_candidate_files(orient_json)
    asset_rows = classify_assets(assets, candidate_files, args.workspace)
    report = build_report(
        args.orient, args.workspace, orient_json, scope_md_path,
        asset_rows, candidate_files,
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_human(report))

    top = report["top_verdict"]
    if top == "fail-asset-uncovered":
        return 1
    if top == "error":
        return 2
    if args.strict and top in ("warn-partial-coverage",):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
