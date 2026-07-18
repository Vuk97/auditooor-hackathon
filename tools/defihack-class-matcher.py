#!/usr/bin/env python3
"""defihack-class-matcher.py — Phase G: DeFiHackLabs catalog → candidate detector seeds.

Loads defihacklabs/catalog.yaml, runs each row's grep_predicates against
a target workspace, and emits a match report with per-row hit counts and
file:line references.

CLI:
    python3 tools/defihack-class-matcher.py --workspace <ws>
    python3 tools/defihack-class-matcher.py --workspace <ws> --catalog <path>
    python3 tools/defihack-class-matcher.py --workspace <ws> --out-dir <dir>
    python3 tools/defihack-class-matcher.py --workspace <ws> --quiet

Exit 0 on success. Prints summary line:
    [defihack-match] N rows scanned · M with hits · K candidate-detector seeds emitted
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import]

    def _load_yaml(text: str) -> Any:
        return yaml.safe_load(text)

except ImportError:
    import json as _json

    def _load_yaml(text: str) -> Any:  # type: ignore[misc]
        """Minimal YAML-subset parser (scalars + lists + dicts, no anchors)."""
        # Strip comments, then delegate to a best-effort heuristic.
        # For this catalog format we rely on the stdlib json loader only if the
        # file happens to be JSON; otherwise fall back to a manual parse.
        # Since the catalog is YAML with specific structure, use a line-by-line parser.
        lines = text.splitlines()
        return _parse_yaml_simple(lines)


def _parse_yaml_simple(lines: list[str]) -> dict:  # type: ignore[return]
    """Parse the defihacklabs catalog YAML format without PyYAML.

    Supports: top-level 'rows:' key → list of dicts with scalar/list fields.
    """
    rows: list[dict] = []
    current: dict | None = None
    in_rows = False
    list_key: str | None = None
    block_scalar_key: str | None = None
    block_scalar_lines: list[str] = []

    def _flush_block() -> None:
        nonlocal block_scalar_key, block_scalar_lines
        if block_scalar_key and current is not None:
            current[block_scalar_key] = " ".join(
                ln.strip() for ln in block_scalar_lines if ln.strip()
            )
        block_scalar_key = None
        block_scalar_lines = []

    for raw in lines:
        line = raw.rstrip()

        # strip comments (outside strings — good enough for catalog)
        stripped = re.sub(r"\s*#.*$", "", line).rstrip()

        # Block scalar continuation (>)
        if block_scalar_key is not None:
            if stripped and (stripped.startswith("  ") or not stripped):
                block_scalar_lines.append(stripped.strip())
                continue
            else:
                _flush_block()

        if not stripped or stripped.startswith("#"):
            continue

        if stripped == "rows:":
            in_rows = True
            continue

        if not in_rows:
            continue

        if stripped == "---":
            continue

        # New row item
        if re.match(r"^\s{2}-\s+id:", stripped) or stripped.startswith("  - id:"):
            if current is not None:
                rows.append(current)
            m = re.match(r".*id:\s*(.+)", stripped)
            current = {"id": m.group(1).strip().strip("\"'")} if m else {}
            list_key = None
            continue

        # List item under list_key
        if list_key and re.match(r"^\s{6}-\s+", stripped):
            val = re.sub(r"^\s{6}-\s+", "", stripped).strip().strip("\"'")
            current.setdefault(list_key, []).append(val)  # type: ignore[union-attr]
            continue

        # Key: > (block scalar)
        m_block = re.match(r"^\s{4}(\w+):\s*>", stripped)
        if m_block and current is not None:
            _flush_block()
            block_scalar_key = m_block.group(1)
            block_scalar_lines = []
            list_key = None
            continue

        # Key: value or Key: (start list)
        m_kv = re.match(r"^\s{4}(\w+):\s*(.*)", stripped)
        if m_kv and current is not None:
            key = m_kv.group(1)
            val = m_kv.group(2).strip().strip("\"'")
            if val == "":
                # Start of a list
                list_key = key
            else:
                list_key = None
                current[key] = val
            continue

        # List items at the block-scalar level (grep_predicates)
        if list_key and re.match(r"^\s{6}-\s+", stripped):
            val = re.sub(r"^\s{6}-\s+", "", stripped).strip().strip("\"'")
            current.setdefault(list_key, []).append(val)  # type: ignore[union-attr]

    _flush_block()
    if current:
        rows.append(current)

    return {"rows": rows}


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CATALOG = REPO_ROOT / "defihacklabs" / "catalog.yaml"

# Vendor/generated paths to suppress
EXCLUDE_DIRS = [
    "external/",
    "vendor/",
    "node_modules/",
    "lib/",
    ".git/",
]


def _load_catalog(catalog_path: Path) -> list[dict]:
    text = catalog_path.read_text(encoding="utf-8")
    try:
        data = _load_yaml(text)
    except Exception as exc:
        print(f"[defihack-match] ERROR: failed to parse catalog: {exc}", file=sys.stderr)
        sys.exit(1)
    rows = data.get("rows") or []
    if not rows:
        print("[defihack-match] ERROR: catalog has no rows", file=sys.stderr)
        sys.exit(1)
    return rows


def _grep(pattern: str, search_root: Path) -> list[str]:
    """Run grep -rEn, suppressing vendor paths. Returns list of 'file:line:match' strings."""
    cmd = ["grep", "-rEn", "--include=*.sol", "--include=*.go", "--include=*.rs",
           "--include=*.py", "--include=*.ts", "--include=*.js", pattern, str(search_root)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        lines = result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    # Filter vendor paths
    out = []
    for ln in lines:
        skip = False
        for excl in EXCLUDE_DIRS:
            if excl in ln:
                skip = True
                break
        if not skip:
            out.append(ln)
    return out


def _run_matcher(
    rows: list[dict],
    workspace: Path,
    quiet: bool,
) -> tuple[list[dict], int]:
    """Run predicates; return (results, candidate_count)."""
    results = []
    candidates = 0

    for row in rows:
        row_id = row.get("id", "?")
        attack_class = row.get("attack_class", "?")
        predicates = row.get("grep_predicates") or []
        mechanism = row.get("mechanism", "")
        detector_status = row.get("detector_status", "unknown")
        wave_candidate = row.get("wave_candidate", "")

        hits_by_pred: dict[str, list[str]] = {}
        for pred in predicates:
            matches = _grep(pred, workspace)
            if matches:
                hits_by_pred[pred] = matches

        total_hits = sum(len(v) for v in hits_by_pred.values())
        is_candidate = total_hits > 0 and detector_status == "gap"
        if is_candidate:
            candidates += 1

        results.append({
            "id": row_id,
            "attack_class": attack_class,
            "mechanism": mechanism,
            "detector_status": detector_status,
            "wave_candidate": wave_candidate,
            "grep_predicates": predicates,
            "predicates_run": len(predicates),
            "predicates_with_hits": len(hits_by_pred),
            "total_hits": total_hits,
            "hits_by_pred": hits_by_pred,
            "is_candidate": is_candidate,
        })

        if not quiet:
            status = "CANDIDATE-SEED" if is_candidate else ("hit" if total_hits > 0 else "no-hit")
            print(f"  [{row_id}] {attack_class}: {total_hits} hits ({status})")

    return results, candidates


def _emit_report(results: list[dict], out_dir: Path, workspace: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "match_report.md"
    lines = [
        f"# DeFiHackLabs class-matcher report",
        f"",
        f"**Workspace**: `{workspace}`  ",
        f"**Generated**: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  ",
        f"",
        f"## Summary",
        f"",
    ]

    rows_scanned = len(results)
    rows_with_hits = sum(1 for r in results if r["total_hits"] > 0)
    candidates = sum(1 for r in results if r["is_candidate"])
    lines += [
        f"- Rows scanned: **{rows_scanned}**",
        f"- Rows with ≥1 hit: **{rows_with_hits}**",
        f"- Candidate-detector seeds (gap + hits): **{candidates}**",
        f"",
        f"## Per-row results",
        f"",
    ]

    for r in results:
        status_tag = "CANDIDATE-SEED" if r["is_candidate"] else r["detector_status"]
        lines += [
            f"### {r['id']} — {r['attack_class']} [{status_tag}]",
            f"",
            f"**Mechanism**: {r['mechanism'].strip()}  ",
            f"**Detector status**: {r['detector_status']}  ",
        ]
        if r["wave_candidate"]:
            lines.append(f"**Wave candidate**: {r['wave_candidate']}  ")
        lines.append(f"**Predicates run**: {r['predicates_run']} · **With hits**: {r['predicates_with_hits']} · **Total hits**: {r['total_hits']}")
        lines.append("")
        if r["hits_by_pred"]:
            for pred, hits in r["hits_by_pred"].items():
                lines.append(f"**Pattern** `{pred}` → {len(hits)} hit(s):")
                for hit in hits[:5]:  # cap at 5 lines per predicate
                    lines.append(f"```")
                    lines.append(hit)
                    lines.append(f"```")
                if len(hits) > 5:
                    lines.append(f"_...and {len(hits) - 5} more_")
                lines.append("")
        else:
            lines.append("_No hits._")
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="DeFiHackLabs class matcher: catalog → candidate detector seeds"
    )
    parser.add_argument("--workspace", required=True, help="Target workspace path to scan")
    parser.add_argument("--catalog", help="Path to catalog.yaml (default: defihacklabs/catalog.yaml)")
    parser.add_argument("--out-dir", help="Output directory for match_report.md")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-row progress output")
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        print(f"[defihack-match] ERROR: workspace not found: {workspace}", file=sys.stderr)
        return 1

    catalog_path = Path(args.catalog).expanduser().resolve() if args.catalog else DEFAULT_CATALOG
    if not catalog_path.exists():
        print(f"[defihack-match] ERROR: catalog not found: {catalog_path}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"[defihack-match] catalog: {catalog_path}")
        print(f"[defihack-match] workspace: {workspace}")

    rows = _load_catalog(catalog_path)
    rows_with_predicates = [r for r in rows if r.get("grep_predicates")]

    if not args.quiet:
        print(f"[defihack-match] {len(rows)} rows loaded · {len(rows_with_predicates)} with predicates")

    results, candidates = _run_matcher(rows, workspace, args.quiet)

    date_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    if args.out_dir:
        out_dir = Path(args.out_dir).expanduser().resolve()
    else:
        ws_name = workspace.name
        out_dir = workspace / "scan-results" / f"defihack-match-{date_str}"

    report_path = _emit_report(results, out_dir, workspace)

    rows_with_hits = sum(1 for r in results if r["total_hits"] > 0)
    print(
        f"[defihack-match] {len(rows)} rows scanned · {rows_with_hits} with hits · "
        f"{candidates} candidate-detector seeds emitted"
    )
    if not args.quiet:
        print(f"[defihack-match] report: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
