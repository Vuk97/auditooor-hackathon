#!/usr/bin/env python3
"""Corpus mining state snapshot — Phase A of the corpus mining plan.

Inventories every corpus the auditooor toolchain consumes, records freshness,
and emits a JSON snapshot + markdown summary.

Usage:
    python3 tools/corpus-mining-state-snapshot.py [--out-json PATH] [--out-md PATH] [--quiet]

Staleness buckets:
    fresh  — last refreshed < 7 days ago
    aging  — 7-21 days ago
    stale  — > 21 days ago (or never)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "reference"
CASE_STUDY = ROOT / "case_study"
AUDITS_DIR = Path.home() / "audits"

DEFAULT_JSON = ROOT / ".auditooor" / "corpus_mining_state.json"
DEFAULT_MD = ROOT / "docs" / "CORPUS_MINING_STATE_SNAPSHOT.md"

NOW = datetime.now(timezone.utc)


def days_ago(dt: datetime | None) -> float | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (NOW - dt).total_seconds() / 86400


def staleness(dt: datetime | None) -> str:
    d = days_ago(dt)
    if d is None:
        return "stale"
    if d < 7:
        return "fresh"
    if d <= 21:
        return "aging"
    return "stale"


def git_last_commit_date(path: Path | str) -> datetime | None:
    """Return the author date of the most recent git commit touching path."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(ROOT), "log", "--format=%aI", "-1", "--", str(path)],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        if out:
            return datetime.fromisoformat(out)
    except Exception:
        pass
    return None


def file_mtime(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except Exception:
        return None


def count_yaml_in(d: Path) -> int:
    if not d.exists():
        return 0
    return len(list(d.rglob("*.yaml")))


def count_files_matching(dirs: list[Path], pattern: str = "*.pdf") -> list[str]:
    results = []
    for d in dirs:
        if d.exists():
            results.extend(str(p) for p in d.glob(pattern))
    return results


def newest_mtime(paths: list[Path]) -> datetime | None:
    """Return the newest modification time across a list of files."""
    latest_dt: datetime | None = None
    for path in paths:
        mt = file_mtime(path)
        if mt and (latest_dt is None or mt > latest_dt):
            latest_dt = mt
    return latest_dt


# ── Individual corpus probes ──────────────────────────────────────────────────

def probe_defimon() -> dict[str, Any]:
    """Last defimon mine via git log on patterns.dsl dirs."""
    last_dt = git_last_commit_date("reference/patterns.dsl")
    # Also check named defimon commits
    try:
        out = subprocess.check_output(
            ["git", "-C", str(ROOT), "log", "--format=%aI %H %s",
             "--all", "--grep=defimon", "-1"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        if out:
            parts = out.split(" ", 2)
            defimon_dt = datetime.fromisoformat(parts[0])
            last_dt = defimon_dt
            sha = parts[1] if len(parts) > 1 else None
        else:
            sha = None
    except Exception:
        sha = None

    pattern_count = count_yaml_in(REF / "patterns.dsl")
    return {
        "corpus": "defimon",
        "source_path": str(REF / "patterns.dsl"),
        "last_mined_at": last_dt.isoformat() if last_dt else None,
        "last_commit_sha": sha,
        "volume": {"yaml_patterns": pattern_count},
        "staleness_days": round(days_ago(last_dt), 1) if last_dt else None,
        "staleness_category": staleness(last_dt),
    }


def probe_solodit() -> dict[str, Any]:
    cursor_path = REF / "solodit_ingest_cursor.json"
    cursor_paths = sorted(REF.glob("solodit_ingest_cursor*.json"))
    last_dt: datetime | None = None
    cursor_data: dict = {}
    latest_cursor_path = cursor_path
    max_cursor_id = None
    for path in cursor_paths:
        try:
            data = json.loads(path.read_text())
            updated = data.get("updated_at")
            path_dt = datetime.fromisoformat(updated) if updated else file_mtime(path)
            cursor_id = data.get("last_id")
            if isinstance(cursor_id, int) and (max_cursor_id is None or cursor_id > max_cursor_id):
                max_cursor_id = cursor_id
            if path_dt and (last_dt is None or path_dt > last_dt):
                last_dt = path_dt
                latest_cursor_path = path
                cursor_data = data
        except Exception:
            path_dt = file_mtime(path)
            if path_dt and (last_dt is None or path_dt > last_dt):
                last_dt = path_dt
                latest_cursor_path = path
    if not cursor_paths and cursor_path.exists():
        try:
            cursor_data = json.loads(cursor_path.read_text())
            updated = cursor_data.get("updated_at")
            if updated:
                last_dt = datetime.fromisoformat(updated)
        except Exception:
            pass
        if last_dt is None:
            last_dt = file_mtime(cursor_path)

    tag_root = ROOT / "audit" / "corpus_tags" / "tags"
    solodit_dirs = [d for d in REF.iterdir() if d.is_dir() and "solodit" in d.name]
    if tag_root.exists():
        solodit_dirs.extend(d for d in tag_root.iterdir() if d.is_dir() and "solodit" in d.name)
    total_yaml = sum(count_yaml_in(d) for d in solodit_dirs)

    return {
        "corpus": "solodit",
        "source_path": str(latest_cursor_path),
        "last_mined_at": last_dt.isoformat() if last_dt else None,
        "cursor_last_id": cursor_data.get("last_id"),
        "cursor_max_id": max_cursor_id,
        "alternate_cursor_count": max(0, len(cursor_paths) - 1),
        "volume": {"yaml_patterns": total_yaml, "subdirs": len(solodit_dirs)},
        "staleness_days": round(days_ago(last_dt), 1) if last_dt else None,
        "staleness_category": staleness(last_dt),
    }


def probe_audit_pdfs() -> dict[str, Any]:
    pdf_patterns = ["prior_audits", "cantina-pdfs", "external-prior-audits", "known-vulns-pdf"]
    pdf_dirs = []
    if AUDITS_DIR.exists():
        for ws in AUDITS_DIR.iterdir():
            if ws.is_dir():
                for pat in pdf_patterns:
                    d = ws / pat
                    if d.exists():
                        pdf_dirs.append(d)

    all_pdfs = count_files_matching(pdf_dirs, "*.pdf")

    mining_run = ROOT / ".auditooor" / "audit_pdf_mining_run.json"
    mined_candidates_dir = REF / "patterns.dsl" / "r99_pdf_mined"
    mined_candidates = list(mined_candidates_dir.glob("*.yaml.candidate")) if mined_candidates_dir.exists() else []

    newest_dt: datetime | None = None
    if mining_run.exists():
        try:
            payload = json.loads(mining_run.read_text())
            run_ts = payload.get("run_ts")
            if run_ts:
                newest_dt = datetime.fromisoformat(run_ts)
        except Exception:
            newest_dt = file_mtime(mining_run)

    if newest_dt is None:
        newest_dt = newest_mtime([Path(p) for p in all_pdfs])

    if newest_dt is None:
        newest_dt = newest_mtime(mined_candidates)

    return {
        "corpus": "audit_pdfs",
        "source_path": str(AUDITS_DIR),
        "last_mined_at": newest_dt.isoformat() if newest_dt else None,
        "volume": {
            "pdf_files": len(all_pdfs),
            "yaml_candidates": len(mined_candidates),
        },
        "staleness_days": round(days_ago(newest_dt), 1) if newest_dt else None,
        "staleness_category": staleness(newest_dt),
        "note": "PDF miner exists; freshness falls back to mining artifacts when available.",
    }


def probe_defihacklabs() -> dict[str, Any]:
    catalog = REF / "corpus_mined" / "defihacklabs_catalog.md"
    last_dt = git_last_commit_date("reference/corpus_mined/defihacklabs_catalog.md")
    if last_dt is None:
        last_dt = file_mtime(catalog)
    row_count = 0
    if catalog.exists():
        row_count = sum(1 for line in catalog.read_text().splitlines() if line.startswith("|"))
    return {
        "corpus": "defihacklabs_catalog",
        "source_path": str(catalog),
        "last_mined_at": last_dt.isoformat() if last_dt else None,
        "volume": {"table_rows": row_count},
        "staleness_days": round(days_ago(last_dt), 1) if last_dt else None,
        "staleness_category": staleness(last_dt),
        "note": "Doc-only; no detector codified yet (Phase E target).",
    }


def probe_big_loss_templates() -> dict[str, Any]:
    blt_dir = REF / "big_loss_templates"
    templates = list(blt_dir.glob("*.json")) if blt_dir.exists() else []
    # Only rust_dlt_state_divergence.json has a consumer tool
    consumers = {
        "rust_dlt_state_divergence.json": "tools/draft-rust-dlt-filing.py",
        "bridge_proof_domain.json": None,
        "consensus_parser_differential.json": None,
    }
    last_dt = git_last_commit_date("reference/big_loss_templates")
    if last_dt is None and blt_dir.exists():
        last_dt = max((file_mtime(f) for f in templates if file_mtime(f)), default=None)
    items = [
        {"file": t.name, "consumer_tool": consumers.get(t.name)}
        for t in templates if t.suffix == ".json" and t.name != "SCHEMA.json" and t.name != "INDEX.json"
    ]
    wired = sum(1 for i in items if i["consumer_tool"])
    return {
        "corpus": "big_loss_templates",
        "source_path": str(blt_dir),
        "last_mined_at": last_dt.isoformat() if last_dt else None,
        "volume": {"templates": len(items), "wired_to_tool": wired},
        "staleness_days": round(days_ago(last_dt), 1) if last_dt else None,
        "staleness_category": staleness(last_dt),
        "templates": items,
    }


def _load_case_study_matcher() -> Any | None:
    """Import the hyphen-named case-study class-matcher to reuse its frontmatter
    parser, so logic-extraction detection matches the consumer's own semantics
    (no duplicate parser). Returns the module or None if it cannot be loaded."""
    import importlib.util

    tool = ROOT / "tools" / "case-study-class-matcher.py"
    if not tool.exists():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "case_study_class_matcher_snapshot", tool
        )
        if spec is None or spec.loader is None:
            return None
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception:
        return None


def _case_study_logic_extracted(matcher: Any | None, path: Path) -> bool:
    """True when the case study carries runnable-check logic in its frontmatter,
    i.e. at least one grep_predicate or runtime_predicate the class-matcher can
    consume. Falls back to a minimal frontmatter scan if the matcher is absent."""
    if matcher is not None:
        try:
            meta = matcher._load_case_study(path)  # noqa: SLF001 - intended reuse
            if meta is not None:
                return bool(meta.grep_predicates or meta.runtime_predicates)
            return False
        except Exception:
            pass
    # Fallback: crude frontmatter scan (only when matcher import failed)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    if not text.startswith("---"):
        return False
    end = text.find("\n---", 3)
    fm = text[:end] if end != -1 else text
    return ("grep_predicates:" in fm) or ("runtime_predicates:" in fm)


def probe_case_studies() -> dict[str, Any]:
    files = sorted(CASE_STUDY.glob("*.md")) if CASE_STUDY.exists() else []
    matcher = _load_case_study_matcher()
    items = []
    for f in files:
        try:
            rel = f.relative_to(ROOT)
        except ValueError:
            rel = f  # case_study dir outside the repo (e.g. under test)
        dt = git_last_commit_date(rel)
        if dt is None:
            dt = file_mtime(f)
        items.append({
            "file": f.name,
            "last_commit_at": dt.isoformat() if dt else None,
            "logic_extracted": _case_study_logic_extracted(matcher, f),
        })
    last_dt = max((datetime.fromisoformat(i["last_commit_at"]) for i in items
                   if i["last_commit_at"]), default=None)
    n_extracted = sum(1 for i in items if i["logic_extracted"])
    if files and n_extracted == len(files):
        note = ("Logic extracted: all case studies carry class-matcher-consumable "
                "grep/runtime predicates (see tools/case-study-class-matcher.py).")
    elif n_extracted:
        note = (f"Logic extracted for {n_extracted}/{len(files)} case studies "
                "(class-matcher grep/runtime predicates); remainder are doc-only.")
    else:
        note = "Doc-only; logic not extracted into runnable checks (Phase F target)."
    return {
        "corpus": "case_studies",
        "source_path": str(CASE_STUDY),
        "last_mined_at": last_dt.isoformat() if last_dt else None,
        "volume": {"files": len(files), "logic_extracted": n_extracted},
        "staleness_days": round(days_ago(last_dt), 1) if last_dt else None,
        "staleness_category": staleness(last_dt),
        "note": note,
        "files": items,
    }


def probe_contest_cache() -> dict[str, Any]:
    cc_dir = REF / "contest_cache"
    files = list(cc_dir.rglob("*.json")) if cc_dir.exists() else []
    last_dt = git_last_commit_date("reference/contest_cache")
    if last_dt is None:
        last_dt = max((file_mtime(f) for f in files if file_mtime(f)), default=None)
    return {
        "corpus": "contest_cache",
        "source_path": str(cc_dir),
        "last_mined_at": last_dt.isoformat() if last_dt else None,
        "volume": {"json_files": len(files)},
        "staleness_days": round(days_ago(last_dt), 1) if last_dt else None,
        "staleness_category": staleness(last_dt),
        "note": "Stub — 1 sample each for cantina/immunefi; not yet bulk-refreshed.",
    }


def probe_multi_language_coverage() -> dict[str, Any]:
    langs = {
        "go": "r94_solodit_go",
        "rust": "r94_solodit_rust",
        "move": "r94_solodit_move",
        "cairo": "r94_solodit_cairo",
        "vyper": "r94_solodit_vyper",
        "circom": "r94_solodit_circom",
        "sway": "r94_solodit_sway",
        "zk": "r94_solodit_zk",
    }
    coverage = {}
    for lang, subdir in langs.items():
        d = REF / ("patterns.dsl." + subdir)
        coverage[lang] = {"yaml_patterns": count_yaml_in(d), "path": str(d)}

    return {
        "corpus": "multi_language_coverage",
        "source_path": str(REF),
        "last_mined_at": None,
        "volume": coverage,
        "staleness_days": None,
        "staleness_category": "aging",  # undated; assume aging
        "note": "Per-language solodit sub-dirs; compilation status unverified.",
    }


# ── Snapshot assembly ─────────────────────────────────────────────────────────

def build_snapshot() -> dict[str, Any]:
    corpora = [
        probe_defimon(),
        probe_solodit(),
        probe_audit_pdfs(),
        probe_defihacklabs(),
        probe_big_loss_templates(),
        probe_case_studies(),
        probe_contest_cache(),
        probe_multi_language_coverage(),
    ]
    stale_list = [c["corpus"] for c in corpora if c["staleness_category"] == "stale"]
    return {
        "schema": "auditooor.corpus_mining_state.v1",
        "generated_at": NOW.isoformat(),
        "stale_corpora": stale_list,
        "corpora": corpora,
    }


def render_markdown(snap: dict[str, Any]) -> str:
    lines = [
        f"# Corpus Mining State Snapshot",
        f"",
        f"Generated: {snap['generated_at']} UTC",
        f"",
        f"## Summary",
        f"",
        f"| Corpus | Last Mined | Volume | Staleness |",
        f"|--------|-----------|--------|-----------|",
    ]
    for c in snap["corpora"]:
        vol = ", ".join(f"{k}={v}" for k, v in c["volume"].items() if not isinstance(v, dict))
        last = (c.get("last_mined_at") or "never")[:10]
        lines.append(f"| {c['corpus']} | {last} | {vol} | {c['staleness_category']} |")

    lines += [
        f"",
        f"## Stale corpora (priority refresh targets)",
        f"",
    ]
    for name in snap["stale_corpora"]:
        lines.append(f"- `{name}`")

    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description="Corpus mining state snapshot")
    p.add_argument("--out-json", default=str(DEFAULT_JSON))
    p.add_argument("--out-md", default=str(DEFAULT_MD))
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    snap = build_snapshot()

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(snap, indent=2, sort_keys=False) + "\n")

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(snap))

    if not args.quiet:
        stale = snap["stale_corpora"]
        print(f"corpus-mining-state-snapshot: {len(snap['corpora'])} corpora inventoried")
        print(f"  stale ({len(stale)}): {', '.join(stale) if stale else 'none'}")
        print(f"  json  → {out_json}")
        print(f"  md    → {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
