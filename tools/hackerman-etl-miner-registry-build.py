#!/usr/bin/env python3
"""Build a machine-readable registry of all Hackerman ETL miners.

Walks every ``tools/hackerman-etl-from-*.py`` script and emits one JSON
descriptor per miner under ``tools/audit/etl_miner_registry/<slug>.json``,
plus an aggregate manifest at ``tools/audit/etl_miner_registry/_manifest.json``.

Each per-miner JSON conforms to the schema:

    {
      "schema": "auditooor.hackerman_etl_miner_registry_entry.v1",
      "tool_path":              "<rel-path-to-miner>",
      "miner_slug":             "<basename-minus-prefix>",
      "description":            "<first line of module docstring>",
      "target_subtree":         "audit/corpus_tags/tags/<subtree>"|None,
      "source_channel":         "gh-api"|"github-rest-api"|"pdf-listing"
                                |"web-scrape"|"commit-history"|"corpus-bridge",
      "verification_tier":      "tier-1"|"tier-2"|"tier-3",
      "companion_test_path":    "<rel-path>"|None,
      "makefile_target":        "<name>"|None,
      "record_count_emitted":   <int>,
      "honest_zero":            <bool>,
      "last_run_commit_sha":    "<sha>"|None
    }

The script is the canonical generator for the registry. It is invoked by:

    make hackerman-etl-registry-build      # regenerate registry
    make hackerman-etl-registry-check      # verify currency (build into tmp + diff)

CLI:

    --out-dir   Output directory (default: tools/audit/etl_miner_registry)
    --check     Build into a tmp dir, diff against the on-disk registry,
                exit 1 if drift is detected; print summary only otherwise.
    --quiet     Suppress per-entry stdout.

Hard rules:
  * Never invents subtrees / record counts / commit SHAs - all derived from
    the live filesystem + ``git log``.
  * If a target subtree is not present on disk and the miner has no resolved
    output dir, the entry is recorded with ``record_count_emitted=0`` and
    ``honest_zero=true``.
  * Output is deterministic: keys sorted, lists sorted, numeric counts not
    re-randomised.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
MINER_DIR = REPO_ROOT / "tools"
TEST_DIR = REPO_ROOT / "tools" / "tests"
TAGS_ROOT = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT_DIR = REPO_ROOT / "tools" / "audit" / "etl_miner_registry"
MAKEFILE_PATH = REPO_ROOT / "Makefile"

REGISTRY_SCHEMA = "auditooor.hackerman_etl_miner_registry_entry.v1"
MANIFEST_SCHEMA = "auditooor.hackerman_etl_miner_registry_manifest.v1"

VALID_SOURCE_CHANNELS = {
    "gh-api",
    "github-rest-api",
    "pdf-listing",
    "web-scrape",
    "commit-history",
    "corpus-bridge",
}
VALID_VERIFICATION_TIERS = {"tier-1", "tier-2", "tier-3"}


# ---------------------------------------------------------------------------
# Curated maps - only consulted when introspection cannot determine the value
# from the miner source. Each row is an honest fallback for a miner whose
# canonical output dir is supplied at the CLI ``--out-dir`` arg without an
# internal DEFAULT_OUT_DIR constant. We MUST NOT invent a subtree that does
# not have an on-disk presence; instead we resolve to the most plausible
# subtree by inspecting historic emissions.
# ---------------------------------------------------------------------------
CURATED_TARGET_SUBTREE = {
    # miner basename -> target subtree dir name under audit/corpus_tags/tags/
    # W5-L7 honest-zero backfill: corpus-mined / findings-go now materialise
    # into dedicated per-miner subtrees so their recovered records are counted
    # instead of being lost to a None (variable) target.
    "hackerman-etl-from-corpus-mined.py":              "corpus_mined",
    "hackerman-etl-from-darknavy-web3.py":             "darknavy_web3_incidents",
    "hackerman-etl-from-eth-client-rust.py":           "ethereum_client_rust",
    "hackerman-etl-from-findings-go.py":               "findings_go",
    "hackerman-etl-from-git-mining.py":                None,
    "hackerman-etl-from-immunefi-public.py":           "immunefi",
    "hackerman-etl-from-l2-zkrollup.py":               "l2_zkrollup",
    "hackerman-etl-from-platforms.py":                 "contest_platforms",
    "hackerman-etl-from-post-mortem.py":               "post_mortem",
    "hackerman-etl-from-prior-audits.py":              "prior_audits",
    "hackerman-etl-from-sig-extracts.py":              "sig_extracts",
    "hackerman-etl-from-solidity-fork-patterns.py":    "solidity_fork_patterns",
    "hackerman-etl-from-solodit-critical-platforms.py": "solodit_critical",
    "hackerman-etl-from-solodit-specs.py":             "solodit_specs",
    "hackerman-etl-from-starknet-cairo.py":            "starknet_cairo_real",
    "hackerman-etl-from-substrate-cosmwasm-frost.py":  "substrate_cosmwasm_frost",
    "hackerman-etl-from-sui-move.py":                  "sui_move",
    "hackerman-etl-from-verdict-tags.py":              None,  # emits to hackerman_records/
    "hackerman-etl-from-vyper-39363.py":               "vyper_cve_2023_39363",
    "hackerman-etl-from-vyper-cve.py":                 "vyper_cve",
    "hackerman-etl-from-zk-auditor-reports.py":        "zk_miners",
    "hackerman-etl-from-zk-contests.py":               "zk_miners",
    "hackerman-etl-from-zkbugs-catalog.py":            "zk_miners",
    "hackerman-etl-from-aptos-move.py":                "aptos_move",
}

CURATED_MAKEFILE_TARGET = {
    # The target predates the registry naming convention and intentionally
    # drops the "from" segment.
    "hackerman-etl-from-darknavy-web3.py": "darknavy-web3-mine",
    "hackerman-etl-from-post-mortem.py": "hackerman-etl-post-mortem",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def miner_slug(tool_path: Path) -> str:
    """``tools/hackerman-etl-from-foo-bar.py`` -> ``foo_bar``."""
    name = tool_path.name
    if not name.startswith("hackerman-etl-from-"):
        raise ValueError(f"unexpected miner name: {name}")
    stem = name[len("hackerman-etl-from-"):]
    if stem.endswith(".py"):
        stem = stem[:-3]
    return stem.replace("-", "_")


def list_miners(root: Path = MINER_DIR) -> List[Path]:
    miners = sorted(root.glob("hackerman-etl-from-*.py"))
    return [m for m in miners if m.is_file()]


def extract_docstring_line1(tool_path: Path) -> str:
    try:
        with tool_path.open("r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        doc = ast.get_docstring(tree) or ""
    except Exception:  # pragma: no cover - parse errors are rare
        return ""
    first = ""
    for line in doc.splitlines():
        s = line.strip()
        if s:
            first = s
            break
    return first


def extract_default_out_dir(tool_path: Path) -> Optional[str]:
    """Best-effort introspection for the miner's default output subtree.

    Looks for a ``DEFAULT_OUT_DIR = REPO_ROOT / ... / "tags" / "<subtree>"``
    pattern (the convention used by ~half of the miners), or for an
    ``argparse`` default referencing the same path. Returns the *subtree
    name only* (e.g. ``"amm_yield_lst_protocols"``) or ``None``.
    """
    try:
        text = tool_path.read_text(encoding="utf-8")
    except Exception:
        return None

    # Pattern A: DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags" / "<x>"
    m = re.search(
        r'DEFAULT_OUT_DIR\s*=\s*REPO_ROOT\s*/\s*"audit"\s*/\s*"corpus_tags"\s*/\s*"tags"\s*/\s*"([a-zA-Z0-9_]+)"',
        text,
    )
    if m:
        return m.group(1)

    # Pattern B: bare "audit/corpus_tags/tags/<x>" string in argparse default / docstring
    excluded = {"_QUARANTINE_FABRICATED_CVE", "_deprecated"}
    for cand in re.findall(r'audit/corpus_tags/tags/([a-zA-Z0-9_]+)', text):
        if cand not in excluded:
            return cand

    return None


def detect_source_channel(tool_path: Path) -> str:
    text = tool_path.read_text(encoding="utf-8", errors="replace")
    # Heuristics, evaluated in priority order. Each rule looks for a syntax
    # that is hard to confuse with another channel.
    if re.search(r"gh\s+api\s+/repos/.+/security-advisories|GH_API.*advisories", text):
        return "gh-api"
    if re.search(r"gh\s+api\s+/repos/.+/(commits|pulls)|git\s+log\s+|fetch_commit_diff|--since.*--author", text):
        return "commit-history"
    if re.search(r"https://api\.github\.com|requests\.get\([\"']https?://api\.github", text):
        return "github-rest-api"
    if re.search(r"pdf|\.pdf\b|pdf-listing|extract_pdf", text, re.IGNORECASE) and "extracted" in text.lower():
        return "pdf-listing"
    if re.search(r"playwright|httpx\.get|requests\.get|BeautifulSoup|html\.parser|WebCache|cache\.fetch|--fetch", text):
        return "web-scrape"
    if re.search(r"reference/findings_go|reference/corpus_mined|sig_extracts/|prior_audit", text):
        return "corpus-bridge"
    # Curated seed default = corpus-bridge (seed-driven miners read from a
    # bundled static table that itself is a curated corpus).
    return "corpus-bridge"


def detect_verification_tier(source_channel: str, tool_path: Path) -> str:
    """Map source channel -> verification tier per ETL doctrine.

    tier-1 = live REST/GHSA pull at run time (re-verifiable)
    tier-2 = commit-history / corpus-bridge / scraped-then-replayed
    tier-3 = curated seed table or static catalogue (manual cross-check)
    """
    if source_channel in {"gh-api", "github-rest-api"}:
        return "tier-1"
    if source_channel in {"commit-history", "corpus-bridge", "web-scrape", "pdf-listing"}:
        return "tier-2"
    return "tier-3"


def companion_test_path(slug: str) -> Optional[Path]:
    cand = TEST_DIR / f"test_hackerman_etl_from_{slug}.py"
    if cand.exists():
        return cand
    return None


def grep_makefile_target(slug: str, miner_basename: str) -> Optional[str]:
    if not MAKEFILE_PATH.exists():
        return None
    try:
        text = MAKEFILE_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    # Look for a target line like "hackerman-etl-from-<slug>:" (hyphenated)
    miner_dash = miner_basename.replace("hackerman-etl-from-", "").replace(".py", "")
    target = f"hackerman-etl-from-{miner_dash}"
    pat = rf"^{re.escape(target)}\s*:"
    if re.search(pat, text, flags=re.MULTILINE):
        return target
    curated = CURATED_MAKEFILE_TARGET.get(miner_basename)
    if curated and re.search(rf"^{re.escape(curated)}\s*:", text, flags=re.MULTILINE):
        return curated
    return None


def count_records_in_subtree(subtree: Optional[str]) -> Tuple[int, bool]:
    """Returns (count, exists_on_disk).

    Counts every ``*.yaml`` file under ``audit/corpus_tags/tags/<subtree>``
    (recursive). YAML is the canonical emission format; ``record.json`` is
    normally a mirror of a sibling ``record.yaml`` and is not double-counted.

    W5-L7 fix: some miners (e.g. ``hackerman-etl-from-move-aptos-sui.py``)
    emit a per-record directory containing only ``record.json`` with no
    ``record.yaml`` sibling. Those JSON-only records were previously
    invisible to the registry and forced a false ``honest_zero``. They are
    now counted, but only when no sibling ``.yaml`` exists (so genuine
    mirror pairs are still counted exactly once).
    """
    if not subtree:
        return 0, False
    root = TAGS_ROOT / subtree
    if not root.exists() or not root.is_dir():
        return 0, False
    count = sum(1 for _ in root.rglob("*.yaml"))
    for jpath in root.rglob("record.json"):
        if not jpath.with_suffix(".yaml").exists():
            count += 1
    return count, True


def git_last_commit_sha(tool_path: Path) -> Optional[str]:
    try:
        rel = tool_path.relative_to(REPO_ROOT)
    except ValueError:
        rel = tool_path
    try:
        out = subprocess.check_output(
            ["git", "log", "-n", "1", "--pretty=format:%H", "--", str(rel)],
            cwd=str(REPO_ROOT),
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or None
    except Exception:
        return None


def build_entry(tool_path: Path) -> Dict[str, Any]:
    slug = miner_slug(tool_path)
    desc = extract_docstring_line1(tool_path)
    derived = extract_default_out_dir(tool_path)
    curated = CURATED_TARGET_SUBTREE.get(tool_path.name)
    subtree = derived if derived else curated  # introspection wins
    source_channel = detect_source_channel(tool_path)
    tier = detect_verification_tier(source_channel, tool_path)
    test_path = companion_test_path(slug)
    makefile_target = grep_makefile_target(slug, tool_path.name)
    rec_count, subtree_present = count_records_in_subtree(subtree)
    last_sha = git_last_commit_sha(tool_path)

    target_subtree = None
    if subtree:
        target_subtree = f"audit/corpus_tags/tags/{subtree}"

    honest_zero = rec_count == 0

    return {
        "schema": REGISTRY_SCHEMA,
        "miner_slug": slug,
        "tool_path": str(tool_path.relative_to(REPO_ROOT)),
        "description": desc,
        "target_subtree": target_subtree,
        "target_subtree_exists_on_disk": bool(subtree_present),
        "source_channel": source_channel,
        "verification_tier": tier,
        "companion_test_path": str(test_path.relative_to(REPO_ROOT)) if test_path else None,
        "makefile_target": makefile_target,
        "record_count_emitted": rec_count,
        "honest_zero": honest_zero,
        "last_run_commit_sha": last_sha,
    }


def emit_entry(out_dir: Path, entry: Dict[str, Any]) -> Path:
    fp = out_dir / f"{entry['miner_slug']}.json"
    fp.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return fp


def build_manifest(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_channel: Dict[str, int] = {}
    by_tier: Dict[str, int] = {}
    honest_zeros: List[str] = []
    total_records = 0
    for e in entries:
        by_channel[e["source_channel"]] = by_channel.get(e["source_channel"], 0) + 1
        by_tier[e["verification_tier"]] = by_tier.get(e["verification_tier"], 0) + 1
        total_records += e["record_count_emitted"]
        if e["honest_zero"]:
            honest_zeros.append(e["miner_slug"])
    return {
        "schema": MANIFEST_SCHEMA,
        "miner_count": len(entries),
        "miners": sorted(e["miner_slug"] for e in entries),
        "honest_zero_miners": sorted(honest_zeros),
        "honest_zero_count": len(honest_zeros),
        "records_total_yaml": total_records,
        "by_source_channel": dict(sorted(by_channel.items())),
        "by_verification_tier": dict(sorted(by_tier.items())),
    }


def render_registry(out_dir: Path, quiet: bool = False) -> Tuple[List[Path], Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    miners = list_miners()
    entries = []
    paths = []
    for m in miners:
        entry = build_entry(m)
        entries.append(entry)
        p = emit_entry(out_dir, entry)
        paths.append(p)
        if not quiet:
            print(f"[registry] {entry['miner_slug']:<48} records={entry['record_count_emitted']:>5}  channel={entry['source_channel']}")
    manifest = build_manifest(entries)
    manifest_path = out_dir / "_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not quiet:
        print(f"[registry] wrote {len(paths)} miner entries + manifest -> {out_dir}")
    return paths, manifest_path


def _read_or_empty(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8")


def check_drift(out_dir: Path) -> int:
    """Render into a tmp dir, diff against on-disk registry, exit non-zero on drift."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        render_registry(tmp_dir, quiet=True)
        # Compare file-by-file
        live_files = {p.name: p for p in out_dir.glob("*.json")} if out_dir.exists() else {}
        rebuilt = {p.name: p for p in tmp_dir.glob("*.json")}
        drifted: List[str] = []
        for name, rp in rebuilt.items():
            lp = live_files.get(name)
            if lp is None or _read_or_empty(lp) != _read_or_empty(rp):
                drifted.append(name)
        for name in set(live_files) - set(rebuilt):
            drifted.append(f"stale:{name}")
        if drifted:
            print("[registry-check] DRIFT detected; run 'make hackerman-etl-registry-build'.")
            for d in sorted(drifted):
                print(f"  drift: {d}")
            return 1
        print(f"[registry-check] OK: {len(rebuilt)} entries current.")
        return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), type=str)
    parser.add_argument("--check", action="store_true", help="Verify registry is up to date.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    out_dir = Path(args.out_dir)
    if args.check:
        return check_drift(out_dir)
    render_registry(out_dir, quiet=args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
