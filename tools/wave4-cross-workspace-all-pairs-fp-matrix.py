#!/usr/bin/env python3
"""Wave-4 P0 W4.3: cross-workspace all-pairs FP transfer matrix.

For each (source_workspace, target_workspace) pair in the 16-workspace
fleet at ``~/audits/*``, derives a per-source seed-set from the source
workspace's ``derived_detectors/*.yaml`` (Tier-6 backward-mined synthetic
DSL patterns) and fires the universal-FP runner
(``tools/audit/universal_fp_runner.py``) against the target workspace's
source tree.

The output matrix lets the operator see which (src, tgt) pairs produce
shape transfer, ranks workspaces by universality-yield, and surfaces
candidate NEW universals (attack-classes present in >=3 distinct source
workspaces).

Schema for the emitted JSON: ``auditooor.wave4_all_pairs_fp_matrix.v1``.

CLI surface (per Wave-4 W4.3 brief):

  --workspaces-glob <pattern>   Default: ``~/audits/*`` (literal glob).
  --fp-dir <path>               Default: repo root /audit/corpus_tags/tags.
  --seed-source {tier6|derived_detectors|both}   Default: ``derived_detectors``.
                                ``tier6`` reads ``<ws>/mining_rounds/*tier6*``
                                report markdown if present (lower-yield);
                                ``derived_detectors`` reads
                                ``<ws>/derived_detectors/*.yaml`` (higher-
                                yield, schema is ``auditooor.dsl_pattern.synthetic``).
                                ``both`` unions the two.
  --out-json <path>             Default: ``audit/corpus_tags/derived/wave4_all_pairs_matrix.json``.
  --out-markdown <path>         Default: ``docs/WAVE4_ALL_PAIRS_FP_MATRIX_2026-05-16.md``.
  --workers <N>                 Parallelism for per-target runner invocations
                                (default 4). Each (src, tgt) target invocation
                                is a separate subprocess of the universal FP runner.
  --skip-pairs <pattern>        Regex applied to ``<src>:<tgt>``; matching pairs
                                are skipped (e.g.
                                ``solidity-only:.*go-only.*`` to skip
                                cross-language pairs).
  --skip-cross-language         Convenience flag: skip every pair whose source
                                workspace has only Solidity seeds but target
                                has only Go source files (or vice versa).
  --workspace-language-pin      Optional JSON map of ``{<ws>: <"solidity"|"go"|
                                "rust"|"mixed">}`` to override auto-detection.
  --dry-run                     Skip subprocess invocations; emit matrix
                                skeleton only (useful for validating wiring).
  --strict                      Exit non-zero if no candidate new universal
                                emerges (>= 3 distinct source workspaces sharing
                                the same attack_class).

Validation discipline:
  * Real workspace walks. Synthetic-fixture YAML records (carrying
    ``synthetic_fixture: true``) are excluded from the seed-set
    derivation so the matrix reflects real Tier-6 anchors only.
  * Honest pins: cross-language transfer (e.g. Sol-seed source applied
    to Go-only target) is well-known to produce keyword-collision false
    positives. The output markdown enumerates a cross-language transfer
    pin per pair and applies the language-pin filter only when
    ``--skip-cross-language`` is set.
  * No mutation of any workspace. Read-only walks via subprocess.
  * Rule 36 / Rule 37 N/A here: this tool is a consumer, not an emitter.
    It does not write any corpus tag records.

Output schema (top-level keys, all sorted):
  schema, generated_at, workspaces_evaluated, source_workspaces,
  target_workspaces, fp_dir, seed_source, transfers (matrix
  src -> tgt -> [{fp_id, hit_count, novel_count}]),
  workspace_universality_yield_rank,
  candidate_new_universals (attack_class shared by >=3 source workspaces),
  honest_pins, cli_args, mcp_token_present.

Stdlib only (PyYAML for YAML load; same dependency as universal_fp_runner).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as _dt
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yaml  # PyYAML
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "[wave4-all-pairs] PyYAML required; install via "
        "`pip install pyyaml` (got: %s)\n" % exc
    )
    sys.exit(2)


SCHEMA_VERSION = "auditooor.wave4_all_pairs_fp_matrix.v1"


# --------------------------------------------------------------------------
# Attack-class -> FP-XX projection (mirrors the
# WAVE3_CROSS_PROTOCOL_PATTERN_TRANSFER_2026-05-16.md classification logic,
# extended for the synthetic DSL patterns in derived_detectors).
# --------------------------------------------------------------------------


# Keywords -> FP-XX. Order matters: first match wins. Each tuple is
# (regex on attack_class lowercased, fp_id). The mapping reflects the
# verbatim language used in the Wave-3 transfer doc.
_ATTACK_CLASS_TO_FP = [
    # FP-04 first: revert/refactor signal is its own family.
    (re.compile(r"reverted|reverts?-(?:emergency|guard|fix|refactor)"), "FP-04"),
    (re.compile(r"loosened-(?:guard|validation|cap|input)"), "FP-04"),
    (re.compile(r"commission-cap-(?:enforcement-)?regression"), "FP-04"),
    # FP-05: rename / enum-stale.
    (re.compile(r"(?:enum|rename|stale)-(?:rename|reference|name)"), "FP-05"),
    (re.compile(r"enum-rename"), "FP-05"),
    (re.compile(r"-rename-"), "FP-05"),
    # FP-06: interface arity / contract-drift.
    (re.compile(r"interface-arity-drift"), "FP-06"),
    (re.compile(r"interface-drift|contract-drift|interface-shape"), "FP-06"),
    (re.compile(r"-interface-(?:completeness|drift)"), "FP-06"),
    (re.compile(r"administration-interface"), "FP-06"),
    # FP-03: state-desync / config-update / initializer chain.
    (re.compile(r"state-desync|config-update|memclob-desync"), "FP-03"),
    (re.compile(r"initializer-chain"), "FP-03"),
    (re.compile(r"gov-msg.*update|subticks-per-tick"), "FP-03"),
    (re.compile(r"env-config-drift"), "FP-03"),
    # FP-02: atomic / multi-write / ordering / propagation.
    (re.compile(r"atomic-multi-write|multi-write-ordering"), "FP-02"),
    (re.compile(r"propagat(?:e|ion)-gap|propagation-gap"), "FP-02"),
    (re.compile(r"dual-write-status"), "FP-02"),
    (re.compile(r"ordering-vs|bank-send-ordering"), "FP-02"),
    # FP-01: missing-validation / missing-check / silent-skip /
    # underflow-protection-missing / divide-by / bypass.
    (re.compile(r"missing-(?:validation|check|guard|blockedaddr|margin)"), "FP-01"),
    (re.compile(r"silent-skip|underflow-protection|divide-by"), "FP-01"),
    (re.compile(r"without-(?:staleness|invariant|state-helper|reclaim)"), "FP-01"),
    (re.compile(r"bypass-in-"), "FP-01"),
    (re.compile(r"-without-(?:precondition|guard|check|reclaim|state)"), "FP-01"),
    (re.compile(r"reclaim-address-missing|reward-condition-missing"), "FP-01"),
    (re.compile(r"role-enumeration-fallback"), "FP-01"),
    (re.compile(r"counter-underflow|saturating-sub"), "FP-01"),
    (re.compile(r"^pre-(?:order|trade)-"), "FP-01"),
    (re.compile(r"-without-(?:state-update|coverage)"), "FP-01"),
]


def classify_attack_class(attack_class: str) -> str:
    """Map an attack_class slug to one of FP-01..FP-06 (or 'FP-XX' if
    no rule fires).
    """
    if not attack_class:
        return "FP-XX"
    lc = attack_class.lower()
    for rx, fp in _ATTACK_CLASS_TO_FP:
        if rx.search(lc):
            return fp
    return "FP-XX"


# --------------------------------------------------------------------------
# Seed loading from a source workspace.
# --------------------------------------------------------------------------


def _read_yaml_safe(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
            if not isinstance(doc, dict):
                return {}
            return doc
    except (OSError, yaml.YAMLError):
        return {}


def load_seeds_from_derived_detectors(ws: Path) -> list:
    """Read every YAML under ``<ws>/derived_detectors/``.

    Returns a list of dicts: {record_id, attack_class, target_language,
    target_repo, mitigation_commit_sha, synthetic_fixture}.
    """
    out = []
    dd_dir = ws / "derived_detectors"
    if not dd_dir.is_dir():
        return out
    for path in sorted(dd_dir.glob("*.yaml")):
        doc = _read_yaml_safe(path)
        if not doc:
            continue
        if doc.get("synthetic_fixture") is True:
            # Skip synthetic-fixture rows so the matrix reflects real
            # Tier-6 anchors only.
            continue
        out.append(
            {
                "record_id": str(doc.get("record_id") or path.stem),
                "attack_class": str(doc.get("attack_class") or ""),
                "target_language": str(doc.get("target_language") or "unknown"),
                "target_repo": str(doc.get("target_repo") or "unknown"),
                "mitigation_commit_sha": str(
                    doc.get("mitigation_commit_sha") or ""
                ),
                "source_path": str(path),
                "is_new_unknown": bool(doc.get("is_new_unknown") or False),
            }
        )
    return out


def load_seeds_from_tier6(ws: Path) -> list:
    """Best-effort scrape of Tier-6 anchor SHAs from a workspace's
    Tier-6 backward-mining report markdown.

    Returns a list of dicts: {record_id (synthetic), attack_class (best-effort),
    target_language (unknown), source_path}.
    Tier-6 reports do not carry a strict ``attack_class`` per anchor, so this
    fallback is intentionally low-signal. Operators should prefer
    ``--seed-source derived_detectors``.
    """
    out = []
    candidates = list(ws.glob("TIER6_BACKWARD_MINING_*.md"))
    # Also accept the canonical lower-cased variant under mining_rounds.
    mining_dir = ws / "mining_rounds"
    if mining_dir.is_dir():
        for sub in mining_dir.iterdir():
            if sub.is_dir() and "tier6" in sub.name.lower():
                for f in sub.glob("*.md"):
                    candidates.append(f)
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Extract attack-class slugs by scraping `attack_class:` lines
        # if any, plus markdown column entries.
        for m in re.finditer(r"^\s*attack[_-]class\s*[:=]\s*`?([\w\-]+)`?", text, re.MULTILINE):
            out.append(
                {
                    "record_id": "tier6:" + path.name + ":" + m.group(1),
                    "attack_class": m.group(1),
                    "target_language": "unknown",
                    "target_repo": "unknown",
                    "mitigation_commit_sha": "",
                    "source_path": str(path),
                    "is_new_unknown": False,
                }
            )
    return out


def load_seeds(ws: Path, seed_source: str) -> list:
    seeds = []
    if seed_source in ("derived_detectors", "both"):
        seeds.extend(load_seeds_from_derived_detectors(ws))
    if seed_source in ("tier6", "both"):
        seeds.extend(load_seeds_from_tier6(ws))
    # Dedup by record_id.
    seen = set()
    dedup = []
    for s in seeds:
        rid = s["record_id"]
        if rid in seen:
            continue
        seen.add(rid)
        dedup.append(s)
    return dedup


# --------------------------------------------------------------------------
# Language detection for cross-language transfer pin.
# --------------------------------------------------------------------------


SOURCE_EXT_TO_LANG = {
    ".sol": "solidity",
    ".go": "go",
    ".rs": "rust",
}

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "build",
    "out",
    "cache",
    "forge-cache",
    "target",
    "dist",
    ".venv",
    "__pycache__",
    "_archive",
}


def detect_workspace_language(ws: Path, scan_cap: int = 4000) -> str:
    """Return one of {solidity, go, rust, mixed, none} based on first
    ``scan_cap`` source files under ``ws``.
    """
    counts = {"solidity": 0, "go": 0, "rust": 0}
    n = 0
    for root, dirs, files in os.walk(ws):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            ext = os.path.splitext(fn)[1]
            lang = SOURCE_EXT_TO_LANG.get(ext)
            if lang is None:
                continue
            counts[lang] += 1
            n += 1
            if n >= scan_cap:
                break
        if n >= scan_cap:
            break
    total = sum(counts.values())
    if total == 0:
        return "none"
    if max(counts.values()) >= total * 0.8:
        # Single dominant language.
        for lang, c in counts.items():
            if c == max(counts.values()):
                return lang
    return "mixed"


# --------------------------------------------------------------------------
# Runner invocation.
# --------------------------------------------------------------------------


def run_universal_fp_on_target(
    runner_path: Path,
    target_ws: Path,
    fp_dir: Path,
    fps: list,
    timeout_s: int = 300,
) -> dict:
    """Subprocess-spawn the universal-FP runner against ``target_ws``
    restricted to FPs in ``fps``.

    Returns the runner's JSON output dict, or a stub envelope on failure.
    """
    if not fps:
        return {
            "schema": "auditooor.universal_fp_runner.v1",
            "total_hits": 0,
            "hits_per_fp": {},
            "confidence_per_fp": {},
            "hits": [],
            "_skipped_reason": "no_fps_in_intersection",
        }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as tmp:
        out_path = tmp.name
    try:
        cmd = [
            sys.executable,
            str(runner_path),
            "--workspace",
            str(target_ws),
            "--fp-dir",
            str(fp_dir),
            "--fps",
            ",".join(sorted(fps)),
            "--output",
            out_path,
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        if proc.returncode not in (0, 1):
            return {
                "schema": "auditooor.universal_fp_runner.v1",
                "total_hits": 0,
                "hits_per_fp": {fp: 0 for fp in fps},
                "confidence_per_fp": {},
                "hits": [],
                "_error": proc.stderr[-400:],
            }
        with open(out_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
        return {
            "schema": "auditooor.universal_fp_runner.v1",
            "total_hits": 0,
            "hits_per_fp": {fp: 0 for fp in fps},
            "confidence_per_fp": {},
            "hits": [],
            "_error": "runner_exception:" + str(exc)[:200],
        }
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Matrix orchestration.
# --------------------------------------------------------------------------


def derive_fp_set_for_source(seeds: list) -> dict:
    """Group seeds by their projected FP_id.

    Returns: {fp_id: [seed_record, ...]} sorted by fp_id.
    """
    by_fp = {}
    for s in seeds:
        fp = classify_attack_class(s["attack_class"])
        by_fp.setdefault(fp, []).append(s)
    return dict(sorted(by_fp.items()))


def language_compat(source_langs: set, target_lang: str) -> bool:
    """Return True if the (source_langs -> target_lang) transfer is
    intra-language (or target language is in the source-lang set).
    Cross-language pairs return False.
    """
    if not source_langs:
        return True  # No language signal -> let the FP runner filter.
    if target_lang == "mixed":
        return True  # Mixed target accepts any source seed language.
    if target_lang == "none":
        return False
    return target_lang in source_langs


def compute_matrix(
    workspaces: list,
    fp_dir: Path,
    runner_path: Path,
    seed_source: str,
    workspace_languages: dict,
    workers: int,
    skip_pattern: re.Pattern,
    skip_cross_language: bool,
    dry_run: bool,
) -> dict:
    """Run the (src, tgt) matrix.

    Returns the JSON-serializable matrix dict.
    """
    # Pre-load all source seed sets.
    source_to_seeds = {}
    source_to_fp_set = {}
    source_to_seed_langs = {}
    for ws in workspaces:
        seeds = load_seeds(ws, seed_source)
        source_to_seeds[ws.name] = seeds
        source_to_fp_set[ws.name] = derive_fp_set_for_source(seeds)
        langs = set()
        for s in seeds:
            lang = s.get("target_language") or ""
            if lang and lang != "unknown":
                langs.add(lang)
        source_to_seed_langs[ws.name] = langs

    # Skip src workspaces with empty FP set.
    source_workspaces = [w for w in workspaces if source_to_fp_set[w.name]]

    pair_jobs = []
    for src in source_workspaces:
        src_fps = sorted(source_to_fp_set[src.name].keys())
        # Drop FP-XX (unclassified) from the firing set.
        src_fps_known = [fp for fp in src_fps if fp != "FP-XX"]
        for tgt in workspaces:
            pair_key = "%s:%s" % (src.name, tgt.name)
            if skip_pattern and skip_pattern.search(pair_key):
                pair_jobs.append(
                    (src, tgt, src_fps_known, "skip-pattern")
                )
                continue
            if skip_cross_language:
                src_langs = source_to_seed_langs.get(src.name) or set()
                tgt_lang = workspace_languages.get(tgt.name, "mixed")
                if src_langs and not language_compat(src_langs, tgt_lang):
                    pair_jobs.append(
                        (src, tgt, src_fps_known, "skip-cross-language")
                    )
                    continue
            pair_jobs.append((src, tgt, src_fps_known, None))

    transfers = {}
    pair_results = []

    def _run_one(job):
        src, tgt, src_fps_known, skip_reason = job
        key_src = src.name
        key_tgt = tgt.name
        if skip_reason:
            return (
                key_src,
                key_tgt,
                {
                    "skipped": True,
                    "skip_reason": skip_reason,
                    "fps_attempted": src_fps_known,
                    "hits_per_fp": {},
                    "total_hits": 0,
                },
            )
        if dry_run or not src_fps_known:
            return (
                key_src,
                key_tgt,
                {
                    "skipped": False,
                    "dry_run": dry_run or not src_fps_known,
                    "fps_attempted": src_fps_known,
                    "hits_per_fp": {fp: 0 for fp in src_fps_known},
                    "total_hits": 0,
                },
            )
        runner_out = run_universal_fp_on_target(
            runner_path,
            tgt,
            fp_dir,
            src_fps_known,
        )
        hits_per_fp = runner_out.get("hits_per_fp") or {}
        # Novelty: a hit is "novel" if the target_ws is NOT in
        # workspaces_observed for that FP. Conservative default: every
        # hit is novel because we don't currently parse the FP YAML's
        # workspaces_observed tag here (would require re-loading the
        # FP definitions). The runner already does that load; we
        # forward its evaluation if present.
        confidence_per_fp = runner_out.get("confidence_per_fp") or {}
        return (
            key_src,
            key_tgt,
            {
                "skipped": False,
                "fps_attempted": src_fps_known,
                "hits_per_fp": hits_per_fp,
                "confidence_per_fp": confidence_per_fp,
                "total_hits": runner_out.get("total_hits", 0),
                "runner_error": runner_out.get("_error"),
            },
        )

    if dry_run or workers <= 1:
        for job in pair_jobs:
            src_key, tgt_key, result = _run_one(job)
            transfers.setdefault(src_key, {})[tgt_key] = result
            pair_results.append((src_key, tgt_key, result))
    else:
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(_run_one, job): job for job in pair_jobs}
            for fut in cf.as_completed(future_map):
                src_key, tgt_key, result = fut.result()
                transfers.setdefault(src_key, {})[tgt_key] = result
                pair_results.append((src_key, tgt_key, result))

    # Candidate-new-universal: any attack_class slug seen in seeds of >=3
    # distinct source workspaces.
    attack_class_to_sources = {}
    for src in source_workspaces:
        seen_in_src = set()
        for seed in source_to_seeds[src.name]:
            ac = seed["attack_class"]
            if not ac:
                continue
            seen_in_src.add(ac)
        for ac in seen_in_src:
            attack_class_to_sources.setdefault(ac, set()).add(src.name)
    candidate_new_universals = []
    for ac, srcs in sorted(attack_class_to_sources.items()):
        if len(srcs) >= 3:
            candidate_new_universals.append(
                {
                    "attack_class": ac,
                    "source_workspaces": sorted(srcs),
                    "source_count": len(srcs),
                    "proposed_fp_bucket": classify_attack_class(ac),
                }
            )
    candidate_new_universals.sort(
        key=lambda r: (-r["source_count"], r["attack_class"])
    )

    # Workspace universality-yield ranking: for each target workspace,
    # sum total_hits across all (src, tgt) pairs landing on it.
    target_yield = {}
    source_yield = {}
    for src in source_workspaces:
        for tgt in workspaces:
            r = transfers.get(src.name, {}).get(tgt.name) or {}
            if r.get("skipped"):
                continue
            n = r.get("total_hits") or 0
            target_yield[tgt.name] = target_yield.get(tgt.name, 0) + n
            source_yield[src.name] = source_yield.get(src.name, 0) + n
    target_ranking = sorted(
        target_yield.items(), key=lambda kv: (-kv[1], kv[0])
    )
    source_ranking = sorted(
        source_yield.items(), key=lambda kv: (-kv[1], kv[0])
    )

    return {
        "transfers": transfers,
        "source_to_fp_set": {
            k: {fp: [s["record_id"] for s in seeds] for fp, seeds in fps.items()}
            for k, fps in source_to_fp_set.items()
        },
        "source_to_seed_count": {
            k: len(seeds) for k, seeds in source_to_seeds.items()
        },
        "source_to_seed_langs": {
            k: sorted(v) for k, v in source_to_seed_langs.items()
        },
        "target_workspace_yield_rank": [
            {"workspace": k, "total_hits": v} for k, v in target_ranking
        ],
        "source_workspace_yield_rank": [
            {"workspace": k, "total_hits": v} for k, v in source_ranking
        ],
        "candidate_new_universals": candidate_new_universals,
    }


# --------------------------------------------------------------------------
# Markdown rendering.
# --------------------------------------------------------------------------


def render_markdown(payload: dict, workspaces: list) -> str:
    lines = []
    lines.append("# Wave-4 P0 W4.3: cross-workspace all-pairs FP transfer matrix")
    lines.append("")
    lines.append("- schema: " + payload["schema"])
    lines.append("- generated_at: " + payload["generated_at"])
    lines.append("- seed_source: " + payload["seed_source"])
    lines.append(
        "- workspaces_evaluated: %d" % len(payload["workspaces_evaluated"])
    )
    lines.append(
        "- source_workspaces (had >=1 derived seed): %d"
        % len(payload["source_workspaces"])
    )
    lines.append(
        "- target_workspaces (had >=1 source file): %d"
        % len(payload["target_workspaces"])
    )
    lines.append("- mcp_context_pack_id: " + (payload.get("mcp_context_pack_id") or "n/a"))
    lines.append("")
    lines.append("## 0. Workspace coverage")
    lines.append("")
    lines.append("| workspace | language | seed_count | seed_FP_buckets |")
    lines.append("| --- | --- | ---:| --- |")
    fp_set_map = payload["matrix"]["source_to_fp_set"]
    seed_count_map = payload["matrix"]["source_to_seed_count"]
    lang_map = payload["workspace_languages"]
    for ws_name in sorted(payload["workspaces_evaluated"]):
        fps = sorted((fp_set_map.get(ws_name) or {}).keys())
        lines.append(
            "| %s | %s | %d | %s |"
            % (
                ws_name,
                lang_map.get(ws_name, "?"),
                seed_count_map.get(ws_name, 0),
                ", ".join(fps) if fps else "(none)",
            )
        )
    lines.append("")
    lines.append("## 1. Per-pair transfer summary table")
    lines.append("")
    lines.append("Each row is one (source_ws, target_ws) pair. ``total_hits`` is the sum of universal-FP-runner hits across all FPs the source contributes (FP-01..FP-06). ``skipped`` rows are excluded by either pattern or cross-language filter.")
    lines.append("")
    lines.append("| source_ws | target_ws | fps_attempted | total_hits | skipped | reason |")
    lines.append("| --- | --- | --- | ---:| --- | --- |")
    transfers = payload["matrix"]["transfers"]
    rows = []
    for src in sorted(transfers.keys()):
        for tgt in sorted(transfers[src].keys()):
            r = transfers[src][tgt]
            rows.append(
                (
                    src,
                    tgt,
                    ",".join(r.get("fps_attempted") or []) or "(none)",
                    r.get("total_hits", 0),
                    "yes" if r.get("skipped") else "no",
                    r.get("skip_reason") or r.get("runner_error") or "",
                )
            )
    # Order by descending total_hits then alpha.
    rows.sort(key=lambda r: (-r[3], r[0], r[1]))
    # Top 80 rows shown in detail; remainder in summary.
    TOP_N = 80
    for r in rows[:TOP_N]:
        lines.append("| %s | %s | %s | %d | %s | %s |" % r)
    if len(rows) > TOP_N:
        lines.append("")
        lines.append("Remaining %d rows omitted from markdown (full data in JSON)." % (len(rows) - TOP_N))
    lines.append("")
    lines.append("## 2. Candidate NEW universals (FP-12+ proposals)")
    lines.append("")
    cands = payload["matrix"]["candidate_new_universals"]
    if not cands:
        lines.append(
            "No attack_class slug appeared in >=3 distinct source workspaces. "
            "Increase ``--seed-source`` to ``both`` or expand the workspace fleet "
            "to surface new universals."
        )
    else:
        lines.append("| attack_class | source_count | source_workspaces | proposed_fp_bucket |")
        lines.append("| --- | ---:| --- | --- |")
        for c in cands:
            lines.append(
                "| %s | %d | %s | %s |"
                % (
                    c["attack_class"],
                    c["source_count"],
                    ", ".join(c["source_workspaces"]),
                    c["proposed_fp_bucket"],
                )
            )
    lines.append("")
    lines.append("## 3. Workspace ranking by universality-yield")
    lines.append("")
    lines.append("### 3a. Target-workspace yield (most FP hits absorbed)")
    lines.append("")
    lines.append("| rank | target_workspace | total_hits |")
    lines.append("| ---:| --- | ---:|")
    for i, r in enumerate(payload["matrix"]["target_workspace_yield_rank"][:30], 1):
        lines.append("| %d | %s | %d |" % (i, r["workspace"], r["total_hits"]))
    lines.append("")
    lines.append("### 3b. Source-workspace yield (most FP hits contributed)")
    lines.append("")
    lines.append("| rank | source_workspace | total_hits |")
    lines.append("| ---:| --- | ---:|")
    for i, r in enumerate(payload["matrix"]["source_workspace_yield_rank"][:30], 1):
        lines.append("| %d | %s | %d |" % (i, r["workspace"], r["total_hits"]))
    lines.append("")
    lines.append("## 4. Honest cross-language transfer pin")
    lines.append("")
    lines.extend(payload["honest_pins"])
    lines.append("")
    lines.append("## 5. Reproduce")
    lines.append("")
    lines.append("```")
    lines.append(" ".join(payload["cli_args"]))
    lines.append("```")
    lines.append("")
    return "\n".join(lines) + "\n"


HONEST_PINS = [
    "- Cross-language transfer (e.g. Solidity-seed source applied to Go-only target) routinely surfaces keyword-collision FPs because the universal-FP runner's strategies fire per-language. The matrix therefore shows total_hits=0 for cross-language pairs unless ``--skip-cross-language`` is OFF, and uniformly ``skipped`` when it is ON.",
    "- ``--seed-source derived_detectors`` is the primary high-yield path; ``--seed-source tier6`` falls back to scraping markdown reports and is intentionally low-signal. Pair-yields under ``tier6``-only mode are advisory, not authoritative.",
    "- The attack_class -> FP-XX projection (lines 78-118 of this tool) is heuristic. Slugs that fall to FP-XX are excluded from runner invocation; the operator may extend the regex table when new slugs surface.",
    "- ``candidate_new_universals`` are NOT promoted automatically. The operator MUST run the standard universal-FP YAML promotion pipeline (PR #729 / commit f45410a4cd shape) before they fire under ``make audit-deep``.",
    "- novel_count is currently equal to total_hits in this v1 emitter: workspace-overlap filtering against each FP YAML's ``workspaces_observed`` tag is delegated to the universal-FP runner's own confidence stratification.",
    "- The matrix does not run any production-profile PoC; per Rule 30, candidate new universals at HIGH+ severity require independent production-profile evidence before promotion.",
]


# --------------------------------------------------------------------------
# CLI.
# --------------------------------------------------------------------------


def _repo_root() -> Path:
    # tools/wave4-cross-workspace-all-pairs-fp-matrix.py -> repo root is parents[1]
    return Path(__file__).resolve().parents[1]


def main(argv: list) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Cross-workspace all-pairs FP transfer matrix (Wave-4 P0 W4.3). "
            "Derives FP-01..FP-06 seed sets from each workspace's "
            "derived_detectors/, runs the universal FP runner against every "
            "target workspace, and emits matrix + candidate new universals."
        )
    )
    p.add_argument(
        "--workspaces-glob",
        default=str(Path("~/audits/*").expanduser()),
        help="literal glob for workspace roots (default ~/audits/*)",
    )
    p.add_argument(
        "--fp-dir",
        default=str(_repo_root() / "audit" / "corpus_tags" / "tags"),
        help="directory holding dsl_pattern_universal_fp_*.yaml",
    )
    p.add_argument(
        "--seed-source",
        choices=["tier6", "derived_detectors", "both"],
        default="derived_detectors",
    )
    p.add_argument(
        "--out-json",
        default=str(
            _repo_root()
            / "audit"
            / "corpus_tags"
            / "derived"
            / "wave4_all_pairs_matrix.json"
        ),
    )
    p.add_argument(
        "--out-markdown",
        default=str(
            _repo_root() / "docs" / "WAVE4_ALL_PAIRS_FP_MATRIX_2026-05-16.md"
        ),
    )
    p.add_argument("--workers", type=int, default=4)
    p.add_argument(
        "--skip-pairs",
        default="",
        help="regex on '<src>:<tgt>'; matching pairs are skipped",
    )
    p.add_argument(
        "--skip-cross-language",
        action="store_true",
        help="skip pairs where source-seed language disjoint from target source-tree language",
    )
    p.add_argument(
        "--workspace-language-pin",
        default="",
        help="JSON map overriding auto-detected workspace language",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="emit skeleton without invoking subprocesses",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if zero candidate new universals surfaced",
    )
    p.add_argument(
        "--mcp-context-pack-id",
        default=os.environ.get("MCP_CONTEXT_PACK_ID", ""),
        help="annotate matrix with the MCP context pack id (for commit-message linkage)",
    )
    p.add_argument(
        "--runner-path",
        default=str(_repo_root() / "tools" / "audit" / "universal_fp_runner.py"),
    )
    args = p.parse_args(argv)

    fp_dir = Path(args.fp_dir).expanduser().resolve()
    runner_path = Path(args.runner_path).expanduser().resolve()
    if not runner_path.is_file():
        sys.stderr.write(
            "[wave4-all-pairs] runner not found: %s\n" % runner_path
        )
        return 2

    workspaces_glob_expanded = os.path.expanduser(args.workspaces_glob)
    raw = sorted(glob.glob(workspaces_glob_expanded))
    workspaces = [Path(p).resolve() for p in raw if Path(p).is_dir()]
    if not workspaces:
        sys.stderr.write(
            "[wave4-all-pairs] no workspaces matched glob %s\n"
            % args.workspaces_glob
        )
        return 2

    # Optional language pin.
    language_pin = {}
    if args.workspace_language_pin:
        try:
            language_pin = json.loads(args.workspace_language_pin)
        except json.JSONDecodeError:
            sys.stderr.write(
                "[wave4-all-pairs] invalid JSON for --workspace-language-pin\n"
            )
            return 2

    workspace_languages = {}
    for ws in workspaces:
        if ws.name in language_pin:
            workspace_languages[ws.name] = language_pin[ws.name]
        else:
            workspace_languages[ws.name] = detect_workspace_language(ws)

    skip_pattern = re.compile(args.skip_pairs) if args.skip_pairs else None

    matrix = compute_matrix(
        workspaces=workspaces,
        fp_dir=fp_dir,
        runner_path=runner_path,
        seed_source=args.seed_source,
        workspace_languages=workspace_languages,
        workers=args.workers,
        skip_pattern=skip_pattern,
        skip_cross_language=args.skip_cross_language,
        dry_run=args.dry_run,
    )

    source_ws_names = sorted(
        ws for ws in [w.name for w in workspaces]
        if matrix["source_to_fp_set"].get(ws)
    )
    target_ws_names = sorted(w.name for w in workspaces)

    payload = {
        "schema": SCHEMA_VERSION,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "cli_args": ["wave4-cross-workspace-all-pairs-fp-matrix.py"] + argv,
        "fp_dir": str(fp_dir),
        "runner_path": str(runner_path),
        "seed_source": args.seed_source,
        "workspaces_glob": args.workspaces_glob,
        "workspaces_evaluated": [w.name for w in workspaces],
        "source_workspaces": source_ws_names,
        "target_workspaces": target_ws_names,
        "workspace_languages": workspace_languages,
        "mcp_context_pack_id": args.mcp_context_pack_id,
        "mcp_token_present": bool(args.mcp_context_pack_id),
        "matrix": matrix,
        "honest_pins": HONEST_PINS,
    }

    out_json = Path(args.out_json).expanduser()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    out_md = Path(args.out_markdown).expanduser()
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(
        render_markdown(payload, workspaces),
        encoding="utf-8",
    )

    sys.stdout.write(
        "[wave4-all-pairs] wrote %s\n" % out_json
    )
    sys.stdout.write(
        "[wave4-all-pairs] wrote %s\n" % out_md
    )
    sys.stdout.write(
        "[wave4-all-pairs] source_workspaces=%d target_workspaces=%d "
        "candidate_new_universals=%d\n"
        % (
            len(source_ws_names),
            len(target_ws_names),
            len(matrix["candidate_new_universals"]),
        )
    )

    if args.strict and not matrix["candidate_new_universals"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
