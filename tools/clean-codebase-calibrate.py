#!/usr/bin/env python3
"""
clean-codebase-calibrate.py — measure auditooor detector precision on clean,
already-audited Solidity codebases (Kimi roadmap #3).

Premise: a codebase that has been thoroughly audited multiple times has
near-zero exploitable bugs left. Any detector hit on such a codebase is
overwhelmingly likely to be a FALSE POSITIVE. By scanning N clean corpora
and aggregating per-detector hit counts, we can rank detectors by their
real-world noise floor and surface the worst offenders for demotion.

This tool DOES NOT auto-demote anything — it only produces measurements
(`tools/clean-corpus-noise.json`) and a list of demotion candidates for
human review.

Subcommands:
  download <name>         Clone a corpus into tools/clean-corpus/<name>/
  download-all            Clone every entry in CORPORA (idempotent).
  run <name>              Scan one corpus, persist tools/clean-corpus/<name>/
                          hits.json + raw scan log.
  run-all                 Scan every downloaded corpus.
  report                  Aggregate hits into tools/clean-corpus-noise.json.
  propose-demotions [thr] Rank detectors by total noise; flag candidates above
                          threshold (default: >=2 hits across corpora).

Stdlib + slither only. No new pip deps.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "tools" / "clean-corpus"
NOISE_JSON = REPO_ROOT / "tools" / "clean-corpus-noise.json"
RUN_CUSTOM = REPO_ROOT / "detectors" / "run_custom.py"

# Curated clean corpora. Each has been audited multiple times by tier-1
# firms. `src_subpath` narrows the scan to the production Solidity tree
# (skips test/, lib/, mocks/). `shallow` keeps the clone fast.
#
# IMPORTANT: directory `name` MUST NOT collide with the VENDORED_MARKERS
# baked into detectors/run_custom.py (which post-filter results whose
# source path contains "solady/src", "solmate/src", "openzeppelin",
# "/lib/", "forge-std", or "/node_modules/"). When scanning a clean copy
# of one of those libraries directly, every absolute path would otherwise
# be classified as vendored and dropped — producing a false 0-hit signal.
# We sidestep that by cloning into neutral on-disk names and scanning a
# staged subdirectory whose joined name does not contain the marker
# substrings. The `display_name` field is what gets persisted into the
# noise report.
CORPORA: dict[str, dict[str, Any]] = {
    "clean-1-vectorized-gas-stdlib": {
        "display_name": "solady",
        "url": "https://github.com/Vectorized/solady.git",
        "src_subpath": "src",
        "stage_subdir": "stage/code",  # avoid 'solady/src' substring
        "shallow": True,
        "note": "Vectorized's gas-optimized stdlib, audited many times.",
    },
    "clean-2-rari-mini-stdlib": {
        "display_name": "solmate",
        "url": "https://github.com/transmissions11/solmate.git",
        "src_subpath": "src",
        "stage_subdir": "stage/code",  # avoid 'solmate/src' substring
        "shallow": True,
        "note": "Rari Capital / transmissions11, audited stdlib.",
    },
    "clean-3-oz-contracts": {
        "display_name": "openzeppelin-contracts",
        "url": "https://github.com/OpenZeppelin/openzeppelin-contracts.git",
        "src_subpath": "contracts",
        "stage_subdir": "stage/code",  # avoid 'openzeppelin' substring in dirname
        "shallow": True,
        "note": "OZ contracts — gold-standard audited library.",
    },
}


# ---------- small helpers ------------------------------------------------

def _log(msg: str) -> None:
    print(f"[clean-calibrate] {msg}", flush=True)


def _corpus_path(name: str) -> Path:
    return CORPUS_DIR / name


def _hits_path(name: str) -> Path:
    return _corpus_path(name) / "hits.json"


def _raw_log_path(name: str) -> Path:
    return _corpus_path(name) / "scan.log"


# Vendored-path substrings hard-coded into detectors/run_custom.py
# VENDORED_MARKERS. Any scan target whose absolute path contains one of
# these has its results dropped by the post-filter. We refuse to scan
# from such a path (the calibrate tool stages a neutral subdir instead).
_VENDORED_PATH_FRAGMENTS = (
    "/lib/", "forge-std", "solady/src", "solmate/src",
    "openzeppelin", "/node_modules/",
)


def _path_collides_with_vendored_filter(path: Path) -> bool:
    """True iff this absolute path would be dropped by run_custom.py's
    VENDORED_MARKERS post-filter. See run_custom.py:529."""
    s = str(path)
    return any(frag in s for frag in _VENDORED_PATH_FRAGMENTS)


def _ensure_corpus_dir() -> None:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)


# ---------- download -----------------------------------------------------

def cmd_download(name: str) -> int:
    """Clone CORPORA[name] into tools/clean-corpus/<name>. Idempotent."""
    if name not in CORPORA:
        _log(f"unknown corpus {name!r}; known: {sorted(CORPORA)}")
        return 2

    spec = CORPORA[name]
    dest = _corpus_path(name)
    _ensure_corpus_dir()

    if dest.exists() and (dest / ".git").exists():
        _log(f"{name}: already cloned at {dest} (skip)")
        return 0
    if dest.exists():
        # partial / failed clone — remove
        shutil.rmtree(dest)

    cmd = ["git", "clone"]
    if spec.get("shallow", True):
        cmd += ["--depth", "1"]
    cmd += [spec["url"], str(dest)]

    _log(f"{name}: cloning {spec['url']} ...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        _log(f"{name}: clone timed out after 300s — skipping")
        return 1
    except Exception as e:  # noqa: BLE001
        _log(f"{name}: clone errored: {e!r} — skipping")
        return 1

    if proc.returncode != 0:
        _log(f"{name}: clone failed rc={proc.returncode}: {proc.stderr[:300]}")
        return 1
    _log(f"{name}: cloned into {dest}")
    return 0


def cmd_download_all() -> int:
    rc = 0
    for name in CORPORA:
        rc |= cmd_download(name)
    return 0 if rc == 0 else 1  # we tolerate partial network failures


# ---------- run ----------------------------------------------------------

# A scan-log line that records a detector hit looks like (run_custom.py:563):
#   "  [HIGH] <description>"
# which is preceded by "=== Running <argument> ===" announcing the detector.
HIT_LINE_RE = re.compile(r"^\s+\[(?:HIGH|MEDIUM|LOW|INFORMATIONAL|OPTIMIZATION)\]")
RUN_LINE_RE = re.compile(r"^=== Running\s+([a-zA-Z0-9_\-]+)\s+===")
TOTAL_RE = re.compile(r"^\[done\]\s+total hits:\s+(\d+)")


def parse_scan_output(text: str) -> dict[str, Any]:
    """Parse run_custom.py stdout/stderr into per-detector hit counts.

    Returns: {
        "per_detector": {arg: int_hits, ...},
        "total_hits":   int,
        "detectors_executed": int,
        "compile_failed": bool,
    }
    """
    per_det: dict[str, int] = {}
    current: str | None = None
    total = 0
    executed = 0
    compile_failed = False

    for raw in text.splitlines():
        m = RUN_LINE_RE.match(raw)
        if m:
            current = m.group(1)
            per_det.setdefault(current, 0)
            executed += 1
            continue
        if current and HIT_LINE_RE.match(raw):
            per_det[current] = per_det.get(current, 0) + 1
            continue
        m = TOTAL_RE.match(raw)
        if m:
            total = int(m.group(1))
        if "Error compiling target" in raw or "Slither compile failed" in raw:
            compile_failed = True

    return {
        "per_detector": per_det,
        "total_hits": total if total else sum(per_det.values()),
        "detectors_executed": executed,
        "compile_failed": compile_failed,
    }


def cmd_run(name: str, tier_filter: str | None = None,
            timeout_s: int = 1800) -> int:
    """Invoke run_custom.py against the cloned corpus, persist hits.json."""
    if name not in CORPORA:
        _log(f"unknown corpus {name!r}")
        return 2

    spec = CORPORA[name]
    root = _corpus_path(name)
    if not root.exists():
        _log(f"{name}: not cloned yet — run `download {name}` first")
        return 1

    # Narrow to the production source tree if specified.
    sub = spec.get("src_subpath")
    raw_target = root / sub if sub else root
    if not raw_target.exists():
        _log(f"{name}: subpath {sub!r} missing; falling back to repo root")
        raw_target = root

    # If the natural scan path would trip run_custom.py's VENDORED_MARKERS
    # post-filter (e.g. "solady/src" substring), stage the .sol files into
    # a neutral subdirectory whose absolute path is marker-free. This lets
    # us measure detector noise on the actual code without having to patch
    # run_custom.py's filter list.
    target = raw_target
    if _path_collides_with_vendored_filter(raw_target.resolve()):
        stage_subdir = spec.get("stage_subdir", "stage/code")
        staged = root / stage_subdir
        if _path_collides_with_vendored_filter(staged.resolve()):
            _log(f"{name}: stage path {staged} ALSO collides with vendored "
                 f"filter — please pick a different stage_subdir")
            return 1
        if not staged.exists():
            staged.mkdir(parents=True, exist_ok=True)
            # Copy *.sol files preserving relative structure. Hardlink-first
            # falls back to copy. Tiny corpora (<400 files) so cost is OK.
            copied = 0
            for sol in raw_target.rglob("*.sol"):
                rel = sol.relative_to(raw_target)
                dst = staged / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.link(sol, dst)
                except OSError:
                    shutil.copy2(sol, dst)
                copied += 1
            _log(f"{name}: staged {copied} .sol files into {staged.relative_to(REPO_ROOT)}")
        target = staged

    # Pick the python that has slither installed. Prefer python3.13 if
    # present (matches CI), else the bare python3.
    py = shutil.which("python3.13") or shutil.which("python3") or sys.executable

    cmd = [py, str(RUN_CUSTOM), str(target)]
    if tier_filter:
        cmd.append(f"--tier={tier_filter}")

    _log(f"{name}: scanning {target} (python={py})")
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
            cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        _log(f"{name}: scan TIMED OUT after {timeout_s}s — skipping")
        _hits_path(name).write_text(json.dumps({
            "name": name, "skipped": True, "reason": "timeout",
            "timeout_s": timeout_s,
        }, indent=2))
        return 1
    except Exception as e:  # noqa: BLE001
        _log(f"{name}: scan errored: {e!r}")
        return 1
    elapsed = time.time() - t0

    output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
    _raw_log_path(name).write_text(output)

    parsed = parse_scan_output(output)

    # Count source files as a rough size signal.
    sol_files = sum(1 for _ in target.rglob("*.sol"))

    record = {
        "name": spec.get("display_name", name),
        "corpus_id": name,
        "url": spec["url"],
        "scanned_path": str(target.relative_to(REPO_ROOT)),
        "sol_files": sol_files,
        "elapsed_s": round(elapsed, 1),
        "rc": proc.returncode,
        "tier_filter": tier_filter or "S,E (default)",
        "compile_failed": parsed["compile_failed"],
        "detectors_executed": parsed["detectors_executed"],
        "total_hits": parsed["total_hits"],
        "per_detector": parsed["per_detector"],
    }
    _hits_path(name).write_text(json.dumps(record, indent=2, sort_keys=True))
    _log(
        f"{name}: rc={proc.returncode} elapsed={elapsed:.0f}s "
        f"detectors={parsed['detectors_executed']} hits={parsed['total_hits']} "
        f"compile_failed={parsed['compile_failed']}"
    )
    if parsed["compile_failed"]:
        _log(f"{name}: compile failed — Slither couldn't load the corpus, hits=0")
    return 0


def cmd_run_all(tier_filter: str | None = None) -> int:
    rc = 0
    for name in CORPORA:
        if not _corpus_path(name).exists():
            _log(f"{name}: not downloaded — skipping")
            continue
        rc |= cmd_run(name, tier_filter=tier_filter)
    return 0 if rc == 0 else 1


# ---------- report -------------------------------------------------------

def aggregate_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Pure aggregation — covered by unit tests.

    Inputs: list of per-corpus hits.json dicts.
    Output: structured noise report.
    """
    per_detector: dict[str, dict[str, Any]] = {}
    total_corpora = 0
    successful_corpora = 0
    skipped: list[str] = []

    for rec in records:
        total_corpora += 1
        if rec.get("skipped") or rec.get("compile_failed"):
            skipped.append(rec.get("name", "?"))
            continue
        successful_corpora += 1
        for det, hits in (rec.get("per_detector") or {}).items():
            slot = per_detector.setdefault(det, {
                "total_hits": 0,
                "corpora_with_hits": 0,
                "by_corpus": {},
            })
            slot["by_corpus"][rec["name"]] = hits
            if hits > 0:
                slot["total_hits"] += hits
                slot["corpora_with_hits"] += 1

    # noise score: total hits across corpora * (1 + corpora_with_hits-1) penalty
    # (a detector hitting on multiple clean codebases is much worse than one
    # detector dumping 50 hits on one weird corpus).
    for det, slot in per_detector.items():
        slot["noise_score"] = slot["total_hits"] * (1 + (slot["corpora_with_hits"] - 1) * 0.5
                                                     if slot["corpora_with_hits"] else 0)

    # Stable inner ordering of by_corpus for clean diffs across runs.
    for slot in per_detector.values():
        slot["by_corpus"] = dict(sorted(slot["by_corpus"].items()))

    ranked = sorted(
        per_detector.items(),
        key=lambda kv: (-kv[1]["noise_score"], -kv[1]["total_hits"], kv[0]),
    )

    return {
        "schema_version": 1,
        "total_corpora": total_corpora,
        "successful_corpora": successful_corpora,
        "skipped_corpora": sorted(skipped),
        "detectors_with_any_hit": sum(1 for d in per_detector.values() if d["total_hits"] > 0),
        "per_detector": dict(ranked),
    }


def cmd_report() -> int:
    if not CORPUS_DIR.exists():
        _log("no clean-corpus/ directory — run `download-all` first")
        return 1
    records: list[dict[str, Any]] = []
    for name in sorted(CORPORA):
        hp = _hits_path(name)
        if not hp.exists():
            _log(f"{name}: no hits.json (not yet scanned) — skipping")
            continue
        try:
            records.append(json.loads(hp.read_text()))
        except Exception as e:  # noqa: BLE001
            _log(f"{name}: failed to parse hits.json: {e!r} — skipping")
            continue

    if not records:
        _log("no scanned corpora found — run `run-all` first")
        return 1

    report = aggregate_records(records)
    report["generated_by"] = "tools/clean-codebase-calibrate.py report"
    report["corpora"] = sorted(spec.get("display_name", k)
                                for k, spec in CORPORA.items())
    # IMPORTANT: do NOT sort_keys at the top level — `per_detector` is
    # already ordered by noise score (highest first) and alphabetizing it
    # would erase the ranking. We DO sort the inner per-corpus dicts so
    # diffs across runs stay stable.
    NOISE_JSON.write_text(json.dumps(report, indent=2))
    _log(
        f"wrote {NOISE_JSON.relative_to(REPO_ROOT)}: "
        f"{report['successful_corpora']}/{report['total_corpora']} corpora, "
        f"{report['detectors_with_any_hit']} detectors with hits"
    )

    # Print top-10 noisiest for quick eyeballing.
    print("\nTop 10 noisiest detectors (across clean corpora):")
    print(f"  {'detector':<55} {'total':>5} {'corpora':>7}  per-corpus")
    for i, (det, slot) in enumerate(report["per_detector"].items()):
        if i >= 10 or slot["total_hits"] == 0:
            break
        per = ", ".join(f"{c}={n}" for c, n in slot["by_corpus"].items() if n > 0)
        print(f"  {det:<55} {slot['total_hits']:>5} {slot['corpora_with_hits']:>7}  {per}")
    return 0


# ---------- propose-demotions -------------------------------------------

def propose_demotions(report: dict[str, Any], min_total_hits: int = 2,
                      min_corpora_with_hits: int = 1) -> list[dict[str, Any]]:
    """Pure: returns demotion candidates, no file writes. Covered by tests."""
    out: list[dict[str, Any]] = []
    for det, slot in (report.get("per_detector") or {}).items():
        if (slot["total_hits"] >= min_total_hits
                and slot["corpora_with_hits"] >= min_corpora_with_hits):
            out.append({
                "detector": det,
                "total_hits": slot["total_hits"],
                "corpora_with_hits": slot["corpora_with_hits"],
                "noise_score": slot.get("noise_score", slot["total_hits"]),
                "by_corpus": dict(slot["by_corpus"]),
            })
    out.sort(key=lambda r: (-r["noise_score"], -r["total_hits"], r["detector"]))
    return out


def cmd_propose_demotions(min_total_hits: int = 2,
                          min_corpora_with_hits: int = 1) -> int:
    if not NOISE_JSON.exists():
        _log("no clean-corpus-noise.json — run `report` first")
        return 1
    report = json.loads(NOISE_JSON.read_text())
    candidates = propose_demotions(report, min_total_hits=min_total_hits,
                                   min_corpora_with_hits=min_corpora_with_hits)
    if not candidates:
        _log(f"no candidates at thresholds total>={min_total_hits}, "
             f"corpora>={min_corpora_with_hits}")
        return 0
    print(f"# Demotion candidates (total>={min_total_hits}, "
          f"corpora>={min_corpora_with_hits}) — NOT auto-demoted")
    print(f"# count: {len(candidates)}")
    print()
    for c in candidates:
        per = ", ".join(f"{k}={v}" for k, v in c["by_corpus"].items() if v > 0)
        print(f"  {c['detector']:<55} total={c['total_hits']:<4} "
              f"corpora={c['corpora_with_hits']:<2} score={c['noise_score']:<5}  [{per}]")
    return 0


# ---------- argv glue ----------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("download", help="clone one corpus")
    sp.add_argument("name")

    sub.add_parser("download-all", help="clone every corpus (idempotent)")

    sp = sub.add_parser("run", help="scan one corpus")
    sp.add_argument("name")
    sp.add_argument("--tier", default=None,
                    help="comma-separated tier filter (default: S,E)")
    sp.add_argument("--timeout", type=int, default=1800,
                    help="scan timeout seconds (default 1800)")

    sp = sub.add_parser("run-all", help="scan every downloaded corpus")
    sp.add_argument("--tier", default=None)

    sub.add_parser("report", help="aggregate into clean-corpus-noise.json")

    sp = sub.add_parser("propose-demotions",
                        help="rank candidates above noise threshold")
    sp.add_argument("--min-total", type=int, default=2)
    sp.add_argument("--min-corpora", type=int, default=1)

    sub.add_parser("list", help="list known corpora")

    args = p.parse_args(argv)
    if args.cmd == "download":
        return cmd_download(args.name)
    if args.cmd == "download-all":
        return cmd_download_all()
    if args.cmd == "run":
        return cmd_run(args.name, tier_filter=args.tier, timeout_s=args.timeout)
    if args.cmd == "run-all":
        return cmd_run_all(tier_filter=args.tier)
    if args.cmd == "report":
        return cmd_report()
    if args.cmd == "propose-demotions":
        return cmd_propose_demotions(min_total_hits=args.min_total,
                                     min_corpora_with_hits=args.min_corpora)
    if args.cmd == "list":
        for k, v in CORPORA.items():
            print(f"  {k:<25} {v['url']}")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
