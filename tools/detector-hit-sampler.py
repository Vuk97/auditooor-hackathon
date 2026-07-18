#!/usr/bin/env python3
"""
detector-hit-sampler.py — empirically sample detector hit-rates across a real corpus.

Phase 21 (PR #84). We ship 1258 wave17 + 376 rust_wave1 detectors but have no
systematic read on which ones actually FIRE on real-world code vs just
author-curated fixtures. This tool fills that gap: point it at a corpus of
.rs/.sol files, run the detector trees in subprocess per-file, aggregate hit
counts, and emit a markdown report highlighting never-fired (dead) and
too-broad (>50 hits → likely FP) detectors.

Usage:
    python3 tools/detector-hit-sampler.py --corpus-dir /path/to/corpus
    make sample CORPUS=/path/to/corpus

The tool is graceful on missing/empty corpora: it prints example usage and
exits 0, so CI never breaks when run without a corpus.
"""
from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
RUST_DETECTORS_DIR = REPO / "detectors" / "rust_wave1"
SOL_DETECTORS_DIR = REPO / "detectors" / "wave17"
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
DOCS_OUT = REPO / "docs" / "DETECTOR_HIT_SAMPLER.md"

PER_FILE_TIMEOUT = 30  # seconds
TOO_BROAD_THRESHOLD = 50

# Cheap heuristic: pull contract/module names without full parsing.
RUST_MOD_RE = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
SOL_CONTRACT_RE = re.compile(
    r"^\s*(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.M,
)


def load_tier_map() -> dict[str, str]:
    """Parse _tier_registry.yaml for detector-name -> tier mapping.

    Simple line-oriented parse to avoid a PyYAML dep.
    """
    out: dict[str, str] = {}
    if not TIER_REGISTRY.exists():
        return out
    current: str | None = None
    for line in TIER_REGISTRY.read_text().splitlines():
        # 2-space indent top-level tier key
        m = re.match(r"^  ([A-Za-z0-9_\-]+):\s*$", line)
        if m:
            current = m.group(1)
            continue
        m = re.match(r"^    tier:\s*([A-Z])\s*$", line)
        if m and current:
            out[current] = m.group(1)
    return out


def contract_name(path: Path, source: str) -> str:
    if path.suffix == ".sol":
        m = SOL_CONTRACT_RE.search(source)
        if m:
            return m.group(1)
    elif path.suffix == ".rs":
        m = RUST_MOD_RE.search(source)
        if m:
            return m.group(1)
    return path.stem


def discover_files(corpus: Path) -> tuple[list[Path], list[Path]]:
    rs = sorted(p for p in corpus.rglob("*.rs")
                if "target" not in p.parts and "tests" not in p.parts)
    sol = sorted(corpus.rglob("*.sol"))
    return rs, sol


# ---- per-file runners ------------------------------------------------------

HIT_LINE = re.compile(r"^\[(?P<det>[a-z0-9_\-]+)\]", re.I)


def _parse_hits_from_stdout(stdout: str) -> list[str]:
    """Best-effort: one hit per line whose first token looks like [detector]."""
    hits: list[str] = []
    for line in stdout.splitlines():
        m = HIT_LINE.match(line.strip())
        if m:
            hits.append(m.group("det"))
    return hits


def run_rust_file(rs_path: Path) -> list[str]:
    """Run rust-detect.py --file on a single .rs; return list of detector names that fired."""
    # rust-detect wants a workspace, but --file overrides discovery and writes
    # a log. We create a tmp workspace so it can write its log there.
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [
            sys.executable, str(HERE / "rust-detect.py"), tmp,
            "--file", str(rs_path),
            "--log", str(Path(tmp) / "hit.log"),
        ]
        try:
            res = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=PER_FILE_TIMEOUT, cwd=str(REPO),
            )
        except subprocess.TimeoutExpired:
            print(f"[timeout] rust detectors on {rs_path}", file=sys.stderr)
            return []
        log = Path(tmp) / "hit.log"
        if not log.exists():
            return _parse_hits_from_stdout(res.stdout)
        hits: list[str] = []
        for line in log.read_text().splitlines():
            # rust-detect log format: "[<detector>] ..." or "## <detector> — N hit(s)"
            m = re.match(r"^##\s+([a-z0-9_\-]+)\s+—\s+(\d+)\s+hit", line)
            if m:
                hits.extend([m.group(1)] * int(m.group(2)))
                continue
            m = HIT_LINE.match(line.strip())
            if m:
                hits.append(m.group("det"))
        return hits


def run_sol_file(sol_path: Path) -> list[str]:
    """Run the solidity scanner on a single .sol file.

    We invoke detectors/run_custom.py against the file's parent dir; this
    is best-effort — if the file needs solc context we don't have, we log
    and return []. For full-tree scans users should invoke
    scan-all-modules-multisolc.sh directly.
    """
    run_custom = REPO / "detectors" / "run_custom.py"
    if not run_custom.exists():
        return []
    cmd = [sys.executable, str(run_custom), str(sol_path.parent)]
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=PER_FILE_TIMEOUT, cwd=str(REPO),
        )
    except subprocess.TimeoutExpired:
        print(f"[timeout] sol detectors on {sol_path}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[warn] sol run failed on {sol_path}: {e}", file=sys.stderr)
        return []
    return _parse_hits_from_stdout(res.stdout + "\n" + res.stderr)


# ---- report ----------------------------------------------------------------

def known_detectors() -> set[str]:
    names: set[str] = set()
    for d in (RUST_DETECTORS_DIR, SOL_DETECTORS_DIR):
        if not d.exists():
            continue
        for py in d.glob("*.py"):
            if py.name.startswith("_"):
                continue
            # normalize underscores -> dashes to match run_custom output style
            names.add(py.stem)
            names.add(py.stem.replace("_", "-"))
    return names


def write_report(hits: collections.Counter, sample_contracts: dict[str, str],
                 tiers: dict[str, str], n_files: int, elapsed: float,
                 corpus: Path) -> None:
    all_known = known_detectors()
    fired = {d for d in hits if hits[d] > 0}
    never_fired = sorted(all_known - fired)
    too_broad = sorted([d for d, n in hits.items() if n > TOO_BROAD_THRESHOLD],
                       key=lambda d: -hits[d])

    lines: list[str] = []
    lines.append("# Detector Hit Sampler Report")
    lines.append("")
    lines.append(f"- Corpus: `{corpus}`")
    lines.append(f"- Files scanned: {n_files}")
    lines.append(f"- Elapsed: {elapsed:.1f}s")
    lines.append(f"- Unique detectors that fired: {len(fired)}")
    lines.append(f"- Never-fired detectors: {len(never_fired)}")
    lines.append(f"- Too-broad (>{TOO_BROAD_THRESHOLD} hits): {len(too_broad)}")
    lines.append("")
    lines.append("## Hits per detector")
    lines.append("")
    lines.append("| detector | tier | hits | most-common-contract |")
    lines.append("|---|---|---|---|")
    for det, n in hits.most_common():
        tier = tiers.get(det) or tiers.get(det.replace("-", "_")) or "?"
        sample = sample_contracts.get(det, "-")
        lines.append(f"| `{det}` | {tier} | {n} | `{sample}` |")
    lines.append("")
    lines.append("## Never-fired detectors")
    lines.append("")
    lines.append("Candidates for demotion / fixture review:")
    lines.append("")
    for d in never_fired:
        lines.append(f"- `{d}`")
    lines.append("")
    lines.append(f"## Too-broad detectors (>{TOO_BROAD_THRESHOLD} hits)")
    lines.append("")
    lines.append("Likely false-positive-prone — inspect before trusting:")
    lines.append("")
    for d in too_broad:
        lines.append(f"- `{d}` — {hits[d]} hits")
    lines.append("")

    DOCS_OUT.parent.mkdir(parents=True, exist_ok=True)
    DOCS_OUT.write_text("\n".join(lines))
    print(f"[ok] wrote {DOCS_OUT}")


def example_usage_and_exit() -> None:
    print(
        "detector-hit-sampler.py — empirically sample detector hit-rates.\n"
        "\n"
        "No corpus supplied (or corpus empty). Example usage:\n"
        "  make sample CORPUS=~/audits/polymarket\n"
        "  python3 tools/detector-hit-sampler.py --corpus-dir ~/audits/polymarket\n"
        "\n"
        "The corpus dir should contain .rs and/or .sol files (scanned recursively).\n"
        "See docs/archive/HIT_SAMPLER.md for interpretation notes.\n"
    )
    sys.exit(0)


def main() -> int:
    ap = argparse.ArgumentParser(description="Detector hit sampler")
    ap.add_argument("--corpus-dir", type=Path, required=False, default=None,
                    help="Directory of .rs / .sol files to scan")
    ap.add_argument("--max-files", type=int, default=0,
                    help="Cap files scanned (0 = no cap)")
    args = ap.parse_args()

    if args.corpus_dir is None or not args.corpus_dir.exists():
        example_usage_and_exit()
    corpus = args.corpus_dir.resolve()
    rs_files, sol_files = discover_files(corpus)
    if not rs_files and not sol_files:
        example_usage_and_exit()
    all_files = rs_files + sol_files
    if args.max_files and args.max_files > 0:
        all_files = all_files[:args.max_files]

    tiers = load_tier_map()
    hits: collections.Counter = collections.Counter()
    sample_contracts: dict[str, str] = {}

    t0 = time.time()
    for i, f in enumerate(all_files, 1):
        print(f"[{i}/{len(all_files)}] {f}", file=sys.stderr)
        try:
            src = f.read_text(errors="replace")
        except Exception as e:
            print(f"[warn] could not read {f}: {e}", file=sys.stderr)
            continue
        cname = contract_name(f, src)
        try:
            if f.suffix == ".rs":
                fired = run_rust_file(f)
            else:
                fired = run_sol_file(f)
        except Exception as e:
            print(f"[warn] scan crashed on {f}: {e}", file=sys.stderr)
            continue
        for det in fired:
            hits[det] += 1
            sample_contracts.setdefault(det, cname)

    write_report(hits, sample_contracts, tiers,
                 n_files=len(all_files), elapsed=time.time() - t0,
                 corpus=corpus)
    return 0


if __name__ == "__main__":
    sys.exit(main())
