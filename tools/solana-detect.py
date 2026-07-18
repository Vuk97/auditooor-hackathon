#!/usr/bin/env python3
"""
solana-detect.py — engine-first detector orchestrator for the Solana / SVM
detector batch (`detectors/solana_wave1/`).

Solana programs are Rust source, but the solana_wave1 detectors are a
distinct, attack-class-curated batch (missing signer/owner check, account
type cosplay, CPI program-id spoofing, PDA bump canonicalization, etc.).
lang-detect.py derives its detector dir as `detectors/<lang>_wave1`, which
for `--lang rust` resolves to the unrelated `rust_wave1` batch. This thin
orchestrator reuses the same AstEngine("rust", ...) parse loop and the same
detector contract but points it at `detectors/solana_wave1/`.

Detector contract (identical to go_wave1 / lang-detect.py):
    def run(engine, filepath) -> list[dict]

Usage:
    python3 tools/solana-detect.py <workspace>
    python3 tools/solana-detect.py --file program.rs
    python3 tools/solana-detect.py --only solana_missing_signer_check --file x.rs
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_AST_ENGINE_PATH = _HERE / "ast-engine.py"

_SKIP_PARTS = {"target", "node_modules", "venv", "__pycache__",
               ".git", "dist", "build"}


def _import_ast_engine():
    spec = importlib.util.spec_from_file_location(
        "ast_engine", _AST_ENGINE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_detectors(detectors_dir: Path, only: str | None):
    dpath = str(detectors_dir)
    if dpath not in sys.path:
        sys.path.insert(0, dpath)
    detectors = []
    for py in sorted(detectors_dir.glob("*.py")):
        if py.name.startswith("_"):
            continue
        if only and py.stem != only:
            continue
        spec = importlib.util.spec_from_file_location(py.stem, py)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"[warn] skipping detector {py.name}: {e}", file=sys.stderr)
            continue
        if not hasattr(mod, "run"):
            continue
        detectors.append((py.stem, mod))
    return detectors


def _discover(root: Path, single: Path | None):
    if single:
        return [single.resolve()]
    out = []
    for p in root.rglob("*.rs"):
        rp = p.resolve()
        if set(rp.parts) & _SKIP_PARTS:
            continue
        out.append(rp)
    return sorted(set(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace", type=Path, nargs="?", default=Path("."),
                    help="Workspace root (default: cwd).")
    ap.add_argument("--only", help="Run only this detector (module stem).")
    ap.add_argument("--file", dest="single_file", type=Path)
    ap.add_argument("--log", type=Path, default=None)
    args = ap.parse_args()

    workspace = args.workspace.resolve()
    ast_engine = _import_ast_engine()

    repo_root = _HERE.parent
    detectors_dir = repo_root / "detectors" / "solana_wave1"
    detectors = _load_detectors(detectors_dir, args.only)
    if not detectors:
        print(f"[err] no detectors under {detectors_dir}", file=sys.stderr)
        sys.exit(1)

    files = _discover(workspace, args.single_file)
    if not files:
        print(f"[err] no rust files found under {workspace}", file=sys.stderr)
        sys.exit(1)

    log_path = args.log or (workspace / "audit" / "solana-detect.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    hits_by_detector = {name: [] for name, _ in detectors}
    total = 0
    parse_errors = 0

    for path in files:
        try:
            source = path.read_bytes()
        except Exception as e:
            print(f"[warn] could not read {path}: {e}", file=sys.stderr)
            continue
        try:
            engine = ast_engine.AstEngine("rust", source)
            engine.parse()
        except Exception as e:
            parse_errors += 1
            print(f"[warn] parse error {path}: {e}", file=sys.stderr)
            continue
        for name, mod in detectors:
            try:
                hits = mod.run(engine, str(path)) or []
            except Exception as e:
                print(f"[warn] detector {name} crashed on {path}: {e}",
                      file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                continue
            for h in hits:
                hits_by_detector[name].append((path, h))
                total += 1

    with log_path.open("w") as f:
        f.write("# solana-detect.log\n")
        f.write(f"# workspace: {workspace}\n")
        f.write(f"# files: {len(files)} parse_errors: {parse_errors} "
                f"total_hits: {total}\n\n")
        for name, _ in detectors:
            bucket = hits_by_detector[name]
            f.write(f"=== {name}  ({len(bucket)} hits) ===\n")
            for p, h in bucket:
                f.write(f"  [{h.get('severity','info')}] {p}:{h.get('line',0)}"
                        f":{h.get('col',0)}  {h.get('message','')}\n")
                f.write(f"      > {h.get('snippet','')}\n")
            f.write("\n")

    print("=== per-detector hit counts ===")
    for name, _ in detectors:
        n = len(hits_by_detector[name])
        flag = "  NOISY" if n > 20 else ""
        print(f"  {n:4d}  {name}{flag}")
    print(f"\n[done] total hits: {total}   log: {log_path}")


if __name__ == "__main__":
    main()
