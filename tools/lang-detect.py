#!/usr/bin/env python3
"""
lang-detect.py — generic tree-sitter detector orchestrator for non-Rust
languages (R74-C follow-on to rust-detect.py).

Walks source files under a workspace root, instantiates AstEngine(lang, ...)
per file, runs every detector module under detectors/<lang>_wave1/, and
writes aggregated hits to <workspace>/audit/<lang>-detect.log.

Detector contract:
    def run(engine, filepath) -> list[dict]

Unlike rust-detect.py (which preserves a back-compat (tree, source, path)
signature), NEW language wave dirs are engine-first: they only ever see
the AstEngine surface.

Usage:
    python3 tools/lang-detect.py --lang go <workspace>
    python3 tools/lang-detect.py --lang python --file foo.py
    python3 tools/lang-detect.py --lang go --only proof_of_life --file x.go
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_AST_ENGINE_PATH = _HERE / "ast-engine.py"


def _import_ast_engine():
    spec = importlib.util.spec_from_file_location(
        "ast_engine", _AST_ENGINE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LANG_EXT = {
    "rust":       (".rs",),
    "go":         (".go",),
    "python":     (".py",),
    "javascript": (".js", ".mjs", ".cjs"),
    "move":       (".move",),
    "cairo":      (".cairo",),
}


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


def _discover(root: Path, lang: str, single: Path | None):
    if single:
        return [single.resolve()]
    exts = LANG_EXT[lang]
    out = []
    for ext in exts:
        for p in root.rglob(f"*{ext}"):
            rp = p.resolve()
            parts = set(rp.parts)
            if parts & {"target", "node_modules", "venv", "__pycache__",
                        ".git", "dist", "build"}:
                continue
            out.append(rp)
    return sorted(set(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace", type=Path, nargs="?", default=Path("."),
                    help="Workspace root (default: cwd).")
    ap.add_argument("--lang", required=True,
                    choices=list(LANG_EXT.keys()))
    ap.add_argument("--only", help="Run only this detector (module stem).")
    ap.add_argument("--file", dest="single_file", type=Path)
    ap.add_argument("--log", type=Path, default=None)
    args = ap.parse_args()

    workspace = args.workspace.resolve()
    ast_engine = _import_ast_engine()

    here = Path(__file__).resolve().parent.parent
    detectors_dir = here / "detectors" / f"{args.lang}_wave1"
    detectors = _load_detectors(detectors_dir, args.only)
    if not detectors:
        print(f"[err] no detectors under {detectors_dir}", file=sys.stderr)
        sys.exit(1)

    files = _discover(workspace, args.lang, args.single_file)
    if not files:
        print(f"[err] no {args.lang} files found under {workspace}",
              file=sys.stderr)
        sys.exit(1)

    log_path = args.log or (workspace / "audit" / f"{args.lang}-detect.log")
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
            engine = ast_engine.AstEngine(args.lang, source)
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
        f.write(f"# {args.lang}-detect.log\n")
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
