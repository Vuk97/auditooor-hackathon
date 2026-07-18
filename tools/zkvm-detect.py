#!/usr/bin/env python3
"""zkvm-detect.py - run zkvm_wave1 generic proof-system detectors over a Rust workspace.

The existing regex-detector runners (detectors/run_regex_detectors.py,
tools/regex-detectors-orchestrator.py) are hard-locked to Solidity (.sol), and
tools/rust-detect.py only loads detectors/rust_wave1 (Anchor/Solana/cosmos shapes).
Neither runs the zk-VM-native detectors against a bespoke proof system's Rust source.
This runner closes that gap: it loads detectors/zkvm_wave1/*.py (run_text API) and
scans the workspace's .rs files, so a bespoke zkVM (e.g. leanEthereum/leanVM) that
matches no framework-specific detector still gets proof-system-native coverage.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
SCHEMA = "auditooor.zkvm_detect.v1"

_EXCLUDE_DIRS = {
    "target", "tests", "benches", "bench", ".git", "node_modules", "vendor",
    ".cargo", "proptest-regressions", "fuzz", "poc-tests", "poc_execution",
}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_detectors(family: str) -> list:
    fam_dir = REPO / "detectors" / family
    out = []
    if not fam_dir.is_dir():
        return out
    for py in sorted(fam_dir.glob("*.py")):
        if py.name.startswith("_") or py.name == "__init__.py":
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"{family}.{py.stem}", py)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"[zkvm-detect] WARN failed to load {py.name}: {e}", file=sys.stderr)
            continue
        if callable(getattr(mod, "run_text", None)):
            out.append((getattr(mod, "DETECTOR_ID", py.stem), mod))
    return out


def discover_rs_files(workspace: Path, single):
    if single:
        return [single.resolve()]
    files = []
    for p in workspace.rglob("*.rs"):
        if set(p.parts) & _EXCLUDE_DIRS:
            continue
        if p.name.endswith("test.rs") or p.name == "tests.rs":
            continue
        files.append(p.resolve())
    return sorted(set(files))


def main() -> int:
    ap = argparse.ArgumentParser(description="zkVM-native detector runner (Rust)")
    ap.add_argument("--workspace", type=Path, help="Workspace root")
    ap.add_argument("--file", dest="single", type=Path, help="Single .rs file (tests)")
    ap.add_argument("--family", default="zkvm_wave1", help="Detector family dir under detectors/")
    ap.add_argument("--scan-root", type=Path, default=None, help="Override scan root (default <ws>/src)")
    ap.add_argument("--json", action="store_true", help="Print manifest JSON to stdout")
    args = ap.parse_args()

    if not args.workspace and not args.single:
        ap.error("one of --workspace or --file is required")

    detectors = load_detectors(args.family)
    if not detectors:
        print(f"[zkvm-detect] ERR no detectors loaded from detectors/{args.family}", file=sys.stderr)
        return 2

    if args.single:
        workspace = args.single.resolve().parent
        files = [args.single.resolve()]
    else:
        workspace = args.workspace.resolve()
        scan_root = args.scan_root.resolve() if args.scan_root else (
            workspace / "src" if (workspace / "src").is_dir() else workspace)
        files = discover_rs_files(scan_root, None)

    findings = []
    per_detector = {name: 0 for name, _ in detectors}
    read_errors = 0
    for rs in files:
        try:
            source = rs.read_text(encoding="utf-8", errors="replace")
        except Exception:
            read_errors += 1
            continue
        for name, mod in detectors:
            try:
                hits = mod.run_text(source, str(rs)) or []
            except Exception as e:
                print(f"[zkvm-detect] WARN detector {name} crashed on {rs}: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                continue
            for h in hits:
                h.setdefault("detector_id", name)
                h["file"] = str(rs)
                findings.append(h)
                per_detector[name] = per_detector.get(name, 0) + 1

    manifest = {
        "schema": SCHEMA,
        "generated_at": _ts(),
        "workspace": str(workspace),
        "family": args.family,
        "detectors_loaded": len(detectors),
        "files_scanned": len(files),
        "read_errors": read_errors,
        "findings_count": len(findings),
        "per_detector_counts": per_detector,
        "findings": findings,
    }

    if not args.single:
        out_dir = workspace / ".auditooor"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "zkvm_detect_manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        log = out_dir / "zkvm_detect.log"
        with log.open("w", encoding="utf-8") as f:
            f.write("# zkvm-detect.log\n")
            f.write(f"# workspace: {workspace}\n")
            f.write(f"# detectors: {len(detectors)}\n")
            f.write(f"# files scanned: {len(files)}\n")
            f.write(f"# total hits: {len(findings)}\n\n")
            for name, _ in detectors:
                bucket = [x for x in findings if x.get("detector_id") == name]
                f.write(f"=== {name}  ({len(bucket)} hits) ===\n")
                for h in bucket:
                    f.write(f"  [{h.get('severity','info')}] {h.get('file')}:{h.get('line',0)}  {h.get('message','')}\n")
                    f.write(f"      > {h.get('snippet','')}\n")
                f.write("\n")
        print(f"[zkvm-detect] {len(detectors)} detectors x {len(files)} files -> "
              f"{len(findings)} hits   log: {log}")

    if args.json or args.single:
        print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
