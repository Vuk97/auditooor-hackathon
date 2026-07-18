#!/usr/bin/env python3
"""Build production-path dossiers for typed candidates."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LIB_PATH = ROOT / "tools" / "lib" / "production_path_dossier.py"


def _load_lib() -> Any:
    spec = importlib.util.spec_from_file_location("production_path_dossier", LIB_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {LIB_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    data["_path"] = str(path)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("candidates", nargs="+", type=Path)
    args = parser.parse_args()

    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[production-path-dossier] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    lib = _load_lib()
    graph = lib.load_graph(ws)
    dossiers = []
    for path in args.candidates:
        try:
            candidate = _read_json(path)
            dossier = lib.build_dossier(candidate, workspace=ws, graph=graph)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            dossier = {
                "schema_version": lib.SCHEMA_VERSION,
                "candidate_id": path.stem,
                "candidate_path": str(path),
                "external_actor_path": "contradicted",
                "in_scope_asset": "uncertain",
                "preconditions": ["missing"],
                "state_transition": {"matched_entrypoints": []},
                "victim_impact": "none",
                "proof_plan": "cannot prove",
                "submit_verdict": "unsafe_to_submit",
                "blockers": ["candidate_unreadable"],
                "error": str(exc),
            }
        dossiers.append(dossier)
        if args.out_dir:
            args.out_dir.mkdir(parents=True, exist_ok=True)
            cid = dossier.get("candidate_id") or path.stem
            safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in str(cid))[:120] or path.stem
            (args.out_dir / f"{safe}.production_path_dossier.json").write_text(
                json.dumps(dossier, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    payload = {
        "schema_version": "auditooor.production_path_dossiers.v1",
        "workspace": str(ws),
        "candidate_count": len(dossiers),
        "dossiers": dossiers,
    }
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
