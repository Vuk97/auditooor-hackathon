#!/usr/bin/env python3
"""Bounded freshness check/refresh wrapper for Hackerman latency sidecars.

Targets:
- detector_relationship_records
- chain_candidates
- chain_unify_payload

Use `--check` for status only (exit 0 when all fresh, 1 when any stale).
Without `--check`, stale targets are rebuilt up to `--max-rebuilds`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hackerman_query_common import DEFAULT_TAGS_DIR, clamp_limit, load_query_module  # noqa: E402


SCHEMA = "auditooor.hackerman_sidecar_refresh_check.v1"


def _load_sidecar_modules() -> dict[str, Any]:
    detector = load_query_module(
        "hackerman-detector-relationships-sidecar.py",
        "_hackerman_detector_relationships_sidecar_refresh_check",
    )
    chain = load_query_module(
        "hackerman-chain-candidates-sidecar.py",
        "_hackerman_chain_candidates_sidecar_refresh_check",
    )
    chain_unify = load_query_module(
        "hackerman-chain-unify-sidecar.py",
        "_hackerman_chain_unify_sidecar_refresh_check",
    )
    return {
        "detector_relationship_records": detector,
        "chain_candidates": chain,
        "chain_unify_payload": chain_unify,
    }


def _resolve_targets(raw_targets: list[str], known_targets: set[str]) -> list[str]:
    chosen: list[str] = []
    for chunk in raw_targets:
        for part in str(chunk).split(","):
            name = part.strip()
            if not name:
                continue
            if name not in known_targets:
                raise ValueError(f"unknown target '{name}'")
            if name not in chosen:
                chosen.append(name)
    return chosen


def _sidecar_path_for(target: str, module: Any, tag_dir: Path, args: argparse.Namespace) -> Path:
    if target == "detector_relationship_records" and args.detector_sidecar:
        return Path(args.detector_sidecar).expanduser().resolve()
    if target == "chain_candidates" and args.chain_sidecar:
        return Path(args.chain_sidecar).expanduser().resolve()
    if target == "chain_unify_payload" and args.chain_unify_sidecar:
        return Path(args.chain_unify_sidecar).expanduser().resolve()
    return module._default_sidecar_path(tag_dir).expanduser().resolve()  # type: ignore[attr-defined]


def _chain_sidecar_path(tag_dir: Path, args: argparse.Namespace) -> Path:
    if args.chain_sidecar:
        return Path(args.chain_sidecar).expanduser().resolve()
    return tag_dir.parent / "derived" / "chain_candidates.jsonl"


def _target_is_fresh(
    target: str,
    module: Any,
    tag_dir: Path,
    sidecar_path: Path,
    args: argparse.Namespace,
) -> tuple[bool, str]:
    if target == "chain_unify_payload":
        return module.sidecar_is_fresh(
            tag_dir,
            sidecar_path,
            chain_sidecar_path=_chain_sidecar_path(tag_dir, args),
            max_hops=args.max_hops,
        )
    return module.sidecar_is_fresh(tag_dir, sidecar_path)


def _build_target_sidecar(
    target: str,
    module: Any,
    tag_dir: Path,
    sidecar_path: Path,
    args: argparse.Namespace,
) -> dict[str, Any]:
    if target == "chain_unify_payload":
        return module.build_sidecar(
            tag_dir,
            sidecar_path,
            chain_sidecar_path=_chain_sidecar_path(tag_dir, args),
            max_hops=args.max_hops,
        )
    return module.build_sidecar(tag_dir, sidecar_path)


def run_refresh(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    if not tag_dir.is_dir():
        return 2, {"error": f"tag dir not found: {tag_dir}"}

    modules = _load_sidecar_modules()
    try:
        targets = _resolve_targets(args.targets, set(modules))
    except ValueError as exc:
        return 2, {"error": str(exc)}
    if not targets:
        return 2, {"error": "no targets selected"}

    max_rebuilds = clamp_limit(args.max_rebuilds, default=len(targets), maximum=32)
    rebuilt = 0
    target_rows: list[dict[str, Any]] = []
    errors = 0

    for target in targets:
        module = modules[target]
        sidecar_path = _sidecar_path_for(target, module, tag_dir, args)
        fresh_before, reason_before = _target_is_fresh(target, module, tag_dir, sidecar_path, args)
        row: dict[str, Any] = {
            "target": target,
            "sidecar_path": str(sidecar_path),
            "fresh_before": bool(fresh_before),
            "reason_before": reason_before,
            "action": "fresh" if fresh_before else "stale",
            "rebuilt": False,
            "fresh_after": bool(fresh_before),
            "reason_after": reason_before,
        }

        if not args.check and not fresh_before:
            if rebuilt >= max_rebuilds:
                row["action"] = "stale_budget_exhausted"
                row["reason_after"] = "max_rebuilds_exhausted"
            else:
                try:
                    meta = _build_target_sidecar(target, module, tag_dir, sidecar_path, args)
                    rebuilt += 1
                    row["rebuilt"] = True
                    row["build_meta"] = {
                        key: meta.get(key)
                        for key in (
                            "records_loaded",
                            "records_emitted",
                            "corpus_file_count",
                            "corpus_fingerprint",
                            "total_chains",
                            "chainable_steps",
                        )
                        if key in meta
                    }
                    fresh_after, reason_after = _target_is_fresh(target, module, tag_dir, sidecar_path, args)
                    row["fresh_after"] = bool(fresh_after)
                    row["reason_after"] = reason_after
                    row["action"] = "rebuilt" if fresh_after else "rebuilt_but_stale"
                except Exception as exc:  # pragma: no cover - defensive wrapper
                    errors += 1
                    row["action"] = "error"
                    row["fresh_after"] = False
                    row["reason_after"] = f"build_failed: {exc}"

        target_rows.append(row)

    stale_after = sum(1 for row in target_rows if not row.get("fresh_after"))
    summary = {
        "schema": SCHEMA,
        "tag_dir": str(tag_dir),
        "check_mode": bool(args.check),
        "targets_requested": targets,
        "targets_scanned": len(target_rows),
        "fresh_before_count": sum(1 for row in target_rows if row.get("fresh_before")),
        "fresh_after_count": sum(1 for row in target_rows if row.get("fresh_after")),
        "rebuilt_count": rebuilt,
        "stale_after_count": stale_after,
        "error_count": errors,
        "max_rebuilds": max_rebuilds,
        "all_fresh": stale_after == 0,
        "targets": target_rows,
    }
    exit_code = 0 if summary["all_fresh"] else 1
    if errors:
        exit_code = 1
    return exit_code, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument(
        "--targets",
        nargs="+",
        default=["detector_relationship_records", "chain_candidates", "chain_unify_payload"],
        help="Space/comma-separated sidecar targets.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only report freshness (exit 0 all fresh, 1 any stale).",
    )
    parser.add_argument(
        "--max-rebuilds",
        type=int,
        default=3,
        help="Bounded number of stale targets to rebuild when not in --check mode.",
    )
    parser.add_argument(
        "--detector-sidecar",
        default=None,
        help="Override path for detector_relationship_records sidecar.",
    )
    parser.add_argument(
        "--chain-sidecar",
        default=None,
        help="Override path for chain_candidates sidecar.",
    )
    parser.add_argument(
        "--chain-unify-sidecar",
        default=None,
        help="Override path for chain_unify_payload sidecar.",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=4,
        help="Max hops for the chain_unify_payload sidecar freshness/build.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    args = parser.parse_args(argv)

    rc, payload = run_refresh(args)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        if payload.get("error"):
            print(payload["error"], file=sys.stderr)
        else:
            mode = "CHECK" if payload.get("check_mode") else "REFRESH"
            print(
                f"{mode}: {payload['fresh_after_count']}/{payload['targets_scanned']} fresh "
                f"(rebuilt={payload['rebuilt_count']}, stale_after={payload['stale_after_count']})"
            )
            for row in payload.get("targets", []):
                print(
                    f"- {row['target']}: {row['action']} "
                    f"(before={row['reason_before']}; after={row['reason_after']})"
                )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
