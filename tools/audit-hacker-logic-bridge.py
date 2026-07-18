#!/usr/bin/env python3
"""Fan out fresh audit detector hits into advisory hacker/proof artifacts."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.audit_hacker_logic_bridge.v1"


DYDX_HIGH_VALUE_PATH_HINTS: tuple[tuple[str, int, str], ...] = (
    ("protocol/x/clob/", 80, "dYdX matching engine / CLOB state path"),
    ("protocol/x/subaccounts/", 78, "dYdX subaccount balance/permission path"),
    ("protocol/x/perpetuals/", 74, "dYdX perpetuals accounting path"),
    ("protocol/x/vault/", 72, "dYdX vault accounting path"),
    ("protocol/x/affiliates/", 68, "dYdX affiliates/rewards accounting path"),
    ("protocol/daemons/slinky/", 70, "Slinky oracle / vote-extension path"),
    ("protocol/indexer/", 56, "indexer / off-chain state propagation boundary"),
    ("protocol/app/abci", 66, "ABCI consensus entrypoint path"),
    ("iavl", 64, "IAVL persistence / apphash path"),
    ("cometbft", 58, "CometBFT consensus boundary"),
    ("/keeper/", 32, "Cosmos keeper state-transition path"),
    ("msg_server", 30, "Cosmos MsgServer transaction path"),
    ("ante", 28, "Cosmos ante/auth path"),
)

DYDX_ATTACK_TEXT_HINTS: tuple[tuple[str, int, str], ...] = (
    ("insurance fund", 40, "insurance-fund accounting signal"),
    ("module account", 36, "module-account accounting signal"),
    ("liquidat", 34, "liquidation state-transition signal"),
    ("oracle", 32, "oracle manipulation/freshness signal"),
    ("price", 28, "price-dependent state signal"),
    ("apphash", 38, "consensus state-divergence signal"),
    ("prepareproposal", 34, "PrepareProposal production path signal"),
    ("processproposal", 34, "ProcessProposal production path signal"),
    ("extendvote", 32, "vote-extension production path signal"),
    ("verifyvoteextension", 32, "vote-extension verification signal"),
    ("iavl", 30, "IAVL persistence signal"),
    ("authz", 28, "authz/account authority signal"),
    ("feegrant", 28, "feegrant/account authority signal"),
    ("permission", 24, "permission bypass signal"),
    ("withdraw", 24, "withdrawal/fund movement signal"),
)

DYDX_LOW_VALUE_HINTS: tuple[tuple[str, int, str], ...] = (
    ("_test.go", -80, "test-only source path"),
    ("/testutil/", -70, "testutil source path"),
    ("/mocks/", -65, "mock source path"),
    ("/mock/", -65, "mock source path"),
    (".pb.go", -55, "generated protobuf source path"),
    ("protocol/app/app.go", -35, "generic app wiring path"),
    ("/cmd/", -30, "CLI/support path"),
)


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"[audit-hacker-logic-bridge] ERR could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[audit-hacker-logic-bridge] ERR invalid JSON in {path}: {exc}") from None


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", str(value or "").strip().lower()).strip("-") or "hit"


def _rel(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return str(path)


def _engage_hits(engage_report: Path) -> list[dict[str, Any]]:
    payload = _load_json(engage_report)
    if not isinstance(payload, dict):
        return []
    hits: list[dict[str, Any]] = []
    for cluster in payload.get("clusters") or []:
        if not isinstance(cluster, dict):
            continue
        detector_slug = str(cluster.get("detector_slug") or "").strip()
        if not detector_slug:
            continue
        for hit in cluster.get("hits") or []:
            if isinstance(hit, dict):
                hits.append({"detector_slug": detector_slug, "hit": hit})
    return hits


def _severity_score(value: str) -> int:
    severity = str(value or "").upper()
    if "CRITICAL" in severity:
        return 45
    if "HIGH" in severity:
        return 32
    if "MEDIUM" in severity:
        return 16
    if "LOW" in severity:
        return 4
    return 0


def _hit_text(hit_row: dict[str, Any]) -> str:
    hit = hit_row.get("hit") if isinstance(hit_row.get("hit"), dict) else {}
    return " ".join(
        str(part or "")
        for part in (
            hit_row.get("detector_slug"),
            hit.get("file_path"),
            hit.get("snippet"),
            hit.get("function_name"),
            hit.get("function_signature"),
            hit.get("severity"),
        )
    ).lower()


def _dydx_priority(hit_row: dict[str, Any]) -> dict[str, Any]:
    hit = hit_row.get("hit") if isinstance(hit_row.get("hit"), dict) else {}
    text = _hit_text(hit_row).replace("\\", "/")
    score = 0
    reasons: list[str] = []

    severity_delta = _severity_score(str(hit.get("severity") or ""))
    if severity_delta:
        score += severity_delta
        reasons.append(f"severity:{str(hit.get('severity') or '').upper()} +{severity_delta}")

    for needle, delta, reason in DYDX_HIGH_VALUE_PATH_HINTS:
        if needle in text:
            score += delta
            reasons.append(f"{reason} +{delta}")

    for needle, delta, reason in DYDX_ATTACK_TEXT_HINTS:
        if needle in text:
            score += delta
            reasons.append(f"{reason} +{delta}")

    for needle, delta, reason in DYDX_LOW_VALUE_HINTS:
        if needle in text:
            score += delta
            reasons.append(f"{reason} {delta}")

    if "panic" in text and "consensus" not in text and "abci" not in text and "apphash" not in text:
        score -= 18
        reasons.append("generic panic signal without consensus/ABCI anchor -18")

    return {
        "score": score,
        "reasons": reasons[:8] or ["no dYdX/Cosmos priority hints matched"],
    }


def _resolve_priority_mode(args: argparse.Namespace, workspace: Path) -> str:
    requested = str(args.priority_mode or "auto").lower()
    if requested != "auto":
        return requested
    target_repo = str(args.target_repo or "").lower()
    workspace_text = str(workspace).lower()
    engage_text = str(args.engage_report or "").lower()
    if target_repo == "dydxprotocol/v4-chain" or "/dydx" in workspace_text or "dydx" in engage_text:
        return "dydx"
    return "input"


def _select_hit_indexes(
    hits: list[dict[str, Any]],
    *,
    args: argparse.Namespace,
    workspace: Path,
) -> tuple[list[int], str, list[dict[str, Any]]]:
    if args.hit_index is not None:
        hit_indexes = [args.hit_index] if 0 <= args.hit_index < len(hits) else []
        return hit_indexes, "explicit", [
            {
                "hit_index": idx,
                "priority_score": 0,
                "priority_reasons": ["explicit --hit-index override"],
            }
            for idx in hit_indexes
        ]

    max_hits = min(max(0, int(args.max_hits)), len(hits))
    mode = _resolve_priority_mode(args, workspace)
    if mode == "input":
        hit_indexes = list(range(max_hits))
        return hit_indexes, mode, [
            {
                "hit_index": idx,
                "priority_score": 0,
                "priority_reasons": ["input-order selection"],
            }
            for idx in hit_indexes
        ]

    ranked_rows: list[dict[str, Any]] = []
    for idx, hit_row in enumerate(hits):
        priority = _dydx_priority(hit_row)
        ranked_rows.append(
            {
                "hit_index": idx,
                "priority_score": priority["score"],
                "priority_reasons": priority["reasons"],
            }
        )
    ranked_rows.sort(key=lambda row: (-int(row["priority_score"]), int(row["hit_index"])))
    selected = ranked_rows[:max_hits]
    return [int(row["hit_index"]) for row in selected], mode, selected


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Audit workspace root")
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help="auditooor repo root")
    parser.add_argument("--engage-report", default="", help="Default: <workspace>/engage_report.json")
    parser.add_argument("--max-hits", type=int, default=3, help="Max detector hits to graph")
    parser.add_argument("--hit-index", type=int, default=None, help="Optional single hit index override")
    parser.add_argument("--max-tasks", type=int, default=200, help="Bounded proof queue task limit")
    parser.add_argument("--top-n", type=int, default=3, help="Attack-class ranker top N per hit")
    parser.add_argument(
        "--priority-mode",
        choices=("auto", "input", "dydx"),
        default="auto",
        help="Hit fanout ordering. auto uses dYdX/Cosmos scoring for dYdX workspaces/target repos.",
    )
    parser.add_argument("--target-repo", default="", help="Target repo hint, e.g. dydxprotocol/v4-chain")
    parser.add_argument("--language", default="", help="Language hint passed into detector action graphs")
    parser.add_argument("--graph-dir", default="", help="Default: <workspace>/.auditooor/detector_action_graphs")
    parser.add_argument("--legacy-graph-out", default="", help="Default: <workspace>/.auditooor/detector_action_graph.json")
    parser.add_argument("--proof-queue-out", default="", help="Default: <workspace>/.auditooor/proof_obligation_queue.json")
    parser.add_argument("--summary-out", default="", help="Default: <workspace>/.auditooor/audit_hacker_logic_bridge.json")
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if selected detector hits cannot be converted into proof-queue tasks.",
    )
    return parser


def _strict_failures(summary: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if summary.get("errors"):
        failures.append(f"{len(summary['errors'])} detector hit(s) failed action-graph conversion")
    if summary.get("hit_indexes") and summary.get("graph_count", 0) < len(summary.get("hit_indexes") or []):
        failures.append("not every selected detector hit produced an action graph")
    if str(summary.get("proof_queue_status") or "").startswith("blocked"):
        failures.append(f"proof queue status is {summary.get('proof_queue_status')!r}")
    if int(summary.get("proof_queue_task_count") or 0) <= 0:
        failures.append("proof queue contains no tasks")
    return failures


def run(argv: list[str] | None = None) -> dict[str, Any]:
    args = build_parser().parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    repo_root = Path(args.repo_root).expanduser().resolve()
    engage_report = Path(args.engage_report).expanduser().resolve() if args.engage_report else workspace / "engage_report.json"
    graph_dir = Path(args.graph_dir).expanduser().resolve() if args.graph_dir else workspace / ".auditooor" / "detector_action_graphs"
    legacy_graph_out = (
        Path(args.legacy_graph_out).expanduser().resolve()
        if args.legacy_graph_out
        else workspace / ".auditooor" / "detector_action_graph.json"
    )
    proof_queue_out = (
        Path(args.proof_queue_out).expanduser().resolve()
        if args.proof_queue_out
        else workspace / ".auditooor" / "proof_obligation_queue.json"
    )
    summary_out = (
        Path(args.summary_out).expanduser().resolve()
        if args.summary_out
        else workspace / ".auditooor" / "audit_hacker_logic_bridge.json"
    )

    action_mod = _load_module(
        "audit_hacker_logic_bridge_action_graph",
        repo_root / "tools" / "detector-hit-action-graph.py",
    )
    proof_mod = _load_module(
        "audit_hacker_logic_bridge_proof_queue",
        repo_root / "tools" / "proof-obligation-queue.py",
    )

    hits = _engage_hits(engage_report)
    hit_indexes, resolved_priority_mode, selected_hit_rows = _select_hit_indexes(hits, args=args, workspace=workspace)
    selected_by_index = {int(row["hit_index"]): row for row in selected_hit_rows}

    graph_paths: list[Path] = []
    graph_rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    graph_dir.mkdir(parents=True, exist_ok=True)

    for hit_index in hit_indexes:
        detector_slug = str(hits[hit_index].get("detector_slug") or f"hit-{hit_index}")
        graph_path = graph_dir / f"hit_{hit_index:03d}_{_slug(detector_slug)}.json"
        try:
            graph_payload = action_mod.build_payload(
                action_mod.build_parser().parse_args(
                    [
                        "--repo-root",
                        str(repo_root),
                        "--workspace",
                        str(workspace),
                        "--engage-report",
                        str(engage_report),
                        "--hit-index",
                        str(hit_index),
                        "--top-n",
                        str(max(1, int(args.top_n))),
                    ]
                    + (["--language", str(args.language or "go")] if resolved_priority_mode == "dydx" and not args.language else [])
                    + (["--language", str(args.language)] if args.language else [])
                )
            )
            _write_json(graph_path, graph_payload)
            if not graph_paths:
                _write_json(legacy_graph_out, graph_payload)
            graph_paths.append(graph_path)
            graph_rows.append(
                {
                    "hit_index": hit_index,
                    "detector_slug": graph_payload.get("detector_hit", {}).get("detector_slug", detector_slug),
                    "file_path": graph_payload.get("detector_hit", {}).get("file_path", ""),
                    "priority_score": selected_by_index.get(hit_index, {}).get("priority_score", 0),
                    "priority_reasons": selected_by_index.get(hit_index, {}).get("priority_reasons", []),
                    "graph_path": _rel(graph_path, workspace),
                    "proof_obligation_count": graph_payload.get("summary", {}).get("proof_obligation_count", 0),
                }
            )
        except BaseException as exc:  # keep advisory bridge best-effort per hit
            if isinstance(exc, (KeyboardInterrupt, SystemExit)) and getattr(exc, "code", 1) == 0:
                raise
            errors.append({"hit_index": hit_index, "detector_slug": detector_slug, "error": str(exc)})

    proof_args = [
        "--workspace",
        str(workspace),
        "--out",
        str(proof_queue_out),
        "--max-tasks",
        str(max(0, int(args.max_tasks))),
    ]
    if graph_paths:
        for graph_path in graph_paths:
            proof_args.extend(["--detector-action-graph", str(graph_path)])
    else:
        proof_args.append("--no-default-detector-action-graph")
    proof_payload = proof_mod.run(proof_args)

    summary = {
        "schema": SCHEMA,
        "workspace": "<workspace>",
        "advisory_only": True,
        "engage_report": _rel(engage_report, workspace),
        "max_hits": max(0, int(args.max_hits)),
        "priority_mode": resolved_priority_mode,
        "target_repo": str(args.target_repo or ""),
        "language": str(args.language or ("go" if resolved_priority_mode == "dydx" else "")),
        "hit_indexes": hit_indexes,
        "selected_hits": selected_hit_rows,
        "engage_hit_count": len(hits),
        "graph_count": len(graph_paths),
        "graph_dir": _rel(graph_dir, workspace),
        "legacy_graph_path": _rel(legacy_graph_out, workspace) if graph_paths else "",
        "proof_queue_path": _rel(proof_queue_out, workspace),
        "proof_queue_status": proof_payload.get("status", "unknown"),
        "proof_queue_task_count": proof_payload.get("summary", {}).get("task_count", 0),
        "graphs": graph_rows,
        "errors": errors,
        "limitations": [
            "Fanout is bounded and advisory; generated graphs are proof worklists, not findings.",
            "Only engage_report detector hits are fanned out; markdown-only reports need a JSON report first.",
            "Queue tasks still require source proof, OOS/dupe checks, and runnable PoC evidence before submission.",
        ],
    }
    strict_failures = _strict_failures(summary) if args.strict else []
    summary["strict"] = bool(args.strict)
    summary["strict_failures"] = strict_failures
    _write_json(summary_out, summary)
    if args.print_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    if strict_failures:
        raise SystemExit("[audit-hacker-logic-bridge] STRICT FAIL: " + "; ".join(strict_failures))
    return summary


def main() -> int:
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
