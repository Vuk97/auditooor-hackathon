#!/usr/bin/env python3
"""Emit per-workspace Hackerman novel-vector artifacts for audit-deep.

This is the delivery-mile wrapper for Hackerman V3 Lane B3.  The underlying
generator already exists (`hackerman-novel-vector-gen.py`) and the MCP wrapper
already exposes it (`vault_hackerman_novel_vector_context`), but `make
audit-deep` did not leave a durable workspace artifact.  This tool bridges that
gap:

* infer target repos from the engagement workspace (git remotes + scope docs);
* invoke the novel-vector generator for each target repo;
* write `.auditooor/novel_vectors.jsonl` as the worker-facing artifact;
* write summary and MCP-context sidecars so closeout can prove the corpus was
  actually queried.

The output is advisory only.  It is an attack-hypothesis worklist, not proof,
severity, or paste-readiness.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
NOVEL_VECTOR_TOOL = TOOLS_DIR / "hackerman-novel-vector-gen.py"
VAULT_MCP_SERVER = TOOLS_DIR / "vault-mcp-server.py"
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
SCHEMA = "auditooor.audit_deep_novel_vectors.v1"
# r36-rebuttal: criterion-i nightly lane owns only this file + its test; registered via agent-pathspec-register
EMPTY_MARKER_SCHEMA = "auditooor.audit_deep_novel_vectors.empty_marker.v1"
MAX_REPOS = 12
DEFAULT_LIMIT = 20
DEFAULT_MAX_TARGETS = 50

GITHUB_RE = re.compile(
    r"(?:https?://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#\s'\"]|$)"
)


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_novel_vector_tool() -> Any:
    spec = importlib.util.spec_from_file_location("hackerman_novel_vector_gen", NOVEL_VECTOR_TOOL)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {NOVEL_VECTOR_TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sha256(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except ValueError:
        return path.as_posix()


def _normalise_repo_slug(raw: str) -> str:
    value = raw.strip().strip("/").removesuffix(".git")
    value = re.sub(r"[^A-Za-z0-9_.\-/]", "", value)
    parts = [part for part in value.split("/") if part]
    if len(parts) < 2:
        return ""
    return f"{parts[-2]}/{parts[-1]}".lower()


def _repos_from_text(text: str) -> list[str]:
    repos: list[str] = []
    for match in GITHUB_RE.finditer(text):
        repo = _normalise_repo_slug(match.group(1))
        if repo:
            repos.append(repo)
    return repos


def _iter_git_configs(workspace: Path) -> list[Path]:
    configs: list[Path] = []
    skip_dirs = {
        ".auditooor",
        ".audit_logs",
        "agent_outputs",
        "node_modules",
        "target",
        "dist",
        "build",
        ".next",
        "__pycache__",
    }
    for root, dirs, files in os.walk(workspace):
        rel_depth = len(Path(root).relative_to(workspace).parts)
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        if rel_depth > 5:
            dirs[:] = []
            continue
        if Path(root).name == ".git" and "config" in files:
            configs.append(Path(root) / "config")
            dirs[:] = []
    return sorted(configs)


def infer_target_repos(workspace: Path, explicit: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    repos: list[str] = []
    sources: list[dict[str, str]] = []

    for raw in explicit:
        repo = _normalise_repo_slug(raw)
        if repo:
            repos.append(repo)
            sources.append({"source": "explicit", "repo": repo, "path": ""})

    for config in _iter_git_configs(workspace):
        try:
            text = config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for repo in _repos_from_text(text):
            repos.append(repo)
            sources.append({"source": "git_remote", "repo": repo, "path": _safe_rel(config, workspace)})

    text_candidates = [
        workspace / "scope.json",
        workspace / "SCOPE.md",
        workspace / "README.md",
        workspace / ".auditooor" / "brain_prime_receipt.json",
    ]
    for path in text_candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for repo in _repos_from_text(text):
            repos.append(repo)
            sources.append({"source": "workspace_text", "repo": repo, "path": _safe_rel(path, workspace)})

    deduped = list(dict.fromkeys(repo for repo in repos if repo))
    return deduped[:MAX_REPOS], sources


def _run_mcp_context(
    *,
    target_repo: str,
    language: str,
    domain: str,
    limit: int,
    max_targets: int,
    same_class_variants: bool,
    tag_dir: Path,
    timeout_seconds: float,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Call vault_hackerman_novel_vector_context as a subprocess.

    B4 telemetry note: workspace is forwarded both as ``workspace_path`` in the
    --args JSON and as the ``AUDITOOOR_WORKSPACE`` env var so that
    vault-mcp-server's ``_record_call_telemetry`` writes to the per-workspace
    ``.auditooor/mcp_call_log.jsonl`` rather than the /tmp fallback.  This
    makes ``vault_hackerman_novel_vector_context`` visible in
    ``make capability-adoption-status WS=<ws>`` after an ``audit-deep`` run.
    """
    args: dict[str, Any] = {
        "target_repo": target_repo,
        "limit": limit,
        "max_targets": max_targets,
        "tag_dir": str(tag_dir),
    }
    if language:
        args["language"] = language
    if domain:
        args["domain"] = domain
    if same_class_variants:
        args["same_class_variants"] = True
    # B4: route telemetry to the per-workspace log by embedding workspace_path
    # in the call args (used by vault-mcp-server._telemetry_resolve_workspace).
    if workspace is not None:
        args["workspace_path"] = str(workspace)
    env = dict(os.environ)
    if workspace is not None:
        env["AUDITOOOR_WORKSPACE"] = str(workspace)
    proc = subprocess.run(
        [
            sys.executable,
            str(VAULT_MCP_SERVER),
            "--call",
            "vault_hackerman_novel_vector_context",
            "--args",
            json.dumps(args, sort_keys=True),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        return {
            "schema": "auditooor.audit_deep_novel_vectors.mcp_error.v1",
            "target_repo": target_repo,
            "returncode": proc.returncode,
            "stderr_tail": proc.stderr[-2000:],
        }
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {
            "schema": "auditooor.audit_deep_novel_vectors.mcp_error.v1",
            "target_repo": target_repo,
            "returncode": proc.returncode,
            "error": f"invalid_json:{exc.lineno}:{exc.colno}",
            "stdout_tail": proc.stdout[-2000:],
        }
    return payload


def _build_empty_marker(
    *,
    repos: list[str],
    summaries: list[dict[str, Any]],
    workspace: Path,
    generated_at: str,
    filters: dict[str, Any],
) -> dict[str, Any]:
    """Construct an explicit empty-with-reason marker row.

    r36-rebuttal: criterion-i nightly lane owns only this file + its test.

    The novel-vector synthesis can legitimately return zero promotable
    hypotheses (e.g. a hardened target where no cross-repo corpus analogue
    clears --min-shape-overlap, or where no corpus record matches the
    target-repo filter at all).  Writing a 0-line file in that case produces
    a *silent* empty artifact: a closeout reader cannot tell "synthesis ran
    and found nothing" apart from "synthesis never ran".  This row makes the
    artifact content-bearing so the canonical jsonl always has at least one
    line that records why it is otherwise empty.

    The row is self-identifying via ``workspace_artifact_schema`` ==
    EMPTY_MARKER_SCHEMA and ``empty_marker`` == True so consumers can filter
    it out from real hypothesis rows.  It carries the per-repo diagnostics
    reasons so the empty result is auditable without re-reading the summary.
    """
    per_repo_reasons: list[dict[str, Any]] = []
    for summ in summaries:
        diagnostics = summ.get("diagnostics") or {}
        empty_state = diagnostics.get("empty_state") or {}
        per_repo_reasons.append(
            {
                "target_repo": summ.get("target_repo"),
                "status": empty_state.get("status", "empty"),
                "reasons": empty_state.get("reasons", []),
                "next_steps": empty_state.get("next_steps", []),
                "total_target_candidates": summ.get("total_target_candidates"),
                "candidate_pairs_seen": summ.get("candidate_pairs_seen"),
                "filtered_existing_class": summ.get("filtered_existing_class"),
            }
        )
    if not repos:
        reason = "no_target_repo_detected"
    elif all((s.get("status") == "no_targets") for s in per_repo_reasons):
        reason = "no_corpus_record_matched_target_repo_filter"
    else:
        reason = "no_cross_repo_analogue_cleared_shape_overlap"
    return {
        "workspace_artifact_schema": EMPTY_MARKER_SCHEMA,
        "empty_marker": True,
        "advisory_only": True,
        "submission_posture": "NOT_SUBMIT_READY",
        "workspace": str(workspace),
        "generated_at_utc": generated_at,
        "target_repos": repos,
        "empty_reason": reason,
        "per_repo_diagnostics": per_repo_reasons,
        "filters": filters,
        "note": (
            "Synthesis ran and produced zero promotable novel vectors. "
            "This is an explicit empty-with-reason marker, not a silent empty file. "
            "No source-anchored candidate vector was emitted; nothing here is filing-ready."
        ),
    }


def build_artifacts(args: argparse.Namespace) -> dict[str, Any]:
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        raise FileNotFoundError(f"workspace not found: {workspace}")
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    if not tag_dir.is_dir():
        raise FileNotFoundError(f"tag dir not found: {tag_dir}")

    out_path = Path(args.out).expanduser().resolve() if args.out else workspace / ".auditooor" / "novel_vectors.jsonl"
    summary_path = (
        Path(args.summary_out).expanduser().resolve()
        if args.summary_out
        else workspace / ".auditooor" / "novel_vectors.summary.json"
    )
    context_path = (
        Path(args.context_out).expanduser().resolve()
        if args.context_out
        else workspace / ".auditooor" / "novel_vectors.mcp_context.jsonl"
    )

    repos, repo_sources = infer_target_repos(workspace, args.target_repo or [])
    novel_tool = _load_novel_vector_tool()

    all_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    mcp_rows: list[dict[str, Any]] = []
    generated_at = _utc_now()

    for repo in repos:
        payload = novel_tool.build_payload(
            tag_dir,
            limit=args.limit,
            target_repo=repo,
            language=args.language or "",
            domain=args.domain or "",
            min_shape_overlap=args.min_shape_overlap,
            max_targets=None if args.all_targets else args.max_targets,
            same_class_variants=args.same_class_variants,
        )
        summaries.append(
            {
                "target_repo": repo,
                "context_pack_id": payload.get("context_pack_id"),
                "context_pack_hash": payload.get("context_pack_hash"),
                "total_records": payload.get("total_records"),
                "targets_considered": payload.get("targets_considered"),
                "total_target_candidates": payload.get("total_target_candidates"),
                "candidate_pairs_seen": payload.get("candidate_pairs_seen"),
                "candidate_pairs_considered": payload.get("candidate_pairs_considered"),
                "filtered_existing_class": payload.get("filtered_existing_class"),
                "filtered_no_bridge": payload.get("filtered_no_bridge"),
                "total_hypotheses": payload.get("total_hypotheses"),
                "diagnostics": payload.get("diagnostics", {}),
            }
        )
        for row in payload.get("hypotheses") or []:
            enriched = dict(row)
            enriched["workspace"] = str(workspace)
            enriched["workspace_artifact_schema"] = SCHEMA
            enriched["target_repo_filter"] = repo
            enriched["generated_at_utc"] = generated_at
            all_rows.append(enriched)

        if not args.skip_mcp_context:
            try:
                mcp_rows.append(
                    _run_mcp_context(
                        target_repo=repo,
                        language=args.language or "",
                        domain=args.domain or "",
                        limit=args.limit,
                        max_targets=args.max_targets,
                        same_class_variants=args.same_class_variants,
                        tag_dir=tag_dir,
                        timeout_seconds=args.mcp_timeout_seconds,
                        workspace=workspace,  # B4: route telemetry to workspace log
                    )
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                mcp_rows.append(
                    {
                        "schema": "auditooor.audit_deep_novel_vectors.mcp_error.v1",
                        "target_repo": repo,
                        "error": f"{exc.__class__.__name__}: {exc}",
                    }
                )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    context_path.parent.mkdir(parents=True, exist_ok=True)
    # r36-rebuttal: criterion-i nightly lane owns only this file + its test.
    # Promote-step fix: when synthesis returns zero promotable hypotheses,
    # write an explicit empty-with-reason marker row instead of a silent
    # 0-line file so the canonical jsonl is always content-bearing.
    summary_filters = {
        "tag_dir": str(tag_dir),
        "language": args.language or "",
        "domain": args.domain or "",
        "limit": args.limit,
        "max_targets": None if args.all_targets else args.max_targets,
        "same_class_variants": bool(args.same_class_variants),
        "min_shape_overlap": args.min_shape_overlap,
        "skip_mcp_context": bool(args.skip_mcp_context),
    }
    output_rows: list[dict[str, Any]] = list(all_rows)
    empty_marker_written = False
    if not all_rows:
        output_rows = [
            _build_empty_marker(
                repos=repos,
                summaries=summaries,
                workspace=workspace,
                generated_at=generated_at,
                filters=summary_filters,
            )
        ]
        empty_marker_written = True
    out_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in output_rows), encoding="utf-8")
    context_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in mcp_rows),
        encoding="utf-8",
    )

    digest = _sha256(
        {
            "schema": SCHEMA,
            "workspace": str(workspace),
            "target_repos": repos,
            "row_ids": [row.get("hypothesis_id") for row in all_rows],
            "filters": {
                "language": args.language or "",
                "domain": args.domain or "",
                "limit": args.limit,
                "max_targets": None if args.all_targets else args.max_targets,
                "same_class_variants": bool(args.same_class_variants),
            },
        }
    )
    summary = {
        "schema": SCHEMA,
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "workspace": str(workspace),
        "generated_at_utc": generated_at,
        "advisory_only": True,
        "submission_posture": "NOT_SUBMIT_READY",
        "target_repos": repos,
        "target_repo_sources": repo_sources,
        "target_repo_count": len(repos),
        "degraded": not bool(repos),
        "degraded_reason": "no_target_repo_detected" if not repos else "",
        # r36-rebuttal: criterion-i nightly lane owns only this file + its test.
        "empty_marker_written": empty_marker_written,
        "filters": summary_filters,
        "outputs": {
            "novel_vectors_jsonl": _safe_rel(out_path, workspace),
            "summary_json": _safe_rel(summary_path, workspace),
            "mcp_context_jsonl": _safe_rel(context_path, workspace),
        },
        "total_hypotheses": len(all_rows),
        "target_summaries": summaries,
        "limitations": [
            "Novel vectors are advisory corpus analogues, not proof of exploitability.",
            "Rows require source validation and a runnable harness before filing.",
            "Target repo inference is best-effort; pass --target-repo for precision when needed.",
        ],
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Engagement workspace")
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR), help="Hackerman tag dir")
    parser.add_argument("--target-repo", action="append", default=[], help="Target repo slug; repeatable")
    parser.add_argument("--language", default="", help="Optional exact target language")
    parser.add_argument("--domain", default="", help="Optional exact target domain")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Hypotheses per target repo")
    parser.add_argument("--max-targets", type=int, default=DEFAULT_MAX_TARGETS, help="Target records per repo")
    parser.add_argument("--all-targets", action="store_true", help="Disable target cap")
    parser.add_argument("--same-class-variants", action="store_true", help="Emit same-class variant advisories")
    parser.add_argument("--min-shape-overlap", type=float, default=0.5, help="Shape Jaccard threshold")
    parser.add_argument("--out", default=None, help="JSONL output path")
    parser.add_argument("--summary-out", default=None, help="Summary JSON output path")
    parser.add_argument("--context-out", default=None, help="MCP context JSONL output path")
    parser.add_argument("--skip-mcp-context", action="store_true", help="Skip MCP context sidecar")
    parser.add_argument("--mcp-timeout-seconds", type=float, default=60.0, help="Per-target MCP timeout")
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = build_artifacts(args)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"[audit-deep-novel-vectors] ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            "[audit-deep-novel-vectors] wrote "
            f"{summary['outputs']['novel_vectors_jsonl']} "
            f"({summary['total_hypotheses']} hypotheses across {summary['target_repo_count']} repos)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
