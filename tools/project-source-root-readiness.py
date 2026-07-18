#!/usr/bin/env python3
"""Validate declared target project source roots for impact/source binding.

This tool is intentionally conservative.  It does not discover arbitrary
repository folders as proof roots.  Operators or upstream intake tooling must
declare candidate roots, then this validator checks that those roots exist,
contain source files, and are not generated fixtures, reports, submissions,
detectors, test PoCs, or other Auditooor-owned material.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.project_source_root_readiness.v1"
DEFAULT_MANIFEST = ".auditooor/project_source_roots.json"
DEFAULT_OUT = ".auditooor/project_source_root_readiness.json"
DEFAULT_OUT_MD = ".auditooor/project_source_root_readiness.md"
SOURCE_SUFFIXES = {".sol", ".rs", ".move", ".cairo", ".vy"}
EXCLUDED_PREFIXES = (
    ".auditooor/",
    ".audit_logs/",
    ".github/",
    "benchmark_fixtures/",
    "detectors/",
    "docs/",
    "examples/",
    "monitoring/",
    "patterns/",
    "poc-tests/",
    "reference/",
    "reports/",
    "source_proofs/",
    "templates/",
    "test_fixtures/",
    "tests/",
    "tools/",
)
EXCLUDED_PARTS = {
    ".git",
    "__pycache__",
    "artifacts",
    "build",
    "cache",
    "coverage",
    "dist",
    "lib",
    "node_modules",
    "out",
    "pocs",
    "submissions",
    "target",
    "test_poc",
    "vendor",
}
PROOF_BOUNDARY = (
    "Validated roots are import/readiness evidence only. They do not prove a "
    "candidate source citation, production reachability, listed impact, exploit "
    "impact, severity, OOS status, or submission readiness."
)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[project-source-root-readiness] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def workspace_relative(workspace: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def is_excluded_relative_path(path_text: str) -> bool:
    normalized = path_text.replace("\\", "/").lstrip("./")
    path = Path(normalized)
    if any(normalized == prefix.rstrip("/") or normalized.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
        return True
    return any(part in EXCLUDED_PARTS for part in path.parts)


def read_declared_roots(manifest_path: Path, cli_roots: list[str]) -> list[dict[str, Any]]:
    roots: list[dict[str, Any]] = []
    manifest = load_json(manifest_path)
    for item in manifest.get("roots") or [] if isinstance(manifest, dict) else []:
        if isinstance(item, str):
            roots.append({"path": item, "source": "manifest"})
        elif isinstance(item, dict):
            roots.append({**item, "source": item.get("source") or "manifest"})
    for root in cli_roots:
        roots.append({"path": root, "source": "cli"})
    return roots


def source_files_under(root: Path, workspace: Path, *, max_files: int = 500) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if len(files) >= max_files:
            break
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        rel = workspace_relative(workspace, path)
        if is_excluded_relative_path(rel):
            continue
        files.append(
            {
                "file": rel,
                "abs_path": str(path.resolve()),
                "suffix": path.suffix,
            }
        )
    return files


def validate_root(workspace: Path, declaration: dict[str, Any], *, allow_external: bool = False) -> dict[str, Any]:
    raw_path = str(declaration.get("path") or "").strip()
    label = str(declaration.get("label") or declaration.get("name") or raw_path or "unnamed")
    if not raw_path:
        return {
            "label": label,
            "declared_path": raw_path,
            "status": "rejected_empty_path",
            "usable": False,
            "source_file_count": 0,
            "sample_files": [],
            "rejection_reasons": ["empty_path"],
        }

    root = Path(raw_path).expanduser()
    if not root.is_absolute():
        root = workspace / root
    rel = workspace_relative(workspace, root)
    reasons: list[str] = []
    try:
        root.resolve().relative_to(workspace.resolve())
        outside_workspace = False
    except ValueError:
        outside_workspace = True
    if outside_workspace and not allow_external:
        reasons.append("outside_workspace")
    if is_excluded_relative_path(rel):
        reasons.append("excluded_generated_or_non_project_path")
    if not root.exists():
        reasons.append("path_missing")
    elif not root.is_dir():
        reasons.append("not_directory")

    files: list[dict[str, Any]] = [] if reasons else source_files_under(root, workspace)
    if not reasons and not files:
        reasons.append("no_supported_source_files")

    status = "ready" if not reasons else "rejected_" + "_and_".join(sorted(reasons))
    suffix_counts = dict(sorted(Counter(file["suffix"] for file in files).items()))
    return {
        "label": label,
        "declared_path": raw_path,
        "resolved_path": str(root.resolve()) if root.exists() else str(root),
        "workspace_relative_path": rel,
        "source": str(declaration.get("source") or "manifest"),
        "expected_languages": list(declaration.get("expected_languages") or []),
        "status": status,
        "usable": status == "ready",
        "source_file_count": len(files),
        "suffix_counts": suffix_counts,
        "language_presence": {
            "solidity": suffix_counts.get(".sol", 0),
            "rust": suffix_counts.get(".rs", 0),
            "move": suffix_counts.get(".move", 0),
            "cairo": suffix_counts.get(".cairo", 0),
            "vyper": suffix_counts.get(".vy", 0),
        },
        "sample_files": files[:50],
        "rejection_reasons": reasons,
        "proof_boundary": PROOF_BOUNDARY,
    }


def build_payload(
    workspace: Path,
    *,
    manifest_path: Path | None = None,
    cli_roots: list[str] | None = None,
    allow_external: bool = False,
) -> dict[str, Any]:
    manifest = manifest_path or workspace / DEFAULT_MANIFEST
    declarations = read_declared_roots(manifest, cli_roots or [])
    roots = [validate_root(workspace, item, allow_external=allow_external) for item in declarations]
    ready = [root for root in roots if root["usable"]]
    all_files = [file for root in ready for file in root["sample_files"]]
    ready_language_counts = Counter()
    for root in ready:
        for language, count in (root.get("language_presence") or {}).items():
            ready_language_counts[language] += int(count or 0)
    return {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "manifest_path": str(manifest),
        "declared_root_count": len(roots),
        "ready_root_count": len(ready),
        "rejected_root_count": len(roots) - len(ready),
        "source_file_count": sum(int(root["source_file_count"]) for root in ready),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "status_counts": dict(sorted(Counter(root["status"] for root in roots).items())),
            "rejection_reason_counts": dict(
                sorted(Counter(reason for root in roots for reason in root["rejection_reasons"]).items())
            ),
            "suffix_counts": dict(sorted(Counter(file["suffix"] for file in all_files).items())),
            "ready_language_counts": dict(sorted(ready_language_counts.items())),
        },
        "roots": roots,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Project Source Root Readiness",
        "",
        PROOF_BOUNDARY,
        "",
        "## Summary",
        "",
        f"- Declared roots: `{payload['declared_root_count']}`",
        f"- Ready roots: `{payload['ready_root_count']}`",
        f"- Rejected roots: `{payload['rejected_root_count']}`",
        f"- Source files under ready roots: `{payload['source_file_count']}`",
        "",
        "## Status Counts",
        "",
    ]
    for key, value in payload["summary"]["status_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Roots", ""])
    for root in payload["roots"]:
        reasons = ", ".join(root["rejection_reasons"]) or "none"
        lines.append(
            f"- `{root['label']}` `{root['workspace_relative_path']}`: "
            f"`{root['status']}`; files=`{root['source_file_count']}`; reasons={reasons}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--root", action="append", default=[])
    parser.add_argument("--allow-external-roots", action="store_true")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    manifest = (args.manifest or workspace / DEFAULT_MANIFEST).expanduser().resolve()
    payload = build_payload(
        workspace,
        manifest_path=manifest,
        cli_roots=args.root,
        allow_external=args.allow_external_roots,
    )
    out_json = (args.out_json or workspace / DEFAULT_OUT).expanduser().resolve()
    out_md = (args.out_md or workspace / DEFAULT_OUT_MD).expanduser().resolve()
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[project-source-root-readiness] OK "
        f"declared={payload['declared_root_count']} ready={payload['ready_root_count']} "
        f"files={payload['source_file_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
