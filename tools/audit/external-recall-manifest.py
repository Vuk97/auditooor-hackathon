#!/usr/bin/env python3
"""Build or validate external recall manifests for realworld-recall-scoreboard.

The scoreboard consumes JSON with schema auditooor.external_recall_samples.v1.
This helper keeps operators from hand-editing that JSON when measuring a local
external repo sample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import sys
import time
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.external_recall_samples.v1"
DEFAULT_INCLUDE = ["**/*.sol"]
DEFAULT_SELECT_LIMIT = 5
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "vendors",
    "lib",
    "libs",
    "out",
    "build",
    "cache",
}

ATTACK_CLASS_HINTS = {
    "access-control": [
        "access",
        "admin",
        "auth",
        "authorized",
        "guardian",
        "hasrole",
        "onlyowner",
        "owner",
        "permission",
        "role",
    ],
    "accounting-state": [
        "accounting",
        "balance",
        "collateral",
        "debt",
        "share",
        "shares",
        "supply",
        "totalassets",
        "totalsupply",
    ],
    "oracle": [
        "aggregator",
        "chainlink",
        "latestanswer",
        "latestrounddata",
        "oracle",
        "price",
        "twap",
    ],
    "reentrancy": [
        "call.value",
        "delegatecall",
        "external call",
        "nonreentrant",
        "reentrant",
        "send(",
        "transfer(",
        "withdraw",
    ],
    "governance": [
        "delegate",
        "governance",
        "governor",
        "proposal",
        "quorum",
        "vote",
    ],
    "signature": [
        "digest",
        "ecrecover",
        "nonces",
        "permit",
        "signature",
        "signer",
    ],
    "liquidation": [
        "healthfactor",
        "liquidate",
        "liquidation",
        "solvency",
    ],
    "slippage": [
        "amountoutminimum",
        "minout",
        "slippage",
        "swap",
    ],
}


def _slugify(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._/-]+", "-", value.strip())
    text = text.strip("-/._").lower()
    return text or "external"


def _stable_sample_id(repo_id: str, rel_path: str, used: set[str]) -> str:
    base = _slugify(f"{repo_id}-{Path(rel_path).with_suffix('').as_posix()}")
    sample_id = base
    if sample_id in used:
        digest = hashlib.sha1(rel_path.encode("utf-8")).hexdigest()[:8]
        sample_id = f"{base}-{digest}"
    used.add(sample_id)
    return sample_id


def _normalize_rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _is_skipped(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        rel_parts = path.parts
    return any(part in SKIP_DIRS for part in rel_parts)


def discover_samples(repo_root: Path, explicit: list[str], includes: list[str]) -> list[Path]:
    root = repo_root.expanduser().resolve()
    found: list[Path] = []
    if explicit:
        for raw in explicit:
            path = Path(raw).expanduser()
            if not path.is_absolute():
                path = root / path
            found.append(path.resolve())
    else:
        for pattern in includes or DEFAULT_INCLUDE:
            for path in root.glob(pattern):
                if path.is_file() and not _is_skipped(path, root):
                    found.append(path.resolve())
    return sorted(dict.fromkeys(found), key=lambda p: p.as_posix())


def _attack_class_terms(attack_class: str) -> list[str]:
    normalized = _slugify(attack_class).replace("_", "-")
    terms: list[str] = []
    for part in re.split(r"[-/]+", normalized):
        if len(part) >= 3:
            terms.append(part)
    for key, hints in ATTACK_CLASS_HINTS.items():
        if key in normalized or normalized in key:
            terms.extend(hints)
    seen: set[str] = set()
    out: list[str] = []
    for term in terms:
        value = term.lower().strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _read_preview(path: Path, max_bytes: int = 200_000) -> str:
    try:
        return path.read_bytes()[:max_bytes].decode("utf-8", errors="ignore").lower()
    except Exception:
        return ""


def select_candidate_samples(
    repo_root: Path,
    samples: list[Path],
    attack_class: str,
    limit: int = DEFAULT_SELECT_LIMIT,
) -> list[dict[str, Any]]:
    """Rank local repo files for operator review before manifest generation.

    This is intentionally a dry-run selector: it does not assert that files are
    vulnerable. It narrows a local external repo to a bounded set of candidate
    files whose paths/content match the chosen scoreboard attack_class.
    """
    root = repo_root.expanduser().resolve()
    terms = _attack_class_terms(attack_class)
    ranked: list[dict[str, Any]] = []
    for sample in samples:
        rel = _normalize_rel(sample, root)
        path_text = rel.lower()
        content = _read_preview(sample)
        score = 0
        reasons: list[str] = []
        for term in terms:
            if term in path_text:
                score += 3
                reasons.append(f"path:{term}")
            if term in content:
                score += 1
                reasons.append(f"content:{term}")
        ranked.append(
            {
                "path": rel,
                "score": score,
                "reasons": reasons[:10],
            }
        )
    ranked.sort(key=lambda row: (-int(row["score"]), row["path"]))
    selected = ranked[: max(limit, 0)]
    if selected and all(int(row["score"]) == 0 for row in selected):
        for row in selected:
            row["reasons"] = ["fallback:no_attack_class_hints_matched"]
    return selected


def build_manifest(
    repo_root: Path,
    repo_id: str,
    samples: list[Path],
    attack_class: str,
    severity: str,
    source: str,
    exclude_detector_slug: str,
    source_state: str,
    source_state_reason: str,
    finding_ref: str,
    source_snapshot_ref: str,
    vulnerable_commit: str,
    fix_commit: str,
    validated_by: str,
    proof_ref: str,
    source_refs: list[str],
    out_path: Path,
) -> dict[str, Any]:
    root = repo_root.expanduser().resolve()
    out_dir = out_path.expanduser().resolve().parent
    used_ids: set[str] = set()
    rows: list[dict[str, str]] = []
    for sample in samples:
        abs_sample = sample.expanduser().resolve()
        rel_to_repo = _normalize_rel(abs_sample, root)
        rel_to_manifest = _normalize_rel(abs_sample, out_dir)
        row = {
            "id": _stable_sample_id(repo_id, rel_to_repo, used_ids),
            "path": rel_to_manifest,
            "attack_class": attack_class.strip(),
            "severity": severity.strip().upper() or "UNKNOWN",
            "source": source.strip() or f"external_repo:{repo_id}",
            "exclude_detector_slug": exclude_detector_slug.strip(),
        }
        optional_fields = {
            "source_state": source_state.strip(),
            "source_state_reason": source_state_reason.strip(),
            "finding_ref": finding_ref.strip(),
            "source_snapshot_ref": source_snapshot_ref.strip(),
            "vulnerable_commit": vulnerable_commit.strip(),
            "fix_commit": fix_commit.strip(),
            "validated_by": validated_by.strip(),
            "proof_ref": proof_ref.strip(),
        }
        for key, value in optional_fields.items():
            if value:
                row[key] = value
        clean_source_refs = [item.strip() for item in source_refs if item.strip()]
        if clean_source_refs:
            row["source_refs"] = clean_source_refs
        rows.append(row)
    return {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repo_id": repo_id,
        "repo_root": str(root),
        "sample_count": len(rows),
        "samples": rows,
    }


def validate_manifest(manifest_path: Path) -> tuple[bool, list[str], dict[str, Any] | None]:
    path = manifest_path.expanduser().resolve()
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, [f"manifest_parse_error: {exc}"], None
    if not isinstance(payload, dict):
        return False, ["manifest_shape_error: manifest must be a JSON object"], None
    if payload.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    raw_samples = payload.get("samples")
    if not isinstance(raw_samples, list):
        errors.append("samples must be a list")
        raw_samples = []
    seen_ids: set[str] = set()
    base = path.parent
    for idx, row in enumerate(raw_samples, 1):
        if not isinstance(row, dict):
            errors.append(f"sample {idx} must be an object")
            continue
        sample_id = str(row.get("id") or "").strip()
        raw_sample_path = str(row.get("path") or "").strip()
        attack_class = str(row.get("attack_class") or "").strip()
        if not sample_id:
            errors.append(f"sample {idx} missing id")
        elif sample_id in seen_ids:
            errors.append(f"sample {sample_id} duplicate id")
        else:
            seen_ids.add(sample_id)
        if not raw_sample_path:
            errors.append(f"sample {sample_id or idx} missing path")
        else:
            sample_path = Path(raw_sample_path).expanduser()
            if not sample_path.is_absolute():
                sample_path = base / sample_path
            if not sample_path.resolve(strict=False).is_file():
                errors.append(
                    f"sample {sample_id or idx} file not found: "
                    f"{sample_path.resolve(strict=False)}"
                )
        if not attack_class:
            errors.append(f"sample {sample_id or idx} missing attack_class")
    return not errors, errors, payload


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _command(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def _workflow_commands(
    *,
    repo_root: Path,
    repo_id: str,
    attack_class: str,
    out_path: Path,
    sample_paths: list[str],
    severity: str = "UNKNOWN",
    source: str = "",
    exclude_detector_slug: str = "",
    source_state: str = "",
    finding_ref: str = "",
    source_snapshot_ref: str = "",
    vulnerable_commit: str = "",
    fix_commit: str = "",
) -> dict[str, str]:
    build_parts = [
        "python3",
        "tools/audit/external-recall-manifest.py",
        "build",
        "--repo-root",
        str(repo_root.expanduser().resolve()),
        "--repo-id",
        repo_id,
        "--attack-class",
        attack_class,
        "--severity",
        severity,
        "--out",
        str(out_path),
    ]
    if source:
        build_parts.extend(["--source", source])
    if exclude_detector_slug:
        build_parts.extend(["--exclude-detector-slug", exclude_detector_slug])
    if source_state:
        build_parts.extend(["--source-state", source_state])
    if finding_ref:
        build_parts.extend(["--finding-ref", finding_ref])
    if source_snapshot_ref:
        build_parts.extend(["--source-snapshot-ref", source_snapshot_ref])
    if vulnerable_commit:
        build_parts.extend(["--vulnerable-commit", vulnerable_commit])
    if fix_commit:
        build_parts.extend(["--fix-commit", fix_commit])
    for sample_path in sample_paths:
        build_parts.extend(["--sample", sample_path])
    validate_parts = [
        "python3",
        "tools/audit/external-recall-manifest.py",
        "validate",
        str(out_path),
        "--json",
    ]
    scoreboard_parts = [
        "python3",
        "tools/audit/realworld-recall-scoreboard.py",
        "--external-manifest",
        str(out_path),
        "--external-only",
        "--out-dir",
        "reports",
    ]
    return {
        "build_manifest": _command(build_parts),
        "validate_manifest": _command(validate_parts),
        "run_scoreboard": _command(scoreboard_parts),
    }


def cmd_build(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root)
    out_path = Path(args.out)
    samples = discover_samples(repo_root, args.sample, args.include)
    manifest = build_manifest(
        repo_root=repo_root,
        repo_id=args.repo_id,
        samples=samples,
        attack_class=args.attack_class,
        severity=args.severity,
        source=args.source,
        exclude_detector_slug=args.exclude_detector_slug,
        source_state=args.source_state,
        source_state_reason=args.source_state_reason,
        finding_ref=args.finding_ref,
        source_snapshot_ref=args.source_snapshot_ref,
        vulnerable_commit=args.vulnerable_commit,
        fix_commit=args.fix_commit,
        validated_by=args.validated_by,
        proof_ref=args.proof_ref,
        source_refs=args.source_ref,
        out_path=out_path,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ok, errors, _ = validate_manifest(out_path)
    result = {
        "ok": ok,
        "manifest_path": str(out_path.resolve()),
        "sample_count": len(manifest["samples"]),
        "errors": errors,
        "scoreboard_command": (
            "python3 tools/audit/realworld-recall-scoreboard.py "
            f"--external-manifest {out_path.resolve()} --external-only"
        ),
    }
    if args.json:
        _print_json(result)
    else:
        status = "valid" if ok else "invalid"
        print(f"[{status}] wrote {out_path} ({len(manifest['samples'])} samples)")
        if errors:
            for err in errors:
                print(f"- {err}")
        print(result["scoreboard_command"])
    return 0 if ok else 1


def cmd_select(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root)
    out_path = Path(args.out)
    samples = discover_samples(repo_root, args.sample, args.include)
    candidates = select_candidate_samples(
        repo_root=repo_root,
        samples=samples,
        attack_class=args.attack_class,
        limit=args.limit,
    )
    sample_paths = [str(row["path"]) for row in candidates]
    result = {
        "ok": bool(candidates),
        "repo_root": str(repo_root.expanduser().resolve()),
        "repo_id": args.repo_id,
        "attack_class": args.attack_class,
        "discovered_sample_count": len(samples),
        "selected_sample_count": len(candidates),
        "candidates": candidates,
        "caveat": (
            "Dry-run candidate selection only; an operator must confirm each "
            "file is a known-vulnerable external sample before scoring recall."
        ),
        "commands": _workflow_commands(
            repo_root=repo_root,
            repo_id=args.repo_id,
            attack_class=args.attack_class,
            out_path=out_path,
            sample_paths=sample_paths,
            severity=args.severity,
            source=args.source,
            exclude_detector_slug=args.exclude_detector_slug,
            source_state=args.source_state,
            finding_ref=args.finding_ref,
            source_snapshot_ref=args.source_snapshot_ref,
            vulnerable_commit=args.vulnerable_commit,
            fix_commit=args.fix_commit,
        ),
    }
    if args.json:
        _print_json(result)
    else:
        if candidates:
            print(
                f"[select] {len(candidates)} candidate(s) from "
                f"{len(samples)} discovered files"
            )
            for row in candidates:
                reasons = ", ".join(row["reasons"]) if row["reasons"] else "no hint"
                print(f"- {row['path']} score={row['score']} reasons={reasons}")
        else:
            print(f"[select] no candidate files discovered under {repo_root}")
        print("")
        print(result["caveat"])
        print(result["commands"]["build_manifest"])
        print(result["commands"]["validate_manifest"])
        print(result["commands"]["run_scoreboard"])
    return 0 if candidates else 1


def cmd_validate(args: argparse.Namespace) -> int:
    ok, errors, payload = validate_manifest(Path(args.manifest))
    result = {
        "ok": ok,
        "manifest_path": str(Path(args.manifest).expanduser().resolve()),
        "sample_count": len(payload.get("samples", [])) if isinstance(payload, dict) else 0,
        "errors": errors,
    }
    if args.json:
        _print_json(result)
    else:
        print(
            f"[{'valid' if ok else 'invalid'}] {result['manifest_path']} "
            f"({result['sample_count']} samples)"
        )
        for err in errors:
            print(f"- {err}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    build = sub.add_parser(
        "build",
        help="generate a scoreboard-compatible external recall manifest",
    )
    build.add_argument("--repo-root", required=True, help="local checked-out repo/sample root")
    build.add_argument(
        "--repo-id",
        required=True,
        help="stable source id, e.g. owner/repo or c4/contest",
    )
    build.add_argument(
        "--attack-class",
        required=True,
        help="scoreboard attack_class for this sample set",
    )
    build.add_argument("--severity", default="UNKNOWN")
    build.add_argument("--source", default="", help="defaults to external_repo:<repo-id>")
    build.add_argument("--exclude-detector-slug", default="")
    build.add_argument(
        "--source-state",
        default="",
        help="optional source state for quality gate: pre_fix, vulnerable, fixed, out_of_class, unknown",
    )
    build.add_argument("--source-state-reason", default="")
    build.add_argument("--finding-ref", default="")
    build.add_argument("--source-snapshot-ref", default="")
    build.add_argument("--vulnerable-commit", default="")
    build.add_argument("--fix-commit", default="")
    build.add_argument("--validated-by", default="")
    build.add_argument("--proof-ref", default="")
    build.add_argument(
        "--source-ref",
        action="append",
        default=[],
        help="repeatable supporting source reference copied into source_refs",
    )
    build.add_argument(
        "--sample",
        action="append",
        default=[],
        help="repo-root-relative sample path; repeatable",
    )
    build.add_argument(
        "--include",
        action="append",
        default=[],
        help="glob under repo root when --sample is omitted",
    )
    build.add_argument("--out", required=True, help="manifest output path")
    build.add_argument("--json", action="store_true")
    build.set_defaults(func=cmd_build)

    select = sub.add_parser(
        "select",
        help="dry-run a bounded sample selector and print exact next commands",
    )
    select.add_argument("--repo-root", required=True, help="local checked-out repo/sample root")
    select.add_argument("--repo-id", required=True, help="stable source id, e.g. owner/repo")
    select.add_argument("--attack-class", required=True, help="target scoreboard attack_class")
    select.add_argument("--severity", default="UNKNOWN")
    select.add_argument("--source", default="", help="defaults to external_repo:<repo-id> during build")
    select.add_argument("--exclude-detector-slug", default="")
    select.add_argument("--source-state", default="")
    select.add_argument("--finding-ref", default="")
    select.add_argument("--source-snapshot-ref", default="")
    select.add_argument("--vulnerable-commit", default="")
    select.add_argument("--fix-commit", default="")
    select.add_argument(
        "--sample",
        action="append",
        default=[],
        help="repo-root-relative sample path to include in the selector pool; repeatable",
    )
    select.add_argument(
        "--include",
        action="append",
        default=[],
        help="glob under repo root when --sample is omitted",
    )
    select.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_SELECT_LIMIT,
        help=f"max candidates to print (default {DEFAULT_SELECT_LIMIT})",
    )
    select.add_argument(
        "--out",
        default="reports/external_recall_samples.json",
        help="manifest path used in generated commands",
    )
    select.add_argument("--json", action="store_true")
    select.set_defaults(func=cmd_select)

    validate = sub.add_parser("validate", help="validate an existing external recall manifest")
    validate.add_argument("manifest")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(func=cmd_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
