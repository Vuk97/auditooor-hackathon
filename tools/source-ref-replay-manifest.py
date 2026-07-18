#!/usr/bin/env python3
"""Build a local-only source-ref replay manifest from finding exports."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.source_ref_replay_manifest.v1"
FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")
SHORT_SHA_RE = re.compile(r"[0-9a-f]{7,39}")

STATUS_IMMUTABLE_READY = "immutable_ready"
STATUS_BLOCKED_NAMED_REF = "blocked_named_ref_unresolved"
STATUS_BLOCKED_LOCAL_SOURCE = "blocked_local_source_missing"
STATUS_BLOCKED_SHORT_SHA = "blocked_short_sha_unresolved"
STATUS_BLOCKED_UNSUPPORTED = "blocked_unsupported_source_ref"
_BLINDSPOT_SCAN_MODULE: Any | None = None


def _load_blindspot_scan_module() -> Any:
    global _BLINDSPOT_SCAN_MODULE
    if _BLINDSPOT_SCAN_MODULE is not None:
        return _BLINDSPOT_SCAN_MODULE
    tool = Path(__file__).resolve().with_name("detector-blindspot-scan.py")
    spec = importlib.util.spec_from_file_location("detector_blindspot_scan", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _BLINDSPOT_SCAN_MODULE = module
    return module


def extract_github_refs(content: str) -> list[dict[str, Any]]:
    """Delegate to detector-blindspot-scan.py to keep extraction behavior aligned."""
    return list(_load_blindspot_scan_module().extract_github_refs(content))


def extract_source_refs(content: str) -> list[dict[str, Any]]:
    """Extract one row candidate per distinct source URL using detector regexes."""
    module = _load_blindspot_scan_module()
    refs: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for pattern in (module.GH_SOURCE_RE, module.GH_RAW_SOURCE_RE):
        for match in pattern.finditer(content):
            url = match.group(0)
            if url in seen_urls:
                continue
            seen_urls.add(url)
            extracted = extract_github_refs(url)
            if extracted:
                refs.append(extracted[0])
    return refs


def _read_json_or_jsonl(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        rows = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{lineno}: {exc}") from exc
        return rows
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON at {path}: {exc}") from exc


def load_finding_export(path: Path) -> list[dict[str, Any]]:
    payload = _read_json_or_jsonl(path)
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("rows", "findings", "results", "items"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
        return [payload]
    raise ValueError(f"finding export must be a JSON object, array, or JSONL rows: {path}")


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _iter_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_strings(child)


def finding_content(row: dict[str, Any]) -> str:
    return "\n".join(_iter_strings(row))


def finding_id(row: dict[str, Any], index: int) -> str:
    for key in ("finding_id", "id", "slug", "uuid"):
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return f"row-{index:04d}"


def finding_title(row: dict[str, Any]) -> str:
    for key in ("title", "name", "summary"):
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _full_sha(value: Any) -> str | None:
    if isinstance(value, str) and FULL_SHA_RE.fullmatch(value):
        return value
    return None


def load_named_ref_lockfile(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    payload = _read_json_or_jsonl(path)
    rows: Iterable[Any]
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        rows = payload["rows"]
    elif isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.items()
    else:
        raise ValueError(f"named-ref lockfile must be JSON object, rows array, or JSONL: {path}")

    locks: dict[str, str] = {}
    if isinstance(payload, dict) and not isinstance(payload.get("rows"), list):
        for key, value in rows:
            commit = _full_sha(value)
            if commit is None and isinstance(value, dict):
                commit = (
                    _full_sha(value.get("resolved_commit"))
                    or _full_sha(value.get("commit"))
                    or _full_sha(value.get("sha"))
                )
            if commit:
                locks[str(key)] = commit
        return locks

    for row in rows:
        if not isinstance(row, dict):
            continue
        repo = row.get("repo")
        ref = row.get("ref") or row.get("original_ref") or row.get("name")
        key = row.get("key") or (f"{repo}@{ref}" if repo and ref else None)
        commit = (
            _full_sha(row.get("resolved_commit"))
            or _full_sha(row.get("commit"))
            or _full_sha(row.get("sha"))
        )
        if key and commit:
            locks[str(key)] = commit
    return locks


def load_local_proofs(path: Path | None) -> dict[str, dict[str, str]]:
    if path is None:
        return {}
    payload = _read_json_or_jsonl(path)
    rows: Iterable[Any]
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        rows = payload["rows"]
    elif isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.items()
    else:
        raise ValueError(f"local proof file must be JSON object, rows array, or JSONL: {path}")

    proofs: dict[str, dict[str, str]] = {}
    if isinstance(payload, dict) and not isinstance(payload.get("rows"), list):
        for key, value in rows:
            if isinstance(value, str):
                proofs[str(key)] = {"local_source_path": value}
            elif isinstance(value, dict):
                proofs[str(key)] = {
                    k: str(v)
                    for k, v in value.items()
                    if k in {"local_source_path", "path", "sha256", "content_sha256"}
                    and v is not None
                }
        return proofs

    for row in rows:
        if not isinstance(row, dict):
            continue
        repo = row.get("repo")
        commit = row.get("resolved_commit") or row.get("commit") or row.get("sha")
        filepath = row.get("filepath") or row.get("path_in_repo")
        key = row.get("key") or (
            f"{repo}@{commit}:{filepath}" if repo and commit and filepath else None
        )
        if key:
            proofs[str(key)] = {
                k: str(v)
                for k, v in row.items()
                if k in {"local_source_path", "path", "sha256", "content_sha256"}
                and v is not None
            }
    return proofs


def source_key(repo: str, commit: str, filepath: str) -> str:
    return f"{repo}@{commit}:{filepath}"


def ref_lock_key(repo: str, ref: str) -> str:
    return f"{repo}@{ref}"


def candidate_source_paths(
    source_root: Path | None,
    repo: str,
    original_ref: str,
    resolved_commit: str,
    filepath: str,
) -> list[Path]:
    if source_root is None:
        return []
    root = source_root
    candidates = [
        root / repo / resolved_commit / filepath,
        root / repo / original_ref / filepath,
        root / filepath,
    ]
    seen: set[Path] = set()
    unique = []
    for path in candidates:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _proof_path(proof: dict[str, str]) -> Path | None:
    value = proof.get("local_source_path") or proof.get("path")
    return Path(value) if value else None


def _proof_sha(proof: dict[str, str]) -> str | None:
    value = proof.get("sha256") or proof.get("content_sha256")
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    return None


def resolve_local_source(
    *,
    repo: str,
    original_ref: str,
    resolved_commit: str,
    filepath: str,
    source_root: Path | None,
    local_proofs: dict[str, dict[str, str]],
) -> tuple[Path | None, str | None, list[str]]:
    blockers: list[str] = []
    key = source_key(repo, resolved_commit, filepath)
    proof = local_proofs.get(key, {})
    proof_file = _proof_path(proof)
    candidates = [proof_file] if proof_file else []
    candidates.extend(
        candidate_source_paths(source_root, repo, original_ref, resolved_commit, filepath)
    )

    for candidate in candidates:
        if candidate is None or not candidate.is_file():
            continue
        digest = sha256_file(candidate)
        expected = _proof_sha(proof)
        if expected and digest != expected:
            blockers.append("local proof hash does not match local source bytes")
            continue
        return candidate, digest, blockers

    if proof_file and not proof_file.is_file():
        blockers.append("local proof path is absent")
    return None, None, blockers


def build_row(
    *,
    ref: dict[str, Any],
    finding: dict[str, Any],
    finding_index: int,
    source_root: Path | None,
    named_ref_locks: dict[str, str],
    local_proofs: dict[str, dict[str, str]],
) -> dict[str, Any]:
    repo = str(ref.get("repo") or "")
    original_ref = str(ref.get("commit") or "")
    filepath = str(ref.get("filepath") or "")
    ref_type = str(ref.get("ref_type") or "")
    blockers: list[str] = []
    resolved_commit: str | None = None

    if not repo or not original_ref or not filepath:
        replay_status = STATUS_BLOCKED_UNSUPPORTED
        blockers.append("source URL could not be converted into repo/ref/filepath")
    elif FULL_SHA_RE.fullmatch(original_ref):
        resolved_commit = original_ref
        replay_status = STATUS_BLOCKED_LOCAL_SOURCE
    elif SHORT_SHA_RE.fullmatch(original_ref):
        resolved_commit = named_ref_locks.get(ref_lock_key(repo, original_ref))
        if resolved_commit is None:
            replay_status = STATUS_BLOCKED_SHORT_SHA
            blockers.append("short SHA requires local resolution to a full 40-character commit")
        else:
            replay_status = STATUS_BLOCKED_LOCAL_SOURCE
    elif ref_type == "named_ref":
        resolved_commit = named_ref_locks.get(ref_lock_key(repo, original_ref))
        if resolved_commit is None:
            replay_status = STATUS_BLOCKED_NAMED_REF
            blockers.append("named ref requires explicit local lockfile resolution")
        else:
            replay_status = STATUS_BLOCKED_LOCAL_SOURCE
    else:
        replay_status = STATUS_BLOCKED_UNSUPPORTED
        blockers.append("unsupported source ref type")

    local_source_path: str | None = None
    local_content_sha256: str | None = None
    if resolved_commit:
        local_path, digest, local_blockers = resolve_local_source(
            repo=repo,
            original_ref=original_ref,
            resolved_commit=resolved_commit,
            filepath=filepath,
            source_root=source_root,
            local_proofs=local_proofs,
        )
        blockers.extend(local_blockers)
        if local_path and digest:
            local_source_path = str(local_path)
            local_content_sha256 = digest
            replay_status = STATUS_IMMUTABLE_READY
        elif replay_status == STATUS_BLOCKED_LOCAL_SOURCE:
            blockers.append("immutable commit is known but local source proof is absent")

    return {
        "finding_id": finding_id(finding, finding_index),
        "title": finding_title(finding),
        "source_url": str(ref.get("url") or ""),
        "repo": repo,
        "original_ref": original_ref,
        "ref_type": ref_type,
        "resolved_commit": resolved_commit,
        "filepath": filepath,
        "local_source_path": local_source_path,
        "local_content_sha256": local_content_sha256,
        "replay_status": replay_status,
        "network_used": False,
        "blockers": blockers,
    }


def build_manifest(
    findings: list[dict[str, Any]],
    *,
    source_root: Path | None = None,
    named_ref_locks: dict[str, str] | None = None,
    local_proofs: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    locks = named_ref_locks or {}
    proofs = local_proofs or {}
    rows: list[dict[str, Any]] = []
    for index, finding in enumerate(findings, start=1):
        for ref in extract_source_refs(finding_content(finding)):
            rows.append(
                build_row(
                    ref=ref,
                    finding=finding,
                    finding_index=index,
                    source_root=source_root,
                    named_ref_locks=locks,
                    local_proofs=proofs,
                )
            )
    rows.sort(
        key=lambda row: (
            row["finding_id"],
            row["repo"],
            row["original_ref"],
            row["filepath"],
            row["source_url"],
        )
    )
    return {
        "schema": SCHEMA,
        "offline": True,
        "network_used": False,
        "row_count": len(rows),
        "rows": rows,
    }


def blocked_status_counts(manifest: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    rows = manifest.get("rows") if isinstance(manifest, dict) else []
    if not isinstance(rows, list):
        return counts
    for row in rows:
        if not isinstance(row, dict):
            continue
        status = str(row.get("replay_status") or "")
        if not status or status == STATUS_IMMUTABLE_READY:
            continue
        counts[status] = counts.get(status, 0) + 1
    return counts


def blocked_manifest_hints(blocked_counts: dict[str, int]) -> list[str]:
    hints: list[str] = []
    if blocked_counts.get(STATUS_BLOCKED_NAMED_REF) or blocked_counts.get(STATUS_BLOCKED_SHORT_SHA):
        hints.append(
            "provide --named-ref-lockfile with owner/repo@ref -> full 40-character commit mappings"
        )
    if blocked_counts.get(STATUS_BLOCKED_LOCAL_SOURCE):
        hints.append(
            "provide --local-source-root or --local-proof for the exact reviewed repo/commit/file bytes"
        )
    if blocked_counts.get(STATUS_BLOCKED_UNSUPPORTED):
        hints.append("fix unsupported source URLs before treating the manifest as replay-ready")
    return hints


def format_blocked_manifest_diagnostic(manifest: dict[str, Any]) -> str | None:
    blocked_counts = blocked_status_counts(manifest)
    if not blocked_counts:
        return None
    summary = ", ".join(
        f"{status}={count}" for status, count in sorted(blocked_counts.items())
    )
    lines = [
        "blocked replay manifest: downstream detector-gap/source-ref regeneration must stop",
        f"blocked rows: {summary}",
    ]
    for hint in blocked_manifest_hints(blocked_counts):
        lines.append(f"- {hint}")
    return "\n".join(lines)


def github_ref_from_manifest_row(row: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one manifest row into the detector_gap github_ref shape."""
    repo = str(row.get("repo") or "").strip()
    original_ref = str(row.get("original_ref") or "").strip()
    resolved_commit = str(row.get("resolved_commit") or "").strip()
    filepath = str(row.get("filepath") or "").strip()
    commit = resolved_commit or original_ref
    if not repo or not commit or not filepath:
        return None

    ref_type = str(row.get("ref_type") or "").strip()
    github_ref: dict[str, Any] = {
        "repo": repo,
        "commit": commit,
        "ref_type": "commit" if resolved_commit else ref_type,
        "filepath": filepath,
    }
    source_url = str(row.get("source_url") or "").strip()
    if source_url:
        github_ref["url"] = source_url
    if resolved_commit:
        github_ref["resolved_commit"] = resolved_commit
    if original_ref and original_ref != commit:
        github_ref["original_ref"] = original_ref
    for key in ("local_source_path", "local_content_sha256", "replay_status"):
        value = row.get(key)
        if value:
            github_ref[key] = value
    return github_ref


def _github_ref_rank(ref: dict[str, Any]) -> tuple[int, int, str, str, str]:
    commit = str(ref.get("commit") or "")
    return (
        1 if ref.get("local_source_path") and ref.get("local_content_sha256") else 0,
        1 if FULL_SHA_RE.fullmatch(commit) else 0,
        str(ref.get("repo") or ""),
        str(ref.get("filepath") or ""),
        str(ref.get("url") or ""),
    )


def manifest_github_refs_by_finding(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the best manifest-backed github_ref candidate per finding id."""
    manifest_rows = manifest.get("rows") if isinstance(manifest, dict) else []
    if not isinstance(manifest_rows, list):
        return {}

    refs: dict[str, dict[str, Any]] = {}
    ranks: dict[str, tuple[int, int, str, str, str]] = {}
    for row in manifest_rows:
        if not isinstance(row, dict) or not row.get("finding_id"):
            continue
        ref = github_ref_from_manifest_row(row)
        if ref is None:
            continue
        finding_id = str(row["finding_id"])
        rank = _github_ref_rank(ref)
        if finding_id not in refs or rank > ranks[finding_id]:
            refs[finding_id] = ref
            ranks[finding_id] = rank
    return refs


def _merge_manifest_github_ref(
    existing: Any,
    manifest_ref: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    if not isinstance(existing, dict) or not existing:
        return dict(manifest_ref), "filled"

    merged = dict(existing)
    before = dict(merged)
    existing_commit = str(existing.get("commit") or "")
    manifest_commit = str(manifest_ref.get("commit") or "")
    should_upgrade_commit = (
        bool(manifest_commit)
        and (
            not existing_commit
            or (
                not FULL_SHA_RE.fullmatch(existing_commit)
                and FULL_SHA_RE.fullmatch(manifest_commit)
            )
        )
    )

    for key, value in manifest_ref.items():
        if value in (None, ""):
            continue
        if key == "commit" and should_upgrade_commit:
            merged[key] = value
        elif key == "ref_type" and should_upgrade_commit:
            merged[key] = value
        elif key not in merged or merged.get(key) in (None, ""):
            merged[key] = value

    if merged == before:
        return merged, "unchanged"
    return merged, "upgraded"


def apply_manifest_github_refs(
    rows: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Fill or upgrade detector_gap github_ref values from a replay manifest."""
    refs_by_finding = manifest_github_refs_by_finding(manifest)
    filled = 0
    upgraded = 0
    unchanged = 0
    matched_finding_ids: set[str] = set()

    for row in rows:
        if not isinstance(row, dict) or row.get("finding_id") is None:
            continue
        finding_id = str(row["finding_id"])
        manifest_ref = refs_by_finding.get(finding_id)
        if manifest_ref is None:
            continue
        matched_finding_ids.add(finding_id)
        merged, action = _merge_manifest_github_ref(row.get("github_ref"), manifest_ref)
        row["github_ref"] = merged
        if action == "filled":
            filled += 1
        elif action == "upgraded":
            upgraded += 1
        else:
            unchanged += 1

    unmatched = sorted(set(refs_by_finding) - matched_finding_ids)
    return {
        "status": "applied",
        "detector_rows_seen": len(rows),
        "manifest_github_ref_finding_count": len(refs_by_finding),
        "filled_github_ref_count": filled,
        "upgraded_github_ref_count": upgraded,
        "unchanged_github_ref_count": unchanged,
        "unmatched_manifest_finding_ids": unmatched,
        "detector_rows_with_github_ref": sum(
            1 for row in rows if isinstance(row, dict) and row.get("github_ref")
        ),
    }


def detector_gap_source_ref_guard(
    rows: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Return a fail-closed guard status for detector_gap rows against a manifest."""
    manifest_rows = manifest.get("rows") if isinstance(manifest, dict) else []
    if not isinstance(manifest_rows, list):
        manifest_rows = []

    manifest_finding_ids = sorted(
        {
            str(row.get("finding_id"))
            for row in manifest_rows
            if isinstance(row, dict) and row.get("finding_id") and row.get("source_url")
        }
    )
    detector_rows_by_finding: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        finding_id = row.get("finding_id")
        if finding_id is not None:
            detector_rows_by_finding.setdefault(str(finding_id), []).append(row)

    missing = [
        finding_id
        for finding_id in manifest_finding_ids
        if not any(
            candidate.get("github_ref")
            for candidate in detector_rows_by_finding.get(finding_id, [])
        )
    ]
    return {
        "status": "blocked_detector_gap_missing_github_ref" if missing else "pass",
        "manifest_source_ref_finding_count": len(manifest_finding_ids),
        "detector_gap_missing_github_ref_finding_ids": missing,
    }


def enforce_detector_gap_source_refs(
    rows: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    guard = detector_gap_source_ref_guard(rows, manifest)
    if guard["status"] != "pass":
        sample = ", ".join(guard["detector_gap_missing_github_ref_finding_ids"][:10])
        raise RuntimeError(
            "source-ref preservation guard failed: detector_gap rows dropped "
            f"github_ref for manifest-backed findings: {sample}"
        )
    return guard


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a local-only replay manifest for GitHub source refs.",
        epilog=(
            "KLBQ-001 residual blocker:\n"
            "- Missing input: the exact 98-row Solodit findings export JSON/JSONL that fed "
            "reports/detector_gap.json.\n"
            "- When that export appears locally, rerun:\n"
            "  python3.13 tools/detector-blindspot-scan.py --data "
            "<absolute-path-to-solodit-findings-export.json> --max-findings 98\n"
            "- Regeneration must fail closed until then because historical detector_gap rows "
            "cannot safely recover github_ref without the original per-finding raw content."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", required=True, type=Path, help="Finding export JSON/JSONL.")
    parser.add_argument("--out", required=True, type=Path, help="Output manifest JSON path.")
    parser.add_argument(
        "--offline",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep the default local-only posture. --no-offline is rejected for now.",
    )
    parser.add_argument(
        "--named-ref-lockfile",
        type=Path,
        help="Local JSON/JSONL mapping owner/repo@ref to a full commit SHA.",
    )
    parser.add_argument(
        "--local-source-root",
        type=Path,
        help="Local root containing either filepath or repo/ref/filepath source copies.",
    )
    parser.add_argument(
        "--local-proof",
        type=Path,
        help="Local JSON/JSONL mapping repo@commit:filepath to path and optional SHA-256.",
    )
    parser.add_argument(
        "--allow-blocked-output",
        action="store_true",
        help=(
            "Write and keep a blocked manifest without failing the CLI. "
            "Default behavior is fail-closed when any row is not immutable_ready."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.offline:
        raise SystemExit("network resolution is not implemented; rerun with --offline")
    findings = load_finding_export(args.input)
    manifest = build_manifest(
        findings,
        source_root=args.local_source_root,
        named_ref_locks=load_named_ref_lockfile(args.named_ref_lockfile),
        local_proofs=load_local_proofs(args.local_proof),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    diagnostic = format_blocked_manifest_diagnostic(manifest)
    if diagnostic is not None:
        print(f"[source-ref-replay-manifest] BLOCKED rows={manifest['row_count']} out={args.out}")
        print(diagnostic, file=sys.stderr)
        if not args.allow_blocked_output:
            print(
                "rerun only after the exact Solodit export and reviewed source inputs exist locally, "
                "or pass --allow-blocked-output to keep the blocked manifest intentionally",
                file=sys.stderr,
            )
            return 2
    else:
        print(f"[source-ref-replay-manifest] OK rows={manifest['row_count']} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
