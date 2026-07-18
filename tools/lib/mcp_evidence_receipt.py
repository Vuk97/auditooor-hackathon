"""Helpers for auditooor.mcp_evidence_receipt.v1 sidecars.

The receipt binds an MCP-derived context pack to the local worker packet that
consumed it. It is intentionally small: enough structure for dispatch gates to
fail closed without loading large packet bodies.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA = "auditooor.mcp_evidence_receipt.v1"
LEGACY_SCHEMA = "mcp_evidence_receipt.v1"
SCHEMA_VALUES = {SCHEMA, LEGACY_SCHEMA}

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
CALLABLE_RE = re.compile(r"^[a-z][a-z0-9_]*$")

REQUIRED_FIELDS = (
    "schema",
    "callable",
    "args_hash",
    "workspace",
    "repo_sha",
    "source_file_hashes",
    "corpus_index_hash",
    "context_pack_id",
    "context_pack_hash",
    "output_artifact_hash",
    "timestamp",
    "consumer_packet_hash",
    "required_call_set",
    "receipt_proof",
)


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def file_sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _repo_sha(workspace: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    sha = proc.stdout.strip()
    return sha if proc.returncode == 0 and HEX40_RE.fullmatch(sha) else "unknown"


def _corpus_index_hash(repo_root: Path | None = None) -> str:
    root = repo_root or Path(__file__).resolve().parents[2]
    manifest = root / "audit" / "corpus_tags" / "index" / "manifest.json"
    if not manifest.is_file():
        return "missing"
    try:
        return file_sha256(manifest)
    except OSError:
        return "missing"


def normalize_source_hashes(rows: Sequence[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows or []:
        path = str(row.get("path") or row.get("input_ref") or row.get("resolved_path") or "").strip()
        sha = str(row.get("sha256") or row.get("source_sha256") or "").strip().lower()
        if not path or not HEX64_RE.fullmatch(sha):
            continue
        marker = (path, sha)
        if marker in seen:
            continue
        seen.add(marker)
        out.append({"path": path, "sha256": sha})
    return out


def build_receipt(
    *,
    callable_name: str,
    workspace: Path,
    context_pack_id: str,
    context_pack_hash: str,
    consumer_packet_hash: str,
    output_artifact_hash: str,
    source_file_hashes: Sequence[dict[str, Any]] | None = None,
    required_call_set: Iterable[str] | None = None,
    args: Any | None = None,
    repo_sha: str | None = None,
    corpus_index_hash: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    calls = [str(call).strip() for call in (required_call_set or []) if str(call).strip()]
    if callable_name and callable_name not in calls:
        calls.insert(0, callable_name)
    receipt = {
        "schema": SCHEMA,
        "callable": str(callable_name or "").strip(),
        "args_hash": stable_hash(args or {}),
        "workspace": str(workspace.expanduser().resolve(strict=False)),
        "repo_sha": repo_sha or _repo_sha(workspace.expanduser().resolve(strict=False)),
        "source_file_hashes": normalize_source_hashes(source_file_hashes),
        "corpus_index_hash": corpus_index_hash or _corpus_index_hash(),
        "context_pack_id": str(context_pack_id or "").strip(),
        "context_pack_hash": str(context_pack_hash or "").strip().lower(),
        "output_artifact_hash": str(output_artifact_hash or "").strip().lower(),
        "timestamp": timestamp or utc_now(),
        "consumer_packet_hash": str(consumer_packet_hash or "").strip().lower(),
        "required_call_set": sorted(set(calls)),
    }
    receipt["receipt_proof"] = stable_hash(receipt)
    return receipt


def validate_receipt(
    receipt: Any,
    *,
    workspace: Path | None = None,
    consumer_packet_hash: str | None = None,
    required_call_set: Iterable[str] | None = None,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(receipt, dict):
        return False, ["receipt_not_json_object"]
    for field in REQUIRED_FIELDS:
        if field not in receipt:
            errors.append(f"missing_{field}")
    if errors:
        return False, errors

    schema = receipt.get("schema")
    if schema not in SCHEMA_VALUES:
        errors.append("invalid_schema")
    callable_name = str(receipt.get("callable") or "")
    if not CALLABLE_RE.fullmatch(callable_name):
        errors.append("invalid_callable")
    for key in ("args_hash", "context_pack_hash", "output_artifact_hash", "consumer_packet_hash"):
        value = str(receipt.get(key) or "")
        if not HEX64_RE.fullmatch(value):
            errors.append(f"invalid_{key}")
    repo_sha = str(receipt.get("repo_sha") or "")
    if repo_sha != "unknown" and not HEX40_RE.fullmatch(repo_sha):
        errors.append("invalid_repo_sha")
    corpus_hash = str(receipt.get("corpus_index_hash") or "")
    if corpus_hash != "missing" and not HEX64_RE.fullmatch(corpus_hash):
        errors.append("invalid_corpus_index_hash")
    if not str(receipt.get("context_pack_id") or "").strip():
        errors.append("missing_context_pack_id")
    if not str(receipt.get("timestamp") or "").strip():
        errors.append("missing_timestamp")
    if not isinstance(receipt.get("source_file_hashes"), list):
        errors.append("invalid_source_file_hashes")
    else:
        for idx, row in enumerate(receipt.get("source_file_hashes") or []):
            if not isinstance(row, dict):
                errors.append(f"invalid_source_file_hashes_{idx}")
                continue
            if not str(row.get("path") or "").strip():
                errors.append(f"missing_source_path_{idx}")
            if not HEX64_RE.fullmatch(str(row.get("sha256") or "")):
                errors.append(f"invalid_source_sha256_{idx}")
    calls = receipt.get("required_call_set")
    if not isinstance(calls, list) or not calls:
        errors.append("invalid_required_call_set")
    else:
        for call in calls:
            if not isinstance(call, str) or not CALLABLE_RE.fullmatch(call):
                errors.append("invalid_required_call")
                break
    proof = str(receipt.get("receipt_proof") or "")
    if not HEX64_RE.fullmatch(proof):
        errors.append("invalid_receipt_proof")
    else:
        body = dict(receipt)
        body.pop("receipt_proof", None)
        if stable_hash(body) != proof:
            errors.append("receipt_proof_mismatch")

    if workspace is not None:
        expected = str(workspace.expanduser().resolve(strict=False))
        actual = str(receipt.get("workspace") or "")
        if actual != expected:
            errors.append("workspace_mismatch")
    if consumer_packet_hash is not None:
        if str(receipt.get("consumer_packet_hash") or "") != consumer_packet_hash:
            errors.append("consumer_packet_hash_mismatch")
    required = {str(call).strip() for call in (required_call_set or []) if str(call).strip()}
    if required:
        present = {str(call) for call in (calls or [])}
        missing = sorted(required - present)
        if missing:
            errors.append("missing_required_calls:" + ",".join(missing))
    return not errors, errors


def validate_receipt_file(
    path: Path,
    *,
    workspace: Path | None = None,
    consumer_packet_hash: str | None = None,
    required_call_set: Iterable[str] | None = None,
) -> tuple[bool, list[str], dict[str, Any] | None]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False, ["receipt_file_missing"], None
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"receipt_file_unreadable:{exc}"], None
    ok, errors = validate_receipt(
        receipt,
        workspace=workspace,
        consumer_packet_hash=consumer_packet_hash,
        required_call_set=required_call_set,
    )
    return ok, errors, receipt if isinstance(receipt, dict) else None

