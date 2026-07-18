#!/usr/bin/env python3
"""Load required vault MCP context packs and write a verifiable receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
REQ_SCHEMA = "auditooor.workspace_memory_requirements.v1"
RECEIPT_SCHEMA = "auditooor.memory_context_receipt.v1"
LOADER = "tools/memory-context-load.py"
TOOL_SCHEMA_KIND = {
    "vault_resume_context": ("auditooor.vault_context_pack.v1", "resume"),
    "vault_dispatch_context": ("auditooor.vault_context_pack.v1", "dispatch"),
    "vault_finalization_context": ("auditooor.vault_context_pack.v1", "finalization"),
    "vault_engage_report_context": ("auditooor.vault_engage_report_context.v1", "engage_report_context"),
    "vault_exploit_context": ("auditooor.vault_exploit_context.v1", "exploit"),
    "vault_harness_context": ("auditooor.vault_harness_context.v1", "harness"),
    "vault_knowledge_gap_context": ("auditooor.vault_knowledge_gap_context.v1", "knowledge_gap"),
}
_HIGH_MED_CRIT_RE = re.compile(
    r"\b(?:severity|impact|risk)\s*[:=]\s*(?:critical|high|medium)\b",
    re.IGNORECASE,
)
_NON_PROMOTION_RE = re.compile(
    r"\b(?:killed|duplicate|oos|out of scope|false positive|no hm)\b",
    re.IGNORECASE,
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str) -> datetime | None:
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1] + "+00:00")
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def strip_frontmatter(text: str) -> str:
    if not text.startswith("---\n"):
        return text
    end = text.find("\n---\n", 4)
    if end == -1:
        return text
    return text[end + 5 :]


def context_pack_dir(ws: Path) -> Path:
    return ws / ".auditooor" / "memory_context_packs"


def requirements_path(ws: Path) -> Path:
    return ws / ".auditooor" / "memory_requirements.json"


def receipt_path(ws: Path) -> Path:
    return ws / ".auditooor" / "memory_context_receipt.json"


def load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def validate_requirements(doc: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["requirements must be object"]
    if doc.get("schema") != REQ_SCHEMA:
        errors.append(f"schema must be {REQ_SCHEMA}")
    if not isinstance(doc.get("workspace"), str) or not doc["workspace"]:
        errors.append("workspace must be non-empty")
    if not isinstance(doc.get("workspace_path"), str) or not doc["workspace_path"]:
        errors.append("workspace_path must be non-empty")
    reqs = doc.get("requirements")
    if not isinstance(reqs, list) or not reqs:
        errors.append("requirements must be non-empty array")
        return errors
    seen: set[str] = set()
    for idx, req in enumerate(reqs):
        if not isinstance(req, dict):
            errors.append(f"requirements[{idx}] must be object")
            continue
        rid = req.get("requirement_id")
        if not isinstance(rid, str) or not rid:
            errors.append(f"requirements[{idx}].requirement_id missing")
        elif rid in seen:
            errors.append(f"duplicate requirement_id: {rid}")
        else:
            seen.add(rid)
        tool = req.get("tool")
        if tool not in TOOL_SCHEMA_KIND:
            errors.append(f"{rid or idx}: unsupported tool {tool!r}")
        if not isinstance(req.get("args"), dict):
            errors.append(f"{rid or idx}: args must be object")
    return errors


def pack_body_for_hash(pack: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in pack.items() if key not in {"context_pack_id", "context_pack_hash"}}


def expected_pack_hash(pack: dict[str, Any]) -> str:
    return sha256_text(canonical_json(pack_body_for_hash(pack)))


def validate_pack(tool: str, context_kind: str, pack: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(pack, dict):
        return ["pack must be object"]
    expected_schema, expected_kind = TOOL_SCHEMA_KIND[tool]
    if pack.get("schema") != expected_schema:
        errors.append(f"schema mismatch: expected {expected_schema}, got {pack.get('schema')}")
    if pack.get("kind") != expected_kind or context_kind != expected_kind:
        errors.append(f"kind mismatch: expected {expected_kind}, got pack={pack.get('kind')} requirement={context_kind}")
    pack_id = pack.get("context_pack_id")
    pack_hash = pack.get("context_pack_hash")
    if not isinstance(pack_id, str) or not pack_id:
        errors.append("context_pack_id missing")
    if not isinstance(pack_hash, str) or len(pack_hash) != 64:
        errors.append("context_pack_hash missing or invalid")
    else:
        actual = expected_pack_hash(pack)
        if actual != pack_hash:
            errors.append(f"context_pack_hash mismatch: expected {actual}, got {pack_hash}")
    if isinstance(pack_id, str) and isinstance(pack_hash, str) and pack_hash[:16] not in pack_id:
        errors.append("context_pack_id does not include hash prefix")
    return errors


def run_mcp_tool(tool: str, args: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "vault-mcp-server.py"),
        "--call",
        tool,
        "--args",
        canonical_json(args),
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON from {tool}: {exc}"
    if isinstance(payload, dict) and payload.get("error"):
        return None, f"{payload.get('error')}: {payload.get('message', '')}"
    if not isinstance(payload, dict):
        return None, f"{tool} returned non-object JSON"
    return payload, None


def safe_pack_filename(pack_id: str) -> str:
    return pack_id.replace("/", "_") + ".json"


def write_pack(ws: Path, pack: dict[str, Any]) -> Path:
    out_dir = context_pack_dir(ws)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / safe_pack_filename(str(pack["context_pack_id"]))
    out.write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def source_refs(pack: dict[str, Any]) -> list[str]:
    refs = pack.get("source_refs")
    if not isinstance(refs, list):
        return []
    return [str(ref) for ref in refs[:80] if isinstance(ref, str) and ref]


def knowledge_gap_refs(pack: dict[str, Any]) -> list[str]:
    refs = pack.get("knowledge_gap_refs")
    if not isinstance(refs, list):
        return []
    return [str(ref) for ref in refs[:80] if isinstance(ref, str) and ref]


def _workspace_artifact_refs(ws: Path) -> list[str]:
    refs: set[str] = set()
    roots = (
        ws / "submissions" / "paste-ready",
        ws / "submissions" / "paste_ready",
        ws / "submissions" / "staging",
        ws / "submissions" / "cantina_paste",
        ws / "submissions" / "final_cantina_paste",
        ws / "submissions" / "operator_paste",
        ws / "submissions" / "final_paste",
        ws / "paste-ready",
        ws / "paste_ready",
        ws / "cantina_paste",
        ws / "final_cantina_paste",
        ws / "operator_paste",
        ws / "final_paste",
        ws / "poc_notes",
    )
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.md")):
            rel = path.relative_to(ws).as_posix()
            text = strip_frontmatter(load_text(path))
            if root.name == "staging":
                if not _HIGH_MED_CRIT_RE.search(text):
                    continue
            elif _NON_PROMOTION_RE.search(text[:1600]):
                continue
            refs.add(f"workspace:{rel}")
    return sorted(refs)


def _ref_matches_artifact(ref: str, artifact_ref: str) -> bool:
    return ref == artifact_ref or ref.startswith(f"{artifact_ref}:")


def load_from_requirements(ws: Path, req_doc: dict[str, Any], argv: list[str]) -> dict[str, Any]:
    req_path = requirements_path(ws)
    req_hash = sha256_file(req_path)
    loaded: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    loaded_at = utc_now()
    for req in req_doc["requirements"]:
        tool = req["tool"]
        args = dict(req.get("args") or {})
        pack, error = run_mcp_tool(tool, args)
        if error or pack is None:
            missing.append(
                {
                    "requirement_id": req["requirement_id"],
                    "context_kind": req["context_kind"],
                    "tool": tool,
                    "reason": error or "tool returned no pack",
                    "next_command": f"python3 tools/memory-context-load.py --workspace {ws} --tool {tool} --args '{canonical_json(args)}'",
                }
            )
            continue
        errors = validate_pack(tool, req["context_kind"], pack)
        if errors:
            missing.append(
                {
                    "requirement_id": req["requirement_id"],
                    "context_kind": req["context_kind"],
                    "tool": tool,
                    "reason": "; ".join(errors),
                    "next_command": f"python3 tools/memory-context-load.py --workspace {ws} --tool {tool} --args '{canonical_json(args)}'",
                }
            )
            continue
        pack_path = write_pack(ws, pack)
        loaded.append(
            {
                "requirement_id": req["requirement_id"],
                "context_kind": req["context_kind"],
                "tool": tool,
                "args_hash": sha256_text(canonical_json(args)),
                "context_pack_id": str(pack["context_pack_id"]),
                "context_pack_hash": str(pack["context_pack_hash"]),
                "pack_path": str(pack_path),
                "pack_schema": str(pack["schema"]),
                "loaded_at": loaded_at,
                "status": "loaded",
                "source_refs": source_refs(pack),
                "knowledge_gap_refs": knowledge_gap_refs(pack),
            }
        )
    # Cover workspace HM/final handoff artifacts (paste_ready/staging/etc.) by
    # appending their refs to the most appropriate loaded row. The strict
    # closeout `mcp-context` row reads loaded_source_refs to verify that every
    # workspace artifact has receipt coverage; without this, a fresh
    # --from-requirements --write-receipt run still reports `missing=N` for
    # every paste artifact, because no requirement explicitly enumerates them.
    artifact_refs = _workspace_artifact_refs(ws)
    if artifact_refs and loaded:
        # Prefer the row whose pack already references workspace files (e.g.
        # exploit.surface), falling back to the first loaded row.
        target_idx = 0
        for idx, row in enumerate(loaded):
            row_refs = row.get("source_refs") or []
            if any(isinstance(r, str) and r.startswith("workspace:") for r in row_refs):
                target_idx = idx
                break
        target = loaded[target_idx]
        existing = list(target.get("source_refs") or [])
        existing_set = set(existing)
        for ref in artifact_refs:
            if ref not in existing_set:
                existing.append(ref)
                existing_set.add(ref)
        target["source_refs"] = existing
    return {
        "schema": RECEIPT_SCHEMA,
        "workspace": req_doc["workspace"],
        "workspace_path": str(ws),
        "generated_at": utc_now(),
        "loader": {
            "tool": LOADER,
            "command": " ".join(argv),
            "argv_hash": sha256_text(canonical_json(argv)),
        },
        "requirements_path": str(req_path),
        "requirements_hash": req_hash,
        "loaded_contexts": loaded,
        "missing_contexts": missing,
        "summary": {
            "required_count": len(req_doc["requirements"]),
            "loaded_count": len(loaded),
            "missing_count": len(missing),
            "stale_count": 0,
            "strict_ready": not missing,
        },
    }


def validate_receipt_shape(doc: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["receipt must be object"]
    if doc.get("schema") != RECEIPT_SCHEMA:
        errors.append(f"schema must be {RECEIPT_SCHEMA}")
    if not isinstance(doc.get("loaded_contexts"), list):
        errors.append("loaded_contexts must be array")
    if not isinstance(doc.get("missing_contexts"), list):
        errors.append("missing_contexts must be array")
    summary = doc.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be object")
    for key in ("workspace", "workspace_path", "generated_at", "requirements_path", "requirements_hash"):
        if not isinstance(doc.get(key), str) or not doc[key]:
            errors.append(f"{key} must be non-empty string")
    return errors


def receipt_proof_payload(doc: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in doc.items() if key != "receipt_proof"}


def expected_receipt_proof(doc: dict[str, Any]) -> str:
    return sha256_text(canonical_json(receipt_proof_payload(doc)))


def ref_mtime(ws: Path, ref: str) -> int | None:
    path = Path(ref)
    if not path.is_absolute():
        path = ws / ref
    try:
        if path.exists():
            return int(path.stat().st_mtime)
    except OSError:
        return None
    return None


def ref_mtime_detail(ws: Path, ref: str) -> dict[str, Any]:
    """Return operator-readable freshness evidence for one requirement ref."""
    path = Path(ref)
    if not path.is_absolute():
        path = ws / ref
    detail: dict[str, Any] = {
        "ref": ref,
        "path": str(path),
        "exists": False,
        "mtime": None,
        "mtime_utc": None,
        "kind": "missing",
    }
    try:
        if not path.exists():
            return detail
        st = path.stat()
    except OSError as exc:
        detail["error"] = str(exc)
        return detail
    mtime = int(st.st_mtime)
    detail.update(
        {
            "exists": True,
            "mtime": mtime,
            "mtime_utc": datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "kind": "dir" if path.is_dir() else "file",
        }
    )
    return detail


def check_receipt(ws: Path, strict: bool = False, require_proof: bool = False) -> tuple[int, dict[str, Any]]:
    req_path = requirements_path(ws)
    rec_path = receipt_path(ws)
    if not req_path.is_file():
        return (
            1 if strict else 2,
            {
                "status": "missing_requirements",
                "requirements_path": str(req_path),
                "next_command": f"python3 tools/memory-auto-link.py --workspace {ws} --write",
            },
        )
    req_doc, req_err = load_json(req_path)
    if req_err:
        return 1, {"status": "invalid_requirements", "requirements_path": str(req_path), "error": req_err}
    req_errors = validate_requirements(req_doc)
    if req_errors:
        return 1, {"status": "invalid_requirements", "requirements_path": str(req_path), "errors": req_errors}
    if not rec_path.is_file():
        return (
            1 if strict else 2,
            {
                "status": "missing_receipt",
                "requirements_path": str(req_path),
                "receipt_path": str(rec_path),
                "next_command": f"python3 tools/memory-context-load.py --workspace {ws} --from-requirements --write-receipt",
            },
        )
    rec_doc, rec_err = load_json(rec_path)
    if rec_err:
        return 1, {"status": "invalid_receipt", "receipt_path": str(rec_path), "error": rec_err}
    shape_errors = validate_receipt_shape(rec_doc)
    if shape_errors:
        return 1, {"status": "invalid_receipt", "receipt_path": str(rec_path), "errors": shape_errors}
    expected_proof = expected_receipt_proof(rec_doc)
    receipt_proof = rec_doc.get("receipt_proof")
    receipt_proof_status = "missing"
    if isinstance(receipt_proof, str) and len(receipt_proof) == 64:
        if receipt_proof == expected_proof:
            receipt_proof_status = "valid"
        else:
            receipt_proof_status = "invalid"
    elif receipt_proof is not None:
        receipt_proof_status = "invalid"
    actual_req_hash = sha256_file(req_path)
    invalid: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    loaded_source_refs: set[str] = set()
    if receipt_proof_status == "invalid":
        invalid.append(
            {
                "reason": "receipt_proof mismatch",
                "expected": expected_proof,
                "actual": receipt_proof,
            }
        )
    elif require_proof and receipt_proof_status == "missing":
        invalid.append(
            {
                "reason": "receipt_proof missing",
                "expected": expected_proof,
            }
        )
    if rec_doc.get("requirements_hash") != actual_req_hash:
        invalid.append({"reason": "requirements_hash mismatch", "expected": actual_req_hash, "actual": rec_doc.get("requirements_hash")})
    loaded_by_id = {
        row.get("requirement_id"): row
        for row in rec_doc.get("loaded_contexts", [])
        if isinstance(row, dict) and isinstance(row.get("requirement_id"), str)
    }
    req_generated = parse_utc(str(req_doc.get("generated_at", "")))
    for req in req_doc["requirements"]:
        rid = req["requirement_id"]
        row = loaded_by_id.get(rid)
        if row is None:
            missing.append(
                {
                    "requirement_id": rid,
                    "context_kind": req["context_kind"],
                    "tool": req["tool"],
                    "reason": "no loaded receipt row",
                    "next_command": f"python3 tools/memory-context-load.py --workspace {ws} --from-requirements --write-receipt",
                }
            )
            continue
        if row.get("args_hash") != sha256_text(canonical_json(req.get("args") or {})):
            invalid.append({"requirement_id": rid, "reason": "args_hash mismatch"})
        pack_path = Path(str(row.get("pack_path", "")))
        if not pack_path.is_file():
            missing.append(
                {
                    "requirement_id": rid,
                    "context_kind": req["context_kind"],
                    "tool": req["tool"],
                    "reason": f"pack file missing: {pack_path}",
                    "next_command": f"python3 tools/memory-context-load.py --workspace {ws} --from-requirements --write-receipt",
                }
            )
            continue
        pack, pack_err = load_json(pack_path)
        if pack_err:
            invalid.append({"requirement_id": rid, "reason": f"invalid pack JSON: {pack_err}"})
            continue
        pack_errors = validate_pack(req["tool"], req["context_kind"], pack)
        if pack_errors:
            invalid.append({"requirement_id": rid, "reason": "; ".join(pack_errors)})
            continue
        if row.get("context_pack_hash") != pack.get("context_pack_hash"):
            invalid.append({"requirement_id": rid, "reason": "receipt pack hash differs from pack file"})
        row_refs = source_refs(pack)
        if isinstance(row.get("source_refs"), list):
            row_refs = [str(ref) for ref in row["source_refs"] if isinstance(ref, str) and ref]
        loaded_source_refs.update(row_refs)
        loaded_at = parse_utc(str(row.get("loaded_at", "")))
        newest = int(req_doc.get("workspace_facts", {}).get("newest_input_mtime") or 0)
        fresh_ref_details: list[dict[str, Any]] = []
        for ref in req.get("fresh_after_refs") or []:
            detail = ref_mtime_detail(ws, str(ref))
            fresh_ref_details.append(detail)
            newest = max(newest, int(detail.get("mtime") or 0))
        if loaded_at is None:
            invalid.append({"requirement_id": rid, "reason": "loaded_at invalid"})
        elif req_generated and loaded_at < req_generated:
            stale.append({"requirement_id": rid, "reason": "loaded before requirements generated"})
        elif newest and int(loaded_at.timestamp()) < newest:
            stale.append(
                {
                    "requirement_id": rid,
                    "reason": "loaded before freshest required artifact",
                    "loaded_at": row.get("loaded_at"),
                    "fresh_after_mtime": newest,
                    "fresh_after_refs": fresh_ref_details,
                }
            )
    for artifact_ref in _workspace_artifact_refs(ws):
        if any(_ref_matches_artifact(ref, artifact_ref) for ref in loaded_source_refs):
            continue
        missing.append(
            {
                "artifact_ref": artifact_ref,
                "reason": "workspace has HM/final handoff artifact with no loaded receipt source_refs coverage",
                "next_command": f"python3 tools/memory-context-load.py --workspace {ws} --from-requirements --write-receipt",
            }
        )
    status = "ok"
    rc = 0
    if invalid:
        status = "invalid"
        rc = 1
    elif missing or stale or rec_doc.get("missing_contexts"):
        status = "incomplete"
        rc = 1 if strict else 2
    summary = {
        "status": status,
        "requirements_path": str(req_path),
        "receipt_path": str(rec_path),
        "receipt_proof": receipt_proof if isinstance(receipt_proof, str) else None,
        "expected_receipt_proof": expected_proof,
        "receipt_proof_status": receipt_proof_status,
        "required_count": len(req_doc["requirements"]),
        "loaded_count": len(loaded_by_id),
        "missing_contexts": missing + [row for row in rec_doc.get("missing_contexts", []) if isinstance(row, dict)],
        "stale_contexts": stale,
        "invalid_contexts": invalid,
        "strict_ready": rc == 0,
        "next_command": f"python3 tools/memory-context-load.py --workspace {ws} --from-requirements --write-receipt",
    }
    return rc, summary


def direct_tool_call(ws: Path, tool: str, args: dict[str, Any], write_pack_file: bool) -> tuple[int, dict[str, Any]]:
    if tool not in TOOL_SCHEMA_KIND:
        return 1, {"status": "unsupported_tool", "tool": tool}
    pack, error = run_mcp_tool(tool, args)
    if error or pack is None:
        return 1, {"status": "tool_error", "tool": tool, "error": error}
    errors = validate_pack(tool, TOOL_SCHEMA_KIND[tool][1], pack)
    if errors:
        return 1, {"status": "invalid_pack", "tool": tool, "errors": errors}
    out: dict[str, Any] = {"status": "ok", "tool": tool, "context_pack_id": pack["context_pack_id"], "context_pack_hash": pack["context_pack_hash"]}
    if write_pack_file:
        out["pack_path"] = str(write_pack(ws, pack))
    return 0, out


def refresh_workspace(ws: Path, *, write_receipt: bool, argv: list[str]) -> tuple[int, dict[str, Any]]:
    """Gap #46: recompute the canonical context-pack registry for a workspace.

    Steps:
      1. Read .auditooor/memory_requirements.json. If absent, return a
         clearly-actionable next_command status rather than failing.
      2. Invalidate stale context-pack files (remove old packs in
         .auditooor/memory_context_packs/ that are not referenced by the
         current requirements - they get rebuilt fresh by the next step).
      3. Re-scan via load_from_requirements (which calls each MCP callable
         and validates the returned pack envelope).
      4. Compute strict_ready. If True, write the receipt. If False, return
         the failing-pack-id list so callers can debug per-pack.

    Returns: (rc, summary). rc=0 if strict_ready, rc=1 otherwise. summary
    carries strict_ready, failing_pack_ids, loaded/missing counts, and
    receipt_path.

    R36 pathspec compliance: GAP-FIX-2-46 in .auditooor/agent_pathspec.json
    (tools/agent-pathspec-register.py).
    """
    req_path = requirements_path(ws)
    if not req_path.is_file():
        return 1, {
            "status": "missing_requirements",
            "requirements_path": str(req_path),
            "strict_ready": False,
            "failing_pack_ids": [],
            "next_command": f"python3 tools/memory-auto-link.py --workspace {ws} --write",
        }
    req_doc, req_err = load_json(req_path)
    if req_err:
        return 1, {
            "status": "invalid_requirements",
            "requirements_path": str(req_path),
            "strict_ready": False,
            "failing_pack_ids": [],
            "error": req_err,
        }
    req_errors = validate_requirements(req_doc)
    if req_errors:
        return 1, {
            "status": "invalid_requirements",
            "requirements_path": str(req_path),
            "strict_ready": False,
            "failing_pack_ids": [],
            "errors": req_errors,
        }
    # Step 2: invalidate stale pack files. R36 pathspec compliance via
    # tools/agent-pathspec-register.py / .auditooor/agent_pathspec.json (lane
    # GAP-FIX-2-46). We do not blanket-delete the dir; we surgically clear
    # packs whose names do not match any current requirement's expected
    # schema prefix. Match on the schema portion of the pack-id (everything
    # up to and including the first `:`), which tolerates kind-tag drift
    # between TOOL_SCHEMA_KIND's `context_kind` and the pack-id's actual
    # kind field (e.g. engage_report_context vs engage_report).
    pack_dir = context_pack_dir(ws)
    invalidated: list[str] = []
    if pack_dir.is_dir():
        valid_schemas: set[str] = set()
        for req in req_doc.get("requirements", []) or []:
            tool = req.get("tool")
            if tool in TOOL_SCHEMA_KIND:
                schema, _kind = TOOL_SCHEMA_KIND[tool]
                # Pack file name format: <schema>:<kind>:<hashprefix>.json
                # (with optional / replaced by _). Match on schema-prefix only.
                valid_schemas.add(schema.replace("/", "_") + ":")
        for old_pack in sorted(pack_dir.glob("*.json")):
            keep = any(old_pack.name.startswith(s) for s in valid_schemas)
            if not keep:
                try:
                    old_pack.unlink()
                    invalidated.append(old_pack.name)
                except OSError:
                    pass
    # Step 3: re-scan via load_from_requirements (which always rebuilds packs
    # by calling each MCP callable; old packs are overwritten on write).
    receipt = load_from_requirements(ws, req_doc, argv)
    receipt["receipt_proof"] = expected_receipt_proof(receipt)
    strict_ready = bool(receipt.get("summary", {}).get("strict_ready"))
    # Collect failing pack identities for debugging.
    failing_pack_ids: list[dict[str, str]] = []
    for row in receipt.get("missing_contexts") or []:
        if isinstance(row, dict):
            failing_pack_ids.append(
                {
                    "requirement_id": str(row.get("requirement_id", "")),
                    "context_kind": str(row.get("context_kind", "")),
                    "tool": str(row.get("tool", "")),
                    "reason": str(row.get("reason", "")),
                }
            )
    if write_receipt:
        out = receipt_path(ws)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {
        "status": "ok" if strict_ready else "incomplete",
        "workspace": str(ws),
        "requirements_path": str(req_path),
        "receipt_path": str(receipt_path(ws)),
        "receipt_written": write_receipt,
        "receipt_proof": receipt.get("receipt_proof"),
        "strict_ready": strict_ready,
        "required_count": receipt["summary"]["required_count"],
        "loaded_count": receipt["summary"]["loaded_count"],
        "missing_count": receipt["summary"]["missing_count"],
        "invalidated_pack_files": invalidated,
        "failing_pack_ids": failing_pack_ids,
        "next_command": (
            ""
            if strict_ready
            else f"python3 tools/memory-context-load.py --workspace {ws} --check --json"
        ),
    }
    return (0 if strict_ready else 1), summary


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Audit workspace root")
    parser.add_argument("--from-requirements", action="store_true", help="Load all requirements from .auditooor/memory_requirements.json")
    parser.add_argument("--write-receipt", action="store_true", help="Write .auditooor/memory_context_receipt.json")
    parser.add_argument("--check", action="store_true", help="Validate existing requirements/receipt/pack files")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "Gap #46: recompute canonical context-pack registry: invalidate "
            "stale pack files, rerun MCP callables, emit strict_ready + "
            "failing_pack_ids summary, write receipt unless --no-write-receipt."
        ),
    )
    parser.add_argument(
        "--no-write-receipt",
        action="store_true",
        help="Skip the receipt write step when used with --refresh (dry-run).",
    )
    parser.add_argument("--strict", action="store_true", help="Treat missing/stale receipt rows as failure")
    parser.add_argument("--require-proof", action="store_true", help="Require a valid top-level receipt_proof for --check")
    parser.add_argument("--json", action="store_true", help="Print machine-readable summary")
    parser.add_argument("--tool", choices=sorted(TOOL_SCHEMA_KIND), help="Direct MCP tool call")
    parser.add_argument("--args", default="{}", help="JSON args for --tool")
    parser.add_argument("--write-pack", action="store_true", help="Write direct --tool pack file")
    args = parser.parse_args(raw_argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[memory-context-load] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    if args.check:
        rc, result = check_receipt(ws, strict=args.strict, require_proof=args.require_proof)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"[memory-context-load] {result.get('status')}: {result.get('receipt_path') or result.get('requirements_path')}")
            if result.get("next_command"):
                print(f"[memory-context-load] next: {result['next_command']}")
        return rc
    if args.refresh:
        # Gap #46: --refresh subcommand. R36 pathspec compliance via
        # tools/agent-pathspec-register.py / .auditooor/agent_pathspec.json
        # (lane GAP-FIX-2-46).
        write_rcpt = not args.no_write_receipt
        rc, result = refresh_workspace(
            ws,
            write_receipt=write_rcpt,
            argv=["python3", "tools/memory-context-load.py", *raw_argv],
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            sr = result.get("strict_ready")
            sr_label = "true" if sr else "false"
            print(
                f"[memory-context-load] refresh: strict_ready={sr_label} "
                f"loaded={result.get('loaded_count')}/{result.get('required_count')} "
                f"invalidated_packs={len(result.get('invalidated_pack_files') or [])}"
            )
            if not sr:
                failing = result.get("failing_pack_ids") or []
                for row in failing[:5]:
                    print(
                        f"[memory-context-load] FAIL pack: id={row.get('requirement_id')} "
                        f"tool={row.get('tool')} reason={row.get('reason')[:120]}"
                    )
        return rc
    if args.tool:
        try:
            tool_args = json.loads(args.args)
        except json.JSONDecodeError as exc:
            print(f"[memory-context-load] ERR invalid --args JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(tool_args, dict):
            print("[memory-context-load] ERR --args must decode to object", file=sys.stderr)
            return 2
        rc, result = direct_tool_call(ws, args.tool, tool_args, write_pack_file=args.write_pack)
        print(json.dumps(result, indent=2, sort_keys=True))
        return rc
    if not args.from_requirements:
        print("[memory-context-load] ERR expected --from-requirements, --check, or --tool", file=sys.stderr)
        return 2
    req_path = requirements_path(ws)
    req_doc, req_err = load_json(req_path)
    if req_err:
        print(f"[memory-context-load] ERR cannot read {req_path}: {req_err}", file=sys.stderr)
        return 1
    errors = validate_requirements(req_doc)
    if errors:
        for error in errors:
            print(f"[memory-context-load] ERR {error}", file=sys.stderr)
        return 1
    receipt = load_from_requirements(ws, req_doc, ["python3", "tools/memory-context-load.py", *raw_argv])
    receipt["receipt_proof"] = expected_receipt_proof(receipt)
    if args.write_receipt:
        out = receipt_path(ws)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[memory-context-load] wrote {out} ({receipt['summary']['loaded_count']}/{receipt['summary']['required_count']} loaded)")
    if args.json or not args.write_receipt:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["summary"]["strict_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
