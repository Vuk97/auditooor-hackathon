#!/usr/bin/env python3
"""Persist the expensive Hackerman chain-unify payload.

The chain-candidates sidecar avoids reparsing corpus YAML, but
`hackerman-chain-unify.py` still has to build edges and enumerate DFS chains on
every MCP call. This sidecar caches the final ranked chain payload so
`vault_hackerman_chain_candidates` can answer from disk when inputs are fresh.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hackerman_query_common import (  # noqa: E402
    DEFAULT_TAGS_DIR,
    corpus_content_fingerprint,
    load_query_module,
    utc_now,
)


SIDECAR_SCHEMA = "auditooor.hackerman_chain_unify_payload_sidecar.v1"
META_SCHEMA = "auditooor.hackerman_chain_unify_payload_sidecar.meta.v1"
DEFAULT_SIDECAR_NAME = "chain_unify_payload.json"
DEFAULT_MAX_CHAINS_PER_SCOPE = 2_000


def _load_unify_tool() -> Any:
    return load_query_module("hackerman-chain-unify.py", "_w610_hcu_sidecar_unify")


def _load_chain_sidecar_tool() -> Any:
    return load_query_module(
        "hackerman-chain-candidates-sidecar.py", "_w610_hcu_sidecar_candidates"
    )


def _default_sidecar_path(tag_dir: Path) -> Path:
    return tag_dir.parent / "derived" / DEFAULT_SIDECAR_NAME


def _default_chain_sidecar_path(tag_dir: Path) -> Path:
    return tag_dir.parent / "derived" / "chain_candidates.jsonl"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_descriptor(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"path": "", "exists": False, "sha256": "", "size": 0}
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        return {"path": str(resolved), "exists": False, "sha256": "", "size": 0}
    return {
        "path": str(resolved),
        "exists": True,
        "sha256": _sha256_file(resolved),
        "size": resolved.stat().st_size,
    }


def _chain_sidecar_manifest_path(chain_sidecar_path: Path) -> Path:
    """Return the manifest path for a given chain-candidates sidecar path."""
    return chain_sidecar_path.with_name(f"{chain_sidecar_path.stem}.manifest.json")


def _chain_sidecar_is_sharded(chain_sidecar_path: Path) -> bool:
    """Return True when the sharded manifest exists (preferred over monolith)."""
    return _chain_sidecar_manifest_path(chain_sidecar_path).is_file()


def _chain_sidecar_stable_path(chain_sidecar_path: Path) -> Path:
    """Return the canonical entrypoint path: manifest if sharded, else monolith."""
    manifest = _chain_sidecar_manifest_path(chain_sidecar_path)
    if manifest.is_file():
        return manifest
    return chain_sidecar_path


def _load_chain_sidecar_meta(chain_sidecar_path: Path) -> dict[str, Any]:
    """Load the meta header from either a sharded manifest or a monolith sidecar."""
    manifest_path = _chain_sidecar_manifest_path(chain_sidecar_path)
    if manifest_path.is_file():
        # Sharded layout: manifest is a single JSON object (the meta).
        doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("chain-candidates sidecar manifest is not a mapping")
        return doc
    if not chain_sidecar_path.is_file():
        raise ValueError(f"chain-candidates sidecar not found: {chain_sidecar_path}")
    # Monolith layout: first non-empty line is the meta header.
    with chain_sidecar_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            doc = json.loads(line)
            if not isinstance(doc, dict):
                raise ValueError("chain-candidates sidecar meta is not a mapping")
            return doc
    raise ValueError("chain-candidates sidecar is empty")


def _expected_meta(
    tag_dir: Path,
    chain_sidecar_path: Path,
    max_hops: int,
    predicate_jsonl: Path | None,
    cache_limit: int,
    max_chains_per_scope: int | None,
) -> dict[str, Any]:
    unify_mod = _load_unify_tool()
    tag_dir = tag_dir.expanduser().resolve()
    chain_sidecar_path = chain_sidecar_path.expanduser().resolve()
    chain_meta = _load_chain_sidecar_meta(chain_sidecar_path)
    corpus_fingerprint, corpus_file_count = corpus_content_fingerprint(tag_dir, recursive=True)
    return {
        "schema_version": META_SCHEMA,
        "sidecar_schema": SIDECAR_SCHEMA,
        "tag_dir": str(tag_dir),
        "corpus_fingerprint": corpus_fingerprint,
        "corpus_file_count": corpus_file_count,
        "chain_candidates_sidecar_path": str(chain_sidecar_path),
        "chain_candidates_sidecar_sha256": _sha256_file(_chain_sidecar_stable_path(chain_sidecar_path)),
        "chain_candidates_meta_schema": str(chain_meta.get("schema_version") or ""),
        "chain_candidates_sidecar_schema": str(chain_meta.get("sidecar_schema") or ""),
        "chain_candidates_corpus_fingerprint": str(chain_meta.get("corpus_fingerprint") or ""),
        "chain_candidates_corpus_file_count": int(chain_meta.get("corpus_file_count") or 0),
        "chain_candidates_records_emitted": int(chain_meta.get("records_emitted") or 0),
        "chain_unify_schema": str(getattr(unify_mod, "SCHEMA", "")),
        "chain_unify_tool_sha256": _sha256_file(TOOLS_DIR / "hackerman-chain-unify.py"),
        "sidecar_tool_sha256": _sha256_file(Path(__file__).resolve()),
        "max_hops": int(max_hops),
        "cache_limit": int(cache_limit),
        "max_chains_per_scope": max_chains_per_scope,
        "predicate_jsonl": _file_descriptor(predicate_jsonl),
    }


def _compare_meta(expected: dict[str, Any], actual: dict[str, Any], min_limit: int) -> tuple[bool, str]:
    if actual.get("schema_version") != META_SCHEMA:
        return False, "sidecar meta schema changed"
    if actual.get("sidecar_schema") != SIDECAR_SCHEMA:
        return False, "sidecar payload schema changed"
    if int(actual.get("cache_limit") or 0) < min_limit:
        return False, "cache limit below requested limit"
    for key in (
        "tag_dir",
        "corpus_fingerprint",
        "corpus_file_count",
        "chain_candidates_sidecar_path",
        "chain_candidates_sidecar_sha256",
        "chain_candidates_meta_schema",
        "chain_candidates_sidecar_schema",
        "chain_candidates_corpus_fingerprint",
        "chain_candidates_corpus_file_count",
        "chain_candidates_records_emitted",
        "chain_unify_schema",
        "chain_unify_tool_sha256",
        "sidecar_tool_sha256",
        "max_hops",
        "max_chains_per_scope",
        "predicate_jsonl",
    ):
        if actual.get(key) != expected.get(key):
            return False, f"{key} changed"
    return True, "fresh"


def load_sidecar(sidecar_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return `(meta, payload)` or raise `ValueError`."""
    if not sidecar_path.is_file():
        raise ValueError(f"sidecar not found: {sidecar_path}")
    try:
        doc = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"sidecar unreadable: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema_version") != META_SCHEMA:
        raise ValueError("sidecar meta header missing or wrong schema")
    if doc.get("sidecar_schema") != SIDECAR_SCHEMA:
        raise ValueError("sidecar payload schema missing or wrong schema")
    meta = doc.get("meta")
    payload = doc.get("payload")
    if not isinstance(meta, dict) or not isinstance(payload, dict):
        raise ValueError("sidecar missing meta or payload mapping")
    return meta, payload


def sidecar_is_fresh(
    tag_dir: Path,
    sidecar_path: Path,
    *,
    chain_sidecar_path: Path | None = None,
    max_hops: int = 4,
    max_chains_per_scope: int | None = None,
    predicate_jsonl: Path | None = None,
    min_limit: int = 1,
) -> tuple[bool, str]:
    try:
        actual, _ = load_sidecar(sidecar_path)
        unify_mod = _load_unify_tool()
        expected = _expected_meta(
            tag_dir,
            chain_sidecar_path or _default_chain_sidecar_path(tag_dir),
            unify_mod.clamp_hops(max_hops),
            predicate_jsonl,
            int(actual.get("cache_limit") or 0),
            unify_mod.clamp_chains_per_scope(max_chains_per_scope)
            if max_chains_per_scope is not None
            else actual.get("max_chains_per_scope"),
        )
        return _compare_meta(expected, actual, min_limit)
    except Exception as exc:
        return False, f"sidecar unreadable: {exc}"


def _slice_payload(
    payload: dict[str, Any],
    limit: int,
    *,
    sidecar_used: bool,
    sidecar_path: Path,
    sidecar_status: str,
    sidecar_reason: str,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    unify_mod = _load_unify_tool()
    limit = unify_mod.clamp_limit(limit)
    out = copy.deepcopy(payload)
    chains = [copy.deepcopy(row) for row in list(payload.get("chains") or [])[:limit]]
    for rank, chain in enumerate(chains, start=1):
        chain["rank"] = rank
    out["limit"] = limit
    out["chains"] = chains
    digest = unify_mod.stable_hash(
        {
            "schema": out.get("schema") or getattr(unify_mod, "SCHEMA", ""),
            "tag_dir": str(out.get("source_tag_dir") or ""),
            "chains": [(c.get("chain_id"), c.get("score")) for c in chains],
        },
        64,
    )
    out["context_pack_id"] = f"{out.get('schema') or getattr(unify_mod, 'SCHEMA', '')}:{digest[:16]}"
    out["context_pack_hash"] = digest
    out["chain_unify_payload_sidecar_used"] = bool(sidecar_used)
    out["chain_unify_payload_sidecar_path"] = str(sidecar_path)
    out["chain_unify_payload_sidecar_status"] = sidecar_status
    out["chain_unify_payload_sidecar_reason"] = sidecar_reason
    out["chain_unify_payload_sidecar_schema"] = SIDECAR_SCHEMA if sidecar_used else ""
    out["chain_unify_payload_cache_limit"] = int((meta or {}).get("cache_limit") or 0)
    return out


def build_sidecar(
    tag_dir: Path,
    out_path: Path,
    *,
    chain_sidecar_path: Path | None = None,
    max_hops: int = 4,
    predicate_jsonl: Path | None = None,
    cache_limit: int | None = None,
    max_chains_per_scope: int | None = DEFAULT_MAX_CHAINS_PER_SCOPE,
) -> dict[str, Any]:
    """Build and atomically write the cached unified-chain payload."""
    unify_mod = _load_unify_tool()
    chain_mod = _load_chain_sidecar_tool()
    tag_dir = tag_dir.expanduser().resolve()
    out_path = out_path.expanduser().resolve()
    chain_sidecar_path = (chain_sidecar_path or _default_chain_sidecar_path(tag_dir)).expanduser().resolve()
    max_hops = unify_mod.clamp_hops(max_hops)
    max_chains_per_scope = unify_mod.clamp_chains_per_scope(max_chains_per_scope)
    cache_limit = unify_mod.clamp_limit(
        cache_limit if cache_limit is not None else getattr(unify_mod, "MAX_LIMIT", 100)
    )
    if cache_limit <= 0:
        cache_limit = getattr(unify_mod, "MAX_LIMIT", 100)
    meta = _expected_meta(
        tag_dir,
        chain_sidecar_path,
        max_hops,
        predicate_jsonl,
        cache_limit,
        max_chains_per_scope,
    )
    _, rows = chain_mod.load_sidecar(chain_sidecar_path)
    payload = unify_mod.build_payload_from_chain_candidate_rows(
        tag_dir,
        [row for row in rows if isinstance(row, dict)],
        cache_limit,
        max_hops,
        predicate_jsonl=predicate_jsonl,
        max_chains_per_scope=max_chains_per_scope,
    )
    meta.update(
        {
            "generated_at_utc": utc_now(),
            "records_loaded": int(payload.get("total_records_loaded") or 0),
            "chainable_steps": int(payload.get("chainable_steps") or 0),
            "unchainable_steps": int(payload.get("unchainable_steps") or 0),
            "total_chains": int(payload.get("total_chains") or 0),
        }
    )
    doc = {
        "schema_version": META_SCHEMA,
        "sidecar_schema": SIDECAR_SCHEMA,
        "meta": meta,
        "payload": payload,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_name(f".{out_path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(out_path)
    return meta


def _fallback_payload(
    tag_dir: Path,
    chain_sidecar_path: Path,
    limit: int,
    max_hops: int,
    predicate_jsonl: Path | None,
    sidecar_path: Path,
    reason: str,
    max_chains_per_scope: int | None,
) -> dict[str, Any]:
    unify_mod = _load_unify_tool()
    chain_mod = _load_chain_sidecar_tool()
    try:
        fresh, chain_reason = chain_mod.sidecar_is_fresh(tag_dir, chain_sidecar_path)
        if fresh:
            _, rows = chain_mod.load_sidecar(chain_sidecar_path)
            payload = unify_mod.build_payload_from_chain_candidate_rows(
                tag_dir,
                [row for row in rows if isinstance(row, dict)],
                limit,
                max_hops,
                predicate_jsonl=predicate_jsonl,
                max_chains_per_scope=max_chains_per_scope,
            )
        else:
            payload = unify_mod.build_payload(
                tag_dir,
                limit,
                max_hops,
                predicate_jsonl=predicate_jsonl,
                max_chains_per_scope=max_chains_per_scope,
            )
            reason = f"{reason}; chain-candidates sidecar not fresh: {chain_reason}"
    except Exception as exc:
        payload = unify_mod.build_payload(
            tag_dir,
            limit,
            max_hops,
            predicate_jsonl=predicate_jsonl,
            max_chains_per_scope=max_chains_per_scope,
        )
        reason = f"{reason}; chain-candidates sidecar fallback failed: {exc}"
    return _slice_payload(
        payload,
        limit,
        sidecar_used=False,
        sidecar_path=sidecar_path,
        sidecar_status="fallback",
        sidecar_reason=reason,
    )


def load_unify_summary(
    tag_dir: Path,
    *,
    chain_sidecar_path: Path | None = None,
    sidecar_path: Path | None = None,
    allow_slow_fallback: bool = True,
    limit: int = 20,
    max_hops: int = 4,
    predicate_jsonl: Path | None = None,
    max_chains_per_scope: int | None = DEFAULT_MAX_CHAINS_PER_SCOPE,
) -> dict[str, Any]:
    """Load cached chain-unify output, falling back to a live build when needed."""
    unify_mod = _load_unify_tool()
    tag_dir = tag_dir.expanduser().resolve()
    chain_sidecar_path = (chain_sidecar_path or _default_chain_sidecar_path(tag_dir)).expanduser().resolve()
    sidecar_path = (sidecar_path or _default_sidecar_path(tag_dir)).expanduser().resolve()
    limit = unify_mod.clamp_limit(limit)
    max_hops = unify_mod.clamp_hops(max_hops)
    max_chains_per_scope = unify_mod.clamp_chains_per_scope(max_chains_per_scope)
    fresh, reason = sidecar_is_fresh(
        tag_dir,
        sidecar_path,
        chain_sidecar_path=chain_sidecar_path,
        max_hops=max_hops,
        predicate_jsonl=predicate_jsonl,
        max_chains_per_scope=max_chains_per_scope,
        min_limit=limit,
    )
    if fresh:
        meta, payload = load_sidecar(sidecar_path)
        return _slice_payload(
            payload,
            limit,
            sidecar_used=True,
            sidecar_path=sidecar_path,
            sidecar_status="fresh",
            sidecar_reason=reason,
            meta=meta,
        )
    if not allow_slow_fallback:
        raise ValueError(f"chain-unify sidecar not usable ({reason}) and slow fallback disabled")
    return _fallback_payload(
        tag_dir,
        chain_sidecar_path,
        limit,
        max_hops,
        predicate_jsonl,
        sidecar_path,
        reason,
        max_chains_per_scope,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--chain-sidecar", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--max-hops", type=int, default=4)
    parser.add_argument("--cache-limit", type=int, default=100)
    parser.add_argument(
        "--max-chains-per-scope",
        type=int,
        default=DEFAULT_MAX_CHAINS_PER_SCOPE,
        help="Bound raw chain enumeration per scope during sidecar build.",
    )
    parser.add_argument("--predicates", default=None)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2
    out_path = (
        Path(args.out).expanduser().resolve()
        if args.out
        else _default_sidecar_path(tag_dir).expanduser().resolve()
    )
    chain_sidecar = (
        Path(args.chain_sidecar).expanduser().resolve()
        if args.chain_sidecar
        else _default_chain_sidecar_path(tag_dir).expanduser().resolve()
    )
    predicate_jsonl = Path(args.predicates).expanduser().resolve() if args.predicates else None
    if args.check:
        fresh, reason = sidecar_is_fresh(
            tag_dir,
            out_path,
            chain_sidecar_path=chain_sidecar,
            max_hops=args.max_hops,
            max_chains_per_scope=args.max_chains_per_scope,
            predicate_jsonl=predicate_jsonl,
            min_limit=1,
        )
        result = {"fresh": fresh, "reason": reason, "sidecar_path": str(out_path)}
        if args.json:
            print(json.dumps(result, sort_keys=True))
        else:
            print(f"{'FRESH' if fresh else 'STALE'}: {reason} ({out_path})")
        return 0 if fresh else 1

    try:
        meta = build_sidecar(
            tag_dir,
            out_path,
            chain_sidecar_path=chain_sidecar,
            max_hops=args.max_hops,
            predicate_jsonl=predicate_jsonl,
            cache_limit=args.cache_limit,
            max_chains_per_scope=args.max_chains_per_scope,
        )
    except Exception as exc:
        print(f"failed to build chain-unify sidecar: {exc}", file=sys.stderr)
        return 2
    result = {
        "built": True,
        "sidecar_path": str(out_path),
        "chain_candidates_sidecar_path": str(chain_sidecar),
        "cache_limit": meta.get("cache_limit"),
        "max_hops": meta.get("max_hops"),
        "max_chains_per_scope": meta.get("max_chains_per_scope"),
        "total_chains": meta.get("total_chains"),
        "chainable_steps": meta.get("chainable_steps"),
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"built chain-unify sidecar: chains={result['total_chains']} "
            f"cache_limit={result['cache_limit']} max_hops={result['max_hops']} -> {out_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
