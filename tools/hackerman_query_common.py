#!/usr/bin/env python3
"""Shared index-backed helpers for the initial hackerman query CLIs."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_DERIVED_DIR = REPO_ROOT / "audit" / "corpus_tags" / "derived"
DEFAULT_CROSS_LANGUAGE_ANALOGUES_SIDECAR = DEFAULT_DERIVED_DIR / "cross_language_analogues.jsonl"
DEFAULT_RECORD_QUALITY_SIDECAR = DEFAULT_DERIVED_DIR / "record_quality.jsonl"
DEFAULT_PROOF_HARDENING_SIDECAR = DEFAULT_DERIVED_DIR / "proof_hardening.jsonl"
FUNCTION_MINDSET_TOOL_PATH = REPO_ROOT / "tools" / "function-mindset.py"
EXCLUDED_CORPUS_SUBTREE_PREFIXES = ("_QUARANTINE_", "_deprecated")
RECORD_TIER_WEIGHTS = {
    "dydx-filed": 5.0,
    "mezo-filed": 4.8,
    "submission-derived": 4.5,
    "local-workspace": 4.0,
    # Wave-2 PR-A follow-up (2026-05-16): real-source CVE/GHSA miners (e.g.
    # PR-B Vyper-CVE rebuilder commit a428d287c4) manually verify a single
    # advisory against the official NVD/GHSA pages at miner-build time and
    # emit this canonical provenance value. Ranks above the heuristic
    # public-archive tier and just below local-workspace.
    "tier-1-officially-disclosed": 3.6,
    # W2.7.a (2026-05-16) addition: off-GitHub-mined records (Immunefi
    # dashboard / Medium feed / public-archive PDFs) emit this single
    # canonical record_tier rather than the legacy public-corpus +
    # sibling-verification_tier two-field workaround. Weight ranks above
    # raw public-corpus (verified provenance) but below local-workspace
    # (workspace-derived artifacts retain higher trust).
    "tier-2-verified-public-archive": 3.0,
    "public-corpus": 2.0,
}
SAFE_PROOF_ARTIFACT_PATH_RE = re.compile(
    r"^(?![A-Za-z][A-Za-z0-9+.-]*://)(?!/)(?!\.\.?/)(?![A-Za-z]:[\\/])"
    r"(?!\\\\)(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$"
)
_FUNCTION_MINDSET_MODULE = None
_FUNCTION_MINDSET_PAYLOAD_CACHE: dict[tuple[str, str, str, str, str, int], dict[str, Any]] = {}


@dataclass(frozen=True)
class CorpusRecordPath:
    path: Path
    relative_path: str


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def safe_proof_artifact_path(value: Any) -> str:
    text = str(value or "").strip().strip("'\"").replace("\\", "/")
    return text if SAFE_PROOF_ARTIFACT_PATH_RE.match(text) else ""


def corpus_record_relative_path(path: Path, tag_dir: Path) -> str:
    try:
        rel = path.relative_to(tag_dir)
    except ValueError:
        rel = path
    return rel.as_posix()


def is_excluded_corpus_record_path(path: Path, tag_dir: Path) -> bool:
    try:
        rel = path.relative_to(tag_dir)
    except ValueError:
        return False
    if not rel.parts:
        return False
    return rel.parts[0].startswith(EXCLUDED_CORPUS_SUBTREE_PREFIXES)


def iter_corpus_record_paths(
    tag_dir: Path,
    *,
    include_excluded: bool = False,
) -> Iterable[CorpusRecordPath]:
    """Yield corpus record files using the index-builder traversal order.

    Mirrors ``tools/hackerman-index-build.py``: recursive ``record.yaml`` first,
    JSON-only ``record.json`` second, then recursive non-``record.yaml`` YAML/YML
    files. Directories with both ``record.yaml`` and ``record.json`` use YAML as
    canonical. Quarantine/deprecated subtrees are skipped unless requested.
    """
    if not tag_dir.exists():
        return

    structured_yaml_paths = sorted(
        p for p in tag_dir.rglob("record.yaml") if p.is_file()
    )
    structured_yaml_parents = {p.parent for p in structured_yaml_paths}
    structured_json_paths = [
        p
        for p in sorted(tag_dir.rglob("record.json"))
        if p.is_file() and p.parent not in structured_yaml_parents
    ]
    flat_paths = [
        p
        for p in sorted(list(tag_dir.rglob("*.yaml")) + list(tag_dir.rglob("*.yml")))
        if p.is_file() and p.name != "record.yaml"
    ]

    for path in structured_yaml_paths + structured_json_paths + flat_paths:
        if not include_excluded and is_excluded_corpus_record_path(path, tag_dir):
            continue
        yield CorpusRecordPath(
            path=path,
            relative_path=corpus_record_relative_path(path, tag_dir),
        )


def slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text


ATTACK_CLASS_ALIASES: dict[str, tuple[str, ...]] = {
    "reentrancy-external-call": (
        "reentrancy",
        "reentrancy-classic",
        "reentrancy-via-hook-or-callback",
        "reentrancy-cross-contract",
        "callback-reentrancy",
        "callback-mid-state-mutation",
        "callback-hook-exploit",
        "read-only-reentrancy",
        "cross-function-reentrancy",
        "single-function-reentrancy",
        "hook-bypass",
        "post-execution-check-skip",
        "applymessage-hook-bypass",
        "pause-check-skip-internal-call",
    ),
    "signature-lazy-execution": (
        "signature-replay",
        "signature-replay-no-nonce",
        "signature-replay-cross-chain",
        "signature-replay-cross-domain",
        "approval-replay",
        "signature-forgery",
        "multi-signer-authentication-skip",
        "post-execution-check-skip",
        "tx-batch-signature-skip",
        "partial-signer-auth-bypass",
    ),
    # D2 cross-lang fix: bare query terms (what callers actually pass) had no alias
    # expansion, so vault_cross_language_pattern_lift("reentrancy"/"stale-oracle")
    # never reached the canonical index keys (reentrancy 1202 rows,
    # stale-or-manipulated-oracle 2628 rows) and returned empty.
    "reentrancy": (
        "reentrancy-external-call",
        "reentrancy-classic",
        "reentrancy-cross-contract",
        "callback-reentrancy",
        "read-only-reentrancy",
        "cross-function-reentrancy",
        "single-function-reentrancy",
    ),
    "stale-oracle": (
        "stale-or-manipulated-oracle",
        "oracle-price-manipulation",
        "oracle-manipulation",
        "oracle-staleness",
        "stale-price",
    ),
    "oracle-manipulation": (
        "stale-or-manipulated-oracle",
        "oracle-price-manipulation",
        "oracle-staleness",
    ),
}


def attack_class_query_terms(value: str) -> list[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    key = slug(raw.split(":", 1)[1] if ":" in raw else raw)
    terms = [raw.split(":", 1)[1] if ":" in raw else raw]
    terms.extend(ATTACK_CLASS_ALIASES.get(key, ()))
    out: list[str] = []
    seen: set[str] = set()
    for term in terms:
        norm = slug(term)
        if not term or norm in seen:
            continue
        seen.add(norm)
        out.append(term)
    return out


def clamp_limit(value: int | None, default: int = 10, maximum: int = 100) -> int:
    try:
        limit = int(value if value is not None else default)
    except (TypeError, ValueError):
        limit = default
    return max(0, min(limit, maximum))


def load_ranker_module() -> Any:
    name = "_hackerman_query_ranker"
    if name in sys.modules:
        return sys.modules[name]
    path = REPO_ROOT / "tools" / "ranker.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_shape_module() -> Any:
    name = "_hackerman_query_shape_hash"
    if name in sys.modules:
        return sys.modules[name]
    path = REPO_ROOT / "tools" / "shape-hash.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_query_module(filename: str, module_name: str) -> Any:
    """Load a hyphen-named tools/<filename> as an importable module.

    Used by the W6-10 exploit-predicate sidecar to import
    `hackerman-exploit-predicates.py` (an unimportable hyphenated name).
    """
    if module_name in sys.modules:
        return sys.modules[module_name]
    path = REPO_ROOT / "tools" / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_function_mindset_module() -> Any:
    name = "_hackerman_query_function_mindset"
    global _FUNCTION_MINDSET_MODULE
    if _FUNCTION_MINDSET_MODULE is not None:
        return _FUNCTION_MINDSET_MODULE
    if name in sys.modules:
        _FUNCTION_MINDSET_MODULE = sys.modules[name]
        return _FUNCTION_MINDSET_MODULE
    path = FUNCTION_MINDSET_TOOL_PATH
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    _FUNCTION_MINDSET_MODULE = mod
    return mod


def corpus_content_fingerprint(
    tag_dir: Path,
    *,
    include_subdirs: tuple[str, ...] = (),
    recursive: bool = False,
) -> tuple[str, int]:
    """Cheap content fingerprint of a corpus dir for sidecar freshness checks.

    Hashes the sorted `(name, size, mtime_ns)` tuples of corpus record files.
    By default this preserves the historical top-level `*.yaml` / `*.yml`
    behavior, plus explicitly opted-in subdirectories. Set ``recursive=True``
    to reuse the canonical recursive corpus walker used by the index builder
    and sidecar coverage report.
    Stats every file but never opens or parses one, so the check costs
    milliseconds even on a 28k-file corpus. A rebuilt, renamed, added, or
    removed record changes the fingerprint.

    Returns `(sha256_hex, file_count)`.
    """
    entries: list[tuple[str, int, int]] = []
    if recursive:
        paths = [item.path for item in iter_corpus_record_paths(tag_dir)]
    else:
        paths = list(tag_dir.glob("*.yaml")) + list(tag_dir.glob("*.yml"))
        for subdir in include_subdirs:
            root = tag_dir / subdir
            if root.is_dir():
                paths.extend(root.rglob("*.yaml"))
                paths.extend(root.rglob("*.yml"))
    for path in sorted(set(paths)):
        try:
            stat = path.stat()
        except OSError:
            continue
        try:
            name = str(path.relative_to(tag_dir))
        except ValueError:
            name = path.name
        entries.append((name, stat.st_size, stat.st_mtime_ns))
    digest = hashlib.sha256(
        json.dumps(entries, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return digest, len(entries)


def yaml_load(text: str) -> Any:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except Exception:
        return load_ranker_module().yaml_load(text)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL sidecar, auto-detecting sharded layout via the manifest.

    If ``<stem>.manifest.json`` exists alongside ``path``, the manifest is
    parsed and all shards under ``<stem>.d/`` are streamed in order.  This
    provides monolith-or-sharded back-compat: callers pass the canonical
    ``.jsonl`` path regardless of whether the sidecar has been sharded.
    """
    manifest_path = path.with_name(f"{path.stem}.manifest.json")
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}
        if isinstance(manifest, dict) and manifest.get("shard_dir"):
            shard_dir = path.parent / str(manifest["shard_dir"])
            rows: list[dict[str, Any]] = []
            for shard in manifest.get("shards") or []:
                shard_path = shard_dir / str(shard.get("path") or "")
                if not shard_path.is_file():
                    continue
                with shard_path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            row = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(row, dict):
                            rows.append(row)
            return rows
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def index_shard_for_key(key: Any) -> str:
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:2]


def index_available(index_dir: Path, index_name: str) -> bool:
    return (index_dir / f"{index_name}.jsonl").exists() or (index_dir / f"{index_name}.d").is_dir()


def read_index_rows(
    index_dir: Path,
    index_name: str,
    *,
    key: str | None = None,
    fuzzy_slug: bool = True,
) -> list[dict[str, Any]]:
    monolith = index_dir / f"{index_name}.jsonl"
    if monolith.exists():
        return read_jsonl(monolith)
    shard_dir = index_dir / f"{index_name}.d"
    if not shard_dir.is_dir():
        return []
    if key is not None and not fuzzy_slug:
        return read_jsonl(shard_dir / f"{index_shard_for_key(key)}.jsonl")
    rows: list[dict[str, Any]] = []
    for path in sorted(shard_dir.glob("*.jsonl")):
        rows.extend(read_jsonl(path))
    return rows


def load_cross_language_analogue_index(path: Path) -> dict[str, list[dict[str, Any]]]:
    """Load the derived analogue sidecar keyed by source record id."""
    index: dict[str, list[dict[str, Any]]] = {}
    for row in read_jsonl(path):
        source_id = str(row.get("source_record_id") or row.get("record_id") or "").strip()
        target_language = str(row.get("target_language") or "").strip()
        pattern_translation = str(row.get("pattern_translation") or "").strip()
        if not source_id or not target_language or not pattern_translation:
            continue
        index.setdefault(source_id, []).append(row)
    return index


def load_record_quality_index(path: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(path):
        for field in ("record_id", "source_audit_ref"):
            key = str(row.get(field) or "").strip()
            if key:
                index[key] = row
    return index


def load_proof_hardening_index(path: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(path):
        for field in ("record_id", "source_audit_ref"):
            key = str(row.get(field) or "").strip()
            if key:
                index[key] = row
    return index


def sidecar_status(path: Path, loaded: bool, label: str) -> tuple[list[str], list[dict[str, str]]]:
    """Return source refs only for loaded sidecars, otherwise explicit gaps."""
    text = str(path)
    if loaded:
        return [text], []
    reason = "missing" if not path.exists() else "empty_or_unusable"
    return [], [{"label": label, "path": text, "reason": reason}]


def attach_record_quality(
    record: dict[str, Any],
    quality_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    row = quality_index.get(str(record.get("record_id") or "")) or quality_index.get(
        str(record.get("source_audit_ref") or "")
    )
    if not row:
        return record
    out = dict(record)
    for field in (
        "record_tier",
        "record_quality_score",
        "source_extraction_method",
        "source_extraction_confidence",
    ):
        if field in row:
            out[field] = row[field]
    if row.get("reason"):
        out["record_quality_reason"] = row["reason"]
    return out


def attach_proof_hardening(
    record: dict[str, Any],
    proof_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    row = proof_index.get(str(record.get("record_id") or "")) or proof_index.get(
        str(record.get("source_audit_ref") or "")
    )
    if not row:
        return record
    out = dict(record)
    out["proof_hardening"] = row
    return out


def record_quality_float(record: dict[str, Any], field: str = "record_quality_score") -> float:
    try:
        return float(record.get(field) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def record_tier_weight(record: dict[str, Any]) -> float:
    return RECORD_TIER_WEIGHTS.get(str(record.get("record_tier") or ""), 0.0)


def proof_hardening_sort_key(record: dict[str, Any]) -> tuple[bool, bool, bool, bool, float]:
    proof = record.get("proof_hardening")
    if not isinstance(proof, dict):
        return (False, False, False, False, -0.0)
    confidence = str(proof.get("function_shape_confidence") or "").strip().lower()
    posture = str(proof.get("submission_posture") or "").strip().upper()
    maturity = record_quality_float(proof, "proof_maturity_score")
    weak_shape = confidence in {
        "function_name_hint",
        "skeleton_signature",
        "synthetic_candidate_not_audit_verified",
    }
    promotion_blocked = proof.get("promotion_allowed") is False
    not_submit_ready = posture == "NOT_SUBMIT_READY"
    low_maturity = maturity > 0 and maturity < 3
    return (weak_shape, promotion_blocked, low_maturity, not_submit_ready, -maturity)


def proof_hardening_match_weight(record: dict[str, Any]) -> float:
    """Return the evidence weight a record should contribute to rank scores."""
    weight = 1.0
    proof = record.get("proof_hardening")
    if isinstance(proof, dict):
        confidence = str(proof.get("function_shape_confidence") or "").strip().lower()
        if confidence == "function_name_hint":
            weight *= 0.25
        elif confidence in {"skeleton_signature", "synthetic_candidate_not_audit_verified"}:
            weight *= 0.35
        if proof.get("promotion_allowed") is False:
            weight *= 0.75
        maturity = record_quality_float(proof, "proof_maturity_score")
        if 0 < maturity < 3:
            weight *= 0.75
    reason = str(record.get("record_quality_reason") or "").lower()
    if "unknown audit year sentinel" in reason:
        weight *= 0.75
    return max(0.05, round(weight, 4))


def record_quality_sort_key(
    record: dict[str, Any],
    *,
    language: str = "",
    target_repo: str = "",
    stable_index: int = 0,
) -> tuple[bool, float, float, bool, bool, bool, bool, float, int, int, int]:
    return (
        str(record.get("verdict_class") or "").upper() == "CANDIDATE",
        -record_tier_weight(record),
        -record_quality_float(record),
        *proof_hardening_sort_key(record),
        -(1 if language and record.get("target_language") == language else 0),
        -(1 if target_repo and record.get("target_repo") == target_repo else 0),
        stable_index,
    )


def cross_language_analogues_for_record(
    record: dict[str, Any],
    row: dict[str, Any] | None,
    analogue_index: dict[str, list[dict[str, Any]]],
    *,
    target_language: str = "",
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Return canonical record analogues plus derived sidecar analogues."""
    row = row or {}
    wanted_language = slug(target_language)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add_analogue(item: dict[str, Any]) -> None:
        language = str(item.get("target_language") or "").strip()
        translation = str(item.get("pattern_translation") or "").strip()
        if not language or not translation:
            return
        if wanted_language and slug(language) != wanted_language:
            return
        analogue_id = str(item.get("analogue_record_id") or "").strip()
        key = (slug(language), translation, analogue_id)
        if key in seen:
            return
        seen.add(key)
        cleaned = {
            "target_language": language,
            "pattern_translation": translation,
        }
        for field in ("analogue_record_id", "confidence", "reason", "attack_class"):
            if item.get(field) not in (None, ""):
                cleaned[field] = item[field]
        out.append(cleaned)

    raw_analogues = record.get("cross_language_analogues") or []
    if isinstance(raw_analogues, list):
        for item in raw_analogues:
            if isinstance(item, dict):
                add_analogue(item)
                if len(out) >= limit:
                    return out

    keys = [
        record_id(record, row),
        str(record.get("source_audit_ref") or ""),
        str(row.get("record_id") or ""),
        str(row.get("verdict_id") or ""),
    ]
    for key in keys:
        if not key:
            continue
        for item in analogue_index.get(key, []):
            add_analogue(item)
            if len(out) >= limit:
                return out
    return out


def attach_cross_language_analogues(
    record: dict[str, Any],
    row: dict[str, Any] | None,
    analogue_index: dict[str, list[dict[str, Any]]],
    *,
    target_language: str = "",
    limit: int = 8,
) -> dict[str, Any]:
    analogues = cross_language_analogues_for_record(
        record,
        row,
        analogue_index,
        target_language=target_language,
        limit=limit,
    )
    if not analogues:
        return record
    out = dict(record)
    out["cross_language_analogues"] = analogues
    return out


def load_tag_file(tag_file: str, tags_dir: Path) -> dict[str, Any]:
    if not tag_file:
        return {}
    path = Path(tag_file)
    if not path.is_absolute():
        path = tags_dir / tag_file
    if not path.exists():
        return {}
    try:
        data = yaml_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def index_key_values(row: dict[str, Any], axis: str) -> set[str]:
    keys: set[str] = set()
    for field in ("key", axis, axis.removeprefix("by_")):
        value = row.get(field)
        if isinstance(value, list):
            keys.update(str(v) for v in value)
        elif value not in (None, ""):
            keys.add(str(value))
    return keys


def row_embedded_record(row: dict[str, Any]) -> dict[str, Any]:
    for field in ("hackerman_record", "record", "tag", "verdict_tag"):
        value = row.get(field)
        if isinstance(value, dict):
            return value
    # Newer indices may project full records directly. Plain corpus indices also
    # carry record_id plus tag_file; those must load the tag to avoid dropping
    # fields not projected into the index row.
    if row.get("schema_version"):
        return dict(row)
    if row.get("record_id") and not row.get("tag_file") and any(
        field in row for field in ("target_component", "attacker_action_sequence", "function_shape", "notes")
    ):
        return dict(row)
    return {}


def records_for_rows(rows: Iterable[dict[str, Any]], tags_dir: Path) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for row in rows:
        record = row_embedded_record(row)
        if not record:
            record = load_tag_file(str(row.get("tag_file") or ""), tags_dir)
        if not record:
            record = {
                "record_id": row.get("record_id") or row.get("verdict_id"),
                "verdict_id": row.get("verdict_id"),
            }
        out.append((row, record))
    return out


def query_index(
    *,
    index_name: str,
    key: str,
    index_dir: Path,
    tags_dir: Path,
    limit: int,
    fuzzy_slug: bool = True,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    rows = read_index_rows(index_dir, index_name, key=key, fuzzy_slug=fuzzy_slug)
    wanted = slug(key) if fuzzy_slug else str(key)
    matched: list[dict[str, Any]] = []
    for row in rows:
        values = index_key_values(row, index_name)
        if not values:
            continue
        if fuzzy_slug:
            ok = any(slug(value) == wanted for value in values)
        else:
            ok = any(str(value) == wanted for value in values)
        if ok:
            matched.append(row)
        if len(matched) >= limit * 4 and limit:
            # Leave room for de-duplication after tag load without reading the
            # whole corpus for high-frequency classes.
            break
    return records_for_rows(matched, tags_dir)


def record_attack_classes(record: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for field in ("attack_class", "attack_classes", "attack_classes_to_try"):
        value = record.get(field)
        if isinstance(value, list):
            values.extend(value)
        elif value not in (None, ""):
            values.append(value)
    return [str(v) for v in values if str(v).strip()]


def record_language(record: dict[str, Any]) -> str:
    return str(record.get("target_language") or record.get("language") or "")


def record_severity(record: dict[str, Any]) -> str:
    return str(
        record.get("severity_at_finding")
        or record.get("severity_final")
        or record.get("severity_claimed")
        or ""
    )


def record_sites(record: dict[str, Any]) -> list[dict[str, Any]]:
    sites = record.get("sites") or []
    return sites if isinstance(sites, list) else []


def record_id(record: dict[str, Any], row: dict[str, Any] | None = None) -> str:
    row = row or {}
    return str(
        record.get("record_id")
        or record.get("verdict_id")
        or row.get("record_id")
        or row.get("verdict_id")
        or row.get("tag_file")
        or ""
    )


def normalized_record(record: dict[str, Any], row: dict[str, Any] | None = None) -> dict[str, Any]:
    row = row or {}
    function_shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
    sites = record_sites(record)
    row_key = str(row.get("key") or "")
    shape_key = row_key if re.fullmatch(r"[0-9a-fA-F]{16}", row_key) else ""
    first_site = sites[0] if sites and isinstance(sites[0], dict) else {}
    if shape_key:
        for site in sites:
            if not isinstance(site, dict):
                continue
            if shape_key in {str(site.get("shape_hash") or ""), str(site.get("shape_hash_fine") or "")}:
                first_site = site
                break
    attack_classes = record_attack_classes(record)
    primary_attack_class = str(record.get("attack_class") or (attack_classes[0] if attack_classes else ""))
    return {
        "record_id": record_id(record, row),
        "source_audit_ref": str(record.get("source_audit_ref") or record.get("verdict_id") or row.get("verdict_id") or ""),
        "target_domain": str(record.get("target_domain") or ""),
        "target_language": record_language(record),
        "target_repo": str(record.get("target_repo") or ""),
        "target_component": str(record.get("target_component") or first_site.get("file_path") or ""),
        "function_signature": str(
            function_shape.get("raw_signature")
            or first_site.get("function_signature")
            or ""
        ),
        "shape_hash": str(row.get("shape_hash") or first_site.get("shape_hash") or shape_key or ""),
        "bug_class": str(record.get("bug_class") or ""),
        "attack_class": primary_attack_class,
        "attack_classes": attack_classes,
        "attacker_role": str(record.get("attacker_role") or ""),
        "attacker_action_sequence": str(record.get("attacker_action_sequence") or ""),
        "required_preconditions": record.get("required_preconditions") or [],
        "impact_class": str(record.get("impact_class") or ""),
        "impact_actor": str(record.get("impact_actor") or ""),
        "impact_dollar_class": str(record.get("impact_dollar_class") or ""),
        "fix_pattern": str(record.get("fix_pattern") or ""),
        "severity_at_finding": record_severity(record),
        "year": record.get("year") or record.get("audit_year") or "",
        "proof_artifact_path": safe_proof_artifact_path(
            record.get("proof_artifact_path") or record.get("poc_path")
        ),
        "verdict_class": str(record.get("verdict_class") or ""),
        "triager_outcome": str(record.get("triager_outcome") or ""),
        "notes": str(record.get("notes") or "")[:1200],
        "tag_file": str(row.get("tag_file") or ""),
    }


def dedupe_records(pairs: Iterable[tuple[dict[str, Any], dict[str, Any]]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    seen: set[str] = set()
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for row, record in pairs:
        key = record_id(record, row)
        if not key:
            key = stable_hash({"row": row, "record": normalized_record(record, row)})[:16]
        if key in seen:
            continue
        seen.add(key)
        out.append((row, record))
    return out


def build_function_shape_recall_payload(
    *,
    target_repo: str,
    file_path: str,
    function_signature: str,
    shape_hash: str,
    language: str,
    limit: int,
) -> dict[str, Any]:
    """Query canonical Hackerman function-shape recall with a small cache."""
    bounded_limit = clamp_limit(limit, default=3, maximum=5)
    cache_key = (
        target_repo or "",
        file_path or "",
        function_signature or "",
        shape_hash or "",
        language or "",
        bounded_limit,
    )
    cached = _FUNCTION_MINDSET_PAYLOAD_CACHE.get(cache_key)
    if cached is not None:
        return dict(cached)
    try:
        mod = load_function_mindset_module()
        args = argparse.Namespace(
            function_signature=function_signature or "",
            shape_hash=shape_hash or "",
            body_hash="",
            language=language or "go",
            target_repo=target_repo or "",
            file_path=file_path or "",
            same_repo_only=False,
            limit=bounded_limit,
            index_dir=str(DEFAULT_INDEX_DIR),
            tags_dir=str(DEFAULT_TAGS_DIR),
            quality_sidecar=str(DEFAULT_RECORD_QUALITY_SIDECAR),
            proof_hardening_sidecar=str(DEFAULT_PROOF_HARDENING_SIDECAR),
            cross_language_sidecar=str(DEFAULT_CROSS_LANGUAGE_ANALOGUES_SIDECAR),
            json=True,
        )
        payload = mod.build_payload(args)
        out = payload if isinstance(payload, dict) else {}
    except Exception as exc:
        out = {
            "degraded": True,
            "reason": f"hackerman_function_query_error: {exc}",
            "ranked_attack_classes": [],
            "sidecar_gaps": [],
            "source_refs": [],
        }
    _FUNCTION_MINDSET_PAYLOAD_CACHE[cache_key] = dict(out)
    return dict(out)


def merge_ranked_attack_classes(
    ranker_rows: list[dict[str, Any]],
    hackerman_rows: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    """Prefer canonical Hackerman rows when both sources name the same class."""
    helper_by_class: dict[str, dict[str, Any]] = {}
    for row in hackerman_rows or []:
        if not isinstance(row, dict):
            continue
        attack_class = str(row.get("attack_class") or row.get("class_id") or "").strip()
        if attack_class and attack_class not in helper_by_class:
            helper_by_class[attack_class] = dict(row)

    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in ranker_rows or []:
        if not isinstance(row, dict):
            continue
        attack_class = str(row.get("attack_class") or row.get("class_id") or "").strip()
        if not attack_class or attack_class in seen:
            continue
        seen.add(attack_class)
        merged.append(dict(helper_by_class.get(attack_class) or row))

    for attack_class, row in helper_by_class.items():
        if attack_class in seen:
            continue
        seen.add(attack_class)
        merged.append(dict(row))

    for idx, row in enumerate(merged, start=1):
        row.setdefault("rank", idx)
    return merged[: max(0, int(limit or 0))]


def first_hackerman_evidence(row: dict[str, Any]) -> dict[str, Any]:
    evidence = row.get("evidence")
    if isinstance(evidence, list):
        first = next((item for item in evidence if isinstance(item, dict)), None)
        if first is not None:
            return first
    return {}


def evidence_record_id(evidence: dict[str, Any]) -> str:
    for key in ("record_id", "verdict_id", "outcome_id", "tag_file", "source_ref"):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def bounded_source_refs(values: Any, limit: int = 5) -> list[str]:
    refs: list[str] = []
    if not isinstance(values, list):
        return refs
    for value in values:
        text = str(value if value is not None else "").strip()
        if not text:
            continue
        try:
            path = Path(text).expanduser()
            if path.is_absolute():
                try:
                    text = path.resolve().relative_to(REPO_ROOT).as_posix()
                except (OSError, ValueError):
                    text = path.name
        except (OSError, RuntimeError):
            pass
        if text not in refs:
            refs.append(text)
        if len(refs) >= limit:
            break
    return refs


def summarize_function_shape_recall(payload: dict[str, Any], limit: int) -> dict[str, Any]:
    if not isinstance(payload, dict) or not payload:
        return {}
    bounded_limit = clamp_limit(limit, default=3, maximum=5)
    ranked = payload.get("ranked_attack_classes")
    hypotheses: list[dict[str, Any]] = []
    if isinstance(ranked, list):
        for row in ranked[:bounded_limit]:
            if not isinstance(row, dict):
                continue
            evidence = first_hackerman_evidence(row)
            summary: dict[str, Any] = {
                "attack_class": str(row.get("attack_class") or row.get("class_id") or ""),
                "score": round(float(row.get("score", 0.0)), 4),
                "confidence": round(float(row.get("confidence", 0.0)), 4),
            }
            source_record_id = evidence_record_id(evidence)
            if source_record_id:
                summary["source_record_id"] = source_record_id
            for field in ("match_kind", "match_weight", "record_tier", "record_quality_score"):
                value = evidence.get(field)
                if value not in (None, ""):
                    summary[field] = value
            hypotheses.append(summary)
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    sidecar_gaps = payload.get("sidecar_gaps") if isinstance(payload.get("sidecar_gaps"), list) else []
    return {
        "schema": payload.get("schema", ""),
        "context_pack_id": payload.get("context_pack_id", ""),
        "degraded": bool(payload.get("degraded", False)),
        "reason": payload.get("reason", ""),
        "total_records_matched": int(payload.get("total_records_matched") or 0),
        "shape_hashes_queried": list(target.get("shape_hashes_queried") or [])[:2],
        "top_hypotheses": hypotheses,
        "source_refs": bounded_source_refs(payload.get("source_refs")),
        "sidecar_gaps": sidecar_gaps[:3],
    }


def _bounded_text(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def build_corpus_backed_hypotheses(
    ranked_rows: list[dict[str, Any]],
    rendered_questions: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    """Pair corpus-derived hacker questions with canonical recall provenance."""
    bounded_limit = clamp_limit(limit, default=3, maximum=5)
    questions_by_class: dict[str, dict[str, Any]] = {}
    for question in rendered_questions or []:
        if not isinstance(question, dict):
            continue
        if str(question.get("question_source") or "") != "corpus-derived":
            continue
        attack_class = str(question.get("attack_class") or "").strip()
        if attack_class and attack_class not in questions_by_class:
            questions_by_class[attack_class] = question

    hypotheses: list[dict[str, Any]] = []
    for row in ranked_rows or []:
        if not isinstance(row, dict):
            continue
        attack_class = str(row.get("attack_class") or row.get("class_id") or "").strip()
        if not attack_class:
            continue
        question = questions_by_class.get(attack_class)
        if not question:
            continue
        evidence = first_hackerman_evidence(row)
        canonical = question.get("canonical_hackerman_evidence")
        canonical = canonical if isinstance(canonical, dict) else {}
        source_record_id = (
            str(canonical.get("source_record_id") or "").strip()
            or str(question.get("source_record_id") or "").strip()
            or evidence_record_id(evidence)
        )
        if not source_record_id:
            continue
        provenance: dict[str, Any] = {"source_record_id": source_record_id}
        for field in ("match_kind", "match_weight", "record_tier", "record_quality_score"):
            value = canonical.get(field)
            if value in (None, ""):
                value = evidence.get(field)
            if value not in (None, ""):
                provenance[field] = value
        item: dict[str, Any] = {
            "attack_class": attack_class,
            "score": round(float(row.get("score", 0.0)), 4),
            "confidence": round(float(row.get("confidence", 0.0)), 4),
            "question": _bounded_text(question.get("question"), 240),
            "proof_obligation": _bounded_text(question.get("proof_obligation"), 220),
            "kill_condition": _bounded_text(question.get("kill_condition"), 220),
            "claim_boundary": _bounded_text(question.get("claim_boundary"), 180),
            "proof_gate": str(question.get("proof_gate") or ""),
            "provenance": provenance,
        }
        analogues = question.get("cross_language_analogues")
        if isinstance(analogues, list) and analogues:
            item["cross_language_analogues"] = [
                {
                    "target_language": str(analogue.get("target_language") or ""),
                    "analogue_record_id": str(analogue.get("analogue_record_id") or ""),
                    "confidence": analogue.get("confidence"),
                }
                for analogue in analogues[:2]
                if isinstance(analogue, dict)
            ]
        hypotheses.append(item)
        if len(hypotheses) >= bounded_limit:
            break
    return hypotheses


@dataclass(frozen=True)
class ParsedSignature:
    language: str
    function_name: str
    receiver_type: str | None
    params: list[dict[str, str]]
    return_types: list[str]
    visibility: str


def parse_signature(signature: str, language: str = "go") -> ParsedSignature:
    lang = (language or "go").lower()
    sig = (signature or "").strip()
    if lang == "solidity":
        return _parse_solidity_signature(sig)
    return _parse_go_signature(sig)


def _split_top_level_commas(blob: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for idx, ch in enumerate(blob):
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(blob[start:idx].strip())
            start = idx + 1
    tail = blob[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _extract_paren_block(text: str, start: int) -> tuple[str, int]:
    depth = 0
    for idx in range(start, len(text)):
        ch = text[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:idx], idx
    return "", start


def _parse_go_signature(sig: str) -> ParsedSignature:
    rest = re.sub(r"^func\s+", "", sig).strip()
    receiver_type: str | None = None
    if rest.startswith("("):
        receiver_blob, end = _extract_paren_block(rest, 0)
        receiver_parts = receiver_blob.split()
        if receiver_parts:
            receiver_type = receiver_parts[-1]
        rest = rest[end + 1:].strip()
    name_match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", rest)
    function_name = name_match.group(1) if name_match else ""
    rest = rest[name_match.end():].strip() if name_match else rest
    params: list[dict[str, str]] = []
    return_types: list[str] = []
    if rest.startswith("("):
        param_blob, end = _extract_paren_block(rest, 0)
        rest_after = rest[end + 1:].strip()
        for part in _split_top_level_commas(param_blob):
            toks = part.rsplit(None, 1)
            if len(toks) == 2:
                names, typ = toks
                for name in [n.strip() for n in names.split(",") if n.strip()]:
                    params.append({"name": name, "type": typ})
            elif part:
                params.append({"name": "", "type": part})
        if rest_after.startswith("("):
            ret_blob, _ = _extract_paren_block(rest_after, 0)
            return_types = [p.strip().split()[-1] for p in _split_top_level_commas(ret_blob) if p.strip()]
        elif rest_after:
            return_types = [rest_after.split()[0]]
    visibility = "exported" if function_name[:1].isupper() else "private"
    return ParsedSignature("go", function_name, receiver_type, params, return_types, visibility)


def _parse_solidity_signature(sig: str) -> ParsedSignature:
    match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", sig)
    function_name = match.group(1) if match else ""
    params: list[dict[str, str]] = []
    return_types: list[str] = []
    if match:
        start = sig.index("(", match.end() - 1)
        param_blob, end = _extract_paren_block(sig, start)
        for part in _split_top_level_commas(param_blob):
            toks = part.split()
            if toks:
                params.append({"name": toks[-1] if len(toks) > 1 else "", "type": toks[0]})
        tail = sig[end + 1:]
        ret_match = re.search(r"\breturns\s*\(", tail)
        if ret_match:
            ret_blob, _ = _extract_paren_block(tail, ret_match.end() - 1)
            for part in _split_top_level_commas(ret_blob):
                toks = part.split()
                if toks:
                    return_types.append(toks[0])
    visibility = "external" if re.search(r"\bexternal\b", sig) else "public"
    return ParsedSignature("solidity", function_name, None, params, return_types, visibility)


def compute_shape_from_signature(signature: str, language: str = "go") -> dict[str, Any]:
    parsed = parse_signature(signature, language)
    sh = load_shape_module()
    shape_hash = sh.compute_shape_hash(
        language=parsed.language,
        params=parsed.params,
        return_types=parsed.return_types,
        visibility=parsed.visibility,
        guards_detected=["error-return"] if parsed.language == "go" and "error" in parsed.return_types else [],
        receiver_type=parsed.receiver_type,
        fine=False,
    )
    shape_hash_fine = sh.compute_shape_hash(
        language=parsed.language,
        params=parsed.params,
        return_types=parsed.return_types,
        visibility=parsed.visibility,
        guards_detected=["error-return"] if parsed.language == "go" and "error" in parsed.return_types else [],
        receiver_type=parsed.receiver_type,
        fine=True,
    )
    return {
        "language": parsed.language,
        "function_name": parsed.function_name,
        "receiver_type": parsed.receiver_type,
        "params": parsed.params,
        "return_types": parsed.return_types,
        "visibility": parsed.visibility,
        "shape_hash": shape_hash,
        "shape_hash_fine": shape_hash_fine,
    }


def infer_language_from_files(files: Iterable[str]) -> str:
    counts: dict[str, int] = {}
    suffix_map = {
        ".go": "go",
        ".sol": "solidity",
        ".rs": "rust",
        ".vy": "vyper",
        ".move": "move",
        ".cairo": "cairo",
        ".ts": "typescript-onchain",
        ".js": "typescript-onchain",
    }
    for file_name in files:
        lang = suffix_map.get(Path(str(file_name)).suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return ""
    if counts.get("solidity", 0) and not any(counts.get(lang, 0) for lang in ("go", "rust", "move", "cairo")):
        return "solidity"
    return max(counts.items(), key=lambda item: (item[1], item[0]))[0]


def infer_domain(text: str) -> str:
    lowered = text.lower()
    domain_terms = {
        "lending": ["lending", "borrow", "trove", "liquity", "stabilitypool", "collateral"],
        "dex": ["dex", "swap", "amm", "pool", "clob", "orderbook"],
        "bridge": ["bridge", "ibc", "packet", "withdrawal proof"],
        "oracle": ["oracle", "price", "slinky", "pyth", "chainlink"],
        "governance": ["governance", "governor", "timelock", "proposal"],
        "staking": ["staking", "validator", "delegation", "slash"],
        "vault": ["vault", "erc4626", "deposit", "withdraw"],
        "rollup": ["rollup", "sequencer", "outbox"],
        "zk-proof": ["zk", "circuit", "proof", "constraint"],
        "consensus": ["consensus", "cometbft", "tendermint", "blocksync"],
    }
    for domain, terms in domain_terms.items():
        if any(term in lowered for term in terms):
            return domain
    return ""


def collect_scope_files(workspace: Path, globs: list[str], explicit_files: list[str]) -> list[str]:
    files: list[str] = []
    source_suffixes = {".go", ".sol", ".rs", ".vy", ".move", ".cairo", ".ts", ".js"}
    skip_dirs = {"node_modules", ".git", "cache", "build", "out", "artifacts", "dist", "vendor", "target", ".next"}

    def add_path(path_text: str) -> None:
        path = Path(path_text)
        resolved = path if path.is_absolute() else workspace / path
        if resolved.is_dir():
            added = 0
            for child in sorted(resolved.rglob("*")):
                if added >= 200:
                    break
                if any(part in skip_dirs for part in child.parts):
                    continue
                if not child.is_file() or child.suffix.lower() not in source_suffixes:
                    continue
                try:
                    files.append(str(child.relative_to(workspace)))
                except ValueError:
                    files.append(str(child))
                added += 1
            return
        files.append(path_text)

    for item in explicit_files:
        for part in str(item).split(","):
            part = part.strip()
            if part:
                add_path(part)
    for pattern in globs:
        for path in sorted(workspace.glob(pattern)):
            if path.is_file():
                try:
                    files.append(str(path.relative_to(workspace)))
                except ValueError:
                    files.append(str(path))
    seen: set[str] = set()
    out: list[str] = []
    for file_name in files:
        if file_name in seen:
            continue
        seen.add(file_name)
        out.append(file_name)
    return out
