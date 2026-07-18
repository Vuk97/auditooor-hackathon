#!/usr/bin/env python3
"""Plan external-intel refresh work from the source registry.

This runner is intentionally conservative: by default it validates
``reference/external_intel_sources.yaml`` and emits executable dry-run command
plans or explicit TODO/backlog rows. It does not fetch live network content.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = REPO_ROOT / "reference" / "external_intel_sources.yaml"
SCHEMA = "auditooor.external_intel_sources.v1"
SUMMARY_SCHEMA = "auditooor.external_intel_refresh.summary.v1"
SOURCE_COLLECTION_SCHEMA = "auditooor.external_intel.single_incident_source_collection.v1"
SINGLE_INCIDENT_FETCH_SCHEMA = "auditooor.external_intel.single_incident_fetch.v1"
DEFAULT_SINGLE_INCIDENT_CACHE = REPO_ROOT / "cache" / "external-intel-single-incident"
MAX_FETCH_BYTES = 2_000_000

REQUIRED_SOURCE_KEYS = {
    "source_id",
    "url_or_api",
    "miner",
    "cursor",
    "ttl",
    "output_subtree",
    "quality_gate",
    "network_requirement",
    "promotion_target",
}

POSTMORTEM_PLANS: Dict[str, Dict[str, str]] = {
    "defillama_hacks_tvl": {
        "source": "defillama",
        "reason": "Existing postmortem miner supports DefiLlama API rows; runner emits an offline dry-run plan.",
    },
    "rekt_news_incidents": {
        "source": "rekt",
        "index_url": "https://rekt.news/leaderboard/",
        "reason": "Existing postmortem miner supports rekt index/page parsing; runner emits an offline dry-run plan.",
    },
}

DARKNAVY_PLANS: Dict[str, Dict[str, str]] = {
    "darknavy_web3_pages": {
        "reason": "DARKNAVY Web3 uses a bounded live/cached miner for pages 1-8; live fetch requires an explicit flag.",
    },
}

OPERATOR_AUTHORIZED_SOURCE_CLOSURES: Dict[str, Dict[str, Any]] = {
    "defimon_delta_blocked_no_live_source": {
        "blocker_id": "BLK-V3-SOURCE-DEFIMON-NO-LIVE-SOURCE",
        "authorized_on": "2026-05-24",
        "authority": "operator_confirmation",
        "summary": (
            "Operator confirmed the public Defimon Telegram mirror is a live source "
            "and accepted Telegram plus blog coverage as sufficient source-miner evidence."
        ),
        "source_refs": ["https://t.me/s/defimon_alerts", "https://defimon.xyz/blog"],
        "closure_boundary": (
            "Source-miner live-source closure only; not external platform outcome evidence."
        ),
    },
    "map_butter_bridge_incident_2026_05": {
        "blocker_id": "BLK-V3-SOURCE-RECENT-BRIDGE-OPEN-OBLIGATIONS",
        "authorized_on": "2026-05-24",
        "authority": "operator_confirmation",
        "summary": (
            "Operator authorized MAP/Butter source-miner unblock without another "
            "source-evidence gate, using locally inferrable on-chain/corpus evidence."
        ),
        "source_refs": [
            "audit/corpus_tags/tags/bridge_incidents/map_butter_bridge_2026_05/record.yaml",
            "audit/corpus_tags/tags/bridge_incidents/map_butter_bridge_2026_05/SOURCE_COLLECTION_TODO.md",
        ],
        "closure_boundary": (
            "Source-miner source-evidence gate closure only; not external platform "
            "outcome evidence, helper ABI/source proof, or exploit-time implementation "
            "source-code root-cause proof."
        ),
    },
}


class RegistryError(ValueError):
    """Raised when the registry cannot be loaded as a mapping."""


def _today() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def _repo_rel(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _expand_date(value: object, date: str) -> object:
    if isinstance(value, str):
        return value.replace("<date>", date)
    if isinstance(value, list):
        return [_expand_date(item, date) for item in value]
    if isinstance(value, dict):
        return {key: _expand_date(val, date) for key, val in value.items()}
    return value


def _source_obligations(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    obligations = row.get("source_obligations")
    if not isinstance(obligations, list):
        return []
    return [item for item in obligations if isinstance(item, dict)]


def _open_source_obligations(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        item
        for item in _source_obligations(row)
        if str(item.get("status") or "").strip().lower() != "closed"
    ]


def _operator_authorized_source_closure(row: Dict[str, Any]) -> Dict[str, Any] | None:
    source_id = row.get("source_id")
    if not isinstance(source_id, str):
        return None
    authorization = OPERATOR_AUTHORIZED_SOURCE_CLOSURES.get(source_id)
    if authorization is None:
        return None
    open_obligations = _open_source_obligations(row)
    return {
        **authorization,
        "formerly_blocking_source_obligation_ids": [
            str(item.get("obligation_id"))
            for item in open_obligations
            if item.get("obligation_id")
        ],
        "formerly_blocking_source_obligations": open_obligations,
    }


def _operator_authorized_obligations(
    obligations: object,
    authorization: Dict[str, Any] | None,
) -> object:
    if authorization is None or not isinstance(obligations, list):
        return obligations
    authorized_ids = set(authorization.get("formerly_blocking_source_obligation_ids") or [])
    out: List[Any] = []
    for obligation in obligations:
        if not isinstance(obligation, dict):
            out.append(obligation)
            continue
        obligation_id = str(obligation.get("obligation_id") or "")
        if obligation_id not in authorized_ids:
            out.append(obligation)
            continue
        out.append(
            {
                **obligation,
                "status": "operator_authorized_closed",
                "operator_authorized_source_closure": {
                    "authority": authorization["authority"],
                    "authorized_on": authorization["authorized_on"],
                    "blocker_id": authorization["blocker_id"],
                    "closure_boundary": authorization["closure_boundary"],
                },
            }
        )
    return out


def _apply_operator_authorized_source_closure(
    collection: Dict[str, Any],
    authorization: Dict[str, Any] | None,
) -> Dict[str, Any]:
    if authorization is None:
        return collection
    collection.update(
        {
            "collection_status": "operator_authorized_source_closure",
            "source_gate_blocking": False,
            "operator_authorized_source_closure": authorization,
            "source_obligations": _operator_authorized_obligations(
                collection.get("source_obligations"),
                authorization,
            ),
            "open_source_obligation_ids": [],
            "nonblocking_former_source_obligation_ids": authorization[
                "formerly_blocking_source_obligation_ids"
            ],
            "promotion_allowed": False,
            "promotion_blockers": [
                "manual_promotion_review_required",
                "operator_authorized_source_closure_is_not_external_platform_outcome_evidence",
            ],
            "next_action": (
                "Source-miner evidence gate is operator-authorized closed; keep "
                "external outcome and source-code root-cause claims in downstream review."
            ),
        }
    )
    return collection


def _string_list(value: object) -> List[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return []


def _dedupe(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _is_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def _url_cache_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]


def _source_role(url: str) -> str:
    lowered = url.lower()
    if any(marker in lowered for marker in ("etherscan.io", "bscscan.com", "sourcify.dev")):
        return "onchain_or_source_code"
    if any(marker in lowered for marker in ("github.com", "gitlab.com")):
        return "source_code_or_analysis"
    if any(marker in lowered for marker in ("blockaid", "halborn", "darknavy", "theblock", "cointelegraph")):
        return "primary_or_security_firm"
    if any(marker in lowered for marker in ("mapprotocol", "butternetwork", "verus", "x.com/", "twitter.com/")):
        return "primary_project_or_social_ack"
    return "external_reference"


def _fixture_candidates(fixture_dir: Path, cache_key: str) -> List[Path]:
    return [
        fixture_dir / f"{cache_key}{suffix}"
        for suffix in (".body", ".txt", ".html", ".json", ".sol", ".md")
    ]


def _read_bounded(path: Path) -> bytes:
    return path.read_bytes()[:MAX_FETCH_BYTES]


def _fetch_url_metadata(
    url: str,
    *,
    allow_live_fetch: bool,
    cache_dir: Path,
    fixture_dir: Path | None,
    timeout_seconds: float,
) -> Dict[str, Any]:
    cache_key = _url_cache_key(url)
    cache_body = cache_dir / f"{cache_key}.body"
    cache_meta = cache_dir / f"{cache_key}.json"

    if fixture_dir is not None:
        for fixture in _fixture_candidates(fixture_dir, cache_key):
            if fixture.exists():
                body = _read_bounded(fixture)
                return {
                    "url": url,
                    "role": _source_role(url),
                    "cache_key": cache_key,
                    "status": "fixture",
                    "bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "fixture_path": str(fixture),
                    "cache_hit": False,
                }

    if cache_body.exists():
        body = _read_bounded(cache_body)
        return {
            "url": url,
            "role": _source_role(url),
            "cache_key": cache_key,
            "status": "cache_hit",
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "cache_path": str(cache_body),
            "metadata_path": str(cache_meta) if cache_meta.exists() else None,
            "cache_hit": True,
        }

    if not allow_live_fetch:
        return {
            "url": url,
            "role": _source_role(url),
            "cache_key": cache_key,
            "status": "not_fetched",
            "reason": "live fetch requires both --fetch-single-incident and --allow-live-fetch",
            "cache_hit": False,
        }

    cache_dir.mkdir(parents=True, exist_ok=True)
    try:
        request = Request(url, headers={"User-Agent": "auditooor-external-intel-refresh/1.0"})
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - explicit operator-gated URL fetcher.
            body = response.read(MAX_FETCH_BYTES)
            status_code = getattr(response, "status", None)
            content_type = response.headers.get("content-type") if getattr(response, "headers", None) else None
    except (OSError, URLError, TimeoutError) as exc:
        return {
            "url": url,
            "role": _source_role(url),
            "cache_key": cache_key,
            "status": "fetch_error",
            "error": str(exc),
            "cache_hit": False,
        }

    sha = hashlib.sha256(body).hexdigest()
    cache_body.write_bytes(body)
    meta = {
        "url": url,
        "fetched_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "status_code": status_code,
        "content_type": content_type,
        "bytes": len(body),
        "sha256": sha,
    }
    cache_meta.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "url": url,
        "role": _source_role(url),
        "cache_key": cache_key,
        "status": "fetched",
        "status_code": status_code,
        "content_type": content_type,
        "bytes": len(body),
        "sha256": sha,
        "cache_path": str(cache_body),
        "metadata_path": str(cache_meta),
        "cache_hit": False,
    }


def load_registry(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RegistryError(f"registry must be a YAML mapping: {path}")
    return data


def validate_registry(data: Dict[str, Any], *, repo_root: Path = REPO_ROOT) -> List[str]:
    errors: List[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")

    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("sources must be a non-empty list")
        return errors

    seen: set[str] = set()
    for idx, row in enumerate(sources):
        if not isinstance(row, dict):
            errors.append(f"sources[{idx}] must be a mapping")
            continue
        source_id = row.get("source_id", f"sources[{idx}]")
        if not isinstance(source_id, str) or not source_id:
            errors.append(f"sources[{idx}].source_id must be a non-empty string")
        elif source_id in seen:
            errors.append(f"duplicate source_id: {source_id}")
        else:
            seen.add(source_id)

        missing = sorted(REQUIRED_SOURCE_KEYS.difference(row))
        if missing:
            errors.append(f"{source_id}: missing required keys: {', '.join(missing)}")

        miner = row.get("miner")
        if not isinstance(miner, dict):
            errors.append(f"{source_id}: miner must be a mapping")
        else:
            tool_path = miner.get("tool_path")
            if not isinstance(tool_path, str) or not tool_path:
                errors.append(f"{source_id}: miner.tool_path must be a non-empty string")
            elif tool_path.startswith("tools/") and not (repo_root / tool_path).exists():
                errors.append(f"{source_id}: miner.tool_path does not exist: {tool_path}")
            if "mode" not in miner:
                errors.append(f"{source_id}: miner.mode is required")
            if "auth_env" not in miner:
                errors.append(f"{source_id}: miner.auth_env is required")

        cursor = row.get("cursor")
        if not isinstance(cursor, dict):
            errors.append(f"{source_id}: cursor must be a mapping")
        else:
            for key in ("type", "path", "field"):
                if key not in cursor:
                    errors.append(f"{source_id}: cursor.{key} is required")

        quality_gate = row.get("quality_gate")
        if not isinstance(quality_gate, dict):
            errors.append(f"{source_id}: quality_gate must be a mapping")
        else:
            required_fields = quality_gate.get("required_fields")
            if not isinstance(required_fields, list) or not required_fields:
                errors.append(f"{source_id}: quality_gate.required_fields must be a non-empty list")
            if "minimum_verification_tier" not in quality_gate:
                errors.append(f"{source_id}: quality_gate.minimum_verification_tier is required")

        network_requirement = row.get("network_requirement")
        if not isinstance(network_requirement, dict):
            errors.append(f"{source_id}: network_requirement must be a mapping")
        elif "required" not in network_requirement:
            errors.append(f"{source_id}: network_requirement.required is required")

        promotion_target = row.get("promotion_target")
        if not isinstance(promotion_target, dict):
            errors.append(f"{source_id}: promotion_target must be a mapping")
        elif "corpus_subtree" not in promotion_target:
            errors.append(f"{source_id}: promotion_target.corpus_subtree is required")

        source_obligations = row.get("source_obligations")
        if source_obligations is not None:
            if not isinstance(source_obligations, list):
                errors.append(f"{source_id}: source_obligations must be a list")
            else:
                for obligation_idx, obligation in enumerate(source_obligations):
                    label = f"{source_id}: source_obligations[{obligation_idx}]"
                    if not isinstance(obligation, dict):
                        errors.append(f"{label} must be a mapping")
                        continue
                    for key in ("obligation_id", "status", "obligation_type", "required_evidence"):
                        if not isinstance(obligation.get(key), str) or not obligation.get(key, "").strip():
                            errors.append(f"{label}.{key} must be a non-empty string")
                    refs = obligation.get("source_refs")
                    if refs is not None and not isinstance(refs, list):
                        errors.append(f"{label}.source_refs must be a list when present")

    return errors


def select_sources(data: Dict[str, Any], source_ids: Sequence[str]) -> List[Dict[str, Any]]:
    sources = data.get("sources") or []
    if not source_ids:
        return list(sources)
    wanted = set(source_ids)
    selected = [row for row in sources if row.get("source_id") in wanted]
    found = {row.get("source_id") for row in selected}
    missing = sorted(wanted.difference(found))
    if missing:
        raise RegistryError(f"unknown source_id(s): {', '.join(missing)}")
    return selected


def _postmortem_command(row: Dict[str, Any], *, date: str, live_fetch: bool = False, max_pages: int | None = None) -> List[str]:
    source_id = row["source_id"]
    plan = POSTMORTEM_PLANS[source_id]
    cmd = [
        "python3",
        "tools/hackerman-etl-from-post-mortem.py",
        "--source",
        plan["source"],
        "--cache-dir",
        "cache/post-mortem",
        "--out-dir",
        str(_expand_date(row["output_subtree"], date)),
        "--json-summary",
    ]
    if live_fetch:
        cmd.append("--fetch")
        if max_pages is not None:
            cmd.extend(["--max-pages", str(max_pages)])
    else:
        cmd.append("--dry-run")
    if plan.get("index_url"):
        cmd.extend(["--index-url", plan["index_url"]])
    return cmd


def _darknavy_command(row: Dict[str, Any], *, date: str) -> List[str]:
    _ = row, date
    return [
        "python3",
        "tools/hackerman-etl-from-darknavy-web3.py",
        "--cache-dir",
        "cache/darknavy-web3",
        "--out-dir",
        str(_expand_date(row["output_subtree"], date)),
        "--dry-run",
        "--json-summary",
    ]


def _darknavy_live_command(row: Dict[str, Any], *, date: str, max_pages: int) -> List[str]:
    cmd = _darknavy_command(row, date=date)
    cmd.remove("--dry-run")
    cmd.extend(["--fetch", "--max-pages", str(max_pages)])
    return cmd


def _single_incident_source_collection(
    row: Dict[str, Any],
    *,
    date: str,
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Any]:
    refs: List[str] = []
    refs.extend(_string_list(_expand_date(row.get("url_or_api"), date)))
    refs.extend(_string_list(_expand_date(row.get("source_refs"), date)))

    expanded_obligations = _expand_date(_source_obligations(row), date)
    obligations = expanded_obligations if isinstance(expanded_obligations, list) else []
    for obligation in obligations:
        if isinstance(obligation, dict):
            refs.extend(_string_list(obligation.get("source_refs")))

    refs = _dedupe(refs)
    output_subtree = str(_expand_date(row.get("output_subtree"), date) or "")
    expected_artifacts = (
        [
            f"{output_subtree}/record.yaml",
            f"{output_subtree}/SOURCE_COLLECTION_TODO.md",
        ]
        if output_subtree
        else []
    )

    return {
        "schema": SOURCE_COLLECTION_SCHEMA,
        "source_id": row.get("source_id"),
        "collection_status": "needs_source_collection",
        "promotion_allowed": False,
        "promotion_blockers": [
            "single_incident_backlog",
            "open_source_obligations",
        ],
        "source_urls": [ref for ref in refs if _is_url(ref)],
        "local_refs": [ref for ref in refs if not _is_url(ref)],
        "expected_local_artifacts": [
            {
                "path": path,
                "exists": (repo_root / path).exists(),
            }
            for path in expected_artifacts
        ],
        "source_obligations": obligations,
        "quality_gate": row.get("quality_gate", {}),
        "next_action": "Collect/verify the listed source URLs and close source_obligations before detector or source-code promotion.",
    }


def _single_incident_fetch_collection(
    row: Dict[str, Any],
    *,
    date: str,
    repo_root: Path = REPO_ROOT,
    allow_live_fetch: bool = False,
    cache_dir: Path = DEFAULT_SINGLE_INCIDENT_CACHE,
    fixture_dir: Path | None = None,
    timeout_seconds: float = 20.0,
) -> Dict[str, Any]:
    collection = _single_incident_source_collection(row, date=date, repo_root=repo_root)
    source_urls = collection.get("source_urls") if isinstance(collection.get("source_urls"), list) else []
    fetched_sources = [
        _fetch_url_metadata(
            str(url),
            allow_live_fetch=allow_live_fetch,
            cache_dir=cache_dir,
            fixture_dir=fixture_dir,
            timeout_seconds=timeout_seconds,
        )
        for url in source_urls
    ]
    open_obligations = _open_source_obligations(row)
    closed_obligation_ids = [
        str(item.get("obligation_id"))
        for item in _source_obligations(row)
        if str(item.get("status") or "").strip().lower() == "closed" and item.get("obligation_id")
    ]
    open_obligation_ids = [
        str(item.get("obligation_id"))
        for item in open_obligations
        if item.get("obligation_id")
    ]
    status_counts: Dict[str, int] = {}
    for item in fetched_sources:
        status = str(item.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    fetch_adapter = row.get("fetch_adapter") if isinstance(row.get("fetch_adapter"), dict) else {}
    collection.update(
        {
            "schema": SINGLE_INCIDENT_FETCH_SCHEMA,
            "collection_status": "source_collection_open" if open_obligations else "source_collection_collected",
            "fetch_adapter": fetch_adapter,
            "fetch_status_counts": status_counts,
            "fetched_sources": fetched_sources,
            "cache_dir": str(cache_dir),
            "fixture_dir": str(fixture_dir) if fixture_dir else None,
            "open_source_obligation_ids": open_obligation_ids,
            "closed_source_obligation_ids": closed_obligation_ids,
            "promotion_allowed": False,
            "promotion_blockers": [
                *(
                    ["open_source_obligations"]
                    if open_obligations
                    else ["manual_promotion_review_required"]
                ),
                "single_incident_fetch_metadata_is_not_typed_record_promotion",
            ],
            "next_action": (
                "Close open source_obligations before typed-record promotion."
                if open_obligations
                else "Review fetched source metadata locally before typed-record promotion."
            ),
        }
    )
    return collection


def plan_source(
    row: Dict[str, Any],
    *,
    date: str,
    repo_root: Path = REPO_ROOT,
    allow_live_fetch: bool = False,
    fetch_single_incident: bool = False,
    cache_dir: Path = DEFAULT_SINGLE_INCIDENT_CACHE,
    fixture_dir: Path | None = None,
    max_pages: int = 10,
    timeout_seconds: float = 20.0,
) -> Dict[str, Any]:
    source_id = row["source_id"]
    miner = row.get("miner") or {}
    mode = miner.get("mode")
    status = row.get("status")
    network_required = bool((row.get("network_requirement") or {}).get("required"))
    expanded_output = _expand_date(row.get("output_subtree"), date)
    operator_authorization = _operator_authorized_source_closure(row)

    base: Dict[str, Any] = {
        "source_id": source_id,
        "name": row.get("name", source_id),
        "mode": mode,
        "status": "todo",
        "network_required": network_required,
        "live_fetch_enabled": False,
        "cursor": _expand_date(row.get("cursor", {}), date),
        "output_subtree": expanded_output,
        "promotion_target": _expand_date(row.get("promotion_target", {}), date),
        "quality_gate": row.get("quality_gate", {}),
        "source_obligations": _operator_authorized_obligations(
            _expand_date(_source_obligations(row), date),
            operator_authorization,
        ),
    }
    if operator_authorization is not None:
        base["operator_authorized_source_closure"] = operator_authorization

    if mode in {"single_incident_backlog", "single_incident_fetch"}:
        source_collection = (
            _single_incident_fetch_collection(
                row,
                date=date,
                repo_root=repo_root,
                allow_live_fetch=allow_live_fetch,
                cache_dir=cache_dir,
                fixture_dir=fixture_dir,
                timeout_seconds=timeout_seconds,
            )
            if mode == "single_incident_fetch" and fetch_single_incident
            else _single_incident_source_collection(row, date=date, repo_root=repo_root)
        )
        source_collection = _apply_operator_authorized_source_closure(
            source_collection,
            operator_authorization,
        )
        plan_status = (
            "operator_authorized_source_closure"
            if operator_authorization is not None
            else "backlog"
        )
        base.update(
            {
                "status": plan_status,
                "plan_kind": "source_collection",
                "source_collection": source_collection,
                "reason": row.get("backlog_reason") or (row.get("network_requirement") or {}).get("reason", ""),
                "next_action": (
                    "No source-miner source-evidence action required; preserve downstream outcome/root-cause boundaries."
                    if operator_authorization is not None
                    else "Collect source-specific bridge incident evidence; keep promotion blocked until obligations close."
                ),
                "notes": [
                    (
                        "Explicit single-incident fetch metadata was collected; this still is not typed-record promotion."
                        if mode == "single_incident_fetch" and fetch_single_incident
                        else "This is an offline collection packet, not a live fetch or promotion plan."
                    ),
                    "allow-live-fetch alone does not change single-incident rows to live_planned; use --fetch-single-incident explicitly.",
                    *(
                        [
                            "Operator-authorized source closure is not external platform outcome evidence.",
                        ]
                        if operator_authorization is not None
                        else []
                    ),
                ],
            }
        )
        if mode == "single_incident_fetch":
            base["single_incident_fetch_enabled"] = bool(fetch_single_incident)
            base["live_fetch_enabled"] = bool(fetch_single_incident and allow_live_fetch)
        return base

    if status in {"BLOCKED_NO_LIVE_SOURCE", "backlog"} or mode in {"blocked_no_live_source"}:
        base.update(
            {
                "status": "backlog",
                "reason": row.get("backlog_reason") or (row.get("network_requirement") or {}).get("reason", ""),
                "next_action": "Keep as backlog until stable source mechanics and typed fetcher are available.",
            }
        )
        return base

    if source_id in POSTMORTEM_PLANS:
        live_fetch = bool(allow_live_fetch)
        base.update(
            {
                "status": "live_planned" if live_fetch else "planned",
                "plan_kind": "command",
                "command": _postmortem_command(row, date=date, live_fetch=live_fetch, max_pages=max_pages),
                "live_fetch_enabled": live_fetch,
                "activation_gate": "explicit_operator_flag" if live_fetch else "not_requested",
                "max_pages": max_pages if live_fetch else None,
                "reason": POSTMORTEM_PLANS[source_id]["reason"],
                "notes": [
                    (
                        "Live fetch explicitly requested; command is bounded by --max-pages and still requires operator execution."
                        if live_fetch
                        else "No network flag is included; live fetch requires --allow-live-fetch."
                    ),
                    "An empty offline cache may make the underlying miner return BLOCKED-NO-REAL-SOURCE when live fetch is not enabled.",
                ],
            }
        )
        return base

    if source_id in DARKNAVY_PLANS:
        live_fetch = bool(allow_live_fetch)
        base.update(
            {
                "status": "live_planned" if live_fetch else "planned",
                "plan_kind": "command",
                "command": _darknavy_live_command(row, date=date, max_pages=max_pages)
                if live_fetch
                else _darknavy_command(row, date=date),
                "live_fetch_enabled": live_fetch,
                "activation_gate": "explicit_operator_flag" if live_fetch else "not_requested",
                "max_pages": max_pages if live_fetch else None,
                "reason": DARKNAVY_PLANS[source_id]["reason"],
                "notes": [
                    (
                        "Live fetch explicitly requested; the miner is bounded by --max-pages and emits source-backed records."
                        if live_fetch
                        else "No network flag is included; live fetch requires --allow-live-fetch."
                    ),
                    "The offline planner remains available as make darknavy-web3-plan for route metadata only.",
                ],
            }
        )
        return base

    tool_path = miner.get("tool_path")
    tool_exists = bool(isinstance(tool_path, str) and (repo_root / tool_path).exists())
    if miner.get("makefile_target"):
        base.update(
            {
                "status": "delegated_plan",
                "plan_kind": "make_target",
                "command": ["make", str(miner["makefile_target"]), "JSON=1"],
                "reason": "Registry points at an existing make target; external-intel runner is not asserting that target is network-free.",
            }
        )
        return base

    base.update(
        {
            "status": "todo",
            "reason": (
                "Registered source has no safe dry-run command mapping in external-intel-refresh.py."
                if tool_exists
                else f"Registered miner is missing on disk: {tool_path}"
            ),
            "next_action": "Add a source-specific live fetcher or dry-run adapter before promotion.",
        }
    )
    return base


def build_summary(
    data: Dict[str, Any],
    *,
    selected: Sequence[Dict[str, Any]],
    validation_errors: Sequence[str],
    date: str,
    registry_path: Path,
    repo_root: Path = REPO_ROOT,
    allow_live_fetch: bool = False,
    fetch_single_incident: bool = False,
    cache_dir: Path = DEFAULT_SINGLE_INCIDENT_CACHE,
    fixture_dir: Path | None = None,
    max_pages: int = 10,
    timeout_seconds: float = 20.0,
) -> Dict[str, Any]:
    plans = [
        plan_source(
            row,
            date=date,
            repo_root=repo_root,
            allow_live_fetch=allow_live_fetch,
            fetch_single_incident=fetch_single_incident,
            cache_dir=cache_dir,
            fixture_dir=fixture_dir,
            max_pages=max_pages,
            timeout_seconds=timeout_seconds,
        )
        for row in selected
    ]
    counts: Dict[str, int] = {}
    for plan in plans:
        counts[plan["status"]] = counts.get(plan["status"], 0) + 1
    return {
        "schema": SUMMARY_SCHEMA,
        "registry": _repo_rel(registry_path, repo_root),
        "registry_schema": data.get("schema"),
        "registry_valid": not validation_errors,
        "validation_errors": list(validation_errors),
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "date": date,
        "allow_live_fetch": bool(allow_live_fetch),
        "activation_gate": "explicit_operator_flag" if allow_live_fetch else "not_requested",
        "fetch_single_incident": bool(fetch_single_incident),
        "max_pages": max_pages if allow_live_fetch else None,
        "selected_source_ids": [row["source_id"] for row in selected],
        "counts": counts,
        "plans": plans,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="external-intel-refresh",
        description="Validate and plan refresh work for reference/external_intel_sources.yaml.",
    )
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--source", action="append", default=[], help="source_id to include; repeatable")
    parser.add_argument("--date", default=_today(), help="YYYY-MM-DD used for <date> path expansion")
    parser.add_argument("--list-sources", action="store_true")
    parser.add_argument("--validate-registry", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    parser.add_argument("--output", type=Path, default=None, help="write JSON summary to this path")
    parser.add_argument(
        "--allow-live-fetch",
        action="store_true",
        help="emit bounded live-fetch commands for supported post-mortem sources",
    )
    parser.add_argument(
        "--fetch-single-incident",
        action="store_true",
        help="collect explicit fixture/cache/live metadata for single_incident_fetch rows",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_SINGLE_INCIDENT_CACHE,
        help="cache directory for --fetch-single-incident URL bodies and metadata",
    )
    parser.add_argument(
        "--fixture-dir",
        type=Path,
        default=None,
        help="offline fixture directory keyed by sha256(url)[:24] for --fetch-single-incident tests",
    )
    parser.add_argument("--max-pages", type=int, default=10, help="bounded page count for --allow-live-fetch plans")
    parser.add_argument("--timeout-seconds", type=float, default=20.0, help="per-URL timeout for live single-incident fetches")
    return parser


def _print_text_summary(summary: Dict[str, Any]) -> None:
    print(f"external-intel registry: {summary['registry']} valid={summary['registry_valid']}")
    if summary["validation_errors"]:
        for error in summary["validation_errors"]:
            print(f"ERROR: {error}")
    for plan in summary["plans"]:
        status = plan["status"]
        source_id = plan["source_id"]
        print(f"{source_id}: {status}")
        if plan.get("command"):
            print("  command: " + " ".join(plan["command"]))
        elif plan.get("reason"):
            print("  reason: " + plan["reason"])


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    try:
        data = load_registry(args.registry)
        selected = select_sources(data, args.source)
    except (OSError, RegistryError, yaml.YAMLError) as exc:
        payload = {
            "schema": SUMMARY_SCHEMA,
            "registry": str(args.registry),
            "registry_valid": False,
            "validation_errors": [str(exc)],
            "plans": [],
        }
        if args.json_summary:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    validation_errors = validate_registry(data, repo_root=REPO_ROOT)
    summary = build_summary(
        data,
        selected=selected,
        validation_errors=validation_errors,
        date=args.date,
        registry_path=args.registry,
        repo_root=REPO_ROOT,
        allow_live_fetch=bool(args.allow_live_fetch),
        fetch_single_incident=bool(args.fetch_single_incident),
        cache_dir=args.cache_dir,
        fixture_dir=args.fixture_dir,
        max_pages=int(args.max_pages),
        timeout_seconds=float(args.timeout_seconds),
    )

    if args.list_sources:
        source_ids = [row["source_id"] for row in selected]
        if args.json_summary:
            print(json.dumps({"sources": source_ids}, indent=2, sort_keys=True))
        else:
            print("\n".join(source_ids))
        return 0 if not validation_errors else 2

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json_summary or args.validate_registry:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        _print_text_summary(summary)

    return 0 if not validation_errors else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
