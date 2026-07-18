#!/usr/bin/env python3
"""Prioritize real-world recall gaps from the recall scoreboard + sidecars.

Reads ``reports/realworld_recall_scoreboard.json`` plus any
``realworld_recall_scoreboard_external*.json`` sidecars and
``external_recall_samples*.json`` manifests that exist in the same reports
directory. The output ranks weak attack classes by:

* missed same-class recall,
* amount of external evidence already available, and
* likely detector-generalization leverage (cross-class detector overlap on
  misses, plus own-detector-vs-sibling-detector gaps).

The tool emits both JSON and Markdown and stays honest about uncertainty:

* schema-validated inputs only; malformed sidecars/manifests are reported,
  not silently consumed;
* scorable recall math is derived from per-sample rows only;
* ``uncategorized`` is routed to a separate taxonomy-debt section instead of
  being mixed into the actionable detector ranking.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORTS_DIR = REPO_ROOT / "reports"
DEFAULT_SCOREBOARD = DEFAULT_REPORTS_DIR / "realworld_recall_scoreboard.json"
DEFAULT_OUT_JSON = DEFAULT_REPORTS_DIR / "realworld_recall_gap_priorities.json"
DEFAULT_OUT_MD = DEFAULT_REPORTS_DIR / "realworld_recall_gap_priorities.md"
DEFAULT_CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
DEFAULT_QUALITY_GLOB = "external_recall_manifest_quality*.json"

SCHEMA = "auditooor.realworld_recall_gap_priorities.v1"
SCOREBOARD_SCHEMA = "auditooor.realworld_recall_scoreboard.v1"
MANIFEST_SCHEMA = "auditooor.external_recall_samples.v1"
QUALITY_SCHEMA = "auditooor.external_recall_manifest_quality.v1"
CLASS_MAP_SCHEMA = "auditooor.detector_class_map_complete.v1"
CLASS_MAP_CONFIDENCES = {"high", "medium", "low"}

LEGACY_ATTACK_CLASS_ALIASES = {
    "reentrancy": "reentrancy-cross-contract",
    "access-control": "admin-bypass",
    "signature-replay": "signature-replay-cross-domain",
    "oracle-manipulation": "oracle-price-manipulation",
    "flashloan": "callback-hook-exploit",
    "bridge-cross-chain": "bridge-proof-domain-bypass",
    "erc4626-vault": "first-depositor-inflation",
    "liquidation": "liquidation-trigger-poison",
    "reward-accounting": "rewards-distribution-skew",
    "rounding-precision": "rounding-direction-attack",
    "dos-griefing": "dos-cap-weakening",
    "upgradeability": "proxy-hijack",
    "governance": "gov-param-injection",
    "token-transfer": "missing-recipient-validation",
    "input-validation": "missing-recipient-validation",
    "mev-ordering": "rounding-direction-attack",
    "nft-asset": "callback-hook-exploit",
    "zk-crypto": "signature-forgery",
    "accounting-state": "fund-loss-via-arithmetic",
    "fee-handling": "fee-redirect",
}

LANGUAGE_BY_SUFFIX = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".yul": "yul",
    ".go": "go",
    ".rs": "rust",
    ".move": "move",
    ".cairo": "cairo",
}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso8601(value: Any) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _relpath(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return str(path.resolve())


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _sample_key(sample: dict[str, Any]) -> str:
    return _sample_key_with_language(
        sample,
        str(sample.get("sample_origin") or ""),
        _sample_language(sample),
    )


def _sample_key_with_language(
    sample: dict[str, Any],
    sample_origin: str,
    target_language: str,
) -> str:
    return "|".join(
        [
            str(sample_origin or ""),
            str(target_language or ""),
            str(sample.get("attack_class") or ""),
            str(sample.get("source") or ""),
            str(sample.get("slug") or sample.get("id") or sample.get("path") or ""),
        ]
    )


def _manifest_key(sample: dict[str, Any]) -> str:
    return _sample_key_with_language(sample, "external_repo", _sample_language(sample))


def _key_language_join_variants(value: Any) -> list[str]:
    language = _normalize_language(value)
    if not language or language == "unknown":
        return ["unknown", "", "solidity"]
    if language == "solidity":
        return ["solidity", "unknown", ""]
    return [language]


def _sample_join_keys(sample: dict[str, Any], sample_origin: str) -> set[str]:
    return {
        _sample_key_with_language(sample, sample_origin, language)
        for language in _key_language_join_variants(_sample_language(sample))
    }


def _manifest_join_keys(sample: dict[str, Any]) -> set[str]:
    return _sample_join_keys(sample, "external_repo")


def _quality_key(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")


def _repo_label(source: str) -> str:
    text = str(source or "").strip()
    if text.startswith("external_repo:"):
        text = text[len("external_repo:") :]
    if ":" in text:
        text = text.split(":", 1)[0]
    return text or "unknown-source"


def _normalize_attack_class(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    if not text:
        return "uncategorized"
    return LEGACY_ATTACK_CLASS_ALIASES.get(text, text)


def _normalize_language(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    aliases = {
        "sol": "solidity",
        "evm": "solidity",
        "golang": "go",
        "cosmos": "go",
        "cosmos-go": "go",
        "substrate": "rust",
        "near": "rust",
        "zebra": "rust",
        "rs": "rust",
    }
    return aliases.get(text, text)


def _language_from_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return LANGUAGE_BY_SUFFIX.get(Path(text).suffix.lower(), "")


def _sample_language(sample: dict[str, Any]) -> str:
    language = _normalize_language(
        sample.get("target_language")
        or sample.get("language")
        or sample.get("lang")
    )
    if language:
        return language
    return (
        _language_from_path(sample.get("path"))
        or _language_from_path(sample.get("vuln_path"))
        or _language_from_path(sample.get("source_path"))
        or _language_from_path(sample.get("source"))
        or "unknown"
    )


def _load_detector_class_map(path: Path = DEFAULT_CLASS_MAP) -> dict[str, set[str]]:
    if not path.exists():
        return {}
    try:
        import yaml

        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    if not isinstance(payload, dict) or payload.get("schema") != CLASS_MAP_SCHEMA:
        return {}
    mappings = payload.get("mappings") or {}
    if not isinstance(mappings, dict):
        return {}

    out: dict[str, set[str]] = {}
    for slug, row in mappings.items():
        if not isinstance(row, dict):
            continue
        attack_class = _normalize_attack_class(row.get("attack_class"))
        confidence = str(row.get("confidence") or "").strip().lower()
        if attack_class == "uncategorized" or confidence not in CLASS_MAP_CONFIDENCES:
            continue
        classes = {attack_class}
        raw_aliases = row.get("attack_class_aliases") or []
        if isinstance(raw_aliases, str):
            raw_aliases = [raw_aliases]
        if isinstance(raw_aliases, list):
            for alias in raw_aliases:
                alias_class = _normalize_attack_class(alias)
                if alias_class != "uncategorized":
                    classes.add(alias_class)
        out[str(slug)] = classes
    return out


DETECTOR_CLASS_MAP = _load_detector_class_map()


def _reconcile_recall_flags(sample: dict[str, Any]) -> dict[str, Any]:
    """Re-interpret historical scoreboard rows with the current class map.

    External sidecar scoreboards are deliberately cached artifacts, but their
    `independent_same_class_fired` boolean can become stale after detector
    taxonomy repairs. The firing detector list is the durable observation, so
    the prioritizer should count a current same-class detector as a catch.
    """
    attack_class = _normalize_attack_class(sample.get("attack_class"))
    detectors = [str(det) for det in (sample.get("independent_firing_detectors") or []) if det]
    matching = [
        det for det in detectors
        if attack_class in DETECTOR_CLASS_MAP.get(det, set())
        and attack_class != "uncategorized"
    ]
    if matching and not bool(sample.get("independent_same_class_fired")):
        sample["_same_class_reconciled_from_current_map"] = True
        sample["_same_class_reconciled_detectors"] = matching[:6]
    if matching:
        sample["independent_same_class_fired"] = True
        sample["independent_any_fired"] = True
    elif detectors and not bool(sample.get("independent_any_fired")):
        sample["_any_reconciled_from_detector_list"] = True
        sample["independent_any_fired"] = True
    return sample


def _priority_band(score: float) -> str:
    if score >= 70.0:
        return "P0"
    if score >= 55.0:
        return "P1"
    if score >= 40.0:
        return "P2"
    return "P3"


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"{path.name}: parse_error: {exc}"
    if not isinstance(payload, dict):
        return None, f"{path.name}: shape_error: top-level JSON must be an object"
    return payload, None


def _quality_index_key(
    attack_class: str,
    source: str,
    kind: str,
    value: str,
    target_language: str = "",
) -> str:
    return "|".join(
        [
            _normalize_attack_class(attack_class),
            _normalize_language(target_language),
            str(source or "").strip(),
            kind,
            _quality_key(value),
        ]
    )


def _quality_index_language_variants(value: Any) -> list[str]:
    language = _normalize_language(value)
    if not language or language == "unknown":
        return ["", "unknown", "solidity"]
    return [language]


def _quality_lookup_language_variants(value: Any) -> list[str]:
    language = _normalize_language(value)
    if not language or language == "unknown":
        return ["", "unknown"]
    return [language]


def _quality_sample_source_path(value: Any, report_path: Path) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    path = Path(text).expanduser()
    if path.is_absolute():
        return _relpath(path, REPO_ROOT) if path.exists() else text
    repo_candidate = REPO_ROOT / path
    if repo_candidate.exists():
        return _relpath(repo_candidate, REPO_ROOT)
    report_candidate = report_path.parent / path
    if report_candidate.exists():
        return _relpath(report_candidate, REPO_ROOT)
    return text


def discover_quality_reports(reports_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    loaded: list[dict[str, Any]] = []
    if not reports_dir.is_dir():
        return loaded, errors
    for path in sorted(reports_dir.glob(DEFAULT_QUALITY_GLOB)):
        payload, err = _load_json(path)
        if err:
            errors.append(err)
            continue
        if payload.get("schema") != QUALITY_SCHEMA:
            errors.append(f"{path.name}: schema_mismatch")
            continue
        rows = payload.get("rows")
        if not isinstance(rows, list):
            errors.append(f"{path.name}: rows_not_list")
            continue
        loaded.append({"path": path.resolve(), "data": payload})
    loaded.sort(
        key=lambda row: (
            _parse_iso8601(row["data"].get("generated_at")),
            str(row["path"]),
        )
    )
    return loaded, errors


def build_quality_index(quality_reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in quality_reports:
        path = item["path"]
        data = item["data"]
        generated_at = str(data.get("generated_at") or "")
        for row in data.get("rows") or []:
            if not isinstance(row, dict):
                continue
            attack_class = str(row.get("attack_class") or "").strip()
            source = str(row.get("source") or "").strip()
            if not attack_class:
                continue
            entry = dict(row)
            entry["target_language"] = _sample_language(row)
            entry["path"] = _quality_sample_source_path(row.get("path"), path)
            entry["_quality_report_path"] = str(path)
            entry["_quality_generated_at"] = generated_at
            keys: list[str] = []
            target_language = _sample_language(row)
            row_id = str(row.get("id") or row.get("slug") or "").strip()
            row_path = str(row.get("path") or row.get("vuln_path") or "").strip()
            for language_key in _quality_index_language_variants(target_language):
                if row_id:
                    keys.append(_quality_index_key(attack_class, source, "id", row_id, language_key))
                    if not source:
                        keys.append(_quality_index_key(attack_class, "", "id", row_id, language_key))
                if row_path:
                    keys.append(_quality_index_key(attack_class, source, "path", row_path, language_key))
                    if not source:
                        keys.append(_quality_index_key(attack_class, "", "path", row_path, language_key))
            for key in keys:
                incumbent = index.get(key)
                if incumbent is None or (
                    _parse_iso8601(generated_at),
                    str(path),
                ) >= (
                    _parse_iso8601(incumbent.get("_quality_generated_at")),
                    str(incumbent.get("_quality_report_path") or ""),
                ):
                    index[key] = entry
    return index


def _quality_for_external_sample(
    sample: dict[str, Any],
    quality_index: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    if str(sample.get("sample_origin") or "") != "external_repo":
        return None
    attack_class = str(sample.get("attack_class") or "").strip()
    source = str(sample.get("source") or "").strip()
    target_language = _sample_language(sample)
    values = [
        ("id", sample.get("slug") or sample.get("id") or ""),
        ("id", sample.get("path") or sample.get("vuln_path") or ""),
        ("path", sample.get("path") or sample.get("vuln_path") or ""),
    ]
    for kind, value in values:
        text = str(value or "").strip()
        if not text:
            continue
        for src in (source, ""):
            for language_key in _quality_lookup_language_variants(target_language):
                key = _quality_index_key(attack_class, src, kind, text, language_key)
                found = quality_index.get(key)
                if found:
                    return found
    return None


def apply_quality_filter(
    measured_samples: list[dict[str, Any]],
    manifest_samples: list[dict[str, Any]],
    quality_index: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    counts = {
        "quality_reports_indexed_rows": len({
            id(row) for row in quality_index.values()
        }),
        "measured_external_rows_kept": 0,
        "measured_external_rows_filtered": 0,
        "manifest_external_rows_kept": 0,
        "manifest_external_rows_filtered": 0,
    }

    filtered_measured: list[dict[str, Any]] = []
    for sample in measured_samples:
        quality = _quality_for_external_sample(sample, quality_index)
        if quality and not bool(quality.get("gap_prioritization_eligible")):
            counts["measured_external_rows_filtered"] += 1
            continue
        if str(sample.get("sample_origin") or "") == "external_repo":
            counts["measured_external_rows_kept"] += 1
        if quality:
            sample = dict(sample)
            sample["_external_recall_quality_state"] = str(quality.get("quality_state") or "")
            sample["_external_recall_source_state"] = str(quality.get("source_state") or "")
            sample["_external_recall_source_path"] = str(quality.get("path") or "")
            sample["_external_recall_quality_report"] = _relpath(
                Path(str(quality.get("_quality_report_path") or "")),
                REPO_ROOT,
            )
        filtered_measured.append(sample)

    filtered_manifests: list[dict[str, Any]] = []
    for sample in manifest_samples:
        externalized = dict(sample)
        externalized.setdefault("sample_origin", "external_repo")
        quality = _quality_for_external_sample(externalized, quality_index)
        if quality and not bool(quality.get("gap_prioritization_eligible")):
            counts["manifest_external_rows_filtered"] += 1
            continue
        counts["manifest_external_rows_kept"] += 1
        if quality:
            sample = dict(sample)
            sample["_external_recall_quality_state"] = str(quality.get("quality_state") or "")
            sample["_external_recall_source_state"] = str(quality.get("source_state") or "")
            sample["_external_recall_source_path"] = str(quality.get("path") or "")
            sample["_external_recall_quality_report"] = _relpath(
                Path(str(quality.get("_quality_report_path") or "")),
                REPO_ROOT,
            )
        filtered_manifests.append(sample)

    return filtered_measured, filtered_manifests, counts


def discover_scoreboards(scoreboard_path: Path, reports_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    candidates: dict[Path, None] = {}
    candidates[scoreboard_path.expanduser().resolve()] = None
    if reports_dir.is_dir():
        for path in sorted(reports_dir.glob("realworld_recall_scoreboard_external*.json")):
            candidates[path.resolve()] = None

    loaded: list[dict[str, Any]] = []
    for path in sorted(candidates):
        if not path.exists():
            if path == scoreboard_path.expanduser().resolve():
                errors.append(f"{path.name}: missing primary scoreboard")
            continue
        payload, err = _load_json(path)
        if err:
            errors.append(err)
            continue
        if payload.get("schema") != SCOREBOARD_SCHEMA:
            errors.append(f"{path.name}: schema_mismatch")
            continue
        loaded.append({"path": path, "data": payload})
    loaded.sort(
        key=lambda row: (
            _parse_iso8601(row["data"].get("generated_at")),
            str(row["path"]),
        )
    )
    return loaded, errors


def discover_manifests(
    reports_dir: Path,
    scoreboards: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    candidates: dict[Path, None] = {}
    if reports_dir.is_dir():
        for path in sorted(reports_dir.glob("external_recall_samples*.json")):
            candidates[path.resolve()] = None
    for item in scoreboards:
        raw = str(item["data"].get("external_manifest") or "").strip()
        if not raw:
            continue
        candidates[Path(raw).expanduser().resolve()] = None

    loaded: list[dict[str, Any]] = []
    for path in sorted(candidates):
        if not path.exists():
            errors.append(f"{path.name}: manifest_missing")
            continue
        payload, err = _load_json(path)
        if err:
            errors.append(err)
            continue
        if payload.get("schema") != MANIFEST_SCHEMA:
            errors.append(f"{path.name}: schema_mismatch")
            continue
        samples = payload.get("samples")
        if not isinstance(samples, list):
            errors.append(f"{path.name}: samples_not_list")
            continue
        loaded.append({"path": path, "data": payload})
    return loaded, errors


def collect_samples(scoreboards: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    latest_by_key: dict[str, dict[str, Any]] = {}
    counts = {
        "scoreboards_loaded": len(scoreboards),
        "per_sample_rows_seen": 0,
        "per_sample_rows_kept": 0,
        "aggregate_only_scoreboards": 0,
    }
    for item in scoreboards:
        path = item["path"]
        data = item["data"]
        rows = data.get("per_sample")
        if not isinstance(rows, list):
            counts["aggregate_only_scoreboards"] += 1
            continue
        generated_at = str(data.get("generated_at") or "")
        for row in rows:
            if not isinstance(row, dict):
                continue
            counts["per_sample_rows_seen"] += 1
            sample = dict(row)
            sample["_scoreboard_generated_at"] = generated_at
            sample["_scoreboard_path"] = str(path)
            sample["attack_class"] = _normalize_attack_class(sample.get("attack_class"))
            sample["target_language"] = _sample_language(sample)
            sample = _reconcile_recall_flags(sample)
            key = _sample_key(sample)
            incumbent = latest_by_key.get(key)
            if incumbent is None:
                latest_by_key[key] = sample
                continue
            incumbent_ts = _parse_iso8601(incumbent.get("_scoreboard_generated_at"))
            sample_ts = _parse_iso8601(sample.get("_scoreboard_generated_at"))
            if (sample_ts, str(path)) >= (
                incumbent_ts,
                str(incumbent.get("_scoreboard_path") or ""),
            ):
                latest_by_key[key] = sample
    kept = sorted(
        latest_by_key.values(),
        key=lambda row: (
            str(row.get("attack_class") or ""),
            str(row.get("sample_origin") or ""),
            str(row.get("slug") or ""),
        ),
    )
    counts["per_sample_rows_kept"] = len(kept)
    return kept, counts


def collect_manifest_samples(manifests: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    latest_by_key: dict[str, dict[str, Any]] = {}
    counts = {
        "manifests_loaded": len(manifests),
        "manifest_rows_seen": 0,
        "manifest_rows_kept": 0,
    }
    for item in manifests:
        path = item["path"]
        data = item["data"]
        for idx, row in enumerate(data.get("samples") or [], 1):
            if not isinstance(row, dict):
                continue
            counts["manifest_rows_seen"] += 1
            sample = dict(row)
            sample["_manifest_path"] = str(path)
            sample["_manifest_index"] = idx
            sample["attack_class"] = _normalize_attack_class(sample.get("attack_class"))
            sample["target_language"] = _sample_language(sample)
            key = _manifest_key(sample)
            latest_by_key[key] = sample
    kept = sorted(
        latest_by_key.values(),
        key=lambda row: (
            str(row.get("attack_class") or ""),
            str(row.get("source") or ""),
            str(row.get("id") or row.get("path") or ""),
        ),
    )
    counts["manifest_rows_kept"] = len(kept)
    return kept, counts


def filter_samples_by_language(
    measured_samples: list[dict[str, Any]],
    manifest_samples: list[dict[str, Any]],
    target_language: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    language = _normalize_language(target_language)
    counts = {
        "target_language_filter_applied": 1 if language else 0,
        "measured_rows_before_language_filter": len(measured_samples),
        "measured_rows_after_language_filter": len(measured_samples),
        "manifest_rows_before_language_filter": len(manifest_samples),
        "manifest_rows_after_language_filter": len(manifest_samples),
    }
    if not language:
        return measured_samples, manifest_samples, counts

    measured = [
        row for row in measured_samples
        if _sample_language(row) == language
    ]
    manifests = [
        row for row in manifest_samples
        if _sample_language(row) == language
    ]
    counts["measured_rows_after_language_filter"] = len(measured)
    counts["manifest_rows_after_language_filter"] = len(manifests)
    return measured, manifests, counts


def _new_class_state() -> dict[str, Any]:
    return {
        "total_samples": 0,
        "internal_samples": 0,
        "external_samples_measured": 0,
        "compile_failed": 0,
        "same_class_catches": 0,
        "any_catches": 0,
        "own_catches": 0,
        "same_class_misses": 0,
        "misses_with_any_independent": 0,
        "own_gap_misses": 0,
        "external_same_class_catches": 0,
        "external_same_class_misses": 0,
        "manifest_external_samples": 0,
        "manifest_external_unmeasured": 0,
        "missed_samples": [],
        "top_cross_class_detectors": Counter(),
        "external_repos": Counter(),
    }


def aggregate_priorities(
    measured_samples: list[dict[str, Any]],
    manifest_samples: list[dict[str, Any]],
    *,
    include_uncategorized: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    by_class: dict[str, dict[str, Any]] = defaultdict(_new_class_state)
    measured_external_keys: set[str] = set()

    for row in measured_samples:
        attack_class = str(row.get("attack_class") or "uncategorized").strip() or "uncategorized"
        state = by_class[attack_class]
        if str(row.get("sample_origin") or "") == "external_repo":
            measured_external_keys.update(_sample_join_keys(row, "external_repo"))
            state["external_repos"][_repo_label(str(row.get("source") or ""))] += 1
        if row.get("compile_error"):
            state["compile_failed"] += 1
            continue
        state["total_samples"] += 1
        if str(row.get("sample_origin") or "") == "external_repo":
            state["external_samples_measured"] += 1
        else:
            state["internal_samples"] += 1
        if bool(row.get("own_detector_fired")):
            state["own_catches"] += 1
        if bool(row.get("independent_any_fired")):
            state["any_catches"] += 1
        if bool(row.get("independent_same_class_fired")):
            state["same_class_catches"] += 1
            if str(row.get("sample_origin") or "") == "external_repo":
                state["external_same_class_catches"] += 1
            continue

        state["same_class_misses"] += 1
        if str(row.get("sample_origin") or "") == "external_repo":
            state["external_same_class_misses"] += 1
        if bool(row.get("independent_any_fired")):
            state["misses_with_any_independent"] += 1
        if bool(row.get("own_detector_fired")):
            state["own_gap_misses"] += 1
        for detector in row.get("independent_firing_detectors") or []:
            if detector:
                state["top_cross_class_detectors"][str(detector)] += 1
        state["missed_samples"].append(
            {
                "slug": str(row.get("slug") or ""),
                "source": str(row.get("source") or ""),
                "sample_origin": str(row.get("sample_origin") or ""),
                "target_language": _sample_language(row),
                "source_path": str(
                    row.get("source_path")
                    or row.get("_external_recall_source_path")
                    or row.get("path")
                    or row.get("vuln_path")
                    or ""
                ),
                "source_state": str(row.get("_external_recall_source_state") or ""),
                "quality_report_path": str(row.get("_external_recall_quality_report") or ""),
                "own_detector_fired": bool(row.get("own_detector_fired")),
                "independent_any_fired": bool(row.get("independent_any_fired")),
                "independent_firing_detectors": [
                    str(det)
                    for det in (row.get("independent_firing_detectors") or [])
                    if det
                ][:6],
            }
        )

    for row in manifest_samples:
        attack_class = str(row.get("attack_class") or "uncategorized").strip() or "uncategorized"
        state = by_class[attack_class]
        state["manifest_external_samples"] += 1
        if not (_manifest_join_keys(row) & measured_external_keys):
            state["manifest_external_unmeasured"] += 1
        state["external_repos"][_repo_label(str(row.get("source") or ""))] += 1

    priorities: list[dict[str, Any]] = []
    taxonomy_debt: list[dict[str, Any]] = []
    totals = {
        "measured_samples": len(measured_samples),
        "measured_scorable_samples": sum(int(state["total_samples"]) for state in by_class.values()),
        "measured_compile_failed": sum(int(state["compile_failed"]) for state in by_class.values()),
        "manifest_samples": len(manifest_samples),
    }

    for attack_class, state in sorted(by_class.items()):
        total = int(state["total_samples"])
        if total <= 0 and int(state["manifest_external_samples"]) <= 0:
            continue
        same_class_recall = round(state["same_class_catches"] / total, 4) if total else 0.0
        any_recall = round(state["any_catches"] / total, 4) if total else 0.0
        self_test_recall = round(state["own_catches"] / total, 4) if total else 0.0
        miss_rate = (state["same_class_misses"] / total) if total else 0.0
        miss_volume_component = _clamp01(state["same_class_misses"] / 10.0)
        missed_same_class_component = round(0.7 * miss_rate + 0.3 * miss_volume_component, 4)
        external_evidence_component = round(
            _clamp01((state["external_samples_measured"] + 0.5 * state["manifest_external_unmeasured"]) / 5.0),
            4,
        )
        wrong_touch_rate = (
            state["misses_with_any_independent"] / state["same_class_misses"]
            if state["same_class_misses"]
            else 0.0
        )
        own_gap_rate = (
            state["own_gap_misses"] / state["same_class_misses"]
            if state["same_class_misses"]
            else 0.0
        )
        any_gap = max(0.0, any_recall - same_class_recall)
        cross_detector_density = _clamp01(len(state["top_cross_class_detectors"]) / 8.0)
        leverage_component = round(
            0.45 * wrong_touch_rate
            + 0.25 * any_gap
            + 0.20 * own_gap_rate
            + 0.10 * cross_detector_density,
            4,
        )
        priority_score = round(
            100.0
            * (
                0.50 * missed_same_class_component
                + 0.25 * external_evidence_component
                + 0.25 * leverage_component
            ),
            1,
        )
        if attack_class == "uncategorized":
            priority_score = round(priority_score * 0.35, 1)

        top_detectors = [
            {"detector": name, "count": count}
            for name, count in state["top_cross_class_detectors"].most_common(5)
        ]
        missed_examples = state["missed_samples"][:5]
        external_repos = [
            {"repo": repo, "samples": count}
            for repo, count in state["external_repos"].most_common(5)
        ]
        external_total = int(state["external_samples_measured"]) + int(state["manifest_external_unmeasured"])
        external_same_total = int(state["external_same_class_catches"]) + int(state["external_same_class_misses"])
        external_same_recall = round(
            state["external_same_class_catches"] / external_same_total, 4
        ) if external_same_total else None

        entry = {
            "attack_class": attack_class,
            "priority_score": priority_score,
            "priority_band": _priority_band(priority_score),
            "samples_total": total,
            "same_class_misses": int(state["same_class_misses"]),
            "same_class_recall": same_class_recall,
            "realworld_recall_any": any_recall,
            "self_test_recall": self_test_recall,
            "gap_vs_self_test_pp": round((self_test_recall - same_class_recall) * 100.0, 1),
            "gap_vs_any_pp": round((any_recall - same_class_recall) * 100.0, 1),
            "missed_same_class_component": missed_same_class_component,
            "external_evidence_component": external_evidence_component,
            "generalization_leverage_component": leverage_component,
            "misses_with_any_independent": int(state["misses_with_any_independent"]),
            "own_gap_misses": int(state["own_gap_misses"]),
            "compile_failed": int(state["compile_failed"]),
            "external_evidence": {
                "measured_external_samples": int(state["external_samples_measured"]),
                "manifest_external_samples": int(state["manifest_external_samples"]),
                "manifest_external_unmeasured": int(state["manifest_external_unmeasured"]),
                "external_same_class_recall": external_same_recall,
                "external_same_class_misses": int(state["external_same_class_misses"]),
                "repo_examples": external_repos,
            },
            "top_cross_class_detectors_on_misses": top_detectors,
            "miss_examples": missed_examples,
        }
        entry["next_tasks"] = build_tasks(entry)

        if attack_class == "uncategorized" and not include_uncategorized:
            taxonomy_debt.append(entry)
        else:
            priorities.append(entry)

    priorities.sort(
        key=lambda row: (
            -float(row["priority_score"]),
            float(row["same_class_recall"]),
            -int(row["same_class_misses"]),
            row["attack_class"],
        )
    )
    for idx, row in enumerate(priorities, 1):
        row["rank"] = idx

    taxonomy_debt.sort(
        key=lambda row: (
            -float(row["same_class_misses"]),
            -float(row["priority_score"]),
        )
    )
    for idx, row in enumerate(taxonomy_debt, 1):
        row["rank"] = idx
    return priorities, taxonomy_debt, totals


def build_tasks(entry: dict[str, Any]) -> list[dict[str, Any]]:
    attack_class = str(entry.get("attack_class") or "unknown")
    missed = int(entry.get("same_class_misses") or 0)
    top_detectors = [
        str(row.get("detector") or "")
        for row in (entry.get("top_cross_class_detectors_on_misses") or [])
        if row.get("detector")
    ]
    miss_examples = [
        str(row.get("slug") or "")
        for row in (entry.get("miss_examples") or [])
        if row.get("slug")
    ]
    external = entry.get("external_evidence") if isinstance(entry.get("external_evidence"), dict) else {}
    repo_examples = [
        str(row.get("repo") or "")
        for row in (external.get("repo_examples") or [])
        if row.get("repo")
    ]
    tasks: list[dict[str, Any]] = []

    if attack_class == "uncategorized":
        tasks.append(
            {
                "task_type": "taxonomy-backfill",
                "summary": (
                    f"Backfill concrete attack classes for the top uncategorized misses "
                    f"({', '.join(miss_examples[:3]) or 'no slug examples available'}) so they can "
                    "enter same-class recall accounting."
                ),
            }
        )
        tasks.append(
            {
                "task_type": "mining",
                "summary": (
                    "Mine prior-audit and external-repo examples for the most common uncategorized "
                    "themes before authoring new detectors; otherwise the prioritizer cannot cluster them honestly."
                ),
            }
        )
        return tasks

    if missed <= 0:
        tasks.append(
            {
                "task_type": "observe",
                "summary": f"{attack_class} has no remaining same-class misses in the measured corpus.",
            }
        )
        return tasks

    if top_detectors:
        detectors_text = ", ".join(top_detectors[:2])
        examples_text = ", ".join(miss_examples[:2]) or "the top missed samples"
        tasks.append(
            {
                "task_type": "detector-generalization",
                "summary": (
                    f"Replay {attack_class} misses against {detectors_text} and split/generalize that logic "
                    f"into a same-class detector. Start with {examples_text}."
                ),
            }
        )
    else:
        examples_text = ", ".join(miss_examples[:2]) or "the current miss set"
        tasks.append(
            {
                "task_type": "new-detector-authoring",
                "summary": (
                    f"Author a fresh {attack_class} detector lane; {missed} misses currently have no useful "
                    f"cross-class overlap. Seed it from {examples_text}."
                ),
            }
        )

    if int(external.get("measured_external_samples") or 0) > 0:
        examples_text = ", ".join(repo_examples[:2]) or "the measured external repos"
        ext_recall = external.get("external_same_class_recall")
        if ext_recall is None:
            recall_text = "n/a"
        else:
            recall_text = f"{float(ext_recall) * 100:.1f}%"
        tasks.append(
            {
                "task_type": "external-replay",
                "summary": (
                    f"Use the measured external {attack_class} samples from {examples_text} as replay fixtures; "
                    f"current external same-class recall is {recall_text}."
                ),
            }
        )
    elif int(external.get("manifest_external_unmeasured") or 0) > 0:
        tasks.append(
            {
                "task_type": "measurement",
                "summary": (
                    f"Score the {int(external.get('manifest_external_unmeasured') or 0)} queued external "
                    f"{attack_class} manifest samples and fold them into the recall scoreboard."
                ),
            }
        )
    else:
        target_count = max(3, int(math.ceil(missed / 2.0)))
        tasks.append(
            {
                "task_type": "mining",
                "summary": (
                    f"Mine at least {target_count} new external {attack_class} samples; current evidence is "
                    "still internal-heavy."
                ),
            }
        )

    if int(entry.get("own_gap_misses") or 0) > 0:
        tasks.append(
            {
                "task_type": "sibling-detector-gap",
                "summary": (
                    f"Prioritize the {int(entry.get('own_gap_misses') or 0)} own-detector-backed misses where "
                    "the authored detector works but no sibling same-class detector generalizes."
                ),
            }
        )
    return tasks


def build_markdown(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    priorities = payload.get("priorities") if isinstance(payload.get("priorities"), list) else []
    taxonomy_debt = payload.get("taxonomy_debt") if isinstance(payload.get("taxonomy_debt"), list) else []
    inputs = payload.get("inputs") if isinstance(payload.get("inputs"), dict) else {}
    target_language = str(payload.get("target_language") or "").strip()
    lines: list[str] = []
    lines.append("# Real-world recall gap priorities")
    lines.append("")
    lines.append(f"Generated: {payload.get('generated_at')}")
    lines.append(f"Schema: `{SCHEMA}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Ranked attack classes: {summary.get('ranked_attack_classes', 0)}")
    lines.append(f"- Taxonomy-debt classes: {summary.get('taxonomy_debt_classes', 0)}")
    lines.append(f"- Measured scorable samples: {summary.get('measured_scorable_samples', 0)}")
    lines.append(f"- External manifest samples: {summary.get('manifest_samples', 0)}")
    if target_language:
        lines.append(f"- Target language filter: `{target_language}`")
    lines.append(f"- Scoreboards loaded: {inputs.get('loaded_scoreboards', 0)}")
    lines.append(f"- Manifests loaded: {inputs.get('loaded_manifests', 0)}")
    lines.append(f"- External quality reports loaded: {inputs.get('loaded_quality_reports', 0)}")
    quality_counts = inputs.get("quality_counts") if isinstance(inputs.get("quality_counts"), dict) else {}
    if quality_counts:
        lines.append(
            f"- Quality-filtered external rows: measured "
            f"{quality_counts.get('measured_external_rows_filtered', 0)}, manifest "
            f"{quality_counts.get('manifest_external_rows_filtered', 0)}"
        )
    language_counts = inputs.get("language_counts") if isinstance(inputs.get("language_counts"), dict) else {}
    if language_counts and target_language:
        lines.append(
            f"- Language-filtered rows: measured "
            f"{language_counts.get('measured_rows_before_language_filter', 0)} -> "
            f"{language_counts.get('measured_rows_after_language_filter', 0)}, manifest "
            f"{language_counts.get('manifest_rows_before_language_filter', 0)} -> "
            f"{language_counts.get('manifest_rows_after_language_filter', 0)}"
        )
    lines.append("")
    lines.append("## Ranking method")
    lines.append("")
    lines.append(
        "- Priority score = 50% missed same-class recall pressure + 25% external evidence "
        "+ 25% detector-generalization leverage."
    )
    lines.append(
        "- `uncategorized` is split out as taxonomy debt because its zero same-class recall is not directly actionable detector work."
    )
    lines.append(
        "- External rows with quality reports marked fixed, post-fix, out-of-class, or unvalidated are filtered before ranking; they are source-state work, not detector gaps."
    )
    lines.append("")
    lines.append("## Top attack classes")
    lines.append("")
    lines.append("| Rank | Band | Score | Attack class | Same-class recall | Misses | External measured | Leverage |")
    lines.append("|-----:|------|------:|--------------|------------------:|-------:|------------------:|---------:|")
    for row in priorities:
        ext = row.get("external_evidence") if isinstance(row.get("external_evidence"), dict) else {}
        lines.append(
            f"| {row.get('rank')} | {row.get('priority_band')} | {float(row.get('priority_score') or 0.0):.1f} | "
            f"{row.get('attack_class')} | {float(row.get('same_class_recall') or 0.0) * 100:.1f}% | "
            f"{int(row.get('same_class_misses') or 0)} | {int(ext.get('measured_external_samples') or 0)} | "
            f"{float(row.get('generalization_leverage_component') or 0.0):.2f} |"
        )
    lines.append("")

    for row in priorities:
        ext = row.get("external_evidence") if isinstance(row.get("external_evidence"), dict) else {}
        lines.append(f"### {row.get('rank')}. {row.get('attack_class')} ({row.get('priority_band')}, {row.get('priority_score')})")
        lines.append("")
        lines.append(
            f"- Same-class recall: {float(row.get('same_class_recall') or 0.0) * 100:.1f}% "
            f"({int(row.get('same_class_misses') or 0)} misses across {int(row.get('samples_total') or 0)} scorable samples)"
        )
        lines.append(
            f"- Gap vs self-test: {float(row.get('gap_vs_self_test_pp') or 0.0):.1f}pp; "
            f"gap vs any-independent: {float(row.get('gap_vs_any_pp') or 0.0):.1f}pp"
        )
        lines.append(
            f"- External evidence: {int(ext.get('measured_external_samples') or 0)} measured, "
            f"{int(ext.get('manifest_external_unmeasured') or 0)} queued, "
            f"external same-class recall: "
            f"{'n/a' if ext.get('external_same_class_recall') is None else f'{float(ext.get('external_same_class_recall')) * 100:.1f}%'}"
        )
        top_detectors = row.get("top_cross_class_detectors_on_misses") or []
        if top_detectors:
            detector_text = ", ".join(
                f"{item.get('detector')} x{item.get('count')}" for item in top_detectors[:3]
            )
            lines.append(f"- Wrong-class detectors already touching misses: {detector_text}")
        miss_examples = row.get("miss_examples") or []
        if miss_examples:
            example_bits = []
            for item in miss_examples[:3]:
                slug = str(item.get("slug") or "")
                if not slug:
                    continue
                language = str(item.get("target_language") or "").strip()
                example_bits.append(f"{slug} ({language})" if language else slug)
            example_text = ", ".join(example_bits)
            if example_text:
                lines.append(f"- Miss examples: {example_text}")
        lines.append("- Next tasks:")
        for task in row.get("next_tasks") or []:
            lines.append(f"  - {task.get('summary')}")
        lines.append("")

    if taxonomy_debt:
        lines.append("## Taxonomy debt")
        lines.append("")
        for row in taxonomy_debt:
            lines.append(
                f"- `{row.get('attack_class')}`: {int(row.get('same_class_misses') or 0)} misses across "
                f"{int(row.get('samples_total') or 0)} scorable samples."
            )
            for task in row.get("next_tasks") or []:
                lines.append(f"  - {task.get('summary')}")
        lines.append("")
    return "\n".join(lines)


def build_stdout(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    inputs = payload.get("inputs") if isinstance(payload.get("inputs"), dict) else {}
    quality_counts = inputs.get("quality_counts") if isinstance(inputs.get("quality_counts"), dict) else {}
    language_counts = inputs.get("language_counts") if isinstance(inputs.get("language_counts"), dict) else {}
    priorities = payload.get("priorities") if isinstance(payload.get("priorities"), list) else []
    lines = []
    lines.append("=" * 72)
    lines.append("real-world recall gap prioritizer")
    lines.append("=" * 72)
    lines.append(f"ranked attack classes   : {summary.get('ranked_attack_classes', 0)}")
    lines.append(f"taxonomy debt classes   : {summary.get('taxonomy_debt_classes', 0)}")
    lines.append(f"scorable measured rows  : {summary.get('measured_scorable_samples', 0)}")
    lines.append(f"manifest sample rows    : {summary.get('manifest_samples', 0)}")
    if str(payload.get("target_language") or "").strip():
        lines.append(f"target language         : {payload.get('target_language')}")
    if quality_counts:
        lines.append(
            "quality-filtered rows   : "
            f"measured {quality_counts.get('measured_external_rows_filtered', 0)}, "
            f"manifest {quality_counts.get('manifest_external_rows_filtered', 0)}"
        )
    if language_counts and str(payload.get("target_language") or "").strip():
        lines.append(
            "language-filtered rows  : "
            f"measured {language_counts.get('measured_rows_before_language_filter', 0)} -> "
            f"{language_counts.get('measured_rows_after_language_filter', 0)}, "
            f"manifest {language_counts.get('manifest_rows_before_language_filter', 0)} -> "
            f"{language_counts.get('manifest_rows_after_language_filter', 0)}"
        )
    if priorities:
        top = priorities[0]
        lines.append(
            f"top priority            : {top.get('attack_class')} "
            f"({top.get('priority_band')}, score {float(top.get('priority_score') or 0.0):.1f})"
        )
    else:
        lines.append("top priority            : none")
    lines.append("=" * 72)
    return "\n".join(lines)


def run(
    *,
    scoreboard_path: Path,
    reports_dir: Path,
    include_uncategorized: bool,
    top_n: int,
    target_language: str = "",
) -> dict[str, Any]:
    scoreboards, scoreboard_errors = discover_scoreboards(scoreboard_path, reports_dir)
    manifests, manifest_errors = discover_manifests(reports_dir, scoreboards)
    quality_reports, quality_errors = discover_quality_reports(reports_dir)
    quality_index = build_quality_index(quality_reports)
    measured_samples, sample_counts = collect_samples(scoreboards)
    manifest_samples, manifest_counts = collect_manifest_samples(manifests)
    measured_samples, manifest_samples, quality_counts = apply_quality_filter(
        measured_samples,
        manifest_samples,
        quality_index,
    )
    target_language_norm = _normalize_language(target_language)
    measured_samples, manifest_samples, language_counts = filter_samples_by_language(
        measured_samples,
        manifest_samples,
        target_language_norm,
    )
    priorities, taxonomy_debt, totals = aggregate_priorities(
        measured_samples,
        manifest_samples,
        include_uncategorized=include_uncategorized,
    )
    if top_n > 0:
        priorities = priorities[:top_n]
        for idx, row in enumerate(priorities, 1):
            row["rank"] = idx
    payload = {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "scoreboard_path": str(scoreboard_path.resolve()),
        "reports_dir": str(reports_dir.resolve()),
        "target_language": target_language_norm,
        "inputs": {
            "loaded_scoreboards": len(scoreboards),
            "loaded_manifests": len(manifests),
            "loaded_quality_reports": len(quality_reports),
            "scoreboard_paths": [_relpath(item["path"], REPO_ROOT) for item in scoreboards],
            "manifest_paths": [_relpath(item["path"], REPO_ROOT) for item in manifests],
            "quality_report_paths": [_relpath(item["path"], REPO_ROOT) for item in quality_reports],
            "scoreboard_errors": scoreboard_errors,
            "manifest_errors": manifest_errors,
            "quality_errors": quality_errors,
            "sample_counts": sample_counts,
            "manifest_counts": manifest_counts,
            "quality_counts": quality_counts,
            "language_counts": language_counts,
        },
        "summary": {
            "ranked_attack_classes": len(priorities),
            "taxonomy_debt_classes": len(taxonomy_debt),
            "measured_samples": totals["measured_samples"],
            "measured_scorable_samples": totals["measured_scorable_samples"],
            "measured_compile_failed": totals["measured_compile_failed"],
            "manifest_samples": totals["manifest_samples"],
            "top_priority_attack_classes": [row["attack_class"] for row in priorities[:5]],
        },
        "priorities": priorities,
        "taxonomy_debt": taxonomy_debt,
    }
    return payload


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scoreboard", default=str(DEFAULT_SCOREBOARD))
    ap.add_argument("--reports-dir", default=str(DEFAULT_REPORTS_DIR))
    ap.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    ap.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    ap.add_argument("--top-n", type=int, default=12)
    ap.add_argument("--target-language", default="",
                    help="Optional target language filter, e.g. solidity, go, rust")
    ap.add_argument("--include-uncategorized", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    payload = run(
        scoreboard_path=Path(args.scoreboard).expanduser(),
        reports_dir=Path(args.reports_dir).expanduser(),
        include_uncategorized=bool(args.include_uncategorized),
        top_n=max(0, int(args.top_n)),
        target_language=str(args.target_language or ""),
    )

    out_json = Path(args.out_json).expanduser()
    out_md = Path(args.out_md).expanduser()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    out_md.write_text(build_markdown(payload), encoding="utf-8")

    if not args.quiet:
        print(build_stdout(payload))
        print(f"[json] {out_json}")
        print(f"[md]   {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
