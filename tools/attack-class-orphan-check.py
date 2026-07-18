#!/usr/bin/env python3
"""Rule 39 attack-class-orphan preflight (Check #74).

HIGH/CRITICAL submissions whose ``attack_class`` is an "orphan" - present in
a single corpus subtree OR with fewer than ``MIN_RECORDS`` corpus records -
must normalise the class, or rebut via ``<!-- r39-rebuttal: <reason> -->``
(<=200 chars).

Source: docs/WAVE2_W29_NEW_GATES_SPEC_2026-05-16.md §2.

Exit codes:
  0 - pass / out-of-scope / accepted rebuttal
  1 - fail (orphan class without rebuttal)
  2 - error (cannot load distribution index)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.rebuttal_util import apply_rebuttal_gate  # noqa: E402


SCHEMA_VERSION = "auditooor.r39_attack_class_orphan_check.v1"
GATE = "R39-ATTACK-CLASS-ORPHAN"
TOOL_REL_PATH = "tools/attack-class-orphan-check.py"

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

MIN_RECORDS_DEFAULT = 20
MIN_SUBTREES_DEFAULT = 2

DEFAULT_DISTRIBUTION_INDEX = "audit/corpus_tags/derived/attack_class_distribution.json"
DEFAULT_TAXONOMY_INDEX = "audit/corpus_tags/derived/attack_class_taxonomy.json"

REBUTTAL_RE = re.compile(
    r"<!--\s*r39-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)

ATTACK_CLASS_PATTERNS = [
    re.compile(r"(?im)^\s*attack_class\s*:\s*[\"']?([A-Za-z0-9_\-/.]+)[\"']?\s*$"),
    re.compile(r"(?im)^\s*\**\s*Attack[ _]Class\s*:\**\s*[\"']?([A-Za-z0-9_\-/.]+)"),
    re.compile(r"(?im)\battack_class\s*=\s*[\"']?([A-Za-z0-9_\-/.]+)"),
]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_aliases() -> dict[str, str]:
    """Parse ``AUDITOOOR_R39_CANONICAL_ALIASES`` env var.

    Format: newline-separated ``non-canonical=>canonical`` rows.
    """
    raw = os.environ.get("AUDITOOOR_R39_CANONICAL_ALIASES", "")
    out: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=>" not in line:
            continue
        left, right = line.split("=>", 1)
        left = left.strip().lower()
        right = right.strip().lower()
        if left and right:
            out[left] = right
    return out


def _severity_from_text(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    patterns = [
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
    ]
    for pattern, source in patterns:
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _extract_attack_class(text: str) -> str | None:
    for pattern in ATTACK_CLASS_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(1).strip().lower()
    return None


def _rebuttal_text(text: str) -> str | None:
    m = REBUTTAL_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _load_distribution(path: Path) -> dict[str, dict[str, Any]]:
    """Load attack-class distribution index.

    Supports two shapes:
    - hackerman-attack-class-distribution.py envelope (with ``matrix`` /
      ``orphan_classes`` keys).
    - hackerman-attack-class-inventory.py / taxonomy emit
      (with ``classes`` -> [{attack_class, total_records, subtrees: []}]).

    Returns a mapping ``attack_class -> {"record_count": int, "subtree_count": int, "subtrees": [..]}``.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}

    # Shape 1: matrix-based distribution envelope.
    matrix = data.get("matrix")
    if isinstance(matrix, dict):
        counts_by_class: dict[str, dict[str, int]] = {}
        for subtree, cells in matrix.items():
            if not isinstance(cells, dict):
                continue
            for ac, n in cells.items():
                if not isinstance(n, int):
                    try:
                        n = int(n)
                    except (TypeError, ValueError):
                        continue
                if n <= 0:
                    continue
                counts_by_class.setdefault(ac, {})[subtree] = n
        for ac, by in counts_by_class.items():
            out[ac.lower()] = {
                "record_count": sum(by.values()),
                "subtree_count": len(by),
                "subtrees": sorted(by.keys()),
            }

    # Shape 2: classes-list emit (taxonomy / inventory).
    classes = data.get("classes")
    if isinstance(classes, list):
        for entry in classes:
            if not isinstance(entry, dict):
                continue
            ac = entry.get("attack_class")
            if not ac:
                continue
            ac_l = ac.lower()
            total = entry.get("total_records") or entry.get("record_count") or 0
            subtrees = entry.get("subtrees") or []
            if ac_l in out:
                # matrix already provided richer data; merge subtrees.
                merged_subtrees = sorted(set(out[ac_l].get("subtrees", []) + list(subtrees)))
                out[ac_l]["subtrees"] = merged_subtrees
                out[ac_l]["subtree_count"] = len(merged_subtrees)
                if total and not out[ac_l].get("record_count"):
                    out[ac_l]["record_count"] = int(total)
            else:
                out[ac_l] = {
                    "record_count": int(total),
                    "subtree_count": len(subtrees),
                    "subtrees": list(subtrees),
                }
    return out


def _load_taxonomy_classes(path: Path) -> set[str]:
    """Return the set of canonical attack_class identifiers.

    Accepts:
    - ``{"classes": [{"attack_class": ...}, ...]}``
    - ``{"canonical_classes": [...]}``
    - top-level list of strings or dicts.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    out: set[str] = set()
    candidates: list[Any] = []
    if isinstance(data, list):
        candidates = data
    elif isinstance(data, dict):
        for key in ("canonical_classes", "classes", "taxonomy"):
            val = data.get(key)
            if isinstance(val, list):
                candidates = val
                break
    for entry in candidates:
        if isinstance(entry, str):
            out.add(entry.lower())
        elif isinstance(entry, dict):
            ac = entry.get("attack_class") or entry.get("name")
            if ac:
                out.add(str(ac).lower())
    return out


def _nearest_canonical(observed: str, canonical: set[str], aliases: dict[str, str]) -> str | None:
    """Suggest a canonical class via env-alias or fuzzy substring match."""
    if observed in aliases:
        return aliases[observed]
    if not canonical:
        return None
    # Exact prefix/suffix substring match (longest first).
    for cls in sorted(canonical, key=lambda c: -len(c)):
        if cls in observed or observed in cls:
            return cls
    # Token overlap fallback.
    obs_tokens = set(re.split(r"[-_/]+", observed))
    best_cls = None
    best_overlap = 0
    for cls in canonical:
        cls_tokens = set(re.split(r"[-_/]+", cls))
        overlap = len(obs_tokens & cls_tokens)
        if overlap > best_overlap:
            best_overlap = overlap
            best_cls = cls
    return best_cls if best_overlap >= 2 else None


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    distribution_index: Path | None = None,
    taxonomy_index: Path | None = None,
    min_records: int | None = None,
    min_subtrees: int | None = None,
    strict: bool = False,
    allow_missing_index: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema": SCHEMA_VERSION,
            "tool": TOOL_REL_PATH,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity_from_text(text, draft, severity_override)

    min_records = min_records if min_records is not None else _env_int(
        "AUDITOOOR_R39_MIN_RECORDS", MIN_RECORDS_DEFAULT
    )
    min_subtrees = min_subtrees if min_subtrees is not None else _env_int(
        "AUDITOOOR_R39_MIN_SUBTREES", MIN_SUBTREES_DEFAULT
    )

    base_payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "tool": TOOL_REL_PATH,
        "gate": GATE,
        "file": str(draft),
        "severity_observed": severity,
        "severity_source": severity_source,
        "strict": strict,
        "min_records_threshold": min_records,
        "min_subtrees_threshold": min_subtrees,
        "rebuttal": None,
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        base_payload["verdict"] = "pass-out-of-scope"
        base_payload["reason"] = "severity below HIGH or missing"
        return 0, base_payload

    rebuttal = _rebuttal_text(text)
    if apply_rebuttal_gate(base_payload, rebuttal):
        return 0, base_payload
    if rebuttal:
        base_payload["rebuttal_oversize"] = True
        base_payload["rebuttal_observed_length"] = len(rebuttal)

    attack_class = _extract_attack_class(text)
    base_payload["attack_class_observed"] = attack_class

    if not attack_class:
        # No attack_class declared -> R38 already flags this; pass through here.
        base_payload["verdict"] = "pass-out-of-scope"
        base_payload["reason"] = "attack_class not declared in draft (R38 owns this signal)"
        return 0, base_payload

    distribution_index = distribution_index or Path(DEFAULT_DISTRIBUTION_INDEX)
    taxonomy_index = taxonomy_index or Path(DEFAULT_TAXONOMY_INDEX)

    if not distribution_index.exists():
        base_payload["distribution_index_missing"] = True
        base_payload["distribution_index_path"] = str(distribution_index)
        if allow_missing_index:
            base_payload["verdict"] = "pass-out-of-scope"
            base_payload["reason"] = "distribution index not available; gate skipped"
            return 0, base_payload
        base_payload["verdict"] = "error"
        base_payload["reason"] = f"distribution index not found: {distribution_index}"
        return 2, base_payload

    try:
        dist = _load_distribution(distribution_index)
    except Exception as exc:
        base_payload["verdict"] = "error"
        base_payload["reason"] = f"distribution index load failed: {exc}"
        return 2, base_payload

    canonical = _load_taxonomy_classes(taxonomy_index) if taxonomy_index.exists() else set()
    aliases = _env_aliases()

    entry = dist.get(attack_class.lower())
    record_count = int(entry.get("record_count", 0)) if entry else 0
    subtree_count = int(entry.get("subtree_count", 0)) if entry else 0
    subtrees_observed = entry.get("subtrees", []) if entry else []

    base_payload["corpus_record_count"] = record_count
    base_payload["corpus_subtree_count"] = subtree_count
    base_payload["corpus_subtrees"] = subtrees_observed
    base_payload["is_in_canonical_taxonomy"] = attack_class.lower() in canonical
    nearest = _nearest_canonical(attack_class.lower(), canonical, aliases)
    base_payload["nearest_canonical_class"] = nearest

    low_records = record_count < min_records
    low_subtrees = subtree_count < min_subtrees

    if low_records and low_subtrees:
        base_payload["verdict"] = "fail-orphan-both"
        base_payload["reason"] = (
            f"attack_class {attack_class!r} has {record_count} records (<{min_records}) "
            f"AND {subtree_count} subtrees (<{min_subtrees})"
        )
        remediation = []
        if nearest:
            remediation.append(f"Normalise attack_class to canonical {nearest!r}")
        remediation.append("OR add <!-- r39-rebuttal: <reason> --> (<=200 chars)")
        base_payload["remediation"] = remediation
        return 1, base_payload

    if low_subtrees:
        base_payload["verdict"] = "fail-orphan-single-subtree"
        base_payload["reason"] = (
            f"attack_class {attack_class!r} present in {subtree_count} subtree(s) (<{min_subtrees})"
        )
        remediation = []
        if nearest:
            remediation.append(f"Normalise attack_class to canonical {nearest!r}")
        remediation.append("OR add <!-- r39-rebuttal: <reason> --> (<=200 chars)")
        base_payload["remediation"] = remediation
        return 1, base_payload

    if low_records:
        base_payload["verdict"] = "fail-orphan-low-record-count"
        base_payload["reason"] = (
            f"attack_class {attack_class!r} has {record_count} corpus records (<{min_records})"
        )
        remediation = []
        if nearest:
            remediation.append(f"Normalise attack_class to canonical {nearest!r}")
        remediation.append("OR add <!-- r39-rebuttal: <reason> --> (<=200 chars)")
        base_payload["remediation"] = remediation
        return 1, base_payload

    if attack_class.lower() in canonical:
        base_payload["verdict"] = "pass-attack-class-canonical"
        base_payload["reason"] = "attack_class in canonical taxonomy with sufficient corpus support"
        return 0, base_payload

    base_payload["verdict"] = "pass-attack-class-supported-non-canonical"
    base_payload["reason"] = (
        "attack_class has sufficient corpus support but is not yet in canonical taxonomy"
    )
    return 0, base_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument(
        "--severity",
        choices=["Critical", "High", "Medium", "Low", "critical", "high", "medium", "low", "auto"],
        default=None,
    )
    parser.add_argument(
        "--distribution-index",
        type=Path,
        default=Path(os.environ.get("AUDITOOOR_R39_DISTRIBUTION_INDEX", DEFAULT_DISTRIBUTION_INDEX)),
    )
    parser.add_argument(
        "--taxonomy-index",
        type=Path,
        default=Path(os.environ.get("AUDITOOOR_R39_TAXONOMY_INDEX", DEFAULT_TAXONOMY_INDEX)),
    )
    parser.add_argument("--min-records", type=int, default=None)
    parser.add_argument("--min-subtrees", type=int, default=None)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--allow-missing-index", action="store_true")
    parser.add_argument("--json", action="store_true", default=True)
    args = parser.parse_args(argv)

    sev_override = None if args.severity in (None, "auto") else args.severity
    rc, payload = run(
        args.draft,
        severity_override=sev_override,
        distribution_index=args.distribution_index,
        taxonomy_index=args.taxonomy_index,
        min_records=args.min_records,
        min_subtrees=args.min_subtrees,
        strict=args.strict,
        allow_missing_index=args.allow_missing_index,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
