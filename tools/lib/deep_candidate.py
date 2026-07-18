"""
Shared emitter for V5 typed deep-lane candidates.

Each deep tool (math/crypto/econ/symbolic/fuzz/source_mine) opt-in wires this
emitter behind a ``--emit-candidate`` flag. The emitter writes one JSON file
per candidate to ``<workspace>/deep_candidates/<lane>_<ts>_<id>.json`` and
returns the path. The default tool outputs are unchanged so existing
audit-deep regression remains green.

Stdlib-only. No new pip deps. The validator
(``tools/validate-deep-candidate.py``) is the source of truth for what
makes a candidate well-formed; this emitter only constructs documents.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCHEMA_VERSION = "deep_candidate.v1"

_LANES = {"math", "crypto", "econ", "symbolic", "fuzz", "source_mine"}
_VALID_ID_RE = re.compile(r"[A-Za-z0-9._:-]+")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(value: str) -> str:
    """Best-effort id-safe slug; preserves alnum and ._:- characters."""
    cleaned = "".join(ch if _VALID_ID_RE.fullmatch(ch) else "-" for ch in value)
    cleaned = cleaned.strip("-")
    return cleaned or "candidate"


def _norm_path(workspace: Path, p: str) -> str:
    """Normalize a file path to be workspace-relative.

    Absolute paths inside the workspace are reduced to a relative form. Paths
    outside the workspace are kept as-is — the validator will reject them so
    the operator sees the failure rather than a silent rewrite.
    """
    candidate = Path(p)
    if not candidate.is_absolute():
        return str(candidate).replace(os.sep, "/")
    try:
        return str(candidate.resolve().relative_to(workspace.resolve())).replace(
            os.sep, "/"
        )
    except ValueError:
        return str(candidate)


def build_candidate(
    *,
    lane: str,
    candidate_id: str,
    files: Iterable[str],
    claim: str,
    trigger: str,
    impact: str,
    reproduction: str,
    confidence: str = "low",
    blocking_questions: Optional[Iterable[str]] = None,
    promotion_status: str = "investigate",
    tool: Optional[str] = None,
    workspace: Optional[Path] = None,
    lane_payload: Optional[Dict[str, Any]] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct a deep_candidate.v1 dict in memory.

    Defaults follow the advisory-floor rule: ``confidence='low'`` and
    ``promotion_status='investigate'``. Callers MUST supply at least one
    ``blocking_questions`` entry for those defaults; otherwise the validator
    will reject the emission.
    """
    if lane not in _LANES:
        raise ValueError(f"unknown lane {lane!r}; expected one of {sorted(_LANES)}")
    if confidence not in {"low", "medium", "high"}:
        raise ValueError(f"invalid confidence {confidence!r}")
    if promotion_status not in {"rejected", "hold", "investigate", "poc_ready"}:
        raise ValueError(f"invalid promotion_status {promotion_status!r}")

    ws = workspace.resolve() if workspace is not None else None
    files_list: List[str]
    if ws is not None:
        files_list = [_norm_path(ws, f) for f in files]
    else:
        files_list = [str(f).replace(os.sep, "/") for f in files]

    doc: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "lane": lane,
        "candidate_id": _slug(candidate_id),
        "files": files_list,
        "claim": claim,
        "trigger": trigger,
        "impact": impact,
        "reproduction": reproduction,
        "confidence": confidence,
        "blocking_questions": list(blocking_questions or []),
        "promotion_status": promotion_status,
    }
    if tool:
        doc["tool"] = tool
    if ws is not None:
        doc["workspace"] = str(ws)
    if lane_payload:
        doc["lane_payload"] = lane_payload
    doc["generated_at"] = generated_at or _now()
    return doc


def candidate_path(workspace: Path, lane: str, candidate_id: str) -> Path:
    """Return the canonical workspace-local path for an emission."""
    if lane not in _LANES:
        raise ValueError(f"unknown lane {lane!r}")
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = workspace / "deep_candidates"
    return out_dir / f"{lane}_{ts}_{_slug(candidate_id)}.json"


def write_candidate(
    candidate: Dict[str, Any],
    *,
    workspace: Path,
    out_dir: Optional[Path] = None,
) -> Path:
    """Write ``candidate`` to disk under the workspace's deep_candidates/ dir.

    Returns the absolute path written. The caller is responsible for running
    the schema validator on the result if it wants a hard gate; the emitter
    is intentionally permissive so that upstream test fixtures (which want to
    exercise INVALID candidates) can write through the same code path.
    """
    target_dir = out_dir if out_dir is not None else (workspace / "deep_candidates")
    target_dir.mkdir(parents=True, exist_ok=True)
    lane = candidate.get("lane", "deep")
    cid = candidate.get("candidate_id", "candidate")
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = target_dir / f"{lane}_{ts}_{_slug(cid)}.json"
    path.write_text(
        json.dumps(candidate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


__all__ = [
    "SCHEMA_VERSION",
    "build_candidate",
    "candidate_path",
    "write_candidate",
]
