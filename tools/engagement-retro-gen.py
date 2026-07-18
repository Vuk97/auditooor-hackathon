#!/usr/bin/env python3
"""engagement-retro-gen.py — PR #128: provenance-backed engagement retrospective.

Given a workspace path, emit:

    <workspace>/RETROSPECTIVE.md       — human-readable retrospective
    <workspace>/retrospective.json     — machine-readable sidecar w/ per-field
                                          provenance + unknown_reason

Inputs (LOCAL ARTIFACTS ONLY — no network, no platform API):

- ``<workspace>/cost_runs/<run_ts>/stage_*.json``
  Aggregated via ``tools/cost-telemetry.py:summarize_workspace`` (advisory;
  never reported as a precise bill — ``est_*`` wording preserved verbatim).
- ``<workspace>/SUBMISSIONS.md`` (or ``<workspace>/submissions/SUBMISSIONS.md``)
  Plus per-finding ``*.md`` siblings for headcount cross-checks.
- ``<workspace>/OUTCOMES.md`` (operator-supplied authoritative ledger; optional).
- ``<workspace>/payouts.json`` (optional ledger — same operator-authoritative role).
- ``reference/outcomes.jsonl`` — treated as PARTIAL/STALE; ONLY consulted as
  advisory; if a workspace ledger is absent, outcomes from this file are
  tagged ``(advisory; partial/stale)`` and never promoted to ground truth.
- ``docs/ROADMAP_10_OF_10_V2.md`` — exit-criteria targets.
- ``docs/10_OF_10_PLAYBOOK.md`` — honest-tone phrase library.

Truth-discipline rules (Codex-revision absorbed):

1. Every metric is an OBJECT — ``{value, provenance, unknown_reason,
   advisory?, wording?}``.
2. Missing data → ``"unknown"`` / ``"NA"``. Never ``0``, ``null``, or ``inf``
   dressed as a metric.
3. Cost: ``est_*`` wording preserved verbatim. Never reported as precise bill.
4. Accept-rate / $/accepted: provenance-backed; if accepted_count is 0 OR
   unknown, emit ``unknown`` / ``NA`` with ``unknown_reason`` set.
5. Lessons extraction: structured-section-first
   (``## Lessons|Retrospective|What worked|What didn't|Anti-patterns?``);
   regex fallback (``AP-\\d+`` / ``FN-\\d+``) tagged
   ``extraction_method="regex_fallback"`` and advisory.
6. ``reference/outcomes.jsonl`` rows are advisory: tagged provenance
   ``"reference/outcomes.jsonl:N (advisory; partial/stale)"`` and never
   promoted to ground truth.

Stdlib only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
COST_TELEMETRY_PATH = HERE / "cost-telemetry.py"
DEFAULT_OUTCOMES_REF = ROOT / "reference" / "outcomes.jsonl"
DEFAULT_PLAYBOOK = ROOT / "docs" / "10_OF_10_PLAYBOOK.md"
DEFAULT_ROADMAP_V2 = ROOT / "docs" / "ROADMAP_10_OF_10_V2.md"

SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------- #
# Cost-telemetry import (hyphenated module name → importlib by file path)
# ---------------------------------------------------------------------------- #


def _load_cost_telemetry(path: Path = COST_TELEMETRY_PATH):
    """Load tools/cost-telemetry.py by file path so ``summarize_workspace``
    can be called as if imported.

    Hermetic-test friendly: callers can override the path via the
    ``--cost-telemetry-path`` CLI flag or by passing a custom path."""
    spec = importlib.util.spec_from_file_location("cost_telemetry", path)
    if spec is None or spec.loader is None:  # pragma: no cover — defensive
        raise RuntimeError(f"could not load cost-telemetry from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------- #
# Metric helpers — every metric is a {value, provenance, unknown_reason} object
# ---------------------------------------------------------------------------- #


def _metric_known(value: Any, provenance: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "value": value,
        "provenance": provenance,
        "unknown_reason": None,
    }
    out.update(extra)
    return out


def _metric_unknown(reason: str, *, na: bool = False, **extra: Any) -> dict[str, Any]:
    """Emit an unknown/NA metric. NEVER 0, NEVER null, NEVER inf."""
    out: dict[str, Any] = {
        "value": "NA" if na else "unknown",
        "provenance": None,
        "unknown_reason": reason,
    }
    out.update(extra)
    return out


# ---------------------------------------------------------------------------- #
# Submissions parsing
# ---------------------------------------------------------------------------- #


_SUBMISSION_HEADING_RE = re.compile(
    # Match per-submission headers like:
    #   "# 🚀 Submission 1 — #OFF.A — High"
    #   "## Draft 3 — UmaCtfAdapter ..."
    #   "### Draft 1 — UmaCtfAdapter priceDisputed ..."
    r"^(#{1,6})\s+(?:[\W_]*?)?(?:Submission|Draft|Finding)\s+(\d+)\s*[—\-:]?\s*(.*)$",
    re.IGNORECASE,
)

_SEVERITY_RE = re.compile(
    r"\b(?:Severity|→\s*Severity)\s*[:=]?\s*\**\s*(Critical|High|Medium|Low|Informational|Info)\b",
    re.IGNORECASE,
)


def _candidate_submissions_paths(ws: Path) -> list[Path]:
    candidates = [
        ws / "SUBMISSIONS.md",
        ws / "submissions" / "SUBMISSIONS.md",
    ]
    return [p for p in candidates if p.is_file()]


def parse_submissions(ws: Path) -> tuple[list[dict[str, Any]], str | None]:
    """Best-effort parse of ``<ws>/SUBMISSIONS.md`` (or under ``submissions/``).

    Returns ``(submissions, source_path_str)``. Each submission is
    ``{id, severity, title, source_line}``. ``id`` is a string; if missing
    falls back to a 1-based index. ``severity`` is normalized to
    Critical/High/Medium/Low/Informational or ``"unknown"``.
    """
    paths = _candidate_submissions_paths(ws)
    if not paths:
        return [], None

    src = paths[0]
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], None

    submissions: list[dict[str, Any]] = []
    lines = text.splitlines()
    current: dict[str, Any] | None = None
    for i, line in enumerate(lines, start=1):
        m = _SUBMISSION_HEADING_RE.match(line)
        if m:
            if current is not None:
                submissions.append(current)
            sub_id = m.group(2)
            tail = (m.group(3) or "").strip()
            # Title: try to peel off the trailing severity tag like " — High"
            sev: str = "unknown"
            sev_match = re.search(
                r"[—\-]\s*(Critical|High|Medium|Low|Informational|Info)\b",
                tail,
                re.IGNORECASE,
            )
            if sev_match:
                sev = sev_match.group(1).capitalize()
                tail = tail[: sev_match.start()].rstrip(" —-")
            current = {
                "id": sub_id,
                "title": tail or f"Submission {sub_id}",
                "severity": sev,
                "source_line": i,
            }
        elif current is not None:
            sm = _SEVERITY_RE.search(line)
            if sm and current.get("severity", "unknown").lower() == "unknown":
                current["severity"] = sm.group(1).capitalize()
    if current is not None:
        submissions.append(current)

    return submissions, str(src.relative_to(ws.parent) if ws.parent in src.parents else src)


# ---------------------------------------------------------------------------- #
# Outcomes — operator-supplied first, reference/outcomes.jsonl advisory only
# ---------------------------------------------------------------------------- #


_OUTCOME_VALUES = {"accepted", "rejected", "duplicate", "pending", "in_review", "paid"}


def _parse_operator_outcomes_md(path: Path) -> dict[str, dict[str, Any]]:
    """Parse a workspace OUTCOMES.md operator ledger.

    Format expected (lenient): a markdown table whose header includes ``id``
    (or ``finding_id``) and ``outcome``, optionally ``paid_usd``. Rows are
    keyed by string id. Returns {} on any parse failure."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    outcomes: dict[str, dict[str, Any]] = {}
    in_table = False
    headers: list[str] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("|") and (
            "id" in line.lower() or "finding" in line.lower()
        ) and "outcome" in line.lower():
            headers = [h.strip().lower() for h in line.strip("|").split("|")]
            in_table = True
            continue
        if in_table and line.startswith("|") and set(line.replace("|", "").strip()) <= {"-", ":", " "}:
            continue
        if in_table and line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) < len(headers):
                cells = cells + [""] * (len(headers) - len(cells))
            row = dict(zip(headers, cells))
            row_id = (
                row.get("id")
                or row.get("finding_id")
                or row.get("#")
                or ""
            ).strip().lstrip("#")
            outcome = (row.get("outcome") or "").strip().lower()
            if not row_id or outcome not in _OUTCOME_VALUES:
                continue
            paid_raw = (row.get("paid_usd") or row.get("paid") or "").strip()
            paid_usd: Any = "unknown"
            if paid_raw:
                cleaned = paid_raw.lstrip("$").replace(",", "").strip()
                try:
                    paid_usd = float(cleaned)
                except ValueError:
                    paid_usd = "unknown"
            outcomes[row_id] = {
                "outcome": outcome,
                "paid_usd": paid_usd,
                "source_line": i,
            }
        elif in_table and not line.startswith("|"):
            in_table = False
            headers = []
    return outcomes


def _parse_payouts_json(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for key, val in data.items():
        if not isinstance(val, dict):
            continue
        outcome = str(val.get("outcome", "")).lower()
        if outcome not in _OUTCOME_VALUES:
            continue
        paid = val.get("paid_usd")
        if not isinstance(paid, (int, float)):
            paid = "unknown"
        out[str(key)] = {
            "outcome": outcome,
            "paid_usd": paid,
            "source_line": None,  # JSON has no line addressability
        }
    return out


def _load_advisory_outcomes_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read ``reference/outcomes.jsonl``. Annotate each row with line number.
    Pure advisory — caller MUST tag provenance ``(advisory; partial/stale)``."""
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            row["_advisory_line"] = i
            rows.append(row)
    return rows


def reconcile_outcomes(
    submissions: list[dict[str, Any]],
    operator_outcomes: dict[str, dict[str, Any]],
    operator_provenance: str | None,
    advisory_rows: list[dict[str, Any]],
    advisory_provenance: str | None,
) -> list[dict[str, Any]]:
    """For each submission produce an outcome metric + paid_usd metric.

    Priority: operator ledger (authoritative) → advisory jsonl (advisory;
    partial/stale) → unknown."""
    out: list[dict[str, Any]] = []
    advisory_index: dict[str, dict[str, Any]] = {}
    for row in advisory_rows:
        fid = str(row.get("finding_id") or row.get("id") or "")
        if fid:
            advisory_index[fid] = row

    for sub in submissions:
        sid = str(sub.get("id"))
        outcome_metric: dict[str, Any]
        paid_metric: dict[str, Any]
        if sid in operator_outcomes and operator_provenance:
            entry = operator_outcomes[sid]
            line = entry.get("source_line")
            prov = (
                f"{operator_provenance}:{line}" if line is not None else operator_provenance
            )
            outcome_metric = _metric_known(entry["outcome"], prov)
            paid_val = entry.get("paid_usd", "unknown")
            if isinstance(paid_val, (int, float)):
                paid_metric = _metric_known(float(paid_val), prov)
            else:
                paid_metric = _metric_unknown(
                    "operator ledger row has no paid_usd column or non-numeric value"
                )
        elif sid in advisory_index and advisory_provenance:
            row = advisory_index[sid]
            line = row.get("_advisory_line")
            prov = f"{advisory_provenance}:{line} (advisory; partial/stale)"
            outcome_metric = _metric_known(
                row.get("outcome", "unknown"),
                prov,
                advisory=True,
            )
            paid_metric = _metric_unknown(
                "no workspace payouts ledger; reference/outcomes.jsonl carries no paid_usd field"
            )
        else:
            outcome_metric = _metric_unknown(
                "no workspace ledger entry; reference/outcomes.jsonl has no row for this id"
            )
            paid_metric = _metric_unknown(
                "no workspace payouts ledger found"
            )
        out.append(
            {
                "id": sid,
                "title": sub.get("title", ""),
                "severity": sub.get("severity", "unknown"),
                "outcome": outcome_metric,
                "paid_usd": paid_metric,
            }
        )
    return out


# ---------------------------------------------------------------------------- #
# Lessons extraction
# ---------------------------------------------------------------------------- #


_STRUCTURED_HEADING_RE = re.compile(
    r"^(#{2,6})\s+(Lessons|Retrospective|What\s+worked|What\s+didn'?t|Anti[-\s]patterns?)\s*$",
    re.IGNORECASE,
)
_REGEX_FALLBACK_BULLET_RE = re.compile(
    r"^\s*[-*]\s+.*?\b(AP-\d+|FN-\d+)\b",
    re.IGNORECASE,
)


def extract_lessons(ws: Path) -> list[dict[str, Any]]:
    """Two-tier extraction.

    Tier 1 (preferred): structured sections under ``## Lessons``,
    ``## Retrospective``, ``## What worked``, ``## What didn't``,
    ``## Anti-patterns``. Captures bullet lines under each heading until
    next heading.

    Tier 2 (regex fallback, advisory): bullet lines in any *.md whose body
    references ``AP-\\d+`` or ``FN-\\d+``. Tagged ``extraction_method=
    regex_fallback`` so downstream consumers know to treat it as advisory.
    """
    lessons: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    md_paths = sorted(p for p in ws.rglob("*.md") if p.is_file())

    # Tier 1: structured sections
    for path in md_paths:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        in_section = False
        section_kind = ""
        for idx, raw in enumerate(lines, start=1):
            heading_m = re.match(r"^(#{1,6})\s+(.*)$", raw)
            if heading_m:
                struct_m = _STRUCTURED_HEADING_RE.match(raw)
                if struct_m:
                    in_section = True
                    section_kind = struct_m.group(2).strip()
                    continue
                # any other heading exits the section
                in_section = False
                section_kind = ""
                continue
            if in_section:
                stripped = raw.strip()
                if stripped.startswith(("- ", "* ", "1.", "2.", "3.")) or (
                    stripped and not stripped.startswith("#")
                ):
                    if not stripped:
                        continue
                    text = stripped.lstrip("-*0123456789. ").strip()
                    if not text:
                        continue
                    key = (str(path), idx)
                    if key in seen:
                        continue
                    seen.add(key)
                    ap_match = re.search(r"\b(AP-\d+)\b", text, re.IGNORECASE)
                    lessons.append(
                        {
                            "text": text,
                            "source_file": str(path),
                            "source_line": idx,
                            "extraction_method": "structured",
                            "section": section_kind,
                            "anti_pattern_match": (
                                ap_match.group(1).upper() if ap_match else None
                            ),
                        }
                    )

    # Tier 2: regex fallback (only if structured found NOTHING in the workspace)
    if not lessons:
        for path in md_paths:
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for idx, raw in enumerate(lines, start=1):
                m = _REGEX_FALLBACK_BULLET_RE.match(raw)
                if not m:
                    continue
                key = (str(path), idx)
                if key in seen:
                    continue
                seen.add(key)
                tag = m.group(1).upper()
                text = raw.strip().lstrip("-* ").strip()
                lessons.append(
                    {
                        "text": text,
                        "source_file": str(path),
                        "source_line": idx,
                        "extraction_method": "regex_fallback",
                        "section": None,
                        "anti_pattern_match": tag if tag.startswith("AP-") else None,
                        "advisory": True,
                    }
                )

    return lessons


# ---------------------------------------------------------------------------- #
# Cost summary → metric objects
# ---------------------------------------------------------------------------- #


def _build_cost_metrics(
    summary: dict[str, Any], ws: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Translate ``cost-telemetry.summarize_workspace`` output into
    provenance-backed metric objects.

    Returns ``(est_cost_usd_metric, est_duration_s_metric)``. Both carry
    ``advisory: true`` and preserve ``est_*`` wording verbatim. If
    ``cost_runs/`` is absent or empty, both metrics are ``"unknown"``.
    """
    stage_count = int(summary.get("stage_count", 0) or 0)
    cost_runs_dir = ws / "cost_runs"
    if stage_count == 0 or not cost_runs_dir.exists():
        reason = (
            "no cost_runs directory under workspace"
            if not cost_runs_dir.exists()
            else "cost_runs/ exists but contains no stage_*.json artifacts"
        )
        cost_metric = _metric_unknown(reason, advisory=True)
        dur_metric = _metric_unknown(reason, advisory=True)
        return cost_metric, dur_metric

    total_cost = float(summary.get("total_est_cost_usd", 0.0) or 0.0)
    total_dur = float(summary.get("total_duration_s", 0.0) or 0.0)
    partial = bool(summary.get("cost_is_partial", False))
    wording = f"est_cost_usd ≈ ${total_cost:.2f} (advisory; not a bill)"
    if partial:
        wording += " — partial: some stages walltime-only, treat as lower bound"

    provenance = (
        f"{cost_runs_dir} via tools/cost-telemetry.py:summarize_workspace"
    )
    cost_metric = _metric_known(
        round(total_cost, 6),
        provenance,
        advisory=True,
        wording=wording,
        cost_is_partial=partial,
    )
    dur_metric = _metric_known(
        round(total_dur, 6),
        provenance,
        advisory=True,
    )
    return cost_metric, dur_metric


# ---------------------------------------------------------------------------- #
# Outcome aggregation → counts & rates
# ---------------------------------------------------------------------------- #


_RESOLVED_VALUES = {"accepted", "rejected", "duplicate", "paid"}


def _aggregate_outcome_counts(
    submissions_with_outcomes: list[dict[str, Any]],
    operator_provenance: str | None,
    advisory_provenance: str | None,
) -> dict[str, dict[str, Any]]:
    """Build accepted_count / rejected_count / duplicate_count / pending_count
    metric objects. Resolved counts come ONLY from operator ledger entries.
    Advisory rows count toward ``pending_count`` if their value is ``pending``,
    but never toward resolved buckets."""
    operator_buckets = {"accepted": 0, "rejected": 0, "duplicate": 0, "paid": 0}
    pending_from_operator = 0
    pending_from_advisory = 0
    has_operator_ledger = False
    has_advisory = False

    for entry in submissions_with_outcomes:
        outcome = entry["outcome"]
        if outcome["value"] == "unknown":
            continue
        prov = outcome.get("provenance") or ""
        is_advisory = "(advisory" in prov or outcome.get("advisory") is True
        val = outcome["value"]
        if not is_advisory:
            has_operator_ledger = True
            if val in operator_buckets:
                operator_buckets[val] += 1
            elif val == "pending" or val == "in_review":
                pending_from_operator += 1
        else:
            has_advisory = True
            if val in ("pending", "in_review"):
                pending_from_advisory += 1
            # Resolved-looking advisory rows are NEVER counted into resolved buckets.

    metrics: dict[str, dict[str, Any]] = {}
    if has_operator_ledger:
        accepted = operator_buckets["accepted"] + operator_buckets["paid"]
        metrics["accepted_count"] = _metric_known(
            accepted, operator_provenance or "operator ledger"
        )
        metrics["rejected_count"] = _metric_known(
            operator_buckets["rejected"], operator_provenance or "operator ledger"
        )
        metrics["duplicate_count"] = _metric_known(
            operator_buckets["duplicate"], operator_provenance or "operator ledger"
        )
    else:
        reason = (
            "no resolved outcomes in workspace ledger; "
            "reference/outcomes.jsonl is partial/stale"
        )
        metrics["accepted_count"] = _metric_unknown(reason)
        metrics["rejected_count"] = _metric_unknown(reason)
        metrics["duplicate_count"] = _metric_unknown(reason)

    pending_total = pending_from_operator + pending_from_advisory
    if pending_total > 0:
        sources: list[str] = []
        if pending_from_operator and operator_provenance:
            sources.append(operator_provenance)
        if pending_from_advisory and advisory_provenance:
            sources.append(f"{advisory_provenance} (advisory)")
        prov = "; ".join(sources) if sources else "operator ledger"
        metrics["pending_count"] = _metric_known(pending_total, prov)
    else:
        if has_operator_ledger or has_advisory:
            # We saw rows, just none pending.
            prov = operator_provenance or (
                f"{advisory_provenance} (advisory)" if advisory_provenance else "operator ledger"
            )
            metrics["pending_count"] = _metric_known(0, prov)
        else:
            metrics["pending_count"] = _metric_unknown(
                "no operator ledger and no advisory rows for any submission id"
            )
    return metrics


def _build_rate_metrics(
    counts: dict[str, dict[str, Any]],
    cost_metric: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    accepted = counts["accepted_count"]
    rejected = counts["rejected_count"]
    duplicate = counts["duplicate_count"]

    if any(m["value"] == "unknown" for m in (accepted, rejected, duplicate)):
        accept_rate = _metric_unknown(
            "denominator inputs are unknown (no resolved outcomes in workspace ledger)"
        )
    else:
        denom = accepted["value"] + rejected["value"] + duplicate["value"]
        if denom == 0:
            accept_rate = _metric_unknown(
                "denominator is 0 (no resolved outcomes)"
            )
        else:
            rate = accepted["value"] / denom
            prov_parts = [
                p
                for p in (
                    accepted.get("provenance"),
                    rejected.get("provenance"),
                    duplicate.get("provenance"),
                )
                if p
            ]
            prov = "; ".join(sorted(set(prov_parts))) or "operator ledger"
            accept_rate = _metric_known(round(rate, 6), prov)

    if accepted["value"] == "unknown":
        dollars_per_accepted = _metric_unknown(
            "accepted_count is unknown; cannot compute $/accepted",
            na=True,
        )
    elif accepted["value"] == 0:
        dollars_per_accepted = _metric_unknown(
            "accepted_count is 0; $/accepted is undefined (NEVER report inf)",
            na=True,
        )
    elif cost_metric["value"] == "unknown":
        dollars_per_accepted = _metric_unknown(
            "est_cost_usd is unknown (no cost_runs telemetry)",
            na=True,
        )
    else:
        ratio = float(cost_metric["value"]) / int(accepted["value"])
        prov = f"{accepted['provenance']}; {cost_metric['provenance']}"
        dollars_per_accepted = _metric_known(
            round(ratio, 6),
            prov,
            advisory=True,
            wording=(
                f"est_cost_usd / accepted_count ≈ ${ratio:.2f} per accepted "
                "(advisory; based on est_cost — not a bill)"
            ),
        )
    return {"accept_rate": accept_rate, "dollars_per_accepted": dollars_per_accepted}


# ---------------------------------------------------------------------------- #
# Time-to-first-submittable
# ---------------------------------------------------------------------------- #


def _time_to_first_submittable(
    ws: Path, submissions_provenance: str | None
) -> dict[str, Any]:
    """Compute time from first ``git log --reverse`` commit in workspace to
    earliest SUBMISSIONS.md submission timestamp.

    Without explicit timestamps in SUBMISSIONS.md (the schema is freeform),
    this is best-effort: emit ``unknown`` with reason if either anchor is
    missing. We DO NOT shell out to git in the MVP — we look for a
    ``<ws>/.first-commit-ts`` operator hint or skip; never silently 0."""
    if submissions_provenance is None:
        return _metric_unknown("no SUBMISSIONS.md found in workspace")

    hint = ws / ".first-commit-ts"
    if not hint.is_file():
        return _metric_unknown(
            "no .first-commit-ts hint and SUBMISSIONS.md timestamps are freeform; "
            "operator must populate workspace ledger to compute"
        )
    try:
        text = hint.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return _metric_unknown("could not read .first-commit-ts")
    try:
        # Accept ISO 8601 or epoch seconds.
        if text.isdigit():
            t0 = datetime.fromtimestamp(int(text), tz=timezone.utc)
        else:
            t0 = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return _metric_unknown(".first-commit-ts is not ISO8601 or epoch seconds")

    # Earliest submission timestamp — operator hint file
    sub_hint = ws / ".first-submission-ts"
    if not sub_hint.is_file():
        return _metric_unknown(
            "no .first-submission-ts hint; SUBMISSIONS.md timestamps are freeform"
        )
    try:
        sub_text = sub_hint.read_text(encoding="utf-8", errors="replace").strip()
        if sub_text.isdigit():
            t1 = datetime.fromtimestamp(int(sub_text), tz=timezone.utc)
        else:
            t1 = datetime.fromisoformat(sub_text.replace("Z", "+00:00"))
    except (OSError, ValueError):
        return _metric_unknown(".first-submission-ts unreadable or not ISO8601")

    delta_s = (t1 - t0).total_seconds()
    if delta_s < 0:
        return _metric_unknown(
            "submission timestamp predates first commit; operator hint files inconsistent"
        )
    return _metric_known(
        round(delta_s, 3),
        f"{ws}/.first-commit-ts and {ws}/.first-submission-ts (operator-supplied)",
    )


# ---------------------------------------------------------------------------- #
# Exit-criteria comparison
# ---------------------------------------------------------------------------- #


def _exit_criteria_rows(
    metrics: dict[str, dict[str, Any]], submissions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Compare measured metrics against ROADMAP_10_OF_10_V2 §Exit Criteria.

    Targets (from V2 §Exit Criteria):
      - accept_rate ≥ 0.5
      - duplicate_rate ≤ 0.2
      - ≥1 High+ accepted
      - $/accepted ≤ $50
      - time_to_first_submittable ≤ 4h (14400s)
    """

    def status_from(value: Any, predicate, unknown_reason: str | None) -> str:
        if value == "unknown" or value == "NA":
            return "UNKNOWN"
        try:
            return "PASS" if predicate(value) else "FAIL"
        except Exception:  # pragma: no cover — defensive
            return "UNKNOWN"

    rows: list[dict[str, Any]] = []
    accept_rate = metrics["accept_rate"]
    rows.append(
        {
            "metric": "accept_rate",
            "target": ">=0.5",
            "actual": accept_rate["value"],
            "status": status_from(
                accept_rate["value"], lambda v: float(v) >= 0.5, accept_rate.get("unknown_reason")
            ),
            "unknown_reason": accept_rate.get("unknown_reason"),
        }
    )

    accepted = metrics["accepted_count"]
    rejected = metrics["rejected_count"]
    duplicate = metrics["duplicate_count"]
    if any(m["value"] == "unknown" for m in (accepted, rejected, duplicate)):
        dup_rate_actual: Any = "unknown"
        dup_status = "UNKNOWN"
        dup_reason = "resolved-outcome inputs are unknown"
    else:
        denom = accepted["value"] + rejected["value"] + duplicate["value"]
        if denom == 0:
            dup_rate_actual = "unknown"
            dup_status = "UNKNOWN"
            dup_reason = "no resolved outcomes"
        else:
            dup_rate_actual = round(duplicate["value"] / denom, 6)
            dup_status = "PASS" if dup_rate_actual <= 0.2 else "FAIL"
            dup_reason = None
    rows.append(
        {
            "metric": "duplicate_rate",
            "target": "<=0.2",
            "actual": dup_rate_actual,
            "status": dup_status,
            "unknown_reason": dup_reason,
        }
    )

    # ≥1 High+ accepted — count submissions whose severity ∈ {High, Critical}
    # AND whose outcome value is in {accepted, paid}.
    high_plus_accepted = 0
    high_plus_unknown = False
    for sub in submissions:
        sev = str(sub.get("severity", "")).lower()
        if sev not in ("high", "critical"):
            continue
        outcome_val = sub["outcome"]["value"]
        if outcome_val in ("accepted", "paid"):
            high_plus_accepted += 1
        elif outcome_val == "unknown":
            high_plus_unknown = True
    if not submissions:
        rows.append(
            {
                "metric": "high_plus_accepted",
                "target": ">=1",
                "actual": "unknown",
                "status": "UNKNOWN",
                "unknown_reason": "no submissions parsed",
            }
        )
    elif high_plus_unknown and high_plus_accepted == 0:
        rows.append(
            {
                "metric": "high_plus_accepted",
                "target": ">=1",
                "actual": "unknown",
                "status": "UNKNOWN",
                "unknown_reason": "high+ submissions exist but outcomes unknown",
            }
        )
    else:
        rows.append(
            {
                "metric": "high_plus_accepted",
                "target": ">=1",
                "actual": high_plus_accepted,
                "status": "PASS" if high_plus_accepted >= 1 else "FAIL",
                "unknown_reason": None,
            }
        )

    dpa = metrics["dollars_per_accepted"]
    rows.append(
        {
            "metric": "dollars_per_accepted",
            "target": "<=$50",
            "actual": dpa["value"],
            "status": status_from(
                dpa["value"], lambda v: float(v) <= 50.0, dpa.get("unknown_reason")
            ),
            "unknown_reason": dpa.get("unknown_reason"),
        }
    )

    ttfs = metrics["time_to_first_submittable_s"]
    rows.append(
        {
            "metric": "time_to_first_submittable_s",
            "target": "<=14400 (4h)",
            "actual": ttfs["value"],
            "status": status_from(
                ttfs["value"], lambda v: float(v) <= 14400.0, ttfs.get("unknown_reason")
            ),
            "unknown_reason": ttfs.get("unknown_reason"),
        }
    )

    return rows


# ---------------------------------------------------------------------------- #
# Honest-tone summary (templated from evidence)
# ---------------------------------------------------------------------------- #


def _format_metric_value(metric: dict[str, Any]) -> str:
    v = metric["value"]
    if v in ("unknown", "NA"):
        return v
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def render_honest_summary(
    submissions: list[dict[str, Any]],
    metrics: dict[str, dict[str, Any]],
    lessons: list[dict[str, Any]],
    exit_rows: list[dict[str, Any]],
) -> list[str]:
    """Templated honest-tone summary. NO freeform claims — every sentence
    cites a metric or a lesson with file:line provenance."""
    lines: list[str] = []
    lines.append("## Honest-Tone Summary")
    lines.append("")

    # Paragraph 1: numeric snapshot
    sub_n = len(submissions)
    cost_word = metrics["est_cost_usd"].get("wording") or _format_metric_value(
        metrics["est_cost_usd"]
    )
    accepted_v = _format_metric_value(metrics["accepted_count"])
    rate_v = _format_metric_value(metrics["accept_rate"])
    dpa_v = _format_metric_value(metrics["dollars_per_accepted"])
    p1 = (
        f"This engagement filed **{sub_n}** submission(s). "
        f"Accepted count: **{accepted_v}**. Accept-rate: **{rate_v}**. "
        f"Cost: {cost_word}. $/accepted: **{dpa_v}**."
    )
    lines.append(p1)
    lines.append("")

    # Paragraph 2: exit-criteria stance
    pass_count = sum(1 for r in exit_rows if r["status"] == "PASS")
    fail_count = sum(1 for r in exit_rows if r["status"] == "FAIL")
    unknown_count = sum(1 for r in exit_rows if r["status"] == "UNKNOWN")
    p2 = (
        f"Against the ROADMAP_10_OF_10_V2 exit criteria: "
        f"**{pass_count}** PASS, **{fail_count}** FAIL, **{unknown_count}** UNKNOWN. "
        "UNKNOWN rows reflect missing inputs, not a passing claim — see the "
        "exit-criteria table below for per-metric `unknown_reason`."
    )
    lines.append(p2)
    lines.append("")

    # Paragraph 3: lessons
    if lessons:
        method_counts: dict[str, int] = {}
        for L in lessons:
            method_counts[L["extraction_method"]] = (
                method_counts.get(L["extraction_method"], 0) + 1
            )
        method_str = ", ".join(
            f"{n} via {m}" for m, n in sorted(method_counts.items())
        )
        p3 = (
            f"Methodology lessons extracted: **{len(lessons)}** "
            f"({method_str}). Each lesson is provenance-tagged with "
            "`source_file:line` in the JSON sidecar; regex-fallback lessons "
            "are advisory and may capture noise."
        )
    else:
        p3 = (
            "Methodology lessons extracted: **0**. No structured `## Lessons` "
            "section nor `AP-N` / `FN-N` bullet was found in workspace `*.md` "
            "files. Operator should add a structured retrospective section."
        )
    lines.append(p3)
    lines.append("")
    return lines


# ---------------------------------------------------------------------------- #
# Markdown rendering
# ---------------------------------------------------------------------------- #


def render_retrospective_md(
    workspace: Path,
    generated_at: str,
    submissions_with_outcomes: list[dict[str, Any]],
    metrics: dict[str, dict[str, Any]],
    lessons: list[dict[str, Any]],
    exit_rows: list[dict[str, Any]],
) -> str:
    L: list[str] = []
    L.append(f"# Engagement Retrospective — `{workspace}`")
    L.append("")
    L.append(f"_Generated: {generated_at}_")
    L.append("")
    L.append(
        "_Inputs: local artifacts only. No platform API was contacted. "
        "Cost numbers are advisory (`est_*` wording preserved). Outcomes "
        "from `reference/outcomes.jsonl` are tagged advisory; partial/stale._"
    )
    L.append("")

    L.extend(render_honest_summary(submissions_with_outcomes, metrics, lessons, exit_rows))

    # Submissions table
    L.append("## Submissions")
    L.append("")
    if not submissions_with_outcomes:
        L.append("_No submissions parsed from workspace SUBMISSIONS.md._")
        L.append("")
    else:
        L.append("| ID | Severity | Title | Outcome | $ paid | Source-of-outcome |")
        L.append("|---|---|---|---|---|---|")
        for s in submissions_with_outcomes:
            outcome = s["outcome"]
            paid = s["paid_usd"]
            outcome_v = outcome["value"]
            paid_v = paid["value"]
            paid_disp = (
                f"${paid_v:.2f}" if isinstance(paid_v, (int, float)) else paid_v
            )
            prov = outcome.get("provenance") or "—"
            title = (s["title"] or "").replace("|", "\\|")
            L.append(
                f"| {s['id']} | {s['severity']} | {title} | {outcome_v} | "
                f"{paid_disp} | {prov} |"
            )
        L.append("")

    # Cost line
    L.append("## Cost (advisory)")
    L.append("")
    cost = metrics["est_cost_usd"]
    dur = metrics["est_duration_s"]
    if cost["value"] == "unknown":
        L.append(f"_cost telemetry: unavailable — {cost['unknown_reason']}_")
    else:
        L.append(f"- {cost['wording']}")
        L.append(
            f"- est_duration_s: {dur['value']:.1f}s "
            f"({float(dur['value']) / 60.0:.1f} min)  _(advisory)_"
        )
    L.append("")

    # Time-to-first-submittable
    L.append("## Time-to-first-submittable")
    L.append("")
    ttfs = metrics["time_to_first_submittable_s"]
    if ttfs["value"] == "unknown":
        L.append(f"- time_to_first_submittable: unknown — {ttfs['unknown_reason']}")
    else:
        secs = float(ttfs["value"])
        L.append(
            f"- time_to_first_submittable: {secs:.0f}s ({secs / 3600.0:.2f}h)"
        )
    L.append("")

    # $/accepted + accept-rate
    L.append("## Accept-rate and $/accepted")
    L.append("")
    rate = metrics["accept_rate"]
    dpa = metrics["dollars_per_accepted"]
    if rate["value"] == "unknown":
        L.append(f"- accept_rate: unknown — {rate['unknown_reason']}")
    else:
        L.append(f"- accept_rate: {rate['value']}")
    if dpa["value"] in ("NA", "unknown"):
        L.append(
            f"- $/accepted: {dpa['value']} — {dpa['unknown_reason']} "
            "(NEVER divide by zero, NEVER report inf)"
        )
    else:
        L.append(f"- $/accepted: {dpa.get('wording') or dpa['value']}")
    L.append("")

    # Lessons
    L.append("## Methodology Lessons")
    L.append("")
    if not lessons:
        L.append("_No structured `## Lessons` section nor `AP-N`/`FN-N` regex match found._")
    else:
        for ls in lessons:
            tag = (
                f" ({ls['anti_pattern_match']})" if ls.get("anti_pattern_match") else ""
            )
            method = ls["extraction_method"]
            advisory = " _[advisory]_" if method == "regex_fallback" else ""
            L.append(
                f"- **{method}**{tag}: {ls['text']}  \n"
                f"  _source: `{ls['source_file']}:{ls['source_line']}`_{advisory}"
            )
    L.append("")

    # Exit criteria
    L.append("## North-star Snapshot vs ROADMAP_10_OF_10_V2 Exit Criteria")
    L.append("")
    L.append("| Metric | Target | Actual | Status | Unknown reason |")
    L.append("|---|---|---|---|---|")
    for row in exit_rows:
        actual = row["actual"]
        if isinstance(actual, float):
            actual_disp = f"{actual:.4f}"
        else:
            actual_disp = str(actual)
        reason = row.get("unknown_reason") or "—"
        L.append(
            f"| {row['metric']} | {row['target']} | {actual_disp} | "
            f"{row['status']} | {reason} |"
        )
    L.append("")
    L.append(
        "_PASS/FAIL/UNKNOWN reflects measurement honesty: UNKNOWN means input "
        "data is missing, not that the criterion is met._"
    )
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------- #
# Top-level orchestration
# ---------------------------------------------------------------------------- #


def generate_retrospective(
    workspace: Path,
    *,
    cost_telemetry_path: Path = COST_TELEMETRY_PATH,
    advisory_outcomes_path: Path | None = DEFAULT_OUTCOMES_REF,
    write_files: bool = True,
) -> dict[str, Any]:
    """Build the retrospective JSON sidecar and (optionally) write
    ``RETROSPECTIVE.md`` + ``retrospective.json`` under ``workspace``.

    Returns the JSON sidecar payload."""
    ws = Path(workspace).expanduser().resolve()
    if not ws.is_dir():
        raise FileNotFoundError(f"workspace not found: {ws}")

    cost_telemetry = _load_cost_telemetry(cost_telemetry_path)
    cost_summary = cost_telemetry.summarize_workspace(ws)

    submissions, sub_provenance = parse_submissions(ws)

    # Operator-supplied outcomes (authoritative)
    operator_outcomes: dict[str, dict[str, Any]] = {}
    operator_provenance: str | None = None
    operator_md = ws / "OUTCOMES.md"
    if operator_md.is_file():
        operator_outcomes = _parse_operator_outcomes_md(operator_md)
        operator_provenance = str(operator_md)
    else:
        payouts_json = ws / "payouts.json"
        if payouts_json.is_file():
            operator_outcomes = _parse_payouts_json(payouts_json)
            operator_provenance = str(payouts_json)

    # Advisory outcomes (PARTIAL/STALE — never authoritative)
    advisory_rows: list[dict[str, Any]] = []
    advisory_provenance: str | None = None
    if advisory_outcomes_path is not None and Path(advisory_outcomes_path).is_file():
        advisory_rows = _load_advisory_outcomes_jsonl(Path(advisory_outcomes_path))
        try:
            advisory_provenance = str(
                Path(advisory_outcomes_path).resolve().relative_to(ROOT)
            )
        except ValueError:
            advisory_provenance = str(advisory_outcomes_path)

    submissions_with_outcomes = reconcile_outcomes(
        submissions,
        operator_outcomes,
        operator_provenance,
        advisory_rows,
        advisory_provenance,
    )

    cost_metric, dur_metric = _build_cost_metrics(cost_summary, ws)

    counts = _aggregate_outcome_counts(
        submissions_with_outcomes, operator_provenance, advisory_provenance
    )
    rates = _build_rate_metrics(counts, cost_metric)

    ttfs = _time_to_first_submittable(ws, sub_provenance)

    submissions_count_metric: dict[str, Any]
    if submissions:
        submissions_count_metric = _metric_known(
            len(submissions), sub_provenance or "workspace SUBMISSIONS.md"
        )
    else:
        submissions_count_metric = _metric_unknown(
            "no SUBMISSIONS.md found in workspace"
        )

    metrics = {
        "submissions_count": submissions_count_metric,
        "accepted_count": counts["accepted_count"],
        "rejected_count": counts["rejected_count"],
        "duplicate_count": counts["duplicate_count"],
        "pending_count": counts["pending_count"],
        "accept_rate": rates["accept_rate"],
        "est_cost_usd": cost_metric,
        "est_duration_s": dur_metric,
        "dollars_per_accepted": rates["dollars_per_accepted"],
        "time_to_first_submittable_s": ttfs,
    }

    lessons = extract_lessons(ws)
    exit_rows = _exit_criteria_rows(metrics, submissions_with_outcomes)

    generated_at = datetime.now(tz=timezone.utc).isoformat()

    sidecar: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(ws),
        "generated_at": generated_at,
        "metrics": metrics,
        "submissions": submissions_with_outcomes,
        "lessons": lessons,
        "exit_criteria": exit_rows,
        "inputs": {
            "cost_summary_present": cost_summary.get("stage_count", 0) > 0,
            "submissions_md": sub_provenance,
            "operator_ledger": operator_provenance,
            "advisory_outcomes": advisory_provenance,
        },
    }

    if write_files:
        md = render_retrospective_md(
            ws, generated_at, submissions_with_outcomes, metrics, lessons, exit_rows
        )
        (ws / "RETROSPECTIVE.md").write_text(md, encoding="utf-8")
        (ws / "retrospective.json").write_text(
            json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return sidecar


# ---------------------------------------------------------------------------- #
# CLI
# ---------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "PR #128 — generate a provenance-backed engagement retrospective "
            "(RETROSPECTIVE.md + retrospective.json) from local workspace artifacts."
        ),
    )
    ap.add_argument("workspace", help="Workspace directory to summarize.")
    ap.add_argument(
        "--cost-telemetry-path",
        default=str(COST_TELEMETRY_PATH),
        help="Path to tools/cost-telemetry.py (override for tests).",
    )
    ap.add_argument(
        "--advisory-outcomes",
        default=str(DEFAULT_OUTCOMES_REF),
        help=(
            "Path to reference/outcomes.jsonl (advisory; partial/stale). "
            "Pass /dev/null to disable."
        ),
    )
    ap.add_argument(
        "--no-write",
        action="store_true",
        help="Skip writing RETROSPECTIVE.md and retrospective.json (preview only).",
    )
    ap.add_argument(
        "--print-json",
        action="store_true",
        help="Print the JSON sidecar to stdout.",
    )
    args = ap.parse_args(argv)

    advisory_path: Path | None = (
        Path(args.advisory_outcomes) if args.advisory_outcomes else None
    )
    sidecar = generate_retrospective(
        Path(args.workspace),
        cost_telemetry_path=Path(args.cost_telemetry_path),
        advisory_outcomes_path=advisory_path,
        write_files=not args.no_write,
    )
    if args.print_json:
        print(json.dumps(sidecar, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
