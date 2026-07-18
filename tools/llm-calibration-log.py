#!/usr/bin/env python3
"""llm-calibration-log.py — single source of truth for LLM-call accuracy.

User mandate: "fully automated, learn as we go, never stop."

The hand-maintained calibration ledger in ``docs/LLM_DELEGATION_MATRIX.md``
goes stale the moment a new PR-review or gap-finding outcome is verified.
Agent prompts that paste hard-coded percentages (Kimi ~67% PR-review,
Minimax ~50%, etc.) drift from reality within a single session.

This tool replaces that hand-maintenance with an append-only JSONL ledger
of every observed LLM-call outcome. Other tools import
``cite_calibration(provider, task_type)`` to inject *current* accuracy
into LLM disclaimers and agent prompts — no more stale percentages.

Schema (one event per line; see :data:`SCHEMA_FIELDS`)::

    {
      "ts": "2026-04-25T22:50:00Z",
      "provider": "kimi" | "minimax" | "claude" | "codex",
      "task_type": "pr-review" | "synthesis" | "redteam" |
                   "methodology-critique" | "gap-finding" |
                   "code-authoring" | "doc-maintenance",
      "task_ref": "PR #167" | "M14 #2 cross-fn-reentrancy" | ...,
      "prompt_hash": "sha256:abc123..." | null,
      "verdict": "TRUE" | "FALSE" | "INDETERMINATE" | "PARTIAL",
      "evidence": "PR #167 verified-true via line-318 grep" | ...,
      "operator": "claude-supervisor" | "agent-aXXX" | "user-manual",
      "session_id": "2026-04-25",
      "model": "kimi-for-coding" | "MiniMax-M2.7" | ...,
      "local_verification_accepted": "true" | "false" | "unknown"
    }

Subcommands::

    llm-calibration-log.py log <provider> <task_type> <task_ref> <verdict>
        [--evidence STR] [--prompt-hash STR] [--operator STR]
        [--session-id STR] [--ts ISO]
    llm-calibration-log.py stats [--provider P] [--task-type T] [--since DATE]
    llm-calibration-log.py cite  [--provider P] [--task-type T]
    llm-calibration-log.py provider-assist [--json]
    llm-calibration-log.py recent [N]
    llm-calibration-log.py validate

Storage: ``tools/calibration/llm_calibration_log.jsonl`` (versioned).

Append-only contract
--------------------
Past entries are NEVER overwritten on disk. To amend a verdict, log a NEW
event with the SAME ``provider`` + ``task_ref`` + ``prompt_hash``; the
later entry wins for query results (see ``_dedupe_keep_latest``).

Stdlib only. No new pip deps. No standalone .md docs.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

THIS_FILE = Path(__file__).resolve()
TOOLS_DIR = THIS_FILE.parent
CALIBRATION_DIR = TOOLS_DIR / "calibration"
LEDGER_PATH = CALIBRATION_DIR / "llm_calibration_log.jsonl"
BUDGET_PATH = CALIBRATION_DIR / "llm_budget.json"


SCHEMA_FIELDS = (
    "ts",
    "provider",
    "task_type",
    "task_ref",
    "prompt_hash",
    "verdict",
    "evidence",
    "operator",
    "session_id",
    # Lane-7 model telemetry: records the concrete provider model/version so
    # calibration remains meaningful when Kimi/MiniMax plans change.
    # Optional on legacy rows; new CLI log rows write a best-effort value.
    "model",
    # Lane-7 addition: records whether local verification (rg / source-ref /
    # test / harness) accepted the provider output for this calibration row.
    # Tri-state: "true" | "false" | "unknown".  Absent on legacy rows (pre-
    # Lane-7); treated as "unknown" at read time. NOT in REQUIRED_FIELDS so
    # the existing 558-row append-only ledger validates without migration.
    "local_verification_accepted",
)

REQUIRED_FIELDS = (
    "ts",
    "provider",
    "task_type",
    "task_ref",
    "verdict",
)

VALID_PROVIDERS = frozenset({
    "kimi",
    "minimax",
    "claude",
    "codex",
})

VALID_TASK_TYPES = frozenset({
    "pr-review",
    "synthesis",
    "redteam",
    "methodology-critique",
    "gap-finding",
    "code-authoring",
    "doc-maintenance",
    "scope-triage",
    # V4 P5 task-type presets — added so per-task accuracy is sliceable
    # separately from the canonical ``pr-review`` aggregate. The set must
    # stay in sync with ``TASK_TYPES`` in ``tools/llm-pr-review.py``;
    # adding a preset there without adding it here makes calibration log
    # writes fail validation.
    "detector-tier-b",
    "gate-hardening",
    "docs-plan",
    "submission-critical",
    "crypto-review",
    "econ-review",
    # P0-3 model-routing task classes. These mirror the operational lanes
    # named in docs/KNOWN_LIMITATIONS.md so routing can be measured by task,
    # not by provider reputation or stale aggregate accuracy.
    "source-extraction",
    "adversarial-kill",
    "poc-wiring",
    "docs-integration",
    # P0-3 burn-down expansion (2026-04-29). The seed calibration matrix at
    # ``reference/llm_calibration_seed.json`` declares one row per
    # (provider, task_type) lane currently being measured; the names below
    # mirror the lanes operators dispatch into so the merge-hook can append
    # outcomes against the same task_type used by routing decisions.
    "missing-path-evidence",
    "oos-review",
    "contradiction-search",
    "harness-implementation",
    "fixture-wiring",
    # P0-3 closure (2026-05-04). Factory/config/liveness extraction & kill
    # lanes were declared in the seed file but never registered as valid
    # task_types here, so the route command refused them with an argparse
    # 'invalid choice' error. They are routed advisory-only by explicit
    # policy until merge-hook telemetry supplies verified outcomes.
    "factory-config-liveness-extraction",
    "factory-config-liveness-kill",
    # Severity review lanes. These record whether a provider correctly
    # recommended a downgrade/escalation after local adjudication; provider
    # output still has no direct severity authority.
    "severity-downgrade",
    "severity-escalation",
})

VALID_VERDICTS = frozenset({
    "TRUE",
    "FALSE",
    "INDETERMINATE",
    "PARTIAL",
})

ROUTING_MIN_DECIDED = 5
ROUTING_MIN_PRECISION = 0.70

# P0-3 seed calibration matrix. The JSON file at this path is the single
# source of truth for per-(provider, task_type) routing rows; the doc at
# ``docs/LLM_DELEGATION_MATRIX.md`` mirrors it. ``routing_status`` consults
# this file BEFORE the JSONL ledger so "we have not yet measured this lane"
# is a first-class refusal class (``cannot-route: insufficient-data`` /
# ``cannot-route: no-calibration``) rather than an implicit pass.
REPO_ROOT = TOOLS_DIR.parent
SEED_PATH = REPO_ROOT / "reference" / "llm_calibration_seed.json"
ROUTING_MIN_SAMPLES = 20

PROVIDER_ASSIST_PROFILES: Dict[str, Dict[str, Any]] = {
    "kimi": {
        "best_use": (
            "Long-context source/spec reading, line-cited candidate "
            "extraction, and architecture sanity checks on scoped packets."
        ),
        "known_failures": (
            "Cross-reference/library gap enumeration without grep-precheck; "
            "multi-file patch generation can produce shape-valid but "
            "unapplyable diffs."
        ),
        "recommended_loop_role": "candidate_extractor",
        "source_refs": [
            "docs/SOURCE_MINING_RUNBOOK.md provider table",
            "docs/V5_P0_CLAUDE_EXECUTION_PLAN_2026-04-27.md delegation model",
            "docs/CAPABILITY_V3_ITER_009_RESULTS.md T2 provider failure",
        ],
    },
    "minimax": {
        "best_use": (
            "Adversarial kill passes, OOS/duplicate/false-positive review, "
            "large-surface synthesis, and contradiction search on bounded "
            "packets."
        ),
        "known_failures": (
            "Can infer missing features from truncated input and can mistake "
            "sampled pattern context for complete library coverage."
        ),
        "recommended_loop_role": "candidate_killer",
        "source_refs": [
            "docs/SOURCE_MINING_RUNBOOK.md provider table",
            "docs/V5_P0_CLAUDE_EXECUTION_PLAN_2026-04-27.md delegation model",
            "docs/PROVIDER_DISPATCH_TEMPLATES.md refusal rules",
        ],
    },
}

PROVIDER_ASSIST_HARD_GUARDS = (
    "provider_output_advisory_only",
    "no_provider_promotion_without_local_verification",
    "no_paste_ready_from_provider_output",
    "no_severity_authority_from_provider_output",
    "line_citations_scope_oos_and_poc_gates_still_required",
)

FCL_SAMPLE_SCHEMA = "auditooor.factory_config_liveness_calibration_sample.v1"
FCL_PROVIDER_TASK_TYPES = {
    "kimi": "factory-config-liveness-extraction",
    "minimax": "factory-config-liveness-kill",
}


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    """Return UTC now in second-precision ISO-8601 with trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ledger_path(override: Optional[Path] = None) -> Path:
    return Path(override) if override is not None else LEDGER_PATH


def load_entries(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Read all events from the JSONL ledger. Skips blank lines.

    Returns an empty list if the file does not exist yet.
    Raises ValueError on any malformed JSON line (with line number).
    """
    p = _ledger_path(path)
    if not p.is_file():
        return []
    out: List[Dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"{p}:{lineno}: malformed JSON: {e}"
                ) from e
    return out


def append_entry(entry: Dict[str, Any], path: Optional[Path] = None) -> None:
    """Append one validated entry to the JSONL ledger.

    Creates the calibration directory if missing. Never overwrites; this
    is the only writer for past data.
    """
    validate_entry(entry)
    p = _ledger_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

VALID_LOCAL_VERIFICATION_VALUES = frozenset({"true", "false", "unknown"})

DEFAULT_MODELS = {
    "kimi": "kimi-for-coding",
    "minimax": "MiniMax-M2.7",
    "claude": "claude-opus-4-5",
    "codex": "unknown",
}

MODEL_ENV_VARS = {
    "kimi": "KIMI_MODEL",
    "minimax": "MINIMAX_MODEL",
    "claude": "ANTHROPIC_MODEL",
    "codex": "CODEX_MODEL",
}


def _resolve_model_hint(provider: str) -> str:
    """Return a stable best-effort model label for new calibration rows."""
    provider_key = (provider or "").lower()
    env_var = MODEL_ENV_VARS.get(provider_key)
    if env_var:
        value = os.environ.get(env_var, "").strip()
        if value:
            return value
    return DEFAULT_MODELS.get(provider_key, "unknown")


def validate_entry(entry: Dict[str, Any]) -> None:
    """Raise ValueError if the entry is not schema-compliant.

    Optional fields (prompt_hash, evidence, operator, session_id, model,
    local_verification_accepted) are allowed to be absent or null.
    Unknown extra fields are rejected so the schema stays tight.

    ``local_verification_accepted`` is a Lane-7 addition. Absent entries
    (legacy rows) are treated as ``"unknown"`` at read time; a present
    value must be one of ``"true"``, ``"false"``, or ``"unknown"``.
    """
    if not isinstance(entry, dict):
        raise ValueError(f"entry must be dict, got {type(entry).__name__}")
    for f in REQUIRED_FIELDS:
        if entry.get(f) in (None, ""):
            raise ValueError(f"missing required field: {f}")
    extra = set(entry.keys()) - set(SCHEMA_FIELDS)
    if extra:
        raise ValueError(f"unknown fields: {sorted(extra)}")
    if entry["provider"] not in VALID_PROVIDERS:
        raise ValueError(
            f"invalid provider: {entry['provider']!r}; "
            f"expected one of {sorted(VALID_PROVIDERS)}"
        )
    if entry["task_type"] not in VALID_TASK_TYPES:
        raise ValueError(
            f"invalid task_type: {entry['task_type']!r}; "
            f"expected one of {sorted(VALID_TASK_TYPES)}"
        )
    if entry["verdict"] not in VALID_VERDICTS:
        raise ValueError(
            f"invalid verdict: {entry['verdict']!r}; "
            f"expected one of {sorted(VALID_VERDICTS)}"
        )
    model = entry.get("model")
    if model is not None and (not isinstance(model, str) or not model.strip()):
        raise ValueError("model must be a non-empty string when present")
    # ts must be parseable ISO-8601.
    ts = entry["ts"]
    if not isinstance(ts, str):
        raise ValueError(f"ts must be ISO-8601 string, got {type(ts).__name__}")
    try:
        # Accept both trailing Z and explicit offset.
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"ts not parseable as ISO-8601: {ts!r} ({e})") from e
    # local_verification_accepted is optional (absent on legacy rows).
    lva = entry.get("local_verification_accepted")
    if lva is not None and lva not in VALID_LOCAL_VERIFICATION_VALUES:
        raise ValueError(
            f"invalid local_verification_accepted: {lva!r}; "
            f"expected one of {sorted(VALID_LOCAL_VERIFICATION_VALUES)}"
        )


def validate_all(entries: Iterable[Dict[str, Any]]) -> List[str]:
    """Run :func:`validate_entry` on every row, return list of errors.

    Empty list => clean ledger.
    """
    errs: List[str] = []
    for i, entry in enumerate(entries):
        try:
            validate_entry(entry)
        except ValueError as e:
            errs.append(f"row {i}: {e}")
    return errs


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def _dedupe_keep_latest(
    entries: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Collapse entries that share (provider, task_ref, prompt_hash).

    The LATER entry (by file order, which is also chronological since we
    only append) wins. This lets an operator amend a past verdict by
    logging a fresh event with the same trio.

    Entries with prompt_hash=None are NEVER deduped — they are treated
    as distinct observations.
    """
    seen: Dict[Tuple[str, str, str], int] = {}
    rows = list(entries)
    for i, e in enumerate(rows):
        ph = e.get("prompt_hash")
        if not ph:
            continue
        key = (e.get("provider", ""), e.get("task_ref", ""), ph)
        seen[key] = i  # later index overwrites
    keep_idx = set(seen.values())
    out: List[Dict[str, Any]] = []
    for i, e in enumerate(rows):
        ph = e.get("prompt_hash")
        if not ph:
            out.append(e)
        elif i in keep_idx:
            out.append(e)
    return out


def _parse_since(since: str) -> datetime:
    """Parse a --since arg. Accepts YYYY-MM-DD or full ISO-8601."""
    s = since.strip()
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        # Date-only: anchor to UTC midnight.
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def filter_entries(
    entries: Iterable[Dict[str, Any]],
    *,
    provider: Optional[str] = None,
    task_type: Optional[str] = None,
    since: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Apply (provider, task_type, since) filters. Order preserved."""
    cutoff = _parse_since(since) if since else None
    out = []
    for e in entries:
        if provider and e.get("provider") != provider:
            continue
        if task_type and e.get("task_type") != task_type:
            continue
        if cutoff:
            ts = e.get("ts", "")
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                continue
            if dt < cutoff:
                continue
        out.append(e)
    return out


def compute_stats(entries: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Tally TRUE/FALSE/PARTIAL/INDETERMINATE counts and accuracy.

    Accuracy = TRUE / (TRUE + FALSE). PARTIAL and INDETERMINATE are
    excluded from the denominator since they are not binary outcomes.
    """
    rows = list(entries)
    counts = {v: 0 for v in VALID_VERDICTS}
    for e in rows:
        v = e.get("verdict")
        if v in counts:
            counts[v] += 1
    decided = counts["TRUE"] + counts["FALSE"]
    accuracy = (counts["TRUE"] / decided) if decided else None
    earliest = min((e.get("ts", "") for e in rows), default="")
    latest = max((e.get("ts", "") for e in rows), default="")
    return {
        "n": len(rows),
        "true": counts["TRUE"],
        "false": counts["FALSE"],
        "partial": counts["PARTIAL"],
        "indeterminate": counts["INDETERMINATE"],
        "decided": decided,
        "accuracy": accuracy,
        "earliest_ts": earliest,
        "latest_ts": latest,
    }


def _slugify_ref(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-")
    return slug[:96] or "sample"


def _normalize_fcl_verdict(verdict: str) -> str:
    normalized = verdict.strip().lower().replace("_", "-")
    mapping = {
        "verified-true": "TRUE",
        "true": "TRUE",
        "tp": "TRUE",
        "pass": "TRUE",
        "verified-false-positive": "FALSE",
        "verified-false": "FALSE",
        "false": "FALSE",
        "fp": "FALSE",
        "fail": "FALSE",
        "verified-partial": "PARTIAL",
        "partial": "PARTIAL",
        "verified-indeterminate": "INDETERMINATE",
        "indeterminate": "INDETERMINATE",
    }
    try:
        return mapping[normalized]
    except KeyError as exc:
        raise ValueError(f"unknown factory-config-liveness verdict: {verdict!r}") from exc


def summarize_lane(
    provider: str,
    task_type: str,
    *,
    path: Optional[Path] = None,
    seed_path: Optional[Path] = None,
) -> Dict[str, Any]:
    rows = _dedupe_keep_latest(load_entries(path))
    stats = compute_stats(filter_entries(rows, provider=provider, task_type=task_type))
    route = routing_status(provider, task_type, path=path, seed_path=seed_path)
    return {
        "provider": provider,
        "task_type": task_type,
        **stats,
        "primary_allowed": route["primary_allowed"],
        "advisory_only": route["advisory_only"],
        "routing_reason": route["reason"],
        "sample_count": route.get("sample_count"),
        "precision_pct": route.get("precision_pct"),
    }


def sync_seed_row_from_ledger(
    provider: str,
    task_type: str,
    *,
    path: Optional[Path] = None,
    seed_path: Optional[Path] = None,
    min_samples: int = ROUTING_MIN_SAMPLES,
) -> Dict[str, Any]:
    seed_file = _seed_path(seed_path)
    seed = load_seed(seed_file) or {"_schema_version": 1, "rows": []}
    rows = seed.setdefault("rows", [])
    row = lookup_seed_row(provider, task_type, seed=seed)
    if row is None:
        row = {
            "provider": provider,
            "task_type": task_type,
            "notes": "Auto-synced from normalized calibration ledger.",
        }
        rows.append(row)

    ledger_rows = _dedupe_keep_latest(load_entries(path))
    stats = compute_stats(filter_entries(ledger_rows, provider=provider, task_type=task_type))
    sample_count = int(stats["decided"])
    if sample_count >= min_samples and stats["accuracy"] is not None:
        precision_pct: int | str = round(100 * stats["accuracy"])
        row.pop("advisory_only_explicit", None)
    else:
        precision_pct = "insufficient-data"
    row["sample_count"] = sample_count
    row["precision_pct"] = precision_pct
    row["last_updated_iso"] = _utcnow_iso()

    seed_file.parent.mkdir(parents=True, exist_ok=True)
    seed_file.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")

    route = routing_status(provider, task_type, path=path, seed_path=seed_file, min_samples=min_samples)
    return {
        "provider": provider,
        "task_type": task_type,
        "seed_sample_count": sample_count,
        "seed_precision_pct": precision_pct,
        "primary_allowed": route["primary_allowed"],
        "routing_reason": route["reason"],
    }


def record_fcl_sample(
    provider: str,
    task_ref: str,
    verdict: str,
    *,
    evidence: str,
    candidate_id: str = "",
    packet_path: str = "",
    local_proof: str = "",
    ledger_path: Optional[Path] = None,
    samples_dir: Optional[Path] = None,
    seed_path: Optional[Path] = None,
) -> Dict[str, Any]:
    if provider not in FCL_PROVIDER_TASK_TYPES:
        raise ValueError(f"unsupported factory-config-liveness provider: {provider!r}")
    task_type = FCL_PROVIDER_TASK_TYPES[provider]
    normalized_verdict = _normalize_fcl_verdict(verdict)
    ts = _utcnow_iso()
    entry: Dict[str, Any] = {
        "ts": ts,
        "provider": provider,
        "task_type": task_type,
        "task_ref": task_ref,
        "verdict": normalized_verdict,
        "evidence": evidence,
    }
    append_entry(entry, path=ledger_path)

    out_dir = Path(samples_dir) if samples_dir is not None else CALIBRATION_DIR / "factory_config_liveness_samples"
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / f"{_slugify_ref(provider + '-' + task_ref)}.json"
    manifest = {
        "schema": FCL_SAMPLE_SCHEMA,
        "recorded_at": ts,
        "provider": provider,
        "task_type": task_type,
        "task_ref": task_ref,
        "candidate_id": candidate_id,
        "packet_path": packet_path,
        "local_proof": local_proof,
        "raw_verdict": verdict,
        "normalized_verdict": normalized_verdict,
        "evidence": evidence,
        "ledger_path": str(_ledger_path(ledger_path)),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary = summarize_lane(provider, task_type, path=ledger_path, seed_path=seed_path)
    return {
        "manifest_path": str(manifest_path),
        "ledger_entry": entry,
        "summary": summary,
    }


def load_budget_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load the active LLM budget config as plain JSON.

    This intentionally does not import ``llm-budget-guard.py`` because
    this module is often imported from tools that only need calibration
    text. The budget guard remains the runtime enforcer; this helper is
    read-only summary plumbing.
    """
    p = Path(path) if path is not None else BUDGET_PATH
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    providers = data.get("providers")
    if not isinstance(providers, dict):
        raise ValueError(f"budget config {p} missing providers object")
    return data


def provider_assist_summary(
    *,
    ledger_path: Optional[Path] = None,
    budget_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Summarize provider-assist routing from ledger + active budget config.

    Output is intentionally advisory: it recommends how to spend paid-tier
    capacity but keeps provider text out of promotion, paste-ready, and
    severity-authority paths.
    """
    rows = _dedupe_keep_latest(load_entries(ledger_path))
    try:
        budget = load_budget_config(budget_path)
    except (OSError, ValueError) as e:
        budget = {"error": str(e), "providers": {}}
    provider_budgets = budget.get("providers", {})
    providers: Dict[str, Any] = {}
    for provider, profile in PROVIDER_ASSIST_PROFILES.items():
        p_rows = filter_entries(rows, provider=provider)
        all_stats = compute_stats(p_rows)
        task_stats: Dict[str, Any] = {}
        for task_type in sorted({r.get("task_type", "") for r in p_rows}):
            if not task_type:
                continue
            s = compute_stats(filter_entries(p_rows, task_type=task_type))
            task_stats[task_type] = s
        budget_row = provider_budgets.get(provider, {})
        providers[provider] = {
            "profile": profile,
            "active_budget": {
                "window_minutes": budget_row.get("window_minutes"),
                "max_calls": budget_row.get("max_calls"),
                "max_tokens": budget_row.get("max_tokens"),
                "soft_ratio": budget_row.get("soft_ratio"),
            },
            "paid_tier_mode": (
                "active-aggressive-audited"
                if provider in ("kimi", "minimax")
                and int(budget_row.get("max_calls") or 0) >= 100
                else "conservative-or-unset"
            ),
            "stats_all_tasks": all_stats,
            "stats_by_task_type": task_stats,
            "loop_recommendation": (
                "Spend paid-tier capacity on bounded provider-assist loops, "
                "not on direct promotion. Keep dispatch-preflight templates, "
                "budget logging, campaign/audit artifacts, and local gates "
                "between provider output and any finding."
            ),
        }
    return {
        "schema": "auditooor.provider_assist_calibration.v1",
        "source_of_truth": {
            "ledger": str(_ledger_path(ledger_path)),
            "budget": str(Path(budget_path) if budget_path else BUDGET_PATH),
            "profile_sources": sorted({
                ref
                for p in PROVIDER_ASSIST_PROFILES.values()
                for ref in p["source_refs"]
            }),
        },
        "hard_guards": list(PROVIDER_ASSIST_HARD_GUARDS),
        "providers": providers,
        "legacy_budget_note": (
            "Old 30/h Kimi and 60/h Minimax ceilings are legacy history only; "
            "the active budget config is authoritative for current loops."
        ),
    }


def _seed_path(override: Optional[Path] = None) -> Path:
    return Path(override) if override is not None else SEED_PATH


def load_seed(path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Load the seed calibration JSON, returning None if it is missing.

    The seed file is a hand-curated mirror of the per-(provider, task_type)
    rows we currently track. Its absence is treated as "no seed configured"
    and routing falls back to the JSONL ledger alone (preserves backward
    compat with deployments that haven't shipped the seed yet). A malformed
    seed raises ValueError so the caller can fail closed loudly.
    """
    p = _seed_path(path)
    if not p.is_file():
        return None
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def lookup_seed_row(
    provider: str,
    task_type: str,
    *,
    seed: Optional[Dict[str, Any]] = None,
    seed_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Return the seed row for provider × task_type, or None if not present.

    Accepts either a pre-loaded seed dict or a path override (for tests).
    The seed itself may be absent (returns None to signal "no seed
    configured"); a missing row inside an existing seed also returns None
    but the caller is expected to map that to ``no-calibration``.
    """
    if seed is None:
        seed = load_seed(seed_path)
    if seed is None:
        return None
    rows = seed.get("rows", [])
    for row in rows:
        if (
            row.get("provider") == provider
            and row.get("task_type") == task_type
        ):
            return row
    return None


def _seed_routing_decision(
    provider: str,
    task_type: str,
    *,
    seed: Optional[Dict[str, Any]],
    min_samples: int,
    min_precision: float,
) -> Optional[Dict[str, Any]]:
    """Derive a routing decision from the seed file alone.

    Returns None when no seed file is configured (backwards-compat: the
    legacy JSONL-only routing path remains in effect). When a seed exists
    but the lane has no row, returns a ``cannot-route: no-calibration``
    decision. When the row exists but ``sample_count`` is below the
    threshold or ``precision_pct`` is the literal sentinel
    ``"insufficient-data"``, returns ``cannot-route: insufficient-data``.

    When the row carries the explicit policy marker
    ``advisory_only_explicit: true``, routing returns
    ``advisory-only-by-explicit-policy`` instead of
    ``cannot-route: insufficient-data``. This is an operator-curated
    decision class used when a lane has no calibration data but is
    intentionally kept advisory-only as a documented routing policy
    (e.g. the lane is reserved for human review, or its task class is
    high-risk and should never auto-promote regardless of sample count).
    The flag does NOT permit primary routing — it only changes the
    refusal reason so downstream stop-condition logic can distinguish
    "we forgot to seed this lane" from "we explicitly chose to keep this
    lane advisory."
    """
    if seed is None:
        return None
    row = lookup_seed_row(provider, task_type, seed=seed)
    base = {
        "provider": provider,
        "task_type": task_type,
        "primary_allowed": False,
        "advisory_only": True,
        "min_samples": int(min_samples),
        "min_precision": float(min_precision),
    }
    if row is None:
        base.update({
            "reason": "cannot-route: no-calibration",
            "sample_count": 0,
            "precision_pct": None,
        })
        return base
    sample_count = int(row.get("sample_count", 0) or 0)
    precision_pct = row.get("precision_pct")
    last_updated = row.get("last_updated_iso")
    advisory_only_explicit = bool(row.get("advisory_only_explicit", False))
    base["sample_count"] = sample_count
    base["precision_pct"] = precision_pct
    base["advisory_only_explicit"] = advisory_only_explicit
    if last_updated:
        base["last_updated_iso"] = last_updated
    if advisory_only_explicit:
        base["reason"] = "advisory-only-by-explicit-policy"
        return base
    if (
        sample_count < min_samples
        or precision_pct == "insufficient-data"
        or precision_pct is None
    ):
        base["reason"] = "cannot-route: insufficient-data"
        return base
    # Numeric precision: convert percent to fraction and apply the standard
    # 70% floor before allowing primary routing.
    try:
        pct_value = float(precision_pct)
    except (TypeError, ValueError):
        base["reason"] = "cannot-route: insufficient-data"
        return base
    if pct_value < (min_precision * 100):
        base["reason"] = "cannot-route: precision-below-threshold"
        return base
    base["primary_allowed"] = True
    base["advisory_only"] = False
    base["reason"] = "primary-allowed-by-seed"
    return base


def routing_status(
    provider: str,
    task_type: str,
    *,
    path: Optional[Path] = None,
    min_decided: int = ROUTING_MIN_DECIDED,
    min_precision: float = ROUTING_MIN_PRECISION,
    seed_path: Optional[Path] = None,
    min_samples: int = ROUTING_MIN_SAMPLES,
) -> Dict[str, Any]:
    """Return the empirical routing state for provider × task_type.

    ``primary_allowed`` means the lane has enough verified TRUE/FALSE rows
    and meets the precision floor. Otherwise callers must treat the model as
    advisory-only for this task class. Missing or malformed ledgers fail
    closed to advisory-only because absence of evidence is not precision.

    Seed precedence: when a seed calibration matrix is present at
    ``reference/llm_calibration_seed.json`` (or an explicit ``seed_path``),
    its row for the requested lane is consulted FIRST. A missing seed file
    is backwards-compatible — routing falls back to the JSONL ledger alone.
    A missing row inside an existing seed yields
    ``cannot-route: no-calibration``; a present row with
    ``sample_count < min_samples`` (or ``precision_pct == "insufficient-data"``)
    yields ``cannot-route: insufficient-data``. This makes "we have no data"
    a first-class refusal class instead of an implicit advisory-only pass.
    """
    try:
        seed = load_seed(seed_path)
    except (OSError, ValueError) as e:
        # Loud failure: a malformed seed is operator-fixable but must not
        # silently fall through to the JSONL path because the seed was
        # supposed to be the source of truth.
        return {
            "provider": provider,
            "task_type": task_type,
            "primary_allowed": False,
            "advisory_only": True,
            "reason": "seed-invalid",
            "detail": str(e),
            "decided": 0,
            "accuracy": None,
            "min_decided": int(min_decided),
            "min_precision": float(min_precision),
            "min_samples": int(min_samples),
        }
    seed_decision = _seed_routing_decision(
        provider,
        task_type,
        seed=seed,
        min_samples=min_samples,
        min_precision=min_precision,
    )
    try:
        rows = load_entries(path)
    except ValueError as e:
        return {
            "provider": provider,
            "task_type": task_type,
            "primary_allowed": False,
            "advisory_only": True,
            "reason": "ledger-invalid",
            "detail": str(e),
            "decided": 0,
            "accuracy": None,
            "min_decided": int(min_decided),
            "min_precision": float(min_precision),
            "min_samples": int(min_samples),
        }
    rows = _dedupe_keep_latest(rows)
    rows = filter_entries(rows, provider=provider, task_type=task_type)
    s = compute_stats(rows)
    reason = "primary-allowed"
    primary_allowed = True
    if s["decided"] == 0:
        primary_allowed = False
        reason = "missing-precision-data"
    elif s["decided"] < min_decided:
        primary_allowed = False
        reason = "insufficient-verified-rows"
    elif s["accuracy"] is None or s["accuracy"] < min_precision:
        primary_allowed = False
        reason = "precision-below-threshold"
    out: Dict[str, Any] = {
        "provider": provider,
        "task_type": task_type,
        "primary_allowed": primary_allowed,
        "advisory_only": not primary_allowed,
        "reason": reason,
        "n": s["n"],
        "true": s["true"],
        "false": s["false"],
        "partial": s["partial"],
        "indeterminate": s["indeterminate"],
        "decided": s["decided"],
        "accuracy": s["accuracy"],
        "earliest_ts": s["earliest_ts"],
        "latest_ts": s["latest_ts"],
        "min_decided": int(min_decided),
        "min_precision": float(min_precision),
        "min_samples": int(min_samples),
    }
    # Seed wins when it can refuse. The seed's authority is "we have not
    # yet measured this lane enough to allow promotion routing"; we
    # surface the seed's reason and clamp primary_allowed to False so the
    # JSONL path cannot accidentally bypass an explicitly insufficient
    # seed row. When the seed says primary-allowed-by-seed, we still
    # require the JSONL path to NOT be in an explicit refusal state — but
    # since the seed is the operator-curated source of truth, its allow
    # is honored even when JSONL is empty (the operator hand-promoted the
    # row, which is the documented out-of-band escape hatch).
    if seed_decision is not None:
        out["seed_row_present"] = lookup_seed_row(
            provider, task_type, seed=seed
        ) is not None
        out["sample_count"] = seed_decision.get("sample_count")
        out["precision_pct"] = seed_decision.get("precision_pct")
        if "advisory_only_explicit" in seed_decision:
            out["advisory_only_explicit"] = seed_decision[
                "advisory_only_explicit"
            ]
        if "last_updated_iso" in seed_decision:
            out["last_updated_iso"] = seed_decision["last_updated_iso"]
        if seed_decision.get("primary_allowed"):
            # Seed allows promotion. Still respect a JSONL-side hard
            # refusal (low precision below 70%) — the seed's row could be
            # stale and JSONL is the live signal.
            if reason == "precision-below-threshold":
                out["reason"] = "precision-below-threshold"
                return out
            out["primary_allowed"] = True
            out["advisory_only"] = False
            out["reason"] = seed_decision["reason"]
            return out
        # Seed refuses. Override the JSONL reason with the seed's refusal
        # so callers see "cannot-route: insufficient-data" /
        # "cannot-route: no-calibration" instead of the generic
        # "missing-precision-data".
        out["primary_allowed"] = False
        out["advisory_only"] = True
        out["reason"] = seed_decision["reason"]
    return out


# ---------------------------------------------------------------------------
# Public helper: cite_calibration (imported by other tools)
# ---------------------------------------------------------------------------

def cite_calibration(
    provider: str,
    task_type: str,
    *,
    path: Optional[Path] = None,
    fallback: str = "",
) -> str:
    """Return a 1-line calibration string suitable for LLM disclaimers.

    Example output::

        "kimi pr-review accuracy: 7/9 = 78% (n=9, since 2026-04-15)"

    If the ledger is missing or has zero matching decided rows, returns
    the ``fallback`` string (caller can pass a static disclaimer).

    Other tools (notably ``tools/llm-pr-review.py``) import this so the
    disclaimer they post on every PR review reflects the *current*
    ledger, not a snapshot from when the file was last hand-edited.
    """
    try:
        rows = load_entries(path)
    except ValueError:
        return fallback
    rows = _dedupe_keep_latest(rows)
    rows = filter_entries(rows, provider=provider, task_type=task_type)
    s = compute_stats(rows)
    if s["decided"] == 0:
        return fallback
    pct = round(100 * s["accuracy"])
    earliest_date = (s["earliest_ts"] or "")[:10]
    return (
        f"{provider} {task_type} accuracy: "
        f"{s['true']}/{s['decided']} = {pct}% "
        f"(n={s['n']}, since {earliest_date})"
    )


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_log(args: argparse.Namespace) -> int:
    entry = {
        "ts": args.ts or _utcnow_iso(),
        "provider": args.provider,
        "task_type": args.task_type,
        "task_ref": args.task_ref,
        "verdict": args.verdict,
    }
    if args.evidence is not None:
        entry["evidence"] = args.evidence
    if args.prompt_hash is not None:
        entry["prompt_hash"] = args.prompt_hash
    if args.operator is not None:
        entry["operator"] = args.operator
    if args.session_id is not None:
        entry["session_id"] = args.session_id
    model = getattr(args, "model", None) or _resolve_model_hint(args.provider)
    entry["model"] = model
    # Lane-7: local_verification_accepted defaults to "unknown" when absent
    # so existing callers that don't pass --local-verification-accepted are
    # not broken. Explicitly pass "unknown" so the field is present on all
    # new rows, making forward-filled coverage checkable.
    lva = getattr(args, "local_verification_accepted", None) or "unknown"
    entry["local_verification_accepted"] = lva
    try:
        append_entry(entry, path=args.ledger)
    except ValueError as e:
        sys.stderr.write(f"log-failed: {e}\n")
        return 2
    sys.stdout.write(
        f"logged: {entry['provider']} {entry['task_type']} "
        f"{entry['task_ref']} -> {entry['verdict']}\n"
    )
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    try:
        rows = load_entries(args.ledger)
    except ValueError as e:
        sys.stderr.write(f"load-failed: {e}\n")
        return 2
    rows = _dedupe_keep_latest(rows)
    rows = filter_entries(
        rows,
        provider=args.provider,
        task_type=args.task_type,
        since=args.since,
    )
    s = compute_stats(rows)
    label_parts = []
    if args.provider:
        label_parts.append(args.provider)
    if args.task_type:
        label_parts.append(args.task_type)
    label = " ".join(label_parts) if label_parts else "all"
    if s["decided"] == 0:
        sys.stdout.write(
            f"{label}: n={s['n']} (no TRUE/FALSE rows yet)\n"
        )
        return 0
    pct = round(100 * s["accuracy"])
    sys.stdout.write(
        f"{label}: {s['true']}T/{s['false']}F = {pct}% "
        f"(n={s['n']}, partial={s['partial']}, "
        f"indeterminate={s['indeterminate']})\n"
    )
    return 0


def cmd_cite(args: argparse.Namespace) -> int:
    if not args.provider or not args.task_type:
        sys.stderr.write("cite requires --provider and --task-type\n")
        return 2
    line = cite_calibration(
        args.provider,
        args.task_type,
        path=args.ledger,
        fallback=f"{args.provider} {args.task_type} accuracy: (no data)",
    )
    sys.stdout.write(line + "\n")
    return 0


def cmd_route(args: argparse.Namespace) -> int:
    status = routing_status(
        args.provider,
        args.task_type,
        path=args.ledger,
        min_decided=args.min_decided,
        min_precision=args.min_precision,
        seed_path=args.seed,
        min_samples=args.min_samples,
    )
    if args.json:
        sys.stdout.write(json.dumps(status, sort_keys=True) + "\n")
    else:
        accuracy = status.get("accuracy")
        accuracy_label = "n/a" if accuracy is None else f"{round(100 * accuracy)}%"
        lane = "primary" if status["primary_allowed"] else "advisory-only"
        sample_count = status.get("sample_count")
        sample_label = (
            "n/a" if sample_count is None else str(sample_count)
        )
        sys.stdout.write(
            f"{status['provider']} {status['task_type']}: {lane} "
            f"({status['reason']}; decided={status.get('decided', 0)}, "
            f"accuracy={accuracy_label}, "
            f"sample_count={sample_label}, "
            f"min_decided={status.get('min_decided', ROUTING_MIN_DECIDED)}, "
            f"min_samples={status.get('min_samples', ROUTING_MIN_SAMPLES)}, "
            f"min_precision={round(100 * status.get('min_precision', ROUTING_MIN_PRECISION))}%)\n"
        )
    return 0 if status["primary_allowed"] else 1


def cmd_provider_assist(args: argparse.Namespace) -> int:
    try:
        summary = provider_assist_summary(
            ledger_path=args.ledger,
            budget_path=args.budget,
        )
    except ValueError as e:
        sys.stderr.write(f"provider-assist-failed: {e}\n")
        return 2
    if args.json:
        sys.stdout.write(json.dumps(summary, sort_keys=True) + "\n")
        return 0
    sys.stdout.write("Provider-assist calibration summary\n")
    sys.stdout.write(
        f"ledger: {summary['source_of_truth']['ledger']}\n"
    )
    sys.stdout.write(
        f"budget: {summary['source_of_truth']['budget']}\n"
    )
    for provider, row in summary["providers"].items():
        budget = row["active_budget"]
        stats = row["stats_all_tasks"]
        accuracy = stats.get("accuracy")
        acc_label = "n/a" if accuracy is None else f"{round(100 * accuracy)}%"
        sys.stdout.write(
            f"- {provider}: {budget.get('max_calls')} calls/"
            f"{budget.get('window_minutes')}m, "
            f"{budget.get('max_tokens')} tokens/"
            f"{budget.get('window_minutes')}m, "
            f"soft_ratio={budget.get('soft_ratio')}; "
            f"all-task decided={stats.get('decided')} accuracy={acc_label}; "
            f"mode={row['paid_tier_mode']}; role="
            f"{row['profile']['recommended_loop_role']}\n"
        )
        sys.stdout.write(f"  best_use: {row['profile']['best_use']}\n")
        sys.stdout.write(
            f"  failures: {row['profile']['known_failures']}\n"
        )
    sys.stdout.write("hard_guards: " + ", ".join(summary["hard_guards"]) + "\n")
    sys.stdout.write(summary["legacy_budget_note"] + "\n")
    return 0


def cmd_recent(args: argparse.Namespace) -> int:
    try:
        rows = load_entries(args.ledger)
    except ValueError as e:
        sys.stderr.write(f"load-failed: {e}\n")
        return 2
    n = args.n if args.n is not None else 10
    tail = rows[-n:] if n > 0 else []
    for e in tail:
        sys.stdout.write(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        rows = load_entries(args.ledger)
    except ValueError as e:
        sys.stderr.write(f"validate-failed: {e}\n")
        return 2
    errs = validate_all(rows)
    if errs:
        for msg in errs:
            sys.stderr.write(f"INVALID: {msg}\n")
        sys.stderr.write(f"{len(errs)} invalid row(s) of {len(rows)}\n")
        return 1
    sys.stdout.write(f"OK: {len(rows)} row(s) valid\n")
    return 0


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llm-calibration-log.py",
        description=(
            "Append-only JSONL ledger of LLM-call outcomes. Replaces the "
            "hand-maintained calibration ledger in docs/LLM_DELEGATION_MATRIX.md."
        ),
    )
    p.add_argument(
        "--ledger",
        type=Path,
        default=None,
        help=f"Ledger path (default: {LEDGER_PATH}).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # log
    p_log = sub.add_parser("log", help="Append a new outcome event.")
    p_log.add_argument("provider", choices=sorted(VALID_PROVIDERS))
    p_log.add_argument("task_type", choices=sorted(VALID_TASK_TYPES))
    p_log.add_argument("task_ref")
    p_log.add_argument("verdict", choices=sorted(VALID_VERDICTS))
    p_log.add_argument("--evidence", default=None)
    p_log.add_argument("--prompt-hash", default=None)
    p_log.add_argument("--operator", default=None)
    p_log.add_argument("--session-id", default=None)
    p_log.add_argument(
        "--model",
        default=None,
        help=(
            "Concrete provider model/version for this observation. Defaults "
            "to provider-specific env/defaults so Kimi/MiniMax upgrades are "
            "tracked in calibration."
        ),
    )
    p_log.add_argument("--ts", default=None,
                       help="ISO-8601 override (default: utcnow).")
    p_log.add_argument(
        "--local-verification-accepted",
        dest="local_verification_accepted",
        choices=sorted(VALID_LOCAL_VERIFICATION_VALUES),
        default="unknown",
        help=(
            "Whether local verification (rg / source-ref / test / harness) "
            "accepted the provider output. Tri-state: true | false | unknown "
            "(default unknown; existing callers unaffected)."
        ),
    )
    p_log.set_defaults(func=cmd_log)

    # stats
    p_stats = sub.add_parser("stats", help="Aggregate accuracy.")
    p_stats.add_argument("--provider", choices=sorted(VALID_PROVIDERS),
                         default=None)
    p_stats.add_argument("--task-type", choices=sorted(VALID_TASK_TYPES),
                         default=None)
    p_stats.add_argument("--since", default=None,
                         help="YYYY-MM-DD or ISO-8601 cutoff (inclusive).")
    p_stats.set_defaults(func=cmd_stats)

    # cite
    p_cite = sub.add_parser(
        "cite",
        help="Print 1-line calibration string for agent prompts.",
    )
    p_cite.add_argument("--provider", choices=sorted(VALID_PROVIDERS),
                        required=True)
    p_cite.add_argument("--task-type", choices=sorted(VALID_TASK_TYPES),
                        required=True)
    p_cite.set_defaults(func=cmd_cite)

    # route
    p_route = sub.add_parser(
        "route",
        help=(
            "Evaluate whether provider × task-type has enough verified "
            "precision for primary routing. Exits 1 for advisory-only."
        ),
    )
    p_route.add_argument("--provider", choices=sorted(VALID_PROVIDERS),
                         required=True)
    p_route.add_argument("--task-type", choices=sorted(VALID_TASK_TYPES),
                         required=True)
    p_route.add_argument("--min-decided", type=int,
                         default=ROUTING_MIN_DECIDED)
    p_route.add_argument("--min-precision", type=float,
                         default=ROUTING_MIN_PRECISION)
    p_route.add_argument(
        "--min-samples",
        type=int,
        default=ROUTING_MIN_SAMPLES,
        help=(
            "Minimum sample_count required in the seed row before "
            "promotion routing is permitted. A row whose sample_count "
            "is below this threshold (or whose precision_pct is the "
            "literal 'insufficient-data') causes the route command to "
            "refuse with reason 'cannot-route: insufficient-data'."
        ),
    )
    p_route.add_argument(
        "--seed",
        type=Path,
        default=None,
        help=(
            f"Override path to the seed calibration JSON (default: "
            f"{SEED_PATH}). When the seed file is absent, routing falls "
            "back to the JSONL ledger only (legacy behaviour)."
        ),
    )
    p_route.add_argument("--json", action="store_true",
                         help="Emit machine-readable routing status.")
    p_route.set_defaults(func=cmd_route)

    # provider-assist
    p_pa = sub.add_parser(
        "provider-assist",
        help=(
            "Summarize Kimi/Minimax provider-assist roles from the live "
            "calibration ledger plus active budget config."
        ),
    )
    p_pa.add_argument(
        "--budget",
        type=Path,
        default=None,
        help=f"Budget config path (default: {BUDGET_PATH}).",
    )
    p_pa.add_argument("--json", action="store_true",
                      help="Emit machine-readable summary.")
    p_pa.set_defaults(func=cmd_provider_assist)

    # recent
    p_recent = sub.add_parser("recent", help="Print last N entries.")
    p_recent.add_argument("n", nargs="?", type=int, default=10)
    p_recent.set_defaults(func=cmd_recent)

    # validate
    p_val = sub.add_parser("validate", help="Schema-check the JSONL ledger.")
    p_val.set_defaults(func=cmd_validate)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
