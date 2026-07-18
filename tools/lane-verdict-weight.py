#!/usr/bin/env python3
"""Track-record verdict weighting (advisory) for the lane verdict bus.

This is an ADVISORY sidecar. It never mutates the bus, never rewrites
``aggregated.json``, and never auto-flips a verdict. It reads the existing
per-lane records (via ``tools/lane-verdict-bus.py``'s own ``read_records`` /
``filter_records``) and, for each candidate, computes a *weighted* verdict
tally where each lane's vote is scaled by that lane's per-(model, task_type)
track record. The weight source is the SAME per-(provider, task_type)
calibration store consulted by routing (``tools/llm-calibration-log.py``'s
seed rows) - this store is the confusion matrix; here it is finally fed back.

Design guarantees (all load-bearing):

* COLD-START BYTE-IDENTITY. A record carries a weight only when BOTH
  ``metadata.model`` and ``metadata.task_type`` are present AND they join to a
  calibrated seed row with enough samples and a numeric precision. When no
  record on a candidate carries such a join key (the current production state,
  since the emitter did not write model/task_type until this build), every
  weight is exactly ``1.0`` and the weighted tally is the plain ``Counter``
  majority - identical to ``lane-verdict-bus.py aggregate``'s ``by_verdict``.
  A unit test locks this against the captured baseline.

* ADVISORY-FIRST behind a NAMED env flag, DEFAULT OFF.
  ``AUDITOOOR_VERDICT_WEIGHT_STRICT`` unset => ``effective_verdict`` is the
  naive majority (weighting is reported but non-authoritative: WARN-only).
  Set => ``effective_verdict`` is the weighted majority. Because cold-start
  makes the two equal, flag-unset is byte-identical to today whenever there is
  no calibration join anyway.

* ESCALATE, never silent-majority. When the weighted majority disagrees with
  the naive majority AND the disagreement is *credible* (the minority side
  that wins under weighting is carried by at least one calibrated lane whose
  precision beats the calibrated lanes on the naive-majority side), the tool
  emits ``escalate: true`` with a human-readable reason. ESCALATE is a signal
  for the operator / downstream R71 consult; it does not change any gate.

* ADDITIVE-ONLY. No field on any bus record is renamed, reordered, or removed.
  This tool only READS ``metadata.model`` / ``metadata.task_type`` (both
  already permitted by the bus's free-form ``metadata`` object) and writes its
  own separate advisory JSON to stdout / an optional sidecar path. It does not
  write ``aggregated.json``.

CLI::

  python3 tools/lane-verdict-weight.py weigh --workspace <ws> \
      [--candidate-id <id>] [--attack-class <class>] [--pretty]

Exit code is always 0 for a successful advisory computation (this is not a
blocking gate); malformed input yields exit 2 with an error payload.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

TOOLS_DIR = Path(__file__).resolve().parent

# The advisory-strict flag. DEFAULT OFF. When unset, the effective verdict is
# the naive majority (weighting is reported but non-authoritative).
WEIGHT_STRICT_ENV = "AUDITOOOR_VERDICT_WEIGHT_STRICT"

WEIGH_SCHEMA_VERSION = "auditooor.lane_verdict_weight.v1"
ERROR_SCHEMA_VERSION = "auditooor.lane_verdict_weight.error.v1"

# Metadata keys we (read-only) consult on each bus record. Both are optional
# and already permitted by the bus's free-form metadata object.
MODEL_KEY = "model"
TASK_TYPE_KEY = "task_type"

# The minimum calibrated samples before a lane's precision is allowed to move
# a weight away from the neutral 1.0. Mirrors the routing sample floor so a
# lane that has not been measured cannot down- or up-weight anything.
DEFAULT_MIN_SAMPLES = 20


class WeightError(RuntimeError):
    """Raised for user-facing errors in the advisory computation."""


def _load_sibling_module(filename: str, mod_name: str):
    """Import a hyphenated sibling tool by path (they are not importable by name)."""
    path = TOOLS_DIR / filename
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise WeightError(f"cannot load module {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


# Reuse - do NOT fork - the bus reader and the calibration weight store.
_bus = _load_sibling_module("lane-verdict-bus.py", "_lvw_lane_verdict_bus")
_calib = _load_sibling_module("llm-calibration-log.py", "_lvw_llm_calibration_log")


def _reverse_default_models() -> dict[str, str]:
    """model-label -> provider-key, from the calibration store's DEFAULT_MODELS.

    ``DEFAULT_MODELS`` maps provider->label (e.g. ``kimi``->``kimi-for-coding``).
    Emitters write the model LABEL, so join on the reverse map. Unknown labels
    fall back to cold-start (weight 1.0), never crash. ``codex``'s label is the
    sentinel ``unknown`` in the store; we drop that so an emitted literal
    ``unknown`` model never spuriously joins to a provider.
    """
    out: dict[str, str] = {}
    for provider, label in getattr(_calib, "DEFAULT_MODELS", {}).items():
        if not isinstance(label, str) or not label or label == "unknown":
            continue
        out.setdefault(label, provider)
    return out


def resolve_provider(model_label: Optional[str]) -> Optional[str]:
    """Map an emitted model label to a calibration provider key, or None.

    Accepts the canonical label (``kimi-for-coding``) or the bare provider key
    itself (``kimi``); anything unrecognised returns None => cold-start.
    """
    if not model_label or not isinstance(model_label, str):
        return None
    label = model_label.strip()
    if not label:
        return None
    reverse = _reverse_default_models()
    if label in reverse:
        return reverse[label]
    valid = getattr(_calib, "VALID_PROVIDERS", frozenset())
    lowered = label.lower()
    if lowered in valid:
        return lowered
    # Best-effort prefix match on the label (e.g. "MiniMax-M2.7-preview").
    for known_label, provider in reverse.items():
        if label.startswith(known_label):
            return provider
    return None


def lane_weight(
    model_label: Optional[str],
    task_type: Optional[str],
    *,
    seed: Optional[dict] = None,
    seed_path: Optional[Path] = None,
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> tuple[float, dict[str, Any]]:
    """Return ``(weight, provenance)`` for one lane's vote.

    ``weight`` is ``precision_pct / 100`` for a calibrated (provider,
    task_type) lane that clears ``min_samples`` and has a numeric precision;
    otherwise it is exactly ``1.0`` (neutral / cold-start). The provenance dict
    explains the decision and is surfaced in the advisory output. This function
    NEVER raises on unknown vocab - it degrades to neutral.
    """
    prov: dict[str, Any] = {
        "model": model_label,
        "task_type": task_type,
        "provider": None,
        "calibrated": False,
        "sample_count": 0,
        "precision_pct": None,
        "weight_reason": "cold-start: no (model,task_type) calibration join",
    }
    provider = resolve_provider(model_label)
    prov["provider"] = provider
    if provider is None or not task_type:
        return 1.0, prov
    valid_tasks = getattr(_calib, "VALID_TASK_TYPES", frozenset())
    if task_type not in valid_tasks:
        prov["weight_reason"] = "cold-start: task_type not in calibration allowlist"
        return 1.0, prov
    try:
        row = _calib.lookup_seed_row(provider, task_type, seed=seed, seed_path=seed_path)
    except Exception:  # noqa: BLE001 - advisory: never let a store read crash us.
        prov["weight_reason"] = "cold-start: calibration store unreadable"
        return 1.0, prov
    if row is None:
        prov["weight_reason"] = "cold-start: no seed row for (provider,task_type)"
        return 1.0, prov
    sample_count = int(row.get("sample_count", 0) or 0)
    precision_pct = row.get("precision_pct")
    prov["sample_count"] = sample_count
    prov["precision_pct"] = precision_pct
    if sample_count < min_samples:
        prov["weight_reason"] = (
            f"cold-start: sample_count {sample_count} < min_samples {min_samples}"
        )
        return 1.0, prov
    try:
        pct = float(precision_pct)
    except (TypeError, ValueError):
        prov["weight_reason"] = "cold-start: precision not numeric (insufficient-data)"
        return 1.0, prov
    weight = max(0.0, pct / 100.0)
    prov["calibrated"] = True
    prov["weight_reason"] = f"calibrated: precision {pct}% over {sample_count} samples"
    return weight, prov


def _record_model(record: Mapping[str, Any]) -> Optional[str]:
    md = record.get("metadata")
    if isinstance(md, Mapping):
        value = md.get(MODEL_KEY)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _record_task_type(record: Mapping[str, Any]) -> Optional[str]:
    md = record.get("metadata")
    if isinstance(md, Mapping):
        value = md.get(TASK_TYPE_KEY)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _naive_majority(counts: Mapping[str, float]) -> Optional[str]:
    """Deterministic argmax with a stable tie-break (verdict name asc).

    Matches the semantics of ``Counter.most_common`` reduced to a single winner
    under the same deterministic ordering the bus aggregate uses (sorted keys).
    """
    if not counts:
        return None
    best_key: Optional[str] = None
    best_val = float("-inf")
    for key in sorted(counts):
        val = counts[key]
        if val > best_val:
            best_val = val
            best_key = key
    return best_key


def weigh_candidate(
    records: Iterable[Mapping[str, Any]],
    *,
    seed: Optional[dict] = None,
    seed_path: Optional[Path] = None,
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> dict[str, Any]:
    """Compute the naive and weighted verdict tallies for one candidate's records.

    Returns a dict with ``naive_by_verdict`` (a plain Counter, byte-identical to
    the bus aggregate for the same records), ``weighted_by_verdict``, both
    majorities, an ``escalate`` flag + reason, and per-lane provenance.
    """
    rows = list(records)
    naive: Counter[str] = Counter()
    weighted: dict[str, float] = defaultdict(float)
    # Track, per verdict, the best calibrated precision backing it (for the
    # credible-disagreement test). None means "no calibrated lane on this side".
    best_calibrated_precision: dict[str, Optional[float]] = defaultdict(lambda: None)
    lanes: list[dict[str, Any]] = []
    for record in rows:
        verdict = str(record.get("verdict") or "UNKNOWN")
        naive[verdict] += 1
        model_label = _record_model(record)
        task_type = _record_task_type(record)
        weight, prov = lane_weight(
            model_label,
            task_type,
            seed=seed,
            seed_path=seed_path,
            min_samples=min_samples,
        )
        weighted[verdict] += weight
        if prov["calibrated"]:
            pct = float(prov["precision_pct"])
            cur = best_calibrated_precision[verdict]
            if cur is None or pct > cur:
                best_calibrated_precision[verdict] = pct
        lanes.append({
            "lane_id": record.get("lane_id"),
            "verdict": verdict,
            "weight": round(weight, 6),
            **prov,
        })

    naive_majority = _naive_majority({k: float(v) for k, v in naive.items()})
    weighted_majority = _naive_majority(dict(weighted))

    escalate = False
    escalate_reason = ""
    if (
        naive_majority is not None
        and weighted_majority is not None
        and weighted_majority != naive_majority
    ):
        winner_prec = best_calibrated_precision.get(weighted_majority)
        loser_prec = best_calibrated_precision.get(naive_majority)
        # Credible only when a calibrated lane actually carries the flipped
        # (weighted-winning) side and it out-precisions the calibrated support
        # (if any) on the naive-majority side. A flip driven purely by uncalibrated
        # neutral votes cannot happen (weights would be 1.0 == counts), so any
        # real flip is calibration-driven; we still require the winning side to
        # have a calibrated backer to avoid escalating on pathological weights.
        if winner_prec is not None and (loser_prec is None or winner_prec > loser_prec):
            escalate = True
            escalate_reason = (
                f"weighted majority {weighted_majority!r} (calibrated precision "
                f"{winner_prec}%) disagrees with naive majority {naive_majority!r}"
                + (
                    f" (calibrated precision {loser_prec}%)"
                    if loser_prec is not None
                    else " (no calibrated backing)"
                )
                + "; operator review advised (advisory-only, no gate changed)"
            )

    strict = bool(os.environ.get(WEIGHT_STRICT_ENV))
    effective = weighted_majority if strict else naive_majority

    return {
        "record_count": len(rows),
        "naive_by_verdict": dict(sorted(naive.items())),
        "naive_majority": naive_majority,
        "weighted_by_verdict": {k: round(v, 6) for k, v in sorted(weighted.items())},
        "weighted_majority": weighted_majority,
        "weight_strict_env_set": strict,
        "effective_verdict": effective,
        "escalate": escalate,
        "escalate_reason": escalate_reason,
        "lanes": lanes,
    }


def weigh(
    workspace: Path,
    *,
    candidate_id: Optional[str] = None,
    attack_class: Optional[str] = None,
    seed_path: Optional[Path] = None,
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> dict[str, Any]:
    """Read the bus and compute weighted advisory verdicts per candidate."""
    all_records = _bus.read_records(workspace)
    matched = _bus.filter_records(
        all_records,
        candidate_id=candidate_id,
        attack_class=attack_class,
    )
    try:
        seed = _calib.load_seed(seed_path)
    except Exception:  # noqa: BLE001 - advisory: a bad seed degrades to cold-start.
        seed = None

    by_candidate: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for record in matched:
        by_candidate[str(record.get("candidate_id") or "unknown")].append(record)

    candidates: dict[str, Any] = {}
    escalations: list[str] = []
    for cand in sorted(by_candidate):
        result = weigh_candidate(
            by_candidate[cand],
            seed=seed,
            seed_path=seed_path,
            min_samples=min_samples,
        )
        candidates[cand] = result
        if result["escalate"]:
            escalations.append(cand)

    return {
        "schema_version": WEIGH_SCHEMA_VERSION,
        "classification": "weighed",
        "advisory_only": True,
        "weight_strict_env": WEIGHT_STRICT_ENV,
        "weight_strict_env_set": bool(os.environ.get(WEIGHT_STRICT_ENV)),
        "workspace": str(workspace.expanduser()),
        "bus_empty": len(all_records) == 0,
        "min_samples": int(min_samples),
        "query": {
            "candidate_id": candidate_id,
            "attack_class": attack_class,
        },
        "candidate_count": len(candidates),
        "escalate_candidates": escalations,
        "candidates": candidates,
    }


def _emit(payload: Mapping[str, Any], *, pretty: bool = False) -> None:
    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(json.dumps(payload, sort_keys=True))


def cmd_weigh(args: argparse.Namespace) -> int:
    payload = weigh(
        Path(args.workspace),
        candidate_id=args.candidate_id,
        attack_class=args.attack_class,
        seed_path=Path(args.seed_path) if args.seed_path else None,
        min_samples=args.min_samples,
    )
    _emit(payload, pretty=args.pretty)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lane-verdict-weight",
        description=(
            "Advisory track-record weighting of lane verdict bus votes. "
            "Never mutates the bus; cold-start == naive majority."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    pw = sub.add_parser("weigh", help="Compute weighted advisory verdicts per candidate.")
    pw.add_argument("--workspace", required=True, help="Workspace root.")
    pw.add_argument("--candidate-id")
    pw.add_argument("--attack-class")
    pw.add_argument("--seed-path", help="Override the calibration seed JSON path (tests).")
    pw.add_argument(
        "--min-samples",
        type=int,
        default=DEFAULT_MIN_SAMPLES,
        help="Minimum calibrated samples before a lane's precision moves its weight.",
    )
    pw.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    pw.set_defaults(func=cmd_weigh)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except WeightError as exc:
        _emit(
            {
                "schema_version": ERROR_SCHEMA_VERSION,
                "classification": "error",
                "error": str(exc),
            },
            pretty=getattr(args, "pretty", False),
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
