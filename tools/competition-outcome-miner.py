#!/usr/bin/env python3
"""Mine closed-competition outcomes into typed capability-data records.

Reads a structured seed table (hard-coded or from --seed-file) and emits
one JSONL row per named anchor.  Each row carries:

  engagement         - competition slug (revert_stableswap / reserve_governor /
                       polymarket)
  finding_id         - competition finding number (string)
  outcome_class      - one of the I5 vocabulary:
                         confirmed_high | confirmed_medium | acknowledged_low |
                         demoted_info | duplicate_cluster | blocked_by_economics |
                         intended_actor_mismatch
  attack_class       - canonical attack-class tag
  triager_lesson     - prose: what would have made our version survive, or why
                       drop pre-PoC
  kill_rubric_question - gate question implied by the lesson (empty string when
                         the lesson does not imply a decision gate)
  prose_to_lesson_compatible_text - concatenation of fields that
                       prose-to-lesson-compiler.py can consume directly to fire
                       the matching predicate(s)

The tool is deterministic and offline-only. It never scrapes live URLs.
Output goes to reports/competition_outcome_mining.jsonl by default.

Usage:
  python3 tools/competition-outcome-miner.py [--out PATH] [--seed-file PATH]
  python3 tools/competition-outcome-miner.py --dry-run
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.competition_outcome_mining.v1"
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.0.0"

OUTCOME_CLASSES = frozenset(
    {
        "confirmed_high",
        "confirmed_medium",
        "acknowledged_low",
        "demoted_info",
        "duplicate_cluster",
        "blocked_by_economics",
        "intended_actor_mismatch",
    }
)

# ---------------------------------------------------------------------------
# Canonical seed data (I5 spec anchors - encoded offline; no live scraping)
# ---------------------------------------------------------------------------
# Each entry is the structured representation of one named anchor from the I5
# spec section of docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md.
# Add new anchors here; the emitter is fully deterministic from this table.
# ---------------------------------------------------------------------------

SEED_ANCHORS: list[dict[str, Any]] = [
    # ---- Revert StableSwap Hooks ----
    {
        "engagement": "revert_stableswap",
        "finding_id": "15",
        "title": "zapIn passes zero slippage to internal addLiquidity",
        "outcome_class": "confirmed_medium",
        "attack_class": "slippage-zero-inner-boundary",
        "triager_lesson": (
            "An initial MEV/OOS objection was beaten because the underlying protocol bug "
            "exists without MEV: zapIn hard-codes zero minAmounts and zero minShares for "
            "its internal addLiquidity call, compounding slippage loss even without a "
            "sandwich. The lesson: a frontrunning/MEV objection can be overridden when "
            "the protocol bug produces loss without any external MEV actor. Build the "
            "no-MEV loss PoC first; address the amplification claim separately."
        ),
        "kill_rubric_question": (
            "Does the loss require a sandwich/MEV actor, or does the protocol's own "
            "zero-inner-slippage boundary produce loss independently of any frontrunner?"
        ),
    },
    {
        "engagement": "revert_stableswap",
        "finding_id": "102",
        "title": "exact-output fee asymmetry",
        "outcome_class": "confirmed_medium",
        "attack_class": "fee-asymmetry-additive-vs-gross-up",
        "triager_lesson": (
            "Confirmed Medium after the triager reversed an initial 'documented behavior' "
            "rejection. Documentation of mechanics is not documentation of the unintended "
            "economic effect: additive fees on an exact-output path are cheaper than the "
            "inverse gross-up math, creating systematic underpayment. The lesson: require "
            "a correct-math control that compares the implemented additive fees against "
            "the inverse gross-up formula. If the two diverge, 'documented mechanics' "
            "does not defeat the finding."
        ),
        "kill_rubric_question": (
            "Does the existing documentation describe the unintended economic effect "
            "(not merely the mechanics), or does it only describe what the code does "
            "without addressing whether the math is correct?"
        ),
    },
    {
        "engagement": "revert_stableswap",
        "finding_id": "8",
        "title": "low-decimal exact-output zero-input drain",
        "outcome_class": "confirmed_medium",
        "attack_class": "scale-descaling-low-decimal-round-down",
        "triager_lesson": (
            "Confirmed Medium. Exact-output paths must round required input obligations "
            "upward; a nonzero scaled obligation must not descale to zero raw token units "
            "for low-decimal tokens. When scaled math rounds down to zero tokens the "
            "caller obtains output for no cost. Mine as a low-decimal / scale-descaling "
            "detector: flag exact-output paths where the input amount computation can "
            "yield zero for nonzero output."
        ),
        "kill_rubric_question": (
            "On this exact-output path, can the required input round down to zero raw "
            "token units while the output remains nonzero for any token with low "
            "decimals (e.g. USDC=6, WBTC=8)?"
        ),
    },
    {
        "engagement": "revert_stableswap",
        "finding_id": "29",
        "title": "native ETH removeLiquidity reentrancy",
        "outcome_class": "confirmed_high",
        "attack_class": "reentrancy-native-transfer-stale-reserve",
        "triager_lesson": (
            "Confirmed High after challenge. Reentrancy coverage that only re-enters "
            "hook functions misses direct PoolManager.swap calls that are possible while "
            "the manager is already unlocked. The unlock/lock re-entrancy window is "
            "opened by the native ETH transfer in removeLiquidity before pool reserves "
            "are updated, allowing stale-reserve swap pricing. Mine as CEI-before-native-"
            "transfer plus stale-reserve-swap: flag any path where native ETH is "
            "transferred before pool reserves (balances/reserves/liquidity) are updated "
            "and a re-entrant swap is possible."
        ),
        "kill_rubric_question": (
            "Is native ETH transferred to an external address before pool reserve state "
            "is finalized, and can a re-entrant swap execute against the stale reserves "
            "while the manager lock is still open?"
        ),
    },
    {
        "engagement": "revert_stableswap",
        "finding_id": "991",
        "title": "sqrtPriceLimitX96 ignored on direct v4 hook path",
        "outcome_class": "demoted_info",
        "attack_class": "missing-slippage-hook-path",
        "triager_lesson": (
            "Confirmed Informational (severity-capped). Missing slippage protection on "
            "a direct v4 hook path is a valid structural observation but is severity-"
            "capped when the impact is generic user slippage rather than objective "
            "reserve theft. The lesson: a missing-slippage finding requires a concrete "
            "harm path (sandwich profiting from broken internal boundaries, or "
            "systematic underpayment) to escape the generic-slippage severity ceiling."
        ),
        "kill_rubric_question": (
            "Is there a concrete harm path beyond generic user slippage (e.g. systematic "
            "underpayment, broken internal accounting, or reserve theft), or is the "
            "impact bounded to user-experienced price variance?"
        ),
    },
    {
        "engagement": "revert_stableswap",
        "finding_id": "995",
        "title": "stale PoolManager sync native settlement",
        "outcome_class": "acknowledged_low",
        "attack_class": "same-tx-composition-dos",
        "triager_lesson": (
            "Confirmed Low. Same-transaction composition DoS is an inconvenience, not a "
            "durable freeze or unavoidable operation failure. The lesson: DoS findings "
            "require either permanent/durable freezing or unavoidable failure on a "
            "core operation to escape the Low tier. Same-block composition issues that "
            "resolve the next transaction are bounded to inconvenience."
        ),
        "kill_rubric_question": (
            "Does this DoS path produce permanent or durable freezing of funds or "
            "unavoidable repeated failure on a core operation, or is it bounded to "
            "inconvenience within a single transaction or block?"
        ),
    },
    # ---- Reserve Governor ----
    {
        "engagement": "reserve_governor",
        "finding_id": "69",
        "title": "ERC4626 first-depositor inflation attack",
        "outcome_class": "confirmed_medium",
        "attack_class": "erc4626-first-depositor-inflation",
        "triager_lesson": (
            "Confirmed Medium. Victim deposit loss can be real even when OpenZeppelin "
            "virtual shares make the attack unprofitable for the attacker. The "
            "unprofitable cap blocks High/Critical profit-framing but does not nullify "
            "the victim loss. The lesson: separate the victim-harm claim from the "
            "attacker-profit claim. File victim-loss at Medium when attacker profit is "
            "capped to near-zero by virtual shares or other mitigations, rather than "
            "walking back the entire finding."
        ),
        "kill_rubric_question": (
            "Does the OZ virtual-share mechanism (or equivalent) make the attacker "
            "unprofitable, and if so, can victim-loss be independently substantiated "
            "for a Medium claim without asserting attacker profit?"
        ),
    },
    {
        "engagement": "reserve_governor",
        "finding_id": "39",
        "title": "public poke reward rounding - zero handout time advancement",
        "outcome_class": "confirmed_medium",
        "attack_class": "zero-handout-time-advancement-low-decimal-reward",
        "triager_lesson": (
            "Confirmed Medium. Public accrual functions that advance time on zero "
            "rounded handout let late entrants redirect low-decimal reward streams. "
            "The lesson: any public-callable accrual function that can advance the "
            "internal time pointer without distributing rewards (because the per-epoch "
            "amount rounds to zero) is a candidate medium-severity manipulation for "
            "low-decimal reward tokens. Mine as zero-handout time advancement."
        ),
        "kill_rubric_question": (
            "Can this public accrual function advance the time pointer while emitting "
            "zero reward tokens due to low-decimal rounding, and does that manipulation "
            "redirect future accruals toward the caller or away from existing holders?"
        ),
    },
    {
        "engagement": "reserve_governor",
        "finding_id": "9",
        "title": "veto threshold denominator mismatch",
        "outcome_class": "confirmed_medium",
        "attack_class": "governance-numerator-denominator-pool-mismatch",
        "triager_lesson": (
            "Confirmed Medium. Governance numerator/denominator pool mismatch is a real "
            "bypass when the threshold uses total supply but votes come only from an "
            "opt-delegated subset. The proof must execute the proposal end-to-end, not "
            "just show arithmetic. The lesson: governance-bypass findings require an "
            "end-to-end PoC that actually enqueues and executes a proposal through the "
            "threshold check; showing math alone is insufficient."
        ),
        "kill_rubric_question": (
            "Does the finding's PoC execute a proposal through the full governance "
            "threshold check (not just arithmetic demonstration), and does it use only "
            "the opt-delegated subset of votes against a total-supply denominator?"
        ),
    },
    # ---- Polymarket ----
    {
        "engagement": "polymarket",
        "finding_id": "198",
        "title": "UmaCtfAdapter priceDisputed reward theft during flag",
        "outcome_class": "blocked_by_economics",
        "attack_class": "reward-theft-admin-gate-economic-infeasibility",
        "triager_lesson": (
            "Team response: Polymarket is the only intended creator so this is an "
            "intended_actor_mismatch, typical rewards are $2-5 per market, admin pause "
            "is part of the attack scenario (admin_or_team_action_prerequisite), and "
            "UMA bonds start around $750. The attack lacks attacker profit because the "
            "mandatory bond cost exceeds the extractable reward value: no attacker "
            "profit is achievable when bonds cost $750 and rewards are $2-5. "
            "The lesson: economic viability and actor ownership are first-class scope "
            "gates that must be evaluated before any PoC work. When the attacker "
            "net-revenue (reward captured) is less than the mandatory bond cost and the "
            "prerequisite requires an admin action, drop pre-PoC. Add both "
            "blocked_by_economics and intended_actor_mismatch outcome classes to the "
            "kill-rubric checklist."
        ),
        "kill_rubric_question": (
            "Is the attacker's net expected revenue (captured reward minus mandatory "
            "bond/gas/capital costs) positive under realistic market conditions, and is "
            "the trigger actor non-privileged (no admin pause or team action required)?"
        ),
    },
]


def _stable_row_id(engagement: str, finding_id: str) -> str:
    digest = hashlib.sha256(f"{engagement}:{finding_id}".encode()).hexdigest()
    return f"com-outcome-{digest[:12]}"


def _prose_to_lesson_text(row: dict[str, Any]) -> str:
    """Build a text string that prose-to-lesson-compiler.py can consume.

    The text concatenates the triager_lesson and relevant framing so the
    compiler can fire its predicate signals (economic_viability_missing,
    intended_actor_mismatch, admin_or_team_action_prerequisite, etc.).
    """
    parts = [
        f"Engagement: {row['engagement']} finding #{row['finding_id']}: {row['title']}",
        f"Outcome: {row['outcome_class']}",
        row["triager_lesson"],
    ]
    if row.get("kill_rubric_question"):
        parts.append(f"Kill-rubric question: {row['kill_rubric_question']}")
    return "\n\n".join(parts)


def emit_records(
    seeds: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    """Deterministically emit one outcome record per seed anchor.

    Args:
        seeds: override the built-in SEED_ANCHORS for testing.
        generated_at: ISO-8601 timestamp string; defaults to utc-now.

    Returns:
        List of dicts, one per anchor, ready for JSONL serialization.
    """
    ts = generated_at or dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    anchors = seeds if seeds is not None else SEED_ANCHORS
    records: list[dict[str, Any]] = []
    for anchor in anchors:
        if anchor["outcome_class"] not in OUTCOME_CLASSES:
            raise ValueError(
                f"Unknown outcome_class {anchor['outcome_class']!r} for "
                f"{anchor['engagement']}#{anchor['finding_id']}. "
                f"Valid: {sorted(OUTCOME_CLASSES)}"
            )
        row: dict[str, Any] = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "tool_version": TOOL_VERSION,
            "row_id": _stable_row_id(anchor["engagement"], anchor["finding_id"]),
            "engagement": anchor["engagement"],
            "finding_id": str(anchor["finding_id"]),
            "title": anchor.get("title", ""),
            "outcome_class": anchor["outcome_class"],
            "attack_class": anchor["attack_class"],
            "triager_lesson": anchor["triager_lesson"],
            "kill_rubric_question": anchor.get("kill_rubric_question", ""),
            "prose_to_lesson_compatible_text": _prose_to_lesson_text(anchor),
            "generated_at_utc": ts,
            "offline_only": True,
            "network_access": False,
        }
        records.append(row)
    return records


def write_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit closed-competition outcome records as JSONL."
    )
    repo_root = Path(__file__).resolve().parents[1]
    default_out = repo_root / "reports" / "competition_outcome_mining.jsonl"
    parser.add_argument(
        "--out",
        default=str(default_out),
        help=f"Output JSONL path (default: {default_out})",
    )
    parser.add_argument(
        "--seed-file",
        default=None,
        help="Optional JSON file with a list of seed anchor dicts (overrides built-in seeds).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print records to stdout instead of writing to disk.",
    )
    args = parser.parse_args(argv)

    seeds: list[dict[str, Any]] | None = None
    if args.seed_file:
        seed_path = Path(args.seed_file)
        try:
            seeds = json.loads(seed_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: could not load seed file {args.seed_file}: {exc}", file=sys.stderr)
            return 1

    records = emit_records(seeds=seeds)

    if args.dry_run:
        for r in records:
            print(json.dumps(r, ensure_ascii=False))
        return 0

    out_path = Path(args.out)
    write_jsonl(records, out_path)
    print(
        f"Wrote {len(records)} records to {out_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
