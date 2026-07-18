#!/usr/bin/env python3
"""agent-learning-k5-seeds.py - K5 concrete backfill seeds from workspace history.

Lane K5 (HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md, line 1356):

  Use the recent workspace history as the first agent-learning training set.
  Named seed engagements: Mezo / dYdX / NUVA / The Graph / Polymarket /
  Revert v4 / Reserve / Spark.

  Acceptance: emits >=1 row of each of the 6 terminal types:
    typed_lesson, proof_artifact, kill_reason, triager_objection,
    hacker_question, NO_ACTION

  Each row carries full K3a fields (proposition / evidence_polarity /
  primary_for / reuse_action / promotion_class / is_primary_signal /
  can_promote_to_proof) and explicit source refs.

  Evidence tiers follow K3 discipline:
    - triager_objection is primary_for=team_position (NOT proof)
    - proof_artifact requires a real runtime-proven PoC (NUVA ExpDec)
    - provider-only rows must be tier-5-quarantine / NO_ACTION
    - kill_reason rows are tier-2 (primary source: engagement ledger)

IMPORTANT: The proof_artifact seed (NUVA ExpDec chain-halt) references the
real runtime-proven PoC at:
  ~/audits/nuva/poc-tests/expdec_chain_halt/expdec_chain_halt_test.go
This is a real Go test that was executed and produced a passing ``go test``
transcript. It is NOT fabricated.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any


LEDGER_SCHEMA = "auditooor.agent_learning_ledger.v1"
TOOL_VERSION = "k5-seeds.v1"

# Terminal kind constants (must match gate's TERMINAL_KINDS set)
TK_TYPED_LESSON = "typed_lesson"
TK_PROOF_ARTIFACT = "proof_artifact"
TK_KILL_REASON = "kill_reason"
TK_TRIAGER_OBJECTION = "triager_objection"
TK_HACKER_QUESTION = "hacker_question"
TK_NO_ACTION = "no_action"

# evidence_polarity enum (gate: EVIDENCE_POLARITIES)
POL_SUPPORTS = "supports"
POL_CONTRADICTS = "contradicts"
POL_LIMITS = "limits"
POL_CONTEXT_ONLY = "context_only"

# primary_for enum (gate: PRIMARY_FOR_SCOPES)
PF_PROOF = "proof"
PF_DUPE = "dupe"
PF_OOS = "OOS"
PF_ECONOMICS = "economics"
PF_SEVERITY_CAP = "severity_cap"
PF_TEAM_POSITION = "team_position"
PF_SOURCE_REACH = "source_reachability"
PF_HARNESS_GAP = "harness_gap"
PF_METHODOLOGY = "methodology"

# reuse_action enum (gate: K4_REUSE_ACTIONS)
RA_ADD_DETECTOR = "add_detector"
RA_ADD_KILL_RUBRIC = "add_kill_rubric"
RA_ADD_PRE_SUBMIT_GATE = "add_pre_submit_gate"
RA_ADD_ORIGINALITY = "add_originality_check"
RA_ADD_PROVIDER_CONSTRAINT = "add_provider_prompt_constraint"
RA_ADD_HARNESS = "add_harness_template"
RA_ADD_HACKER_Q = "add_hacker_question"
RA_NONE = "none"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _base(
    artifact_id: str,
    *,
    terminal_kind: str,
    terminal_outcome: str,
    proposition: str,
    evidence_polarity: str,
    primary_for: str,
    reuse_action: str,
    promotion_class: str,
    is_primary_signal: bool,
    source_refs: list[str],
    engagement: str,
    evidence_tier: str,
    rationale: str,
    ts: str,
) -> dict[str, Any]:
    """Build a single K3a-scoped learning ledger row."""
    return {
        "schema": LEDGER_SCHEMA,
        "ts": ts,
        "source": TOOL_VERSION,
        "workspace": f"k5-seeds/{engagement}",
        "artifact_id": artifact_id,
        "terminal_kind": terminal_kind,
        "terminal_outcome": terminal_outcome,
        "proposition": proposition[:240],
        "evidence_polarity": evidence_polarity,
        "primary_for": primary_for,
        "reuse_action": reuse_action,
        # K3 promotion-rule fields
        "promotion_class": promotion_class,
        "is_primary_signal": is_primary_signal,
        "can_promote_to_proof": bool(terminal_kind == TK_PROOF_ARTIFACT and is_primary_signal),
        # provenance
        "evidence_tier": evidence_tier,
        "source_refs": source_refs,
        "engagement": engagement,
        "rationale": rationale,
        # gate-compatible flags
        "quarantine": True,
        "provider_only": False,
        "source_has_local_proof": (terminal_kind == TK_PROOF_ARTIFACT),
        "promotion_authority": False,
        "submit_ready": False,
        "severity": "none",
        "selected_impact": "",
    }


def build_seeds(ts: str) -> list[dict[str, Any]]:
    """Return all K5 backfill seed rows, one per named engagement thread."""

    rows: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 1. typed_lesson - Mezo negative oracle reachability + quality-score failures
    # Evidence tier: tier-3 (derived from engagement memory / session
    # outcome; no on-chain PoC reproduced).
    # Lesson: quality-score failures on Mezo surfaced that oracle-reachability
    # checks (can the price feed actually be called from the attack path?) were
    # never mechanically verified before filing.  Provider-level confidence
    # inflated severity; local harness gate was missing.
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-mezo-oracle-reachability-quality-fail",
            terminal_kind=TK_TYPED_LESSON,
            terminal_outcome="curated_lesson",
            proposition=(
                "Mezo engagement: oracle-reachability checks absent from pre-submit "
                "gate caused quality-score failures; provider confidence inflated "
                "severity without local call-path verification."
            ),
            evidence_polarity=POL_LIMITS,
            primary_for=PF_HARNESS_GAP,
            reuse_action=RA_ADD_HARNESS,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:mezo",
                "memory:feedback_no_long_rescans.md",
                "memory:auditooor_r38_r41_session.md",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
            ],
            engagement="mezo",
            evidence_tier="tier-3",
            rationale=(
                "Engagement ledger shows negative oracle-reachability outcomes; "
                "quality-score reviewer flagged missing call-path evidence as the "
                "primary rejection reason.  Lesson: add oracle-reachability step to "
                "pre-submit harness before any price-manipulation severity claim."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 2. proof_artifact - NUVA ExpDec chain-halt positive path (REAL PoC)
    # Evidence tier: tier-2 (primary source: reproduced Go test transcript
    # against real cosmos-sdk / ExpDec code path, runtime-proven).
    # This is the ONE proof_artifact seed allowed by K3.  It cites the
    # real PoC file that was executed and passed.
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-nuva-expdec-chain-halt-proof",
            terminal_kind=TK_PROOF_ARTIFACT,
            terminal_outcome="needs_human_primary_review",
            proposition=(
                "NUVA engagement: ExpDec exponent-overflow in Cosmos/Go consensus "
                "path triggers chain-halt; runtime-proven via Go test against real "
                "cosmos-sdk node entry point (FinalizeBlock path)."
            ),
            evidence_polarity=POL_SUPPORTS,
            primary_for=PF_PROOF,
            reuse_action=RA_ADD_DETECTOR,
            promotion_class="primary_promoted",
            is_primary_signal=True,
            source_refs=[
                "engagement:nuva",
                "poc:~/audits/nuva/poc-tests/expdec_chain_halt/expdec_chain_halt_test.go",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
                "memory:project_iter11_state_snapshot.md",
            ],
            engagement="nuva",
            evidence_tier="tier-2",
            rationale=(
                "Go test expdec_chain_halt_test.go executed against real cosmos-sdk "
                "node (simapp.Setup + ApplyBlock path); produced passing 'go test' "
                "transcript.  Chain-halt confirmed via panic on integer overflow in "
                "ExpDec coefficient path.  Primary signal: local reproduction + "
                "source refs + proof status all present."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 3. kill_reason - dYdX OOS oracle/validator-infra holds
    # Evidence tier: tier-2 (primary source: Cantina triager rejection +
    # engagement lifecycle ledger at ~/audits/dydx).
    # Lesson: oracle and validator-infra findings are structurally OOS on
    # dYdX Cantina bounty (not listed assets; triager closed without review).
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-dydx-oracle-validator-infra-oos-kill",
            terminal_kind=TK_KILL_REASON,
            terminal_outcome="curated_lesson",
            proposition=(
                "dYdX Cantina: oracle/validator-infra findings are structurally OOS; "
                "triager hard-closed without review regardless of severity claim or "
                "PoC quality."
            ),
            evidence_polarity=POL_CONTRADICTS,
            primary_for=PF_OOS,
            reuse_action=RA_ADD_KILL_RUBRIC,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:dydx",
                "ledger:~/audits/dydx/.auditooor/commit_lifecycle_ledger.json",
                "memory:dydx_iter_1_through_6_plus_escalation_FINAL.md",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
            ],
            engagement="dydx",
            evidence_tier="tier-2",
            rationale=(
                "Multiple oracle and validator-infra lanes (Slinky oracle adoption, "
                "VE adoption, bridge-state-bloat) were held OOS by triager; none "
                "reached payout.  Engagement ledger records DROP-OOS verdict for all "
                "these lanes.  Kill rubric: skip oracle/validator-infra on dYdX "
                "Cantina unless finding has direct fund-loss proof on listed assets."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 4. triager_objection - dYdX cantina-213 in-process-vs-node-level rejection
    # Evidence tier: tier-2 (primary source: verbatim triager rejection text
    # recorded in dydx_cantina_review_status_20260511.md + wave13 complete).
    # The triager's verbatim ask is the primary signal for the objection class.
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-dydx-cantina213-in-process-node-level-objection",
            terminal_kind=TK_TRIAGER_OBJECTION,
            terminal_outcome="curated_lesson",
            proposition=(
                "dYdX cantina-213: triager rejected HIGH because PoC was in-process "
                "microbenchmark only; demanded node-level reproduction with external "
                "mempool ingress path and end-to-end block-production/SLO metrics."
            ),
            evidence_polarity=POL_CONTRADICTS,
            primary_for=PF_TEAM_POSITION,
            reuse_action=RA_ADD_PRE_SUBMIT_GATE,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:dydx",
                "cantina-submission:cantina-213",
                "memory:dydx_cantina_review_status_20260511.md",
                "memory:wave13_complete_2026_05_11.md",
                "rule:R18/L32 in-process-vs-node-level gate (Check #58)",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
            ],
            engagement="dydx",
            evidence_tier="tier-2",
            rationale=(
                "Triager verbatim: 'current evidence is primarily microbenchmark/"
                "in-process contention; does not demonstrate clear production-grade "
                "impact.  Please provide: realistic node-level reproduction; end-to-end "
                "impact metrics; attacker cost model.'  This objection class was "
                "codified as Rule 18 / Check #58 (agent-learning-gate enforced)."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 5. hacker_question - The Graph rounding-drain OOS/sandwich closure
    # Evidence tier: tier-3 (engagement memory; outcome was OOS / econ
    # rejection; open architectural question remains for future engagements).
    # Lesson: rounding-drain bugs in decentralized indexing protocols need a
    # concrete attacker-profit model before filing; sandwich-style extraction
    # must survive slippage/deadline defenses.
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-graph-rounding-drain-sandwich-hacker-q",
            terminal_kind=TK_HACKER_QUESTION,
            terminal_outcome="needs_human_primary_review",
            proposition=(
                "The Graph engagement: rounding-drain closed OOS/sandwich; open "
                "question - under what economic conditions does a rounding-drain in "
                "a decentralized-indexing reward curve survive slippage/deadline "
                "defenses and produce net attacker profit?"
            ),
            evidence_polarity=POL_LIMITS,
            primary_for=PF_ECONOMICS,
            reuse_action=RA_ADD_HACKER_Q,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:the-graph",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
                "memory:auditooor_tooling_consolidation_megaplan.md",
            ],
            engagement="the-graph",
            evidence_tier="tier-3",
            rationale=(
                "Rounding-drain OOS closure and sandwich-style rejection indicate the "
                "economic model was underspecified: no attacker cost model, no "
                "slippage/deadline defense traversal, no net-profit proof.  Future "
                "Graph/indexing-protocol workers should answer this question before "
                "promoting any rounding-drain to HIGH+."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 6. NO_ACTION - Polymarket live-state/economics rejection
    # Evidence tier: tier-3 (session memory; outcome was rejection of live-
    # state and economics-only candidates; no new tooling needed - the OOS
    # and economics gates already cover this; record for coverage accounting).
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-polymarket-live-state-economics-no-action",
            terminal_kind=TK_NO_ACTION,
            terminal_outcome="verified_no_action",
            proposition=(
                "Polymarket engagement: live-state/economics-only candidates were "
                "rejected as OOS or non-fund-loss; no new gate or detector needed "
                "beyond existing economics + OOS checks already in pre-submit-check."
            ),
            evidence_polarity=POL_CONTEXT_ONLY,
            primary_for=PF_METHODOLOGY,
            reuse_action=RA_NONE,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:polymarket",
                "case_study:r53-polymarket-retriage-470",
                "memory:feedback_recurring_agent_mistakes.md",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
            ],
            engagement="polymarket",
            evidence_tier="tier-3",
            rationale=(
                "r53-polymarket-retriage-470 case study: 3 confident 'novel' findings "
                "all collapsed to OOS; live-state / economics reasoning was the "
                "common failure mode.  Existing pre-submit-check OOS + economics gates "
                "already cover this; no additional artifact needed.  Record as "
                "NO_ACTION for coverage accounting."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 7. typed_lesson - Revert v4 hook slippage/reentrancy/exact-output outcomes
    # Evidence tier: tier-3 (engagement memory; outcomes span multiple hook
    # classes; lesson is about detector tuning needed for v4 hook surface).
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-revert-v4-hook-slippage-reentrancy-lesson",
            terminal_kind=TK_TYPED_LESSON,
            terminal_outcome="curated_lesson",
            proposition=(
                "Revert v4 engagement: hook-slippage, reentrancy, and exact-output "
                "outcomes show current detectors miss v4-specific hook composition "
                "paths; add v4-hook-aware slippage + reentrancy detector variants."
            ),
            evidence_polarity=POL_LIMITS,
            primary_for=PF_SOURCE_REACH,
            reuse_action=RA_ADD_DETECTOR,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:revert-v4",
                "memory:auditooor_r38_r41_session.md",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
            ],
            engagement="revert-v4",
            evidence_tier="tier-3",
            rationale=(
                "Hook-slippage and exact-output paths in Uniswap v4 require detector "
                "variants that track call-site composition through beforeSwap/afterSwap "
                "hooks.  Current detectors fire on direct slippage checks but miss "
                "cases where the hook itself modifies amountSpecified between phases."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 8. kill_reason - Reserve governance/ERC4626 scanner hard-kills
    # Evidence tier: tier-2 (engagement ledger; governance scanner hard-kills
    # are primary-source outcome records from the Reserve engagement run).
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-reserve-governance-erc4626-scanner-hard-kill",
            terminal_kind=TK_KILL_REASON,
            terminal_outcome="curated_lesson",
            proposition=(
                "Reserve engagement: governance/ERC4626 scanner candidates were "
                "hard-killed by pre-submit check because governance timelock + "
                "multi-sig defenses covered all attack paths; not fileable under "
                "fund-loss rubric."
            ),
            evidence_polarity=POL_CONTRADICTS,
            primary_for=PF_SOURCE_REACH,
            reuse_action=RA_ADD_KILL_RUBRIC,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:reserve",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
                "memory:auditooor_tooling_consolidation_megaplan.md",
            ],
            engagement="reserve",
            evidence_tier="tier-2",
            rationale=(
                "Reserve protocol has multi-layer governance defenses (timelock + "
                "multi-sig + guardian veto).  Scanner hits on governance/ERC4626 "
                "paths were hard-killed because at least 2 independent fully-covering "
                "guards exist on every attack path (Rule 29 protection-cardinality "
                "principle).  Kill rubric: skip governance/ERC4626 on Reserve unless "
                "PoC bypasses BOTH timelock and multi-sig."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 9. triager_objection - Spark duplicate-family distinctions
    # Evidence tier: tier-2 (primary source: Cantina/Immunefi duplicate
    # closure records for LEAD H-D and LEAD F-N; verbatim closure text
    # available in engagement memory).
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-spark-duplicate-family-leaf-status-objection",
            terminal_kind=TK_TRIAGER_OBJECTION,
            terminal_outcome="curated_lesson",
            proposition=(
                "Spark engagement: LEAD H-D and LEAD F-N closed as dupes of #77043 "
                "because one fix closes all leaf-status guard gaps; filing 2 separate "
                "narrow reports rather than one comprehensive report enumerating all "
                "4 call sites was the structural failure."
            ),
            evidence_polarity=POL_CONTRADICTS,
            primary_for=PF_DUPE,
            reuse_action=RA_ADD_PRE_SUBMIT_GATE,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:spark",
                "memory:spark_lead_hd_fn_closed_dupe.md",
                "rule:L30-MISSING-GUARD-ENUMERATION (Check #48)",
                "rule:L31-DUPE-PREFLIGHT (Check #49)",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
            ],
            engagement="spark",
            evidence_tier="tier-2",
            rationale=(
                "External #77043 reporter enumerated all 4 call sites of the missing "
                "validateTransferLeavesNotExitedToL1 guard in ONE report; auditooor "
                "filed 2 narrow reports covering only 2 of 4 call sites.  Both closed "
                "as dupes.  Codified as Rule 30 (enumerate-all-callsites) and Rule 31 "
                "(dupe-preflight Q1+Q2).  Pre-submit-check Checks #48 and #49 now "
                "enforce this."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 10. hacker_question - Spark FROST signed-message attack surface
    # Evidence tier: tier-3 (from CLAUDE.md / memory anchor describing the
    # FROST threshold-signing library as PoI-eligible; open question about
    # whether nonce-reuse or malleability vectors exist in the FROST crate
    # used by Spark; no PoC attempted yet).
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-spark-frost-signed-message-nonce-reuse-hacker-q",
            terminal_kind=TK_HACKER_QUESTION,
            terminal_outcome="needs_human_primary_review",
            proposition=(
                "Spark engagement: lightsparkdev/frost (FROST threshold-signing "
                "library) is PoI-eligible; open question - does the FROST nonce "
                "generation path have a nonce-reuse or malleability vector exploitable "
                "from a Spark mainnet signing session?"
            ),
            evidence_polarity=POL_LIMITS,
            primary_for=PF_SOURCE_REACH,
            reuse_action=RA_ADD_HACKER_Q,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:spark",
                "memory:spark_sdk_repo_inventory.md",
                "global-claude-md:Spark Primacy of Impact doctrine",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
            ],
            engagement="spark",
            evidence_tier="tier-3",
            rationale=(
                "Spark uses lightsparkdev/frost for threshold signing (PoI-eligible "
                "per CLAUDE.md Spark doctrine).  FROST nonce-reuse and scalar "
                "malleability bugs are known classes in the literature.  No audit "
                "coverage of this surface exists in the engagement record.  Future "
                "Spark workers should audit nonce generation before claiming safe."
            ),
            ts=ts,
        )
    )

    # ------------------------------------------------------------------
    # 11. NO_ACTION - dYdX severity walk-backs (multiple lanes)
    # Evidence tier: tier-2 (engagement ledger).
    # Several dYdX lanes walked back from CRITICAL/HIGH to DROP or MEDIUM
    # after defense-in-depth traversal.  No new tooling needed - R25/Check
    # #63 already enforces this.  Record for coverage accounting.
    # ------------------------------------------------------------------
    rows.append(
        _base(
            artifact_id="k5-dydx-severity-walkbacks-no-action",
            terminal_kind=TK_NO_ACTION,
            terminal_outcome="verified_no_action",
            proposition=(
                "dYdX engagement: multiple CRITICAL/HIGH severity walk-backs after "
                "defense-in-depth traversal (MaxTxBytes, ValidateNestedMsg, cap "
                "short-circuit); existing R25 Check #63 already enforces traversal "
                "requirement; no additional artifact needed."
            ),
            evidence_polarity=POL_CONTEXT_ONLY,
            primary_for=PF_METHODOLOGY,
            reuse_action=RA_NONE,
            promotion_class="suggest_only",
            is_primary_signal=False,
            source_refs=[
                "engagement:dydx",
                "memory:dydx_iter_1_through_6_plus_escalation_FINAL.md",
                "rule:R25 defense-in-depth-traversal (Check #63)",
                "plan:HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md#K5",
            ],
            engagement="dydx",
            evidence_tier="tier-2",
            rationale=(
                "Cantina-213, FARTCOIN, commission-cap, leverage, underflow, VE-"
                "adoption, Slinky, bridge-state-bloat, parser-tail+nil-deref lanes "
                "all walked back after traversal revealed defense-in-depth kills.  "
                "R25 (Check #63) was codified as direct result.  NO_ACTION: the rule "
                "exists; no duplicate artifact needed.  Record for accounting coverage."
            ),
            ts=ts,
        )
    )

    return rows


def emit(rows: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def _terminal_kind_coverage(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    coverage: dict[str, list[str]] = {}
    for row in rows:
        kind = str(row.get("terminal_kind") or "")
        coverage.setdefault(kind, []).append(str(row.get("artifact_id") or ""))
    return coverage


def _validate_rows(rows: list[dict[str, Any]]) -> list[str]:
    """Offline schema-conformance check (mirrors gate logic)."""
    errors: list[str] = []
    required_kinds = {
        TK_TYPED_LESSON,
        TK_PROOF_ARTIFACT,
        TK_KILL_REASON,
        TK_TRIAGER_OBJECTION,
        TK_HACKER_QUESTION,
        TK_NO_ACTION,
    }
    seen_kinds = set()
    for row in rows:
        aid = row.get("artifact_id", "<unknown>")
        # K3a fields
        for field in ("proposition", "evidence_polarity", "primary_for", "reuse_action"):
            if not str(row.get(field) or "").strip():
                errors.append(f"{aid}: missing K3a field '{field}'")
        # evidence_polarity enum
        ep = row.get("evidence_polarity")
        if ep not in {"supports", "contradicts", "limits", "context_only"}:
            errors.append(f"{aid}: invalid evidence_polarity '{ep}'")
        # primary_for enum
        pf = row.get("primary_for")
        if pf not in {
            "proof", "dupe", "OOS", "economics", "severity_cap",
            "team_position", "source_reachability", "harness_gap", "methodology",
        }:
            errors.append(f"{aid}: invalid primary_for '{pf}'")
        # reuse_action enum
        ra = row.get("reuse_action")
        if ra not in {
            "add_detector", "add_kill_rubric", "add_pre_submit_gate",
            "add_originality_check", "add_provider_prompt_constraint",
            "add_harness_template", "add_hacker_question", "none",
        }:
            errors.append(f"{aid}: invalid reuse_action '{ra}'")
        # source_refs
        if not row.get("source_refs"):
            errors.append(f"{aid}: missing source_refs")
        # NO_ACTION must not be provider_only promoted to proof_artifact
        kind = str(row.get("terminal_kind") or "")
        seen_kinds.add(kind)
        if kind == TK_PROOF_ARTIFACT:
            if not row.get("is_primary_signal"):
                errors.append(f"{aid}: proof_artifact without is_primary_signal=True")
            if not row.get("source_has_local_proof"):
                errors.append(f"{aid}: proof_artifact without source_has_local_proof=True")
            if row.get("provider_only"):
                errors.append(f"{aid}: provider_only row reached proof_artifact (K3 escape)")
    # Coverage check
    missing_kinds = required_kinds - seen_kinds
    if missing_kinds:
        errors.append(f"Missing required terminal kinds: {sorted(missing_kinds)}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/agent_learning_k5_seeds.jsonl"),
        help="Output JSONL path (default: reports/agent_learning_k5_seeds.jsonl)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate rows and print stats without writing output file.",
    )
    parser.add_argument(
        "--json",
        dest="print_json",
        action="store_true",
        help="Print summary JSON to stdout.",
    )
    args = parser.parse_args(argv)
    ts = _utc_now()
    rows = build_seeds(ts)
    errors = _validate_rows(rows)
    coverage = _terminal_kind_coverage(rows)
    summary = {
        "schema": "auditooor.k5-seeds-manifest.v1",
        "generated_at_utc": ts,
        "total_rows": len(rows),
        "terminal_kind_coverage": {k: len(v) for k, v in sorted(coverage.items())},
        "artifact_ids": [str(r.get("artifact_id") or "") for r in rows],
        "validation_errors": errors,
        "valid": not errors,
        "output_path": str(args.output),
        "check_only": args.check,
    }
    if errors:
        for err in errors:
            print(f"ERROR: {err}", flush=True)
        return 1
    if not args.check:
        emit(rows, args.output)
        print(f"K5 seeds written: {len(rows)} rows -> {args.output}")
    else:
        print(f"K5 seeds check OK: {len(rows)} rows, all 6 terminal kinds covered")
    if args.print_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
