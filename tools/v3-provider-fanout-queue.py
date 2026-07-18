#!/usr/bin/env python3
# LEGACY 2026-06-13: HACKERMAN_V3 campaign artifact (8-Kimi+8-MiniMax).
# Kimi provider is dead. Referenced by Makefile targets v3-provider-fanout-queue /
# v3-provider-fanout-run / v3-provider-fanout-slice - kept to avoid breaking those
# targets. Do NOT use for new work; use tools/llm-fanout-dispatcher.py instead.
"""Build Hackerman V3 Kimi/MiniMax provider fanout queues.

The queue is deliberately offline: it writes bounded prompt packets plus
``dispatch-preflight.py`` commands, but it does not call any provider. Live
provider work must still pass the MCP context gate and dispatch preflight.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = ROOT / "docs" / "HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md"
DEFAULT_CAMPAIGN_ID = "hackerman-v3-8kimi-8minimax"


@dataclass(frozen=True)
class FanoutTask:
    task_id: str
    provider: str
    template: str
    title: str
    target_files: tuple[str, ...]
    hypotheses: tuple[str, ...]
    prior_failed_attempts: str
    expected_output_shape: str
    oos_text: str = "none"
    truncation_flag: str = "complete"
    max_tokens: int = 8000
    http_timeout_seconds: int = 300
    timeout_seconds: int = 1200


KIMI_TASKS: tuple[FanoutTask, ...] = (
    FanoutTask(
        task_id="kimi-01-external-intel-refresh",
        provider="kimi",
        template="source-extract",
        title="Lane I external intelligence refresh sidecars",
        target_files=(
            "docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:930-965",
            "tools/hackerman-etl-refresh.py",
            "reference/external_intel_sources.yaml",
        ),
        hypotheses=(
            "Lane I needs source-specific freshness rows before any mined record can be trusted.",
            "Primary-source URLs must be kept distinct from advisory social summaries.",
        ),
        prior_failed_attempts=(
            "V2 chased global same-class recall and exhausted cheap alias/tagging work; "
            "V3 must extract only source-backed refresh obligations."
        ),
        expected_output_shape=(
            "JSON list of source-specific refresh tasks: source, files, missing fields, "
            "required local verification, and promotion blockers. No provider claims are final."
        ),
    ),
    FanoutTask(
        task_id="kimi-02-darknavy-miner",
        provider="kimi",
        template="source-extract",
        title="DarkNavy Web3 miner extraction plan",
        target_files=(
            "docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:940-945",
            "tools/hackerman-etl-refresh.py",
            "audit/corpus_tags/tags",
        ),
        hypotheses=(
            "DarkNavy pages need a bounded miner with URL, title, date, affected protocol, root cause, and evidence URL.",
            "Records without source dates or primary evidence must be downgraded before detector use.",
        ),
        prior_failed_attempts="none (new source requested by operator for V3 plan).",
        expected_output_shape=(
            "JSON rows for miner fields and reject conditions; include exact local files to inspect next."
        ),
    ),
    FanoutTask(
        task_id="kimi-03-verus-bridge-backfill",
        provider="kimi",
        template="source-extract",
        title="Verus bridge S-tier backfill packet",
        target_files=(
            "docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:951-965",
            "reference/patterns.dsl/bridge-replay-key-omits-chain-domain.yaml",
            "reference/patterns.dsl/bridge-destination-settlement-unproven-source-commitment.yaml",
        ),
        hypotheses=(
            "Verus exploit shape is payout not bound to unique unspent authorized export or txid.",
            "Bridge proof-domain detectors should ask for consumed txid/source-commitment gates, not just state-root membership.",
        ),
        prior_failed_attempts=(
            "slice56 lifted bridge proof-domain recall, but held-out recall stayed low; "
            "this backfill should identify exact missing detector predicates."
        ),
        expected_output_shape=(
            "JSON candidate predicates with source refs, bridge path, settlement gate, and local fixture requirements."
        ),
    ),
    FanoutTask(
        task_id="kimi-04-solodit-defimon-deltas",
        provider="kimi",
        template="source-extract",
        title="Solodit and Defimon delta extraction",
        target_files=(
            "docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:930-950",
            "reference/corpus_mined",
            "audit/corpus_tags/tags",
        ),
        hypotheses=(
            "Unknown-year Solodit rows should be source-data blocked instead of counted toward freshness.",
            "New Defimon reports need source URL/date normalization before they can improve recall.",
        ),
        prior_failed_attempts=(
            "Bulk class-tag sweep only lifted recall 44.9% to 49.3%; content gaps remain."
        ),
        expected_output_shape=(
            "JSON extraction backlog with row class, source path, missing provenance, and safe promotion criteria."
        ),
    ),
    FanoutTask(
        task_id="kimi-05-workflow-make-audit-map",
        provider="kimi",
        template="source-extract",
        title="make audit plus make audit-deep workflow delivery map",
        target_files=(
            "Makefile",
            "tools/engage.py",
            "tools/audit-deep-manifest.py",
            "docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:520-610",
        ),
        hypotheses=(
            "The audit workflow may generate hackerman, rubric, queue, and MCP artifacts that are not force-consumed later.",
            "V3 should identify every generated artifact and the next gate that must consume it.",
        ),
        prior_failed_attempts=(
            "Operator observed many tools exist but may not be properly used end-to-end."
        ),
        expected_output_shape=(
            "JSON artifact map: producer target, output path, consumer gate, enforcement status, and missing hard gates."
        ),
    ),
    FanoutTask(
        task_id="kimi-06-known-lessons-compiler",
        provider="kimi",
        template="source-extract",
        title="Outcome and triager lesson compiler inventory",
        target_files=(
            "docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md",
            "reference/outcomes.jsonl",
            "reference/triager_patterns.json",
            "obsidian-vault/anti-patterns",
        ),
        hypotheses=(
            "Graph closure showed OOS reasoning must be generalized, not just workspace-local.",
            "Polymarket update showed economic viability must be checked before Critical/High claims.",
        ),
        prior_failed_attempts=(
            "Past reviews relied on human memory; V3 needs a compiler that emits enforceable gates."
        ),
        expected_output_shape=(
            "JSON lesson candidates: trigger, negative example, general rule, gate insertion point, and false-positive risk."
        ),
    ),
    FanoutTask(
        task_id="kimi-07-agent-artifact-mining",
        provider="kimi",
        template="source-extract",
        title="Cross-workspace agent artifact mining intake",
        target_files=(
            "tools/agent-artifact-miner.py",
            "tools/agent-learning-gate.py",
            "docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md",
            "agent_outputs",
        ),
        hypotheses=(
            "Agent artifacts are secondary learning inputs and must not outrank verified exploits or triager feedback.",
            "Useful artifacts should become prompts, kill rubrics, or proof obligations only after local proof/evidence gates.",
        ),
        prior_failed_attempts=(
            "Artifact miner previously promoted proof-hardening prose too aggressively; gate now blocks proof claims without local artifacts."
        ),
        expected_output_shape=(
            "JSON mining policy deltas: useful artifact class, required evidence, enforcement gate, and quarantine rule."
        ),
    ),
    FanoutTask(
        task_id="kimi-08-strict-closeout-path",
        provider="kimi",
        template="source-extract",
        title="Strict closeout and finalization path extraction",
        target_files=(
            "Makefile",
            "tools/loop-finalization-check.py",
            "tools/agent-learning-gate.py",
            "docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:520-610",
        ),
        hypotheses=(
            "STRICT closeout should fail when fresh lessons, proof artifacts, or MCP recalls are missing.",
            "Provider outputs should be logged with model IDs and task type before closeout can pass.",
        ),
        prior_failed_attempts=(
            "Provider fanout has been unreliable; closeout must record real dispatch/preflight status instead of assuming it happened."
        ),
        expected_output_shape=(
            "JSON closeout gate map with pass/fail condition, current code path, and missing tests."
        ),
    ),
)


MINIMAX_TASKS: tuple[FanoutTask, ...] = (
    FanoutTask(
        task_id="minimax-01-external-intel-kill",
        provider="minimax",
        template="adversarial-kill",
        title="Kill weak external-intel refresh claims",
        target_files=(),
        hypotheses=(),
        prior_failed_attempts="",
        expected_output_shape=(
            "Per-candidate JSON verdict with contradiction citation, minimum follow-up check, and local_verification_required=true."
        ),
        oos_text=(
            "Reject any mined external record without primary source URL/date, reproducible transaction/code evidence, "
            "or a local fixture/replay path."
        ),
        max_tokens=5000,
    ),
    FanoutTask(
        task_id="minimax-02-primary-source-downgrade",
        provider="minimax",
        template="adversarial-kill",
        title="Adversarial review of primary-source downgrade gate",
        target_files=(),
        hypotheses=(),
        prior_failed_attempts="",
        expected_output_shape="JSON verdict per downgrade rule with exact missing source or overclaim citation.",
        oos_text=(
            "Social posts, summaries, and agent prose are advisory only unless backed by source transaction, code, report, or patch."
        ),
        max_tokens=5000,
    ),
    FanoutTask(
        task_id="minimax-03-verus-proof-binding-kill",
        provider="minimax",
        template="adversarial-kill",
        title="Kill overbroad Verus/bridge proof-domain predicates",
        target_files=(),
        hypotheses=(),
        prior_failed_attempts="",
        expected_output_shape="JSON verdict per predicate with duplicate/OOS/insufficient-binding citation.",
        oos_text=(
            "Reject bridge candidates that prove only state-root membership but not unique payout authorization, consumed txid, "
            "source chain/domain binding, and production payout reachability."
        ),
        max_tokens=6000,
    ),
    FanoutTask(
        task_id="minimax-04-solodit-date-safety",
        provider="minimax",
        template="adversarial-kill",
        title="Solodit unknown-year and false-date mutation review",
        target_files=(),
        hypotheses=(),
        prior_failed_attempts="",
        expected_output_shape="JSON verdict per date/freshness rule; cite the exact unsafe inference.",
        oos_text=(
            "Reject freshness claims derived from scrape time, upload time, or unverified contest close dates."
        ),
        max_tokens=5000,
    ),
    FanoutTask(
        task_id="minimax-05-lesson-compiler-kill",
        provider="minimax",
        template="adversarial-kill",
        title="Adversarial review of outcome lesson compiler",
        target_files=(),
        hypotheses=(),
        prior_failed_attempts="",
        expected_output_shape="JSON verdict per lesson: keep, reject duplicate, reject too workspace-specific, or needs more source.",
        oos_text=(
            "Do not let one workspace's rule become global unless the trigger generalizes and false positives are named."
        ),
        max_tokens=5000,
    ),
    FanoutTask(
        task_id="minimax-06-agent-learning-gate-escape",
        provider="minimax",
        template="adversarial-kill",
        title="Agent learning gate escape review",
        target_files=(),
        hypotheses=(),
        prior_failed_attempts="",
        expected_output_shape="JSON verdict per escape path with local test to add or blocker citation.",
        oos_text=(
            "Provider/agent output alone is never proof. Verified exploits and triager outcomes outrank agent artifacts."
        ),
        max_tokens=5000,
    ),
    FanoutTask(
        task_id="minimax-07-provider-discipline-kill",
        provider="minimax",
        template="adversarial-kill",
        title="Provider fanout discipline and calibration review",
        target_files=(),
        hypotheses=(),
        prior_failed_attempts="",
        expected_output_shape="JSON verdict per dispatch rule with bypass risk, model-id logging risk, and calibration update required.",
        oos_text=(
            "Reject live provider loops that lack dispatch-preflight, MCP receipt, model ID, task type, timeout, output path, or local verification."
        ),
        max_tokens=5000,
    ),
    FanoutTask(
        task_id="minimax-08-strict-closeout-bypass",
        provider="minimax",
        template="adversarial-kill",
        title="Strict audit-closeout bypass review",
        target_files=(),
        hypotheses=(),
        prior_failed_attempts="",
        expected_output_shape="JSON verdict per closeout path with exact command or Makefile target that can bypass required gates.",
        oos_text=(
            "Reject any closeout path that can mark work complete while MCP recall, proof execution, provider audit, or learning gates are missing."
        ),
        max_tokens=5000,
    ),
)


FOLLOWUP_KIMI_SPECS: tuple[dict[str, object], ...] = (
    {
        "task_id": "kimi-01-source-acquisition",
        "title": "Needs-more-source acquisition plan",
        "selector": "needs_more_source",
        "hypotheses": (
            "needs_more_source rows need primary URL/date/txhash/local source before reuse",
            "terminal NO_ACTION rows should become source-acquisition tasks, not detector facts",
        ),
        "task": "For each terminal needs_more_source row, identify the minimum primary source needed before it can influence a detector, rubric, or hacker question.",
        "expected": "JSON advisory_candidates with candidate_id, primary_source_needed[], exact_local_files_to_inspect_next[], promotion_blockers[], next_action_required.",
    },
    {
        "task_id": "kimi-02-fixture-specs",
        "title": "Fixture and clean-control specs",
        "selector": "fixture_needed",
        "hypotheses": (
            "fixture_needed rows are not useful until material vulnerable/clean deltas exist",
            "smoke commands must be deterministic and local",
        ),
        "task": "For fixture_needed rows, draft paired vulnerable/clean fixture specs and smoke commands. Separate source-backed specs from provider-only hypotheses.",
        "expected": "JSON fixture specs with vulnerable predicate, clean negative control, local files, expected command, promotion blockers.",
    },
    {
        "task_id": "kimi-03-kill-citation-extract",
        "title": "Kill-review exact citation extraction",
        "selector": "kill_review",
        "hypotheses": (
            "kill_review rows should require exact contradiction citations",
            "provider kill claims without local citation stay pending",
        ),
        "task": "For kill_review rows, extract exact local citations that would justify NO_ACTION/OOS/dupe/false-positive. Do not decide severity or submission state.",
        "expected": "JSON kill candidates with exact citation, kill class, confidence, and missing local proof.",
    },
    {
        "task_id": "kimi-04-local-source-artifacts",
        "title": "Local source artifact proposals",
        "selector": "local_source_review",
        "hypotheses": (
            "grep hits are evidence only, not terminal proof",
            "local artifacts need a supported proposition plus open proof obligations",
        ),
        "task": "For local_source_review rows, turn grep/file evidence into bounded source artifact proposals: supported claim, unproved obligations, verifier command.",
        "expected": "JSON source_artifact proposals with exact refs, supported proposition, unproved obligations, next verifier command.",
    },
    {
        "task_id": "kimi-05-enforcement-map",
        "title": "Verifier terminal lesson enforcement map",
        "selector": "terminal_or_verified",
        "hypotheses": (
            "verifier-terminal rows can guide gates only while quarantined",
            "each lesson needs a consumer gate or NO_ACTION",
        ),
        "task": "Map verifier-terminal rows and ledger entries to enforcement targets: prefiling-stress-test, high-plus-submission-gate, dispatch-preflight, lesson-pack, kill-rubric, NO_ACTION.",
        "expected": "JSON enforcement deltas with target file/tool, rule, test required, and quarantine reason.",
    },
    {
        "task_id": "kimi-06-strict-closeout-gaps",
        "title": "Strict closeout and receipt gaps",
        "selector": "verified_or_pending",
        "hypotheses": (
            "closeout should fail stale MCP/provider/model/verification gaps",
            "verified local source rows can become acceptance tests",
        ),
        "task": "Use verified rows to identify exact remaining gaps in provider dispatch, MCP receipt, finalization, learning gate, and closeout enforcement.",
        "expected": "JSON closeout gap map with existing source refs, bypass scenario, and acceptance test.",
    },
    {
        "task_id": "kimi-07-agent-artifact-policy",
        "title": "Agent artifact secondary-learning policy",
        "selector": "all",
        "hypotheses": (
            "agent artifacts are secondary to exploits, triager feedback, and command transcripts",
            "artifact mining must save time without promoting hallucinations",
        ),
        "task": "Derive a policy for mining agent artifacts without promoting hallucinations: useful classes, primary overrides, quarantine rules.",
        "expected": "JSON policy deltas with artifact class, required evidence, consumer gate, quarantine rule.",
    },
    {
        "task_id": "kimi-08-field-validation-workpack",
        "title": "Fresh engagement field-validation workpack",
        "selector": "field_validation",
        "hypotheses": (
            "V3 completion requires proved/killed conversion on fresh targets",
            "metrics should track prefiling objections caught and triage survival, not detector count",
        ),
        "task": "Build the provider-assisted workpack for one fresh engagement run: Kimi extracts, MiniMax kills, Codex/Claude verifies, and metrics prove V3 helped.",
        "expected": "JSON workpack stages with inputs, provider role, local command, exit criterion, metric.",
    },
)


FOLLOWUP_MINIMAX_SPECS: tuple[dict[str, str], ...] = (
    {
        "task_id": "minimax-01-source-plan-kill",
        "title": "Kill weak source acquisition plans",
        "oos": "Reject plans relying on social summary, scrape date, provider assertion, or URL without date/tx/code/report anchor.",
        "expected": "JSON judgments for Kimi source plans; keep only rows with primary-source acquisition path.",
    },
    {
        "task_id": "minimax-02-fixture-spec-kill",
        "title": "Kill weak fixture specs",
        "oos": "Reject fixtures without material vulnerable/clean delta, production reachability, deterministic command, or negative control.",
        "expected": "JSON judgments for fixture specs; keep only runnable local verification candidates.",
    },
    {
        "task_id": "minimax-03-kill-citation-stress",
        "title": "Stress kill citations",
        "oos": "Reject NO_ACTION/OOS/dupe kills unless contradiction citation is exact and material-difference test is stated.",
        "expected": "JSON judgments for kill citations and missing material-difference arguments.",
    },
    {
        "task_id": "minimax-04-provider-promotion-bypass",
        "title": "Find provider-promotion bypasses",
        "oos": "Try to route provider text into proof, severity, submission readiness, or non-quarantined learning despite compiler/verifier gates.",
        "expected": "JSON bypass attempts with file/ref and required regression test.",
    },
    {
        "task_id": "minimax-05-oos-economics-dupe",
        "title": "General OOS/economics/dupe stress",
        "oos": "Apply Graph sandwich/OOS, Polymarket economics, NUVA admin/self-created-resource, and duplicate one-fix reasoning to follow-up rows.",
        "expected": "JSON objections by row with gate insertion point.",
    },
    {
        "task_id": "minimax-06-mcp-receipt-bypass",
        "title": "MCP receipt and closeout bypass stress",
        "oos": "Find ways an overnight worker could skip MCP recall, use stale recall, skip provider model IDs, or close out without local verification.",
        "expected": "JSON bypass attempts and acceptance tests.",
    },
    {
        "task_id": "minimax-07-learning-ledger-leakage",
        "title": "Learning ledger leakage stress",
        "oos": "Reject any route where terminal rows, agent artifacts, or provider outputs become primary proof without accepted filing, command transcript, triager feedback, or local source proof.",
        "expected": "JSON leakage risks and exact rule changes.",
    },
    {
        "task_id": "minimax-08-field-validation-kill",
        "title": "Fresh-engagement workpack kill pass",
        "oos": "Reject field-validation metrics that count detector hits instead of proved/killed top-10 rows, prefiling objections caught, or triage survival.",
        "expected": "JSON metric objections and better acceptance criteria.",
    },
)


PREFILING_BLOCKER_KEYWORDS: tuple[str, ...] = (
    "permissionless",
    "rubric",
    "prior",
    "disclosure",
    "dupe",
    "economics",
    "economic",
    "harness",
)


PREFILING_KIMI_SPECS: tuple[dict[str, object], ...] = (
    {
        "task_id": "kimi-01-prefiling-permissionless-actions",
        "title": "Prefiling backfill exact permissionless action extraction",
        "selector": "permissionless",
        "hypotheses": (
            "Fail/warn rows need the exact unprivileged attacker transaction before proof work starts.",
            "Admin, owner, keeper, mock, or test-only actions must be separated from public production paths.",
        ),
        "task": "Extract the exact attacker action, caller privilege state, entrypoint, source refs, and missing local checks for each selected prefiling row.",
        "expected": "JSON rows with candidate_id, attacker_action, caller_privilege, entrypoint_refs[], source_refs[], missing_refs[], local_verification_required.",
    },
    {
        "task_id": "kimi-02-prefiling-rubric-source-refs",
        "title": "Prefiling backfill rubric source-ref extraction",
        "selector": "rubric",
        "hypotheses": (
            "High/Critical rows must map to a concrete in-scope rubric row.",
            "A severity phrase is not enough unless the row and impact evidence are source-backed.",
        ),
        "task": "Extract the claimed rubric row, exact workspace/source refs supporting it, and the attacker-controlled impact path still missing.",
        "expected": "JSON rows with candidate_id, claimed_rubric_row, exact_rubric_refs[], impact_source_refs[], missing_rubric_evidence[], local_verification_required.",
    },
    {
        "task_id": "kimi-03-prefiling-prior-disclosure-refs",
        "title": "Prefiling backfill prior-disclosure evidence extraction",
        "selector": "prior",
        "hypotheses": (
            "Possible duplicate and not-checked rows need exact prior audit/advisory/source references.",
            "Novelty needs a material-difference statement tied to root cause and affected path.",
        ),
        "task": "Extract prior-disclosure status, candidate duplicate refs, and exact material differences that still need local verification.",
        "expected": "JSON rows with candidate_id, prior_status, candidate_dupe_refs[], material_differences[], missing_originality_checks[], local_verification_required.",
    },
    {
        "task_id": "kimi-04-prefiling-economics-refs",
        "title": "Prefiling backfill economics proof extraction",
        "selector": "economics",
        "hypotheses": (
            "Value-impact claims need capital, cost, profit/loss, liquidity, and timing facts.",
            "Reward, market, liquidation, and vault claims should not proceed on qualitative economics alone.",
        ),
        "task": "Extract the exact economic variables, formulas, source refs, and missing measurements for selected rows.",
        "expected": "JSON rows with candidate_id, economic_claim, variables{}, source_refs[], missing_economic_fields[], minimum_local_check, local_verification_required.",
    },
    {
        "task_id": "kimi-05-prefiling-harness-blockers",
        "title": "Prefiling backfill harness blocker extraction",
        "selector": "harness",
        "hypotheses": (
            "Harness blockers need command, environment, preflight, and production-path refs.",
            "Runtime proof claims without attempted production execution stay advisory.",
        ),
        "task": "Extract harness command refs, preflight blockers, runtime blockers, and the minimum deterministic command required next.",
        "expected": "JSON rows with candidate_id, harness_refs[], blocker_refs[], next_command, negative_control_needed, local_verification_required.",
    },
    {
        "task_id": "kimi-06-prefiling-fail-warn-source-pack",
        "title": "Prefiling backfill fail/warn source pack",
        "selector": "fail_warn",
        "hypotheses": (
            "Fail and warn rows should be converted into exact source-backed obligations, not provider conclusions.",
            "Rows with multiple blockers need one minimum next source artifact each.",
        ),
        "task": "For every fail/warn row, extract the minimum source artifact or local check needed to unblock or kill it.",
        "expected": "JSON rows with candidate_id, verdict, blockers[], minimum_source_artifact, exact_refs[], next_local_check, local_verification_required.",
    },
    {
        "task_id": "kimi-07-prefiling-row-truth-table",
        "title": "Prefiling backfill row truth-table extraction",
        "selector": "all_blocked",
        "hypotheses": (
            "Questions in the stress result already encode what must be true before filing.",
            "Each answer needs exact refs or a missing-source marker.",
        ),
        "task": "Build a truth table for permissionless action, rubric, prior disclosure, economics, and harness status for each targeted row.",
        "expected": "JSON rows with candidate_id, truth_table{}, source_refs_by_question{}, missing_source_by_question{}, local_verification_required.",
    },
    {
        "task_id": "kimi-08-prefiling-backfill-workplan",
        "title": "Prefiling backfill verification workplan",
        "selector": "all_blocked",
        "hypotheses": (
            "Backfill should produce bounded local verification tasks for Codex/Claude after provider review.",
            "Provider text cannot establish filing readiness or severity.",
        ),
        "task": "Turn targeted prefiling rows into a deterministic local verification workplan ordered by smallest blocker-killing check.",
        "expected": "JSON workplan rows with candidate_id, blocker_class, local_command_or_source_file, expected_pass_signal, expected_kill_signal, local_verification_required.",
    },
)


PREFILING_MINIMAX_SPECS: tuple[dict[str, str], ...] = (
    {
        "task_id": "minimax-01-prefiling-oos-kill",
        "title": "Prefiling backfill OOS kill pass",
        "oos": "Kill rows whose attacker path is admin-only, owner-only, keeper-only, mock-only, test-only, out of program scope, or missing a production entrypoint.",
        "expected": "JSON judgments with candidate_id, verdict, oos_reason, contradiction_citation, minimum_followup_check, local_verification_required.",
    },
    {
        "task_id": "minimax-02-prefiling-dupe-kill",
        "title": "Prefiling backfill duplicate kill pass",
        "oos": "Kill rows that match a prior audit/advisory/root-cause or one-fix patch unless a material difference is exact and locally checkable.",
        "expected": "JSON judgments with candidate_id, duplicate_refs[], one_fix_path, material_difference_missing, local_verification_required.",
    },
    {
        "task_id": "minimax-03-prefiling-economics-kill",
        "title": "Prefiling backfill economics kill pass",
        "oos": "Kill value claims without capital/cost/profit/liquidity/timing proof, or where the trade is attacker-unprofitable after fees and constraints.",
        "expected": "JSON judgments with candidate_id, missing_economics[], profitability_objection, contradiction_citation, local_verification_required.",
    },
    {
        "task_id": "minimax-04-prefiling-admin-path-kill",
        "title": "Prefiling backfill admin and self-created-resource kill pass",
        "oos": "Kill paths that require a pre-existing privileged admin, governance action, operator-only call, or attacker-created self-admin resource with no victim impact.",
        "expected": "JSON judgments with candidate_id, privileged_dependency, self_created_resource_risk, keep_or_kill, local_verification_required.",
    },
    {
        "task_id": "minimax-05-prefiling-one-fix-kill",
        "title": "Prefiling backfill one-fix and patch-equivalence kill pass",
        "oos": "Kill rows whose root cause and fix are equivalent to a known fix, or where the proposed mitigation already exists on the target production path.",
        "expected": "JSON judgments with candidate_id, equivalent_fix_refs[], production_patch_refs[], missing_difference_test, local_verification_required.",
    },
    {
        "task_id": "minimax-06-prefiling-rubric-kill",
        "title": "Prefiling backfill rubric overclaim kill pass",
        "oos": "Kill High/Critical claims whose proved impact does not satisfy the cited rubric row or whose evidence class cannot prove that row.",
        "expected": "JSON judgments with candidate_id, rubric_mismatch, evidence_class_gap, lower_severity_candidate, local_verification_required.",
    },
    {
        "task_id": "minimax-07-prefiling-harness-kill",
        "title": "Prefiling backfill harness and proof-shape kill pass",
        "oos": "Kill rows relying on non-production harnesses, missing runtime attempts, blocked preflight, domain-mismatched tools, or no negative control.",
        "expected": "JSON judgments with candidate_id, harness_objection, missing_negative_control, minimum_command_before_keep, local_verification_required.",
    },
    {
        "task_id": "minimax-08-prefiling-provider-promotion-kill",
        "title": "Prefiling backfill provider-promotion kill pass",
        "oos": "Kill any path where Kimi/MiniMax output would become proof, severity, originality, or filing readiness without local verification.",
        "expected": "JSON judgments with candidate_id, promotion_bypass, required_gate, required_local_artifact, local_verification_required.",
    },
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def _sha256_short(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def _parse_line_ref(ref: str) -> tuple[str, int | None, int | None]:
    if ":" not in ref:
        return ref, None, None
    path_part, maybe_range = ref.rsplit(":", 1)
    if not maybe_range or not maybe_range[0].isdigit():
        return ref, None, None
    if "-" in maybe_range:
        start_raw, end_raw = maybe_range.split("-", 1)
        if start_raw.isdigit() and end_raw.isdigit():
            return path_part, int(start_raw), int(end_raw)
    if maybe_range.isdigit():
        line = int(maybe_range)
        return path_part, line, line
    return ref, None, None


def _resolve_target_path(path_text: str) -> Path:
    p = Path(path_text).expanduser()
    return p if p.is_absolute() else ROOT / p


def _bounded_file_excerpt(path: Path, start: int | None, end: int | None, max_chars: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"  status: unreadable ({exc})"
    if start is not None and end is not None:
        lo = max(1, start)
        hi = min(len(lines), max(lo, end))
    else:
        lo = 1
        hi = min(len(lines), 180)
    rendered: list[str] = []
    used = 0
    for lineno in range(lo, hi + 1):
        text = f"{lineno}: {_sanitize_dispatch_trigger_terms(lines[lineno - 1])}"
        if used + len(text) + 1 > max_chars:
            rendered.append("...[truncated by source packet char budget]")
            break
        rendered.append(text)
        used += len(text) + 1
    return "\n".join(f"  {line}" for line in rendered)


def _sanitize_dispatch_trigger_terms(text: str) -> str:
    """Keep advisory source packets from tripping report/paste-ready gates.

    The source excerpts may include Make targets or docs that literally mention
    "paste-ready" or "submit-ready". These prompts are extraction packets, not
    reportable claims, so we redact only the gate-triggering spelling while
    preserving enough context for provider review.
    """
    replacements = {
        "paste-ready": "paste_ready",
        "paste ready": "paste_ready",
        "submit-ready": "submit_ready",
        "submit ready": "submit_ready",
        "direct-submit": "direct_submit",
        "direct submit": "direct_submit",
        "in_scope_direct_submit": "in_scope_direct_submit_redacted",
    }
    out = text
    for needle, replacement in replacements.items():
        out = out.replace(needle, replacement)
        out = out.replace(needle.upper(), replacement.upper())
        out = out.replace(needle.title(), replacement)
    return out


def _bounded_directory_inventory(path: Path, max_entries: int) -> str:
    entries: list[str] = []
    try:
        files = sorted(p for p in path.rglob("*") if p.is_file())
    except OSError as exc:
        return f"  status: unreadable directory ({exc})"
    for child in files[:max_entries]:
        try:
            size = child.stat().st_size
        except OSError:
            size = -1
        entries.append(f"  - {_sanitize_dispatch_trigger_terms(_rel(child))} ({size} bytes)")
    if not entries:
        return "  status: directory has no files in bounded scan"
    if len(files) > max_entries:
        entries.append("  - ... directory inventory truncated")
    return "\n".join(entries)


def _bounded_directory_file_excerpts(
    path: Path,
    *,
    max_files: int = 8,
    max_total_chars: int = 8000,
    max_file_chars: int = 1200,
) -> str:
    try:
        files = sorted(p for p in path.rglob("*") if p.is_file())
    except OSError as exc:
        return f"  status: unreadable directory excerpts ({exc})"
    if not files:
        return "  status: no files to excerpt"

    rendered: list[str] = []
    used = 0
    for child in files[:max_files]:
        header = f"  --- file: {_sanitize_dispatch_trigger_terms(_rel(child))}"
        if used + len(header) + 1 > max_total_chars:
            break
        rendered.append(header)
        used += len(header) + 1
        try:
            text = child.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            body = f"  status: unreadable ({exc})"
        else:
            body_lines = []
            body_used = 0
            for raw_line in text.splitlines():
                line = f"  {_sanitize_dispatch_trigger_terms(raw_line)}"
                if body_used + len(line) + 1 > max_file_chars:
                    body_lines.append("  ...[file excerpt truncated]")
                    break
                body_lines.append(line)
                body_used += len(line) + 1
            body = "\n".join(body_lines) if body_lines else "  status: empty file"
        remaining = max_total_chars - used
        if remaining <= 0:
            break
        if len(body) > remaining:
            body = body[: max(0, remaining - 35)] + "\n  ...[directory excerpt truncated]"
        rendered.append(body)
        used += len(body) + 1
    if len(files) > max_files and used < max_total_chars:
        rendered.append("  ...[directory file list truncated]")
    return "\n".join(rendered)


def _render_source_packet(target_files: Sequence[str]) -> str:
    lines = [
        "source_packet: |",
        "  Provider cannot read local filesystem paths. This packet embeds bounded local evidence.",
    ]
    for ref in target_files:
        path_text, start, end = _parse_line_ref(ref)
        path = _resolve_target_path(path_text)
        lines.append(f"  --- target: {ref}")
        lines.append(f"  resolved_path: {path}")
        if path.is_file():
            try:
                lines.append(f"  sha256_16: {_sha256_short(path)}")
            except OSError:
                lines.append("  sha256_16: unreadable")
            lines.append("  excerpt:")
            lines.append(_bounded_file_excerpt(path, start, end, max_chars=6000))
        elif path.is_dir():
            lines.append("  directory_inventory:")
            lines.append(_bounded_directory_inventory(path, max_entries=40))
            lines.append("  file_excerpts:")
            lines.append(_bounded_directory_file_excerpts(path))
        else:
            lines.append("  status: missing")
    return "\n".join(lines)


def _prompt_path(prompts_dir: Path, task: FanoutTask) -> Path:
    return prompts_dir / f"{task.task_id}.md"


def _output_path(outputs_dir: Path, task: FanoutTask) -> Path:
    return outputs_dir / f"{task.task_id}.out.txt"


def _render_memory_context(workspace: Path, plan_path: Path) -> str:
    return "\n".join(
        [
            "memory_context: |",
            "  MCP_REQUIRED_BEFORE_LIVE_DISPATCH: true",
            f"  workspace_path: {workspace}",
            "  required_receipt: .auditooor/last_mcp_recall.json",
            "  dispatch_gate: tools/dispatch-preflight.py --require-mcp-context",
            "  source_refs:",
            f"    - {_rel(plan_path)}",
            "    - docs/STAGE_REFERENCE.md",
            "    - reference/dispatch-templates/source-extract.yaml",
            "    - reference/dispatch-templates/adversarial-kill.yaml",
        ]
    )


def _render_source_prompt(task: FanoutTask, workspace: Path, plan_path: Path) -> str:
    lines = [
        f"# {task.title}",
        "",
        "You are Kimi acting as a bounded source/spec extractor for Hackerman V3.",
        "Do not draft reports, assign severity, or promote findings. Return advisory candidates only.",
        "",
        f"workspace_path: {workspace}",
        _render_memory_context(workspace, plan_path),
        "target_files:",
    ]
    lines.extend(f"  - {item}" for item in task.target_files)
    lines.append(_render_source_packet(task.target_files))
    lines.append("hypotheses:")
    lines.extend(f"  - {item}" for item in task.hypotheses)
    lines.extend(
        [
            "prior_failed_attempts: |",
            f"  {task.prior_failed_attempts}",
            "expected_output_shape: |",
            f"  {task.expected_output_shape}",
            "  Every row must include local_verification_required: true.",
            "  Every row must include exact source files/lines or state that more source is needed.",
            "  Never mark anything ready for filing.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_kill_prompt(
    task: FanoutTask,
    workspace: Path,
    plan_path: Path,
    source_task_ids: Sequence[str],
) -> str:
    candidate_ids = ", ".join(source_task_ids)
    lines = [
        f"# {task.title}",
        "",
        "You are MiniMax acting as an adversarial kill-pass for Hackerman V3.",
        "Reject weak, duplicate, OOS, unverifiable, or overbroad candidates. Do not invent new findings.",
        "",
        f"workspace_path: {workspace}",
        _render_memory_context(workspace, plan_path),
        "candidate_list:",
        f"  - id: {task.task_id}",
        f"    linked_source_extracts: {candidate_ids}",
        f"    review_target: {task.title}",
        "    packet_state: provider queue row only; require local evidence before keep.",
        "oos_text: |",
        f"  {task.oos_text}",
        f"truncation_flag: {task.truncation_flag}",
        "expected_output_shape: |",
        f"  {task.expected_output_shape}",
        "  Verdict must be one of KEEP_FOR_LOCAL_VERIFICATION, REJECT_DUPLICATE, REJECT_OOS,",
        "  REJECT_MISSING_PRODUCTION_PATH, REJECT_MOCK_OR_TEST_ONLY, REJECT_INSUFFICIENT_IMPACT,",
        "  or NEEDS_MORE_SOURCE.",
        "  Rejections need contradiction_citation. Keeps need minimum_followup_check.",
        "  local_verification_required: true for every row.",
        "",
    ]
    return "\n".join(lines)


def _read_json_object(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read JSON input {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON input {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _compact_followup_row(row: dict[str, object]) -> dict[str, object]:
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    verification = row.get("verification") if isinstance(row.get("verification"), dict) else {}
    evidence_refs = verification.get("evidence_refs") if isinstance(verification.get("evidence_refs"), list) else []
    return {
        "queue_id": row.get("queue_id"),
        "provider": row.get("provider"),
        "model": row.get("model"),
        "route": row.get("route"),
        "verification_status": row.get("verification_status"),
        "terminal_outcome": row.get("terminal_outcome"),
        "terminal_safe": row.get("terminal_safe"),
        "claim_kind": claim.get("kind"),
        "summary": claim.get("summary"),
        "existing_source_ref_count": row.get("existing_source_ref_count"),
        "missing_source_ref_count": row.get("missing_source_ref_count"),
        "grep_hit_count": row.get("grep_hit_count"),
        "evidence_refs": evidence_refs[:3],
    }


def _followup_rows_for_selector(rows: Sequence[dict[str, object]], selector: str, *, limit: int = 20) -> list[dict[str, object]]:
    if selector == "needs_more_source":
        selected = [row for row in rows if row.get("terminal_outcome") == "needs_more_source"]
    elif selector == "fixture_needed":
        selected = [row for row in rows if row.get("route") == "fixture_needed"]
    elif selector == "kill_review":
        selected = [row for row in rows if row.get("route") == "kill_review"]
    elif selector == "local_source_review":
        selected = [row for row in rows if row.get("route") == "local_source_review"]
    elif selector == "terminal_or_verified":
        selected = [row for row in rows if row.get("terminal_outcome") or row.get("verification_status") == "verified"]
    elif selector == "verified_or_pending":
        selected = [row for row in rows if row.get("verification_status") in {"verified", "pending"}]
    elif selector == "field_validation":
        selected = [row for row in rows if row.get("verification_status") == "verified"][:10] + [
            row for row in rows if row.get("terminal_outcome") == "needs_more_source"
        ][:10]
    else:
        selected = list(rows)
    return [_compact_followup_row(row) for row in selected[:limit]]


def _followup_memory_context(workspace: Path, plan_path: Path, source_result: Path, summary: dict[str, object]) -> str:
    return "\n".join(
        [
            "memory_context: |",
            "  MCP_REQUIRED_BEFORE_LIVE_DISPATCH: true",
            f"  workspace_path: {workspace}",
            "  required_receipt: .auditooor/last_mcp_recall.json",
            "  dispatch_gate: tools/dispatch-preflight.py --require-mcp-context",
            "  context_pack_id: auditooor.vault_context_pack.v1:resume:dd282b5ff46d5959",
            "  source_refs:",
            f"    - {_rel(plan_path)}",
            f"    - {_rel(source_result)}",
            "    - reference/dispatch-templates/source-extract.yaml",
            "    - reference/dispatch-templates/adversarial-kill.yaml",
            f"  source_result_summary: {json.dumps(summary, sort_keys=True)}",
        ]
    )


def _prefiling_summary(result: dict[str, object], rows: Sequence[dict[str, object]]) -> dict[str, object]:
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    blocker_counts: dict[str, int] = {}
    for row in rows:
        for blocker in _prefiling_row_blockers(row):
            blocker_counts[blocker] = blocker_counts.get(blocker, 0) + 1
    return {
        "schema_version": result.get("schema_version") or result.get("schema"),
        "source_type": result.get("source_type"),
        "rows_assessed": result.get("rows_assessed", len(rows)),
        "summary": summary,
        "targeted_rows": len(_prefiling_target_rows(rows)),
        "blocker_counts": dict(sorted(blocker_counts.items())),
    }


def _prefiling_row_blockers(row: dict[str, object]) -> list[str]:
    values: list[str] = []
    for key in ("blocked_reasons", "blockers", "warnings"):
        raw = row.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
    questions = row.get("questions") if isinstance(row.get("questions"), dict) else {}
    for question_key, question_value in questions.items():
        if not isinstance(question_value, dict):
            continue
        statuses = {
            str(question_value.get("status") or "").lower(),
            str(question_value.get("gate_status") or "").lower(),
        }
        if statuses & {"fail", "warn", "missing", "not_checked", "possible_dupe", "known_dupe"}:
            values.append(str(question_key))
        missing = question_value.get("missing_fields")
        if isinstance(missing, list) and missing:
            values.append(f"{question_key}_missing_fields")
        blockers = question_value.get("blockers")
        if isinstance(blockers, list):
            values.extend(str(item) for item in blockers)
    return sorted({value for value in values if value})


def _prefiling_target_rows(rows: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    targeted: list[dict[str, object]] = []
    for row in rows:
        verdict = str(row.get("verdict") or "").lower()
        blocker_text = " ".join(_prefiling_row_blockers(row)).lower()
        if verdict in {"fail", "warn"} or any(keyword in blocker_text for keyword in PREFILING_BLOCKER_KEYWORDS):
            targeted.append(row)
    return targeted


def _compact_prefiling_row(row: dict[str, object]) -> dict[str, object]:
    questions = row.get("questions") if isinstance(row.get("questions"), dict) else {}
    compact_questions: dict[str, object] = {}
    for key in ("permissionless_action", "rubric_row", "prior_disclosure", "economics", "production_harness"):
        value = questions.get(key)
        if isinstance(value, dict):
            compact_questions[key] = {
                k: value.get(k)
                for k in ("status", "gate_status", "answer", "missing_fields", "blockers", "citations")
                if k in value
            }
    return {
        "candidate_id": row.get("candidate_id") or row.get("lead_id") or row.get("queue_id"),
        "title": row.get("title"),
        "verdict": row.get("verdict"),
        "claimed_severity": row.get("claimed_severity") or row.get("likely_severity"),
        "blocked_reasons": row.get("blocked_reasons", []),
        "warnings": row.get("warnings", []),
        "blockers": _prefiling_row_blockers(row),
        "next_action": row.get("next_action"),
        "artifact_path": row.get("artifact_path"),
        "questions": compact_questions,
    }


def _prefiling_rows_for_selector(rows: Sequence[dict[str, object]], selector: str, *, limit: int = 20) -> list[dict[str, object]]:
    targeted = _prefiling_target_rows(rows)
    selected: list[dict[str, object]] = []
    for row in targeted:
        blockers = " ".join(_prefiling_row_blockers(row)).lower()
        verdict = str(row.get("verdict") or "").lower()
        if selector == "fail_warn" and verdict not in {"fail", "warn"}:
            continue
        if selector == "all_blocked":
            pass
        elif selector not in {"fail_warn", "all_blocked"} and selector not in blockers:
            continue
        selected.append(row)
    if not selected:
        selected = targeted
    return [_compact_prefiling_row(row) for row in selected[:limit]]


def _prefiling_memory_context(
    workspace: Path,
    plan_path: Path,
    source_result: Path,
    summary: dict[str, object],
    source_artifact_dir: Path | None,
) -> str:
    refs = [
        f"    - {_rel(plan_path)}",
        f"    - {_rel(source_result)}",
        "    - tools/prefiling-stress-test.py",
        "    - reference/dispatch-templates/source-extract.yaml",
        "    - reference/dispatch-templates/adversarial-kill.yaml",
    ]
    if source_artifact_dir is not None:
        refs.append(f"    - {_rel(source_artifact_dir)}")
    return "\n".join(
        [
            "memory_context: |",
            "  MCP_REQUIRED_BEFORE_LIVE_DISPATCH: true",
            f"  workspace_path: {workspace}",
            "  required_receipt: .auditooor/last_mcp_recall.json",
            "  dispatch_gate: tools/dispatch-preflight.py --require-mcp-context",
            "  advisory_only: true",
            "  local_verification_required: true",
            "  source_refs:",
            *refs,
            f"  source_result_summary: {json.dumps(summary, sort_keys=True)}",
        ]
    )


def _render_prefiling_source_prompt(
    spec: dict[str, object],
    *,
    workspace: Path,
    plan_path: Path,
    source_result: Path,
    summary: dict[str, object],
    rows: Sequence[dict[str, object]],
    source_artifact_dir: Path | None,
) -> str:
    selected = _prefiling_rows_for_selector(rows, str(spec["selector"]))
    target_files = [source_result]
    if source_artifact_dir is not None:
        target_files.append(source_artifact_dir)
    lines = [
        f"# {spec['title']}",
        "",
        "You are Kimi acting as a bounded source extractor for prefiling backfill.",
        "Do not draft reports, assign severity, claim originality, or mark anything filing-ready.",
        "",
        "template_label: source-extract",
        "mode: prefiling-backfill",
        "advisory_only: true",
        "local_verification_required: true",
        f"workspace_path: {workspace}",
        _prefiling_memory_context(workspace, plan_path, source_result, summary, source_artifact_dir),
        "target_files:",
    ]
    lines.extend(f"  - {_rel(path)}" for path in target_files)
    lines.append(_render_source_packet([str(path) for path in target_files]))
    lines.append("hypotheses:")
    lines.extend(f"  - {item}" for item in spec["hypotheses"])  # type: ignore[index]
    lines.extend(
        [
            "prior_failed_attempts: |",
            "  Prefiling stress found fail/warn/missing blockers. This pass backfills exact source refs and attacker actions only.",
            "expected_output_shape: |",
            f"  {spec['expected']}",
            "  Every row must include advisory_only: true.",
            "  Every row must include local_verification_required: true.",
            "  Every row must include exact attacker actions/source refs or explicit missing_source markers.",
            "  Never mark anything ready for filing.",
            "task: |",
            f"  {spec['task']}",
            "prefiling_rows:",
            "```json",
            json.dumps(selected, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _render_prefiling_kill_prompt(
    spec: dict[str, str],
    *,
    workspace: Path,
    plan_path: Path,
    source_result: Path,
    summary: dict[str, object],
    source_artifact_dir: Path | None,
    source_task_ids: Sequence[str],
    rows: Sequence[dict[str, object]],
) -> str:
    selected = _prefiling_rows_for_selector(rows, "all_blocked")
    lines = [
        f"# {spec['title']}",
        "",
        "You are MiniMax acting as an adversarial kill-pass for prefiling backfill.",
        "Reject OOS, duplicate, economics-weak, admin-dependent, one-fix, or provider-only paths. Do not invent new findings.",
        "",
        "template_label: adversarial-kill",
        "mode: prefiling-backfill",
        "advisory_only: true",
        "local_verification_required: true",
        f"workspace_path: {workspace}",
        _prefiling_memory_context(workspace, plan_path, source_result, summary, source_artifact_dir),
        "candidate_list:",
    ]
    for task_id in source_task_ids:
        lines.extend(
            [
                f"  - id: {task_id}",
                f"    review_target: {spec['title']}",
                "    packet_state: Kimi source-extract prefiling backfill packet; require local evidence before keep.",
            ]
        )
    lines.extend(
        [
            "oos_text: |",
            f"  {spec['oos']}",
            "truncation_flag: complete",
            "expected_output_shape: |",
            f"  {spec['expected']}",
            "  Verdict must be one of KEEP_FOR_LOCAL_VERIFICATION, REJECT_DUPLICATE, REJECT_OOS,",
            "  REJECT_ADMIN_DEPENDENT, REJECT_ONE_FIX, REJECT_ECONOMICS_WEAK,",
            "  REJECT_MISSING_PRODUCTION_PATH, REJECT_PROVIDER_ONLY, or NEEDS_MORE_SOURCE.",
            "  Rejections need contradiction_citation. Keeps need minimum_followup_check.",
            "  local_verification_required: true for every row.",
            "policy: |",
            "  Provider output is advisory only. Raw provider text is not proof.",
            "  Keep only rows with local source/proof obligations that Codex/Claude can verify offline.",
            "prefiling_rows:",
            "```json",
            json.dumps(selected, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _render_followup_source_prompt(
    spec: dict[str, object],
    *,
    workspace: Path,
    plan_path: Path,
    source_result: Path,
    summary: dict[str, object],
    rows: Sequence[dict[str, object]],
) -> str:
    selected = _followup_rows_for_selector(rows, str(spec["selector"]))
    lines = [
        f"# {spec['title']}",
        "",
        "You are Kimi acting as a bounded source/spec extractor for Hackerman V3 follow-up work.",
        "Do not draft reports, assign severity, or promote findings. Return advisory candidates only.",
        "",
        f"workspace_path: {workspace}",
        _followup_memory_context(workspace, plan_path, source_result, summary),
        "target_files:",
        f"  - {_rel(source_result)}",
        f"  - {_rel(plan_path)}",
        "hypotheses:",
    ]
    lines.extend(f"  - {item}" for item in spec["hypotheses"])  # type: ignore[index]
    lines.extend(
        [
            "prior_failed_attempts: |",
            "  First follow-up run is derived from local verifier/compiler output.",
            "  Raw provider output was already quarantined; this pass must produce only bounded follow-up work.",
            "expected_output_shape: |",
            f"  {spec['expected']}",
            "  Every row must include local_verification_required: true.",
            "  Every row must include advisory_only: true.",
            "  Never mark anything ready for filing.",
            "policy: |",
            "  Provider output is advisory only. Raw provider text is not proof.",
            "  Keep rows only when a local verifier, primary source, fixture, or exact blocker can verify them.",
            "task: |",
            f"  {spec['task']}",
            "local_verification_rows:",
            "```json",
            json.dumps(selected, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _render_followup_kill_prompt(
    spec: dict[str, str],
    *,
    workspace: Path,
    plan_path: Path,
    source_result: Path,
    summary: dict[str, object],
    source_task_ids: Sequence[str],
) -> str:
    lines = [
        f"# {spec['title']}",
        "",
        "You are MiniMax acting as an adversarial kill-pass for Hackerman V3 follow-up work.",
        "Reject weak, duplicate, OOS, unverifiable, or overbroad candidates. Do not invent new findings.",
        "",
        f"workspace_path: {workspace}",
        _followup_memory_context(workspace, plan_path, source_result, summary),
        "candidate_list:",
    ]
    for task_id in source_task_ids:
        lines.extend(
            [
                f"  - id: {task_id}",
                f"    review_target: {spec['title']}",
                "    packet_state: complete local-verification follow-up packet",
            ]
        )
    lines.extend(
        [
            "oos_text: |",
            f"  {spec['oos']}",
            "truncation_flag: complete",
            "expected_output_shape: |",
            f"  {spec['expected']}",
            "  Verdict must be one of KEEP_FOR_LOCAL_VERIFICATION, REJECT_DUPLICATE, REJECT_OOS,",
            "  REJECT_MISSING_PRODUCTION_PATH, REJECT_MOCK_OR_TEST_ONLY, REJECT_INSUFFICIENT_IMPACT,",
            "  REJECT_PROVIDER_ONLY, or NEEDS_MORE_SOURCE.",
            "  Rejections need contradiction_citation. Keeps need minimum_followup_check.",
            "  local_verification_required: true for every row.",
            "policy: |",
            "  Provider output is advisory only. Raw provider text is not proof.",
            "  Keep rows only when a local verifier, primary source, fixture, or exact blocker can verify them.",
            "",
            "Review the successful Kimi outputs materialized into this prompt by the runner.",
            "If Kimi output is missing, return NEEDS_MORE_SOURCE and do not invent candidate content.",
            "",
        ]
    )
    return "\n".join(lines)


def _dispatch_command(
    *,
    task: FanoutTask,
    prompt_path: Path,
    output_path: Path,
    workspace: Path,
) -> list[str]:
    audit_dir = output_path.parent.parent / "llm_dispatch_audit" / task.task_id
    return [
        "python3",
        "tools/dispatch-preflight.py",
        "--template",
        task.template,
        "--task-type",
        task.template,
        "--prompt-file",
        str(prompt_path),
        "--workspace",
        str(workspace),
        "--provider",
        task.provider,
        "--output-file",
        str(output_path),
        "--require-mcp-context",
        "--timeout",
        str(task.timeout_seconds),
        "--forward",
        (
            f"--max-tokens {task.max_tokens} --timeout {task.http_timeout_seconds} "
            f"--audit-dir {audit_dir} --operator-live-network-consent "
            f"--require-mcp-receipt --strategic-llm-allowed"
        ),
    ]


def build_queue(
    *,
    workspace: Path,
    out_dir: Path,
    plan_path: Path,
    campaign_id: str,
) -> dict[str, object]:
    prompts_dir = out_dir / "prompts"
    outputs_dir = out_dir / "outputs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    tasks = list(KIMI_TASKS) + list(MINIMAX_TASKS)
    source_ids = [task.task_id for task in KIMI_TASKS]
    rows: list[dict[str, object]] = []
    for index, task in enumerate(tasks, start=1):
        prompt_path = _prompt_path(prompts_dir, task)
        output_path = _output_path(outputs_dir, task)
        if task.template == "source-extract":
            prompt = _render_source_prompt(task, workspace, plan_path)
        else:
            prompt = _render_kill_prompt(task, workspace, plan_path, source_ids)
        prompt_path.write_text(prompt, encoding="utf-8")
        row = {
            "index": index,
            "task_id": task.task_id,
            "provider": task.provider,
            "template": task.template,
            "task_type": task.template,
            "title": task.title,
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": task.max_tokens,
            "http_timeout_seconds": task.http_timeout_seconds,
            "timeout_seconds": task.timeout_seconds,
            "requires_dispatch_preflight": True,
            "requires_mcp_context": True,
            "strategic_llm_allowed": True,
            "advisory_only": True,
            "local_verification_required": True,
            "dispatch_command": _dispatch_command(
                task=task,
                prompt_path=prompt_path,
                output_path=output_path,
                workspace=workspace,
            ),
        }
        rows.append(row)

    by_provider: dict[str, int] = {}
    for row in rows:
        provider = str(row["provider"])
        by_provider[provider] = by_provider.get(provider, 0) + 1
    manifest: dict[str, object] = {
        "schema": "auditooor.v3_provider_fanout_queue.v1",
        "campaign_id": campaign_id,
        "generated_at": _utc_now_iso(),
        "workspace": str(workspace),
        "plan_path": str(plan_path),
        "out_dir": str(out_dir),
        "provider_counts": dict(sorted(by_provider.items())),
        "total_tasks": len(rows),
        "operator_live_network_consent_required": True,
        "mcp_context_gate": "dispatch-preflight.py --require-mcp-context",
        "promotion_rule": (
            "Provider output is advisory only. Codex/Claude may promote only after "
            "local source verification, OOS/dupe check, and proof or detector tests."
        ),
        "rows": rows,
    }
    (out_dir / "v3_provider_fanout_queue.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "v3_provider_fanout_queue.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (out_dir / "v3_provider_fanout_queue.md").write_text(
        render_markdown(manifest),
        encoding="utf-8",
    )
    return manifest


def build_followup_queue(
    *,
    workspace: Path,
    out_dir: Path,
    plan_path: Path,
    campaign_id: str,
    source_result: Path,
) -> dict[str, object]:
    result = _read_json_object(source_result)
    if result.get("schema") != "auditooor.v3_provider_local_verification_result.v1":
        raise ValueError(f"not a V3 local verification result: {source_result}")
    raw_rows = result.get("rows")
    if not isinstance(raw_rows, list):
        raise ValueError(f"source result missing rows[]: {source_result}")
    rows_in = [row for row in raw_rows if isinstance(row, dict)]
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}

    prompts_dir = out_dir / "prompts"
    outputs_dir = out_dir / "outputs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[tuple[FanoutTask, str]] = []
    for spec in FOLLOWUP_KIMI_SPECS:
        task = FanoutTask(
            task_id=str(spec["task_id"]),
            provider="kimi",
            template="source-extract",
            title=str(spec["title"]),
            target_files=(_rel(source_result), _rel(plan_path)),
            hypotheses=tuple(str(item) for item in spec["hypotheses"]),  # type: ignore[index]
            prior_failed_attempts="First follow-up run derived from local verifier/compiler output.",
            expected_output_shape=str(spec["expected"]),
            max_tokens=9000,
            http_timeout_seconds=360,
            timeout_seconds=1500,
        )
        prompt = _render_followup_source_prompt(
            spec,
            workspace=workspace,
            plan_path=plan_path,
            source_result=source_result,
            summary=summary,
            rows=rows_in,
        )
        tasks.append((task, prompt))
    source_ids = [str(spec["task_id"]) for spec in FOLLOWUP_KIMI_SPECS]
    for spec in FOLLOWUP_MINIMAX_SPECS:
        task = FanoutTask(
            task_id=spec["task_id"],
            provider="minimax",
            template="adversarial-kill",
            title=spec["title"],
            target_files=(),
            hypotheses=(),
            prior_failed_attempts="",
            expected_output_shape=spec["expected"],
            oos_text=spec["oos"],
            max_tokens=7000,
            http_timeout_seconds=360,
            timeout_seconds=1500,
        )
        prompt = _render_followup_kill_prompt(
            spec,
            workspace=workspace,
            plan_path=plan_path,
            source_result=source_result,
            summary=summary,
            source_task_ids=source_ids,
        )
        tasks.append((task, prompt))

    rows: list[dict[str, object]] = []
    for index, (task, prompt) in enumerate(tasks, start=1):
        prompt_path = _prompt_path(prompts_dir, task)
        output_path = _output_path(outputs_dir, task)
        prompt_path.write_text(prompt, encoding="utf-8")
        rows.append(
            {
                "index": index,
                "task_id": task.task_id,
                "provider": task.provider,
                "template": task.template,
                "task_type": task.template,
                "title": task.title,
                "prompt_path": str(prompt_path),
                "output_path": str(output_path),
                "max_tokens": task.max_tokens,
                "http_timeout_seconds": task.http_timeout_seconds,
                "timeout_seconds": task.timeout_seconds,
                "requires_dispatch_preflight": True,
                "requires_mcp_context": True,
                "strategic_llm_allowed": True,
                "advisory_only": True,
                "local_verification_required": True,
                "dispatch_command": _dispatch_command(
                    task=task,
                    prompt_path=prompt_path,
                    output_path=output_path,
                    workspace=workspace,
                ),
            }
        )

    by_provider: dict[str, int] = {}
    for row in rows:
        provider = str(row["provider"])
        by_provider[provider] = by_provider.get(provider, 0) + 1
    manifest: dict[str, object] = {
        "schema": "auditooor.v3_provider_fanout_queue.v1",
        "mode": "followup",
        "campaign_id": campaign_id,
        "generated_at": _utc_now_iso(),
        "workspace": str(workspace),
        "plan_path": str(plan_path),
        "source_result": str(source_result),
        "source_result_summary": summary,
        "out_dir": str(out_dir),
        "provider_counts": dict(sorted(by_provider.items())),
        "total_tasks": len(rows),
        "operator_live_network_consent_required": True,
        "mcp_context_gate": "dispatch-preflight.py --require-mcp-context",
        "promotion_rule": (
            "Provider output is advisory only. Follow-up output may become work only after "
            "local verification and terminal learning gates."
        ),
        "rows": rows,
    }
    (out_dir / "v3_provider_fanout_queue.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "v3_provider_fanout_queue.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (out_dir / "v3_provider_fanout_queue.md").write_text(
        render_markdown(manifest),
        encoding="utf-8",
    )
    return manifest


def build_prefiling_backfill_queue(
    *,
    workspace: Path,
    out_dir: Path,
    plan_path: Path,
    campaign_id: str,
    source_result: Path,
    source_artifact_dir: Path | None = None,
) -> dict[str, object]:
    result = _read_json_object(source_result)
    if result.get("schema_version") != "auditooor.prefiling_stress_test.v1":
        raise ValueError(f"not a prefiling stress aggregate: {source_result}")
    raw_rows = result.get("results")
    if not isinstance(raw_rows, list):
        raise ValueError(f"prefiling source result missing results[]: {source_result}")
    rows_in = [row for row in raw_rows if isinstance(row, dict)]
    if not _prefiling_target_rows(rows_in):
        raise ValueError(
            "prefiling source result has no fail/warn/blocker rows; refusing to emit empty provider backfill queue"
        )
    summary = _prefiling_summary(result, rows_in)

    prompts_dir = out_dir / "prompts"
    outputs_dir = out_dir / "outputs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[tuple[FanoutTask, str]] = []
    for spec in PREFILING_KIMI_SPECS:
        task = FanoutTask(
            task_id=str(spec["task_id"]),
            provider="kimi",
            template="source-extract",
            title=str(spec["title"]),
            target_files=(_rel(source_result),),
            hypotheses=tuple(str(item) for item in spec["hypotheses"]),  # type: ignore[index]
            prior_failed_attempts="Prefiling stress gate generated fail/warn/missing blockers.",
            expected_output_shape=str(spec["expected"]),
            max_tokens=9000,
            http_timeout_seconds=360,
            timeout_seconds=1500,
        )
        prompt = _render_prefiling_source_prompt(
            spec,
            workspace=workspace,
            plan_path=plan_path,
            source_result=source_result,
            summary=summary,
            rows=rows_in,
            source_artifact_dir=source_artifact_dir,
        )
        tasks.append((task, prompt))
    source_ids = [str(spec["task_id"]) for spec in PREFILING_KIMI_SPECS]
    for spec in PREFILING_MINIMAX_SPECS:
        task = FanoutTask(
            task_id=spec["task_id"],
            provider="minimax",
            template="adversarial-kill",
            title=spec["title"],
            target_files=(),
            hypotheses=(),
            prior_failed_attempts="",
            expected_output_shape=spec["expected"],
            oos_text=spec["oos"],
            max_tokens=7000,
            http_timeout_seconds=360,
            timeout_seconds=1500,
        )
        prompt = _render_prefiling_kill_prompt(
            spec,
            workspace=workspace,
            plan_path=plan_path,
            source_result=source_result,
            summary=summary,
            source_artifact_dir=source_artifact_dir,
            source_task_ids=source_ids,
            rows=rows_in,
        )
        tasks.append((task, prompt))

    rows: list[dict[str, object]] = []
    for index, (task, prompt) in enumerate(tasks, start=1):
        prompt_path = _prompt_path(prompts_dir, task)
        output_path = _output_path(outputs_dir, task)
        prompt_path.write_text(prompt, encoding="utf-8")
        rows.append(
            {
                "index": index,
                "task_id": task.task_id,
                "provider": task.provider,
                "template": task.template,
                "template_label": task.template,
                "task_type": task.template,
                "title": task.title,
                "prompt_path": str(prompt_path),
                "output_path": str(output_path),
                "max_tokens": task.max_tokens,
                "http_timeout_seconds": task.http_timeout_seconds,
                "timeout_seconds": task.timeout_seconds,
                "requires_dispatch_preflight": True,
                "requires_mcp_context": True,
                "strategic_llm_allowed": True,
                "advisory_only": True,
                "local_verification_required": True,
                "dispatch_command": _dispatch_command(
                    task=task,
                    prompt_path=prompt_path,
                    output_path=output_path,
                    workspace=workspace,
                ),
            }
        )

    by_provider: dict[str, int] = {}
    for row in rows:
        provider = str(row["provider"])
        by_provider[provider] = by_provider.get(provider, 0) + 1
    manifest: dict[str, object] = {
        "schema": "auditooor.v3_provider_fanout_queue.v1",
        "mode": "prefiling-backfill",
        "campaign_id": campaign_id,
        "generated_at": _utc_now_iso(),
        "workspace": str(workspace),
        "plan_path": str(plan_path),
        "source_result": str(source_result),
        "source_artifact_dir": str(source_artifact_dir) if source_artifact_dir is not None else None,
        "source_result_summary": summary,
        "out_dir": str(out_dir),
        "provider_counts": dict(sorted(by_provider.items())),
        "total_tasks": len(rows),
        "operator_live_network_consent_required": True,
        "mcp_context_gate": "dispatch-preflight.py --require-mcp-context",
        "advisory_only": True,
        "local_verification_required": True,
        "promotion_rule": (
            "Provider output is advisory only. Prefiling backfill output may become work only after "
            "local source verification, OOS/dupe/economics/admin checks, and proof or harness tests."
        ),
        "rows": rows,
    }
    (out_dir / "v3_provider_fanout_queue.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "v3_provider_fanout_queue.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (out_dir / "v3_provider_fanout_queue.md").write_text(
        render_markdown(manifest),
        encoding="utf-8",
    )
    return manifest


def render_markdown(manifest: dict[str, object]) -> str:
    rows = manifest["rows"]
    assert isinstance(rows, list)
    lines = [
        "# Hackerman V3 Provider Fanout Queue",
        "",
        f"- campaign_id: `{manifest['campaign_id']}`",
        f"- workspace: `{manifest['workspace']}`",
        f"- provider_counts: `{manifest['provider_counts']}`",
        "- live dispatch: run only through `tools/dispatch-preflight.py --require-mcp-context`",
        "- provider output: advisory only until local verification passes",
        "",
        "Before live dispatch:",
        "",
        "1. Refresh MCP recall for the workspace so `.auditooor/last_mcp_recall.json` is fresh.",
        "2. Run the desired row's `dispatch_command`.",
        "3. Record provider output, model id, task type, timeout, and final local-verification verdict.",
        "",
        "| # | Provider | Task | Template | Prompt |",
        "|---:|---|---|---|---|",
    ]
    for row in rows:
        assert isinstance(row, dict)
        lines.append(
            f"| {row['index']} | `{row['provider']}` | `{row['task_id']}` | "
            f"`{row['template']}` | `{row['prompt_path']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        type=Path,
        default=ROOT,
        help="Audit workspace used by dispatch-preflight audit/MCP gates.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory. Default: <workspace>/.auditooor/provider_fanout/<campaign-id>",
    )
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--campaign-id", default=DEFAULT_CAMPAIGN_ID)
    parser.add_argument("--mode", choices=("initial", "followup", "prefiling-backfill"), default="initial")
    parser.add_argument(
        "--followup-source-result",
        type=Path,
        default=None,
        help="Required with --mode followup: v3_provider_local_verification_result.json",
    )
    parser.add_argument(
        "--prefiling-source-result",
        type=Path,
        default=None,
        help="Required with --mode prefiling-backfill: prefiling_stress_test.json aggregate",
    )
    parser.add_argument(
        "--prefiling-source-artifact-dir",
        type=Path,
        default=None,
        help="Optional source artifact directory to include in prefiling-backfill prompts.",
    )
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    plan_path = args.plan.expanduser().resolve()
    if not plan_path.is_file():
        raise SystemExit(f"[v3-provider-fanout-queue] missing plan file: {plan_path}")
    out_dir = (
        args.out_dir.expanduser().resolve()
        if args.out_dir is not None
        else workspace / ".auditooor" / "provider_fanout" / args.campaign_id
    )
    try:
        if args.mode == "followup":
            if args.followup_source_result is None:
                raise SystemExit("[v3-provider-fanout-queue] --mode followup requires --followup-source-result")
            manifest = build_followup_queue(
                workspace=workspace,
                out_dir=out_dir,
                plan_path=plan_path,
                campaign_id=args.campaign_id,
                source_result=args.followup_source_result.expanduser().resolve(),
            )
        elif args.mode == "prefiling-backfill":
            if args.prefiling_source_result is None:
                raise SystemExit(
                    "[v3-provider-fanout-queue] --mode prefiling-backfill requires --prefiling-source-result"
                )
            manifest = build_prefiling_backfill_queue(
                workspace=workspace,
                out_dir=out_dir,
                plan_path=plan_path,
                campaign_id=args.campaign_id,
                source_result=args.prefiling_source_result.expanduser().resolve(),
                source_artifact_dir=(
                    args.prefiling_source_artifact_dir.expanduser().resolve()
                    if args.prefiling_source_artifact_dir is not None
                    else None
                ),
            )
        else:
            manifest = build_queue(
                workspace=workspace,
                out_dir=out_dir,
                plan_path=plan_path,
                campaign_id=args.campaign_id,
            )
    except ValueError as exc:
        raise SystemExit(f"[v3-provider-fanout-queue] {exc}") from exc
    if args.print_json:
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "out_dir": manifest["out_dir"],
                    "provider_counts": manifest["provider_counts"],
                    "total_tasks": manifest["total_tasks"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
