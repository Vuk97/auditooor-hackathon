#!/usr/bin/env python3
# r36: lane AUTO-COVERAGE-CLOSER registered in .auditooor/agent_pathspec.json
"""auto-coverage-closer.py - generic, bounded ORCHESTRATOR that drives BOTH
coverage axes (SURFACE units + RUBRIC impact classes) to closure.

# This tool emits no corpus record.

WHAT IT DOES (the gap it fills)
-------------------------------
audit-run-full already has a PARTIAL surface-axis closer:
  coverage-to-hunt-seed.py  (UPSERT one unhunted-surface queue row per
    uncovered unit)
  -> coverage-source-scan   (exploit-queue-source-miner, cites each)
  -> hunt-coverage gate G15  (credits scanned units; self-heals via
    auto_seed_heal).

That chain closes the SURFACE axis at a COARSE "queued for a look" credit. The
remaining gaps this orchestrator closes:
  (a) no per-unit deterministic-hunter hypothesis/verdict (only coarse queued
      credit). This tool runs a BOUNDED DETERMINISTIC hunt per uncovered unit
      (per-function adversarial questions) and writes a per-unit verdict
      sidecar = ``mechanical-hunt-no-finding`` (NO attack_class/severity/claim)
      OR ``needs-llm-depth`` (questions emitted, no proven impact).
  (b) NO rubric/impact-class axis closer. rubric-coverage-workspace-check.py
      emits ``uncovered_rows`` (UNATTEMPTED impact classes) but nothing
      re-dispatches a hunt for them. This tool shells rubric-to-hunt-seed.py to
      seed one impact-class hunt brief per uncovered rubric row.
  (c) no bounded re-check loop. This tool runs --max-iters passes, re-building
      coverage + re-running the G15 gate + the rubric check each iter, and
      STOPS on fixpoint (effective_uncovered did not strictly decrease) OR
      coverage>=threshold OR max-iters. Never infinite-loops.
  (d) no residual worker-dispatch queue. This tool emits
      ``.auditooor/coverage_residual_worker_queue.json`` listing the units +
      impact classes that still need LLM depth after the mechanical passes.

IT DOES NOT
-----------
  - re-implement the existing tools: it SHELLS coverage-to-hunt-seed.py and
    rubric-to-hunt-seed.py, and IMPORTS hunt-coverage-gate.check +
    per-function-hacker-questions.gen_questions.
  - spawn Claude / LLM agents: the deterministic hunt is mechanical question
    generation + a re-scan; LLM depth is QUEUED for a worker, not invoked here.
  - attach any attack_class / severity / claim to a no-finding verdict (R80
    finding-evidence-honesty discipline). A ``mechanical-hunt-no-finding``
    verdict self-labels ``coverage_credit=mechanical-source-cited`` so it is
    explicitly NOT citable as an R80 PoC.

HONESTY (R76 / R80)
-------------------
  Per-unit verdicts are one of exactly two honest values:
    - ``mechanical-hunt-no-finding``: the deterministic pass generated zero
      adversarial questions for the unit (no invariant anchor) - records
      coverage credit ONLY, carries NO attack_class/severity/claim and is NOT
      citable as proof of safety OR of a bug.
    - ``needs-llm-depth``: the deterministic pass generated >=1 adversarial
      question but proved NOTHING - the unit needs an LLM-depth lane. The
      questions are recorded as hunt fuel; still NO proven impact.
  Neither verdict ever asserts a bug exists or a unit is safe.

Schema (--json verdict): auditooor.auto_coverage_closer.v1
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.auto_coverage_closer.v1"
TOOLS_DIR = Path(__file__).resolve().parent

COVERAGE_REPORT_REL = os.path.join(".auditooor", "coverage_report.json")
RUBRIC_REPORT_REL = os.path.join(".auditooor", "rubric_coverage_report.json")
PER_UNIT_VERDICT_DIR_REL = os.path.join(".auditooor", "coverage_unit_verdicts")
RESIDUAL_QUEUE_REL = os.path.join(".auditooor", "coverage_residual_worker_queue.json")
RESIDUAL_QUEUE_SCHEMA = "auditooor.coverage_residual_worker_queue.v1"
RUN_SNAPSHOT_REL = os.path.join(".auditooor", "auto_coverage_closer_last_result.json")

# Aggregate per-(unit, question) JSONL that the L37 hacker-questions gate
# (audit-completeness-check.check_hacker_questions) globs for at the .auditooor
# top level (per_fn_hacker_questions*). Folding the per-unit verdict sidecars
# into one JSONL credits the REAL adversarial questions the arsenal pass
# emitted. HONEST: questions only - no attack_class, severity, or claim.
# r36-rebuttal: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
PER_FN_HACKER_QUESTIONS_REL = os.path.join(
    ".auditooor", "per_fn_hacker_questions.jsonl"
)
PER_FN_HACKER_QUESTIONS_SCHEMA = "auditooor.per_fn_hacker_questions.v1"

# GENERIC language-detection-by-extension for the impact-methodology fold below.
# Any workspace whose in-scope units live under one of these extensions is
# eligible for impact-methodology stamping (Solidity AND Go/Rust/Move/Vyper/
# Cairo alike) - this is what makes the fold language-agnostic rather than a
# Solidity-only special case.
_IMPACT_FOLD_LANG_BY_EXT = {
    ".sol": "solidity", ".vy": "vyper", ".go": "go", ".rs": "rust",
    ".move": "move", ".cairo": "cairo",
}

# --------------------------------------------------------------------------
# function-anchor enrichment for the per_fn / lane folds
# --------------------------------------------------------------------------
# The two folds below (`_fold_per_fn_hacker_questions`,
# `_fold_lane_hypotheses_into_corpus`) historically wrote per_fn rows carrying
# only `unit_id` + `source_path` and NO `function_name`, `language`, line range
# or `excerpt`. Downstream (the batch/anchor builder + the obligation seeder)
# then had nothing to resolve, so every Go obligation surfaced as FN "?",
# LINE RANGE 0..0, "excerpt unavailable", language "unknown" (axelar-dlt:
# "125 of 138 open ... by language: unknown=125"), and workers had to bypass
# the anchor and read whole files. Populate a REAL anchor at the SOURCE fold so
# the Go per-fn path mirrors the Solidity/EVM path. Reuses the Go-receiver-aware
# excerpt resolver in per-fn-mimo-batch-gen.py (do NOT rebuild it - L10).
_PERFN_MIMO_BATCH_TOOL = Path(__file__).resolve().parent / "per-fn-mimo-batch-gen.py"
_PERFN_EXCERPT_MOD: Any | None = "unset"  # type: ignore[assignment]


def _perfn_excerpt_mod() -> Any | None:
    global _PERFN_EXCERPT_MOD
    if _PERFN_EXCERPT_MOD == "unset":
        _PERFN_EXCERPT_MOD = _import_by_path(
            "_acc_perfn_excerpt", _PERFN_MIMO_BATCH_TOOL)
    return _PERFN_EXCERPT_MOD


def _fn_name_from_unit(unit_id: str) -> str:
    """Extract the bare function name from a unit_id such as
    ``src/x/keeper/msg_server.go::ConfirmTransferKey`` or ``deductFee``.
    Mirrors _impact_methodology_rows_for_unit's derivation (rsplit `::` then
    `.`), so the enriched function_name is never the whole path::qualified id."""
    if not unit_id:
        return ""
    return unit_id.rsplit("::", 1)[-1].rsplit(".", 1)[-1].strip()


def _resolve_anchor_source(ws_path: Path, source_path: str) -> Path | None:
    """Resolve a possibly-relative (or trailing ``:line``) source_path to an
    on-disk file under the workspace. Language-agnostic."""
    if not source_path:
        return None
    raw = str(source_path)
    # tolerate a trailing ':line' anchor the caller may not have split.
    if ":" in raw:
        head, _, tail = raw.rpartition(":")
        if head and tail.isdigit():
            raw = head
    p = Path(raw)
    if p.is_absolute() and p.is_file():
        return p
    cand = ws_path / raw
    if cand.is_file():
        return cand
    return p if p.is_file() else None


def _enrich_fn_anchor(ws_path: Path, unit_id: str, source_path: str) -> dict:
    """Return the function-anchor metadata a per_fn obligation must carry:
    ``function_name`` (bare, non-"?"), ``language`` (by extension, never
    "unknown" for a recognised source), and - when the definition site can be
    located - ``line_start``/``line_end``/``file_line``/``excerpt``. Best
    effort: always populates function_name + language; the line range/excerpt
    are added only when the resolver finds the definition site."""
    fn = _fn_name_from_unit(str(unit_id or ""))
    ext = Path(str(source_path or "")).suffix.lower()
    lang = _IMPACT_FOLD_LANG_BY_EXT.get(ext, "unknown")
    out: dict = {"language": lang}
    if fn:
        out["function_name"] = fn
    resolved = _resolve_anchor_source(ws_path, str(source_path or ""))
    mod = _perfn_excerpt_mod()
    if resolved is not None and mod is not None and hasattr(mod, "read_file_excerpt"):
        try:
            excerpt, start, end = mod.read_file_excerpt(str(resolved), fn)
        except Exception:
            excerpt, start, end = "", 0, 0
        if start and end:
            out["line_start"] = int(start)
            out["line_end"] = int(end)
            out["file_line"] = f"{source_path}:{int(start)}"
        if excerpt:
            out["excerpt"] = excerpt[:2000]
    return out

_IMPACT_RENDERER_CACHE = "unset"


def _impact_renderer_fn():
    """Lazy-load tools/hacker_question_renderer.render_impact_questions (or
    None). Mirrors per-function-hacker-questions.py's `_impact_renderer()` so
    the SAME provenance-stamping code path is reused here, not reimplemented -
    this is the generic fix for the Go/Rust question_source gap: the
    auto-coverage-closer corpus writer (the one that actually runs during
    `make audit` for every language) previously never called the renderer at
    all, so its output rows carried no `question_source`."""
    global _IMPACT_RENDERER_CACHE
    if _IMPACT_RENDERER_CACHE != "unset":
        return _IMPACT_RENDERER_CACHE
    fn = None
    try:
        spec = importlib.util.spec_from_file_location(
            "hacker_question_renderer",
            str(TOOLS_DIR / "hacker_question_renderer.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        fn = getattr(mod, "render_impact_questions", None)
    except Exception:
        fn = None
    _IMPACT_RENDERER_CACHE = fn
    return fn


def _impact_methodology_rows_for_unit(
    unit_id: str, source_path: str, run_id: str, workspace_name: str,
) -> list[dict]:
    """Render impact-methodology question(s) for ONE in-scope function-bound
    unit, in the SAME per_fn_hacker_questions.v1 row shape as the rest of this
    module's fold, carrying `question_source: impact-methodology` +
    `impact_id` (the provenance markers
    impact-methodology-corpus-provenance-check.py asserts). Generic across
    languages via `_IMPACT_FOLD_LANG_BY_EXT`; returns [] when the renderer is
    unavailable, the unit has no recognised source extension, or the renderer
    attaches nothing (e.g. a pure view/getter)."""
    if os.environ.get("AUDITOOOR_PERFN_Q_NO_IMPACT"):
        return []
    render = _impact_renderer_fn()
    if render is None or not source_path or not unit_id:
        return []
    ext = Path(source_path).suffix.lower()
    lang = _IMPACT_FOLD_LANG_BY_EXT.get(ext)
    if lang is None:
        return []
    fn_name = unit_id.rsplit("::", 1)[-1].rsplit(".", 1)[-1] if unit_id else unit_id
    try:
        imp_rows = render(
            function_name=fn_name, function_signature="", language=lang,
            file_path=source_path, max_questions=1,
        )
    except Exception:
        return []
    out: list[dict] = []
    for r in imp_rows or []:
        q = str((r or {}).get("question") or "").strip()
        if not q:
            continue
        out.append({
            "schema_version": PER_FN_HACKER_QUESTIONS_SCHEMA,
            "workspace": workspace_name,
            "run_id": run_id or None,
            "unit_id": unit_id,
            "function": fn_name,
            "source_path": source_path,
            "language": lang,
            "question": q,
            "question_class": "impact-methodology",
            "question_source": "impact-methodology",
            "impact_id": r.get("impact_id", ""),
            "impact_severity_hint": r.get("impact_severity_hint", ""),
            "reasoning_axis": r.get("reasoning_axis", "impact"),
        })
    return out

# SADL / CRC / SIDL / ORL / RDL hypothesis JSONL artifacts (emitted by audit-deep
# Steps 22/23/24/25/26).  These are FOLDED into per_fn_hacker_questions.jsonl by
# _fold_lane_hypotheses_into_corpus() so the hunt (per_fn_hacker_questions
# gate + LLM hunt) sees them as additional fuel.
# NO-AUTO-CREDIT: every folded record carries verdict=needs-fuzz; folding
# alone does NOT resolve any unit's verdict or flip any gate.
SADL_HYPOTHESES_REL = os.path.join(".auditooor", "self_dealing_hypotheses.jsonl")
CRC_HYPOTHESES_REL = os.path.join(".auditooor", "callback_reentrancy_hypotheses.jsonl")
SHARE_INFLATION_HYPOTHESES_REL = os.path.join(".auditooor", "share_inflation_hypotheses.jsonl")
ORACLE_REACHABILITY_HYPOTHESES_REL = os.path.join(".auditooor", "oracle_reachability_hypotheses.jsonl")
ROUNDING_DRAIN_HYPOTHESES_REL = os.path.join(".auditooor", "rounding_drain_hypotheses.jsonl")
MEV_ORDERING_HYPOTHESES_REL = os.path.join(".auditooor", "mev_ordering_hypotheses.jsonl")
ACCESS_CONTROL_HYPOTHESES_REL = os.path.join(".auditooor", "access_control_hypotheses.jsonl")
INIT_UPGRADE_HYPOTHESES_REL = os.path.join(".auditooor", "init_upgrade_hypotheses.jsonl")
# Go wave-2 advisory lanes (G2/G4/G5/G6/G7/G8/G11/G12/G13), emitted by
# go-detector-runner under the AUDITOOR_G* envs (auto-run in audit-deep Step 5b).
# These were built-but-dormant orphans until wired: the runner never ran with the
# envs set, and even when it did the emitted *_hypotheses.jsonl dead-ended with no
# consumer. Folding them here (needs-fuzz, no-auto-credit) makes the Go advisory
# hypotheses hunt fuel, exactly like the Solidity lanes above. See
# methodology_capability_must_be_wired_not_just_built.
GO_ADVISORY_HYPOTHESES_REL = [
    os.path.join(".auditooor", "attacker_divisor_zero_hypotheses.jsonl"),
    os.path.join(".auditooor", "nondeterministic_time_float_rand_hypotheses.jsonl"),
    os.path.join(".auditooor", "unmarshal_type_ambiguity_first_match_hypotheses.jsonl"),
    os.path.join(".auditooor", "goroutine_fanout_unsync_shared_hypotheses.jsonl"),
    os.path.join(".auditooor", "onesided_acceptance_hypotheses.jsonl"),
    os.path.join(".auditooor", "decode_malformed_then_trusted_hypotheses.jsonl"),
    os.path.join(".auditooor", "decode_consumption_type_nil_hypotheses.jsonl"),
    os.path.join(".auditooor", "ingress_unbounded_loop_or_panic_hypotheses.jsonl"),
    os.path.join(".auditooor", "goroutine_no_toplevel_recover_hypotheses.jsonl"),
    os.path.join(".auditooor", "ctx_cancellation_ignored_verdict_hypotheses.jsonl"),
    os.path.join(".auditooor", "sentinel_loss_hypotheses.jsonl"),
    os.path.join(".auditooor", "iter_bound_bypass_hypotheses.jsonl"),
    os.path.join(".auditooor", "consensus_write_determinism_census_hypotheses.jsonl"),
    os.path.join(".auditooor", "go_slice_aliasing.jsonl"),
    os.path.join(".auditooor", "goroutine_lifecycle_safety_census_hypotheses.jsonl"),
    os.path.join(".auditooor", "go_unbounded_alloc_noprogress_hypotheses.jsonl"),
]
# Rust wave-2 advisory axes (RU3/RU6/RU7/RU9/RU10/RU11), emitted by
# rust-detector-runner under the AUDITOOR_RUST_*_AXIS envs (auto-run in audit-deep
# Step 5c). Same orphan class as the Go lanes: the runner was never invoked by the
# pipeline. Folding them here (needs-fuzz, no-auto-credit) makes the Rust advisory
# hypotheses hunt fuel. See methodology_capability_must_be_wired_not_just_built.
RUST_ADVISORY_HYPOTHESES_REL = [
    os.path.join(".auditooor", "rust_oob_hypotheses.jsonl"),
    os.path.join(".auditooor", "rust_nondet_hypotheses.jsonl"),
    os.path.join(".auditooor", "rust_lockpoison_hypotheses.jsonl"),
    os.path.join(".auditooor", "rust_strslice_hypotheses.jsonl"),
    os.path.join(".auditooor", "rust_entropy_hypotheses.jsonl"),
    os.path.join(".auditooor", "rust_dropsafety_hypotheses.jsonl"),
    os.path.join(".auditooor", "rust_panic_reach_hypotheses.jsonl"),
    os.path.join(".auditooor", "rust_eager_alloc_nomax_hypotheses.jsonl"),
    os.path.join(".auditooor", "rust_unsafe_soundness_obligation_hypotheses.jsonl"),
]
# Net-new general-logic advisory lanes (wave 2026-07-11), EVM/cross-language,
# emitted by the standalone screens auto-run in audit-deep Step 5f. Same
# needs-fuzz / no-auto-credit contract as GO/RUST: folding them here makes each
# a hunt-fuel candidate. A6 cache/source writer-set coherence, A7 cross-module
# sibling reentrancy, A15 stale-grant survival, E9 ordering-dependent invariant.
# See methodology_capability_must_be_wired_not_just_built.
NETNEW_ADVISORY_HYPOTHESES_REL = [
    os.path.join(".auditooor", "cache_source_writer_set_hypotheses.jsonl"),
    os.path.join(".auditooor", "cross_module_sibling_reentrancy.jsonl"),
    os.path.join(".auditooor", "stale_grant_survival_hypotheses.jsonl"),
    os.path.join(".auditooor", "ordering_dependent_invariant_hypotheses.jsonl"),
    os.path.join(".auditooor", "storage_slot_bijection_hypotheses.jsonl"),
    # wave-2 net-new caps (2026-07-11): E7 pre-cap amplification, A14 deploy->init
    # ordering-window, R2 invariant-suspension-window, R6 async-cancel coupled-state,
    # E12 inclusion-proof positional soundness, R4 cross-client consensus divergence,
    # Z2 zk lookup-argument membership bound.
    os.path.join(".auditooor", "e7_precap_amplification_hypotheses.jsonl"),
    os.path.join(".auditooor", "deploy_initialize_ordering_hypotheses.jsonl"),
    os.path.join(".auditooor", "invariant_suspension_window_hypotheses.jsonl"),
    os.path.join(".auditooor", "async_cancel_coupled_state_hypotheses.jsonl"),
    os.path.join(".auditooor", "e12_inclusion_position_hypotheses.jsonl"),
    os.path.join(".auditooor", "cross_client_consensus_divergence_hypotheses.jsonl"),
    os.path.join(".auditooor", "zk_lookup_membership_hypotheses.jsonl"),
    # wave-2 needs-fix caps (2026-07-11, refuter-fixed): C1 JS/Oscript value-moving
    # surface, R3 delegation trust-closure.
    os.path.join(".auditooor", "js_oscript_value_moving_surface_hypotheses.jsonl"),
    os.path.join(".auditooor", "delegation_trust_closure.jsonl"),
    # gen-2 caps (2026-07-11 self-sustaining generator wjbkzptzq): MQ-B01
    # lifecycle-transition-graph, MQ-B03 deferred-execution param-binding,
    # MQ-B04 quorum-degradation. Advisory-first needs-fuzz.
    os.path.join(".auditooor", "lifecycle_transition_graph_hypotheses.jsonl"),
    os.path.join(".auditooor", "deferred_execution_param_binding_hypotheses.jsonl"),
    os.path.join(".auditooor", "quorum_degradation_hypotheses.jsonl"),
    os.path.join(".auditooor", "total_order_comparator_hypotheses.jsonl"),
    os.path.join(".auditooor", "declared_control_mutator_completeness_hypotheses.jsonl"),
    os.path.join(".auditooor", "narrowing_lossy_cast_hypotheses.jsonl"),
    os.path.join(".auditooor", "recover_completeness_hypotheses.jsonl"),
    os.path.join(".auditooor", "rounding_direction_consistency_hypotheses.jsonl"),
    os.path.join(".auditooor", "operand_commensurability_hypotheses.jsonl"),
    os.path.join(".auditooor", "randomness_unbiasability_hypotheses.jsonl"),
    # gen-ext caps (2026-07-11 external-corpus refresh wf_682bcedf; mutation-verified
    # on real fleet code + distinct-adversarial-verify-CONFIRMED): EXT02 ABCI
    # PrepareProposal/ProcessProposal predicate-symmetry, EXT03 verifier->executor
    # semantic divergence (JIT/codegen width/encoding), EXT07 RAII/Drop-glue bypass
    # via raw-slot overwrite on error paths. Advisory-first needs-fuzz.
    os.path.join(".auditooor", "abci_phase_predicate_symmetry_hypotheses.jsonl"),
    os.path.join(".auditooor", "verifier_executor_divergence_hypotheses.jsonl"),
    os.path.join(".auditooor", "raii_drop_glue_bypass_hypotheses.jsonl"),
    # gen-ext wave-2 (2026-07-11; adversarial-verifier-fixed then re-CONFIRMED):
    # EXT01 multi-source field-authority differential (redundant-header smuggling),
    # EXT04 cross-layer committed-vs-consumed cardinality divergence, EXT05 nested
    # length-prefix parent-bound (RLP/TLV OOB), EXT06 Rust Send/Sync bound omission
    # at a share boundary (fixture-verified; fleet compiler-redundant), EXT08 unsound
    # hand-rolled guard predicate (Cetus checked-math class). Advisory-first.
    os.path.join(".auditooor", "multi_source_field_authority_differential_hypotheses.jsonl"),
    os.path.join(".auditooor", "cross_layer_cardinality_divergence_hypotheses.jsonl"),
    os.path.join(".auditooor", "nested_length_prefix_parent_bound_hypotheses.jsonl"),
    os.path.join(".auditooor", "send_sync_bound_omission_hypotheses.jsonl"),
    os.path.join(".auditooor", "guard_predicate_soundness_hypotheses.jsonl"),
    # gen-ext round-2 (2026-07-11 wf_0768c38f; mutation-verified on real fleet +
    # distinct-adversarial-verify CONFIRMED): EXT2-01 mid-transition snapshot
    # phase-freshness (lido ValidatorExitDelayVerifier), EXT2-05 generic/phantom-type
    # vs runtime-selector desync (OZ Sui-Move pool), EXT2-06 non-monotonic guard
    # composition (morpho MetaMorphoV1_1 timelock). Advisory-first needs-fuzz.
    os.path.join(".auditooor", "mid_transition_snapshot_phase_freshness_hypotheses.jsonl"),
    os.path.join(".auditooor", "generic_type_selector_desync_hypotheses.jsonl"),
    os.path.join(".auditooor", "non_monotonic_guard_composition_hypotheses.jsonl"),
    # gen-ext round-2 remainder EXT2-02/03/04 (built earlier, smoke-verified this
    # tick to fire sane LOW counts across nuva(6/0/1) + morpho(13) + monero-oxide(6),
    # no FP-spray); drained from the built-but-unwired orphan trap. Advisory needs-fuzz.
    os.path.join(".auditooor", "object_graph_xref_consistency_hypotheses.jsonl"),
    os.path.join(".auditooor", "failopen_classifier_default_arm_hypotheses.jsonl"),
    os.path.join(".auditooor", "queue_fairness_resource_mutation_hypotheses.jsonl"),
    # GEN-A1 (wf_ba1ca1ee, 2026-07-11): parse-consume byte-conservation seam (Sol+Go
    # arms; Rust arm = rust-non-exact-decode-trailing-bytes-scan). SHIP-verified:
    # mutation-witness on morpho BytesLib.get (0->1 on require-removed), sei fires 14,
    # nuva silent-TN (all Go decoders are .pulsar.go codegen). Advisory needs-fuzz.
    os.path.join(".auditooor", "byte_conservation_hypotheses.jsonl"),
    # GEN-A2 (wf_608a6684): traversal terminal-state canonicalization (a variable-
    # length-walk verifier must accept iff the canonical terminal was reached). SHIP:
    # mutation-witness on lido fx-portal Merkle.checkMembership (silent->fires on
    # dropped ==root); sei fires 2 (ICS23 IBC batch verifiers); nuva silent-TN.
    os.path.join(".auditooor", "terminal_canonicalization_hypotheses.jsonl"),
    # GEN-A3 (wf_5fd34f86): ephemeral-store reset-conservation + write-tier fidelity
    # (must-reset-between-scopes store's reset must dominate every exit/revert edge;
    # set/reset tier must agree). SHIP: mutation-witness on lido CircuitBreaker
    # nonReentrant (fires on removed reset / early-return); lido fires 1 real
    # (V3Template UPGRADE_STARTED_SLOT tstore-never-reset); nuva silent-TN.
    os.path.join(".auditooor", "reset_conservation_hypotheses.jsonl"),
    # GEN-A4 (wf_7123a76c): external-call boundary state-invalidation (a local value
    # read-before-untrusted-extcall + used-after without re-read; temporal staleness
    # DISTINCT from CEI/reentrancy - fires on a nonReentrant fn where the token mutates
    # its own balance during transfer). SHIP: mutation-witness on etherfi
    # Liquifier.depositWithERC20; etherfi 9 / morpho 6; nuva silent-TN.
    os.path.join(".auditooor", "extcall_boundary_invalidation_hypotheses.jsonl"),
    # GEN-A5 (wf_bae5b614): implicit domain-disjointness assumption (a predicate trusts
    # an unstated X-cannot-inhabit-Y: EOA-not-contract / zero-signer / decode-into-type /
    # reserved-id / untagged-discriminant, no domain-sep or impossibility proof). SHIP,
    # defects=[]: mutation-witness on morpho-blue setAuthorizationWithSig (!=address(0)
    # removed -> fires); etherfi 25 / morpho 5; nuva silent-TN.
    os.path.join(".auditooor", "domain_disjointness_hypotheses.jsonl"),
    # GEN-EL1 (wf_7a1ba4e3): compiler-known-bug shape-JOIN (pinned-version-affected AND
    # source-trigger-shape present; version-alone != finding - closes the E2 gap, strict
    # subset). SHIP, both halves load-bearing (morpho Bundler3 3-case witness). lido
    # fires 6 real leads (SOL-2022-2/6); morpho 0; nuva silent-TN.
    os.path.join(".auditooor", "compiler_shape_join_hypotheses.jsonl"),
    # GEN-EL4 (wf_0eea2b06): crypto-preimage soundness census (domain-sep-absent /
    # nonce-reuse / low-s-malleability / empty-signer-array; distinct from A5 zero-signer
    # + journal-collision). SHIP defects=[]: morpho-blue setAuthorizationWithSig witness;
    # morpho 3 + lido 1 real low-s leads; nuva silent-TN.
    os.path.join(".auditooor", "crypto_preimage_soundness_hypotheses.jsonl"),
    # GEN-EL3: non-canonical serialization acceptance (a decode -> canonicality-
    # sensitive sink keyed on RAW bytes with no re-encode/canonical check; two
    # byte-distinct encodings of one logical value -> two keys). Distinct from the
    # E1 re-encode-equality differential + A5 untagged-decode. Mutation-verified on
    # sei cosmos unknownproto (cache-key gzippedPb -> raw protoBlob -> fires);
    # optimism 2 real rust leads (kona keccak256(hint.data)); sei/nuva silent-TN.
    os.path.join(".auditooor", "noncanonical_serialization_hypotheses.jsonl"),
    # GEN-EL2: ABI selector/dispatch collision soundness (a selector->fn dispatch
    # STRUCTURE - Diamond/EIP-2535 facet map, transparent-proxy admin/impl clash,
    # assembly switch, router bytes4->addr - lacking collision rejection routes a
    # colliding/duplicate selector into a privileged fn). Flags the UNGUARDED
    # STRUCTURE only, never brute-forced numeric keccak4 coincidences. Distinct from
    # function_signature_shape (name/arg) + W1 guard-drop + journal-collision
    # (encodePacked). Mutation-verified on beanstalk LibDiamond (strip the
    # require(oldFacetAddress==address(0)) add-guard -> fires); etherfi 2 in-scope
    # proxy-clash leads; nuva/morpho/lido/ssv silent-TN.
    os.path.join(".auditooor", "selector_dispatch_collision_hypotheses.jsonl"),
    # GEN-EL5: gas-metering/opcode-repricing fragility (a safety argument resting on
    # a gas magic-number - 2300-stipend transfer/send to a stored addr, fixed-gas
    # call, gasleft() threshold gate, gas-bounded loop, 63/64 forward - that an
    # EIP-1884/2929/3529 repricing shifts to re-enable reentrancy/DoS). FP-scoped to
    # LOAD-BEARING gas constants (stored-addr payee = medium, msg.sender = low, ERC20
    # 2-arg + robust .call{value} = silent). Distinct from go-unbounded-alloc /
    # rust-eager-alloc (alloc-size DoS) + generic reentrancy (missing-guard) +
    # unbounded-loop (missing-bound). Mutation-verified on lido AssetRecoverer
    # (call{value} -> transfer -> fires); morpho+lido 1 lead each; nuva/ssv silent-TN.
    os.path.join(".auditooor", "gas_repricing_fragility_hypotheses.jsonl"),
    # GEN-EL6: toolchain-flag semantic-drift (a build/toolchain flag that changes
    # SEMANTICS not just optimization silently invalidates a source safety
    # assumption - Rust [profile.release] overflow-checks=off JOINed against a real
    # bare-arith site, Solidity evmVersion cancun/prague enabling tstore/mcopy,
    # viaIR+inline-assembly, a negated go build-tag gating a validation path).
    # FP-scoped to SEMANTIC flags (optimizer/opt-level never flagged); the Rust arm
    # requires BOTH config-off AND a source site. Upgrades stale-pin-check with a
    # flag/evmVersion axis (sibling, exposes check_toolchain_flag_drift()). Distinct
    # from compiler-known-bug-E2 (solc version window) + GEN-EL5 (source gas const).
    # Mutation-verified (near Cargo overflow-checks flip + lido foundry evmVersion
    # paris->cancun flip); lido 9 / morpho 14 leads; near/near-intents/nuva silent-TN.
    os.path.join(".auditooor", "toolchain_flag_drift_hypotheses.jsonl"),
    # GEN-R3: unsound transmute/pointer-cast type-confusion (Rust). Every
    # reinterpreting cast must discharge size-eq + alignment + all-bit-patterns-valid
    # + no-lifetime-extension; fires ONLY the four undischargeable forms (generic-param
    # transmute, lifetime transmute, bytes->niche-type bool/char/NonZero/reference/
    # fn-pointer, stricter-align ptr-cast-deref). Discriminating screen - stays SILENT
    # on sound repr-C POD / repr-transparent / bytemuck-Pod casts (unlike R13 blanket
    # unsafe inventory). Distinct from RU3 (slice OOB) / RU1 (Send-Sync). Mutation-
    # verified on near key_conversion.rs (RistrettoPoint transmute -> bool/lifetime
    # fires); near 6 leads (JIT fn-pointer + wasmtime &static-mut lifetime); near-
    # intents/leansig silent-TN. Rust-only (nuva N/A, no Rust surface).
    os.path.join(".auditooor", "transmute_type_confusion_hypotheses.jsonl"),
    # GEN-R1: panic-during-Drop double-drop/UAF (Rust). An unsafe manual drop/dealloc
    # loop (drop_in_place / ptr::read+drop / ManuallyDrop::drop / rebuild-drop-then-
    # write) must consume-before-drop (set_len(0) / advance a progress drop-guard
    # BEFORE a panicking element Drop) else the unwind re-observes an already-freed
    # slot = double-drop/UAF. FP-scoped: consume-first + POD/Copy drops stay silent.
    # Distinct from raii-drop-glue-bypass (skip-cleanup leak on ?-path) + RU7 (lock-
    # poison). Mutation-verified on a faithful Vec::truncate synthetic (no real
    # consume-before-drop loop exists in fleet - stated); near 1 ptr-read-double-drop
    # lead; monero-oxide/near-intents/base-azul/leansig silent-TN. Rust-only (nuva N/A).
    os.path.join(".auditooor", "panic_during_drop_hypotheses.jsonl"),
    # GEN-R5: release-mode silent integer overflow to alloc/index (Rust). An untrusted
    # numeric length/cap/count/offset tainted through bare + - * << / narrowing-as into
    # a memory-safety sink (with_capacity/reserve/set_len/get_unchecked/slice-range/
    # ptr-add/from_raw_parts/copy_nonoverlapping) with no checked_/saturating_/try_into
    # guard wraps silently in release (no debug panic) -> undersized alloc + later OOB
    # / wrapped offset. Requires BOTH untrusted taint AND a memory sink (owned .len()
    # arith + literals + guarded sites stay silent). INVERSE of rust-panic-reach
    # (debug-panic DoS); COMPOSES with GEN-EL6 (overflow-checks=off config); distinct
    # from rust-eager-alloc/decode-bomb (correct-but-huge alloc size) + rust-numeric-
    # overflow-underflow-scan (owned .len() arith). Mutation-verified on near
    # vmctx_plus_offset (try_from -> as fires); near 19 / monero-oxide 1 / leansig 3
    # leads; near-intents silent-TN. Rust-only (nuva N/A, no Rust surface).
    os.path.join(".auditooor", "release_silent_overflow_hypotheses.jsonl"),
    # GEN-D: consensus-nondeterministic-return-ordering (Go). A `for k := range
    # map` whose body appends to a slice reaching a consensus-serialized RETURN
    # (ValidatorUpdate/EndBlock event/PrepareProposal tx-order/genesis-export/denom)
    # with NO dominating sort.Slice/Strings before the sink -> per-validator
    # ordering divergence -> AppHash halt. FP-scoped: sorted slices + pre-sorted
    # key iteration + keyed-map-write (m[k]=append) + local/len()-only reads stay
    # silent; unconfirmed keeper sinks = medium. Sibling of consensus-write-
    # determinism-census (store.Set sink; GEN-D adds the ABCI/genesis return-slice
    # sink); distinct from G4 (nondeterministic VALUES not map-ORDER). Mutation-
    # verified on polygon cosmos-sdk nft/keeper genesis.go ExportGenesis (strip
    # sort.Strings(owners) -> fires genesis-export/high); nuva/sei silent-TN.
    os.path.join(".auditooor", "consensus_map_order_return_hypotheses.jsonl"),
    # GEN-4B: value-conserving division rounds-against-beneficiary (cross-lang lift
    # of EVM-W3). A division splitting a conserved quantity (assets<->shares, fee<->
    # principal, reward<->stake) must round the residual toward protocol not the
    # quotient recipient. Two arms: divide-before-multiply (a/b*c amplifies the
    # truncated residual - infix + method-chain .Quo().Mul() across sol/rust/go/move)
    # and wrong-rounding-direction (round-up payout / round-down debt, medium). FP-
    # scoped: requires a conserved hint AND DBM-or-wrong-direction; multiply-before-
    # divide + pure div + display ratio + loop index stay silent. Cross-lang net-new
    # vs W3 (Solidity-only). Mutation-verified on etherfi GlobalIndexLibrary.sol:73
    # (a*b/c -> a/c*b fires DBM/high); morpho 1 WRD-medium; nuva/near silent-TN.
    os.path.join(".auditooor", "division_rounds_against_beneficiary_hypotheses.jsonl"),
    # GEN-4C: width-narrowing cast on attacker operand (cross-lang lift of Glider#2
    # EVM-downcast). A narrowing integer cast (wider->narrower) on a value-bearing
    # operand truncates high bits -> a large amount/id/index wraps small. FP-scoped:
    # source genuinely wider AND value-bearing; widening/masked/SafeCast/try_into
    # silent. Mutation-verified on morpho VaultV2.sol:639 (toUint128 -> bare fires);
    # nuva silent-TN.
    os.path.join(".auditooor", "width_narrowing_cast_hypotheses.jsonl"),
    # GEN-4A: vault max-exit helper rounding-vs-paired-exit. A 4626-family max*/
    # preview* helper and its paired exit (withdraw/redeem) must round consistently;
    # opposite rounding lets maxWithdraw() over-exit or revert. CROSS-FUNCTION
    # consistency check (distinct from GEN-4B single-expression). nuva silent-clean-TN.
    os.path.join(".auditooor", "vault_maxexit_rounding_hypotheses.jsonl"),
    # GEN-4D: discarded-fallible-result-on-a-value-path (Go/Rust/Move). A fallible
    # value-moving call (transfer/mint/burn/send*coins/withdraw/settle) whose
    # error/Result/bool-success is DISCARDED lets a FAILED transfer proceed as
    # success -> phantom credit / lost funds. Go: `_ =`/`x, _ =` blank in the
    # error (last) position + curated bare-statement cosmos-bank op (receiver-dot
    # required; interface method SIGNATURES excluded). Rust: `let _ =` + `.ok();`
    # discard + `let _ = <bal>.checked_sub()`. Move: `let _ =` coin op. FP-scoped:
    # word-exact value verbs (WEAK send/pay/... need a value-noun co-token; `value`
    # excluded as too generic); checked/`if err`/`?`/unwrap/named-error silent.
    # DEDUP: Solidity low-level-call return defers to W6-P1 (not scanned). Mutation-
    # verified on sei ibc-go relay.go:296 (checked SendCoins -> `_ =` fires); nuva
    # silent-TN (interface decls suppressed); sei/polygon WithdrawValidatorCommission
    # TP (dev //nolint:errcheck).
    os.path.join(".auditooor", "discarded_fallible_result_hypotheses.jsonl"),
]

PER_UNIT_VERDICT_SCHEMA = "auditooor.coverage_unit_verdict.v1"

VERDICT_NO_FINDING = "mechanical-hunt-no-finding"
VERDICT_NEEDS_LLM = "needs-llm-depth"
# Self-label proving the no-finding verdict is mechanical-source-cited credit
# only and NOT an R80 PoC.
COVERAGE_CREDIT_LABEL = "mechanical-source-cited"

# Top-level RUN verdicts. The closer is a BOUNDED orchestrator, so it does not
# itself pass/fail any audit gate; its run verdict must nonetheless reconcile to
# the STRICT L37 function-coverage axis and never CLAIM coverage is closed while
# the strict gate still reports >=1 uncovered function (or is unresolved).
#   - VERDICT_COVERAGE_CLOSED: the strict axis is genuinely closed
#     (status ``ok`` with zero strict-uncovered, or the gate tool is
#     ``unavailable`` - same definition the per-iter ``stop_reason`` uses). Only
#     here may the run report a heatmap coverage_fraction of 1.0.
#   - VERDICT_RESIDUAL_OPEN: the strict axis is still OPEN (>=1 uncovered fn) or
#     UNRESOLVED (status ``failed``/timeout). The heatmap can read 1.0 here
#     because it counts every ENUMERATED unit as covered, but that is a FALSE
#     GREEN - so the run must NOT label itself coverage-closed and the reported
#     coverage_fraction is reconciled to the strict count (never 1.0 while
#     strict-uncovered > 0; ``None`` when the strict count is unknown).
# This is an HONESTY reconciliation, not a gate: it never flips any audit-complete
# signal green - it only stops the closer's own run verdict from lying.
VERDICT_COVERAGE_CLOSED = "pass-coverage-closed-or-fixpoint"
VERDICT_RESIDUAL_OPEN = "coverage-residual-open"

# Fields a per-unit verdict MUST NOT carry when it is a no-finding (honest
# finding-evidence invariant, R80). Asserted at build time + by the test.
FORBIDDEN_NO_FINDING_FIELDS = (
    "attack_class", "severity", "likely_severity", "bug_class", "impact",
    "claim", "suspicion", "vulnerability_class", "finding_class",
    "exploit_proven", "is_vulnerable",
)

COVERAGE_SEED_TOOL = TOOLS_DIR / "coverage-to-hunt-seed.py"
RUBRIC_SEED_TOOL = TOOLS_DIR / "rubric-to-hunt-seed.py"
HACKER_Q_TOOL = TOOLS_DIR / "per-function-hacker-questions.py"
RANKER_TOOL = TOOLS_DIR / "per-fn-question-ranker.py"
HUNT_GATE_TOOL = TOOLS_DIR / "hunt-coverage-gate.py"
HEATMAP_TOOL = TOOLS_DIR / "workspace-coverage-heatmap.py"
RUBRIC_TOOL = TOOLS_DIR / "rubric-coverage-workspace-check.py"
# r36-rebuttal: lane L37-CERTORA-SCOPE-FIX registered in .auditooor/agent_pathspec.json
FN_COV_TOOL = TOOLS_DIR / "function-coverage-completeness.py"

# r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
# --------------------------------------------------------------------------
# full bounded per-unit ARSENAL (item 4)
# --------------------------------------------------------------------------
# Each uncovered unit is driven through the SAME bounded arsenal we use for
# better auditing - NOT only per-function hacker-questions. Every tool is gated
# by a PER-TOOL timeout (env-overridable); a slow tool is NEVER skipped, it is
# time-bounded and, if it exceeds the budget, recorded as a ``timeout`` status
# (not a no-op). File-scoped tools are cached per source file so multiple units
# in the same file do not re-run the whole-file scan, while the PER-UNIT verdict
# sidecar still records WHICH tools ran for that unit + their result. Honest:
# the only two RESULT values are ``no-finding`` (tool ran, emitted no
# hypothesis) and ``hypothesis`` (tool emitted a candidate question / harness /
# invariant - which is hunt FUEL, NOT a proven bug). No tool result is ever
# promoted to a claim (R76 / R80 safe).
INVARIANT_SYNTH_TOOL = TOOLS_DIR / "invariant-auto-synth.py"
RUST_DETECTOR_TOOL = TOOLS_DIR / "rust-detector-runner.py"
GO_DETECTOR_TOOL = TOOLS_DIR / "go-detector-runner.py"
PER_FN_MIMO_TOOL = TOOLS_DIR / "per-fn-mimo-batch-gen.py"

# Map source extension -> scoped detector tool (None = no detector for the ext).
_DETECTOR_BY_EXT = {
    ".rs": RUST_DETECTOR_TOOL,
    ".go": GO_DETECTOR_TOOL,
}


# Per-tool timeout budgets (seconds). Env-overridable so a fast CI run can tune
# them down and a deep run up. A slow tool is time-bounded, NOT skipped.
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


ARSENAL_TIMEOUT_HACKER_Q = _env_int("AUDITOOOR_ACC_TIMEOUT_HACKER_Q", 20)
ARSENAL_TIMEOUT_DETECTOR = _env_int("AUDITOOOR_ACC_TIMEOUT_DETECTOR", 60)
ARSENAL_TIMEOUT_MIMO = _env_int("AUDITOOOR_ACC_TIMEOUT_MIMO", 60)
ARSENAL_TIMEOUT_INVARIANT = _env_int("AUDITOOOR_ACC_TIMEOUT_INVARIANT", 60)
# Strict function-coverage-completeness --emit-worklist subprocess budget. The
# strict gate is the AUTHORITATIVE uncovered-set source (see
# _genuine_uncovered_units); a fixed 180s cap silently failed-closed to an EMPTY
# worklist on large workspaces (e.g. injective ~6.4k units), which the closer
# then mistook for "genuinely covered" - a false green. Env-overridable + a
# larger default so the parallel fcc-perf work or a deep run is not artificially
# capped. A genuine failure/timeout is now SURFACED, never treated as covered.
FCC_WORKLIST_TIMEOUT = _env_int("AUDITOOOR_ACC_TIMEOUT_FCC_WORKLIST", 900)

# Status values for the strict-uncovered worklist probe. ``ok`` = the strict
# gate ran and its worklist (possibly empty) is authoritative; ``unavailable`` =
# the gate tool is missing (no strict axis to reconcile); ``failed`` = the gate
# ran but errored / timed out / emitted unparseable output - the strict
# uncovered set is UNKNOWN and must NOT be treated as empty/covered.
FCC_STATUS_OK = "ok"
FCC_STATUS_UNAVAILABLE = "unavailable"
FCC_STATUS_FAILED = "failed"

# Honest per-tool result vocabulary.
TOOL_RESULT_NO_FINDING = "no-finding"
TOOL_RESULT_HYPOTHESIS = "hypothesis"
TOOL_STATUS_RAN = "ran"
TOOL_STATUS_TIMEOUT = "timeout"
TOOL_STATUS_UNAVAILABLE = "unavailable"
TOOL_STATUS_ERROR = "error"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=str(path.parent), suffix=".tmp", delete=False, encoding="utf-8"
    ) as tf:
        json.dump(data, tf, indent=2)
        tmp = tf.name
    os.replace(tmp, str(path))


def _slug_unit(unit: str) -> str:
    return (
        unit.replace("/", "-").replace("\\", "-").replace("::", "--").replace(".", "-")
    )[:120]


def _unit_verdict_path(ws_path: Path, unit: str) -> Path:
    """The persisted per-unit verdict sidecar path for ``unit``.

    Single source of truth for where ``_run_unit_deterministic_hunt`` writes its
    verdict, so the "already processed?" check below and the writer can never
    disagree on the slug.
    """
    return ws_path / PER_UNIT_VERDICT_DIR_REL / (_slug_unit(unit) + ".json")


def _unit_already_processed(ws_path: Path, unit: str) -> bool:
    """True when ``unit`` already has a persisted per-unit verdict sidecar.

    The verdict sidecar is the strict-worklist-drain contract artifact: a unit
    that has been driven through the deterministic arsenal in a prior iter (or a
    prior run) has a sidecar on disk. The bounded loop consults this so each iter
    advances to the NEXT slice of the strict-uncovered worklist instead of
    re-hunting the same front ``unit_cap`` units forever - which is what made the
    closer fixpoint after 2 iters while thousands of strict-uncovered functions
    were never touched.
    """
    return _unit_verdict_path(ws_path, unit).is_file()


# --------------------------------------------------------------------------
# module imports (no re-implementation)
# --------------------------------------------------------------------------
def _import_by_path(name: str, path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None


_HACKER_Q_MOD = None
_HUNT_GATE_MOD = None
_HEATMAP_MOD = None
_RUBRIC_MOD = None


def _hacker_q_mod() -> Any | None:
    global _HACKER_Q_MOD
    if _HACKER_Q_MOD is None:
        _HACKER_Q_MOD = _import_by_path("_acc_hacker_q", HACKER_Q_TOOL)
    return _HACKER_Q_MOD


def _hunt_gate_mod() -> Any | None:
    global _HUNT_GATE_MOD
    if _HUNT_GATE_MOD is None:
        _HUNT_GATE_MOD = _import_by_path("_acc_hunt_gate", HUNT_GATE_TOOL)
    return _HUNT_GATE_MOD


def _heatmap_mod() -> Any | None:
    global _HEATMAP_MOD
    if _HEATMAP_MOD is None:
        _HEATMAP_MOD = _import_by_path("_acc_heatmap", HEATMAP_TOOL)
    return _HEATMAP_MOD


def _rubric_mod() -> Any | None:
    global _RUBRIC_MOD
    if _RUBRIC_MOD is None:
        _RUBRIC_MOD = _import_by_path("_acc_rubric", RUBRIC_TOOL)
    return _RUBRIC_MOD


# --------------------------------------------------------------------------
# measurement re-reads
# --------------------------------------------------------------------------
def _rebuild_coverage_report(ws_path: Path) -> dict:
    """Regenerate coverage_report.json at no-cap via the MEASURE tool."""
    mod = _heatmap_mod()
    if mod is not None and hasattr(mod, "build_coverage_report"):
        try:
            scope = None
            if hasattr(mod, "resolve_scope"):
                try:
                    scope = mod.resolve_scope(ws_path)
                except Exception:
                    scope = None
            report = mod.build_coverage_report(ws_path, list_cap=-1)
            if isinstance(report, dict):
                out = ws_path / COVERAGE_REPORT_REL
                try:
                    _atomic_write_json(out, report)
                except OSError:
                    pass
                return report
        except Exception:
            pass
    # fall back to whatever is on disk
    p = ws_path / COVERAGE_REPORT_REL
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def _read_g15_result(ws_path: Path, run_id: str) -> dict:
    """Run the hunt-coverage gate check (import; never shells) and return its
    result dict. Falls back to the cached last-result sidecar if the import
    path fails."""
    mod = _hunt_gate_mod()
    if mod is not None and hasattr(mod, "check"):
        try:
            return mod.check(
                str(ws_path),
                min_coverage=1.0,
                auto_seed_heal=False,
                run_id=run_id,
            )
        except Exception:
            pass
    sidecar = ws_path / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
    if sidecar.is_file():
        try:
            return json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def _genuine_uncovered_units(ws_path: Path) -> tuple[list[str], str]:
    # r36-rebuttal: lane L37-CERTORA-SCOPE-FIX registered in .auditooor/agent_pathspec.json
    """Genuinely-uncovered ENTRY functions per the strict L37 gate
    (``function-coverage-completeness.evaluate``): every external/public/entry
    function whose classification is NOT ``real-attack`` (i.e. ``hollow`` or
    ``untouched``).

    WHY: the G15 hunt-coverage gate AND the coverage_report.json heatmap both
    credit skip-logged / mechanically-scanned / merely-ENUMERATED units as
    covered, so they can report uncovered=0 (coverage_fraction=1.0) while the
    strict gate still fails (a function with a sentinel harness, a "queued for a
    look" skip-log, or no per-function attack verdict at all is NOT a
    ``real-attack``). When that happens the per-unit deterministic hunt would run
    over an EMPTY set and emit zero per_fn questions, leaving the scoped hunt
    nothing to do and the L37 function-coverage gate permanently red. Folding the
    strict gate's hollow/untouched set into the closer's residual reconciles the
    two notions: the closer drives a per-unit hunt (and emits per_fn questions)
    over exactly the functions the strict gate counts as uncovered.

    Returns ``(units, status)`` where ``units`` are ``file::fn`` strings (the
    format ``_per_unit_hunt_pass`` consumes) and ``status`` is one of
    ``FCC_STATUS_OK`` (gate ran, worklist - possibly empty - is authoritative),
    ``FCC_STATUS_UNAVAILABLE`` (gate tool missing), or ``FCC_STATUS_FAILED``
    (gate errored / timed out / emitted unparseable output - the strict
    uncovered set is UNKNOWN). The status is LOAD-BEARING: an empty list under
    ``ok`` means genuinely covered, but an empty list under ``failed`` must NOT
    be mistaken for covered - that exact conflation was the coverage-notion
    false-green this tool exists to prevent. Earlier code raised the gate over a
    fixed 180s subprocess cap and swallowed the resulting ``TimeoutExpired``
    (and JSON-parse errors) into a bare ``return []`` - on a large workspace the
    strict axis silently vanished and the closer declared coverage met. The
    timeout is now env-overridable (``AUDITOOOR_ACC_TIMEOUT_FCC_WORKLIST``,
    default ``FCC_WORKLIST_TIMEOUT``) and a failure returns ``FCC_STATUS_FAILED``
    instead of a covered-looking empty.

    Shells the gate CLI rather than importing it - the gate defines a
    module-level @dataclass whose string annotations only resolve when the file
    is the top-level module, so a spec_from_file_location import raises under
    Python 3.14.
    r36-rebuttal: lane L37-CERTORA-SCOPE-FIX registered in .auditooor/agent_pathspec.json"""
    if not FN_COV_TOOL.is_file():
        return [], FCC_STATUS_UNAVAILABLE
    try:
        proc = subprocess.run(
            [sys.executable, str(FN_COV_TOOL),
             "--workspace", str(ws_path), "--emit-worklist", "--json"],
            capture_output=True, text=True, timeout=max(1, FCC_WORKLIST_TIMEOUT),
        )
    except subprocess.TimeoutExpired:
        # The strict axis did NOT resolve. Returning [] here would let the caller
        # mistake "unknown" for "genuinely covered" - the false green. Surface it.
        return [], FCC_STATUS_FAILED
    except Exception:
        return [], FCC_STATUS_FAILED
    # A non-zero rc (other than the gate's own fail-functions exit) or an
    # unparseable body means the worklist is UNKNOWN, not empty-covered.
    out = (proc.stdout or "").strip()
    if not out:
        return [], FCC_STATUS_FAILED
    try:
        payload = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        return [], FCC_STATUS_FAILED
    rows = payload.get("worklist")
    if rows is None:
        # No worklist key at all -> the emit-worklist contract was not honoured;
        # treat as failed rather than as an authoritative empty.
        return [], FCC_STATUS_FAILED
    units: list[str] = []
    for f in rows:
        fn = str(f.get("function") or f.get("name") or "").strip()
        fl = str(f.get("file_line") or "").strip()
        fpath = fl.rsplit(":", 1)[0] if ":" in fl else fl
        fpath = fpath or str(f.get("file") or "").strip()
        if fn and fpath:
            units.append(f"{fpath}::{fn}")
    return units, FCC_STATUS_OK


def _g15_effective_uncovered(g15: dict, report: dict) -> tuple[int, list[str]]:
    """Effective-uncovered count + the unlogged-uncovered unit list.

    Prefer the G15 gate's effective accounting (it credits scanned/skip-logged
    units). Fall back to the raw coverage report uncovered count.
    """
    if isinstance(g15, dict) and g15.get("verdict"):
        eff = g15.get("uncovered_count")
        units = g15.get("unlogged_uncovered")
        if eff is None:
            eff = g15.get("raw_uncovered_count")
        if units is None:
            units = list(report.get("uncovered_units") or [])
        try:
            eff_i = int(eff) if eff is not None else len(report.get("uncovered_units") or [])
        except (TypeError, ValueError):
            eff_i = len(report.get("uncovered_units") or [])
        return eff_i, [str(u) for u in (units or [])]
    units = [str(u) for u in (report.get("uncovered_units") or [])]
    return len(units), units


def _coverage_fraction(g15: dict, report: dict) -> float:
    if isinstance(g15, dict) and g15.get("coverage_fraction") is not None:
        try:
            return float(g15["coverage_fraction"])
        except (TypeError, ValueError):
            pass
    total = int(report.get("total_units") or 0)
    covered = int(report.get("covered") or 0)
    return (covered / total) if total else 1.0


def _read_rubric_uncovered(ws_path: Path) -> tuple[dict, list[dict]]:
    """(report, uncovered_rows) via the canonical rubric tool import."""
    mod = _rubric_mod()
    if mod is not None and hasattr(mod, "build_report"):
        try:
            _verdict, report = mod.build_report(ws_path)
            if isinstance(report, dict):
                try:
                    _atomic_write_json(ws_path / RUBRIC_REPORT_REL, report)
                except OSError:
                    pass
                return report, list(report.get("uncovered_rows") or [])
        except Exception:
            pass
    p = ws_path / RUBRIC_REPORT_REL
    if p.is_file():
        try:
            report = json.loads(p.read_text(encoding="utf-8"))
            return report, list(report.get("uncovered_rows") or [])
        except (OSError, ValueError):
            return {}, []
    return {}, []


# --------------------------------------------------------------------------
# seeding (shell the existing tools)
# --------------------------------------------------------------------------
def _shell(cmd: list[str]) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        return cp.returncode, cp.stdout, cp.stderr
    except Exception as exc:  # noqa: BLE001 - orchestration is best-effort
        return 1, "", str(exc)


def _seed_surface(ws_path: Path, run_id: str) -> dict:
    cmd = [
        sys.executable, str(COVERAGE_SEED_TOOL),
        "--workspace-path", str(ws_path),
        "--rebuild-report", "--json",
    ]
    if run_id:
        cmd += ["--run-id", run_id]
    rc, out, err = _shell(cmd)
    parsed = {}
    try:
        parsed = json.loads(out) if out.strip() else {}
    except ValueError:
        parsed = {}
    return {
        "rc": rc,
        "seed_rows_total": int(parsed.get("seed_rows_total") or 0),
        "rows_written": int(parsed.get("rows_written") or 0),
        "rows_updated": int(parsed.get("rows_updated") or 0),
        "verdict": parsed.get("verdict"),
        "stderr_tail": (err or "").strip()[-300:],
    }


def _seed_rubric(ws_path: Path, run_id: str) -> dict:
    cmd = [
        sys.executable, str(RUBRIC_SEED_TOOL),
        "--workspace-path", str(ws_path),
        "--rebuild-report", "--seed-queue", "--json",
    ]
    if run_id:
        cmd += ["--run-id", run_id]
    rc, out, err = _shell(cmd)
    parsed = {}
    try:
        parsed = json.loads(out) if out.strip() else {}
    except ValueError:
        parsed = {}
    return {
        "rc": rc,
        "uncovered_rows_seeded": int(parsed.get("uncovered_rows_seeded") or 0),
        "queue_rows_written": int(parsed.get("queue_rows_written") or 0),
        "queue_rows_updated": int(parsed.get("queue_rows_updated") or 0),
        "seeded_briefs": parsed.get("seeded_briefs") or [],
        "verdict": parsed.get("verdict"),
        "stderr_tail": (err or "").strip()[-300:],
    }


# --------------------------------------------------------------------------
# bounded deterministic per-unit hunt
# --------------------------------------------------------------------------
# Stop-words filtered from camelCase/underscore token splits so that
# grammatical particles ('to', 'if', 'and', etc.) embedded in compound
# function names (constructor, _checkIfAllowedToTransact, …) do NOT
# spuriously trigger attack-class anchors meant for standalone semantic
# tokens like 'transfer', 'owner', 'amount', 'receiver'.
_FN_STOP_WORDS: frozenset[str] = frozenset({
    "to", "if", "and", "or", "is", "get", "set", "the", "an", "a",
    "of", "in", "at", "by", "for", "as", "on", "with", "from",
    "be", "has", "can", "do", "not",
})


def _fn_tokens(name: str) -> set[str]:
    """Split a function name on underscores + camelCase transitions and
    return the set of lowercase tokens with stop-words and single-char
    fragments removed.

    Examples
    --------
    _msgSender  -> {'msg', 'sender'}
    constructor -> {'constructor'}
    withdraw    -> {'withdraw'}
    _getFeeAndFeeReceiver -> {'fee', 'receiver'}
    """
    parts = re.split(r"[_]|(?<=[a-z])(?=[A-Z])", name)
    return {p.lower() for p in parts
            if len(p) > 1 and p.lower() not in _FN_STOP_WORDS}


def _unit_invariant_candidates(unit: str) -> list[str]:
    """Map a coverage unit to neutral invariant-anchor strings so the
    per-function-hacker-questions generator can emit adversarial questions.

    These anchors are derived ONLY from the unit's lexical shape (function
    name token set, after camelCase/underscore split and stop-word removal);
    they assert nothing. They are inputs to the deterministic question
    generator, not claims.

    Token-set matching (instead of substring matching) prevents short
    keywords like 'to', 'send', 'sig', 'abi' from firing on compound names
    that merely contain them as substrings (constructor, _msgSender,
    _reassign, _applyCustomFee, …).
    """
    _file, _sep, fn = unit.partition("::")
    toks = _fn_tokens(fn or _file)
    anchors: list[str] = []
    keyword_map = [
        (("transfer", "send", "withdraw", "deposit", "mint", "burn", "move"),
         "sum-preserved-conservation"),
        (("owner", "admin", "auth", "role", "permission", "access"),
         "access-control-missing-authz"),
        (("call", "execute", "invoke", "delegate", "external"),
         "reentrancy-external-call"),
        (("amount", "value", "balance", "qty"),
         "amount-nonzero"),
        (("recipient", "dest", "receiver"),
         "recipient-nonzero"),
        (("deadline", "expiry", "timestamp"),
         "deadline-future"),
        (("sign", "verify", "nonce", "sig", "ecdsa", "schnorr"),
         "nonce-reuse-malleability"),
        (("serialize", "encode", "decode", "borsh", "abi"),
         "serialization-roundtrip"),
    ]
    for keywords, anchor in keyword_map:
        if any(k in toks for k in keywords):
            anchors.append(anchor)
    return anchors


def _build_unit_fn_record(unit: str, source_path: str) -> dict:
    file_key, _sep, fn = unit.partition("::")
    return {
        "function": fn or file_key,
        "file": source_path or file_key,
        "language": "?",
        "invariant_candidates": _unit_invariant_candidates(unit),
    }


# r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
def _shell_timeout(cmd: list[str], timeout_s: int) -> tuple[int, str, str, bool]:
    """Run a bounded subprocess. Returns (rc, stdout, stderr, timed_out).

    A slow tool is NEVER skipped; it is time-bounded by ``timeout_s`` and, on
    expiry, returns timed_out=True so the caller records a ``timeout`` status
    rather than a silent no-op.
    """
    try:
        cp = subprocess.run(
            cmd, capture_output=True, text=True, timeout=max(1, timeout_s)
        )
        return cp.returncode, cp.stdout, cp.stderr, False
    except subprocess.TimeoutExpired:
        return 124, "", "timeout", True
    except Exception as exc:  # noqa: BLE001 - per-tool isolation
        return 1, "", str(exc), False


def _arsenal_hacker_q(fn_rec: dict) -> tuple[dict, list[dict]]:
    """In-process per-function adversarial questions. Returns (record, questions).

    hypothesis when >=1 question emitted, else no-finding. No proven claim.
    """
    questions: list[dict] = []
    mod = _hacker_q_mod()
    if mod is not None and hasattr(mod, "gen_questions"):
        try:
            questions = mod.gen_questions(fn_rec) or []
        except Exception:
            questions = []
    result = TOOL_RESULT_HYPOTHESIS if questions else TOOL_RESULT_NO_FINDING
    rec = {
        "tool": "per-function-hacker-questions",
        "status": TOOL_STATUS_RAN,
        "result": result,
        "detail": {"question_count": len(questions)},
    }
    return rec, questions


def _arsenal_scoped_detector(
    ws_path: Path, source_path: str, cache: dict
) -> dict:
    """Scoped regex/rust/go detector re-run on the unit's source file's
    containing directory (cached per directory so units in the same dir reuse
    the single scan). hypothesis when the detector reports >=1 hit, else
    no-finding. Honest: a hit is a candidate to triage, NOT a proven bug.
    """
    ext = os.path.splitext(source_path)[1].lower()
    tool = _DETECTOR_BY_EXT.get(ext)
    rec = {"tool": "scoped-detector", "status": TOOL_STATUS_UNAVAILABLE,
           "result": "n/a", "detail": {"ext": ext}}
    if tool is None or not tool.is_file():
        return rec
    abs_src = ws_path / source_path
    scan_dir = abs_src.parent if abs_src.exists() else ws_path
    cache_key = ("detector", str(scan_dir))
    if cache_key in cache:
        cached = dict(cache[cache_key])
        cached["detail"] = dict(cached.get("detail") or {})
        cached["detail"]["cached"] = True
        return cached
    rc, out, _err, timed_out = _shell_timeout(
        [sys.executable, str(tool), "--scan", str(scan_dir), "--json"],
        ARSENAL_TIMEOUT_DETECTOR,
    )
    if timed_out:
        rec.update(status=TOOL_STATUS_TIMEOUT, result="n/a")
        return rec
    hits = None
    try:
        # tools print a human line then optional JSON; grab the JSON tail.
        for line in reversed((out or "").strip().splitlines()):
            line = line.strip()
            if line.startswith("{"):
                d = json.loads(line)
                hits = d.get("hits") or d.get("total_hits") or d.get("findings")
                if isinstance(hits, list):
                    hits = len(hits)
                break
    except (ValueError, TypeError):
        hits = None
    if hits is None:
        # fall back to the on-disk findings sidecar the runner writes
        for fname in ("rust_findings.json", "go_findings.json"):
            fp = scan_dir / ".auditooor" / fname
            if fp.is_file():
                try:
                    fd = json.loads(fp.read_text(encoding="utf-8"))
                    h = fd.get("hits") or fd.get("findings") or []
                    hits = len(h) if isinstance(h, list) else int(h or 0)
                    break
                except (OSError, ValueError, TypeError):
                    continue
    hit_n = int(hits) if isinstance(hits, int) else 0
    rec.update(
        status=TOOL_STATUS_RAN if rc == 0 else TOOL_STATUS_ERROR,
        result=TOOL_RESULT_HYPOTHESIS if hit_n > 0 else TOOL_RESULT_NO_FINDING,
        detail={"ext": ext, "hits": hit_n, "scan_dir": str(scan_dir)},
    )
    cache[cache_key] = rec
    return rec


def _arsenal_invariant_synth(
    ws_path: Path, source_path: str, run_id: str, cache: dict
) -> dict:
    """Scoped invariant-auto-synth on the unit's source file (cached per file).
    hypothesis when >=1 invariant record synthesized, else no-finding. A
    synthesized invariant is a PROPERTY to attempt, NOT a proven finding.
    """
    rec = {"tool": "invariant-auto-synth", "status": TOOL_STATUS_UNAVAILABLE,
           "result": "n/a", "detail": {}}
    if not INVARIANT_SYNTH_TOOL.is_file():
        return rec
    cache_key = ("invariant", source_path)
    if cache_key in cache:
        cached = dict(cache[cache_key])
        cached["detail"] = dict(cached.get("detail") or {})
        cached["detail"]["cached"] = True
        return cached
    out_dir = ws_path / ".auditooor" / "coverage_unit_invariants"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / (_slug_unit(source_path) + ".json")
    rc, out, _err, timed_out = _shell_timeout(
        [
            sys.executable, str(INVARIANT_SYNTH_TOOL),
            "--workspace", str(ws_path),
            "--src-glob", source_path,
            "--output", str(out_json),
            "--max-files", "1",
            "--json",
        ],
        ARSENAL_TIMEOUT_INVARIANT,
    )
    if timed_out:
        rec.update(status=TOOL_STATUS_TIMEOUT, result="n/a")
        return rec
    records = 0
    try:
        for line in reversed((out or "").strip().splitlines()):
            line = line.strip()
            if line.startswith("{"):
                records = int(json.loads(line).get("records") or 0)
                break
    except (ValueError, TypeError):
        records = 0
    rec.update(
        status=TOOL_STATUS_RAN if rc == 0 else TOOL_STATUS_ERROR,
        result=TOOL_RESULT_HYPOTHESIS if records > 0 else TOOL_RESULT_NO_FINDING,
        detail={"invariant_records": records, "output": str(out_json)},
    )
    cache[cache_key] = rec
    return rec


def _arsenal_mimo_harness(
    ws_path: Path, unit: str, source_path: str, questions: list[dict], run_id: str
) -> dict:
    """Per-fn mimo/per-fn-harness brief for the unit. Emits an ADVISORY mimo
    harness task brief (hunt fuel) keyed to the unit; hypothesis when a brief
    is produced. The brief is a starting point for an LLM-depth lane, NOT a
    proven finding - it carries no attack_class/severity/claim.
    """
    rec = {"tool": "per-fn-mimo-harness", "status": TOOL_STATUS_RAN,
           "result": TOOL_RESULT_NO_FINDING, "detail": {}}
    # The per-fn mimo harness brief is built from the unit's adversarial
    # questions. With >=1 question we emit a bounded advisory brief sidecar;
    # with none there is nothing to seed a harness from (no-finding).
    if not questions:
        return rec
    file_key, _sep, fn = unit.partition("::")
    brief = {
        "schema": "auditooor.coverage_unit_mimo_harness_brief.v1",
        "generated_at_utc": _utc_now(),
        "run_id": run_id or None,
        "unit_id": unit,
        "source_path": source_path,
        "function": fn or file_key,
        "advisory": True,
        "is_r80_poc": False,
        "harness_questions": [
            q.get("question") for q in questions if isinstance(q, dict)
        ][:8],
        "note": (
            "advisory per-fn mimo harness brief - hunt fuel for an LLM-depth "
            "lane; carries NO attack_class/severity/claim (R80 safe)"
        ),
    }
    out = ws_path / ".auditooor" / "coverage_unit_mimo_briefs" / (
        _slug_unit(unit) + ".json"
    )
    try:
        _atomic_write_json(out, brief)
        rec.update(
            result=TOOL_RESULT_HYPOTHESIS,
            detail={"brief_path": str(out),
                    "harness_question_count": len(brief["harness_questions"])},
        )
    except OSError as exc:
        rec.update(status=TOOL_STATUS_ERROR, result="n/a",
                   detail={"error": str(exc)})
    return rec


def _run_unit_arsenal(
    ws_path: Path,
    unit: str,
    source_path: str,
    fn_rec: dict,
    run_id: str,
    cache: dict,
) -> tuple[list[dict], list[dict]]:
    """Drive ONE uncovered unit through the FULL bounded arsenal.

    Returns (tool_records, questions). Each tool record is
    {tool, status, result, detail}. The tools run are:
      1. per-function-hacker-questions (in-process)
      2. scoped detector re-run (rust/go regex detectors, per-dir cached)
      3. per-fn mimo harness brief (advisory hunt fuel)
      4. invariant-auto-synth (scoped per-file, per-file cached)
    Every tool is per-tool-timeout bounded; a slow tool is time-bounded, not
    skipped. Honest: results are only no-finding / hypothesis; never a claim.
    """
    records: list[dict] = []
    hq_rec, questions = _arsenal_hacker_q(fn_rec)
    records.append(hq_rec)
    records.append(_arsenal_scoped_detector(ws_path, source_path, cache))
    records.append(
        _arsenal_mimo_harness(ws_path, unit, source_path, questions, run_id)
    )
    records.append(
        _arsenal_invariant_synth(ws_path, source_path, run_id, cache)
    )
    return records, questions


def _run_unit_deterministic_hunt(
    ws_path: Path,
    unit: str,
    source_path: str,
    run_id: str,
    arsenal_cache: dict | None = None,
) -> dict:
    """Run a BOUNDED deterministic hunt for ONE uncovered unit + write a
    per-unit verdict sidecar. Returns the verdict dict.

    Drives the unit through the FULL bounded arsenal (per-fn hacker-questions +
    scoped detector re-run + per-fn mimo harness brief + invariant-synth), each
    per-tool-timeout bounded, and records WHICH tools ran + their result in the
    sidecar. No LLM is invoked. The verdict is one of two HONEST values; neither
    carries a claim.  <!-- r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json -->
    """
    fn_rec = _build_unit_fn_record(unit, source_path)
    cache = arsenal_cache if arsenal_cache is not None else {}
    tool_records, questions = _run_unit_arsenal(
        ws_path, unit, source_path, fn_rec, run_id, cache
    )
    # A unit "needs LLM depth" when ANY arsenal tool emitted a hypothesis
    # (adversarial question, detector hit, mimo harness brief, or synthesized
    # invariant). It is "no-finding" ONLY when every tool ran clean. Either way
    # NOTHING is proven - the verdict carries no claim.
    hypothesis_tools = [
        r["tool"] for r in tool_records
        if r.get("result") == TOOL_RESULT_HYPOTHESIS
    ]
    if hypothesis_tools:
        verdict = VERDICT_NEEDS_LLM
        reason = (
            "arsenal pass emitted hypotheses from %d tool(s) (%s); no impact "
            "proven mechanically - requires LLM-depth lane"
            % (len(hypothesis_tools), ", ".join(hypothesis_tools))
        )
    else:
        verdict = VERDICT_NO_FINDING
        reason = (
            "arsenal pass: every tool ran clean (no question / detector hit / "
            "harness / invariant); coverage credit only - NOT a safety proof "
            "and NOT a finding"
        )

    sidecar = {
        "schema": PER_UNIT_VERDICT_SCHEMA,
        "generated_at_utc": _utc_now(),
        "run_id": run_id or None,
        "workspace": ws_path.name,
        "unit_id": unit,
        "source_path": source_path,
        "verdict": verdict,
        "reason": reason,
        # self-label so this is never mistaken for an R80 PoC
        "coverage_credit": COVERAGE_CREDIT_LABEL,
        "is_r80_poc": False,
        # WHICH tools ran + their (no-finding | hypothesis) result
        "arsenal_tools": tool_records,
        "arsenal_tools_ran": [r["tool"] for r in tool_records],
        "arsenal_hypothesis_tools": hypothesis_tools,
        "adversarial_questions": [
            q.get("question") for q in questions if isinstance(q, dict)
        ],
        "question_count": len(questions),
    }
    # R80 honest-no-finding invariant: a no-finding verdict carries NO claim.
    if verdict == VERDICT_NO_FINDING:
        for f in FORBIDDEN_NO_FINDING_FIELDS:
            if f in sidecar:
                raise AssertionError(
                    "no-finding honesty invariant violated: claim field %r" % f
                )

    out = ws_path / PER_UNIT_VERDICT_DIR_REL / (_slug_unit(unit) + ".json")
    try:
        _atomic_write_json(out, sidecar)
    except OSError:
        pass
    sidecar["sidecar_path"] = str(out)
    return sidecar


def _source_path_for_unit(ws_path: Path, unit: str) -> str:
    """Best-effort concrete source path for a unit (reuse coverage-to-hunt-seed
    helper when available)."""
    seed_mod = _import_by_path("_acc_seed", COVERAGE_SEED_TOOL)
    file_key = unit.partition("::")[0]
    if seed_mod is not None and hasattr(seed_mod, "_unit_source_path"):
        try:
            return seed_mod._unit_source_path("", file_key, ws_path)
        except Exception:
            pass
    return file_key


def _per_unit_hunt_pass(
    ws_path: Path,
    uncovered_units: list[str],
    run_id: str,
    unit_cap: int,
) -> dict:
    no_finding = 0
    needs_llm = 0
    needs_llm_units: list[str] = []
    processed: list[str] = []
    # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
    # Shared arsenal cache across the pass: file-scoped tools (detector per dir,
    # invariant-synth per file) run ONCE and are reused by every unit in that
    # file/dir - keeps the full arsenal bounded without skipping any tool.
    arsenal_cache: dict = {}
    arsenal_tool_tally: dict[str, dict[str, int]] = {}
    for unit in uncovered_units[: max(0, unit_cap)] if unit_cap >= 0 else uncovered_units:
        sp = _source_path_for_unit(ws_path, unit)
        verdict = _run_unit_deterministic_hunt(
            ws_path, unit, sp, run_id, arsenal_cache=arsenal_cache
        )
        processed.append(unit)
        for tr in verdict.get("arsenal_tools") or []:
            t = tr.get("tool", "?")
            r = tr.get("result", "?")
            arsenal_tool_tally.setdefault(t, {})
            arsenal_tool_tally[t][r] = arsenal_tool_tally[t].get(r, 0) + 1
        if verdict["verdict"] == VERDICT_NEEDS_LLM:
            needs_llm += 1
            needs_llm_units.append(unit)
        else:
            no_finding += 1
    return {
        "units_processed": len(processed),
        "mechanical_hunt_no_finding": no_finding,
        "needs_llm_depth": needs_llm,
        "needs_llm_depth_units": needs_llm_units,
        "arsenal_tool_tally": arsenal_tool_tally,
    }


# --------------------------------------------------------------------------
# residual worker-dispatch queue
# --------------------------------------------------------------------------
def _emit_residual_queue(
    ws_path: Path,
    needs_llm_units: list[str],
    uncovered_rows: list[dict],
    run_id: str,
) -> dict:
    # SCOPE-INTEGRITY FIX (obyte step-3, 2026-07-10): the residual worker queue is
    # the OBLIGATION denominator - hunt-obligation-resolve.py reads
    # residual_surface_units as the exact threshold the residual-llm-depth hunt
    # must meet. Building it from needs_llm_units with NO scope filter let OOS
    # source paths (SCOPE.md OOS dirs such as counterstake-bridge/evm-v1.0/, which
    # exist on disk and so flow through the deterministic pass, but are excluded
    # from inscope_units.jsonl) leak in: 19 OOS units inflated the threshold to 41
    # while only 22 in-scope units were coverable, making the obligation
    # STRUCTURALLY UNRESOLVABLE (a false-red the hunt could never clear). The OOS
    # leak also basename-collided the in-scope evm/ units with their evm-v1.0/
    # namesakes (the same file-blind collision class fixed in
    # function-coverage-completeness). Drop any unit whose source path is not in
    # inscope_units.jsonl; keep-all only when the manifest is absent (legacy /
    # backward-compatible, identical contract to _fold_question_in_scope). This
    # can only SHRINK the queue, never add a unit, so it is false-green-safe.
    inscope = _load_inscope_source_paths(ws_path)
    kept_units: list[str] = []
    oos_filtered: list[str] = []
    for u in needs_llm_units:
        if _fold_question_in_scope(ws_path, _source_path_for_unit(ws_path, u), inscope):
            kept_units.append(u)
        else:
            oos_filtered.append(u)
    unit_items = [
        {
            "kind": "surface-unit",
            "unit_id": u,
            "source_path": _source_path_for_unit(ws_path, u),
            "reason": "deterministic pass left adversarial questions unresolved; "
                      "needs LLM-depth hunt",
            "lane_type": "hunt",
        }
        for u in kept_units
    ]
    class_items = [
        {
            "kind": "rubric-class",
            "tier": str(r.get("tier") or "?"),
            "rubric_id": str(r.get("rubric_id") or ""),
            "rubric_sentence": str(r.get("sentence") or ""),
            "reason": "impact class still UNATTEMPTED after mechanical seed; "
                      "needs LLM-depth hunt",
            "lane_type": "hunt",
        }
        for r in uncovered_rows
    ]
    payload = {
        "schema": RESIDUAL_QUEUE_SCHEMA,
        "generated_at_utc": _utc_now(),
        "run_id": run_id or None,
        "workspace": ws_path.name,
        "workspace_path": str(ws_path),
        "residual_surface_units": len(unit_items),
        "residual_surface_units_oos_filtered": len(oos_filtered),
        "residual_rubric_classes": len(class_items),
        "total_residual": len(unit_items) + len(class_items),
        "items": unit_items + class_items,
    }
    _atomic_write_json(ws_path / RESIDUAL_QUEUE_REL, payload)
    return payload


# --------------------------------------------------------------------------
# SADL + CRC + SIDL + ORL + RDL hypothesis fold into per_fn_hacker_questions corpus
# --------------------------------------------------------------------------
def _load_inscope_source_paths(ws_path: Path) -> set[str] | None:
    """Absolute source paths of the in-scope units from inscope_units.jsonl.

    Returns None when the manifest is absent (caller falls back to a lenient
    exists-and-not-vendored check). Used to keep folded hypothesis questions
    R76-grounded + in-scope: a Solidity workspace must not accrue rust/go/ts or
    stale cross-workspace hypothesis questions whose source is out of scope.
    """
    mf = ws_path / ".auditooor" / "inscope_units.jsonl"
    if not mf.is_file():
        return None
    out: set[str] = set()
    try:
        text = mf.read_text(encoding="utf-8")
    except OSError:
        return None
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            row = json.loads(ln)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(row, dict):
            continue
        rel = row.get("file") or row.get("path") or row.get("source_path")
        if not rel:
            continue
        p = Path(str(rel))
        ap = p if p.is_absolute() else ws_path / str(rel)
        try:
            out.add(str(ap.resolve()))
        except OSError:
            out.add(str(ap))
    return out or None


def _fold_question_in_scope(ws_path: Path, file_rel: str,
                            inscope: set[str] | None) -> bool:
    """True iff a folded hypothesis question's source file is in-scope + real.

    GENERIC FIX (hyperlane step-3, 2026-06-21): the lane-hypothesis fold appended
    questions by source_path with NO scope filter, so stale/cross-language (rust)
    hypotheses polluted a Solidity workspace's per-fn hunt worklist (172 rust /
    23 solidity observed). Dropping out-of-scope or non-existent source paths
    keeps the worklist R76-grounded + scoped, for every workspace.
    """
    # No authoritative manifest -> cannot determine scope; keep-all (legacy,
    # backward compatible). The filter only engages when inscope_units.jsonl
    # exists, which is the authoritative in-scope source set.
    if inscope is None:
        return True
    if not file_rel:
        return False  # manifest present but record has no source -> not verifiable
    p = Path(str(file_rel))
    ap = p if p.is_absolute() else ws_path / str(file_rel)
    try:
        aps = str(ap.resolve())
    except OSError:
        aps = str(ap)
    return aps in inscope


def _fold_lane_hypotheses_into_corpus(ws_path: Path, run_id: str) -> dict:
    """Read self_dealing_hypotheses.jsonl, callback_reentrancy_hypotheses.jsonl,
    share_inflation_hypotheses.jsonl, oracle_reachability_hypotheses.jsonl, and
    rounding_drain_hypotheses.jsonl (emitted by audit-deep Steps 22-26) and APPEND
    their records to per_fn_hacker_questions.jsonl so the hunt sees them as
    additional adversarial fuel.

    NO-AUTO-CREDIT contract: every appended record carries verdict=needs-fuzz.
    This function NEVER increments per_function_verified, never flips a gate
    to pass, and never resolves a unit's verdict.  The records are
    HYPOTHESIS-ONLY - they identify a candidate attack shape; the LLM hunt
    and the fuzz campaign must independently confirm or refute each one.

    Schema contract: each folded record is a valid per_fn_hacker_questions.v1
    entry - same shape the L37 hacker-questions gate expects:
      {schema_version, workspace, run_id, unit_id, source_path, question,
       attack_class, verdict}
    attack_class and verdict are included (unlike the arsenal-question fold
    which omits them) because these come from a tool with a known class and an
    explicit needs-fuzz verdict - they are NOT proven claims.

    Returns a summary dict for the run result.
    """
    sources: list[tuple[str, Path]] = [
        ("SADL",    ws_path / SADL_HYPOTHESES_REL),
        ("CRC",     ws_path / CRC_HYPOTHESES_REL),
        ("SIDL",    ws_path / SHARE_INFLATION_HYPOTHESES_REL),
        ("ORL",     ws_path / ORACLE_REACHABILITY_HYPOTHESES_REL),
        ("RDL",     ws_path / ROUNDING_DRAIN_HYPOTHESES_REL),
        ("MOL",     ws_path / MEV_ORDERING_HYPOTHESES_REL),
        ("ACL-COV", ws_path / ACCESS_CONTROL_HYPOTHESES_REL),
        ("IUL",     ws_path / INIT_UPGRADE_HYPOTHESES_REL),
    ] + [("GO-ADV", ws_path / rel) for rel in GO_ADVISORY_HYPOTHESES_REL] \
      + [("RUST-ADV", ws_path / rel) for rel in RUST_ADVISORY_HYPOTHESES_REL] \
      + [("NETNEW-ADV", ws_path / rel) for rel in NETNEW_ADVISORY_HYPOTHESES_REL]
    appended = 0
    skipped_files: list[str] = []
    out_of_scope_filtered = 0
    inscope_paths = _load_inscope_source_paths(ws_path)

    out_path = ws_path / PER_FN_HACKER_QUESTIONS_REL
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return {"appended": 0, "error": "could not create .auditooor dir"}

    new_records: list[dict] = []
    for source_label, jsonl_path in sources:
        if not jsonl_path.is_file():
            skipped_files.append(f"{source_label} (absent)")
            continue
        try:
            raw = jsonl_path.read_text(encoding="utf-8")
        except OSError:
            skipped_files.append(f"{source_label} (read error)")
            continue
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(obj, dict):
                continue
            # Build a canonical per_fn_hacker_questions record.
            fn_name = obj.get("function") or obj.get("reentry_target") or "?"
            file_rel = obj.get("file") or obj.get("reentry_target_file") or ""
            # GENERIC scope/R76 filter: drop folded hypotheses whose source is
            # out-of-scope or non-existent (e.g. stale rust paths in a Solidity ws).
            if not _fold_question_in_scope(ws_path, file_rel, inscope_paths):
                out_of_scope_filtered += 1
                continue
            attack_class = obj.get("attack_class", "")
            # Human-readable question synthesised from the hypothesis fields.
            if source_label == "SADL":
                collapse = obj.get("collapse_expr", "")
                note = obj.get("note", "")
                question = (
                    f"[SADL] Does {fn_name} permit identity collapse "
                    f"({collapse})? {note}"
                ).strip()
            elif source_label == "SIDL":
                ac = obj.get("attack_class", "share-inflation")
                note = obj.get("note", "")
                question = (
                    f"[SIDL] Can an attacker exploit {fn_name} via a "
                    f"{ac} attack to inflate the share price? {note}"
                ).strip()
            elif source_label == "ORL":
                read_kind = obj.get("read_kind", "oracle read")
                value_loss_path = obj.get("value_loss_path", "")
                note = obj.get("note", "")
                extra = value_loss_path or note
                question = (
                    f"[ORL] Can an attacker manipulate the {read_kind} consumed by "
                    f"{fn_name} to cause a value-loss via oracle-price-manipulation? "
                    f"{extra}"
                ).strip()
                attack_class = obj.get("attack_class", "oracle-price-manipulation")
            elif source_label == "RDL":
                op = obj.get("rounding_op", "rounding-op")
                direction = obj.get("direction", "?")
                vpath = obj.get("value_path", "?")
                note = obj.get("direction_reason", obj.get("note", ""))
                question = (
                    f"[RDL] Does repeated calling of {fn_name} drain the protocol "
                    f"via {op} ({direction}, {vpath} path)? {note}"
                ).strip()
                attack_class = obj.get("attack_class", "rounding-drain")
            elif source_label == "MOL":
                state_read = obj.get("read_kind", "mutable pool/price state")
                sens = obj.get("sensitivity_reason", "")
                prot = obj.get("protection_reason", "")
                extra = " ".join(x for x in (sens, prot) if x).strip()
                question = (
                    f"[MOL] Can an attacker sandwich/front-run {fn_name} by ordering a "
                    f"tx around it - its payout depends on {state_read} and it lacks "
                    f"ordering protection? {extra}"
                ).strip()
                attack_class = obj.get("attack_class", "sandwich-front-run-ordering")
            elif source_label == "ACL-COV":
                # Skip typed-skip note records - they carry no actionable question.
                if obj.get("_acl_skip") or obj.get("verdict") == "typed-skip":
                    continue
                admin_action = obj.get("admin_action", "privileged admin action")
                guard_reason = obj.get("guard_reason", "")
                lang = obj.get("language", "unknown")
                question = (
                    f"[ACL-COV] Is {fn_name} a privileged admin action callable "
                    f"without authorization ({admin_action})? {guard_reason}"
                ).strip()
                attack_class = obj.get("attack_class", "missing-authorization-privilege-escalation")
            elif source_label == "IUL":
                iou = obj.get("init_or_upgrade", "initializer/upgrade")
                missing = obj.get("missing_guard", "")
                dcount = obj.get("diamond_candidate_count")
                if dcount:
                    question = (
                        f"[IUL] Verify diamondCut owner-gates all {dcount} Init* "
                        f"contracts; a directly-callable init mutating Diamond "
                        f"storage would be unprotected. {missing}"
                    ).strip()
                else:
                    question = (
                        f"[IUL] Is {fn_name} an unprotected {iou} (callable to "
                        f"(re)initialize or upgrade without authorization)? {missing}"
                    ).strip()
                attack_class = obj.get("attack_class", "unprotected-initialization-or-upgrade")
            elif source_label == "GO-ADV":
                # One generic branch for all 9 Go wave-2 advisory lanes. Each
                # record carries file/line/function/pattern_id/attack_class/source
                # (the G-lane tag) + a snippet; synthesise a needs-fuzz question
                # from the record's own class so no lane is silently dropped.
                pid = obj.get("pattern_id", "")
                glane = obj.get("source", "GO")
                snippet = (obj.get("snippet") or "").strip().replace("\n", " ")[:160]
                cls = attack_class or pid or "go-advisory"
                question = (
                    f"[{glane}] Go advisory ({cls}): does {fn_name} at {file_rel} "
                    f"exhibit the {pid or cls} defect? {snippet}"
                ).strip()
                attack_class = obj.get("attack_class", pid or "go-advisory")
            elif source_label == "RUST-ADV":
                # One generic branch for all 6 Rust wave-2 advisory axes. Each record
                # carries file/line/function/axis/attack_class/source + a snippet.
                axis = obj.get("axis", "")
                snippet = (obj.get("snippet") or "").strip().replace("\n", " ")[:160]
                cls = attack_class or axis or "rust-advisory"
                question = (
                    f"[RUST-ADV/{axis or '?'}] Rust advisory ({cls}): does {fn_name} at "
                    f"{file_rel} exhibit the {cls} defect? {snippet}"
                ).strip()
                attack_class = obj.get("attack_class", axis or "rust-advisory")
            elif source_label == "NETNEW-ADV":
                # One generic branch for ALL net-new general-logic advisory screens
                # (arch-deep A1-A5, enforcement-layer EL1-EL6, Rust R1/R3/R5, Go
                # GEN-D consensus, cross-lang GEN-4B..., + future). Each row carries
                # capability + severity + why_severity_anchored (a full mechanism
                # explanation) + arm/return_sink/sink/unsound_form-style class hints.
                # Synthesise a faithful needs-fuzz question from the row's OWN class
                # so no net-new lane folds through to a mislabelled CRC question.
                cap = obj.get("capability", "GEN")
                sev = obj.get("severity", "")
                # the most specific class hint the row carries.
                cls = (obj.get("attack_class") or obj.get("arm")
                       or obj.get("unsound_form") or obj.get("return_sink")
                       or obj.get("sink") or obj.get("drift_kind")
                       or obj.get("dispatch_kind") or obj.get("gas_construct")
                       or cap)
                why = (obj.get("why_severity_anchored") or "").strip().replace(
                    "\n", " ")[:220]
                question = (
                    f"[{cap}/{cls}] {sev or 'advisory'} net-new-logic: does "
                    f"{fn_name} at {file_rel} exhibit the {cls} defect? {why}"
                ).strip()
                # classify by the SPECIFIC defect (arm/return_sink/...), mirroring
                # the GO-ADV branch's pattern_id use; fall back to the capability.
                attack_class = obj.get("attack_class") or str(cls) or (
                    str(cap).lower().replace("_", "-"))
            else:  # CRC
                window_fn = obj.get("function", "?")
                target_fn = obj.get("reentry_target", "?")
                note = obj.get("note", "")
                question = (
                    f"[CRC] Can an attacker re-enter {target_fn} from within "
                    f"{window_fn}'s callback window? {note}"
                ).strip()
            # NO-AUTO-CREDIT: verdict is always needs-fuzz; the record is
            # hunt fuel, not a proven impact.
            lane_rec = {
                "schema_version": PER_FN_HACKER_QUESTIONS_SCHEMA,
                "workspace": ws_path.name,
                "run_id": run_id or None,
                "unit_id": fn_name,
                "source_path": file_rel,
                "question": question,
                "attack_class": attack_class,
                "verdict": "needs-fuzz",
                "source": source_label,
            }
            lane_rec.update(_enrich_fn_anchor(ws_path, str(fn_name or ""), str(file_rel or "")))
            new_records.append(lane_rec)

    if new_records:
        try:
            # APPEND to the existing per_fn_hacker_questions.jsonl (which may
            # have already been written by _fold_per_fn_hacker_questions above).
            with out_path.open("a", encoding="utf-8") as fh:
                for rec in new_records:
                    fh.write(json.dumps(rec) + "\n")
            appended = len(new_records)
        except OSError:
            return {"appended": 0, "error": "write failed", "skipped": skipped_files}

    # ENFORCEMENT (operator: "nothing must be advisory - we end up skipping it").
    # Every folded advisory hypothesis (all sources incl. the net-new general-logic
    # screens) also becomes an OPEN hacker-question OBLIGATION in
    # hacker_question_obligations.jsonl. The audit-complete `fail-open-hacker-
    # questions` (F2 E2.1) signal then fail-closes under STRICT while ANY obligation
    # is open, and hacker-question-obligation-resolve.py only moves open->killed when
    # a CITED per-question verdict sidecar exists - so a fired advisory row can no
    # longer be silently skipped: it must be answered/refuted-with-evidence before
    # audit-complete passes. Best-effort + idempotent (dedup by obligation_id); a
    # failure here never breaks the per_fn fold.
    obl_created = 0
    if new_records:
        try:
            obl_created = _seed_advisory_obligations(ws_path, new_records)
        except Exception:  # pragma: no cover - never break the fold on this
            obl_created = -1

    return {
        "appended": appended,
        "skipped_files": skipped_files,
        "out_of_scope_filtered": out_of_scope_filtered,
        "obligations_seeded": obl_created,
        "path": str(out_path),
    }


def _seed_advisory_obligations(ws_path: Path, records: list[dict]) -> int:
    """Append each folded advisory per_fn_hacker_questions record as an OPEN
    obligation so `fail-open-hacker-questions` enforces its resolution. Returns
    the count of newly-appended (non-duplicate) obligations. Idempotent."""
    import importlib.util
    mod_path = Path(__file__).resolve().parent / "hacker-question-obligations.py"
    if not mod_path.is_file():
        return 0
    spec = importlib.util.spec_from_file_location("hqo_seed", mod_path)
    hqo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hqo)
    rows = []
    for rec in records:
        q = (rec.get("question") or "").strip()
        unit = rec.get("unit_id") or "?"
        fpath = rec.get("source_path") or ""
        if not q or not fpath:
            continue
        # Prefer the enriched anchor the fold stamped (function_name/language);
        # fall back to deriving from the unit_id so a pre-enrichment record still
        # gets a bare fn name + language rather than the whole path::qualified id
        # and "unknown" (which surfaced as "by language: unknown=125" on axelar-dlt).
        fn_name = rec.get("function_name") or _fn_name_from_unit(str(unit)) or unit
        language = rec.get("language")
        if not language:
            ext = Path(str(fpath)).suffix.lower()
            language = _IMPACT_FOLD_LANG_BY_EXT.get(ext, "unknown")
        ob = hqo.make_obligation(
            workspace=ws_path.name,
            file=fpath,
            function_signature=unit,
            function_name=fn_name,
            language=language,
            attack_class=rec.get("attack_class") or "advisory",
            question=q,
            question_source="auto-coverage-closer-advisory-fold",
            rationale=("advisory needs-fuzz hypothesis from a net-new/general-logic "
                       "screen; must be answered or refuted-with-evidence, never "
                       "silently skipped"),
            state="open",
        )
        # Tag as ADVISORY corpus-fuel so the hacker-question gate's corpus-grounding
        # branch (audit-completeness-check.check_hacker_questions_resolved) can credit
        # it once a non-vacuous corpus-driven-hunt has GROUNDED the corpus against
        # target source - exactly the DESIGNED resolution path for advisory hypotheses.
        # Without these two fields the resolver's grounding branch keyed on
        # {advisory_only, source_kind} matched NEITHER a corpus-grounding credit NOR a
        # per-question source sidecar, so an auto-coverage-closer advisory fold sat
        # PERMANENTLY OPEN (axelar-dlt 2026-07-13: 9 folds fail-open-hacker-questions,
        # neither credit branch ever fired). These folds are needs-fuzz HUNT-FUEL, not
        # real per-fn source obligations - they are answered by grounding, never by a
        # per-question verdict sidecar. NEVER-FALSE-PASS: only the closer's OWN folds
        # get this advisory tag, so a genuine per-fn obligation (untagged) still
        # requires a real per-fn verdict sidecar and is never grounding-credited.
        ob["advisory_only"] = True
        ob["source_kind"] = "auto_coverage_closer_advisory_fold"
        rows.append(ob)
    if not rows:
        return 0
    summ = hqo.append_obligations(ws_path, rows)
    return int(summ.get("appended", 0))


# --------------------------------------------------------------------------
# recall-gap reweighting of the per-fn hacker-questions worklist
# --------------------------------------------------------------------------
# Repo-level recall-gap scoreboard prioritizer output (emitted by
# tools/audit/realworld-recall-gap-prioritizer.py). It ranks attack classes by
# how badly the detector library MISSES real-world same-class bugs, so the
# worklist can be reweighted to attack the highest-recall-gap angles FIRST.
RECALL_GAP_PRIORITIES_REL = os.path.join(
    "reports", "realworld_recall_gap_priorities.json"
)
# Legacy worklist class names -> canonical recall-gap attack_class names.
# Mirrors realworld-recall-gap-prioritizer.LEGACY_ATTACK_CLASS_ALIASES so the
# coarse lexical question classes line up with the scoreboard taxonomy.
_RECALL_GAP_CLASS_ALIASES = {
    "access-control-missing-authz": "admin-bypass",
    "access-control-missing": "admin-bypass",
    "access-control": "admin-bypass",
    "reentrancy-external-call": "reentrancy-cross-contract",
    "reentrancy": "reentrancy-cross-contract",
    "nonce-reuse-malleability": "signature-replay-cross-domain",
    "signature-replay": "signature-replay-cross-domain",
    "sum-preserved-conservation": "fund-loss-via-arithmetic",
    "amount-nonzero": "fund-loss-via-arithmetic",
    "recipient-nonzero": "missing-recipient-validation",
    "serialization-roundtrip": "serialization-confusion",
}
# Question text -> coarse class, reusing the SAME keyword taxonomy the unit
# anchor builder uses (_unit_invariant_candidates), so the fold can infer a
# routing class from the question string WITHOUT re-running the producer.
# (keyword set, coarse-class) - first match wins; falls back to generic.
_RECALL_GAP_QUESTION_KEYWORDS = [
    (("owner", "admin", "auth", "role", "permission", "access", "signer",
      "onlyowner", "authorized"), "access-control-missing-authz"),
    (("reentr", "external call", "callback", "delegatecall", "hook"),
     "reentrancy-external-call"),
    (("nonce", "signature", "ecdsa", "schnorr", "replay", "malleab"),
     "nonce-reuse-malleability"),
    (("conservation", "sum", "balance", "invariant is violated", "fund",
      "withdraw", "deposit", "mint", "burn"), "sum-preserved-conservation"),
    (("recipient", "receiver", "destination"), "recipient-nonzero"),
    (("serialize", "deserialize", "encode", "decode", "borsh", "abi"),
     "serialization-roundtrip"),
]
# Neutral default score when no recall-gap signal is available (so a missing
# scoreboard is graceful: the worklist still dedups + stable-sorts, just with a
# flat priority). Generic / unclassifiable rows sit at the default.
_RECALL_GAP_DEFAULT_SCORE = 1.0


def _load_recall_gap_class_priority(repo_root: Path | None = None) -> dict:
    """Load {canonical_attack_class -> priority_score} from the repo-level
    recall-gap prioritizer JSON.

    The scoreboard prioritizer (realworld-recall-gap-prioritizer.py) writes
    ``reports/realworld_recall_gap_priorities.json`` with a ``priorities`` list
    of ``{attack_class, priority_score, ...}`` rows. Higher priority_score = a
    BIGGER real-world recall gap = the class the hunt should attack first.

    Returns ``{}`` when the file is absent or malformed - the caller treats an
    empty map as "no reweighting signal", so the worklist still dedups +
    stable-sorts (no behavior regression vs. the pre-fix flat append).
    """
    root = repo_root or TOOLS_DIR.parent
    path = Path(root) / RECALL_GAP_PRIORITIES_REL
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    rows = data.get("priorities")
    if not isinstance(rows, list):
        return {}
    out: dict[str, float] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ac = str(row.get("attack_class") or "").strip()
        if not ac:
            continue
        try:
            score = float(row.get("priority_score"))
        except (TypeError, ValueError):
            continue
        # keep the strongest (max) gap signal per class
        if ac not in out or score > out[ac]:
            out[ac] = score
    return out


def _classify_question_class(question: str) -> str:
    """Infer a coarse routing class from a question string using the same
    keyword taxonomy the unit anchor builder uses. Routing label only - NOT an
    attack_class claim, severity, or finding (R80 safe)."""
    q = (question or "").lower()
    for keywords, cls in _RECALL_GAP_QUESTION_KEYWORDS:
        if any(k in q for k in keywords):
            return cls
    return "generic"


def _score_question(question: str, class_priority: dict) -> float:
    """Map a question to its recall-gap priority score via its coarse class.
    Falls back to the neutral default when the class is generic or the
    scoreboard has no row for it."""
    if not class_priority:
        return _RECALL_GAP_DEFAULT_SCORE
    cls = _classify_question_class(question)
    canonical = _RECALL_GAP_CLASS_ALIASES.get(cls, cls)
    score = class_priority.get(canonical)
    if score is None:
        return _RECALL_GAP_DEFAULT_SCORE
    return float(score)


def _reweight_dedup_sort_worklist(
    ws_path: Path, repo_root: Path | None = None
) -> dict:
    """Finalize the assembled per_fn_hacker_questions worklist so the hunt
    attacks the highest-recall-gap angles first.

    Runs AFTER both folds (per-unit sidecars + lane hypotheses). It:
      1) de-duplicates rows by (unit_id, normalized question) - the count-cap
         folds appended dup rows from overlapping sidecars/lanes;
      2) attaches a neutral ``priority_score`` derived from the repo-level
         recall-gap prioritizer (degraded -> flat default, no regression);
      3) STABLE score-sorts descending, so a P0 recall-gap class (e.g.
         bridge-proof-domain-bypass) outranks the generic access-control bulk
         that historically dominated 79% of the worklist.

    HONEST (R80): ``priority_score`` is a recall-gap ORDERING hint, not an
    attack_class / severity / claim. No row gains a finding label; rows are only
    re-ordered + de-duplicated. A missing scoreboard degrades gracefully to a
    dedup + stable pass-through.
    """
    out = ws_path / PER_FN_HACKER_QUESTIONS_REL
    if not out.is_file():
        return {"path": str(out), "reweighted": False, "reason": "no_worklist"}
    # S3: emit a ranked sibling (per_fn_hacker_questions.jsonl.ranked.jsonl) via the
    # per-function question ranker (scanner-corroboration boost + KDE/OOS hard-zero,
    # top-N cap). NON-DESTRUCTIVE: the canonical worklist `out` is left intact for
    # coverage accounting; the hunt fire (Makefile mimo-harness-hunt) PREFERS the
    # ranked sibling when present. Best-effort - a missing ranker / nonzero rc / empty
    # output leaves no sibling and the fire falls back to the full worklist (no regression).
    ranked_sidecar = {"emitted": False}
    if RANKER_TOOL.is_file():
        ranked_path = Path(str(out) + ".ranked.jsonl")
        try:
            rc = subprocess.run(
                ["python3", str(RANKER_TOOL), "--questions", str(out),
                 "--workspace", str(ws_path), "--output", str(ranked_path),
                 "--top-n", str(int(os.environ.get("AUDITOOOR_RANKER_TOP_N", "500"))),
                 "--json"],
                capture_output=True, text=True, timeout=300,
            )
            if rc.returncode == 0 and ranked_path.is_file() and ranked_path.stat().st_size > 0:
                ranked_sidecar = {"emitted": True, "path": str(ranked_path)}
        except (subprocess.SubprocessError, OSError, ValueError):
            pass
    rows: list[dict] = []
    try:
        for line in out.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    except OSError:
        return {"path": str(out), "reweighted": False, "reason": "unreadable"}

    class_priority = _load_recall_gap_class_priority(repo_root)
    seen: set[tuple] = set()
    deduped: list[tuple[int, float, dict]] = []
    dropped_dups = 0
    for idx, obj in enumerate(rows):
        q = str(obj.get("question") or "")
        key = (
            str(obj.get("unit_id") or obj.get("source_path") or ""),
            " ".join(q.split()).lower(),
        )
        if key in seen:
            dropped_dups += 1
            continue
        seen.add(key)
        score = _score_question(q, class_priority)
        obj["priority_score"] = round(score, 4)
        deduped.append((idx, score, obj))

    # STABLE sort: primary = priority_score desc; tie-break = original order
    # (idx asc) so equal-priority rows keep their fold order deterministically.
    deduped.sort(key=lambda t: (-t[1], t[0]))
    ordered = [obj for _idx, _score, obj in deduped]

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=str(out.parent), suffix=".tmp",
            delete=False, encoding="utf-8",
        ) as tf:
            for rec in ordered:
                tf.write(json.dumps(rec) + "\n")
            tmp = tf.name
        os.replace(tmp, str(out))
    except OSError:
        return {"path": str(out), "reweighted": False, "reason": "write_failed"}

    top_score = ordered[0]["priority_score"] if ordered else None
    return {
        "path": str(out),
        "reweighted": True,
        "recall_gap_signal": bool(class_priority),
        "recall_gap_classes": len(class_priority),
        "rows_in": len(rows),
        "rows_out": len(ordered),
        "dropped_dups": dropped_dups,
        "top_priority_score": top_score,
        "score_sorted": True,
        "ranked_sidecar": ranked_sidecar,
    }


# --------------------------------------------------------------------------
# per-(unit, question) hacker-questions aggregate (FIX 1)
# --------------------------------------------------------------------------
def _fold_per_fn_hacker_questions(ws_path: Path, run_id: str) -> dict:
    """Fold every per-unit verdict sidecar with question_count>=1 into ONE
    aggregate JSONL at ``<ws>/.auditooor/per_fn_hacker_questions.jsonl``,
    one record per (unit, question), so the L37 hacker-questions gate
    (which globs the .auditooor top level for ``per_fn_hacker_questions*``
    and accepts >=1 genuine JSONL line) credits the real adversarial
    questions the arsenal pass emitted.

    HONEST (R80): each record carries the unit, source path, and ONE
    adversarial question string ONLY - no attack_class, no severity, no
    claim. The question is hunt fuel, not a proven impact.

    Generic: reads whatever the per-unit pass wrote, language-agnostic.

    r36-rebuttal: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
    """
    sidecar_dir = ws_path / PER_UNIT_VERDICT_DIR_REL
    records: list[dict] = []
    units_with_questions = 0
    out_of_scope_filtered = 0
    inscope_paths = _load_inscope_source_paths(ws_path)
    if sidecar_dir.is_dir():
        for sc in sorted(sidecar_dir.glob("*.json")):
            try:
                obj = json.loads(sc.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(obj, dict):
                continue
            # GENERIC scope/R76 filter: skip stale or out-of-scope per-unit
            # sidecars (e.g. rust units left over from an unscoped earlier pass
            # in a Solidity-scoped workspace). Keeps the folded worklist scoped.
            if not _fold_question_in_scope(
                ws_path, obj.get("source_path") or "", inscope_paths
            ):
                out_of_scope_filtered += 1
                continue
            qs = obj.get("adversarial_questions") or []
            qcount = obj.get("question_count")
            # Trust question_count>=1 as the fold gate; fall back to len(qs).
            try:
                has_q = int(qcount) >= 1 if qcount is not None else bool(qs)
            except (TypeError, ValueError):
                has_q = bool(qs)
            if not has_q:
                continue
            unit_id = obj.get("unit_id")
            source_path = obj.get("source_path")
            emitted = 0
            anchor = _enrich_fn_anchor(ws_path, str(unit_id or ""), str(source_path or ""))
            for q in qs:
                if not isinstance(q, str) or not q.strip():
                    continue
                rec = {
                    "schema_version": PER_FN_HACKER_QUESTIONS_SCHEMA,
                    "workspace": ws_path.name,
                    "run_id": run_id or None,
                    "unit_id": unit_id,
                    "source_path": source_path,
                    "question": q,
                }
                rec.update(anchor)
                records.append(rec)
                emitted += 1
            if emitted:
                units_with_questions += 1
            # GENERIC impact-methodology fold: this closer is the writer that
            # actually runs during `make audit` for EVERY language (Go/Rust
            # workspaces included - unlike per-function-hacker-questions.py's
            # producer chain, which is only wired into the on-demand
            # scoped-hunt-plan/mimo-harness-hunt targets, not `make audit`
            # itself). Stamp a `question_source: impact-methodology` row per
            # in-scope, function-bound unit here too, so the corpus carries
            # real provenance regardless of workspace language.
            impact_rows = _impact_methodology_rows_for_unit(
                str(unit_id or ""), str(source_path or ""), run_id, ws_path.name,
            )
            if impact_rows:
                records.extend(impact_rows)

    out = ws_path / PER_FN_HACKER_QUESTIONS_REL
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        # atomic JSONL write
        with tempfile.NamedTemporaryFile(
            mode="w", dir=str(out.parent), suffix=".tmp",
            delete=False, encoding="utf-8",
        ) as tf:
            for rec in records:
                tf.write(json.dumps(rec) + "\n")
            tmp = tf.name
        os.replace(tmp, str(out))
    except OSError:
        pass
    return {
        "path": str(out),
        "records": len(records),
        "units_with_questions": units_with_questions,
        "out_of_scope_filtered": out_of_scope_filtered,
    }


def _reconcile_run_verdict(
    strict_count: int | None,
    strict_status: str | None,
    heatmap_fraction: float | None,
    total_units: int,
) -> tuple[str, float | None]:
    """Reconcile the RUN-level verdict + reported coverage_fraction to the
    STRICT L37 axis so the closer never CLAIMS coverage is closed while the
    strict gate still reports uncovered functions (the hyperbridge false-green:
    final_coverage_fraction=1.0 reported alongside final_strict_uncovered_count
    = 1914). The heatmap counts every ENUMERATED unit as covered, so its
    fraction reads 1.0 even when nothing has a real per-function attack verdict;
    the strict axis is authoritative.

    Returns ``(verdict, reconciled_fraction)``:
      - strict CLOSED (status ``ok`` with 0 uncovered, or ``unavailable`` - the
        same definition the per-iter ``stop_reason`` guard uses): the heatmap
        fraction is trustworthy, so verdict=VERDICT_COVERAGE_CLOSED and the
        fraction is the heatmap value unchanged.
      - strict OPEN (status ``ok`` with >=1 uncovered): verdict
        =VERDICT_RESIDUAL_OPEN and the fraction is reconciled to
        ``(total - strict_uncovered) / total`` (NEVER 1.0 while uncovered>0).
        When the heatmap has no total to reconcile against, the fraction is
        ``None`` (unknown) rather than a misleading 1.0.
      - strict UNRESOLVED (status ``failed``/timeout - count unknown): verdict
        =VERDICT_RESIDUAL_OPEN and the fraction is ``None`` - the strict axis
        could not be measured, so no coverage fraction may be claimed.

    This is an honesty reconciliation only: it flips NO audit-complete gate. It
    cannot manufacture a green, because the only path to VERDICT_COVERAGE_CLOSED
    / a 1.0 fraction requires the strict axis to be genuinely closed or the gate
    tool to be absent (``unavailable``) - exactly the conditions under which the
    heatmap 1.0 is itself honest.
    """
    # UNKNOWN strict axis (gate errored/timed out) -> never claim closed, never
    # report a fraction. count may be 0 here purely because the probe failed.
    if strict_status == FCC_STATUS_FAILED or strict_count is None:
        return VERDICT_RESIDUAL_OPEN, None
    # Genuinely closed: strict ran ok with 0 uncovered, OR the gate tool is
    # absent (unavailable) - matches the stop_reason strict_axis_closed guard.
    strict_closed = (
        strict_status == FCC_STATUS_OK and int(strict_count) == 0
    ) or strict_status == FCC_STATUS_UNAVAILABLE
    if strict_closed:
        return VERDICT_COVERAGE_CLOSED, heatmap_fraction
    # OPEN: strict ran ok and reports >=1 uncovered fn. The heatmap fraction is a
    # false green; reconcile it to the strict count so it can never read 1.0.
    if total_units and int(total_units) > 0:
        covered = max(0, int(total_units) - int(strict_count))
        reconciled = covered / int(total_units)
        # Defensive clamp: a strict-open axis can NEVER report a full fraction.
        if reconciled >= 1.0:
            reconciled = float(int(total_units) - 1) / int(total_units)
        # And never report ABOVE the heatmap's own (over-credited) fraction.
        if heatmap_fraction is not None:
            reconciled = min(reconciled, float(heatmap_fraction))
        return VERDICT_RESIDUAL_OPEN, round(reconciled, 6)
    # No total to reconcile against -> the fraction is unknown, not 1.0.
    return VERDICT_RESIDUAL_OPEN, None


# --------------------------------------------------------------------------
# bounded loop
# --------------------------------------------------------------------------
def run(
    ws_path: Path,
    *,
    max_iters: int = 3,
    coverage_threshold: float = 1.0,
    unit_cap: int = 400,
    run_id: str = "",
) -> dict:
    iters: list[dict] = []
    prev_effective: int | None = None
    # The strict-uncovered residual (uncovered strict fns that still have NO
    # persisted per-unit verdict sidecar) is the AUTHORITATIVE worklist the loop
    # drains. Termination reconciles to THIS, not the trivial heatmap
    # effective-uncovered, so the closer keeps driving the per-unit hunt over the
    # strict-uncovered set until it is genuinely processed (or a real per-iter
    # budget is hit) instead of fixpointing on a heatmap that reports cov=1.0.
    prev_strict_residual: int | None = None
    stop_reason = "max-iters-reached"
    last_needs_llm: list[str] = []
    last_uncovered_rows: list[dict] = []

    for i in range(1, max(1, max_iters) + 1):
        # 1) PRE-SEED measurement: capture the genuinely-uncovered units BEFORE
        #    seeding. The surface seed self-heals coverage credit, so the
        #    per-unit deterministic hunt MUST run over the pre-seed uncovered
        #    set (the units that have no hypothesis yet) - that is exactly the
        #    deterministic-hunter layer the coarse "queued for a look" credit
        #    lacks.
        pre_report = _rebuild_coverage_report(ws_path)
        pre_g15 = _read_g15_result(ws_path, run_id)
        _pre_eff, pre_uncovered_units = _g15_effective_uncovered(pre_g15, pre_report)
        # if G15 already credits everything, fall back to the raw uncovered
        # units from the coverage report so the deterministic hunt still records
        # a per-unit verdict for each unhunted unit.
        if not pre_uncovered_units:
            pre_uncovered_units = [
                str(u) for u in (pre_report.get("uncovered_units") or [])
            ]
        # r36-rebuttal: lane L37-CERTORA-SCOPE-FIX registered in .auditooor/agent_pathspec.json
        # UNION with the strict L37 function-coverage gate's genuinely-uncovered
        # entry functions (hollow/untouched). The G15 + raw report axes credit
        # skip-logged / mechanically-scanned units as covered and can both be
        # empty while the strict gate still fails. Folding its uncovered set in
        # guarantees the per-unit hunt + per_fn questions cover exactly the
        # functions L37 counts as uncovered (otherwise the scoped hunt has 0
        # questions and function-coverage stays permanently red).
        _seen_pre = {str(u) for u in pre_uncovered_units}
        strict_units, strict_status = _genuine_uncovered_units(ws_path)
        for _u in strict_units:
            if _u not in _seen_pre:
                pre_uncovered_units.append(_u)
                _seen_pre.add(_u)
        # The strict L37 gate is the AUTHORITATIVE uncovered-set notion. When it
        # reports >=1 uncovered function, the coverage axis is NOT closed even if
        # the trivial enumeration heatmap says coverage_fraction=1.0. When it
        # FAILED/timed out, the strict axis is UNKNOWN and the closer must not
        # declare coverage met off the heatmap alone - both are tracked here and
        # consulted by the termination guard below so the heatmap notion can
        # never produce a false green over an unresolved strict axis.
        strict_uncovered_count = len(strict_units)
        # The strict-uncovered RESIDUAL = strict uncovered fns that still have NO
        # persisted per-unit verdict sidecar (i.e. not yet driven through the
        # deterministic arsenal in this or a prior run). This is the worklist the
        # bounded loop drains; termination is reconciled to it (NOT the heatmap
        # effective-uncovered, which is flat at 0 even when 29k strict fns remain
        # unhunted). The single source of truth for "processed" is the sidecar on
        # disk (see _unit_already_processed) - so the per-unit pass and the
        # residual accounting can never disagree.
        strict_residual_units = [
            u for u in strict_units if not _unit_already_processed(ws_path, u)
        ]
        strict_residual_pre = len(strict_residual_units)

        # ORDER the worklist so the unprocessed strict residual is hunted FIRST.
        # Without this, the per-unit pass re-hunts the same front ``unit_cap``
        # units every iter (the strict set is returned in a stable order) and
        # never advances - which is exactly why the closer fixpointed after 2
        # iters with only 24 of 29,371 questions emitted. Each iter now consumes
        # the next ``unit_cap``-sized slice of the strict residual, draining it.
        _seen_order: set[str] = set()
        ordered_units: list[str] = []
        for _u in strict_residual_units + pre_uncovered_units:
            if _u not in _seen_order:
                ordered_units.append(_u)
                _seen_order.add(_u)

        # 2) per-unit bounded deterministic hunt over the PRE-SEED uncovered set,
        #    strict-residual-first so each iter advances through the worklist.
        per_unit = _per_unit_hunt_pass(ws_path, ordered_units, run_id, unit_cap)
        last_needs_llm = per_unit["needs_llm_depth_units"]
        # Strict residual AFTER this iter's pass: how many strict-uncovered fns
        # still have no sidecar. This is what the termination guard reconciles to.
        strict_residual_post = sum(
            1 for u in strict_units if not _unit_already_processed(ws_path, u)
        )

        # 3) SURFACE seed (shell coverage-to-hunt-seed)
        surface_seed = _seed_surface(ws_path, run_id)
        # 4) RUBRIC seed (shell rubric-to-hunt-seed)
        rubric_seed = _seed_rubric(ws_path, run_id)

        # 5) POST-SEED re-measure: coverage report + G15 gate + rubric uncovered
        report = _rebuild_coverage_report(ws_path)
        g15 = _read_g15_result(ws_path, run_id)
        effective_uncovered, _post_uncovered_units = _g15_effective_uncovered(g15, report)
        cov_frac = _coverage_fraction(g15, report)
        rubric_report, uncovered_rows = _read_rubric_uncovered(ws_path)
        last_uncovered_rows = uncovered_rows

        iter_rec = {
            "iter": i,
            "surface_seed": surface_seed,
            "rubric_seed": rubric_seed,
            "coverage_fraction": round(cov_frac, 6),
            # Enumeration total from the heatmap - load-bearing for the strict
            # reconciliation in the result builder (covered = total - strict
            # uncovered). 0 when the heatmap has no total (fraction unknown).
            "coverage_total_units": int(report.get("total_units") or 0),
            "effective_uncovered": effective_uncovered,
            "g15_verdict": g15.get("verdict") if isinstance(g15, dict) else None,
            "rubric_rows_uncovered": int(rubric_report.get("rows_uncovered", len(uncovered_rows))),
            "strict_uncovered_count": strict_uncovered_count,
            "strict_uncovered_status": strict_status,
            # strict residual = strict uncovered fns with no per-unit sidecar yet.
            # pre = before this iter's pass; post = after. The bounded loop drains
            # ``post`` toward 0 across iters; termination reconciles to it.
            "strict_residual_pre": strict_residual_pre,
            "strict_residual_post": strict_residual_post,
            "per_unit_hunt": per_unit,
        }
        iters.append(iter_rec)

        # 5) bounded-loop termination checks (after recording the iter)
        # The strict L37 function-coverage gate is authoritative over the trivial
        # enumeration heatmap (which counts every ENUMERATED unit as covered, so
        # it reports coverage_fraction=1.0 even when no unit has a real attack
        # verdict). The coverage axis is "closed" ONLY when the strict gate ran
        # (status ok) AND returned zero uncovered functions. A strict failure /
        # timeout (status failed) means the strict set is UNKNOWN - the closer
        # must NOT declare coverage met off the heatmap alone. This guard is the
        # root-cause fix for the coverage-notion false green.
        strict_axis_closed = (
            strict_status == FCC_STATUS_OK and strict_uncovered_count == 0
        ) or strict_status == FCC_STATUS_UNAVAILABLE
        if (
            cov_frac >= coverage_threshold
            and not uncovered_rows
            and strict_axis_closed
        ):
            stop_reason = "coverage-threshold-met-and-rubric-complete"
            break
        # FIXPOINT, reconciled to BOTH axes - the STRICT residual AND the heatmap
        # effective-uncovered. ROOT-CAUSE FIX: the heatmap's effective-uncovered
        # is trivially 0 / coverage_fraction=1.0 even when tens of thousands of
        # strict-uncovered functions have never been hunted, so using ONLY it for
        # the fixpoint stopped the closer after 2 iters with only 24 of 29,371
        # per_fn questions emitted. The loop must keep driving the per-unit hunt
        # over the strict-uncovered worklist until that residual is genuinely
        # processed, and NOT early-stop because the heatmap is flat.
        #
        # The loop made PROGRESS this iter if EITHER axis advanced: the heatmap
        # effective-uncovered strictly decreased, OR (under an ``ok`` strict
        # status) the strict residual strictly decreased. It only fixpoints when
        # NEITHER advanced. While the strict residual is still draining (each iter
        # consumes the next unit_cap slice) the trivial heatmap fraction can no
        # longer early-stop the loop. A genuinely drained strict residual (it was
        # >0 and is now 0, every strict-uncovered fn has a persisted per-unit
        # verdict) is reported as the dedicated ``strict-residual-drained``
        # terminal; a stuck non-zero residual (e.g. sidecar writes failing) is an
        # HONEST ``fixpoint-no-progress``, NEVER a coverage-met green.
        strict_known = strict_status == FCC_STATUS_OK
        heatmap_progressed = (
            prev_effective is not None and effective_uncovered < prev_effective
        )
        strict_progressed = (
            strict_known
            and prev_strict_residual is not None
            and strict_residual_post < prev_strict_residual
        )
        strict_just_drained = (
            strict_known
            and strict_residual_post == 0
            and prev_strict_residual is not None
            and prev_strict_residual > 0
        )
        if prev_effective is not None or prev_strict_residual is not None:
            if not heatmap_progressed and not strict_progressed:
                # No axis advanced this iter -> terminal. Distinguish a genuinely
                # drained strict worklist (clean, complete) from a stuck residual.
                stop_reason = (
                    "strict-residual-drained"
                    if strict_known and strict_residual_post == 0
                    and prev_strict_residual not in (None, 0)
                    else "fixpoint-no-progress"
                )
                break
            if strict_just_drained and not heatmap_progressed:
                # The strict worklist was the only axis still demanding iters and
                # it is now fully drained -> stop on the dedicated terminal rather
                # than burning another iter just to observe no-progress.
                stop_reason = "strict-residual-drained"
                break
        prev_effective = effective_uncovered
        if strict_known:
            prev_strict_residual = strict_residual_post
    else:
        stop_reason = "max-iters-reached"

    residual = _emit_residual_queue(
        ws_path, last_needs_llm, last_uncovered_rows, run_id
    )

    # FIX 1: after the per-unit pass, fold every sidecar's adversarial
    # questions into ONE aggregate JSONL that the L37 hacker-questions gate
    # credits. r36-rebuttal: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
    hacker_q = _fold_per_fn_hacker_questions(ws_path, run_id)

    # FIX 2: fold SADL + CRC + SIDL hypotheses (emitted by audit-deep Steps
    # 22/23/24) into the same per_fn_hacker_questions.jsonl corpus so the
    # hunt sees them as additional adversarial fuel.  NO-AUTO-CREDIT: every
    # appended record carries verdict=needs-fuzz; folding does NOT resolve
    # any unit's verdict or flip any gate.
    lane_fold = _fold_lane_hypotheses_into_corpus(ws_path, run_id)

    # FIX 3 (hacker-reweighting): finalize the assembled worklist so the hunt
    # attacks the highest-recall-gap angles first. Dedups the count-cap dup rows
    # both folds appended, attaches a recall-gap-derived priority_score, and
    # stable score-sorts. Degrades gracefully (dedup-only) when the repo-level
    # recall-gap scoreboard is absent. R80: ordering hint only, no claim.
    worklist_reweight = _reweight_dedup_sort_worklist(ws_path)

    final_iter = iters[-1] if iters else {}
    # Reconcile the RUN verdict + reported coverage_fraction to the authoritative
    # STRICT L37 axis. The heatmap coverage_fraction counts enumeration=covered
    # (reads 1.0 even when nothing has a real attack verdict), so reporting it
    # raw alongside a non-zero strict-uncovered count is the false-green this
    # tool exists to prevent. The reconciliation NEVER flips an audit-complete
    # gate - it only stops the closer's own run verdict/fraction from lying.
    _final_strict_count = final_iter.get("strict_uncovered_count")
    _final_strict_status = final_iter.get("strict_uncovered_status")
    _final_heatmap_fraction = final_iter.get("coverage_fraction")
    run_verdict, reconciled_fraction = _reconcile_run_verdict(
        _final_strict_count,
        _final_strict_status,
        _final_heatmap_fraction,
        int(final_iter.get("coverage_total_units") or 0),
    )
    result = {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "run_id": run_id or None,
        "workspace": ws_path.name,
        "workspace_path": str(ws_path),
        "max_iters": max_iters,
        "coverage_threshold": coverage_threshold,
        "iters_run": len(iters),
        "stop_reason": stop_reason,
        # Reconciled to the STRICT axis: NEVER 1.0 while strict-uncovered > 0,
        # ``None`` when the strict axis is unresolved. The raw heatmap value is
        # preserved separately for transparency / debugging.
        "final_coverage_fraction": reconciled_fraction,
        "final_heatmap_coverage_fraction": _final_heatmap_fraction,
        "final_effective_uncovered": final_iter.get("effective_uncovered"),
        "final_rubric_rows_uncovered": final_iter.get("rubric_rows_uncovered"),
        # The strict L37 axis is the authoritative coverage notion. Surfaced so
        # downstream consumers do not have to re-derive it from the heatmap (the
        # heatmap counts enumeration=covered, hence coverage_fraction=1.0). A
        # non-zero count or a ``failed`` status means coverage is NOT genuinely
        # closed regardless of final_coverage_fraction.
        "final_strict_uncovered_count": final_iter.get("strict_uncovered_count"),
        "final_strict_uncovered_status": final_iter.get("strict_uncovered_status"),
        # The strict-uncovered RESIDUAL after the final iter: strict-uncovered fns
        # that still lack a persisted per-unit verdict sidecar. This is the
        # worklist the loop drains; a non-zero value means more iters (or a higher
        # per-iter unit_cap) are needed to finish hunting the strict set. It is
        # the honest "how much real coverage work remains" number - distinct from
        # the heatmap-derived final_effective_uncovered, which is trivially 0.
        "final_strict_residual": final_iter.get("strict_residual_post"),
        "iters": iters,
        "residual_worker_queue": {
            "path": str(ws_path / RESIDUAL_QUEUE_REL),
            "residual_surface_units": residual["residual_surface_units"],
            "residual_rubric_classes": residual["residual_rubric_classes"],
            "total_residual": residual["total_residual"],
        },
        "per_fn_hacker_questions": hacker_q,  # r36-rebuttal: lane L37-RUST-CREDIT registered
        "lane_hypothesis_fold": lane_fold,    # SADL+CRC+SIDL+ORL hypotheses folded into corpus (needs-fuzz, no-auto-credit)
        "worklist_reweight": worklist_reweight,  # recall-gap reweight + dedup + score-sort (FIX 3)
        # Reconciled to the strict axis (see _reconcile_run_verdict): only
        # VERDICT_COVERAGE_CLOSED when the strict gate is genuinely closed /
        # unavailable; VERDICT_RESIDUAL_OPEN while strict-uncovered > 0 or the
        # strict axis is unresolved. NEVER a hardcoded "closed".
        "verdict": run_verdict,
    }
    try:
        _atomic_write_json(ws_path / RUN_SNAPSHOT_REL, result)
    except OSError:
        pass
    return result


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--workspace", required=True,
                   help="Absolute workspace PATH (contains .auditooor/).")
    p.add_argument("--max-iters", type=int, default=3,
                   help="Max bounded passes (default 3). Loop also stops on "
                        "fixpoint or coverage>=threshold.")
    p.add_argument("--coverage-threshold", type=float, default=1.0,
                   help="Stop when coverage fraction >= this AND rubric complete.")
    p.add_argument("--unit-cap", type=int, default=400,
                   help="Max uncovered units to deterministically hunt per iter "
                        "(-1 = no cap).")
    p.add_argument("--run-id",
                   default=os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID", ""))
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    ws_path = Path(os.path.expanduser(args.workspace))
    if not ws_path.is_absolute():
        ws_path = (Path.cwd() / ws_path).resolve()
    if not ws_path.is_dir():
        print("error: workspace path not found: %s" % ws_path, file=sys.stderr)
        return 2

    result = run(
        ws_path,
        max_iters=args.max_iters,
        coverage_threshold=args.coverage_threshold,
        unit_cap=args.unit_cap,
        run_id=args.run_id,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            "%s: verdict=%s, %d iter(s), stop=%s, final_cov=%s, eff_uncovered=%s, "
            "strict_uncovered=%s(%s), strict_residual=%s, rubric_uncovered=%s, "
            "residual=%d"
            % (
                result["workspace"], result["verdict"],
                result["iters_run"], result["stop_reason"],
                result["final_coverage_fraction"],
                result["final_effective_uncovered"],
                result["final_strict_uncovered_count"],
                result["final_strict_uncovered_status"],
                result["final_strict_residual"],
                result["final_rubric_rows_uncovered"],
                result["residual_worker_queue"]["total_residual"],
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
