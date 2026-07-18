#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
"""audit-completeness-check.py - L37 gate: an AUDIT is the WHOLE documented pipeline.

Background
----------
``hunt-completeness-check.py`` (L35/L36) certifies that the HUNT half of the
pipeline ran end-to-end (dedup-first, full clone, audit-deep, coverage
matrix, cluster coverage, artifact mining). But a workspace can pass
hunt-completeness and still be only HALF audited: the documented pipeline
also requires Tier-6 commit-mining, the LANGUAGE-CORRECT live engines, the
audit-preflight per-function packs, the exploit-queue, chain-synthesis, the
exploit-conversion-loop + prove-top-leads judgment/proof-task step, originality-vs-the-
full-advisory-set, 7-artifact agent learning, and the cross-workspace seed
back into the corpus.

Empirical anchor (this self-audit, 2026-05-29): a presence grid across the
real audit workspaces showed centrifuge-v3 ran the Solidity engines
(``.auditooor/solidity-deep-audit/``) yet had ZERO exploit-queue, ZERO
chain-synth, ZERO conversion, ZERO learning, ZERO ``mining_rounds/``, and
ZERO audit-deep report. dydx (Go/Rust) was the most-complete workspace and
STILL lacked chain-synthesis. Nothing stopped either from being declared
"audited / done". L37 is the mechanical blocking gate that no workspace may
be certified audited until ALL pipeline stages ran WITH EVIDENCE.

This tool is deterministic, stdlib-only, offline-safe, and NEVER re-runs any
stage - it reads the artifacts a real end-to-end audit leaves behind. It is
the AUDIT-level peer of ``hunt-completeness-check.py``; it composes with it
(signal (b) below delegates to the hunt gate) rather than duplicating it.

The pipeline-completeness signals
---------------------------------
(a) tier6-mining        Tier-6 bidirectional commit-mining ran -
                        ``mining_rounds/`` is a non-empty artifact dir.
(b) hunt-complete       the HUNT half passed - delegates to
                        ``hunt-completeness-check.evaluate`` (verdict
                        ``pass-hunt-complete``). Carries the hunt gate's own
                        failures through so the operator sees them.
(c) live-engines        the LANGUAGE-CORRECT live engines ran. The tool
                        scans the in-scope source tree for language markers
                        and requires the engine artifact directory for EACH
                        present language:
                          - Solidity/Vyper -> ``.auditooor/solidity-deep-audit/``
                          - Go/Rust/Move/Cairo (cosmos / substrate / etc.) ->
                            an ``.audit_logs/audit_deep*`` manifest/report
                        A workspace with .sol that only produced a Go-style
                        audit-deep (or vice-versa) FAILS
                        ``fail-engines-not-run-for-language``.
(d) audit-preflight     the audit-preflight per-function packs ran -
                        ``.auditooor/per_function_invariants/`` OR a
                        per-function-preflight output.
(e) exploit-queue       the exploit-queue was built -
                        ``.auditooor/exploit_queue.json``.
(f) chain-synth         chain-synthesis ran -
                        ``.auditooor/chain_synthesis*`` (dir or json).
<!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json; orchestrator commits -->
(c2) engine-harness     the engine(s) ran WITH PROVEN HARNESSES, not rc=0
                        zero-output AND not tautological stubs. Two-stage check:
                        (1) at least one engine step must show a POSITIVE
                        harness / property / spec count actually executed
                        (halmos ``check_*``, medusa+echidna property fns, rust
                        proptest/bolero/kani harnesses). A step that returned
                        ``status:ok`` / ``returncode:0`` with empty stdout and
                        zero harnesses is the Morpho false-pass and FAILS
                        ``fail-engine-false-pass``. (2) the signal then CALLS
                        PR4's engine-harness PROOF gate
                        (``tools/engine-harness-proof-check.py`` against the EVM
                        proof manifest at
                        ``<ws>/.auditooor/evm_engine_proof/engine_harness_proof.json``):
                        the signal passes iff harness count > 0 AND EVERY
                        counted harness passes the proof gate. A counted-but-
                        unproven (fake / tautological) harness FAILS
                        ``fail-engine-false-pass`` - "ran with output" is not
                        "ran a real target-call harness". Staged rollout: when
                        the proof gate is not yet on disk it degrades to legacy
                        positive-count credit in default mode; ``--strict`` /
                        ``AUDITOOOR_L37_ENGINE_PROOF_STRICT=1`` requires the
                        proof gate (a production audit MUST produce the
                        manifest before L37 credits the engines).
(g) exploit-conversion  the exploit-conversion-loop ran -
                        ``.auditooor/current_to_exploit_conversion_gate.json``
                        (or ``exploit_conversion_loop_manifest.json``). Advisory
                        by default; absence FAILS ``fail-conversion-loop-not-run``
                        only when ``ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1``.
(g2) prove-top-leads    prove-top-leads produced a proof/judgment artifact -
                        a ``prove_top_leads_*`` artifact. Advisory by default;
                        absence FAILS ``fail-prove-top-leads-not-run`` only when
                        ``ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1``.
(h) originality         originality-vs-the-full-advisory-set ran - an
                        originality / advisory-corpus artifact exists.
(h2) advisory-corpus    the target's PUBLISHED-advisory count (from the advisory
                        miner or a cached count) EQUALS the corpus advisory-
                        record count for that target. A 4-of-25 partial mine
                        (the Zebra false-clean) FAILS
                        ``fail-advisory-corpus-incomplete``.
(i) learning            the 7-artifact agent learning ran -
                        ``.auditooor/agent_artifact_mining_report.json`` (or
                        a learning-loop / corpus-delta report).
(i2) mined-landed       sidecar-count EQUALS corpus-record-count for the
                        workspace (the LEARNING_DEBT close). A workspace cannot
                        be audit-complete with un-landed sidecars; a mismatch
                        FAILS ``fail-mined-not-landed``.
(j) cross-ws-seed       the cross-workspace seed back into the corpus ran -
                        a cross-workspace ledger / state / seed artifact. ADD-A
                        enforcement: when a SAME-FAMILY SIBLING workspace exists
                        (a sibling dir alongside this workspace whose engagement
                        family matches), the cross_workspace_seed artifact is
                        MANDATORY - there is prior same-family knowledge to seed
                        from, so its absence is the distinct fail
                        ``fail-cross-ws-seed-sibling-exists``. With no sibling the
                        artifact is still required (existing behavior).
(j2) brain-prime        ADD-D: the brain-prime intake step ran -
                        ``<ws>/BRAIN_PRIMING_REPORT.md`` OR the brain-prime
                        receipt ``<ws>/.auditooor/brain_prime_receipt.json``.
                        Absence FAILS ``fail-no-brain-prime``.
(j3) hacker-questions   ADD-D: the per-function hacker-question artifact exists -
                        a ``*hacker_question*`` / ``per_fn_hacker_questions*`` /
                        ``per-function-hacker-questions*`` JSONL/JSON under the
                        workspace or ``.auditooor/``. Absence FAILS
                        ``fail-no-hacker-questions``.
(k) fork-divergence     if the workspace is a fork / vendored target (a pinned
                        git-rev in Cargo.toml / go.mod, a vendored upstream
                        tree, or a git-remote != the canonical upstream), a
                        fork-divergence-probe artifact must exist. Absence on a
                        fork target FAILS ``fail-fork-divergence-not-run``;
                        non-fork targets pass automatically. PR10 widens the
                        accepted evidence to include the PR8 ADD-C fork-divergence
                        HUNT stage's ``proof_obligation_queue.json``
                        (``fork_divergence_last_run`` marker) so a fork target
                        that ran ``fork-divergence-hunt-stage.py --emit-queue``
                        is credited.
(l) novel-vector        PR10/PR9: the novel-vector stage ran - target-specific
                        invariants were derived AND an engine searched for an
                        unknown violation. Accepted artifacts:
                        ``<ws>/.auditooor/novel_vector_invariants*.json`` (the
                        novel-vector-invariant-miner output) OR a pr9 0-day demo
                        summary (``pr9_0day_demo*/pr9_0day_demo_summary.json`` /
                        ``<ws>/.auditooor/pr9_0day_demo*``). Absence FAILS
                        ``fail-no-novel-vector``.
(m) adversarial-panel   PR10/PR8 ADD-B: a candidate cannot reach FINAL_LEADS
                        without surviving the 3-lens adversarial panel. When a
                        FINAL_LEADS set exists (``<ws>/.auditooor/final_leads*`` /
                        ``FINAL_LEADS.md``), an adversarial-panel artifact
                        (``<ws>/.auditooor/adversarial_panel*.json`` /
                        ``*adversarial_candidate_verify*``) is MANDATORY; its
                        absence FAILS ``fail-no-adversarial-panel``. With no
                        FINAL_LEADS set the panel is N/A and passes.
(o) coverage-map        SWEPT-SURFACE coverage: a workspace cannot be certified
                        audit-complete without a coverage report
                        (``<ws>/.auditooor/coverage_report.json``, schema
                        ``auditooor.workspace_coverage_report.v1``) enumerating
                        every in-scope unit (Solidity functions; file-level for
                        Go/Rust/Move/Cairo) and classifying covered vs UNCOVERED.
                        ABSENCE of the report FAILS ``fail-no-coverage-map`` -
                        "is every surface actually audited?" cannot be answered
                        without the map. The signal ALWAYS surfaces the true
                        ``uncovered`` count in its verdict/reason. HIGH-UNCOVERED
                        (coverage_fraction below the warn threshold, default
                        0.50) does NOT fail - it emits a LOUD warn carrying the
                        uncovered count. The honest answer to high-uncovered is
                        to REPORT it loudly, never paper it over; failing on it
                        would only incentivize hiding the signal. Empirical
                        anchor: Hyperbridge reported 742/743 contracts UNCOVERED.
(n) evm-0day-proof      PR10/PR5a: for an EVM (Solidity/Vyper) workspace that has
                        a Medium+ EVM candidate in the exploit-queue, the EVM
                        0-day proof-conversion pipeline may produce an artifact
                        (``<ws>/.auditooor/evm_0day_proof*.json`` /
                        ``*evm_0day_proof*``). Non-EVM workspaces, and EVM
                        workspaces with no Medium+ EVM candidate, pass
                        automatically. Absence on a qualifying workspace is
                        advisory by default and FAILS ``fail-no-evm-0day-proof``
                        only when ``ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1``.
(p) rubric-coverage     RUBRIC coverage: the COMPLEMENTARY axis to (o). Where
                        (o) coverage-map asks "did every in-scope SURFACE get a
                        hypothesis?", this asks "for the program SEVERITY.md,
                        did the workspace produce >=1 candidate for EACH impact/
                        severity ROW?". A complete audit wants BOTH - surface%
                        catches "we never looked at 740 contracts", rubric%
                        catches "we never tried for a freeze-class bug". The
                        signal reads ``<ws>/.auditooor/rubric_coverage_report.json``
                        (schema ``auditooor.workspace_rubric_coverage.v1``,
                        produced by ``tools/rubric-coverage-workspace-check.py
                        --write-report``). ABSENCE of the report OR no
                        SEVERITY.md FAILS ``fail-no-rubric-coverage`` - "did we
                        try for every impact class?" cannot be answered without
                        the map. Mirroring (o): LOW rubric coverage
                        (rubric_coverage_fraction below the warn threshold,
                        default 0.50) does NOT fail - it emits a LOUD warn
                        carrying the UNCOVERED rubric rows (the impact classes
                        NObody attempted). The honest answer to low coverage is
                        to REPORT the uncovered rows loudly, never paper them
                        over. The report's candidate->row mapping uses the same
                        R52 load-bearing-noun HONEST match: a row counts covered
                        only when a real candidate's impact wording genuinely
                        maps to it.
(q) hunt-trust          HUNT-TRUST: the META-signal over (o)/(p). Where (o) and
                        (p) report coverage COUNTS, this asks "can you TRUST the
                        hunt those counts came from?". It delegates to
                        ``tools/hunt-run-health-check.py`` (schema
                        ``auditooor.hunt_run_health.v1``) - either reading a
                        pre-generated ``<ws>/.auditooor/hunt_run_health_report.json``
                        (the Makefile wire, mirroring the coverage/rubric report
                        wires) or IMPORTING ``build_report()`` read-only and
                        generating it live against the corpus derived-root.
                        WARN-NOT-FAIL like (o)/(p), but softer (it never even
                        requires the report to be present):
                          - failed-run / needs_re_hunt -> a LOUD warn ("HUNT
                            FAILED-RUN: coverage is NOT trustworthy, re-hunt
                            before relying on it") carrying success_fraction +
                            rate_limited count. Signal PASSES.
                          - degraded -> a softer warn. Signal PASSES.
                          - healthy / insufficient-data / no-records /
                            unavailable -> PASS quiet.
                        The top-level result carries a ``hunt_trust_warn`` block
                        and a human line, exactly like ``coverage_warn`` /
                        ``rubric_coverage_warn``. The signal only DOWNGRADES to a
                        fail under the opt-in ``--strict`` /
                        ``AUDITOOOR_L37_HUNT_TRUST_STRICT=1`` flag; default mode
                        never fails, so certification behavior is unchanged for
                        non-opt-in callers. Empirical anchor: dydx + morpho
                        (2026-05-28) were rate-limited into ~0 real anchored
                        hypotheses yet showed "covered" units from a few agent
                        artifacts - coverage you cannot trust the hunt behind.
(s) function-coverage   PER-FUNCTION ATTACK completeness: a workspace cannot be
                        certified audit-complete while in-scope functions were
                        never ATTACKED with a real per-function verdict. Where
                        (o) coverage-map asks "did every surface get a HYPOTHESIS
                        token?" (a token can be a noise CCIA heuristic angle or a
                        vacuous per-function harness), this asks the sharper
                        "did every in-scope function get a REAL attack with a
                        recorded verdict?". It delegates to
                        ``tools/function-coverage-completeness.py`` (which owns
                        the language-aware in-scope-function enumeration -
                        Solidity incl. multi-line signatures, plus Rust/Go/Move/
                        Cairo - and excludes test/lib/mock/interface/script).
                        Empirical anchor: the Morpho false-pass produced 79
                        per-function harnesses yet only 4/179 units were REAL
                        attacks (audit-honesty-check / L37); CCIA flagged a TEST-
                        helper callback as "MEDIUM unauthenticated". This signal
                        FAILS ``fail-function-coverage-incomplete`` when the tool
                        reports untouched / hollow in-scope functions. Graceful
                        degradation (mirrors depth-certificate): if the tool /
                        inputs are absent / unimportable / raise, the signal
                        WARNS and PASSES (tooling-absence does not block L37). It
                        inherits the l37-rebuttal override (signal key
                        ``function-coverage:``).
(t) cross-function-coverage  the COMPOSITION completeness axis. coverage-map (o)
                        credits a unit on any hypothesis token; function-coverage
                        (s) credits a FUNCTION on a real per-function attack;
                        depth-certificate (R81) credits per-guard negative-space
                        + sibling-path asymmetry. NONE of them asks the
                        COMPOSITION question: "is there a MUTATION-VERIFIED test
                        asserting the invariant that spans TWO-OR-MORE
                        functions?" (the deposit/withdraw round-trip
                        conservation; the open->fund->close state-machine global
                        invariant). A protocol can have 100% per-function
                        coverage and still be broken by a composition bug no
                        single-function harness expresses. It delegates to
                        ``tools/cross-function-invariant-coverage.py`` which
                        generically enumerates the cross-function REQUIREMENTS
                        (L30 sibling pairs both-arms-present + multi-function
                        state-machine sequences via shared co-mutated state) and
                        runs the anti-stub mutation-verified coverage check (a
                        referencing test with NO mutation kill = uncovered). It
                        FAILS ``fail-cross-function-uncovered`` when a requirement
                        lacks a mutation-verified test. Graceful degradation
                        (mirrors depth-certificate): tool/inputs absent /
                        no-source / no-requirements WARN-pass. Inherits the
                        l37-rebuttal override (signal key
                        ``cross-function-coverage:``).

Verdict vocabulary
------------------
- ``pass-audit-complete``               all signals present.
- ``fail-no-tier6-mining``              signal (a) violated.
- ``fail-hunt-incomplete``              signal (b) violated.
- ``fail-no-live-engines``              signal (c): no engine ran at all.
- ``fail-engines-not-run-for-language`` signal (c): a present language has no
                                        matching engine artifact.
- ``fail-engine-false-pass``            signal (c2): engine ran but executed
                                        ZERO harnesses (rc=0 zero-output).
- ``fail-hollow-not-genuinely-audited`` signal (r): tools/audit-honesty-check.py
                                        flags the workspace as HOLLOW - it
                                        returned a HARD hollow verdict
                                        (fail-fake-coverage / fail-hollow-engines
                                        / fail-mock-target / fail-stub-harnesses).
                                        Softer honesty signals (coverage-below-100
                                        / needs-work alone) do NOT trip this -
                                        L37's coverage-map / rubric axes own the
                                        coverage question. Honesty tooling-absence
                                        / error degrades to WARN-pass.
- ``fail-no-audit-preflight``           signal (d) violated.
- ``fail-no-exploit-queue``             signal (e) violated.
- ``fail-no-chain-synth``               signal (f) violated.
- ``fail-conversion-loop-not-run``      signal (g) violated.
- ``fail-prove-top-leads-not-run``      signal (g2) violated.
- ``fail-exploit-queue-all-leads-disqualification-killed``
                                        signal (u): every top-N exploit-queue
                                        lead (by priority_score) is
                                        proof_status=killed via a quality-gate
                                        disqualification with no cited
                                        negative_control / clean_control -
                                        "couldn't auto-prove" was recorded as
                                        "killed" with no genuine refutation.
- ``fail-no-originality``               signal (h) violated.
- ``fail-advisory-corpus-incomplete``   signal (h2): published != corpus
                                        advisory-record count.
- ``fail-no-learning``                  signal (i) violated.
- ``fail-mined-not-landed``             signal (i2): sidecar != corpus-record
                                        count (un-landed sidecars).
- ``fail-no-cross-ws-seed``             signal (j) violated (no sibling).
- ``fail-cross-ws-seed-sibling-exists`` signal (j): a same-family sibling
                                        workspace exists but no seed artifact
                                        (ADD-A).
- ``fail-no-brain-prime``               signal (j2): no brain-prime artifact
                                        (ADD-D).
- ``fail-no-hacker-questions``          signal (j3): no per-function hacker-
                                        question artifact (ADD-D).
- ``fail-fork-divergence-not-run``      signal (k): fork target without a
                                        fork-divergence-probe artifact.
- ``fail-no-novel-vector``              signal (l): no novel-vector miner /
                                        pr9 0-day-demo artifact.
- ``fail-no-adversarial-panel``         signal (m): FINAL_LEADS set exists but no
                                        adversarial-panel artifact.
- ``fail-no-evm-0day-proof``            signal (n): EVM workspace w/ Medium+ EVM
                                        candidate but no EVM 0-day proof-conversion artifact.
- ``fail-no-coverage-map``              signal (o): no SWEPT-SURFACE coverage
                                        report (cannot certify "every surface
                                        audited"). High-uncovered does NOT fail;
                                        it warns loudly with the uncovered count.
- ``fail-no-rubric-coverage``           signal (p): no RUBRIC coverage report or
                                        no SEVERITY.md (cannot certify "every
                                        impact class attempted"). Low rubric
                                        coverage does NOT fail; it warns loudly
                                        with the UNCOVERED rubric rows.
- ``fail-hunt-untrustworthy``           signal (q): ONLY under opt-in
                                        ``--strict`` / ``AUDITOOOR_L37_HUNT_TRUST_STRICT=1``
                                        when the hunt behind the coverage was a
                                        failed-run / rate-limited shell. In
                                        DEFAULT mode signal (q) never fails - it
                                        warns loudly via ``hunt_trust_warn`` and
                                        PASSES.
- ``fail-function-coverage-incomplete`` signal (s): tools/function-coverage-
                                        completeness.py reports in-scope
                                        function(s) that were never ATTACKED with
                                        a real per-function verdict (untouched /
                                        hollow). Tooling-absence / inputs-absence
                                        / error degrades to WARN-pass.
- ``fail-cross-function-uncovered``     signal (t): tools/cross-function-
                                        invariant-coverage.py reports a cross-
                                        function invariant requirement (L30
                                        sibling pair or multi-function state-
                                        machine sequence) that lacks a MUTATION-
                                        VERIFIED test. Tooling-absence / no-source
                                        / no-requirements degrades to WARN-pass.
- ``error``                             unreadable workspace / internal error.

Coverage warn (non-fatal): when a coverage report IS present but
``coverage_fraction`` is below the warn threshold
(``AUDITOOOR_L37_COVERAGE_WARN_FRACTION``, default 0.50), the top-level result
carries a ``coverage_warn`` block (uncovered count + fraction) and each
``signals[*]`` coverage row is annotated, but the signal still PASSES. The
warn is surfaced in the human output and the JSON so the operator sees the
loud UNCOVERED count without the gate papering it over.

The check evaluates all signals and reports every failing signal in
``failures``; the top-level ``verdict`` is the FIRST failing signal in
declaration order so the operator gets a stable single-line summary.

Exit code
---------
- 0 on ``pass-audit-complete``.
- 1 on any ``fail-*`` verdict.
- 2 on ``error`` (bad arguments / missing workspace).

Override
--------
Visible bounded line ``l37-rebuttal: <reason>`` (<=200 chars) OR HTML-comment
form ``<!-- l37-rebuttal: <reason> -->`` placed in
``<WS>/.auditooor/audit_completeness_rebuttal.txt``. A non-empty, in-bounds
reason flips a single named signal (``<signal>: <reason>``) or all signals
(``all: <reason>`` or a bare reason) to ``ok-rebuttal``. Empty or oversized
reasons are ignored; the original fail stands. The rebuttal is reserved for
stages that are genuinely N/A for the engagement (e.g. a non-EVM target
where the Solidity engine cannot apply, or a first-ever workspace with no
sibling corpus to seed against).

RELATED TOOLS (tool-duplication preflight, per global memory)
-------------------------------------------------------------
- ``hunt-completeness-check.py`` (L35/L36) - HUNT half only; this tool
  DELEGATES to it for signal (b) and does NOT re-implement its checks.
- ``loop-finalization-check.py`` - per-slice closeout manifest gate; calls
  the hunt gate when a manifest declares the workspace hunt-done. L37 is
  the AUDIT-level analogue and can be wired into loop-finalization the same
  way (delegating to ``evaluate`` here).
- ``audit-completion-marker.py`` - records/checks a freshness marker for
  ``make audit``; orthogonal (it answers "did make audit run recently",
  not "did the WHOLE pipeline run with evidence").

CLI
---
    python3 tools/audit-completeness-check.py <workspace> [--json] [--strict]

Usage
-----
    make audit-complete WS=~/audits/<project>
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.l37_audit_completeness.v1"
GATE = "L37-AUDIT-COMPLETENESS"

# Ordered signal -> failing verdict map. Order is load-bearing: the top-level
# verdict is the FIRST failing signal in this order. Tier-6 + hunt-complete
# come first because they are the structural prerequisites for everything
# downstream (you cannot have a meaningful exploit-queue / chain-synth without
# having actually hunted the full tree).
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
_SIGNAL_ORDER = (
    # =====================================================================
    # BAND A: engine-reality (manifest phase: engine) - can we trust the engines/harness ran at all
    # =====================================================================
    ("tier6-mining", "fail-no-tier6-mining"),
    ("hunt-complete", "fail-hunt-incomplete"),
    ("live-engines", "fail-no-live-engines"),
    ("engine-harness", "fail-engine-false-pass"),
    # WHOLE-WORKSPACE honesty (signal r): delegates to audit-honesty-check.py and
    # fails when the workspace is hollow (fake-coverage / hollow-engines /
    # mock-target / stub-harnesses). Sits with the engine-reality signals because
    # it is the cross-cutting "is this workspace genuinely audited, not just
    # artifact-present?" check. Fires before the coverage axes (which are
    # warn-not-fail) so a hollow workspace is caught as a hard fail.
    ("hollow-not-genuinely-audited", "fail-hollow-not-genuinely-audited"),
    ("audit-preflight", "fail-no-audit-preflight"),
    # =====================================================================
    # BAND B: flow-substrate producers (manifest phase: substrate) - dataflow / coupled-state / value-mover conservation substrates the downstream lenses depend on, hoisted UP FRONT
    # =====================================================================
    # DATAFLOW-SUBSTRATE-HEALTH: the step-1c slice is the SHARED substrate under EVERY
    # dataflow-dependent lens (path-mode hunt, guard-reachability, chain-synth, state-
    # coupling). It is advisory with a SILENT function-mode fallback, so a starved arm
    # downgrades all those lenses without a flag (root-caused on NUVA's Go feeder). This
    # generalizes the SCC-only feeder gate to ALL languages + ALL lenses: a starved arm
    # (genuine build/load failures + near-zero real paths) hard-fails under STRICT. MUST be
    # in _SIGNAL_ORDER (bijection guard) or it is computed then dropped. Rebuttal:
    # ``dataflow-substrate-health:``.
    ("dataflow-substrate-health", "fail-dataflow-substrate-starved"),
    # STATE-COUPLING (SCG, Aptos coupled-state axis): the enumeration floor for the
    # must-move-together invariant class (conserved-with / flush-group / paired-lifecycle
    # / cross-domain-conservation). check_state_coupling AUTO-EMITS the SCG then FAILS
    # when a promotable semantic-ssa coupled-state edge is unprobed. Advisory-WARN by
    # default; hard-fails only under AUDITOOOR_L37_STRICT=1 (the SignalResult.ok already
    # encodes that policy). MUST live here in _SIGNAL_ORDER, not only in by_signal - a
    # signal computed but absent from _SIGNAL_ORDER is SILENTLY DROPPED from the failure
    # aggregation (the not-bypassable-audit hole fixed 2026-07-08: the isolated signal
    # failed-closed but the terminal verdict passed regardless). Rebuttal: ``state-coupling:``.
    ("state-coupling", "fail-open-coupled-state-edge"),
    # ENFORCEMENT-POINT (WSITB B1 plane, increment-1 CONSERVATION class): the coverage
    # floor over ENFORCEMENT POINTS (not impacts). check_enforcement_point AUTO-EMITS the
    # WSITB plane (tools/wsitb-enforcement-plane.py) then FAILS when a severity-eligible
    # conservation node still has q8_verdict=='unanalyzed' (an un-analyzed enforcement
    # point). Advisory-WARN by default; enforces ONLY under the dedicated opt-in env
    # AUDITOOOR_ENFORCEMENT_POINT_ENFORCE (NOT the strict L37 umbrella - unvalidated), with a
    # degraded-feeder secondary fail-closed only when that same env is set.
    # MUST live here in _SIGNAL_ORDER, not only in by_signal - a signal absent from
    # _SIGNAL_ORDER is computed then SILENTLY DROPPED from the failure aggregation.
    # Rebuttal: ``enforcement-point:``.
    ("enforcement-point", "fail-unanalyzed-enforcement-point"),
    # =====================================================================
    # BAND C: reasoning (manifest phase: reasoning) - hacker-questions + reasoner-obligations (logic reasoners), driven BEFORE the fuzz/drive band that consumes them
    # =====================================================================
    ("hacker-questions", "fail-no-hacker-questions"),
    # r36-rebuttal: lane FIX-F2-DONE-GATE registered in .auditooor/agent_pathspec.json
    # HACKER-QUESTIONS-RESOLVED (F2 E2.1): the CONTENT sibling of the existence-only
    # hacker-questions signal above. hacker-questions asks "did the per-fn hacker-Q
    # artifact get written?"; this asks the sharper "was every emitted obligation
    # DRIVEN TO A TERMINAL VERDICT?" - it reads
    # .auditooor/hacker_question_obligations.jsonl and FAILS under STRICT if any row
    # is still open (state not in the terminal set) OR carries a terminal state with
    # NO verified per-question verdict sidecar (un-fakeable: a hand-written
    # state=resolved with no sidecar counts as OPEN). Keyed by the row `language`
    # field so a Solidity-only resolution cannot green a mixed repo's circom/move
    # half. Sits right after the existence-only signal (the two hacker-Q axes).
    # WARN-passes when the obligations file is absent / has 0 rows (no debt to
    # resolve). Inherits the l37-rebuttal override (signal key ``hacker-questions-resolved:``).
    ("hacker-questions-resolved", "fail-open-hacker-questions"),
    # ATTESTATION-COUNT-INTEGRITY (E5): the number-vs-artifact sibling of the
    # hacker-Q axes. hacker-questions/-resolved verify the obligation ROWS; this
    # verifies a step-attestation's CLAIMED obligation total against the recomputed
    # artifact count AND that a KILL-only verdict cluster carries per-row reasons
    # (a reasonless-KILL bucket is not a terminal adjudication). DEFAULT-OFF
    # dedicated env AUDITOOOR_ATTESTATION_COUNT_STRICT (NOT subsumed by the global
    # L37 umbrella, so `make audit-complete` stays byte-identical); WARN-passes
    # otherwise. Rebuttal key: ``attestation-count-integrity:``.
    ("attestation-count-integrity", "fail-attestation-count-mismatch"),
    # impact-methodology-corpus: DELIVERY gate for the impact-methodology
    # capability. hacker-questions/-resolved assert the corpus EXISTS and its
    # obligations are RESOLVED (counts); this asserts the corpus actually CARRIES
    # the impact-methodology, FRESH + FUNCTION-SPECIALIZED (not a stale, pre-
    # capability or generic corpus that goes green on count alone). Rebuttal key:
    # ``impact-methodology-corpus:``.
    ("impact-methodology-corpus", "fail-impact-methodology-absent"),
    # PROVIDER-LIVENESS (F2 E2.4): a dead/401/402 provider for the configured hunt
    # model produces empty hunts that get mis-credited as "examined, 0 findings". If
    # there are OPEN hacker-Q obligations AND the configured provider is unusable,
    # the obligations can never be honestly resolved - so this fires a RED gate
    # rather than letting a silent dead provider green the workspace. WARN-passes
    # when there are no open obligations (nothing to hunt) or the provider is usable.
    ("provider-liveness", "fail-llm-provider-dead"),
    ("fork-divergence", "fail-fork-divergence-not-run"),
    # r36-rebuttal: lane FIX-FORK-DIVERGENCE-CONTENT registered in .auditooor/agent_pathspec.json
    # FORK-DIVERGENCE-CONTENT: the CONTENT sibling of fork-divergence. fork-divergence
    # asks "did the divergence PROBE run?" (a hunt-stage artifact exists); this asks the
    # stronger question "is there a content-rich upstream-divergence MANIFEST that
    # enumerates the actual deviations from the upstream fork?" A workspace that greps as
    # a fork/vendored target (package.json/go.mod/Cargo.toml deps or SCOPE prose naming a
    # known upstream) REQUIRES .auditooor/upstream_divergence.json with a non-empty
    # upstream + >=1 deviation carrying file/kind/summary; mere file presence is not
    # credit. Non-fork targets WARN-pass. tools/upstream-divergence-manifest.py owns the
    # scan (signal key ``fork-divergence-content:``); inherits the l37-rebuttal override.
    ("fork-divergence-content", "fail-upstream-fork-divergence-manifest-missing"),
    # Capability-wiring integrity: repo-level report-only advisory (never fails here); flags
    # methodology capabilities that are orphans / broken-flows in the audit pipeline. MUST
    # live in _SIGNAL_ORDER or it is computed then silently dropped (bijection guard).
    ("capability-wiring-integrity", "fail-capability-wiring-orphans"),
    # CAPABILITY-FIRING-FRACTION (LOGIC_ARSENAL_ROADMAP axis 1): the FIRING dimension
    # of capability-wiring-integrity (invoked=True fraction over the resolvable
    # denominator), JOINED into the umbrella so a wired-by-closure-but-never-invoked
    # arsenal fails audit-complete under strict. Advisory-WARN by default; fail-closed
    # under AUDITOOOR_L37_CAPABILITY_FIRING_FRACTION_STRICT / global AUDITOOOR_L37_STRICT
    # when the invoked fraction is below the floor. MUST live in _SIGNAL_ORDER or it is
    # computed then silently dropped (bijection guard). Rebuttal: ``capability-firing-fraction:``.
    ("capability-firing-fraction", "fail-capability-firing-too-low"),
    # LOGIC #3 callgraph SET-DIFFERENCE reasoner (Euler $197M) JOIN. The pre-hunt
    # producer emits unguarded_mutation_obligations.jsonl but the umbrella never READ
    # it (produced-but-unread) - so the unguarded-downward-mutation trust-layer probe
    # could never fail audit-complete. Advisory-first (report-only by default), fails
    # closed only under the DEDICATED AUDITOOOR_L37_CALLGRAPH_SETDIFF_STRICT (or the
    # global AUDITOOOR_L37_STRICT) when the reasoner never ran while a dataflow
    # substrate exists. MUST live in _SIGNAL_ORDER or it is computed then silently
    # dropped (bijection guard). Rebuttal: ``callgraph-set-difference:``.
    ("callgraph-set-difference", "fail-callgraph-setdiff-unprobed"),
    # LOGIC-OBLIGATION-RESOLUTION (LOGIC_ARSENAL_ROADMAP "ENFORCE, NOT ADVISORY"): the
    # umbrella JOIN over ALL pre-hunt logic reasoners (step-2d-*). Each reasoner emits an
    # obligation ledger that exploit_queue ingests + the per-fn OPEN-OBLIGATIONS block
    # folds; this signal FAILS when a reasoner-emitted obligation never reached a terminal
    # verdict (still needs_source/open). ENFORCED / DEFAULT-ON under the L37 umbrella
    # (advisory-first wave complete, operator "ENFORCE, NOT ADVISORY" 2026-07-13):
    # fail-closed on an OPEN obligation under the standard STRICT path (global
    # AUDITOOOR_L37_STRICT=1, which make audit-complete exports by default), with a
    # per-gate opt-out (AUDITOOOR_L37_LOGIC_OBLIGATION_RESOLUTION_STRICT in {0,false,no}).
    # MUST live in _SIGNAL_ORDER (bijection guard). Rebuttal: ``logic-obligation-resolution:``.
    ("logic-obligation-resolution", "fail-logic-obligation-unresolved"),
    # REASONER-FIRING-NONVACUITY (LOGIC_ARSENAL_ROADMAP, the FIRING half of the
    # shape->logic inversion): the sibling logic-obligation-resolution signal proves every
    # EMITTED obligation reached a terminal verdict, but a reasoner can pass the ORDERING
    # gate while emitting ZERO obligations and leaving ZERO trace of examining anything - a
    # silently-empty / never-written ledger reads identically to "ran clean". This signal
    # asserts every wired reasoner FIRED: examined>0 AND (>=1 emitted obligation OR an
    # explicit cited-empty examined-record OR a recorded source-cited surface-absent
    # exemption). A SILENTLY vacuous reasoner (empty/missing ledger, no record) FAILS.
    # Advisory-WARN by default; fail-closed under AUDITOOOR_L37_REASONER_FIRING_STRICT /
    # global AUDITOOOR_L37_STRICT (per-gate opt-out honored). MUST live in _SIGNAL_ORDER
    # (bijection guard). Rebuttal: ``reasoner-firing-nonvacuity:``.
    ("reasoner-firing-nonvacuity", "fail-reasoner-vacuous"),
    # EXECUTED-REFUTATION-HONESTY (LOGIC_ARSENAL_ROADMAP logic #2): rejects a grep-only
    # NEGATIVE on a value-mover unit (no executed refutation + guard-neutralization mutant
    # receipt). Standalone tool JOINED into the umbrella so a grep-NEGATIVE can fail
    # audit-complete. Advisory-WARN by default; fail-closed under
    # AUDITOOOR_L37_EXECUTED_REFUTATION_HONESTY_STRICT / global AUDITOOOR_L37_STRICT. MUST
    # live in _SIGNAL_ORDER (bijection guard). Rebuttal: ``executed-refutation-honesty:``.
    ("executed-refutation-honesty", "fail-executed-refutation-dishonest"),
    # =====================================================================
    # BAND D: drive (manifest phase: drive) - exploit-queue/chain-synth/conversion + originality/corpus/proof feedback + harness/invariant-fuzz/fuzz-saturation, DOWN after the reasoning substrate that feeds them
    # =====================================================================
    ("exploit-queue", "fail-no-exploit-queue"),
    ("chain-synth", "fail-no-chain-synth"),
    ("exploit-conversion", "fail-conversion-loop-not-run"),
    ("prove-top-leads", "fail-prove-top-leads-not-run"),
    # EXPLOIT-QUEUE-RESOLUTION (signal u): the morpho-3% false-pass gate.
    # prove-top-leads passes when a prove_top_leads_* artifact exists; it does
    # NOT inspect whether the leads it touched were genuinely resolved or merely
    # gate-killed. This signal reads the exploit-queue, ranks rows by
    # priority_score, and FAILS when every top-N candidate row is killed
    # exclusively by disqualification (quality_gate_status in the
    # disqualification set / proof_status=killed) with no cited
    # negative_control / clean_control artifact - distinguishing a real
    # refutation from "couldn't auto-prove, recorded as killed".
    # Advisory by default (parallel to prove-top-leads); hard-fails only when
    # ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 OR the explicit env flag
    # AUDITOOOR_L37_EXPLOIT_QUEUE_RESOLUTION_STRICT=1.
    ("exploit-queue-resolution", "fail-exploit-queue-all-leads-disqualification-killed"),
    # CONVERSION-THROUGHPUT (D1): the WHOLE-corpus sibling of exploit-queue-resolution
    # (which only inspects the top-5). Measures the fraction of NON-VACUOUS corpus/
    # hacker-Q leads that reach a terminal work-backed verdict and emits the UNDRIVEN
    # count loudly. ADVISORY-FIRST (throughput gap, NOT a false-green): WARN by
    # default, hard-fail ONLY under the dedicated AUDITOOOR_CONVERSION_THROUGHPUT_STRICT
    # (NOT subsumed by the L37 umbrella, so a routine run is byte-identical), and
    # DELIBERATELY not wired into audit-done-guard done=True this wave. Rebuttal key:
    # ``conversion-throughput:``.
    ("conversion-throughput", "fail-conversion-throughput-leak"),
    ("originality", "fail-no-originality"),
    ("advisory-corpus", "fail-advisory-corpus-incomplete"),
    ("learning", "fail-no-learning"),
    ("mined-landed", "fail-mined-not-landed"),
    ("cross-ws-seed", "fail-no-cross-ws-seed"),
    ("brain-prime", "fail-no-brain-prime"),
    # PR10 proof-conversion stages (downstream of the hunt/engine signals):
    # they collect proof/judgment artifacts, so they fire LAST in the ordering
    # after every upstream stage.
    ("novel-vector", "fail-no-novel-vector"),
    ("adversarial-panel", "fail-no-adversarial-panel"),
    ("evm-0day-proof", "fail-no-evm-0day-proof"),
    # r36-rebuttal: lane FIX-INVARIANT-FUZZ-GATE registered in .auditooor/agent_pathspec.json
    # INVARIANT-FUZZ completeness: an invariant harness that was BUILT must be
    # multi-invariant + mutation-verified + ACTUALLY FUZZED by a coverage-guided
    # engine. A built-but-never-fuzzed harness fails here (signal key ``invariant-fuzz:``).
    ("invariant-fuzz", "fail-invariant-fuzz-incomplete"),
    # FUZZ-SATURATION adequacy: invariant-fuzz asks "did the campaign hit the call
    # FLOOR (>=1M / >=500K)?" - a raw proxy. This sibling asks the real adequacy
    # question: did coverage SATURATE (stop growing) by end-of-run, measured from
    # the engine's own coverage-over-time curve? A campaign still-climbing at the
    # floor was INADEQUATE (10M really would have found more); one saturated at
    # 150K was adequate. ADVISORY-FIRST first landing (validated on STRATA only;
    # NOT yet lifted to the global L37 layer): strict is the DEDICATED
    # AUDITOOOR_FUZZ_SATURATION_STRICT ONLY, so `make audit-complete STRICT=1`
    # surfaces but does not block on it, and UNMEASURED (truncated / non-retained
    # log) is ALWAYS a WARN - never a retro-red. Sits right after invariant-fuzz
    # (the campaign-quality axes). Inherits the l37-rebuttal override (signal key
    # ``fuzz-saturation:``).
    ("fuzz-saturation", "fail-fuzz-still-climbing"),
    # INVARIANT-OBLIGATION recall: every value-moving function's DERIVED invariant
    # obligation (value_moving_functions floor + per_fn question_class) must be tested
    # (mutation-verified enumerated category) or dispositioned - the per-item RECALL
    # backstop that makes "all invariants held" falsifiable (the corpus/family axis is
    # breadth; this is per-item over the code's own value-movers). ADVISORY-FIRST:
    # strict is the DEDICATED AUDITOOOR_INVARIANT_OBLIGATION_STRICT only (not global
    # L37) - live validation shows real open obligations on parked ws, so auto-hard-
    # fail would retro-red; surfaces the gap every audit, hard-fails only under the
    # dedicated env. Inherits the l37-rebuttal override (signal key ``invariant-obligation:``).
    ("invariant-obligation", "fail-invariant-obligation-uncovered"),
    # r36-rebuttal: lane FIX-CORE-COVERAGE-GATE registered in .auditooor/agent_pathspec.json
    # CORE-COVERAGE: the per-CORE-CONTRACT sibling of invariant-fuzz. invariant-fuzz
    # asks "was each BUILT harness broad + non-vacuous + actually fuzzed?" but never
    # asks WHICH contract its CUT is - a periphery-only harness set (logging/view/
    # config shims) passes invariant-fuzz. This signal closes that periphery-only
    # false-green: if the workspace flags in-scope value-moving CORE contracts (the
    # canonical value_moving_functions.json set), it REQUIRES >=1 mutation-verified
    # stateful invariant harness whose CUT is one of those core contracts; else it
    # fails (signal key ``core-coverage:``). Sits right after invariant-fuzz (the two
    # harness-quality axes) and before exploit-class. WARN-passes on tooling-absence /
    # no-core-contracts / no-mutation-evidence (mirrors depth-certificate). Inherits
    # the l37-rebuttal override (signal key ``core-coverage:``).
    ("core-coverage", "fail-core-coverage-periphery-only"),
    # =====================================================================
    # BAND E: per-unit / meta coverage (manifest phases: depth + verdict) - the cross-cutting coverage/depth/completeness axes, hunt-trust LAST
    # =====================================================================
    # SWEPT-SURFACE coverage map fires LAST: it is the cross-cutting "is every
    # surface actually audited?" signal over the whole tree.
    ("coverage-map", "fail-no-coverage-map"),
    # RUBRIC coverage is the COMPLEMENTARY axis to coverage-map: coverage-map
    # asks "did every SURFACE get a hypothesis?"; rubric-coverage asks "did
    # every rubric IMPACT CLASS get a candidate?". Both fire last as the two
    # cross-cutting completeness axes.
    ("rubric-coverage", "fail-no-rubric-coverage"),
    # DEPTH-CERTIFICATE (R81): the per-UNIT depth axis, complementary to the
    # per-SURFACE coverage axes above. coverage-map/rubric-coverage ask "did we
    # TOUCH every surface / rubric class?"; depth-certificate asks "did we audit
    # each unit DEEPLY - per-guard negative-space + proactive sibling-path
    # guard-diff, with survivors validated?". It is a cross-cutting completeness
    # axis like coverage-map, so it sits right after rubric-coverage and before
    # the hunt-trust meta-signal. It ALSO enforces "0 findings = smell": a
    # workspace cannot be audit-complete with 0 findings unless the depth passes
    # ran WITH EVIDENCE. Delegates to depth-certificate-check.check_depth().
    ("depth-certificate", "fail-no-depth-certificate"),
    # FUNCTION-COVERAGE (signal s): the per-FUNCTION ATTACK completeness axis,
    # sibling to depth-certificate. coverage-map (o) asks "did every surface get
    # a HYPOTHESIS token?" (and a token can be a noise CCIA heuristic angle or a
    # vacuous per-function harness); this asks the sharper "did every in-scope
    # FUNCTION get a REAL attack with a recorded verdict?". An audit cannot be
    # complete while in-scope functions were never attacked. Delegates to
    # tools/function-coverage-completeness.py; WARN-passes on tooling-absence /
    # no-inputs (mirrors depth-certificate). Sits right after depth-certificate
    # (the two per-unit axes) and before the unhunted-followthrough /
    # hunt-trust signals.
    ("function-coverage", "fail-function-coverage-incomplete"),
    # CROSS-FUNCTION-COVERAGE: the COMPOSITION axis, the THIRD per-unit-and-above
    # completeness sibling to depth-certificate (per-guard / per-sibling-pair
    # asymmetry) and function-coverage (per-function attack). Where those ask
    # "is each UNIT covered?", this asks the COMPOSITION question coverage-map /
    # function-coverage / depth-certificate cannot: "is there a MUTATION-VERIFIED
    # test asserting the invariant that spans TWO-OR-MORE functions?" - the
    # deposit/withdraw round-trip conservation, the open->fund->close state-
    # machine global invariant. A workspace can have 100% per-function coverage
    # and still be broken by a composition bug no single-function harness
    # expresses. It is the FINAL cross-cutting completeness axis, so it sits
    # right after function-coverage and before the unhunted-followthrough /
    # hunt-trust meta-signals. Delegates to
    # tools/cross-function-invariant-coverage.check(ws); WARN-passes on
    # tooling-absence / no-source / no-requirements (mirrors depth-certificate).
    # Inherits the l37-rebuttal override (signal key ``cross-function-coverage:``).
    ("cross-function-coverage", "fail-cross-function-uncovered"),
    # r36-rebuttal: lane WIRE-GO-COVERAGE-ENFORCE registered in .auditooor/agent_pathspec.json
    # GO-COVERAGE-BASIS: the coverage-DENOMINATOR-correctness sibling of
    # function-coverage. function-coverage asks "did every in-scope function get a
    # real attack + verdict?" over WHATEVER denominator the fcc gate used; this asks
    # the prior question "was that denominator the RIGHT surface for the language/
    # domain?". For a confident Cosmos-SDK/CometBFT Go-L1, the denominator must be
    # the external entry-point surface (msg-server/ABCI/precompile/ante/IBC/RPC),
    # NOT every exported Go helper (the Solidity-internal analog). Fails when the ws
    # is Cosmos-Go-L1 but the fcc result lacks go_entry_surface.applied=True
    # (kill-switch left on / detection failed / stale pre-capability artifact) - so
    # a Go L1 can never silently pass/fail on the every-exported denominator.
    # Non-Cosmos workspaces N/A-pass. Advisory-first: WARN by default, hard-fail
    # only under AUDITOOOR_L37_GO_COVERAGE_BASIS_STRICT / the global
    # AUDITOOOR_L37_STRICT. WARN-passes on tooling-absence (mirrors function-
    # coverage). Sits right after function-coverage (the denominator it audits).
    # Inherits the l37-rebuttal override (signal key ``go-coverage-basis:``).
    # Global-rule admission (operator-approved, standing authority 2026-07-04): both
    # new signals were validated across 3 DISTINCT workspaces before lifting to the
    # global layer - SEI (Cosmos-Go, correctly flags genuine wrong-basis + unattested),
    # NUVA (Cosmos-Go, fail-closed re-attest requirement, never a false pass), STRATA
    # (non-Cosmos, N/A-pass under strict). Fail-closed-only: can never green a ws that
    # was not already green.
    # <!-- admitted: signal:GO_COVERAGE_BASIS -->
    # <!-- admitted: signal:MANUAL_STEP -->
    ("go-coverage-basis", "fail-go-coverage-wrong-basis"),
    # r36-rebuttal: lane WIRE-GO-COVERAGE-ENFORCE registered in .auditooor/agent_pathspec.json
    # MANUAL-STEP-REQUIRED: enforcement for pipeline steps that REQUIRE a manual
    # model action and cannot be safely autorun (the go-ethereum fork-delta prune
    # cautionary tale). An applicable-but-unattested manual step fails closed under
    # strict and surfaces the exact remediation instruction. N/A-passes when no
    # manual step applies. Advisory-first: WARN by default, hard-fail only under
    # AUDITOOOR_L37_MANUAL_STEP_STRICT / the global AUDITOOOR_L37_STRICT. WARN-passes
    # on tooling-absence. Inherits the l37-rebuttal override (signal key
    # ``manual-step-required:``).
    ("manual-step-required", "fail-manual-step-unattested"),
    # E2 compiler-feature-screen: an in-scope (pinned compiler version x language feature)
    # pair affected by a known miscompilation, or an un-screened affected pair (dedicated
    # opt-in AUDITOOOR_COMPILER_FEATURE_SCREEN_STRICT; advisory by default). MUST be in
    # _SIGNAL_ORDER or it is computed then silently dropped from failure aggregation.
    ("compiler-feature-screen", "fail-compiler-feature-unscreened"),
    # A2 cross-module trust-boundary seam: report-only advisory (never fails); surfaces
    # guarded-producer x unguarded-consumer-bypass edges as hunt review candidates.
    ("cross-module-trust-seam", "fail-cross-module-trust-seam"),
    # B3 enforcement-layer census: flags a trust layer present in source with 0 hunt
    # sidecars = a layer we never hunted. Advisory-WARN by default; hard-fails ONLY under
    # the dedicated opt-in AUDITOOOR_ENFORCEMENT_LAYER_CENSUS_STRICT (deliberately NOT the
    # L37 umbrella yet - present-detection is broader than credit, so dedicated-env-first).
    ("enforcement-layer-census", "fail-enforcement-layer-unhunted"),
    # r36-rebuttal: lane FIX-EXPLOIT-CLASS-GATE registered in .auditooor/agent_pathspec.json
    # EXPLOIT-CLASS coverage: every systemic/compositional exploit class tooling cannot
    # auto-find must carry a backed disposition (signal key ``exploit-class:``).
    ("exploit-class", "fail-exploit-class-undispositioned"),
    # COMPLETENESS-MATRIX (enumeration floor): the JOIN layer over the per-unit
    # axes. The other signals each read their own sidecar in isolation and
    # WARN-pass on absence, so a cell that was NEVER ENUMERATED (asset with no
    # invariant set, blank impact ledger, function never on the worklist) is
    # invisible. This asserts the cross-product (asset x function x invariant x
    # impact) is fully enumerated with a per-cell status; fail signals a
    # never-enumerated cell. Loud-WARN by default, HARD only under
    # AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE=1 (deliberate switch, not a silent
    # retroactive re-fail). Honors l37-rebuttal (signal key completeness-matrix).
    ("completeness-matrix", "fail-completeness-matrix-uncovered-cells"),
    # UNHUNTED-FOLLOWTHROUGH: a cross-cutting completeness axis like
    # coverage-map / depth-certificate. coverage-map asks "did we TOUCH every
    # surface?"; this asks "for every surface we IDENTIFIED as unhunted /
    # identified-but-no-verdict, did we drive it to a TERMINAL verdict
    # (confirmed / refuted / filed / killed) - or did we ABANDON it?". An audit
    # cannot be complete while it carries abandoned unhunted-surfaces with no
    # terminal verdict. Delegates to
    # tools/unhunted-surface-followthrough-gate.evaluate(); WARN-passes on
    # tooling-absence / no-inputs (mirrors depth-certificate). Sits after
    # depth-certificate and before the hunt-trust meta-signal.
    ("unhunted-followthrough", "fail-unhunted-followthrough-abandoned"),
    # INSCOPE-DISPOSITION: the generic, language-agnostic scope-integrity backstop
    # (strata 2026-07-01). Every OOS/vendored/trusted disposition, in ANY tool for
    # ANY language, is checked against the authoritative inscope_units.jsonl: an
    # in-scope first-party unit can NEVER be closed out-of-scope. Fails closed under
    # strict; WARN otherwise; WARN-passes on no-manifest. Delegates to
    # tools/inscope-disposition-guard.evaluate().
    ("inscope-disposition", "fail-inscope-marked-oos"),
    # BUSINESS-FLOW COVERAGE (2026-07-01, cross-module combination axis): every
    # DRIVABLE business flow (operation / asset-lifecycle / state-machine /
    # long-transaction) must be driven by >=1 hunt/harness. An undriven
    # cross-module flow is a real coverage gap the per-function axis misses
    # (strata insolvency loss-transition). Fails CLOSED under strict - NOT
    # advisory. Delegates to tools/business_flow_decompose.coverage().
    ("business-flow-coverage", "fail-business-flow-undriven"),
    # HUNT-TRUST fires DEAD LAST: it is the meta-signal over the coverage axes.
    # coverage-map (o) and rubric-coverage (p) report numbers; hunt-trust (q)
    # answers "can you TRUST the hunt those numbers came from?". A coverage
    # number from a rate-limited / failed-run hunt is NOT real coverage. Like
    # (o)/(p) it is WARN-not-fail: it never blocks certification, it loudly
    # caveats the coverage so the operator re-hunts before relying on it.
    ("hunt-trust", "fail-hunt-untrustworthy"),
)

# ---------------------------------------------------------------------------
# PHASE-BAND conformance (the "upgrade" of the signal-registry bijection guard).
# Each signal is pinned to one of 5 phase bands mirroring the manifest
# (readme_runbook_steps.json phase field) collapsed to 5 headline bands:
#   A engine-reality  (manifest engine)    B flow-substrate (manifest substrate)
#   C reasoning       (manifest reasoning) D drive          (manifest drive)
#   E per-unit/meta   (manifest depth+verdict)
# _SIGNAL_ORDER MUST be NON-DECREASING in band rank so the headline verdict
# (verdict = failures[0]) is the earliest-PHASE failure, not an arbitrary
# hand-maintained position that silently drifts from the runbook. The map MUST
# also be a bijection with _SIGNAL_ORDER (every ordered signal banded, no orphan
# band entry) - together this catches BOTH order-drift and registry-drift at
# import time, a strict superset of the old set-only bijection guard.
# ---------------------------------------------------------------------------
_PHASE_BAND_ORDER = ("A", "B", "C", "D", "E")
_SIGNAL_PHASE_BAND = {
    'tier6-mining': 'A',
    'hunt-complete': 'A',
    'live-engines': 'A',
    'engine-harness': 'A',
    'hollow-not-genuinely-audited': 'A',
    'audit-preflight': 'A',
    'dataflow-substrate-health': 'B',
    'state-coupling': 'B',
    'enforcement-point': 'B',
    'hacker-questions': 'C',
    'hacker-questions-resolved': 'C',
    'attestation-count-integrity': 'C',
    'impact-methodology-corpus': 'C',
    'provider-liveness': 'C',
    'fork-divergence': 'C',
    'fork-divergence-content': 'C',
    'capability-wiring-integrity': 'C',
    'capability-firing-fraction': 'C',
    'callgraph-set-difference': 'C',
    'logic-obligation-resolution': 'C',
    'reasoner-firing-nonvacuity': 'C',
    'executed-refutation-honesty': 'C',
    'exploit-queue': 'D',
    'chain-synth': 'D',
    'exploit-conversion': 'D',
    'prove-top-leads': 'D',
    'exploit-queue-resolution': 'D',
    'conversion-throughput': 'D',
    'originality': 'D',
    'advisory-corpus': 'D',
    'learning': 'D',
    'mined-landed': 'D',
    'cross-ws-seed': 'D',
    'brain-prime': 'D',
    'novel-vector': 'D',
    'adversarial-panel': 'D',
    'evm-0day-proof': 'D',
    'invariant-fuzz': 'D',
    'fuzz-saturation': 'D',
    'invariant-obligation': 'D',
    'core-coverage': 'D',
    'coverage-map': 'E',
    'rubric-coverage': 'E',
    'depth-certificate': 'E',
    'function-coverage': 'E',
    'cross-function-coverage': 'E',
    'go-coverage-basis': 'E',
    'manual-step-required': 'E',
    'compiler-feature-screen': 'E',
    'cross-module-trust-seam': 'E',
    'enforcement-layer-census': 'E',
    'exploit-class': 'E',
    'completeness-matrix': 'E',
    'unhunted-followthrough': 'E',
    'inscope-disposition': 'E',
    'business-flow-coverage': 'E',
    'hunt-trust': 'E',
}


def _assert_phase_band_conformance():
    """Fail LOUD at import on phase-band drift: (1) every _SIGNAL_ORDER signal
    carries a band and no band entry is an orphan (bijection), and (2)
    _SIGNAL_ORDER is non-decreasing in band rank (so failures[0] is the
    earliest-phase failure). Supersedes the set-only registry bijection."""
    ordered = [s for s, _ in _SIGNAL_ORDER]
    banded = set(_SIGNAL_PHASE_BAND)
    missing = set(ordered) - banded
    orphan = banded - set(ordered)
    if missing or orphan:
        raise AssertionError(
            "phase-band registry drift: _SIGNAL_ORDER signals missing a band "
            f"{sorted(missing)} / band entries with no signal {sorted(orphan)}")
    rank = {b: i for i, b in enumerate(_PHASE_BAND_ORDER)}
    prev_rank, prev_sig = -1, None
    for s in ordered:
        r = rank[_SIGNAL_PHASE_BAND[s]]
        if r < prev_rank:
            raise AssertionError(
                f"_SIGNAL_ORDER is not phase-band sorted: {s!r} (band "
                f"{_SIGNAL_PHASE_BAND[s]}) follows {prev_sig!r} of a later band - "
                "reorder the tuple into its band or fix its _SIGNAL_PHASE_BAND entry")
        prev_rank, prev_sig = r, s


_assert_phase_band_conformance()

# The cross-ws-seed sibling-aware sub-verdict (ADD-A): reported INSIDE the
# cross-ws-seed signal but maps to a distinct top-level verdict so the operator
# knows a same-family sibling workspace existed and the seed was still skipped.
_CROSS_WS_SIBLING_VERDICT = "fail-cross-ws-seed-sibling-exists"

# The language-engine sub-verdict is reported INSIDE the live-engines signal
# but maps to a distinct top-level verdict so the operator knows the engine
# ran for the wrong language.
_LANG_MISMATCH_VERDICT = "fail-engines-not-run-for-language"

_REBUTTAL_MAX = 200
_REBUTTAL_RE = re.compile(
    r"(?:<!--\s*)?l37-rebuttal:\s*(?P<reason>.+?)(?:\s*-->)?\s*$",
    re.IGNORECASE,
)

# Source-language markers. Maps a language label to (extensions, engine kind).
# engine kind "solidity" => requires .auditooor/solidity-deep-audit/.
# engine kind "audit-deep" => requires an .audit_logs/audit_deep* manifest.
_LANG_EXT = {
    "solidity": ((".sol",), "solidity"),
    "rust": ((".rs",), "audit-deep"),
    "go": ((".go",), "audit-deep"),
    "move": ((".move",), "audit-deep"),
    "cairo": ((".cairo",), "audit-deep"),
    "vyper": ((".vy",), "solidity"),
    # ZK circuit languages (item 5). circom (.circom), zokrates (.zok), noir
    # (.nr). These have no Solidity/Go deep engine; the live-engine artifact for
    # a ZK workspace is a ZK certifying artifact (zk-circom-analyze candidates /
    # zk-engagement-probe surface / zk_preflight_packs). The "zk" engine kind is
    # handled by ``_has_zk_engine`` in check_live_engines.
    "circom": ((".circom",), "zk"),
    "zokrates": ((".zok",), "zk"),
    "noir": ((".nr",), "zk"),
}

# Directories we never treat as in-scope source when classifying language.
_SRC_PRUNE = {
    ".git", "node_modules", "lib", "out", "artifacts", "cache",
    "poc-tests", "poc_execution", "target", "vendor", "third_party",
    ".audit_logs", ".auditooor", "submissions", "prior_audits",
    "mining_rounds", "reports", "docs", "test", "tests", "mocks",
}


@dataclass
class SignalResult:
    signal: str
    ok: bool
    reason: str
    verdict_override: str | None = None  # distinct fail verdict (e.g. lang mismatch)
    artifacts: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def _is_file(p: Path) -> bool:
    try:
        return p.is_file()
    except OSError:
        return False


def _nonempty_dir(p: Path, suffixes: tuple[str, ...] = ()) -> bool:
    """True iff ``p`` is a dir with >=1 non-dotfile entry (optionally with a
    matching suffix). Recurses for suffix matching."""
    if not _exists(p) or not p.is_dir():
        return False
    try:
        for c in p.iterdir():
            if c.name.startswith("."):
                continue
            if not suffixes:
                return True
            if c.is_file() and c.name.endswith(suffixes):
                return True
            if c.is_dir():
                for g in c.rglob("*"):
                    if g.is_file() and not g.name.startswith(".") and g.name.endswith(suffixes):
                        return True
        return False
    except OSError:
        return False


def _glob_first(d: Path, patterns: tuple[str, ...]) -> Path | None:
    if not _exists(d) or not d.is_dir():
        return None
    for pat in patterns:
        try:
            for m in sorted(d.glob(pat)):
                if _exists(m):
                    return m
        except OSError:
            continue
    return None


# --------------------------------------------------------------------------
# Rebuttal parsing
# --------------------------------------------------------------------------
def _load_rebuttal(ws: Path) -> dict[str, str]:
    """Return {signal_name_or_'*': reason}. ``all:<reason>`` flips every
    signal; ``<signal>:<reason>`` flips one named signal; a bare ``<reason>``
    flips every signal (treated as ``all:``)."""
    out: dict[str, str] = {}
    rb_path = ws / ".auditooor" / "audit_completeness_rebuttal.txt"
    txt = _read_text(rb_path)
    if not txt:
        return out
    known = {s for s, _ in _SIGNAL_ORDER} | {"all"}
    for line in txt.splitlines():
        m = _REBUTTAL_RE.search(line.strip())
        if not m:
            continue
        reason = m.group("reason").strip()
        if not reason or len(reason) > _REBUTTAL_MAX:
            continue
        # r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json
        key = "*"
        body = reason
        if ":" in reason:
            head, _, tail = reason.partition(":")
            head_l = head.strip().lower()
            if head_l in known:
                # A recognized "<signal>:" prefix with an EMPTY tail is an
                # incomplete rebuttal - ignore it rather than mis-promoting
                # the bare "<signal>:" string to an all-signal rebuttal.
                if not tail.strip():
                    continue
                key = "*" if head_l == "all" else head_l
                body = tail.strip()
        out[key] = body
    return out


def _rebuttal_for(rebuttals: dict[str, str], signal: str) -> str | None:
    if signal in rebuttals:
        return rebuttals[signal]
    if "*" in rebuttals:
        return rebuttals["*"]
    return None


# --------------------------------------------------------------------------
# Signal (a): Tier-6 bidirectional commit-mining ran
# --------------------------------------------------------------------------
def check_tier6_mining(ws: Path) -> SignalResult:
    mining = ws / "mining_rounds"
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("TIER6_MINING")
    detail = {"mining_rounds": str(mining), "strict": strict}
    if not _nonempty_dir(mining):
        return SignalResult(
            signal="tier6-mining", ok=False,
            reason=(
                "no non-empty mining_rounds/ artifact; Tier-6 bidirectional "
                "commit-mining did not run"
            ),
            artifacts=[], detail=detail,
        )
    rounds_total = 0
    rounds_ran = 0
    ran_round_names: list[str] = []
    targets_processed_total = 0
    try:
        round_dirs = [d for d in mining.iterdir()
                      if d.is_dir() and not d.name.startswith(".")]
    except OSError:
        round_dirs = []

    def _posint(v: Any) -> bool:
        return isinstance(v, int) and not isinstance(v, bool) and v > 0

    for rd in round_dirs:
        rounds_total += 1
        ran_this = False
        try:
            files = [f for f in rd.iterdir()
                     if f.is_file() and not f.name.startswith(".")]
        except OSError:
            files = []
        # (1) real git-commits-mining output JSON in the round
        for f in files:
            nm = f.name.lower()
            if nm.endswith("_git_commits_mining.json") or nm.endswith("commits_mining.json"):
                payload = _load_json(f)
                if isinstance(payload, dict) and (
                    _posint(payload.get("commits_scanned"))
                    or (isinstance(payload.get("commits"), list) and len(payload["commits"]) > 0)
                    or _posint(payload.get("security_fix_count"))
                    or _posint(payload.get("commit_count"))
                ):
                    ran_this = True
                    break
        # (2) commit_mining_manifest.json that processed >=1 target and emitted
        #     a per-target verdict (ran / ok / skipped_existing / skipped_no_gh_auth
        #     all mean the orchestration consumed a target and recorded a result --
        #     distinct from an empty no-target manifest).
        if not ran_this:
            man = rd / "commit_mining_manifest.json"
            if _is_file(man):
                mp = _load_json(man)
                if isinstance(mp, dict):
                    rows = mp.get("rows")
                    summ = mp.get("summary") or {}
                    targets_seen = mp.get("targets_seen")
                    rows_ok = isinstance(rows, list) and any(
                        isinstance(r, dict) and (r.get("status") or r.get("recommendation"))
                        for r in rows
                    )
                    processed = (
                        rows_ok
                        or (_posint(targets_seen) and isinstance(summ, dict) and any(
                            _posint(summ.get(k)) for k in
                            ("ran", "ok", "skipped_existing", "skipped_no_gh_auth", "failed")
                        ))
                    )
                    if processed:
                        ran_this = True
                        if _posint(targets_seen):
                            targets_processed_total += targets_seen
        # (3) substantive CLOSEOUT.md (legacy pre-manifest rounds).
        # A bare char-count is insufficient: any 200-char placeholder text would
        # pass.  Require at least one real-mining structural marker AND the
        # absence of known boilerplate sentinel phrases.
        # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
        if not ran_this:
            co = rd / "CLOSEOUT.md"
            if _is_file(co):
                txt = _read_text(co) or ""
                _MINING_MARKERS = [
                    r"[0-9a-f]{40}",                          # a git SHA
                    r"commits[_ ](?:analyzed|scanned)\s*[:=]\s*[1-9]",
                    r"security_fix_count\s*[:=]\s*[1-9]",
                    r"targets_processed\s*[:=]\s*[1-9]",
                ]
                _BOILERPLATE = [
                    "no targets were processed",
                    "no commits were scanned",
                    "placeholder",
                ]
                low = txt.strip().lower()
                has_marker = any(
                    re.search(p, txt, re.I) for p in _MINING_MARKERS
                )
                has_boilerplate = any(b in low for b in _BOILERPLATE)
                if len(low) >= 200 and has_marker and not has_boilerplate:
                    ran_this = True
        if ran_this:
            rounds_ran += 1
            ran_round_names.append(rd.name)
    detail.update({
        "rounds_total": rounds_total,
        "rounds_ran": rounds_ran,
        "ran_rounds": ran_round_names[:8],
        "targets_processed": targets_processed_total,
    })
    if rounds_ran > 0:
        return SignalResult(
            signal="tier6-mining", ok=True,
            reason=(
                f"Tier-6 commit-mining ran with genuine output "
                f"({rounds_ran}/{rounds_total} round(s) carry a real mining JSON / "
                f"target-processing manifest / substantive closeout)"
            ),
            artifacts=[str(mining)], detail=detail,
        )
    hollow = (
        f"mining_rounds/ present ({rounds_total} round-dir(s)) but NONE carry "
        f"genuine-ran evidence: no real *_git_commits_mining.json with commits, "
        f"no manifest that processed a target, no substantive CLOSEOUT.md - "
        f"file-presence-only, the mining stage did not actually run over a target"
    )
    if strict:
        return SignalResult(
            signal="tier6-mining", ok=False, reason=hollow,
            artifacts=[str(mining)], detail=detail,
        )
    return SignalResult(
        signal="tier6-mining", ok=True, reason="WARN: " + hollow,
        artifacts=[str(mining)], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (b): the HUNT half passed (delegates to hunt-completeness-check)
# --------------------------------------------------------------------------
def _load_hunt_completeness_module():
    tool_path = Path(__file__).resolve().with_name("hunt-completeness-check.py")
    spec = importlib.util.spec_from_file_location("_hunt_completeness_acc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclass field() introspection (Python 3.14)
    # can resolve the module dict for SignalResult's default_factory fields.
    sys.modules["_hunt_completeness_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _live_capability_set_hash():
    """The current capability_set_hash (T1), or None. Stamped into the
    audit_complete_last_result.json marker so audit-done-guard can re-stale a
    prior pass when the capability set changed underneath it. Delegates to the
    ONE shared source (capability-wiring-integrity-check.current_capability_set_hash)
    so the written hash matches the guard's re-computation byte-for-byte."""
    try:
        tool_path = Path(__file__).resolve().with_name(
            "capability-wiring-integrity-check.py")
        spec = importlib.util.spec_from_file_location("_capset_hash_acc", tool_path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_capset_hash_acc"] = mod
        spec.loader.exec_module(mod)
        fn = getattr(mod, "current_capability_set_hash", None)
        if fn is None:
            return None
        return fn()
    except Exception:
        return None


def check_hunt_complete(ws: Path) -> SignalResult:
    mod = _load_hunt_completeness_module()
    if mod is None or not hasattr(mod, "evaluate"):
        return SignalResult(
            signal="hunt-complete", ok=False,
            reason="unable to load hunt-completeness-check helper",
            artifacts=[], detail={"helper": "unavailable"},
        )
    try:
        result = mod.evaluate(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="hunt-complete", ok=False,
            reason=f"hunt-completeness gate raised: {exc}",
            artifacts=[], detail={"error": str(exc)},
        )
    verdict = result.get("verdict")
    if verdict == "pass-hunt-complete":
        return SignalResult(
            signal="hunt-complete", ok=True,
            reason="hunt-completeness gate PASS (dedup-first + a-e)",
            artifacts=[], detail={"hunt_verdict": verdict},
        )
    failures = result.get("failures", [])
    return SignalResult(
        signal="hunt-complete", ok=False,
        reason=(
            f"hunt-completeness gate NOT passed: verdict={verdict} "
            f"({', '.join(failures) if failures else result.get('reason', '')})"
        ),
        artifacts=[], detail={"hunt_verdict": verdict, "hunt_failures": failures},
    )


# --------------------------------------------------------------------------
# Signal (c): LANGUAGE-CORRECT live engines ran
# --------------------------------------------------------------------------
def _scope_source_root(ws: Path) -> Path:
    """Prefer <ws>/src as the in-scope source root; fall back to ws."""
    src = ws / "src"
    if _exists(src) and src.is_dir():
        return src
    return ws


def _detect_languages(ws: Path) -> dict[str, int]:
    """Scan the in-scope source root for language markers; return
    {language: file_count} for any language with >=1 source file. Prunes
    vendored / tooling / non-source dirs so we classify only target source."""
    root = _scope_source_root(ws)
    ext_to_lang = {}
    for lang, (exts, _kind) in _LANG_EXT.items():
        for e in exts:
            ext_to_lang[e] = lang
    counts: dict[str, int] = {}
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            # prune in place
            dirnames[:] = [
                d for d in dirnames
                if d not in _SRC_PRUNE and not d.startswith(".")
            ]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                lang = ext_to_lang.get(ext)
                if lang:
                    counts[lang] = counts.get(lang, 0) + 1
    except OSError:
        pass
    return counts


def _has_solidity_engine(ws: Path) -> bool:
    return _nonempty_dir(ws / ".auditooor" / "solidity-deep-audit")


# ZK certifying-signal artifacts (item 5). A ZK circuit workspace (circom /
# zokrates / noir) has no Solidity or Go deep engine; its live-engine evidence
# is a ZK analysis/preflight artifact left behind by the ZK tools
# (zk-circom-analyze.py -> zk_circom_candidates.jsonl, zk-engagement-probe.py ->
# zk_surface.json, the zk_preflight_packs manifest, or a zk-chain-synth output).
# We require a NON-EMPTY artifact so an empty placeholder file does not vacuously
# certify a ZK engine.
_ZK_ENGINE_ARTIFACT_RELS = (
    (".auditooor", "zk_circom_candidates.jsonl"),
    (".auditooor", "zk_surface.json"),
    (".auditooor", "zk_analysis.json"),
    (".auditooor", "zk_deep_audit.json"),
)
_ZK_ENGINE_ARTIFACT_DIRS = (
    (".auditooor", "zk_preflight_packs"),
    (".auditooor", "zk_deep_audit"),
)


def _zk_engine_artifacts(ws: Path) -> list[str]:
    """Return the ZK certifying artifacts present (non-empty) for this
    workspace, or [] when none. Used as the live-engine evidence for a ZK
    circuit target."""
    found: list[str] = []
    for rel in _ZK_ENGINE_ARTIFACT_RELS:
        p = ws.joinpath(*rel)
        try:
            if p.is_file() and p.stat().st_size > 0:
                found.append(str(p))
        except OSError:
            continue
    for rel in _ZK_ENGINE_ARTIFACT_DIRS:
        d = ws.joinpath(*rel)
        if _nonempty_dir(d):
            found.append(str(d))
    return found


def _has_zk_engine(ws: Path) -> bool:
    return bool(_zk_engine_artifacts(ws))


def _load_audit_deep_manifest_module():
    tool_path = Path(__file__).resolve().with_name("audit-deep-manifest.py")
    spec = importlib.util.spec_from_file_location("_l37_audit_deep_manifest", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_l37_audit_deep_manifest"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _audit_deep_freshness(
    ws: Path,
    *,
    require_full_invariant_denominator: bool = False,
) -> dict:
    """Use audit-deep-manifest.py as the current-run freshness authority."""
    mod = _load_audit_deep_manifest_module()
    if mod is None or not hasattr(mod, "check_freshness"):
        return {
            "ok": False,
            "verdict": "error",
            "reason": "unable to load audit-deep-manifest freshness authority",
        }
    try:
        return mod.check_freshness(
            ws,
            audit_run_manifest=ws / ".auditooor" / "audit_run_full_manifest.jsonl",
            require_full_invariant_denominator=require_full_invariant_denominator,
        )
    except Exception as exc:  # pragma: no cover - defensive fail-close
        return {"ok": False, "verdict": "error", "reason": f"freshness check raised: {exc}"}


def _fresh_source_manifest_kinds(freshness: dict) -> set[str]:
    if freshness.get("verdict") != "pass-fresh-deep-manifest":
        return set()
    out: set[str] = set()
    for row in freshness.get("source_manifests") or []:
        if not isinstance(row, dict) or not row.get("fresh"):
            continue
        kind = str(row.get("kind") or "").strip()
        if kind:
            out.add(kind)
    return out


# Verdicts from check_freshness that mean the manifest's *current-run COUPLING*
# (the audit_run_full_manifest.jsonl start row / run-start ordering / its run_id)
# could not be established, NOT that the engine itself failed. A genuinely-
# successful deep-engine run can hit one of these purely because the run-start
# bookkeeping row is absent / unmatched (a CI shard ran the engine but never
# wrote the start row, a resumed run, a manually-invoked engine pass, etc.). When
# the freshness authority returns one of these, L37 must fall back to a POSITIVE
# completeness check on the manifests themselves (see
# ``_complete_successful_manifest_kinds``) so a real, complete, all-engines-ok
# run is not false-negatived. Genuine execution / integrity failures
# (``fail-conflicting-deep-manifest`` / ``fail-stale-deep-manifest`` / etc.) are
# DELIBERATELY excluded - those mean the engine actually failed or the evidence
# is tampered, and must stay failing.
_RUN_COUPLING_FRESHNESS_VERDICTS = frozenset({
    "fail-no-current-run-start",
    "fail-current-run-start-not-found",
    "fail-current-run-missing-run-id",
})


def _row_invariant_denominator_complete(row: dict) -> bool:
    """True iff this source-manifest row carries POSITIVE evidence of a complete
    in-scope invariant denominator (no denominator>executed gap). Reads the
    execution_detail emitted by audit-deep-manifest's assessment.

    Honest bar: a row WITHOUT a denominator signal at all does NOT pass (we never
    credit a manifest that never reported any invariant-denominator accounting).
    A row WITH a denominator signal passes only when there are zero denominator
    errors AND, when the synced ``invariant_denominator_status`` string is
    present, it is exactly ``complete-full-invariant-denominator``.
    """
    detail = row.get("execution_detail")
    if not isinstance(detail, dict):
        return False
    # The synced status string is the strongest signal when present.
    status = detail.get("invariant_denominator_status")
    if isinstance(status, str) and status:
        return status == "complete-full-invariant-denominator"
    # Otherwise fall back to the per-check accounting: there must be at least one
    # invariant-denominator check AND zero denominator-exceeds-executed errors.
    check_count = detail.get("invariant_denominator_check_count")
    error_count = detail.get("invariant_denominator_error_count")
    if not isinstance(check_count, int) or check_count <= 0:
        return False
    if not isinstance(error_count, int) or error_count != 0:
        return False
    return True


def _independent_source_manifest_rows(ws: Path) -> list[dict]:
    """Assess every source deep-engine manifest INDEPENDENT of the current-run
    start coupling.

    ``check_freshness`` short-circuits with an EMPTY ``source_manifests`` list
    when it cannot find a current-run start row (the run-coupling failure). To
    run the POSITIVE-completeness fallback we therefore re-assess each manifest
    directly via audit-deep-manifest's ``_source_manifest_status`` with a
    permissive run_start (epoch) and run_id=None - this yields the per-manifest
    ``execution_ok`` / ``workspace_matches`` / invariant-denominator detail
    WITHOUT the run-start ordering or run_id-matching requirement, which is
    exactly the coupling we are deliberately bypassing. Engine SUCCESS and
    workspace/schema/denominator integrity are STILL enforced by the row's
    ``execution_ok`` (engines genuinely ran and succeeded with backed evidence),
    so this never credits a failed / partial / tampered manifest.
    """
    mod = _load_audit_deep_manifest_module()
    if mod is None or not hasattr(mod, "_source_manifest_status") or not hasattr(mod, "SOURCE_MANIFESTS"):
        return []
    try:
        from datetime import datetime, timezone
        epoch = datetime.fromtimestamp(0, timezone.utc)
        # A solidity language present => require the full invariant denominator,
        # matching check_live_engines' require_full_invariant_denominator.
        langs = _detect_languages(ws)
        require_full = any(_LANG_EXT[lang][1] == "solidity" for lang in langs)
        rows: list[dict] = []
        for rel, kind in mod.SOURCE_MANIFESTS:
            try:
                row = mod._source_manifest_status(
                    ws / rel, kind, ws, epoch, None,
                    require_full_invariant_denominator=require_full,
                )
            except Exception:
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows
    except Exception:
        return []


def _complete_successful_manifest_kinds(freshness: dict, ws: Path | None = None) -> set[str]:
    """POSITIVE-completeness fallback acceptance for the live-engines signal.

    Returns the set of source-manifest kinds whose row proves a GENUINELY
    complete + successful deep-engine run INDEPENDENT of the current-run start
    coupling. A kind is credited ONLY when its row shows ALL of:
      - the manifest exists and matches THIS workspace,
      - the manifest schema matches the expected schema,
      - the deep-engine assessment passed (``execution_ok`` is True - engines
        genuinely succeeded; a failed / tampered / no-target run is excluded),
      - the run_id does NOT mismatch (a manifest from a DIFFERENT run is stale,
        not a coupling false-negative), and
      - for the Solidity kinds, the in-scope invariant denominator is COMPLETE
        (``_row_invariant_denominator_complete``) so a partial-denominator run is
        not silently upgraded to a full-proof live engine.

    This is NEVER vacuous: ``execution_ok`` already encodes "engines actually
    ran and succeeded with backed evidence", and the denominator-complete bar
    encodes "the full in-scope invariant denominator executed". A syntactic-only
    Rust/Go source-graph manifest (rust-source-graph / rust-cross-crate-graph)
    is INTENTIONALLY excluded from the credited kinds below - only an executed
    deep-engine manifest (solidity-deep-audit / solidity-deep-all-harnesses /
    audit-deep-all-manifest) counts as a live ENGINE.
    """
    # Only the executed deep-engine kinds are eligible to be credited as a live
    # engine via this fallback. Syntactic source/graph extraction manifests
    # (rust-source-graph, rust-cross-crate-graph, go-dlt-audit-enforcement is a
    # graph/enforcement manifest, legacy-audit-deep-manifest) are deliberately
    # NOT here: a graph pass is not an executed engine.
    _EXECUTED_ENGINE_KINDS = {
        "solidity-deep-audit",
        "solidity-deep-all-harnesses",
        "audit-deep-all-manifest",
    }
    # Solidity kinds additionally require the invariant denominator to be complete.
    _SOLIDITY_KINDS = {"solidity-deep-audit", "solidity-deep-all-harnesses"}
    out: set[str] = set()
    rows = freshness.get("source_manifests") or []
    # check_freshness short-circuits with an EMPTY source_manifests list when the
    # current-run start row is absent (fail-no-current-run-start /
    # fail-current-run-missing-run-id). Re-assess the manifests independently of
    # the coupling so the fallback has rows to inspect.
    if not rows and ws is not None:
        rows = _independent_source_manifest_rows(ws)
    for row in rows:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind") or "").strip()
        if kind not in _EXECUTED_ENGINE_KINDS:
            continue
        if not row.get("exists"):
            continue
        if not row.get("workspace_matches"):
            continue
        if row.get("schema_matches") is False:
            continue
        if not row.get("execution_ok"):
            continue
        if row.get("run_id_mismatch"):
            continue
        if kind in _SOLIDITY_KINDS and not _row_invariant_denominator_complete(row):
            continue
        out.add(kind)
    return out


# R28: reason substrings that indicate a FIXABLE engine misconfig (the operator can
# repair it and actually fuzz) - as opposed to a genuine no-applicable-engine arm. Kept
# conservative: matches remappings/solc/import/compile/project-root/config, NOT
# "no medusa/echidna-equivalent" (genuine) or a bare "not installed" (environmental).
_ENGINE_SKIP_MISCONFIG_RE = re.compile(
    r"remapping|solc\s|solc-|solc version|import[^\n]{0,40}not\s+found|file\s+not\s+found|"
    r"compilation\s+failed|compile\s+error|ParserError|could\s+not\s+resolve|"
    r"no\s+single\s+forge\s+project\s+root|foundry\.toml|hardhat\.config|SourceUnit|"
    r"remappings\.txt|no\s+forge\s+root|multiple\s+forge\s+roots",
    re.IGNORECASE)


def _independent_typed_deep_skip(ws: Path) -> dict | None:
    """Coupling-independent read of a TYPED deep-engine skip record.

    ``check_freshness`` only surfaces ``pass-explicit-deep-skip`` when it could
    first establish the current-run START COUPLING (a matching
    ``audit_run_full_manifest.jsonl`` start row with a run_id). On a workspace
    that ran the engines but never wrote that bookkeeping row (a resumed run, a
    CI shard, a manually-invoked deep pass), ``check_freshness`` short-circuits
    at ``fail-no-current-run-start`` with ``skip=null`` - the SAME coupling we
    already bypass for genuinely-complete manifests via
    ``_complete_successful_manifest_kinds``. This helper re-reads the typed-skip
    authority directly with a permissive ``run_start`` (epoch) and ``run_id``
    (None) so an honestly-emitted ``.auditooor/stage_skips.json`` typed-skip is
    credited INDEPENDENT of the run-start ordering / run_id coupling.

    A skip is recognised ONLY when it carries a non-empty ``reason`` and no read
    ``error``. This is NOT a false-pass: the skip is a DOCUMENTED, JUSTIFIED
    declaration that a language arm has no applicable coverage-guided engine in
    this run (e.g. a Cosmos Go chain with no medusa/echidna equivalent wired, or
    the EVM coverage-guided fuzzers blocked rc=2 on a mixed Go+Solidity layout).
    It credits a typed-skip disposition - which the caller surfaces as a
    ``typed-skip`` (not a hollow pass and not a faked harness count) - rather
    than a hollow false-pass or a silent miss. A missing skip file returns None.
    """
    mod = _load_audit_deep_manifest_module()
    if mod is None or not hasattr(mod, "_typed_skip_reason"):
        return None
    skip_key = getattr(mod, "DEFAULT_SKIP_KEY", "NO_AUDIT_DEEP_REASON")
    try:
        from datetime import datetime, timezone
        epoch = datetime.fromtimestamp(0, timezone.utc)
        skip = mod._typed_skip_reason(ws, skip_key, epoch, None)
    except Exception:
        return None
    if not isinstance(skip, dict):
        return None
    if skip.get("error"):
        return None
    reason = str(skip.get("reason") or "").strip()
    if not reason:
        return None
    # R28 (enforcement-gap 2026-07-03): a typed deep-engine skip greens live-engines even
    # when the skip REASON is a FIXABLE misconfig (remappings / solc version / import
    # resolution / compile error / "no single forge project root on a mixed layout") rather
    # than a GENUINE no-applicable-engine arm (no medusa/echidna equivalent for a Go/Cosmos
    # module) - laundering a fixable engine error into a documented skip. Classify it; the
    # suspect flag is ALWAYS surfaced for visibility, and under
    # AUDITOOOR_ENGINE_SKIP_MISCONFIG_STRICT a fixable-misconfig skip is NOT credited
    # (return None -> the typed-skip pass is withheld; the operator fixes the config or
    # re-attempts the native toolchain, e.g. point forge at the .sol subtree). Default OFF
    # -> unchanged (a mixed genuine+fixable reason like NUVA's is flagged but still credited).
    if _ENGINE_SKIP_MISCONFIG_RE.search(reason):
        skip["misconfig_launder_suspect"] = True
        if os.environ.get("AUDITOOOR_ENGINE_SKIP_MISCONFIG_STRICT", "").strip().lower() in ("1", "true", "yes", "on"):
            return None
    return skip


def _nonevm_engine_executed(ws: Path) -> bool:
    """A non-EVM (Rust/Go/Move) language has its matching live engine iff a
    language engine manifest shows a POSITIVE executed test/harness count. This
    is the SAME genuine-execution evidence the engine-harness signal credits.
    A failed/skipped EVM engine profile (halmos/medusa/echidna have no forge
    project on a non-EVM target) must NOT make live-engines fail when the
    language engine genuinely ran. NOT a false-pass: requires a real positive
    executed count, never a spec-doc 'profile success' with zero runs. Generic."""
    _EVM = {"halmos", "medusa", "echidna"}
    for sub in ("fuzz_runs", ".audit_logs/fuzz_runs"):
        d = ws / sub
        if not d.is_dir():
            continue
        for man in d.glob("*/manifest.json"):
            data = _load_json(man) or {}
            if str(data.get("engine") or "").lower() in _EVM:
                continue
            status = str(data.get("status") or "").lower()
            count = 0
            for k in ("tests_passed", "tests_run", "harness_count",
                      "executed_harnesses", "properties_checked"):
                try:
                    count = max(count, int(data.get(k) or 0))
                except (ValueError, TypeError):
                    pass
            if status in ("pass", "ok", "counterexample") and count > 0:
                return True
    return False


def _authored_harnesses_genuinely_executed_completeness(ws: Path) -> bool:
    """True iff .auditooor/solidity-deep-audit/engine-harness-execution.json
    records at least one authored poc-tests/*-engine-harness/ harness that:
      - ran forge test with tests_passed > 0 and status in ("pass", "pass-with-failures")
      - contains a genuine (non-assert(true)) assertion in its test/src Solidity files.

    Mirrors audit-honesty-check.py's _authored_engine_harnesses_genuinely_executed.
    NOT a false-pass: both the execution record AND a real assertion must be present.
    An assert(true)-only harness is still a stub and returns False.
    """
    exec_path = ws / ".auditooor" / "solidity-deep-audit" / "engine-harness-execution.json"
    if not _exists(exec_path):
        return False
    data = _load_json(exec_path)
    if not isinstance(data, dict):
        return False
    if str(data.get("schema") or "") != "auditooor.engine_harness_execution.v1":
        return False
    try:
        total_executed = int(data.get("executed_engine_harness_count") or 0)
    except (ValueError, TypeError):
        return False
    if total_executed <= 0:
        return False
    harnesses = data.get("harnesses") or []
    for h in harnesses:
        if not isinstance(h, dict):
            continue
        try:
            tests_passed = int(h.get("tests_passed") or 0)
        except (ValueError, TypeError):
            continue
        status = str(h.get("status") or "").lower()
        if tests_passed <= 0 or status not in ("pass", "pass-with-failures"):
            continue
        root = h.get("root") or ""
        if not root:
            continue
        root_path = Path(root)
        sol_files: list[Path] = []
        # Only scan the test dir for genuine assertions - scanning src/ would
        # credit require() calls in imported production contracts, letting an
        # assert(true)-only stub harness look genuine.
        # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
        for sub in ("test",):
            d = root_path / sub
            if d.is_dir():
                sol_files.extend(d.rglob("*.sol"))
        sol_files.extend(root_path.glob("*.sol"))
        for sf in sol_files[:50]:
            txt = _read_text(sf)
            if txt is None:
                continue
            has_genuine_assert = "assertEq(" in txt or "require(" in txt
            has_any_assert = "assert(" in txt
            has_only_stub = "assert(true)" in txt and not has_genuine_assert
            if has_genuine_assert or (has_any_assert and not has_only_stub):
                return True
    return False


# Coverage-guided campaign call-count thresholds (the canonical step-2c bars).
_CAMPAIGN_CALL_THRESHOLD = {"echidna": 500_000, "medusa": 1_000_000}
_CAMPAIGN_TOTAL_CALLS_RE = re.compile(r"Total calls:\s*([0-9][0-9_,]*)", re.IGNORECASE)


def _fuzz_log_max_calls(ws: Path) -> int:
    """Parse the RAW step-2c engine logs (.auditooor/fuzz_logs/*.log, incl. the
    _campaign_index.log) for ``Total calls: N`` lines and return the max N seen,
    or 0 when there is no parseable evidence of executed calls. This is the
    anti-tamper cross-check: a fuzz_campaign_receipt.json call count is only
    credited when a real engine log independently corroborates >= threshold
    executed calls. A no-target / rc=6 / zero-call auto-run leaves no such line,
    so it can never satisfy the cross-check."""
    log_dir = ws / ".auditooor" / "fuzz_logs"
    if not _exists(log_dir) or not log_dir.is_dir():
        return 0
    best = 0
    try:
        logs = list(log_dir.glob("*.log"))
    except OSError:
        return 0
    for lp in logs:
        txt = _read_text(lp)
        if not txt:
            continue
        for m in _CAMPAIGN_TOTAL_CALLS_RE.finditer(txt):
            try:
                n = int(m.group(1).replace(",", "").replace("_", ""))
            except (ValueError, TypeError):
                continue
            if n > best:
                best = n
    return best


def _standalone_coverage_campaign_executed(ws: Path) -> dict:
    """Credit a STANDALONE coverage-guided engine campaign (the step-2c runner:
    echidna >=500k / medusa >=1M over the real CUT) that is recorded in
    .auditooor/fuzz_campaign_receipt.json but lives OUTSIDE the solidity-deep-audit
    manifest the legacy accept-paths read. Returns {"ok": bool, "reason": str,
    "calls": int, "artifacts": [..]}.

    NEVER a false-pass. Three non-droppable guards, all required for a credit:
      (i)   real-CUT harness: campaign.harness resolves to an existing file under
            ws and is not a mock-only path;
      (ii)  executed calls >= per-engine threshold, parsed from the RAW engine log
            (not the receipt JSON) - the receipt's own call count must ALSO be
            >= threshold, and we credit on min(receipt, corroborating-raw-log is
            present) so a hand-faked receipt with no real log cannot pass;
      (iii) non-vacuity: >=1 behavior-changing mutant killed (campaign or receipt
            totals non_vacuity_kills, or a mutation_detail baseline=PASS ->
            mutant=FAIL) - blocks an assert(true)/tautological campaign.
    Plus: schema match, workspace match, result.passed>=1, result.failed==0
    (or an explicitly mutant-labeled kill campaign). Any missing file / mismatch
    / sub-threshold / unreadable log returns ok=False.
    """
    out = {"ok": False, "reason": "", "calls": 0, "artifacts": []}
    receipt_path = ws / ".auditooor" / "fuzz_campaign_receipt.json"
    if not _exists(receipt_path):
        out["reason"] = "no fuzz_campaign_receipt.json"
        return out
    data = _load_json(receipt_path)
    if not isinstance(data, dict):
        out["reason"] = "receipt not a JSON object"
        return out
    if str(data.get("schema") or "") != "auditooor.fuzz_campaign_receipt.v1":
        out["reason"] = "receipt schema mismatch"
        return out
    # workspace match: receipt records the basename (e.g. "ssv-network")
    rcv_ws = str(data.get("workspace") or "").strip()
    if rcv_ws and rcv_ws not in (ws.name, str(ws), str(ws.resolve())):
        out["reason"] = f"receipt workspace '{rcv_ws}' != '{ws.name}'"
        return out
    max_log_calls = _fuzz_log_max_calls(ws)
    totals = data.get("totals") if isinstance(data.get("totals"), dict) else {}
    try:
        totals_kills = int(totals.get("non_vacuity_kills") or 0)
    except (ValueError, TypeError):
        totals_kills = 0
    campaigns = data.get("campaigns") or []
    for c in campaigns:
        if not isinstance(c, dict):
            continue
        engine = str(c.get("engine") or "").lower()
        thr = _CAMPAIGN_CALL_THRESHOLD.get(engine)
        if thr is None:
            continue
        res = c.get("result") if isinstance(c.get("result"), dict) else {}
        try:
            calls = int(res.get("calls") or 0)
            passed = int(res.get("passed") or 0)
            failed = int(res.get("failed") or 0)
        except (ValueError, TypeError):
            continue
        # (ii) receipt call count must clear the bar...
        if calls < thr or passed < 1:
            continue
        # ...AND the raw engine log must independently corroborate >= threshold.
        if max_log_calls < thr:
            continue
        # passed-clean OR an explicit mutant-kill campaign (failed>0 by design)
        is_mutant_campaign = "mutant" in str(c.get("name") or "").lower()
        if failed != 0 and not is_mutant_campaign:
            continue
        # (i) real-CUT harness under ws, not a mock-only path
        harness = str(c.get("harness") or "").replace("\\", "/")
        if not harness:
            continue
        hp = (ws / harness).resolve()
        try:
            if not (hp.is_file() and hp.is_relative_to(ws.resolve())):
                continue
        except (OSError, ValueError):
            continue
        base = hp.name.lower()
        if base.startswith("mock") or "/mock" in harness.lower():
            continue
        # (iii) non-vacuity: a behavior-changing mutant must have been killed
        try:
            c_kills = int(c.get("non_vacuity_kills") or 0)
        except (ValueError, TypeError):
            c_kills = 0
        md_kill = any(
            isinstance(m, dict)
            and str(m.get("baseline") or "").upper() == "PASS"
            and str(m.get("mutant_result") or "").upper() == "FAIL"
            for m in (c.get("mutation_detail") or [])
        )
        if c_kills < 1 and totals_kills < 1 and not md_kill:
            continue
        out["ok"] = True
        out["calls"] = max(calls, max_log_calls)
        out["reason"] = (
            f"standalone {engine} campaign '{c.get('name')}' executed "
            f"{calls} calls (raw-log corroborated {max_log_calls} >= {thr}) on real CUT "
            f"{harness}; non-vacuity kill present"
        )
        out["artifacts"] = [str(receipt_path), str(ws / ".auditooor" / "fuzz_logs")]
        return out
    out["reason"] = (
        "no campaign cleared all guards (engine threshold + raw-log corroboration "
        f"[max_log_calls={max_log_calls}] + real-CUT harness + non-vacuity kill)"
    )
    return out


def check_live_engines(ws: Path) -> SignalResult:
    langs = _detect_languages(ws)
    require_full_invariant_denominator = any(
        _LANG_EXT[lang][1] == "solidity" for lang in langs
    )
    legacy_solidity_engine_dir = _has_solidity_engine(ws)
    deep_freshness = _audit_deep_freshness(
        ws,
        require_full_invariant_denominator=require_full_invariant_denominator,
    )
    fresh_manifest_kinds = _fresh_source_manifest_kinds(deep_freshness)
    # POSITIVE-completeness fallback (item 2): when the freshness authority could
    # not establish the current-run START COUPLING (no start row / unmatched
    # run_id) - NOT when the engine genuinely failed - accept any manifest that
    # is independently proven complete + successful + (for Solidity) full-
    # invariant-denominator. This rescues a genuinely-successful Solidity/Go/Rust
    # engine run from a run-id-coupling false-negative without ever crediting a
    # failed / partial / syntactic-only / tampered manifest.
    coupling_fallback_kinds: set[str] = set()
    if deep_freshness.get("verdict") in _RUN_COUPLING_FRESHNESS_VERDICTS:
        coupling_fallback_kinds = _complete_successful_manifest_kinds(deep_freshness, ws)
    accepted_manifest_kinds = fresh_manifest_kinds | coupling_fallback_kinds
    sol_engine = bool(
        accepted_manifest_kinds.intersection({"solidity-deep-audit", "solidity-deep-all-harnesses"})
    )
    # Fallback: authored poc-tests/*-engine-harness/ harnesses ran forge test with genuine
    # (non-assert(true)) assertions and at least one passing test. This is the same execution
    # evidence that audit-honesty-check.py credits via _authored_engine_harnesses_genuinely_executed;
    # we mirror it here so the live-engines signal does not false-negative a workspace where
    # the Solidity manifest freshness authority fails (missing start-row / no run_id) but
    # the authored harnesses genuinely ran. NOT a false-pass: requires a real
    # engine-harness-execution.json with executed_engine_harness_count > 0 AND genuine
    # assertions in the source. An assert(true)-only harness is still a stub and does not count.
    sol_engine_authored = False
    if not sol_engine:
        sol_engine_authored = _authored_harnesses_genuinely_executed_completeness(ws)
        sol_engine = sol_engine_authored
    # Standalone coverage-guided campaign accept-path (serving-join fix): a real
    # step-2c echidna(>=500k)/medusa(>=1M) campaign over the real CUT, recorded in
    # .auditooor/fuzz_campaign_receipt.json + corroborated by the raw fuzz_logs and
    # carrying a non-vacuity mutant kill, is genuine live-engine evidence even when
    # it lives outside the solidity-deep-audit manifest. Additive + never-false-pass
    # (see _standalone_coverage_campaign_executed guards).
    sol_engine_campaign = None
    if not sol_engine:
        sol_engine_campaign = _standalone_coverage_campaign_executed(ws)
        if sol_engine_campaign.get("ok"):
            sol_engine = True
    deep = "audit-deep-all-manifest" in accepted_manifest_kinds
    deep_skip = deep_freshness.get("verdict") == "pass-explicit-deep-skip"
    # Coupling-independent typed deep-engine skip fallback: when the freshness
    # authority could NOT establish the current-run START COUPLING (no start row
    # / unmatched run_id), it short-circuits with skip=null before it ever reads
    # the typed-skip record - the same coupling we already bypass for genuinely-
    # complete manifests above (coupling_fallback_kinds). Re-read the typed-skip
    # authority directly so an honestly-emitted .auditooor/stage_skips.json typed
    # deep-engine skip (a documented arm with no applicable coverage-guided
    # engine in this run) is credited as a typed-skip, NOT a silent miss. NOT a
    # false-pass: requires a non-empty reason + no read error.
    independent_deep_skip: dict | None = None
    if not deep_skip and deep_freshness.get("verdict") in _RUN_COUPLING_FRESHNESS_VERDICTS:
        independent_deep_skip = _independent_typed_deep_skip(ws)
        if independent_deep_skip is not None:
            deep_skip = True
    # ZK certifying-signal hook (item 5): a ZK circuit workspace is detected
    # + gated by its own engine artifact rather than the Solidity / audit-deep
    # manifests.
    zk_artifacts = _zk_engine_artifacts(ws)
    zk_engine = bool(zk_artifacts)
    arts: list[str] = []
    if legacy_solidity_engine_dir:
        arts.append(str(ws / ".auditooor" / "solidity-deep-audit"))
    if deep:
        arts.append(str(ws / ".audit_logs"))
    if zk_engine:
        arts.extend(zk_artifacts)
    if sol_engine_campaign and sol_engine_campaign.get("ok"):
        arts.extend(sol_engine_campaign.get("artifacts") or [])
    if deep_skip:
        skip = deep_freshness.get("skip")
        if not isinstance(skip, dict) and independent_deep_skip is not None:
            skip = independent_deep_skip
        skip_path = skip.get("path") if isinstance(skip, dict) else None
        if skip_path:
            arts.append(str(ws / str(skip_path)))

    detail = {
        "languages": langs,
        "solidity_engine": sol_engine,
        "solidity_engine_authored_harnesses": sol_engine_authored,
        "solidity_engine_campaign": sol_engine_campaign,
        "solidity_engine_dir": legacy_solidity_engine_dir,
        "audit_deep": deep,
        "audit_deep_skip": deep_skip,
        "audit_deep_skip_coupling_independent": independent_deep_skip is not None,
        "audit_deep_skip_record": independent_deep_skip or deep_freshness.get("skip"),
        "zk_engine": zk_engine,
        "zk_engine_artifacts": zk_artifacts,
        "audit_deep_freshness": deep_freshness,
        "fresh_manifest_kinds": sorted(fresh_manifest_kinds),
        "coupling_fallback_kinds": sorted(coupling_fallback_kinds),
        "accepted_manifest_kinds": sorted(accepted_manifest_kinds),
        "require_full_invariant_denominator": require_full_invariant_denominator,
    }

    if not langs:
        # No recognizable source languages: require SOME engine ran.
        if legacy_solidity_engine_dir or deep or deep_skip or zk_engine:
            return SignalResult(
                signal="live-engines", ok=True,
                reason="no recognized source language; engine artifact or typed deep-engine skip present",
                artifacts=arts, detail=detail,
            )
        return SignalResult(
            signal="live-engines", ok=False,
            reason="no recognized source language and no engine artifact (no Solidity engine, no audit-deep, no ZK engine)",
            artifacts=arts, detail=detail,
        )

    # For each present language, require the matching engine artifact.
    missing: list[str] = []
    for lang, n in langs.items():
        kind = _LANG_EXT[lang][1]
        if kind == "solidity":
            if not sol_engine:
                missing.append(
                    f"{lang}({n} files): no fresh current-run Solidity deep manifest "
                    "with full invariant denominator execution "
                    "(.auditooor/solidity-deep-audit/manifest.json)"
                )
        elif kind == "zk":
            # A ZK circuit language requires a ZK certifying artifact
            # (zk-circom-analyze candidates / zk-engagement-probe surface /
            # zk_preflight_packs / zk_deep_audit). A typed deep-engine skip also
            # satisfies it (the workspace honestly declared no runnable ZK engine).
            if not zk_engine and not deep_skip:
                missing.append(
                    f"{lang}({n} files): no ZK certifying artifact "
                    "(.auditooor/zk_circom_candidates.jsonl / zk_surface.json / "
                    "zk_preflight_packs/) and no typed deep-engine skip"
                )
        else:  # audit-deep (Rust / Go / Move / non-EVM)
            if not deep and not deep_skip and not _nonevm_engine_executed(ws):
                missing.append(
                    f"{lang}({n} files): no fresh current-run .audit_logs/audit_deep* manifest, "
                    "no genuine non-EVM engine execution (fuzz_runs/*/manifest.json with a "
                    "positive executed test/harness count), and no typed deep-engine skip"
                )

    if missing:
        return SignalResult(
            signal="live-engines", ok=False,
            verdict_override=_LANG_MISMATCH_VERDICT,
            reason=(
                "in-scope source language(s) lack the matching live engine: "
                + "; ".join(missing)
            ),
            artifacts=arts, detail={**detail, "missing_for_language": missing},
        )
    return SignalResult(
        signal="live-engines", ok=True,
        reason=(
            "language-correct live engine artifact or typed skip present for all detected language(s): "
            + ", ".join(f"{k}={v}" for k, v in sorted(langs.items()))
        ),
        artifacts=arts, detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (c2): engines ran WITH HARNESSES, not rc=0 zero-output
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# The Morpho false-pass: an engine step JSON with returncode=0 / status=ok but
# an EMPTY stdout_tail and no executed harness/property/spec is "engines ran"
# yet executed NOTHING. This signal requires >=1 engine step across ALL engine
# artifacts to show a POSITIVE executed-harness count. "Ran with zero harnesses"
# is a fail, not a pass.
# --------------------------------------------------------------------------
def _load_json(p: Path) -> dict | None:
    txt = _read_text(p)
    if txt is None:
        return None
    try:
        obj = json.loads(txt)
        return obj if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        return None


_TYPED_ENVELOPE_TOOL = Path(__file__).with_name("zero-day-proof-envelope-verify.py")
_TYPED_ENVELOPE_MOD: Any | None = None


def _load_typed_envelope_tool() -> Any:
    """Load the shared typed-proof identity validator once per process."""
    global _TYPED_ENVELOPE_MOD
    if _TYPED_ENVELOPE_MOD is not None:
        return _TYPED_ENVELOPE_MOD
    spec = importlib.util.spec_from_file_location(
        "auditooor_audit_completeness_typed_proof_envelope",
        _TYPED_ENVELOPE_TOOL,
    )
    if spec is None or spec.loader is None:
        raise ValueError("typed_proof_envelope_tool_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _TYPED_ENVELOPE_MOD = module
    return module


def _typed_queue_entries(
    payload: dict, *, workspace: Path | None = None, queue_path: Path | None = None,
) -> dict[str, dict] | None:
    """Rebuild exact admitted identities before closeout credits terminal text."""
    if "zero_day_proof_admission" not in payload:
        return None
    if payload.get("entries") not in (None, []):
        raise ValueError("typed_proof_envelope_legacy_entries_present")
    if workspace is not None or queue_path is not None:
        if workspace is None or queue_path is None:
            raise ValueError("typed_proof_envelope_workspace_required")
        try:
            _load_typed_envelope_tool().verify_persisted(workspace, queue_path)
        except Exception as exc:
            raise ValueError(f"typed_proof_envelope_invalid:{exc}") from exc
    try:
        envelope = _load_typed_envelope_tool().build_envelope(payload)
    except Exception as exc:
        raise ValueError(f"typed_proof_envelope_invalid:{exc}") from exc
    return {entry["lead_id"]: entry for entry in envelope["entries"]}


# Engine-step JSON: a step EXECUTED harnesses iff its status is a ran-state AND
# it shows positive evidence of an executed harness/property/spec. We look for:
#   - a non-empty stdout_tail / stdout_log with content, AND status in {ok,pass,
#     completed}, OR
#   - an explicit positive count field (tests_passed/harness_count/property_count
#     /spec_count/proptest_cases/checks/properties), OR
#   - a "<N> tests passed" / "<N> properties" phrase in notes/stdout_tail.
_RAN_STATES = {"ok", "pass", "passed", "completed", "fail", "failed", "counterexample"}
_SKIP_STATES = {"skipped", "skip", "cannot-run", "not-run", "error", "noop", "no-op"}
_COUNT_FIELDS = (
    "tests_passed", "tests_run", "harness_count", "harnesses", "property_count",
    "properties", "spec_count", "specs", "checks", "check_count",
    "proptest_cases", "cases_run", "executed_harnesses",
)
_HARNESS_PHRASE_RE = re.compile(
    r"(\d+)\s+(?:tests?|propert(?:y|ies)|harness(?:es)?|checks?|specs?)\b",
    re.IGNORECASE,
)


_NON_HARNESS_TOOL_TOKENS = (
    "aderyn",
    "semgrep",
    "regex-detector",
    "foundry-scaffold",
    "source-miner",
    "mine-solidity",
)


def _step_executed_harnesses(obj: dict, label: str = "") -> tuple[bool, str]:
    """Return (executed>0, why). Conservative: a step is only credited with
    harness execution on POSITIVE evidence."""
    status = str(obj.get("status", "")).strip().lower()
    schema = str(obj.get("schema", "")).strip().lower()
    tool = str(obj.get("tool") or obj.get("engine") or "").strip().lower()
    identity = f"{label} {tool} {schema}".lower()
    if status in _SKIP_STATES:
        return False, f"status={status} (engine did not run harnesses)"
    # Scanner/source-mining artifacts are useful audit evidence, but stdout from
    # a successful scan is not evidence that a fuzz/property harness executed.
    # Keep this ahead of generic count/stdout heuristics because scanner reports
    # may legitimately contain fields such as checks or cases.
    if any(tok in identity for tok in _NON_HARNESS_TOOL_TOKENS):
        return False, f"tool={tool or label} is analysis/scanning, not harness execution"
    # explicit positive count
    for fld in _COUNT_FIELDS:
        v = obj.get(fld)
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)) and v > 0:
            return True, f"{fld}={v}"
        if isinstance(v, str):
            try:
                if int(v.strip()) > 0:
                    return True, f"{fld}={v}"
            except ValueError:
                pass
        if isinstance(v, list) and len(v) > 0:
            return True, f"{fld} list len={len(v)}"
    # phrase in notes/stdout_tail
    for fld in ("notes", "stdout_tail", "summary", "result"):
        txt = obj.get(fld)
        if isinstance(txt, str):
            m = _HARNESS_PHRASE_RE.search(txt)
            if m and int(m.group(1)) > 0:
                return True, f"{fld}: '{m.group(0)}'"
    # status ran AND non-empty stdout content => credit (a fuzzer that printed
    # output exercised at least one target). Empty stdout + ran-state is the
    # false-pass and is NOT credited.
    if status in _RAN_STATES:
        stdout_tail = obj.get("stdout_tail")
        if isinstance(stdout_tail, str) and stdout_tail.strip():
            return True, f"status={status} with non-empty stdout"
        # a referenced stdout_log file with bytes
        log = obj.get("stdout_log")
        if isinstance(log, str) and log:
            lp = Path(log)
            try:
                if lp.is_file() and lp.stat().st_size > 0:
                    return True, f"status={status} with non-empty stdout_log"
            except OSError:
                pass
        sb = obj.get("stdout_bytes")
        if isinstance(sb, (int, float)) and sb > 0:
            return True, f"status={status} with stdout_bytes={sb}"
        return False, f"status={status} but EMPTY stdout / zero harness count (false-pass shape)"
    return False, f"status={status or 'unknown'}: no executed-harness evidence"


def _collect_engine_steps(ws: Path) -> list[tuple[str, dict]]:
    """Return (label, json) for every engine-step artifact we can find:
    solidity-deep-audit step JSONs + rust fuzz_runs manifest.json."""
    out: list[tuple[str, dict]] = []
    sda = ws / ".auditooor" / "solidity-deep-audit"
    if _exists(sda) and sda.is_dir():
        try:
            for c in sorted(sda.glob("*.json")):
                if c.name.endswith(".output.json"):
                    continue
                obj = _load_json(c)
                if obj is not None:
                    out.append((c.name, obj))
        except OSError:
            pass
    # rust proptest/bolero/kani manifests under fuzz_runs/<ts>/manifest.json
    fr = ws / "fuzz_runs"
    if _exists(fr) and fr.is_dir():
        try:
            for m in sorted(fr.glob("*/manifest.json")):
                obj = _load_json(m)
                if obj is not None:
                    out.append((str(m.relative_to(ws)), obj))
        except OSError:
            pass
    return out


_EVM_ENGINE_TOKENS = (
    "echidna",
    "halmos",
    "medusa",
    "foundry",
    "forge",
    "hevm",
    "manticore",
    "solidity",
)
_NON_EVM_ENGINE_TOKENS = (
    "rust-proptest",
    "cargo",
    "proptest",
    "bolero",
    "kani",
    "cargo-fuzz",
    "libfuzzer",
    "afl",
)


def _engine_step_requires_evm_proof(
    label: str, obj: dict, ws: Path | None = None
) -> bool:
    """Return true when a counted engine step must be checked by the EVM
    harness proof gate.

    L37's PR4 proof gate is Solidity/EVM-specific. Rust proptest, Bolero, Kani,
    and cargo-fuzz manifests can be real dynamic engine evidence but will never
    produce an EVM harness manifest. Applying the EVM gate to those Rust steps
    creates a false failure.

    Workspace-shape guard (generic, non-EVM false-pass fix): a Solidity-named
    engine/detector step (``aderyn-solidity`` / ``semgrep-solidity`` /
    ``regex-detectors-solidity``, or a no-op ``foundry-scaffold-*`` wrapper)
    can appear on a NON-Solidity workspace because the pipeline auto-scaffolds
    ``.sol`` invariant harnesses against Rust source. With NO in-scope
    Solidity/Vyper source there is no real EVM harness for the proof gate to
    prove (it honestly returns ``pass-no-engine-harness``), so holding the step
    to the EVM proof gate is a false failure. We therefore require EVM proof
    only when the workspace actually carries in-scope Solidity/Vyper source
    (``_is_evm_workspace`` - the same in-scope-source language detector the rest
    of L37 uses, which ignores pruned ``test/``/``tests/`` scaffolds). A genuine
    EVM workspace running echidna/halmos/medusa/foundry against real ``.sol``
    source still detects that source and keeps requiring proof, so this does
    NOT weaken the gate for real EVM targets.
    """
    engine = str(obj.get("engine") or obj.get("tool") or "").strip().lower()
    schema = str(obj.get("schema") or "").strip().lower()
    if schema == "auditooor.engine_harness_execution.v1":
        return True
    text = f"{label} {engine}".lower()
    if any(tok in text for tok in _NON_EVM_ENGINE_TOKENS):
        return False
    if any(tok in text for tok in _EVM_ENGINE_TOKENS):
        # Only require EVM harness proof when the workspace actually carries
        # in-scope Solidity/Vyper source. A Solidity-named engine/detector step
        # (``aderyn-solidity`` / ``semgrep-solidity`` /
        # ``regex-detectors-solidity``, or a no-op ``foundry-scaffold-*`` /
        # ``foundry-invariant-runner`` wrapper) can still appear on a
        # NON-Solidity workspace because the pipeline auto-scaffolds ``.sol``
        # invariant harnesses against Rust source. With NO in-scope
        # Solidity/Vyper source there is no real EVM harness for the proof gate
        # to prove - it honestly returns ``pass-no-engine-harness`` - so holding
        # the step to the EVM proof gate is a false failure. ``_is_evm_workspace``
        # is the same in-scope-source language detector the rest of L37 uses (it
        # ignores pruned ``test/``/``tests/`` scaffolds and only counts target
        # source). A genuine EVM workspace running echidna/halmos/medusa/foundry
        # against real ``.sol`` source still detects that source and keeps
        # requiring the proof - the gate is NOT weakened for real EVM targets.
        if ws is not None and not _is_evm_workspace(ws):
            return False
        return True
    return False


# --------------------------------------------------------------------------
# Signal (c2) delegation: PR4 engine-harness PROOF gate
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# A POSITIVE executed-harness count proves the engine RAN something, but not
# that what it ran is a REAL target-call harness rather than a tautological
# stub (``assert(true)`` / ``check_noop()`` / a fuzz target that touches no
# in-scope function). PR4's proof gate (``tools/engine-harness-proof-check.py``)
# inspects each EVM engine harness against the EVM proof manifest at
# ``<ws>/.auditooor/evm_engine_proof/engine_harness_proof.json`` and classifies
# each counted harness as proof-bearing or a fake/tautological stub.
#
# L37 wiring contract (this lane, PR4b): the engine-harness signal CALLS the
# proof gate. The signal passes iff (harness count > 0) AND every counted
# harness passes the proof gate. A counted-but-unproven harness fails closed
# as the same Morpho false-pass verdict (``fail-engine-false-pass``) - "ran
# with output" is not the same as "ran a real harness".
#
# Resilience / staged rollout: PR4a owns the proof-gate tool and lands in
# parallel. Until the proof-gate module is on disk AND a proof manifest exists
# for the workspace, this signal degrades to the legacy positive-count
# behavior (so pre-PR4a workspaces and the existing all-pass fixture stay
# green). In strict mode (``AUDITOOOR_L37_ENGINE_PROOF_STRICT=1`` /
# ``--strict``) an ABSENT proof gate or ABSENT manifest fails closed - a
# production audit MUST produce the proof manifest before L37 credits the
# engines (PR4 DoD).
# --------------------------------------------------------------------------
_ENGINE_PROOF_MANIFEST_REL = (
    ".auditooor", "evm_engine_proof", "engine_harness_proof.json",
)


def _engine_proof_strict() -> bool:
    return os.environ.get("AUDITOOOR_L37_ENGINE_PROOF_STRICT", "").strip() not in (
        "", "0", "false", "no",
    )


def _enforce_autonomous_proof_conversion() -> bool:
    return os.environ.get("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", "").strip() == "1"


PROVE_TOP_LEADS_REQUIRED_GROUPS = {
    "source_mine": ".auditooor/prove_top_leads_source_mine.json",
    "source_mined_impact_contracts": (
        ".auditooor/prove_top_leads_source_mined_impact_contracts.json"
    ),
    "prefiling_stress": ".auditooor/prove_top_leads_prefiling_stress_test.json",
    "candidate_judgment": ".auditooor/prove_top_leads_candidate_judgment_packet.json",
    "outcome_lesson_gate": ".auditooor/prove_top_leads_outcome_lesson_gate.json",
}

PROVE_TOP_LEADS_NO_LEADS_SCHEMA = "auditooor.prove_top_leads_no_leads.v1"
PROVE_TOP_LEADS_NO_LEADS_PATTERNS = (
    ".auditooor/prove_top_leads_no_leads.json",
)
PROVE_TOP_LEADS_QUEUE_RELS = (
    ".auditooor/exploit_queue.json",
    ".auditooor/exploit_queue.source_mined.json",
    ".auditooor/exploit_queue.zero_day_admitted.json",
)
PROVE_TOP_LEADS_TYPED_ADMITTED_REL = ".auditooor/exploit_queue.zero_day_admitted.json"


def _glob_all_relative(ws: Path, patterns: tuple[str, ...]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for pattern in patterns:
        for path in sorted(ws.glob(pattern)):
            if not path.is_file():
                continue
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            out.append(path)
    return out


def _queue_row_count_from_payload(obj: Any) -> int:
    if isinstance(obj, list):
        return len(obj)
    if not isinstance(obj, dict):
        return 0
    for key in ("queue", "items", "candidates", "rows", "leads"):
        value = obj.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def _current_prove_top_leads_queue_counts(ws: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rel in PROVE_TOP_LEADS_QUEUE_RELS:
        path = ws / rel
        counts[rel] = (
            _queue_row_count_from_payload(_load_json(path))
            if path.is_file()
            else 0
        )
    return counts


def _typed_prove_top_leads_all_terminal(ws: Path) -> tuple[bool, bool]:
    """Return (present, all_exact_terminal) for the admitted proof queue.

    No-leads is a terminal consumer. It cannot replace an admitted obligation's
    parent identity with a prefiling summary or a bare status token.
    """
    path = ws / PROVE_TOP_LEADS_TYPED_ADMITTED_REL
    if not path.is_file():
        return False, True
    payload = _load_json(path)
    if not isinstance(payload, dict):
        return True, False
    try:
        _load_typed_envelope_tool().verify_persisted(ws, path)
        entries = _typed_queue_entries(payload)
    except ValueError:
        return True, False
    except Exception:
        return True, False
    if entries is None:
        return True, False
    rows = payload.get("queue")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return True, False
    if len(entries) != len(rows):
        return True, False
    for row in rows:
        lead_id = row.get("lead_id")
        entry = entries.get(str(lead_id)) if isinstance(lead_id, str) else None
        if entry is None or not _lead_is_terminal_work_backed(row, entry):
            return True, False
    return True, True


def _valid_prove_top_leads_no_leads_manifest(ws: Path, path: Path) -> bool:
    obj = _load_json(path)
    if not isinstance(obj, dict):
        return False
    if obj.get("schema") != PROVE_TOP_LEADS_NO_LEADS_SCHEMA:
        return False
    status = str(
        obj.get("status")
        or obj.get("verdict")
        or obj.get("result")
        or ""
    ).strip().lower().replace("_", "-")
    has_no_leads_verdict = bool(
        obj.get("no_leads") is True
        or obj.get("no_provable_leads") is True
        or status in {
            "no-leads",
            "no-provable-leads",
            "no-proof-targets",
            "no-candidates",
            "empty-queue",
        }
    )
    if not has_no_leads_verdict:
        return False
    lead_count = obj.get("lead_count")
    if lead_count is None:
        lead_count = obj.get("candidate_count")
    if lead_count is None:
        lead_count = obj.get("queue_row_count")
    if lead_count != 0:
        return False
    declared_counts = obj.get("current_queue_rows")
    if declared_counts is None:
        declared_counts = obj.get("queue_row_counts")
    if not isinstance(declared_counts, dict):
        return False
    current_counts = _current_prove_top_leads_queue_counts(ws)
    # Freshness: the manifest's declared counts must match the LIVE queue (a stale
    # manifest written against an old queue is rejected).
    for rel, current in current_counts.items():
        # Legacy manifests predate the admitted typed queue. They remain valid only
        # when that queue is still absent; once the typed artifact exists it is a
        # canonical proof input and its exact live count is mandatory.
        if (
            rel == PROVE_TOP_LEADS_TYPED_ADMITTED_REL
            and rel not in declared_counts
            and not (ws / rel).is_file()
        ):
            continue
        if declared_counts.get(rel) != current:
            return False
    typed_present, typed_all_terminal = _typed_prove_top_leads_all_terminal(ws)
    if typed_present and not typed_all_terminal:
        return False
    # Accept EITHER (a) an empty queue (nothing to prove), OR (b) a non-empty
    # PROCESSED queue where every eligible TOP lead is already terminal - a genuine
    # honest-0 (large corpus-driven-hunt queue, all top leads adjudicated, nothing
    # submit-ready). Case (b) is gated on an UN-FAKEABLE corroboration: the
    # producer-computed prefiling-stress artifact must independently report
    # top_n==0 (0 non-terminal top rows) with terminal rows skipped. The manifest
    # cannot self-assert this - the prefiling producer recomputes top_n from the
    # live queue each audit-deep run, so a hand-forged "all terminal" claim is
    # contradicted the moment a non-terminal lead exists.
    if all(c == 0 for c in current_counts.values()):
        return True
    if obj.get("all_top_leads_terminal") is True and _prefiling_confirms_all_terminal(ws):
        return True
    return False


def _prefiling_confirms_all_terminal(ws: Path) -> bool:
    """UN-FAKEABLE corroboration for a non-empty-queue no-leads manifest: the
    prefiling-stress producer found 0 NON-TERMINAL top leads to assess (top_n==0,
    rows_assessed==0) while >=1 queue row was skipped as already-terminal. That is
    the producer's own evidence that every eligible top lead is adjudicated - a
    processed queue with nothing left to prove, not an empty/unrun one."""
    prefiling_path = ws / ".auditooor" / "prove_top_leads_prefiling_stress_test.json"
    obj = _load_json(prefiling_path)
    if not isinstance(obj, dict):
        return False
    try:
        top_n = int(obj.get("top_n") or 0)
        rows_assessed = int(obj.get("rows_assessed") or 0)
        terminal_skipped = int(obj.get("terminal_rows_skipped") or 0)
    except (TypeError, ValueError):
        return False
    # FRESHNESS: a prefiling-stress artifact written BEFORE the exploit_queue it
    # claims to assess is stale corroboration - the queue may have been
    # regenerated (e.g. corpus_driven_hunt appending thousands of obligations)
    # AFTER the prefiling producer ran, so its "0 non-terminal top leads" verdict
    # says nothing about the live queue (observed: axelar 2026-07-12, prefiling
    # dated 02:24 vs exploit_queue regenerated 13:38, +7116 obligations). Require
    # the prefiling-stress artifact's mtime to be >= every live queue file's
    # mtime; a stale artifact can never corroborate.
    try:
        prefiling_mtime = prefiling_path.stat().st_mtime
    except OSError:
        return False
    for rel in PROVE_TOP_LEADS_QUEUE_RELS:
        queue_path = ws / rel
        if not queue_path.is_file():
            continue
        try:
            queue_mtime = queue_path.stat().st_mtime
        except OSError:
            return False
        if prefiling_mtime < queue_mtime:
            # mtime-stale. The anti-staleness intent is to reject a queue that was
            # REGENERATED WITH NEW OBLIGATIONS after prefiling ran (axelar 2026-07-12:
            # +7116 leads). But audit-completeness-check itself REWRITES the queue
            # in place (synthetic-lead-drop / provenance-filter passes) on the SAME
            # rows without adding any, which bumps mtime past a still-valid prefiling
            # and false-reds an honest all-terminal queue (NUVA 2026-07-14 churn).
            # CONTENT fallback: accept iff the queue's current assessable row count is
            # NOT GREATER than what prefiling evaluated (rows_assessed + terminal_
            # skipped). A grown queue (new leads) still fails; an in-place re-touch or
            # a shrink (rows dropped) passes - neither introduces an un-assessed lead.
            assessed_total = rows_assessed + terminal_skipped
            current = _queue_row_count_from_payload(_load_json(queue_path))
            if current > assessed_total:
                return False
    # `top_n` is the ASSESSMENT WINDOW size the producer was run with, NOT the
    # count of non-terminal leads. The old `top_n == 0` check was BACKWARDS: it
    # only accepted an EMPTY window (--top-n 0), which trivially yields
    # rows_assessed==0 even when non-terminal leads exist (2026-07-07 loophole),
    # while REJECTING the genuinely-strong evidence of a REAL window (--top-n 10)
    # that assessed the top leads and found 0 non-terminal (rows_assessed==0).
    # Correct: demand a NON-EMPTY window (top_n > 0) that assessed 0 non-terminal
    # leads while >=1 queue row was skipped as already-terminal.
    return top_n > 0 and rows_assessed == 0 and terminal_skipped > 0


def _prove_top_leads_group_payload_valid(group: str, path: Path) -> bool:
    obj = _load_json(path)
    if not isinstance(obj, dict):
        return False
    if group == "source_mine":
        if obj.get("schema") != "auditooor.exploit_queue_source_miner.v1":
            return False
        return any(
            isinstance(obj.get(key), int)
            for key in ("selected_rows", "source_found", "blocked")
        ) or isinstance(obj.get("artifacts"), list)
    if group == "source_mined_impact_contracts":
        contracts = obj.get("contracts")
        if not isinstance(contracts, list):
            return False
        return any(isinstance(row, dict) for row in contracts)
    if group == "prefiling_stress":
        results = obj.get("results")
        if not isinstance(results, list):
            return False
        return any(isinstance(row, dict) for row in results)
    if group == "candidate_judgment":
        if obj.get("advisory_only") is True or obj.get("candidate_not_submit_ready") is True:
            return False
        packets = obj.get("packets")
        return isinstance(packets, list) and any(isinstance(row, dict) for row in packets)
    if group == "outcome_lesson_gate":
        if obj.get("schema") != "auditooor.outcome_lesson_gate.v1":
            return False
        status = str(obj.get("status") or obj.get("verdict") or "").strip().lower()
        return status in {"pass", "ok", "completed", "complete", "no-blockers"}
    return False


def _prove_top_leads_artifact_set(ws: Path) -> dict[str, Any]:
    groups = {}
    invalid_groups: list[str] = []
    for group, rel in PROVE_TOP_LEADS_REQUIRED_GROUPS.items():
        path = ws / rel
        if path.is_file() and path.stat().st_size > 0 and _prove_top_leads_group_payload_valid(group, path):
            groups[group] = [str(path)]
        else:
            groups[group] = []
            if path.is_file() and path.stat().st_size > 0:
                invalid_groups.append(group)
    missing = [group for group, paths in groups.items() if not paths]
    no_leads_candidates = _glob_all_relative(ws, PROVE_TOP_LEADS_NO_LEADS_PATTERNS)
    valid_no_leads = [
        str(path)
        for path in no_leads_candidates
        if _valid_prove_top_leads_no_leads_manifest(ws, path)
    ]
    complete = not missing
    no_leads_complete = bool(valid_no_leads)
    artifacts: list[str] = []
    if complete:
        for paths in groups.values():
            artifacts.extend(paths)
    elif no_leads_complete:
        artifacts.extend(valid_no_leads)
    return {
        "artifact_groups": groups,
        "missing_required_groups": missing,
        "invalid_required_groups": invalid_groups,
        "artifact_set_complete": complete,
        "no_leads_manifest": valid_no_leads[0] if valid_no_leads else None,
        "no_leads_manifest_complete": no_leads_complete,
        "current_queue_rows": _current_prove_top_leads_queue_counts(ws),
        "weak_prove_top_leads_candidates": [
            str(path)
            for path in _glob_all_relative(
                ws,
                (".auditooor/prove_top_leads_*", "reports/prove_top_leads_*"),
            )
        ],
        "artifacts": artifacts,
    }


def _load_engine_proof_gate_module():
    """Load PR4a's tools/engine-harness-proof-check.py if it is on disk."""
    tool_path = Path(__file__).resolve().with_name("engine-harness-proof-check.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_engine_harness_proof_acc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_engine_harness_proof_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _call_engine_proof_gate(ws: Path) -> dict | None:
    """Invoke PR4a's proof gate for the workspace.

    Returns the gate's verdict payload, or ``None`` when the gate tool is not
    on disk (PR4a not yet landed). The expected payload shape (PR4a contract):
        {"verdict": "pass-engine-harness-proof" | "fail-...",
         "proven": [<harness labels>], "unproven": [<harness labels>], ...}
    We probe ``evaluate(ws)`` first (the repo's sibling-gate convention), then
    fall back to a thin subprocess call if only a CLI is exposed.
    """
    mod = _load_engine_proof_gate_module()
    if mod is None:
        return None
    # Preferred: an evaluate(ws) callable, mirroring hunt-completeness-check.
    if hasattr(mod, "evaluate"):
        try:
            res = mod.evaluate(ws)
            if isinstance(res, dict):
                return res
        except Exception as exc:  # pragma: no cover (defensive)
            return {"verdict": "error", "reason": f"proof gate raised: {exc}"}
    return None


def check_engine_harness(ws: Path) -> SignalResult:
    steps = _collect_engine_steps(ws)
    strict = _engine_proof_strict()
    manifest = ws.joinpath(*_ENGINE_PROOF_MANIFEST_REL)
    has_manifest = _exists(manifest) and manifest.is_file()

    if not steps:
        # No engine STEP artifacts at all. live-engines (signal c) already
        # governs "did any engine ran"; here we only fail when steps exist but
        # NONE executed a harness. With zero step artifacts, defer to (c).
        return SignalResult(
            signal="engine-harness", ok=True,
            reason="no engine-step artifacts to score (live-engines signal governs engine presence)",
            artifacts=[], detail={"engine_steps": 0},
        )

    # Positive executed-harness count (the "ran something" precondition).
    executed = []
    not_executed = []
    for label, obj in steps:
        ok, why = _step_executed_harnesses(obj, label)
        entry = {
            "step": label,
            "why": why,
            "requires_evm_proof": _engine_step_requires_evm_proof(label, obj, ws),
        }
        (executed if ok else not_executed).append(entry)

    if not executed:
        # A documented deep-engine skip can honestly close a scanner-only arm
        # when the proof gate independently confirms that no engine harness
        # exists. Historically scanner stdout accidentally supplied the
        # positive execution count needed to reach the later typed-skip branch.
        # Preserve the intended disposition directly, without pretending the
        # scanner executed a harness.
        skip_record = _independent_typed_deep_skip(ws)
        proof = _call_engine_proof_gate(ws) if skip_record is not None else None
        if (
            proof is not None
            and str(proof.get("verdict", "")).strip() == "pass-no-engine-harness"
            and not (proof.get("proven") or proof.get("proven_harnesses"))
            and not (proof.get("unproven") or proof.get("unproven_harnesses"))
            and skip_record is not None
        ):
            return SignalResult(
                signal="engine-harness",
                ok=True,
                reason=(
                    "engine-harness TYPED-SKIP: analysis/scanner steps ran but no "
                    "harness execution was credited; the proof gate independently "
                    "confirmed no engine harness exists and a documented deep-engine "
                    f"skip is on disk. skip reason: {skip_record.get('reason')}"
                ),
                artifacts=[str(ws / str(skip_record.get("path")))] if skip_record.get("path") else [],
                detail={
                    "executed": [],
                    "not_executed": not_executed,
                    "proof_gate": "ran",
                    "proof_verdict": "pass-no-engine-harness",
                    "disposition": "engine-harness-typed-skip",
                    "typed_deep_engine_skip": skip_record,
                    "strict": strict,
                },
            )
        # Zero executed harnesses across all steps: the original Morpho
        # false-pass. (count > 0) precondition fails before the proof gate.
        return SignalResult(
            signal="engine-harness", ok=False,
            reason=(
                f"{len(steps)} engine step(s) present but ZERO executed harnesses - "
                "rc=0 / status=ok with empty stdout and no harness/property/spec count "
                "(the Morpho false-pass): "
                + "; ".join(f"{s['step']}: {s['why']}" for s in not_executed[:4])
            ),
            artifacts=[], detail={"executed": [], "not_executed": not_executed},
        )

    evm_executed = [e for e in executed if e.get("requires_evm_proof")]
    non_evm_executed = [e for e in executed if not e.get("requires_evm_proof")]
    if not evm_executed:
        return SignalResult(
            signal="engine-harness",
            ok=True,
            reason=(
                f"{len(executed)} non-EVM engine step(s) executed harnesses with "
                f"positive count (e.g. {executed[0]['step']}: {executed[0]['why']}); "
                "EVM harness proof gate is not applicable"
            ),
            artifacts=[e["step"] for e in executed],
            detail={
                "executed": executed,
                "not_executed": not_executed,
                "evm_executed": evm_executed,
                "non_evm_executed": non_evm_executed,
                "proof_gate": "not-applicable-non-evm",
                "strict": strict,
            },
        )

    # count > 0. Now require every counted EVM harness to pass PR4's proof gate.
    proof = _call_engine_proof_gate(ws)
    proof_available = proof is not None

    # TYPED DEEP-ENGINE SKIP (evaluated BEFORE the strict manifest-missing /
    # proof-unavailable branches): when the proof gate AUTHORITATIVELY confirms
    # there is NO real engine harness to prove (verdict ``pass-no-engine-harness``
    # with empty proven AND unproven lists - the rc=2-blocked-on-mixed-layout
    # shape where halmos / medusa / echidna produced no harness and the only
    # "EVM" steps are solidity-named scanners) AND a documented typed deep-engine
    # skip is on disk, the engine arm is honestly recorded as a TYPED-SKIP
    # instead of a hollow false-pass. This runs ahead of the strict
    # ``has_manifest`` / ``proof_available`` early-returns because, when the proof
    # gate has already PROVEN no harness exists, there is nothing for a proof
    # manifest to certify - so a missing manifest is not a hidden-unproven-output
    # risk here. It does NOT fake an executed-harness count, does NOT credit a
    # detected fake/tautological stub (``unproven`` non-empty keeps failing
    # below), and requires a non-empty skip reason on disk.
    if proof_available:
        _ts_pverdict = str(proof.get("verdict", "")).strip()
        _ts_proven = proof.get("proven") or proof.get("proven_harnesses") or []
        _ts_unproven = proof.get("unproven") or proof.get("unproven_harnesses") or []
        if _ts_pverdict == "pass-no-engine-harness" and not _ts_proven and not _ts_unproven:
            _ts_skip = _independent_typed_deep_skip(ws)
            if _ts_skip is not None:
                return SignalResult(
                    signal="engine-harness", ok=True,
                    reason=(
                        "engine-harness TYPED-SKIP: the EVM coverage-guided engine arm "
                        "(halmos / medusa / echidna) produced no engine harness "
                        f"(proof gate verdict={_ts_pverdict}; "
                        f"{proof.get('reason', 'no engine harness files discovered')}) and a "
                        "documented typed deep-engine skip is on disk - recorded as a "
                        "typed-skip, NOT a hollow false-pass and NOT a faked harness "
                        f"count. skip reason: {_ts_skip.get('reason')}"
                    ),
                    artifacts=[str(ws / str(_ts_skip.get("path")))] if _ts_skip.get("path") else [],
                    detail={"executed": executed, "not_executed": not_executed,
                            "evm_executed": evm_executed,
                            "non_evm_executed": non_evm_executed,
                            "proof_gate": "ran", "proof_verdict": _ts_pverdict,
                            "proven": _ts_proven, "unproven": _ts_unproven,
                            "has_manifest": has_manifest,
                            "proof_reason": proof.get("reason"),
                            "disposition": "engine-harness-typed-skip",
                            "strict": strict,
                            "typed_deep_engine_skip": _ts_skip},
                )

    if strict and not has_manifest:
        return SignalResult(
            signal="engine-harness", ok=False,
            reason=(
                f"{len(evm_executed)} executed EVM harness(es) but the engine-harness "
                "proof manifest is missing; strict mode cannot credit "
                "unproven engine output"
            ),
            artifacts=[],
            detail={"executed": executed, "not_executed": not_executed,
                    "evm_executed": evm_executed,
                    "non_evm_executed": non_evm_executed,
                    "proof_gate": "manifest-missing", "strict": True,
                    "has_manifest": False},
        )

    if not proof_available:
        # PR4a proof gate not on disk yet. In strict mode this is a hard fail
        # (a production audit MUST run the proof gate). In default mode degrade
        # to the legacy positive-count pass so pre-PR4a workspaces stay green.
        if strict:
            return SignalResult(
                signal="engine-harness", ok=False,
                reason=(
                    f"{len(evm_executed)} executed EVM harness(es) but the engine-harness "
                    "PROOF gate (tools/engine-harness-proof-check.py) is unavailable "
                    "and strict mode requires it - cannot credit unproven harnesses"
                ),
                artifacts=[],
                detail={"executed": executed, "not_executed": not_executed,
                        "evm_executed": evm_executed,
                        "non_evm_executed": non_evm_executed,
                        "proof_gate": "unavailable", "strict": True},
            )
        return SignalResult(
            signal="engine-harness", ok=True,
            reason=(
                f"{len(evm_executed)} EVM engine step(s) executed harnesses with "
                f"positive count (e.g. {evm_executed[0]['step']}: {evm_executed[0]['why']}); "
                "proof gate not yet on disk - legacy positive-count credit (non-strict)"
            ),
            artifacts=[e["step"] for e in executed],
            detail={"executed": executed, "not_executed": not_executed,
                    "evm_executed": evm_executed,
                    "non_evm_executed": non_evm_executed,
                    "proof_gate": "unavailable", "strict": False},
        )

    # Proof gate ran. It is authoritative: every counted harness must be
    # proof-bearing. The gate's own verdict carries the pass/fail.
    pverdict = str(proof.get("verdict", "")).strip()
    proven = proof.get("proven") or proof.get("proven_harnesses") or []
    unproven = proof.get("unproven") or proof.get("unproven_harnesses") or []
    drifted_unproven = proof.get("drifted_unproven") or []
    gate_pass = (
        pverdict == "pass-engine-harness-proof"
        and bool(proven)
        and not unproven
    )
    advisory_only = bool(proof.get("advisory_only"))

    if gate_pass:
        return SignalResult(
            signal="engine-harness", ok=True,
            reason=(
                f"{len(evm_executed)} executed EVM harness(es), all PROVEN by the engine-harness "
                f"proof gate (verdict={pverdict or 'pass'}, proven={len(proven)})"
            ),
            artifacts=[e["step"] for e in executed],
            detail={"executed": executed, "not_executed": not_executed,
                    "evm_executed": evm_executed,
                    "non_evm_executed": non_evm_executed,
                    "proof_gate": "ran", "proof_verdict": pverdict,
                    "proven": proven, "unproven": unproven,
                    "has_manifest": has_manifest},
        )

    if advisory_only and not _enforce_autonomous_proof_conversion():
        return SignalResult(
            signal="engine-harness",
            ok=True,
            reason=(
                f"{len(evm_executed)} executed EVM harness step(s); proof gate found "
                "only advisory generated harnesses, so no proof credit is claimed. "
                "Autonomous proof conversion is advisory by default; set "
                "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 to require proof-backed "
                "harnesses."
            ),
            artifacts=[e["step"] for e in executed],
            detail={
                "executed": executed,
                "not_executed": not_executed,
                "evm_executed": evm_executed,
                "non_evm_executed": non_evm_executed,
                "proof_gate": "ran",
                "proof_verdict": pverdict,
                "proven": proven,
                "unproven": unproven,
                "has_manifest": has_manifest,
                "proof_reason": proof.get("reason"),
                "advisory_only": True,
                "advisory_autonomous_proof_conversion": True,
                "enforce_autonomous_proof_conversion": False,
            },
        )

    # TYPED DEEP-ENGINE SKIP (not a false-pass): the proof gate found NO real
    # engine harness files at all (``pass-no-engine-harness`` with an empty
    # ``unproven`` list) - i.e. the EVM coverage-guided fuzz arm (halmos / medusa
    # / echidna) produced no harness, the rc=2-blocked-on-a-mixed-layout shape -
    # NOT a tautological stub the gate detected (which keeps ``unproven``
    # non-empty and STILL fails below). When a DOCUMENTED, JUSTIFIED typed
    # deep-engine skip is on disk (.auditooor/stage_skips.json), the engine arm
    # is honestly recorded as a TYPED-SKIP rather than the Morpho hollow
    # false-pass. This does NOT fake an executed-harness count: no harness is
    # credited, the disposition is explicitly ``engine-harness-typed-skip``, and
    # a detected fake/tautological stub (unproven present) is excluded so it
    # cannot launder a stub into a pass.
    skip_record = _independent_typed_deep_skip(ws)
    no_harness_blocked = (
        pverdict == "pass-no-engine-harness" and not unproven and not proven
    )
    if skip_record is not None and no_harness_blocked:
        return SignalResult(
            signal="engine-harness", ok=True,
            reason=(
                "engine-harness TYPED-SKIP: the EVM coverage-guided engine arm "
                "(halmos / medusa / echidna) produced no engine harness "
                f"(proof gate verdict={pverdict}; "
                f"{proof.get('reason', 'no engine harness files discovered')}) and a "
                "documented typed deep-engine skip is on disk - recorded as a "
                "typed-skip, NOT a hollow false-pass and NOT a faked harness "
                f"count. skip reason: {skip_record.get('reason')}"
            ),
            artifacts=[str(ws / str(skip_record.get("path")))] if skip_record.get("path") else [],
            detail={"executed": executed, "not_executed": not_executed,
                    "evm_executed": evm_executed,
                    "non_evm_executed": non_evm_executed,
                    "proof_gate": "ran", "proof_verdict": pverdict,
                    "proven": proven, "unproven": unproven,
                    "has_manifest": has_manifest, "proof_reason": proof.get("reason"),
                    "disposition": "engine-harness-typed-skip",
                    "typed_deep_engine_skip": skip_record},
        )

    return SignalResult(
        signal="engine-harness", ok=False,
        reason=(
            f"{len(evm_executed)} executed EVM harness(es) but the engine-harness proof gate "
            f"FAILED (verdict={pverdict or 'fail'}): "
            + (
                # Drifted-but-real: a sibling/closeout edit staled an otherwise
                # non-vacuous mutation sidecar. The fix is a RE-VERIFY (re-run
                # mutation-verify-coverage to refresh the sidecar hash), NOT
                # authoring a real harness - mislabeling these "fake stubs" sends
                # the operator down the wrong debug path.
                f"{len(drifted_unproven)} counted harness(es) have a STALE/DRIFTED "
                f"mutation sidecar (real proof, hash no longer matches the on-disk "
                f"harness - re-verify via mutation-verify-coverage): "
                f"({', '.join(str(u) for u in drifted_unproven[:4])})"
                + (
                    f"; {len(unproven) - len(drifted_unproven)} other unproven"
                    if len(unproven) > len(drifted_unproven) else ""
                )
                if drifted_unproven
                else (
                    f"{len(unproven)} counted harness(es) are fake/tautological stubs "
                    f"({', '.join(str(u) for u in unproven[:4])})"
                    if unproven else proof.get("reason", "no proof-bearing harness")
                )
            )
            + " - L37 will not count tautological engine output"
        ),
        artifacts=[],
        detail={"executed": executed, "not_executed": not_executed,
                "evm_executed": evm_executed,
                "non_evm_executed": non_evm_executed,
                "proof_gate": "ran", "proof_verdict": pverdict,
                "proven": proven, "unproven": unproven,
                "has_manifest": has_manifest, "proof_reason": proof.get("reason")},
    )


# --------------------------------------------------------------------------
# Signal (d): audit-preflight per-function packs ran
# --------------------------------------------------------------------------
def check_audit_preflight(ws: Path) -> SignalResult:
    a = ws / ".auditooor"
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("AUDIT_PREFLIGHT")
    detail: dict = {"strict": strict}

    def _posint(v: Any) -> bool:
        return isinstance(v, int) and not isinstance(v, bool) and v > 0

    def _dir_has_real_packs(d: Path) -> bool:
        # >=1 non-dotfile file with substantive json/jsonl content.
        if not _exists(d) or not d.is_dir():
            return False
        try:
            for c in d.rglob("*"):
                if not c.is_file() or c.name.startswith("."):
                    continue
                if c.name.lower() == "manifest.json":
                    mp = _load_json(c)
                    if isinstance(mp, dict) and any(
                        _posint(mp.get(k)) for k in
                        ("count", "total", "functions", "entries", "n", "pack_count",
                         # the per-function-invariant manifest emits `function_count`
                         # (+ a `functions` list), NOT a bare `count` - NUVA 2026-06-30.
                         "function_count", "unit_count", "invariant_count")
                    ):
                        return True
                    # a non-empty `functions` / `packs` / `units` LIST is real content
                    # (the manifest enumerates the per-function packs as a list).
                    if isinstance(mp, dict) and any(
                        isinstance(mp.get(k), list) and mp[k]
                        for k in ("packs", "functions", "units", "entries")
                    ):
                        return True
                    continue
                if c.suffix.lower() in (".json", ".jsonl"):
                    try:
                        if c.stat().st_size > 2:
                            if c.suffix.lower() == ".jsonl":
                                txt = _read_text(c) or ""
                                if any(ln.strip() for ln in txt.splitlines()):
                                    return True
                            else:
                                p = _load_json(c)
                                if isinstance(p, list) and len(p) > 0:
                                    return True
                                if isinstance(p, dict) and len(p) > 0:
                                    return True
                    except OSError:
                        continue
        except OSError:
            return False
        return False

    def _preflight_json_ran(p: Path) -> bool:
        obj = _load_json(p)
        if not isinstance(obj, dict):
            return False
        # a real preflight emits a STRING decision / status / scope / processed counts.
        if any(isinstance(obj.get(k), str) and obj.get(k).strip()
               for k in ("decision", "status", "auditooor_status", "verdict")):
            return True
        if any(_posint(obj.get(k)) for k in
               ("functions", "function_count", "packs", "entries", "count", "total")):
            return True
        if isinstance(obj.get("packs"), list) and obj["packs"]:
            return True
        if isinstance(obj.get("worklist"), list) and obj["worklist"]:
            return True
        return False

    genuine: list[str] = []
    pfi = a / "per_function_invariants"
    if _dir_has_real_packs(pfi):
        genuine.append(str(pfi))
    pcadp = a / "per_contract_audit_deep_plan.json"
    if _is_file(pcadp):
        obj = _load_json(pcadp)
        if isinstance(obj, (list, dict)) and len(obj) > 0:
            genuine.append(str(pcadp))
    present: list[Path] = []
    try:
        if _exists(a) and a.is_dir():
            for c in a.iterdir():
                nm = c.name.lower()
                # r36-rebuttal: funnel-generic-fixes-wave3
                # "pre_flight" (underscore) is the canonical dir name emitted
                # by the per-function preflight orchestrator (pre_flight_packs/).
                # "preflight" (no underscore) covers legacy/custom variants.
                if "preflight" in nm or "pre_flight" in nm or nm.startswith("per_function"):
                    present.append(c)
    except OSError:
        pass
    for c in present:
        s = str(c)
        if s in genuine:
            continue
        if c.is_dir():
            if _dir_has_real_packs(c):
                genuine.append(s)
        elif c.suffix.lower() == ".json":
            if _preflight_json_ran(c):
                genuine.append(s)
        elif c.suffix.lower() == ".jsonl":
            txt = _read_text(c) or ""
            if any(ln.strip() for ln in txt.splitlines()):
                genuine.append(s)
    present_candidates = [str(c) for c in present] + \
        ([str(pfi)] if _exists(pfi) else []) + ([str(pcadp)] if _is_file(pcadp) else [])
    detail["genuine_artifacts"] = genuine
    detail["present_candidates"] = present_candidates
    if genuine:
        return SignalResult(
            signal="audit-preflight", ok=True,
            reason=(
                "audit-preflight per-function pack(s) present WITH genuine "
                f"processed content ({len(genuine)} artifact(s))"
            ),
            artifacts=genuine, detail=detail,
        )
    if not present_candidates:
        return SignalResult(
            signal="audit-preflight", ok=False,
            reason=(
                "no audit-preflight per-function pack "
                "(.auditooor/per_function_invariants/ or per-function preflight output)"
            ),
            artifacts=[], detail=detail,
        )
    hollow = (
        "audit-preflight artifact(s) PRESENT but HOLLOW: no manifest/json/dir "
        "carries processed content (no decision/status/verdict, no function "
        "packs, empty containers) - file-presence-only, the preflight did not run"
    )
    if strict:
        return SignalResult(
            signal="audit-preflight", ok=False, reason=hollow,
            artifacts=present_candidates, detail=detail,
        )
    return SignalResult(
        signal="audit-preflight", ok=True, reason="WARN: " + hollow,
        artifacts=present_candidates, detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (e): exploit-queue built
# --------------------------------------------------------------------------
def check_exploit_queue(ws: Path) -> SignalResult:
    a = ws / ".auditooor"
    eq = a / "exploit_queue.json"
    eq_mined = a / "exploit_queue.source_mined.json"
    survivors = a / "exploit_queue.survivors.json"
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("EXPLOIT_QUEUE")
    detail: dict = {"strict": strict}

    def _posint(v: Any) -> bool:
        return isinstance(v, int) and not isinstance(v, bool) and v > 0

    present = [p for p in (eq, eq_mined) if _is_file(p)]
    detail["present"] = [str(p) for p in present]
    if not present:
        return SignalResult(
            signal="exploit-queue", ok=False,
            reason="no .auditooor/exploit_queue.json; the exploit-queue was not built",
            artifacts=[], detail=detail,
        )

    def _queue_ran(p: Path) -> tuple[bool, str]:
        obj = _load_json(p)
        if not isinstance(obj, dict):
            return (False, "unparseable")
        q = obj.get("queue")
        ent = obj.get("entries")
        if (isinstance(q, list) and len(q) > 0) or (isinstance(ent, list) and len(ent) > 0):
            return (True, f"queue={len(q) if isinstance(q, list) else 0}/"
                          f"entries={len(ent) if isinstance(ent, list) else 0}")
        if any(_posint(obj.get(k)) for k in
               ("total_candidates", "candidate_rows", "survived_rows", "top_n")):
            return (True, "candidate counts > 0")
        bi = obj.get("broken_invariant_ids")
        if isinstance(bi, list) and len(bi) > 0:
            return (True, f"broken_invariant_ids={len(bi)}")
        bench = obj.get("benchmark")
        if isinstance(bench, dict) and any(_posint(bench.get(k)) for k in
                ("rows_killed", "rows_inconclusive", "rows_chain_derived",
                 "rows_proved", "rows_accepted")):
            return (True, "benchmark rows processed")
        sms = obj.get("source_mining_summary")
        if isinstance(sms, dict) and _posint(sms.get("candidate_rows")):
            return (True, "source_mining_summary processed rows")
        return (False, "hollow")

    ran_any = False
    why: str | None = None
    for p in present:
        ok, msg = _queue_ran(p)
        if ok:
            ran_any = True
            why = f"{p.name}: {msg}"
            break
    honest_empty = False
    if not ran_any and _is_file(survivors):
        sv = _load_json(survivors)
        if isinstance(sv, dict) and (
            isinstance(sv.get("note"), str) and sv["note"].strip()
            and isinstance(sv.get("survivors"), list)
            and _posint(sv.get("candidates_evaluated"))
        ):
            honest_empty = True
            why = (f"survivors empty but HONEST: candidates_evaluated="
                   f"{sv.get('candidates_evaluated')}, explicit note present")
            detail["survivors"] = str(survivors)
    detail["ran_any"] = ran_any or honest_empty
    if ran_any or honest_empty:
        return SignalResult(
            signal="exploit-queue", ok=True,
            reason=f"exploit-queue built and processed input ({why})",
            artifacts=detail["present"] + ([str(survivors)] if honest_empty else []),
            detail=detail,
        )
    hollow = (
        "exploit_queue.json PRESENT but HOLLOW: empty queue/entries, zero "
        "candidate counts, no processed-input evidence (broken_invariants/"
        "benchmark/source_mining_summary all absent or zero) and no honest "
        "survivors note - file-presence-only, the queue was not built over input"
    )
    # A file-present hollow artifact is the exact bypass vector: a real pipeline
    # that ran produces at least one positive-count field.  Fail unconditionally
    # regardless of strict mode - the signal is hard-required in _SIGNAL_ORDER.
    # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    return SignalResult(
        signal="exploit-queue", ok=False, reason=hollow,
        artifacts=detail["present"], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (f): chain-synthesis ran
# --------------------------------------------------------------------------
def _l37_gate_strict(name: str) -> bool:
    """L37 per-signal strict toggle. Strict mode for a named L37 signal is
    enabled by AUDITOOOR_L37_<NAME>_STRICT=1 or the global AUDITOOOR_L37_STRICT=1.
    Mirrors the AUDITOOOR_L37_EXPLOIT_CONVERSION_STRICT idiom used by signal (g)
    (check_exploit_conversion). Place near _enforce_autonomous_proof_conversion()."""
    key = "AUDITOOOR_L37_" + name.strip().upper() + "_STRICT"
    if os.environ.get(key, "").strip() == "1":
        return True
    if os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1":
        return True
    return False


def _gate_default_on_strict(env: str) -> bool:
    """Uniform default-ON-under-L37 gate predicate (graduation 2026-07-03,
    operator decision - the audit-the-audits gates E5/E6/F1/D1 now ENFORCE by
    default whenever the STRICT audit runs, with a per-gate opt-out).

    Semantics (single source of truth; used by check_attestation_count_integrity,
    the E6 revalidate branch, the F1 verdict/worklist JOIN reader, and
    check_conversion_throughput):

        explicit opt-out : <env> in {0,false,no}     -> DISABLED (escape hatch)
        explicit opt-in  : <env> any other truthy    -> ENFORCED
        unset (default)  : ENFORCED iff AUDITOOOR_L37_STRICT is truthy
                           (unset/0/false/no on L37 -> advisory, so a bare
                           non-strict / library caller keeps advisory behaviour)

    NEVER-FALSE-PASS is unchanged: only WHEN the gate hard-fails moves; the gate
    body / defect logic is untouched."""
    v = os.environ.get(env, "").strip().lower()
    if v in ("0", "false", "no"):
        return False               # explicit per-gate opt-out
    if v:                          # any other explicit value -> opt-in
        return True
    # unset -> default-ON under the L37 strict umbrella (advisory otherwise)
    return os.environ.get("AUDITOOOR_L37_STRICT", "").strip().lower() not in (
        "", "0", "false", "no")


# --------------------------------------------------------------------------
# 100%-terminal-adjudication strict axes (generic, all-workspace).
#
# The honesty bug these three close: `make audit-complete STRICT=1` used to PASS
# while three completeness axes were only ADVISORY WARNs - (1) the mechanism
# plane's UNSCANNED cells, (2) the swept-surface uncovered fraction, and (3) the
# rubric rows nobody attempted. A pass could therefore hide 62% unswept + N
# unadjudicated mechanisms behind loud-but-non-fatal warns. Under STRICT each of
# these becomes a REQUIRED terminal adjudication: covered / cleared-with-citation
# / dispositioned-with-reason / a real finding / an explicit operator waiver.
#
# Each axis has its OWN opt-in env AND is subsumed by the umbrella
# AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT and by the global AUDITOOOR_L37_STRICT
# (what `make audit-complete STRICT=1` exports). Non-strict (nothing exported)
# stays byte-identical WARN-pass (backward-compat for pre-existing audits).
#
# "100%" means 100% TERMINAL-ADJUDICATED, NOT 100% harness-execution: a unit may
# be terminal by being reviewed/covered OR by carrying a source-cited disposition
# / N-A reason. These gates never demand "execute every function".
# --------------------------------------------------------------------------
def _all_axes_strict() -> bool:
    """Umbrella: every completeness axis must reach a terminal verdict. Set by the
    global L37 STRICT gate, the dedicated umbrella env, or --strict propagation."""
    if os.environ.get("AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT", "").strip() == "1":
        return True
    return os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1"


def _rubric_attempt_strict() -> bool:
    """Signal (p): an UNATTEMPTED rubric impact row with no explicit N-A-with-reason
    or candidate FAILs. Opt-in AUDITOOOR_RUBRIC_ATTEMPT_STRICT, subsumed by the
    umbrella / global STRICT."""
    if os.environ.get("AUDITOOOR_RUBRIC_ATTEMPT_STRICT", "").strip() == "1":
        return True
    return _all_axes_strict()


def _swept_terminal_strict() -> bool:
    """Signal (o): a swept-surface UNCOVERED unit with NO terminal verdict FAILs.
    Opt-in AUDITOOOR_SWEPT_TERMINAL_STRICT, subsumed by the umbrella / global
    STRICT."""
    if os.environ.get("AUDITOOOR_SWEPT_TERMINAL_STRICT", "").strip() == "1":
        return True
    return _all_axes_strict()


def _disposition_proof_quality_lib():
    """Lazily import tools/lib/disposition_proof_quality.py (offline stdlib). The
    module supplies ``proof_strict_enabled`` + ``reason_is_terminal_quality``:
    under AUDITOOOR_DISPOSITION_PROOF_STRICT an N-A/cleared reason is TERMINAL only
    when it PROVES the impact unreachable (code-guard file:line / mechanism-level
    absence argument / named in-protocol cap), NOT when it merely notes a keyword
    grep found 0 hits. Returns None if the lib cannot be loaded (advisory-first:
    the loader then keeps its legacy behaviour, never a false-fail)."""
    try:
        tool_path = Path(__file__).resolve().parent / "lib" / "disposition_proof_quality.py"
        spec = importlib.util.spec_from_file_location(
            "_disposition_proof_quality", str(tool_path))
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None


def _load_terminal_dispositions(ws: Path, name: str) -> dict[str, str]:
    """Load a JSONL disposition sidecar mapping a unit/row key -> reason. Used by
    both the swept-surface (unit) and rubric-attempt (row) axes so an operator can
    terminally CLEAR an otherwise-uncovered cell with a source-cited reason instead
    of forcing a harness over it. NEVER-FALSE-PASS: a row is only credited when it
    carries BOTH a non-empty key AND a >=1-char reason string; a bare/uncited entry
    is ignored (rejected). Missing file => empty dict (no credit).

    DISPOSITION-QUALITY (operator directive 2026-07-02, advisory-first behind
    AUDITOOOR_DISPOSITION_PROOF_STRICT): an N-A / cleared / dispositioned reason is
    TERMINAL only when it PROVES the impact UNREACHABLE - a code-guard/structural
    fact at file:line, a MECHANISM-level absence argument (name the mechanism the
    impact WOULD use and why the deployed asset structurally cannot reach it), or a
    named in-protocol cap/recovery. A reason whose ONLY evidence is a keyword-grep /
    "no X found" / "0 hits" is REJECTED under strict (it is not a genuine attempt -
    the 'killing easier than keeping' false-negative anti-pattern). Absent STRICT
    the credit set is byte-identical to the legacy behaviour."""
    out: dict[str, str] = {}
    path = ws / ".auditooor" / name
    txt = _read_text(path)
    if not txt:
        return out
    dq = _disposition_proof_quality_lib()
    proof_strict = bool(dq is not None and dq.proof_strict_enabled())
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(row, dict):
            continue
        key = str(row.get("unit") or row.get("row") or row.get("key")
                  or row.get("sentence") or "").strip()
        reason = str(row.get("reason") or row.get("disposition") or "").strip()
        # fail-closed: a disposition needs a concrete key AND a real reason.
        if not (key and len(reason) >= 8):
            continue
        # DISPOSITION-QUALITY strict: a grep-only / absence-only N-A reason does NOT
        # credit the cell (advisory-first; off => legacy behaviour preserved).
        if proof_strict and not dq.reason_is_terminal_quality(reason):
            continue
        out[key] = reason
    return out


def check_chain_synth(ws: Path) -> SignalResult:
    """Signal (f): chain-synthesis ran over the available queue/invariants and
    emitted a VERDICT-BEARING artifact.

    The prior implementation false-passed on mere file/dir presence: a hollow
    ``{"chains_synthesized": 0}`` (or ``{}``) artifact returned ok=True because
    only the path was checked, never the content. That let a no-verdict /
    never-ran stub certify the stage (verified false-pass, 2026-06-07).

    Corrected contract (PASS iff the artifact proves the stage PROCESSED input
    and reached a verdict):
      - a ``chains_synthesized`` count > 0 OR a non-empty ``narratives`` /
        ``narrative`` / positive ``advancing_chains`` (positive synthesis
        result), OR
      - an explicit applicability / blocked reason field
        (``applicability_verdict`` / ``applicability_reason`` / a ``status``
        that is a real ran-state such as ``complete`` / ``blocked-*``), OR
      - positive processed-input evidence: ``matched_templates`` /
        ``source_link_entries`` / ``proof_obligations`` > 0, a non-empty
        ``blocked_chains`` / ``broken_invariant_ids`` list, or an
        ``input_counts`` map showing leads/invariants were consumed.

    0 chains WITH an explicit reason is HONEST and PASSES (e.g. the real
    auditooor.chain_synthesis_report.v1 with status=blocked-missing-hop-evidence,
    applicability_verdict=pass-not-applicable, 832 broken invariants processed).
    A hollow ``{"chains_synthesized": 0}`` / ``{}`` artifact with NO verdict, NO
    reason, and NO processed-input evidence is the false-pass shape: WARN-pass by
    default, fail-closed under strict.

    Strict = ``_enforce_autonomous_proof_conversion() or
    _l37_gate_strict('CHAIN_SYNTH')``. Default is advisory (WARN-pass) so
    non-opt-in callers are unchanged.
    """
    a = ws / ".auditooor"
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("CHAIN_SYNTH")

    # Collect candidate report artifacts. Prefer the MOST-RECENT date-stamped
    # json (sorted last) over an old run; fall back to a chain_synthesis/ dir.
    json_candidates: list[Path] = []
    if _exists(a) and a.is_dir():
        # Prefer the date-stamped synthesis REPORT (chain_synthesis_*.json). Only
        # fall back to the broader chain_synth*.json glob - which ALSO matches
        # auxiliary sidecars like chain_synth_source_links.json - when no real
        # report exists. (The prior two-glob + dedup left a sidecar last, so
        # reports[-1] evaluated the WRONG file and false-flagged a genuinely-ran
        # chain-synth as HOLLOW.)
        try:
            json_candidates = [p for p in sorted(a.glob("chain_synthesis*.json")) if _is_file(p)]
        except OSError:
            json_candidates = []
        if not json_candidates:
            try:
                json_candidates = [p for p in sorted(a.glob("chain_synth*.json")) if _is_file(p)]
            except OSError:
                json_candidates = []
    seen: set[str] = set()
    reports: list[Path] = []
    for p in json_candidates:
        if str(p) in seen:
            continue
        seen.add(str(p))
        reports.append(p)

    # Pick the FRESHEST report by mtime (not insertion order) so the most-recent
    # run is evaluated regardless of glob/dedup ordering.
    def _report_mtime(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return 0.0

    # A different tool (chained-attack-planner, schema
    # auditooor.chained_attack_plans.v1) writes its hollow advisory output to a
    # chain_synthesis_<date>.json filename that COLLIDES with the genuine
    # chain-synthesizer report. Picking the freshest-by-mtime then evaluated the
    # planner artifact (no chains_synthesized / matched_templates / proof_obligations)
    # and false-flagged a genuinely-ran chain-synth as HOLLOW (near-intents
    # 2026-06-26). Prefer the freshest report that actually carries the chain-synth
    # REPORT schema; fall back to freshest-overall only when none match (so a tool
    # that renames its schema still surfaces something rather than vanishing).
    def _is_chain_synth_report(p: Path) -> bool:
        d = _load_json(p)
        if not isinstance(d, dict):
            return False
        if "chains_synthesized" in d or "matched_templates" in d or "proof_obligations" in d:
            return True
        if str(d.get("schema", "")).startswith("auditooor.chain_synth"):
            return True
        # The current chain-synthesizer report schema (schema_version + plans +
        # summary + submission_posture) carries its processed-input evidence in
        # `summary` (detector_cluster_count / exploit_angle_count / ...) rather
        # than the legacy chains_synthesized field. Recognize it so it is SELECTED
        # as the report (not the source_links sidecar). NUVA 2026-06-30.
        if "plans" in d and ("summary" in d or "submission_posture" in d):
            return True
        return False
    _schema_reports = [p for p in reports if _is_chain_synth_report(p)]
    _selectable = _schema_reports or reports
    latest = max(_selectable, key=_report_mtime) if _selectable else None

    chain_dir = a / "chain_synthesis"
    has_dir = _nonempty_dir(chain_dir)

    detail: dict = {
        "reports_found": [p.name for p in reports],
        "evaluated_artifact": (latest.name if latest is not None else None),
        "chain_synthesis_dir": (str(chain_dir) if has_dir else None),
        "strict": strict,
    }

    if latest is None and not has_dir:
        return SignalResult(
            signal="chain-synth", ok=False,
            reason="no .auditooor/chain_synthesis* artifact; chain-synthesis did not run",
            artifacts=[], detail=detail,
        )

    payload = _load_json(latest) if latest is not None else None

    def _posint(v: Any) -> bool:
        return isinstance(v, int) and not isinstance(v, bool) and v > 0

    chains = (payload or {}).get("chains_synthesized")
    advancing = (payload or {}).get("advancing_chains")
    narratives = (payload or {}).get("narratives")
    narrative = (payload or {}).get("narrative")
    status = (payload or {}).get("status")
    appl_verdict = (payload or {}).get("applicability_verdict")
    appl_reason = (payload or {}).get("applicability_reason")
    matched = (payload or {}).get("matched_templates")
    src_links = (payload or {}).get("source_link_entries")
    src_links_total = (payload or {}).get("source_link_entries_total")
    proof_obl = (payload or {}).get("proof_obligations")
    blocked = (payload or {}).get("blocked_chains")
    input_counts = (payload or {}).get("input_counts")
    broken_inv = (payload or {}).get("broken_invariant_ids")
    # Current chain-synthesizer report schema: processed-input evidence lives in
    # `summary` (detector_cluster_count / exploit_angle_count / hacker_brief_qdet_count
    # / big_loss_actor_sequence_count / defihack_predicate_match_count / brief_candidate_count)
    # and the ran-state in `submission_posture`. A report that processed >=1 detector
    # cluster / exploit angle / brief and emitted a posture is a genuine ran-over-input
    # verdict even when it synthesized 0 chains (honest negative). NUVA 2026-06-30.
    summary = (payload or {}).get("summary")
    submission_posture = (payload or {}).get("submission_posture")
    _summary_processed = isinstance(summary, dict) and any(
        _posint(summary.get(k)) for k in (
            "detector_cluster_count", "exploit_angle_count", "hacker_brief_qdet_count",
            "big_loss_actor_sequence_count", "defihack_predicate_match_count",
            "brief_candidate_count", "max_plans",
        )
    )

    # (1) positive synthesis result
    positive_result = bool(
        _posint(chains)
        or _posint(advancing)
        or (isinstance(narratives, list) and len(narratives) > 0)
        or (isinstance(narrative, dict) and len(narrative) > 0)
    )
    # (2) explicit verdict / reason field (honest 0-chains-with-reason)
    explicit_reason = bool(
        (isinstance(appl_verdict, str) and appl_verdict.strip())
        or (isinstance(appl_reason, str) and appl_reason.strip())
        or (isinstance(status, str) and status.strip()
            and status.strip().lower() not in {"", "unknown", "n/a", "none"})
        or (isinstance(submission_posture, str) and submission_posture.strip()
            and submission_posture.strip().lower() not in {"", "unknown", "n/a", "none"})
    )
    # (3) processed-input evidence (the stage actually consumed queue/invariants)
    processed_input = bool(
        _posint(matched)
        or _posint(src_links)
        or _posint(src_links_total)
        or _posint(proof_obl)
        or (isinstance(blocked, list) and len(blocked) > 0)
        or (isinstance(broken_inv, list) and len(broken_inv) > 0)
        or (isinstance(input_counts, dict)
            and any(_posint(input_counts.get(k)) for k in input_counts))
        or _summary_processed
    )

    verdict_bearing = positive_result or explicit_reason or processed_input
    detail.update({
        "chains_synthesized": chains,
        "advancing_chains": advancing,
        "status": status,
        "applicability_verdict": appl_verdict,
        "matched_templates": matched,
        "positive_result": positive_result,
        "explicit_reason": explicit_reason,
        "processed_input": processed_input,
        "verdict_bearing": verdict_bearing,
        "payload_parsed": payload is not None,
    })

    if verdict_bearing:
        if positive_result:
            why = (
                f"chain-synthesis ran with a positive result "
                f"(chains_synthesized={chains}, advancing_chains={advancing}, "
                f"narratives={len(narratives) if isinstance(narratives, list) else 0})"
            )
        elif explicit_reason and not processed_input:
            why = (
                f"chain-synthesis ran and emitted an explicit verdict "
                f"(status={status!r}, applicability_verdict={appl_verdict!r}); "
                f"0 chains with a stated reason is honest"
            )
        else:
            why = (
                f"chain-synthesis ran over input "
                f"(matched_templates={matched}, source_link_entries={src_links}, "
                f"proof_obligations={proof_obl}, broken_invariants="
                f"{len(broken_inv) if isinstance(broken_inv, list) else 0}); "
                f"status={status!r}, applicability_verdict={appl_verdict!r}"
            )
        return SignalResult(
            signal="chain-synth", ok=True, reason=why,
            artifacts=[str(latest)] if latest is not None else [str(chain_dir)],
            detail=detail,
        )

    # Artifact PRESENT but HOLLOW: no positive result, no explicit verdict/reason,
    # no processed-input evidence (the {"chains_synthesized": 0} / {} false-pass
    # shape, an unparseable json, or a dir with no verdict-bearing report).
    if latest is None and has_dir:
        hollow_reason = (
            "chain_synthesis/ dir present but no verdict-bearing chain_synthesis*.json "
            "report; cannot prove the stage processed input or reached a verdict"
        )
    else:
        hollow_reason = (
            f"chain-synthesis artifact present but HOLLOW: chains_synthesized={chains}, "
            f"no explicit applicability/status verdict and no processed-input evidence "
            f"(matched_templates/source_link_entries/proof_obligations/input_counts all "
            f"absent or zero){' (unparseable JSON)' if payload is None else ''} - "
            f"file-presence-only, not a genuine ran-over-input verdict"
        )

    if strict:
        return SignalResult(
            signal="chain-synth", ok=False, reason=hollow_reason,
            artifacts=([str(latest)] if latest is not None else [str(chain_dir)]),
            detail=detail,
        )
    return SignalResult(
        signal="chain-synth", ok=True, reason="WARN: " + hollow_reason,
        artifacts=([str(latest)] if latest is not None else [str(chain_dir)]),
        detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (g): exploit-conversion-loop ran (advisory unless env-enforced)
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
# --------------------------------------------------------------------------
def check_exploit_conversion(ws: Path) -> SignalResult:
    a = ws / ".auditooor"
    conv_candidates = [
        a / "current_to_exploit_conversion_gate.json",
        a / "exploit_conversion_loop_manifest.json",
        a / "exploit_conversion_benchmark.json",
    ]
    conv = [c for c in conv_candidates if _is_file(c)]
    detail = {
        "conversion_artifacts": [str(c) for c in conv],
        "advisory_autonomous_proof_conversion": True,
        "enforce_autonomous_proof_conversion": _enforce_autonomous_proof_conversion(),
    }
    if not conv:
        if not _enforce_autonomous_proof_conversion():
            return SignalResult(
                signal="exploit-conversion", ok=True,
                reason=(
                    "no exploit-conversion-loop artifact; autonomous proof conversion "
                    "is advisory by default. Set ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 "
                    "to enable enforced artifact mode"
                ),
                artifacts=[], detail=detail,
            )
        return SignalResult(
            signal="exploit-conversion", ok=False,
            reason=(
                "no exploit-conversion-loop artifact "
                "(current_to_exploit_conversion_gate.json / exploit_conversion_loop_manifest.json); "
                "the exploit-conversion loop did not run and "
                "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 requires it"
            ),
            artifacts=[], detail=detail,
        )
    # Artifact PRESENT. File-presence alone is the false-pass: an empty /
    # boilerplate-only conversion gate would pass here. Assert a CONCRETE,
    # checkable content property of the artifact that encodes genuine work:
    #   - the gate declares a real boolean `start_exploit_conversion_allowed`
    #     (the conversion loop actually adjudicated eligibility - not absent,
    #     not a placeholder string), AND
    #   - it carries POSITIVE numeric evidence the loop ran: either
    #     sidecar_freshness.total > 0 (sidecars were enumerated) OR
    #     proof_artifact_feedback_status.proof_artifact_index_rows > 0
    #     (proof-artifact feedback was indexed) OR a non-empty
    #     remaining_current_gaps list (the loop adjudicated current gaps).
    # A field merely EXISTING / non-empty-string is NOT enough; we require a
    # numeric > 0 or a real bool. Boilerplate template strings cannot satisfy
    # this.
    # <!-- r36-rebuttal: lane-L37-HARDEN registered in .auditooor/agent_pathspec.json -->
    strict_conversion = (
        _enforce_autonomous_proof_conversion()
        or os.environ.get(
            "AUDITOOOR_L37_EXPLOIT_CONVERSION_STRICT", ""
        ).strip() == "1"
    )
    payload: dict | None = None
    for c in conv:
        payload = _load_json(c)
        if payload is not None:
            break
    adjudicated = isinstance(payload, dict) and isinstance(
        payload.get("start_exploit_conversion_allowed"), bool
    )
    sidecar = (payload or {}).get("sidecar_freshness") or {}
    proof_fb = (payload or {}).get("proof_artifact_feedback_status") or {}
    gaps = (payload or {}).get("remaining_current_gaps")
    sidecar_total = sidecar.get("total") if isinstance(sidecar, dict) else None
    proof_rows = (
        proof_fb.get("proof_artifact_index_rows")
        if isinstance(proof_fb, dict)
        else None
    )
    positive_work = bool(
        (isinstance(sidecar_total, int) and sidecar_total > 0)
        or (isinstance(proof_rows, int) and proof_rows > 0)
        or (isinstance(gaps, list) and len(gaps) > 0)
    )
    non_vacuous = adjudicated and positive_work
    detail.update({
        "conversion_gate_adjudicated": adjudicated,
        "conversion_gate_positive_work": positive_work,
        "sidecar_total": sidecar_total,
        "proof_artifact_index_rows": proof_rows,
        "remaining_current_gaps_count": (
            len(gaps) if isinstance(gaps, list) else None
        ),
        "non_vacuous": non_vacuous,
        "strict": strict_conversion,
    })
    if non_vacuous:
        return SignalResult(
            signal="exploit-conversion", ok=True,
            reason=(
                "exploit-conversion-loop artifact present and non-vacuous "
                f"(adjudicated start_exploit_conversion_allowed="
                f"{(payload or {}).get('start_exploit_conversion_allowed')}, "
                f"sidecar_total={sidecar_total}, proof_rows={proof_rows})"
            ),
            artifacts=[str(c) for c in conv],
            detail=detail,
        )
    # Artifact present but VACUOUS (no adjudicated bool or no positive work
    # evidence - the file-presence false-pass shape). Fail-closed under strict;
    # WARN-pass otherwise so default certification behavior is unchanged for
    # non-opt-in callers.
    vac_reason = (
        "exploit-conversion-loop artifact present but VACUOUS: "
        f"adjudicated_bool={adjudicated}, positive_work={positive_work} "
        "(no start_exploit_conversion_allowed bool and/or no positive "
        "sidecar/proof/gap evidence - file-presence-only, not genuine work)"
    )
    if strict_conversion:
        return SignalResult(
            signal="exploit-conversion", ok=False,
            reason=vac_reason,
            artifacts=[str(c) for c in conv],
            detail=detail,
        )
    return SignalResult(
        signal="exploit-conversion", ok=True,
        reason="WARN: " + vac_reason,
        artifacts=[str(c) for c in conv],
        detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (g2): prove-top-leads produced a proof/judgment artifact
# (advisory unless env-enforced)
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
# --------------------------------------------------------------------------
def check_prove_top_leads(ws: Path) -> SignalResult:
    a = ws / ".auditooor"
    prove = _glob_first(a, ("prove_top_leads_*",))
    if prove is None:
        # also accept a reports/ variant
        prove = _glob_first(ws / "reports", ("prove_top_leads_*",))
    artifact_set = _prove_top_leads_artifact_set(ws)
    detail = {
        "prove_top_leads": str(prove) if prove else None,
        "advisory_autonomous_proof_conversion": True,
        "enforce_autonomous_proof_conversion": _enforce_autonomous_proof_conversion(),
        **artifact_set,
    }
    if prove is None:
        if not _enforce_autonomous_proof_conversion():
            return SignalResult(
                signal="prove-top-leads", ok=True,
                reason=(
                    "no prove_top_leads_* judgment/proof-task artifact; autonomous "
                    "proof conversion is advisory by default. Set "
                    "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 to enable enforced "
                    "artifact mode"
                ),
                artifacts=[], detail=detail,
            )
        return SignalResult(
            signal="prove-top-leads", ok=False,
            reason=(
                "no prove_top_leads_* judgment/proof-task artifact; the "
                "prove-top-leads proof-conversion step did not run and "
                "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 requires it"
            ),
            artifacts=[], detail=detail,
        )
    if _enforce_autonomous_proof_conversion():
        if artifact_set["artifact_set_complete"]:
            return SignalResult(
                signal="prove-top-leads", ok=True,
                reason="prove-top-leads full artifact set present",
                artifacts=artifact_set["artifacts"],
                detail=detail,
            )
        if artifact_set["no_leads_manifest_complete"]:
            return SignalResult(
                signal="prove-top-leads", ok=True,
                reason="prove-top-leads structured no-leads manifest present",
                artifacts=artifact_set["artifacts"],
                detail=detail,
            )
        return SignalResult(
            signal="prove-top-leads", ok=False,
            reason=(
                "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 requires the full "
                "prove-top-leads artifact set or a structured no-leads manifest; "
                "a bare prove_top_leads_* file is insufficient"
            ),
            artifacts=[],
            detail=detail,
        )
    return SignalResult(
        signal="prove-top-leads", ok=True,
        reason="prove-top-leads judgment/proof-task artifact present",
        artifacts=[str(prove)], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (u): EXPLOIT-QUEUE RESOLUTION - the morpho-3% false-pass gate
# All top-N leads killed by disqualification with no negative_control means
# "couldn't auto-prove" was recorded as "killed" without a genuine refutation.
# Advisory by default; strict under ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1
# or AUDITOOOR_L37_EXPLOIT_QUEUE_RESOLUTION_STRICT=1.
# --------------------------------------------------------------------------
_EQ_RESOLUTION_STRICT_ENV = "AUDITOOOR_L37_EXPLOIT_QUEUE_RESOLUTION_STRICT"
_DEFAULT_EQ_RESOLUTION_TOP_N = 5
_DISQ_QUALITY_GATE_STATUSES = frozenset({
    "disqualified",
    "closed_negative_source_proof",
    "closed_negative",
    "blocked_r76_hallucinated_source_claim",
})
_DISQ_PROOF_STATUSES = frozenset({
    "killed", "drop", "dropped", "disqualified",
})


# A genuine negative control cites a CONCRETE, checkable artifact - a
# file:line, a named test, or a concrete revert/guard/assert outcome. A
# prescriptive template ("PoC must include a baseline run...", "Differential:
# run the normal path...") describes what a PoC SHOULD do; it is NOT evidence
# the candidate was proven safe. Same discipline as R76 (cite real source) and
# R80 (assert(true) / "engine should run" is not proof). Without this, the
# disqualification gate is trivially satisfied by a boilerplate string - the
# exact morpho-3% false-pass it exists to prevent.
_NEG_CONTROL_EVIDENCE_RE = re.compile(
    r"[\w./-]+\.(?:sol|rs|go|move|cairo|vy|py|ts|sw):\d+"      # file:line
    r"|\.t\.sol\b|\btest_[A-Za-z0-9_]+|[A-Za-z0-9_]+Test\b|::test"  # named test
    r"|---\s*PASS|Suite result: ok"                              # test transcript
    r"|\b(?:reverts?|reverted|require\(|assert(?:Eq|Ge|Le|Gt|Lt|True|False)?|"
    r"does not fire|did not fire|NotLiquidatable|guard at|"
    r"counterexample|invariant holds|0 findings? after)\b",
    re.I,
)


def _negative_control_is_substantive(val) -> bool:
    """True iff the negative_control / clean_control text is genuine evidence
    (cites a concrete artifact), not a prescriptive boilerplate template."""
    if not val:
        return False
    return bool(_NEG_CONTROL_EVIDENCE_RE.search(str(val)))


def _is_disqualification_kill(row: dict) -> bool:
    """True iff a row is killed by quality-gate disqualification with no
    genuine negative_control / clean_control artifact backing the kill.
    A real refutation must cite a SUBSTANTIVE negative_control / clean_control
    (a concrete checkable artifact, not a boilerplate "PoC must..." template)."""
    proof = str(row.get("proof_status") or "").strip().lower()
    gate = str(row.get("quality_gate_status") or "").strip().lower()
    if proof not in _DISQ_PROOF_STATUSES and gate not in _DISQ_QUALITY_GATE_STATUSES:
        return False
    has_real_control = (
        _negative_control_is_substantive(row.get("negative_control"))
        or _negative_control_is_substantive(row.get("clean_control"))
    )
    return not has_real_control


def _top_n_leads_by_priority(rows: list, n: int) -> list:
    """Return the top-n non-advisory candidate rows sorted descending by
    priority_score. Excludes advisory rows and not_candidate rows."""
    cands = [
        r for r in rows
        if isinstance(r, dict)
        and not r.get("row_is_advisory")
        and str(r.get("proof_status") or "").lower() != "not_candidate"
    ]

    def _score(r: dict) -> float:
        try:
            return float(r.get("priority_score") or 0)
        except (ValueError, TypeError):
            return 0.0

    return sorted(cands, key=_score, reverse=True)[:n]


def _eq_resolution_strict() -> bool:
    # G7: subsume this gate under the global AUDITOOOR_L37_STRICT umbrella like
    # its ~30 sibling gates (via _l37_gate_strict), not only its two dedicated
    # envs. Previously a bare `audit-completeness-check.py --strict` (which sets
    # AUDITOOOR_L37_STRICT but not ENFORCE_AUTONOMOUS_PROOF_CONVERSION /
    # _EQ_RESOLUTION_STRICT_ENV) let a disqualification-kill-all exploit-queue
    # WARN-pass. The canonical `make audit-complete STRICT=1` path already exports
    # ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 so this only newly-fail-closes raw
    # --strict runs; no canonical-path behavior change.
    return (
        _enforce_autonomous_proof_conversion()
        or os.environ.get(_EQ_RESOLUTION_STRICT_ENV, "").strip()
        not in ("", "0", "false", "no")
        # pre-existing gate (dedicated env AUDITOOOR_L37_EXPLOIT_QUEUE_RESOLUTION_STRICT
        # already referenced); adding the L37 umbrella form is a consistency fix, not
        # a net-new global rule. <!-- admitted: signal:EXPLOIT_QUEUE_RESOLUTION -->
        or _l37_gate_strict("EXPLOIT_QUEUE_RESOLUTION")
    )


def check_exploit_queue_resolution(ws: Path) -> SignalResult:
    eq = ws / ".auditooor" / "exploit_queue.json"
    obj = _load_json(eq)
    strict = _eq_resolution_strict()
    try:
        n = int(
            os.environ.get("AUDITOOOR_L37_EQ_RESOLUTION_TOP_N")
            or _DEFAULT_EQ_RESOLUTION_TOP_N
        )
    except (ValueError, TypeError):
        n = _DEFAULT_EQ_RESOLUTION_TOP_N
    if obj is None:
        return SignalResult(
            signal="exploit-queue-resolution", ok=True,
            reason="no exploit_queue.json; exploit-queue signal governs presence",
            artifacts=[], detail={"queue_present": False, "strict": strict},
        )
    rows = obj.get("queue") or obj.get("items") or obj.get("candidates") or []
    if not isinstance(rows, list):
        rows = []
    top_n = _top_n_leads_by_priority(rows, n)
    if not top_n:
        return SignalResult(
            signal="exploit-queue-resolution", ok=True,
            reason="exploit-queue has no non-advisory candidate rows; resolution check N/A",
            artifacts=[str(eq)],
            detail={"candidate_rows": 0, "top_n": n, "strict": strict},
        )
    disq_killed = [r for r in top_n if _is_disqualification_kill(r)]
    genuinely_resolved = [r for r in top_n if not _is_disqualification_kill(r)]
    detail = {
        "top_n": n,
        "top_n_candidates": len(top_n),
        "disqualification_killed": len(disq_killed),
        "genuinely_resolved": len(genuinely_resolved),
        "strict": strict,
        "disq_killed_ids": [
            r.get("candidate_id") or r.get("id") or r.get("title") or "?"
            for r in disq_killed
        ],
    }
    if genuinely_resolved:
        return SignalResult(
            signal="exploit-queue-resolution", ok=True,
            reason=(
                f"{len(genuinely_resolved)} of top-{n} exploit-queue leads have a "
                f"genuine resolution ({len(disq_killed)} disqualification-killed)"
            ),
            artifacts=[str(eq)], detail=detail,
        )
    # All top-N leads are disqualification-killed.
    if not strict:
        return SignalResult(
            signal="exploit-queue-resolution", ok=True,
            reason=(
                f"WARN: all top-{n} exploit-queue leads are disqualification-killed "
                "with no negative_control (morpho-3% pattern); set "
                "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 or "
                f"{_EQ_RESOLUTION_STRICT_ENV}=1 to fail-close"
            ),
            artifacts=[str(eq)], detail=detail,
        )
    return SignalResult(
        signal="exploit-queue-resolution", ok=False,
        reason=(
            f"all {len(top_n)} top-{n} exploit-queue leads are proof_status=killed "
            "exclusively via quality-gate disqualification with no "
            "negative_control / clean_control artifact - 'couldn't auto-prove' "
            "was recorded as 'killed' with no genuine refutation (morpho-3% pattern)"
        ),
        artifacts=[str(eq)], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (D1): conversion-throughput delivery-leak.
#
# THE DELIVERY GAP (operator-caught NUVA/SSV 2026-07-03, id15/20): the audit
# passes while ~0% of the NON-VACUOUS corpus-hunt-fuel / hacker-Q lead corpus
# reaches a TERMINAL, work-backed verdict (proved / refuted-with-evidence /
# filed). check_exploit_queue_resolution only inspects the TOP-5 leads and passes
# on all-unproved rows, so the fact that 7680 of 7814 NUVA leads sit at
# proof_status=unproved / needs_harness (never driven to a work-backed terminal)
# is INVISIBLE. This signal measures the WHOLE-corpus conversion throughput and
# emits the UNDRIVEN COUNT loudly.
#
# SCOPE-HONESTY: this is a THROUGHPUT gap, NOT a false-green (operator flagged the
# id15/20 severity as OVERSTATED). It is ADVISORY-FIRST and DELIBERATELY not wired
# into audit-done-guard's done=True in this wave - a huge corpus of unproved leads
# is a delivery backlog, not an incorrect certification, so bricking done on it
# would be wrong. Hard-fail ONLY under the dedicated
# AUDITOOOR_CONVERSION_THROUGHPUT_STRICT (NOT subsumed by the L37 umbrella), so a
# routine run is byte-identical. Rebuttal key: ``conversion-throughput:``.
#
# A lead is TERMINAL work-backed when:
#   - proof_status in {proved, confirmed, filed, promoted_to_poc, promoted_to_chain}
#     (a genuine positive outcome), OR
#   - it is refuted WITH a SUBSTANTIVE negative_control (reuses
#     _negative_control_is_substantive - a cited artifact, not a boilerplate
#     "PoC must..." template), OR
#   - quality_gate_status in {filed, promoted}.
# An unproved / needs_harness / bare-killed row is UNDRIVEN (not terminal).
# --------------------------------------------------------------------------
_CONVERSION_THROUGHPUT_STRICT_ENV = "AUDITOOOR_CONVERSION_THROUGHPUT_STRICT"
# Advisory floor: below this terminal-fraction the corpus is flagged as a
# throughput leak. A workspace with a tiny lead corpus (<_CONVERSION_MIN_ROWS)
# is not meaningfully measurable, so it WARN-passes regardless.
_CONVERSION_TERMINAL_FRACTION_FLOOR = 0.05
_CONVERSION_MIN_ROWS = 50
_CONVERSION_TERMINAL_PROOF_STATES = frozenset(
    {"proved", "confirmed", "filed", "promoted_to_poc", "promoted_to_chain",
     "poc_pass"})

# Terminal-REFUTED proof_status vocabulary. SERVING-JOIN: this set MUST equal the
# vocabulary the miner (tools/exploit-queue.py _SOURCE_MINED_TERMINAL_PROOF_STATUSES)
# WRITES for a refuted/closed lead, otherwise honestly-refuted leads score 0 and
# the whole corpus reads as a conversion-throughput LEAK even though the work is
# done (axelar-dlt wrote 5545 `closed_negative` leads that matched NEITHER the old
# {killed,refuted,disqualified} reader nor _CONVERSION_TERMINAL_PROOF_STATES).
# Crediting is GATED on a substantive negative-control (see _lead_is_terminal_work_backed)
# so a bare token with only boilerplate nc is NOT credited - no false-green.
_CONVERSION_TERMINAL_REFUTED_PROOF_STATES = frozenset(
    {"killed", "refuted", "disqualified",
     "disproved", "closed_negative", "false_positive",
     "not_exploitable", "drop", "dropped"})


def _lead_is_terminal_work_backed(row: dict, typed_entry: dict | None = None) -> bool:
    """True iff a lead reached a terminal, WORK-BACKED verdict (not merely
    'recorded'). Positive outcome, refuted-with-substantive-negative-control, or
    filed/promoted. A bare killed / unproved / needs_harness row is NOT terminal."""
    if not isinstance(row, dict):
        return False
    proof = str(row.get("proof_status") or "").strip().lower()
    positive_terminal = proof in _CONVERSION_TERMINAL_PROOF_STATES
    qgs = str(row.get("quality_gate_status") or "").strip().lower()
    promoted_terminal = qgs in ("filed", "promoted")
    negative_terminal = (
        proof in _CONVERSION_TERMINAL_REFUTED_PROOF_STATES
        or qgs in _DISQ_QUALITY_GATE_STATUSES
    )
    if typed_entry is not None:
        # Admitted proof rows have immutable parents. A status token remains a
        # classification, not a closure, until a source-cited exact terminal
        # verdict binds it to that parent pair and envelope.
        return (
            (positive_terminal or promoted_terminal or negative_terminal)
            and _load_typed_envelope_tool().terminal_record_matches(typed_entry, row)
        )
    if positive_terminal or promoted_terminal:
        return True
    # refuted WITH a substantive negative control (a cited artifact, not boilerplate)
    if proof in _CONVERSION_TERMINAL_REFUTED_PROOF_STATES:
        nc = row.get("negative_control") or row.get("clean_control")
        if _negative_control_is_substantive(nc):
            return True
    return False


def check_conversion_throughput(ws: Path) -> SignalResult:
    """Signal (D1): whole-corpus conversion throughput. Measures the fraction of
    NON-VACUOUS exploit-queue leads that reach a terminal, work-backed verdict,
    independent of the top-5 exploit-queue-resolution check. ADVISORY-FIRST: WARN
    with a LOUD undriven-count by default; hard-fail ONLY under the dedicated
    AUDITOOOR_CONVERSION_THROUGHPUT_STRICT. Never wired into done=True (throughput
    gap, not a false-green).

    DEFAULT-ON graduation (2026-07-03): the dedicated env now defaults ENFORCED
    under the L37 strict umbrella (what `make audit-complete STRICT=1` exports),
    with a per-gate opt-out via AUDITOOOR_CONVERSION_THROUGHPUT_STRICT=0. A bare
    non-strict / library caller (L37 unset) still gets advisory behaviour."""
    strict = _gate_default_on_strict(_CONVERSION_THROUGHPUT_STRICT_ENV)
    eq = ws / ".auditooor" / "exploit_queue.json"
    obj = _load_json(eq)
    if obj is None:
        return SignalResult(
            signal="conversion-throughput", ok=True,
            reason="no exploit_queue.json; conversion-throughput N/A (no lead corpus)",
            artifacts=[], detail={"queue_present": False, "strict": strict})
    try:
        typed_entries = _typed_queue_entries(obj, workspace=ws, queue_path=eq)
    except ValueError as exc:
        return SignalResult(
            signal="conversion-throughput", ok=False,
            reason=f"typed proof queue is invalid: {exc}",
            artifacts=[str(eq)], detail={"queue_present": True, "typed_proof_queue": True},
        )
    rows = obj.get("queue") or obj.get("items") or obj.get("candidates") or []
    if not isinstance(rows, list):
        rows = []
    # NON-VACUOUS = not an advisory-only / claim-boundary lead (those resolve via
    # grounding, not per-lead proof, exactly like the hacker-Q advisory class).
    nonvacuous = [r for r in rows if isinstance(r, dict)
                  and r.get("advisory_only") is not True]
    n = len(nonvacuous)
    terminal = sum(
        1
        for r in nonvacuous
        if _lead_is_terminal_work_backed(
            r,
            typed_entries.get(str(r.get("lead_id"))) if typed_entries is not None else None,
        )
    )
    undriven = n - terminal
    frac = (terminal / n) if n else 1.0
    detail = {
        "queue_present": True,
        "nonvacuous_leads": n,
        "terminal_work_backed": terminal,
        "undriven": undriven,
        "terminal_fraction": round(frac, 4),
        "floor": _CONVERSION_TERMINAL_FRACTION_FLOOR,
        "strict": strict,
        "strict_env": _CONVERSION_THROUGHPUT_STRICT_ENV,
        "typed_proof_queue": typed_entries is not None,
    }
    # Too small a corpus to measure meaningfully -> pass (no delivery signal).
    if n < _CONVERSION_MIN_ROWS:
        return SignalResult(
            signal="conversion-throughput", ok=True,
            reason=(f"conversion-throughput N/A: only {n} non-vacuous lead(s) "
                    f"(< {_CONVERSION_MIN_ROWS}); {terminal} terminal"),
            artifacts=[str(eq)], detail=detail)
    if frac >= _CONVERSION_TERMINAL_FRACTION_FLOOR:
        return SignalResult(
            signal="conversion-throughput", ok=True,
            reason=(f"conversion-throughput OK: {terminal}/{n} non-vacuous leads "
                    f"({frac:.1%}) reached a terminal work-backed verdict"),
            artifacts=[str(eq)], detail=detail)
    reason = (
        f"conversion-throughput LEAK: only {terminal}/{n} non-vacuous corpus/hacker-Q "
        f"leads ({frac:.1%}) reached a TERMINAL work-backed verdict "
        f"(proved / refuted-with-evidence / filed); {undriven} leads are UNDRIVEN "
        f"(unproved / needs-harness / bare-killed). This is a DELIVERY throughput "
        f"gap, not a false-green - drive more leads to a work-backed terminal or "
        f"disposition them")
    if strict:
        return SignalResult(
            signal="conversion-throughput", ok=False, reason=reason,
            artifacts=[str(eq)], detail=detail)
    return SignalResult(
        signal="conversion-throughput", ok=True, reason="WARN: " + reason,
        artifacts=[str(eq)], detail=detail)


# --------------------------------------------------------------------------
# Signal (h): originality-vs-the-full-advisory-set ran
# --------------------------------------------------------------------------
def check_originality(ws: Path) -> SignalResult:
    a = ws / ".auditooor"
    candidates = [
        a / "originality_report.json",
        a / "originality.json",
        a / "originality_vs_advisory_set.json",
        a / "dupe_advisory_check.json",
        a / "external_corpus_search.json",
    ]
    found = [c for c in candidates if _is_file(c)]
    g = _glob_first(a, ("originality_report*.json", "originality_vs_advisory_set*.json", "*advisory*set*.json", "*dupe_advisory*"))
    if g is not None and str(g) not in {str(c) for c in found}:
        found.append(g)
    # reports/ dir variant
    g2 = _glob_first(ws / "reports", ("originality_report*.json", "originality_vs_advisory_set*.json", "*advisory*set*.json"))
    if g2 is not None and str(g2) not in {str(c) for c in found}:
        found.append(g2)

    if not found:
        # No artifact at all -> hard fail (real ok=False, no advisory flags). Strict catches it.
        return SignalResult(
            signal="originality", ok=False,
            reason=(
                "no originality-vs-advisory-set artifact "
                "(.auditooor/originality*.json / dupe_advisory_check.json)"
            ),
            artifacts=[], detail={"found": []},
        )

    # Inspect each artifact. A scan genuinely RAN against a non-empty advisory/
    # corpus set iff it emitted a verdict (keyword_count>0) AND a non-zero
    # comparison cardinality (corpus_compared / advisories_scanned / candidates /
    # local_files_scanned / corpus_trust active / vault_scan / evidence rows).
    # 0 dupe HITS is the common honest result and PASSES; hits>0 is NEVER required.
    ran_ok: list[dict[str, Any]] = []   # artifacts that prove a non-vacuous scan ran
    failing: list[dict[str, Any]] = []  # explicit fail/error/duplicate posture
    hollow: list[dict[str, Any]] = []   # empty {} / keyword_count==0 / zero corpus compared
    for f in found:
        obj = _load_json(f)
        if not isinstance(obj, dict) or not obj:
            hollow.append({"artifact": str(f), "reason": "empty-or-unreadable"})
            continue

        status = str(
            obj.get("status") or obj.get("verdict") or obj.get("result") or ""
        ).strip().lower()
        ok_value = obj.get("ok")

        # Explicit failing posture (real dupe / scan error) -> hard fail.
        if status in {"fail", "failed", "error", "duplicate", "likely-dupe"} or ok_value is False:
            failing.append({
                "artifact": str(f),
                "status": status or ("ok=false" if ok_value is False else ""),
            })
            continue

        # --- Scan-ran determination (schema auditooor.originality_before_proof_gate.v1) ---
        counts = obj.get("counts") if isinstance(obj.get("counts"), dict) else {}
        keyword_count = _coerce_int(counts.get("keyword_count"))
        if keyword_count == 0:
            kws = obj.get("keywords")
            if isinstance(kws, list):
                keyword_count = len(kws)

        # Comparison cardinality: how much advisory/corpus surface was compared,
        # independent of whether any hit landed.
        corpus_compared = (
            _coerce_int(counts.get("local_files_scanned"))
            + _coerce_int(counts.get("vault_hits"))
            + _coerce_int(obj.get("corpus_compared"))
            + _coerce_int(obj.get("advisories_scanned"))
            + _coerce_int(obj.get("candidates"))
            + _coerce_int(obj.get("candidate_count"))
        )
        ct = obj.get("corpus_trust")
        corpus_trust_active = (
            isinstance(ct, dict)
            and str(ct.get("trust_scope") or "").strip().lower()
            in {"active", "fallback-active", "serving"}
        )
        src = obj.get("source")
        vault_scan_enabled = isinstance(src, dict) and bool(src.get("vault_scan_enabled"))
        ev = obj.get("evidence")
        evidence_rows = len(ev) if isinstance(ev, list) else 0

        scan_compared_nonempty = (
            corpus_compared > 0
            or corpus_trust_active
            or vault_scan_enabled
            or evidence_rows > 0
        )

        if keyword_count > 0 and scan_compared_nonempty:
            ran_ok.append({
                "artifact": str(f),
                "keyword_count": keyword_count,
                "corpus_compared": corpus_compared,
                "corpus_trust_active": corpus_trust_active,
                "vault_scan_enabled": vault_scan_enabled,
                "evidence_rows": evidence_rows,
                "status": status or "ran",
            })
        else:
            hollow.append({
                "artifact": str(f),
                "reason": ("keyword_count==0" if keyword_count == 0 else "zero-corpus-compared"),
                "keyword_count": keyword_count,
                "corpus_compared": corpus_compared,
            })

    # 1) Any explicit failing posture -> hard fail (real dupe / scan error).
    if failing:
        return SignalResult(
            signal="originality", ok=False,
            reason="originality artifact present but records show fail/error/duplicate posture",
            artifacts=[d["artifact"] for d in failing],
            detail={
                "found": [str(f) for f in found],
                "failing_artifacts": failing,
                "ran_ok": ran_ok,
                "hollow": hollow,
            },
        )

    # 2) At least one artifact proves a non-vacuous scan ran -> PASS (0 hits OK).
    if ran_ok:
        return SignalResult(
            signal="originality", ok=True,
            reason=(
                "originality scan ran against a non-empty advisory/corpus set "
                f"(keyword_count>0, corpus compared) across {len(ran_ok)} artifact(s); "
                "0 dupe hits is an honest passing result"
            ),
            artifacts=[d["artifact"] for d in ran_ok],
            detail={
                "found": [str(f) for f in found],
                "ran_ok": ran_ok,
                "hollow": hollow,
            },
        )

    # 3) Artifact(s) present but NONE prove a scan ran (empty {} / keyword_count=0 /
    #    zero corpus compared). Advisory WARN by default; fail-closed under strict.
    enforce = _enforce_autonomous_proof_conversion()
    reason_hollow = (
        "originality artifact present but proves NO scan ran "
        "(empty {} / keyword_count=0 / zero corpus compared)"
    )
    if not enforce:
        return SignalResult(
            signal="originality", ok=True,
            reason=(
                reason_hollow
                + " - advisory WARN by default; set ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 to fail-close."
            ),
            artifacts=[str(f) for f in found],
            detail={
                "found": [str(f) for f in found],
                "ran_ok": ran_ok,
                "hollow": hollow,
                "advisory_autonomous_proof_conversion": True,
                "enforce_autonomous_proof_conversion": False,
            },
        )
    return SignalResult(
        signal="originality", ok=False,
        reason=reason_hollow + " - fail-closed under strict.",
        artifacts=[],
        detail={
            "found": [str(f) for f in found],
            "ran_ok": ran_ok,
            "hollow": hollow,
            "advisory_autonomous_proof_conversion": True,
            "enforce_autonomous_proof_conversion": True,
        },
    )


# --------------------------------------------------------------------------
# Signal (i): 7-artifact agent learning ran
# --------------------------------------------------------------------------
def check_learning(ws: Path) -> SignalResult:
    """Signal (j): 7-artifact agent learning ran.

    Prior implementation false-passed on mere file presence: an empty {}
    agent_artifact_mining_report.json (or any stub JSON) returned ok=True
    because only the path was checked, never the content.

    Corrected contract (PASS iff the artifact proves agent-artifact-miner ran):
      - JSON artifacts: schema_version = 'auditooor.agent_artifact_mining.v2'
        AND total_artifacts (int) AND no_learning_reason (bool) present.
      - A 0-artifacts run (total_artifacts=0, no_learning_reason=True) is
        GENUINE - the miner ran and found nothing to learn.
      - Non-JSON artifacts (JSONL, MD) pass on presence (harder to stub).

    Hollow {}, missing schema_version, or non-int total_artifacts -> WARN-pass
    by default; fail-closed under AUDITOOOR_L37_LEARNING_STRICT=1 or
    AUDITOOOR_L37_STRICT=1.
    """
    _SCHEMA = "auditooor.agent_artifact_mining.v2"
    a = ws / ".auditooor"
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("LEARNING")

    def _is_genuine(p: Path) -> tuple[bool, str]:
        obj = _load_json(p)
        if not isinstance(obj, dict):
            return False, "unparseable or non-dict JSON"
        if obj.get("schema_version") != _SCHEMA:
            return False, f"schema_version mismatch (got {obj.get('schema_version')!r})"
        ta = obj.get("total_artifacts")
        nlr = obj.get("no_learning_reason")
        if not isinstance(ta, int):
            return False, "total_artifacts missing or not int"
        if not isinstance(nlr, bool):
            return False, "no_learning_reason missing or not bool"
        return True, ""

    candidates = [
        a / "agent_artifact_mining_report.json",
        a / "agent_artifact_lesson_candidates.json",
        ws / "reports" / "agent_learning_report.json",
        ws / "reports" / "agent_artifact_mine_report.json",
        a / "corpus_delta.json",
        ws / "reports" / "corpus_delta.json",
    ]
    found = [c for c in candidates if _is_file(c)]
    g = _glob_first(ws / "reports", ("learning_loop_*.json", "*learn*report*.json"))
    if g is not None and str(g) not in {str(f) for f in found}:
        found.append(g)
    if not found:
        return SignalResult(
            signal="learning", ok=False,
            reason=(
                "no agent-artifact learning report "
                "(.auditooor/agent_artifact_mining_report.json or reports/learning_loop_*.json)"
            ),
            artifacts=[], detail={},
        )

    hollow_files: list[tuple[Path, str]] = []
    genuine_files: list[Path] = []
    for f in found:
        if f.suffix == ".json":
            gen, reason = _is_genuine(f)
            if gen:
                genuine_files.append(f)
            else:
                hollow_files.append((f, reason))
        else:
            genuine_files.append(f)  # non-JSON: presence sufficient

    if genuine_files:
        detail: dict[str, Any] = {"found": [str(f) for f in found]}
        for gf in genuine_files:
            if gf.suffix == ".json":
                obj2 = _load_json(gf) or {}
                detail["total_artifacts"] = obj2.get("total_artifacts")
                detail["no_learning_reason"] = obj2.get("no_learning_reason")
                break
        return SignalResult(
            signal="learning", ok=True,
            reason="7-artifact agent learning report ran with genuine schema",
            artifacts=[str(f) for f in genuine_files[:3]], detail=detail,
        )

    hollow_desc = "; ".join(f"{f.name}: {r}" for f, r in hollow_files[:2])
    hollow_reason = (
        f"learning artifact(s) present but HOLLOW: {hollow_desc} - "
        "schema_version + total_artifacts (int) + no_learning_reason (bool) "
        "required to prove agent-artifact-miner actually ran"
    )
    if strict:
        return SignalResult(
            signal="learning", ok=False, reason=hollow_reason,
            artifacts=[str(f) for f, _ in hollow_files[:2]], detail={"hollow": [f.name for f, _ in hollow_files]},
        )
    return SignalResult(
        signal="learning", ok=True, reason="WARN: " + hollow_reason,
        artifacts=[str(f) for f, _ in hollow_files[:2]], detail={"hollow": [f.name for f, _ in hollow_files]},
    )


# --------------------------------------------------------------------------
# Signal (j): cross-workspace seed back into the corpus ran (ADD-A sibling-aware)
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# ADD-A: when a SAME-FAMILY SIBLING workspace exists alongside this workspace,
# the cross_workspace_seed artifact is MANDATORY - there is prior same-family
# knowledge in a sibling that this audit must seed from. Its absence in that
# case fails with the distinct verdict ``fail-cross-ws-seed-sibling-exists`` so
# the operator knows the seed was skipped DESPITE a sibling being present. With
# no sibling, absence still fails (existing always-required behavior).
#
# Family resolution is deterministic + offline: a workspace's engagement family
# is read from (in order) an explicit ``.auditooor/engagement_family.txt`` /
# ``ENGAGEMENT_FAMILY`` marker, the ``engagement_family`` field of its
# cross_workspace_seed ledger, then a dir-name family-signal match. Siblings are
# the directories alongside ``<ws>`` (same parent) excluding ``<ws>`` itself.
# --------------------------------------------------------------------------
# Repo-name / dir-name substring -> protocol-family token (mirrors
# cross-workspace-seed.py FAMILY_SIGNALS; ordered most-specific first).
_FAMILY_SIGNALS: tuple[tuple[str, str], ...] = (
    ("morpho", "morpho-blue"),
    ("aave", "aave"),
    ("compound", "compound"),
    ("euler", "euler"),
    ("uniswap", "uniswap"),
    ("curve", "curve"),
    ("balancer", "balancer"),
    ("erc4626", "erc4626-vault"),
    ("erc-4626", "erc4626-vault"),
    ("dydx", "dydx-perps"),
    ("cosmos", "cosmos-sdk"),
    ("cometbft", "cosmos-sdk"),
    ("tendermint", "cosmos-sdk"),
    ("substrate", "substrate"),
    ("polkadot", "substrate"),
    ("parachain", "substrate"),
    ("hyperbridge", "cross-chain-bridge"),
    ("ismp", "cross-chain-bridge"),
    ("bridge", "cross-chain-bridge"),
    ("optimism", "l2-rollup"),
    ("arbitrum", "l2-rollup"),
    ("rollup", "l2-rollup"),
    ("spark", "bitcoin-statechain"),
    ("statechain", "bitcoin-statechain"),
    ("lightning", "bitcoin-lightning"),
    ("frost", "threshold-signing"),
    ("solana", "solana"),
    ("anchor", "solana"),
    ("aztec", "zk-rollup"),
    ("zk", "zk-rollup"),
    ("circom", "zk-circuit"),
)


def _family_from_name(name: str) -> str | None:
    blob = name.lower()
    for needle, family in _FAMILY_SIGNALS:
        if needle in blob:
            return family
    return None


def _engagement_family(ws: Path) -> str | None:
    """Resolve a workspace's engagement family deterministically and offline.

    Order: explicit marker file -> cross_workspace_seed ledger field ->
    dir-name family-signal match. Returns None when no family can be derived.
    """
    a = ws / ".auditooor"
    # explicit marker file (one-line family token)
    for marker in (a / "engagement_family.txt", ws / "ENGAGEMENT_FAMILY"):
        txt = _read_text(marker)
        if txt and txt.strip():
            return txt.strip().splitlines()[0].strip().lower()
    # cross_workspace_seed ledger field
    for ledger_name in ("cross_workspace_seed.json", "cross_workspace_ledger.json",
                        "cross_workspace_state.json"):
        obj = _load_json(a / ledger_name)
        if obj:
            for k in ("engagement_family", "protocol_family", "family", "target_domain"):
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip().lower()
                if isinstance(v, list) and v and isinstance(v[0], str):
                    return v[0].strip().lower()
    # dir-name fallback
    return _family_from_name(ws.name)


def _same_family_sibling(ws: Path) -> tuple[Path, str] | None:
    """Return (sibling_dir, family) for the first sibling workspace sharing this
    workspace's engagement family, or None. A sibling is a directory alongside
    ``<ws>`` (same parent) that is itself an auditooor workspace (has a
    ``.auditooor`` dir) and resolves to the same family token."""
    fam = _engagement_family(ws)
    if not fam:
        return None
    try:
        parent = ws.resolve().parent
    except OSError:
        return None
    if not _exists(parent) or not parent.is_dir():
        return None
    try:
        for sib in sorted(parent.iterdir()):
            try:
                if sib.resolve() == ws.resolve():
                    continue
            except OSError:
                continue
            if not sib.is_dir() or sib.name.startswith("."):
                continue
            # only treat real auditooor workspaces as siblings
            if not _exists(sib / ".auditooor"):
                continue
            sib_fam = _engagement_family(sib)
            if sib_fam and sib_fam == fam:
                return (sib, fam)
    except OSError:
        return None
    return None


def _corpus_hunt_fuel_present(ws: Path) -> bool:
    """PR7a: detect corpus-driven-hunt proof-queue fuel rows.

    corpus-driven-hunt.py --emit-proof-queue UPSERTs ``corpus-hunt-fuel`` /
    ``corpus-hunt-hacker-q`` rows into ``<ws>/.auditooor/exploit_queue.json``.
    These rows are direct evidence the cross-workspace invariant corpus (the
    invariant library mined from sibling engagements) seeded this workspace's
    proof obligations - a legitimate cross-seed signal. Bounded read, never
    raises.
    """
    eq = ws / ".auditooor" / "exploit_queue.json"
    if not _is_file(eq):
        return False
    try:
        data = json.loads(eq.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return False
    for row in (data.get("queue") or []):
        if isinstance(row, dict) and row.get("source") in (
            "corpus-hunt-fuel", "corpus-hunt-hacker-q",
        ):
            return True
    return False


def check_cross_ws_seed(ws: Path) -> SignalResult:
    """Signal (j): cross-workspace seed ran with GENUINE-EXECUTION evidence.

    Prior implementation false-passed on mere file presence: a hollow {} JSON
    or a 2-byte 'cross_ws_patterns.md' satisfied the gate because only path
    existence was checked, never content. Corrected contract (PASS iff the
    artifact proves the stage processed cross-workspace knowledge):

      - cross_workspace_seed.json: schema present AND (generated_at_utc set
        OR totals dict has at least one positive integer value)
      - differential_seed_queue.json: correct schema AND hypotheses / selected_siblings
        list is present (even an empty list proves the tool ran and found nothing)
      - corpus-hunt-fuel rows in exploit_queue.json: source field = corpus-hunt-fuel
        or corpus-hunt-hacker-q (already content-verified by _corpus_hunt_fuel_present)
      - .md pattern files: non-trivial content >200 bytes
      - cross_workspace_ledger/state JSON: non-empty entries list OR generated_at
        field with >2 other fields

    Hollow triggers (WARN-pass by default, fail-closed under strict):
      - Empty {} JSON under any cross_workspace_* name
      - cross_ws_patterns.md with <=200 bytes
      - JSON without schema or generated_at_utc

    Strict = _enforce_autonomous_proof_conversion() or
    _l37_gate_strict('CROSS_WS_SEED'). Default is advisory (WARN-pass).
    """
    a = ws / ".auditooor"
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("CROSS_WS_SEED")

    def _posint_v(v: Any) -> bool:
        return isinstance(v, int) and not isinstance(v, bool) and v > 0

    def _artifact_genuine(p: Path) -> tuple[bool, str]:
        """Returns (is_genuine, reason). Does NOT raise."""
        try:
            name = p.name.lower()
            # Markdown / .md files: genuine if non-trivial content (>200 bytes).
            if name.endswith(".md"):
                try:
                    size = p.stat().st_size
                except OSError:
                    size = 0
                if size > 200:
                    return True, f"non-trivial .md file ({size} bytes)"
                return False, f".md file hollow or boilerplate ({size} bytes <= 200)"
            # JSON files: load and inspect content.
            obj = _load_json(p)
            if not isinstance(obj, dict):
                return False, "unparseable or non-dict JSON"
            schema = str(obj.get("schema") or obj.get("schema_id") or "")
            gen_at = obj.get("generated_at_utc") or obj.get("generated_at") or obj.get("timestamp")
            # cross_workspace_seed.v1: needs generated_at_utc OR positive totals.
            if "cross_workspace_seed" in schema or "cross_workspace_seed" in name:
                totals = obj.get("totals") or {}
                if gen_at or any(_posint_v(v) for v in (totals.values() if isinstance(totals, dict) else [])):
                    return True, (
                        f"cross_workspace_seed ran "
                        f"(generated_at_utc={gen_at}, totals={totals})"
                    )
                return False, f"cross_workspace_seed.json hollow: generated_at_utc={gen_at!r}, totals={totals}"
            # differential_seed_queue.v1: correct schema + hypotheses or selected_siblings list.
            if "differential_seed" in schema or "differential_seed" in name:
                hyps = obj.get("hypotheses")
                siblings = obj.get("selected_siblings")
                if isinstance(hyps, list) or isinstance(siblings, list):
                    return True, (
                        f"differential_seed_queue ran "
                        f"(hypotheses={len(hyps or [])}, "
                        f"siblings={len(siblings or [])})"
                    )
                return False, f"differential_seed_queue.json hollow: hypotheses={hyps!r}"
            # cross_workspace_ledger / state JSON: non-empty entries OR gen_at + >2 fields.
            if "cross_workspace" in name or "cross_ws" in name or "pattern_migration" in name:
                entries = (
                    obj.get("entries")
                    or obj.get("patterns")
                    or obj.get("seeds")
                    or obj.get("pulls")
                )
                if isinstance(entries, (list, dict)) and len(entries) > 0:
                    return True, f"cross_workspace artifact with non-empty entries ({type(entries).__name__})"
                if gen_at and len(obj) > 2:
                    return True, f"cross_workspace artifact ran at {gen_at}"
                return False, f"cross_workspace JSON hollow: entries={entries!r}, gen_at={gen_at!r}"
            # Unknown cross-workspace JSON: be conservative - require gen_at + non-trivial size.
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            if gen_at and size > 100:
                return True, f"cross-workspace JSON with gen_at={gen_at} ({size} bytes)"
            return False, f"cross-workspace JSON not recognised: schema={schema!r}, gen_at={gen_at!r}"
        except Exception as exc:  # pragma: no cover
            return False, f"error inspecting {p.name}: {exc}"

    candidates = [
        a / "cross_workspace_seed.json",
        # ADD-A differential seed (cross-workspace-differential-seed.py).
        a / "differential_seed_queue.json",
        a / "cross_workspace_ledger.json",
        a / "cross_workspace_state.json",
        a / "cross_ws_patterns.md",
        a / "pattern_migration_alert.md",
        ws / "cross_ws_patterns.md",
        ws / "pattern_migration_alert.md",
    ]
    found = [c for c in candidates if _exists(c)]
    g = _glob_first(
        a,
        ("cross_workspace_*", "cross_ws_*", "differential_seed_*",
         "*pattern_migration*"),
    )
    if g is not None and str(g) not in {str(c) for c in found}:
        found.append(g)

    # PR7a: corpus-driven-hunt proof-queue fuel (content-verified by
    # _corpus_hunt_fuel_present - source field check, not mere file presence).
    corpus_fuel = _corpus_hunt_fuel_present(ws)
    if corpus_fuel:
        eq = a / "exploit_queue.json"
        if str(eq) not in {str(c) for c in found}:
            found.append(eq)

    sibling = _same_family_sibling(ws)
    sib_detail = (
        {"same_family_sibling": str(sibling[0]), "family": sibling[1]}
        if sibling else {"same_family_sibling": None}
    )

    # --- Genuine-execution check ---
    # corpus_fuel is already content-verified (source field scan, not path scan).
    if corpus_fuel:
        reason = (
            "cross-workspace seed genuine: corpus-driven-hunt proof-queue fuel "
            "(source=corpus-hunt-fuel rows in exploit_queue.json)"
        )
        return SignalResult(
            signal="cross-ws-seed", ok=True, reason=reason,
            artifacts=[str(a / "exploit_queue.json")],
            detail={"found": [str(f) for f in found],
                    "corpus_hunt_fuel": True,
                    "genuine": True,
                    "genuine_reason": "corpus-hunt-fuel rows",
                    **sib_detail},
        )

    genuine_artifact: Path | None = None
    genuine_reason = ""
    hollow_found: list[Path] = []
    for c in found:
        if not _is_file(c):
            continue
        gen, why = _artifact_genuine(c)
        if gen:
            genuine_artifact = c
            genuine_reason = why
            break
        hollow_found.append(c)

    if genuine_artifact is not None:
        return SignalResult(
            signal="cross-ws-seed", ok=True,
            reason=f"cross-workspace seed genuine: {genuine_reason}",
            artifacts=[str(genuine_artifact)],
            detail={"found": [str(f) for f in found],
                    "corpus_hunt_fuel": False,
                    "genuine": True,
                    "genuine_reason": genuine_reason,
                    **sib_detail},
        )

    # Artifact(s) found but all hollow.
    if found:
        hollow_reason = (
            f"cross-workspace seed artifact(s) present but HOLLOW "
            f"({', '.join(p.name for p in hollow_found)}): "
            "no generated_at_utc, no positive totals, no hypotheses/siblings list, "
            "and .md content <=200 bytes - file-presence-only, not a genuine ran-with-knowledge verdict"
        )
        detail = {"found": [str(f) for f in found],
                  "corpus_hunt_fuel": False,
                  "genuine": False,
                  "hollow_reason": hollow_reason,
                  "strict": strict,
                  **sib_detail}
        if strict:
            return SignalResult(signal="cross-ws-seed", ok=False,
                                reason=hollow_reason, artifacts=[str(f) for f in hollow_found],
                                detail=detail)
        return SignalResult(signal="cross-ws-seed", ok=True,
                            reason="WARN: " + hollow_reason,
                            artifacts=[str(f) for f in hollow_found], detail=detail)

    # No artifact at all.
    if sibling is not None:
        sib_dir, fam = sibling
        return SignalResult(
            signal="cross-ws-seed", ok=False,
            verdict_override=_CROSS_WS_SIBLING_VERDICT,
            reason=(
                f"same-family sibling workspace exists ({sib_dir.name}, "
                f"family={fam}) but no cross_workspace_seed / "
                "differential_seed_queue artifact - this audit did NOT seed "
                "from prior same-family knowledge. Run "
                "tools/cross-workspace-differential-seed.py "
                f"--workspace {ws.name} (ADD-A)"
            ),
            artifacts=[], detail=sib_detail,
        )

    return SignalResult(
        signal="cross-ws-seed", ok=False,
        reason=(
            "no cross-workspace seed artifact "
            "(.auditooor/cross_workspace_*.json / cross_ws_patterns.md / pattern_migration_alert.md)"
        ),
        artifacts=[], detail=sib_detail,
    )


# --------------------------------------------------------------------------
# Signal (j2): brain-prime intake step ran (ADD-D)
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# brain-prime.py emits <ws>/BRAIN_PRIMING_REPORT.md and a receipt at
# <ws>/.auditooor/brain_prime_receipt.json. Either is sufficient evidence the
# "where to hunt first" intake step ran before the workers were dispatched.
# --------------------------------------------------------------------------
def check_brain_prime(ws: Path) -> SignalResult:
    """Signal (j2): brain-prime intake step ran (ADD-D).

    Prior implementation false-passed on mere file presence: an empty {}
    brain_prime_receipt.json or a one-line BRAIN_PRIMING_REPORT.md returned
    ok=True because only the path was checked, never the content.

    Corrected contract (PASS iff the artifact proves brain-prime.py ran):
      - Receipt JSON: schema = 'auditooor.brain_prime_receipt.v1' present.
        mcp.skipped=True with correct schema is GENUINE (ran in skip mode).
      - MD report: size >= 500 bytes AND contains 'Generated:' or 'Phase A'.

    Hollow {} (no schema) or tiny MD (< 500 bytes) -> WARN-pass by default;
    fail-closed under AUDITOOOR_L37_BRAIN_PRIME_STRICT=1 or AUDITOOOR_L37_STRICT=1.
    """
    _SCHEMA = "auditooor.brain_prime_receipt.v1"
    _MD_MIN = 500
    _MD_MARKERS = ("Generated:", "Phase A")
    a = ws / ".auditooor"
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("BRAIN_PRIME")

    def _is_genuine_json(p: Path) -> tuple[bool, str]:
        obj = _load_json(p)
        if not isinstance(obj, dict):
            return False, "unparseable or non-dict JSON"
        if obj.get("schema") != _SCHEMA:
            return False, f"schema mismatch (got {obj.get('schema')!r}, want {_SCHEMA!r})"
        return True, ""

    def _is_genuine_md(p: Path) -> tuple[bool, str]:
        txt = _read_text(p)
        if txt is None:
            return False, "unreadable"
        if len(txt) < _MD_MIN:
            return False, f"too small ({len(txt)} bytes < {_MD_MIN})"
        if not any(m in txt for m in _MD_MARKERS):
            return False, f"missing report markers {_MD_MARKERS}"
        return True, ""

    candidates = [
        ws / "BRAIN_PRIMING_REPORT.md",
        a / "brain_prime_receipt.json",
        a / "BRAIN_PRIMING_REPORT.md",
        ws / "reports" / "BRAIN_PRIMING_REPORT.md",
    ]
    found = [c for c in candidates if _is_file(c)]
    g = _glob_first(a, ("brain_prime*", "*brain_priming*"))
    if g is not None and str(g) not in {str(f) for f in found}:
        found.append(g)
    g2 = _glob_first(ws, ("BRAIN_PRIMING_REPORT*", "brain_prime*"))
    if g2 is not None and str(g2) not in {str(f) for f in found}:
        found.append(g2)

    if not found:
        return SignalResult(
            signal="brain-prime", ok=False,
            reason=(
                "no brain-prime artifact (BRAIN_PRIMING_REPORT.md or "
                ".auditooor/brain_prime_receipt.json); the brain-prime intake step did not run (ADD-D)"
            ),
            artifacts=[], detail={},
        )

    hollow_files: list[tuple[Path, str]] = []
    genuine_files: list[Path] = []
    for f in found:
        if f.suffix == ".json":
            gen, reason = _is_genuine_json(f)
            if gen:
                genuine_files.append(f)
            else:
                hollow_files.append((f, reason))
        elif f.suffix in (".md", ".txt"):
            gen, reason = _is_genuine_md(f)
            if gen:
                genuine_files.append(f)
            else:
                hollow_files.append((f, reason))
        else:
            genuine_files.append(f)

    if genuine_files:
        return SignalResult(
            signal="brain-prime", ok=True,
            reason=f"brain-prime intake ran: {genuine_files[0].name}",
            artifacts=[str(f) for f in genuine_files[:2]],
            detail={"found": [str(f) for f in found]},
        )

    hollow_desc = "; ".join(f"{f.name}: {r}" for f, r in hollow_files[:2])
    hollow_reason = (
        f"brain-prime artifact(s) present but HOLLOW: {hollow_desc} - "
        f"receipt JSON needs schema={_SCHEMA!r}; "
        f"MD report needs >={_MD_MIN} bytes with markers {_MD_MARKERS}"
    )
    if strict:
        return SignalResult(
            signal="brain-prime", ok=False, reason=hollow_reason,
            artifacts=[str(f) for f, _ in hollow_files[:2]],
            detail={"hollow": [f.name for f, _ in hollow_files]},
        )
    return SignalResult(
        signal="brain-prime", ok=True, reason="WARN: " + hollow_reason,
        artifacts=[str(f) for f, _ in hollow_files[:2]],
        detail={"hollow": [f.name for f, _ in hollow_files]},
    )


# --------------------------------------------------------------------------
# Signal (j3): per-function hacker-question artifact exists (ADD-D)
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# per-function-hacker-questions.py emits a caller-named JSONL of adversarial
# per-function questions (schema auditooor.per_fn_hacker_questions.v1). The
# artifact name is caller-chosen, so we match a family of name patterns under
# the workspace and .auditooor/.
# --------------------------------------------------------------------------
def check_hacker_questions(ws: Path) -> SignalResult:
    """Signal (j3): per-function hacker-question artifact exists (ADD-D).

    Prior implementation false-passed on mere file presence: an empty JSONL
    or a minimal {} JSON returned ok=True because only the path was checked.

    Corrected contract (PASS iff the artifact proves the tool ran):
      - JSONL artifacts: >= 1 non-empty line with valid JSON.
      - JSON artifacts: schema or schema_version field contains
        'hacker_questions' (case-insensitive). The per_fn_hacker_questions.v1
        and per_fn_hacker_questions_status.v1 schemas both satisfy this.

    Empty JSONL or {} JSON without hacker_questions schema -> WARN-pass by
    default; fail-closed under AUDITOOOR_L37_HACKER_QUESTIONS_STRICT=1 or
    AUDITOOOR_L37_STRICT=1.
    """
    _SCHEMA_SUBSTR = "hacker_questions"
    a = ws / ".auditooor"
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("HACKER_QUESTIONS")

    def _is_genuine_json(p: Path) -> tuple[bool, str]:
        obj = _load_json(p)
        if not isinstance(obj, dict):
            return False, "unparseable or non-dict JSON"
        schema = str(obj.get("schema") or obj.get("schema_version") or "")
        if _SCHEMA_SUBSTR not in schema.lower():
            return False, (
                f"schema does not reference hacker_questions "
                f"(got {schema!r})"
            )
        return True, ""

    def _is_genuine_jsonl(p: Path) -> tuple[bool, str]:
        txt = _read_text(p)
        if txt is None:
            return False, "unreadable"
        lines = [ln for ln in txt.splitlines() if ln.strip()]
        if not lines:
            return False, "empty JSONL file (0 records)"
        try:
            json.loads(lines[0])
        except (json.JSONDecodeError, ValueError):
            return False, "first line not valid JSON"
        return True, ""

    name_patterns = (
        "per_fn_hacker_questions*", "per-fn-hacker-questions*",
        "per_function_hacker_questions*", "per-function-hacker-questions*",
        "*hacker_questions*", "*hacker-questions*",
    )
    found: list[Path] = []
    for d in (a, ws, ws / "reports"):
        g = _glob_first(d, name_patterns)
        if g is not None and str(g) not in {str(f) for f in found}:
            found.append(g)

    if not found:
        return SignalResult(
            signal="hacker-questions", ok=False,
            reason=(
                "no per-function hacker-question artifact "
                "(per_fn_hacker_questions*.jsonl / *hacker_questions*); "
                "the per-function hacker-question step did not run (ADD-D)"
            ),
            artifacts=[], detail={},
        )

    hollow_files: list[tuple[Path, str]] = []
    genuine_files: list[Path] = []
    for f in found:
        if f.suffix == ".jsonl":
            gen, reason = _is_genuine_jsonl(f)
            if gen:
                genuine_files.append(f)
            else:
                hollow_files.append((f, reason))
        elif f.suffix == ".json":
            gen, reason = _is_genuine_json(f)
            if gen:
                genuine_files.append(f)
            else:
                hollow_files.append((f, reason))
        else:
            genuine_files.append(f)  # other extensions: presence sufficient

    if genuine_files:
        detail: dict[str, Any] = {"found": [str(f) for f in found]}
        for gf in genuine_files:
            if gf.suffix == ".json":
                obj2 = _load_json(gf) or {}
                counts = obj2.get("counts")
                if isinstance(counts, dict):
                    detail["counts"] = counts
                break
        return SignalResult(
            signal="hacker-questions", ok=True,
            reason=f"per-function hacker-question artifact ran: {genuine_files[0].name}",
            artifacts=[str(f) for f in genuine_files[:2]], detail=detail,
        )

    hollow_desc = "; ".join(f"{f.name}: {r}" for f, r in hollow_files[:2])
    hollow_reason = (
        f"hacker-question artifact(s) present but HOLLOW: {hollow_desc} - "
        f"JSON needs schema/schema_version containing {_SCHEMA_SUBSTR!r}; "
        "JSONL needs >= 1 valid JSON record"
    )
    if strict:
        return SignalResult(
            signal="hacker-questions", ok=False, reason=hollow_reason,
            artifacts=[str(f) for f, _ in hollow_files[:2]],
            detail={"hollow": [f.name for f, _ in hollow_files]},
        )
    return SignalResult(
        signal="hacker-questions", ok=True, reason="WARN: " + hollow_reason,
        artifacts=[str(f) for f, _ in hollow_files[:2]],
        detail={"hollow": [f.name for f, _ in hollow_files]},
    )


# --------------------------------------------------------------------------
# Signal: hacker-questions-resolved (F2 E2.1) - the CONTENT sibling of the
# existence-only hacker-questions signal.
# <!-- r36-rebuttal: lane FIX-F2-DONE-GATE registered in .auditooor/agent_pathspec.json -->
#
# hacker-question-obligations.py writes one OPEN row per pre-source-read hacker
# question into <ws>/.auditooor/hacker_question_obligations.jsonl. An obligation
# is genuinely RESOLVED only when it has been driven to a terminal state by
# hacker-question-obligation-resolve.py, which requires an R76-verified
# per-question verdict sidecar. A hand-written state=resolved with NO matching
# verified sidecar is un-fakeable: it counts as still OPEN. This signal FAILS
# under STRICT while any obligation is open, keyed by the row `language` field so
# a Solidity-only resolution can never green a mixed repo's circom/move half.
# --------------------------------------------------------------------------

# Terminal obligation states (the row is genuinely resolved). Mirrors
# hacker-question-obligations.VALID_STATES minus "open", plus the spec's explicit
# {resolved, closed} vocabulary.
_OBLIGATION_TERMINAL_STATES = frozenset(
    {"resolved", "closed", "answered", "killed", "promoted_to_chain", "promoted_to_poc"}
)


def _read_obligations_jsonl(ws: Path) -> list[dict]:
    """Read .auditooor/hacker_question_obligations.jsonl -> list of row dicts.

    Returns [] if the file is absent / unreadable. Skips blank / unparseable
    lines (mirrors hacker-question-obligations.load_obligations)."""
    p = ws / ".auditooor" / "hacker_question_obligations.jsonl"
    txt = _read_text(p)
    if txt is None:
        return []
    rows: list[dict] = []
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _is_corpus_fuel_obligation(row: dict) -> bool:
    """True iff a hacker_question_obligations.jsonl row is a MINED-CORPUS-FUEL lead
    rather than a genuine PER-FUNCTION in-scope-source hacker-Q obligation.

    Root cause (NUVA 2026-07-03): the mined-findings-hunter-bridge appended 500
    mined-corpus leads INTO hacker_question_obligations.jsonl tagged
    `question_source="mined-finding"`, all with the FAKE `function_name=
    "mined_findings_hunter_bridge"` and `file="<workspace>/.auditooor/
    mined_findings_hunter_bridge.json"` (a bridge ARTIFACT, not a source file, with
    the literal unexpanded `<workspace>` placeholder). These are corpus PATTERNS to
    apply against in-scope code - they belong to the CORPUS-conversion track (the
    current-to-exploit conversion-throughput gate, which independently holds them
    accountable), NOT the per-function hacker-Q attestation/resolution track. Left
    mixed in, they inflated the per-fn attestation denominator (647 genuine -> 1147)
    and the per-fn resolution denominator - a double-count, not a real per-fn gap.

    NEVER-FALSE-EXCLUDE (fail-closed): only an UNAMBIGUOUS corpus-fuel marker
    excludes a row. A genuine per-fn obligation carries a real question_source
    (per-fn / rubric / shape / ...) and a real source `file`; it is never dropped.
    The mined-finding leads remain fully accountable under conversion-throughput -
    this only stops them double-counting in the PER-FN gates.
    """
    qsrc = str(row.get("question_source") or "").strip().lower()
    if qsrc == "mined-finding":
        return True
    fn = str(row.get("function_name") or "").strip()
    if fn == "mined_findings_hunter_bridge":
        return True
    f = str(row.get("file") or "")
    if "mined_findings_hunter_bridge" in f or "<workspace>" in f:
        return True
    return False


# Package-manager / vendored-dependency cache path fragments. A per-fn obligation
# whose `file` lives under one of these is a VENDORED third-party dependency (Go module
# cache, npm, cargo, python site-packages), NOT the audited in-scope repo. Per SCOPE.md
# primacy-of-impact, a finding must LAND on an in-scope asset; the mechanism MAY traverse
# vendored code, but hunting the vendored dependency's OWN functions per-fn is out of
# scope (any in-scope impact via it is captured by the in-scope caller's hunt). NUVA
# 2026-07-04: 72 obligations targeted /go/pkg/mod/.../cosmos-sdk@.../baseapp/baseapp.go
# (ProcessProposalVerifyTx / SetCircuitBreaker / AnteHandler / AddRunTxRecoveryHandler) -
# vendored Provenance-fork cosmos-sdk, OOS.
_VENDORED_PATH_FRAGMENTS = (
    "/go/pkg/mod/", "/node_modules/", "/.cargo/registry/",
    "/site-packages/", "/vendor/",
)


def _is_oos_vendored_obligation(row: dict) -> bool:
    """True iff the obligation's `file` is under a package-manager / vendored-dependency
    cache path (a third-party dep, not the in-scope repo). NEVER-FALSE-EXCLUDE: only an
    UNAMBIGUOUS vendored-cache path fragment excludes a row; an in-scope src/ file is
    never dropped."""
    f = str(row.get("file") or "").replace("\\", "/")
    return any(frag in f for frag in _VENDORED_PATH_FRAGMENTS)


def _read_per_fn_obligations_jsonl(ws: Path) -> list[dict]:
    """`_read_obligations_jsonl` with the corpus-fuel mined-finding leads removed. This is
    the ATTESTATION-COUNT denominator: it must match the step-0f attestation's claimed
    per-fn total, which counted every genuine per-fn obligation INCLUDING those whose
    mechanism traverses a vendored dependency. (Corpus-fuel stays accountable under the
    conversion-throughput gate.)"""
    return [r for r in _read_obligations_jsonl(ws) if not _is_corpus_fuel_obligation(r)]


def _read_inscope_per_fn_obligations_jsonl(ws: Path) -> list[dict]:
    """`_read_per_fn_obligations_jsonl` with vendored-dependency (OOS) rows ALSO removed.
    This is the HACKER-Q-RESOLUTION denominator: a vendored third-party function
    (/go/pkg/mod/.../baseapp.go) is OUT OF SCOPE, so it does not need an in-scope
    per-fn verdict sidecar (any in-scope impact via it is captured by the in-scope
    caller's hunt). Distinct from the attestation-count denominator, which keeps the
    vendored rows so the recomputed total still matches the step-0f attestation claim."""
    return [r for r in _read_per_fn_obligations_jsonl(ws)
            if not _is_oos_vendored_obligation(r)]


def _verified_sidecar_index(ws: Path):
    """Return the resolver's VERIFIED-sidecar index (by_qid, by_file_fn) so a
    terminal-status row is only credited when a real R76-verified verdict sidecar
    backs it (un-fakeable). On any import / runtime error returns ({}, {}) so the
    caller falls back to the row-state check alone (fail-open on tool error, never
    a false-green: missing index just means terminal rows need a real state, which
    is the weaker but still-honest check)."""
    try:
        tool = Path(__file__).resolve().with_name("hacker-question-obligation-resolve.py")
        spec = importlib.util.spec_from_file_location("_hqor_l37", str(tool))
        if spec is None or spec.loader is None:
            return {}, {}
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        by_qid, by_file_fn, _accepted, _rejected = mod._build_sidecar_index(ws, None)
        return by_qid, by_file_fn

    except Exception:
        return {}, {}


def _obligation_has_verified_sidecar(ob: dict, by_qid: dict, by_file_fn: dict) -> bool:
    """True iff a VERIFIED verdict sidecar matches this obligation (by
    obligation_id == sidecar.question_id, else by (file, function_name) tried exact
    THEN by basename). The basename fallback MUST mirror the resolver's
    hacker-question-obligation-resolve._match_obligation: the sidecar index
    (_build_sidecar_index) keys by_file_fn under BOTH (abs_path, fn) AND (basename, fn),
    and an obligation often anchors a RELATIVE path while a hunt sidecar's
    function_anchor is ABSOLUTE. Without the basename fallback here, the GATE credited
    FEWER obligations than the standalone resolver flipped to terminal - producing a
    permanent false-red fail-open-hacker-questions (axelar-dlt 2026-07-12: resolver
    state=9 open, but this gate counted 53 open because 53 resolver-credited rows only
    matched by basename). R76-verification still gates the index, so basename-matching
    a verified sidecar is un-fakeable."""
    oid = str(ob.get("obligation_id", "")).strip()
    if oid and oid in by_qid:
        return True
    f = str(ob.get("file", "")).strip()
    fn = str(ob.get("function_name", "")).strip() or str(ob.get("function_signature", "")).strip()
    if f and fn:
        if (f, fn) in by_file_fn:
            return True
        base = f.replace("\\", "/").split("/")[-1]
        if base and (base, fn) in by_file_fn:
            return True
    return False


def _corpus_hunt_grounded(ws: Path) -> tuple[bool, int]:
    """True iff a NON-VACUOUS corpus-driven-hunt ran for this workspace:
    <ws>/.auditooor/corpus_driven_hunt.json exists with >=1 hypothesis carrying real
    in-target evidence (an anchored corpus invariant).

    This is the DESIGNED resolution path for ADVISORY corpus_mined_finding
    obligations ("does this known bug-class apply on the target's in-scope code"):
    they are answered by grounding the corpus against target source + hunting the
    grounded leads, NOT by a per-question source sidecar (their `file` is the corpus
    artifact, not a source unit, so a per-question sidecar can never match). When the
    grounding did NOT run, advisory obligations stay OPEN (the lessons were not
    checked) - so this is not a free pass. Returns (grounded, n_anchored)."""
    p = ws / ".auditooor" / "corpus_driven_hunt.json"
    txt = _read_text(p)
    if txt is None:
        return False, 0
    try:
        d = json.loads(txt)
    except (json.JSONDecodeError, ValueError):
        return False, 0
    hyps = d.get("hypotheses") if isinstance(d, dict) else (d if isinstance(d, list) else [])
    if not isinstance(hyps, list):
        return False, 0
    anchored = sum(1 for h in hyps
                   if isinstance(h, dict) and h.get("in_target_evidence"))
    return anchored > 0, anchored


# E6 (enforcement id17, 2026-07-03): revalidate a not-applicable/ABSENT credit
# against CURRENT source. The NOT-APPLICABLE auto-disposition credits an
# obligation because its anchored function is claimed ABSENT from this workspace
# (a cross-engagement corpus mis-anchor). But that note is STICKY: if the source
# later grows the function (or the anchor was wrong and the fn was here all
# along), the sticky note keeps crediting a fn that IS present - a stale credit.
# NUVA: 58 rows credited FromUnderlyingAssetAmount @ valuation_engine.go:135 and
# CalculateAUMFee @ interest.go:87 as "absent" while both ARE defined in-scope;
# 72 OTHER rows correctly credit vendored cosmos-sdk fns (~/go/pkg/mod) that are
# genuinely out-of-tree. This helper reopens ONLY the stale ones (cited fn present
# in an in-WORKSPACE source file), keeping genuinely-absent / vendored-OOS credits.
_NOTAPPLICABLE_REVALIDATE_STRICT_ENV = "AUDITOOOR_NOTAPPLICABLE_REVALIDATE_STRICT"

# Function-definition shapes across the supported source languages. Presence is a
# definition (not merely a mention), so a call-site or comment does not count.
_FN_DEF_PATTERNS = (
    # Go: func Name( / func (r Recv) Name(
    r"func\s+(?:\([^)]*\)\s*)?{name}\s*\(",
    # Solidity / Vyper: function Name( ; Vyper def Name(
    r"function\s+{name}\s*\(",
    r"\bdef\s+{name}\s*\(",
    # Rust: fn Name( / pub fn Name(
    r"\bfn\s+{name}\s*\(",
    # generic decl fallback: `Name(` preceded by a def-ish keyword handled above;
    # also match TS/JS `Name(` after function/const-arrow is covered by def/function.
)


def _fn_present_in_workspace_source(ws: Path, ob: dict) -> bool:
    """True iff the obligation's cited function is DEFINED in an in-WORKSPACE
    source file. Reopen-only when True: a vendored / genuinely-absent anchor (file
    outside the workspace tree, e.g. ~/go/pkg/mod, or a symbol not defined
    anywhere in-scope) stays credited. Conservative: on any read error or an
    un-namable function, returns False (keep the existing credit; never
    false-reopen)."""
    fn = str(ob.get("function_name") or "").strip()
    if not fn or not re.match(r"^[A-Za-z_]\w*$", fn):
        # function_signature is often a hash / shape id, not a real symbol - a
        # non-identifier is not something we can source-grep, so do not reopen.
        return False
    cited = str(ob.get("file", "")).replace("\\", "/")
    ws_str = str(ws).replace("\\", "/")
    # Candidate files: the cited file IF it lives inside the workspace tree, else
    # (cited file is vendored/absent) do NOT search - a vendored anchor is exactly
    # the genuinely-absent class we must keep credited.
    cand: Path | None = None
    if cited:
        cp = Path(cited)
        try:
            in_ws = str(cp.resolve()).replace("\\", "/").startswith(
                ws_str.rstrip("/") + "/") or cited.startswith(ws_str)
        except OSError:
            in_ws = cited.startswith(ws_str)
        if in_ws and _is_file(cp):
            cand = cp
    if cand is None:
        return False
    txt = _read_text(cand)
    if txt is None:
        return False
    for pat in _FN_DEF_PATTERNS:
        try:
            if re.search(pat.format(name=re.escape(fn)), txt):
                return True
        except re.error:
            continue
    return False


def check_hacker_questions_resolved(ws: Path) -> SignalResult:
    """Signal (F2 E2.1): every hacker-question obligation driven to a terminal,
    sidecar-backed verdict.

    PASS (default): the obligations file is absent / 0 rows (no debt), or every
    row is terminal AND backed by a verified sidecar.
    Under STRICT (AUDITOOOR_L37_HACKER_QUESTIONS_RESOLVED_STRICT=1 or the global
    AUDITOOOR_L37_STRICT=1): FAIL when any row is open (state not terminal) OR
    carries a terminal state with NO verified verdict sidecar. WARN-passes the
    same conditions outside STRICT so the backlog is surfaced without bricking a
    non-strict run.

    Keyed by the row `language` field: the failing-language breakdown is recorded
    in detail so no language is silently skipped by a single-language filter."""
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("HACKER_QUESTIONS_RESOLVED")
    # IN-SCOPE PER-FN denominator: exclude BOTH mined-finding corpus-fuel (corpus-track,
    # accountable under conversion-throughput) AND vendored-dependency OOS rows (a
    # /go/pkg/mod/.../baseapp.go function is out of scope and needs no in-scope per-fn
    # verdict). NUVA 2026-07-03/04: 500 corpus leads + 72 vendored baseapp inflated the
    # resolution denominator from 575 genuine in-scope -> 1147.
    rows = _read_inscope_per_fn_obligations_jsonl(ws)
    if not rows:
        return SignalResult(
            signal="hacker-questions-resolved", ok=True,
            reason=("no hacker_question_obligations.jsonl rows (no per-fn hacker-Q "
                    "obligations to resolve)"),
            artifacts=[], detail={"rows": 0},
        )

    by_qid, by_file_fn = _verified_sidecar_index(ws)
    _grounded, _n_anchored = _corpus_hunt_grounded(ws)

    # An obligation is OPEN (unresolved) when its state is non-terminal OR it
    # claims a terminal state but has no verified sidecar (un-fakeable).
    # E6: when the dedicated env is set, a not-applicable/ABSENT credit is
    # re-validated against current source; a cited fn that IS present in-workspace
    # is a STALE credit and gets reopened.
    # DEFAULT-ON graduation (2026-07-03): the revalidation now defaults ENFORCED
    # under the L37 strict umbrella (what `make audit-complete STRICT=1` exports),
    # with a per-gate OPT-OUT via AUDITOOOR_NOTAPPLICABLE_REVALIDATE_STRICT=0. A
    # bare non-strict / library caller (L37 unset) trusts the sticky note exactly
    # as before (advisory), so no unrelated caller reopens rows. The reopen /
    # presence logic below is unchanged (NEVER-FALSE-PASS preserved).
    _notapplicable_revalidate = _gate_default_on_strict(
        _NOTAPPLICABLE_REVALIDATE_STRICT_ENV)
    stale_reopened = 0
    stale_rows: list[dict] = []
    open_by_lang: dict[str, int] = {}
    open_rows: list[dict] = []
    terminal_rows = 0
    grounding_resolved = 0
    for ob in rows:
        state = str(ob.get("state") or ob.get("status") or "open").strip().lower()
        is_terminal = state in _OBLIGATION_TERMINAL_STATES
        has_sidecar = _obligation_has_verified_sidecar(ob, by_qid, by_file_fn)
        # A matching R76-VERIFIED sidecar IS the un-fakeable resolution, regardless of
        # the obligation's `state` field. The pipeline REGENERATES obligations (state
        # resets to `open`) each `make audit` / dataflow re-emit, and the standalone
        # resolver that flips state -> terminal runs OUTSIDE this gate - so within a
        # single `make audit-complete` run the freshly-regenerated obligations are
        # state=open even though their verified sidecars are already on disk. Crediting
        # only `is_terminal AND has_sidecar` counted them OPEN and produced a permanent
        # false-red fail-open-hacker-questions (nuva/axelar-dlt/axelar-sc 2026-07-12:
        # standalone resolve => 0 open, but the in-pipeline gate => fail-open every run).
        # Credit on has_sidecar (the same _verified_sidecar_index the resolver uses, so
        # NEVER-FALSE-PASS: a hand-set terminal WITHOUT a real sidecar still falls
        # through to OPEN below). Scope the state-independent credit to GENUINE per-fn
        # source obligations: advisory / corpus-mined / agent-artifact lessons keep
        # their original is_terminal-gated path (they resolve via the corpus-driven-hunt
        # grounding branch below, NOT a per-question source sidecar).
        _genuine_perfn = (
            not ob.get("advisory_only")
            and str(ob.get("source_kind", "")) not in (
                "corpus_mined_finding", "agent_artifact_lesson_candidate")
        )
        if has_sidecar and (is_terminal or _genuine_perfn):
            terminal_rows += 1
            continue
        # ADVISORY artifact-derived lessons are answered by the corpus-driven-hunt
        # grounding (their `file` is a corpus/agent artifact, NOT an in-scope source
        # unit, so a per-question source sidecar can NEVER match). This covers BOTH
        # `corpus_mined_finding` (solodit/corpus lessons) AND
        # `agent_artifact_lesson_candidate` (mined-findings-hunter-bridge lessons):
        # same advisory class, same artifact-file shape, same resolution path. Keying
        # only on source_kind=="corpus_mined_finding" left the 36 agent-artifact
        # lessons permanently OPEN (near-intents 2026-06-26) even though their file
        # (.auditooor/mined_findings_hunter_bridge.json) is an artifact a sidecar can
        # never anchor. Count resolved ONLY when a non-vacuous corpus-driven-hunt ran;
        # if it did not, they fall through to OPEN (not a free pass). Gated on
        # advisory_only + a non-source artifact `file` so a genuine source-unit
        # obligation is never grounding-credited.
        _ob_file = str(ob.get("file", "")).replace("\\", "/")
        _is_artifact_file = (
            "/.auditooor/" in _ob_file
            or _ob_file.startswith("<workspace>")
            or "mined_findings" in _ob_file
            or not re.search(r"\.(rs|sol|go|cairo|move|circom|ts|js|py)$", _ob_file)
        )
        if (ob.get("advisory_only") is True
                and str(ob.get("source_kind", "")) in (
                    "corpus_mined_finding", "agent_artifact_lesson_candidate")
                and _is_artifact_file
                and _grounded):
            grounding_resolved += 1
            continue
        # AUTO-COVERAGE-CLOSER ADVISORY FOLDS: needs-fuzz hypotheses emitted by the
        # net-new/general-logic advisory screens (auto-coverage-closer._seed_advisory_
        # obligations; source_kind=auto_coverage_closer_advisory_fold, advisory_only=True).
        # Unlike the corpus-mined/agent-artifact class above, these fold rows legitimately
        # anchor a REAL in-scope source file (they came from a source-walking screen), so
        # `_is_artifact_file` is False for them - yet they are still ADVISORY corpus-fuel
        # answered by the corpus-driven-hunt GROUNDING, NOT by a per-question source
        # sidecar (needs-fuzz fuel, never a discrete hunt verdict). Credit them on the
        # SAME grounding evidence the class above requires (_grounded => a non-vacuous
        # corpus-driven-hunt ran); if grounding did NOT run they fall through to OPEN
        # (not a free pass). NEVER-FALSE-PASS: gated on the closer's OWN explicit advisory
        # tag (advisory_only + this exact source_kind), which only _seed_advisory_
        # obligations stamps - a genuine per-fn source obligation is untagged and can
        # never reach this credit (it still needs a real per-fn verdict sidecar). Fixes
        # axelar-dlt 2026-07-13: 9 folds neither grounding- nor sidecar-credited => a
        # permanent fail-open-hacker-questions with no resolving branch.
        if (ob.get("advisory_only") is True
                and str(ob.get("source_kind", "")) == "auto_coverage_closer_advisory_fold"
                and _grounded):
            grounding_resolved += 1
            continue
        # NOT-APPLICABLE auto-disposition: an obligation auto-resolved by
        # hacker-question-obligation-resolve because its anchored file/function is
        # ABSENT from this workspace (a cross-engagement corpus mis-anchor: vendored
        # upstream dep in ~/go/pkg/mod, or a function-shape match whose symbol is not
        # actually here). It is terminal-by-design and a SOURCE sidecar can NEVER
        # anchor (the code is not in the workspace to verify) - exactly like the
        # advisory-grounding class above. Credit it ONLY when the terminal state
        # carries the resolver's documented auto-disposition note. NEVER-FALSE-PASS:
        # a genuinely-open / un-disposed obligation has no such note; only the
        # resolver writes it, and only for an absent-from-workspace anchor.
        if is_terminal and "auto-resolved not-applicable" in str(ob.get("operator_notes", "")):
            # E6 revalidation: a not-applicable credit is only honest while the
            # cited function is genuinely ABSENT. Under the dedicated env, if the
            # function IS present in an in-workspace source file, the "absent"
            # premise is FALSE and the credit is STALE - reopen the row (fall
            # through to open-handling). Vendored / genuinely-absent anchors
            # (cited file outside the workspace, or symbol not defined in-scope)
            # are NOT reopened - _fn_present_in_workspace_source returns False for
            # them, so they stay credited. Env-unset: the branch credits exactly
            # as before (byte-identical).
            if _notapplicable_revalidate and _fn_present_in_workspace_source(ws, ob):
                stale_reopened += 1
                if len(stale_rows) < 20:
                    stale_rows.append({
                        "obligation_id": str(ob.get("obligation_id", "")),
                        "function_name": str(ob.get("function_name", "")),
                        "file": str(ob.get("file", "")),
                    })
                # do NOT continue: fall through so this row is counted OPEN below.
            else:
                grounding_resolved += 1
                continue
        # open: either non-terminal, or terminal-without-verified-sidecar
        lang = str(ob.get("language") or "unknown").strip().lower() or "unknown"
        open_by_lang[lang] = open_by_lang.get(lang, 0) + 1
        if len(open_rows) < 20:
            open_rows.append({
                "obligation_id": str(ob.get("obligation_id", "")),
                "state": state,
                "language": lang,
                "has_verified_sidecar": has_sidecar,
            })

    n_open = sum(open_by_lang.values())
    obl_path = str(ws / ".auditooor" / "hacker_question_obligations.jsonl")

    if n_open == 0:
        return SignalResult(
            signal="hacker-questions-resolved", ok=True,
            reason=(f"all {len(rows)} hacker-question obligation(s) resolved: "
                    f"{terminal_rows} sidecar-backed + {grounding_resolved} advisory "
                    f"corpus-mined answered by a non-vacuous corpus-driven-hunt "
                    f"({_n_anchored} anchored)"),
            artifacts=[obl_path],
            detail={"rows": len(rows), "resolved": terminal_rows,
                    "resolved_by_grounding": grounding_resolved, "open": 0,
                    "stale_not_applicable_reopened": stale_reopened,
                    "notapplicable_revalidate": _notapplicable_revalidate},
        )

    lang_desc = ", ".join(f"{k}={v}" for k, v in sorted(open_by_lang.items()))
    _stale_note = (
        f"; {stale_reopened} STALE not-applicable credit(s) reopened by E6 "
        f"(cited fn is PRESENT in-scope, not absent)" if stale_reopened else "")
    # If the open rows are advisory corpus-mined lessons and the grounding did NOT
    # run, the remediation is the corpus-driven-hunt, not per-question sidecars.
    _fix = (f"run `make corpus-driven-hunt WS={ws} EMIT_PROOF_QUEUE=1` (advisory "
            "corpus-mined lessons resolve via grounding)") if not _grounded else (
            f"run `python3 tools/hacker-question-obligation-resolve.py --workspace "
            f"{ws}` after a real per-fn hunt produces verdict sidecars")
    reason = (
        f"{n_open} of {len(rows)} hacker-question obligation(s) still OPEN (no "
        f"terminal verified verdict sidecar) by language: {lang_desc}{_stale_note}; {_fix}"
    )
    detail = {
        "rows": len(rows),
        "resolved": terminal_rows,
        "resolved_by_grounding": grounding_resolved,
        "corpus_hunt_grounded": _grounded,
        "open": n_open,
        "open_by_language": open_by_lang,
        "open_sample": open_rows,
        "stale_not_applicable_reopened": stale_reopened,
        "stale_not_applicable_sample": stale_rows,
        "notapplicable_revalidate": _notapplicable_revalidate,
    }
    if strict:
        return SignalResult(
            signal="hacker-questions-resolved", ok=False, reason=reason,
            artifacts=[obl_path], detail=detail,
        )
    return SignalResult(
        signal="hacker-questions-resolved", ok=True, reason="WARN: " + reason,
        artifacts=[obl_path], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (E5): attestation-count integrity + KILL disposition-distinctness.
#
# THE HONESTY BUG (operator-caught NUVA 2026-07-03, id22): two independent
# credit-leaks let a step-0f attestation green a per-fn hacker-Q hunt that was
# NOT actually driven to a resolved terminal state:
#
#  (1) attestation-count-mismatch: a step attestation payload
#      (.auditooor/attestations/step-*.json) carries a free-text `summary` /
#      `note` claiming "N obligations, all resolved" whose N MATCHES NO artifact
#      on disk. NUVA's step-0f claimed "647 obligations, all resolved" while
#      hacker_question_obligations.jsonl actually holds 1147 rows (killed=517,
#      answered=130, open=500). The attestation gate (readme-attestation-check)
#      only verifies the VERBATIM runbook text, never the CLAIMED NUMBER against
#      the artifact - so a wrong count sails through. This signal RECOMPUTES the
#      obligation total from the artifact and flags any attestation whose claimed
#      obligation-count does not match the recomputed total.
#
#  (2) KILL-only-no-reason: a per-fn hacker-Q verdict cluster
#      (.auditooor/hacker_question_verdicts/*.json) that is 100% KILL with a
#      large fraction of EMPTY `reason` fields is not a terminal adjudication -
#      a bucket of reasonless KILLs is "couldn't/didn't drive it", not "refuted
#      with evidence". NUVA: 575/575 KILL, 264 with an empty reason. Closing a
#      cell is a claim of ABSENCE and must carry a per-row reason, exactly like
#      the disposition-distinctness guard requires a cited reason for a NEGATIVE
#      finding kill. (Complements disposition-distinctness-guard.py --sweep,
#      which reads oos_check_*/mechanism_dispositions/known_dead_ends but NOT the
#      hacker_question_verdicts KILL cluster.)
#
# The "500 open greened via grounding" leg is BY DESIGN (advisory corpus-mined
# lessons resolve via the corpus-driven-hunt, not per-question sidecars) - this
# signal does NOT re-red that; only the false attestation TOTAL and the
# KILL-only-EMPTY-reason cluster are enforceable defects here.
#
# DEFAULT-ON (graduation 2026-07-03, operator decision explicitly overriding the
# prior "never retro-red a parked audit" default-OFF doctrine): the gate ENFORCES
# by default whenever the strict audit runs (under AUDITOOOR_L37_STRICT, which
# `make audit-complete STRICT=1` always sets), with a per-gate OPT-OUT via
# AUDITOOOR_ATTESTATION_COUNT_STRICT=0. A bare non-strict / library caller (L37
# unset) keeps advisory WARN-pass so no unrelated tool breaks. The predicate is
# the shared _gate_default_on_strict(); the DEFECT logic below is unchanged
# (NEVER-FALSE-PASS preserved - only WHEN it hard-fails moved). Rebuttal key:
# ``attestation-count-integrity:``.
# --------------------------------------------------------------------------
_ATTESTATION_COUNT_STRICT_ENV = "AUDITOOOR_ATTESTATION_COUNT_STRICT"

# Fraction of KILL verdicts that may carry an empty reason before the cluster is
# flagged as a non-terminal KILL-only bucket. A handful of empty reasons is
# tolerable noise; a large fraction (NUVA: 264/575 = 46%) is the defect.
_KILL_EMPTY_REASON_FRACTION = 0.20
# Minimum KILL-cluster size before the empty-reason fraction is meaningful (a
# 2-row cluster with 1 empty reason is not a systemic KILL-only bucket).
_KILL_CLUSTER_MIN = 10
# Regex to pull an obligation-count claim out of an attestation free-text field.
_ATTEST_OBLIGATION_COUNT_RE = re.compile(r"(\d+)\s+obligation", re.IGNORECASE)


def _attestation_obligation_claims(ws: Path) -> list[dict]:
    """Scan .auditooor/attestations/step-*.json for free-text summary/note fields
    that claim "<N> obligations" and return [{"step","claimed","path"}]. Only the
    NUMERIC claim is extracted; the mismatch is decided by the caller against the
    recomputed artifact total. Absent dir / unparseable file -> [] (no claim to
    check, no false-red)."""
    out: list[dict] = []
    adir = ws / ".auditooor" / "attestations"
    if not _exists(adir) or not adir.is_dir():
        return out
    try:
        files = sorted(adir.glob("step-*.json"))
    except OSError:
        return out
    for fp in files:
        txt = _read_text(fp)
        if txt is None:
            continue
        try:
            d = json.loads(txt)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        blob = " ".join(
            str(d.get(k, "")) for k in ("summary", "note", "notes", "detail")
        )
        m = _ATTEST_OBLIGATION_COUNT_RE.search(blob)
        if not m:
            continue
        out.append({
            "step": str(d.get("step") or d.get("step_id") or fp.stem),
            "claimed": int(m.group(1)),
            "path": str(fp),
        })
    return out


def _kill_only_no_reason_cluster(ws: Path) -> dict:
    """Inspect .auditooor/hacker_question_verdicts/*.json. Return
    {"total","kill","empty_reason","empty_fraction","flagged"} where `flagged` is
    True iff the cluster is a KILL-dominated bucket (>= _KILL_CLUSTER_MIN KILLs)
    with an empty-reason fraction >= _KILL_EMPTY_REASON_FRACTION. A reason counts
    as present when any of the row's reason-carrying fields is non-blank (mirrors
    the disposition-distinctness reason-field set). Absent dir -> not flagged."""
    out = {"total": 0, "kill": 0, "empty_reason": 0, "empty_fraction": 0.0,
           "flagged": False}
    vdir = ws / ".auditooor" / "hacker_question_verdicts"
    if not _exists(vdir) or not vdir.is_dir():
        return out
    try:
        files = sorted(vdir.glob("*.json"))
    except OSError:
        return out
    for fp in files:
        txt = _read_text(fp)
        if txt is None:
            continue
        try:
            d = json.loads(txt)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        out["total"] += 1
        verdict = str(d.get("verdict") or d.get("state") or "").strip().upper()
        if verdict not in ("KILL", "KILLED"):
            continue
        out["kill"] += 1
        reason = ""
        for k in ("reason", "reasoning", "kill_reason", "justification",
                  "rationale"):
            v = d.get(k)
            if isinstance(v, str) and v.strip():
                reason = v.strip()
                break
        if not reason:
            out["empty_reason"] += 1
    if out["kill"] >= _KILL_CLUSTER_MIN:
        out["empty_fraction"] = out["empty_reason"] / out["kill"]
        # KILL-dominated bucket: the verdict cluster is (almost) entirely KILL.
        kill_dominated = out["total"] > 0 and (out["kill"] / out["total"]) >= 0.90
        out["flagged"] = bool(
            kill_dominated and out["empty_fraction"] >= _KILL_EMPTY_REASON_FRACTION
        )
    return out


def check_attestation_count_integrity(ws: Path) -> SignalResult:
    """Signal (E5): a step attestation must not claim an obligation total that
    contradicts the artifact, and a KILL-only verdict cluster must carry per-row
    reasons.

    PASS (default): no attestation obligation-count claim mismatches the
    recomputed total AND the KILL verdict cluster is not a reasonless bucket.
    DEFAULT-ON graduation (2026-07-03): AUDITOOOR_ATTESTATION_COUNT_STRICT now
    defaults ENFORCED under the L37 strict umbrella (what `make audit-complete
    STRICT=1` exports), with a per-gate opt-out via
    AUDITOOOR_ATTESTATION_COUNT_STRICT=0. A bare non-strict / library caller
    (L37 unset) still WARN-passes (advisory-first); under strict a mismatch OR a
    flagged KILL-only-no-reason cluster FAILs."""
    strict = _gate_default_on_strict(_ATTESTATION_COUNT_STRICT_ENV)
    # PER-FN denominator (see _read_per_fn_obligations_jsonl): the step-0f attestation
    # counts GENUINE per-fn hacker-Q obligations. The mined-finding corpus-fuel leads that
    # the bridge appended to the same file (question_source=mined-finding, artifact file)
    # are a different class - counting them here fabricated a 647-vs-1147 mismatch where the
    # 647 was the correct genuine per-fn total. They stay accountable under conversion-throughput.
    rows = _read_per_fn_obligations_jsonl(ws)
    recomputed = len(rows)
    claims = _attestation_obligation_claims(ws)
    mismatches = [c for c in claims if c["claimed"] != recomputed]
    kill_cluster = _kill_only_no_reason_cluster(ws)

    obl_path = str(ws / ".auditooor" / "hacker_question_obligations.jsonl")
    detail = {
        "recomputed_obligation_rows": recomputed,
        "attestation_claims": claims,
        "attestation_count_mismatches": mismatches,
        "kill_cluster": kill_cluster,
        "strict": strict,
        "strict_env": _ATTESTATION_COUNT_STRICT_ENV,
    }

    # Nothing to check: no attestation count claim AND no verdict cluster on disk.
    if not claims and kill_cluster["total"] == 0:
        return SignalResult(
            signal="attestation-count-integrity", ok=True,
            reason=("no step-attestation obligation-count claim and no "
                    "hacker_question_verdicts cluster to audit (no debt)"),
            artifacts=[], detail=detail,
        )

    problems: list[str] = []
    if mismatches:
        for c in mismatches:
            problems.append(
                f"attestation-count-mismatch: step {c['step']} attestation claims "
                f"{c['claimed']} obligation(s) but hacker_question_obligations.jsonl "
                f"has {recomputed} row(s)"
            )
    if kill_cluster["flagged"]:
        problems.append(
            f"KILL-only-no-reason: {kill_cluster['kill']} of "
            f"{kill_cluster['total']} hacker-Q verdicts are KILL and "
            f"{kill_cluster['empty_reason']} carry an EMPTY reason "
            f"({kill_cluster['empty_fraction']:.0%} of KILLs) - a reasonless KILL "
            "bucket is not a terminal adjudication"
        )

    if not problems:
        return SignalResult(
            signal="attestation-count-integrity", ok=True,
            reason=(f"attestation obligation-count(s) match the {recomputed}-row "
                    f"artifact and the KILL verdict cluster carries per-row reasons "
                    f"({kill_cluster['kill']} kills, "
                    f"{kill_cluster['empty_reason']} empty)"),
            artifacts=[obl_path], detail=detail,
        )

    reason = "; ".join(problems) + (
        "; recompute the attestation total from the artifact and add a per-row "
        "reason to each KILL verdict (an empty-reason KILL is not a resolution)"
    )
    if strict:
        return SignalResult(
            signal="attestation-count-integrity", ok=False, reason=reason,
            artifacts=[obl_path], detail=detail,
        )
    return SignalResult(
        signal="attestation-count-integrity", ok=True, reason="WARN: " + reason,
        artifacts=[obl_path], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal: provider-liveness (F2 E2.4) - a dead/401/402 hunt provider with OPEN
# hacker-Q obligations is a RED gate, not a silent skip.
# <!-- r36-rebuttal: lane FIX-F2-DONE-GATE registered in .auditooor/agent_pathspec.json -->
#
# A dead provider (e.g. kimi 401/402) produces empty hunts that get treated as
# "examined, 0 findings". If there are OPEN obligations AND the configured hunt
# provider is unusable, the obligations can never be honestly resolved. This
# reuses tools/llm-preflight-auth.py (the same readiness check audit-closeout
# already probes for) to detect the dead provider and fires a RED gate.
#
# Offline / test-safe: invoked with --dry-run (no network) so a missing key
# surfaces as unusable; the AUDITOOOR_L37_PROVIDER_LIVENESS_VERDICT env seam lets
# a caller (or test) inject "usable" / "dead" without any provider call.
# --------------------------------------------------------------------------
_HUNT_PROVIDER_ENV = "AUDITOOOR_HUNT_PROVIDER"
_PROVIDER_LIVENESS_VERDICT_ENV = "AUDITOOOR_L37_PROVIDER_LIVENESS_VERDICT"


def _configured_hunt_provider() -> str:
    """The provider the canonical hunt would dispatch to. Resolved from
    AUDITOOOR_HUNT_PROVIDER; defaults to 'all' (probe every known provider) so the
    gate is not silently keyed to one missing-by-default provider."""
    prov = os.environ.get(_HUNT_PROVIDER_ENV, "").strip().lower()
    return prov or "all"


def _provider_usable_via_preflight(provider: str) -> tuple[bool, str]:
    """Run tools/llm-preflight-auth.py --dry-run --json for `provider` and return
    (usable, error_class). Reuses the invocation surface audit-closeout-check.py
    probes for. Offline: --dry-run never contacts a provider; a no-key state still
    reports unusable for an explicit single provider. On any tool error returns
    (True, 'preflight-unavailable') so a missing tool cannot brick the gate
    (fail-open: the OTHER F2 gates still enforce obligation resolution)."""
    # Test / caller seam: an explicit verdict env short-circuits the subprocess.
    forced = os.environ.get(_PROVIDER_LIVENESS_VERDICT_ENV, "").strip().lower()
    if forced in ("usable", "ok", "live", "1", "true"):
        return True, "forced-usable"
    if forced in ("dead", "down", "401", "402", "no-key", "0", "false"):
        return False, f"forced-{forced}"

    tool = Path(__file__).resolve().with_name("llm-preflight-auth.py")
    if not _exists(tool):
        return True, "preflight-unavailable"
    args = [sys.executable, str(tool), "--dry-run", "--json", "--provider", provider]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=20)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return True, f"preflight-error:{type(exc).__name__}"
    # Parse the per-provider JSON records; the gate is "dead" iff EVERY probed
    # provider is unusable (no usable hunt path exists at all).
    any_usable = False
    saw_record = False
    worst_err = "unknown"
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(rec, dict) or "usable" not in rec:
            continue
        saw_record = True
        if rec.get("usable"):
            any_usable = True
        else:
            worst_err = str(rec.get("error_class") or worst_err)
    if not saw_record:
        return True, "preflight-no-records"
    return any_usable, ("usable" if any_usable else worst_err)


def check_provider_liveness(ws: Path) -> SignalResult:
    """Signal (F2 E2.4): the configured hunt provider must be live when there are
    OPEN hacker-Q obligations.

    PASS when there are no open obligations (nothing to hunt) OR the configured
    provider is usable. FAILS `fail-llm-provider-dead` when open obligations exist
    AND the provider is dead (401/402/no-key) - a dead provider silently producing
    empty hunts must not be mis-credited as 'examined, 0 findings'.

    Advisory by default; hard-fails under STRICT
    (AUDITOOOR_L37_PROVIDER_LIVENESS_STRICT=1 or the global AUDITOOOR_L37_STRICT=1)
    so the dead-provider state only reds a strict run."""
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("PROVIDER_LIVENESS")
    rows = _read_obligations_jsonl(ws)
    open_rows = [
        r for r in rows
        if str(r.get("state") or r.get("status") or "open").strip().lower()
        not in _OBLIGATION_TERMINAL_STATES
    ]
    if not open_rows:
        return SignalResult(
            signal="provider-liveness", ok=True,
            reason="no open hacker-Q obligations; provider-liveness not gating",
            artifacts=[], detail={"open_obligations": 0},
        )

    provider = _configured_hunt_provider()
    usable, err = _provider_usable_via_preflight(provider)
    detail = {
        "open_obligations": len(open_rows),
        "provider": provider,
        "usable": usable,
        "error_class": err,
    }
    if usable:
        return SignalResult(
            signal="provider-liveness", ok=True,
            reason=(f"{len(open_rows)} open obligation(s) but the configured hunt "
                    f"provider ({provider}) is usable ({err})"),
            artifacts=[], detail=detail,
        )

    reason = (
        f"configured hunt provider ({provider}) is DEAD ({err}) while "
        f"{len(open_rows)} hacker-Q obligation(s) are still OPEN - a dead provider "
        "produces empty hunts mis-credited as 'examined, 0 findings'; restore the "
        "provider credential (AUDITOOOR_HUNT_PROVIDER / settings) before resolving "
        "obligations"
    )
    if strict:
        return SignalResult(
            signal="provider-liveness", ok=False, reason=reason,
            artifacts=[], detail=detail,
        )
    return SignalResult(
        signal="provider-liveness", ok=True, reason="WARN: " + reason,
        artifacts=[], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (h2): advisory-corpus completeness - published == corpus record count
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# The Zebra 4-of-25 false-clean: an advisory miner emitted records for only 4
# of the 25 published advisories yet the workspace looked "originality-clean".
# This signal requires a per-workspace advisory-parity ledger declaring
# published_advisory_count and corpus_advisory_record_count, and FAILS unless
# they are equal (corpus covers every published advisory for the target).
# --------------------------------------------------------------------------
_PUBLISHED_KEYS = (
    "published_advisory_count", "published_count", "published_advisories",
    "advisories_published", "total_published",
)
_CORPUS_KEYS = (
    "corpus_advisory_record_count", "corpus_record_count", "corpus_count",
    "advisory_records_in_corpus", "records_landed", "advisories_landed",
    "ingested_count",
)


def _coerce_int(v) -> int:
    """Coerce a single value to int, returning 0 for None/bool/non-numeric.
    Used by content-assertion gates that sum optional count fields."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    return 0


def _coerce_count(obj: dict, keys: tuple[str, ...]) -> int | None:
    for k in keys:
        v = obj.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, list):
            return len(v)
        if isinstance(v, str):
            try:
                return int(v.strip())
            except ValueError:
                continue
    return None


# Scan-execution evidence keys: any one of these proves the miner actually ran
_ADV_SCAN_EVIDENCE_KEYS = (
    "source_files_used",   # morpho: list of scanned files
    "source_summary",      # dydx: dict with underlying_verdict from API call
    "scanned_at_utc",      # explicit scan timestamp
    "generated_at_utc",    # generation timestamp
    "scan_method",         # how the scan ran
)


def _has_scan_evidence(obj: dict) -> bool:
    """True iff the advisory-corpus ledger carries STRONG evidence a real miner
    scan ran - not just a hollow count declaration or a bare timestamp.

    Strong evidence requires at least one of:
      - source_files_used: a non-empty list (the miner enumerated real files)
      - source_summary: a non-empty dict (the miner returned structured results)
      - advisories_scanned: an integer > 0 (the miner counted real entries)

    Timestamp fields (scanned_at_utc / generated_at_utc / scan_method) alone are
    NOT sufficient: they can be set by a stub that never queried any source.  They
    remain available via _has_weak_scan_evidence() for informational detail only.
    r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    """
    v = obj.get("source_files_used")
    if isinstance(v, list) and len(v) > 0:
        return True
    v = obj.get("source_summary")
    if isinstance(v, dict) and v:
        return True
    v = obj.get("advisories_scanned")
    if isinstance(v, int) and not isinstance(v, bool) and v > 0:
        return True
    return False


def _has_weak_scan_evidence(obj: dict) -> bool:
    """True iff the ledger has at least a timestamp / method field - a weaker
    tier used only for informational detail, not to satisfy the 0/0 hollow
    guard.  See _has_scan_evidence() for the strong-evidence check."""
    for k in ("scanned_at_utc", "generated_at_utc", "scan_method"):
        if obj.get(k):
            return True
    return False


def check_advisory_corpus(ws: Path) -> SignalResult:
    a = ws / ".auditooor"
    # Mirror the pattern used by every other advisory-default signal: wire in
    # ENFORCE_AUTONOMOUS_PROOF_CONVERSION so the 0/0 hollow path is blocked
    # under the production enforcement mode even without an explicit per-signal
    # strict env var.
    # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("ADVISORY_CORPUS")
    candidates = [
        a / "advisory_corpus_parity.json",
        a / "advisory_parity.json",
        a / "advisory_corpus_inventory.json",
        ws / "reports" / "advisory_corpus_parity.json",
    ]
    ledger = next((c for c in candidates if _is_file(c)), None)
    if ledger is None:
        g = _glob_first(a, ("advisory_corpus*.json", "advisory_parity*.json"))
        ledger = g
    if ledger is None:
        return SignalResult(
            signal="advisory-corpus", ok=False,
            reason=(
                "no advisory-corpus parity ledger "
                "(.auditooor/advisory_corpus_parity.json declaring "
                "published_advisory_count vs corpus_advisory_record_count); "
                "cannot confirm the target's published advisories are all in corpus"
            ),
            artifacts=[], detail={},
        )
    obj = _load_json(ledger) or {}
    published = _coerce_count(obj, _PUBLISHED_KEYS)
    corpus = _coerce_count(obj, _CORPUS_KEYS)
    # Strong evidence: source_files_used / source_summary / advisories_scanned>0.
    # Timestamp-only fields (scanned_at_utc / generated_at_utc / scan_method) are
    # recorded as weak_scan_evidence for informational detail only; they no longer
    # satisfy the 0/0 hollow guard (Fix 7: timestamp-only != proof-of-scan).
    # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    has_scan = _has_scan_evidence(obj)
    has_weak_scan = _has_weak_scan_evidence(obj)
    detail = {"ledger": str(ledger), "published": published, "corpus": corpus,
              "has_scan_evidence": has_scan, "has_weak_scan_evidence": has_weak_scan}
    if published is None or corpus is None:
        return SignalResult(
            signal="advisory-corpus", ok=False,
            reason=(
                f"advisory-corpus ledger {ledger.name} present but missing a count "
                "field (need published_advisory_count AND corpus_advisory_record_count)"
            ),
            artifacts=[str(ledger)], detail=detail,
        )
    if corpus < published:
        return SignalResult(
            signal="advisory-corpus", ok=False,
            reason=(
                f"advisory-corpus INCOMPLETE: {corpus} corpus advisory-record(s) "
                f"of {published} published for this target (the Zebra "
                f"{corpus}-of-{published} false-clean)"
            ),
            artifacts=[str(ledger)], detail=detail,
        )
    # corpus >= published: parity satisfied. For published==0, require STRONG scan
    # evidence (source_files_used / source_summary / advisories_scanned>0) - a bare
    # timestamp is no longer sufficient to pass the hollow guard.
    if published == 0 and not has_scan:
        hollow_reason = (
            f"advisory-corpus ledger {ledger.name} claims 0/0 (no published advisories) "
            f"but carries no strong scan-execution evidence "
            f"(source_files_used / source_summary / advisories_scanned>0 absent); "
            + (
                "timestamp fields present but insufficient (weak evidence only); "
                if has_weak_scan else ""
            )
            + "cannot confirm the miner actually ran a search - this may be a hollow stub"
        )
        if strict:
            return SignalResult(
                signal="advisory-corpus", ok=False, reason=hollow_reason,
                artifacts=[str(ledger)], detail=detail,
            )
        return SignalResult(
            signal="advisory-corpus", ok=True, reason="WARN: " + hollow_reason,
            artifacts=[str(ledger)], detail=detail,
        )
    return SignalResult(
        signal="advisory-corpus", ok=True,
        reason=f"advisory-corpus complete: {corpus}/{published} published advisories in corpus",
        artifacts=[str(ledger)], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (i2): mined == landed - sidecar count equals corpus-record count
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# The LEARNING_DEBT close: a workspace's hunt produced N sidecars but only M<N
# landed as corpus records. A workspace cannot be audit-complete while sidecars
# remain un-landed. This signal counts hunt_findings_sidecars/*.json and
# requires a landed ledger asserting landed_count == sidecar_count (or counts
# the corpus records directly when a ledger declares both).
# --------------------------------------------------------------------------
_SIDECAR_KEYS = ("sidecar_count", "sidecars", "mined_count", "mined")
_LANDED_KEYS = ("landed_count", "landed", "corpus_record_count", "records_landed")
_EXPLICIT_ACCOUNTED_KEYS = ("sidecars_accounted", "n_sidecars_accounted")
_EXPLICIT_MINED_LANDED_LEDGER_NAMES = {
    "mined_landed_parity.json",
    "sidecar_landed_parity.json",
}


# Top-level keys that mark a sidecar as a genuine FINDING record (a hypothesis
# that must be landed/dispositioned), vs a bare harness-EXECUTION task-record
# (task_id + status + result-metadata, no finding content) that the hunt tooling
# also drops into hunt_findings_sidecars/. The mined-landed parity gate counts
# "mined FINDINGS", so an execution task-record with no finding content is not a
# mined finding and must not inflate the mined count (it has nothing to land).
# r36-rebuttal: lane MINED-LANDED-FINDING-CONTENT registered in .auditooor/agent_pathspec.json
_FINDING_CONTENT_KEYS = (
    "verdict", "disposition", "candidate_finding", "hypothesis", "title",
    "analysis", "finding", "severity_if_true", "poc",
)


def _is_finding_sidecar(path: Path) -> bool:
    """True iff the sidecar carries genuine finding content. A pure harness-
    execution task-record (only task_id/workspace/status/result/harness_version/
    tags, no finding field) is NOT a mined finding."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        # Unreadable - be conservative and count it (a real finding may be
        # corrupted; do not silently drop it from the mined set).
        return True
    if not isinstance(obj, dict):
        return True
    return any(
        isinstance(obj.get(k), (str, list, dict)) and obj.get(k)
        for k in _FINDING_CONTENT_KEYS
    )


def _count_sidecars(ws: Path) -> int:
    d = ws / "hunt_findings_sidecars"
    if not _exists(d) or not d.is_dir():
        return 0
    n = 0
    try:
        for c in d.glob("*.json"):
            if c.is_file() and not c.name.startswith(".") and _is_finding_sidecar(c):
                n += 1
    except OSError:
        return 0
    return n


def check_mined_landed(ws: Path) -> SignalResult:
    """Signal (i2): mined == landed parity, content-asserted + advisory.

    Genuine-content contract (not file-presence-only):
      - a mined-landed parity ledger must declare BOTH a mined/sidecar count and
        a landed/corpus-record count, and
      - the ledger's own declared sidecar count must MATCH the live filesystem
        ``hunt_findings_sidecars/*.json`` count (catches a stale ledger that
        under-counts the real sidecars), and
      - landed must be >= mined (no un-landed LEARNING_DEBT).

    Advisory by DEFAULT: any genuine-content failure (no ledger while sidecars
    exist, missing landed field, ledger-vs-filesystem count mismatch, or
    landed < mined) returns ok=True with a ``WARN:`` reason on a normal run.
    It returns ok=False ONLY under strict = _enforce_autonomous_proof_conversion()
    or _l37_gate_strict('MINED_LANDED'). Trivially passes (ok=True, no WARN) when
    there are zero sidecars or when full parity holds.
    """
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("MINED_LANDED")
    a = ws / ".auditooor"
    ledger_candidates = [
        a / "mined_landed_parity.json",
        a / "learning_parity_manifest.json",
        a / "sidecar_landed_parity.json",
        ws / "reports" / "mined_landed_parity.json",
    ]
    ledger = next((c for c in ledger_candidates if _is_file(c)), None)
    sidecar_fs = _count_sidecars(ws)

    def _warn(reason: str, ok_detail: dict, arts: list[str]) -> SignalResult:
        # Advisory WARN-pass by default; fail-closed only under strict.
        d = dict(ok_detail)
        d["strict"] = strict
        if strict:
            return SignalResult(
                signal="mined-landed", ok=False, reason=reason,
                artifacts=arts, detail=d,
            )
        return SignalResult(
            signal="mined-landed", ok=True, reason="WARN: " + reason,
            artifacts=arts, detail=d,
        )

    if ledger is not None:
        obj = _load_json(ledger) or {}
        mined = _coerce_count(obj, _SIDECAR_KEYS)
        landed = _coerce_count(obj, _LANDED_KEYS)
        accounted = None
        if ledger.name in _EXPLICIT_MINED_LANDED_LEDGER_NAMES:
            accounted = _coerce_count(obj, _EXPLICIT_ACCOUNTED_KEYS)
            if accounted is not None and (landed is None or accounted > landed):
                landed = accounted
        ledger_declared_mined = mined
        if mined is None:
            mined = sidecar_fs
        detail = {
            "ledger": str(ledger),
            "mined": mined,
            "landed": landed,
            "accounted": accounted,
            "sidecar_fs_count": sidecar_fs,
            "ledger_declared_mined": ledger_declared_mined,
        }
        # Genuine content: a landed field MUST be present.
        if landed is None:
            return _warn(
                f"mined-landed ledger {ledger.name} present but missing a "
                "landed_count / corpus_record_count field (no genuine "
                "parity assertion)",
                detail, [str(ledger)],
            )
        # Genuine content: the ledger's declared sidecar count MUST equal the
        # live filesystem count. A stale ledger under-counting real sidecars is
        # a parity mismatch even when its own landed==mined.
        if (
            ledger_declared_mined is not None
            and ledger_declared_mined != sidecar_fs
        ):
            return _warn(
                f"mined-landed ledger {ledger.name} declares "
                f"sidecar/mined count {ledger_declared_mined} but the live "
                f"filesystem has {sidecar_fs} hunt_findings_sidecars/*.json "
                "(stale ledger; parity not genuinely asserted over current "
                "sidecars)",
                detail, [str(ledger)],
            )
        if landed < mined:
            return _warn(
                f"un-landed sidecars (LEARNING_DEBT): {landed} landed of "
                f"{mined} mined; workspace cannot be audit-complete with "
                "un-landed sidecars",
                detail, [str(ledger)],
            )
        detail["strict"] = strict
        return SignalResult(
            signal="mined-landed", ok=True,
            reason=(
                f"mined==landed parity: {landed}/{mined} sidecars landed in "
                f"corpus (ledger count matches filesystem {sidecar_fs})"
            ),
            artifacts=[str(ledger)], detail=detail,
        )

    # No ledger. Zero sidecars -> nothing to land -> genuine trivial pass.
    if sidecar_fs == 0:
        return SignalResult(
            signal="mined-landed", ok=True,
            reason="no hunt_findings_sidecars to land (mined==landed trivially)",
            artifacts=[],
            detail={"mined": 0, "landed": 0, "sidecar_fs_count": 0,
                    "strict": strict},
        )
    # Sidecars exist but no parity ledger asserts they landed -> advisory.
    return _warn(
        f"{sidecar_fs} hunt_findings_sidecars/*.json present but no "
        "mined-landed parity ledger (.auditooor/mined_landed_parity.json) "
        "asserting landed_count == sidecar_count; cannot confirm sidecars "
        "landed in corpus",
        {"mined": sidecar_fs, "landed": None, "sidecar_fs_count": sidecar_fs},
        [],
    )


# --------------------------------------------------------------------------
# Signal (k): fork-divergence-probe ran on fork / vendored targets
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# If the workspace is a fork / vendored target (a pinned git-rev in Cargo.toml
# / go.mod, a vendored upstream tree, or git-remote != the canonical upstream),
# a fork-divergence-probe artifact must exist. Non-fork targets pass.
# --------------------------------------------------------------------------
# Pinned-rev markers: `rev = "<sha>"` (Cargo.toml git dep), `replace ... =>`
# w/ a pseudo-version / sha (go.mod fork), `branch = "..."` git dep.
_CARGO_GIT_REV_RE = re.compile(r"""\brev\s*=\s*["'][0-9a-f]{7,40}["']""", re.IGNORECASE)
_CARGO_GIT_DEP_RE = re.compile(r"""\bgit\s*=\s*["']https?://""", re.IGNORECASE)
_GOMOD_REPLACE_RE = re.compile(r"^\s*replace\s+\S+\s+=>\s+\S+", re.MULTILINE)
_GOMOD_PSEUDO_RE = re.compile(r"-[0-9]{14}-[0-9a-f]{12}\b")


def _detect_fork(ws: Path) -> tuple[bool, list[str]]:
    """Heuristic fork/vendored detection. Returns (is_fork, reasons)."""
    reasons: list[str] = []
    # Cargo.toml pinned git rev / git dep
    for cargo in (ws / "Cargo.toml", ws / "src" / "Cargo.toml"):
        txt = _read_text(cargo)
        if txt is None:
            continue
        if _CARGO_GIT_REV_RE.search(txt):
            reasons.append(f"{cargo.name}: pinned git rev")
        elif _CARGO_GIT_DEP_RE.search(txt):
            reasons.append(f"{cargo.name}: git dependency")
    # go.mod replace / pseudo-version (fork pin)
    for gomod in (ws / "go.mod", ws / "src" / "go.mod"):
        txt = _read_text(gomod)
        if txt is None:
            continue
        if _GOMOD_REPLACE_RE.search(txt):
            reasons.append("go.mod: replace directive (fork)")
        elif _GOMOD_PSEUDO_RE.search(txt):
            reasons.append("go.mod: pseudo-version pin")
    # vendored upstream tree
    for vend in ("vendor", "third_party", "external"):
        d = ws / vend
        if _exists(d) and d.is_dir():
            try:
                if any(True for _ in d.iterdir()):
                    reasons.append(f"vendored upstream tree: {vend}/")
            except OSError:
                pass
    # explicit fork marker file
    for marker in ("FORK_OF.txt", ".auditooor/fork_target.json", "FORK.md"):
        if _exists(ws / marker):
            reasons.append(f"explicit fork marker: {marker}")
    diff_reason = _same_family_unproven_differential_seed_reason(ws)
    if diff_reason:
        reasons.append(diff_reason)
    return (len(reasons) > 0, reasons)


def _same_family_unproven_differential_seed_reason(ws: Path) -> str | None:
    seed = ws / ".auditooor" / "differential_seed_queue.json"
    obj = _load_json(seed)
    if not isinstance(obj, dict):
        return None
    if obj.get("schema") != "auditooor.cross_workspace_differential_seed.v1":
        return None
    target_families = {
        str(fam).strip().lower()
        for fam in obj.get("target_families", [])
        if str(fam).strip()
    }
    if not target_families:
        return None
    same_family_siblings: set[str] = set()
    selected = obj.get("selected_siblings")
    if isinstance(selected, list):
        for sibling in selected:
            if not isinstance(sibling, dict):
                continue
            sibling_families = {
                str(fam).strip().lower()
                for fam in sibling.get("families", [])
                if str(fam).strip()
            }
            if target_families & sibling_families:
                workspace_name = str(sibling.get("workspace") or "").strip()
                if workspace_name:
                    same_family_siblings.add(workspace_name)
    if not same_family_siblings:
        return None
    unresolved_statuses = {"", "open", "todo", "unproven", "unknown", "needs_source", "needs_proof"}
    unresolved_count = 0
    hypotheses = obj.get("hypotheses")
    if isinstance(hypotheses, list):
        for row in hypotheses:
            if not isinstance(row, dict):
                continue
            prior_workspace = str(row.get("prior_workspace") or "").strip()
            if prior_workspace and prior_workspace not in same_family_siblings:
                continue
            verdict = str(row.get("verdict") or "").strip().lower()
            if verdict in unresolved_statuses:
                unresolved_count += 1
    if unresolved_count == 0:
        return None
    families = ",".join(sorted(target_families))
    siblings = ",".join(sorted(same_family_siblings))
    return (
        "same-family differential seed has unproven hypotheses "
        f"(families={families}; siblings={siblings}; unproven={unresolved_count})"
    )


def _fork_divergence_hunt_stage_ran(ws: Path) -> Path | None:
    """PR8 ADD-C: the fork-divergence HUNT stage
    (``tools/fork-divergence-hunt-stage.py --emit-queue``) writes the
    not-backported upstream-security leads into
    ``<ws>/.auditooor/proof_obligation_queue.json`` and stamps a
    ``fork_divergence_last_run`` marker on the queue. A queue carrying that
    marker is direct evidence the fork-divergence hunt ran."""
    q = ws / ".auditooor" / "proof_obligation_queue.json"
    if not _is_file(q):
        return None
    obj = _load_json(q)
    if obj and isinstance(obj, dict) and obj.get("fork_divergence_last_run"):
        return q
    return None


def _has_fork_divergence_artifact(ws: Path) -> Path | None:
    a = ws / ".auditooor"
    # canonical fork-divergence-prober output
    g = _glob_first(a, (
        "fork_divergence*.json", "fork-divergence*.json",
        "*fork_divergence*", "*fork-divergence*",
    ))
    if g is not None:
        return g
    # PR8 ADD-C: the fork-divergence HUNT stage's proof-obligation queue.
    q = _fork_divergence_hunt_stage_ran(ws)
    if q is not None:
        return q
    # markdown / report variants in .auditooor or reports/
    for d in (a, ws / "reports"):
        g2 = _glob_first(d, ("*fork_divergence*", "*fork-divergence*", "*forkdivergence*"))
        if g2 is not None:
            return g2
    return None


def _fork_divergence_artifact_genuine(art: Path) -> tuple[bool, str]:
    """Returns (is_genuine, reason). Genuine iff the artifact proves the
    fork-divergence probe actually RAN (schema + generated_utc), not merely
    that someone created a file named fork_divergence*.json."""
    name = art.name
    # proof_obligation_queue.json with fork_divergence_last_run: content-verified
    # by _fork_divergence_hunt_stage_ran already; trust that path.
    if "proof_obligation_queue" in name:
        obj = _load_json(art)
        if obj and isinstance(obj, dict) and obj.get("fork_divergence_last_run"):
            return True, "proof_obligation_queue with fork_divergence_last_run timestamp"
        return False, "proof_obligation_queue without fork_divergence_last_run"
    # canonical fork_divergence_probe / fork-divergence-prober output
    obj = _load_json(art)
    if not isinstance(obj, dict):
        return False, f"unparseable JSON in {name}"
    schema = str(obj.get("schema") or "")
    gen_utc = (
        obj.get("generated_utc")
        or obj.get("generated_at_utc")
        or obj.get("generated_at")
        or obj.get("timestamp")
    )
    if "fork_divergence_prober" in schema and gen_utc:
        return True, (
            f"fork_divergence_prober artifact ran "
            f"(schema={schema}, generated_utc={gen_utc})"
        )
    # Permissive fallback: any fork/divergence-named JSON with gen_utc.
    fname_lower = name.lower()
    if gen_utc and ("fork" in fname_lower or "divergence" in fname_lower):
        return True, f"fork-divergence artifact with generated_utc={gen_utc}"
    return False, (
        f"hollow: schema={schema!r}, generated_utc={gen_utc!r}; "
        "cannot prove the fork-divergence probe ran"
    )


def check_fork_divergence(ws: Path) -> SignalResult:
    """Signal (k): fork-divergence-probe ran with GENUINE-EXECUTION evidence.

    Prior implementation false-passed on mere file presence: an empty {} JSON
    named fork_divergence_result.json satisfied the gate because only the path
    was checked, never the content. Corrected contract (PASS iff the artifact
    proves the prober RAN):

      - fork_divergence_probe.json with schema=auditooor.fork_divergence_prober.v1
        AND generated_utc non-empty (even 0 leads is a genuine offline result)
      - proof_obligation_queue.json with fork_divergence_last_run timestamp
        (already content-verified by _fork_divergence_hunt_stage_ran)
      - Any fork/divergence-named JSON with a generated_utc field

    Hollow triggers (WARN-pass by default, fail-closed under strict):
      - Empty {} JSON under any fork_divergence* name
      - JSON missing both schema and generated_utc

    Strict = _enforce_autonomous_proof_conversion() or
    _l37_gate_strict('FORK_DIVERGENCE'). Default is advisory (WARN-pass).
    Non-fork targets pass with N/A.
    """
    is_fork, reasons = _detect_fork(ws)
    if not is_fork:
        return SignalResult(
            signal="fork-divergence", ok=True,
            reason="not a fork/vendored target; fork-divergence probe N/A",
            artifacts=[], detail={"is_fork": False},
        )

    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("FORK_DIVERGENCE")
    art = _has_fork_divergence_artifact(ws)
    detail: dict = {
        "is_fork": True, "fork_reasons": reasons,
        "fork_divergence_artifact": str(art) if art else None,
        "strict": strict,
    }
    if art is None:
        return SignalResult(
            signal="fork-divergence", ok=False,
            reason=(
                "fork/vendored target (" + "; ".join(reasons) + ") but no "
                "fork-divergence-probe artifact (.auditooor/fork_divergence*.json); "
                "the fork-divergence probe did not run"
            ),
            artifacts=[], detail=detail,
        )

    gen, why = _fork_divergence_artifact_genuine(art)
    detail.update({"genuine": gen, "genuine_reason": why})
    if gen:
        return SignalResult(
            signal="fork-divergence", ok=True,
            reason=f"fork target with genuine fork-divergence-probe artifact: {why}",
            artifacts=[str(art)], detail=detail,
        )

    # Artifact present but hollow.
    hollow_reason = (
        f"fork-divergence artifact present ({art.name}) but HOLLOW: {why}; "
        "file-presence-only, not a genuine ran-with-output verdict"
    )
    if strict:
        return SignalResult(
            signal="fork-divergence", ok=False,
            reason=hollow_reason, artifacts=[str(art)], detail=detail,
        )
    return SignalResult(
        signal="fork-divergence", ok=True,
        reason="WARN: " + hollow_reason, artifacts=[str(art)], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (l): novel-vector stage ran (PR9 / PR10)
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# The novel-vector stage derives TARGET-SPECIFIC invariants
# (tools/novel-vector-invariant-miner.py) and has an engine search for an
# unknown violation (tools/pr9-novel-vector-0day-demo.py). Either artifact is
# evidence the stage ran: the miner's novel_vector_invariants*.json, or the
# pr9 demo's pr9_0day_demo_summary.json.
# --------------------------------------------------------------------------
def check_novel_vector(ws: Path) -> SignalResult:
    """Signal: novel-vector invariant-miner or pr9 0-day demo ran.

    Prior implementation false-passed on mere file presence: a stub
    {'empty_marker': true} without a schema returned ok=True because only
    the path was checked, never the content.

    Corrected contract (PASS iff the artifact proves the tool ran):
      - JSON artifacts: schema = 'auditooor.audit_deep_novel_vectors.v1'
        OR schema containing 'novel_vector' (case-insensitive). The tool
        writes this schema even when it finds 0 vectors (empty_marker_written=True
        + advisory_only=True is a GENUINE ran-with-0-results outcome).
      - pr9_0day_demo* files/dirs: presence sufficient (demo output).

    Stub {} or {'empty_marker': true} without schema -> WARN-pass by default;
    fail-closed under AUDITOOOR_L37_NOVEL_VECTOR_STRICT=1 or
    AUDITOOOR_L37_STRICT=1.
    """
    _SCHEMA = "auditooor.audit_deep_novel_vectors.v1"
    _SCHEMA_SUBSTR = "novel_vector"
    a = ws / ".auditooor"
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("NOVEL_VECTOR")

    def _is_genuine_json(p: Path) -> tuple[bool, str]:
        obj = _load_json(p)
        if not isinstance(obj, dict):
            return False, "unparseable or non-dict JSON"
        schema = str(obj.get("schema") or "")
        if schema == _SCHEMA or _SCHEMA_SUBSTR in schema.lower():
            return True, ""
        return False, (
            f"schema does not identify a novel-vector run "
            f"(got {schema!r}, want {_SCHEMA!r} or containing {_SCHEMA_SUBSTR!r})"
        )

    found: list[Path] = []
    g = _glob_first(a, ("novel_vector_invariants*.json", "novel_vector*.json",
                        "novel-vector*.json"))
    if g is not None:
        found.append(g)
    for d in (a, ws, ws / "reports"):
        s = _glob_first(d, ("pr9_0day_demo*", "*pr9_0day_demo_summary*"))
        if s is not None and str(s) not in {str(f) for f in found}:
            found.append(s)
    if not any("pr9_0day_demo" in str(f) for f in found):
        demo = _glob_first(a, ("*0day_demo*",)) or _glob_first(ws, ("*0day_demo*",))
        if demo is not None and str(demo) not in {str(f) for f in found}:
            found.append(demo)

    if not found:
        return SignalResult(
            signal="novel-vector", ok=False,
            reason=(
                "no novel-vector artifact "
                "(.auditooor/novel_vector_invariants*.json or pr9_0day_demo*/"
                "pr9_0day_demo_summary.json); the novel-vector stage did not run"
            ),
            artifacts=[], detail={},
        )

    hollow_files: list[tuple[Path, str]] = []
    genuine_files: list[Path] = []
    for f in found:
        if "pr9_0day_demo" in f.name or "0day_demo" in f.name:
            genuine_files.append(f)  # demo artifacts: presence sufficient
        elif f.suffix == ".json":
            gen, reason = _is_genuine_json(f)
            if gen:
                genuine_files.append(f)
            else:
                hollow_files.append((f, reason))
        else:
            hollow_files.append((f, "non-JSON, non-demo artifact: schema not checkable"))

    if genuine_files:
        detail: dict[str, Any] = {"found": [str(f) for f in found]}
        for gf in genuine_files:
            if gf.suffix == ".json":
                obj2 = _load_json(gf) or {}
                detail["advisory_only"] = obj2.get("advisory_only")
                detail["empty_marker_written"] = obj2.get("empty_marker_written")
                detail["target_repo_count"] = obj2.get("target_repo_count")
                break
        return SignalResult(
            signal="novel-vector", ok=True,
            reason=f"novel-vector stage ran: {genuine_files[0].name}",
            artifacts=[str(f) for f in genuine_files[:2]], detail=detail,
        )

    hollow_desc = "; ".join(f"{f.name}: {r}" for f, r in hollow_files[:2])
    hollow_reason = (
        f"novel-vector artifact(s) present but HOLLOW: {hollow_desc} - "
        f"JSON needs schema={_SCHEMA!r} (or {_SCHEMA_SUBSTR!r} in schema); "
        "use empty_marker_written=True + schema to signal a genuine 0-vectors run"
    )
    if strict:
        return SignalResult(
            signal="novel-vector", ok=False, reason=hollow_reason,
            artifacts=[str(f) for f, _ in hollow_files[:2]],
            detail={"hollow": [f.name for f, _ in hollow_files]},
        )
    return SignalResult(
        signal="novel-vector", ok=True, reason="WARN: " + hollow_reason,
        artifacts=[str(f) for f, _ in hollow_files[:2]],
        detail={"hollow": [f.name for f, _ in hollow_files]},
    )


# --------------------------------------------------------------------------
# Signal (m): adversarial 3-lens panel gated FINAL_LEADS (PR8 ADD-B / PR10)
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# A candidate cannot reach FINAL_LEADS without surviving the 3-lens adversarial
# panel (tools/adversarial-candidate-verify.py). When a FINAL_LEADS set exists,
# an adversarial-panel artifact is MANDATORY. With no FINAL_LEADS set the panel
# is N/A (nothing has been promoted to a final lead yet) and passes.
# --------------------------------------------------------------------------
def _has_final_leads(ws: Path) -> Path | None:
    a = ws / ".auditooor"
    for d in (a, ws, ws / "reports"):
        g = _glob_first(d, ("final_leads*", "FINAL_LEADS*", "final-leads*"))
        if g is not None:
            return g
    return None


def _has_adversarial_panel(ws: Path) -> Path | None:
    a = ws / ".auditooor"
    for d in (a, ws, ws / "reports"):
        g = _glob_first(d, (
            "adversarial_panel*.json", "adversarial-panel*.json",
            "*adversarial_candidate_verify*", "*adversarial_candidate*",
        ))
        if g is not None:
            return g
    return None


# The canonical schema emitted by adversarial-candidate-verify.py.
_ADVERSARIAL_PANEL_SCHEMA = "auditooor.adversarial_candidate_verify.v1"


def _adversarial_panel_genuine(art: Path) -> tuple[bool, str]:
    """Returns (is_genuine, reason). Genuine iff the artifact contains an
    actual 3-lens panel verdict from adversarial-candidate-verify.py, not merely
    that a file matching adversarial_panel* exists.

    A hypothesis-generation file (auditooor.adversarial_hypothesis_differential_hunter.v1
    or advisory_only=True) is NOT a panel verdict and does NOT satisfy the gate.
    """
    obj = _load_json(art)
    if not isinstance(obj, dict):
        return False, f"unparseable JSON in {art.name}"
    schema = str(obj.get("schema_id") or obj.get("schema") or "")
    panel_verdict = obj.get("panel_verdict")
    lenses = obj.get("lenses")
    candidates_reviewed = obj.get("candidates_reviewed")
    results = obj.get("results")

    # Primary: canonical adversarial_candidate_verify.v1 schema.
    if _ADVERSARIAL_PANEL_SCHEMA in schema:
        if isinstance(panel_verdict, str) and panel_verdict.strip():
            return True, (
                f"adversarial_candidate_verify.v1 artifact "
                f"(panel_verdict={panel_verdict!r}, "
                f"lenses={len(lenses) if isinstance(lenses, list) else 0})"
            )
        if isinstance(lenses, list) and len(lenses) > 0:
            return True, (
                f"adversarial_candidate_verify.v1 artifact with "
                f"{len(lenses)} lens entries (panel_verdict absent)"
            )

    # Batch-results variant: top-level results array of per-candidate records.
    if isinstance(results, list) and len(results) > 0:
        first = results[0]
        if isinstance(first, dict) and first.get("panel_verdict"):
            return True, (
                f"adversarial panel batch results: "
                f"{len(results)} candidate(s) with panel_verdict"
            )

    # candidates_reviewed counter (some implementations emit a summary record).
    if isinstance(candidates_reviewed, int) and not isinstance(candidates_reviewed, bool) \
            and candidates_reviewed > 0:
        return True, f"adversarial panel: candidates_reviewed={candidates_reviewed}"

    # Hypothesis / advisory files explicitly excluded.
    if "adversarial_hypothesis" in schema or obj.get("advisory_only") is True:
        return False, (
            f"hypothesis/advisory-only file ({schema!r}) is NOT a panel verdict; "
            "requires adversarial-candidate-verify.py run"
        )

    return False, (
        f"hollow: schema={schema!r}, panel_verdict={panel_verdict!r}, "
        f"lenses={type(lenses).__name__}, results={type(results).__name__}; "
        "cannot prove the 3-lens adversarial panel ran"
    )


def check_adversarial_panel(ws: Path) -> SignalResult:
    """Signal (m): adversarial 3-lens panel gated FINAL_LEADS with GENUINE-EXECUTION evidence.

    Prior implementation false-passed on mere file presence: an empty {}
    named adversarial_panel_result.json satisfied the gate when FINAL_LEADS
    existed, because only the path was checked, never the content. Corrected
    contract (PASS iff the artifact proves the panel actually ran):

      - No FINAL_LEADS: N/A, always passes (nothing promoted yet).
      - FINAL_LEADS exists AND genuine panel artifact: ok=True.
      - FINAL_LEADS exists AND hollow/hypothesis-only artifact: WARN-pass by
        default, fail-closed under strict.
      - FINAL_LEADS exists AND no panel artifact at all: fail (existing behavior).

    Genuine = schema_id=auditooor.adversarial_candidate_verify.v1 AND
    (panel_verdict non-empty OR lenses list has >= 1 entry OR
    candidates_reviewed > 0 OR results array non-empty with panel_verdict).

    An adversarial_hypothesis_*.json file (advisory_only=True, schema
    auditooor.adversarial_hypothesis_differential_hunter.v1) does NOT satisfy
    the panel requirement - it generates hypotheses, it does not run the panel.

    Strict = _enforce_autonomous_proof_conversion() or
    _l37_gate_strict('ADVERSARIAL_PANEL'). Default is advisory (WARN-pass).
    """
    final_leads = _has_final_leads(ws)
    if final_leads is None:
        return SignalResult(
            signal="adversarial-panel", ok=True,
            reason="no FINAL_LEADS set; adversarial panel N/A (nothing promoted yet)",
            artifacts=[], detail={"final_leads": None},
        )

    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("ADVERSARIAL_PANEL")
    panel = _has_adversarial_panel(ws)
    detail: dict = {
        "final_leads": str(final_leads),
        "adversarial_panel": str(panel) if panel else None,
        "strict": strict,
    }
    if panel is None:
        return SignalResult(
            signal="adversarial-panel", ok=False,
            reason=(
                f"FINAL_LEADS set exists ({final_leads.name}) but no "
                "adversarial-panel artifact (.auditooor/adversarial_panel*.json); "
                "a candidate cannot reach FINAL_LEADS without surviving the "
                "3-lens adversarial panel (PR8 ADD-B)"
            ),
            artifacts=[], detail=detail,
        )

    gen, why = _adversarial_panel_genuine(panel)
    detail.update({"genuine": gen, "genuine_reason": why})
    if gen:
        return SignalResult(
            signal="adversarial-panel", ok=True,
            reason=f"FINAL_LEADS gated by genuine adversarial-panel artifact: {why}",
            artifacts=[str(panel)], detail=detail,
        )

    # Artifact present but hollow.
    hollow_reason = (
        f"adversarial-panel artifact present ({panel.name}) but HOLLOW: {why}; "
        f"FINAL_LEADS set ({final_leads.name}) requires a genuine "
        "adversarial_candidate_verify.v1 panel verdict, not a hypothesis "
        "or placeholder file"
    )
    if strict:
        return SignalResult(
            signal="adversarial-panel", ok=False,
            reason=hollow_reason, artifacts=[str(panel)], detail=detail,
        )
    return SignalResult(
        signal="adversarial-panel", ok=True,
        reason="WARN: " + hollow_reason, artifacts=[str(panel)], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (n): EVM 0-day PROOF pipeline on a qualifying EVM workspace (PR5a)
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# For an EVM (Solidity/Vyper) workspace that has a Medium+ EVM candidate in the
# exploit-queue, the EVM 0-day PROOF pipeline (tools/evm-0day-proof-pipeline.py)
# can produce a proof artifact. Non-EVM workspaces, and EVM workspaces with no
# Medium+ EVM candidate, pass automatically. Missing proof is advisory unless
# ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1.
# --------------------------------------------------------------------------
_EVM_LANGS = {"solidity", "vyper"}
_MEDIUM_PLUS_RE = re.compile(r"\b(medium|high|critical)\b", re.IGNORECASE)

# Canonical corpus-driven-hunt fuel `source` markers, identical to the set used by
# `_corpus_hunt_fuel_present` above and `tools/exploit-queue.py:_CORPUS_HUNT_SOURCES`.
# A row carrying one of these in its `source` field is a MINED-CORPUS PATTERN applied
# against an in-scope symbol (a cross-workspace invariant seed), NOT a genuine,
# confirmed per-workspace 0-day candidate. The codebase already excludes this exact
# class from the per-fn attestation/resolution gates via `_is_corpus_fuel_obligation`
# (obligation rows) and quarantines it under the conversion-throughput gate; the EVM
# 0-day-proof qualifier must not double-count it as a real Medium+ EVM candidate.
_CORPUS_HUNT_FUEL_SOURCES = frozenset({"corpus-hunt-fuel", "corpus-hunt-hacker-q"})


def _is_evm_workspace(ws: Path) -> bool:
    langs = _detect_languages(ws)
    return any(l in _EVM_LANGS for l in langs)


def _row_is_corpus_hunt_fuel(row: dict) -> bool:
    """True iff an exploit-queue row is corpus-driven-hunt fuel rather than a genuine
    per-workspace candidate. NEVER-FALSE-EXCLUDE (fail-closed): only an UNAMBIGUOUS
    corpus-fuel marker excludes a row - the canonical `source` field, or a
    `corpus-hunt-fuel: ...` title prefix (the exploit-queue writer stamps both, see
    tools/exploit-queue.py / tools/corpus-driven-hunt.py). A genuine candidate carries
    a real source (e.g. a DSL/Slither/hunt lead) and is never dropped here."""
    if not isinstance(row, dict):
        return False
    if str(row.get("source") or "").strip().lower() in _CORPUS_HUNT_FUEL_SOURCES:
        return True
    title = str(row.get("title") or "").strip().lower()
    if title.startswith("corpus-hunt-fuel") or title.startswith("corpus-hunt-hacker-q"):
        return True
    return False


def _canonical_corpus_fuel_lead_ids(ws: Path) -> set[str]:
    """Collect the lead_ids of every corpus-fuel row across BOTH the base and the
    source-mined exploit queues. The base `exploit_queue.json` can lose the `source`
    tag on re-population (NUVA 2026-07-04: 98 rows that are `source=corpus-hunt-fuel`
    in exploit_queue.source_mined.json re-appeared in the base queue with an EMPTY
    `source` and a stripped `corpus-hunt-fuel:` title). The source-mined queue is the
    authoritative labelling, so a row that is corpus-fuel THERE is corpus-fuel here
    even if the base copy lost its markers. Bounded read, never raises."""
    ids: set[str] = set()
    for rel in ("exploit_queue.source_mined.json", "exploit_queue.json"):
        obj = _load_json(ws / ".auditooor" / rel)
        if not isinstance(obj, dict):
            continue
        rows = obj.get("queue") or obj.get("items") or obj.get("candidates") or []
        if not isinstance(rows, list):
            continue
        for row in rows:
            if _row_is_corpus_hunt_fuel(row):
                lid = str(row.get("lead_id") or "").strip()
                if lid:
                    ids.add(lid)
    return ids


_TERMINAL_NEGATIVE_PROOF_STATUSES = frozenset({
    "closed_negative",
    "closed_negative_source_proof",
    "disqualified",
    "killed",
    "refuted",
    "drop",
    "dropped",
    "adjudicated_negative",
    "terminal_negative",
    "invalid",
})


def _row_is_terminal_negative(row: dict) -> bool:
    """True iff an exploit-queue row is at a terminal-NEGATIVE (refuted) state - a
    REFUTED lead, not an OPEN Medium+ EVM 0-day obligation. Reads proof_status /
    quality_gate_status. Shares _DISQ_QUALITY_GATE_STATUSES so the two gates agree on
    what 'refuted' means. Accountability for the QUALITY of the refutation lives in the
    separate disqualification signal (_is_disqualification_kill), not here."""
    if not isinstance(row, dict):
        return False
    proof = str(row.get("proof_status") or "").strip().lower()
    gate = str(row.get("quality_gate_status") or "").strip().lower()
    return (proof in _TERMINAL_NEGATIVE_PROOF_STATUSES
            or gate in _DISQ_QUALITY_GATE_STATUSES)


def _has_medium_plus_evm_candidate(ws: Path) -> bool:
    """Read the exploit-queue and return True iff any queued candidate is a GENUINE
    Medium+ EVM candidate. Conservative: any severity field at Medium/High/Critical
    counts - EXCEPT corpus-driven-hunt fuel rows, which are cross-workspace invariant
    seeds (mined patterns), not confirmed per-workspace 0-day candidates. Counting
    corpus-fuel here produced a FALSE-RED evm-0day-proof (NUVA 2026-07-04): the entire
    Medium+ population was `corpus-hunt-fuel: INV-*` rows @ Go/Cosmos + mock/test
    helpers, so the gate demanded an EVM 0-day proof artifact for leads that are not
    real EVM candidates. Corpus-fuel stays fully accountable under the
    exploit-conversion/throughput gate; it just no longer double-counts here.

    TERMINAL-NEGATIVE exclusion (axelar-sc 2026-07-12): a lead whose proof_status /
    quality_gate_status is a terminal-NEGATIVE token (closed_negative /
    closed_negative_source_proof / disqualified / killed / refuted / dropped) is a
    REFUTED lead, not an OPEN Medium+ EVM 0-day obligation - there is nothing left to
    prove-convert, the candidate was already driven to a negative terminal. Counting
    it here produced a FALSE-RED evm-0day-proof (the entire Medium+ population was 10
    `likely_severity: high` rows ALL at proof_status=closed_negative, so the gate
    demanded a 0-day proof artifact for leads that were already refuted). These
    refuted leads stay FULLY accountable under the SEPARATE exploit-queue
    disqualification signal (signal u / _is_disqualification_kill), which independently
    requires a SUBSTANTIVE negative_control for every closed_negative kill - so a lazy
    "couldn't auto-prove -> closed_negative" dodge is still red there. This exclusion
    only stops the DOUBLE-COUNT here; it opens no hole."""
    eq = ws / ".auditooor" / "exploit_queue.json"
    obj = _load_json(eq)
    if not obj:
        return False
    rows = obj.get("queue") or obj.get("items") or obj.get("candidates") or []
    if not isinstance(rows, list):
        return False
    corpus_fuel_ids = _canonical_corpus_fuel_lead_ids(ws)
    for row in rows:
        if not isinstance(row, dict):
            continue
        # Exclude corpus-fuel rows by their own markers OR by canonical (source-mined)
        # lead_id labelling (the base queue can lose the tag on re-population).
        if _row_is_corpus_hunt_fuel(row):
            continue
        lid = str(row.get("lead_id") or "").strip()
        if lid and lid in corpus_fuel_ids:
            continue
        # Exclude terminal-NEGATIVE (refuted) leads: not an OPEN 0-day obligation.
        if _row_is_terminal_negative(row):
            continue
        for k in ("severity", "tier", "impact_tier", "proposed_severity", "likely_severity"):
            v = row.get(k)
            if isinstance(v, str) and _MEDIUM_PLUS_RE.search(v):
                return True
    return False


def _has_evm_0day_proof(ws: Path) -> Path | None:
    a = ws / ".auditooor"
    for d in (a, ws, ws / "reports"):
        g = _glob_first(d, (
            "evm_0day_proof*.json", "evm-0day-proof*.json", "*evm_0day_proof*",
        ))
        if g is not None:
            return g
    return None


_EVM_0DAY_PROOF_PASS_STATES = {
    "proof_backed",
}
_EVM_0DAY_PROOF_FAIL_STATES = {
    "error",
    "fail",
    "failed",
    "blocked",
    "blocked_with_obligation",
    "blocked-with-obligation",
    "candidate_not_submit_ready",
    "not_submit_ready",
    "scaffold_only_not_run",
    "scaffold-only-not-run",
    "scaffolded",
    "not_run",
    "no_run",
}


def _status_token(value: object) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _evm_0day_proof_state(path: Path) -> tuple[bool, str, dict]:
    obj = _load_json(path)
    if not isinstance(obj, dict):
        return False, "EVM 0-day proof artifact is missing or malformed JSON", {}
    states = {
        _status_token(obj.get("verdict")),
        _status_token(obj.get("status")),
        _status_token(obj.get("result")),
        _status_token(obj.get("final_result")),
        _status_token(obj.get("proof_status")),
    }
    states.discard("")
    detail = {"proof_states": sorted(states)}
    if states & _EVM_0DAY_PROOF_PASS_STATES:
        return True, "EVM 0-day proof artifact is proof-backed", detail
    if states & _EVM_0DAY_PROOF_FAIL_STATES:
        return False, "EVM 0-day proof artifact is not proof-backed", detail
    return False, "EVM 0-day proof artifact has no recognized proof-backed verdict", detail


def check_evm_0day_proof(ws: Path) -> SignalResult:
    if not _is_evm_workspace(ws):
        return SignalResult(
            signal="evm-0day-proof", ok=True,
            reason="not an EVM workspace; EVM 0-day proof pipeline N/A",
            artifacts=[], detail={"is_evm": False},
        )
    if not _has_medium_plus_evm_candidate(ws):
        return SignalResult(
            signal="evm-0day-proof", ok=True,
            reason="EVM workspace with no Medium+ EVM candidate in exploit-queue; proof pipeline N/A",
            artifacts=[], detail={"is_evm": True, "medium_plus_candidate": False},
        )
    # Honest-0 consistency with prove-top-leads: if a VALID prove-top-leads no-leads
    # manifest exists (every top lead terminal/adjudicated, corroborated by the
    # UN-FAKEABLE prefiling producer via _valid_prove_top_leads_no_leads_manifest),
    # then the Medium+ EVM candidate(s) are among those terminal leads and there is no
    # OPEN EVM 0-day proof obligation - the same evidence that greens prove-top-leads
    # greens this. Reuses the prefiling corroboration, so it cannot be gamed here
    # independently (a hand-forged manifest is rejected by the prefiling producer).
    _ptl_set = _prove_top_leads_artifact_set(ws)
    if _ptl_set.get("no_leads_manifest_complete"):
        _nlm = _ptl_set.get("no_leads_manifest")
        return SignalResult(
            signal="evm-0day-proof", ok=True,
            reason=(
                "EVM Medium+ candidate(s) present but the prove-top-leads no-leads "
                "manifest is VALID (all top leads terminal/adjudicated, prefiling "
                "top_n=0) - no open EVM 0-day proof obligation remains"
            ),
            artifacts=[_nlm] if _nlm else [],
            detail={"is_evm": True, "medium_plus_candidate": True,
                    "resolved_by_no_leads_manifest": _nlm},
        )
    art = _has_evm_0day_proof(ws)
    detail = {"is_evm": True, "medium_plus_candidate": True,
              "evm_0day_proof": str(art) if art else None,
              "advisory_autonomous_proof_conversion": True,
              "enforce_autonomous_proof_conversion": _enforce_autonomous_proof_conversion()}
    if art is None:
        if not _enforce_autonomous_proof_conversion():
            return SignalResult(
                signal="evm-0day-proof", ok=True,
                reason=(
                    "EVM workspace has a Medium+ EVM candidate but no EVM 0-day "
                    "proof artifact; autonomous proof conversion is advisory by "
                    "default. Set ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 to "
                    "enable enforced artifact mode"
                ),
                artifacts=[], detail=detail,
            )
        return SignalResult(
            signal="evm-0day-proof", ok=False,
            reason=(
                "EVM workspace has a Medium+ EVM candidate in the exploit-queue "
                "but no EVM 0-day proof-conversion artifact "
                "(.auditooor/evm_0day_proof*.json); the EVM 0-day proof-conversion "
                "pipeline did not run for the qualifying candidate and "
                "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 requires it"
            ),
            artifacts=[], detail=detail,
        )
    proof_ok, proof_reason, proof_detail = _evm_0day_proof_state(art)
    detail.update(proof_detail)
    detail["proof_valid"] = proof_ok
    if not proof_ok:
        if not _enforce_autonomous_proof_conversion():
            return SignalResult(
                signal="evm-0day-proof", ok=True,
                reason=(
                    f"{proof_reason} ({art.name}); autonomous proof conversion "
                    "is advisory by default. Set "
                    "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 to require a "
                    "proof-backed artifact"
                ),
                artifacts=[str(art)], detail=detail,
            )
        return SignalResult(
            signal="evm-0day-proof", ok=False,
            reason=(
                f"{proof_reason} ({art.name}) and "
                "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 requires proof-backed "
                "EVM proof evidence"
            ),
            artifacts=[str(art)], detail=detail,
        )
    return SignalResult(
        signal="evm-0day-proof", ok=True,
        reason=f"EVM 0-day proof-conversion artifact proof-backed ({art.name})",
        artifacts=[str(art)], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (o): SWEPT-SURFACE coverage map present + uncovered count surfaced
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# A workspace cannot be certified audit-complete without a coverage report
# enumerating every in-scope unit and classifying covered vs UNCOVERED. The
# report is produced by tools/workspace-coverage-heatmap.py --coverage-report.
# ABSENCE fails closed (fail-no-coverage-map). The signal ALWAYS surfaces the
# true uncovered count. HIGH-UNCOVERED does NOT fail - it emits a loud,
# non-fatal warn (the honest answer to "is every surface audited?" is to REPORT
# the uncovered count loudly, never paper it over). Empirical anchor:
# Hyperbridge reported 742/743 contracts UNCOVERED.
# --------------------------------------------------------------------------
_COVERAGE_SCHEMA = "auditooor.workspace_coverage_report.v1"
_SOURCE_FRESHNESS_SCHEMA = "auditooor.coverage_source_freshness.v1"
_NUMERATOR_FRESHNESS_SCHEMA = "auditooor.coverage_numerator_freshness.v1"
_SOURCE_FRESHNESS_ALGORITHM = "sha256-canonical-json-v1"
_SOURCE_FRESHNESS_FIELDS = (
    "schema",
    "algorithm",
    "coverage_basis",
    "scope_mode",
    "scope_globs_sha256",
    "source_files_count",
    "source_files_sha256",
    "source_units_count",
    "source_units_sha256",
    "function_denominator_status",
    "function_level_extensions",
    "partial_function_extensions",
    "source_unit_extensions",
    "partial_function_reasons",
    "full_in_scope_function_denominator",
    "denominator_sha256",
)
_COVERAGE_TOP_LEVEL_DENOMINATOR_FIELDS = (
    "function_denominator_status",
    "function_level_extensions",
    "partial_function_extensions",
    "source_unit_extensions",
    "partial_function_reasons",
    "full_in_scope_function_denominator",
)
_NUMERATOR_FRESHNESS_FIELDS = (
    "schema",
    "algorithm",
    "coverage_basis",
    "coverage_tokens_count",
    "coverage_tokens_sha256",
    "covered_units_count",
    "covered_units_sha256",
    "uncovered_units_count",
    "uncovered_units_sha256",
    "numerator_artifacts_count",
    "numerator_artifacts_sha256",
    "total_units_count",
    "numerator_sha256",
)
_COVERAGE_WARN_FRACTION_DEFAULT = 0.50


def _load_coverage_heatmap_module() -> tuple[Any | None, str | None]:
    tool = Path(__file__).resolve().with_name("workspace-coverage-heatmap.py")
    if not tool.is_file():
        return None, "workspace-coverage-heatmap.py missing"
    try:
        spec = importlib.util.spec_from_file_location("_auditooor_workspace_coverage_heatmap", tool)
        if spec is None or spec.loader is None:
            return None, "unable to load workspace-coverage-heatmap.py"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, None
    except Exception as exc:  # pragma: no cover - defensive diagnostic path
        return None, f"coverage heatmap load failed: {exc.__class__.__name__}: {exc}"


def _recompute_source_freshness(ws: Path) -> tuple[dict | None, str | None]:
    module, error = _load_coverage_heatmap_module()
    if module is None:
        return None, error
    try:
        return module.build_source_freshness(ws), None
    except Exception as exc:  # pragma: no cover - defensive diagnostic path
        return None, f"source freshness recompute failed: {exc.__class__.__name__}: {exc}"


def _recompute_coverage_numerator_freshness(ws: Path) -> tuple[dict | None, str | None]:
    module, error = _load_coverage_heatmap_module()
    if module is None:
        return None, error
    try:
        report = module.build_coverage_report(ws)
        freshness = report.get("numerator_freshness") if isinstance(report, dict) else None
        return freshness if isinstance(freshness, dict) else None, None
    except Exception as exc:  # pragma: no cover - defensive diagnostic path
        return None, f"coverage numerator recompute failed: {exc.__class__.__name__}: {exc}"


def _recompute_coverage_report(ws: Path, list_cap: int | None = None) -> tuple[dict | None, str | None]:
    module, error = _load_coverage_heatmap_module()
    if module is None:
        return None, error
    try:
        report = (
            module.build_coverage_report(ws, list_cap=list_cap)
            if list_cap is not None
            else module.build_coverage_report(ws)
        )
        return report if isinstance(report, dict) else None, None
    except Exception as exc:  # pragma: no cover - defensive diagnostic path
        return None, f"coverage report recompute failed: {exc.__class__.__name__}: {exc}"


def _source_freshness_malformed(freshness: dict) -> str | None:
    if freshness.get("schema") != _SOURCE_FRESHNESS_SCHEMA:
        return "missing or invalid source_freshness.schema"
    if freshness.get("algorithm") != _SOURCE_FRESHNESS_ALGORITHM:
        return "missing or invalid source_freshness.algorithm"
    if freshness.get("coverage_basis") != "source-unit":
        return "missing or invalid source_freshness.coverage_basis"
    for key in _SOURCE_FRESHNESS_FIELDS:
        if key not in freshness:
            return f"missing source_freshness.{key}"
    if not isinstance(freshness.get("source_files_count"), int):
        return "source_freshness.source_files_count must be an integer"
    if not isinstance(freshness.get("source_units_count"), int):
        return "source_freshness.source_units_count must be an integer"
    if not isinstance(freshness.get("function_denominator_status"), str):
        return "source_freshness.function_denominator_status must be a string"
    if not isinstance(freshness.get("function_level_extensions"), list):
        return "source_freshness.function_level_extensions must be a list"
    if not isinstance(freshness.get("partial_function_extensions"), list):
        return "source_freshness.partial_function_extensions must be a list"
    if not isinstance(freshness.get("source_unit_extensions"), list):
        return "source_freshness.source_unit_extensions must be a list"
    if not isinstance(freshness.get("partial_function_reasons"), dict):
        return "source_freshness.partial_function_reasons must be a dict"
    if not isinstance(freshness.get("full_in_scope_function_denominator"), bool):
        return "source_freshness.full_in_scope_function_denominator must be a boolean"
    return None


def _numerator_freshness_malformed(freshness: dict) -> str | None:
    if freshness.get("schema") != _NUMERATOR_FRESHNESS_SCHEMA:
        return "missing or invalid numerator_freshness.schema"
    if freshness.get("algorithm") != _SOURCE_FRESHNESS_ALGORITHM:
        return "missing or invalid numerator_freshness.algorithm"
    if freshness.get("coverage_basis") != "source-unit":
        return "missing or invalid numerator_freshness.coverage_basis"
    for key in _NUMERATOR_FRESHNESS_FIELDS:
        if key not in freshness:
            return f"missing numerator_freshness.{key}"
    for key in (
        "coverage_tokens_count",
        "covered_units_count",
        "uncovered_units_count",
        "numerator_artifacts_count",
        "total_units_count",
    ):
        if not isinstance(freshness.get(key), int):
            return f"numerator_freshness.{key} must be an integer"
    return None


def _count_inscope_units(ws: Path) -> int:
    """Count distinct in-scope units declared in
    ``<ws>/.auditooor/inscope_units.jsonl``.

    This is the GENERIC in-scope denominator the rest of the pipeline writes
    (workspace-coverage-heatmap mode 3). It accepts either row shape -
    ``{"unit": "<path>::<fn>"}`` or ``{"file": ..., "function": ...}`` (function
    level) and ``{"file": ...}`` / ``{"unit": "<path>"}`` (file level for
    Go/Rust/Move/Cairo) - and dedups by the canonical key so duplicate rows do
    not inflate the count. Returns 0 when the manifest is absent / empty /
    unreadable (so the basis-mismatch guard only fires when there is a REAL
    declared in-scope surface to contradict).
    """
    p = ws / ".auditooor" / "inscope_units.jsonl"
    if not _is_file(p):
        return 0
    txt = _read_text(p)
    if not txt:
        return 0
    seen: set[str] = set()
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(d, dict):
            continue
        unit = d.get("unit")
        if isinstance(unit, str) and unit.strip():
            seen.add(unit.strip())
            continue
        fp = d.get("file") or d.get("path") or d.get("file_line")
        fn = d.get("function") or d.get("fn")
        if isinstance(fp, str) and fp.strip():
            key = f"{fp.strip()}::{fn.strip()}" if isinstance(fn, str) and fn.strip() else fp.strip()
            seen.add(key)
    return len(seen)


def _coverage_warn_fraction() -> float:
    raw = os.environ.get("AUDITOOOR_L37_COVERAGE_WARN_FRACTION", "").strip()
    if not raw:
        return _COVERAGE_WARN_FRACTION_DEFAULT
    try:
        v = float(raw)
    except ValueError:
        return _COVERAGE_WARN_FRACTION_DEFAULT
    if v < 0.0 or v > 1.0:
        return _COVERAGE_WARN_FRACTION_DEFAULT
    return v


def _coverage_numerator_malformed(obj: dict, total: int, covered: Any, uncovered: int, frac: float) -> str | None:
    if not isinstance(covered, int):
        return "covered must be an integer"
    if total < 0 or covered < 0 or uncovered < 0:
        return "total_units, covered, and uncovered must be nonnegative"
    if covered > total:
        return "covered cannot exceed total_units"
    if uncovered > total:
        return "uncovered cannot exceed total_units"
    if covered + uncovered != total:
        return "covered plus uncovered must equal total_units"
    if not 0.0 <= float(frac) <= 1.0:
        return "coverage_fraction must be between 0 and 1"
    expected_frac = round((covered / total) if total else 1.0, 6)
    if round(float(frac), 6) != expected_frac:
        return "coverage_fraction must match covered divided by total_units"

    uncovered_units = obj.get("uncovered_units")
    if not isinstance(uncovered_units, list):
        return "uncovered_units must be a list"
    listed = obj.get("uncovered_units_listed")
    if not isinstance(listed, int) or listed < 0:
        return "uncovered_units_listed must be a nonnegative integer"
    if listed != len(uncovered_units):
        return "uncovered_units_listed must equal len(uncovered_units)"
    omitted = obj.get("uncovered_units_omitted")
    if not isinstance(omitted, int) or omitted < 0:
        return "uncovered_units_omitted must be a nonnegative integer"
    if len(uncovered_units) + omitted != uncovered:
        return "uncovered_units plus omitted count must equal uncovered"
    truncated = obj.get("uncovered_units_truncated")
    if not isinstance(truncated, bool):
        return "uncovered_units_truncated must be a boolean"
    if truncated != (omitted > 0):
        return "uncovered_units_truncated must match omitted count"
    return None


def check_coverage_map(ws: Path) -> SignalResult:
    report = ws / ".auditooor" / "coverage_report.json"
    if not _is_file(report):
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "no SWEPT-SURFACE coverage report "
                "(.auditooor/coverage_report.json); cannot certify that every "
                "in-scope surface was actually audited. Run "
                "tools/workspace-coverage-heatmap.py --coverage-report "
                f"--workspace-path {ws}"
            ),
            artifacts=[], detail={"coverage_report": str(report)},
        )
    obj = _load_json(report) or {}
    schema = str(obj.get("schema", "")).strip()
    coverage_basis = str(obj.get("coverage_basis", "")).strip()
    source_freshness = obj.get("source_freshness")
    numerator_freshness = obj.get("numerator_freshness")
    total = obj.get("total_units")
    covered = obj.get("covered")
    uncovered = obj.get("uncovered")
    frac = obj.get("coverage_fraction")
    raw_workspace = str(obj.get("workspace") or "").strip()
    raw_workspace_name = str(obj.get("workspace_name") or "").strip()

    # A present-but-malformed report (missing the load-bearing counts) cannot
    # answer the coverage question; fail closed so it is not silently credited.
    if schema != _COVERAGE_SCHEMA or coverage_basis != "source-unit" or not isinstance(total, int) or \
            not isinstance(covered, int) or not isinstance(uncovered, int) or not isinstance(frac, (int, float)) or \
            not isinstance(source_freshness, dict) or not isinstance(numerator_freshness, dict):
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                f"coverage report present ({report.name}) but malformed "
                "(missing schema/coverage_basis/source_freshness/numerator_freshness/total_units/"
                "covered/uncovered/coverage_fraction); "
                "cannot read the swept-surface coverage signal"
            ),
            artifacts=[str(report)],
            detail={"coverage_report": str(report), "schema": schema,
                    "coverage_basis": coverage_basis, "total_units": total,
                    "covered": covered, "uncovered": uncovered},
        )

    try:
        workspace_matches = bool(raw_workspace) and (
            Path(raw_workspace).expanduser().resolve(strict=False) == ws.resolve(strict=False)
        )
    except OSError:
        workspace_matches = False
    if not workspace_matches or raw_workspace_name != ws.name:
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report belongs to a different workspace; regenerate "
                "with tools/workspace-coverage-heatmap.py --coverage-report"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "stored_workspace": raw_workspace,
                "expected_workspace": str(ws),
                "stored_workspace_name": raw_workspace_name,
                "expected_workspace_name": ws.name,
            },
        )

    numerator_error = _coverage_numerator_malformed(obj, total, covered, uncovered, float(frac))
    if numerator_error:
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report present but numerator fields are internally "
                "inconsistent; regenerate with "
                "tools/workspace-coverage-heatmap.py --coverage-report"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "numerator_error": numerator_error,
                "total_units": total,
                "covered": covered,
                "uncovered": uncovered,
                "coverage_fraction": frac,
                "uncovered_units_listed": obj.get("uncovered_units_listed"),
                "uncovered_units_omitted": obj.get("uncovered_units_omitted"),
                "uncovered_units_truncated": obj.get("uncovered_units_truncated"),
            },
        )

    if total == 0:
        # Producer/consumer BASIS MISMATCH (item 3): the coverage report's
        # source-unit denominator is 0, but the GENERIC in-scope manifest
        # (inscope_units.jsonl) declares real units. A 0-source-unit report must
        # FAIL - never vacuously pass with fraction=1.0 - when there is a real
        # in-scope surface it failed to enumerate. Surface the contradiction
        # explicitly so the operator regenerates the coverage report against the
        # same basis the rest of the pipeline uses.
        inscope_units = _count_inscope_units(ws)
        if inscope_units > 0:
            return SignalResult(
                signal="coverage-map", ok=False,
                reason=(
                    "coverage report has zero source units but "
                    f"inscope_units.jsonl declares {inscope_units} in-scope "
                    "unit(s) - producer/consumer coverage-basis MISMATCH; the "
                    "swept-surface report enumerated an empty denominator while a "
                    "real in-scope surface exists. Regenerate with "
                    "tools/workspace-coverage-heatmap.py --coverage-report against "
                    "the same scope basis as inscope_units.jsonl"
                ),
                artifacts=[str(report)],
                detail={
                    "coverage_report": str(report),
                    "schema": schema,
                    "coverage_basis": coverage_basis,
                    "total_units": total,
                    "covered": covered,
                    "uncovered": uncovered,
                    "coverage_fraction": frac,
                    "inscope_units_count": inscope_units,
                    "basis_mismatch": True,
                },
            )
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report has zero source units; cannot certify full "
                "in-scope coverage from an empty denominator"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "total_units": total,
                "covered": covered,
                "uncovered": uncovered,
                "coverage_fraction": frac,
                "inscope_units_count": inscope_units,
            },
        )

    malformed_freshness = _source_freshness_malformed(source_freshness)
    if malformed_freshness:
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report present but missing a valid source denominator "
                "fingerprint; regenerate with "
                "tools/workspace-coverage-heatmap.py --coverage-report"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "source_freshness_error": malformed_freshness,
            },
        )

    malformed_numerator_freshness = _numerator_freshness_malformed(numerator_freshness)
    if malformed_numerator_freshness:
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report present but missing a valid coverage numerator "
                "fingerprint; regenerate with "
                "tools/workspace-coverage-heatmap.py --coverage-report"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "numerator_freshness_error": malformed_numerator_freshness,
            },
        )

    stored_numerator_mismatches = {}
    for report_key, freshness_key in (
        ("total_units", "total_units_count"),
        ("covered", "covered_units_count"),
        ("uncovered", "uncovered_units_count"),
        ("coverage_tokens", "coverage_tokens_count"),
    ):
        if report_key in obj and obj.get(report_key) != numerator_freshness.get(freshness_key):
            stored_numerator_mismatches[f"coverage_report.{report_key}_vs_numerator_freshness.{freshness_key}"] = {
                "stored": obj.get(report_key),
                "fingerprint": numerator_freshness.get(freshness_key),
            }
    if stored_numerator_mismatches:
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report numerator fields are out of sync with the "
                "stored coverage numerator fingerprint"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "numerator_freshness": numerator_freshness,
                "mismatches": stored_numerator_mismatches,
            },
        )

    recomputed, recompute_error = _recompute_source_freshness(ws)
    if not isinstance(recomputed, dict):
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report present but current source denominator "
                "fingerprint could not be recomputed; cannot trust stored report "
                "freshness"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "recompute_error": recompute_error,
            },
        )
    mismatches = {
        f"source_freshness.{key}": {
            "stored": source_freshness.get(key),
            "recomputed": recomputed.get(key),
        }
        for key in _SOURCE_FRESHNESS_FIELDS
        if source_freshness.get(key) != recomputed.get(key)
    }
    if total != source_freshness.get("source_units_count"):
        mismatches["total_units_vs_source_units_count"] = {
            "stored_total_units": total,
            "stored_source_units_count": source_freshness.get("source_units_count"),
        }
    for key in _COVERAGE_TOP_LEVEL_DENOMINATOR_FIELDS:
        if obj.get(key) != recomputed.get(key):
            mismatches[f"coverage_report.{key}"] = {
                "stored": obj.get(key),
                "recomputed": recomputed.get(key),
            }
    if mismatches:
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report source denominator fingerprint is stale or out "
                "of sync with current source tree"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "recomputed_source_freshness": recomputed,
                "source_freshness": source_freshness,
                "mismatches": mismatches,
            },
        )

    recomputed_numerator, numerator_recompute_error = _recompute_coverage_numerator_freshness(ws)
    if not isinstance(recomputed_numerator, dict):
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report present but current coverage numerator "
                "fingerprint could not be recomputed; cannot trust stored report "
                "freshness"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "recompute_error": numerator_recompute_error,
            },
        )
    numerator_mismatches = {
        f"numerator_freshness.{key}": {
            "stored": numerator_freshness.get(key),
            "recomputed": recomputed_numerator.get(key),
        }
        for key in _NUMERATOR_FRESHNESS_FIELDS
        if numerator_freshness.get(key) != recomputed_numerator.get(key)
    }
    if numerator_mismatches:
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report numerator fingerprint is stale or out of sync "
                "with current coverage artifacts"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "source_freshness_verified": True,
                "recomputed_numerator_freshness": recomputed_numerator,
                "numerator_freshness": numerator_freshness,
                "mismatches": numerator_mismatches,
            },
        )

    stored_uncovered_units = obj.get("uncovered_units")
    stored_visible_count = len(stored_uncovered_units) if isinstance(stored_uncovered_units, list) else None
    recomputed_report, report_recompute_error = _recompute_coverage_report(
        ws,
        list_cap=stored_visible_count,
    )
    if not isinstance(recomputed_report, dict):
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report present but current visible coverage report "
                "could not be recomputed; cannot trust stored report freshness"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "recompute_error": report_recompute_error,
            },
        )
    visible_uncovered_mismatches = {}
    for key in (
        "uncovered_units",
        "uncovered_units_listed",
        "uncovered_units_omitted",
        "uncovered_units_truncated",
    ):
        if obj.get(key) != recomputed_report.get(key):
            visible_uncovered_mismatches[f"coverage_report.{key}"] = {
                "stored": obj.get(key),
                "recomputed": recomputed_report.get(key),
            }
    if visible_uncovered_mismatches:
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                "coverage report visible uncovered-unit list is stale or out "
                "of sync with current coverage artifacts"
            ),
            artifacts=[str(report)],
            detail={
                "coverage_report": str(report),
                "schema": schema,
                "coverage_basis": coverage_basis,
                "source_freshness_verified": True,
                "numerator_freshness_verified": True,
                "mismatches": visible_uncovered_mismatches,
            },
        )

    warn_threshold = _coverage_warn_fraction()
    high_uncovered = total > 0 and float(frac) < warn_threshold
    detail = {
        "coverage_report": str(report),
        "coverage_basis": coverage_basis,
        "source_freshness_verified": True,
        "source_freshness": source_freshness,
        "numerator_freshness_verified": True,
        "numerator_freshness": numerator_freshness,
        "total_units": total,
        "covered": covered,
        "uncovered": uncovered,  # TRUE count, always surfaced
        "coverage_fraction": frac,
        "warn_threshold": warn_threshold,
        "high_uncovered": high_uncovered,
        "uncovered_units_truncated": bool(obj.get("uncovered_units_truncated")),
        "uncovered_units_omitted": obj.get("uncovered_units_omitted"),
        # ADVISORY accounting note (additive; changes no verdict): a unit is
        # "covered" here when ANY hypothesis / hunt-hit / candidate TOKEN
        # references it. A token can be a noise CCIA heuristic angle or a
        # vacuous per-function harness, so token-coverage is NOT proof that the
        # function was actually ATTACKED with a real verdict. The authority on
        # per-function attack is the separate hard-required ``function-coverage``
        # signal (s); the ``hollow-not-genuinely-audited`` signal (r) hard-fails
        # vacuous (assert(true)) harnesses via audit-honesty-check. This field
        # demotes the token-coverage number to advisory-for-attack-proof so it is
        # never silently read as "every function was attacked".
        "coverage_basis_note": (
            "token-coverage (hypothesis/hunt-hit/candidate references); NOT proof "
            "of per-function attack - see signal (s) function-coverage and signal "
            "(r) hollow-not-genuinely-audited for attack/harness reality"
        ),
    }

    # The signal PASSES whenever a valid report is present (presence is the
    # requirement; the uncovered count is informational/warn, not a fail). The
    # uncovered count is ALWAYS in the reason so it is never papered over.
    base_reason = (
        f"swept-surface coverage report present: {covered}/{total} units covered, "
        f"{uncovered} UNCOVERED (coverage_fraction={frac})"
    )

    # 100%-terminal axis (SWEPT-SURFACE): under strict every uncovered unit must
    # reach a terminal verdict. Terminal = the unit is credited SKIPPED with a
    # reason in the report (skipped_coverage_reasons) OR it carries an explicit
    # source-cited disposition in .auditooor/swept_surface_dispositions.jsonl.
    # Anything left uncovered-without-terminal-verdict FAILs under strict; the
    # operator waiver is a `coverage-map:<reason>` line in the rebuttal file (the
    # standard signal-rebuttal path, applied by evaluate()). NEVER-FALSE-PASS: a
    # bare/uncited disposition entry is rejected by _load_terminal_dispositions.
    uncovered_units = obj.get("uncovered_units")
    if not isinstance(uncovered_units, list):
        uncovered_units = []
    skipped_reasons = obj.get("skipped_coverage_reasons")
    skipped_keys: set[str] = set()
    if isinstance(skipped_reasons, dict):
        skipped_keys = {str(k) for k in skipped_reasons.keys()}
    elif isinstance(skipped_reasons, list):
        for it in skipped_reasons:
            if isinstance(it, dict):
                u = str(it.get("unit") or it.get("key") or "").strip()
                if u:
                    skipped_keys.add(u)
            elif isinstance(it, str):
                skipped_keys.add(it)
    dispositions = _load_terminal_dispositions(ws, "swept_surface_dispositions.jsonl")
    non_terminal_units = [
        u for u in (str(x) for x in uncovered_units)
        if u not in skipped_keys and u not in dispositions
    ]
    # If the report truncated the uncovered list, we cannot prove the tail is
    # terminal - fail-closed under strict (do not credit an un-listable tail).
    unlistable_tail = bool(obj.get("uncovered_units_truncated")) or (
        isinstance(obj.get("uncovered_units_omitted"), int)
        and obj["uncovered_units_omitted"] > 0
    )
    strict = _swept_terminal_strict()
    detail["strict"] = strict
    detail["swept_non_terminal_uncovered"] = len(non_terminal_units)
    detail["swept_non_terminal_sample"] = non_terminal_units[:12]
    detail["swept_uncovered_list_truncated"] = unlistable_tail
    if strict and (non_terminal_units or (unlistable_tail and uncovered > 0)):
        n = len(non_terminal_units)
        tail_note = (
            " (uncovered-unit list is TRUNCATED - the omitted tail cannot be "
            "proven terminal)" if unlistable_tail else ""
        )
        return SignalResult(
            signal="coverage-map", ok=False,
            reason=(
                base_reason + f"  [STRICT FAIL: {n} uncovered unit(s) with NO "
                "terminal verdict - cover them, mark them skipped-with-reason in "
                "the coverage report, add a .auditooor/swept_surface_dispositions."
                "jsonl {unit,reason} row, or waive with a `coverage-map:<reason>` "
                "rebuttal line]" + tail_note
            ),
            artifacts=[str(report)], detail=detail,
        )

    if high_uncovered:
        detail["coverage_warn"] = (
            f"HIGH-UNCOVERED: {uncovered}/{total} units UNCOVERED "
            f"(coverage_fraction={frac} < warn threshold {warn_threshold})"
        )
        return SignalResult(
            signal="coverage-map", ok=True,
            reason=base_reason + f"  [WARN: high-uncovered, threshold {warn_threshold}]",
            artifacts=[str(report)], detail=detail,
        )
    return SignalResult(
        signal="coverage-map", ok=True,
        reason=base_reason,
        artifacts=[str(report)], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (p): RUBRIC coverage map present + uncovered rubric rows surfaced
# <!-- r36-rebuttal: lane-L37-RUBRIC-COVERAGE registered in .auditooor/agent_pathspec.json -->
#
# The COMPLEMENTARY axis to (o) coverage-map. coverage-map is the SURFACE axis
# ("did every contract/fn get a hypothesis?"); this is the RUBRIC axis ("did
# every SEVERITY.md impact ROW get a candidate?"). A workspace cannot be
# certified audit-complete without a rubric-coverage report enumerating every
# rubric row and classifying covered vs UNCOVERED. The report is produced by
# tools/rubric-coverage-workspace-check.py --write-report and reuses the R52
# load-bearing-noun HONEST match (a row is covered only when a real candidate's
# impact wording genuinely maps to it). ABSENCE fails closed
# (fail-no-rubric-coverage). LOW coverage does NOT fail - it emits a loud,
# non-fatal warn carrying the UNCOVERED rubric rows (the impact classes NObody
# attempted). Mirrors coverage-map exactly: fail on absence, warn on low.
# --------------------------------------------------------------------------
_RUBRIC_COVERAGE_SCHEMA = "auditooor.workspace_rubric_coverage.v1"
_RUBRIC_COVERAGE_WARN_FRACTION_DEFAULT = 0.50


def _rubric_coverage_warn_fraction() -> float:
    raw = os.environ.get("AUDITOOOR_L37_RUBRIC_WARN_FRACTION", "").strip()
    if not raw:
        return _RUBRIC_COVERAGE_WARN_FRACTION_DEFAULT
    try:
        v = float(raw)
    except ValueError:
        return _RUBRIC_COVERAGE_WARN_FRACTION_DEFAULT
    if v < 0.0 or v > 1.0:
        return _RUBRIC_COVERAGE_WARN_FRACTION_DEFAULT
    return v


def check_rubric_coverage(ws: Path) -> SignalResult:
    report = ws / ".auditooor" / "rubric_coverage_report.json"
    if not _is_file(report):
        return SignalResult(
            signal="rubric-coverage", ok=False,
            reason=(
                "no RUBRIC coverage report "
                "(.auditooor/rubric_coverage_report.json); cannot certify that "
                "every SEVERITY.md impact class was attempted. Run "
                "tools/rubric-coverage-workspace-check.py --write-report "
                f"{ws}"
            ),
            artifacts=[], detail={"rubric_coverage_report": str(report)},
        )
    obj = _load_json(report) or {}
    schema = str(obj.get("schema", "")).strip()
    total = obj.get("total_rows")
    covered = obj.get("rows_with_candidate")
    uncovered = obj.get("rows_uncovered")
    frac = obj.get("rubric_coverage_fraction")
    uncovered_rows = obj.get("uncovered_rows")

    # A present-but-malformed report (missing the load-bearing counts) cannot
    # answer the rubric-coverage question; fail closed so it is not silently
    # credited (mirrors coverage-map's malformed-report guard).
    if schema != _RUBRIC_COVERAGE_SCHEMA or not isinstance(total, int) or \
            not isinstance(uncovered, int) or not isinstance(frac, (int, float)):
        return SignalResult(
            signal="rubric-coverage", ok=False,
            reason=(
                f"rubric coverage report present ({report.name}) but malformed "
                "(missing schema/total_rows/rows_uncovered/"
                "rubric_coverage_fraction); cannot read the rubric-coverage signal"
            ),
            artifacts=[str(report)],
            detail={"rubric_coverage_report": str(report), "schema": schema,
                    "total_rows": total, "rows_uncovered": uncovered},
        )

    warn_threshold = _rubric_coverage_warn_fraction()
    low_coverage = total > 0 and float(frac) < warn_threshold
    # Compact uncovered-row labels for the verdict surface (the impact classes
    # NObody attempted) - ALWAYS surfaced, never papered over.
    uncovered_labels: list[str] = []
    if isinstance(uncovered_rows, list):
        for r in uncovered_rows:
            if isinstance(r, dict):
                rid = f"{r.get('rubric_id')} " if r.get("rubric_id") else ""
                uncovered_labels.append(
                    f"[{r.get('tier', '?')}] {rid}{str(r.get('sentence', ''))[:80]}"
                )

    detail = {
        "rubric_coverage_report": str(report),
        "total_rows": total,
        "rows_with_candidate": covered,
        "rows_uncovered": uncovered,  # TRUE count, always surfaced
        "rubric_coverage_fraction": frac,
        "candidates_scanned": obj.get("candidates_scanned"),
        "warn_threshold": warn_threshold,
        "low_coverage": low_coverage,
        "uncovered_rows": uncovered_labels,  # the impact classes NObody tried
    }

    base_reason = (
        f"rubric coverage report present: {covered}/{total} rubric rows have "
        f">=1 candidate, {uncovered} impact class(es) UNATTEMPTED "
        f"(rubric_coverage_fraction={frac})"
    )
    if uncovered_labels:
        base_reason += " :: UNCOVERED: " + " | ".join(uncovered_labels[:6])

    # 100%-terminal axis (RUBRIC): under strict every UNATTEMPTED rubric impact row
    # must reach a terminal verdict. A row is terminal when it has >=1 candidate
    # (covered) OR carries an explicit N-A-with-reason (or a candidate) in
    # .auditooor/rubric_attempt_dispositions.jsonl keyed on the rubric sentence /
    # id. An unattempted row with neither a candidate NOR an N-A reason is a hidden
    # gap and FAILs under strict. Operator waiver: a `rubric-coverage:<reason>`
    # rebuttal line (standard signal-rebuttal path). NEVER-FALSE-PASS: a bare/uncited
    # disposition entry is rejected by _load_terminal_dispositions.
    dispositions = _load_terminal_dispositions(ws, "rubric_attempt_dispositions.jsonl")
    non_terminal_rows: list[str] = []
    if isinstance(uncovered_rows, list):
        for r in uncovered_rows:
            if not isinstance(r, dict):
                continue
            sent = str(r.get("sentence", "")).strip()
            rid = str(r.get("rubric_id", "")).strip()
            keyed = (sent in dispositions) or (rid and rid in dispositions)
            if not keyed:
                non_terminal_rows.append(f"[{r.get('tier', '?')}] {sent[:80]}")
    strict = _rubric_attempt_strict()
    detail["strict"] = strict
    detail["rubric_non_terminal_rows"] = len(non_terminal_rows)
    detail["rubric_non_terminal_sample"] = non_terminal_rows[:12]
    if strict and non_terminal_rows:
        return SignalResult(
            signal="rubric-coverage", ok=False,
            reason=(
                base_reason + f"  [STRICT FAIL: {len(non_terminal_rows)} rubric "
                "impact row(s) UNATTEMPTED with no candidate and no explicit N-A "
                "reason - author a candidate, add a .auditooor/rubric_attempt_"
                "dispositions.jsonl {row/sentence,reason} N-A row, or waive with a "
                "`rubric-coverage:<reason>` rebuttal line]"
            ),
            artifacts=[str(report)], detail=detail,
        )

    # The signal PASSES whenever a valid report is present (presence is the
    # requirement; low coverage is informational/warn, not a fail).
    if low_coverage:
        detail["rubric_coverage_warn"] = (
            f"LOW-RUBRIC-COVERAGE: {uncovered}/{total} impact class(es) "
            f"UNATTEMPTED (rubric_coverage_fraction={frac} < warn threshold "
            f"{warn_threshold})"
        )
        return SignalResult(
            signal="rubric-coverage", ok=True,
            reason=base_reason + f"  [WARN: low rubric coverage, threshold {warn_threshold}]",
            artifacts=[str(report)], detail=detail,
        )
    return SignalResult(
        signal="rubric-coverage", ok=True,
        reason=base_reason,
        artifacts=[str(report)], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (q): HUNT-TRUST - is the hunt behind the coverage numbers trustworthy?
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
#
# coverage-map (o) and rubric-coverage (p) report COUNTS. This signal asks the
# meta-question: can you TRUST the hunt those counts came from? A workspace
# whose per-function LLM hunt was rate-limited into ~0 real anchored hypotheses
# (dydx + morpho, 2026-05-28) can still show "covered" units that came only
# from a handful of agent artifacts while the actual per-function hunt produced
# NOTHING. Coverage you cannot trust the hunt behind is not real coverage.
#
# The signal delegates to tools/hunt-run-health-check.py (schema
# auditooor.hunt_run_health.v1). It reads its verdict in two ways, preferring a
# pre-generated report so the Makefile can wire report-generation before the
# gate (mirroring the coverage-report / rubric-report wires for (o)/(p)):
#   1. report-file: <ws>/.auditooor/hunt_run_health_report.json (the Makefile
#      wire writes the build_report() payload here).
#   2. fallback: IMPORT hunt-run-health-check.py read-only and call
#      build_report() against the corpus derived-root, keyed off the workspace
#      basename. This makes the signal work even before the Makefile wire lands.
#
# WARN-NOT-FAIL discipline (mirrors (o)/(p), but even softer - hunt-trust is a
# pure caveat, it never even requires the report to be PRESENT):
#   - verdict == failed-run / needs_re_hunt -> a LOUD warn ("HUNT FAILED-RUN:
#     coverage is NOT trustworthy, re-hunt before relying on it") carrying the
#     success_fraction + rate_limited count. Signal still PASSES.
#   - verdict == degraded -> a SOFTER warn. Signal still PASSES.
#   - verdict == healthy / insufficient-data / no-records / unavailable ->
#     PASS quiet (no warn).
# Rebuttable like every L37 signal via `l37-rebuttal: hunt-trust: <reason>`.
#
# It only ever DOWNGRADES to a fail under the explicit `--strict` env flag (a
# production audit that has a failed-run hunt behind its coverage should not be
# silently certified); default mode never fails, so the gate's certification
# behavior is unchanged for everyone who does not opt in.
# --------------------------------------------------------------------------
_HUNT_RUN_HEALTH_SCHEMA = "auditooor.hunt_run_health.v1"
_HUNT_TRUST_REPORT_REL = (".auditooor", "hunt_run_health_report.json")
_HUNT_TRUST_FAILED_VERDICTS = {"failed-run"}
_HUNT_TRUST_DEGRADED_VERDICTS = {"degraded"}
# verdicts that mean "no trust problem to surface": a healthy hunt, a hunt too
# small to condemn, or no hunt records at all (nothing to caveat).
_HUNT_TRUST_QUIET_VERDICTS = {
    # "healthy-clean": the per-function hunt mechanically engaged the surface
    # (each function got an explicit applies_to_target verdict) but anchored
    # few/no findings - i.e. a trustworthy clean / low-yield run on a target
    # that genuinely has little to find. That is NOT a trust problem; a clean
    # 0-finding workspace must be able to certify. See hunt-run-health-check
    # verdict_for() engaged-vs-empty distinction.
    "healthy", "healthy-clean", "insufficient-data", "no-records", "unavailable",
}


def _hunt_trust_strict() -> bool:
    return os.environ.get("AUDITOOOR_L37_HUNT_TRUST_STRICT", "").strip() not in (
        "", "0", "false", "no",
    )


def _load_hunt_run_health_module():
    """Load tools/hunt-run-health-check.py read-only (finite-H owns it; we never
    edit it). Returns the module or None when it is not on disk / fails to load.
    """
    tool_path = Path(__file__).resolve().with_name("hunt-run-health-check.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_hunt_run_health_acc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_hunt_run_health_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _hunt_run_health_payload(ws: Path) -> tuple[dict | None, str]:
    """Resolve the hunt-run-health report for ``ws``. Returns (payload, source).

    source in {"report-file", "import", "unavailable"}. Preference order:
      1. a pre-generated report at <ws>/.auditooor/hunt_run_health_report.json
         (the Makefile wire writes build_report() output here, mirroring the
         coverage-report / rubric-report wires).
      2. IMPORT hunt-run-health-check.build_report() and generate it live.
    Never raises; degrades to (None, "unavailable") on any error.
    """
    # 1. report-file (the Makefile-wired path)
    report = ws.joinpath(*_HUNT_TRUST_REPORT_REL)
    if _is_file(report):
        obj = _load_json(report)
        if isinstance(obj, dict) and obj.get("verdict"):
            return obj, "report-file"

    # 2. import + build_report() fallback
    mod = _load_hunt_run_health_module()
    if mod is None or not hasattr(mod, "build_report"):
        return None, "unavailable"
    # The derived corpus root the hunt sidecars live under. Default to the MCP
    # repo's audit/corpus_tags/derived (two parents up from this tool, then
    # audit/corpus_tags/derived). Env override for non-default layouts / tests.
    derived_override = os.environ.get("AUDITOOOR_L37_DERIVED_ROOT", "").strip()
    if derived_override:
        derived_root = Path(os.path.expanduser(derived_override))
    else:
        repo_root = Path(__file__).resolve().parents[1]
        derived_root = repo_root / "audit" / "corpus_tags" / "derived"
    if not _exists(derived_root) or not derived_root.is_dir():
        return None, "unavailable"
    try:
        payload = mod.build_report(derived_root, ws.name, str(ws))
    except Exception:
        return None, "unavailable"
    if isinstance(payload, dict) and payload.get("verdict"):
        return payload, "import"
    return None, "unavailable"


def check_hunt_trust(ws: Path) -> SignalResult:
    payload, source = _hunt_run_health_payload(ws)

    if payload is None:
        # No hunt-run-health signal available at all. This is NOT a problem to
        # surface (there may simply be no LLM hunt records for this workspace);
        # the signal passes quiet so it never blocks a non-LLM-hunt workspace.
        # NOTE: signal-UNAVAILABLE is distinct from the never-ran no-records
        # verdict below - here the gate could not even resolve a report.
        return SignalResult(
            signal="hunt-trust", ok=True,
            reason=(
                "hunt-run-health signal unavailable (no report-file and "
                "hunt-run-health-check.py / corpus derived-root not reachable); "
                "no coverage-trust caveat to surface"
            ),
            artifacts=[],
            detail={"hunt_run_health": "unavailable", "source": source},
        )

    verdict = str(payload.get("verdict", "")).strip().lower()
    total = payload.get("total_records")
    success = payload.get("success")
    rate_limited = payload.get("rate_limited")
    frac = payload.get("success_fraction")
    needs_re_hunt = bool(payload.get("needs_re_hunt"))
    # Strict for hunt-trust fires on the standalone AUDITOOOR_L37_HUNT_TRUST_STRICT
    # opt-in OR the main L37 gate (AUDITOOOR_L37_STRICT=1, what `make audit-complete
    # STRICT=1` sets). PRIOR BUG (strata 2026-07-01): failed-run keyed only on the
    # standalone flag, so a genuinely untrustworthy hunt sailed through the main
    # STRICT gate; and `degraded` had NO strict path at all. A production audit
    # STRICT-certified must not green a hunt the hunt-trust meta-signal calls
    # untrustworthy - see the degraded branch below.
    strict = _hunt_trust_strict() or _l37_gate_strict("HUNT_TRUST")

    detail = {
        "source": source,
        "hunt_run_health_verdict": verdict,
        "total_records": total,
        "success": success,
        "rate_limited": rate_limited,
        "success_fraction": frac,
        "needs_re_hunt": needs_re_hunt,
        "hunt_dirs_scanned": payload.get("hunt_dirs_scanned"),
    }

    # --- failed-run / needs-re-hunt: the LOUD caveat ---
    if verdict in _HUNT_TRUST_FAILED_VERDICTS or needs_re_hunt:
        warn = (
            f"HUNT FAILED-RUN: coverage is NOT trustworthy, re-hunt before "
            f"relying on it - the per-function hunt for this workspace produced "
            f"success_fraction={frac} ({success}/{total} records anchored, "
            f"{rate_limited} rate-limited). The coverage-map (o)/rubric-coverage "
            f"(p) numbers came from a hunt that effectively did not run."
        )
        detail["hunt_trust_warn"] = warn
        if strict:
            # opt-in: a production audit must not be certified with a failed-run
            # hunt behind its coverage.
            return SignalResult(
                signal="hunt-trust", ok=False,
                reason=warn + " [STRICT: failing closed]",
                artifacts=[], detail=detail,
            )
        return SignalResult(
            signal="hunt-trust", ok=True,
            reason=warn + "  [WARN: hunt-trust, signal passes]",
            artifacts=[], detail=detail,
        )

    # --- degraded: coverage trust genuinely reduced ---
    # `degraded` means hunt-run-health's ran_frac (success + engaged) < the healthy
    # fraction: the per-function hunt did NOT mechanically engage most of the
    # surface (the bulk of records are `empty` - ran but produced no anchor AND no
    # explicit applies_to_target verdict). This is distinct from `healthy-clean`
    # (ran_frac >= healthy: the model engaged every function and cleanly declined),
    # which passes quiet. So failing `degraded` under STRICT punishes UNDER-
    # ENGAGEMENT, never a genuinely-clean 0-finding audit. PRIOR BUG (strata
    # 2026-07-01): this branch had no strict path, so a STRICT audit-complete
    # certified honest-0 over a hunt that only engaged 18% of its 814 records
    # (the corpus-driven-hunt proof-queue hypotheses were grounding-resolved but
    # never individually verdicted). Fail closed under the main L37 gate; the
    # default stays an advisory WARN-pass, and an operator with a genuine reason
    # can still l37-rebuttal the signal.
    if verdict in _HUNT_TRUST_DEGRADED_VERDICTS:
        warn = (
            f"HUNT DEGRADED: coverage trust is reduced - success_fraction={frac} "
            f"({success}/{total} records anchored, {rate_limited} rate-limited). "
            f"The hunt engaged fewer than half its records with a real per-function "
            f"verdict; most records are empty (ran but anchored nothing and gave no "
            f"applies_to_target). Re-hunt to drive the surface to real verdicts "
            f"before certifying coverage."
        )
        detail["hunt_trust_warn"] = warn
        if strict:
            return SignalResult(
                signal="hunt-trust", ok=False,
                reason=warn + " [STRICT: failing closed]",
                artifacts=[], detail=detail,
            )
        return SignalResult(
            signal="hunt-trust", ok=True,
            reason=warn + "  [WARN: hunt-trust, signal passes]",
            artifacts=[], detail=detail,
        )

    # --- no-records: the NEVER-RAN-WITH-EVIDENCE caveat ---
    # The hunt-run-health signal found ZERO anchored hunt records for this
    # workspace (total_records==0, typically hunt_dirs_scanned==[]). The prior
    # implementation greened this as "coverage is trustworthy", which is the
    # presence-only / vacuous-pass trap: a hunt that never anchored a single
    # record cannot vouch that coverage was hunted with evidence. Surface it as
    # a caveat (WARN by default, fail-closed under strict). This is distinct
    # from ``insufficient-data`` / ``healthy`` below, which prove the hunt RAN
    # and anchored >0 records, and distinct from the ``payload is None``
    # signal-unavailable branch above. Strict here = autonomous-proof-conversion
    # OR the HUNT_TRUST L37 toggle (mirrors the chain-synth strict idiom), so an
    # opt-in production audit fails closed on a never-ran hunt while the default
    # stays advisory WARN-pass.
    if verdict == "no-records":
        nr_strict = (
            _enforce_autonomous_proof_conversion()
            or _l37_gate_strict("HUNT_TRUST")
        )
        warn = (
            f"HUNT NO-RECORDS: the per-function hunt produced ZERO anchored "
            f"records for this workspace (total_records={total}, "
            f"hunt_dirs_scanned={payload.get('hunt_dirs_scanned')}); the "
            f"hunt-trust signal cannot vouch that coverage was hunted with "
            f"evidence - this is a never-ran-with-evidence state, not a "
            f"trustworthy-coverage state."
        )
        detail["hunt_trust_warn"] = warn
        detail["strict"] = nr_strict
        if nr_strict:
            return SignalResult(
                signal="hunt-trust", ok=False,
                reason=warn + " [STRICT: failing closed]",
                artifacts=[], detail=detail,
            )
        return SignalResult(
            signal="hunt-trust", ok=True,
            reason=warn + "  [WARN: hunt-trust, signal passes]",
            artifacts=[], detail=detail,
        )

    # --- healthy / insufficient-data: RAN WITH EVIDENCE, pass quiet ---
    # These verdicts prove the hunt RAN and anchored >0 records (healthy = at/
    # above the healthy success fraction; insufficient-data = ran but too few
    # records to condemn). A genuinely-clean workspace that hunted and found
    # nothing to caveat stays GREEN here, even under strict.
    return SignalResult(
        signal="hunt-trust", ok=True,
        reason=(
            f"hunt-run-health verdict={verdict or 'unknown'} "
            f"(success_fraction={frac}, {success}/{total} anchored); "
            "the hunt ran with evidence - coverage is trustworthy / no "
            "failed-run caveat"
        ),
        artifacts=[], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (r): WHOLE-WORKSPACE honesty - not hollow / fake-coverage / mock-only
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# L37 already certifies that each pipeline STAGE left an artifact behind, but a
# workspace can leave every artifact behind and still be HOLLOW: 100%-reported
# coverage that is really budget-skipped, "engines ran" that are really
# engine-error / assert(true) advisory stubs, or a harness whose only target is
# a Mock reimplementation rather than in-scope source. tools/audit-honesty-check.py
# is the whole-workspace honesty gate that computes the HONEST numbers and emits
# those hollow-class verdicts. This signal delegates to it and fails L37 (verdict
# ``fail-hollow-not-genuinely-audited``) when the honesty gate returns ANY of the
# four HARD hollow verdicts:
#     fail-fake-coverage | fail-hollow-engines | fail-mock-target | fail-stub-harnesses
# It deliberately does NOT fail on the SOFTER honesty signals
# (``coverage-below-100`` / ``needs-work`` standing alone): L37 has its own
# coverage-map / rubric-coverage axes for the coverage question, and a partial
# coverage fraction is a warn-not-fail there. We inspect honesty's full ``fails``
# LIST (not just its single top-level ``verdict``) because when several gaps
# co-occur the honesty verdict aggregates to ``needs-work`` while a HARD hollow
# verdict is still present in the list.
#
# Graceful degradation (mirrors how the other OPTIONAL L37 signals degrade): if
# the honesty tool is missing, unimportable, or raises, this signal WARNS and
# PASSES rather than hard-failing L37 on tooling-absence. Operators mark
# hollow-but-intentional (e.g. a greenfield workspace with no engine harnesses
# yet) via the EXISTING audit_completeness_rebuttal.txt mechanism using the
# signal name ``hollow-not-genuinely-audited`` (or ``all:``).
# --------------------------------------------------------------------------
_HONESTY_HARD_FAILS = frozenset({
    "fail-fake-coverage",
    "fail-hollow-engines",
    "fail-mock-target",
    "fail-stub-harnesses",
    # R81: a "genuinely audited" claim with coverage/engines present but ZERO
    # fresh depth-layer evidence (no per-guard negative-space + sibling-diff
    # cert) is itself hollow. audit-honesty-check.py emits fail-depth-not-run;
    # registering it here routes it through the existing
    # fail-hollow-not-genuinely-audited path so the depth layer underpins
    # pass-genuinely-audited the same way R80 underpins honesty.
    "fail-depth-not-run",
    # R80/R81: per-function harnesses were generated and ran but every one
    # returned error/silent-skip (0 mutation-verified genuine). Detected by
    # the DEEP_AUDIT_HOLLOW.flag + genuine_coverage_manifest double-check in
    # audit-honesty-check.py. Cross-function kills do NOT substitute for
    # per-function conservation evidence on value-moving functions.
    "fail-hollow-per-function-harnesses",
})


def _load_audit_honesty_module():
    """Load tools/audit-honesty-check.py if it is on disk; else None."""
    tool_path = Path(__file__).resolve().with_name("audit-honesty-check.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_audit_honesty_acc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_audit_honesty_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def check_honesty(ws: Path) -> SignalResult:
    mod = _load_audit_honesty_module()
    if mod is None or not hasattr(mod, "check") or not hasattr(mod, "_detect_lang"):
        # Tooling absent / unimportable: fail-closed under strict (the honesty
        # gate IS the hollow-workspace detection layer; its absence under strict
        # is itself a hollow-pass risk).  Outside strict, degrade gracefully.
        # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
        if _l37_gate_strict("HONESTY"):
            return SignalResult(
                signal="hollow-not-genuinely-audited", ok=False,
                reason=(
                    "audit-honesty-check.py unavailable; STRICT mode requires "
                    "honesty tooling to be present "
                    "(AUDITOOOR_L37_HONESTY_STRICT=1 or AUDITOOOR_L37_STRICT=1)"
                ),
                artifacts=[], detail={"honesty_tool": "unavailable", "strict": True},
            )
        return SignalResult(
            signal="hollow-not-genuinely-audited", ok=True,
            reason=(
                "audit-honesty-check.py unavailable; honesty signal degraded to "
                "WARN-pass (tooling-absence does not block L37 outside strict mode)"
            ),
            artifacts=[], detail={"honesty_tool": "unavailable", "strict": False},
        )
    try:
        lang = mod._detect_lang(ws)
        res = mod.check(ws, lang)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="hollow-not-genuinely-audited", ok=True,
            reason=(
                f"audit-honesty-check raised ({exc}); honesty signal degraded to "
                "WARN-pass (tooling-error does not block L37)"
            ),
            artifacts=[], detail={"honesty_error": str(exc)},
        )

    honesty_verdict = res.get("verdict")
    honesty_fails = res.get("fails") or []
    hard_present = sorted(set(honesty_fails) & _HONESTY_HARD_FAILS)
    detail = {
        "honesty_verdict": honesty_verdict,
        "honesty_fails": honesty_fails,
        "hard_hollow_fails": hard_present,
        "honesty_gaps": res.get("gaps", []),
    }
    if hard_present:
        return SignalResult(
            signal="hollow-not-genuinely-audited", ok=False,
            reason=(
                "audit-honesty-check flags the workspace as HOLLOW (not genuinely "
                f"audited): {', '.join(hard_present)}"
                + (f"; honesty-verdict={honesty_verdict}" if honesty_verdict else "")
                + (f"; gaps: {'; '.join(res.get('gaps', [])[:3])}" if res.get("gaps") else "")
            ),
            artifacts=[], detail=detail,
        )
    # No HARD hollow verdict. Softer signals (coverage-below-100 / needs-work
    # standing alone) do NOT fail L37 here - L37's own coverage-map / rubric
    # axes cover the coverage question as warn-not-fail.
    return SignalResult(
        signal="hollow-not-genuinely-audited", ok=True,
        reason=(
            f"audit-honesty-check verdict={honesty_verdict or 'unknown'}: no HARD "
            "hollow verdict (fake-coverage / hollow-engines / mock-target / "
            "stub-harnesses) present"
            + (f"; soft signals: {', '.join(honesty_fails)}" if honesty_fails else "")
        ),
        artifacts=[], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal: depth-certificate (R81)
#
# The per-UNIT depth axis. ``make audit-deep`` now runs two depth passes - the
# per-guard NEGATIVE-SPACE pass and the proactive SIBLING-PATH guard-diff pass -
# and stamps a roll-up cert at ``<ws>/.auditooor/depth_certificate.json``.
# tools/depth-certificate-check.py is the GATE over that cert; it exposes a
# reusable ``check_depth(ws) -> dict``. This signal delegates to it and FAILS
# L37 (verdict ``fail-no-depth-certificate``) when the cert is absent, stale,
# missing a depth pass, has an unvalidated survivor, or trips the zero-findings
# smell. It is the R80-style EXTEND-not-duplicate path: one tool owns the cert
# logic; L37 imports it. The depth tool's own r81-rebuttal (read from
# ``depth_certificate_rebuttal.txt``) is honored INSIDE check_depth, and L37's
# l37-rebuttal (signal key ``depth-certificate:``) overrides on top in evaluate().
#
# Graceful degradation: if the depth tool is missing / unimportable / raises,
# this signal WARNS and PASSES rather than hard-failing L37 on tooling-absence
# (mirrors the honesty/optional signals).
# --------------------------------------------------------------------------
def _load_depth_cert_module():
    """Load tools/depth-certificate-check.py if it is on disk; else None."""
    tool_path = Path(__file__).resolve().with_name("depth-certificate-check.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_depth_cert_acc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_depth_cert_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


# The depth verdicts that are an actual FAIL of the depth layer (vs an
# ok-rebuttal / pass). All of them map to L37's single fail-no-depth-certificate.
_DEPTH_FAIL_VERDICTS = frozenset({
    "fail-no-depth-certificate",
    "fail-depth-pending",
    # fail-depth-not-run: the producer wrote a cert whose verdict is
    # ``depth-not-run`` - the depth passes never ran. This MUST fail L37, not
    # WARN-pass: a present-but-not-run cert is the vacuous-pass trap (item 4).
    # ``depth-audited`` stays reachable when the mechanical passes ran with
    # evidence and survivors carry a recorded disposition; ``depth-not-run`` /
    # ``depth-pending`` stay failing when that real work is absent.
    "fail-depth-not-run",
    "fail-negative-space-not-run",
    "fail-sibling-diff-not-run",
    "fail-survivors-unvalidated",
    "fail-zero-findings-smell",
    # fail-depth-stale (strata 2026-07-01, loop-caught): the cert's mtime is
    # OLDER than one of its depth inputs (inscope_units.jsonl / negative_space_*
    # / dataflow_paths.jsonl / sibling_guard_asymmetries.jsonl). The tool's own
    # docstring names this "the ~537x-stale-cert failure mode that kept a
    # workspace silently at depth-pending while the cert claimed otherwise" -
    # yet this verdict was OMITTED from the fail set, so the L37 signal
    # WARN-passed a stale cert, reproducing the exact bug it exists to catch.
    "fail-depth-stale",
    "error",
})


def check_depth_certificate(ws: Path) -> SignalResult:
    mod = _load_depth_cert_module()
    if mod is None or not hasattr(mod, "check_depth"):
        # Tooling absent / unimportable: fail-closed under strict (depth-cert is
        # the R81 layer; its absence under strict voids the depth guarantee).
        # Outside strict, degrade gracefully.
        # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
        if _l37_gate_strict("DEPTH_CERTIFICATE"):
            return SignalResult(
                signal="depth-certificate", ok=False,
                reason=(
                    "depth-certificate-check.py unavailable; STRICT mode requires "
                    "depth tooling to be present "
                    "(AUDITOOOR_L37_DEPTH_CERTIFICATE_STRICT=1 or "
                    "AUDITOOOR_L37_STRICT=1)"
                ),
                artifacts=[], detail={"depth_tool": "unavailable", "strict": True},
            )
        return SignalResult(
            signal="depth-certificate", ok=True,
            reason=(
                "depth-certificate-check.py unavailable; depth signal degraded to "
                "WARN-pass (tooling-absence does not block L37)"
            ),
            artifacts=[], detail={"depth_tool": "unavailable"},
        )
    try:
        res = mod.check_depth(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        # G11: a RAISED exception must fail closed under strict exactly like the
        # module-absent branch above and like a returned verdict="error" (which is
        # in _DEPTH_FAIL_VERDICTS). Previously this branch unconditionally
        # WARN-passed, so a depth tool that CRASHED greened the R81 depth guarantee
        # under STRICT - stricter for a clean "error" verdict than for a crash.
        # pre-existing gate (the module-absent branch above already calls this same
        # _l37_gate_strict("DEPTH_CERTIFICATE")); mirroring it is not a new rule.
        # <!-- admitted: signal:DEPTH_CERTIFICATE -->
        if _l37_gate_strict("DEPTH_CERTIFICATE"):
            return SignalResult(
                signal="depth-certificate", ok=False,
                reason=(
                    f"depth-certificate-check raised ({exc}); STRICT mode requires "
                    "depth tooling to run cleanly "
                    "(AUDITOOOR_L37_DEPTH_CERTIFICATE_STRICT=1 or AUDITOOOR_L37_STRICT=1)"
                ),
                artifacts=[], detail={"depth_error": str(exc), "strict": True},
            )
        return SignalResult(
            signal="depth-certificate", ok=True,
            reason=(
                f"depth-certificate-check raised ({exc}); depth signal degraded to "
                "WARN-pass (tooling-error does not block L37)"
            ),
            artifacts=[], detail={"depth_error": str(exc)},
        )

    depth_verdict = (res or {}).get("verdict")
    depth_reason = (res or {}).get("reason", "")
    cert_path = (res or {}).get("cert_path")
    detail = {
        "depth_verdict": depth_verdict,
        "depth_reason": depth_reason,
        "depth_detail": (res or {}).get("detail", {}),
        "cert_path": cert_path,
    }
    if depth_verdict in _DEPTH_FAIL_VERDICTS:
        return SignalResult(
            signal="depth-certificate", ok=False,
            reason=(
                "depth-certificate-check FAILS the per-unit depth layer "
                f"({depth_verdict}): {depth_reason}"
            ),
            artifacts=[str(cert_path)] if cert_path else [], detail=detail,
        )
    # pass-depth-audited / ok-rebuttal (the depth tool already honored its own
    # r81-rebuttal): the depth layer is satisfied.
    return SignalResult(
        signal="depth-certificate", ok=True,
        reason=(
            f"depth-certificate-check verdict={depth_verdict or 'unknown'}: "
            "per-guard negative-space + sibling-path guard-diff ran with evidence"
        ),
        artifacts=[str(cert_path)] if cert_path else [], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal: function-coverage (s)
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# The per-FUNCTION ATTACK axis, sibling to depth-certificate. coverage-map (o)
# credits a unit "covered" when ANY hypothesis / hunt-hit / candidate token
# references it - and that token can be a noise CCIA heuristic angle (it flagged
# a TEST-helper callback as "MEDIUM unauthenticated") or a vacuous per-function
# harness (Morpho: 79 harnesses, only 4/179 units real). This signal asks the
# sharper question: did every in-scope FUNCTION get a REAL attack with a
# recorded verdict, not just a token reference?
#
# tools/function-coverage-completeness.py owns the language-aware in-scope-
# function enumeration (Solidity incl. multi-line signatures, Rust/Go/Move/
# Cairo) and the test/lib/mock/interface/script exclusion. This signal
# DELEGATES to it - the R80/depth-certificate EXTEND-not-duplicate path: one
# tool owns the per-function logic, L37 imports and runs it. It FAILS L37
# (verdict ``fail-function-coverage-incomplete``) when the tool reports
# untouched / hollow in-scope functions. It inherits the l37-rebuttal override
# (signal key ``function-coverage:``) applied on top in evaluate().
#
# Tool-interface tolerance: A1 owns the tool and lands in parallel. To stay
# resilient to which reusable entry-point name it exposes, this signal probes
# ``check_function_coverage(ws)`` -> ``check(ws)`` -> ``evaluate(ws)`` /
# ``evaluate(str(ws))`` in turn (mirroring the sibling gates' ``check_depth`` /
# ``evaluate`` conventions). The returned payload's ``verdict`` is matched
# against the function-coverage FAIL set below; anything else PASSES.
#
# Graceful degradation (mirrors depth-certificate): if the tool is missing /
# unimportable / exposes no recognized entry-point / raises, this signal WARNS
# and PASSES rather than hard-failing L37 on tooling-absence.
# --------------------------------------------------------------------------
def _load_function_coverage_module():
    """Load tools/function-coverage-completeness.py if on disk; else None."""
    tool_path = Path(__file__).resolve().with_name(
        "function-coverage-completeness.py"
    )
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "_function_coverage_acc", tool_path
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_function_coverage_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


# Verdicts that are NOT a function-coverage failure even though they are not a
# plain pass: an ``error`` / ``no-inputs`` / ``no-source`` / ``unavailable``
# verdict is tooling/input absence, not an attacked-function deficit, so it
# WARN-passes (mirrors depth-certificate degrading on tooling-absence). Any
# ``ok-rebuttal`` is already an honored rebuttal. Everything else that starts
# with ``fail-`` is treated as a real per-function attack deficit and routes
# through L37's single ``fail-function-coverage-incomplete``. Matching on the
# ``fail-`` PREFIX (rather than an exact enumeration) keeps the wiring resilient
# to whichever exact fail-vocabulary the function-coverage tool ships - e.g. its
# current ``fail-functions-untouched-or-hollow`` - without this gate needing an
# update each time the tool's verdict string changes.
_FUNCTION_COVERAGE_NON_FAIL_VERDICTS = frozenset({
    "error",
    "no-inputs",
    "pass-no-inputs",
    "no-source",
    "pass-no-source",
    "unavailable",
    "ok-rebuttal",
})


def _is_function_coverage_fail(verdict: str | None) -> bool:
    """True iff ``verdict`` denotes a real per-function attack deficit.

    A ``fail-`` prefixed verdict fails UNLESS it is one of the explicit
    tooling/input-absence verdicts (treated as WARN-pass). Non-``fail-``
    verdicts (pass-* / ok-rebuttal / unknown) PASS.
    """
    if not verdict:
        return False
    v = str(verdict).strip().lower()
    if v in _FUNCTION_COVERAGE_NON_FAIL_VERDICTS:
        return False
    return v.startswith("fail-")


# SHARED CONTRACT (per-language producers): the ONE canonical mutation-coverage
# file every gate reads is <ws>/.auditooor/mutation_verify_coverage.json. When
# the producer has written it, L37 MUST consume the producer's mutation evidence
# (a harness only counts as a real per-function attack when it is mutation-
# verified non-vacuous - the R80 finding-evidence-honesty discipline applied at
# the coverage-gate level). We enable the function-coverage tool's
# ``mutation_verify`` bar when that producer file exists OR when the operator set
# the env opt-in, and otherwise preserve current (fast, syntactic-anti-stub)
# behavior so producer-less workspaces are unchanged.
_MUTATION_VERIFY_COVERAGE_REL = (".auditooor", "mutation_verify_coverage.json")
_MUTATION_VERIFY_COVERAGE_ALT_REL = (".auditooor", "mutation-verify-coverage.json")


def _producer_mutation_evidence_present(ws: Path) -> bool:
    for rel in (_MUTATION_VERIFY_COVERAGE_REL, _MUTATION_VERIFY_COVERAGE_ALT_REL):
        p = ws.joinpath(*rel)
        try:
            if p.is_file() and p.stat().st_size > 0:
                return True
        except OSError:
            continue
    return False


def _function_coverage_mutation_verify_enabled(ws: Path) -> bool:
    env = os.environ.get("AUDITOOOR_FCC_MUTATION_VERIFY", "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    return _producer_mutation_evidence_present(ws)


# Sentinel returned by _call_function_coverage_gate when the module exposes
# NONE of the recognized entry-point names. Distinct from None (which means
# "entry-point found and called, but returned None/non-dict").
# r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
_NO_ENTRY_POINT = object()


def _call_function_coverage_gate(mod, ws: Path):
    """Probe the recognized reusable entry-points in order.

    Returns:
      - a dict:             entry-point found and returned a valid payload
      - None:               entry-point found but returned None / non-dict
      - _NO_ENTRY_POINT:    no recognized entry-point attribute on the module

    Raises on an unhandled exception (the caller degrades raises to WARN-pass).

    When the SHARED-CONTRACT producer mutation-evidence file is present (or the
    env opt-in is set), the ``evaluate`` entry-point is invoked with
    ``mutation_verify=True`` so the gate consumes the producer's mutation
    verdicts (a harness-derived attack must be mutation-verified non-vacuous).
    The ``check_function_coverage`` / ``check`` aliases are tried first for
    interface resilience; if either exists it is assumed to encapsulate the
    workspace's own mutation policy.
    r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    """
    if hasattr(mod, "check_function_coverage"):
        return mod.check_function_coverage(ws)
    if hasattr(mod, "check"):
        return mod.check(ws)
    if hasattr(mod, "evaluate"):
        mv = _function_coverage_mutation_verify_enabled(ws)
        # evaluate may take a Path or a str, and may or may not accept the
        # mutation_verify kwarg. Try the richest call first, degrade to the
        # plain forms so an older tool signature still works.
        try:
            return mod.evaluate(ws, mutation_verify=mv)
        except TypeError:
            pass
        try:
            return mod.evaluate(ws)
        except TypeError:
            return mod.evaluate(str(ws))
    return _NO_ENTRY_POINT


def check_function_coverage(ws: Path) -> SignalResult:
    mod = _load_function_coverage_module()
    if mod is None:
        # Tooling absent / unimportable: degrade gracefully (warn, do not
        # hard-fail L37 on tooling-absence) - mirrors depth-certificate.
        return SignalResult(
            signal="function-coverage", ok=True,
            reason=(
                "function-coverage-completeness.py unavailable; per-function "
                "attack signal degraded to WARN-pass (tooling-absence does not "
                "block L37)"
            ),
            artifacts=[], detail={"function_coverage_tool": "unavailable"},
        )
    try:
        res = _call_function_coverage_gate(mod, ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="function-coverage", ok=True,
            reason=(
                f"function-coverage-completeness raised ({exc}); per-function "
                "attack signal degraded to WARN-pass (tooling-error does not "
                "block L37)"
            ),
            artifacts=[], detail={"function_coverage_error": str(exc)},
        )

    if res is _NO_ENTRY_POINT:
        # Module loaded but exposes none of check_function_coverage / check /
        # evaluate: genuine tooling-interface mismatch, degrade gracefully.
        return SignalResult(
            signal="function-coverage", ok=True,
            reason=(
                "function-coverage-completeness exposes no recognized reusable "
                "entry-point (check_function_coverage / check / evaluate); "
                "per-function attack signal degraded to WARN-pass"
            ),
            artifacts=[], detail={"function_coverage_tool": "no-entry-point"},
        )

    if not isinstance(res, dict):
        # Entry-point WAS found and called but returned None or a non-dict
        # payload - this is a tool-side error, not tooling absence.  Under
        # strict mode, fail closed; outside strict, WARN-pass.
        # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
        bad_type_reason = (
            f"function-coverage-completeness entry-point returned a non-dict "
            f"payload (type={type(res).__name__}); tool error - per-function "
            "attack signal cannot be verified"
        )
        if _l37_gate_strict("FUNCTION_COVERAGE"):
            return SignalResult(
                signal="function-coverage", ok=False,
                reason=bad_type_reason,
                artifacts=[], detail={"function_coverage_tool": "bad-return-type"},
            )
        return SignalResult(
            signal="function-coverage", ok=True,
            reason="WARN: " + bad_type_reason,
            artifacts=[], detail={"function_coverage_tool": "bad-return-type"},
        )

    fc_verdict = res.get("verdict")
    fc_reason = res.get("reason", "")
    report_path = res.get("report_path") or res.get("report")
    untouched = res.get("untouched_functions") or res.get("untouched") or []
    detail = {
        "function_coverage_verdict": fc_verdict,
        "function_coverage_reason": fc_reason,
        "function_coverage_detail": res.get("detail", {}),
        "untouched_count": (
            len(untouched) if isinstance(untouched, (list, tuple, set, dict)) else None
        ),
        "report_path": report_path,
    }
    if _is_function_coverage_fail(fc_verdict):
        return SignalResult(
            signal="function-coverage", ok=False,
            reason=(
                "function-coverage-completeness FAILS the per-function attack "
                f"layer ({fc_verdict}): {fc_reason}"
            ),
            artifacts=[str(report_path)] if report_path else [], detail=detail,
        )
    # pass-* / ok-rebuttal / no-inputs / no-source / error / unknown all PASS
    # (the tool already honored its own rebuttal; error / no-inputs / no-source
    # are absence, not a per-function deficit).
    return SignalResult(
        signal="function-coverage", ok=True,
        reason=(
            f"function-coverage-completeness verdict={fc_verdict or 'unknown'}: "
            "every in-scope function was attacked with a real verdict (or no "
            "in-scope functions / inputs present)"
        ),
        artifacts=[str(report_path)] if report_path else [], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal: cross-function-coverage
# <!-- r36-rebuttal: lane-B-CROSS-FUNCTION-INVARIANT registered -->
#
# The COMPOSITION axis. coverage-map (o) credits a unit "covered" on any
# hypothesis token; function-coverage (s) credits a FUNCTION on a real
# per-function attack; depth-certificate (R81) credits per-guard negative-space
# + sibling-path asymmetry. NONE of them asks the COMPOSITION question: "is
# there a MUTATION-VERIFIED test asserting the invariant that spans TWO-OR-MORE
# functions?" - the deposit/withdraw round-trip conservation, the
# open->fund->close state-machine global invariant. A protocol can have 100%
# per-function coverage and still be broken by a composition bug no single-
# function harness expresses.
#
# tools/cross-function-invariant-coverage.py owns the generic, language-aware
# enumeration of cross-function REQUIREMENTS (L30 sibling pairs that both exist
# in-tree + multi-function state-machine sequences detected via shared co-
# mutated state) and the anti-stub mutation-verified coverage check (a
# referencing test with NO mutation kill = uncovered). This signal DELEGATES to
# it - the R80/depth-certificate EXTEND-not-duplicate path: one tool owns the
# composition logic, L37 imports and runs it. It FAILS L37 (verdict
# ``fail-cross-function-uncovered``) when a cross-function requirement lacks a
# mutation-verified test. It inherits the l37-rebuttal override (signal key
# ``cross-function-coverage:``).
#
# Graceful degradation (mirrors depth-certificate / function-coverage): if the
# tool is missing / unimportable / exposes no recognized entry-point / raises,
# this signal WARNS and PASSES rather than hard-failing L37 on tooling-absence.
# pass-no-source / pass-no-requirements / pass-cross-function-covered /
# ok-rebuttal / error all PASS; only a genuine ``fail-cross-function-uncovered``
# fails the signal.
# --------------------------------------------------------------------------
def _load_cross_function_module():
    """Load tools/cross-function-invariant-coverage.py if on disk; else None."""
    tool_path = Path(__file__).resolve().with_name(
        "cross-function-invariant-coverage.py"
    )
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "_cross_function_invariant_acc", tool_path
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclass field() introspection (Python 3.14) can
    # resolve the module dict for the @dataclass default_factory fields.
    sys.modules["_cross_function_invariant_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _call_cross_function_gate(mod, ws: Path):
    """Probe the recognized reusable entry-points in order: check(ws) ->
    evaluate(ws). Returns the gate's payload dict, or raises (the caller
    degrades raises to WARN-pass)."""
    if hasattr(mod, "check"):
        return mod.check(ws)
    if hasattr(mod, "evaluate"):
        try:
            return mod.evaluate(ws)
        except TypeError:
            return mod.evaluate(str(ws))
    return None


def check_cross_function_coverage(ws: Path) -> SignalResult:
    mod = _load_cross_function_module()
    if mod is None:
        # Tooling absent / unimportable: degrade gracefully (warn, do not
        # hard-fail L37 on tooling-absence) - mirrors depth-certificate.
        return SignalResult(
            signal="cross-function-coverage", ok=True,
            reason=(
                "cross-function-invariant-coverage.py unavailable; composition "
                "axis degraded to WARN-pass (tooling-absence does not block L37)"
            ),
            artifacts=[], detail={"cross_function_tool": "unavailable"},
        )
    try:
        res = _call_cross_function_gate(mod, ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="cross-function-coverage", ok=True,
            reason=(
                f"cross-function-invariant-coverage raised ({exc}); composition "
                "axis degraded to WARN-pass (tooling-error does not block L37)"
            ),
            artifacts=[], detail={"cross_function_error": str(exc)},
        )

    if not isinstance(res, dict):
        return SignalResult(
            signal="cross-function-coverage", ok=True,
            reason=(
                "cross-function-invariant-coverage exposes no recognized reusable "
                "entry-point (check / evaluate) returning a dict; composition "
                "axis degraded to WARN-pass"
            ),
            artifacts=[], detail={"cross_function_tool": "no-entry-point"},
        )

    xf_verdict = res.get("verdict")
    xf_reason = res.get("reason", "")
    report_path = res.get("report_path")
    detail = {
        "cross_function_verdict": xf_verdict,
        "cross_function_reason": xf_reason,
        "requirement_count": res.get("requirement_count"),
        "covered_count": res.get("covered_count"),
        "uncovered_count": res.get("uncovered_count"),
        "uncovered": res.get("uncovered", []),
        "mutation_backend_available": res.get("mutation_backend_available"),
        "report_path": report_path,
    }
    # Only a genuine uncovered-requirement fails. pass-* / ok-rebuttal /
    # pass-no-source / pass-no-requirements / error all PASS (error / no-source
    # are absence, not a composition deficit; the tool already honored its own
    # xfi-rebuttal).
    if xf_verdict == "fail-cross-function-uncovered":
        return SignalResult(
            signal="cross-function-coverage", ok=False,
            reason=(
                "cross-function-invariant-coverage FAILS the composition axis "
                f"({xf_verdict}): {xf_reason}"
            ),
            artifacts=[str(report_path)] if report_path else [], detail=detail,
        )
    return SignalResult(
        signal="cross-function-coverage", ok=True,
        reason=(
            f"cross-function-invariant-coverage verdict={xf_verdict or 'unknown'}: "
            "every cross-function invariant requirement has a mutation-verified "
            "test (or no requirements / no source / rebutted)"
        ),
        artifacts=[str(report_path)] if report_path else [], detail=detail,
    )


# --------------------------------------------------------------------------
# Signal: invariant-fuzz (you cannot BUILD an invariant harness and skip fuzzing it)
# r36-rebuttal: lane FIX-INVARIANT-FUZZ-GATE registered in .auditooor/agent_pathspec.json
#
# tools/invariant-fuzz-completeness.py owns the scan: for EVERY invariant harness
# it requires breadth (>=2 invariants), non-vacuity (a mutation-verify test), and
# real engine-run evidence (medusa/echidna corpus / deep-engine fuzz artifact). A
# harness AUTHORED but never fuzzed FAILS. EXTEND-not-duplicate: one tool owns the
# gate, L37 imports + runs it. WARN-passes on tooling-absence (degrade, never
# hard-fail on the tool missing). `pass-no-invariant-harness` PASSES (not every
# workspace/language has an applicable harness).
def _load_invariant_fuzz_module():
    tool_path = Path(__file__).resolve().with_name("invariant-fuzz-completeness.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_invariant_fuzz_acc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_invariant_fuzz_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _load_exploit_class_module():
    tool_path = Path(__file__).resolve().with_name("exploit-class-coverage.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_exploit_class_acc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_exploit_class_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def check_exploit_class(ws: Path) -> SignalResult:
    # r36-rebuttal: lane FIX-EXPLOIT-CLASS-GATE registered in .auditooor/agent_pathspec.json
    # The ENFORCED manual-authoring checklist: the systemic / compositional classes tooling
    # cannot auto-find (multi-step-economic, system-invariant, stateful-history, cross-chain,
    # upgradability, oracle, governance, donation, rounding, access-composition) must each carry
    # a BACKED disposition. WARN-pass only on tooling-absence; otherwise a real fail blocks L37.
    mod = _load_exploit_class_module()
    if mod is None:
        return SignalResult(
            signal="exploit-class", ok=True,
            reason="exploit-class-coverage.py unavailable; degraded to WARN-pass",
            artifacts=[], detail={"exploit_class_tool": "unavailable"})
    try:
        res = mod.evaluate(ws)
    except Exception as exc:  # pragma: no cover
        return SignalResult(
            signal="exploit-class", ok=True,
            reason=f"exploit-class-coverage raised ({exc}); WARN-pass",
            artifacts=[], detail={"exploit_class_error": str(exc)})
    v = res.get("verdict", "") if isinstance(res, dict) else ""
    if v == "fail-exploit-class-undispositioned":
        return SignalResult(
            signal="exploit-class", ok=False,
            reason=f"exploit-class-coverage FAILS: {res.get('reason', '')}",
            artifacts=[], detail=res)
    return SignalResult(
        signal="exploit-class", ok=True,
        reason=f"exploit-class-coverage verdict={v or 'unknown'}: {res.get('reason', '') if isinstance(res, dict) else ''}",
        artifacts=[], detail={"verdict": v})


def _load_completeness_matrix_module():
    tool_path = Path(__file__).resolve().with_name("completeness-matrix-build.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_completeness_matrix", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_completeness_matrix"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def check_completeness_matrix(ws: Path) -> SignalResult:
    """Enumeration-floor JOIN: the cross-product (asset x function x invariant x
    impact) must be fully ENUMERATED with a per-cell status. Fixes the
    absence-is-invisible class - the other completeness gates WARN-pass when a
    cell was NEVER ENUMERATED. Builds .auditooor/completeness_matrix.json via
    completeness-matrix-build.py.

    Rollout posture (deliberate, safe): tooling-absence -> WARN-pass (consistent
    with the other coverage signals; a workspace without the tool is not
    retroactively broken). A genuinely INCOMPLETE matrix (never-enumerated cells)
    is a loud WARN by default and a HARD FAIL only under
    AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE=1, so flipping enforcement on is a
    deliberate operator switch rather than a silent retroactive re-fail of
    workspaces certified before this gate existed. Honors the l37-rebuttal /
    completeness-matrix-rebuttal override.
    """
    mod = _load_completeness_matrix_module()
    if mod is None:
        return SignalResult(
            signal="completeness-matrix", ok=True,
            reason="completeness-matrix-build.py unavailable; degraded to WARN-pass",
            artifacts=[], detail={"completeness_matrix_tool": "unavailable"})
    # v2 IMPACT x MECHANISM axis: run the mechanism detectors first so their
    # .auditooor/mechanism_scan/*.json sidecars exist when the matrix builds. This
    # is what populates the impact-mechanism plane (else every cell reports as
    # 'not-enumerated-unscanned'). Best-effort: a driver error never fails this gate
    # - an un-run detector correctly leaves its cell NOT-ENUMERATED (fail-closed).
    try:
        import importlib.util as _il_msr
        _msr_path = Path(__file__).resolve().with_name("mechanism-scan-run.py")
        _spec_msr = _il_msr.spec_from_file_location("_mechanism_scan_run", str(_msr_path))
        if _spec_msr and _spec_msr.loader:
            _msr = _il_msr.module_from_spec(_spec_msr)
            _spec_msr.loader.exec_module(_msr)
            _msr.run(ws)
    except Exception:
        pass
    # A1 pre-hunt rewire: prefer an on-disk matrix produced by the pre-hunt
    # `completeness-matrix-build --enumerate-only` step, so the enumeration the
    # pipeline ran BEFORE the hunt is the one this terminal gate reads (single
    # source of truth; no double-build divergence). DEFAULT-OFF behind the same
    # dedicated env that gates the Makefile pre-hunt step
    # (AUDITOOOR_PREHUNT_MATRIX). With the env UNSET this branch never runs and the
    # gate rebuilds via mod.build_matrix exactly as before - byte-identical. The
    # preference is honored ONLY when the on-disk matrix is NEWER than every
    # relevant input the mechanism scan just refreshed (a stale file is ignored and
    # we fall back to a fresh build, so the gate can never read a pre-hunt matrix
    # that predates this run's own mechanism scan).
    _prehunt_matrix = os.environ.get(
        "AUDITOOOR_PREHUNT_MATRIX", "").strip().lower() in ("1", "true", "yes", "on")
    _matrix_path = ws / ".auditooor" / "completeness_matrix.json"
    m = None
    if _prehunt_matrix and _matrix_path.is_file():
        try:
            _disk = json.loads(_matrix_path.read_text(encoding="utf-8"))
            if (isinstance(_disk, dict)
                    and str(_disk.get("schema", "")) == "auditooor.completeness_matrix.v1"
                    and "verdict" in _disk and "enumeration_worklist" in _disk):
                m = _disk
        except (OSError, ValueError):
            m = None
    try:
        if m is None:
            m = mod.build_matrix(ws)
            # Persist the artifact so the human-openable matrix exists alongside the gate.
            out = ws / ".auditooor" / "completeness_matrix.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
            try:
                mod._write_md(ws, m)
            except Exception:
                pass
    except Exception as exc:  # pragma: no cover
        return SignalResult(
            signal="completeness-matrix", ok=True,
            reason=f"completeness-matrix-build raised ({exc}); WARN-pass",
            artifacts=[], detail={"completeness_matrix_error": str(exc)})

    # F1 (id24,30): verdict/worklist JOIN. The reader used to key ONLY on
    # m["verdict"]; a matrix can report verdict=="complete" while its
    # enumeration_worklist still lists VALUE-MOVING not-enumerated cells (a
    # serving-join / staleness / verdict-computation gap - NUVA: NuvaVault 2/10,
    # CrossChainManager 3/10 invariant cells). Fold the worklist into the verdict so
    # "complete" cannot coexist with a value-moving not-enumerated cell. HONORS THE
    # INTERFACE-FILE TRAP: only rows tagged cell_kind=="value_moving" count; the 33
    # dropped_nonentry interface files (IFullERC20 / ECRecover) that
    # _drop_nonentry_file legitimately drops are NEVER re-red. DEFAULT-ON graduation
    # (2026-07-03): AUDITOOOR_MATRIX_WORKLIST_JOIN_STRICT now defaults ENFORCED under
    # the L37 strict umbrella (what `make audit-complete STRICT=1` exports), with a
    # per-gate OPT-OUT via AUDITOOOR_MATRIX_WORKLIST_JOIN_STRICT=0. A bare non-strict /
    # library caller (L37 unset) keeps the byte-identical advisory pass. The
    # interface-file trap + value_moving JOIN logic below is unchanged.
    _worklist_join_strict = _gate_default_on_strict(
        "AUDITOOOR_MATRIX_WORKLIST_JOIN_STRICT")
    # NON-VALUE-MOVING FILE guard (Strata 2026-07-07): a worklist cell tagged
    # cell_kind=value_moving but whose FILE has ZERO value-moving functions in
    # value_moving_functions.json (transfer_hit/ledger_write_hit) has NO invariant to
    # enumerate - it is proxy/beacon/type-library infrastructure the tagger over-labeled
    # (function=None, 0 rows). Same principle as the per-function non-entry drop, at the
    # file level. NEVER-FALSE: a file with >=1 real value-moving function stays counted;
    # the guard only fires when the file is ABSENT from the value-moving set entirely.
    _vm_files: set = set()
    try:
        _vmd = json.loads((ws / ".auditooor" / "value_moving_functions.json").read_text(encoding="utf-8"))
        for _f in (_vmd.get("functions") or []):
            if _f.get("transfer_hit") or _f.get("ledger_write_hit"):
                _vm_files.add(Path(str(_f.get("file") or "").split(":")[0]).name)
    except Exception:
        _vm_files = set()  # feed absent -> disable the guard (fail-closed to old behaviour)

    def _cell_file_is_value_moving(r: dict) -> bool:
        if not _vm_files:
            return True  # no feed -> do not drop anything (byte-identical to before)
        _a = str(r.get("asset") or r.get("file") or r.get("unit") or "")
        _bn = Path(_a.split(":")[0]).name
        return _bn in _vm_files

    _value_moving_unenum = [
        r for r in (m.get("enumeration_worklist") or [])
        if isinstance(r, dict)
        and str(r.get("cell_kind", "value_moving")) == "value_moving"
        and str(r.get("status", "")) in ("not-enumerated", "absent", "undriven",
                                         "not-enumerated-unscanned",
                                         "not-enumerated-open")
        and _cell_file_is_value_moving(r)
    ]
    _join_false_green = (
        _worklist_join_strict
        and m.get("verdict") == "complete"
        and len(_value_moving_unenum) > 0
    )

    if m.get("verdict") == "complete" and not _join_false_green:
        return SignalResult(
            signal="completeness-matrix", ok=True,
            reason="completeness-matrix complete: every in-scope (asset,function,invariant,impact) cell enumerated",
            artifacts=[str(ws / ".auditooor" / "completeness_matrix.json")],
            detail={"verdict": "complete", "denominators": m.get("denominators"),
                    "cells": m.get("cells"),
                    "worklist_value_moving_unenumerated": 0})

    rebuttal = None
    try:
        rebuttal = mod._rebuttal(ws)
    except Exception:
        rebuttal = None

    # F1 verdict/worklist JOIN false-green: the matrix said complete, but its own
    # worklist still lists VALUE-MOVING not-enumerated cells. Under the dedicated
    # env this is a hard FAIL regardless of the matrix's own verdict field (a
    # verdict==complete that contradicts the worklist is exactly the false-green
    # this fix closes). A completeness-matrix-rebuttal still escapes it.
    if _join_false_green:
        _sample = _value_moving_unenum[:8]
        _jr = (f"completeness-matrix verdict=complete but the enumeration worklist "
               f"still lists {len(_value_moving_unenum)} VALUE-MOVING not-enumerated "
               f"cell(s) (verdict/worklist JOIN false-green); the interface/library "
               f"'dropped_nonentry' rows are excluded")
        if rebuttal:
            return SignalResult(
                signal="completeness-matrix", ok=True,
                reason=f"{_jr}; but rebuttal honored: {rebuttal}",
                artifacts=[], detail={"verdict": "join-false-green",
                                      "worklist_value_moving_unenumerated": len(_value_moving_unenum),
                                      "rebuttal": rebuttal, "sample": _sample})
        return SignalResult(
            signal="completeness-matrix", ok=False,
            reason=_jr, artifacts=[str(ws / ".auditooor" / "completeness_matrix.json")],
            detail={"verdict": "join-false-green",
                    "worklist_value_moving_unenumerated": len(_value_moving_unenum),
                    "sample": _sample,
                    "strict_env": "AUDITOOOR_MATRIX_WORKLIST_JOIN_STRICT"})

    # Enforce hard-fail on never-enumerated cells under the dedicated env switch OR
    # the main L37 STRICT gate (AUDITOOOR_L37_STRICT=1, what `make audit-complete
    # STRICT=1` sets) - mirrors the hunt-trust degraded-strict fix (strata 2026-07-01).
    # A STRICT-certified audit must not green a completeness matrix with an in-scope
    # (asset,function,invariant,impact) cell that was NEVER ENUMERATED (never-
    # enumerated == false-GREEN: absence read as coverage). Default (non-strict)
    # stays advisory WARN-pass; the rebuttal path above still escapes it.
    enforce = (
        os.environ.get("AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE", "") not in ("", "0", "false", "no")
        or _l37_gate_strict("COMPLETENESS_MATRIX")
    )
    reasons = "; ".join(m.get("reasons", []))[:400]
    if rebuttal:
        return SignalResult(
            signal="completeness-matrix", ok=True,
            reason=f"completeness-matrix incomplete but rebuttal honored: {rebuttal}",
            artifacts=[], detail={"verdict": "incomplete", "rebuttal": rebuttal, "reasons": m.get("reasons")})
    if enforce:
        return SignalResult(
            signal="completeness-matrix", ok=False,
            reason=f"completeness-matrix INCOMPLETE (never-enumerated cells): {reasons}",
            artifacts=[], detail={"verdict": "incomplete", "reasons": m.get("reasons"),
                                  "not_enumerated_assets": [a["asset_id"] for a in m.get("not_enumerated_assets", [])]})
    return SignalResult(
        signal="completeness-matrix", ok=True,
        reason=("completeness-matrix INCOMPLETE (WARN; set AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE=1 to "
                f"hard-fail): {reasons}"),
        artifacts=[], detail={"verdict": "incomplete", "warn_only": True, "reasons": m.get("reasons")})


def check_invariant_fuzz(ws: Path) -> SignalResult:
    mod = _load_invariant_fuzz_module()
    if mod is None:
        return SignalResult(
            signal="invariant-fuzz", ok=True,
            reason="invariant-fuzz-completeness.py unavailable; degraded to WARN-pass",
            artifacts=[], detail={"invariant_fuzz_tool": "unavailable"})
    try:
        res = mod.evaluate(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="invariant-fuzz", ok=True,
            reason=f"invariant-fuzz-completeness raised ({exc}); WARN-pass",
            artifacts=[], detail={"invariant_fuzz_error": str(exc)})
    v = res.get("verdict", "") if isinstance(res, dict) else ""
    # SERVING-JOIN FIX (lane FIX-INVARIANT-FUZZ-AGGREGATOR): the gate's FAILING
    # verdict vocabulary is more than the legacy `fail-invariant-fuzz-incomplete` -
    # its STRICT asset-coverage gap emits `fail-invariant-fuzz-asset-gap` (a real,
    # blocking fail under AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT / L37). Keying only
    # on the legacy string silently mapped a strict asset-gap fail to ok=True, so
    # audit-complete greened with N uncovered value-moving assets (nuva: 15). Treat
    # ANY `fail-invariant-fuzz*` verdict as blocking; `warn-*`/`pass-*` stay pass by
    # design (advisory asset-gap is a WARN, not a retro-red).
    if isinstance(v, str) and v.startswith("fail-invariant-fuzz"):
        return SignalResult(
            signal="invariant-fuzz", ok=False,
            reason=f"invariant-fuzz-completeness FAILS ({v}): {res.get('reason', '')}",
            artifacts=[], detail=res)
    return SignalResult(
        signal="invariant-fuzz", ok=True,
        reason=f"invariant-fuzz-completeness verdict={v or 'unknown'}: {res.get('reason', '') if isinstance(res, dict) else ''}",
        artifacts=[], detail={"verdict": v})


_DF_FAIL_REASON = ("timed out", "timeout", "panic", "packages.load", "load/build failure",
                   "build failure", "compile", "empty output", "rc=", "exit status",
                   "no schema-valid", "error")
_DF_BENIGN_REASON = ("no-cargo-toml", "no-go-mod", "no go.mod", "unsupported",
                     "not present", "absent", "no-")


def _dataflow_arm_health(ws: Path) -> dict:
    """Per-language dataflow substrate health from dataflow_paths.jsonl. A language arm is
    STARVED when it has GENUINE build/load/timeout/panic degrade record(s) AND produced
    near-zero real (non-degraded) paths - i.e. the whole arm failed, so EVERY dataflow-
    dependent lens over that language (path-mode hunt, guard-reachability, chain-synth, SCC)
    was silently downgraded to function-mode. This GENERALIZES the SCC-only feeder gate to
    all lenses + all languages. Robust against the two false-positive classes measured
    2026-07-08: (a) a benign absence degrade (no-cargo-toml on a non-Rust ws) is NOT a
    failure; (b) a healthy arm with a FEW individual file-compile failures (morpho sol
    real=473 fail=2, nuva go real=1436 fail=1 simapp panic) is NOT starved - only near-zero
    real yield alongside genuine failures is. Generic to every ws."""
    p = ws / ".auditooor" / "dataflow_paths.jsonl"
    out: dict = {"present": p.is_file(), "languages": {}, "starved": []}
    if not p.is_file():
        return out
    by_lang: dict = {}
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                r = json.loads(line)
            except Exception:
                continue
            lang = r.get("language") or "?"
            d = by_lang.setdefault(lang, {"real": 0, "genuine_fail": 0})
            if r.get("degraded"):
                reason = str(r.get("degrade_reason") or "").lower()
                if not any(b in reason for b in _DF_BENIGN_REASON) and any(
                        f in reason for f in _DF_FAIL_REASON):
                    d["genuine_fail"] += 1
            else:
                d["real"] += 1
    except OSError:
        return out
    for lang, d in by_lang.items():
        starved = d["genuine_fail"] > 0 and d["real"] < 10
        d["starved"] = starved
        if starved:
            out["starved"].append(lang)
    out["languages"] = by_lang
    return out


def check_dataflow_substrate_health(ws: Path) -> SignalResult:
    """SUBSTRATE-HEALTH gate (2026-07-08): the dataflow slice (step-1c) is the SHARED
    substrate under EVERY dataflow-dependent lens - path-mode hunt, guard-reachability,
    chain-synth, AND state-coupling. It is advisory ("never blocks") with a SILENT
    function-mode fallback, so a degraded arm quietly downgrades all those lenses without a
    flag (root-caused on NUVA's Go feeder; the SCC gate caught it for the coupled-state axis
    ONLY). This generalizes that check to ALL languages + ALL lenses: if any language arm is
    STARVED (genuine build/load failures + near-zero real paths) the substrate is degraded ->
    WARN advisory, HARD-FAIL under AUDITOOOR_L37_STRICT=1. A healthy arm (NUVA go now
    real=1436) or a benign absence (no-cargo-toml) does NOT trip it."""
    h = _dataflow_arm_health(ws)
    if not h["present"]:
        return SignalResult(signal="dataflow-substrate-health", ok=True,
                            reason="no dataflow slice (step-1c advisory not run); WARN-pass",
                            artifacts=[], detail=h)
    starved = h["starved"]
    strict = os.environ.get("AUDITOOOR_L37_STRICT") == "1"
    ok = not (starved and strict)
    return SignalResult(
        signal="dataflow-substrate-health", ok=ok,
        reason=("dataflow substrate healthy across "
                f"{sorted(h['languages'])}" if not starved else
                f"STARVED dataflow arm(s) {starved} (genuine build/load failures + near-zero "
                f"real paths) - every dataflow-dependent lens (hunt/guard-reachability/chain-"
                f"synth/SCC) was silently downgraded"
                + ("" if ok else " (STRICT: fix the feeder before done)")),
        artifacts=[str(ws / ".auditooor" / "dataflow_paths.jsonl")], detail=h)


def _modules_with_real_dataflow_paths(ws: Path) -> set:
    """Module ids (normalized to a ``src/...`` tail) that have >=1 REAL (non-degraded)
    analyzed path in dataflow_paths.jsonl. A stale DEGRADE record for such a module (a
    later timed-out re-run of a huge cosmos pkg) is superseded - the slice genuinely
    covers it. Used to filter false PARTIAL-DEGRADE on state-coupling."""
    covered: set = set()

    def _tail(s: str) -> str:
        s = str(s or "").strip().rstrip("/")
        i = s.find("src/")
        return s[i:] if i >= 0 else s

    for name in ("dataflow_paths.jsonl",):
        p = ws / ".auditooor" / name
        if not p.is_file():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if not isinstance(o, dict):
                continue
            if o.get("degraded") or o.get("run_failure") or o.get("status") == "degraded":
                continue
            for key in ("module", "module_root", "module_rel", "src", "src_root"):
                if o.get(key):
                    covered.add(_tail(o[key]))
            for slot in ("source", "sink"):
                d = o.get(slot)
                if isinstance(d, dict) and d.get("file"):
                    t = _tail(d["file"])
                    parts = t.split("/")
                    if len(parts) >= 2 and parts[0] == "src":
                        covered.add("/".join(parts[:2]))
    return {c for c in covered if c}


def _module_is_covered(module_rel: str, covered: set) -> bool:
    """A degraded module is genuinely covered iff a real-path module id matches its
    src-tail by path-prefix (conservative: no loose substring match)."""
    s = str(module_rel or "").strip().rstrip("/")
    i = s.find("src/")
    tail = s[i:] if i >= 0 else s
    if not tail:
        return False
    for c in covered:
        if tail == c or c.startswith(tail + "/") or tail.startswith(c + "/"):
            return True
    return False


def check_state_coupling(ws: Path) -> SignalResult:
    """L37 gate for the State-Coupling Graph (the Aptos-class coupled-state axis). This is
    what WIRES the SCC capability into audit-complete: state-coupling-completeness-check.py
    AUTO-EMITS the SCG (tools/state-coupling-graph.py -> state_coupling_edges.jsonl) then
    gates on PROMOTABLE semantic-ssa edges that are not probe-resolved. Advisory-first: ok
    stays True unless the strict L37 umbrella is on AND an open promotable coupled-state
    edge exists (an unprobed must-move-together violator). Degrades to WARN-pass if the tool
    is missing. Without this, the SCG only ran when invoked by hand and never fed the gate
    or the exploit-queue on a real audit (measured 2026-07-08: 0 SCG rows in NUVA's queue)."""
    tool_path = Path(__file__).resolve().with_name("state-coupling-completeness-check.py")
    if not tool_path.is_file():
        return SignalResult(signal="state-coupling", ok=True,
                            reason="state-coupling-completeness-check.py unavailable; WARN-pass",
                            artifacts=[], detail={"state_coupling_tool": "unavailable"})
    spec = importlib.util.spec_from_file_location("_state_coupling_acc", tool_path)
    if spec is None or spec.loader is None:
        return SignalResult(signal="state-coupling", ok=True,
                            reason="state-coupling loader failed; WARN-pass", artifacts=[])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_state_coupling_acc"] = mod
    try:
        spec.loader.exec_module(mod)
        # Enable the SCG subtype arms (xcontract / interruption / shared-cursor / handle-freshness)
        # so they EMIT and feed the hunt + exploit-queue as advisory review candidates. They are
        # env-gated OFF by default in state-coupling-graph.py (SCG_XCONTRACT/SCG_INTERRUPTION/
        # SCG_SHARED_CURSOR/SCG_HANDLE_FRESHNESS). Turning them ON does NOT gate a green ws:
        # _promotable() in state-coupling-completeness-check.py demotes every subtype-arm edge to
        # advisory unless AUDITOOOR_SCG_SUBTYPES_STRICT=1 (or, for the R1 handle-freshness arm, its
        # dedicated early-adopter env AUDITOOOR_HANDLE_FRESHNESS_ENFORCE=1). Without SCG_HANDLE_
        # FRESHNESS here the R1 arm would be an orphan that only runs by hand and never feeds the
        # gate or the exploit-queue on a real audit (the 2026-07-08 NUVA-0-rows failure this gate
        # docstring warns about). setdefault so an operator can still force an arm OFF with a "0".
        for _scg_env in ("SCG_XCONTRACT", "SCG_INTERRUPTION", "SCG_SHARED_CURSOR",
                         "SCG_HANDLE_FRESHNESS"):
            os.environ.setdefault(_scg_env, "1")
        mod.main(["--workspace", str(ws)])  # auto-emits the SCG + writes the verdict artifact
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="state-coupling", ok=True,
                            reason=f"state-coupling-completeness raised ({exc}); WARN-pass",
                            artifacts=[], detail={"state_coupling_error": str(exc)})
    art = ws / ".auditooor" / "state_coupling_completeness.json"
    try:
        res = json.loads(art.read_text(encoding="utf-8")) if art.is_file() else {}
    except (OSError, ValueError):
        res = {}
    verdict = str(res.get("verdict") or "")
    open_edges = int(res.get("open_edges") or 0)
    strict = os.environ.get("AUDITOOOR_L37_STRICT") == "1"
    # advisory-first: FAIL under the strict umbrella with an open promotable edge...
    ok = not (open_edges > 0 and strict)
    # ...OR when the Go coupled-state FEEDER is DEGRADED. A starved go-dataflow arm (Go
    # state-write sinks present but 0 sink.cell - e.g. a toolchain/GOPROXY build failure,
    # root-caused NUVA 2026-07-08) produces almost NO coupled-state edges, so a "0 open
    # edges" pass is FALSE completeness: the coupled-state axis was never genuinely covered
    # (measured NUVA: 35 sinks / 0 cells, yet the gate PASSED). Read the resolver accounting;
    # a degraded feeder blocks done under STRICT (WARN-advisory otherwise), so a starved
    # feeder can no longer masquerade as a clean coupled-state 0.
    feeder_status = ""
    degraded_inscope = False
    degraded_modules: list = []
    acct_p = ws / ".auditooor" / "state_coupling_conserved_accounting.json"
    try:
        if acct_p.is_file():
            _acct = json.loads(acct_p.read_text(encoding="utf-8"))
            feeder_status = str(_acct.get("slice_resolution_status") or "")
            degraded_inscope = bool(_acct.get("slice_go_degraded_inscope"))
            degraded_modules = _acct.get("slice_go_degraded_modules") or []
    except (OSError, ValueError):
        feeder_status = ""
    feeder_degraded = feeder_status == "0-go-feeder-degraded"
    # SUPERSEDED-DEGRADE guard (serving-join, 2026-07-14 axelar): a go-dataflow
    # module can carry a stale DEGRADE record (a later timed-out re-run of a huge
    # cosmos pkg, e.g. src/axelar-core @ 1800s) ALONGSIDE thousands of REAL analyzed
    # paths from a prior successful run in the SAME dataflow_paths.jsonl (axelar:
    # 4154 real axelar-core records vs 3 degrade records). A module with real paths
    # is genuinely covered; the stale degrade must not override it. Filter
    # degraded_modules to those that ACTUALLY lack real (non-degraded) dataflow paths.
    if degraded_modules:
        _covered = _modules_with_real_dataflow_paths(ws)
        _genuine = [m for m in degraded_modules
                    if not _module_is_covered(str(m.get("module_rel") or ""), _covered)]
        if len(_genuine) != len(degraded_modules):
            degraded_modules = _genuine
            degraded_inscope = bool(degraded_inscope) and bool(_genuine)
    if feeder_degraded and strict:
        ok = False
    # PARTIAL degrade: some Go modules starved while others resolved (name2cell>0 -> status
    # "resolved"). That must NOT silently pass if a degraded module carries IN-SCOPE surface
    # (anti-silent-suppression, NUVA 2026-07-08). Block under STRICT only when the starvation
    # hit code we must cover; an OOS module degrade (test/sim/genesis wiring) is WARN-surface.
    if degraded_inscope and strict:
        ok = False
    # R1 HANDLE-FRESHNESS UN-ANALYZED fail-closed (mirrors the degraded-feeder block above): the
    # arm found a recyclable-handle holder in a language it could NOT resolve (parser gap /
    # unsupported language), so a "0 open edges" pass is FALSE completeness on the handle-freshness
    # axis - a STARVED arm cannot masquerade as a clean 0 (anti-silent-suppression). Advisory-first:
    # blocks ONLY under the dedicated early-adopter env AUDITOOOR_HANDLE_FRESHNESS_ENFORCE (+ the
    # strict L37 umbrella), so it does not false-RED the fleet before the arm is >=3-ws validated.
    hf_unanalyzed = bool(res.get("handle_freshness_unanalyzed_inscope"))
    hf_enforce = os.environ.get("AUDITOOOR_HANDLE_FRESHNESS_ENFORCE") == "1"
    if hf_unanalyzed and strict and hf_enforce:
        ok = False
    degraded_note = ""
    if degraded_modules:
        _shown = "; ".join(f"{m.get('module_rel', '?')} ({str(m.get('reason', ''))[:60]})"
                           for m in degraded_modules[:3])
        degraded_note = (f"; Go dataflow PARTIAL DEGRADE"
                         + (" [IN-SCOPE - coupled-state surface NOT covered]" if degraded_inscope
                            else " [out-of-scope modules only]")
                         + f": {_shown}")
    # Name the UNCOVERED SURFACE in the reason - the failing gate must say WHAT to audit
    # (which coupled cells + which violator file:line), not just a count (operator ask
    # 2026-07-08). Pull the actionable worklist the completeness check now emits.
    surface = ""
    for d in (res.get("open_edge_details") or [])[:3]:
        viol = (d.get("violators") or [{}])[0]
        site = viol.get("site") or "?"
        fn = viol.get("fn") or "?"
        surface += (f"; [{d.get('kind')}] {d.get('cell_a')}<->{d.get('cell_b')} "
                    f"omitted by {fn}@{site}")
    if len(res.get("open_edge_details") or []) > 3:
        surface += f"; (+{len(res['open_edge_details']) - 3} more - see {art.name})"
    return SignalResult(
        signal="state-coupling", ok=ok,
        reason=(f"state-coupling-completeness verdict={verdict or 'unknown'}: "
                f"{open_edges} open promotable coupled-state edge(s)"
                + surface
                + ("; Go coupled-state FEEDER DEGRADED (state-write sinks without cell "
                   "- the go-dataflow arm was starved, coupled-state axis NOT covered)"
                   if feeder_degraded else "")
                + degraded_note
                + ("; R1 handle-freshness UN-ANALYZED: a recyclable-handle holder in a language the "
                   "arm cannot parse - the stale-handle-after-recycle axis was NOT covered "
                   f"(examples: {[e.get('file') for e in (res.get('handle_freshness_unanalyzed_examples') or [])][:3]})"
                   if hf_unanalyzed else "")
                + ("" if ok else " (STRICT: probe/resolve edges + fix the Go feeder before done)")),
        artifacts=[str(art)] if art.is_file() else [],
        detail={**res, "feeder_status": feeder_status,
                "go_degraded_inscope": degraded_inscope,
                "go_degraded_modules": degraded_modules})


def check_enforcement_point(ws: Path) -> SignalResult:
    """WSITB B1 gate (enforcement-point plane, increment-1 CONSERVATION class). Copied
    from check_state_coupling: AUTO-EMITS the plane (tools/wsitb-enforcement-plane.py ->
    wsitb_enforcement_plane.json) then gates on SEVERITY-ELIGIBLE UN-ANALYZED enforcement
    points (a conserved-with coupled set whose q8 verdict is still 'unanalyzed'). The plane
    covers ENFORCEMENT POINTS not impacts: a node with no terminal q8 verdict AND
    severity-eligible is an un-analyzed enforcement point. Advisory-WARN by default; enforce
    ONLY under the dedicated opt-in env AUDITOOOR_ENFORCEMENT_POINT_ENFORCE (deliberately NOT
    the strict L37 umbrella - B1 is not yet fleet-validated so it registers no global rule).
    Degraded-feeder secondary fail-closed only when that env is set (a starved substrate
    cannot masquerade as a clean 0).
    Fail-OPEN (WARN-pass) when the tool is missing. Rebuttal key: ``enforcement-point:``."""
    tool_path = Path(__file__).resolve().with_name("wsitb-enforcement-plane.py")
    if not tool_path.is_file():
        return SignalResult(signal="enforcement-point", ok=True,
                            reason="wsitb-enforcement-plane.py unavailable; WARN-pass",
                            artifacts=[], detail={"enforcement_point_tool": "unavailable"})
    spec = importlib.util.spec_from_file_location("_wsitb_enforcement_plane", tool_path)
    if spec is None or spec.loader is None:
        return SignalResult(signal="enforcement-point", ok=True,
                            reason="enforcement-point loader failed; WARN-pass", artifacts=[])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_wsitb_enforcement_plane"] = mod
    try:
        spec.loader.exec_module(mod)
        # Step 3f's canonical producer is the consolidated coverage plane. The
        # legacy increment-1 emitter writes wsitb_enforcement_plane.json and
        # rebuilds a separate, slither-dependent denominator; consuming it here
        # made Step 5 disagree with the already-verified Step 3f result and
        # resurrected stale un-analyzed points. Reuse the same producer output.
        nodes, acct = mod.consolidate_plane(ws)
        mod.write_consolidated(ws, nodes, acct)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="enforcement-point", ok=True,
                            reason=f"wsitb-enforcement-plane raised ({exc}); WARN-pass",
                            artifacts=[], detail={"enforcement_point_error": str(exc)})
    plane = ws / ".auditooor" / "enforcement_point_coverage_plane.json"
    acct_p = ws / ".auditooor" / "enforcement_point_coverage_accounting.json"
    try:
        doc = json.loads(plane.read_text(encoding="utf-8")) if plane.is_file() else {}
    except (OSError, ValueError):
        doc = {}
    try:
        acct = json.loads(acct_p.read_text(encoding="utf-8")) if acct_p.is_file() else {}
    except (OSError, ValueError):
        acct = {}
    nodes = (doc.get("points") if isinstance(doc, dict) else [])
    nodes = nodes if isinstance(nodes, list) else []
    open_points = [n for n in nodes if isinstance(n, dict)
                   and not n.get("analyzed") and n.get("severity_eligible")]
    n_open = len(open_points)
    # DEDICATED opt-in ONLY (deliberately NOT the strict L37 umbrella): B1 WSITB is not
    # yet fleet-validated (the Sigma-conservation kill does not reproduce until the Solidity
    # dataflow arm emits distinct-flow hops so co-accumulation promotes to semantic-ssa), so
    # it must NOT register a global L37 rule or hard-fail the strict umbrella on any
    # workspace. It enforces SOLELY under its own explicit env; promote it into the L37
    # umbrella (with the >=3-workspace admission the global-rule gate requires) once the
    # kill reproduces across the fleet.
    strict = (os.environ.get("AUDITOOOR_ENFORCEMENT_POINT_STRICT", "").strip() == "1"
              or os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1")
    ok = not (n_open > 0 and strict)
    # degraded-feeder secondary fail-closed under strict: a starved substrate (schema
    # absent / dataflow errored) reporting 0 open points is FALSE completeness, not a
    # clean 0. Slither-degraded alone only drops guard_in_closure (advisory) so it does
    # NOT block; a resolution status naming a starved edge/dataflow feeder does.
    status = str(acct.get("slice_resolution_status") or "")
    feeder_starved = status in ("0-schema-module-absent",) or bool(acct.get("dataflow_degraded"))
    if feeder_starved and strict:
        ok = False
    # name-the-surface reason (cap 3 + "(+N more)").
    surface = ""
    for n in open_points[:3]:
        member = ""
        cs = n.get("coupled_set") or []
        writers = {w.get("fn") for w in (n.get("writers") or []) if isinstance(w, dict)}
        omitted = [c for c in cs]  # the coupled set the owner must move together
        owner = n.get("owner") or "?"
        w0 = next((w for w in (n.get("writers") or []) if isinstance(w, dict)
                   and w.get("fn") == owner), None)
        site = f"{w0.get('file')}:{w0.get('line')}" if w0 and w0.get("file") else "?"
        member = ", ".join(omitted[:4])
        surface += (f"; [conservation] {n.get('term') or member} owner={owner}@{site} "
                    f"un-analyzed (omits {member})")
    if n_open > 3:
        surface += f"; (+{n_open - 3} more - see {plane.name})"
    n_violated = int(acct.get("violated_points") or 0)
    return SignalResult(
        signal="enforcement-point", ok=ok,
        reason=(f"wsitb-enforcement-plane: {n_open} severity-eligible un-analyzed "
                f"enforcement point(s) [conservation]"
                + (f"; {n_violated} with a CONFIRMED partial-flush (gated at state-coupling)"
                   if n_violated else "")
                + surface
                + (f"; feeder status={status}" if status else "")
                + ("; SUBSTRATE STARVED (schema/dataflow feeder degraded - the enforcement "
                   "plane was not genuinely built)" if feeder_starved else "")
                + ("" if ok else " (STRICT: analyze each enforcement point to a terminal "
                   "q8 verdict + fix the feeder before done)")),
        artifacts=[str(plane)] if plane.is_file() else [],
        detail={"nodes_emitted": len(nodes),
                "severity_eligible_unanalyzed": n_open,
                "violated_points": n_violated,
                "accounting": acct})


def check_compiler_feature_screen(ws: Path) -> SignalResult:
    """E2/E2b compiler-feature-screen. The compiler is a TRUSTED ENFORCEMENT (bytecode
    preserves source semantics); this auto-emits tools/compiler-feature-screen.py which JOINs
    every in-scope (pinned solc/vyper version x language feature) pair against the curated
    per-advisory windows and flags an affected pair (e.g. transient storage pinned in
    [0.8.28,0.8.34) = tstore-poison) or leaves an un-screened pair as a blind spot. E2b widen:
    detection spans transient-storage + udvt + abi-nested-dynamic + inline-asm + immutable, but
    the L37 GATE is SCOPED to gate_eligible_flagged only - the sole graduated feature is
    transient-storage (per-advisory feature_tagged window + fleet-validated 0 FLAGs on green
    ws). It fails-closed ONLY under the dedicated per-signal env
    AUDITOOOR_L37_COMPILER_FEATURE_SCREEN_STRICT (STAGED, umbrella WITHHELD) on a gate-eligible
    transient FLAG; the global AUDITOOOR_L37_STRICT umbrella is deliberately NOT wired because
    the gate-eligible transient FLAG currently reproduces on only 2 ws (below the >=3-ws
    global-rule-admission bar; same doctrine as B3). Widened advisory FLAGs + UNSCREENED rows
    are WARN-surface + exploit-queue hunt fuel, NEVER gate (their windows are wide/shape-
    specific, so FLAG-gating them would fleet-RED green ws). A feature graduates into the
    global umbrella only after >=3-workspace 1:1 validation. Rebuttal: compiler-feature-screen:."""
    tool = Path(__file__).resolve().with_name("compiler-feature-screen.py")
    if not tool.is_file():
        return SignalResult(signal="compiler-feature-screen", ok=True,
                            reason="compiler-feature-screen.py unavailable; WARN-pass", artifacts=[])
    try:
        spec = importlib.util.spec_from_file_location("_cfs_mod", tool)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_cfs_mod"] = mod
        spec.loader.exec_module(mod)
        result = mod.run(ws, mod.DEFAULT_ADVISORY_DIRS)
        out = ws / ".auditooor" / "compiler_feature_screen.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="compiler-feature-screen", ok=True,
                            reason=f"compiler-feature-screen raised ({exc}); WARN-pass", artifacts=[])
    if not result.get("substrate_present"):
        return SignalResult(signal="compiler-feature-screen", ok=True,
                            reason="no in-scope Solidity/Vyper contracts to screen; fail-open pass",
                            artifacts=[str(out)])
    c = result.get("counts", {}) or {}
    uns = int(c.get("unscreened", 0) or 0)
    flg = int(c.get("flagged", 0) or 0)
    # E2b: the gate fails-closed ONLY on a GATE-ELIGIBLE FLAG (a graduated feature -
    # transient-storage - on a per-advisory feature_tagged window). Widened advisory FLAGs
    # (udvt / abi-nested-dynamic / inline-asm / immutable) and UNSCREENED rows are
    # WARN-surface, NEVER gate: their windows are wide/shape-specific, so FLAG-gating them
    # would fleet-RED green EVM ws (measured ~179 false FLAGs + 111/43/27 UNSCREENED across
    # lido/etherfi/optimism). transient FLAGs on the green fleet = 0 (those ws pin <0.8.28).
    # STAGED, dedicated-env only: gate on AUDITOOOR_L37_COMPILER_FEATURE_SCREEN_STRICT, NOT
    # the global AUDITOOOR_L37_STRICT umbrella. A gate-eligible transient FLAG currently
    # reproduces on only 2 ws (morpho, polygon - both already-red, genuine solc-0.8.28
    # transient state-vars), below the >=3-ws bar the global-rule-admission gate requires
    # for a new global L37 signal (same doctrine as B3 enforcement-layer-census). Promote to
    # the umbrella (add `or _l37_gate_strict(...)`) once >=3 distinct ws attribute the rule.
    strict = os.environ.get("AUDITOOOR_L37_COMPILER_FEATURE_SCREEN_STRICT", "").strip() == "1"
    gate_flags = int(c.get("gate_eligible_flagged", 0) or 0)
    ok = not (strict and gate_flags > 0)
    surf = ""
    shown = 0
    # surface the gate-eligible FLAG(s) FIRST (they decide the verdict), then advisory rows.
    _ordered = sorted(
        (result.get("rows") or []),
        key=lambda r: (0 if (r.get("verdict") == "FLAG" and r.get("gate_eligible")) else 1))
    for r in _ordered:
        if r.get("verdict") in ("FLAG", "UNSCREENED") and shown < 3:
            _tag = "GATE-FLAG" if (r.get("verdict") == "FLAG" and r.get("gate_eligible")) \
                else r.get("verdict")
            surf += (f"; [{_tag}] {r.get('file')} @{r.get('pinned_version')} "
                     f"feature={r.get('feature')}")
            shown += 1
    return SignalResult(
        signal="compiler-feature-screen", ok=ok,
        reason=(f"compiler-feature-screen: screened={c.get('screened_pairs', 0)} "
                f"flagged={flg} gate_eligible_flagged={gate_flags} unscreened={uns} "
                f"(widened FLAG/UNSCREENED = advisory queue-fuel, only a gate-eligible "
                f"transient FLAG gates)" + surf
                + ("" if ok else "; (bump the pinned version out of the miscompilation "
                   "window, or add a per-row compiler-feature-rebuttal after confirming "
                   "the feature is not hit)")),
        artifacts=[str(out)],
        detail={"flagged": flg, "gate_eligible_flagged": gate_flags,
                "unscreened": uns, "counts": c})


def check_cross_module_trust_seam(ws: Path) -> SignalResult:
    """A2 cross-module trust-boundary seam (advisory, report-only). Auto-emits the seam
    plane: a state var written by a GUARDED producer (module B validates X before writing)
    but reachable at an in-scope consumer sink via an UNGUARDED bypass path is a
    trusted-but-bypassable seam (north-star: A trusts that B validated X and does not
    re-check; find the path around B). Report-only advisory - the seams are review
    candidates for the hunt, not a pass/fail gate; fail-OPEN on a degraded feeder (R80).
    Rebuttal: cross-module-trust-seam:."""
    tool = Path(__file__).resolve().with_name("cross-module-trust-seam.py")
    if not tool.is_file():
        return SignalResult(signal="cross-module-trust-seam", ok=True,
                            reason="cross-module-trust-seam.py unavailable; WARN-pass", artifacts=[])
    try:
        spec = importlib.util.spec_from_file_location("_cmts_mod", tool)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_cmts_mod"] = mod
        spec.loader.exec_module(mod)
        acct = mod.emit(ws, None, 500)
        # A17 freshness-TOCTOU arm auto-runs alongside A2 (report-only, fail-OPEN):
        # a value validated FRESH at write time but consumed as CURRENT with no
        # freshness re-check. force=True so it runs in every audit-complete; the
        # rows fold into the enforcement-point plane (wsitb _consolidate_a2) for
        # the dedicated-env fail-closed. Advisory here - never blocks this signal.
        ft_acct: dict = {}
        if hasattr(mod, "emit_freshness_toctou_seams"):
            try:
                ft_acct = mod.emit_freshness_toctou_seams(ws, None, 500, force=True) or {}
            except Exception:  # pragma: no cover (defensive) - fail-open
                ft_acct = {}
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="cross-module-trust-seam", ok=True,
                            reason=f"cross-module-trust-seam raised ({exc}); WARN-pass", artifacts=[])
    jl = ws / ".auditooor" / "cross_module_trust_seams.jsonl"
    ftjl = ws / ".auditooor" / "freshness_toctou_seams.jsonl"
    arts = [str(jl)] if jl.is_file() else []
    if ftjl.is_file():
        arts.append(str(ftjl))
    if not isinstance(acct, dict) or str(acct.get("status", "")).startswith("0-") or acct.get("degraded"):
        st = acct.get("status") if isinstance(acct, dict) else "?"
        return SignalResult(signal="cross-module-trust-seam", ok=True,
                            reason=f"advisory: seam detector degraded/not-run ({st}); fail-open",
                            artifacts=arts)
    rows = int(acct.get("rows", 0) or 0)
    ft_rows = int(ft_acct.get("rows", 0) or 0) if isinstance(ft_acct, dict) else 0
    return SignalResult(
        signal="cross-module-trust-seam", ok=True,
        reason=(f"advisory: {rows} cross-module trust-seam edge(s) "
                f"(guarded-producer x unguarded-consumer-bypass); "
                f"{ft_rows} freshness-TOCTOU seam(s) (validate-here/consume-stale-there); "
                f"un_disposed={acct.get('un_disposed', 0)} - review candidates, not a gate"),
        artifacts=arts,
        detail={"rows": rows, "freshness_toctou_rows": ft_rows,
                "un_disposed": acct.get("un_disposed", 0)})


def check_enforcement_layer_census(ws: Path) -> SignalResult:
    """B3 enforcement-layer census. Auto-emits tools/enforcement-layer-census.py: detects
    which trust layers (access-control / crypto / serialization / consensus / upgrade /
    oracle / conservation) are PRESENT in the in-scope source and counts hunt sidecars
    mapped to each; a layer present in source with 0 sidecars is FLAGGED (we never hunted
    it). Advisory-WARN by default; enforces ONLY under the dedicated opt-in env
    AUDITOOOR_ENFORCEMENT_LAYER_CENSUS_STRICT (deliberately NOT the strict L37 umbrella yet
    - present-detection is intentionally broader than credit, so the dedicated env lands
    FIRST; umbrella-promote once flagged==0 is verified across the currently-green fleet).
    Fail-OPEN (WARN-pass) when the tool is missing. Rebuttal: enforcement-layer-census:."""
    tool = Path(__file__).resolve().with_name("enforcement-layer-census.py")
    if not tool.is_file():
        return SignalResult(signal="enforcement-layer-census", ok=True,
                            reason="enforcement-layer-census.py unavailable; WARN-pass", artifacts=[])
    try:
        spec = importlib.util.spec_from_file_location("_elc_mod", tool)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_elc_mod"] = mod
        spec.loader.exec_module(mod)
        mod.main(["--workspace", str(ws)])
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="enforcement-layer-census", ok=True,
                            reason=f"enforcement-layer-census raised ({exc}); WARN-pass", artifacts=[])
    p = ws / ".auditooor" / "enforcement_layer_census.json"
    doc = {}
    try:
        doc = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
    except (OSError, ValueError):
        doc = {}
    flagged = doc.get("flagged_layers") or []
    # DEDICATED opt-in ONLY (deliberately NOT the strict L37 umbrella yet): B3
    # present-detection is intentionally broader than sidecar credit (an advisory
    # over-flag is safe, a false-green is not - enforcement-layer-census.py), so a
    # genuinely-green ws can legitimately carry a present-but-unhunted layer with 0
    # sidecars. Landing the dedicated env FIRST (this stage) gives the census teeth
    # under an explicit opt-in without retro-redding the fleet; promote it into the
    # L37 umbrella (add `or AUDITOOOR_L37_STRICT`) once flagged==0 is verified across
    # the currently-green fleet. Rebuttal key: ``enforcement-layer-census:``.
    strict = os.environ.get("AUDITOOOR_ENFORCEMENT_LAYER_CENSUS_STRICT", "").strip() == "1"
    ok = not (flagged and strict)
    if flagged:
        reason = (f"advisory: {len(flagged)} present-but-0-sidecar enforcement layer(s) "
                  f"[{', '.join(flagged[:6])}] - hunt-worklist candidates"
                  + ("; hunt-worklist candidates, not a gate" if ok else
                     "; (STRICT: hunt each flagged trust layer, or add an "
                     "enforcement-layer-census-rebuttal, before done)"))
    else:
        reason = "advisory: every present enforcement layer has >=1 sidecar"
    return SignalResult(
        signal="enforcement-layer-census", ok=ok, reason=reason,
        artifacts=[str(p)] if p.is_file() else [],
        detail={"flagged_layers": flagged, "strict": strict})


def check_capability_wiring_integrity(ws: Path) -> SignalResult:
    """Repo-level capability-set WIRING audit (advisory, report-only). Shells the
    whole-flow wiring auditor tools/capability-wiring-integrity-check.py, which
    enumerates reference/capability_inventory.jsonl and per cap asserts the whole
    flow (INVOKED / FEEDS-FROM / FEEDS-TO / DAG-ORDER / ENFORCED), flagging orphans
    (never invoked or no consumer) + broken-flows (invoked but source-less / wrong
    DAG order). This is a REPO-level gate (is the arsenal actually wired?), NOT a
    per-workspace one, so it runs against the mcp repo root, not `ws`. Report-only
    advisory: fail-OPEN when the tool/inventory is undecidable, and NEVER fail-closes
    here (a cap-set orphan is methodology debt, not a per-audit block; the dedicated
    AUDITOOOR_WIRING_INTEGRITY_STRICT=1 run of the tool is the hard gate). Grounds
    the STALE-DONE-ON-CAPABILITY-CHANGE rule via the capability_set_hash it surfaces.
    Rebuttal: capability-wiring-integrity:."""
    tool = Path(__file__).resolve().with_name("capability-wiring-integrity-check.py")
    repo_root = Path(__file__).resolve().parent.parent
    if not tool.is_file():
        return SignalResult(signal="capability-wiring-integrity", ok=True,
                            reason="capability-wiring-integrity-check.py unavailable; WARN-pass",
                            artifacts=[])
    try:
        spec = importlib.util.spec_from_file_location("_cwi_mod", tool)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_cwi_mod"] = mod
        spec.loader.exec_module(mod)
        doc, _rc = mod.run(repo_root, False)  # enforce=False: advisory at the signal layer
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="capability-wiring-integrity", ok=True,
                            reason=f"capability-wiring-integrity raised ({exc}); WARN-pass",
                            artifacts=[])
    if not isinstance(doc, dict) or "counts" not in doc:
        return SignalResult(signal="capability-wiring-integrity", ok=True,
                            reason="capability-wiring-integrity produced no counts; fail-open",
                            artifacts=[])
    counts = doc.get("counts") or {}
    orphan = int(counts.get("orphan", 0) or 0)
    broken = int(counts.get("broken_flow", 0) or 0)
    return SignalResult(
        signal="capability-wiring-integrity", ok=True,
        reason=(f"advisory: {orphan} orphan + {broken} broken-flow capabilit(y/ies) of "
                f"{counts.get('total', 0)} (wired={counts.get('wired', 0)}, "
                f"unknown={counts.get('unknown', 0)}) - methodology-debt review candidates, not a gate"),
        detail={"orphans": orphan, "broken_flows": broken,
                "capability_set_hash": doc.get("capability_set_hash"),
                "wiring_warn": (orphan + broken) > 0})


def check_callgraph_set_difference(ws: Path) -> SignalResult:
    """LOGIC #3 callgraph SET-DIFFERENCE reasoner join (Euler $197M). The pre-hunt
    producer tools/callgraph-set-difference-hunter.py computes
    {fns mutating a protected qty DOWNWARD} \\ {fns reaching the required post-state
    solvency/health CHECK} and emits each survivor as an unguarded-mutation-entrypoint
    obligation into <ws>/.auditooor/unguarded_mutation_obligations.jsonl. That output
    was previously PRODUCED-BUT-UNREAD by the L37 umbrella (exploit-queue ingests the
    obligations, but audit-complete never JOINED the reasoner - so "did we even run the
    unguarded-downward-mutation trust-layer probe?" could never FAIL audit-complete).
    This signal reads the reasoner's artifact so the umbrella SEES it.

    Advisory-first (report-only by default, mirroring cross-module-trust-seam /
    enforcement-layer-census): PASS reporting survivor obligation count; NEVER
    fail-closes under the default `make audit-complete` (a survivor is a hunt-worklist
    candidate, not a per-audit block). A DOCUMENTED dedicated STRICT flag
    AUDITOOOR_L37_CALLGRAPH_SETDIFF_STRICT=1 (also honored via the global
    AUDITOOOR_L37_STRICT=1) makes it fail-closed when the reasoner NEVER RAN while a
    dataflow substrate exists (dataflow_paths.jsonl present) - i.e. the trust-layer
    probe was skipped. Fail-OPEN (WARN-pass) when there is no dataflow substrate
    (nothing to reason over) or the artifact is unreadable. Rebuttal:
    ``callgraph-set-difference:``."""
    aud = ws / ".auditooor"
    obl = aud / "unguarded_mutation_obligations.jsonl"
    # Substrate presence: the reasoner is only meaningful when a dataflow closure
    # exists to diff over. No substrate -> nothing to probe -> WARN-pass.
    substrate = (aud / "dataflow_paths.jsonl")
    has_substrate = substrate.is_file() or bool(list(aud.glob("dataflow_paths.*.jsonl"))) \
        if aud.is_dir() else False
    strict = (
        os.environ.get("AUDITOOOR_L37_CALLGRAPH_SETDIFF_STRICT", "").strip() == "1"
        or os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1"
    )
    ran = obl.is_file()
    survivors = 0
    if ran:
        try:
            for line in obl.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    survivors += 1
        except OSError:
            return SignalResult(
                signal="callgraph-set-difference", ok=True,
                reason="advisory: unguarded_mutation_obligations.jsonl unreadable; fail-open",
                artifacts=[])
    arts = [str(obl)] if ran else []
    if not ran:
        # Producer never ran. If a substrate exists it SHOULD have (skipped probe);
        # advisory-WARN by default, fail-closed only under the dedicated/global STRICT.
        if has_substrate:
            ok = not strict
            reason = (
                "advisory: callgraph set-difference reasoner did NOT run "
                "(no unguarded_mutation_obligations.jsonl) despite a dataflow substrate "
                "- unguarded-downward-mutation trust layer unprobed"
                + ("; hunt-worklist candidate, not a gate" if ok else
                   "; (STRICT: run tools/callgraph-set-difference-hunter.py, or add a "
                   "callgraph-set-difference-rebuttal, before done)")
            )
            return SignalResult(
                signal="callgraph-set-difference", ok=ok, reason=reason,
                artifacts=arts,
                detail={"ran": False, "has_substrate": True, "strict": strict})
        return SignalResult(
            signal="callgraph-set-difference", ok=True,
            reason="advisory: no dataflow substrate (dataflow_paths.jsonl absent); "
                   "nothing to reason over - WARN-pass",
            artifacts=arts, detail={"ran": False, "has_substrate": False, "strict": strict})
    return SignalResult(
        signal="callgraph-set-difference", ok=True,
        reason=(f"advisory: callgraph set-difference reasoner ran; {survivors} "
                f"unguarded-mutation-entrypoint obligation(s) (DOWN\\CHECK survivors) "
                f"- hunt-worklist candidates, not a gate"),
        artifacts=arts,
        detail={"ran": True, "survivors": survivors, "strict": strict})


def check_logic_obligation_resolution(ws: Path) -> SignalResult:
    """LOGIC-OBLIGATION RESOLUTION umbrella JOIN (docs/LOGIC_ARSENAL_ROADMAP.md,
    "ENFORCE, NOT ADVISORY"). The 8 core pre-hunt reasoners + the language reasoners
    (step-2d-* runbook steps) each EMIT an obligation ledger that exploit-queue.py
    ingests and per-fn-mimo-batch-gen.py folds into the per-fn OPEN-OBLIGATIONS block.
    Nothing asserted the emitted obligation ever reached a TERMINAL verdict, so a
    reasoner could surface 19 numeric-boundary obligations and the hunt could ignore
    every one while audit-complete still passed. This signal reads every reasoner
    ledger via tools/logic-obligation-resolution-check.py and reports the OPEN count.

    ENFORCED / DEFAULT-ON under the L37 umbrella (the advisory-first wave is complete;
    operator directive LOGIC_ARSENAL_ROADMAP "ENFORCE, NOT ADVISORY", 2026-07-13).
    Fail-closed (ok=False, fail-logic-obligation-unresolved) under the standard STRICT
    path - the global AUDITOOOR_L37_STRICT=1 that `make audit-complete` exports by
    default (or the dedicated AUDITOOOR_L37_LOGIC_OBLIGATION_RESOLUTION_STRICT=1) - when
    >=1 emitted obligation is still OPEN, OR (with a dataflow substrate) when no reasoner
    ledger ran at all. Per-gate opt-out: AUDITOOOR_L37_LOGIC_OBLIGATION_RESOLUTION_STRICT
    in {0,false,no} downgrades to advisory (a bare / library caller with L37 unset also
    stays advisory - no retro-red). Fail-OPEN when nothing was reasoned (no substrate /
    no ledger). Rebuttal: ``logic-obligation-resolution:``. Global-rule admission is
    operator-directed (same directive): <!-- admitted: signal:LOGIC_OBLIGATION_RESOLUTION -->"""
    tool = Path(__file__).resolve().with_name("logic-obligation-resolution-check.py")
    if not tool.is_file():
        return SignalResult(signal="logic-obligation-resolution", ok=True,
                            reason="logic-obligation-resolution-check.py unavailable; WARN-pass",
                            artifacts=[])
    # ENFORCE (operator directive, LOGIC_ARSENAL_ROADMAP "ENFORCE, NOT ADVISORY",
    # 2026-07-13): the advisory-first wave is complete, so this signal is now
    # DEFAULT-ON under the L37 umbrella (RUBRIC axis #4: "audit-complete STRICT/L37
    # default-ON ... with a per-gate opt-out"). An OPEN reasoner obligation FAILS
    # audit-complete under the standard STRICT path (AUDITOOOR_L37_STRICT=1, which
    # `make audit-complete` exports by default) - not only under the dedicated env.
    # Explicit per-gate opt-out: AUDITOOOR_L37_LOGIC_OBLIGATION_RESOLUTION_STRICT in
    # {0,false,no} downgrades to advisory (escape hatch for a bare / library caller,
    # mirroring the E4/D2/G1/G2 default-ON graduations). Behaviour under the standard
    # STRICT path is unchanged (still fail-closed on an OPEN obligation); this only
    # formalizes the graduation + the per-gate opt-out. The tool honors the same env;
    # the umbrella toggle name below is mapped so the tool's check() sees it too.
    strict = _gate_default_on_strict("AUDITOOOR_L37_LOGIC_OBLIGATION_RESOLUTION_STRICT")
    prev = os.environ.get("AUDITOOOR_L37_LOGIC_OBLIGATION_STRICT")
    if strict:
        os.environ["AUDITOOOR_L37_LOGIC_OBLIGATION_STRICT"] = "1"
    try:
        spec = importlib.util.spec_from_file_location("_logic_obl_mod", tool)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_logic_obl_mod"] = mod
        spec.loader.exec_module(mod)
        res = mod.check(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="logic-obligation-resolution", ok=True,
                            reason=f"logic-obligation-resolution raised ({exc}); WARN-pass",
                            artifacts=[])
    finally:
        if strict and prev is None:
            os.environ.pop("AUDITOOOR_L37_LOGIC_OBLIGATION_STRICT", None)
    ok = bool(res.get("ok", True)) if isinstance(res, dict) else True
    reason = res.get("reason", "") if isinstance(res, dict) else ""
    return SignalResult(
        signal="logic-obligation-resolution", ok=ok,
        reason=f"logic-obligation-resolution: {reason}",
        artifacts=list(res.get("artifacts", []) or []) if isinstance(res, dict) else [],
        detail=res if isinstance(res, dict) else {})


def check_reasoner_firing_nonvacuity(ws: Path) -> SignalResult:
    """REASONER-FIRING NON-VACUITY JOIN (LOGIC_ARSENAL_ROADMAP, the FIRING half of the
    shape->logic inversion). The sibling logic-obligation-resolution signal proves every
    EMITTED reasoner obligation reached a terminal verdict. But a reasoner can pass the
    ORDERING gate (wired to run pre-hunt) while emitting ZERO obligations and leaving ZERO
    trace of having examined anything: a silently-empty / never-written ledger reads
    identically to "ran clean and found nothing". That is coverage-theater / vacuity - the
    reasoner is wired but dead - and audit-complete still passes.

    This signal reads every wired reasoner ledger (the _REASONER_LEDGERS registry, single
    source of truth in logic-obligation-resolution-check.py) via
    tools/reasoner-firing-nonvacuity-check.py and asserts each reasoner FIRED: examined>0
    AND one of {>=1 anchored obligation emitted, an explicit cited-empty examined-record,
    a RECORDED source-cited surface-absent exemption}. A reasoner that is SILENTLY vacuous
    (empty/missing ledger with no record) is the fail-loud case - a real capability gap.

    Advisory-WARN by default (a bare / library caller with L37 unset stays advisory -
    no retro-red). Fail-closed (ok=False, fail-reasoner-vacuous) under the standard STRICT
    path (global AUDITOOOR_L37_STRICT=1 that `make audit-complete` exports by default) or
    the dedicated AUDITOOOR_L37_REASONER_FIRING_STRICT=1, with a per-gate opt-out
    (AUDITOOOR_L37_REASONER_FIRING_STRICT in {0,false,no} downgrades to advisory). The gate
    NEVER auto-exempts a vacuous reasoner - surfacing the gap is the point; the exemption
    path requires an explicit recorded artifact. Rebuttal: ``reasoner-firing-nonvacuity:``.
    Global-rule admission (LOGIC_ARSENAL_ROADMAP "ENFORCE, NOT ADVISORY"):
    <!-- admitted: signal:REASONER_FIRING_NONVACUITY -->"""
    tool = Path(__file__).resolve().with_name("reasoner-firing-nonvacuity-check.py")
    if not tool.is_file():
        return SignalResult(signal="reasoner-firing-nonvacuity", ok=True,
                            reason="reasoner-firing-nonvacuity-check.py unavailable; WARN-pass",
                            artifacts=[])
    strict = _gate_default_on_strict("AUDITOOOR_L37_REASONER_FIRING_STRICT")
    prev = os.environ.get("AUDITOOOR_L37_REASONER_FIRING_STRICT")
    if strict:
        os.environ["AUDITOOOR_L37_REASONER_FIRING_STRICT"] = "1"
    try:
        spec = importlib.util.spec_from_file_location("_reasoner_firing_mod", tool)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_reasoner_firing_mod"] = mod
        spec.loader.exec_module(mod)
        res = mod.check(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="reasoner-firing-nonvacuity", ok=True,
                            reason=f"reasoner-firing-nonvacuity raised ({exc}); WARN-pass",
                            artifacts=[])
    finally:
        if strict and prev is None:
            os.environ.pop("AUDITOOOR_L37_REASONER_FIRING_STRICT", None)
    ok = bool(res.get("ok", True)) if isinstance(res, dict) else True
    reason = res.get("reason", "") if isinstance(res, dict) else ""
    return SignalResult(
        signal="reasoner-firing-nonvacuity", ok=ok,
        reason=f"reasoner-firing-nonvacuity: {reason}",
        artifacts=list(res.get("artifacts", []) or []) if isinstance(res, dict) else [],
        detail=res if isinstance(res, dict) else {})


def check_executed_refutation_honesty(ws: Path) -> SignalResult:
    """EXECUTED-REFUTATION HONESTY umbrella JOIN (LOGIC_ARSENAL_ROADMAP logic #2).
    tools/executed-refutation-negative-gate.py REJECTS as non-honest any NEGATIVE
    verdict (cleared/kill) on a value-mover unit whose local_verification_cmd is
    grep-only OR that has no matching executed poc_execution_record + guard-
    neutralization mutant receipt (a grep-NEGATIVE, the R3 diagnosis). It existed as
    a standalone tool but was never JOINED to the L37 umbrella, so a grep-only KILL of
    a value-mover could not fail audit-complete.

    Advisory-first: WARN-pass by default; fail-closed (ok=False,
    fail-executed-refutation-dishonest) only under the dedicated
    AUDITOOOR_L37_EXECUTED_REFUTATION_HONESTY_STRICT=1 OR the global
    AUDITOOOR_L37_STRICT=1 when >=1 non-honest value-mover NEGATIVE remains.
    WARN-passes when there are 0 value-mover negatives to check. Rebuttal:
    ``executed-refutation-honesty:``. Global-rule admission is operator-directed
    (LOGIC_ARSENAL_ROADMAP "ENFORCE, NOT ADVISORY", 2026-07-13):
    <!-- admitted: signal:EXECUTED_REFUTATION_HONESTY -->"""
    tool = Path(__file__).resolve().with_name("executed-refutation-negative-gate.py")
    if not tool.is_file():
        return SignalResult(signal="executed-refutation-honesty", ok=True,
                            reason="executed-refutation-negative-gate.py unavailable; WARN-pass",
                            artifacts=[])
    # step-4d: (re)emit the executed-depth-conversion obligation worklist so a
    # needs-llm-depth verdict + every grep-only value-mover NEGATIVE has a per-unit
    # executed-refutation obligation on disk (idempotent; never clobbers a resolved
    # poc_execution_record). This is the "audit-complete invokes the lane" wiring -
    # advisory/fail-open so a missing tool never blocks the honesty signal itself.
    conv = Path(__file__).resolve().with_name("executed-depth-conversion.py")
    if conv.is_file():
        try:
            _cspec = importlib.util.spec_from_file_location("_exec_depth_conv_mod", conv)
            _cmod = importlib.util.module_from_spec(_cspec)
            sys.modules["_exec_depth_conv_mod"] = _cmod
            _cspec.loader.exec_module(_cmod)
            _cmod.emit_obligations(ws)
        except Exception:  # pragma: no cover (defensive) - fail-open
            pass
    try:
        spec = importlib.util.spec_from_file_location("_exec_refut_mod", tool)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_exec_refut_mod"] = mod
        spec.loader.exec_module(mod)
        res = mod.scan(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="executed-refutation-honesty", ok=True,
                            reason=f"executed-refutation-honesty raised ({exc}); WARN-pass",
                            artifacts=[])
    flagged = res.get("flagged", []) if isinstance(res, dict) else []
    considered = int(res.get("considered_value_mover_negatives", 0) or 0) if isinstance(res, dict) else 0
    strict = _l37_gate_strict("EXECUTED_REFUTATION_HONESTY")
    if considered == 0:
        return SignalResult(
            signal="executed-refutation-honesty", ok=True,
            reason="executed-refutation-honesty: 0 value-mover NEGATIVE verdicts to check; WARN-pass",
            detail={"considered": 0, "flagged": 0, "strict": strict})
    ok = (not flagged) or (not strict)
    reason = (
        f"executed-refutation-honesty: {len(flagged)} non-honest value-mover NEGATIVE(s) "
        f"of {considered} (grep-only or no executed-refutation+guard-neutralization receipt)"
        + ("" if not flagged else
           ("; advisory - review candidates, not a gate" if ok else
            "; (STRICT: replace each grep-NEGATIVE with an executed refutation + "
            "guard-neutralization mutant, or add an executed-refutation-honesty-rebuttal)")))
    return SignalResult(
        signal="executed-refutation-honesty", ok=ok, reason=reason,
        detail={"considered": considered, "flagged": len(flagged),
                "flagged_detail": flagged[:20], "strict": strict})


def check_capability_firing_fraction(ws: Path) -> SignalResult:
    """CAPABILITY-FIRING-FRACTION umbrella JOIN (LOGIC_ARSENAL_ROADMAP axis 1: the
    north-star firing metric). The sibling capability-wiring-integrity signal is
    report-only (never fails); this JOINS its FIRING dimension (the invoked=True
    fraction over the RESOLVABLE denominator) into the umbrella so an arsenal that is
    wired-by-closure but not actually INVOKED can fail audit-complete. Shells
    tools/capability-wiring-integrity-check.py run() with enforce=strict, which
    computes invoked_fraction_low against the min-invoked-ratio floor.

    Repo-level (runs against the mcp repo root, not `ws`). Advisory-first: WARN-pass
    by default; fail-closed (ok=False, fail-capability-firing-too-low) only under the
    dedicated AUDITOOOR_L37_CAPABILITY_FIRING_FRACTION_STRICT=1 OR the global
    AUDITOOOR_L37_STRICT=1 when the invoked fraction is below the floor. Fail-OPEN when
    the tool/inventory is undecidable. Rebuttal: ``capability-firing-fraction:``.
    Global-rule admission is operator-directed (LOGIC_ARSENAL_ROADMAP "ENFORCE, NOT
    ADVISORY", 2026-07-13): <!-- admitted: signal:CAPABILITY_FIRING_FRACTION -->"""
    tool = Path(__file__).resolve().with_name("capability-wiring-integrity-check.py")
    repo_root = Path(__file__).resolve().parent.parent
    if not tool.is_file():
        return SignalResult(signal="capability-firing-fraction", ok=True,
                            reason="capability-wiring-integrity-check.py unavailable; WARN-pass",
                            artifacts=[])
    strict = _l37_gate_strict("CAPABILITY_FIRING_FRACTION")
    try:
        spec = importlib.util.spec_from_file_location("_cff_mod", tool)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_cff_mod"] = mod
        spec.loader.exec_module(mod)
        doc, _rc = mod.run(repo_root, strict)  # enforce=strict: firing floor is live only under strict
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(signal="capability-firing-fraction", ok=True,
                            reason=f"capability-firing-fraction raised ({exc}); WARN-pass",
                            artifacts=[])
    if not isinstance(doc, dict) or "invoked" not in doc:
        return SignalResult(signal="capability-firing-fraction", ok=True,
                            reason="capability-firing-fraction produced no invoked block; fail-open",
                            artifacts=[])
    inv = doc.get("invoked") or {}
    frac = inv.get("invoked_fraction")
    low = bool(inv.get("invoked_fraction_low"))
    ok = not (strict and low)
    reason = (
        f"capability-firing-fraction: invoked={inv.get('invoked_true')}/"
        f"{inv.get('resolvable')} (fraction={frac}, floor={inv.get('min_invoked_ratio')})"
        + ("" if ok else
           "; (STRICT: firing fraction below floor - WIRE the wired-by-closure caps to "
           "invoked=True, or add a capability-firing-fraction-rebuttal)"))
    return SignalResult(
        signal="capability-firing-fraction", ok=ok, reason=reason,
        detail={"invoked_fraction": frac, "invoked_fraction_low": low,
                "capability_set_hash": doc.get("capability_set_hash"), "strict": strict,
                "firing_warn": low})


# --------------------------------------------------------------------------
# Signal: impact-methodology-corpus (DELIVERY, not presence). The impact-
# methodology capability was previously only injected into the dispatch BRIEF +
# guarded by a YAML-consistency drift gate + a resolution COUNT - none asserted
# that the persisted per-fn corpus actually CARRIES the capability, is FRESH, or
# is FUNCTION-SPECIALIZED. So a stale pre-capability corpus (SSV June-23, 0 impact
# rows) went green. This signal fails closed when a value surface's corpus lacks
# impact-methodology provenance or carries only generic (non-fn-bound) impact
# prose. Rebuttal override key: ``impact-methodology-corpus:``.
# --------------------------------------------------------------------------
def _load_impact_corpus_module():
    tool_path = Path(__file__).resolve().with_name(
        "impact-methodology-corpus-provenance-check.py")
    if not tool_path.is_file():
        return None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("_impact_corpus_acc", tool_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_impact_corpus_acc"] = mod
        spec.loader.exec_module(mod)  # type: ignore
        return mod
    except Exception:
        return None


def check_impact_methodology_corpus(ws: Path) -> SignalResult:
    mod = _load_impact_corpus_module()
    if mod is None:
        return SignalResult(
            signal="impact-methodology-corpus", ok=True,
            reason="impact-methodology-corpus-provenance-check.py unavailable; WARN-pass",
            artifacts=[], detail={"impact_corpus_tool": "unavailable"})
    try:
        res = mod.check(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="impact-methodology-corpus", ok=True,
            reason=f"impact-corpus check raised ({exc}); WARN-pass",
            artifacts=[], detail={"impact_corpus_error": str(exc)})
    v = res.get("verdict", "") if isinstance(res, dict) else ""
    ok = v in (mod.VERDICT_PASS, mod.VERDICT_NA)
    return SignalResult(
        signal="impact-methodology-corpus", ok=ok,
        reason=f"impact-methodology-corpus verdict={v or 'unknown'}: {res.get('reason', '') if isinstance(res, dict) else ''}",
        artifacts=[], detail=res if isinstance(res, dict) else {"verdict": v})


# --------------------------------------------------------------------------
# Signal: core-coverage (a periphery-only invariant harness set must FAIL)
# r36-rebuttal: lane FIX-CORE-COVERAGE-GATE registered in .auditooor/agent_pathspec.json
#
# tools/core-coverage-completeness.py owns the scan: if the workspace flags
# in-scope value-moving CORE contracts (the canonical
# value_moving_functions.json set), it REQUIRES >=1 mutation-verified stateful
# invariant harness whose CUT (source_file) is one of those core contracts. A
# harness set that is broad / non-vacuous / fuzzed but targets only PERIPHERY
# (logging/view/config shims) PASSES invariant-fuzz yet FAILS here. EXTEND-not-
# duplicate (the depth-certificate / cross-function / invariant-fuzz pattern):
# one tool owns the gate, L37 imports + runs it. WARN-passes on tooling-absence
# (value-moving producer missing). ``pass-no-core-contracts`` /
# ``pass-core-mutation-evidence-absent`` / ``pass-core-covered`` all PASS - only
# ``fail-core-coverage-periphery-only`` blocks L37. Inherits the l37-rebuttal
# override (signal key ``core-coverage:``) applied on top in evaluate().
# --------------------------------------------------------------------------
def _load_core_coverage_module():
    tool_path = Path(__file__).resolve().with_name("core-coverage-completeness.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_core_coverage_acc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_core_coverage_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def check_core_coverage(ws: Path) -> SignalResult:
    # r36-rebuttal: lane FIX-CORE-COVERAGE-GATE registered in .auditooor/agent_pathspec.json
    mod = _load_core_coverage_module()
    if mod is None:
        return SignalResult(
            signal="core-coverage", ok=True,
            reason="core-coverage-completeness.py unavailable; degraded to WARN-pass",
            artifacts=[], detail={"core_coverage_tool": "unavailable"})
    try:
        res = mod.evaluate(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="core-coverage", ok=True,
            reason=f"core-coverage-completeness raised ({exc}); WARN-pass",
            artifacts=[], detail={"core_coverage_error": str(exc)})
    v = res.get("verdict", "") if isinstance(res, dict) else ""
    # Tooling-absence verdict from inside the tool also degrades to WARN-pass.
    if v in ("pass-tooling-absent", ""):
        return SignalResult(
            signal="core-coverage", ok=True,
            reason=f"core-coverage degraded/WARN-pass: {res.get('reason', '') if isinstance(res, dict) else ''}",
            artifacts=[], detail=res if isinstance(res, dict) else {"verdict": v})
    if v == "fail-core-coverage-periphery-only":
        return SignalResult(
            signal="core-coverage", ok=False,
            reason=f"core-coverage FAILS (periphery-only harness set): {res.get('reason', '')}",
            artifacts=[], detail=res)
    return SignalResult(
        signal="core-coverage", ok=True,
        reason=f"core-coverage verdict={v or 'unknown'}: {res.get('reason', '') if isinstance(res, dict) else ''}",
        artifacts=[], detail=res if isinstance(res, dict) else {"verdict": v})


# --------------------------------------------------------------------------
# Signal: fork-divergence-content (the CONTENT sibling of fork-divergence)
# r36-rebuttal: lane FIX-FORK-DIVERGENCE-CONTENT registered in .auditooor/agent_pathspec.json
#
# fork-divergence asks "did the divergence PROBE run?"; this asks the stronger
# "is there a content-rich upstream-divergence MANIFEST enumerating the actual
# deviations from the upstream fork?" A workspace that greps as a fork/vendored
# target REQUIRES .auditooor/upstream_divergence.json with a non-empty upstream
# + >=1 deviation carrying file/kind/summary (mere presence is not credit).
# tools/upstream-divergence-manifest.py owns the scan. EXTEND-not-duplicate: one
# tool owns the gate, L37 imports + runs it. WARN-passes on tooling-absence /
# no-source / no-fork-detected; only ``fail-upstream-fork-divergence-manifest-
# missing`` blocks L37. Inherits the l37-rebuttal override (signal key
# ``fork-divergence-content:``) applied on top in evaluate().
# --------------------------------------------------------------------------
def _load_upstream_divergence_module():
    tool_path = Path(__file__).resolve().with_name("upstream-divergence-manifest.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_upstream_divergence_acc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_upstream_divergence_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def check_fork_divergence_content(ws: Path) -> SignalResult:
    # r36-rebuttal: lane FIX-FORK-DIVERGENCE-CONTENT registered in .auditooor/agent_pathspec.json
    mod = _load_upstream_divergence_module()
    if mod is None:
        return SignalResult(
            signal="fork-divergence-content", ok=True,
            reason="upstream-divergence-manifest.py unavailable; degraded to WARN-pass",
            artifacts=[], detail={"fork_divergence_content_tool": "unavailable"})
    try:
        res = mod.evaluate(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="fork-divergence-content", ok=True,
            reason=f"upstream-divergence-manifest raised ({exc}); WARN-pass",
            artifacts=[], detail={"fork_divergence_content_error": str(exc)})
    v = res.get("verdict", "") if isinstance(res, dict) else ""
    if v == "fail-upstream-fork-divergence-manifest-missing":
        return SignalResult(
            signal="fork-divergence-content", ok=False,
            reason=f"fork-divergence-content FAILS (fork target without populated manifest): {res.get('reason', '')}",
            artifacts=[], detail=res)
    # error / pass-no-source / pass-no-fork-detected / pass-fork-divergence-populated all PASS.
    return SignalResult(
        signal="fork-divergence-content", ok=True,
        reason=f"fork-divergence-content verdict={v or 'unknown'}: {res.get('reason', '') if isinstance(res, dict) else ''}",
        artifacts=[], detail=res if isinstance(res, dict) else {"verdict": v})


# --------------------------------------------------------------------------
# Signal: unhunted-followthrough
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
#
# FOLLOW-THROUGH completeness. A workspace can pass every coverage axis above
# and still ABANDON surfaces it explicitly identified as "unhunted" /
# "identified-but-no-verdict" in its exploit_queue / reports/ triage artifacts
# without ever driving them to a TERMINAL verdict (confirmed / refuted / filed
# / killed). An audit is not complete while those surfaces are left dangling.
#
# tools/unhunted-surface-followthrough-gate.py owns the scan logic and exposes
# a reusable ``evaluate(workspace: str) -> dict`` (verdicts: error /
# pass-no-workspace-inputs / pass-no-surfaces / fail-abandoned-surfaces). This
# signal delegates to it - the R80/depth-certificate EXTEND-not-duplicate path:
# one tool owns the gate, L37 imports and runs it. This signal FAILS L37
# (verdict ``fail-unhunted-followthrough-abandoned``) only on
# ``fail-abandoned-surfaces``; every other verdict (including no-inputs / no-
# surfaces) PASSES. It inherits the l37-rebuttal override (signal key
# ``unhunted-followthrough:``) applied on top in evaluate().
#
# Graceful degradation (mirrors depth-certificate): if the gate tool is
# missing / unimportable / raises, this signal WARNS and PASSES rather than
# hard-failing L37 on tooling-absence.
# --------------------------------------------------------------------------
def _load_unhunted_followthrough_module():
    """Load tools/unhunted-surface-followthrough-gate.py if on disk; else None."""
    tool_path = Path(__file__).resolve().with_name(
        "unhunted-surface-followthrough-gate.py"
    )
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "_unhunted_followthrough_acc", tool_path
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_unhunted_followthrough_acc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _load_inscope_disposition_guard():
    tool_path = Path(__file__).resolve().parent / "inscope-disposition-guard.py"
    if not tool_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_inscope_disp_guard", tool_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_inscope_disp_guard"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _load_go_coverage_basis_guard():
    tool_path = Path(__file__).resolve().parent / "go-coverage-basis-check.py"
    if not tool_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_go_coverage_basis_guard", tool_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_go_coverage_basis_guard"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _load_manual_step_required_guard():
    tool_path = Path(__file__).resolve().parent / "manual-step-required-check.py"
    if not tool_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_manual_step_required_guard", tool_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_manual_step_required_guard"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _load_business_flow_module():
    tool_path = Path(__file__).resolve().parent / "business_flow_decompose.py"
    if not tool_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_business_flow_decompose", tool_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_business_flow_decompose"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def check_business_flow_coverage(ws: Path) -> SignalResult:
    """Signal: every DRIVABLE cross-module business flow was driven by a
    hunt/harness. An undriven flow is an un-enumerated combination the per-fn
    axis misses. Fails CLOSED under strict (NOT advisory); WARN otherwise;
    WARN-passes on tooling-absence / no-flows (never a false green)."""
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("BUSINESS_FLOW")
    mod = _load_business_flow_module()
    if mod is None or not hasattr(mod, "coverage"):
        return SignalResult(
            signal="business-flow-coverage", ok=True,
            reason="business_flow_decompose.py unavailable; signal degraded to "
                   "WARN-pass (tooling-absence does not block L37)",
            artifacts=[], detail={"strict": strict})
    try:
        rep = mod.coverage(ws) or {}
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="business-flow-coverage", ok=True,
            reason=f"business_flow_decompose raised ({exc}); WARN-pass "
                   "(tooling-error does not block L37)",
            artifacts=[], detail={"error": str(exc), "strict": strict})
    verdict = rep.get("verdict")
    undriven = rep.get("undriven_flows") or []
    detail = {"verdict": verdict, "drivable_flows": rep.get("drivable_flows", 0),
              "undriven": undriven[:30], "undriven_count": len(undriven), "strict": strict}
    if verdict == "warn-undriven-flows" and undriven:
        reason = (f"business-flow-coverage FAILS: {len(undriven)} DRIVABLE cross-module "
                  f"flow(s) driven by NO hunt/harness (first: {undriven[0]}) - a combination "
                  "coverage gap the per-function axis misses")
        if strict:
            return SignalResult(signal="business-flow-coverage", ok=False,
                                reason=reason, artifacts=[], detail=detail)
        return SignalResult(signal="business-flow-coverage", ok=True,
                            reason="WARN: " + reason, artifacts=[], detail=detail)
    return SignalResult(
        signal="business-flow-coverage", ok=True,
        reason=f"business-flow-coverage verdict={verdict}: every drivable cross-module "
               f"flow ({rep.get('drivable_flows', 0)}) is driven by a hunt/harness",
        artifacts=[], detail=detail)


def check_inscope_disposition(ws: Path) -> SignalResult:
    """Signal: NO disposition marks an IN-SCOPE unit out-of-scope.

    The generic, language-agnostic backstop for the strata 2026-07-01 class - a
    disposition tool auto-closed an in-scope first-party unit as vendored/OOS
    using a local heuristic that contradicted the authoritative inscope_units.jsonl
    manifest. An in-scope unit is first-party BY DEFINITION and can never be
    OOS/vendored/trusted. Delegates to inscope-disposition-guard.evaluate().

    Fail-closed under strict (a wrong-scope closure is an unambiguous bug, not
    debt); WARN otherwise. WARN-passes on tooling-absence / no-manifest (setup
    not run) - never a false green."""
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("INSCOPE_DISPOSITION")
    mod = _load_inscope_disposition_guard()
    if mod is None or not hasattr(mod, "evaluate"):
        return SignalResult(
            signal="inscope-disposition", ok=True,
            reason="inscope-disposition-guard.py unavailable; signal degraded to "
                   "WARN-pass (tooling-absence does not block L37)",
            artifacts=[], detail={"strict": strict})
    try:
        res = mod.evaluate(str(ws)) or {}
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="inscope-disposition", ok=True,
            reason=f"inscope-disposition-guard raised ({exc}); WARN-pass "
                   "(tooling-error does not block L37)",
            artifacts=[], detail={"error": str(exc), "strict": strict})
    verdict = res.get("verdict")
    viols = res.get("violations") or []
    detail = {"verdict": verdict, "violation_count": len(viols),
              "violations": viols[:20], "strict": strict}
    if verdict == "fail-inscope-marked-oos" and viols:
        reason = (f"inscope-disposition-guard FAILS: {len(viols)} IN-SCOPE unit(s) "
                  "closed out-of-scope (vendored/trusted/OOS) - an in-scope first-party "
                  f"unit can never be OOS. First: {viols[0].get('ref','')} "
                  f"[{viols[0].get('oos_class','')}] in {viols[0].get('artifact','')}")
        if strict:
            return SignalResult(signal="inscope-disposition", ok=False,
                                reason=reason, artifacts=[], detail=detail)
        return SignalResult(signal="inscope-disposition", ok=True,
                            reason="WARN: " + reason, artifacts=[], detail=detail)
    return SignalResult(
        signal="inscope-disposition", ok=True,
        reason=f"inscope-disposition-guard verdict={verdict}: no in-scope unit "
               "carries an out-of-scope disposition",
        artifacts=[], detail=detail)


def check_go_coverage_basis(ws: Path) -> SignalResult:
    """Signal: a Cosmos-SDK / CometBFT Go-L1 workspace measured its function-
    coverage denominator on the ENTRY-POINT surface, not the every-exported set.

    The generic backstop for the 2026-07-04 entry-point-basis class (commit
    bccc99da1b). A Go `export` is a linkage property (the Solidity-`internal`
    analog); scoring coverage over every exported keeper helper is wrong-basis.
    tools/go_entrypoint_surface.py narrows this automatically (fail-open; env
    kill-switch AUDITOOOR_FCC_GO_ENTRYPOINT_SCOPE=0). This gate catches the case
    the producer cannot: the workspace IS a confident Cosmos-Go-L1 but the fcc
    result does NOT record go_entry_surface.applied=True (kill-switch left on /
    detection failed / stale pre-capability artifact) - so the coverage number
    was computed on the every-exported denominator.

    Advisory-first: WARN otherwise, fail-closed under strict =
    _l37_gate_strict('GO_COVERAGE_BASIS'). Non-Cosmos workspaces N/A-pass
    silently (Solidity/Rust/Move/Cairo unaffected). NEVER green-passes on a
    missing fcc result for a Cosmos-Go-L1 (that is fail-fcc-missing, not a pass);
    degrades to a genuine WARN-pass only on tooling-absence. Delegates to
    tools/go-coverage-basis-check.evaluate()."""
    strict = _l37_gate_strict("GO_COVERAGE_BASIS")
    mod = _load_go_coverage_basis_guard()
    if mod is None or not hasattr(mod, "evaluate"):
        return SignalResult(
            signal="go-coverage-basis", ok=True,
            reason="go-coverage-basis-check.py unavailable; signal degraded to "
                   "WARN-pass (tooling-absence does not block L37)",
            artifacts=[], detail={"strict": strict})
    try:
        res = mod.evaluate(str(ws)) or {}
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="go-coverage-basis", ok=True,
            reason=f"go-coverage-basis-check raised ({exc}); WARN-pass "
                   "(tooling-error does not block L37)",
            artifacts=[], detail={"error": str(exc), "strict": strict})
    verdict = res.get("verdict", "")
    detail = {"verdict": verdict, "strict": strict,
              "is_cosmos_go": res.get("is_cosmos_go"),
              "fcc_present": res.get("fcc_present"),
              "go_entry_surface_applied": res.get("go_entry_surface_applied"),
              "instruction": res.get("instruction")}
    artifacts = [res["fcc_path"]] if res.get("fcc_path") else []
    if verdict in ("fail-wrong-basis", "fail-fcc-missing"):
        reason = res.get("reason", f"go-coverage-basis {verdict}")
        if strict:
            return SignalResult(signal="go-coverage-basis", ok=False,
                                reason=reason, artifacts=artifacts, detail=detail)
        return SignalResult(
            signal="go-coverage-basis", ok=True,
            reason=(reason if reason.startswith("WARN:") else "WARN: " + reason),
            artifacts=artifacts, detail=detail)
    # pass-not-cosmos-go / pass-entry-point-basis / pass-detector-unavailable
    return SignalResult(
        signal="go-coverage-basis", ok=True,
        reason=res.get("reason", f"go-coverage-basis {verdict}"),
        artifacts=artifacts, detail=detail)


def _load_fuzz_saturation_checker():
    tool_path = Path(__file__).resolve().parent / "fuzz-coverage-saturation-check.py"
    if not tool_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_fuzz_saturation_checker", tool_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_fuzz_saturation_checker"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


def check_fuzz_saturation(ws: Path) -> SignalResult:
    """Signal: every RETAINED fuzz campaign reached COVERAGE SATURATION, not just
    a raw call-count floor.

    The call count (medusa >=1M / echidna >=500K) is a PROXY; the real adequacy
    criterion is whether coverage stopped growing. tools/fuzz-coverage-saturation-
    check.py reads each campaign log's coverage-over-time curve and classifies
    SATURATED (floor was enough - the last ~40% of calls added ~0 new coverage) /
    STILL_CLIMBING (coverage still rising at end-of-run => the floor was
    INSUFFICIENT; extend, do not credit) / UNMEASURED (no retained curve).

    ADVISORY-FIRST + NEVER-RETRO-RED (first landing, validated on STRATA only -
    not yet lifted to the global L37 layer): strict is gated on the DEDICATED
    AUDITOOOR_FUZZ_SATURATION_STRICT only, so `make audit-complete STRICT=1`
    surfaces this signal but does NOT block on it. A PROVEN STILL_CLIMBING
    campaign hard-fails ONLY under that dedicated env; UNMEASURED is ALWAYS a WARN
    (absence of a retained coverage curve is a log-retention gap - e.g. cron log
    truncation - NOT proof of inadequacy, so it never retro-reds a workspace).
    WARN-passes on tooling-absence."""
    strict = os.environ.get("AUDITOOOR_FUZZ_SATURATION_STRICT", "").strip().lower() \
        not in ("", "0", "false", "no")
    mod = _load_fuzz_saturation_checker()
    if mod is None or not hasattr(mod, "check_workspace"):
        return SignalResult(
            signal="fuzz-saturation", ok=True,
            reason="fuzz-coverage-saturation-check.py unavailable; WARN-pass "
                   "(tooling-absence does not block L37)",
            artifacts=[], detail={"strict": strict})
    try:
        res = mod.check_workspace(ws) or {}
    except Exception as exc:  # noqa: BLE001
        return SignalResult(
            signal="fuzz-saturation", ok=True,
            reason=f"fuzz-saturation raised ({exc}); WARN-pass (tooling-error does not block L37)",
            artifacts=[], detail={"error": str(exc), "strict": strict})
    climbers = [r for r in res.get("results", []) if r.get("verdict") == "STILL_CLIMBING"]
    unmeasured = res.get("unmeasured", 0)
    detail = {"strict": strict, "campaigns": res.get("campaigns"),
              "saturated": res.get("saturated"), "still_climbing": res.get("still_climbing"),
              "unmeasured": unmeasured}
    if climbers:
        names = ", ".join(os.path.basename(r["log"]) for r in climbers)
        reason = (f"{len(climbers)} fuzz campaign(s) STILL CLIMBING at end-of-run "
                  f"(coverage NOT saturated - the call floor was insufficient; extend the "
                  f"campaign rather than crediting it): {names}")
        arts = [r["log"] for r in climbers]
        if strict:
            return SignalResult(signal="fuzz-saturation", ok=False, reason=reason,
                                artifacts=arts, detail=detail)
        return SignalResult(signal="fuzz-saturation", ok=True, reason="WARN: " + reason,
                            artifacts=arts, detail=detail)
    if unmeasured:
        return SignalResult(
            signal="fuzz-saturation", ok=True,
            reason=(f"WARN: {unmeasured} fuzz campaign(s) UNMEASURED (coverage-over-time "
                    "curve not retained; cannot certify saturation - retain full engine logs)"),
            artifacts=[], detail=detail)
    return SignalResult(
        signal="fuzz-saturation", ok=True,
        reason=res.get("verdict", "pass-fuzz-saturated"), artifacts=[], detail=detail)


def _load_invariant_obligation_module():
    tool_path = Path(__file__).resolve().parent / "invariant-obligation-coverage.py"
    if not tool_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_invariant_obligation", tool_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_invariant_obligation"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


def check_invariant_obligation_coverage(ws: Path) -> SignalResult:
    """Signal: every value-moving function's DERIVED invariant obligation is
    discharged by a mutation-verified tested invariant OR a cited disposition.

    Ties the audit's OWN produced per-item material (value_moving_functions +
    per_fn_hacker_questions question_class) to an invariant-coverage requirement,
    so 'all invariants held' is falsifiable: an untested, undispositioned
    value-moving obligation is an OPEN gap, not a vacuous pass (the corpus/family
    axis is breadth; this is per-item RECALL over the code's own value-movers).

    ADVISORY-FIRST + NEVER-RETRO-RED: strict is the DEDICATED
    AUDITOOOR_INVARIANT_OBLIGATION_STRICT ONLY (not global L37) - live validation
    2026-07-07 shows real open obligations on parked ws (nuva 2, morpho 41,
    beanstalk 67), so auto-hard-fail would retro-red them; the signal SURFACES the
    gap on every audit and hard-fails only under the dedicated env, pending
    per-ws remediation. WARN-passes on tooling/artifact absence."""
    strict = os.environ.get("AUDITOOOR_INVARIANT_OBLIGATION_STRICT", "").strip().lower() \
        not in ("", "0", "false", "no")
    mod = _load_invariant_obligation_module()
    if mod is None or not hasattr(mod, "check"):
        return SignalResult(signal="invariant-obligation", ok=True,
                            reason="invariant-obligation-coverage.py unavailable; WARN-pass",
                            artifacts=[], detail={"strict": strict})
    try:
        res = mod.check(ws) or {}
    except Exception as exc:  # noqa: BLE001
        return SignalResult(signal="invariant-obligation", ok=True,
                            reason=f"invariant-obligation raised ({exc}); WARN-pass",
                            artifacts=[], detail={"error": str(exc)})
    openc = res.get("open_count", 0)
    detail = {"strict": strict, "obligations": res.get("obligations"),
              "covered": res.get("covered"), "open_count": openc,
              "value_moving_assets": res.get("value_moving_assets"),
              "open": res.get("open", [])[:20]}
    if openc:
        names = ", ".join(f"{o['asset']}:{o['required_category']}" for o in res.get("open", [])[:8])
        reason = (f"{openc} value-moving obligation(s) UNCOVERED (no tested invariant + no "
                  f"disposition): {names}")
        if strict:
            return SignalResult(signal="invariant-obligation", ok=False, reason=reason,
                                artifacts=[], detail=detail)
        return SignalResult(signal="invariant-obligation", ok=True, reason="WARN: " + reason,
                            artifacts=[], detail=detail)
    return SignalResult(signal="invariant-obligation", ok=True,
                        reason=res.get("verdict", "pass-obligations-covered"),
                        artifacts=[], detail=detail)


def check_manual_step_required(ws: Path) -> SignalResult:
    """Signal: every REQUIRING-MANUAL-MODEL-ACTION step that APPLIES to this
    workspace was completed + attested.

    The operator's key ask (2026-07-04): some steps cannot be safely autorun (the
    go-ethereum fork-delta prune "fucked things up" when it pruned files it had
    not proven unmodified). For those, the model performs the step by hand and
    ATTESTS it; this gate detects an applicable-but-unattested manual step and
    fails closed under strict while surfacing the exact instruction so the model
    knows what to do.

    Advisory-first: WARN otherwise, fail-closed under strict =
    _l37_gate_strict('MANUAL_STEP'). N/A-passes silently when no manual step
    applies. WARN-passes on tooling-absence (mirrors function-coverage). Delegates
    to tools/manual-step-required-check.evaluate()."""
    strict = _l37_gate_strict("MANUAL_STEP")
    mod = _load_manual_step_required_guard()
    if mod is None or not hasattr(mod, "evaluate"):
        return SignalResult(
            signal="manual-step-required", ok=True,
            reason="manual-step-required-check.py unavailable; signal degraded to "
                   "WARN-pass (tooling-absence does not block L37)",
            artifacts=[], detail={"strict": strict})
    try:
        res = mod.evaluate(str(ws)) or {}
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="manual-step-required", ok=True,
            reason=f"manual-step-required-check raised ({exc}); WARN-pass "
                   "(tooling-error does not block L37)",
            artifacts=[], detail={"error": str(exc), "strict": strict})
    verdict = res.get("verdict", "")
    unattested = res.get("unattested") or []
    detail = {"verdict": verdict, "strict": strict,
              "applicable_count": res.get("applicable_count"),
              "unattested": unattested[:10]}
    if verdict == "fail-manual-step-unattested" and unattested:
        first = unattested[0]
        reason = (f"manual-step-required FAILS: {len(unattested)} applicable "
                  f"REQUIRING-MANUAL-MODEL-ACTION step(s) not completed/attested. "
                  f"First: [{first.get('id')}] {first.get('reason')}. "
                  f"INSTRUCTION: {first.get('instruction')}")
        if strict:
            return SignalResult(signal="manual-step-required", ok=False,
                                reason=reason, artifacts=[], detail=detail)
        return SignalResult(signal="manual-step-required", ok=True,
                            reason="WARN: " + reason, artifacts=[], detail=detail)
    return SignalResult(
        signal="manual-step-required", ok=True,
        reason=res.get("reason", f"manual-step-required {verdict}"),
        artifacts=[], detail=detail)


def check_unhunted_followthrough(ws: Path) -> SignalResult:
    """Signal: every identified unhunted surface has a terminal follow-through.

    Genuine-content contract (not presence-only):
      - the follow-through gate must have RUN over scannable workspace inputs
        (json/text artifacts scanned > 0) AND report a real verdict, and
      - any ``abandoned_surfaces`` it reports are a REAL follow-through
        obligation (a surface identified but left with no terminal verdict).

    Advisory by DEFAULT: a ``fail-abandoned-surfaces`` verdict (abandoned
    surfaces > 0) returns ok=True with a ``WARN:`` reason on a normal run, so a
    normal audit-completeness run is NOT hard-failed by open follow-through
    debt. It returns ok=False ONLY under strict =
    _enforce_autonomous_proof_conversion() or _l37_gate_strict('UNHUNTED').
    Tooling-absence / tooling-error / no-inputs / no-surfaces all degrade to a
    genuine WARN-free pass.
    """
    strict = _enforce_autonomous_proof_conversion() or _l37_gate_strict("UNHUNTED")
    mod = _load_unhunted_followthrough_module()
    if mod is None or not hasattr(mod, "evaluate"):
        # Tooling absent / unimportable: degrade gracefully (do not hard-fail
        # L37 on tooling-absence) - mirrors depth-certificate.
        return SignalResult(
            signal="unhunted-followthrough", ok=True,
            reason=(
                "unhunted-surface-followthrough-gate.py unavailable; "
                "follow-through signal degraded to WARN-pass "
                "(tooling-absence does not block L37)"
            ),
            artifacts=[], detail={"unhunted_tool": "unavailable", "strict": strict},
        )
    try:
        res = mod.evaluate(str(ws))
    except Exception as exc:  # pragma: no cover (defensive)
        return SignalResult(
            signal="unhunted-followthrough", ok=True,
            reason=(
                f"unhunted-surface-followthrough-gate raised ({exc}); "
                "follow-through signal degraded to WARN-pass "
                "(tooling-error does not block L37)"
            ),
            artifacts=[], detail={"unhunted_error": str(exc), "strict": strict},
        )

    res = res or {}
    uh_verdict = res.get("verdict")
    abandoned = res.get("abandoned_surfaces") or []
    stats = res.get("stats", {}) if isinstance(res.get("stats"), dict) else {}
    json_scanned = stats.get("json_artifacts_scanned")
    text_scanned = stats.get("text_artifacts_scanned")
    scanned_total = 0
    for v in (json_scanned, text_scanned):
        if isinstance(v, int) and not isinstance(v, bool) and v > 0:
            scanned_total += v
    detail = {
        "unhunted_verdict": uh_verdict,
        "unhunted_stats": stats,
        "abandoned_count": len(abandoned),
        "abandoned_surfaces": abandoned,
        "scannable_inputs": scanned_total,
        "strict": strict,
    }

    # Gate did not actually run over inputs: no genuine obligation to enforce.
    if scanned_total == 0 and uh_verdict in (
        None, "pass-no-workspace-inputs", "error", "pass-no-surfaces",
    ):
        return SignalResult(
            signal="unhunted-followthrough", ok=True,
            reason=(
                f"unhunted-surface-followthrough-gate verdict="
                f"{uh_verdict or 'unknown'}: gate found no scannable workspace "
                "inputs / no surfaces (no follow-through obligation)"
            ),
            artifacts=[], detail=detail,
        )

    # Gate RAN and found abandoned surfaces: a REAL follow-through obligation.
    if uh_verdict == "fail-abandoned-surfaces" and len(abandoned) > 0:
        reason = (
            "unhunted-surface-followthrough-gate FAILS: "
            f"{len(abandoned)} identified unhunted-surface(s) (of "
            f"{scanned_total} scannable inputs) were ABANDONED with no "
            "terminal verdict (confirmed / refuted / filed / killed)"
        )
        if strict:
            return SignalResult(
                signal="unhunted-followthrough", ok=False, reason=reason,
                artifacts=[], detail=detail,
            )
        return SignalResult(
            signal="unhunted-followthrough", ok=True,
            reason="WARN: " + reason, artifacts=[], detail=detail,
        )

    # Gate ran, no abandoned surfaces -> genuine pass.
    return SignalResult(
        signal="unhunted-followthrough", ok=True,
        reason=(
            f"unhunted-surface-followthrough-gate verdict="
            f"{uh_verdict or 'unknown'}: no abandoned unhunted-surfaces "
            f"across {scanned_total} scannable inputs (all identified surfaces "
            "have a terminal verdict)"
        ),
        artifacts=[], detail=detail,
    )


# --------------------------------------------------------------------------
# Orchestration
# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered -->
# --------------------------------------------------------------------------
def evaluate(ws: Path) -> dict:
    rebuttals = _load_rebuttal(ws)

    by_signal = {
        "tier6-mining": check_tier6_mining(ws),
        "hunt-complete": check_hunt_complete(ws),
        "live-engines": check_live_engines(ws),
        "engine-harness": check_engine_harness(ws),
        "hollow-not-genuinely-audited": check_honesty(ws),
        "audit-preflight": check_audit_preflight(ws),
        "exploit-queue": check_exploit_queue(ws),
        "chain-synth": check_chain_synth(ws),
        "exploit-conversion": check_exploit_conversion(ws),
        "prove-top-leads": check_prove_top_leads(ws),
        "exploit-queue-resolution": check_exploit_queue_resolution(ws),
        "conversion-throughput": check_conversion_throughput(ws),  # D1
        "originality": check_originality(ws),
        "advisory-corpus": check_advisory_corpus(ws),
        "learning": check_learning(ws),
        "mined-landed": check_mined_landed(ws),
        "cross-ws-seed": check_cross_ws_seed(ws),
        "brain-prime": check_brain_prime(ws),
        "hacker-questions": check_hacker_questions(ws),
        # r36-rebuttal: lane FIX-F2-DONE-GATE registered in .auditooor/agent_pathspec.json
        "hacker-questions-resolved": check_hacker_questions_resolved(ws),
        "attestation-count-integrity": check_attestation_count_integrity(ws),  # E5
        "provider-liveness": check_provider_liveness(ws),
        "fork-divergence": check_fork_divergence(ws),
        "fork-divergence-content": check_fork_divergence_content(ws),  # r36-rebuttal: lane FIX-FORK-DIVERGENCE-CONTENT
        "novel-vector": check_novel_vector(ws),
        "adversarial-panel": check_adversarial_panel(ws),
        "evm-0day-proof": check_evm_0day_proof(ws),
        "coverage-map": check_coverage_map(ws),
        "rubric-coverage": check_rubric_coverage(ws),
        "depth-certificate": check_depth_certificate(ws),
        "function-coverage": check_function_coverage(ws),
        "cross-function-coverage": check_cross_function_coverage(ws),
        "go-coverage-basis": check_go_coverage_basis(ws),  # r36-rebuttal: lane WIRE-GO-COVERAGE-ENFORCE
        "manual-step-required": check_manual_step_required(ws),  # r36-rebuttal: lane WIRE-GO-COVERAGE-ENFORCE
        "impact-methodology-corpus": check_impact_methodology_corpus(ws),
        "invariant-fuzz": check_invariant_fuzz(ws),  # r36-rebuttal: lane FIX-INVARIANT-FUZZ-GATE
        "dataflow-substrate-health": check_dataflow_substrate_health(ws),  # step-1c substrate under ALL dataflow lenses; fail-closed on a starved arm (any language)
        "state-coupling": check_state_coupling(ws),  # WIRES the SCG (Aptos coupled-state axis) into audit-complete: auto-emit + gate
        "enforcement-point": check_enforcement_point(ws),  # WSITB B1 plane (conservation): auto-emit + gate on un-analyzed enforcement points
        "compiler-feature-screen": check_compiler_feature_screen(ws),  # E2: (pinned version x feature) vs advisory windows; dedicated-env-only
        "cross-module-trust-seam": check_cross_module_trust_seam(ws),  # A2: guarded-producer x unguarded-consumer-bypass seam (report-only advisory)
        "enforcement-layer-census": check_enforcement_layer_census(ws),  # B3: present-but-0-sidecar trust layer (report-only advisory)
        "capability-wiring-integrity": check_capability_wiring_integrity(ws),  # repo-level cap-set wiring audit (report-only advisory)
        "capability-firing-fraction": check_capability_firing_fraction(ws),  # LOGIC_ARSENAL axis 1: invoked=True firing floor JOIN (advisory-first)
        "callgraph-set-difference": check_callgraph_set_difference(ws),  # LOGIC #3 Euler set-diff reasoner JOIN (produced-but-unread -> now read; advisory-first)
        "logic-obligation-resolution": check_logic_obligation_resolution(ws),  # ENFORCE: every reasoner obligation reaches a terminal verdict (advisory-first)
        "reasoner-firing-nonvacuity": check_reasoner_firing_nonvacuity(ws),  # FIRING half: every wired reasoner examined>0 + emitted/exempt (fail-loud on silent vacuity)
        "executed-refutation-honesty": check_executed_refutation_honesty(ws),  # LOGIC #2: grep-NEGATIVE on a value-mover fails (advisory-first)
        "fuzz-saturation": check_fuzz_saturation(ws),  # coverage-saturation adequacy (advisory-first)
        "invariant-obligation": check_invariant_obligation_coverage(ws),  # per-item obligation recall (advisory-first)
        "core-coverage": check_core_coverage(ws),  # r36-rebuttal: lane FIX-CORE-COVERAGE-GATE
        "exploit-class": check_exploit_class(ws),  # r36-rebuttal: lane FIX-EXPLOIT-CLASS-GATE
        "completeness-matrix": check_completeness_matrix(ws),  # enumeration-floor JOIN gate
        "unhunted-followthrough": check_unhunted_followthrough(ws),
        "inscope-disposition": check_inscope_disposition(ws),
        "business-flow-coverage": check_business_flow_coverage(ws),
        "hunt-trust": check_hunt_trust(ws),
    }

    # G12 signal-registry bijection (the "no signal silently skipped" invariant):
    # the terminal verdict is built by iterating _SIGNAL_ORDER and looking up
    # by_signal[signal]. A signal COMPUTED here but ABSENT from _SIGNAL_ORDER is
    # silently dropped from failures[] - it can never fail the gate, an invisible
    # false-green vector. Fail LOUD on drift rather than silently skip. No-op while
    # the registry is in sync (the intended steady state); catches a future
    # mis-registration at author time instead of letting it green a real fail.
    _ordered_signals = {s for s, _ in _SIGNAL_ORDER}
    _dropped_signals = set(by_signal) - _ordered_signals
    if _dropped_signals:
        raise AssertionError(
            "signal-registry drift: signals computed but MISSING from _SIGNAL_ORDER "
            "(silently dropped from the audit-complete verdict) - add them to "
            f"_SIGNAL_ORDER: {sorted(_dropped_signals)}")

    signals_out = []
    failures = []
    rebutted = []
    for signal, fail_verdict in _SIGNAL_ORDER:
        r = by_signal[signal]
        # Distinct fail verdict (e.g. language-mismatch) overrides the default.
        effective_fail = r.verdict_override or fail_verdict
        eff_ok = r.ok
        rb = None
        if not r.ok:
            rb = _rebuttal_for(rebuttals, signal)
            if rb:
                eff_ok = True
                rebutted.append({"signal": signal, "reason": rb})
        detail = r.detail if isinstance(r.detail, dict) else {}
        advisory_proof_conversion = bool(
            eff_ok
            and detail.get("advisory_autonomous_proof_conversion") is True
            and detail.get("enforce_autonomous_proof_conversion") is not True
        )
        advisory_without_artifact = advisory_proof_conversion and not r.artifacts
        artifact_requirement = "artifact-backed"
        if advisory_proof_conversion and r.artifacts:
            artifact_requirement = "advisory-artifact-present"
        elif not r.artifacts:
            if advisory_without_artifact:
                artifact_requirement = "advisory-without-artifact"
            elif not r.ok and rb:
                artifact_requirement = "explicit-l37-rebuttal"
            elif eff_ok:
                artifact_requirement = "not-required-for-this-workspace"
            else:
                artifact_requirement = "missing-required-artifact-or-signal"
        if not r.ok and rb:
            signal_verdict = "ok-rebuttal"
        elif advisory_without_artifact:
            signal_verdict = "advisory-without-artifact"
        elif advisory_proof_conversion and r.artifacts:
            signal_verdict = "advisory-artifact-present"
        elif r.ok:
            signal_verdict = "pass"
        else:
            signal_verdict = effective_fail
        signals_out.append({
            "signal": signal,
            "ok": eff_ok,
            "raw_ok": r.ok,
            "verdict": signal_verdict,
            "reason": r.reason,
            "artifacts": r.artifacts,
            "detail": r.detail,
            "policy": "advisory" if advisory_proof_conversion else "hard-required",
            "hard_required": not advisory_proof_conversion,
            "artifact_present": bool(r.artifacts),
            "advisory_without_artifact": advisory_without_artifact,
            "artifact_requirement": artifact_requirement,
        })
        if not eff_ok:
            failures.append(effective_fail)

    if not failures:
        verdict = "pass-audit-complete"
        reason = (
            "all hard-required audit-completeness signals are satisfied under "
            "L37 policy; advisory proof-conversion stages are reported "
            "separately from artifact-backed stages"
        )
    else:
        verdict = failures[0]
        first_failing = next(s for s in signals_out if not s["ok"])
        reason = first_failing["reason"]

    # Surface BOTH cross-cutting coverage axes' warns at the top level so the
    # operator sees the loud UNCOVERED counts even on a PASS (never papered
    # over). coverage_warn = SURFACE axis (o); rubric_coverage_warn = RUBRIC
    # axis (p) carrying the impact classes NObody attempted.
    coverage_warn = by_signal["coverage-map"].detail.get("coverage_warn")
    rubric_coverage_warn = by_signal["rubric-coverage"].detail.get("rubric_coverage_warn")
    rubric_uncovered_rows = by_signal["rubric-coverage"].detail.get("uncovered_rows")
    # HUNT-TRUST (q): the meta-caveat over the coverage axes. When the hunt
    # behind the coverage numbers failed-run / is degraded, surface the loud
    # caveat at the top level so the operator sees "coverage is NOT trustworthy,
    # re-hunt" even on an otherwise-PASS audit (never papered over).
    hunt_trust_warn = by_signal["hunt-trust"].detail.get("hunt_trust_warn")

    return {
        "schema": SCHEMA,
        "gate": GATE,
        "workspace": str(ws),
        "verdict": verdict,
        "reason": reason,
        "failures": failures,
        "rebutted": rebutted,
        "coverage_warn": coverage_warn,  # None unless high-uncovered (SURFACE)
        "rubric_coverage_warn": rubric_coverage_warn,  # None unless low (RUBRIC)
        "rubric_uncovered_rows": rubric_uncovered_rows,  # impact classes NObody tried
        "hunt_trust_warn": hunt_trust_warn,  # None unless failed-run / degraded hunt
        "signals": signals_out,
    }


def _print_human(result: dict) -> None:
    print(f"[{GATE}] verdict={result['verdict']}")
    print(f"[{GATE}] workspace={result['workspace']}")
    for s in result["signals"]:
        mark = "ADVISORY" if s.get("policy") == "advisory" else ("PASS" if s["ok"] else "FAIL")
        rb = " (rebuttal)" if s["verdict"] == "ok-rebuttal" else ""
        print(f"  [{mark}] {s['signal']}{rb}: {s['reason']}")
    if result.get("coverage_warn"):
        print(f"[{GATE}] *** SURFACE COVERAGE WARN: {result['coverage_warn']} ***")
    if result.get("rubric_coverage_warn"):
        print(f"[{GATE}] *** RUBRIC COVERAGE WARN: {result['rubric_coverage_warn']} ***")
    if result.get("rubric_uncovered_rows"):
        print(f"[{GATE}] *** UNATTEMPTED IMPACT CLASSES (rubric rows with no candidate): ***")
        for lbl in result["rubric_uncovered_rows"]:
            print(f"      - {lbl}")
    if result.get("hunt_trust_warn"):
        print(f"[{GATE}] *** HUNT-TRUST WARN: {result['hunt_trust_warn']} ***")
    if result["failures"]:
        print(f"[{GATE}] reason: {result['reason']}")


def _load_completion_marker_lib():
    """Load audit-completion-marker.py as a module (hyphenated filename). Returns
    the module or None on any error (caller then skips the best-effort re-sign).
    Mirrors audit-done-guard.py._load_completion_marker_lib so both sides share
    the same signing primitives."""
    import importlib.util as _ilu
    p = Path(__file__).resolve().with_name("audit-completion-marker.py")
    spec = _ilu.spec_from_file_location("_acm_completeness", str(p))
    if spec is None or spec.loader is None:
        return None
    mod = _ilu.module_from_spec(spec)
    sys.modules["_acm_completeness"] = mod
    spec.loader.exec_module(mod)
    return mod


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="audit-completeness-check.py",
        description="L37 audit-completeness gate: an AUDIT is the WHOLE documented pipeline.",
    )
    p.add_argument("workspace", help="Path to the audit workspace.")
    p.add_argument("--json", action="store_true", help="Emit JSON verdict payload.")
    p.add_argument(
        "--strict", action="store_true",
        help="Strict mode: require PR4's engine-harness PROOF gate + EVM proof "
             "manifest before the engine-harness signal can credit any harness. "
             "Also hard-fail untrustworthy hunt-run health. Other completeness "
             "signals already fail closed.",
    )
    args = p.parse_args(argv)

    if args.strict:
        # Thread strict into ALL L37 signals via the global umbrella env var so
        # _l37_gate_strict() returns True for every WARN-pass signal (tier6-mining,
        # chain-synth, cross-ws-seed, learning, brain-prime, hacker-questions,
        # fork-divergence, novel-vector, adversarial-panel, honesty, depth-cert).
        # The two narrower vars remain for per-signal override use; they are now
        # subsumed by the global.
        # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        os.environ["AUDITOOOR_L37_ENGINE_PROOF_STRICT"] = "1"
        os.environ["AUDITOOOR_L37_HUNT_TRUST_STRICT"] = "1"

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not _exists(ws) or not ws.is_dir():
        payload = {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error", "reason": "workspace path does not exist or is not a directory",
            "failures": ["error"], "rebutted": [], "signals": [],
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"[{GATE}] verdict=error reason={payload['reason']}")
        return 2

    try:
        # Own our stdout: `--json` is a machine-readable contract, so any diagnostic
        # a sub-tool (SCG emit, ELC class table, etc.) prints while we compute the
        # signals must NOT pollute the single JSON object we emit. Route every
        # sub-tool stdout write to stderr (nothing is swallowed - real errors still
        # surface on stderr); only the final json.dumps below reaches real stdout.
        with contextlib.redirect_stdout(sys.stderr):
            result = evaluate(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        payload = {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error", "reason": f"internal error: {exc}",
            "failures": ["error"], "rebutted": [], "signals": [],
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"[{GATE}] verdict=error reason={payload['reason']}")
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)

    # r36-rebuttal: lane FIX-AUDIT-COMPLETE-MARKER registered in .auditooor/agent_pathspec.json
    # Persist the verdict so downstream consumers (audit-done-guard, dashboards)
    # can read the gate result without re-running it. The marker reflects the
    # REAL verdict (pass or fail) + whether STRICT was in force; a stale or
    # non-pass marker keeps audit-done-guard at NOT-DONE, so this cannot fake it.
    try:
        marker = ws / ".auditooor" / "audit_complete_last_result.json"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps({
            "schema": SCHEMA, "gate": GATE,
            "verdict": result.get("verdict"),
            "strict": bool(args.strict) or os.environ.get("AUDITOOOR_L37_STRICT") == "1",
            "failures": result.get("failures", []),
            "rebutted": result.get("rebutted", []),
            "workspace": str(ws),
            # T1 (stale-done-on-capability-set-hash-change): stamp the capability
            # set this pass was produced under, so audit-done-guard can re-stale
            # the pass once new capabilities are wired (they may surface findings
            # this pass never had a chance to). None if the inventory is
            # unreadable -> the guard grandfathers (cannot verify => no spurious
            # stale). See capability-wiring-integrity-check.current_capability_set_hash.
            "capability_set_hash": _live_capability_set_hash(),
        }, indent=2), encoding="utf-8")
    except OSError:
        pass

    # FIX-AUDIT-COMPLETE-MARKER: re-sign the completion marker
    # (.audit_logs/audit_completion.json) IN THE SAME STEP as the authoritative
    # result write above. The completion marker carries a tamper_signature block
    # whose recorded `verdict` + `enforcer_hash` are captured at marker-WRITE
    # time. Writing the fresh audit_complete_last_result.json here WITHOUT
    # re-signing left the signed marker stale (its tamper_signature.verdict and
    # enforcer_hash frozen at an earlier run), so audit-done-guard.py's ADVISORY
    # marker-tamper check emitted a false `FORGED_VERDICT (signed marker failed
    # verification)` even though the operator never hand-edited anything (nuva
    # 2026-07-12: result at 19:58, signed marker at 05:23). write_marker() reads
    # the authoritative verdict we JUST wrote and re-computes enforcer_hash over
    # the current toolchain, keeping the signed marker consistent with the fresh
    # result. This is a re-sign of a legitimately-produced marker, NOT a
    # tamper-detection weakening: a bare unsigned marker still verifies as
    # FORGED_VERDICT.
    try:
        _acm = _load_completion_marker_lib()
        if _acm is not None:
            _acm.write_marker(ws, repo_root=Path(__file__).resolve().parents[1])
    except Exception:
        # Re-signing is best-effort metadata upkeep; never let it change the gate
        # verdict or break the run.
        pass

    if result["verdict"] == "pass-audit-complete":
        return 0
    if result["verdict"] == "error":
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
