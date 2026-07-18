#!/usr/bin/env python3
"""harness-failure-memory.py - durable memory for recurring harness failures.

MCL-5 turns repeated harness failures into structured memory:

  - emit canonical rows to reports/harness_failures.jsonl
  - write generated notes under obsidian-vault/harness-failures/
  - give L4 a source for high-priority harness root-cause candidates

The vault notes are projections. The report JSONL is the source of truth.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = REPO_ROOT / "reports" / "harness_failures.jsonl"
DEFAULT_VAULT = REPO_ROOT / "obsidian-vault"
DEFAULT_NOTES_DIR = DEFAULT_VAULT / "harness-failures"
SCHEMA = "auditooor.harness_failure_root.v1"
EVENT_SCHEMA = "auditooor.harness_failure_event.v1"
EVENT_SUMMARY_SCHEMA = "auditooor.harness_failure_event_summary.v1"
ROOT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,80}$")
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,160}$")
KG_REF_RE = re.compile(
    r"^(?:G[0-9A-Za-z][A-Za-z0-9._:-]*|KG-[0-9]{8}-[0-9]{3}|KLBQ-[0-9]{3})$"
)
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
DATETIME_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
SEVERITIES = {"low", "medium", "high"}
STATUSES = {"active", "mitigated", "watch"}
EVENT_STATES = {"pending", "finalized", "stale"}
FINALIZATION_STATUSES = {"landed", "blocked", "failed", "deferred", "false_positive"}
NEXT_ACTION_KINDS = {"record_finalization", "refresh_event_evidence", "mitigate_root_cause", "none"}
REQUIRED_ROW_FIELDS = (
    "schema",
    "root_cause_id",
    "title",
    "status",
    "severity",
    "symptom",
    "first_seen",
    "last_seen",
    "occurrence_count",
    "tools_affected",
    "known_fix",
    "guard",
    "counter_example_links",
    "source_paths",
    "last_validated_at",
)
STRING_ROW_FIELDS = {
    "schema",
    "root_cause_id",
    "title",
    "status",
    "severity",
    "symptom",
    "first_seen",
    "last_seen",
    "known_fix",
    "guard",
    "last_validated_at",
}
LIST_ROW_FIELDS = {"tools_affected", "counter_example_links", "source_paths"}
REQUIRED_EVENT_FIELDS = (
    "schema",
    "event_id",
    "root_cause_id",
    "event_state",
    "occurred_at",
    "command",
    "exit_code",
    "workspace",
    "commit",
    "raw_log_path",
    "harness_path",
    "classifier_confidence",
    "knowledge_gap_refs",
    "recurrence_window",
    "finalization_task_id",
    "finalization_status",
    "stale_reason",
    "next_action",
)
STRING_EVENT_FIELDS = {
    "schema",
    "event_id",
    "root_cause_id",
    "event_state",
    "occurred_at",
    "command",
    "workspace",
    "commit",
    "raw_log_path",
    "harness_path",
    "finalization_task_id",
    "finalization_status",
    "stale_reason",
}
ROOT_FILES = {"AGENTS.md", "Makefile", "README.md"}
SAFE_PREFIXES = (
    "docs/",
    "tools/",
    "reports/",
    "reference/",
    "detectors/",
    "patterns/",
    "obsidian-vault/tasks/finalized/",
)
EVENT_REF_ROOT_FILES = ROOT_FILES | {"pyproject.toml", "foundry.toml", "package.json"}
EVENT_SAFE_PREFIXES = SAFE_PREFIXES + (
    "agent_outputs/",
    "audit/",
    "poc_notes/",
    "test/",
    "src/",
    "lib/",
)
FORBIDDEN_PARTS = {".git", ".archive", ".privacy", "_archive", "_privacy_quarantine"}


SEED_ROOTS: list[dict[str, Any]] = [
    {
        "root_cause_id": "m14-prompt-shape-regression",
        "title": "M14 prompt-shape regression produced smoke-passing fake detectors",
        "status": "mitigated",
        "severity": "high",
        "symptom": (
            "LLM dispatch optimized for fixture shape instead of bug-class semantics; "
            "91/91 newly emitted YAMLs collapsed to fake predicates while smoke passed."
        ),
        "first_seen": "2026-05-04",
        "last_seen": "2026-05-04",
        "occurrence_count": 91,
        "tools_affected": [
            "tools/agent-dispatch-prompt-lint.py",
            "tools/wirer-output-diversity-check.py",
            "tools/predicate-semantic-lint.py",
        ],
        "known_fix": (
            "Require acceptance criteria, M14 discipline, semantic bug-class anchoring, "
            "prompt lint, predicate semantic lint, and cohort diversity checks before promotion."
        ),
        "guard": "make memory-next-loop-test and guarded wire/promote wrappers",
        "counter_example_links": [
            "docs/archive/2026-05/CONTINUATION_PLAN.md",
            "docs/HARNESS_HARDENING_2026-05-04.md",
            "tools/agent-dispatch-prompt-lint.py",
            "tools/wirer-output-diversity-check.py",
        ],
        "source_paths": [
            "docs/archive/2026-05/CONTINUATION_PLAN.md",
            "docs/HARNESS_HARDENING_2026-05-04.md",
            "tools/agent-dispatch-prompt-lint.py",
            "tools/wirer-output-diversity-check.py",
        ],
        "match_patterns": [r"fp_repair_v2", r"91/91", r"M14-trap"],
    },
    {
        "root_cause_id": "fixture-smoke-mode-flag-missing",
        "title": "Fixture smoke-mode flag must be exported by smoke targets",
        "status": "mitigated",
        "severity": "medium",
        "symptom": (
            "Smoke-only inventory and diagnostic targets can accidentally run as if they were "
            "full validation unless AUDITOOOR_FIXTURE_SMOKE_MODE is set."
        ),
        "first_seen": "2026-05-04",
        "last_seen": "2026-05-04",
        "occurrence_count": 2,
        "tools_affected": [
            "tools/inventory-smoke-test.py",
            "tools/silent-detector-diagnostic.py",
            "Makefile",
        ],
        "known_fix": "Makefile smoke targets export AUDITOOOR_FIXTURE_SMOKE_MODE=1 explicitly.",
        "guard": "Makefile smoke-mode targets and agent preflight for fixture-smoke work",
        "counter_example_links": [
            "docs/archive/2026-05/feedback_recurring_agent_mistakes_addendum.md",
            "tools/inventory-smoke-test.py",
            "tools/silent-detector-diagnostic.py",
        ],
        "source_paths": [
            "Makefile",
            "docs/archive/2026-05/feedback_recurring_agent_mistakes_addendum.md",
            "tools/inventory-smoke-test.py",
            "tools/silent-detector-diagnostic.py",
        ],
        "match_patterns": [r"AUDITOOOR_FIXTURE_SMOKE_MODE", r"smoke-mode"],
    },
    {
        "root_cause_id": "empty-setup-sol-harness",
        "title": "Generated Foundry harnesses must not leave Setup.sol empty",
        "status": "mitigated",
        "severity": "high",
        "symptom": (
            "Harness scaffold generation wrote test/Setup.sol without deploy/setup content, "
            "leaving forge builds green enough to proceed but semantically useless."
        ),
        "first_seen": "2026-05-04",
        "last_seen": "2026-05-04",
        "occurrence_count": 2,
        "tools_affected": ["tools/harness-scaffold-emitter.py", "forge"],
        "known_fix": "Always emit non-empty Setup.sol with a real setup skeleton or explicit blocked state.",
        "guard": "tools/tests/test_harness_scaffold_emitter.py",
        "counter_example_links": [
            "docs/archive/2026-04/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md",
            "tools/tests/test_harness_scaffold_emitter.py",
        ],
        "source_paths": [
            "docs/archive/2026-04/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md",
            "tools/harness-scaffold-emitter.py",
            "tools/tests/test_harness_scaffold_emitter.py",
            "docs/archive/2026-05/AUDITOOOR_CONTROL_PLANE_PLAN.md",
        ],
        "match_patterns": [r"Setup\.sol", r"must not be empty"],
    },
    {
        "root_cause_id": "forge-std-resolution",
        "title": "Recon/Chimera harnesses need deterministic forge-std resolution",
        "status": "mitigated",
        "severity": "medium",
        "symptom": (
            "Harness scaffolds failed or became non-portable when lib/forge-std existed "
            "but remappings did not point the generated project at it."
        ),
        "first_seen": "2026-04-29",
        "last_seen": "2026-05-04",
        "occurrence_count": 2,
        "tools_affected": ["tools/chimera-scaffold.py", "forge", "Recon/Chimera"],
        "known_fix": "When a workspace has lib/forge-std, write remappings.txt that resolves forge-std.",
        "guard": "tools/tests/test_chimera_scaffold.py and forge harness self-tests",
        "counter_example_links": [
            "docs/archive/2026-04/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md",
            "docs/archive/2026-04/RECON_CHIMERA_INTEGRATION_PLAN_2026-04-29.md",
        ],
        "source_paths": [
            "docs/archive/2026-04/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md",
            "docs/archive/2026-04/RECON_CHIMERA_INTEGRATION_PLAN_2026-04-29.md",
            "tools/chimera-scaffold.py",
            "tools/tests/test_chimera_scaffold.py",
        ],
        "match_patterns": [r"forge-std", r"remappings\.txt"],
    },
    {
        "root_cause_id": "wirer-diversity-collapse",
        "title": "Detector wirer cohorts can collapse to one predicate trick",
        "status": "mitigated",
        "severity": "high",
        "symptom": (
            "A batch of generated detectors shared one generic predicate pattern, creating "
            "many apparently different but semantically identical fakes."
        ),
        "first_seen": "2026-05-04",
        "last_seen": "2026-05-04",
        "occurrence_count": 91,
        "tools_affected": [
            "tools/wirer-output-diversity-check.py",
            "tools/inventory-bulk-promote.py",
            "reference/patterns.dsl/",
        ],
        "known_fix": "Fail closed when one output cohort exceeds diversity max-share or repeats a canonical trick signature.",
        "guard": "tools/wirer-output-diversity-check.py in guarded promotion wrappers",
        "counter_example_links": ["docs/HARNESS_HARDENING_2026-05-04.md"],
        "source_paths": [
            "docs/HARNESS_HARDENING_2026-05-04.md",
            "tools/wirer-output-diversity-check.py",
            "docs/archive/2026-05/CONTROL_PLANE_BUILD_STATUS.md",
        ],
        "match_patterns": [r"diversity", r"cohort", r"91/91"],
    },
    {
        "root_cause_id": "recon-log-tooling-failure-origin",
        "title": "Recon/Chimera logs must distinguish tool failure from protocol evidence",
        "status": "mitigated",
        "severity": "medium",
        "symptom": (
            "Recon log bridges can misclassify runner/tooling failures as protocol-level "
            "counterexamples unless the failure origin is preserved."
        ),
        "first_seen": "2026-05-04",
        "last_seen": "2026-05-04",
        "occurrence_count": 2,
        "tools_affected": ["tools/recon-log-bridge.py", "Recon/Chimera"],
        "known_fix": "Persist failure_origin/tooling_failure markers and keep them out of proof-grade evidence.",
        "guard": "tools/tests/test_recon_log_bridge_tooling_failure_origin.py",
        "counter_example_links": [
            "docs/archive/2026-04/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md",
            "tools/tests/test_recon_log_bridge_tooling_failure_origin.py",
        ],
        "source_paths": [
            "docs/archive/2026-04/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md",
            "tools/recon-log-bridge.py",
            "tools/tests/test_recon_log_bridge.py",
            "tools/tests/test_recon_log_bridge_tooling_failure_origin.py",
        ],
        "match_patterns": [r"tooling_failure", r"failure_origin", r"Recon"],
    },
    {
        "root_cause_id": "fork-replay-proof-boundary",
        "title": "Fork-replay evidence must stay execution-bound and pinned",
        "status": "mitigated",
        "severity": "medium",
        "symptom": (
            "High/Critical claims can overread fork-replay scaffolds unless manifests are "
            "pinned, executed, and impact assertions are explicitly checked."
        ),
        "first_seen": "2026-05-04",
        "last_seen": "2026-05-04",
        "occurrence_count": 2,
        "tools_affected": ["tools/fork-replay.py", "tools/pre-submit-check.sh"],
        "known_fix": "Emit Check-22 semantic bundles only for live executed replay rows with pinned fork_block and proof-grade PASS assertions; hermetic/advisory rows remain Check-36 history only.",
        "guard": "python3 -m unittest tools.tests.test_pre_submit_fork_replay -v",
        "counter_example_links": [
            "docs/archive/2026-05/FORK_REPLAY_HARNESS.md",
            "tools/tests/test_pre_submit_fork_replay.py",
        ],
        "source_paths": [
            "docs/archive/2026-05/FORK_REPLAY_HARNESS.md",
            "tools/fork-replay.py",
            "tools/pre-submit-check.sh",
            "tools/tests/test_pre_submit_fork_replay.py",
        ],
        "match_patterns": [r"fork-replay", r"replay-tx", r"source-only"],
    },
    {
        "root_cause_id": "nested-foundry-env-check-skip",
        "title": "Env-check must detect nested Foundry project roots",
        "status": "mitigated",
        "severity": "medium",
        "symptom": (
            "Audit wrapper workspaces with real projects under external/<repo> could report "
            "env-check success while skipping forge dependency checks."
        ),
        "first_seen": "2026-05-06",
        "last_seen": "2026-05-06",
        "occurrence_count": 1,
        "tools_affected": ["tools/engage.py", "tools/forge-deps-checker.py"],
        "known_fix": (
            "Search shallow nested workspace roots while skipping dependency and build-output "
            "directories before deciding env-check has no Foundry project."
        ),
        "guard": "python3 -m unittest tools.tests.test_forge_deps_checker",
        "counter_example_links": ["tools/tests/test_forge_deps_checker.py"],
        "source_paths": [
            "tools/engage.py",
            "tools/forge-deps-checker.py",
            "tools/tests/test_forge_deps_checker.py",
        ],
        "match_patterns": [r"nested Foundry", r"foundry\.toml", r"external/"],
    },
    {
        "root_cause_id": "forge-deps-remapping-and-pragma-fp",
        "title": "Forge dependency checker must be remapping and pragma aware",
        "status": "mitigated",
        "severity": "medium",
        "symptom": (
            "Healthy remappings.txt/node_modules layouts and caret Solidity pragmas can be "
            "flagged as dependency and solc failures."
        ),
        "first_seen": "2026-05-06",
        "last_seen": "2026-05-06",
        "occurrence_count": 1,
        "tools_affected": ["tools/forge-deps-checker.py", "forge", "solc-select"],
        "known_fix": (
            "Resolve imports with Foundry remappings from remappings.txt/foundry.toml, "
            "node_modules, local aliases, and compare installed solc versions against "
            "pragma ranges instead of raw strings."
        ),
        "guard": (
            "python3 tools/forge-deps-checker.py <workspace> and "
            "python3 -m unittest tools.tests.test_forge_deps_checker"
        ),
        "counter_example_links": ["tools/tests/test_forge_deps_checker.py"],
        "source_paths": [
            "tools/forge-deps-checker.py",
            "tools/tests/test_forge_deps_checker.py",
        ],
        "match_patterns": [r"remappings\.txt", r"node_modules", r"\^0\.8\."],
    },
]


TAXONOMY_DOC = "docs/HARNESS_FAILURE_TAXONOMY.md"
TAXONOMY_FORENSIC = "agent_outputs/harness_enforcement_2026-06-27/HARNESS_FAILURE_TAXONOMY.md"


# The 20 confirmed semantic harness-failure modes (1-20, plus the 4b refinement),
# mirrored from docs/HARNESS_FAILURE_TAXONOMY.md (the canonical source). Each seed is a
# valid validate_row() row: root_cause_id == the canonical mode-name; known_fix == the
# proven fix; symptom embeds the real_example_file_line (matching \.sol:\d+|\.json) so a
# consumer can recover the example without an extra schema field. source_paths cite only
# in-repo tool/doc paths that EXIST. dispatch-agent-with-prebriefing.py imports
# semantic_mode_seeds() / SEMANTIC_MODE_NAMES to render the "KNOWN HARNESS-FAILURE MODES -
# do NOT reproduce" block.
SEMANTIC_MODE_SEEDS: list[dict[str, Any]] = [
    {
        "root_cause_id": "unlimited-params",
        "title": "Mode 1 unlimited-params: setUp caps to type(uintN).max so the guard never binds",
        "status": "active",
        "severity": "high",
        "symptom": (
            "setUp sets a cap/bound/limit variable to type(uintN).max (or 2**256-1) so the guard "
            "the invariant tests against can never bind; a guard-removal mutant cannot be killed. "
            "Real example EconInvariant_MetaMorpho.t.sol:42."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": ["tools/lib/harness_vacuity.py"],
        "known_fix": (
            "Keep caps finite and binding (morpho MetaMorpho CAP_A=1e20, CAP_B=5e19); add a static "
            "detector mirroring the _CONST_FOLD arm in harness_vacuity.py that flags type(uintN).max "
            "/ 2**256-1 assigned to a cap/bound/limit name."
        ),
        "guard": "tools/lib/harness_vacuity.py setUp-max-bound detector",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [TAXONOMY_DOC, "tools/lib/harness_vacuity.py"],
    },
    {
        "root_cause_id": "self-bounded-handler",
        "title": "Mode 2 self-bounded-handler: handler pre-bounds to valid so the violation is never attempted",
        "status": "active",
        "severity": "high",
        "symptom": (
            "The fuzz handler pre-bounds inputs to always-valid (bound(x, 1, cap-headroom)) so the "
            "violating action is NEVER attempted; a guard-removal mutant survives because nothing "
            "tries to cross the guard. Real example SSVClusterSolvencyMedusa.sol:330."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/invariant-fuzz-completeness.py",
            "tools/lib/harness_vacuity.py",
        ],
        "known_fix": (
            "Bound by available balance/idle, not cap-headroom (morpho VaultV2InvariantHandler bounds "
            "by token.balanceOf); require a guard-removal mutation-verify against the chimera/echidna "
            "CUT that FAILS the campaign; add a static handler-bound check flagging "
            "bound(x,1,cap-headroom)-shaped pre-bounding to the valid range."
        ),
        "guard": "tools/invariant-fuzz-completeness.py handler-attempts-violation check",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/invariant-fuzz-completeness.py",
            "tools/lib/harness_vacuity.py",
        ],
    },
    {
        "root_cause_id": "silent-revert-actions",
        "title": "Mode 3 silent-revert-actions: every action reverts in try/catch so state never changes",
        "status": "active",
        "severity": "high",
        "symptom": (
            "Every handler action reverts inside try/catch so contract state never changes; invariants "
            "hold trivially. Real example CashSolvencyHarness.sol:322."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": ["tools/invariant-fuzz-completeness.py"],
        "known_fix": (
            "Require >=1 witness/ghost counter asserted >0 (a reachability witness that at least one "
            "value-moving action landed, etherfi CashSolvency wBorrow/wRepay/wSupply); reject a "
            "harness where every action body is try/catch-wrapped with no post-success state assertion."
        ),
        "guard": "tools/invariant-fuzz-completeness.py reachability-witness check",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [TAXONOMY_DOC, "tools/invariant-fuzz-completeness.py"],
    },
    {
        "root_cause_id": "harness-internal-accounting",
        "title": "Mode 4 harness-internal-accounting: invariants assert ghost counters not real storage",
        "status": "active",
        "severity": "high",
        "symptom": (
            "Invariants assert harness-tracked counters (totalIn/totalOut/custodyHeld/protectedValue) "
            "maintained by construction in drive*/mutate*, not REAL contract storage. No source mutant "
            "can flip them. Real example SiloFacet_Invariant.t.sol:159."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/lib/harness_vacuity.py",
            "tools/mutation-verify-coverage.py",
        ],
        "known_fix": (
            "Assert against target.<view>() real reads (ssv property_operator_index_monotone reads "
            "s.operators[].ethSnapshot.index); add a model-counter-invariant heuristic to "
            "harness_vacuity.py (all invariant operands are harness state vars mutated by an in-harness "
            "mutate*/drive*, never a target.<view>() read); treat real_output_bound=None as "
            "needs-binding for poc-tests/*-engine-harness paths."
        ),
        "guard": "tools/lib/harness_vacuity.py model-counter-invariant detector",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/lib/harness_vacuity.py",
            "tools/mutation-verify-coverage.py",
        ],
    },
    {
        "root_cause_id": "dead-cut-guard",
        "title": "Mode 4b dead-CUT-guard: bindTarget defined but setUp never calls it so target stays zero",
        "status": "active",
        "severity": "high",
        "symptom": (
            "The harness DEFINES bindTarget(address) and an interface to the real CUT but setUp never "
            "calls it, so target stays address(0); every real-CUT call is silently skipped by "
            "if(address(target)!=address(0)) and only harness ghost state is asserted. Real example "
            "VaultV2_Invariant.t.sol:104."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": ["tools/lib/harness_vacuity.py"],
        "known_fix": (
            "Flag any harness whose only real-CUT external call is behind "
            "if(address(x)!=address(0)) while setUp never assigns x; enforce setUp_binds_target in "
            "harness_vacuity.py."
        ),
        "guard": "tools/lib/harness_vacuity.py dead-CUT-guard detector (enforce setUp_binds_target)",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [TAXONOMY_DOC, "tools/lib/harness_vacuity.py"],
    },
    {
        "root_cause_id": "tautological-assert",
        "title": "Mode 5 tautological-assert: assert(true) / reflexive-AND / skeleton TODO bodies",
        "status": "active",
        "severity": "high",
        "symptom": (
            "assert(true), a>=b||b>=a, x==x, len>=0, or assertTrue(false, materialized-skeleton/TODO); "
            "also the controlCase && realInvariant wrap where controlCase is "
            "(after>=before||before>=after). Real example CashModuleCore_FuzzProps.sol:76."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": ["tools/lib/harness_vacuity.py"],
        "known_fix": (
            "Add a tautological-subterm detector for (<reflexive-or-always-true>) && <expr> and "
            "(a>=b||b>=a) && ... and a never-mutated bool gate; recognise assertTrue(false, "
            "materialized-skeleton/TODO) as a distinct sentinel-skeleton class so the denominator "
            "excludes it AND it can be re-queued."
        ),
        "guard": "tools/lib/harness_vacuity.py tautological-subterm-AND + skeleton class detector",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [TAXONOMY_DOC, "tools/lib/harness_vacuity.py"],
    },
    {
        "root_cause_id": "mock-callpath-vacuity",
        "title": "Mode 6 mock-callpath-vacuity: mock delivers value differently so value-moving fn never runs",
        "status": "active",
        "severity": "high",
        "symptom": (
            "A mock delivers value differently than prod (.call needs receive() vs force-send via "
            "SafeSend/selfdestruct which needs none) so the value-moving fn silently never executes. "
            "Real example CashSolvencyHarness.sol:212."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/lib/harness_vacuity.py",
            "tools/mutation-verify-coverage.py",
        ],
        "known_fix": (
            "Authoring brief mandates value-delivery parity: if prod force-sends "
            "(SafeSend/selfdestruct), the mock CUT subclass MUST add receive()/fallback() so the "
            "value-moving fn executes; verify the value-moving handler is reached (witness counter >0). "
            "Static detector + witness-counter check are the automated backstops; the dynamic mutant "
            "kill is the final witness once the CUT is bound."
        ),
        "guard": "tools/mutation-verify-coverage.py witness-counter execution check",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/lib/harness_vacuity.py",
            "tools/mutation-verify-coverage.py",
        ],
    },
    {
        "root_cause_id": "compile-cascade",
        "title": "Mode 7 compile-cascade: remapping/floor-pragma/cross-language wrapper never builds",
        "status": "active",
        "severity": "high",
        "symptom": (
            "Remappings/base-ctor/floor-pragma/cross-language wrapper means the harness never builds, "
            "so 0 genuine coverage despite a real harness (incl. a Solidity .t.sol stub scaffolded "
            "over a Rust CUT). Real example Invariant_lib.rs.t.sol:1."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/gen-invariants.sh",
            "tools/mutation-verify-coverage.py",
        ],
        "known_fix": (
            "Add a language-detection precheck to gen-invariants.sh that routes .rs/.cairo/.move CUTs "
            "to cargo/proptest and refuses to emit a .t.sol StdInvariant wrapper for a non-Solidity "
            "path; extend the step-4b build-readiness gate to cover vendored OZ layouts so the in-tree "
            "runner is made build-ready instead of bypassed."
        ),
        "guard": "tools/gen-invariants.sh language-router precheck",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/gen-invariants.sh",
            "tools/mutation-verify-coverage.py",
        ],
    },
    {
        "root_cause_id": "prefix-runner-mismatch",
        "title": "Mode 8 prefix-runner-mismatch: check_ vs test_ vs invariant_ so engine never runs it",
        "status": "active",
        "severity": "medium",
        "symptom": (
            "check_ vs test_ vs invariant_ naming so the engine never runs the property. Real example "
            "Halmos_SSVClusters_deposit.t.sol:32."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/invariant-fuzz-completeness.py",
            "tools/mutation-verify-coverage.py",
        ],
        "known_fix": "Widen _PROP_RE to also recognise function check_ Halmos-convention properties.",
        "guard": "tools/invariant-fuzz-completeness.py _PROP_RE widened to check_",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/invariant-fuzz-completeness.py",
            "tools/mutation-verify-coverage.py",
        ],
    },
    {
        "root_cause_id": "equivalent-mutant",
        "title": "Mode 9 equivalent-mutant: panic-only EVM-enforced mutant credited as a genuine kill",
        "status": "active",
        "severity": "high",
        "symptom": (
            "The applied mutant is EVM-enforced (panic 0x11 underflow / 0x01 overflow / "
            "balance-on-transfer) and CANNOT be killed by a property - any assertion, even "
            "assert(true) after the revert, would kill it. Real example mvc-ssvclusters-deposit.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/mutation-verify-coverage.py",
            "tools/mutation-engine.py",
            "tools/engine-harness-proof-check.py",
            "tools/audit-honesty-check.py",
        ],
        "known_fix": (
            "Tag each kill with kill_kind (scan output_tail for Panic(uint256)/0x11/0x01 vs "
            "invariant_/property_ assertion frames); require >=1 non-panic behavior-changing kill "
            "before verdict=non-vacuous (else equivalent-mutant-only, not credited); mirror the "
            "exclusion into engine-harness-proof-check.py and audit-honesty-check.py via a shared "
            "helper."
        ),
        "guard": "tools/mutation-verify-coverage.py kill_kind classification",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/mutation-verify-coverage.py",
            "tools/mutation-engine.py",
            "tools/engine-harness-proof-check.py",
            "tools/audit-honesty-check.py",
        ],
    },
    {
        "root_cause_id": "medusa-selfdestruct-vm-limit",
        "title": "Mode 10 medusa-selfdestruct-vm-limit: medusa stack-underflows on selfdestruct ETH send",
        "status": "active",
        "severity": "medium",
        "symptom": (
            "medusa stack-underflows on selfdestruct/SafeSend ETH delivery; a break from a vm-error "
            "trace is NOT a finding. Real example mutation_verify_coverage.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/invariant-fuzz-completeness.py",
            "tools/mutation-verify-coverage.py",
        ],
        "known_fix": (
            "Detect selfdestruct/SafeSend in the CUT in invariant-fuzz-completeness.py / the step-2c "
            "runner and require/auto-select echidna; warn when only a medusa campaign exists for a "
            "selfdestruct-path CUT."
        ),
        "guard": "tools/invariant-fuzz-completeness.py echidna auto-select for selfdestruct CUT",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/invariant-fuzz-completeness.py",
            "tools/mutation-verify-coverage.py",
        ],
    },
    {
        "root_cause_id": "serving-join",
        "title": "Mode 11 serving-join: genuine kills on disk but the gate reader keys on a narrow schema",
        "status": "active",
        "severity": "high",
        "symptom": (
            "Genuine kills on disk but the gate reader keys on a narrow path/schema, so an aggregate "
            "reports 0 covered while the evidence exists. Real example mvc-vaultv2-allocateInternal.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/mutation-verify-coverage.py",
            "tools/engine-harness-proof-check.py",
            "tools/core-coverage-completeness.py",
        ],
        "known_fix": (
            "Add a sibling registration entrypoint to "
            "mutation-verify-coverage.py::_persist_durable_sidecar so a hand-authored "
            "*_MutantVacuity.t.sol / chimera proof emits a conforming sidecar; teach the ledger / "
            "cross-function-coverage PRODUCER to ingest .auditooor/mvc_sidecar/*.json."
        ),
        "guard": "tools/mutation-verify-coverage.py sibling sidecar registration + producer ingest",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/mutation-verify-coverage.py",
            "tools/engine-harness-proof-check.py",
            "tools/core-coverage-completeness.py",
        ],
    },
    {
        "root_cause_id": "setup-crash-false-kill",
        "title": "Mode 12 setup-crash-false-kill: a mutant that breaks setUp is recorded as a kill",
        "status": "active",
        "severity": "high",
        "symptom": (
            "A mutation that breaks the harness's own setUp/seed path makes setUp() revert; a producer "
            "keying on exit-code/status==fail records a mutant kill even though the invariant property "
            "never executed. Real example mvc-omnibridge-fintransfer.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/invariant-fuzz-completeness.py",
            "tools/mutation-verify-coverage.py",
            "tools/engine-harness-proof-check.py",
            "tools/audit-honesty-check.py",
        ],
        "known_fix": (
            "Promote _is_genuine_invariant_kill to a shared tools/lib/ module; have the producer "
            "(mutation-verify-coverage.py) and the other two consumers import it. A kill whose "
            "output_tail names ONLY a setUp()/compile/cast revert is reclassified "
            "harness-broken-by-mutant, not killed."
        ),
        "guard": "tools/mutation-verify-coverage.py shared _is_genuine_invariant_kill at producer",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/invariant-fuzz-completeness.py",
            "tools/mutation-verify-coverage.py",
            "tools/engine-harness-proof-check.py",
            "tools/audit-honesty-check.py",
        ],
    },
    {
        "root_cause_id": "stale-sidecar",
        "title": "Mode 13 stale-sidecar: generator clobbers a genuine harness after evidence is banked",
        "status": "active",
        "severity": "high",
        "symptom": (
            "A scaffold generator overwrites an already-genuine hand-authored harness with an "
            "assert(true) advisory scaffold AFTER the mvc_sidecar mutation evidence was banked. The "
            "sidecar persists genuine-looking kills while the on-disk harness is now a tautology. Real "
            "example mvc-ssvstaking-stake.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/per-function-invariant-gen.py",
            "tools/mutation-verify-coverage.py",
            "tools/lib/harness_vacuity.py",
        ],
        "known_fix": (
            "At per-function-invariant-gen.py read the existing file and SKIP when "
            "is_sentinel_only_harness()==False (emit status=preserved-existing-real-harness); at "
            "mutation-verify-coverage.py::_persist_durable_sidecar record harness_source_sha256; every "
            "consumer re-hashes the named harness_path and rejects the sidecar when the hash drifted."
        ),
        "guard": "tools/per-function-invariant-gen.py no-clobber + harness_source_sha256",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/per-function-invariant-gen.py",
            "tools/mutation-verify-coverage.py",
            "tools/lib/harness_vacuity.py",
        ],
    },
    {
        "root_cause_id": "sentinel-density-inversion",
        "title": "Mode 14 sentinel-density-inversion: most emitted harnesses are sentinels, file-count over-credits",
        "status": "active",
        "severity": "high",
        "symptom": (
            "The vast majority of emitted per-fn harnesses are assert(true) scaffolds; the generator "
            "floods test/ with sentinels that dilute and mask the genuine ones. Any aggregate count "
            "keyed on file-presence over-credits. Real example Halmos_BridgeToken_mint.t.sol:42."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/lib/harness_vacuity.py",
            "tools/invariant-fuzz-completeness.py",
        ],
        "known_fix": (
            "Every coverage count must be over NON-sentinel harnesses (run harness_vacuity.py over the "
            "on-disk set and exclude sentinels from numerator and denominator)."
        ),
        "guard": "tools/invariant-fuzz-completeness.py non-sentinel denominator",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/lib/harness_vacuity.py",
            "tools/invariant-fuzz-completeness.py",
        ],
    },
    {
        "root_cause_id": "smoke-then-orphan",
        "title": "Mode 15 smoke-then-orphan: harness passes a smoke checkpoint but never gets the 1M run",
        "status": "active",
        "severity": "high",
        "symptom": (
            "A step-2c harness passes a short smoke checkpoint, the brief defers the >=1M run to the "
            "orchestrator, and the orchestrator records status=skipped (dry-run, engine NOT invoked) - "
            "the harness is real but never receives its >=1M campaign or mutation kill. Real example "
            "status.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": ["tools/invariant-fuzz-completeness.py"],
        "known_fix": (
            "Extract the engine's executed call count and assert total >= 1,000,000 per genuine "
            "campaign (MIN_CALLS=1_000_000); hard-fail any campaign manifest whose status is "
            "skipped/dry-run/engine-was-NOT-invoked."
        ),
        "guard": "tools/invariant-fuzz-completeness.py MIN_CALLS=1_000_000 + no-dry-run gate",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [TAXONOMY_DOC, "tools/invariant-fuzz-completeness.py"],
    },
    {
        "root_cause_id": "cluster-credit-masks-per-invariant",
        "title": "Mode 16 cluster-credit-masks-per-invariant: cluster green inherited by un-mutated invariants",
        "status": "active",
        "severity": "high",
        "symptom": (
            "An mvc_sidecar marks a whole cluster mutation_verified=true on a cluster-level "
            "mutants_killed>=N; individual invariants within the cluster that have NO behavior-changing "
            "mutant inherit the green. Real example liquid_restaking.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/engine-harness-proof-check.py",
            "tools/audit-honesty-check.py",
            "tools/mutation-verify-coverage.py",
        ],
        "known_fix": (
            "Record per-invariant mutant attribution (which invariant each killed mutant was caught BY, "
            "from the failing assertion frame) in the sidecar; require every CREDITED invariant to "
            "have >=1 attributed behavior-changing kill."
        ),
        "guard": "tools/engine-harness-proof-check.py per-invariant mutant attribution",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/engine-harness-proof-check.py",
            "tools/audit-honesty-check.py",
            "tools/mutation-verify-coverage.py",
        ],
    },
    {
        "root_cause_id": "auth-degrade-to-skeleton",
        "title": "Mode 17 auth-degrade-to-skeleton: invalid LLM credential silently falls back to skeletons",
        "status": "active",
        "severity": "high",
        "symptom": (
            "The LLM authoring credential is invalid (http-401/402) and the pipeline silently falls "
            "back to fail-closed skeletons / typed-skips instead of halting. The harness body is never "
            "even authored. The corpus looks large but is mostly dead. Real example "
            "llm_dispatch_depth_probe.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": ["tools/dispatch-agent-with-prebriefing.py"],
        "known_fix": (
            "A credential-preflight probe (smallest viable: a tiny authenticated no-op) invoked BEFORE "
            "dispatch and by the step-2c/step-4 authoring make target; on http-401/402 FAIL CLOSED "
            "(block dispatch, do not emit a degraded skeleton). Wire into step-0f so "
            "backend-authenticates is verified."
        ),
        "guard": "tools/dispatch-agent-with-prebriefing.py credential-preflight (fail-closed)",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [TAXONOMY_DOC, "tools/dispatch-agent-with-prebriefing.py"],
    },
    {
        "root_cause_id": "zero-byte-unit-spec",
        "title": "Mode 18 zero-byte-unit-spec: generator writes 0-byte coverage-unit specs (fail-open)",
        "status": "active",
        "severity": "medium",
        "symptom": (
            "The per-unit invariant generator writes 0-byte coverage_unit_invariants/*.json with no "
            "non-empty guard; downstream authors have no spec to build from. A generator that succeeds "
            "producing empty files is a silent-skip at the spec layer. Real example "
            "coverage_unit_invariants.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": ["tools/per-function-invariant-gen.py"],
        "known_fix": (
            "Add a non-empty-output assertion to per-function-invariant-gen.py so it NEVER writes a "
            "0-byte spec (fail-closed on empty render); on missing pre-flight pack, skip the unit "
            "rather than emit a sentinel counted in the denominator."
        ),
        "guard": "tools/per-function-invariant-gen.py non-empty-output assertion",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [TAXONOMY_DOC, "tools/per-function-invariant-gen.py"],
    },
    {
        "root_cause_id": "wrong-cut-oos-target",
        "title": "Mode 19 wrong-cut-oos-target: generator enumerates OOS/vendored symbols as coverage units",
        "status": "active",
        "severity": "medium",
        "symptom": (
            "The generator enumerates over ALL discoverable symbols (vendored / deployed-zip / "
            "interface paths) with no in-scope src/ filter, so OOS units become coverage units. Real "
            "example Halmos_IERC20_transfer.t.sol:41."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/per-function-invariant-gen.py",
            "tools/evm-engine-harness-author.py",
        ],
        "known_fix": (
            "Filter CUT candidates against .auditooor/inscope_units.jsonl (the same allow-list "
            "invariant-fuzz-completeness._has_in_scope_solidity_source reads) in "
            "per-function-invariant-gen.py (discover_solidity_files/discover_generic_files) and "
            "evm-engine-harness-author.py."
        ),
        "guard": "tools/per-function-invariant-gen.py inscope_units.jsonl CUT filter",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/per-function-invariant-gen.py",
            "tools/evm-engine-harness-author.py",
        ],
    },
    {
        "root_cause_id": "typed-skip-at-scale",
        "title": "Mode 20 typed-skip-at-scale: honest typed-skips at scale with no follow-through to bind the CUT",
        "status": "active",
        "severity": "medium",
        "symptom": (
            "The generator, when it cannot derive constructor args/proxy topology, correctly emits an "
            "honestly-labeled model-only typed-skip - but at scale this produces dozens of dead "
            "harnesses with no automated follow-through to bind the real CUT, leaving function-coverage "
            "permanently RED. Real example attempt_manifest.json."
        ),
        "first_seen": "2026-06-27",
        "last_seen": "2026-06-27",
        "occurrence_count": 1,
        "tools_affected": [
            "tools/per-function-invariant-gen.py",
            "tools/evm-engine-harness-author.py",
        ],
        "known_fix": (
            "Seed the generator with the repo's own test setUp (proven on the 3 etherfi chimera "
            "clusters and morpho VaultV2) so bindTarget is materialized, not stubbed; add a "
            "skeleton-followthrough producer that re-queues typed-skips with a deployment recipe."
        ),
        "guard": "tools/per-function-invariant-gen.py repo-setUp seeding + followthrough re-queue",
        "counter_example_links": [TAXONOMY_DOC],
        "source_paths": [
            TAXONOMY_DOC,
            "tools/per-function-invariant-gen.py",
            "tools/evm-engine-harness-author.py",
        ],
    },
]


SEED_ROOTS.extend(SEMANTIC_MODE_SEEDS)

# Stable accessor + name set other tools (dispatch-agent-with-prebriefing.py) import to
# render the 20 confirmed semantic harness-failure modes. Keep ordered (modes 1..20).
SEMANTIC_MODE_NAMES: tuple[str, ...] = tuple(seed["root_cause_id"] for seed in SEMANTIC_MODE_SEEDS)


def semantic_mode_seeds() -> list[dict[str, Any]]:
    """Return deep copies of the 20 confirmed semantic harness-failure mode seeds.

    Mirrors docs/HARNESS_FAILURE_TAXONOMY.md. Each returned dict is a valid
    validate_row() row; root_cause_id is the canonical mode-name and known_fix is the
    proven fix. Consumers render these as "KNOWN HARNESS-FAILURE MODES - do NOT
    reproduce" bullets in the dispatch brief.
    """
    return [dict(seed) for seed in SEMANTIC_MODE_SEEDS]


def today() -> str:
    return dt.date.today().isoformat()


def clean_text(value: Any) -> str:
    text = str(value if value is not None else "").strip()
    return "".join(" " if ord(ch) < 32 else ch for ch in text)


def list_from_value(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def clean_string_list(value: Any) -> list[str]:
    out: list[str] = []
    for item in list_from_value(value):
        text = clean_text(item)
        if text and text not in out:
            out.append(text)
    return out


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or "harness-failure"


def rel_display(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return str(path)


def safe_repo_ref(value: Any, repo: Path, *, must_exist: bool = True) -> bool:
    text = clean_text(value)
    if not text or any(ch in text for ch in "`\n\r"):
        return False
    if text.startswith("/") or text.startswith("~") or "://" in text:
        return False
    parts = tuple(part for part in Path(text).parts if part and part != ".")
    if not parts or any(part == ".." or part.startswith(".") or part in FORBIDDEN_PARTS for part in parts):
        return False
    rel = "/".join(parts)
    if rel not in ROOT_FILES and not any(rel.startswith(prefix) for prefix in SAFE_PREFIXES):
        return False
    target = (repo / rel).resolve()
    try:
        target.relative_to(repo.resolve())
    except ValueError:
        return False
    return target.exists() if must_exist else True


def safe_event_ref(value: Any, repo: Path, *, must_exist: bool = False) -> bool:
    text = clean_text(value)
    if not text or any(ch in text for ch in "`\n\r"):
        return False
    if text.startswith("/") or text.startswith("~") or "://" in text:
        return False
    parts = tuple(part for part in Path(text).parts if part and part != ".")
    if not parts or any(part == ".." or part.startswith(".") or part in FORBIDDEN_PARTS for part in parts):
        return False
    rel = "/".join(parts)
    if rel not in EVENT_REF_ROOT_FILES and not any(rel.startswith(prefix) for prefix in EVENT_SAFE_PREFIXES):
        return False
    target = (repo / rel).resolve()
    try:
        target.relative_to(repo.resolve())
    except ValueError:
        return False
    return target.exists() if must_exist else True


def normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "schema": row.get("schema") or SCHEMA,
        "root_cause_id": slugify(str(row.get("root_cause_id") or "")),
        "title": clean_text(row.get("title")),
        "status": clean_text(row.get("status")),
        "severity": clean_text(row.get("severity")),
        "symptom": clean_text(row.get("symptom")),
        "first_seen": clean_text(row.get("first_seen")),
        "last_seen": clean_text(row.get("last_seen")),
        "occurrence_count": row.get("occurrence_count"),
        "tools_affected": clean_string_list(row.get("tools_affected")),
        "known_fix": clean_text(row.get("known_fix")),
        "guard": clean_text(row.get("guard")),
        "counter_example_links": clean_string_list(row.get("counter_example_links")),
        "source_paths": clean_string_list(row.get("source_paths")),
        "last_validated_at": clean_text(row.get("last_validated_at") or today()),
    }
    try:
        normalized["occurrence_count"] = int(normalized["occurrence_count"])
    except (TypeError, ValueError):
        normalized["occurrence_count"] = 0
    return normalized


def raw_row_errors(row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_ROW_FIELDS:
        if key not in row:
            errors.append(f"{key} is required")
    extra = set(row.keys()) - set(REQUIRED_ROW_FIELDS)
    if extra:
        errors.append(f"unexpected fields: {', '.join(sorted(extra))}")
    for key in STRING_ROW_FIELDS:
        if key in row and not isinstance(row[key], str):
            errors.append(f"{key} must be string")
    for key in LIST_ROW_FIELDS:
        if key in row and not isinstance(row[key], list):
            errors.append(f"{key} must be list")
        elif key in row and any(not isinstance(item, str) for item in row[key]):
            errors.append(f"{key} entries must be strings")
    if "occurrence_count" in row and (
            not isinstance(row["occurrence_count"], int) or isinstance(row["occurrence_count"], bool)):
        errors.append("occurrence_count must be integer")
    return errors


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "schema": event.get("schema") or EVENT_SCHEMA,
        "event_id": clean_text(event.get("event_id")),
        "root_cause_id": slugify(str(event.get("root_cause_id") or "")),
        "event_state": clean_text(event.get("event_state") or "pending"),
        "occurred_at": clean_text(event.get("occurred_at")),
        "command": clean_text(event.get("command")),
        "exit_code": event.get("exit_code"),
        "workspace": clean_text(event.get("workspace")),
        "commit": clean_text(event.get("commit")),
        "raw_log_path": clean_text(event.get("raw_log_path")),
        "harness_path": clean_text(event.get("harness_path")),
        "classifier_confidence": event.get("classifier_confidence"),
        "knowledge_gap_refs": clean_string_list(event.get("knowledge_gap_refs")),
        "recurrence_window": event.get("recurrence_window"),
        "finalization_task_id": clean_text(event.get("finalization_task_id")),
        "finalization_status": clean_text(event.get("finalization_status")),
        "stale_reason": clean_text(event.get("stale_reason")),
        "next_action": normalize_next_action(event.get("next_action")),
    }
    try:
        normalized["exit_code"] = int(normalized["exit_code"])
    except (TypeError, ValueError):
        normalized["exit_code"] = -1
    try:
        normalized["classifier_confidence"] = float(normalized["classifier_confidence"])
    except (TypeError, ValueError):
        normalized["classifier_confidence"] = -1.0
    return normalized


def raw_event_errors(event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_EVENT_FIELDS:
        if key not in event:
            errors.append(f"{key} is required")
    extra = set(event.keys()) - set(REQUIRED_EVENT_FIELDS)
    if extra:
        errors.append(f"unexpected fields: {', '.join(sorted(extra))}")
    for key in STRING_EVENT_FIELDS:
        if key in event and not isinstance(event[key], str):
            errors.append(f"{key} must be string")
    if "exit_code" in event and (not isinstance(event["exit_code"], int) or isinstance(event["exit_code"], bool)):
        errors.append("exit_code must be integer")
    if "classifier_confidence" in event and (
            not isinstance(event["classifier_confidence"], (int, float))
            or isinstance(event["classifier_confidence"], bool)):
        errors.append("classifier_confidence must be number")
    if "knowledge_gap_refs" in event and not isinstance(event["knowledge_gap_refs"], list):
        errors.append("knowledge_gap_refs must be list")
    elif "knowledge_gap_refs" in event and any(not isinstance(item, str) for item in event["knowledge_gap_refs"]):
        errors.append("knowledge_gap_refs entries must be strings")
    if "recurrence_window" in event and not isinstance(event["recurrence_window"], dict):
        errors.append("recurrence_window must be object")
    if "next_action" in event and not isinstance(event["next_action"], dict):
        errors.append("next_action must be object")
    return errors


def validate_recurrence_window(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    errors: list[str] = []
    required = {"first_seen", "last_seen", "event_count"}
    missing = sorted(required - set(value.keys()))
    if missing:
        errors.append(f"recurrence_window missing fields: {', '.join(missing)}")
    extra = sorted(set(value.keys()) - required)
    if extra:
        errors.append(f"recurrence_window unexpected fields: {', '.join(extra)}")
    for key in ("first_seen", "last_seen"):
        if key in value and (not isinstance(value[key], str) or DATE_RE.match(value[key]) is None):
            errors.append(f"recurrence_window.{key} must be YYYY-MM-DD")
    if "event_count" in value and (
            not isinstance(value["event_count"], int)
            or isinstance(value["event_count"], bool)
            or value["event_count"] < 1):
        errors.append("recurrence_window.event_count must be positive integer")
    return errors


def normalize_next_action(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"kind": "", "owner_lane": "", "command": "", "blocked_by": []}
    return {
        "kind": clean_text(value.get("kind")),
        "owner_lane": clean_text(value.get("owner_lane")),
        "command": clean_text(value.get("command")),
        "blocked_by": clean_string_list(value.get("blocked_by")),
    }


def validate_next_action(value: Any, *, event_state: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["next_action must be object"]
    required = {"kind", "owner_lane", "command", "blocked_by"}
    missing = sorted(required - set(value.keys()))
    if missing:
        errors.append(f"next_action missing fields: {', '.join(missing)}")
    extra = sorted(set(value.keys()) - required)
    if extra:
        errors.append(f"next_action unexpected fields: {', '.join(extra)}")
    action = normalize_next_action(value)
    if action["kind"] not in NEXT_ACTION_KINDS:
        errors.append(f"next_action.kind must be one of {sorted(NEXT_ACTION_KINDS)}")
    if not action["owner_lane"]:
        errors.append("next_action.owner_lane is required")
    if not isinstance(value.get("blocked_by"), list) or any(
        not isinstance(item, str) for item in value.get("blocked_by", [])
    ):
        errors.append("next_action.blocked_by must be list of strings")
    command = action["command"]
    if any(token in command.lower() for token in ("tbd", "todo", "unknown", "maybe")):
        errors.append("next_action.command must be exact, not placeholder prose")
    if event_state == "finalized":
        if action["kind"] != "none":
            errors.append("finalized events require next_action.kind=none")
        if command:
            errors.append("finalized events require empty next_action.command")
    else:
        if action["kind"] == "none":
            errors.append("non-finalized events require an actionable next_action.kind")
        if not command:
            errors.append("non-finalized events require next_action.command")
    if event_state == "pending" and action["kind"] != "record_finalization":
        errors.append("pending events require next_action.kind=record_finalization")
    if event_state == "stale" and action["kind"] not in {"refresh_event_evidence", "record_finalization"}:
        errors.append("stale events require refresh_event_evidence or record_finalization next action")
    return errors


def validate_event(event: dict[str, Any], repo: Path = REPO_ROOT) -> list[str]:
    errors: list[str] = raw_event_errors(event)
    normalized = normalize_event(event)
    if normalized["schema"] != EVENT_SCHEMA:
        errors.append(f"schema must be {EVENT_SCHEMA}")
    if EVENT_ID_RE.match(normalized["event_id"]) is None:
        errors.append("event_id must be stable event identifier")
    if ROOT_ID_RE.match(normalized["root_cause_id"]) is None:
        errors.append("root_cause_id must be lowercase slug-safe")
    if normalized["event_state"] not in EVENT_STATES:
        errors.append(f"event_state must be one of {sorted(EVENT_STATES)}")
    if DATETIME_RE.match(normalized["occurred_at"]) is None:
        errors.append("occurred_at must be ISO-8601 seconds with timezone")
    if not normalized["command"]:
        errors.append("command is required")
    if normalized["exit_code"] < 0:
        errors.append("exit_code must be non-negative")
    if not safe_event_ref(normalized["workspace"], repo, must_exist=False):
        errors.append(f"unsafe workspace ref: {normalized['workspace']}")
    if re.fullmatch(r"[0-9a-f]{7,40}", normalized["commit"]) is None:
        errors.append("commit must be 7-40 lowercase hex characters")
    for key in ("raw_log_path", "harness_path"):
        if not safe_event_ref(normalized[key], repo, must_exist=False):
            errors.append(f"unsafe {key}: {normalized[key]}")
    if not 0.0 <= normalized["classifier_confidence"] <= 1.0:
        errors.append("classifier_confidence must be between 0 and 1")
    for ref in normalized["knowledge_gap_refs"]:
        if KG_REF_RE.match(ref) is None:
            errors.append(f"invalid knowledge_gap_ref: {ref}")
    errors.extend(validate_recurrence_window(normalized["recurrence_window"]))
    errors.extend(validate_next_action(event.get("next_action"), event_state=normalized["event_state"]))
    finalization_task_id = normalized["finalization_task_id"]
    finalization_status = normalized["finalization_status"]
    stale_reason = normalized["stale_reason"]
    if normalized["event_state"] == "finalized":
        if EVENT_ID_RE.match(finalization_task_id) is None:
            errors.append("finalized events require finalization_task_id")
        if finalization_status not in FINALIZATION_STATUSES:
            errors.append(f"finalization_status must be one of {sorted(FINALIZATION_STATUSES)}")
        if stale_reason:
            errors.append("finalized events require empty stale_reason")
    elif normalized["event_state"] == "pending":
        if finalization_task_id or finalization_status or stale_reason:
            errors.append("pending events must not set finalization_task_id, finalization_status, or stale_reason")
    elif normalized["event_state"] == "stale":
        if finalization_task_id or finalization_status:
            errors.append("stale events must not set finalization_task_id or finalization_status")
        if not stale_reason:
            errors.append("stale events require stale_reason")
    return errors


def validate_row(row: dict[str, Any], repo: Path = REPO_ROOT) -> list[str]:
    errors: list[str] = raw_row_errors(row)
    normalized = normalize_row(row)
    if normalized["schema"] != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if ROOT_ID_RE.match(normalized["root_cause_id"]) is None:
        errors.append("root_cause_id must be lowercase slug-safe")
    for key in ("title", "symptom", "known_fix", "guard"):
        if not normalized[key]:
            errors.append(f"{key} is required")
    if normalized["status"] not in STATUSES:
        errors.append(f"status must be one of {sorted(STATUSES)}")
    if normalized["severity"] not in SEVERITIES:
        errors.append(f"severity must be one of {sorted(SEVERITIES)}")
    for key in ("first_seen", "last_seen", "last_validated_at"):
        if DATE_RE.match(normalized[key]) is None:
            errors.append(f"{key} must be YYYY-MM-DD")
    if normalized["occurrence_count"] < 1:
        errors.append("occurrence_count must be positive")
    for key in ("tools_affected", "source_paths"):
        if not normalized[key]:
            errors.append(f"{key} must be non-empty")
    for ref in [*normalized["source_paths"], *normalized["counter_example_links"]]:
        if not safe_repo_ref(ref, repo):
            errors.append(f"unsafe or missing source ref: {ref}")
    return errors


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSONL") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no}: row must be object")
        rows.append(value)
    return rows


def validate_report(path: Path, repo: Path = REPO_ROOT) -> list[str]:
    if not path.is_file():
        return [f"{path}: report missing"]
    errors: list[str] = []
    seen: set[str] = set()
    try:
        rows = read_jsonl(path)
    except ValueError as exc:
        return [str(exc)]
    for index, raw in enumerate(rows, start=1):
        row = normalize_row(raw)
        if row["root_cause_id"] in seen:
            errors.append(f"{path}:{index}: duplicate root_cause_id {row['root_cause_id']}")
        seen.add(row["root_cause_id"])
        for error in validate_row(raw, repo=repo):
            errors.append(f"{path}:{index}: {error}")
    return errors


def validate_event_report(path: Path, repo: Path = REPO_ROOT) -> list[str]:
    return validate_event_report_with_finalization(path, repo=repo, finalization_ledger=None)


def task_finalization_index(path: Path) -> tuple[dict[str, str], list[str]]:
    if not path.is_file():
        return {}, [f"{path}: task-finalization ledger missing"]
    rows: dict[str, str] = {}
    errors: list[str] = []
    try:
        raw_rows = read_jsonl(path)
    except ValueError as exc:
        return {}, [str(exc)]
    for index, row in enumerate(raw_rows, start=1):
        task_id = clean_text(row.get("task_id"))
        status = clean_text(row.get("status"))
        if not task_id:
            errors.append(f"{path}:{index}: task_id is required for event finalization lookup")
            continue
        if status not in FINALIZATION_STATUSES:
            errors.append(f"{path}:{index}: status must be one of {sorted(FINALIZATION_STATUSES)}")
            continue
        rows[task_id] = status
    return rows, errors


def validate_event_rows(
    events: list[dict[str, Any]],
    repo: Path = REPO_ROOT,
    *,
    finalization_rows: dict[str, str] | None = None,
    finalization_ledger: Path | None = None,
    source_label: str | None = None,
) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(events, start=1):
        prefix = f"{source_label}:{index}" if source_label else f"event {index}"
        event_id = clean_text(raw.get("event_id"))
        if event_id in seen:
            errors.append(f"{prefix}: duplicate event_id {event_id}")
        seen.add(event_id)
        for error in validate_event(raw, repo=repo):
            errors.append(f"{prefix}: {error}")
        event = normalize_event(raw)
        if finalization_rows is not None and event["event_state"] == "finalized":
            ledger_status = finalization_rows.get(event["finalization_task_id"])
            if ledger_status is None:
                errors.append(
                    f"{prefix}: finalized event task {event['finalization_task_id']} missing from "
                    f"{finalization_ledger}"
                )
            elif ledger_status != event["finalization_status"]:
                errors.append(
                    f"{prefix}: finalized event status {event['finalization_status']} does not match "
                    f"task-finalization ledger status {ledger_status}"
                )
    return errors


def validate_event_report_with_finalization(
    path: Path,
    repo: Path = REPO_ROOT,
    *,
    finalization_ledger: Path | None = None,
) -> list[str]:
    if not path.is_file():
        return [f"{path}: event report missing"]
    errors: list[str] = []
    try:
        events = read_jsonl(path)
    except ValueError as exc:
        return [str(exc)]
    finalization_rows: dict[str, str] = {}
    if finalization_ledger is not None:
        finalization_rows, ledger_errors = task_finalization_index(finalization_ledger)
        errors.extend(ledger_errors)
    errors.extend(
        validate_event_rows(
            events,
            repo=repo,
            finalization_rows=finalization_rows if finalization_ledger is not None else None,
            finalization_ledger=finalization_ledger,
            source_label=str(path),
        )
    )
    return errors


def date_from_event(event: dict[str, Any]) -> str:
    occurred_at = clean_text(event.get("occurred_at"))
    return occurred_at[:10] if DATE_RE.match(occurred_at[:10]) else ""


def recurrence_dates_from_event(event: dict[str, Any]) -> tuple[str, str]:
    window = event.get("recurrence_window")
    if not isinstance(window, dict):
        event_date = date_from_event(event)
        return event_date, event_date
    first_seen = clean_text(window.get("first_seen"))
    last_seen = clean_text(window.get("last_seen"))
    if DATE_RE.match(first_seen) is None:
        first_seen = date_from_event(event)
    if DATE_RE.match(last_seen) is None:
        last_seen = date_from_event(event)
    return first_seen, last_seen


def sorted_unique(values: list[Any]) -> list[Any]:
    out: list[Any] = []
    for value in values:
        if value not in out:
            out.append(value)
    return sorted(out)


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for raw in events:
        event = normalize_event(raw)
        buckets.setdefault(event["root_cause_id"], []).append(event)

    roots: list[dict[str, Any]] = []
    for root_cause_id, root_events in sorted(buckets.items()):
        first_dates = sorted(
            first
            for first, _last in (recurrence_dates_from_event(event) for event in root_events)
            if first
        )
        last_dates = sorted(
            last
            for _first, last in (recurrence_dates_from_event(event) for event in root_events)
            if last
        )
        root_events.sort(key=lambda event: (event["occurred_at"], event["event_id"]))
        roots.append({
            "root_cause_id": root_cause_id,
            "event_count": len(root_events),
            "event_state_counts": {
                state: sum(1 for event in root_events if event["event_state"] == state)
                for state in sorted(EVENT_STATES)
            },
            "first_seen": first_dates[0] if first_dates else "",
            "last_seen": last_dates[-1] if last_dates else "",
            "commands": sorted_unique([event["command"] for event in root_events]),
            "exit_codes": sorted_unique([event["exit_code"] for event in root_events]),
            "workspaces": sorted_unique([event["workspace"] for event in root_events]),
            "commits": sorted_unique([event["commit"] for event in root_events]),
            "raw_log_paths": sorted_unique([event["raw_log_path"] for event in root_events]),
            "harness_paths": sorted_unique([event["harness_path"] for event in root_events]),
            "knowledge_gap_refs": sorted_unique([
                ref
                for event in root_events
                for ref in event["knowledge_gap_refs"]
            ]),
            "max_classifier_confidence": max(event["classifier_confidence"] for event in root_events),
            "event_ids": [event["event_id"] for event in root_events],
            "pending_event_ids": [
                event["event_id"] for event in root_events if event["event_state"] == "pending"
            ],
            "stale_event_ids": [
                event["event_id"] for event in root_events if event["event_state"] == "stale"
            ],
            "finalized_task_ids": sorted_unique([
                event["finalization_task_id"]
                for event in root_events
                if event["event_state"] == "finalized" and event["finalization_task_id"]
            ]),
            "next_action_kinds": sorted_unique([
                event["next_action"]["kind"]
                for event in root_events
                if event["next_action"]["kind"]
            ]),
        })
    return {
        "schema": EVENT_SUMMARY_SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "event_count": sum(len(root_events) for root_events in buckets.values()),
        "root_cause_count": len(roots),
        "event_state_counts": {
            state: sum(
                1
                for root_events in buckets.values()
                for event in root_events
                if event["event_state"] == state
            )
            for state in sorted(EVENT_STATES)
        },
        "roots": roots,
    }


def materialize_rows_from_events(
    events: list[dict[str, Any]],
    repo: Path = REPO_ROOT,
    *,
    event_source: Path | None = None,
    finalization_ledger: Path | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    if not events:
        return [], ["event-derived aggregate requires at least one event row"]

    source_ref = ""
    if event_source is not None:
        source_ref = rel_display(event_source.resolve(), repo)
        if not safe_repo_ref(source_ref, repo):
            errors.append(f"unsafe or missing event source ref: {source_ref}")

    finalization_rows: dict[str, str] | None = None
    if finalization_ledger is not None:
        finalization_rows, ledger_errors = task_finalization_index(finalization_ledger)
        errors.extend(ledger_errors)
    errors.extend(
        validate_event_rows(
            events,
            repo=repo,
            finalization_rows=finalization_rows,
            finalization_ledger=finalization_ledger,
        )
    )
    if errors:
        return [], errors

    seeded_rows = {row["root_cause_id"]: row for row in build_rows(repo)}
    materialized_events = [event for event in events if normalize_event(event)["event_state"] != "stale"]
    if not materialized_events:
        return [], ["event-derived aggregate requires at least one non-stale event row"]

    summary = summarize_events(materialized_events)
    rows: list[dict[str, Any]] = []
    for root_summary in summary["roots"]:
        root_cause_id = root_summary["root_cause_id"]
        seed = seeded_rows.get(root_cause_id)
        if seed is None:
            errors.append(
                f"cannot materialize aggregate for unknown root_cause_id {root_cause_id}: "
                "no seeded root metadata"
            )
            continue
        if not root_summary["first_seen"] or not root_summary["last_seen"]:
            errors.append(f"cannot materialize aggregate for {root_cause_id}: missing recurrence dates")
            continue
        row = normalize_row({
            **seed,
            "first_seen": root_summary["first_seen"],
            "last_seen": root_summary["last_seen"],
            "occurrence_count": root_summary["event_count"],
            "last_validated_at": today(),
        })
        if source_ref:
            for key in ("source_paths", "counter_example_links"):
                if source_ref not in row[key]:
                    row[key].append(source_ref)
        row_errors = validate_row(row, repo=repo)
        if row_errors:
            errors.extend(f"{root_cause_id}: {error}" for error in row_errors)
            continue
        rows.append(row)

    if errors:
        return [], errors
    rows.sort(key=lambda item: (item["status"] != "active", item["root_cause_id"]))
    return rows, []


def scan_matches(repo: Path, seed: dict[str, Any], scan_paths: list[Path]) -> list[str]:
    patterns = [re.compile(pattern, re.I) for pattern in seed.get("match_patterns") or []]
    if not patterns:
        return []
    matches: list[str] = []
    for base in scan_paths:
        if not base.exists():
            continue
        paths = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if any(pattern.search(text) for pattern in patterns):
                ref = rel_display(path, repo)
                if safe_repo_ref(ref, repo) and ref not in matches:
                    matches.append(ref)
    return matches[:8]


def build_rows(repo: Path = REPO_ROOT, scan_paths: list[Path] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    scan_paths = scan_paths or []
    for seed in SEED_ROOTS:
        row = normalize_row({**seed, "last_validated_at": today()})
        extra_refs = scan_matches(repo, seed, scan_paths)
        for ref in extra_refs:
            if ref not in row["source_paths"]:
                row["source_paths"].append(ref)
        row["occurrence_count"] = max(row["occurrence_count"], len(extra_refs), 1)
        rows.append(row)
    rows.sort(key=lambda item: (item["status"] != "active", item["root_cause_id"]))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")


def yaml_scalar(value: Any) -> str:
    text = clean_text(value).replace('"', "'")
    return f'"{text}"'


def note_text(row: dict[str, Any]) -> str:
    lines = [
        "---",
        f"schema: {yaml_scalar(SCHEMA)}",
        f"root_cause_id: {yaml_scalar(row['root_cause_id'])}",
        f"title: {yaml_scalar(row['title'])}",
        f"status: {yaml_scalar(row['status'])}",
        f"severity: {yaml_scalar(row['severity'])}",
        f"occurrence_count: {row['occurrence_count']}",
        f"first_seen: {yaml_scalar(row['first_seen'])}",
        f"last_seen: {yaml_scalar(row['last_seen'])}",
        "tools_affected:",
    ]
    lines.extend(f"  - {yaml_scalar(item)}" for item in row["tools_affected"])
    lines.extend([
        "tags:",
        "  - memory/harness-failure",
        "---",
        "",
        f"# Harness Failure - {row['title']}",
        "",
        "## Symptom",
        "",
        row["symptom"],
        "",
        "## Known Fix",
        "",
        row["known_fix"],
        "",
        "## Guard",
        "",
        row["guard"],
        "",
        "## Counter-Examples / Evidence",
        "",
    ])
    refs = row["counter_example_links"] or row["source_paths"]
    lines.extend(f"- `{ref}`" for ref in refs)
    lines.extend(["", "## Source Paths", ""])
    lines.extend(f"- `{ref}`" for ref in row["source_paths"])
    lines.append("")
    return "\n".join(lines)


def index_text(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Harness Failure Memory",
        "",
        "_Generated projection. Canonical source: `reports/harness_failures.jsonl`._",
        "",
        "| Root Cause | Status | Severity | Count | Guard |",
        "|---|---|---|---:|---|",
    ]
    for row in rows:
        note = f"{row['root_cause_id']}.md"
        lines.append(
            f"| [{row['root_cause_id']}]({note}) | `{row['status']}` | "
            f"`{row['severity']}` | {row['occurrence_count']} | {row['guard']} |")
    lines.append("")
    return "\n".join(lines)


def write_projections(notes_dir: Path, rows: list[dict[str, Any]]) -> list[str]:
    notes_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    expected = {f"{row['root_cause_id']}.md" for row in rows}
    expected.add("INDEX.md")
    for stale in notes_dir.glob("*.md"):
        if stale.name in expected:
            continue
        try:
            text = stale.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if SCHEMA in text:
            stale.unlink()
    for row in rows:
        path = notes_dir / f"{row['root_cause_id']}.md"
        path.write_text(note_text(row), encoding="utf-8")
        written.append(str(path))
    index = notes_dir / "INDEX.md"
    index.write_text(index_text(rows), encoding="utf-8")
    written.append(str(index))
    return written


def build_payload(report: Path, notes_dir: Path, rows: list[dict[str, Any]], dry_run: bool) -> dict[str, Any]:
    return {
        "schema": "auditooor.harness_failure_memory_run.v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "dry_run": dry_run,
        "report": str(report),
        "notes_dir": str(notes_dir),
        "root_cause_count": len(rows),
        "rows": rows,
    }


def self_test() -> int:
    rows = build_rows(REPO_ROOT)
    required = {
        "m14-prompt-shape-regression",
        "fixture-smoke-mode-flag-missing",
        "empty-setup-sol-harness",
        "forge-std-resolution",
        "wirer-diversity-collapse",
    }
    got = {row["root_cause_id"] for row in rows}
    missing = sorted(required - got)
    if missing:
        print(f"missing required seeds: {', '.join(missing)}", file=sys.stderr)
        return 1
    errors: list[str] = []
    for row in rows:
        errors.extend(validate_row(row, repo=REPO_ROOT))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="auditooor-harness-memory-") as tmp:
        notes = Path(tmp) / "notes"
        written = write_projections(notes, rows)
        if len(written) != len(rows) + 1:
            print("projection write count mismatch", file=sys.stderr)
            return 1
    print(f"[harness-failure-memory] self-test ok ({len(rows)} root causes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=str(REPO_ROOT))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--vault-dir", default=str(DEFAULT_VAULT))
    parser.add_argument("--notes-dir", default=None)
    parser.add_argument("--events-report", default=None,
                        help="optional per-occurrence harness-failure event JSONL to validate")
    parser.add_argument("--event-summary", default=None,
                        help="optional JSON summary path to materialize from --events-report")
    parser.add_argument("--task-finalization-ledger", default=None,
                        help="optional task_finalization.jsonl used to verify finalized event rows")
    parser.add_argument("--scan-path", action="append", default=[],
                        help="optional repo-relative file/dir to scan for matching failure evidence")
    parser.add_argument("--write", action="store_true",
                        help="write canonical report and vault projections")
    parser.add_argument("--validate", action="store_true",
                        help="validate existing report instead of emitting")
    parser.add_argument("--validate-events", action="store_true",
                        help="validate --events-report and optionally write --event-summary")
    parser.add_argument("--from-events", action="store_true",
                        help="materialize aggregate root report from validated --events-report rows")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    repo = Path(args.repo).resolve()
    report = Path(args.report).resolve()
    vault = Path(args.vault_dir).resolve()
    notes_dir = Path(args.notes_dir).resolve() if args.notes_dir else vault / "harness-failures"

    if args.validate_events:
        if not args.events_report:
            print("--validate-events requires --events-report", file=sys.stderr)
            return 2
        events_report = Path(args.events_report).resolve()
        finalization_ledger = (
            Path(args.task_finalization_ledger).resolve()
            if args.task_finalization_ledger else None
        )
        errors = validate_event_report_with_finalization(
            events_report,
            repo=repo,
            finalization_ledger=finalization_ledger,
        )
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 1
        events = read_jsonl(events_report)
        summary = summarize_events(events)
        if args.event_summary:
            summary_path = Path(args.event_summary).resolve()
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(f"[harness-failure-memory] {events_report} event report valid")
            print(f"events: {summary['event_count']}")
            print(f"root causes: {summary['root_cause_count']}")
            if args.event_summary:
                print(f"summary: {Path(args.event_summary).resolve()}")
        return 0

    if args.validate:
        errors = validate_report(report, repo=repo)
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 1
        print(f"[harness-failure-memory] {report} valid")
        return 0

    if args.from_events:
        if not args.events_report:
            print("--from-events requires --events-report", file=sys.stderr)
            return 2
        events_report = Path(args.events_report).resolve()
        finalization_ledger = (
            Path(args.task_finalization_ledger).resolve()
            if args.task_finalization_ledger else None
        )
        if not events_report.is_file():
            print(f"{events_report}: event report missing", file=sys.stderr)
            return 1
        try:
            events = read_jsonl(events_report)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        rows, event_errors = materialize_rows_from_events(
            events,
            repo=repo,
            event_source=events_report,
            finalization_ledger=finalization_ledger,
        )
        if event_errors:
            print("\n".join(event_errors), file=sys.stderr)
            return 2
    else:
        scan_paths = [
            (repo / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
            for path in args.scan_path
        ]
        rows = build_rows(repo, scan_paths=scan_paths)
    errors: list[str] = []
    for row in rows:
        errors.extend(validate_row(row, repo=repo))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 2

    dry_run = not args.write
    if args.write:
        write_jsonl(report, rows)
        write_projections(notes_dir, rows)

    payload = build_payload(report, notes_dir, rows, dry_run=dry_run)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        action = "would write" if dry_run else "wrote"
        print(f"[harness-failure-memory] {action} {len(rows)} root cause rows")
        if args.from_events:
            print(f"source events: {Path(args.events_report).resolve()}")
        print(f"report: {report}")
        print(f"notes: {notes_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
