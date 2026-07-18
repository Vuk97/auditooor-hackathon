#!/usr/bin/env python3
"""Generate a compact agent-facing index of Hackerman and MCP entry points."""
from __future__ import annotations

import argparse
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"


# Wave-1 auto-discovery configuration. Each section globs `tools/` for a fixed
# filename pattern, then optionally filters the matches by an explicit
# allowlist / denylist. Tools live next to this script; sorting is stable so
# the generated doc is deterministic.
WAVE1_ETL_GLOB = "hackerman-etl-from-*.py"
WAVE1_STRATIFY_APPLY_GATES = [
    "hackerman-stratify-verification-tier.py",
    "hackerman-apply-verification-tier.py",
    "hackerman-record-verification-tier-check.py",
    "hackerman-baseline-freeze.py",
    "hackerman-tier-history-snapshot.py",
    "hackerman-gates-status.py",
    "hackerman-pre-merge.py",
    "hackerman-integrity-check.py",
    "hackerman-pr726-merge-checklist.py",
    "hackerman-pr726-density-analyzer.py",
    "hackerman-tag-wave-close.py",
    "hackerman-wave1-shipment-receipt.py",
]
WAVE1_AGGREGATORS = [
    "hackerman-corpus-stats.py",
    "hackerman-attack-class-distribution.py",
    "hackerman-attack-class-inventory.py",
    "hackerman-attack-class-severity-matrix.py",
    "hackerman-audit-firm-coverage-matrix.py",
    "hackerman-language-stats.py",
    "hackerman-severity-stats.py",
    "hackerman-year-stats.py",
    "hackerman-domain-stats.py",
    "hackerman-target-repo-stats.py",
    "hackerman-contest-contributor-stats.py",
    "hackerman-growth-chart.py",
    "hackerman-health-dashboard.py",
    "hackerman-corpus-snapshot-html.py",
    "hackerman-corpus-diff.py",
    "hackerman-capability-adoption.py",
]
WAVE1_INSPECTION_PREVIEW = [
    "hackerman-record-quality.py",
    "hackerman-record-validate.py",
    "hackerman-record-provenance-audit.py",
    "hackerman-tier3-deep-attribution-analyzer.py",
    "hackerman-audit-firm-pdf-preview-extractor.py",
    "hackerman-audit-firm-pdf-url-sanity.py",
    "hackerman-reentrancy-pattern-extractor.py",
    "hackerman-detector-seed-extractor.py",
    "hackerman-detector-seed-per-language.py",
    "hackerman-cross-corpus-dupe-finder.py",
    "hackerman-corpus-subdir-acceptance-check.py",
    "hackerman-bug-class-shift-detector.py",
    "hackerman-nvd-verification-sweep.py",
    "hackerman-docs-cross-link-audit.py",
    "hackerman-proof-hardening.py",
]

OPERATOR_INDEX: OrderedDict[str, Any] = OrderedDict(
    [
        ("schema", "auditooor.hackerman_operator_index.v1"),
        ("purpose", "Compact machine-readable entrypoints for cold agent/operator pickup."),
        ("generated_from", "tools/hackerman-tooling-index.py"),
        ("refresh_command", "python3 tools/hackerman-tooling-index.py --format operator-json"),
        ("roadmap_status_command", "make capability-roadmap-status JSON=1"),
        (
            "canonical_docs",
            [
                "docs/HACKERMAN_MCP_TOOLING_INDEX.md",
                "docs/CODEX_HANDOFF_AND_RESUME_2026-05-16.md",
                "docs/AUDITOOOR_OPERATOR_PLAYBOOK_2026-05-16.md",
                "docs/VAULT_MCP_SERVER.md",
                "docs/MCP_AUDIT_AGENT_START.md",
            ],
        ),
        (
            "first_commands",
            [
                "bash tools/auditooor-session-start.sh ~/audits/<project>",
                "make v3-source-first-audit WS=~/audits/<project> TOP_N=25",
                "python3 tools/vault-mcp-server.py --call vault_brain_prime_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":8}'",
                "python3 tools/vault-mcp-server.py --call vault_exploit_queue_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":10}'",
                "make audit-hacker-logic-bridge WS=~/audits/<project>",
                "make capability-roadmap-status JSON=1",
            ],
        ),
        (
            "mcp_discovery_callables",
            [
                "vault_toolsite_context",
                "vault_resume_context",
                "vault_dispatch_context",
                "vault_engage_report_context",
                "vault_brain_prime_context",
                "vault_function_mindset",
                "vault_hacker_brief_for_lane",
            ],
        ),
        (
            "gap_probe_commands",
            [
                "make capability-roadmap-status JSON=1",
                "python3 tools/hackerman-capability-status.py --format json",
                "python3 tools/audit/external-recall-manifest.py select --repo-root /path/to/repo --repo-id owner/repo --attack-class <class> --limit 5 --json",
                "python3 tools/hackerman-backfill-proof-artifact-path.py --mine-proof-hardening-sidecar --dry-run --json-summary",
                "python3 tools/hackerman-backfill-solodit-years.py --dry-run --json-summary",
                "make hackerman-solodit-date-enrichment-queue LIMIT=50 JSON=1",
            ],
        ),
        (
            "intent_to_workflow_id",
            OrderedDict(
                [
                    ("fresh_session", "mcp-session-start"),
                    ("first_audit_pass", "v3-source-first-audit"),
                    ("roadmap_status", "capability-roadmap"),
                    ("cheap_provider_fanout", "provider-capacity-routing"),
                    ("bounded_recall", "vault-recall-packs"),
                    ("component_detector_pass", "make-audit"),
                    ("deep_audit_pass", "make-audit-deep"),
                    ("audit_deep_manifest_summary", "audit-deep-manifest-summary"),
                    ("brain_prime_lanes", "brain-prime"),
                    ("source_read_attack_hypotheses", "function-mindset-and-hacker-questions"),
                    ("corpus_refresh_or_query", "hackerman-etl-query"),
                    ("novel_vector_hypotheses", "hackerman-novel-vector-hypotheses"),
                    ("realworld_recall_gap_priorities", "realworld-recall-gap-priorities"),
                    ("multi_step_attack", "chained-attack-planning"),
                    ("predicate_yaml_lint", "predicate-yaml-lint"),
                    ("go_cosmos_bootstrap", "go-cosmos-engagement-bootstrap"),
                    ("high_critical_execution_bridge", "high-impact-execution-bridge"),
                    ("known_limitations", "known-limitations-burndown"),
                    ("handoff_closeout", "loop-finalization-check"),
                    ("submission_gate", "pre-submit-gates"),
                    # Lane 9 (Wave-6, 2026-05-19) — exploit-conversion intents
                    ("exploit_queue", "exploit-conversion-queue"),
                    ("what_to_prove_next", "exploit-conversion-queue"),
                    ("severity_oracle", "exploit-conversion-severity-scope-oracle"),
                    ("scope_oracle", "exploit-conversion-severity-scope-oracle"),
                    ("falsify_lead", "exploit-conversion-falsification"),
                    ("negative_control", "exploit-conversion-falsification"),
                    ("conversion_gate", "exploit-conversion-gate"),
                    ("conversion_loop", "exploit-conversion-loop"),
                    ("run_proof_workbench", "exploit-conversion-loop"),
                    ("cosmos_production_harness", "exploit-conversion-benchmark"),
                    ("mine_worker_artifacts", "agent-artifact-miner"),
                    ("provider_fanout", "provider-capacity-routing"),
                    ("kimi_minimax", "provider-capacity-routing"),
                ]
            ),
        ),
    ]
)


MANIFEST: list[dict[str, Any]] = [
    {
        "id": "v3-source-first-audit",
        "section": "V3 source-first audit",
        "summary": "Canonical first-run pass for a workspace; enforces source-first prerequisites, mines commit history, runs the audit/deep path, and leaves bounded recall surfaces before dispatch or proof work.",
        "tasks": [
            "v3 source first",
            "source-first audit",
            "first run audit",
            "one button audit",
            "start source first",
            "what do I prove next",
            "fresh workspace audit",
            "source-first first pass",
        ],
        "commands": [
            "bash tools/auditooor-session-start.sh ~/audits/<project>",
            "make v3-source-first-audit WS=~/audits/<project> TOP_N=25",
            "python3 tools/vault-mcp-server.py --call vault_brain_prime_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":8}'",
            "python3 tools/vault-mcp-server.py --call vault_exploit_queue_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":10}'",
        ],
        "callables": [
            "vault_brain_prime_context",
            "vault_exploit_queue_context",
            "vault_current_to_exploit_conversion_gate_context",
            "vault_toolsite_context",
        ],
    },
    {
        "id": "mcp-session-start",
        "section": "MCP session start",
        "summary": "Use this first in a fresh workspace to load the Layer-1 recall packs and write the freshness witness; vault_toolsite_context discovers the rest of the manifest in one call.",
        "tasks": [
            "start mcp session",
            "fresh agent start",
            "load memory",
            "write freshness witness",
            "session start recall",
        ],
        "commands": [
            "make session-start",
            "bash tools/auditooor-session-start.sh <workspace_path>",
            "make install-hooks",
            "make install-session-start-shim",
            "python3 tools/vault-mcp-server.py --call vault_toolsite_context --args '{\"task\":\"session start\",\"limit\":8}'",
        ],
        "callables": [
            "vault_resume_context",
            "vault_exploit_context",
            "vault_harness_context",
            "vault_knowledge_gap_context",
            "vault_toolsite_context",
        ],
    },
    {
        "id": "capability-roadmap",
        "section": "Capability roadmap and toolsite gaps",
        "summary": "Use this to see what remains after Hackerman V2. V3 is the active roadmap and focuses on exploit conversion: pre-filing judgment, queue-to-proof closure, corpus-to-hunter delivery, chain proof, and feedback loops.",
        "tasks": [
            "inspect capability roadmap",
            "inspect remaining work",
            "check hackerman status",
            "toolsite gaps",
            "capability status",
        ],
        "commands": [
            "sed -n '1,220p' docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md",
            "sed -n '1,220p' docs/HACKERMAN_MCP_CAPABILITY_ROADMAP_2026-05-15.md",
            "python3 tools/hackerman-tooling-index.py --format json",
            "python3 tools/hackerman-tooling-index.py --format operator-json",
            "python3 tools/vault-mcp-server.py --call vault_toolsite_context --args '{\"task\":\"start audit\",\"limit\":5}'",
            "make capability-roadmap-status JSON=1",
            "make capability-status WS=~/audits/<project>",
        ],
        "callables": [
            "vault_toolsite_context",
            "vault_dispatch_context",
            "vault_resume_context",
            "vault_knowledge_gap_context",
            "vault_function_mindset",
            "vault_hacker_brief_for_lane",
        ],
    },
    {
        "id": "provider-capacity-routing",
        "section": "Provider capacity, models, and cheap-driver routing",
        "summary": "Use this before burning Kimi/MiniMax tokens or after changing provider models. The report is model-aware: it records active/default model IDs, budget ceilings, recent dispatch telemetry grouped by provider+model, and current task-fit notes.",
        "tasks": [
            "provider capacity",
            "current kimi model",
            "current minimax model",
            "cheap llm fanout",
            "model upgrade calibration",
            "provider routing",
            "provider task fit",
        ],
        "commands": [
            "python3 tools/provider-capacity-report.py --print-json",
            "python3 tools/llm-calibration-log.py provider-assist",
            "python3 tools/llm-calibration-log.py stats --provider minimax --since 2026-05-17",
            "python3 tools/llm-calibration-log.py stats --provider kimi --since 2026-05-17",
            "python3 tools/vault-mcp-server.py --call vault_provider_capacity --args '{\"provider\":\"minimax\",\"limit\":8}'",
            "python3 tools/vault-mcp-server.py --call vault_llm_calibration --args '{\"provider\":\"minimax\",\"limit\":8}'",
        ],
        "callables": [
            "vault_provider_capacity",
            "vault_llm_calibration",
            "vault_toolsite_context",
        ],
    },
    {
        "id": "vault-recall-packs",
        "section": "Vault recall packs",
        "summary": "Use bounded MCP recall before raw vault scans or broad repo searches.",
        "tasks": [
            "ask mcp for memory",
            "recall memory",
            "resume context",
            "exploit memory",
            "harness memory",
            "knowledge gaps",
        ],
        "commands": [
            "python3 tools/vault-mcp-server.py --call vault_resume_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":4}'",
            "python3 tools/vault-mcp-server.py --call vault_exploit_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":8}'",
            "python3 tools/vault-mcp-server.py --call vault_harness_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":8}'",
            "python3 tools/vault-mcp-server.py --call vault_knowledge_gap_context --args '{\"status\":\"open\",\"limit\":8}'",
            "python3 tools/vault-mcp-server.py --call vault_route --args '{\"workspace_path\":\"~/audits/<project>\"}'",
        ],
        "callables": [
            "vault_resume_context",
            "vault_exploit_context",
            "vault_harness_context",
            "vault_knowledge_gap_context",
            "vault_route",
        ],
    },
    {
        "id": "make-audit",
        "section": "make audit",
        "summary": "Component detector pass; builds detector, memory, and bridge artifacts when rerunning or debugging one stage.",
        "tasks": [
            "start audit",
            "run make audit",
            "component detector pass",
            "rerun detector pass",
            "detector memory bridge",
        ],
        "commands": [
            "make audit WS=~/audits/<project>",
        ],
        "callables": [
            "vault_engage_report_context",
            "vault_detector_action_graph_context",
            "vault_hacker_brief_for_lane",
        ],
    },
    {
        "id": "make-audit-deep",
        "section": "make audit-deep",
        "summary": "Opt-in deep pass for extra engines, conversion-loop handoff, and per-workspace Hackerman novel-vector artifacts.",
        "tasks": [
            "deep audit",
            "audit deep",
            "run extra engines",
            "deeper hypothesis generation",
            "conversion loop",
            "proof workbench",
            "novel vector artifact",
        ],
        "commands": [
            "make audit-deep WS=~/audits/<project>",
            "DEEP_PROFILE=all make audit-deep WS=~/audits/<project>",
            "make audit-deep-novel-vectors WS=~/audits/<project>",
            "make exploit-conversion-loop WS=~/audits/<project> TOP_N=10",
        ],
        "callables": [
            "vault_resume_context",
            "vault_exploit_context",
            "vault_harness_context",
            "vault_audit_deep_manifest_summary",
        ],
    },
    {
        "id": "audit-deep-manifest-summary",
        "section": "Audit-deep manifest summarizer",
        "summary": "Read-only compact summary of audit-deep manifest/report outputs so agents can inspect deep-run state without opening large artifacts.",
        "tasks": [
            "audit deep manifest summary",
            "summarize audit deep manifest",
            "deep audit handoff status",
            "audit deep bridge outputs",
        ],
        "commands": [
            "make audit-deep-manifest WS=~/audits/<project> JSON=1",
            "python3 tools/audit-deep-manifest.py --workspace ~/audits/<project> --json",
            "python3 tools/vault-mcp-server.py --call vault_audit_deep_manifest_summary --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":8}'",
        ],
        "callables": [
            "vault_audit_deep_manifest_summary",
            "vault_toolsite_context",
        ],
    },
    {
        "id": "brain-prime",
        "section": "Brain prime",
        "summary": "Generate the Brain Priming Report plus the .auditooor/brain_prime_receipt.json receipt so the workspace has ranked first-hunt lanes before worker dispatch.",
        "tasks": [
            "brain prime",
            "brain-prime",
            "prime the brain",
            "where to hunt first",
            "recommended hunt lanes",
            "brain priming report",
        ],
        "commands": [
            "make brain-prime WS=~/audits/<project>",
            "make brain-prime-dry-run WS=~/audits/<project>",
            "python3 tools/brain-prime.py --workspace ~/audits/<project> --target-repo owner/repo",
            "sed -n '1,220p' docs/BRAIN_PRIMING.md",
        ],
        "callables": [
            "vault_brain_prime_context",
            "vault_hacker_brief_for_lane",
            "vault_function_mindset",
            "vault_attack_class_evidence",
        ],
    },
    {
        "id": "audit-hacker-logic-bridge",
        "section": "make audit-hacker-logic-bridge",
        "summary": "Fan fresh detector hits into attacker graphs and proof-obligation queues.",
        "tasks": [
            "turn detector hit into proof tasks",
            "detector to hacker logic",
            "proof obligation queue",
            "attacker graph",
        ],
        "commands": [
            "make audit-hacker-logic-bridge WS=~/audits/<project>",
        ],
        "callables": [
            "vault_engage_report_context",
            "vault_detector_action_graph_context",
            "vault_hacker_brief_for_lane",
        ],
    },
    {
        "id": "originality-dupe-preproof",
        "section": "Originality / dupe pre-proof recall",
        "summary": "Before expensive proof hardening, run bounded prior-art and duplicate recall, then run the originality-before-proof gate for an enforceable pre-proof decision.",
        "tasks": [
            "originality before proof",
            "originality before proof gate",
            "dupe before proof",
            "prior art before proof hardening",
            "pre proof originality",
            "preproof duplicate recall",
            "check prior audits",
            "avoid duplicate proof work",
        ],
        "commands": [
            "python3 tools/vault-mcp-server.py --call vault_originality_context --args '{\"workspace_path\":\"~/audits/<project>\",\"keywords\":[\"<candidate-term>\"],\"limit\":8}'",
            "python3 tools/vault-mcp-server.py --call vault_dupe_rejection_context --args '{\"workspace_path\":\"~/audits/<project>\",\"bug_class\":\"<bug-class>\",\"limit\":8}'",
            "python3 tools/vault-mcp-server.py --call vault_originality_before_proof_gate --args '{\"workspace_path\":\"~/audits/<project>\",\"draft_path\":\"<draft.md>\",\"max_evidence\":12}'",
            "python3 tools/originality-before-proof-gate.py <draft.md> --workspace ~/audits/<project> --json",
            "python3 tools/dedup-grep.py ~/audits/<project> --candidate <candidate.md> --json",
            "python3 tools/cross-workspace-duplicate-check.py <draft.md> --workspace <project> --json",
        ],
        "callables": [
            "vault_originality_context",
            "vault_dupe_rejection_context",
            "vault_originality_before_proof_gate",
            "vault_toolsite_context",
        ],
    },
    {
        "id": "high-impact-execution-bridge",
        "section": "High-impact execution bridge",
        "summary": "Bridge High/Critical invariant rows into scaffold attempts, handoff briefs, and poc-execution-record commands; this is execution readiness, not proof.",
        "tasks": [
            "execution bridge",
            "high impact execution",
            "high critical harness handoff",
            "scaffold to poc execution record",
            "proof execution handoff",
            "cosmos evidence pack",
            "cosmos runtime marker evidence",
        ],
        "commands": [
            "make high-impact-execution-bridge WS=~/audits/<project> JSON=1",
            "make high-impact-execution-bridge WS=~/audits/<project> ROW=<row-id> JSON=1",
            "python3 tools/vault-mcp-server.py --call vault_high_impact_execution_bridge_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":8}'",
            "python3 tools/vault-mcp-server.py --call vault_cosmos_evidence_pack_context --args '{\"exec_record_path\":\"<path/to/cosmos_production_harness_exec.json>\",\"limit\":8}'",
        ],
        "callables": [
            "vault_high_impact_execution_bridge_context",
            "vault_poc_execution_record_context",
            "vault_cosmos_evidence_pack_context",
            "vault_harness_context",
        ],
    },
    {
        "id": "control-plane-ready",
        "section": "Control-plane-ready Phase A preflight",
        "summary": "Dispatch preflight for MCP self-test, brain-prime receipt readiness, strict V3 worker-packet evidence, high-impact bridge availability, and optional strict finalization evidence; this is not proof or submit readiness.",
        "tasks": [
            "control plane ready",
            "control-plane-ready",
            "dispatch preflight",
            "before worker dispatch",
            "brain prime readiness",
            "mcp self test",
            "high impact bridge availability",
            "phase a preflight",
            "strict dispatch gate",
        ],
        "commands": [
            "make control-plane-ready WS=~/audits/<project> JSON=1",
            "make control-plane-ready WS=~/audits/<project> JSON=1 STRICT=1",
            "make v3-worker-packet WS=~/audits/<project> SEVERITY=High STRICT=1",
            "python3 tools/control-plane-ready-preflight.py --workspace ~/audits/<project> --json",
            "python3 tools/control-plane-ready-preflight.py --workspace ~/audits/<project> --json --strict",
            "python3 tools/vault-mcp-server.py --call vault_toolsite_context --args '{\"task\":\"control plane ready dispatch preflight\",\"limit\":5}'",
        ],
        "callables": [
            "vault_toolsite_context",
            "vault_brain_prime_context",
            "vault_high_impact_execution_bridge_context",
        ],
    },
    {
        "id": "function-mindset-and-hacker-questions",
        "section": "Function mindset and hacker questions",
        "summary": "Use this when reading source or ranking a target function; it renders corpus-backed attack hypotheses, function-signature shape, and lane-auto-invoked function-shape attack evidence proof obligations. The Claude Read hook surfaces a bounded systemMessage by default; raw JSON is available with AUDITOOOR_PRE_SOURCE_READ_RAW_JSON=1.",
        "tasks": [
            "get function mindset",
            "hacker questions",
            "pre source read",
            "source read injection",
            "rank attack classes",
            "function shape",
            "before source read",
            "lane brief auto-invoke",
            "function signature shape",
        ],
        "commands": [
            "make pre-source-read-inject SOURCE=<path/to/source.go> WORKSPACE=~/audits/<project> TARGET_REPO=owner/repo",
            "bash tools/claude-pre-source-read-hook.sh <path/to/source.go>",
            "AUDITOOOR_PRE_SOURCE_READ_RAW_JSON=1 bash tools/claude-pre-source-read-hook.sh <path/to/source.go>",
            "make hacker-brief WS=~/audits/<project> LANE=<id> FILES='src/A.sol,src/B.sol'",
            "python3 tools/vault-mcp-server.py --call vault_function_mindset --args '{\"target_repo\":\"owner/repo\",\"file_path\":\"src/A.sol\",\"function_signature\":\"function foo() external\"}'",
            "python3 tools/vault-mcp-server.py --call vault_function_signature_shape --args '{\"file_path\":\"src/A.sol\",\"function_signature\":\"function foo() external\"}'",
            "python3 tools/vault-mcp-server.py --call vault_function_shape_attack_evidence --args '{\"workspace_path\":\"~/audits/<project>\",\"file_path\":\"src/A.sol\",\"function_signature\":\"function foo() external\"}'",
            "python3 tools/vault-mcp-server.py --call vault_hacker_brief_for_lane --args '{\"workspace_path\":\"~/audits/<project>\",\"lane_id\":\"<lane-id>\",\"files\":[\"src/A.sol\"],\"limit\":20}'",
        ],
        "callables": [
            "vault_function_mindset",
            "vault_function_signature_shape",
            "vault_function_shape_attack_evidence",
            "vault_hacker_brief_for_lane",
            "vault_attack_class_evidence",
        ],
    },
    {
        "id": "hackerman-etl-query",
        "section": "Hackerman ETL / query tools",
        "summary": "Refresh the curated attacker-memory corpus, rebuild indices, and derive chain/predicate/gap views; the chain-candidates and chain-unify payload sidecars keep corpus walks and expensive chain DFS off the MCP path. proof_artifact_path stays available for downstream proof linking, but proof-artifact feedback is report-first: index, promotion-review, status-only-review, and reconciliation commands surface evidence links for operator review and must not bulk-apply blocked candidates. Wave-4 W4.1 (`hackerman-cve-ghsa-delta-watch`) polls NVD/GHSA for tier-1 advisory deltas and W4.2 (`hackerman-etl-post-mortem`) mines public exploit post-mortems into tier-2 records.",
        "tasks": [
            "refresh hackerman corpus",
            "query hackerman",
            "cross language analogues",
            "go cosmos coverage",
            "proof artifact feedback",
            "proof artifact index",
            "Solodit unknown-year enrichment queue",
            "exploit predicates",
            "chain candidates",
        ],
        "commands": [
            "make hackerman-refresh DRY_RUN=1",
            "make hackerman-refresh",
            "make hackerman-index",
            "make hackerman-chain-candidates-sidecar",
            "make hackerman-chain-unify-sidecar",
            "make hackerman-detector-relationships-sidecar",
            "make hackerman-sidecar-refresh-check CHECK=1 JSON=1",
            "make hackerman-chain-candidates LIMIT=20",
            "make hackerman-exploit-predicates",
            "make hackerman-detector-relationships ENGAGE_REPORT=~/audits/<project>/engage_report.json LIMIT=10",
            "make hackerman-go-cosmos-inventory",
            "make hackerman-go-cosmos-stage-imports OUT_DIR=/private/tmp/hackerman-go-cosmos-stage LIMIT=20",
            "make hackerman-audit-firm-report-class-backfill JSON=1",
            "make hackerman-backfill-proof-artifact-path DRY_RUN=1 JSON=1",
            "make hackerman-solodit-date-enrichment-queue LIMIT=50 JSON=1",
            "make hackerman-cve-ghsa-delta-watch APPLY=1",
            "make hackerman-etl-post-mortem SOURCE=rekt CACHE_DIR=cache/post-mortem",
            "make capability-roadmap-status JSON=1",
            "make capability-status WS=~/audits/<project>",
            "python3 tools/hackerman-etl-refresh.py --dry-run --workspace ~/audits/<project>",
            "python3 tools/hackerman-index-build.py",
            "python3 tools/hackerman-cross-language-analogues.py --tags-dir audit/corpus_tags/tags --out audit/corpus_tags/derived/cross_language_analogues.jsonl",
            "python3 tools/hackerman-chain-candidates-sidecar.py --check",
            "python3 tools/hackerman-chain-unify-sidecar.py --check",
            "python3 tools/hackerman-detector-relationships-sidecar.py --check",
            "python3 tools/hackerman-sidecar-refresh-check.py --check --json",
            "python3 tools/hackerman-chain-candidates.py --limit 20",
            "python3 tools/hackerman-exploit-predicates.py --tag-dir audit/corpus_tags/tags --json",
            "python3 tools/hackerman-detector-relationships.py --engage-report ~/audits/<project>/engage_report.json --limit 10 --json",
            "python3 tools/hackerman-go-cosmos-inventory.py --json",
            "python3 tools/hackerman-go-cosmos-stage-imports.py --out-dir /private/tmp/hackerman-go-cosmos-stage --json-summary",
            "python3 tools/hackerman-backfill-audit-firm-report-class.py --json-summary",
            "make hackerman-proof-artifact-index ROOTS=~/audits OUT=audit/corpus_tags/derived/proof_artifact_index.jsonl REPORT=reports/proof_artifact_index.md JSON=1",
            "make hackerman-proof-artifact-accepted-writeback OUT=audit/corpus_tags/derived/proof_artifact_accepted_writeback.jsonl",
            "make hackerman-proof-artifact-promotion-review PROOF_ARTIFACT_INDEX=audit/corpus_tags/derived/proof_artifact_index.jsonl OUT=reports/proof_artifact_promotion_review.jsonl MISSING_RECORD_IMPORT_QUEUE=reports/proof_artifact_missing_record_import_queue.jsonl INCLUDE_BLOCKED=1 JSON=1",
            "make hackerman-proof-artifact-status-only-review PROOF_ARTIFACT_INDEX=audit/corpus_tags/derived/proof_artifact_index.jsonl OUT=reports/proof_artifact_status_only_review.jsonl JSON=1",
            "make hackerman-proof-artifact-status-only-reconciliation PROOF_ARTIFACT_INDEX=audit/corpus_tags/derived/proof_artifact_index.jsonl OUT=reports/proof_artifact_status_only_reconciliation.jsonl JSON=1",
            "make hackerman-proof-artifact-status-only-promotion-review STATUS_ONLY_RECONCILIATION=reports/proof_artifact_status_only_reconciliation.jsonl OUT=reports/proof_artifact_promotion_review_status_only_resolved.jsonl JSON=1",
            "python3 tools/hackerman-backfill-proof-artifact-path.py --dry-run --json-summary",
            "python3 tools/hackerman-solodit-date-enrichment-queue.py --limit 50 --json-summary",
            "make hacker-brief WS=~/audits/<project> LANE=<id> FILES='src/A.sol,src/B.sol'",
            "python3 tools/vault-mcp-server.py --call vault_hacker_brief_for_lane --args '{\"workspace_path\":\"~/audits/<project>\",\"lane_id\":\"<lane-id>\",\"files\":[\"src/A.sol\"],\"limit\":20}'",
            "python3 tools/vault-mcp-server.py --call vault_function_mindset --args '{\"target_repo\":\"owner/repo\",\"file_path\":\"src/A.sol\",\"function_signature\":\"function foo() external\"}'",
            "python3 tools/vault-mcp-server.py --call vault_attack_class_evidence --args '{\"attack_class\":\"reentrancy\",\"min_outcome_weight\":0}'",
            "python3 tools/vault-mcp-server.py --call vault_cross_language_pattern_lift --args '{\"source_language\":\"solidity\",\"target_language\":\"go\",\"limit\":10}'",
            "python3 tools/vault-mcp-server.py --call vault_hackerman_chain_candidates --args '{\"limit\":20}'",
            "python3 tools/vault-mcp-server.py --call vault_hackerman_exploit_predicates --args '{\"limit\":20}'",
            "python3 tools/vault-mcp-server.py --call vault_hackerman_go_cosmos_inventory --args '{}'",
            "python3 tools/vault-mcp-server.py --call vault_proof_artifact_index_context --args '{\"engagement\":\"<project>\",\"confidence\":\"high\",\"limit\":10}'",
        ],
        "callables": [
            "vault_hacker_brief_for_lane",
            "vault_function_mindset",
            "vault_attack_class_evidence",
            "vault_cross_language_pattern_lift",
            "vault_hackerman_chain_candidates",
            "vault_hackerman_detector_relationships",
            "vault_hackerman_exploit_predicates",
            "vault_hackerman_go_cosmos_inventory",
            "vault_proof_artifact_index_context",
        ],
    },
    {
        "id": "hackerman-novel-vector-hypotheses",
        "section": "Hackerman advisory novel-vector hypotheses",
        "summary": "Generate advisory-only residual attack-vector hypotheses from Hackerman corpus analogues and typed predicate state; this seeds local source review and does not claim exploitability, severity, or submission readiness.",
        "tasks": [
            "novel vector hypotheses",
            "novel-vector hypotheses",
            "untried attack vector",
            "residual attack class",
            "same-class variant advisory",
            "advisory corpus analogue",
            "target repo novel vector",
            "shape analogue hypothesis",
            "predicate bridge hypothesis",
        ],
        "commands": [
            "make hackerman-novel-vector-gen",
            "make hackerman-novel-vector-gen JSON=1 LIMIT=10",
            "make hackerman-novel-vector-gen TARGET_REPO=owner/repo JSON=1 MAX_TARGETS=50",
            "make hackerman-novel-vector-gen TARGET_REPO=owner/repo JSON=1 SAME_CLASS_VARIANTS=1",
            "make audit-deep-novel-vectors WS=~/audits/<project> TARGET_REPO=owner/repo JSON=1",
            "make hackerman-novel-vector-gen JSONL=1 LIMIT=20",
            "make hackerman-novel-vector-gen JSON=1 ALL_TARGETS=1",
            "make hackerman-novel-vector-gen OUT=agent_outputs/novel_vectors.jsonl LIMIT=20",
            "python3 tools/hackerman-novel-vector-gen.py --tag-dir audit/corpus_tags/tags",
            "python3 tools/hackerman-novel-vector-gen.py --tag-dir audit/corpus_tags/tags --json",
            "python3 tools/hackerman-novel-vector-gen.py --tag-dir audit/corpus_tags/tags --target-repo owner/repo --max-targets 50 --json",
            "python3 tools/hackerman-novel-vector-gen.py --tag-dir audit/corpus_tags/tags --target-repo owner/repo --same-class-variants --json",
            "python3 tools/hackerman-novel-vector-gen.py --tag-dir audit/corpus_tags/tags --all-targets --json",
            "python3 tools/hackerman-novel-vector-gen.py --tag-dir audit/corpus_tags/tags --out agent_outputs/novel_vectors.jsonl",
            "python3 tools/vault-mcp-server.py --call vault_hackerman_novel_vector_context --args '{\"target_repo\":\"owner/repo\",\"language\":\"go\",\"domain\":\"consensus\",\"limit\":10,\"max_targets\":50}'",
        ],
        "callables": [
            "vault_hackerman_novel_vector_context",
            "vault_attack_class_evidence",
            "vault_hackerman_chain_candidates",
            "vault_hackerman_exploit_predicates",
            "vault_function_mindset",
        ],
    },
    {
        "id": "chained-attack-planning",
        "section": "Chained-attack planning and multi-step analysis",
        "summary": "Use this when assessing whether a single-step finding chains into a multi-step attack; surfaces vault_chained_attack_plan_context plans, candidate chains from corpus, and per-step exploit predicates so the orchestrator can audit predicate coverage before drafting.",
        "tasks": [
            "chained attack planning",
            "multi-step attack analysis",
            "exploit predicate audit",
            "audit chain plan",
            "predicate coverage check",
            "multi step exploit",
        ],
        "commands": [
            "python3 tools/vault-mcp-server.py --call vault_chained_attack_plan_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":5}'",
            "python3 tools/vault-mcp-server.py --call vault_hackerman_chain_candidates --args '{\"limit\":20}'",
            "python3 tools/vault-mcp-server.py --call vault_hackerman_exploit_predicates --args '{\"limit\":20}'",
            "make hackerman-chain-candidates LIMIT=20",
            "make hackerman-exploit-predicates",
        ],
        "callables": [
            "vault_chained_attack_plan_context",
            "vault_hackerman_chain_candidates",
            "vault_hackerman_exploit_predicates",
            "vault_attack_class_evidence",
        ],
    },
    {
        "id": "predicate-yaml-lint",
        "section": "Predicate YAML lint",
        "summary": "Advisory lint for DSL predicate YAML keys and shapes that would otherwise surface as predicate-engine runtime warnings; strict mode is opt-in for cleanup gates.",
        "tasks": [
            "predicate yaml lint",
            "lint predicate yaml",
            "dsl predicate warnings",
            "predicate engine warnings",
            "unsupported predicate keys",
            "stringified predicate entries",
            "strict predicate lint",
        ],
        "commands": [
            "make predicate-yaml-lint",
            "make predicate-yaml-lint PATHS=reference/patterns.dsl/<pattern>.yaml",
            "make predicate-yaml-lint PATHS=reference/patterns.dsl REPORT=reports/predicate_yaml_lint.md",
            "make predicate-yaml-lint PATHS=reference/patterns.dsl STRICT=1",
            "python3 tools/predicate-yaml-lint.py reference/patterns.dsl --report reports/predicate_yaml_lint.md",
            "python3 tools/predicate-yaml-lint.py reference/patterns.dsl --strict",
        ],
        "callables": [
            "vault_toolsite_context",
        ],
    },
    {
        "id": "go-cosmos-engagement-bootstrap",
        "section": "Go / Cosmos engagement bootstrap",
        "summary": "Use this when opening a new Go / Cosmos-SDK / cometbft / IBC / Tendermint engagement; surfaces the cross-language analogue lift and corpus-derived go-cosmos coverage inventory so the orchestrator can spot lanes the Solidity-heavy corpus would otherwise miss.",
        "tasks": [
            "new Go engagement bootstrap",
            "new Cosmos engagement bootstrap",
            "go cosmos coverage",
            "cosmos sdk engagement start",
            "cross language analogue lookup",
            "cometbft hunt bootstrap",
        ],
        "commands": [
            "python3 tools/vault-mcp-server.py --call vault_hackerman_go_cosmos_inventory --args '{}'",
            "python3 tools/vault-mcp-server.py --call vault_cross_language_pattern_lift --args '{\"source_language\":\"solidity\",\"target_language\":\"go\",\"limit\":10}'",
            "make hackerman-go-cosmos-inventory",
            "make hackerman-go-cosmos-stage-imports OUT_DIR=/private/tmp/hackerman-go-cosmos-stage LIMIT=20",
            "make cosmos-production-harness-plan POC_DIR=~/audits/<project>/poc-tests/<lead> CLAIM_FILE=~/audits/<project>/submissions/staging/<draft.md>",
            "make cosmos-production-harness-tasks POC_DIR=~/audits/<project>/poc-tests/<lead> CLAIM_FILE=~/audits/<project>/submissions/staging/<draft.md> FORMAT=markdown",
            "make cosmos-production-harness-exec WS=~/audits/<project> POC_DIR=~/audits/<project>/poc-tests/<lead> CANDIDATE_ID=<lead> CMD='go test ./... -run <TestName> -count=1 -v' REQUIRE_RUNTIME_MARKERS=1 TARGET_APP_CHAIN=dydx PRINT_JSON=1",
            "make cosmos-production-harness-evidence-pack EXEC_RECORD=~/audits/<project>/poc_execution/<lead>/cosmos_production_harness_exec.json OUT_MD=~/audits/<project>/poc_execution/<lead>/COSMOS_PRODUCTION_HARNESS_EVIDENCE_PACK.md",
            "python3 tools/hackerman-cross-language-analogues.py --tags-dir audit/corpus_tags/tags --out audit/corpus_tags/derived/cross_language_analogues.jsonl",
            "python3 tools/cosmos-production-harness-plan.py --poc-dir ~/audits/<project>/poc-tests/<lead> --claim-file ~/audits/<project>/submissions/staging/<draft.md>",
            "python3 tools/cosmos-production-harness-tasks.py --poc-dir ~/audits/<project>/poc-tests/<lead> --claim-file ~/audits/<project>/submissions/staging/<draft.md> --format markdown",
            "python3 tools/cosmos-production-harness-evidence-pack.py --exec-record ~/audits/<project>/poc_execution/<lead>/cosmos_production_harness_exec.json --out-md ~/audits/<project>/poc_execution/<lead>/COSMOS_PRODUCTION_HARNESS_EVIDENCE_PACK.md",
        ],
        "callables": [
            "vault_hackerman_go_cosmos_inventory",
            "vault_cross_language_pattern_lift",
            "vault_attack_class_evidence",
            "vault_hackerman_chain_candidates",
        ],
    },
    {
        "id": "external-recall-measurement",
        "section": "External recall measurement",
        "summary": "Build and validate external-repo recall manifests so the real-world recall scoreboard measures generalization beyond internal fixtures. Manifests may carry `repo_root` plus `solc_version` / `compiler_version`; the scorer uses that compiler via `SOLC_VERSION` without changing global solc-select state.",
        "tasks": [
            "external recall manifest",
            "external repo recall",
            "real world recall scoreboard",
            "measure detector generalization",
            "close external repo recall gap",
        ],
        "commands": [
            "make external-recall-select REPO_ROOT=/path/to/repo REPO_ID=owner/repo ATTACK_CLASS=<class> LIMIT=5 JSON=1",
            "python3 tools/audit/external-recall-manifest.py select --repo-root /path/to/repo --repo-id owner/repo --attack-class <class> --limit 5 --json",
            "make external-recall-manifest REPO_ROOT=/path/to/repo REPO_ID=owner/repo ATTACK_CLASS=<class> OUT=reports/external_recall_samples.json JSON=1",
            "python3 tools/audit/external-recall-manifest.py build --repo-root /path/to/repo --repo-id owner/repo --attack-class <class> --out reports/external_recall_samples.json --json",
            "python3 tools/audit/external-recall-manifest.py validate reports/external_recall_samples.json --json",
            "python3 tools/audit/realworld-recall-scoreboard.py --external-manifest reports/external_recall_samples.json --external-only",
            "cp reports/realworld_recall_<slice>/realworld_recall_scoreboard.json reports/realworld_recall_scoreboard_external_<slice>.json",
            "make realworld-recall-drilldown QUEUE=reports/realworld_recall_work_queue.jsonl ATTACK_CLASS=<class> JSON=1",
        ],
        "callables": [
            "vault_toolsite_context",
        ],
    },
    {
        "id": "realworld-recall-gap-priorities",
        "section": "Real-world recall gap priorities",
        "summary": "Read-only ranking of real-world recall gaps from scoreboard/manifests so workers can pick detector-generalization work with strongest external evidence first. The work queue auto-discovers `reports/external_recall_manifest_quality*.json` by default, emits `provider_dispatch_ready`, `workability_status`, `workability_blockers`, `quality_report_paths`, and summary counters so Kimi/MiniMax fanout only receives rows that can plausibly close. Use `--no-auto-quality-reports` only for regression/debug runs that intentionally reproduce the old raw queue.",
        "tasks": [
            "realworld recall gap priorities",
            "recall gap prioritizer",
            "realworld recall drilldown",
            "recall drilldown packet",
            "prioritize real world recall gaps",
            "detector generalization priorities",
            "provider dispatch ready rows",
            "workability blockers",
        ],
        "commands": [
            "python3 tools/audit/realworld-recall-gap-prioritizer.py --scoreboard reports/realworld_recall_scoreboard.json --out-json reports/realworld_recall_gap_priorities.json --out-md reports/realworld_recall_gap_priorities.md",
            "make realworld-recall-work-queue OUT=reports/realworld_recall_work_queue.jsonl JSON=1",
            "python3 tools/audit/realworld-recall-work-queue.py --priorities reports/realworld_recall_gap_priorities.json --out reports/realworld_recall_work_queue_raw.jsonl --no-auto-quality-reports --json-summary",
            "make realworld-recall-drilldown QUEUE=reports/realworld_recall_work_queue.jsonl JSON=1",
            "python3 tools/audit/realworld-recall-drilldown.py --queue reports/realworld_recall_work_queue.jsonl --attack-class <class> --json",
            "python3 tools/vault-mcp-server.py --call vault_realworld_recall_gap_priorities --args '{\"limit\":10}'",
            "python3 tools/vault-mcp-server.py --call vault_realworld_recall_gap_priorities --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":10}'",
        ],
        "callables": [
            "vault_realworld_recall_gap_priorities",
            "vault_toolsite_context",
        ],
    },
    {
        "id": "known-limitations-burndown",
        "section": "Known-limitations burndown",
        "summary": "Use this to inspect active known limitations, harness/memory blockers, and closure queues before choosing capability work.",
        "tasks": [
            "inspect known limitations",
            "known limitation burndown",
            "known limitations status",
            "harness memory status",
            "capability blockers",
        ],
        "commands": [
            "make known-limitations-dispatch JSON=1",
            "make known-limitations-harness-memory-status JSON=1",
            "make known-limitations-burndown WS=~/audits/<project> JSON=1",
            "make capability-roadmap-status JSON=1",
            "make capability-status WS=~/audits/<project>",
        ],
        "callables": [
            "vault_knowledge_gap_context",
            "vault_harness_context",
            "vault_resume_context",
        ],
    },
    {
        "id": "finalization-manifest",
        "section": "Finalization manifest",
        "summary": "Build or inspect the bounded closeout manifest before loop-finalization-check so slice evidence is explicit and reusable.",
        "tasks": [
            "finalization manifest",
            "build finalization manifest",
            "inspect current finalization manifest",
            "manifest before finalization check",
            "collect slice closeout manifest",
        ],
        "commands": [
            "python3 tools/finalization-manifest.py --workspace ~/audits/<project> --json",
            "python3 tools/finalization-manifest.py --workspace ~/audits/<project> --out /tmp/finalization_manifest.json --json",
            "python3 tools/vault-mcp-server.py --call vault_finalization_manifest_context --args '{\"workspace_path\":\"~/audits/<project>\"}'",
            "python3 tools/vault-mcp-server.py --call vault_toolsite_context --args '{\"task\":\"finalization manifest\",\"limit\":5}'",
        ],
        "callables": [
            "vault_finalization_manifest_context",
            "vault_toolsite_context",
        ],
    },
    {
        "id": "loop-finalization-check",
        "section": "Loop finalization gate",
        "summary": "Validate per-slice closeout manifests before handoff or closure.",
        "tasks": [
            "finalize a loop",
            "loop finalize",
            "slice closeout",
            "check loop artifacts",
            "agent outputs collected",
        ],
        "commands": [
            "make loop-finalization-check MANIFEST=<path/to/manifest.json>",
            "python3 tools/loop-finalization-check.py --manifest <path/to/manifest.json> --json",
        ],
        "callables": [
            "vault_loop_finalization_check",
        ],
    },
    {
        "id": "wave4-capability-tools",
        "section": "Wave-4 capability tools",
        "summary": "Curated map of the Wave-4 capability uplift tools under `tools/audit/` (plus the two deep-engine helpers under `tools/`). Each row gives the tool path, its one-line purpose, and how it is invoked: a dedicated `make` target, a direct CLI run, or an `make audit-deep` pipeline stage. These tools cover differential testing, capability-readiness reporting, bug-class prioritisation, invariant-harness generation, FP/TP feedback scoring, cross-session memory carry, corpus-freshness monitoring, precompile differential exec, detector catch-rate backtesting, and deep-engine output parsing.",
        "tasks": [
            "wave-4 capability tools",
            "differential test runner",
            "capability readiness dashboard",
            "bug class prioritizer",
            "invariant harness generator",
            "fp tp feedback loop",
            "session memory carry",
            "mcp corpus freshness monitor",
            "precompile differential engine",
            "detector catch rate backtest",
            "deep engine output parse",
            "universal fp runner",
            "list wave4 tools",
        ],
        "commands": [
            "# differential-test-runner.py - compare two source trees (upstream vs fork) for security-relevant divergences. CLI only.",
            "python3 tools/audit/differential-test-runner.py --upstream <upstream-tree> --fork <fork-tree> --language go --out <report.json>",
            "# capability-readiness-dashboard.py (Lane W4.11) - GREEN/YELLOW/RED readiness per capability across exists / wired / tested / exercised axes.",
            "make capability-readiness",
            "make capability-readiness JSON=1 STRICT=1",
            "python3 tools/audit/capability-readiness-dashboard.py --json",
            "# bug-class-prioritizer.py - rank attack classes to hunt first for a target profile. CLI only.",
            "python3 tools/audit/bug-class-prioritizer.py --profile <profile> --taxonomy <taxonomy>",
            "# invariant-harness-generator.py (W4.6) - generate a baseline echidna/medusa invariant harness + configs for a workspace.",
            "make invariant-harness-gen WS=~/audits/<project>",
            "python3 tools/audit/invariant-harness-generator.py ~/audits/<project> --contract <name> --force",
            "# fp_tp_feedback_loop.py (Lane W4.7) - score universal-FP shapes by precision vs the verdict ledger.",
            "make fp-tp-feedback-loop LEDGER=<verdict-ledger.jsonl>",
            "python3 tools/audit/fp_tp_feedback_loop.py --ledger <verdict-ledger.jsonl> --runner-output <runner.json>",
            "# session-memory-carry.py - carry an audit session's learnings forward into the vault. CLI only.",
            "python3 tools/audit/session-memory-carry.py --workspace ~/audits/<project> --json",
            "python3 tools/audit/session-memory-carry.py --sync-all-workspaces",
            "# mcp-corpus-freshness-monitor.py - per-MCP-callable corpus freshness monitor; STRICT=1 fails on AGING/STALE segments.",
            "make mcp-freshness",
            "make mcp-freshness STRICT=1",
            "python3 tools/audit/mcp-corpus-freshness-monitor.py --print",
            "# precompile-differential-engine.py (W4.11) - real precompile differential exec engine; invoked by a11-precompile-diff when UPSTREAM+FORK point at two Rust trees.",
            "make a11-precompile-diff WS=~/audits/<project> UPSTREAM=<revm-tree> FORK=<base-azul-tree>",
            "python3 tools/audit/precompile-differential-engine.py --upstream <revm-tree> --fork <base-azul-tree> --inputs <inputs-dir> --out <report.json>",
            "# detector-catch-rate-backtest.py - honest catch-rate backtest of the auditooor detector roster against the corpus. CLI only.",
            "python3 tools/audit/detector-catch-rate-backtest.py --patterns-dir <patterns-dir> --output <report.json>",
            "# deep-engine-output-parse.py - parse deep-engine runner artifacts into a structured findings summary; also a make audit-deep pipeline stage.",
            "make deep-engine-output-parse WS=~/audits/<project>",
            "python3 tools/deep-engine-output-parse.py --workspace ~/audits/<project>",
            "# universal_fp_runner.py - fire universal-FP fingerprints (FP-01..FP-06) against a workspace; wired as a make audit-deep pipeline stage.",
            "make wave3-fp-runner WS=~/audits/<project>",
            "python3 tools/audit/universal_fp_runner.py --workspace ~/audits/<project> --output <out.json> --markdown-output <out.md>",
        ],
        "callables": [],
    },
    {
        "id": "pre-submit-gates",
        "section": "Pre-submit gates",
        "summary": "Run the strict filing gate before paste-ready or submission-bound claims leave the workspace; the HIGH+ MCP wrapper now includes bounded severity-calibration output and only blocks on deterministic overclaim findings.",
        "tasks": [
            "check submission gates",
            "pre submit check",
            "high plus gate",
            "high+ submission gate",
            "mcp submission gate",
            "live hardening gate",
            "paste ready gate",
            "submission quality",
            "filing proof quality",
            "high critical severity calibration",
            "severity axis report",
        ],
        "commands": [
            "bash tools/pre-submit-check.sh <draft.md>",
            "python3 tools/high-plus-submission-gate.py <draft.md> --workspace ~/audits/<project> --severity High --json",
            "python3 tools/vault-mcp-server.py --call vault_high_plus_submission_gate --args '{\"draft_path\":\"<draft.md>\",\"workspace_path\":\"~/audits/<project>\",\"severity\":\"High\"}'",
            "python3 tools/control-test-discipline-check.py <draft.md> --strict --json",
            "python3 tools/panic-context-audit.py <draft.md> --strict --json",
            "python3 tools/severity-calibration-check.py <draft.md> --strict --json",
            "python3 tools/severity-calibration-gate.py <draft.md> --json --markdown-report reports/severity_calibration_gate.md",
            "python3 tools/pre-submit-watchdog.py ~/audits/<project> --changed <draft.md> --mode quick --json --advisory",
        ],
        "callables": [
            "vault_high_plus_submission_gate",
            "vault_toolsite_context",
        ],
    },
]

# Lane 9 (Wave-6, 2026-05-19) - exploit-conversion operator-surface workflow entries.
# Defined separately so they can be inserted before hackerman-etl-query in build_index()
# (earlier MANIFEST index breaks ties in vault_toolsite_context scoring).
_LANE9_EXPLOIT_CONVERSION_WORKFLOWS: list[dict[str, Any]] = [
    {
        "id": "exploit-conversion-loop",
        "section": "Exploit conversion loop - proof workbench",
        "summary": (
            "Run the V3 proof workbench in one safe command. The loop executes "
            "the current-to-exploit gate, chained attack planner, agent artifact "
            "miner, exploit queue refresh, source mining, source-mined "
            "impact-contract generation, harness binding queue, "
            "severity/scope oracle, PoC falsification runner, and conversion "
            "benchmark. Default posture emits artifacts only; it does not execute "
            "harness commands unless EXECUTE_READY=1 is explicitly set."
        ),
        "tasks": [
            "conversion loop",
            "proof workbench",
            "run exploit conversion",
            "queue to proof loop",
            "prove top leads safely",
            "audit deep conversion artifacts",
            "run all conversion tools",
        ],
        "commands": [
            "make exploit-conversion-loop WS=~/audits/<project> TOP_N=10",
            "make exploit-conversion-loop WS=~/audits/<project> TOP_N=10 EXECUTE_READY=1",
            "python3 tools/exploit-conversion-loop.py --workspace ~/audits/<project> --top-n 10 --json",
            "cat ~/audits/<project>/.auditooor/exploit_conversion_loop_manifest.json",
        ],
        "callables": [
            "vault_current_to_exploit_conversion_gate_context",
            "vault_exploit_queue_context",
            "vault_exploit_severity_scope_oracle",
            "vault_poc_falsification_context",
        ],
    },
    {
        "id": "exploit-conversion-queue",
        "section": "Exploit queue - exploit queue context - what do I prove next",
        "summary": (
            "Build and inspect the canonical exploit queue so a worker knows exactly "
            "what to prove next via exploit queue context. The exploit-queue.py tool reads workspace audit "
            "artifacts (engage_report, hacker_brief, proof_obligation_queue, "
            "chain_candidates, exploit_predicates, etc.) and emits a ranked top-10 "
            "exploit queue to <ws>/.auditooor/exploit_queue.json. The "
            "exploit-queue-source-miner.py C1 worker closes needs_source rows into "
            "source_artifact sidecars and a patched exploit_queue.source_mined.json "
            "without claiming proof. Complete generated impact-contract fields can "
            "advance to mapped; incomplete rows remain generated_unvalidated. Neither "
            "state claims proof, severity, harness readiness, or submission readiness. Use "
            "vault_exploit_queue_context via MCP to read "
            "bounded rows without loading the full artifact."
        ),
        "tasks": [
            "exploit queue",
            "exploit queue context",
            "what do I prove next",
            "ranked prove list",
            "top leads to prove",
            "next proof candidate",
            "proof candidate ranking",
            "close needs_source rows",
            "source artifact for queue row",
            "prove top leads",
            "queue to harness execution",
        ],
        "commands": [
            "python3 tools/exploit-queue.py --workspace ~/audits/<project> --json",
            "python3 tools/exploit-queue.py --workspace ~/audits/<project> --top-n 10",
            "make exploit-queue-source-mine WS=~/audits/<project> TOP_N=10",
            "make source-mined-impact-contracts WS=~/audits/<project> UPDATE_QUEUE=1",
            "make prove-top-leads WS=~/audits/<project> TOP_N=10",
            "python3 tools/exploit-queue-source-miner.py --workspace ~/audits/<project> --top-n 10 --json",
            "python3 tools/vault-mcp-server.py --call vault_exploit_queue_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":10}'",
            "cat ~/audits/<project>/.auditooor/exploit_queue.md",
        ],
        "callables": [
            "vault_exploit_queue_context",
            "vault_current_to_exploit_conversion_gate_context",
            "vault_high_impact_execution_bridge_context",
        ],
    },
    {
        "id": "exploit-conversion-severity-scope-oracle",
        "section": "Exploit severity and scope oracle",
        "summary": (
            "Advisory severity and scope read for an exploit-queue row before "
            "drafting. The exploit-severity-scope-oracle.py tool composes "
            "existing severity-calibration, scope-reasoner, and originality "
            "surfaces into a single bounded advisory output. Returns "
            "selected_severity, scope_status, likely_triager_objections, "
            "required_proof_upgrades, and recommended_next_step. Use "
            "vault_exploit_severity_scope_oracle via MCP to read an oracle "
            "output without loading the full draft surface."
        ),
        "tasks": [
            "severity oracle",
            "scope oracle",
            "triager objections",
            "exploit severity scope oracle",
            "severity advisory",
            "scope advisory",
            "likely triager objections",
            "required proof upgrades",
            "scope status",
            "recommended next step",
        ],
        "commands": [
            "python3 tools/exploit-severity-scope-oracle.py --queue-row <row.json> --json",
            "python3 tools/exploit-severity-scope-oracle.py --queue-row <row.json> --workspace ~/audits/<project> --json",
            "python3 tools/vault-mcp-server.py --call vault_exploit_severity_scope_oracle --args '{\"oracle_path\":\"<oracle-output.json>\"}'",
            "python3 tools/vault-mcp-server.py --call vault_exploit_severity_scope_oracle --args '{\"oracle_json\":{\"selected_severity\":\"High\",\"scope_status\":\"in_scope\"}}'",
        ],
        "callables": [
            "vault_exploit_severity_scope_oracle",
            "vault_exploit_queue_context",
            "vault_severity_calibration",
        ],
    },
    {
        "id": "exploit-conversion-falsification",
        "section": "PoC falsification runner",
        "summary": (
            "Prove, disprove, or bound a serious exploit lead before drafting. "
            "The poc-falsification-runner.py tool takes a queue row JSON, an "
            "optional harness command, and optional severity oracle output; "
            "runs the command, records negative controls, production-path "
            "checks, and restart/multi-validator checks, and emits a "
            "structured verdict (proved|disproved|inconclusive|needs_harness). "
            "Use vault_poc_falsification_context via MCP to read a bounded "
            "falsification result."
        ),
        "tasks": [
            "falsify this lead",
            "falsification runner",
            "negative control",
            "poc falsification",
            "prove or disprove",
            "poc verdict",
            "disprove lead",
            "negative control run",
            "production path check",
            "poc falsification context",
        ],
        "commands": [
            "python3 tools/poc-falsification-runner.py --queue-row <row.json> --cmd 'true' --json",
            "python3 tools/poc-falsification-runner.py --queue-row <row.json> --cmd 'forge test --match-test <TestName>' --json",
            "python3 tools/poc-falsification-runner.py --queue-row <row.json> --severity-oracle <oracle.json> --json",
            "python3 tools/vault-mcp-server.py --call vault_poc_falsification_context --args '{\"result_path\":\"<result.json>\"}'",
            "python3 tools/vault-mcp-server.py --call vault_poc_falsification_context --args '{\"result_json\":{\"verdict\":\"proved\",\"candidate_id\":\"EQ-001\"}}'",
        ],
        "callables": [
            "vault_poc_falsification_context",
            "vault_exploit_severity_scope_oracle",
            "vault_exploit_queue_context",
        ],
    },
    {
        "id": "exploit-conversion-gate",
        "section": "Current-to-exploit conversion gate",
        "summary": (
            "Check whether exploit-conversion work is allowed to start. "
            "The current-to-exploit-conversion-gate.py tool reads the latest "
            "capability roadmap slice, KNOWN_LIMITATIONS_BURNDOWN_MAP, sidecar "
            "freshness, current real-world recall status, and proof-artifact feedback, "
            "then emits a gate verdict (start_exploit_conversion_allowed plus "
            "blocked_reasons). V3 policy: same-class recall is attention-ranking only; "
            "it no longer hard-blocks exploit conversion. Use "
            "vault_current_to_exploit_conversion_gate_context via MCP to read the "
            "bounded gate summary."
        ),
        "tasks": [
            "conversion gate",
            "exploit conversion gate",
            "can I start exploit conversion",
            "current to exploit gate",
            "gate verdict",
            "blocked reasons",
            "conversion allowed",
            "recall attention backlog",
        ],
        "commands": [
            "python3 tools/current-to-exploit-conversion-gate.py --json",
            "python3 tools/current-to-exploit-conversion-gate.py",
            "python3 tools/vault-mcp-server.py --call vault_current_to_exploit_conversion_gate_context --args '{\"limit\":8}'",
            "cat reports/current_to_exploit_conversion_gate.json",
        ],
        "callables": [
            "vault_current_to_exploit_conversion_gate_context",
            "vault_exploit_queue_context",
            "vault_realworld_recall_gap_priorities",
        ],
    },
    # Lane 6 (Wave-6, 2026-05-19) - agent-artifact-miner workflow (promoted from stub).
    {
        "id": "agent-artifact-miner",
        "section": "Agent artifact miner - mine worker outputs for capability",
        "summary": (
            "Turn every worker output and failed PoC into future capability artifacts. "
            "The agent-artifact-miner.py tool scans a workspace for agent-produced "
            "artifacts (REPORT.md files, dispatch outputs, submission files, commit-mining "
            "outputs, PoC files, memory/backfill files) and emits structured learning "
            "records: candidate detector patterns, hacker questions, rejection/kill patterns, "
            "harness template requests, proof-artifact mapping candidates, known limitations, "
            "and roadmap gaps. Output is written to <ws>/agent_artifact_mining_report.json. "
            "Use vault_agent_artifact_mining_context via MCP to read a bounded summary "
            "(total_artifacts, artifact_type_counts, no_learning_reason, titles sample) "
            "without loading the full report. Schema: auditooor.agent_artifact_mining.v1."
        ),
        "tasks": [
            "mine worker artifacts",
            "agent artifact miner",
            "mine worker outputs",
            "worker output mining",
            "capability artifacts",
            "agent artifact mining context",
            "learning artifacts",
            "detector pattern seeds",
            "failed poc mining",
            "rejection pattern mining",
            "harness template request",
            "proof artifact mapping",
            "known limitation mining",
            "roadmap gap mining",
        ],
        "commands": [
            "python3 tools/agent-artifact-miner.py --workspace ~/audits/<project> --out ~/audits/<project>/agent_artifact_mining_report.json",
            "python3 tools/agent-artifact-miner.py --workspace ~/audits/<project> --json",
            "python3 tools/vault-mcp-server.py --call vault_agent_artifact_mining_context --args '{\"workspace_path\":\"~/audits/<project>\",\"limit\":10}'",
            "cat ~/audits/<project>/agent_artifact_mining_report.json | python3 -m json.tool | head -40",
        ],
        "callables": [
            "vault_agent_artifact_mining_context",
            "vault_exploit_queue_context",
        ],
    },
    # Exploit-conversion benchmark workflow (Wave-6, 2026-05-19) - promoted from stub.
    {
        "id": "exploit-conversion-benchmark",
        "section": "Exploit conversion benchmark - measure conversion yield over time",
        "summary": (
            "Measure and track the yield of the exploit-conversion pipeline over time. "
            "The exploit-conversion-benchmark.py tool reads the exploit queue, agent "
            "artifact mining report, and falsification results for a workspace and emits "
            "a structured benchmark: total_leads_queued, leads_proved, leads_disproved, "
            "leads_inconclusive, conversion_rate, top_attack_classes, and a per-lead "
            "proof-status matrix. Useful for tracking whether the capability loop is "
            "actually producing fileable leads at the expected rate. "
            "Run after each loop iteration to surface yield gaps early."
        ),
        "tasks": [
            "exploit conversion benchmark",
            "conversion yield",
            "proof success rate",
            "leads proved rate",
            "exploit pipeline benchmark",
            "benchmark exploit conversion",
            "conversion rate",
            "yield tracking",
            "proof status matrix",
        ],
        "commands": [
            "python3 tools/audit/exploit-conversion-benchmark.py --workspace ~/audits/<project> --json",
            "python3 tools/audit/exploit-conversion-benchmark.py --workspace ~/audits/<project>",
            "cat reports/exploit_conversion_benchmark.json | python3 -m json.tool",
        ],
        "callables": [
            "vault_exploit_queue_context",
            "vault_agent_artifact_mining_context",
            "vault_poc_falsification_context",
        ],
    },
]


def _discover_tools(glob_pattern: str | None = None, allowlist: list[str] | None = None) -> list[str]:
    """Return sorted relative tool paths matching ``glob_pattern`` and/or
    ``allowlist``. Allowlist entries that are not present on disk are silently
    dropped so the generator stays robust if a Wave-1 tool is renamed or
    retired; a missing tool surfaces as a shorter section, not an error.
    """
    found: set[str] = set()
    if glob_pattern is not None:
        for path in TOOLS_DIR.glob(glob_pattern):
            if path.is_file():
                found.add(path.name)
    if allowlist is not None:
        for name in allowlist:
            if (TOOLS_DIR / name).is_file():
                found.add(name)
    return sorted(found)


def _wave1_section(
    *,
    section_id: str,
    section_title: str,
    summary: str,
    tasks: list[str],
    tool_files: list[str],
    extra_commands: list[str] | None = None,
    callables: list[str] | None = None,
) -> dict[str, Any]:
    """Build a Wave-1 manifest row by mapping each discovered tool to a
    `python3 tools/<name>.py --help` invocation. This keeps the index
    auto-aware of new Wave-1 tools without hand-edited command lists.
    """
    commands: list[str] = []
    for tool_name in tool_files:
        commands.append(f"python3 tools/{tool_name} --help")
    if extra_commands:
        commands.extend(extra_commands)
    return {
        "id": section_id,
        "section": section_title,
        "summary": summary,
        "tasks": tasks,
        "commands": commands,
        "callables": callables or [],
        "tool_count": len(tool_files),
    }


def build_wave1_sections() -> list[dict[str, Any]]:
    """Auto-discover Wave-1 tooling sections (14-17)."""
    etl_tools = _discover_tools(glob_pattern=WAVE1_ETL_GLOB)
    stratify_tools = _discover_tools(allowlist=WAVE1_STRATIFY_APPLY_GATES)
    aggregator_tools = _discover_tools(allowlist=WAVE1_AGGREGATORS)
    inspection_tools = _discover_tools(allowlist=WAVE1_INSPECTION_PREVIEW)

    return [
        _wave1_section(
            section_id="wave1-etl-miners",
            section_title="Wave-1 ETL miners",
            summary=(
                "Auto-discovered list of `tools/hackerman-etl-from-*.py` miners "
                "that fan the public corpus into the Hackerman attacker-memory "
                "tags. Run individually for targeted refreshes, or batch via "
                "`make hackerman-refresh`. Each miner accepts `--help` for "
                "per-source flags and output paths."
            ),
            tasks=[
                "refresh hackerman corpus from a specific source",
                "rerun a single ETL miner",
                "wave-1 etl",
                "etl miner inventory",
                "list etl miners",
                "miner registry",
            ],
            tool_files=etl_tools,
            extra_commands=[
                "make hackerman-refresh DRY_RUN=1",
                "make hackerman-refresh",
                "make hackerman-etl-registry-build",
                "python3 tools/hackerman-etl-miner-registry-build.py --json",
                "python3 tools/hackerman-etl-miner-scaffold.py --help",
                "python3 tools/hackerman-etl-refresh.py --dry-run --workspace ~/audits/<project>",
            ],
            callables=[
                "vault_attack_class_evidence",
                "vault_cross_language_pattern_lift",
            ],
        ),
        _wave1_section(
            section_id="wave1-stratify-apply-gates",
            section_title="Wave-1 stratify / apply / gates",
            summary=(
                "Auto-discovered stratification + application + integrity-gate "
                "tools that score, tag, and gate the Hackerman corpus by "
                "verification-tier. Stratify candidates, apply tier tags into "
                "function_shape.shape_tags, snapshot tier history, and run the "
                "composite pre-merge / integrity / gates-status checks before "
                "shipping a Wave."
            ),
            tasks=[
                "stratify hackerman records",
                "apply verification tier",
                "verification tier candidates",
                "tier history snapshot",
                "baseline freeze",
                "pre merge hackerman",
                "integrity check hackerman",
                "gates status",
                "wave close tag",
                "wave shipment receipt",
                "pr726 merge checklist",
            ],
            tool_files=stratify_tools,
            extra_commands=[
                "make hackerman-baseline-freeze",
                "make hackerman-tier-history-snapshot",
                "make hackerman-tier-history-list",
                "make hackerman-gates-status",
                "make hackerman-gates-status-json",
                "make hackerman-integrity-check",
                "make hackerman-integrity-check-json",
                "make hackerman-pre-merge",
                "make hackerman-tag-wave-close",
                "make hackerman-wave1-shipment-receipt",
            ],
            callables=[
                "vault_attack_class_evidence",
                "vault_hackerman_chain_candidates",
            ],
        ),
        _wave1_section(
            section_id="wave1-aggregators",
            section_title="Wave-1 aggregators",
            summary=(
                "Auto-discovered aggregator tools that reduce the Hackerman "
                "corpus into per-axis statistics, coverage matrices, growth "
                "charts, and health dashboards. Use these to inspect "
                "Wave-level deltas, attack-class spread, contributor stats, "
                "and audit-firm coverage before planning the next wave."
            ),
            tasks=[
                "corpus stats",
                "attack class distribution",
                "attack class inventory",
                "attack class severity matrix",
                "audit firm coverage matrix",
                "language distribution",
                "severity distribution",
                "year distribution",
                "domain distribution",
                "target repo distribution",
                "contributor stats",
                "growth chart",
                "health dashboard",
                "corpus snapshot html",
                "corpus diff",
                "capability adoption",
            ],
            tool_files=aggregator_tools,
            extra_commands=[
                "make hackerman-corpus-stats",
                "make hackerman-stats-all",
                "make hackerman-stats-all-json",
                "make hackerman-attack-class-distribution",
                "make hackerman-attack-class-severity-matrix",
                "make hackerman-audit-firm-coverage-matrix",
                "make hackerman-language-stats",
                "make hackerman-severity-stats",
                "make hackerman-year-stats",
                "make hackerman-domain-stats",
                "make hackerman-target-repo-stats",
                "make hackerman-contest-contributor-stats",
                "make hackerman-health-dashboard",
                "make hackerman-corpus-snapshot-html",
            ],
            callables=[
                "vault_hackerman_chain_candidates",
                "vault_hackerman_go_cosmos_inventory",
            ],
        ),
        _wave1_section(
            section_id="wave1-inspection-preview",
            section_title="Wave-1 inspection / preview tools",
            summary=(
                "Auto-discovered preview / inspection / validation tools that "
                "drill into individual Hackerman records, extract derived "
                "preview JSONL artifacts (reentrancy patterns, detector seeds, "
                "PDF previews), or audit cross-corpus duplicates, provenance, "
                "schema conformance, and docs cross-links. These are read-only "
                "and safe to run during a hunt."
            ),
            tasks=[
                "inspect a hackerman record",
                "validate a hackerman record",
                "audit record provenance",
                "tier3 deep attribution",
                "reentrancy pattern preview",
                "detector seed preview",
                "cross corpus dupe preview",
                "subdir acceptance check",
                "bug class shift detector",
                "nvd verification sweep",
                "audit firm pdf preview",
                "audit firm pdf url sanity",
                "docs cross link audit",
                "proof hardening",
            ],
            tool_files=inspection_tools,
            extra_commands=[
                "python3 tools/hackerman-record-validate.py --validate <path/to/record.yaml>",
                "python3 tools/hackerman-record-validate.py --validate-dir audit/corpus_tags/tags",
                "python3 tools/hackerman-record-quality.py --json-summary",
                "python3 tools/hackerman-cross-corpus-dupe-finder.py --json",
                "python3 tools/hackerman-tier3-deep-attribution-analyzer.py --help",
                "python3 tools/hackerman-detector-seed-extractor.py --dry-run",
                "python3 tools/hackerman-docs-cross-link-audit.py --json",
            ],
            callables=[
                "vault_attack_class_evidence",
                "vault_function_shape_attack_evidence",
            ],
        ),
    ]


def build_index() -> dict[str, Any]:
    # Insert Lane 9 exploit-conversion workflows immediately after 'brain-prime'
    # (index 7 in MANIFEST) so they rank above hackerman-etl-query on tied
    # vault_toolsite_context task-phrase scores ("exploit queue", etc.).
    brain_prime_idx = next(
        (i for i, row in enumerate(MANIFEST) if row.get("id") == "brain-prime"), -1
    )
    insert_at = brain_prime_idx + 1 if brain_prime_idx >= 0 else len(MANIFEST)
    base = [dict(item) for item in MANIFEST]
    for offset, lane9_row in enumerate(_LANE9_EXPLOIT_CONVERSION_WORKFLOWS):
        base.insert(insert_at + offset, dict(lane9_row))
    workflows = base
    workflows.extend(build_wave1_sections())
    return OrderedDict(
        [
            ("name", "Hackerman MCP Tooling Index"),
            ("summary", "Curated local workflows and MCP entry points for agents."),
            ("generated_from", "tools/hackerman-tooling-index.py"),
            ("operator_index", build_operator_index_from_workflows(workflows)),
            ("workflow_count", len(workflows)),
            ("workflows", workflows),
        ]
    )


def build_operator_index_from_workflows(workflows: list[dict[str, Any]]) -> OrderedDict[str, Any]:
    workflow_ids = {str(row.get("id") or "") for row in workflows}
    sidecar = OrderedDict(OPERATOR_INDEX)
    sidecar["workflow_count"] = len(workflows)
    sidecar["workflow_ids_available"] = [
        workflow_id
        for workflow_id in sidecar["intent_to_workflow_id"].values()
        if workflow_id in workflow_ids
    ]
    sidecar["current_gap_ids_source"] = "Run roadmap_status_command; gap ids are intentionally not hardcoded here."
    return sidecar


def build_operator_index(index: dict[str, Any] | None = None) -> OrderedDict[str, Any]:
    full_index = index if index is not None else build_index()
    existing = full_index.get("operator_index")
    if isinstance(existing, OrderedDict):
        return existing
    if isinstance(existing, dict):
        return OrderedDict(existing)
    return build_operator_index_from_workflows(list(full_index.get("workflows", [])))


COMPACT_WORKFLOW_IDS = (
    "mcp-session-start",
    "v3-source-first-audit",
    "make-audit",
    "brain-prime",
    "make-audit-deep",
    "exploit-conversion-loop",
    "exploit-conversion-queue",
    "exploit-conversion-falsification",
    "exploit-conversion-severity-scope-oracle",
    "exploit-conversion-gate",
    "originality-dupe-preproof",
    "function-mindset-and-hacker-questions",
    "hackerman-etl-query",
    "agent-artifact-miner",
    "high-impact-execution-bridge",
    "finalization-manifest",
    "loop-finalization-check",
    "pre-submit-gates",
    "control-plane-ready",
)


def _first_commands(commands: list[str], *, limit: int = 3) -> list[str]:
    """Return a bounded command sample for compact markdown cards."""
    return list(commands[:limit])


def render_markdown(index: dict[str, Any]) -> str:
    operator_index = build_operator_index(index)
    quick_index = [
        ("Session freshness", "bash tools/auditooor-session-start.sh ~/audits/<project>", "vault_toolsite_context`, `vault_resume_context"),
        ("First workspace pass", "make v3-source-first-audit WS=~/audits/<project> TOP_N=25", "vault_brain_prime_context`, `vault_exploit_queue_context"),
        ("Component detector pass", "make audit WS=~/audits/<project>", "vault_engage_report_context"),
        ("Deep detector pass", "make audit-deep WS=~/audits/<project>", "vault_resume_context`, `vault_harness_context"),
        ("Ranked hunt lanes", "make brain-prime WS=~/audits/<project>", "vault_brain_prime_context"),
        ("Top proof targets", "make exploit-conversion-loop WS=~/audits/<project> TOP_N=10", "vault_exploit_queue_context"),
        ("Lane-scoped attacker memory", "make hacker-brief WS=~/audits/<project> LANE=<id>", "vault_hacker_brief_for_lane"),
        ("Detector-to-proof bridge", "make audit-hacker-logic-bridge WS=~/audits/<project>", "vault_detector_action_graph_context"),
        ("Mined findings to hunter obligations", "make mined-findings-hunter-bridge WS=~/audits/<project>", ".auditooor/mined_findings_hunter_bridge.json`, `.auditooor/hacker_question_obligations.jsonl"),
        ("Advisory novel vectors", "make hackerman-novel-vector-gen TARGET_REPO=owner/repo JSON=1 MAX_TARGETS=50", "vault_hackerman_novel_vector_context`, `vault_attack_class_evidence`, `vault_hackerman_exploit_predicates"),
        ("High/Critical execution readiness", "make high-impact-execution-bridge WS=~/audits/<project> JSON=1", "vault_high_impact_execution_bridge_context`, `vault_cosmos_evidence_pack_context"),
        ("Submission gates", "bash tools/pre-submit-check.sh <draft.md> and make paste-ready WS=~/audits/<project> DRAFT=<draft.md>", "vault_finalization_context`, `vault_engagement_status"),
        ("Finalization / closeout", "make loop-finalization-check MANIFEST=<manifest.json> and make audit-closeout WS=~/audits/<project>", "vault_finalization_context"),
        ("Worker-dispatch readiness", "make control-plane-ready WS=~/audits/<project> JSON=1 && make v3-worker-packet WS=~/audits/<project> SEVERITY=High STRICT=1", "vault_toolsite_context`, `vault_brain_prime_context"),
        ("Cheap provider fanout", "python3 tools/provider-capacity-report.py --print-json", "vault_provider_capacity`, `vault_llm_calibration`, `vault_toolsite_context"),
    ]
    lines: list[str] = [
        "# Hackerman MCP Tooling Index",
        "",
        "Compact local workflow and MCP entry map for agents. This is the operator front door, not the full inventory.",
        "",
        "For a fresh agent session, run `bash tools/auditooor-session-start.sh ~/audits/<project>` for the target workspace, then run `make v3-source-first-audit WS=~/audits/<project> TOP_N=25`. Immediately inspect `vault_brain_prime_context` and `vault_exploit_queue_context` before dispatch or proof work. Use MCP recall before raw vault scans. Keep pre-filing judgment, `make audit-hacker-logic-bridge`, `make loop-finalization-check`, and `bash tools/pre-submit-check.sh` in the loop before any handoff that matters.",
        "",
        "Codex and Claude own integration, proof quality, and final judgment. Kimi/MiniMax are advisory extraction, wide review, and counter-argument fanout unless a task packet explicitly gives them a bounded implementation lane.",
        "",
        "Machine-readable cold-start sidecar:",
        f"- `{operator_index['refresh_command']}`",
        "- `python3 tools/hackerman-tooling-index.py --format json` for the full machine-readable workflow inventory",
        "- `python3 tools/hackerman-tooling-index.py --format full-markdown` for the legacy long Markdown inventory",
        f"- Roadmap status probe: `{operator_index['roadmap_status_command']}`",
        f"- MCP discovery callables: `{', '.join(operator_index['mcp_discovery_callables'])}`",
        "",
        "## Operator audit-start quick index",
        "Use this when the task is \"what do I run right now?\" rather than \"show me every tool.\"",
        "",
        "| Need | Primary command | Companion read surface |",
        "| --- | --- | --- |",
    ]
    for need, command, read_surface in quick_index:
        lines.append(f"| {need} | `{command}` | `{read_surface}` |")
    lines.append("")

    workflow_by_id = {str(workflow.get("id") or ""): workflow for workflow in index["workflows"]}
    selected = [workflow_by_id[workflow_id] for workflow_id in COMPACT_WORKFLOW_IDS if workflow_id in workflow_by_id]
    lines.extend(
        [
            "## Compact workflow cards",
            "These are the commands a live audit agent should reach for first. Use the JSON or full-markdown formats for exhaustive discovery.",
            "",
        ]
    )
    for i, workflow in enumerate(selected, start=1):
        lines.extend(
            [
                f"## {i}. {workflow['section']}",
                workflow["summary"],
                "",
            ]
        )
        command_limit = 4 if workflow.get("id") in {"v3-source-first-audit", "control-plane-ready", "exploit-conversion-queue"} else 3
        for command in _first_commands(workflow["commands"], limit=command_limit):
            lines.append(f"- `{command}`")
        if workflow["callables"]:
            lines.append(f"- MCP callables: `{', '.join(workflow['callables'])}`")
        if workflow.get("tasks"):
            lines.append(f"- Task phrases: `{', '.join(workflow['tasks'][:8])}`")
        lines.append("")

    lines.extend(
        [
            f"Generated from the curated manifest in `tools/hackerman-tooling-index.py`; compact cards shown: {len(selected)} of {index['workflow_count']} workflows.",
            "For the broader MCP contract, see `docs/VAULT_MCP_SERVER.md` and `docs/MCP_AUDIT_AGENT_START.md`.",
            "This file is the canonical compact command map; `--format json` is the canonical full inventory and `agent_outputs/hackerman_tooling_index*.md` files are historical run artifacts.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_full_markdown(index: dict[str, Any]) -> str:
    """Render the legacy exhaustive Markdown inventory for debugging/discovery."""
    lines: list[str] = [
        "# Hackerman MCP Full Tooling Inventory",
        "",
        "Exhaustive generated workflow inventory. Operators should start from `docs/HACKERMAN_MCP_TOOLING_INDEX.md` and use this only for deep tool discovery.",
        "",
    ]
    for i, workflow in enumerate(index["workflows"], start=1):
        lines.extend(
            [
                f"## {i}. {workflow['section']}",
                workflow["summary"],
                "",
            ]
        )
        if "tool_count" in workflow:
            lines.append(
                f"- Auto-discovered tool count: `{workflow['tool_count']}` "
                f"(refreshed from `tools/` on every regeneration)"
            )
        for command in workflow["commands"]:
            lines.append(f"- `{command}`")
        if workflow["callables"]:
            lines.append(f"- MCP callables: `{', '.join(workflow['callables'])}`")
        if workflow.get("tasks"):
            lines.append(f"- Task phrases: `{', '.join(workflow['tasks'])}`")
        lines.append("")
    lines.append("Generated from the curated manifest in `tools/hackerman-tooling-index.py`.")
    return "\n".join(lines) + "\n"


def render_json(index: dict[str, Any]) -> str:
    return json.dumps(index, indent=2, ensure_ascii=False) + "\n"


def render_operator_json(index: dict[str, Any]) -> str:
    return json.dumps(build_operator_index(index), indent=2, ensure_ascii=False) + "\n"


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--format",
        choices=("markdown", "full-markdown", "json", "operator-json"),
        default="markdown",
        help="Output format (default: markdown).",
    )
    # --json is a shorthand alias for --format json recognised by Lane 9 constraint.
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Shorthand for --format json.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.json and args.format == "markdown":
        args.format = "json"
    return args


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    index = build_index()
    if args.format == "json":
        print(render_json(index), end="")
    elif args.format == "operator-json":
        print(render_operator_json(index), end="")
    elif args.format == "full-markdown":
        print(render_full_markdown(index), end="")
    else:
        print(render_markdown(index), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
