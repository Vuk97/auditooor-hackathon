# auditooor - convenience targets for common operations

# Strict ordered runs propagate the hard-block contract into every recipe.
ifeq ($(PIPELINE_STRICT),1)
export PIPELINE_STRICT
endif

# Later phases are intentionally callable only through an authorized parent
# driver. The exact token is passed by audit-pipeline-full at each phase.
define _require_pipeline_phase_token
	@if [ "$(AUDITOOOR_PIPELINE_PHASE_TOKEN)" != "$(1)" ]; then \
	  echo "[$(1)] ERROR: direct invocation is blocked; expected AUDITOOOR_PIPELINE_PHASE_TOKEN=$(1) from the ordered parent driver" >&2; \
	  exit 2; \
	fi
endef

# GitHub/source-only reviews have an explicit topology disposition. This does
# not fabricate deployment evidence; it tells downstream gates to require
# source-only proof where live state would otherwise be needed.
ifeq ($(SOURCE_ONLY),1)
export AUDITOOOR_SOURCE_ONLY
AUDITOOOR_SOURCE_ONLY := 1
endif
ifeq ($(GITHUB_ONLY),1)
export AUDITOOOR_SOURCE_ONLY
AUDITOOOR_SOURCE_ONLY := 1
endif

.PHONY: help init update clean setup originality reports extract test parity build compile compile-regression-guard compile-strict inventory ledger all ci ci-check skill-issues known-limitations-check known-limitations-check-test dashboard dashboard-json dashboard-html detector-health-dashboard verify-loop gaps gaps-smoke detector-dedupe fixture-dupe bootstrap cross-link cross-link-suggestions cross-link-full stage-reference-check tool-ref-check doc-cascade-check doc-cascade-check-test docs-check docs-check-playbook cleanup-inventory workspace-inventory submission-tracker-check outcome-telemetry outcome-telemetry-test outcome-scoreboard outcome-scoreboard-test cost-summary cost-telemetry-test fork-replay-test fuzz-runner-test fuzz-runner-manifest-schema-test fuzz-campaign fuzz-campaign-test fuzz-quick fuzz-quick-test evidence-matrix-test symbolic-runner-test econ-simulator-test invariant-templates-test invariant-templates-check outcome-reweight-test economic-risk-card economic-risk-card-test coverage-matrix lint freshness tier-move tier-move-bulk sample severity-reconcile parity-drafts scan fp-calibration auto-fp-triage hypothesis correlator-validate correlator-test exploit-regression novel-candidates narrate family-map engage xws-lookup clean-submissions clean-engage-candidates submission-sync verify-pocs scrape-diffs-v2 workspace-bootstrap-test engagement-dashboard engagement-dashboard-test scope-reasoner scope-reasoner-test intake-baseline intake-saturation-score intake-baseline-test new-engagement make-new-engagement-test audit-prep audit-deep audit-deep-test audit-deep-live-test hydra hydra-test audit-completion-marker-test audit-closeout audit-closeout-case-study audit-closeout-test invariant-ledger invariant-ledger-check invariant-ledger-test harness-plan harness-plan-test harness-scaffold harness-scaffold-test invariant-harness-gen invariant-harness-gen-test semantic-graph semantic-graph-test critical-hunt critical-hunt-test base-critical-matrix base-critical-matrix-test base-critical-hunt base-critical-hunt-test base-rpc-crash-probe base-rpc-crash-probe-test verifier-upgrade-surface verifier-upgrade-surface-test live-verifier-config-check live-verifier-config-check-test verifier-upgrade-kit-forge-test a11-precompile-diff a11-precompile-diff-test base-block-delay-probe base-block-delay-probe-test rust-decode-bomb-scan rust-decode-bomb-scan-test base-rust-swival-shape-scan base-rust-swival-shape-scan-test poc-execution-record poc-execution-record-test deep-counterexample-record deep-counterexample-record-test deep-counterexample-collect deep-counterexample-collect-test deep-counterexample-replay-scaffold deep-counterexample-replay-scaffold-test deep-counterexample-queue deep-counterexample-queue-test chimera-scaffold chimera-ledger-scaffold chimera-scaffold-test recon-log-bridge recon-log-bridge-test deep-engine-output-parse deep-engine-output-parse-test coverage-introspect coverage-introspect-test p1-extraction-queue p1-extraction-queue-test p1-extraction-run p1-extraction-run-test zkbugs-ingest zkbugs-ingest-test zkbugs-ingest-0xparc zkbugs-ingest-0xparc-test zkbugs-ingest-all zkbugs-brief-queue zkbugs-brief-queue-test zkbugs-provider-result zkbugs-provider-result-test zkbugs-provider-loop zkbugs-provider-loop-test zkbugs-pull zkbugs-status zkbugs-pipeline-wiring-test zkbugs-coverage-by-framework zk-engagement-probe-surface zk-verifier-bugclass-checklist zk-verifier-bugclass-checklist-test zk-function-mindset-honk zk-verify-persist zk-hunt zkbugs-readiness-check zkbugs-detectorization-map-run zkbugs-prior-audit-class-check zk-etl-verifier circom-detect circom-detect-test cosmos-detect cosmos-detect-test agent-preflight agent-preflight-test calibration-log-hook calibration-log-hook-test pattern-merge-rescan pattern-merge-rescan-test pattern-taxonomy pattern-taxonomy-test findings-to-pattern forever-status print-ws-resolved source-mine source-mine-test paste-ready paste-ready-test dispatch-validate dispatch-validate-test dispatch-validate-list dispatch-preflight dispatch-preflight-test worker-brief-check worker-brief-check-test pre-source-read-inject pre-source-read-inject-test base-snappy-bomb-test severity-claim-guard severity-claim-guard-test upstream-equivalent-gate upstream-equivalent-gate-test deployment-timeline deployment-timeline-test mcp-route mcp-route-test proof-obligation-queue exploit-queue exploit-queue-test agent-artifact-mine agent-artifact-mine-test exploit-conversion-benchmark exploit-conversion-benchmark-test provider-fanout-discipline-check provider-fanout-discipline-check-test promote-exploit-queue-to-ledger promote-exploit-queue-to-ledger-test bug-bounty-oos-ingest poc-revert-selector-check poc-revert-selector-check-test
.PHONY: base-lessons-inventory corpus-mining-inventory corpus-detectorization-inventory corpus-detectorization-inventory-test impact-matrix impact-contract-check impact-family-worklist impact-family-worklist-test impact-worklist coverage-inventory agent-output-inventory agent-recall impact-analysis-queue harness-task-queue source-proof-task-queue high-impact-impact-contract-skeletons pr560-next-actions tool-coverage-inventory known-limitations-burndown automation-closure base-automation-closure automation-closure-test pr560-closure-inventory-test logic-flow-bypass-accounting-worklist solodit-taxonomy-triage solodit-rest-direct solodit-language-refresh-test operator-action-digest operator-action-digest-all operator-action-tracker-test
.PHONY: impact-miss-offset-benchmark impact-miss-harness-blocker-executor source-proof-impact-bridge impact-proof-requirement-manifests impact-proof-source-citation-backfill impact-proof-project-evidence-executor high-impact-execution-bridge foundry-version-report foundry-v17-trial-plan foundry-v17-normalization-plan foundry-v17-trial-executor foundry-v17-blocker-closure
.PHONY: big-loss-template-compose big-loss-template-compose-test big-loss-template-runner big-loss-template-runner-test draft-rust-dlt-filing draft-rust-dlt-filing-test
.PHONY: defimon-staleness-check big-loss-template-emit lane9-commitments-test
.PHONY: corpus-trust-build trusted-corpus-index trusted-corpus-check corpus-trust-report corpus-trust-ci corpus-trust-test
.PHONY: hunt-complete hunt-complete-test
.PHONY: agent-recall-suggest agent-recall-suggest-test
.PHONY: v3-provider-fanout-queue v3-provider-followup-queue v3-provider-prefiling-backfill-queue v3-provider-fanout-run v3-provider-fanout-closeout v3-provider-local-verification-queue v3-provider-local-verify v3-provider-learning-compiler v3-provider-campaign-completeness-gate v3-provider-fanout-slice v3-provider-fanout-queue-test v3-provider-campaign-completeness-gate-test v3-provider-closure-queue
.PHONY: rust-from-u8-panic-on-untrusted-input-scan rust-from-u8-panic-on-untrusted-input-scan-test rust-non-exact-decode-trailing-bytes-scan rust-non-exact-decode-trailing-bytes-scan-test rust-discarded-verify-bool-scan rust-discarded-verify-bool-scan-test rust-existence-only-cache-gate-scan rust-existence-only-cache-gate-scan-test rust-hardfork-precompile-address-mismatch-scan rust-hardfork-precompile-address-mismatch-scan-test rust-host-length-cast-unbounded-alloc-scan rust-host-length-cast-unbounded-alloc-scan-test rust-numeric-overflow-underflow-scan rust-numeric-overflow-underflow-scan-test rust-option-iter-misclassifier-scan rust-option-iter-misclassifier-scan-test go-txid-chain-truth-scan go-txid-chain-truth-scan-test go-refund-tweak-survivability-scan go-refund-tweak-survivability-scan-test
.PHONY: git-commits-mining-test
.PHONY: spark-regtest-harness spark-regtest-teardown spark-regtest-harness-test
.PHONY: regex-detectors zkvm-detect l29-filing-audit paste-hash-status capability-status capability-roadmap-status corpus-mining-state hunt-coverage-gate coverage-to-hunt-seed mechanism-to-exploit-queue rehunt-uncovered rehunt-uncovered-test auto-coverage-close auditor-capability-ci
.PHONY: detect detect-test rust-fixture-detector precision-detector inventory-smoke-detector
.PHONY: audit-asset-test audit-asset-test-test
.PHONY: control-status control-snapshot control-handoff control-gaps control-providers control-workpacks control-plan control-report control-plane-ready control-plane-ready-test
.PHONY: vault-refresh vault-sync vault-status vault-mcp-server vault-mcp-self-test vault-mcp-self-test-regression vault-mcp-self-test-regression-test vault-mcp-test memory-auto-link memory-context-load memory-context-test vault-deepen vault-dashboard agent-calibration-refresh agent-calibration-refresh-test
.PHONY: memory-anti-pattern-emitter memory-tools-api-emitter memory-commits-emitter memory-bug-class-emitter
.PHONY: slither-cache-warm slither-cache-stats slither-cache-clear slither-cache-self-test
.PHONY: inventory-smoke inventory-smoke-ci smoke-tooling-test silent-detector-diagnostic silent-detector-diagnostic-smoke
.PHONY: memory-privacy-audit memory-privacy-audit-quarantine memory-privacy-audit-self-test
.PHONY: memory-gap-analysis memory-next-loop memory-next-loop-dry-run memory-next-loop-test memory-next-loop-smoke goal-loop-status goal-loop-status-test memory-audit-packet memory-audit-packet-test shared-memory-index shared-memory-index-test memory-brief memory-brief-test obsidian-memory-entrypoints obsidian-memory-entrypoints-test operational-memory-day-to-day operational-memory-day-to-day-test known-limitations-dispatch known-limitations-dispatch-test known-limitations-harness-memory-status known-limitations-harness-memory-status-test impact-contract-preflight-status impact-contract-preflight-status-test scanner-wiring-burndown scanner-wiring-burndown-test scanner-worker-next-rows scanner-worker-next-rows-test detector-proof-gap-queue detector-proof-gap-queue-test rust-detector-coverage rust-detector-coverage-test rust-fixture-regression-list rust-fixture-regression-list-test rust-xfail-burndown rust-xfail-burndown-test harness-execution-queue harness-execution-queue-test commit-lifecycle-ledger commit-lifecycle-ledger-test commit-mining-next-jobs commit-mining-next-jobs-test commit-mining-scan-tasks commit-mining-scan-tasks-test commit-mining-source-review commit-mining-source-review-test commit-mining-source-disposition commit-mining-source-disposition-test source-mirror-queue source-mirror-queue-test source-mirror-verify source-mirror-verify-test harness-failure-memory harness-failure-memory-validate harness-failure-memory-test task-finalization-validate task-finalization-report task-finalization-test knowledge-gap-validate knowledge-gap-list knowledge-gap-summary knowledge-gap-rebuild-projections knowledge-gap-test exploit-memory-brief exploit-memory-brief-validate exploit-memory-brief-test outcome-semantics-test control-plane-test memory-control-plane-test model-takeover-readiness model-takeover-handoff model-takeover-readiness-test model-takeover-handoff-test
.PHONY: memory-rollup-daily memory-rollup-weekly memory-rollups-backfill
.PHONY: memory-watcher-start memory-watcher-stop memory-watcher-status memory-watcher-self-test
.PHONY: batch-checkpoint-status batch-checkpoint-status-test batch-boundary-preflight
.PHONY: fork-replay fork-replay-hermetic
.PHONY: cross-seed cross-workspace-finding-graph cross-workspace-dedup-check cross-workspace-recurrence cross-workspace-state
.PHONY: source-ref-replay-manifest source-ref-replay-manifest-fixture source-root-blocker-emitter harness-binding-manifest local-corpus-commit-ref-inventory scanner-wiring-truth-inventory
.PHONY: findings-go-validate findings-go-validate-test findings-solidity-validate findings-solidity-validate-test
.PHONY: attack-class-rank detector-hit-action-graph detector-provenance-v2 detector-proof-context detector-proof-context-test solana-detect solana-detect-test
.PHONY: audit-depth depth-probe-run
.PHONY: dataflow-slice
.PHONY: audit audit-fast audit-preflight audit-preflight-test audit-deep audit-deep-medium audit-deep-overnight audit-deep-full audit-run-full audit-run-full-serial-board v3-source-first-audit v3-source-first-prereq-gate v3-source-first-prereq-gate-test v3-source-first-prior-audit-dupe-gate v3-source-first-row-gate v3-source-first-row-gate-test audit-deep-manifest audit-deep-manifest-test audit-deep-solidity _audit-deep-solidity-genuine-coverage _audit-deep-perlang-genuine-coverage audit-deep-go-engine audit-deep-rust-engine genuine-coverage audit-deep-solidity-per-function-harnesses audit-deep-solidity-all-harnesses audit-deep-engines-only audit-deep-ccia-attack-angles audit-deep-per-contract audit-deep-per-contract-test audit-deep-per-fn-invariant audit-deep-per-fn-invariant-test gen-composition-fixtures gen-composition-fixtures-test econ-fuzzer-scaffold econ-fuzzer-scaffold-test deep-engines-provision deep-engines-provision-check fp-calibration-clean-corpus fp-calibration-clean-corpus-test fp-tp-feedback-loop fp-tp-feedback-loop-test tier-stratify tier-stratify-test hunt hunt-full hunt-deterministic prior-history-prehunt-gate audit-pipeline-full _audit-pipeline-full
.PHONY: cvl-spec-risk-scan cvl-spec-risk-scan-test
.PHONY: help help-all help-audit help-dev proof-feedback-regression-test

help:
	@echo "auditooor - operator front door"
	@echo ""
	@echo "AUDIT LOOP:"
	@echo "  make v3-source-first-audit WS=~/audits/<project> Canonical first pass"
	@echo "  make audit WS=~/audits/<project>                 Detector/mining component pass"
	@echo "  make audit-fast WS=~/audits/<project>            Refresh live-target report only"
	@echo "  make brain-prime WS=~/audits/<project>           Ranked first-hunt lanes"
	@echo "  make audit-deep WS=~/audits/<project>            Deep pass after audit evidence"
	@echo "  make audit-deep-medium WS=~/audits/<project>     Bounded live deep engines"
	@echo "  make audit-deep-overnight WS=~/audits/<project>  Strict long-running deep pass"
	@echo "  make audit-run-full WS=~/audits/<project> STRICT=1 EXECUTE_READY=1 MAX_FUNCTIONS=0"
	@echo "                                                   Full-scope audit gate. Proof conversion is advisory unless AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1"
	@echo "  make exploit-conversion-loop WS=~/audits/<project> TOP_N=10"
	@echo "                                                   Top proof workbench"
	@echo "  make corpus-driven-hunt WS=~/audits/<project> EMIT_PROOF_QUEUE=1"
	@echo "                                                   Turn corpus invariants into proof-queue fuel"
	@echo "  make fresh-target-forward-test WS=~/audits/<project>-fwdtest REPO=github.com/Owner/Repo PIN=<sha>"
	@echo "                                                   Measure a locked fresh target"
	@echo "  make evm-0day-proof WS=~/audits/<project> CANDIDATE=<row.json>|QUEUE=<queue.json>"
	@echo "                                                   Run EVM proof pipeline on one lead"
	@echo "  make cvl-spec-risk-scan WS=~/audits/<project>    Inventory Certora/CVL proof obligations"
	@echo "  make orient-prefilter WS=~/audits/<project> CANDIDATES=<orient.json>"
	@echo "                                                   Advisory ORIENT kill-risk prefilter"
	@echo "  make paste-ready WS=~/audits/<project> DRAFT=<draft.md>"
	@echo "                                                   Generate paste-ready draft after gates"
	@echo "  make loop-finalization-check MANIFEST=<manifest.json>"
	@echo "                                                   Validate slice closeout evidence"
	@echo ""
	@echo "CORE CHECKS:"
	@echo "  make docs-check                                  Docs / stage / tool-reference checks"
	@echo "  make readme-check                                README render check"
	@echo "  bash tools/pre-submit-check.sh <draft.md>        Submission rule gates"
	@echo "  make workflow-fullness-check DRAFT=<draft.md>    Run Gap #39 fullness gate directly"
	@echo "  make global-chain-template-library-build         Rebuild global chain-template corpus"
	@echo ""
	@echo "MORE HELP:"
	@echo "  make help-audit                                  Audit and proof-conversion commands"
	@echo "  make hackerman-help                              Hackerman corpus / MCP command map"
	@echo "  make vault-mcp-help                              Vault MCP callable help"
	@echo "  make help-dev                                    Repo development / CI commands"
	@echo "  make help-all                                    Legacy full command inventory"

help-audit:
	@echo "auditooor - audit/proof commands"
	@echo "  bash tools/auditooor-session-start.sh ~/audits/<project>"
	@echo "      Refresh local operational memory and MCP recall context"
	@echo "  make v3-source-first-audit WS=~/audits/<project>"
	@echo "      Canonical source-first path: operator truth + source pins -> audit-deep -> strict row gate"
	@echo "  make audit WS=~/audits/<project>"
	@echo "      Run the detector + mining component pass"
	@echo "  make audit-fast WS=~/audits/<project>"
	@echo "      Regenerate docs/LIVE_TARGET_REPORT without audit closeout/roadmap sidecars"
	@echo "  make brain-prime WS=~/audits/<project>"
	@echo "      Generate brain-prime receipt and ranked first-hunt lanes"
	@echo "  make audit-deep WS=~/audits/<project>"
	@echo "      Run deep engines after make audit evidence exists"
	@echo "  make audit-deep-medium WS=~/audits/<project>"
	@echo "      Run audit-deep with DEEP_PROFILE=medium (bounded live halmos/fuzz)"
	@echo "  make audit-deep-overnight WS=~/audits/<project>"
	@echo "      Run MCP-preflighted strict/all-profile deep engines for unattended sessions"
	@echo "  make audit-deep-manifest WS=~/audits/<project> JSON=1"
	@echo "      Read-only summary of audit-deep outputs"
	@echo "  make audit-run-full WS=~/audits/<project> STRICT=1 EXECUTE_READY=1 MAX_FUNCTIONS=0"
	@echo "      Run terminal full-scope audit gate; proof conversion is advisory unless AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1"
	@echo "  make audit-run-full-serial-board [WS=~/audits/<project>|AUDITS_ROOT=~/audits] [LIVE_STATUS=1] [JSON=1]"
	@echo "      Read-only board of certified, running, failed, and no-run audit-run-full workspaces"
	@echo "  make audit-run-full-status WS=~/audits/<project> [JSON=1]"
	@echo "      Read-only latest audit-run-full verdict for one workspace"
	@echo "  make audit-complete WS=~/audits/<project> [STRICT=1] [JSON=1]"
	@echo "      Read-only L37 full-audit evidence gate for one workspace"
	@echo "  make audit-hacker-logic-bridge WS=~/audits/<project>"
	@echo "      Turn detector output into action graphs and proof obligations"
	@echo "  make mined-findings-hunter-bridge WS=~/audits/<project>"
	@echo "      Convert mined finding rows into hunter bridge artifacts and hacker-question obligations"
	@echo "  make exploit-conversion-loop WS=~/audits/<project> TOP_N=10"
	@echo "      Run the V3 proof workbench in artifact-only mode"
	@echo "  make corpus-driven-hunt WS=~/audits/<project> EMIT_PROOF_QUEUE=1"
	@echo "      Convert trusted corpus invariants and hacker questions into live proof obligations"
	@echo "  make fresh-target-forward-test WS=~/audits/<project>-fwdtest REPO=github.com/Owner/Repo PIN=<sha>"
	@echo "      Run the fresh-target forward-test harness and write a measurement row"
	@echo "  make evm-0day-proof WS=~/audits/<project> CANDIDATE=<row.json>|QUEUE=<queue.json>"
	@echo "      Convert one EVM candidate or queue row into a proof-backed or blocked verdict"
	@echo "  make cvl-spec-risk-scan WS=~/audits/<project> [JSON=1]"
	@echo "      Write .auditooor/cvl_coverage_audit.json from local Certora/CVL specs"
	@echo "  make prove-top-leads WS=~/audits/<project> TOP_N=10"
	@echo "      Build queue-to-harness handoff artifacts for top leads"
	@echo "  make current-to-exploit-conversion-gate JSON=1"
	@echo "      Check whether exploit-conversion work is currently allowed"
	@echo "  make paste-ready WS=~/audits/<project> DRAFT=<draft.md>"
	@echo "      Generate paste-ready output after pre-submit gates"
	@echo "  make audit-closeout WS=~/audits/<project>"
	@echo "      Verify audit/deep/finalization closeout state"

help-dev:
	@echo "auditooor - development/CI commands"
	@echo "  make all                         test + parity + compile"
	@echo "  make ci                          alias for make all"
	@echo "  make test                        Rust fixture suite"
	@echo "  make parity                      parity-report gate"
	@echo "  make compile                     compile DSL patterns"
	@echo "  make docs-check                  docs/stage/tool-reference checks"
	@echo "  make readme-check                README render check"
	@echo "  make tool-ref-check              Makefile tool reference check"
	@echo "  make proof-feedback-regression-test  proof-artifact feedback regressions"
	@echo "  make agent-preflight             mechanical pre-PR guardrails"
	@echo "  make capability-readiness JSON=1 capability readiness dashboard"
	@echo ""
	@echo "WIRE-1 hunt-tool wrappers (Phase MINUS-1):"
	@echo "  make pattern-migration-alert [AUDITS_DIR=~/audits] [OUT=...]   cross-engagement PAID match (P5)"
	@echo "  make refresh-corpus-clusters                                   weekly Solodit embed+cluster refresh (P1)"
	@echo "  make refresh-corpus-clusters-status                            >14d staleness check"
	@echo "  make scan-report-thicken LOG=<scan-hits.txt> [OUT=...]        classifier scoring on scan log (P5)"
	@echo "  make boost-classifier [OUT=...]                                P4 triager training-data pipeline"
	@echo "  make digest-to-patterns WS=<workspace> [SIMILARITY=0.45]      P1 prior-audit pattern extraction"
	@echo "  make reactivate-graveyard [INCLUDE_REWORK=1]                  apply R54 graveyard-audit verdicts"
	@echo "  make reactivate-graveyard-dry                                  dry-run of reactivate-graveyard"
	@echo "  make glider-transpile-all [WRITE=1] [LIMIT=N]                  P3 Glider->DSL transpile chain"
	@echo "  make forge-test TEST=<Test.t.sol> [WS=<ws>]                   intelligent forge runner"
	@echo "  make detector-detect TARGET=<file|dir>                         auto-detect language + run detectors"
	@echo "  make detector-wizard CLASS=... FN_NAME_REGEX=... ...           scaffold new canonical bug class"

help-all:
	@echo "auditooor - smart-contract + Rust/DLT audit toolkit"
	@echo ""
	@echo "PRIMARY TARGETS:"
	@echo "  make test              Run Rust fixture suite (760 assertions should pass)"
	@echo "  make parity            Run parity-report.py; fail if <100%"
	@echo "  make compile           Compile all DSL patterns into detectors/wave17/"
	@echo "  make build             Alias for compile"
	@echo "  make all               test + parity + compile (primary CI gate)"
	@echo "  make ci                Alias for all (used by .github/workflows/ci.yml)"
	@echo "  make known-limitations-check         Single-entry burn-down gate (docs/KNOWN_LIMITATIONS.md)"
	@echo "                                        STRICT=1 promotes advisory WARN to FAIL"
	@echo "  make known-limitations-check-test    Run regression tests for the burn-down gate target"
	@echo "  make inventory         Regenerate docs/TOOLS_INVENTORY.md"
	@echo "  make ledger            Generate docs/LEDGER_SUMMARY.md (per-topic rollup)"
	@echo "  make skill-issues      Regenerate docs/SKILL_ISSUES_STATUS.md rollup"
	@echo "  make dashboard         Engagement pipeline snapshot (iter9 T4; set AUDITS_DIR / THRESHOLD)"
	@echo "  make dashboard-json    Same, JSON output (for CI/pipeline consumers)"
	@echo "  make detector-health-dashboard  Detector-library health snapshot (prior dashboard)"
	@echo "  make forever-status    Read-only snapshot of the forever-mode background loops + watchdog (JSON=1, WATCH=1)"
	@echo "  make verify-loop       Run continuous-verification.sh --once (see docs/VERIFICATION_LOOP.md)"
	@echo "  make gaps CORPUS=<path> Run real-corpus gap analysis (operator-supplied corpus; writes docs/GAP_ANALYSIS.md)"
	@echo "  make gaps-smoke        Hermetic gap-analyzer mechanics smoke (does not measure real corpus parity)"
	@echo "  make docs-check        Validate docs links, stage map, and Makefile tool refs"
	@echo "  make docs-check-playbook Validate failure-mode/playbook structure"
	@echo "  make control-status WS=<workspace>     Local-only auditooorctl status inspector"
	@echo "  make control-snapshot WS=<workspace>   Local-only auditooorctl JSON snapshot (optional OUT=<path>)"
	@echo "  make control-handoff WS=<workspace>    Local-only Claude/Codex handoff packet (AUDIENCE=claude)"
	@echo "  make control-plan WS=<workspace>       Local-only dry-run execution plan via auditooorctl plan"
	@echo "  make control-report WS=<workspace>     Local-only control takeover report"
	@echo "  make control-gaps WS=<workspace>       Local-only auditooorctl gap scorer"
	@echo "  make control-providers WS=<workspace>  Local-only auditooorctl provider task router"
	@echo "  make control-workpacks WS=<workspace>  Local-only bounded provider workpacks (optional OUT=<path>)"
	@echo "  make control-plane-ready WS=<workspace> [STRICT=1] Phase A MCP/brain-prime/high-impact preflight"
	@echo "  make memory-watcher-start      Install + start §M_ARCH L1 event watcher daemon (launchd)"
	@echo "  make memory-watcher-stop       Uninstall L1 watcher daemon"
	@echo "  make memory-watcher-status     L1 watcher daemon status + log tail"
	@echo "  make memory-watcher-self-test  L1 watcher CI self-test (51 events → vault notes, no fsevents needed)"
	@echo "  make memory-gap-analysis       Refresh vault NEXT_LOOP candidates"
	@echo "  make memory-next-loop          Emit bounded next-loop dispatch manifest"
	@echo "  make memory-next-loop-dry-run  Preview bounded next-loop dispatch manifest"
	@echo "  make memory-next-loop-test     Run dispatcher and prompt-lint tests"
	@echo "  make memory-next-loop-smoke    Hermetic analyzer-to-dispatcher smoke"
	@echo "  make goal-loop-status          Emit active continuous-goal loop status"
	@echo "  make goal-loop-status-test     Run goal-loop-status tests"
	@echo "  make batch-checkpoint-status   Say if batched push/docs checkpoint is due (LOOPS=N, JSON=1)"
	@echo "  make batch-checkpoint-status-test Run batch checkpoint status tests"
	@echo "  make batch-boundary-preflight  Run memory/PR hygiene preflight (STRICT=1, PR_BODY=<path>)"
	@echo "  make memory-audit-packet       Emit bounded memory/audit handoff packet"
	@echo "  make memory-audit-packet-test  Run memory-audit-packet tests"
	@echo "  make shared-memory-index       Emit callable shared-memory artifact index"
	@echo "  make shared-memory-index-test  Run shared-memory-index tests"
	@echo "  make memory-brief              Emit compact model handoff briefs from shared-memory index"
	@echo "  make memory-brief-test         Run memory-brief tests"
	@echo "  make obsidian-memory-entrypoints Emit Obsidian/shared-memory entrypoint report"
	@echo "  make obsidian-memory-entrypoints-test Run obsidian-memory-entrypoints tests"
	@echo "  make operational-memory-day-to-day Emit daily operational-memory packet"
	@echo "  make operational-memory-day-to-day-test Run operational-memory-day-to-day tests"
	@echo "  make known-limitations-dispatch Emit known-limitations dispatch queue"
	@echo "  make known-limitations-dispatch-test Run known-limitations-dispatch tests"
	@echo "  make known-limitations-harness-memory-status Emit fail-closed harness/memory status packet"
	@echo "  make known-limitations-harness-memory-status-test Run harness/memory status tests"
	@echo "  make impact-contract-preflight-status Emit KLBQ-010 route-coverage status packet"
	@echo "  make impact-contract-preflight-status-test Run KLBQ-010 route-coverage status tests"
	@echo "  make scanner-wiring-burndown   Emit scanner truth burn-down queue"
	@echo "  make scanner-wiring-burndown-test Run scanner-wiring-burndown tests"
	@echo "  make scanner-worker-next-rows  Select unclaimed scanner rows from latest/local queue"
	@echo "  make scanner-worker-next-rows-test Run scanner-worker-next-rows tests"
	@echo "  make detector-proof-gap-queue  Emit detector proof/fixture gap queue"
	@echo "  make detector-proof-gap-queue-test Run detector-proof-gap-queue tests"
	@echo "  make rust-detector-coverage    Emit Rust detector coverage/lift inventory (latest cached scanner inputs; REFRESH_SCANNER_INPUTS=1 for live)"
	@echo "  make rust-detector-coverage-test Run rust-detector-coverage tests"
	@echo "  make rust-fixture-regression-list Emit dynamic Rust fixture regression detector list"
	@echo "  make rust-fixture-regression-list-test Run Rust fixture regression list tests"
	@echo "  make rust-xfail-burndown       Emit Rust generated-XFAIL burndown packet"
	@echo "  make rust-xfail-burndown-test  Run Rust XFAIL burndown tests"
	@echo "  make harness-execution-queue   Emit dry-run harness execution queue (set IN=<manifest>)"
	@echo "  make harness-execution-queue-test Run harness-execution-queue tests"
	@echo "  make commit-lifecycle-ledger   Emit commit/ref lifecycle ledger"
	@echo "  make commit-lifecycle-ledger-test Run commit-lifecycle-ledger tests"
	@echo "  make commit-mining-next-jobs   Emit offline commit-mining next-job queue"
	@echo "  make commit-mining-next-jobs-test Run commit-mining-next-jobs tests"
	@echo "  make commit-mining-scan-tasks  Emit mirror-verified commit-mining scan tasks"
	@echo "  make commit-mining-scan-tasks-test Run commit-mining-scan-task tests"
	@echo "  make commit-mining-source-review Emit source-review packets from commit-mining scan tasks"
	@echo "  make commit-mining-source-review-test Run commit-mining source-review tests"
	@echo "  make commit-mining-source-disposition Emit source disposition queue from commit-mining source-review packets"
	@echo "  make commit-mining-source-disposition-test Run commit-mining source-disposition tests"
	@echo "  make source-mirror-queue       Emit source mirror/replay queue"
	@echo "  make source-mirror-queue-test  Run source-mirror-queue tests"
	@echo "  make source-mirror-verify      Offline-verify ready source mirror rows"
	@echo "  make source-mirror-verify-test Run source-mirror-verify tests"
	@echo "  make external-intel-refresh    Validate/plan external intel refreshes offline (JSON=1, SOURCE=<id>)"
	@echo "  make external-intel-refresh-test Run external intel registry/runner tests"
	@echo "  make queue-proof-hard-close    Fail-closed exploit queue -> PoC execution closeout"
	@echo "  make field-validation-report   Summarize field-validation readiness signals"
	@echo "  make field-validation-platform-id-gaps WS=<workspace>  Read-only platform-ID backfill gap report"
	@echo "  make audit-workflow-coverage-map Show make audit/deep V3 concept coverage"
	@echo "  make mining-coverage-dashboard Show source-corpus mining freshness/backlog"
	@echo "  make source-miner-backlog-actions Emit read-only source-miner backlog action report"
	@echo "  make lesson-enforcement-inventory Compile triager/outcome prose into lesson predicates"
	@echo "  make phase-b-e-measurement-report Emit Phase B gate + Phase E A/B measurement summary"
	@echo "  make p4-provider-readiness-probe Emit offline P4 provider-readiness probe"
	@echo "  make triager-pre-filing-simulator WS=<workspace> DRAFT=<draft.md> Run local rules-only P4 triager precheck"
	@echo "  make agent-artifact-mine-all AUDITS_ROOT=~/audits Refresh agent-artifact reports + state for all workspaces"
	@echo "  make agent-learning-compiler WS=<workspace> Compile mined artifacts into terminal ledger rows"
	@echo "  make agent-artifact-lesson-candidates Extract advisory lessons from agent artifacts"
	@echo "  make hackerman-sidecar-coverage-report Compare recursive corpus records against hunter sidecars"
	@echo "  make v3-roadmap-sidecars    Refresh V3 roadmap sidecar evidence"
	@echo "  make outcome-lesson-gate    Run outcome/triager lesson gate on a draft/workspace"
	@echo "  make provider-keep-verification-backfill Emit local-verification packets for provider KEEP rows"
	@echo "  make v3-provider-campaign-completeness-gate Enforce approved live-provider campaign accounting"
	@echo "  make v3-provider-source-collection-queue Deduplicate needs-more-source rows into source tasks"
	@echo "  make v3-provider-closure-queue Build source + terminal judgment closure packets"
	@echo "  make hacker-question-workflow-audit Audit hacker-question obligations through proof gates"
	@echo "  make darknavy-web3-mine   Mine DARKNAVY Web3 exploit-analysis pages"
	@echo "  make model-takeover-readiness  Emit fail-closed model takeover readiness packet"
	@echo "  make model-takeover-handoff    Emit bounded provider handoff packet from readiness inputs"
	@echo "  make model-takeover-readiness-test Run model takeover readiness tests"
	@echo "  make model-takeover-handoff-test Run model takeover handoff tests"
	@echo "  make harness-failure-memory    Refresh canonical harness-failure memory (dry-run unless WRITE=1)"
	@echo "  make harness-failure-memory-validate Validate reports/harness_failures.jsonl"
	@echo "  make harness-failure-memory-test Run harness-failure memory tests"
	@echo "  make task-finalization-validate Validate reports/task_finalization.jsonl"
	@echo "  make task-finalization-report   Summarize task finalization ledger"
	@echo "  make task-finalization-pr-status Check PR #607-#638 finalization coverage"
	@echo "  make task-finalization-pr-backfill Backfill PR #607-#638 finalization rows (dry-run unless WRITE=1)"
	@echo "  make task-finalization-test     Run task finalization ledger tests"
	@echo "  make knowledge-gap-validate     Validate reports/knowledge_gaps.jsonl"
	@echo "  make knowledge-gap-list         List open knowledge gaps (JSON=1 for JSON)"
	@echo "  make knowledge-gap-summary      Summarize knowledge-gap ledger"
	@echo "  make knowledge-gap-rebuild-projections Rebuild knowledge-gap vault projections (dry-run unless WRITE=1)"
	@echo "  make knowledge-gap-test         Run knowledge-gap ledger tests"
	@echo "  make exploit-memory-brief WS=~/audits/<project> [JSON=1] Build advisory exploit-memory brief"
	@echo "  make exploit-memory-brief-validate BRIEF=<path> Validate exploit-memory brief JSON"
	@echo "  make exploit-memory-brief-test  Run exploit-memory brief tests"
	@echo "  make outcome-semantics-test     Run no-reason outcome/memory poisoning regressions"
	@echo "  make memory-control-plane-test  Run memory/control-plane regression umbrella"
	@echo "  make vault-mcp-server          Serve bounded MCP-style vault query tools"
	@echo "  make vault-mcp-self-test       Run vault MCP fixture self-test"
	@echo "  make vault-mcp-self-test-regression  Self-test + live vault_resume_context pack-id invariant (CISS-002)"
	@echo "  make vault-mcp-test            Run vault MCP unit tests"
	@echo "  make memory-auto-link WS=~/audits/<project>     Derive workspace memory requirements"
	@echo "  make memory-context-load WS=~/audits/<project>  Load required MCP packs and write receipt"
	@echo "  make cleanup-inventory Regenerate docs/cleanup stale-file inventory"
	@echo "  make stage-reference-check Validate docs/STAGE_REFERENCE.md against engage.py"
	@echo "  make tool-ref-check    Validate Makefile tools/*.py and tools/*.sh references"
	@echo "  make doc-cascade-check Flag stale README/docs/reference entries when a tool changes"
	@echo "                          (set DOC_CASCADE_BASE=<ref> / DOC_CASCADE_ARGS=--working-tree|--json)"
	@echo "  make doc-cascade-check-test  Run check-doc-cascade.py regression tests"
	@echo "  make agent-preflight   Mechanical foot-gun guardrails before agent-PR push"
	@echo "                          (set AGENT_PREFLIGHT_ARGS=--no-network for offline)"
	@echo "  make agent-preflight-test  Run agent-preflight-check.py regression tests"
	@echo "  make dispatch-validate TEMPLATE=<name> PROMPT=<file>  Pre-dispatch prompt validator (gap 6)"
	@echo "                                    See docs/PROVIDER_DISPATCH_TEMPLATES.md"
	@echo "  make dispatch-validate-list       List available dispatch templates"
	@echo "  make dispatch-validate-test       Run dispatch-template.py regression tests"
	@echo "  make dispatch-preflight TEMPLATE=<name> PROMPT=<file> [WORKSPACE=<dir>]"
	@echo "                                    Mandatory validate-then-dispatch wrapper (PR #535)"
	@echo "  make dispatch-preflight-test      Run dispatch-preflight.py regression tests"
	@echo "  make v3-worker-packet WS=~/audits/<project> [SEVERITY=High]  Build canonical worker packet receipt"
	@echo "  make calibration-log-hook PR=<N>  Auto-grade dual-LLM PR review (set DRY_RUN=1 to preview)"
	@echo "  make calibration-log-hook-test    Run llm-pr-review-merge-hook regression tests"
	@echo "  make pattern-merge-rescan SINCE=<commit-or-pr> [WORKSPACES=ws1,ws2]"
	@echo "                                    Re-scan workspaces against patterns added since SINCE"
	@echo "  make pattern-merge-rescan-test    Run pattern-merge-rescan regression tests"
	@echo "  make pattern-taxonomy             V5 Gap-27 - cluster pattern names by token co-occurrence"
	@echo "                                    into reference/pattern_taxonomy.json (used by llm-pr-review.py)"
	@echo "  make pattern-taxonomy-test        Run pattern-taxonomy + findings-to-pattern regression tests"
	@echo "  make logic-flow-bypass-accounting-worklist [SPEC_DIR=<dir>] [OUT_JSON=<path>] [OUT_MD=<path>] [LIMIT=N]"
	@echo "                                    Build advisory corpus-first accounting/value-flow logic-bypass worklist"
	@echo "  make solodit-taxonomy-triage [INPUT=<path>] [FORMAT=json|markdown] [OUTPUT=<path>]"
	@echo "                                    Extract uncategorized Solodit blindspot rows for manual taxonomy assignment"
	@echo "  make solodit-rest-direct [OUT_DIR=<dir>] [LANGUAGE=rust,go] [MAX_PAGES=N] [MIN_SEVERITY=HIGH]"
	@echo "                                    Direct Cyfrin/Solodit REST ingest with language-scoped cursors"
	@echo "  make solodit-language-refresh-test  Run Solodit language-filter regression tests"
	@echo "  make findings-to-pattern FINDING=<md>  V5 Gap-24/34 - convert finding markdown into a CANDIDATE"
	@echo "                                    pattern + TODO fixture scaffolds. Never auto-promotes."
	@echo ""
	@echo "WORKSPACE / ONBOARDING:"
	@echo "  audit start path: make v3-source-first-audit -> make brain-prime -> make hacker-brief"
	@echo "                    -> make audit-hacker-logic-bridge -> make high-impact-execution-bridge"
	@echo "                    -> bash tools/pre-submit-check.sh -> make paste-ready / make loop-finalization-check"
	@echo "                    -> make audit-closeout -> make control-plane-ready"
	@echo "  make v3-source-first-audit WS=~/audits/<project> Run the canonical source-first audit workflow"
	@echo "  make audit WS=~/audits/<project> Run the detector/mining component workflow"
	@echo "  make audit-deep WS=~/audits/<project> Run audit + opt-in deep tools (halmos/medusa/...) - see docs/TOOL_COST_BENEFIT.md"
	@echo "  make audit-deep-overnight WS=~/audits/<project> Strict MCP-preflighted all-profile deep pass for unattended sessions"
	@echo "  make audit-deep-manifest WS=~/audits/<project> [JSON=1] [OUT=<path>] Read-only summary of audit-deep manifests + downstream handoff outputs"
	@echo "  make audit-deep-novel-vectors WS=~/audits/<project> Emit Hackerman novel-vector artifacts under .auditooor/"
	@echo "  make audit-deep-solidity WS=~/audits/<project> Run Solidity deep tools with offline-safe skip artifacts"
	@echo "  make genuine-coverage WS=~/audits/<project> PRODUCE mutation-verified per-function harnesses (the stage function-coverage-completeness.py DEMANDS): emit per-function attack worklist + harness-build dispatch brief + re-run mutation-verify; writes .auditooor/genuine_coverage_manifest.json"
	@echo "  make deep-engines-provision [ENGINE=halmos|medusa|echidna]  W5-D1 install pinned halmos/medusa/echidna into tools/deep-engine-bin/"
	@echo "  make deep-engines-provision-check  W5-D1 offline-safe deep-engine resolution status"
	@echo "  make brain-prime WS=~/audits/<project> Generate brain-prime receipt + ranked first-hunt lanes"
	@echo "  make engage-report-mcp-feed WS=~/audits/<project> Refresh bounded detector clusters via vault_engage_report_context (engage_report.json preferred, md fallback)"
	@echo "  make detector-action-graph-mcp-feed WS=~/audits/<project> DETECTOR=<slug> Query bounded MCP hacker/action-graph context"
	@echo "  make chained-attack-plan-mcp-feed WS=~/audits/<project> Preview bounded MCP chain-plan context"
	@echo "  make chained-attack-plan-mcp-feed-test Run chained plan MCP wrapper tests"
	@echo "  make detector-proof-context WS=~/audits/<project> DETECTOR=<slug>|ALL=1 Preview read-only advisory Solidity detector proof worklist"
	@echo "  make detector-proof-context-test Run detector proof-context wrapper tests"
	@echo "  make detector-provenance-v2 DETECTOR=<id> Resolve the local detector implementation, source refs, and focused tests"
	@echo "                                    Optional: REPO_ROOT=<path> OUT=<path> PRETTY=1"
	@echo "  make attack-class-rank DETECTOR=<slug> FILE=<path> FUNC=<name> CONTEXT='<notes>' Rank local advisory attack-class hypotheses"
	@echo "  make detector-hit-action-graph WS=~/audits/<project> DETECTOR=<slug> Build advisory attacker graph + proof obligations from a detector hit"
	@echo "  make audit-hacker-logic-bridge WS=~/audits/<project> Emit advisory multi-hit action graphs + proof queue from fresh audit output"
	@echo "  make mined-findings-hunter-bridge WS=~/audits/<project> Convert mined findings into hunter bridge + hacker-question obligations"
	@echo "  make hackerman-refresh [DRY_RUN=1] Refresh indexed attacker-memory corpus (Solodit/Rust/fork-pattern ETL)"
	@echo "  make hackerman-index             Rebuild Hackerman indices from existing corpus tags"
	@echo "  make validate-hackerman          Validate hackerman_record YAMLs (auto-dispatches v1/v1.1 by schema_version)"
	@echo "  make predicate-yaml-lint         Advisory lint for DSL predicate YAML keys/shapes (STRICT=1 to fail)"
	@echo "  make schema-tier-enum-validate   Wave-2 W2.7.a gate: record_tier enum contains tier-2-verified-public-archive"
	@echo "  make schema-tier-1-enum-validate Wave-2 PR-A follow-up gate: record_tier + verification_tier enums contain tier-1-officially-disclosed"
	@echo "  make hackerman-chain-candidates-sidecar Build cached chain-candidate rows for MCP reuse"
	@echo "  make hackerman-detector-relationships-sidecar Build cached detector-relationship rows for MCP reuse"
	@echo "  make hackerman-sidecar-refresh-check CHECK=1 JSON=1 Check/refresh detector-relationship + chain-candidate sidecars"
	@echo "  make hackerman-chain-candidates  Rank multi-signal corpus groups as chained exploit candidates"
	@echo "  make hackerman-chain-unify       Construct precondition/postcondition multi-hop exploit chains"
	@echo "  make hackerman-exploit-predicates Emit deterministic exploit predicates from Hackerman records"
	@echo "  make hackerman-predicate-compose Emit composable typed exploit predicates (requires/yields state tokens)"
	@echo "  make hackerman-novel-vector-gen  Emit advisory novel-vector hypotheses (JSON=1 for JSON, JSONL=1 or OUT=<path> for JSONL)"
	@echo "  make hackerman-detector-relationships ENGAGE_REPORT=<path> Join detector hits to Hackerman corpus records"
	@echo "  make hackerman-go-cosmos-inventory Emit Go/Cosmos corpus coverage and import-gap inventory"
	@echo "  make hackerman-go-cosmos-stage-imports OUT_DIR=/private/tmp/hackerman-go-cosmos-stage Stage uncovered Go/Cosmos corpus records for review"
	@echo "  make hacker-brief WS=~/audits/<project> LANE=<id> Generate the lane-scoped hacker brief from MCP recall"
	@echo "  make audit-question-burndown WS=~/audits/<project> Summarize PASS/FAIL/UNKNOWN question debt after brief spawn"
	@echo "  make chained-attack-plans WS=~/audits/<project> Compose local exploit/swarm/big-loss artifacts into advisory chain plans"
	@echo "  make proof-obligation-queue WS=~/audits/<project> Build proof tasks from action graph / brief / chain planning"
	@echo "  make high-impact-execution-bridge WS=~/audits/<project> [ROW=<row_id>] [JSON=1] Bridge High/Critical invariant rows into execution-ready handoff artifacts"
	@echo "  bash tools/pre-submit-check.sh <draft.md> Run submission rule gates before paste-ready/finalization"
	@echo "  make paste-ready WS=~/audits/<project> DRAFT=<draft.md> Generate a paste-ready draft after pre-submit gates pass"
	@echo "  make submission-sync WORKSPACE=~/audits/<project> Refresh nested submissions/SUBMISSIONS.md from local draft state"
	@echo "  make proof-queue-freshness-marker-test Run proof queue freshness marker tests"
	@echo "  make loop-finalization-check MANIFEST=<path>|WS=<ws> Validate per-slice closeout manifests"
	@echo "  make agent-cycle-close WS=~/audits/<project> MANIFEST=<path> [AGENT=codex] [TASK=<slice>] Append close event with strict manifest gate"
	@echo "  make audit-closeout WS=~/audits/<project>  Close-out gate: did the audit actually run? (Codex P0 #1, V5 Gap-23/24)"
	@echo "                          (set REQUIRE_DEEP=1 to fail on missing audit_deep_all_manifest.json,"
	@echo "                           JSON=1 for machine-readable output, WRITE_MANIFEST=1 to persist .audit_logs/audit_closeout_manifest.json)"
	@echo "  make audit-closeout-test  Run audit-closeout-check.py regression tests"
	@echo "  make control-plane-ready WS=~/audits/<project> [JSON=1] [STRICT=1] Dispatch preflight for MCP, brain-prime, and high-impact bridge readiness"
	@echo "  make invariant-ledger WS=~/audits/<project> Init INVARIANT_LEDGER.md + .auditooor/invariant_ledger.json (PR #511 Slice 2; idempotent)"
	@echo "  make invariant-ledger-check WS=~/audits/<project>  Validate ledger schema + artifact refs"
	@echo "                                  (set REQUIRE_HIGH_IMPACT_INVARIANTS=1 to fail on High/Critical rows lacking harness/replay/blocker)"
	@echo "  make invariant-ledger-test       Run invariant-ledger.py regression tests"
	@echo "  make harness-plan WS=~/audits/<project> [ROW=<id>] [ALL=1] [OUT=<path>]  Emit per-row harness plans (PR #526 gap 3)"
	@echo "  make harness-plan-test           Run invariant-harness-planner.py regression tests"
	@echo "  make harness-scaffold WS=~/audits/<project> [ROW=<id>] [ALL=1] [FORCE=1]  Plan + emit executable scaffold (PR #535)"
	@echo "  make harness-scaffold-test       Run harness-scaffold-emitter.py regression tests"
	@echo "  make invariant-harness-gen WS=<workspace> [CONTRACT=<name>] [FORCE=1]  W4.6 baseline echidna/medusa invariant harness + configs"
	@echo "  make invariant-harness-gen-test  Run invariant-harness-generator.py regression tests"
	@echo "  make spark-regtest-harness WS=~/audits/spark  Spin up bitcoind regtest + fund wallets + emit regtest_state.json (L29-Disc-6 CRIT-1 evidence)"
	@echo "  make spark-regtest-teardown WS=~/audits/spark  Stop bitcoind regtest + remove pidfile"
	@echo "  make spark-regtest-harness-test  Smoke-test spark-regtest-harness.sh --check (no daemon)"
	@echo "  make semantic-graph WS=~/audits/<project> Emit .auditooor/semantic_graph.{json,md}"
	@echo "  make semantic-graph-query WS=~/audits/<project> Execute semantic_graph_query worklist specs (set IMPACT_WORKLIST=1 for source_review_handoff specs)"
	@echo "  make semantic-detector-worklist WS=~/audits/<project> Emit advisory detector rewrite tasks from semantic paths"
	@echo "  make semantic-detector-adjudication WS=~/audits/<project> Turn semantic query matches into advisory detector briefs/fixture gates/source-only rows"
	@echo "  make semantic-scanner-inventory WS=~/audits/<project> Emit bounded semantic scanner route/coverage inventory plus detector/fixture task queue"
	@echo "  make callgraph-limitation-queue Generate detector-lint callgraph blocker closure tasks"
	@echo "  make callgraph-terminal-conversion Convert executed callgraph blocker rows into terminal evidence"
	@echo "  make semantic-fixture-smoke-tasks WS=~/audits/<project> Build fixture smoke task manifest, materialize extraction manifests, and ingest smoke JSON"
	@echo "  make semantic-fixture-smoke-gate WS=~/audits/<project> Gate semantic detector fixture rows on paired fixture smoke output"
	@echo "  make semantic-live-depth-blockers WS=~/audits/<project> Join semantic rows to live proof-pair/depth blockers"
	@echo "  make semantic-live-depth-queue WS=~/audits/<project> Verify same-block proof pairs that close semantic/live depth rows"
	@echo "  make live-topology-proof-requirements WS=~/audits/<project> Emit offline proof-pair requirements when live topology is absent"
	@echo "  make live-topology-proof-executor WS=~/audits/<project> Validate proof requirements against live topology rows"
	@echo "  make rust-runtime-semantic-blockers WS=~/audits/<project> Emit Rust/DLT runtime-semantic blocker queue and safe detectorization handoffs"
	@echo "  make critical-hunt WS=~/audits/<project> Opt-in high-impact surface shortlist (never submission text)"
	@echo "  make critical-hunt-test  Run semantic graph / critical hunt / dossier tests"
	@echo "  make detect WS=<workspace> DETECTOR=<id> [OUTPUT=<json>]  Canonical detector runner (Wave O-B Gap#2)"
	@echo "                                    All detector IDs: python3 tools/run-detector.py --list-detectors"
	@echo "  make detect-test              Run run-detector.py regression tests"
	@echo "  make rust-fixture-detector DETECTOR=<id>  Re-run one Rust fixture pair via tools/rust-detect.py --only/--file"
	@echo "  make precision-detector DETECTOR=<id> [FIXTURES=N]  Run detector-precision-matrix for one Solidity detector"
	@echo "                                    Optional: JSON_OUT=<path> MD_OUT=<path> WORKERS=<n> TIMEOUT=<sec> SEED=<n> NO_SPOT_CHECK=1"
	@echo "  make inventory-smoke-detector DETECTOR=<id>  Run inventory-smoke-test for one Solidity detector"
	@echo "                                    Optional: OUTPUT_DIR=<path> WORKERS=<n> INCLUDE_GRAVEYARD=1"
	@echo "  make rust-cache-miss-scan WS=~/audits/<project> [STRICT=1] Rust cache-miss / silent-Ok policy scanner (PR #546 K7-3)"
	@echo "  make base-rpc-crash-probe WS=<ws> [STRICT=1]   Wave-10 Lane F A8 RPC-crash probe (default-to-kill)"
	@echo "  make base-rpc-crash-probe-test  Tests for the A8 RPC-crash probe"
	@echo "  make rust-decode-bomb-scan WS=<ws> [JSON=1] [STRICT=1]  Generic Rust decode-bomb scanner (PR #556 Wave 6 G)"
	@echo "  make rust-decode-bomb-scan-test  Tests for the Rust decode-bomb scanner"
	@echo "  make base-rust-swival-shape-scan WS=<ws> [JSON=1] [STRICT=1]  Swival-derived Rust candidate scanner"
	@echo "  make base-rust-swival-shape-scan-test  Tests for the Swival-derived Rust candidate scanner"
	@echo "  make corpus-detectorization-inventory [WS=<ws>]  Inventory Swival/ZKBugs/ReCon/source-mining detectorization routes"
	@echo "  make source-proof-record WS=~/audits/<project> CANDIDATE=<id> [VERDICT=<proved_source_only|killed|blocked_missing_impact_contract>]"
	@echo "                                    Record source-only proof evidence under source_proofs/"
	@echo "  make poc-execution-record WS=~/audits/<project> BRIEF=<md> RESULT=<proved|disproved|blocked_env|blocked_path|needs_human> [BRIDGE_ROW=<id> PROOF_TASK_ID=<id> DETECTOR=<slug>]"
	@echo "                                    Record PoC command/output evidence under poc_execution/ with optional advisory proof-task linkage"
	@echo "  make poc-execution-record-test    Run PoC execution manifest regression tests"
	@echo "  make deep-counterexample-record WS=~/audits/<project> ENGINE=<engine> TARGET=<function>"
	@echo "                                    Record replayable deep_counterexample.v1 evidence"
	@echo "  make deep-counterexample-record-test  Run deep counterexample schema tests"
	@echo "  make deep-counterexample-collect WS=~/audits/<project>  Collect fuzz/symbolic counterexample manifests"
	@echo "  make deep-counterexample-collect-test Run deep counterexample collector tests"
	@echo "  make deep-counterexample-replay-scaffold RECORD=<deep_counterexample.v1.json>"
	@echo "                                    Create skipped Forge replay scaffold from a deep counterexample"
	@echo "  make deep-counterexample-replay-scaffold-test Run replay scaffold tests"
	@echo "  make deep-counterexample-queue WS=~/audits/<project>  Build model-routed replay execution queue"
	@echo "  make deep-counterexample-queue-test Run deep counterexample queue tests"
	@echo "  make chimera-scaffold WS=~/audits/<project> ROW=<ledger-row>  Scaffold advisory Recon/Chimera harness"
	@echo "  make chimera-ledger-scaffold WS=~/audits/<project>  Batch scaffold advisory Chimera harnesses from Solidity ledger rows"
	@echo "  make recon-log-bridge WS=~/audits/<project> ENGINE=<medusa|echidna|halmos> LOG=<path>  Convert fuzz log to advisory deep counterexample"
	@echo "  make coverage-introspect WS=~/audits/<project> V5 Gap-46 - opt-in coverage-gaps deep profile (NOT in DEEP_PROFILE=all)"
	@echo "  make p1-extraction-queue        Build #311 P1 fixture extraction queue"
	@echo "                                  (set SEARCH_ROOTS='~/audits/foo /archive/bar', OUT=<dir>, TOP=<n>, QUEUE_MAX=<n>)"
	@echo "  make p1-extraction-run          Execute a P1 extraction queue with per-row logs/manifest"
	@echo "                                  (set QUEUE=<json>, OUT=<manifest>, LIMIT=<n>, DRY_RUN=1, ACCEPT=1)"
	@echo "  make source-ref-replay-manifest-fixture  Rebuild reports/source_ref_replay_manifest_fixture.json from checked-in local fixtures"
	@echo "  make zkbugs-ingest              Import a local zksecurity/zkbugs checkout into farming briefs"
	@echo "  make zkbugs-brief-queue         Build Kimi/Minimax prompt queue from zkBugs briefs"
	@echo "  make zkbugs-task-map            Route zkBugs rows into detector/invariant/replay tasks"
	@echo "  make zkbugs-provider-result     Record Kimi/Minimax zkBugs triage verdicts"
	@echo "  make zkbugs-provider-loop       Run resumable Kimi->Minimax zkBugs farming loop"
	@echo "  make zkbugs-pull                Run full zkBugs pipeline once (ingest -> queue -> loop --once -> result)"
	@echo "                                  (DRY_RUN=1 prints plan; LIVE=1 required to call providers)"
	@echo "  make hackerman-proof-artifact-accepted-writeback  Emit accepted outcome proof sidecar"
	@echo "  make zkbugs-status              Print zkBugs corpus counts, queue depth, last-pull timestamp"
	@echo "  make circom-detect WS=<path>    Run lightweight Circom text detectors"
	@echo "  make cosmos-detect WS=<path>    Run Wave 2 Cosmos-SDK Go DSL executor (backend: cosmos)"
	@echo "  make cosmos-production-harness-tasks POC_DIR=... [CLAIM_FILE=...] [ARTIFACT_DIR=...]  Emit Cosmos production-harness task artifacts"
	@echo "  make cosmos-production-harness-evidence-pack EXEC_RECORD=... [OUT_MD=...]  Summarize triager evidence rows from a Cosmos exec record"
	@echo "  make solana-detect WS=<path>    Run W6-7 Solana/SVM detector batch (Rust/Anchor)"
	@echo "  make solana-detect-test         Run solana_wave1 detector fixture regression"
	@echo "  make go-txid-chain-truth-scan WS=<path> [OUT=<path>]  Advisory-only Go txid chain-truth seed scanner"
	@echo "  make go-refund-tweak-survivability-scan WS=<path> [OUT=<path>]  Advisory-only Go refund/key-tweak scanner"
	@echo "  make engage WORKSPACE=~/audits/<project> Run lower-level stage control"
	@echo "  make bootstrap         One-shot new-clone setup (deps + venv + make all) - see docs/ONBOARDING.md"
	@echo "  make init              Initialize optional Glider query corpus submodule"
	@echo "  make update            Pull latest versions of all submodules"
	@echo "  make setup PROJECT=xyz Scaffold a new audit workspace at ~/audits/xyz"
	@echo "  make new-engagement NAME=<slug> SOURCE=<url> Spin up full engagement workspace (9-step scaffold; idempotent)"
	@echo "                          see docs/ENGAGEMENT_3_KICKOFF.md §2"
	@echo "  make audit-prep WS=~/audits/<project>  Scaffold RUBRIC_COVERAGE.md, ASSET_PLAN_*.md, OOS_CHECKLIST.md"
	@echo "                          Run after editing SCOPE.md + SEVERITY.md, before make audit"
	@echo "  make workspace-inventory Inventory local ~/audits workspaces and artifacts"
	@echo "  make intake-baseline WORKSPACE=~/audits/<project> Write mechanical intake/PDF/scanner-readiness artifacts"
	@echo "  make intake-saturation-score WS=~/audits/<project> Write prior-audit module saturation artifact"
	@echo "  make submission-tracker-check WORKSPACE=~/audits/<project> Validate SUBMISSIONS.md consistency"
	@echo "  make record-submission WS=~/audits/<project> PLATFORM=<p> ID=<id> URL=<url> Record a filed report"
	@echo "  make record-pending-filed-without-platform-id WS=~/audits/<project> LOCAL_ID=<id> Record filed-without-platform-ID pending tracker row"
	@echo "  make record-outcome WS=~/audits/<project> ID=<id> STATE=<state> Record a triager outcome"
	@echo "  make update-outcome WS=~/audits/<project> FINDING=<id> VERDICT=<state> [NEW_RULE_CODIFIED=1] Post-triage outcome update"
	@echo "  make list-submissions WS=~/audits/<project> [OUTCOME=<state>] List tracked submissions"
	@echo "  make validate-outcome-ledger WS=~/audits/<project> [STRICT=1] Audit P0-4 scoreboard linkage in outcomes.jsonl"
	@echo "  make outcome-telemetry AUDITS_DIR=~/audits Build accept/dupe/reject dashboard"
	@echo "  make outcome-telemetry-test Run the outcome telemetry smoke test"
	@echo "  make cost-summary WORKSPACE=~/audits/<project> Print per-stage walltime + est_cost_usd (PR 210, advisory)"
	@echo "  make cost-telemetry-test Run the cost telemetry offline test suite (PR 210)"
	@echo "  make fork-replay WS=<ws> FN=<id> [PROTOCOL=<name>] [BLOCK=N] [TX=0x...] [DRY_RUN=1|HERMETIC=1]"
	@echo "                           F4 fork-replay harness - standardized PoC replay (act13-fork-replay)"
	@echo "  make fork-replay-hermetic  Hermetic self-test (no RPC required)"
	@echo "  make fork-replay-test    Run fork replay artifact smoke test"
	@echo "  make fuzz-runner-test    Run bounded fuzz runner smoke test (advisory; not in make all)"
	@echo "  make fuzz-campaign WS=<ws> TARGET=<C>  V5 PR4 fuzz campaign wrapper (advisory)"
	@echo "  make fuzz-campaign-test  Run fuzz-campaign wrapper hermetic tests"
	@echo "  make fuzz-quick WS=<ws> [TARGETS=5]   Seed/emit latest FUZZ lane targets into audit/corpus_tags/<ws>/fuzz_targets.jsonl"
	@echo "  make fuzz-quick-test     Run fuzz target corpus emission tests"
	@echo "  make scope-reasoner DRAFT=<path>  Run scope reasoner on a single draft (advisory-only)"
	@echo "  make scope-reasoner-test          Run scope-reasoner regression tests (capv3 iter2 T5)"
	@echo "  make fuzz-runner-manifest-schema-test  Run capv3-iter1-T1 manifest regression (advisory; not in make all)"
	@echo "  make symbolic-runner-test Run symbolic runner smoke test (Phase C, advisory; not in make all)"
	@echo "  make econ-simulator-test Run economic-simulator prototype tests (PR 207, advisory; not in make all)"
	@echo "  make econ-simulator-live-test Run econ-simulator live-mode offline tests (PR 207-b, advisory; not in make all)"
	@echo "  make invariant-templates-test    Run formal invariant library smoke tests (PR 110)"
	@echo "  make invariant-templates-check   Check invariant template files + MANIFEST exist (cheap)"
	@echo "  make economic-risk-card WORKSPACE=~/audits/<p> Generate hypothesis-generating economic risk card (PR 111)"
	@echo "  make economic-risk-card-test     Run economic-risk-card offline smoke tests (PR 111)"
	@echo "  make foundry-version-report WS=<ws>  Offline Foundry version inventory"
	@echo "  make foundry-v17-blocker-closure     Summarize v1.7 dry-run blockers"
	@echo "  make high-impact-execution-bridge WS=<ws> [ROW=<id>] [JSON=1]  Bridge High/Critical invariant rows to scaffold + poc-execution-record handoffs (NOT proof)"
	@echo "  make harness-binding-manifest INPUT=<plan.{json,jsonl}> OUT=<manifest.json> [WS=<workspace>]"
	@echo "                                    Build local-only harness binding manifests from plan/report rows"
	@echo "  make source-ref-replay-manifest INPUT=<findings.{json,jsonl}> OUT=<manifest.json>"
	@echo "                                    Preserve local-only GitHub source refs for replay/citation review"
	@echo "  make source-root-blocker-emitter INPUT=<locator.json> OUT=<blockers.{json,jsonl}> [JSONL=1]"
	@echo "                                    Emit local-only source-root knowledge-gap blockers from locator reports"
	@echo "  make local-corpus-commit-ref-inventory INPUTS='<paths...>' OUT=<inventory.json>"
	@echo "                                    Inventory local corpus GitHub commit/source refs without network access"
	@echo "  make scanner-wiring-truth-inventory OUT=<inventory.json> [REPO_ROOT=<path>] [LIMIT=<n>]"
	@echo "                                    Emit local scanner wiring truth ledger for memory dispatch"
	@echo "  make reports           Clone the Hexens audit report archive to /tmp/hexens-reports"
	@echo "  make extract DIR=<dir> Extract all PDFs in DIR to plain text (.txt alongside)"
	@echo "  make originality KW=<kw> Grep all audit corpora for keyword KW"
	@echo "  make submission-sync WORKSPACE=~/audits/<project> Summarize STATUS.md counts from the active submission ledger"
	@echo "  make clean-submissions WORKSPACE=~/audits/<project> Render triager-clean drafts from nested submissions/SUBMISSIONS.md"
	@echo "  make clean-engage-candidates WORKSPACE=~/audits/<project> Render triager-clean engage_candidates drafts"
	@echo "  make clean             Remove scratch files"
	@echo "  make vault-refresh     Build Obsidian knowledge vault (all patterns/detectors/findings)"
	@echo "  make vault-sync        Incremental vault sync (changed sources only)"
	@echo "  make vault-status      Vault staleness status"
	@echo "  make memory-rollup-daily [DATE=YYYY-MM-DD]  Daily rollup (L2 memory layer)"
	@echo "  make memory-rollup-weekly [WEEK=YYYY-W##]   Weekly rollup with trend lines"
	@echo "  make memory-rollups-backfill                Backfill last 30 days of daily + 5 weeks of weekly"

# ─── Core repo maintenance targets ───────────────────────────────────────────

test:
	@bash detectors/rust_wave1/test_fixtures/test_detectors.sh

parity:
	@python3 tools/parity-report.py > docs/R94_PARITY_REPORT.md 2>/tmp/.parity.err
	@cat /tmp/.parity.err | tail -3
	@if ! grep -q "bidirectional=100.0%" /tmp/.parity.err docs/R94_PARITY_REPORT.md 2>/dev/null; then \
	  echo "[parity] FAIL - not 100%"; \
	  tail -8 docs/R94_PARITY_REPORT.md; \
	  exit 1; \
	fi
	@echo "[parity] ✅ 100.0% bidirectional"

compile: build compile-regression-guard detector-fp-shape-lint

build:
	@python3 tools/pattern-compile.py --all

# Burn-down item #12 (P1-1): exits non-zero if any of the four
# malformed-YAML / unsupported-key shapes regress. Self-contained - the
# tests build synthetic YAMLs in tempdirs and never touch the live
# `reference/patterns.dsl/` corpus. Running this from `make compile`
# means a new bad-shape pattern emitted by `pattern-compile.py` cannot
# silently land alongside legitimate detectors.
compile-regression-guard:
	@python3 -m unittest \
	    tools.tests.test_pattern_compile_documentation_only \
	    tools.tests.test_pattern_compile_regressions

# Opt-in burn-down convenience: compile every YAML under both strict
# flags. Currently fails on the legacy 1,400+ corpus by design - use
# this when burning down individual rows rather than as a CI gate.
compile-strict:
	@python3 tools/pattern-compile.py --all --strict-all

inventory:
	@python3 tools/generate-tools-inventory.py

# ACT-15 smoke-mode targets (foot-gun #20 hardening - always export the flag)
inventory-smoke:
	@AUDITOOOR_FIXTURE_SMOKE_MODE=1 python3 tools/inventory-smoke-test.py \
		--output-dir /private/tmp/auditooor-inventory \
		--workers 4

inventory-smoke-ci:
	@python3 -m unittest \
		tools.tests.test_inventory_smoke_test \
		tools.tests.test_detector_precision_matrix \
		-v

smoke-tooling-test: inventory-smoke-ci

inventory-smoke-detector:
	@if [ -z "$(DETECTOR)" ]; then echo "usage: make inventory-smoke-detector DETECTOR=<id> [OUTPUT_DIR=<path>] [WORKERS=<n>] [INCLUDE_GRAVEYARD=1]"; exit 2; fi
	@AUDITOOOR_FIXTURE_SMOKE_MODE=1 python3 tools/inventory-smoke-test.py \
		--output-dir "$(if $(OUTPUT_DIR),$(OUTPUT_DIR),/private/tmp/auditooor-inventory)" \
		--detector "$(DETECTOR)" \
		--workers "$(if $(WORKERS),$(WORKERS),4)" \
		$(if $(INCLUDE_GRAVEYARD),--include-graveyard)

silent-detector-diagnostic:
	@python3 tools/silent-detector-diagnostic.py \
		--output-dir /private/tmp/auditooor-inventory

silent-detector-diagnostic-smoke:
	@AUDITOOOR_FIXTURE_SMOKE_MODE=1 python3 tools/silent-detector-diagnostic.py \
		--output-dir /tmp/silent_d_pass3_with_smoke_mode \
		--run-smoke


ledger:
	@python3 tools/ledger-summary.py

skill-issues:
	@python3 tools/skill-issues-rollup.py

# Iter9 T4: engagement dashboard operator-friendly wrappers.
# `make dashboard` = engagement-pipeline snapshot (markdown).
# `make dashboard-json` = same, JSON for CI/pipeline consumers.
# No auto-hook: operator invokes manually at iter close.
dashboard:
	@python3 tools/engagement-dashboard.py \
	  --audits-dir $(if $(AUDITS_DIR),$(AUDITS_DIR),$(HOME)/audits) \
	  $(if $(THRESHOLD),--threshold $(THRESHOLD))

dashboard-json:
	@python3 tools/engagement-dashboard.py \
	  --audits-dir $(if $(AUDITS_DIR),$(AUDITS_DIR),$(HOME)/audits) \
	  $(if $(THRESHOLD),--threshold $(THRESHOLD)) \
	  --json

# Prior `dashboard` behavior (pre-iter9-T4) preserved at explicit target:
# the detector-library health snapshot.
detector-health-dashboard:
	@python3 tools/detector-health-dashboard.py

# KLBQ-015 A2 + A8: extract detector seeds from engagement verdicts /
# closeouts / HOLD_NOTE markdowns. Emits YAML stubs under
# detectors/from_verdicts/ for downstream detector authors to lift into
# real DSL / regex / AST rules.
extract-detector-seeds:
	@python3 tools/verdict-seed-extractor.py --out-dir detectors/from_verdicts

# Wave-2 #10: mine an external-findings family into the canonical derived corpus
# then promote it via the existing invariant_library_extended +
# detector_synthesis_v2 routers (mirrors the zkbugs-dataset wiring). Provide a
# findings source via FINDINGS_MD=<file> or FINDINGS_JSON=<file> and a
# FAMILY=<bug-class keyword>. DRY_RUN=1 to preview the promotion only.
.PHONY: external-findings-mine
external-findings-mine: ## Mine FAMILY external findings into derived/ then promote (FINDINGS_MD=|FINDINGS_JSON= FAMILY= [DRY_RUN=1])
	@if [ -z "$(FAMILY)" ]; then echo "ERROR: FAMILY=<bug-class keyword> required"; exit 2; fi
	@if [ -z "$(FINDINGS_MD)" ] && [ -z "$(FINDINGS_JSON)" ]; then \
	  echo "ERROR: FINDINGS_MD=<file> or FINDINGS_JSON=<file> required"; exit 2; fi
	@python3 tools/external-findings-miner.py \
	  --family "$(FAMILY)" \
	  $(if $(FINDINGS_MD),--findings-md "$(FINDINGS_MD)") \
	  $(if $(FINDINGS_JSON),--findings-json "$(FINDINGS_JSON)") \
	  --to-derived
	@python3 tools/promote-mined-to-canonical.py \
	  --only-router invariant_library_extended \
	  --only-router detector_synthesis_v2 \
	  $(if $(DRY_RUN),--dry-run) --json

dashboard-html:
	@python3 tools/health-dashboard-html.py

# Forever-mode observability: read-only health snapshot of the 5 background
# loops + watchdog. See tools/forever-mode-status.py docstring + 30/10 Step 5.
# Pass JSON=1 for JSON output; WATCH=1 for 30s refresh.
forever-status:
	@python3 tools/forever-mode-status.py \
	  $(if $(JSON),--json) \
	  $(if $(WATCH),--watch)

registry-disk-consistency-check:
	@python3 tools/registry-disk-consistency-check.py

registry-quarantine-check:
	@python3 tools/registry-quarantine-fakes.py --json-out /tmp/_quarantine_check.json

all: test parity compile registry-disk-consistency-check registry-quarantine-check cross-workspace-finding-graph proof-feedback-regression-test
	@echo ""
	@echo "[all] ✅ test + parity + compile + registry-disk-consistency-check + registry-quarantine-check + cross-workspace-finding-graph + proof-feedback-regression-test all passed"

proof-feedback-regression-test:
	@python3 -m unittest \
	  tools.tests.test_hackerman_backfill_proof_artifact_path \
	  tools.tests.test_hackerman_capability_status \
	  tools.tests.test_proof_artifact_accepted_writeback \
	  -v

# §K cross-workspace intake seed (FIX 3) - pull prior same-family/language
# learnings from the corpus at audit-start and write a brief-injectable seed
# to <ws>/.auditooor/cross_workspace_seed.{json,md}. Advisory: a vault failure
# records a degrade reason but never fails the audit. Wired into `make audit`
# just before hacker-brief so the seed is present when briefs are assembled.
cross-seed:
	@if [ -z "$(WS)" ]; then \
	  echo "usage: make cross-seed WS=<workspace> [LIMIT=15]"; exit 2; fi
	@python3 tools/cross-workspace-seed.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(LIMIT),--limit "$(LIMIT)")

# §K cross-workspace state - finding graph (strict mode; fails on drift)
cross-workspace-finding-graph:
	@python3 tools/cross-workspace-finding-linker.py \
	  $(if $(AUDITS_DIR),--audits-dir "$(AUDITS_DIR)") \
	  --out reports/cross_workspace_finding_graph.json \
	  --strict

# §K cross-workspace state - dedup check before filing
cross-workspace-dedup-check:
	@if [ -z "$(SUB)" ]; then \
	  echo "usage: make cross-workspace-dedup-check SUB=<paste-ready.md> [WS=<workspace>]"; exit 2; fi
	@python3 tools/cross-workspace-duplicate-check.py "$(SUB)" \
	  $(if $(WS),--workspace "$(WS)") \
	  $(if $(AUDITS_DIR),--audits-dir "$(AUDITS_DIR)")

# §K cross-workspace state - recurrence promotion signal
cross-workspace-recurrence:
	@python3 tools/recurrence-as-promotion-signal.py \
	  $(if $(AUDITS_DIR),--audits-dir "$(AUDITS_DIR)") \
	  --out reports/tier_s_candidates.json

# §K cross-workspace state - full state aggregator
cross-workspace-state:
	@python3 tools/cross-workspace-state-aggregator.py \
	  $(if $(AUDITS_DIR),--audits-dir "$(AUDITS_DIR)") \
	  --out reports/cross_workspace_state.json

ci: all

ci-check: registry-disk-consistency-check registry-quarantine-check
	@python3 tools/ci-check-all.py

verify-loop:
	@bash tools/continuous-verification.sh --once

gaps:
	@test -n "$(CORPUS)" || { echo "usage: make gaps CORPUS=/path/to/findings.json (or run make gaps-smoke for hermetic CI mechanics)" >&2; exit 2; }
	@python3 tools/gap-analyzer.py "$(CORPUS)"

gaps-smoke:
	@echo "[gaps-smoke] hermetic mechanics check (does not measure real corpus parity)" >&2
	@python3 tools/gap-analyzer.py --smoke \
	    --out "$${TMPDIR:-/tmp}/auditooor_gap_analysis_smoke.md" \
	    --manifest .auditooor/gap_analysis_smoke.json

detector-dedupe:
	@python3 tools/detector-dedupe.py

fixture-dupe:
	@python3 tools/fixture-duplicate-detector.py

cross-link:
	@python3 tools/cross-link-validator.py --strict --scope repo-only \
	  --path README.md --path docs/README.md --path docs/HACKATHON_GUIDE.md \
	  --path docs/JUDGE_WALKTHROUGH.md --path docs/ORDERED_ZERO_DAY_PIPELINE_ROADMAP_2026-07-17.md \
	  --report-out "$${TMPDIR:-/tmp}/auditooor-cross-link-report.md"

cross-link-suggestions:
	@python3 tools/cross-link-validator.py --fix-suggestions --scope repo-only

cross-link-full:
	@python3 tools/cross-link-validator.py --fix-suggestions --scope full

.PHONY: judge-check
judge-check: ## Run the offline public review suite used by hackathon judges
	@python3 -m unittest \
	  tools.tests.test_pipeline_manifest_validate \
	  tools.tests.test_pipeline_receipt \
	  tools.tests.test_pipeline_state_machine \
	  tools.tests.test_pipeline_full_executor_authority \
	  tools.tests.test_pipeline_full_step_order_and_gaps \
	  tools.tests.test_readme_runbook_manifest_v2 \
	  tools.tests.test_judge_demo
	@python3 tools/check-stage-reference.py
	@python3 tools/check-makefile-tool-refs.py
	@python3 tools/cross-link-validator.py --strict --scope repo-only \
	  --path README.md --path docs/README.md --path docs/HACKATHON_GUIDE.md \
	  --path docs/JUDGE_WALKTHROUGH.md --path docs/ORDERED_ZERO_DAY_PIPELINE_ROADMAP_2026-07-17.md \
	  --report-out "$${TMPDIR:-/tmp}/auditooor-cross-link-report.md"

.PHONY: judge-demo
judge-demo: ## Show fail-closed ordering using the real manifest and state machine
	@python3 tools/judge-demo.py

stage-reference-check:
	@python3 tools/check-stage-reference.py

tool-ref-check:
	@python3 tools/check-makefile-tool-refs.py

# Flag stale README / docs / reference entries when a tool/script
# changes in the current diff (default base origin/main). Read-only -
# never edits docs. Exit 1 only when at least one STALE finding is
# detected; REVIEW findings are advisory and exit 0.
#
#   make doc-cascade-check                       # diff vs origin/main
#   make doc-cascade-check DOC_CASCADE_BASE=main # custom base
#   make doc-cascade-check DOC_CASCADE_ARGS=--working-tree
#   make doc-cascade-check DOC_CASCADE_ARGS=--json
DOC_CASCADE_BASE ?= origin/main
VAULT ?= obsidian-vault
# brain-prime is advisory; wall-clock budget so a large external/ tree degrades
# instead of spinning. Override with BRAIN_PRIME_TIMEOUT=<secs> or set
# BRAIN_PRIME_SKIP=1 to bypass entirely (see make audit call sites).
BRAIN_PRIME_TIMEOUT ?= 180
doc-cascade-check:
	@python3 tools/check-doc-cascade.py --base $(DOC_CASCADE_BASE) $(DOC_CASCADE_ARGS)

doc-cascade-check-test:
	@python3 -m unittest tools.tests.test_check_doc_cascade -v

agent-preflight:
	@python3 tools/agent-preflight-check.py $(AGENT_PREFLIGHT_ARGS)

agent-preflight-test:
	@python3 -m unittest tools.tests.test_agent_preflight_check -v

# Auto-grade a single merged PR's dual-LLM review verdict pair against the
# merge outcome and append per-provider rows to
# tools/calibration/llm_calibration_log.jsonl. Read-only on PR data.
#   make calibration-log-hook PR=215            # one PR
#   make calibration-log-hook PR=215 DRY_RUN=1  # preview only
calibration-log-hook:
	@if [ -z "$(PR)" ]; then \
		echo "usage: make calibration-log-hook PR=<N> [DRY_RUN=1]"; \
		exit 2; \
	fi
	@python3 tools/llm-pr-review-merge-hook.py \
		$(if $(DRY_RUN),--dry-run,) \
		process $(PR)

calibration-log-hook-test:
	@python3 -m unittest tools.tests.test_llm_pr_review_merge_hook -v

# Codex P0 #2 - operator-driven post-merge pattern rescan.
# Re-scans recently active workspaces against patterns added since SINCE
# (commit SHA or PR number). Outputs <ws>/postmerge_rescan_<date>.md plus
# <ws>/.audit_logs/postmerge_rescan_<date>.json. NOT CI-driven.
# Examples:
#   make pattern-merge-rescan SINCE=252
#   make pattern-merge-rescan SINCE=ed8e076e WORKSPACES=~/audits/<project-a>,~/audits/<project-b>
pattern-merge-rescan:
	@if [ -z "$(SINCE)" ]; then \
		echo 'usage: make pattern-merge-rescan SINCE=<commit-or-pr> [WORKSPACES=ws1,ws2]'; \
		exit 2; \
	fi
	@python3 tools/pattern-merge-rescan.py --since "$(SINCE)" \
		$(if $(WORKSPACES),--workspaces "$(WORKSPACES)") \
		$(if $(DRY_RUN),--dry-run)

pattern-merge-rescan-test:
	@python3 -m unittest tools.tests.test_pattern_merge_rescan -v

docs-check: stage-reference-check tool-ref-check cross-link detector-registry-completeness universal-task-ledger-check vault-ontology-check section-sources-collision-check agents-md-sync mcp-pin-drift-check cross-lang-detector-map-check hackerman-tooling-index-check mcp-callable-count-check capability-role-enum-check

# WAVE-2 items 11+12: fail-closed enum assertion that every capability record
# carries a role in {finder, referee, infra}. Guards against a regen or a
# hand-edit dropping/mistyping the machine-derivable role field.
.PHONY: capability-role-enum-check
capability-role-enum-check:
	@python3 -c "import json,sys,collections; \
p='reference/capability_inventory.jsonl'; \
valid={'finder','referee','infra'}; \
recs=[json.loads(l) for l in open(p) if l.strip()]; \
bad=[(i,r.get('id'),r.get('role')) for i,r in enumerate(recs) if r.get('role') not in valid]; \
c=collections.Counter(r.get('role') for r in recs); \
sys.exit('[capability-role-enum-check] FAIL %d record(s) with role not in %s: %s'%(len(bad),sorted(valid),bad[:10])) if bad else print('[capability-role-enum-check] OK %d records, roles=%s'%(len(recs),dict(c)))"

.PHONY: hackerman-tooling-index-check
hackerman-tooling-index-check:
	@python3 -m unittest tools.tests.test_hackerman_tooling_index -v

# Wave-1 hackerman capability lift (PR #726) - cross-link audit for the
# hackerman / wave / PR_726 doc family. Walks docs/HACKERMAN*.md,
# docs/WAVE*.md, docs/PR_726*.md and verifies every internal Markdown
# link target resolves on disk. Emits per-doc verdict (clean / broken-
# links) plus a summary at docs/HACKERMAN_DOCS_CROSS_LINK_AUDIT_2026-05-16.md.
# Pass ARGS="--strict" to fail closed on any broken link.
.PHONY: hackerman-docs-cross-link-audit
hackerman-docs-cross-link-audit:
	@python3 tools/hackerman-docs-cross-link-audit.py --report-out docs/HACKERMAN_DOCS_CROSS_LINK_AUDIT_2026-05-16.md $(ARGS)

# Wave-1 hackerman capability lift (PR #726) - immutable Wave-1 close-state
# shipment receipt. Captures PR #726 commit count + HEAD SHA + corpus
# baseline SHA + total records + tier distribution + Wave-2 readiness
# verdict + all hackerman-* target names + vault_* MCP callables + the
# HACKERMAN docs inventory into a canonical envelope
# (auditooor.hackerman_wave1_shipment_receipt.v1). Default output path:
# audit/wave1_snapshots/shipment_receipt/<utc-date>.json. Pass
# RECEIPT_ARGS="--strict" to fail closed when readiness != ready, or
# RECEIPT_ARGS="--baseline-path <p> --out <p>" for explicit pinning.
.PHONY: hackerman-wave1-shipment-receipt
hackerman-wave1-shipment-receipt:
	@python3 tools/hackerman-wave1-shipment-receipt.py $(RECEIPT_ARGS)

# wave-2 #11: LIFT-28 corpus enrichment. The enricher had ZERO make targets, so
# global_chain_templates sat enriched on only 1/2653 records while 3 per-fn hunt
# consumers (per-fn-question-ranker, dispatch-agent-with-prebriefing, the MCP server)
# read applicable_contract_kinds / applicable_function_role_patterns. This target keeps
# both corpora (hacker-questions + chain-templates) enriched so per-fn matching works.
.PHONY: corpus-lift28-enrich
corpus-lift28-enrich:
	@python3 tools/lift28-enrich-corpora.py $(if $(DRY_RUN),--dry-run) $(if $(HQ_ONLY),--hacker-questions-only) $(if $(TPL_ONLY),--templates-only)

# wave-2 #13: ETL ~526 public Cantina report PDFs into the corpus. The 683-line miner
# existed with zero make targets + an absent output subtree (pure supply add). Network-gated;
# default OUT_DIR keeps records under the canonical tags tree.
.PHONY: corpus-etl-cantina-reports
corpus-etl-cantina-reports:
	@python3 tools/hackerman-etl-from-cantina-reports.py \
	  --out-dir $(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/cantina_reports) \
	  $(if $(DRY_RUN),--dry-run) --json-summary

# wave-2 #14: keep the ETL miner registry (consumed by vault_corpus_lineage for
# provenance) fresh. The build/check tool was in no pipeline, so the registry drifted
# (90 miners on disk vs 79 cataloged) -> degraded lineage lookups. -build regenerates;
# -check is a fail-on-drift gate.
# wave-2 C3: regenerate invariant->runnable-plan candidates. The seeder was orphaned, so
# invariant_runnable_plans.jsonl was stale (1394 vs a fresh 16162 = every corpus invariant).
# planned != mutation-verified (R80-safe: a plan is a candidate).
.PHONY: corpus-invariant-plans
corpus-invariant-plans:
	@python3 tools/invariant-library-harness-seed.py --out audit/corpus_tags/derived/invariant_runnable_plans.jsonl

.PHONY: corpus-etl-miner-registry corpus-etl-miner-registry-check
corpus-etl-miner-registry:
	@python3 tools/hackerman-etl-miner-registry-build.py
corpus-etl-miner-registry-check:
	@python3 tools/hackerman-etl-miner-registry-build.py --check

# Wave-1 hackerman capability lift (PR #726) - live smoke test for the
# Wave-1 MCP callable surface. Invokes every Wave-1 vault_* callable and
# validates that the JSON envelope returned by each callable contains the
# canonical schema / context_pack_id / context_pack_hash / source_refs
# triple. Exits 0 only on all-pass; CI gates can depend on this target.
.PHONY: hackerman-mcp-smoke-test
hackerman-mcp-smoke-test:
	@python3 tools/hackerman-mcp-smoke-test.py $(SMOKE_ARGS)

# Wave-1 hackerman capability lift (PR #726) - wall-clock latency benchmark
# for every vault_* MCP callable. Invokes each callable 3 times (default)
# against the live corpus and emits per-callable mean / median / p99 plus a
# top-10-by-p99 operator-triage list to guide Wave-2 perf work. Operator-
# review tool; not gated in CI. Pass BENCH_ARGS="--runs 5 --only vault_X"
# for subsetting and tuning. The -json variant emits the machine envelope.
.PHONY: hackerman-mcp-latency-benchmark hackerman-mcp-latency-benchmark-json
hackerman-mcp-latency-benchmark:
	@python3 tools/hackerman-mcp-latency-benchmark.py $(BENCH_ARGS)

hackerman-mcp-latency-benchmark-json:
	@python3 tools/hackerman-mcp-latency-benchmark.py --json $(BENCH_ARGS)

# Wave-1 hackerman capability lift (PR #726) - parity check that every
# tools/hackerman-*.py has a matching tools/tests/test_hackerman_*.py file.
# Default: report only, exit 0. STRICT=1 fails (exit 1) on any missing test.
.PHONY: hackerman-tool-tests-parity-check hackerman-tool-tests-parity-check-test
hackerman-tool-tests-parity-check:
	@if [ "$(STRICT)" = "1" ]; then \
		python3 tools/hackerman-tool-tests-parity-check.py --strict; \
	else \
		python3 tools/hackerman-tool-tests-parity-check.py || true; \
	fi

hackerman-tool-tests-parity-check-test:
	@python3 -m unittest tools.tests.test_hackerman_tool_tests_parity_check -v

# Lane W6-10 (hackermind wiring audit P3) - build the exploit-predicate
# latency sidecar. vault_hackerman_exploit_predicates re-parses ~28k corpus
# YAMLs on every call (~49-61s); this target runs that extraction once and
# writes audit/corpus_tags/derived/exploit_predicates.jsonl so the MCP
# callable reads a pre-computed JSONL (~1s) instead. The callable falls back
# to the full corpus parse when the sidecar is missing or stale. Pass
# CHECK=1 to only report freshness (exit 0 fresh, 1 stale) without rebuilding.
.PHONY: hackerman-exploit-predicates-sidecar hackerman-exploit-predicates-sidecar-test
hackerman-exploit-predicates-sidecar:
	@if [ "$(CHECK)" = "1" ]; then \
		python3 tools/hackerman-exploit-predicates-sidecar.py --check; \
	else \
		python3 tools/hackerman-exploit-predicates-sidecar.py; \
	fi

hackerman-exploit-predicates-sidecar-test:
	@python3 -m unittest tools.tests.test_hackerman_exploit_predicates_sidecar -v

# Wave-2 capability #17 (PR rank-17): ingest a live-audit workspace's own
# LIVE_TARGET_REPORT.json + engage_report.md shape into the hackerman corpus as
# tier-3-synthetic records, then refresh the exploit-predicates + chain-candidate
# sidecars so the MCP `target_repo=<slug>` filter surfaces the live workspace.
# Idempotent: the ingest overwrites by stable (cluster_id,file,line) key, so
# re-engages refresh stale rows instead of duplicating them. The ingest returns
# ok:false gracefully when a workspace has no surface yet, so the auto-invoke
# from `engage` is `-@` (non-fatal).
.PHONY: hackerman-target-ingest hackerman-target-ingest-test
hackerman-target-ingest:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hackerman-target-ingest WS=<workspace-path> [DRY_RUN=1]'; exit 1; fi
	@python3 tools/hackerman-target-as-destination-ingest.py --workspace "$(WS)" $(if $(DRY_RUN),--dry-run) --json
	@python3 tools/hackerman-exploit-predicates-sidecar.py
	@python3 tools/hackerman-chain-candidates-sidecar.py

hackerman-target-ingest-test:
	@python3 -m unittest tools.tests.test_hackerman_target_ingest -v

# Wave-1 hackerman capability lift (PR #726) - new-miner scaffolding tool.
# Emits a runnable skeleton for tools/hackerman-etl-from-<NAME>.py + its
# companion test + an attribution README under
# audit/corpus_tags/tags/<NAME>/. Idempotent: refuses to overwrite
# existing files unless FORCE=1 is set. See
# tools/hackerman-etl-miner-scaffold.py docstring for full CLI surface.
.PHONY: hackerman-etl-miner-scaffold hackerman-etl-miner-scaffold-test
hackerman-etl-miner-scaffold:
	@if [ -z "$(NAME)" ] || [ -z "$(SOURCE_CHANNEL)" ] || [ -z "$(TARGET_DOMAIN)" ]; then \
		echo 'Usage: make hackerman-etl-miner-scaffold NAME=<slug> SOURCE_CHANNEL=<ghsa|web-scrape|pdf-listing|commit-history|corpus-bridge> TARGET_DOMAIN=<vault|dex|lending|...> [FORCE=1]'; \
		exit 2; \
	fi
	@python3 tools/hackerman-etl-miner-scaffold.py \
		--name "$(NAME)" \
		--source-channel "$(SOURCE_CHANNEL)" \
		--target-domain "$(TARGET_DOMAIN)" \
		$(if $(FORCE),--force)

hackerman-etl-miner-scaffold-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_miner_scaffold -v

# Generic repo-agnostic advisory miner (tier-1-officially-disclosed). Mines any
# owner/repo's published GitHub Security Advisories into the record +
# GENERALIZED-invariant + detector-seed triple. ECOSYSTEM sets target-language;
# CACHE_FILE forces an offline/deterministic run.
.PHONY: advisory-mine advisory-mine-test
advisory-mine:
	@if [ -z "$(REPO)" ]; then \
		echo 'Usage: make advisory-mine REPO=<owner/repo> [ECOSYSTEM=crates.io|npm|go|pypi] [EXTRA_CVE=CVE-...] [CACHE_FILE=<path>] [DRY_RUN=1] [JSON=1]'; \
		exit 2; \
	fi
	@python3 tools/hackerman-etl-from-advisories.py \
		--repo "$(REPO)" \
		$(if $(ECOSYSTEM),--ecosystem "$(ECOSYSTEM)") \
		$(if $(EXTRA_CVE),--extra-cve "$(EXTRA_CVE)") \
		$(if $(CACHE_FILE),--cache-file "$(CACHE_FILE)") \
		$(if $(RECORDS_DIR),--records-dir "$(RECORDS_DIR)") \
		$(if $(INVARIANTS_OUT),--invariants-out "$(INVARIANTS_OUT)") \
		$(if $(DETECTOR_SEEDS_OUT),--detector-seeds-out "$(DETECTOR_SEEDS_OUT)") \
		$(if $(CORPUS_DIR),--corpus-dir "$(CORPUS_DIR)") \
		$(if $(DRY_RUN),--dry-run) \
		$(if $(JSON),--json-summary)

advisory-mine-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_advisories -v

# Wave-6 K-R.5 - Cross-lang detector map validator
.PHONY: cross-lang-detector-map-check

cross-lang-detector-map-check:
	@python3 tools/cross-lang-detector-map-check.py --validate

# Wave-4 E-3 - MCP pin drift detector
.PHONY: mcp-pin-drift-check mcp-pin-drift-check-strict mcp-callable-usage-audit mcp-callable-count-check mcp-callable-count-check-strict

mcp-pin-drift-check:
	@if [ "$(STRICT)" = "1" ]; then \
		python3 tools/mcp-pin-drift-check.py --strict; \
	else \
		python3 tools/mcp-pin-drift-check.py || true; \
	fi

mcp-pin-drift-check-strict:
	python3 tools/mcp-pin-drift-check.py --strict

# Wave-4 E-4 - MCP callable usage audit
mcp-callable-usage-audit:
	python3 tools/mcp-callable-usage-audit.py --out audit/mcp_callable_usage_2026-05-11.md

# Phase NEG-H (2026-05-23) - MCP callable count reconciliation gate.
# Asserts the live `TOOL_SCHEMAS` count in `tools/vault-mcp-server.py` agrees
# with the count claims in `docs/MCP_LANE_SPECIFIC_CALLABLES.md` and
# `docs/HACKERMAN_MCP_CALLABLE_REFERENCE_2026-05-16.md`. Set
# MCP_CALLABLE_EXPECTED_COUNT=N to pin the expected live count, and
# INCLUDE_USER_CLAUDE_MD=1 to also audit `~/.claude/CLAUDE.md` ("Layer 2 MCP
# callables" anchor). Drift is a hard failure.
mcp-callable-count-check:
	python3 tools/mcp-callable-count-check.py $(if $(MCP_CALLABLE_EXPECTED_COUNT),--expected-count $(MCP_CALLABLE_EXPECTED_COUNT),) $(if $(INCLUDE_USER_CLAUDE_MD),--include-user-claude-md,)

mcp-callable-count-check-strict:
	$(MAKE) mcp-callable-count-check INCLUDE_USER_CLAUDE_MD=1

# Wave-4 E-1 - per-tool sentinel freshness check
.PHONY: agents-md-sync
agents-md-sync:
	@if [ "$(STRICT)" = "1" ]; then \
		python3 tools/agents-md-sync-check.py --check; \
	else \
		python3 tools/agents-md-sync-check.py --check || echo "[agents-md-sync] warn: drift detected (set STRICT=1 to hard-fail)"; \
	fi

# Tier-B #16 (PR #658) - SECTION_SOURCES collision guard
section-sources-collision-check:
	@python3 tools/section-sources-collision-check.py

# Lane 8 (PR #658) - README + dashboard auto-render
readme-refresh:
	@python3 tools/readme-render.py --update-readme

readme-check:
	@python3 tools/readme-render.py --check

# Lane 9/Phase D (PR #658) - frame extractor (drafts only, manual promotion)
vault-frame-extract:
	@python3 tools/vault-frame-extractor.py

vault-frame-extract-dry:
	@python3 tools/vault-frame-extractor.py --dry-run

# Track E-0 (Wave-3) - MCP discipline enforcement hooks + session start
.PHONY: install-hooks install-session-start-shim session-start mcp-callable-count iter-rollup iter-rollup-test rule-contract-check rule-contract-check-test

install-hooks:
	bash tools/install-hooks.sh install

# P17: replay rule/Check self-test contracts (advisory-first). Wired into the
# git pre-commit chain as an ADVISORY note by default; set
# AUDITOOOR_RULE_CONTRACT_STRICT=1 to enforce (opt-in graduation).
rule-contract-check:
	python3 tools/rule-contract-check.py

rule-contract-check-test:
	python3 -m unittest tools.tests.test_rule_contract_check -v

install-session-start-shim:
	bash tools/install-session-start-shim.sh install

session-start:
	bash tools/auditooor-session-start.sh

# Cross-iter hunt index - consolidated view of every lane verdict + fileable
# finding across reports/v3_iter_*. Writes reports/ITER_INDEX.md.
# Intended cron: 0 */6 * * *
iter-rollup:
	python3 tools/iter-rollup.py --since 60d --emit reports/ITER_INDEX.md

iter-rollup-test:
	python3 -m unittest tools.tests.test_iter_rollup -v

mcp-callable-count:
	@python3 -c "import re,pathlib; t=pathlib.Path('tools/vault-mcp-server.py').read_text(); print(len(set(re.findall(r'\"name\":\\s*\"(vault_\\w+)\"', t))))"

# Lane 7 (PR #658) - PATH-shim wrappers install
install-mcp-wrappers:
	@bash tools/install-wrappers.sh install

# Wave-6 E-2: install + auto-add ~/.auditooor/bin to shell PATH
.PHONY: wrappers-install-default-on
wrappers-install-default-on:
	bash tools/install-wrappers.sh install --auto-add-to-path

# Wave-6 E-2: check PATH inclusion
.PHONY: wrappers-check-path
wrappers-check-path:
	@bash tools/install-wrappers.sh check-path

# Wave-6 E-2: verify freshness gate is wired into all installed wrappers
.PHONY: wrappers-check-freshness-wiring
wrappers-check-freshness-wiring:
	@bash tools/install-wrappers.sh check-freshness-wiring

mcp-wrappers-check:
	@bash tools/install-wrappers.sh check

# Lane 12 (PR #658 deferred-2) - auto-update LLM_DELEGATION_MATRIX.md
llm-matrix-update:
	@python3 tools/llm-delegation-matrix-update.py

llm-matrix-check:
	@python3 tools/llm-delegation-matrix-update.py --check

llm-matrix-test:
	@python3 -m unittest tools.tests.test_llm_delegation_matrix_update -v

# Lane 1 (PR #658) - vault PR sync
vault-pr-sync:
	@python3 tools/vault-pr-sync.py

vault-pr-sync-check:
	@python3 tools/vault-pr-sync.py --check

vault-pr-sync-test:
	@python3 -m unittest tools.tests.test_vault_pr_sync -v

# Lane 6 (PR #658) - universal task ledger schema validation
universal-task-ledger-check:
	@if [ -f obsidian-vault/universal_task_ledger.jsonl ] || [ -f $$HOME/Documents/Codex/auditooor/obsidian-vault/universal_task_ledger.jsonl ]; then \
	  python3 tools/universal-task-ledger-validate.py; \
	else \
	  echo "[universal-task-ledger-check] no ledger present yet (Phase 1 commit 1 ships schema only); skipping"; \
	fi

# Lane 11 (PR #658) - vault ontology validation
# Advisory by default; STRICT_VAULT_ONTOLOGY=1 escalates to hard-fail.
vault-ontology-check:
	@if [ "$$STRICT_VAULT_ONTOLOGY" = "1" ]; then \
	  python3 tools/vault-ontology-validate.py --check-cross-refs --strict --summary-only; \
	else \
	  python3 tools/vault-ontology-validate.py --summary-only || true; \
	fi

# Combined Lane 6 + Lane 11 unit tests
universal-task-ledger-test:
	@python3 -m unittest tools.tests.test_universal_task_ledger_validate -v

# Lane 6 T12 - CAPV3 ITER cadence wired into universal task ledger.
# Each CAPV3_ITER*.md group becomes one next_loop_priority meta-task.
# Usage:
#   make capv3-ledger-emit WS=<worktree>        # dry-run summary
#   make capv3-ledger-emit WS=<worktree> JSON=1 # emit JSONL to stdout
#   make capv3-ledger-emit WS=<worktree> APPLY=1 # write/merge into ledger
capv3-ledger-emit:
	@python3 tools/capv3-iter-ledger-emit.py \
		$(if $(WS),--workspace $(WS)) \
		$(if $(filter 1,$(JSON)),--json) \
		$(if $(filter 1,$(APPLY)),--apply)

capv3-ledger-emit-test:
	@python3 -m unittest tools.tests.test_capv3_iter_ledger_emit -v

# Lane 6 T10 - cross-workspace ledger emitter (PR #658 Tier-B #10).
# Routes a universal-task-ledger row to the appropriate cross-* tool.
# Router map lives in reference/cross_ws_router_map.json - extend there,
# not here. --dry-run is the default; pass APPLY=1 to actually invoke.
# Usage:
#   make cross-ws-ledger-emit WS=~/audits/dydx ROW=TCOMMIT_MINING-20260509-foo  # dry-run
#   make cross-ws-ledger-emit WS=~/audits/spark ROW=TFILING_LIFECYCLE-20260509-lead1 APPLY=1
#   make cross-ws-ledger-emit REFRESH=1        # refresh state dashboard only
#   make cross-ws-ledger-emit LIST=1           # list all routes
cross-ws-ledger-emit:
	@python3 tools/cross-workspace-ledger-emit.py \
		$(if $(WS),--workspace $(WS)) \
		$(if $(ROW),--row $(ROW)) \
		$(if $(AUDITS_DIR),--audits-dir $(AUDITS_DIR)) \
		$(if $(PASTE_READY),--paste-ready $(PASTE_READY)) \
		$(if $(filter 1,$(APPLY)),--apply) \
		$(if $(filter 1,$(REFRESH)),--refresh-state) \
		$(if $(filter 1,$(LIST)),--list-routes)

cross-ws-ledger-emit-test:
	@python3 -m unittest tools.tests.test_cross_workspace_ledger_emit -v

vault-ontology-test:
	@python3 -m unittest tools.tests.test_vault_ontology_validate -v

# L28-B enforcement - diff documented patterns vs wired detectors.
# Advisory by default (STRICT=0); fails closed with STRICT=1.
# Under docs-check: runs in warn mode so the existing green chain stays green
# while the wiring backlog (mined DSL rounds) is worked down.
# Explicit strict gate: make detector-registry-completeness STRICT=1
# Usage: make detector-registry-completeness [STRICT=1] [TSV=1]
detector-registry-completeness:
	@STRICT=$(or $(STRICT),0) python3 tools/detector-registry-completeness-check.py \
		$(if $(filter 1,$(TSV)),--tsv)

# L28-B fix - regex-API detector runner.
# Runs `detectors/run_regex_detectors.py` against the workspace's Solidity
# source tree. The wave17 detectors (v4_hook_take_before_pricing, etc.) export
# `scan(source, file_path)` and are NOT Slither AbstractDetector subclasses, so
# `detectors/run_custom.py` does NOT discover them; without this target,
# `make audit` skipped them silently. The runner is also auto-fired from
# `tools/workspace-scan-orchestrator.py` when invoked through `make audit`.
# Usage:
#   make regex-detectors WS=<workspace>
#   make regex-detectors WS=<workspace> DETECTOR=<name>   # filter to one
#   make regex-detectors TARGET=<dir>                     # raw target dir override
regex-detectors:
	@target="$(or $(TARGET),$(_WS_RESOLVED))"; \
	if [ -z "$$target" ]; then \
	  echo 'Usage: make regex-detectors WS=<workspace> [DETECTOR=<name>]'; exit 2; fi; \
	if [ ! -d "$$target" ] && [ ! -f "$$target" ]; then \
	  echo "[regex-detectors] ERR target not found: $$target"; exit 2; fi; \
	ws="$(_WS_RESOLVED)"; \
	if [ -z "$$ws" ] || [ ! -d "$$ws" ]; then ws="$$target"; fi; \
	python3 detectors/run_regex_detectors.py "$$target" \
	  --workspace "$$ws" \
	  $(if $(DETECTOR),--detector "$(DETECTOR)")

# zkvm-detect - run zk-VM / bespoke-proof-system native detectors (detectors/zkvm_wave1)
# over a Rust workspace. Unlike run_regex_detectors (Solidity-only) and rust-detect
# (rust_wave1 Anchor/Solana shapes), these gate on generic proof-system signals
# (Fiat-Shamir, field-canonical, sumcheck, tweak/domain-sep, unsafe SIMD packing) so a
# bespoke zkVM (leanEthereum/leanVM) that matches no framework detector still gets coverage.
# Auto-runs inside `make audit-deep` for any Rust workspace. Usage: make zkvm-detect WS=<ws>
zkvm-detect:
	@ws="$(_WS_RESOLVED)"; \
	if [ -z "$$ws" ] || [ ! -d "$$ws" ]; then echo 'Usage: make zkvm-detect WS=<workspace>'; exit 2; fi; \
	python3 tools/zkvm-detect.py --workspace "$$ws" $(if $(JSON),--json)

# L29-Filing audit - advisory walk over every paste-ready file in the
# workspace. Each file is run through tools/l29_filing_check.py --check all.
# Reports per-file PASS / FAIL / SOFT-SKIP. Exits 0 even when individual files
# fail (advisory; pre-submit-check.sh remains the strict filing gate). The
# point is to surface the L29 capability state of the workspace at a glance.
# Usage: make l29-filing-audit WS=<workspace>
l29-filing-audit:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make l29-filing-audit WS=<workspace>'; exit 2; fi
	@ws="$(_WS_RESOLVED)"; \
	dir="$$ws/submissions/paste_ready"; \
	if [ ! -d "$$dir" ]; then \
	  echo "[l29-filing-audit] no paste_ready/ dir at $$dir - nothing to audit"; \
	  exit 0; fi; \
	n=0; pass=0; fail=0; soft=0; \
	for f in "$$dir"/*.md; do \
	  [ -f "$$f" ] || continue; \
	  n=$$((n+1)); \
	  out=$$(python3 tools/l29_filing_check.py --check all "$$f" 2>&1); rc=$$?; \
	  base=$$(basename "$$f"); \
	  if [ $$rc -eq 0 ] && echo "$$out" | grep -qi "soft-skip\|skipped"; then \
	    soft=$$((soft+1)); printf "  [SOFT] %s\n" "$$base"; \
	  elif [ $$rc -eq 0 ]; then \
	    pass=$$((pass+1)); printf "  [PASS] %s\n" "$$base"; \
	  else \
	    fail=$$((fail+1)); printf "  [FAIL] %s - rc=%s\n" "$$base" "$$rc"; \
	    echo "$$out" | sed 's/^/    /' | head -8; \
	  fi; \
	done; \
	echo ""; \
	printf "[l29-filing-audit] paste_ready files=%s  pass=%s  fail=%s  soft-skip=%s  (advisory)\n" \
	  "$$n" "$$pass" "$$fail" "$$soft"

# Paste-content-hash status - list paste-ready files and whether each has a
# recorded SHA-256 sidecar (`.hash` file written by tools/paste_content_hash.py
# --record). Advisory; never fails. Verifies live hash matches recorded hash
# when the sidecar exists.
# Usage: make paste-hash-status WS=<workspace>
paste-hash-status:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make paste-hash-status WS=<workspace>'; exit 2; fi
	@ws="$(_WS_RESOLVED)"; \
	dir="$$ws/submissions/paste_ready"; \
	if [ ! -d "$$dir" ]; then \
	  echo "[paste-hash-status] no paste_ready/ dir at $$dir - nothing to check"; \
	  exit 0; fi; \
	n=0; recorded=0; missing=0; mismatch=0; \
	for f in "$$dir"/*.md; do \
	  [ -f "$$f" ] || continue; \
	  n=$$((n+1)); \
	  base=$$(basename "$$f"); \
	  if [ -f "$$f.hash" ]; then \
	    if python3 tools/paste_content_hash.py --verify "$$f" >/dev/null 2>&1; then \
	      recorded=$$((recorded+1)); printf "  [OK   ] %s\n" "$$base"; \
	    else \
	      mismatch=$$((mismatch+1)); printf "  [MISMATCH] %s - content drift after record\n" "$$base"; \
	    fi; \
	  else \
	    missing=$$((missing+1)); printf "  [NO-HASH] %s - never recorded\n" "$$base"; \
	  fi; \
	done; \
	echo ""; \
	printf "[paste-hash-status] paste_ready files=%s  recorded=%s  missing=%s  mismatch=%s  (advisory)\n" \
	  "$$n" "$$recorded" "$$missing" "$$mismatch"

# Capability-status - single-pass summary of the L28/L29 capability surface
# of a workspace. Front-door for "where do I stand?" - runs:
#   1. detector-registry-completeness (L28-B / docs ↔ wired detector diff)
#   2. regex-detectors                (L28-B / wave* regex-API detectors)
#   3. l29-filing-audit               (L29 / paste-ready file gates)
#   4. paste-hash-status              (L29 / paste-content-hash sidecars)
# Each sub-step is advisory. Total exit code = 0 unless make-level errors
# (missing tool, missing workspace) occur.
# Usage: make capability-status WS=<workspace>
capability-status:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make capability-status WS=<workspace>'; exit 2; fi
	@echo "=== capability-status (L28/L29 surface) ==="
	@echo ""
	@echo "── 1/4 detector-registry-completeness (L28-B advisory) ──"
	@$(MAKE) --no-print-directory detector-registry-completeness 2>&1 | tail -8 || true
	@echo ""
	@echo "── 2/4 regex-detectors (L28-B wave* regex API) ──"
	@$(MAKE) --no-print-directory regex-detectors WS="$(WS)" 2>&1 | tail -20 || true
	@echo ""
	@echo "── 3/4 l29-filing-audit (L29 advisory) ──"
	@$(MAKE) --no-print-directory l29-filing-audit WS="$(WS)" 2>&1 | tail -10 || true
	@echo ""
	@echo "── 4/4 paste-hash-status (L29 advisory) ──"
	@$(MAKE) --no-print-directory paste-hash-status WS="$(WS)" 2>&1 | tail -10 || true
	@echo ""
	@echo "── 5/5 corpus-mining-state (Phase A freshness) ──"
	@$(MAKE) --no-print-directory corpus-mining-state 2>&1 | tail -6 || true
	@echo ""
	@echo "── 6/6 big-loss-template-runner (Phase F - scope-matched templates) ──"
	@$(MAKE) --no-print-directory big-loss-template-runner WS="$(WS)" 2>&1 | tail -20 || true
	@echo ""
	@echo "── 7/7 hackerman-corpus (indexed attacker-memory coverage) ──"
	@python3 -c 'import json, sys; from pathlib import Path; root=Path.cwd(); ws=Path(sys.argv[1]).expanduser(); tags=root/"audit"/"corpus_tags"/"tags"; index=root/"audit"/"corpus_tags"/"index"; v1=sum(1 for p in tags.glob("*.yaml") if "auditooor.hackerman_record.v1" in p.read_text(encoding="utf-8", errors="ignore")) if tags.is_dir() else 0; idx=sorted(p.name for p in index.glob("by_*.jsonl")) if index.is_dir() else []; print(f"hackerman_records_v1={v1}"); print(f"hackerman_index_files={len(idx)} ({'"'"', '"'"'.join(idx[:10])})"); brief=ws/".auditooor"/"hacker_brief.hackerman.json"; data=json.loads(brief.read_text(encoding="utf-8")) if brief.is_file() else None; print(f"workspace_hackerman_brief=present records={len(data.get('"'"'records'"'"', []))} total={data.get('"'"'total_records_matched'"'"', 0)}" if data else "workspace_hackerman_brief=missing")' "$(WS)"
	@echo ""
	@echo "=== capability-status complete ==="

# auditor-capability-ci - honest single-report capability metric publisher.
# Runs tools/capability-metric-publisher.py, which composes
# tools/auditor-backtest.py across the TRAIN / DEV / HELD_OUT / FIXED_REF
# (negative control) / FRESH_TARGET splits and publishes ONE report to
# reports/capability_metrics/latest.{json,md}.
#
# HELD_OUT strict line recall is THE finding-power headline; TRAIN recall is
# reported but tagged circular and never the headline. The report also carries
# the NA-rate, the fixed-ref false-positive rate (a detector firing on POST-FIX
# source = FP), and an honest fresh-target slot (summarized-or-not-run, never
# fabricated).
#
# With no corpus this still writes an empty-but-valid report and exits 0 in
# non-strict mode so a fresh checkout can publish diagnostics. STRICT=1 is a
# claim-grade mode: it fails when no held-out cases are supplied unless
# MIN_HELDOUT_SCORABLE=0 is set explicitly.
#
# Usage:
#   make auditor-capability-ci                       # publish (always exit 0)
#   make auditor-capability-ci STRICT=1 CASES=...    # exit non-zero on gate breach
#   make auditor-capability-ci CASES=reference/fetchable_vuln_corpus.jsonl
#   make auditor-capability-ci CASES=... CORPUS_DETECTOR_DIR=/tmp/new_detectors
#   make auditor-capability-ci LOCAL_CHECKOUT_ROOT=~/vuln_checkouts   # offline
auditor-capability-ci:
	@python3 tools/capability-metric-publisher.py \
	  $(if $(CASES),--cases $(CASES),) \
	  $(if $(FIXED_REF_CASES),--fixed-ref-cases $(FIXED_REF_CASES),) \
	  $(if $(CORPUS_DETECTOR_DIR),--corpus-detector-dir $(CORPUS_DETECTOR_DIR),) \
	  $(if $(LOCAL_CHECKOUT_ROOT),--local-checkout-root $(LOCAL_CHECKOUT_ROOT),) \
	  $(if $(NA_RATE_MAX),--na-rate-max $(NA_RATE_MAX),) \
	  $(if $(FIXED_REF_FP_MAX),--fixed-ref-fp-max $(FIXED_REF_FP_MAX),) \
	  $(if $(MIN_HELDOUT_SCORABLE),--min-heldout-scorable $(MIN_HELDOUT_SCORABLE),) \
	  $(if $(STRICT),--strict-ci,)

# Roadmap-status - compact machine-readable Hackerman/MCP capability snapshot.
# Usage: make capability-roadmap-status [JSON=1] [WS=<workspace>]
capability-roadmap-status:
	@python3 tools/hackerman-capability-status.py \
	  $(if $(JSON),--format json,) \
	  $(if $(WS),--workspace "$(WS)",)

# Capability-adoption-status - count MCP callable invocations across .auditooor
# mcp_call_log.jsonl files; flag LOW_ADOPTION (<3) and DEAD_ADOPTION (==0) over
# the last N=7 hunt iterations (default; override with N=<int>).
# Usage:
#   make capability-adoption-status WS=<workspace>           # single workspace
#   make capability-adoption-status WS_GLOB='~/audits/*'     # several
#   make capability-adoption-status N=14 JSON=1 WS=<ws>      # JSON output
capability-adoption-status:
	@python3 tools/hackerman-capability-adoption.py \
	  $(if $(WS),--workspace "$(WS)",) \
	  $(if $(WS_GLOB),--workspace-glob "$(WS_GLOB)",) \
	  $(if $(N),--iterations "$(N)",--iterations 7) \
	  $(if $(JSON),--format json,)

# Phase A - corpus mining freshness snapshot
# Usage: make corpus-mining-state
corpus-mining-state:
	@python3 tools/corpus-mining-state-snapshot.py

# MCP recall pack router - recommend the right pack (resume / exploit /
# harness / knowledge-gap) for the current workspace. See
# ``docs/next-loop/mcp_route_design_2026-05-06.md``.
mcp-route:
	@python3 tools/pre-mcp-route-check.py \
		--workspace-path $(or $(WORKSPACE),$(CURDIR)) \
		$(if $(INTENT),--intent $(INTENT)) \
		$(if $(KEYWORDS),--task-keywords "$(KEYWORDS)") \
		$(if $(ARTIFACTS),--recent-artifacts "$(ARTIFACTS)") \
		$(if $(JSON),--json)

mcp-route-test:
	@python3 -m unittest tools.tests.test_vault_route -v

cleanup-inventory:
	@python3 tools/cleanup-inventory.py $(if $(JSON),--print-json)

# Agent calibration memory - emit provider/task-type/incident/routing notes into vault.
agent-calibration-refresh:
	@python3 tools/agent-calibration-vault-emit.py --vault-dir $(or $(VAULT),obsidian-vault)

agent-calibration-refresh-test:
	@python3 tools/agent-calibration-vault-emit.py --dry-run

# ── §M_ARCH Layer L1 - Memory event watcher (ACT-17) ───────────────────────
memory-watcher-start:
	@bash tools/install-memory-watcher-launchd.sh

memory-watcher-stop:
	@bash tools/install-memory-watcher-launchd.sh --uninstall

memory-watcher-status:
	@bash tools/install-memory-watcher-launchd.sh --status

memory-watcher-self-test:
	@python3 tools/memory-event-watcher.py \
	  --simulate-events tools/memory-watcher-simulate-events.jsonl \
	  --vault-dir /tmp/auditooor-watcher-self-test-vault \
	  --report-out reports/memory_event_watcher_self_test.json

# ── PLAN-MEM Tier-1 emitters (ACT-26) ────────────────────────────────────────
# Run individually or as part of vault-refresh.

memory-anti-pattern-emitter:
	@python3 tools/memory-anti-pattern-emitter.py --vault-dir $(VAULT)

memory-tools-api-emitter:
	@python3 tools/memory-tools-api-emitter.py --vault-dir $(VAULT)

memory-commits-emitter:
	@python3 tools/memory-commits-emitter.py --vault-dir $(VAULT) --head

memory-bug-class-emitter:
	@python3 tools/memory-bug-class-emitter.py --vault-dir $(VAULT)

# ── Obsidian shared-memory vault (ACT-4 / E in CONTINUATION_PLAN.md) ────────
# Regenerable from canonical sources - vault is gitignored.
vault-refresh: agent-calibration-refresh
	@python3 tools/obsidian-vault-emit.py --vault-dir $(VAULT) --deep
	@python3 tools/memory-deep-crawler.py --vault-dir $(VAULT)
	@echo "[vault-refresh] Running PLAN-MEM Tier-1 emitters..."
	@python3 tools/memory-anti-pattern-emitter.py --vault-dir $(VAULT)
	@python3 tools/memory-tools-api-emitter.py --vault-dir $(VAULT)
	@python3 tools/memory-bug-class-emitter.py --vault-dir $(VAULT)
	@echo "[vault-refresh] Running privacy audit (fail-closed)..."
	@python3 tools/memory-privacy-audit.py --vault $(VAULT) --whitelist reports/privacy_audit_whitelist.yaml || \
		(echo "ERROR: vault-refresh aborted - privacy audit found HIGH/CRITICAL matches." && \
		 echo "       Run: python3 tools/memory-privacy-audit.py --vault $(VAULT) --quarantine" && \
		 echo "       Then add false positives to reports/privacy_audit_whitelist.yaml" && exit 1)

vault-sync:
	@python3 tools/obsidian-vault-sync.py --vault-dir $(VAULT)
	@python3 tools/memory-deep-crawler.py --vault-dir $(VAULT)

vault-status:
	@python3 tools/obsidian-vault-sync.py --vault-dir $(VAULT) --status
	@python3 tools/memory-deep-crawler.py --vault-dir $(VAULT) --status

# T2-DEEP-CRAWLER-SECTIONS / Loop 12 BBB:
# Audits memory-deep-crawler section freshness, emits
# reports/deep_crawler_staleness_<DATE>.json (schema
# auditooor.deep_crawler_staleness.v1) and prints a per-section staleness
# table. Advisory by default (always exit 0); set STRICT=1 to fail if any
# section is >14d stale or missing.
#
# Usage:
#   make deep-crawler-staleness-check
#   make deep-crawler-staleness-check STRICT=1
deep-crawler-staleness-check:
	@python3 tools/deep-crawler-staleness-check.py --print $(if $(filter 1,$(STRICT)),--strict,)

# LANE W4.14 - per-MCP-callable corpus-segment freshness monitor.
# Audits every ETL-miner registry entry (tools/audit/etl_miner_registry/),
# computes per-segment age from the registry last-run commit + youngest
# record mtime, emits reports/mcp_corpus_freshness_<DATE>.json (schema
# auditooor.mcp_corpus_freshness.v1) and prints a worst-first table with
# per-segment re-pull guidance. Advisory by default; STRICT=1 fails when
# any segment is AGING (>14d) or STALE (>30d).
#
# Usage:
#   make mcp-freshness
#   make mcp-freshness STRICT=1
.PHONY: mcp-freshness mcp-freshness-test
mcp-freshness:
	@python3 tools/audit/mcp-corpus-freshness-monitor.py --print $(if $(filter 1,$(STRICT)),--strict,)

mcp-freshness-test:
	@python3 -m unittest tools.tests.test_mcp_corpus_freshness_monitor -v

vault-mcp-server:
	@python3 tools/vault-mcp-server.py --vault-dir $(VAULT)

vault-mcp-self-test:
	@python3 tools/vault-mcp-server.py --self-test

# CISS-002 / SPARK-FIX-004: regression invariant for the vault-mcp self-test.
# Runs the fixture self-test, then a follow-up `vault_resume_context` call
# against a real workspace, asserting both that the self-test passes AND
# that the resume call returns a non-empty `context_pack_id`. This guards
# against silent regressions where the self-test still exits 0 but the
# live recall path is broken (e.g. KeyError-style fixture drift).
#
# Tolerates the lead-in stderr/stdout banner the server emits before its
# JSON payload (see `[vault-mcp-server]` prefix lines).
#
# Usage:
#   make vault-mcp-self-test-regression                   # uses repo root as WS
#   make vault-mcp-self-test-regression WS=<workspace>    # explicit workspace
vault-mcp-self-test-regression:
	@python3 tools/vault-mcp-server.py --self-test
	@WS_RESOLVED='$(if $(WS),$(_WS_RESOLVED),$(CURDIR))'; \
	  python3 tools/vault-mcp-server.py --call vault_resume_context \
	    --args "{\"workspace_path\":\"$$WS_RESOLVED\",\"limit\":2}" \
	  | python3 -c "import json,sys; lines=sys.stdin.read().splitlines(); body='\n'.join(l for l in lines if not l.startswith('[vault-mcp-server]')); d=json.loads(body); pid=d.get('context_pack_id'); assert pid, 'context_pack_id missing from vault_resume_context payload'; print('[vault-mcp-self-test-regression] PASS context_pack_id=%s' % pid)"

vault-mcp-self-test-regression-test:
	@python3 -m unittest tools.tests.test_vault_mcp_self_test -v

vault-mcp-test:
	@python3 -m unittest \
		tools.tests.test_vault_mcp_server \
		tools.tests.test_vault_mcp_server_docs_alignment \
		-v

memory-auto-link:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make memory-auto-link WS=<workspace> [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make memory-auto-link" "$(_WS_RESOLVED)"
	@python3 tools/memory-auto-link.py --workspace "$(_WS_RESOLVED)" --write $(if $(JSON),--json)

memory-context-load:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make memory-context-load WS=<workspace> [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make memory-context-load" "$(_WS_RESOLVED)"
	@python3 tools/memory-context-load.py --workspace "$(_WS_RESOLVED)" --from-requirements --write-receipt $(if $(JSON),--json)

memory-context-test:
	@python3 -m unittest tools.tests.test_memory_context_tools -v

# §M_ARCH L4 - memory gap analyzer (ACT-19).
# Heuristic surface; operator review mandatory; no auto-dispatch.
# See docs/MEMORY_GAP_ANALYZER.md.
memory-gap-analysis:
	@python3 tools/memory-gap-analyzer.py --vault-dir $(VAULT)

memory-next-loop:
	@python3 tools/memory-gap-analyzer.py --vault-dir $(VAULT)
	@python3 tools/memory-next-loop-dispatcher.py --vault-dir $(VAULT)

memory-next-loop-dry-run:
	@# Run the analyzer (writes candidates.jsonl which the dispatcher reads),
	@# then dispatch in --dry-run so no /tmp prompts are written.
	@python3 tools/memory-gap-analyzer.py --vault-dir $(VAULT)
	@python3 tools/memory-next-loop-dispatcher.py --vault-dir $(VAULT) --dry-run

memory-next-loop-test:
	@python3 -m unittest tools.tests.test_memory_next_loop_dispatcher tools.tests.test_agent_dispatch_prompt_lint tools.tests.test_harness_failure_memory -v

memory-next-loop-smoke:
	@python3 -m unittest tools.tests.test_memory_next_loop_dispatcher.MemoryNextLoopDispatcherManifestTest.test_analyzer_to_dispatcher_hermetic_smoke -v

goal-loop-status:
	@python3 tools/goal-loop-status.py \
	  --out "$(if $(OUT),$(OUT),reports/goal_loop_status_2026-05-05.json)" \
	  --md-out "$(if $(MD_OUT),$(MD_OUT),docs/GOAL_LOOP_STATUS_2026-05-05.md)"

goal-loop-status-test:
	@python3 -m unittest tools.tests.test_goal_loop_status -v

batch-checkpoint-status:
	@python3 tools/batch-checkpoint-status.py \
	  --loops-since-checkpoint "$(if $(LOOPS),$(LOOPS),0)" \
	  $(if $(COMMIT_THRESHOLD),--commit-threshold "$(COMMIT_THRESHOLD)",) \
	  $(if $(LOOP_THRESHOLD),--loop-threshold "$(LOOP_THRESHOLD)",) \
	  $(if $(FORCE),--force-checkpoint,) \
	  $(if $(JSON),,--markdown)

batch-checkpoint-status-test:
	@python3 -m unittest tools.tests.test_batch_checkpoint_status -v

batch-boundary-preflight:
	@python3 tools/batch-boundary-preflight.py \
	  $(if $(PR_BODY),--pr-body "$(PR_BODY)",) \
	  $(if $(STRICT),--strict,) \
	  $(if $(PR_STRICT),--pr-strict,) \
	  $(if $(TIMEOUT),--timeout "$(TIMEOUT)",)

memory-audit-packet:
	@python3 tools/memory-audit-packet.py . \
	  --json-out "$(if $(JSON_OUT),$(JSON_OUT),reports/memory_audit_packet_status_2026-05-05.json)" \
	  --doc-out "$(if $(DOC_OUT),$(DOC_OUT),docs/MEMORY_AUDIT_PACKET_STATUS_2026-05-05.md)" \
	  $(if $(MAX_ITEMS),--max-items "$(MAX_ITEMS)",) \
	  $(if $(MAX_TEXT),--max-text "$(MAX_TEXT)",) \
	  $(if $(PRINT_JSON),--stdout-format json,) \
	  $(if $(SUMMARY),--stdout-format summary,)

memory-audit-packet-test:
	@python3 -m unittest tools.tests.test_memory_audit_packet -v

shared-memory-index:
	@python3 tools/shared-memory-index.py \
	  --root . \
	  --output "$(if $(OUT),$(OUT),reports/shared_memory_index_2026-05-05.json)" \
	  --markdown-output "$(if $(MD_OUT),$(MD_OUT),docs/SHARED_MEMORY_INDEX_2026-05-05.md)" \
	  $(if $(PRINT_JSON),--print-json,)

shared-memory-index-test:
	@python3 -m unittest tools.tests.test_shared_memory_index -v

memory-brief:
	@python3 tools/memory-brief.py \
	  --root . \
	  --index "$(if $(IN),$(IN),reports/shared_memory_index_2026-05-05.json)" \
	  --output "$(if $(OUT),$(OUT),reports/memory_brief_2026-05-05.json)" \
	  --markdown-output "$(if $(MD_OUT),$(MD_OUT),docs/MEMORY_BRIEF_2026-05-05.md)" \
	  $(if $(CATEGORY),--category "$(CATEGORY)",) \
	  --provider "$(if $(PROVIDER),$(PROVIDER),agent)" \
	  $(if $(TASK),--task "$(TASK)",) \
	  $(if $(MAX_OBJECTS),--max-objects-per-source-category "$(MAX_OBJECTS)",) \
	  $(if $(PRINT_JSON),--print-json,)

memory-brief-test:
	@python3 -m unittest tools.tests.test_memory_brief -v

obsidian-memory-entrypoints:
	@python3 tools/obsidian-memory-entrypoints.py \
	  --repo-root . \
	  --output "$(if $(OUT),$(OUT),reports/obsidian_memory_entrypoints_2026-05-05.json)" \
	  --markdown-output "$(if $(MD_OUT),$(MD_OUT),docs/OBSIDIAN_MEMORY_ENTRYPOINTS_2026-05-05.md)" \
	  $(if $(PRINT_MD),--markdown,) \
	  $(if $(PRINT_JSON),--json,)

obsidian-memory-entrypoints-test:
	@python3 -m unittest tools.tests.test_obsidian_memory_entrypoints -v

operational-memory-day-to-day:
	@python3 tools/operational-memory-day-to-day.py \
	  --root . \
	  --date "$(if $(DATE),$(DATE),2026-05-05)" \
	  --memory-path "$(if $(MEMORY_PATH),$(MEMORY_PATH),/Users/wolf/.codex/memories/auditooor_perpetual_loop.md)" \
	  --vault-path "$(if $(VAULT_PATH),$(VAULT_PATH),/Users/wolf/Documents/Codex/auditooor/obsidian-vault)" \
	  --md-out "$(if $(MD_OUT),$(MD_OUT),docs/OPERATIONAL_MEMORY_DAY_TO_DAY_2026-05-05.md)" \
	  --json-out "$(if $(OUT),$(OUT),reports/operational_memory_day_to_day_2026-05-05.json)" \
	  --format "$(if $(FORMAT),$(FORMAT),summary)" \
	  $(if $(NO_WRITE),--no-write,)

operational-memory-day-to-day-test:
	@python3 -m unittest tools.tests.test_operational_memory_day_to_day -v

known-limitations-dispatch:
	@python3 tools/known-limitations-dispatch.py \
	  --input "$(if $(IN),$(IN),reports/known_limitations_burndown_queue_2026-05-05.json)" \
	  --output "$(if $(OUT),$(OUT),reports/known_limitations_dispatch_2026-05-05.json)" \
	  --docs "$(if $(MD_OUT),$(MD_OUT),docs/KNOWN_LIMITATIONS_DISPATCH_2026-05-05.md)" \
	  $(if $(PRINT_JSON),--print-json,)

known-limitations-dispatch-test:
	@python3 -m unittest tools.tests.test_known_limitations_dispatch -v

scanner-wiring-burndown:
	@python3 tools/scanner-wiring-burndown.py \
	  $(if $(IN),"$(IN)",) \
	  --repo-root . \
	  $(if $(IN),,$(if $(NO_REFRESH),,--refresh-from-repo)) \
	  --live-inventory-limit "$(if $(LIVE_INVENTORY_LIMIT),$(LIVE_INVENTORY_LIMIT),12000)" \
	  --json-out "$(if $(JSON_OUT),$(JSON_OUT),reports/scanner_wiring_burndown_queue_2026-05-05.json)" \
	  --md-out "$(if $(MD_OUT),$(MD_OUT),docs/SCANNER_WIRING_BURNDOWN_QUEUE_2026-05-05.md)" \
	  $(if $(ACTION_LIMIT),--action-limit "$(ACTION_LIMIT)",) \
	  $(if $(PER_LANE_LIMIT),--per-lane-limit "$(PER_LANE_LIMIT)",) \
	  $(if $(PRINT_JSON),--print-json,)

scanner-wiring-burndown-test:
	@python3 -m unittest tools.tests.test_scanner_wiring_burndown -v

scanner-worker-next-rows:
	@python3 tools/scanner-worker-next-rows.py \
	  --repo-root "$(if $(REPO_ROOT),$(REPO_ROOT),.)" \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(ACTIVE_CLAIMS),--active-claims "$(ACTIVE_CLAIMS)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(SCAN_LIMIT),--scan-limit "$(SCAN_LIMIT)") \
	  $(if $(INCLUDE_DOCUMENTATION_ONLY),--include-documentation-only) \
	  $(if $(PROMPT_MODE),--prompt-mode "$(PROMPT_MODE)") \
	  $(if $(OUT),--json-out "$(OUT)") \
	  $(if $(MD_OUT),--md-out "$(MD_OUT)") \
	  $(if $(PROMPT_OUT_DIR),--prompt-out-dir "$(PROMPT_OUT_DIR)") \
	  $(if $(MARKDOWN),--markdown)

scanner-worker-next-rows-test:
	@python3 -m unittest tools.tests.test_scanner_worker_next_rows -v

detector-proof-gap-queue:
	@python3 tools/detector-proof-gap-queue.py \
	  --repo-root . \
	  $(if $(IN),--inventory "$(IN)",) \
	  $(if $(BURNDOWN),--burndown "$(BURNDOWN)",) \
	  --json-out "$(if $(OUT),$(OUT),reports/detector_proof_gap_queue_2026-05-05.json)" \
	  --md-out "$(if $(MD_OUT),$(MD_OUT),docs/DETECTOR_PROOF_GAP_QUEUE_2026-05-05.md)" \
	  $(if $(NO_REFRESH),,--refresh-from-repo) \
	  --live-inventory-limit "$(if $(LIVE_INVENTORY_LIMIT),$(LIVE_INVENTORY_LIMIT),12000)" \
	  $(if $(SECTION_LIMIT),--section-limit "$(SECTION_LIMIT)",) \
	  $(if $(FULL_THROTTLE_LIMIT),--full-throttle-limit "$(FULL_THROTTLE_LIMIT)",) \
	  $(if $(PRINT_JSON),--print-json,)

detector-proof-gap-queue-test:
	@python3 -m unittest tools.tests.test_detector_proof_gap_queue -v

rust-detector-coverage:
	@python3 tools/rust-detector-coverage.py . \
	  --json-out "$(if $(OUT),$(OUT),reports/rust_detector_coverage_2026-05-05.json)" \
	  --md-out "$(if $(MD_OUT),$(MD_OUT),docs/RUST_DETECTOR_COVERAGE_2026-05-05.md)" \
	  $(if $(TRUTH),--truth-report "$(TRUTH)",) \
	  $(if $(BURNDOWN),--burndown-report "$(BURNDOWN)",) \
	  $(if $(TRUTH),,$(if $(BURNDOWN),,$(if $(REFRESH_SCANNER_INPUTS),--refresh-scanner-inputs,))) \
	  --live-inventory-limit "$(if $(LIVE_INVENTORY_LIMIT),$(LIVE_INVENTORY_LIMIT),12000)" \
	  $(if $(TOP),--top "$(TOP)",)

rust-detector-coverage-test:
	@python3 -m unittest tools.tests.test_rust_detector_coverage -v

rust-fixture-regression-list:
	@python3 tools/rust-fixture-regression-list.py \
	  --repo . \
	  --report "$(if $(IN),$(IN),reports/rust_detector_coverage_2026-05-05.json)" \
	  $(if $(SUMMARY),--summary,)

rust-fixture-regression-list-test:
	@python3 -m unittest tools.tests.test_rust_fixture_regression_list -v

rust-xfail-burndown:
	@python3 tools/rust-xfail-burndown.py . \
	  --json-out "$(if $(OUT),$(OUT),reports/rust_xfail_burndown_2026-05-05.json)" \
	  --md-out "$(if $(MD_OUT),$(MD_OUT),docs/RUST_XFAIL_BURNDOWN_2026-05-05.md)" \
	  $(if $(HELPER_OUTPUT),--helper-output "$(HELPER_OUTPUT)",) \
	  $(if $(HARNESS_OUTPUT),--harness-output "$(HARNESS_OUTPUT)",) \
	  $(if $(TIMEOUT),--timeout "$(TIMEOUT)",)

rust-xfail-burndown-test:
	@python3 -m unittest tools.tests.test_rust_xfail_burndown -v

harness-execution-queue:
	@python3 tools/harness-execution-queue.py \
	  --input "$(if $(IN),$(IN),reports/harness_binding_manifest_status_2026-05-05.json)" \
	  --workspace "$(if $(WS),$(WS),.)" \
	  --out "$(if $(OUT),$(OUT),reports/harness_execution_queue_2026-05-05.json)" \
	  $(if $(PRINT_JSON),--print-json,)

harness-execution-queue-test:
	@python3 -m unittest tools.tests.test_harness_execution_queue -v

commit-lifecycle-ledger:
	@python3 tools/commit-lifecycle-ledger.py \
	  --repo-root . \
	  --json-out "$(if $(JSON_OUT),$(JSON_OUT),reports/commit_lifecycle_ledger_2026-05-05.json)" \
	  --md-out "$(if $(MD_OUT),$(MD_OUT),docs/COMMIT_LIFECYCLE_LEDGER_2026-05-05.md)" \
	  $(if $(STDOUT),--stdout,)

commit-lifecycle-ledger-test:
	@python3 -m unittest tools.tests.test_commit_lifecycle_ledger -v

commit-mining-next-jobs:
	@python3 tools/commit-mining-next-jobs.py \
	  --repo-root . \
	  --date "$(if $(DATE),$(DATE),2026-05-05)" \
	  $(if $(OUT),--out "$(OUT)",) \
	  $(if $(MD_OUT),--markdown-out "$(MD_OUT)",) \
	  $(if $(PRINT_JSON),--json,)

commit-mining-next-jobs-test:
	@python3 -m unittest tools.tests.test_commit_mining_next_jobs -v

commit-mining-scan-tasks:
	@python3 tools/commit-mining-scan-task-emitter.py \
	  --repo-root . \
	  --date "$(if $(DATE),$(DATE),2026-05-05)" \
	  $(if $(NEXT_JOBS),--next-jobs "$(NEXT_JOBS)",) \
	  $(if $(VERIFY),--source-mirror-verify "$(VERIFY)",) \
	  $(if $(OUT),--out "$(OUT)",) \
	  $(if $(MD_OUT),--markdown-out "$(MD_OUT)",) \
	  $(if $(PRINT_JSON),--json,)

commit-mining-scan-tasks-test:
	@python3 -m unittest tools.tests.test_commit_mining_scan_task_emitter -v

commit-mining-source-review:
	@python3 tools/commit-mining-source-review.py \
	  --repo . \
	  --input "$(if $(INPUT),$(INPUT),reports/commit_mining_scan_tasks_2026-05-05.json)" \
	  --out "$(if $(OUT),$(OUT),reports/commit_mining_source_review_2026-05-05.json)" \
	  --markdown-out "$(if $(MD_OUT),$(MD_OUT),docs/COMMIT_MINING_SOURCE_REVIEW_2026-05-05.md)"

commit-mining-source-review-test:
	@python3 -m unittest tools.tests.test_commit_mining_source_review -v

commit-mining-source-disposition:
	@python3 tools/commit-mining-source-disposition.py \
	  --repo . \
	  --input "$(if $(INPUT),$(INPUT),reports/commit_mining_source_review_2026-05-05.json)" \
	  --out "$(if $(OUT),$(OUT),reports/commit_mining_source_disposition_2026-05-05.json)" \
	  --markdown-out "$(if $(MD_OUT),$(MD_OUT),docs/COMMIT_MINING_SOURCE_DISPOSITION_2026-05-05.md)" \
	  $(if $(MAX_QUEUE_ITEMS),--max-queue-items "$(MAX_QUEUE_ITEMS)",) \
	  $(if $(PRINT_JSON),--json,)

commit-mining-source-disposition-test:
	@python3 -m unittest tools.tests.test_commit_mining_source_disposition -v

commit-mining-review-task-packet:
	@python3 tools/commit-mining-review-task-packet.py \
	  --repo . \
	  --input "$(if $(INPUT),$(INPUT),reports/commit_mining_source_disposition_2026-05-05.json)" \
	  --out "$(if $(OUT),$(OUT),reports/commit_mining_review_task_packet_2026-05-05.json)" \
	  --markdown-out "$(if $(MD_OUT),$(MD_OUT),docs/COMMIT_MINING_REVIEW_TASK_PACKET_2026-05-05.md)" \
	  $(if $(MAX_TASKS),--max-tasks "$(MAX_TASKS)",) \
	  $(if $(PRINT_JSON),--json,)

commit-mining-review-task-packet-test:
	@python3 -m unittest tools.tests.test_commit_mining_review_task_packet -v

.PHONY: audit-target-commit-mining audit-target-commit-mining-test
audit-target-commit-mining:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-target-commit-mining WS=<workspace> [COMMIT_MINING_WINDOW=90] [FORCE=1] [DRY_RUN=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-target-commit-mining" "$(_WS_RESOLVED)"
	@_cm_to=""; if command -v gtimeout >/dev/null 2>&1; then _cm_to="gtimeout --kill-after=30 -s TERM $${AUDITOOOR_TARGET_COMMIT_MINING_TIMEOUT:-900}"; elif command -v timeout >/dev/null 2>&1; then _cm_to="timeout --kill-after=30 -s TERM $${AUDITOOOR_TARGET_COMMIT_MINING_TIMEOUT:-900}"; fi; \
	  if [ -z "$$_cm_to" ]; then echo "[audit-target-commit-mining] ERROR: requires gtimeout/timeout; refusing unbounded GitHub history mining" >&2; exit 127; fi; \
	  $$_cm_to python3 tools/audit-target-commit-mining.py \
	    --workspace "$(_WS_RESOLVED)" \
	    --window "$(if $(COMMIT_MINING_WINDOW),$(COMMIT_MINING_WINDOW),90)" \
	    $(if $(FORCE),--force,) \
	    $(if $(DRY_RUN),--dry-run,) \
	    $(if $(JSON),--json,)

audit-target-commit-mining-test:
	@python3 -m unittest tools.tests.test_audit_target_commit_mining -v

# --- Discovery scanners + fail-closed gates (generic, every workspace) ---------
# Step-1/2 high-signal static discovery passes that the canonical funnel lacked:
#  - incomplete-guard-ack: in-tree FIXME/TODO/skip-return co-located with a guard/
#    sink (developer-confessed incompleteness). Auto-run inside `make audit-depth`;
#    enforced fail-closed at `audit-done-guard` (Gap B).
#  - skipped-test: developer-confessed skipped/disabled tests. Same wiring.
#  - multi-repo-mining-coverage: every scope.json in_scope upstream repo mined,
#    not just the primary (Gap A). Auto-run via audit-target-commit-mining.
.PHONY: incomplete-guard-ack-scan incomplete-guard-ack-gate incomplete-guard-ack-test \
        igal-triage-emit igal-disposition igal-triage-test \
        skipped-test-scan skipped-test-gate skipped-test-test \
        multi-repo-mining-coverage-check multi-repo-mining-coverage-test
incomplete-guard-ack-scan:
	@if [ -z "$(WS)" ]; then echo 'Usage: make incomplete-guard-ack-scan WS=<workspace>'; exit 2; fi
	@python3 tools/incomplete-guard-acknowledgement-scanner.py --workspace "$(_WS_RESOLVED)" --emit $(if $(JSON),--json)
incomplete-guard-ack-gate:
	@if [ -z "$(WS)" ]; then echo 'Usage: make incomplete-guard-ack-gate WS=<workspace> [STRICT=1]'; exit 2; fi
	@python3 tools/incomplete-guard-ack-gate.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json)
incomplete-guard-ack-test:
	@python3 -m pytest tools/tests/test_incomplete_guard_acknowledgement_scanner.py -q
# IGAL canonical triage chain (ONE runbook step on every workspace):
#   make incomplete-guard-ack-scan WS=<ws>   # discovery (also auto-runs in audit-depth)
#   make igal-triage-emit WS=<ws>            # emit Agent(sonnet) batches from HIGH bucket
#   -> dispatch each .auditooor/igal_triage/_agent_plan/batch_*.md via Agent through spawn-worker.sh
#   make igal-disposition WS=<ws>            # fold verdicts -> dispositions; fileable -> open leads
#   make incomplete-guard-ack-gate WS=<ws> STRICT=1   # fail-closed authority
igal-triage-emit:
	@if [ -z "$(WS)" ]; then echo 'Usage: make igal-triage-emit WS=<workspace> [INCLUDE_MED=1] [BATCH_SIZE=12]'; exit 2; fi
	@python3 tools/igal-triage-emit.py --workspace "$(_WS_RESOLVED)" $(if $(INCLUDE_MED),--include-med) $(if $(BATCH_SIZE),--batch-size $(BATCH_SIZE)) $(if $(JSON),--json)
igal-disposition:
	@if [ -z "$(WS)" ]; then echo 'Usage: make igal-disposition WS=<workspace>'; exit 2; fi
	@python3 tools/igal-disposition-ingest.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json)
igal-triage-test:
	@python3 -m pytest tools/tests/test_igal_triage_chain.py -q
skipped-test-scan:
	@if [ -z "$(WS)" ]; then echo 'Usage: make skipped-test-scan WS=<workspace>'; exit 2; fi
	@python3 tools/skipped-test-marker-scan.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json)
skipped-test-gate:
	@if [ -z "$(WS)" ]; then echo 'Usage: make skipped-test-gate WS=<workspace> [STRICT=1]'; exit 2; fi
	@python3 tools/skipped-test-disposition-gate.py --workspace "$(_WS_RESOLVED)" --check $(if $(STRICT),--strict) $(if $(JSON),--json)
skipped-test-test:
	@python3 -m pytest tools/tests/test_skipped_test_marker_scan.py -q
multi-repo-mining-coverage-check:
	@if [ -z "$(WS)" ]; then echo 'Usage: make multi-repo-mining-coverage-check WS=<workspace> [STRICT=1]'; exit 2; fi
	@python3 tools/multi-repo-mining-coverage-check.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json)
multi-repo-mining-coverage-test:
	@python3 -m pytest tools/tests/test_multi_repo_mining_coverage.py -q

source-mirror-queue:
	@python3 tools/source-mirror-queue.py \
	  --repo-root . \
	  --json-out "$(if $(OUT),$(OUT),reports/source_mirror_queue_2026-05-05.json)" \
	  --markdown-out "$(if $(MD_OUT),$(MD_OUT),docs/SOURCE_MIRROR_QUEUE_2026-05-05.md)"

source-mirror-queue-test:
	@python3 -m unittest tools.tests.test_source_mirror_queue -v

source-mirror-verify:
	@python3 tools/source-mirror-verify.py \
	  --queue "$(if $(IN),$(IN),reports/source_mirror_queue_2026-05-05.json)" \
	  --out "$(if $(OUT),$(OUT),reports/source_mirror_verify_2026-05-05.json)" \
	  --base-dir "$(if $(BASE_DIR),$(BASE_DIR),.)" \
	  $(if $(MIRROR_ROOT),--mirror-root "$(MIRROR_ROOT)",) \
	  $(if $(REPO_MAP),--repo-map "$(REPO_MAP)",) \
	  $(if $(FAIL_ON_BLOCKED),--fail-on-blocked,)

source-mirror-verify-test:
	@python3 -m unittest tools.tests.test_source_mirror_verify -v

model-takeover-readiness:
	@python3 tools/model-takeover-readiness.py \
	  $(if $(JSON),--json) \
	  $(if $(FAIL_ON_BLOCKERS),--fail-on-blockers) \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(DOC),--doc "$(DOC)") \
	  $(if $(MAX_ITEMS),--max-items-per-artifact "$(MAX_ITEMS)")

model-takeover-handoff:
	@python3 tools/model-takeover-handoff.py \
	  --root . \
	  $(if $(READINESS_REPORT),--readiness-report "$(READINESS_REPORT)") \
	  $(if $(READINESS_DOC),--readiness-doc "$(READINESS_DOC)") \
	  $(if $(JSON_OUT),--json-out "$(JSON_OUT)") \
	  $(if $(DOC_OUT),--doc-out "$(DOC_OUT)") \
	  $(if $(PROVIDER),--provider "$(PROVIDER)") \
	  $(if $(MAX_ARTIFACTS),--max-artifacts "$(MAX_ARTIFACTS)") \
	  $(if $(MAX_ITEMS),--max-items-per-artifact "$(MAX_ITEMS)") \
	  $(if $(MAX_TEXT),--max-text "$(MAX_TEXT)") \
	  $(if $(STDOUT_FORMAT),--stdout-format "$(STDOUT_FORMAT)") \
	  $(if $(FAIL_ON_BLOCKERS),--fail-on-blockers)

model-takeover-readiness-test:
	@python3 -m unittest tools.tests.test_model_takeover_readiness -v

model-takeover-handoff-test:
	@python3 -m unittest tools.tests.test_model_takeover_handoff -v

harness-failure-memory:
	@python3 tools/harness-failure-memory.py $(if $(WRITE),--write,) $(if $(JSON),--json)

harness-failure-memory-validate:
	@python3 tools/harness-failure-memory.py --validate

harness-failure-memory-test:
	@python3 -m unittest tools.tests.test_harness_failure_memory -v

known-limitations-harness-memory-status:
	@python3 tools/known-limitations-harness-memory-status.py \
	  $(if $(BURNDOWN),--burndown "$(BURNDOWN)") \
	  $(if $(DISPATCH),--dispatch "$(DISPATCH)") \
	  $(if $(OUT),--output "$(OUT)") \
	  $(if $(DOC),--docs "$(DOC)") \
	  $(if $(PRINT_JSON),--print-json)

known-limitations-harness-memory-status-test:
	@python3 -m unittest tools.tests.test_known_limitations_harness_memory_status -v

impact-contract-preflight-status:
	@python3 tools/impact-contract-preflight-status.py \
	  $(if $(JSON_OUT),--json-out "$(JSON_OUT)") \
	  $(if $(MD_OUT),--md-out "$(MD_OUT)") \
	  $(if $(PRINT_JSON),--print-json)

impact-contract-preflight-status-test:
	@python3 -m unittest tools.tests.test_impact_contract_preflight_status -v

task-finalization-validate:
	@python3 tools/task-finalization-ledger.py validate

task-finalization-report:
	@python3 tools/task-finalization-ledger.py report --limit 10

task-finalization-summary:
	@python3 tools/task-finalization-ledger.py summary $(if $(JSON),--json)

task-finalization-pr-status:
	@python3 tools/task-finalization-ledger.py pr-range-status --base-ref origin/main --start-pr 607 --end-pr 638 $(if $(JSON),--json)

task-finalization-pr-backfill:
	@python3 tools/task-finalization-ledger.py backfill-pr-range --base-ref origin/main --start-pr 607 --end-pr 638 --owner codex $(if $(WRITE),--write,--dry-run) $(if $(JSON),--json)

task-finalization-test:
	@python3 -m unittest tools.tests.test_task_finalization_ledger -v

knowledge-gap-validate:
	@python3 tools/knowledge-gap-log.py validate

knowledge-gap-list:
	@python3 tools/knowledge-gap-log.py list $(if $(STATUS),--status $(STATUS),) $(if $(JSON),--json)

knowledge-gap-summary:
	@python3 tools/knowledge-gap-log.py summary $(if $(JSON),--json)

knowledge-gap-rebuild-projections:
	@python3 tools/knowledge-gap-log.py rebuild-projections $(if $(WRITE),,--dry-run) $(if $(JSON),--json)

knowledge-gap-test:
	@python3 -m unittest tools.tests.test_knowledge_gap_log -v

exploit-memory-brief:
	@test -n "$(WS)" || { echo "usage: make exploit-memory-brief WS=~/audits/<project> [JSON=1]" >&2; exit 2; }
	@python3 tools/exploit-memory-brief.py --workspace "$(WS)" $(if $(JSON),--json)

exploit-memory-brief-validate:
	@test -n "$(BRIEF)" || { echo "usage: make exploit-memory-brief-validate BRIEF=<exploit_memory_brief.json>" >&2; exit 2; }
	@python3 tools/exploit-memory-brief.py --validate "$(BRIEF)" $(if $(JSON),--json)

exploit-memory-brief-test:
	@python3 -m unittest tools.tests.test_exploit_memory_brief -v

outcome-semantics-test:
	@python3 -m unittest \
	  tools.tests.test_unknown_reason_decline_semantics \
	  tools.tests.test_outcome_telemetry_manifest \
	  tools.tests.test_outcome_calibration_resolved_linkage_validator \
	  tools.tests.test_outcome_reweight \
	  tools.tests.test_outcome_calibration_route_evidence_importer \
	  tools.tests.test_outcome_calibration_scorecard \
	  -v

control-plane-test:
	@python3 -m unittest \
	  tools.tests.test_control_integration \
	  tools.tests.test_auditooorctl_control_commands \
	  tools.tests.test_auditooorctl_status \
	  tools.tests.test_control_workpacks \
	  -v

memory-control-plane-test:
	@$(MAKE) memory-next-loop-test
	@$(MAKE) batch-checkpoint-status-test
	@$(MAKE) task-finalization-test
	@$(MAKE) knowledge-gap-test
	@$(MAKE) vault-mcp-test
	@$(MAKE) exploit-memory-brief-test
	@$(MAKE) outcome-semantics-test
	@$(MAKE) control-plane-test

# ACT-20 - standalone privacy audit targets
memory-privacy-audit:
	@python3 tools/memory-privacy-audit.py --vault obsidian-vault --whitelist reports/privacy_audit_whitelist.yaml

memory-privacy-audit-quarantine:
	@python3 tools/memory-privacy-audit.py --vault obsidian-vault --whitelist reports/privacy_audit_whitelist.yaml --quarantine

memory-privacy-audit-self-test:
	@python3 tools/memory-privacy-audit.py --self-test

# Lane 7 (PR #658 Tier-B #11) - secret-scrub over git-changed files
secret-scrub-changed:
	@python3 tools/secret-scrub-changed-files.py --upstream "@{upstream}"

secret-scrub-changed-test:
	@python3 -m unittest tools.tests.test_secret_scrub_changed_files -v

# -----------------------------------------------------------------------
# Layer L2 Memory Rollups (ACT-18)
# -----------------------------------------------------------------------
memory-rollup-daily:
	@python3 tools/memory-rollup-daily.py --vault-dir obsidian-vault \
	  $(if $(DATE),--date $(DATE))

memory-rollup-weekly:
	@python3 tools/memory-rollup-weekly.py --vault-dir obsidian-vault \
	  $(if $(WEEK),--week $(WEEK))

memory-rollups-backfill:
	@echo "[backfill] Generating daily rollups for last 30 days..."
	@python3 tools/memory-rollup-daily.py --vault-dir obsidian-vault --backfill 30
	@echo "[backfill] Generating weekly rollups for last 5 weeks..."
	@python3 tools/memory-rollup-weekly.py --vault-dir obsidian-vault --backfill 5
	@echo "[backfill] Done. See obsidian-vault/rollups/"

vault-deepen:
	@python3 tools/obsidian-vault-emit.py --vault-dir obsidian-vault --deep

vault-dashboard:
	@python3 tools/obsidian-vault-dashboard.py --vault-dir obsidian-vault

# ACT-11: Slither compile cache targets (37-100x speedup for precision-matrix)
slither-cache-warm:
	@python3 tools/slither-compile-cache.py --warm detectors/test_fixtures

slither-cache-stats:
	@python3 tools/slither-compile-cache.py --stats

slither-cache-clear:
	@python3 tools/slither-compile-cache.py --clear

slither-cache-self-test:
	@python3 tools/slither-cache-self-test.py

# PR 211 - sanity check for FAILURE_MODES.md + 10_OF_10_PLAYBOOK.md.
# grep-based, NOT a full parser. Asserts:
#   - both files exist
#   - every FM-### row in FAILURE_MODES.md has all required fields
#     (First seen, What happened, Why it was possible, How it was caught,
#      What prevents regression now, Status vocabulary affected,
#      Artifact classification affected)
#   - 10_OF_10_PLAYBOOK.md has all 8 section headings (1. .. 8.)
# Authoritative test (parses markdown + cross-checks the status vocab set)
# lives at tools/tests/test_failure_modes_doc.py.
docs-check-playbook:
	@set -e ; \
	fm="docs/FAILURE_MODES.md" ; \
	pb="docs/10_OF_10_PLAYBOOK.md" ; \
	if [ ! -f "$$fm" ]; then echo "[docs-check-playbook] ERR missing $$fm"; exit 2; fi ; \
	if [ ! -f "$$pb" ]; then echo "[docs-check-playbook] ERR missing $$pb"; exit 2; fi ; \
	rows=$$(grep -cE '^### FM-[0-9]{3} ' "$$fm" || true) ; \
	if [ "$$rows" -lt 17 ]; then \
	  echo "[docs-check-playbook] ERR expected >=17 FM-### rows in $$fm, got $$rows"; exit 2; fi ; \
	for field in \
	  '\*\*First seen:\*\*' \
	  '\*\*What happened:\*\*' \
	  '\*\*Why it was possible:\*\*' \
	  '\*\*How it was caught:\*\*' \
	  '\*\*What prevents regression now:\*\*' \
	  '\*\*Status vocabulary affected:\*\*' \
	  '\*\*Artifact classification affected:\*\*' ; do \
	  c=$$(grep -cE "$$field" "$$fm" || true) ; \
	  if [ "$$c" -lt "$$rows" ]; then \
	    echo "[docs-check-playbook] ERR field $$field missing on some FM rows ($$c < $$rows)"; exit 2; fi ; \
	done ; \
	for n in 1 2 3 4 5 6 7 8 ; do \
	  if ! grep -qE "^## $$n\. " "$$pb" ; then \
	    echo "[docs-check-playbook] ERR $$pb missing section $$n"; exit 2; fi ; \
	done ; \
	echo "[docs-check-playbook] OK ($$rows FM rows, 8 playbook sections)"

workspace-inventory:
	@python3 tools/workspace-inventory.py \
	  --audits-dir "$(if $(AUDITS_DIR),$(AUDITS_DIR),$(HOME)/audits)" \
	  $(if $(ALL),--all) \
	  $(if $(JSON),--json)

intake-baseline:
	@if [ -z "$(WORKSPACE)" ]; then echo "Usage: make intake-baseline WORKSPACE=<path>"; exit 1; fi
	@python3 tools/intake-baseline.py "$(WORKSPACE)"

intake-saturation-score:
	@if [ -z "$(WS)" ] && [ -z "$(WORKSPACE)" ]; then echo "Usage: make intake-saturation-score WS=<path>"; exit 1; fi
	@python3 tools/target-saturation-score.py "$(if $(WS),$(WS),$(WORKSPACE))"

intake-baseline-test:
	@python3 tools/tests/test_intake_baseline.py

# Wave-5 W5-H3 - repo-to-workspace intake scaffolder.
# Collapses the manual 6-file intake editor session to one command:
# emits the workspace skeleton with SCOPE.md / SEVERITY.md /
# INTAKE_BASELINE.md / PRIOR_CONCERNS.md / scope.json / workspace lock
# pre-populated as far as automatable; human parts left as TODO(human).
#   make intake-scaffold REPO=<url-or-path> PIN=<sha> PLATFORM=<slug>
intake-scaffold:
	@if [ -z "$(REPO)" ] || [ -z "$(PIN)" ] || [ -z "$(PLATFORM)" ]; then \
	  echo "Usage: make intake-scaffold REPO=<url-or-path> PIN=<sha> PLATFORM=<cantina|immunefi|sherlock|code4rena|hats|other> [NAME=<slug>] [AUDITS_DIR=<dir>] [SCOPE_URL=<url>]"; \
	  exit 2; \
	fi
	@python3 tools/audit/intake-scaffolder.py \
		--repo "$(REPO)" --pin "$(PIN)" --platform "$(PLATFORM)" \
		$(if $(NAME),--name "$(NAME)",) \
		$(if $(AUDITS_DIR),--audits-dir "$(AUDITS_DIR)",) \
		$(if $(SCOPE_URL),--scope-url "$(SCOPE_URL)",)

intake-scaffold-test:
	@python3 -m unittest tools.tests.test_intake_scaffolder

submission-tracker-check:
	@if [ -z "$(WORKSPACE)" ]; then echo "Usage: make submission-tracker-check WORKSPACE=<path>"; exit 1; fi
	@python3 tools/check-submission-tracker.py "$(WORKSPACE)" $(if $(JSON),--json)

operator-action-digest: ## Digest of all pending operator actions for a workspace (WS=<path>)
	@python3 tools/operator-action-tracker.py \
	  $(if $(WS),--workspace "$(WS)") \
	  $(if $(SINCE),--since "$(SINCE)") \
	  $(if $(AUDITS_ROOT),--audits-root "$(AUDITS_ROOT)") \
	  $(if $(JSON),--json)

operator-action-digest-all: ## Digest of all pending operator actions across all workspaces
	@python3 tools/operator-action-tracker.py \
	  --workspace "$(CURDIR)" \
	  --audits-root "$(HOME)/audits" \
	  $(if $(SINCE),--since "$(SINCE)") \
	  $(if $(JSON),--json)

operator-action-tracker-test: ## Run tests for operator-action-tracker
	@python3 -m unittest tools.tests.test_operator_action_tracker -v

outcome-telemetry:
	@python3 tools/outcome-telemetry.py \
	  $(if $(WORKSPACE),"$(WORKSPACE)") \
	  --audits-dir "$(if $(AUDITS_DIR),$(AUDITS_DIR),$(HOME)/audits)" \
	  $(if $(JSON),--json) \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(WRITE_JSONL),--write-jsonl "$(WRITE_JSONL)")

outcome-telemetry-test:
	@python3 tools/tests/test_outcome_telemetry.py

# T1-P0-4 v0 - outcome learning scoreboard.
# Reads reference/outcomes.jsonl and writes reports/outcome_scoreboard.json.
# Offline, deterministic, never mutates the ledger.
outcome-scoreboard:
	@python3 tools/outcome-scoreboard.py \
	  $(if $(OUTCOMES),--outcomes "$(OUTCOMES)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(ROLLING_DAYS),--rolling-days $(ROLLING_DAYS)) \
	  $(if $(TOP_REGRESSIONS),--top-regressions $(TOP_REGRESSIONS)) \
	  $(if $(STDOUT),--stdout)

outcome-scoreboard-test:
	@python3 -m unittest tools.tests.test_outcome_scoreboard

# T1-PRIORITY-3 v0 - agent-found-behavior recall pipeline.
# Reads reports/outcome_scoreboard.json + reference/outcomes.jsonl and emits
# reports/agent_recall_suggestions_<DATE>.json with per-lane scanner-improvement
# action suggestions (pause / split-detector / add-allow-list / lower-confidence-
# threshold / observe). Offline, stdlib-only, never mutates inputs.
agent-recall-suggest:
	@python3 tools/agent-recall-suggester.py \
	  $(if $(SCOREBOARD),--scoreboard "$(SCOREBOARD)") \
	  $(if $(LEDGER),--ledger "$(LEDGER)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(REGRESSION_PP),--regression-pp $(REGRESSION_PP)) \
	  $(if $(TOP_N),--top-n $(TOP_N)) \
	  $(if $(STDOUT),--stdout)

agent-recall-suggest-test:
	@python3 -m unittest tools.tests.test_agent_recall_suggester

# PR 210 - cost telemetry summarizer. Advisory only (est_cost_usd, not a bill).
# Usage: make cost-summary WORKSPACE=~/audits/<project> [JSON=1]
# If WORKSPACE is unset, defaults to the first dir under ~/audits/.
cost-summary:
	@ws="$(WORKSPACE)"; \
	if [ -z "$$ws" ]; then \
	  ws="$$(ls -1d $(HOME)/audits/*/ 2>/dev/null | head -1)"; \
	  if [ -z "$$ws" ]; then \
	    echo "[cost-summary] ERR no workspace given and none found under $(HOME)/audits/"; \
	    exit 2; \
	  fi; \
	  echo "[cost-summary] defaulting to first workspace: $$ws"; \
	fi; \
	python3 tools/cost-telemetry.py --summarize "$$ws" $(if $(JSON),--json)

cost-telemetry-test:
	@python3 tools/tests/test_cost_telemetry.py

# F4 fork-replay harness (act13-fork-replay).
# Usage: make fork-replay WS=<workspace> FN=<finding-id> [PROTOCOL=<name>] [BLOCK=N] [TX=0x...] [DRY_RUN=1] [HERMETIC=1]
# Self-test (no RPC): make fork-replay-hermetic
fork-replay:
	@if [ -z "$(WS)" ] || [ -z "$(FN)" ]; then \
	  echo "usage: make fork-replay WS=<workspace> FN=<finding-id> [PROTOCOL=<name>] [BLOCK=N] [TX=0x...] [DRY_RUN=1] [HERMETIC=1]"; \
	  echo ""; \
	  echo "Examples:"; \
	  echo "  make fork-replay WS=~/audits/base-azul FN=FN2 PROTOCOL=optimism BLOCK=21500000 TX=0xabc123"; \
	  echo "  make fork-replay WS=. FN=TEST HERMETIC=1  # hermetic self-test (no RPC needed)"; \
	  echo "  make fork-replay WS=. FN=DEMO DRY_RUN=1 PROTOCOL=arbitrum  # dry-run only"; \
	  exit 2; \
	fi
	@python3 tools/fork-replay.py \
	  $(if $(HERMETIC),--hermetic) \
	  $(if $(DRY_RUN),--dry-run) \
	  --workspace "$(WS)" \
	  --finding-id $(FN) \
	  $(if $(PROTOCOL),--protocol $(PROTOCOL)) \
	  $(if $(BLOCK),--block $(BLOCK)) \
	  $(if $(TX),--replay-tx $(TX)) \
	  $(if $(RECIPE),--recipe $(RECIPE)) \
	  $(if $(OVERRIDE),--override-contract "$(OVERRIDE)") \
	  $(if $(ASSERT),--assert "$(ASSERT)")

fork-replay-hermetic:
	@echo "[fork-replay-hermetic] Running hermetic self-test (no RPC required)"
	@python3 tools/fork-replay.py \
	  --hermetic \
	  --finding-id TEST \
	  --workspace /tmp/fork-replay-hermetic-$$$$ \
	  --override-contract "OptimismPortal=detectors/_fixtures/replay_harness/OptimismPortalStub.sol" \
	  --override-contract "Inbox=detectors/_fixtures/replay_harness/ArbitrumInboxStub.sol"
	@echo "[fork-replay-hermetic] PASS"

# Cosmos/Go fork-replay branch - symbolic equivalent of Solidity fork-replay for
# Cosmos SDK / Go-based audit workspaces.  Self-skips when no Cosmos/Go shape is
# detected (go.mod / app/app.go / cmd/*/main.go absent); always exits 0.
# Usage: make fork-replay-cosmos-go WS=<workspace> FN=<finding-id> [HERMETIC=1] [DRY_RUN=1]
# Self-test: make fork-replay-cosmos-go-test
.PHONY: fork-replay-cosmos-go fork-replay-cosmos-go-test
fork-replay-cosmos-go:
	@if [ -z "$(WS)" ] || [ -z "$(FN)" ]; then \
	  echo "usage: make fork-replay-cosmos-go WS=<workspace> FN=<finding-id> [HERMETIC=1] [DRY_RUN=1]"; \
	  echo ""; \
	  echo "Examples:"; \
	  echo "  make fork-replay-cosmos-go WS=~/audits/dydx FN=FN1 HERMETIC=1"; \
	  echo "  make fork-replay-cosmos-go WS=~/audits/dydx FN=DEMO DRY_RUN=1"; \
	  exit 2; \
	fi
	@python3 tools/fork-replay-cosmos-go.py \
	  --workspace "$(WS)" \
	  --finding-id $(FN) \
	  $(if $(HERMETIC),--hermetic,) \
	  $(if $(DRY_RUN),--dry-run,)

fork-replay-cosmos-go-test:
	@echo "[fork-replay-cosmos-go-test] Running hermetic self-test"
	@python3 tools/fork-replay-cosmos-go.py --hermetic --workspace /tmp/frcg-$$$$ --finding-id TEST
	@echo "[fork-replay-cosmos-go-test] PASS"

fork-replay-test:
	@python3 tools/tests/test_fork_replay_cli.py
	@python3 tools/tests/test_fork_replay_package.py
	@python3 tools/tests/test_fork_replay_assert.py
	@python3 tools/tests/test_pre_submit_fork_replay.py
	@python3 tools/tests/test_fork_replay_config.py
	@python3 tools/tests/test_fork_replay_assert_impact_bound.py
	@python3 tools/tests/test_submission_packager_fork_replay_layout.py

# PR 107 - bounded fuzz runner (advisory; intentionally NOT wired into `make all`
# or `fork-replay-test`). Run manually or via CI when explicitly invoked.
fuzz-runner-test:
	@python3 tools/tests/test_fuzz_runner.py

# V5 PR 4 - fuzz campaign wrapper over existing fuzz/deep tooling.
# Bounded campaign farm; orchestrates tools/fuzz-runner.sh + forge invariant +
# tools/symbolic-ce-to-forge.py + tools/poc-scaffold.py. PR 4 first-impl
# scope: forge-only; medusa/echidna/halmos orchestration deferred.
fuzz-campaign:
	@if [ -z "$(WS)" ] || [ -z "$(TARGET)" ]; then \
	  echo "usage: make fuzz-campaign WS=<workspace> TARGET=<Contract> [PROFILE=invariant|fuzz] [DURATION=600]"; \
	  exit 2; \
	fi
	@python3 tools/fuzz-campaign.py \
	  --workspace $(WS) \
	  --target $(TARGET) \
	  --profile $(if $(PROFILE),$(PROFILE),invariant) \
	  --duration $(if $(DURATION),$(DURATION),600) \
	  --out $(WS)/fuzz_campaigns/$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),$(TARGET)-$(shell date -u +%Y%m%dT%H%M%SZ))

fuzz-campaign-test:
	@python3 -m unittest tools.tests.test_fuzz_campaign

fuzz-quick:
	@if [ -z "$(WS)" ]; then \
	  echo "usage: make fuzz-quick WS=<workspace|slug> [TARGETS=5] [INPUT=<fuzz_results.json>]"; \
	  exit 2; \
	fi
	@python3 tools/fuzz-target-corpus.py \
	  --workspace "$(WS)" \
	  $(if $(INPUT),--input "$(INPUT)",) \
	  --limit $(if $(TARGETS),$(TARGETS),5) \
	  $(if $(OUT),--out "$(OUT)",) \
	  $(if $(JSON),--json)

fuzz-quick-test:
	@python3 -m unittest tools.tests.test_fuzz_target_corpus

# capv3 iter2 T5 - scope-reasoner regex prototype (advisory-only; flags
# likely-OOS drafts before submission). Run on a single draft, or use
# scope-reasoner-test for the offline regression suite.
scope-reasoner:
	@if [ -z "$(DRAFT)" ]; then \
	  echo "usage: make scope-reasoner DRAFT=<path-to-source-draft.md> [SCOPE=<path>]"; \
	  exit 2; \
	fi
	@python3 tools/scope-reasoner.py --draft $(DRAFT) $(if $(SCOPE),--scope $(SCOPE))

scope-reasoner-test:
	@python3 -m unittest tools.tests.test_scope_reasoner tools.tests.test_scope_reasoner_check23 tools.tests.test_scope_oos_semantic_gate

# capv3 iter1 T1 - task-spec manifest regression for the end-to-end
# centrifuge-v3 fuzz run (advisory; not wired into `make all`). Skips cleanly
# if the workspace is absent - no network, no engine install.
fuzz-runner-manifest-schema-test:
	@python3 tools/tests/test_fuzz_runner_manifest_schema.py

# PR 108 - evidence-matrix offline unit test (no network, no subprocess).
evidence-matrix-test:
	@python3 tools/tests/test_evidence_matrix.py

# PR 109 - symbolic-execution slice (Phase C kickoff; A-AUTH only; advisory;
# intentionally NOT wired into `make all` or `ci-check`). Run manually.
symbolic-runner-test:
	@python3 tools/tests/test_symbolic_runner.py

# PR 207 iter4 T4 - economic-simulator prototype (advisory-only; dry-run
# default; first validated target is POLY-ITER3-R77-06). Intentionally NOT
# wired into `make all` or `ci-check`; run manually or via iter loop. No
# real halmos/anvil/RPC invocation in the offline suite.
econ-simulator-test:
	@python3 tools/tests/test_econ_simulator.py

# PR 207-b iter10 T4 - econ-simulator live-mode code-path (halmos + anvil
# behind --live flag). Still advisory-only; every manifest preserves
# evidence_matrix_contributes: false. Tests use unittest.mock.patch on
# subprocess.run / subprocess.Popen / shutil.which - NO real halmos/anvil
# invocation in the offline suite. Gate promotion remains PR 207-e.
econ-simulator-live-test:
	@python3 tools/tests/test_econ_simulator_live_mode.py

# PR 205 - contest-leaderboard ingestion (offline skeleton; advisory-only).
# Reads pre-fetched JSON caches under reference/contest_cache/{cantina,immunefi}/
# and writes novelty seeds to reference/contest_patterns.jsonl. Advisory only:
# seeds never auto-promote into reference/patterns.dsl/. Live fetch is NOT
# implemented this iter. Test target follows the symbolic-runner pattern:
# standalone, not auto-wired into `make all` or `make test` - run manually.
contest-ingest-test:
	@python3 tools/tests/test_contest_ingest.py

# PR 110 - Formal Invariant Library v1. The *-check target is cheap (existence +
# section headers); the *-test target runs the full unittest suite.
invariant-templates-check:
	@for slug in conservation solvency monotonicity fee-accrual-bounds oracle-freshness access-control-symmetry; do \
	  f="reference/invariants/$$slug.md"; \
	  if [ ! -f "$$f" ]; then echo "[invariant-templates-check] FAIL: missing $$f"; exit 1; fi; \
	  for sec in "## Invariant statement" "## Applicability criteria" "## Non-applicability warnings" "## Candidate witness test" "## Attach this invariant to a candidate" "## Expected counterexample shape" "## Related bug classes"; do \
	    if ! grep -qF "$$sec" "$$f"; then echo "[invariant-templates-check] FAIL: $$f missing section: $$sec"; exit 1; fi; \
	  done; \
	done
	@if [ ! -f reference/invariants/MANIFEST.json ]; then echo "[invariant-templates-check] FAIL: missing MANIFEST.json"; exit 1; fi
	@python3 -c "import json; json.loads(open('reference/invariants/MANIFEST.json').read())"
	@echo "[invariant-templates-check] OK: 6 templates + MANIFEST.json"

invariant-templates-test:
	@python3 tools/tests/test_attach_invariant.py

# PR 112 - outcome-driven reweighting. Offline unit test (no network).
outcome-reweight-test:
	@python3 tools/tests/test_outcome_reweight.py

# PR 111 - Economic Risk Card. HYPOTHESIS-GENERATING per-engagement card
# (liquidation cascade, sandwich/MEV, governance, supply pressure, fee path,
# oracle dependency). Offline: no forge/slither/halmos/network. Not wired
# into `make all`, `ci-check`, `pre-submit-check.sh`, or any blocking gate.
economic-risk-card:
	@python3 tools/economic-risk-card.py "$(WORKSPACE)" \
	  $(if $(CONTRACT),--contract "$(CONTRACT)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(JSON_OUT),--json-out "$(JSON_OUT)")

economic-risk-card-test:
	@python3 tools/tests/test_economic_risk_card.py

# iter7 T5 - workspace-bootstrap.py offline tests. No network. No `~/audits/`
# touched; tests use tempfile sandboxes.
workspace-bootstrap-test:
	@python3 tools/tests/test_workspace_bootstrap.py

# PR #546 Wave 2 Agent E - rust-cache-miss-policy-scanner.py.
# Walks Rust crate sources under <ws>/external/<*>/crates/ and flags
# cache-miss / silent-success / deferred-validation patterns. Default-to-kill:
# every emitted row starts at `kill_or_reframe` until impact-mapped via
# `make base-critical-matrix`. Stdlib-only.
#
#   make rust-cache-miss-scan WS=~/audits/base-azul
#   make rust-cache-miss-scan WS=~/audits/base-azul STRICT=1
#   make rust-cache-miss-scan WS=~/audits/base-azul OUT=/tmp/cm
rust-cache-miss-scan:
	@if [ -z "$(WS)" ]; then echo "usage: make rust-cache-miss-scan WS=<workspace> [OUT=<dir>] [STRICT=1]"; exit 2; fi
	@python3 tools/rust-cache-miss-policy-scanner.py \
	  --workspace "$(WS)" \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(STRICT),--strict)

rust-cache-miss-scan-test:
	@python3 tools/tests/test_rust_cache_miss_policy_scanner.py

# iter10 T1 - ccia-rust.py (Rust/Soroban CCIA adapter - advisory-only).
# Heuristic attack-angle scanner for .rs files under <workspace>/src/.
# Confidence capped at {low, medium}; never emits `high`. NO ledger writes.
# Offline test fixtures in tmpfile sandboxes + a real-source smoke test
# against ~/audits/k2/src/ (skipped if unavailable). Not wired into
# `make all` or `ci-check` - run manually or via iter loop.
ccia-rust-test:
	@python3 tools/tests/test_ccia_rust.py

# iter8 T5 - engagement-dashboard.py operator-visibility tool. Read-only
# summary over `<AUDITS_DIR>/*/reference/outcomes.jsonl` + packaging reports.
# Invoke with `make engagement-dashboard AUDITS_DIR=~/audits JSON=1` for JSON.
engagement-dashboard:
	@python3 tools/engagement-dashboard.py --audits-dir $(if $(AUDITS_DIR),$(AUDITS_DIR),$(HOME)/audits) $(if $(JSON),--json)

engagement-dashboard-test:
	@python3 tools/tests/test_engagement_dashboard.py

cross-learnings:
	@echo "[cross-learnings] cross-engagement-learner.py is archived; prefer make xws-lookup for current cross-workspace mapping"
	@python3 tools/_archived/cross-engagement-learner.py --out docs/archive/CROSS_ENGAGEMENT_LEARNINGS.md

xws-lookup:
	@echo "[xws-lookup] cross-workspace-lookup.py is archived; using cross-ws-pattern-mapper.py"
	@python3 tools/cross-ws-pattern-mapper.py \
	  --audits-dir "$(if $(AUDITS_DIR),$(AUDITS_DIR),$(HOME)/audits)" \
	  $(if $(PATTERN),--pattern "$(PATTERN)") \
	  $(if $(SUGGEST),--suggest) \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(JSON),--json) \
	  $(if $(GENERATE_CCIA),--generate-ccia)

coverage-matrix:
	@python3 tools/detector-coverage-matrix.py

lint:
	@python3 tools/detector-lint.py > docs/DETECTOR_LINT_REPORT.md
	@echo "[lint] wrote docs/DETECTOR_LINT_REPORT.md"
	@grep -E "^##|^\*\*Count" docs/DETECTOR_LINT_REPORT.md | head -40

# Cross-cut single entry point for the docs/KNOWN_LIMITATIONS.md burn-down.
# Runs the detector-lint flag matrix + focused unit tests with a single PASS/
# WARN/FAIL summary. Default mode reports remaining burn-down items as WARN
# (advisory) and exits 0; STRICT=1 promotes WARN to FAIL and adds the
# audit-closeout regression test.
#
#   make known-limitations-check
#   make known-limitations-check STRICT=1
#
# See tools/known-limitations-check.sh for gate definitions and exit codes.
known-limitations-check:
	@STRICT=$(if $(STRICT),$(STRICT),0) bash tools/known-limitations-check.sh

known-limitations-check-test:
	@python3 -m unittest tools.tests.test_make_known_limitations_check

freshness:
	@python3 tools/pattern-freshness-audit.py

dsl-audit:
	@python3 tools/dsl-migration-helper.py --audit

tier-move:
	@if [ -z "$(DET)" ] || [ -z "$(FROM)" ] || [ -z "$(TO)" ]; then \
	  echo "Usage: make tier-move DET=<name> FROM=<S|E|A|B|C|D> TO=<S|E|A|B|C|D> [REASON=\"...\"] [DRY_RUN=1]"; \
	  exit 1; \
	fi
	@python3 tools/detector-tier-mover.py --det $(DET) --from $(FROM) --to $(TO) \
	  $(if $(REASON),--reason "$(REASON)") $(if $(DRY_RUN),--dry-run)

tier-move-bulk:
	@if [ -z "$(FILE)" ]; then echo "Usage: make tier-move-bulk FILE=<moves.yaml> [DRY_RUN=1]"; exit 1; fi
	@python3 tools/detector-tier-mover.py --bulk $(FILE) $(if $(DRY_RUN),--dry-run)

# Phase 21: empirically sample detector hit-rates against a user-supplied corpus.
# Graceful when CORPUS is unset/missing - prints example usage and exits 0.
# See docs/HIT_SAMPLER.md for interpretation notes.
sample:
	@python3 tools/detector-hit-sampler.py $(if $(CORPUS),--corpus-dir $(CORPUS)) $(if $(MAX_FILES),--max-files $(MAX_FILES))

# Phase 24: cross-check DSL severity/confidence vs BUG_CLASSES tier/severity.
# Advisory only - always exits 0. Writes docs/SEVERITY_RECONCILE_REPORT.md.
severity-reconcile:
	@python3 tools/pattern-severity-reconciler.py

# Phase 28: generate first-draft sibling detectors for BUG_CLASSES flagged
# rust_only / sol_only. Drafts are reviewer prompts - NOT auto-registered in
# BUG_CLASSES or test_detectors.sh. Idempotent. See docs/PARITY_GAP_DRAFTS.md.
parity-drafts:
	@python3 tools/parity-gap-closer.py

# Phase 28 (SKILL_ISSUES #52): scan detectors against known-clean reference
# codebases (OZ / Solady / Solmate) to surface candidate false-positives.
# Graceful when ~/.calibration-workspaces is empty - prints clone instructions
# and exits 0. See docs/FP_CALIBRATION.md.
fp-calibration:
	@bash tools/fp-calibration.sh

# Phase 29: auto-triage the FP-calibration report into action bins
# (graveyard / tighten / whitelist / ok). Recommendations only - does NOT
# move files or edit patterns. Graceful when no report exists (prints SKIPPED,
# exits 0). Writes docs/AUTO_FP_TRIAGE.md. See tools/auto-fp-triage.py.
auto-fp-triage:
	@python3 tools/auto-fp-triage.py

# Phase 32: surface BUG_CLASSES we may be missing, via analogical reasoning
# over the existing registry + public exploit-anchor fixtures. Complements
# gap-analyzer.py (corpus-based). Writes docs/NOVEL_BUG_CANDIDATES.md.
novel-candidates:
	@python3 tools/novel-bug-class-surfacer.py

# Phase 34: cluster BUG_CLASSES into families via agglomerative Jaccard over
# the top-5 analogical neighbours. Emits docs/BUG_CLASS_FAMILY_MAP.{md,html}
# (SVG treemap). Complements novel-candidates (which surfaces gaps) and
# DETECTOR_COVERAGE_MATRIX (which shows topic × language counts).
family-map:
	@python3 tools/bug-class-family-map.py

# ─── Existing onboarding targets ─────────────────────────────────────────────

init:
	@echo "No submodules are required for the public judge build."

bootstrap:
	@bash scripts/bootstrap-newclone.sh

update:
	@echo "No submodules are configured for the public judge build."

setup:
	@if [ -z "$(PROJECT)" ]; then echo "Usage: make setup PROJECT=<name>"; exit 1; fi
	./tools/setup-workspace.sh $(PROJECT)

# capv3 iter-006 T4 - one-command engagement spin-up per the 9-step contract in
# docs/ENGAGEMENT_3_KICKOFF.md §2. Does NOT acquire a real engagement - this
# target only scaffolds the workspace shape so the operator can paste bounty
# text + run `make engage`. Idempotent: a second invocation with the same slug
# warns + no-ops + exits 0 (no mutations).
#
# Vocabulary (target stdout, report-local; no §5 row added this iter):
#   - "[new-engagement] created <slug>" on fresh scaffold
#   - "[new-engagement] already-exists <slug>" on idempotent no-op
#   - "[new-engagement] error …" on missing args / scaffold failure
#
# Hard rule: this target MUST NOT pull from SOURCE. SOURCE is recorded in
# SCOPE.md + scope.json as provenance; no HTTP fetch happens here.
new-engagement:
	@if [ -z "$(NAME)" ]; then \
	  echo "[new-engagement] error: NAME required" >&2 ; \
	  echo "  Usage: make new-engagement NAME=<slug> SOURCE=<url>" >&2 ; \
	  echo "  See docs/ENGAGEMENT_3_KICKOFF.md §2 for the 9-step contract." >&2 ; \
	  exit 2 ; \
	fi
	@if [ -z "$(SOURCE)" ]; then \
	  echo "[new-engagement] error: SOURCE required" >&2 ; \
	  echo "  Usage: make new-engagement NAME=<slug> SOURCE=<url>" >&2 ; \
	  echo "  See docs/ENGAGEMENT_3_KICKOFF.md §2 for the 9-step contract." >&2 ; \
	  exit 2 ; \
	fi
	@ws="$(HOME)/audits/$(NAME)" ; \
	if [ -e "$$ws" ]; then \
	  echo "[new-engagement] already-exists $(NAME) - $$ws exists; no-op (idempotent)" ; \
	  exit 0 ; \
	fi ; \
	bash tools/setup-workspace.sh "$(NAME)" "$(HOME)/audits" >/dev/null ; \
	mkdir -p "$$ws/submissions/staging" ; \
	mkdir -p "$$ws/submissions/ready" ; \
	mkdir -p "$$ws/submissions/packaged" ; \
	mkdir -p "$$ws/evidence/fork-replay" ; \
	mkdir -p "$$ws/evidence/pocs" ; \
	mkdir -p "$$ws/reference" ; \
	mkdir -p "$$ws/engage_candidates" ; \
	: > "$$ws/reference/outcomes.jsonl" ; \
	printf '{"bounty_url": "%s", "slug": "%s"}\n' "$(SOURCE)" "$(NAME)" > "$$ws/scope.json" ; \
	printf '\n<!-- provenance: SOURCE=%s (captured by make new-engagement) -->\n' "$(SOURCE)" >> "$$ws/SCOPE.md" ; \
	if [ ! -f "$$ws/submissions/SUBMISSIONS.md" ]; then \
	  printf '# Submissions - %s\n\nEmpty tracker. Drafts land here as they are packaged.\n' "$(NAME)" > "$$ws/submissions/SUBMISSIONS.md" ; \
	fi ; \
	echo "[new-engagement] created $(NAME) at $$ws" ; \
	echo "" ; \
	echo "Next steps:" ; \
	echo "  1. Edit $$ws/SCOPE.md and paste in the bounty scope." ; \
	echo "  2. Edit $$ws/SEVERITY.md and paste in the bounty severity rubric." ; \
	echo "  3. Run: make audit-prep WS=$$ws" ; \
	echo "     (scaffolds RUBRIC_COVERAGE.md, ASSET_PLAN_*.md, OOS_CHECKLIST.md)" ; \
	echo "  4. Open each ASSET_PLAN_*.md and fill in strategy + roots, then set 'Plan status: ready'." ; \
	echo "  5. Run: make audit WS=$$ws"

make-new-engagement-test:
	@python3 -m unittest tools.tests.test_make_new_engagement

# audit-prep - idempotent scaffold step between "edit SCOPE/SEVERITY" and "make audit".
#
# Derives RUBRIC_COVERAGE.md (from SEVERITY.md), scaffolds ASSET_PLAN_*.md (from
# SCOPE.md asset classes), and derives OOS_CHECKLIST.md / SEVERITY_CAPS.md (from
# SCOPE.md). None of these need operator input beyond the two source files being
# populated. All three tools are idempotent (skip existing files unless --force).
#
# Canonical flow for a brand-new workspace:
#   1. make new-engagement NAME=<slug> SOURCE=<url>
#   2. Edit SCOPE.md + SEVERITY.md (paste bounty content)
#   3. make audit-prep WS=<ws>
#   4. Open each ASSET_PLAN_*.md; fill strategy + roots; set "Plan status: ready"
#   5. make audit WS=<ws>
#
# Usage:
#   make audit-prep WS=~/audits/<project>
## attest-mechanical: auto-record README attestation rows for every EXECUTED
## mechanical step (artifact-on-disk = proof it ran). Closes the Theme-C
## done-blocker: the per-step attestation gate fail-closes audit-done-guard, but
## --attest was manual-only, so autonomously-run workspaces sat at
## fail-readme-attestation-missing forever. Manual-judgment steps (SCOPE/SEVERITY/
## clone/toolchain/2c-fuzz/4b-econ) are NOT auto-attested - they still need an
## explicit agent read. Run each tick (and the loop prompt calls it).
.PHONY: attest-mechanical
attest-mechanical:
	@if [ -z "$(WS)" ]; then echo "Usage: make attest-mechanical WS=<workspace>"; exit 2; fi
	@python3 tools/readme-attestation-check.py --attest-executed-mechanical --ws "$(_WS_RESOLVED)"

audit-prep:
	@if [ -z "$(WS)" ]; then \
	  echo "Usage: make audit-prep WS=<workspace>"; exit 2; \
	fi
	@ws="$(_WS_RESOLVED)" ; \
	if [ ! -d "$$ws" ]; then \
	  echo "[audit-prep] ERR workspace not found: $$ws"; exit 2; \
	fi ; \
	echo "[audit-prep] running scaffold tools for $$ws ..." ; \
	echo "" ; \
	echo "--- init-rubric-coverage.sh ---" ; \
	bash tools/init-rubric-coverage.sh "$$ws" || true ; \
	echo "" ; \
	echo "--- init-asset-plan.sh ---" ; \
	bash tools/init-asset-plan.sh "$$ws" || true ; \
	echo "" ; \
	echo "--- extract-oos.sh ---" ; \
	bash tools/extract-oos.sh "$$ws" || true ; \
	echo "" ; \
	echo "--- program-intake-check (are the program's PoC rules + known-issue fix-status ingested? see docs/PROGRAM_INTAKE.md) ---" ; \
	python3 tools/program-intake-check.py --workspace "$$ws" \
	  || echo "[audit-prep] program-intake INCOMPLETE (advisory): author .auditooor/program_rules.json + prior_audits/known_issues.jsonl per docs/PROGRAM_INTAKE.md" ; \
	echo "" ; \
	echo "--- retract-invalid-candidates (DEFAULT: move stale-poc paste-ready findings to _killed/) ---" ; \
	python3 tools/retract-invalid-candidates.py --workspace "$$ws" --apply \
	  || echo "[audit-prep] WARN retract-invalid-candidates non-zero (advisory)" ; \
	echo "" ; \
	echo "--- program-impact-mapping-check --check-methodology-drift (G9 gate; was orphaned) ---" ; \
	python3 tools/program-impact-mapping-check.py --check-methodology-drift \
	  || echo "[audit-prep] WARN methodology-mapping drift (advisory): a corpus impact_id is absent from the IMPACT_METHODOLOGY_TO_CHECK31 map (or corpus absent). Re-run: python3 tools/program-impact-mapping-check.py --check-methodology-drift" ; \
	echo "" ; \
	echo "[audit-prep] done." ; \
	echo "" ; \
	echo "If ASSET_PLAN_*.md files were created, open each one and:" ; \
	echo "  - Replace 'TBD' strategy + roots with concrete values" ; \
	echo "  - Change 'Plan status: missing' to 'Plan status: ready'" ; \
	echo "Then run: make audit WS=$$ws"

## Move INVALID paste-ready findings (stale-poc: PoC imports a source file removed at the
## current pin) out to submissions/_killed/ so they cannot be filed and cannot block a
## co-located valid finding's pre-submit poc-freshness gate. Runs by DEFAULT in audit-prep.
## Dry-run: make retract-invalid WS=<ws> ; apply: make retract-invalid WS=<ws> APPLY=1
retract-invalid:
	@if [ -z "$(WS)" ]; then echo "Usage: make retract-invalid WS=<workspace> [APPLY=1]"; exit 2; fi
	@ws="$(_WS_RESOLVED)" ; \
	if [ "$(APPLY)" = "1" ]; then \
	  python3 tools/retract-invalid-candidates.py --workspace "$$ws" --apply ; \
	else \
	  python3 tools/retract-invalid-candidates.py --workspace "$$ws" ; \
	fi

reports:
	./tools/clone-hexens-reports.sh

extract:
	@if [ -z "$(DIR)" ]; then echo "Usage: make extract DIR=<pdf-dir>"; exit 1; fi
	./tools/extract-pdfs.sh $(DIR)

originality:
	@if [ -z "$(KW)" ]; then echo "Usage: make originality KW=<keyword>"; exit 1; fi
	./tools/originality-grep.sh $(KW)

scan:
	@if [ -z "$(WORKSPACE)" ]; then echo "Usage: make scan WORKSPACE=<path> [MODE=discovery|maintenance] [OUT=<dir>]"; exit 1; fi
	@python3 tools/workspace-scan-orchestrator.py --workspace $(WORKSPACE) \
		$(if $(MODE),--mode $(MODE),) \
		$(if $(OUT),--out $(OUT),)

# Wave O-B - canonical single-detector runner (Gap #2 closure).
# Usage:
#   make detect WS=~/audits/base-azul DETECTOR=rust-discarded-verify-bool-scan
#   make detect WS=~/audits/base-azul DETECTOR=rust-discarded-verify-bool-scan OUTPUT=/tmp/out.json
# Available detector IDs: python3 tools/run-detector.py --list-detectors
detect:
	@if [ -z "$(WS)" ]; then echo "usage: make detect WS=<workspace> DETECTOR=<id> [OUTPUT=<json>]"; exit 2; fi
	@if [ -z "$(DETECTOR)" ]; then echo "usage: make detect WS=<workspace> DETECTOR=<id> [OUTPUT=<json>]"; exit 2; fi
	@python3 tools/run-detector.py \
		--workspace "$(_WS_RESOLVED)" \
		--detector "$(DETECTOR)" \
		$(if $(OUTPUT),--output "$(OUTPUT)")

detect-test:
	@python3 -m unittest tools.tests.test_run_detector -v

rust-fixture-detector:
	@if [ -z "$(DETECTOR)" ]; then echo "usage: make rust-fixture-detector DETECTOR=<id>"; exit 2; fi
	@set -eu; \
	HERE="detectors/rust_wave1/test_fixtures"; \
	POS="$$HERE/$(DETECTOR)_positive.rs"; \
	NEG="$$HERE/$(DETECTOR)_negative.rs"; \
	if [ ! -f "$$POS" ]; then echo "[rust-fixture-detector] missing fixture: $$POS"; exit 1; fi; \
	if [ ! -f "$$NEG" ]; then echo "[rust-fixture-detector] missing fixture: $$NEG"; exit 1; fi; \
	TMPLOG="$$(mktemp -t rust-fixture-detector.XXXXXX.log)"; \
	trap 'rm -f "$$TMPLOG"' EXIT; \
	count_hits() { \
	  awk -v det="$$1" '$$1 == "===" && $$2 == det { gsub(/[()]/, "", $$3); print $$3; found=1; exit } END { if (!found) print 0 }' "$$2"; \
	}; \
	run_mode() { \
	  mode="$$1"; \
	  fixture="$$2"; \
	  python3 tools/rust-detect.py "$$HERE" --only "$(DETECTOR)" --file "$$fixture" --log "$$TMPLOG" >/dev/null 2>&1; \
	  hits="$$(count_hits "$(DETECTOR)" "$$TMPLOG")"; \
	  hits="$${hits:-0}"; \
	  if [ "$$mode" = "positive" ]; then \
	    if [ "$$hits" -ge 1 ]; then \
	      echo "PASS  $(DETECTOR) positive ($$hits hits)"; \
	    else \
	      echo "FAIL  $(DETECTOR) positive (expected >=1, got 0)"; \
	      exit 1; \
	    fi; \
	  else \
	    if [ "$$hits" -eq 0 ]; then \
	      echo "PASS  $(DETECTOR) negative (0 hits)"; \
	    else \
	      echo "FAIL  $(DETECTOR) negative (expected 0, got $$hits)"; \
	      exit 1; \
	    fi; \
	  fi; \
	}; \
	run_mode positive "$$POS"; \
	run_mode negative "$$NEG"

precision-detector:
	@if [ -z "$(DETECTOR)" ]; then echo "usage: make precision-detector DETECTOR=<id> [FIXTURES=<n>] [JSON_OUT=<path>] [MD_OUT=<path>] [WORKERS=<n>] [TIMEOUT=<sec>] [SEED=<n>] [NO_SPOT_CHECK=1]"; exit 2; fi
	@AUDITOOOR_FIXTURE_SMOKE_MODE=1 python3 tools/detector-precision-matrix.py \
		--detector "$(DETECTOR)" \
		$(if $(FIXTURES),--sample-fixtures "$(FIXTURES)") \
		$(if $(JSON_OUT),--json-out "$(JSON_OUT)") \
		$(if $(MD_OUT),--md-out "$(MD_OUT)") \
		$(if $(WORKERS),--workers "$(WORKERS)") \
		$(if $(TIMEOUT),--timeout "$(TIMEOUT)") \
		$(if $(SEED),--seed "$(SEED)") \
		$(if $(NO_SPOT_CHECK),--no-spot-check)

hypothesis:
	@if [ -z "$(HYPOTHESIS)" ] || [ -z "$(CLASS)" ]; then \
	  echo 'Usage: make hypothesis HYPOTHESIS="<prose>" CLASS="<kebab-name>"'; exit 1; fi
	@python3 tools/hypothesis-to-detector.py \
	  --hypothesis "$(HYPOTHESIS)" --class "$(CLASS)"

correlator-validate:
	@bash tools/correlator-validate.sh || echo "[correlator-validate] some cases fail - see docs/CORRELATOR_VALIDATION.md"

correlator-test:
	@python3 tools/tests/test_exploit_chain_correlator.py

exploit-regression:
	@python3 tools/exploit-anchor-regression.py

# Phase 38: detector-hit → historical exploit-anchor ranker (reverse direction).
# Use case: during `make engage`, surface "this looks like Euler/Cream/Curve
# because <shared tokens>" for each detector hit. Optional CODE=<file> enriches
# the query with a code snippet. See docs/REVERSE_CORRELATOR.md.
reverse-correlate:
	@if [ -z "$(DETECTOR)" ]; then \
	  echo 'Usage: make reverse-correlate DETECTOR=<detector-slug> [CODE=<file>] [TOP=5]'; exit 1; fi
	@python3 tools/reverse-correlator.py \
	  --detector "$(DETECTOR)" \
	  $(if $(CODE),--code "$(CODE)") \
	  --top $${TOP:-5}

narrate:
	@if [ -z "$(EXPLOIT)" ]; then \
	  echo 'Usage: make narrate EXPLOIT=<url-or-file> [FORMAT=markdown|slack|screen]'; exit 1; fi
	@python3 tools/attack-chain-narrator.py \
	  --exploit "$(EXPLOIT)" --format "$${FORMAT:-markdown}"

# Phase 38: UNIFIED ENGAGEMENT - single entrypoint that runs the whole pipeline
# (flow-gate → orchestrator → per-hit dupe-risk + reverse-correlator +
# cross-workspace-lookup → analogical clustering → engage_report.md).
# See docs/ENGAGE.md for usage and example output.
engage:
	@if [ -z "$(WORKSPACE)" ]; then \
	  echo 'Usage: make engage WORKSPACE=<path> [SKIP_FLOW_GATE=1] [ONLY_DETECTOR=<name>] [OUT=<dir>] [QUIET=1] [ENGAGE_EXTRA_ARGS=...]'; exit 1; fi
	@python3 tools/engage.py --workspace "$(WORKSPACE)" \
	  $(if $(SKIP_FLOW_GATE),--skip-flow-gate) \
	  $(if $(ONLY_DETECTOR),--only-detector "$(ONLY_DETECTOR)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(QUIET),--quiet) \
	  $(ENGAGE_EXTRA_ARGS)
	@# Wave-2 #17: make this workspace queryable as hacker corpus (target_repo=<slug>).
	@# Non-fatal (-@): the ingest returns ok:false gracefully on workspaces with no
	@# surface yet, so engage stays green regardless.
	-@$(MAKE) hackerman-target-ingest WS="$(WORKSPACE)"

submission-sync:
	@if [ -z "$(WORKSPACE)" ]; then echo "Usage: make submission-sync WORKSPACE=<path>"; exit 1; fi
	@bash tools/submission-sync.sh "$(WORKSPACE)"

# Phase 36: render nested submissions/SUBMISSIONS.md into triager-clean
# markdown files under <WORKSPACE>/submissions/clean/. Root-level manual
# ledgers are intentionally unsupported here. Skips Draft 9 by default
# (pass SKIP_DRAFT=N to override). Also lints the rendered output (25/25).
clean-submissions:
	@if [ -z "$(WORKSPACE)" ]; then echo "Usage: make clean-submissions WORKSPACE=<path> [SKIP_DRAFT=N]"; exit 1; fi
	@python3 tools/submission-render.py $(WORKSPACE) \
	  $(if $(SKIP_DRAFT),--skip-draft $(SKIP_DRAFT))
	@python3 tools/submissions-lint.py $(WORKSPACE) --triager-clean --clean-glob --strict

# Phase 39 tail: render the parallel engage_candidates/*.md drafts into
# submissions/engage_candidates/clean/<slug>.md (same render_draft + Cantina form-fields
# block as clean-submissions). Graceful when engage_candidates/ doesn't exist.
# Lint then covers BOTH clean/ and submissions/engage_candidates/clean/ in one pass.
clean-engage-candidates:
	@if [ -z "$(WORKSPACE)" ]; then echo "Usage: make clean-engage-candidates WORKSPACE=<path>"; exit 1; fi
	@python3 tools/submission-render.py $(WORKSPACE) --engage-candidates
	@python3 tools/submissions-lint.py $(WORKSPACE) --triager-clean --clean-glob --strict

# ─── Phase 42: PoC verification gate ─────────────────────────────────────────
# Usage:
#   make verify-pocs WORKSPACE=~/audits/<project>
#   make verify-pocs WORKSPACE=~/audits/<project> DRAFT=3
#   make verify-pocs WORKSPACE=~/audits/<project> STRICT=1
verify-pocs:
	@if [ -z "$(WORKSPACE)" ]; then echo "usage: make verify-pocs WORKSPACE=<path> [DRAFT=N] [STRICT=1]" >&2; exit 2; fi
	@bash tools/verify-pocs.sh "$(WORKSPACE)" \
	  $(if $(DRAFT),--draft $(DRAFT)) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(STRICT),--strict)

# ─── Phase 51b: Solodit corpus miner ─────────────────────────────────────────
# Mines the 19k+ Solodit findings corpus (detectors/_specs/solodit_raw/ +
# detectors/_specs/drafts_audit_text/) for GitHub commit/PR URLs, clones
# repos, extracts diffs, and auto-splits vuln/clean fixture pairs into
# patterns/fixtures/auto/. Resumable via LEDGER at reference/diff_scrape_ledger.json.
#
# Usage:
#   make scrape-diffs-v2           # mine 100 candidates
#   make scrape-diffs-v2 LIMIT=500 # mine 500 candidates
#   make scrape-diffs-v2 DRY_RUN=1 # preview without cloning
#   python3 tools/scrape-diffs-v2.py --status  # check ledger / on-disk counts
scrape-diffs-v2:
	@python3 tools/scrape-diffs-v2.py \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(LIMIT),--limit $(LIMIT),--limit 100)

clean:
	@echo "Nothing to clean - auditooor has no build artifacts"




# ─── Integrated from parallel agent branches ─────────────────────────────

# From claudeboy-pr212
ci-preflight:
	@bash tools/ci-preflight.sh

# From claudeboy-pr212
ci-preflight-test:
	@python3 tools/tests/test_ci_preflight.py

# From claudeboy-manual-submission-ledger
record-submission:
	@python3 tools/track-submissions.py record "$(WS)" \
	  --platform "$(PLATFORM)" \
	  --report-url "$(URL)" \
	  --report-id "$(ID)" \
	  $(if $(TITLE),--title "$(TITLE)") \
	  $(if $(SEVERITY),--severity "$(SEVERITY)")

record-pending-filed-without-platform-id:
	@python3 tools/track-submissions.py record-pending-filed-without-platform-id "$(WS)" \
	  --local-id "$(LOCAL_ID)" \
	  $(if $(PLATFORM),--platform "$(PLATFORM)") \
	  $(if $(TITLE),--title "$(TITLE)") \
	  $(if $(SEVERITY),--severity "$(SEVERITY)") \
	  $(if $(SOURCE_PATH),--source-path "$(SOURCE_PATH)") \
	  $(if $(OPERATOR_NOTE),--operator-note "$(OPERATOR_NOTE)")

# From claudeboy-manual-submission-ledger
# iter6-T2: after a successful transition, auto-emit `list --outcome $(STATE)`
# so the operator immediately sees the row in its new terminal state. The bare
# `list` default stays `--outcome pending` (= "what's still outstanding"); this
# follow-up list is the targeted confirmation. If the transition call above
# exits non-zero, make halts before printing the confirmation - no misleading
# "transition complete" banner ever appears on failure.
record-outcome:
	@python3 tools/track-submissions.py record-outcome "$(WS)" \
	  --report-id "$(ID)" \
	  --state "$(STATE)" $(if $(NEW_RULE_CODIFIED),--new-rule-codified)
	@echo ""
	@echo "[record-outcome] Confirming transition - rows now in state '$(STATE)':"
	@python3 tools/track-submissions.py list --workspace "$(WS)" --outcome "$(STATE)"

# Learning-loop outcome closeout: same append-only writer as record-outcome,
# but named for post-triage update steps and accepts FINDING/VERDICT aliases.
.PHONY: update-outcome
update-outcome:
	@if [ -z "$(WS)" ] || [ -z "$(or $(FINDING),$(ID))" ] || [ -z "$(or $(VERDICT),$(STATE))" ]; then \
	  echo 'Usage: make update-outcome WS=<workspace> FINDING=<report-id> VERDICT=<state> [NEW_RULE_CODIFIED=1]'; exit 2; \
	fi
	@python3 tools/track-submissions.py record-outcome "$(WS)" \
	  --report-id "$(or $(FINDING),$(ID))" \
	  --state "$(or $(VERDICT),$(STATE))" $(if $(NEW_RULE_CODIFIED),--new-rule-codified)
	@echo ""
	@echo "[update-outcome] Confirming transition - rows now in state '$(or $(VERDICT),$(STATE))':"
	@python3 tools/track-submissions.py list --workspace "$(WS)" --outcome "$(or $(VERDICT),$(STATE))"

# From claudeboy-manual-submission-ledger
list-submissions:
	@python3 tools/track-submissions.py list --workspace "$(WS)" \
	  $(if $(OUTCOME),--outcome "$(OUTCOME)")

# P0-4 burn-down: audit reference/outcomes.jsonl for missing scoreboard
# linkage. Pass STRICT=1 to flip the exit code from advisory (0) to
# fail-closed (1) when any row is incomplete.
validate-outcome-ledger:
	@python3 tools/track-submissions.py validate-ledger "$(WS)" \
	  $(if $(JSON),--json) \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(STRICT),--strict-linkage)

# From claudeboy-manual-submission-ledger
track-submissions-test:
	@python3 tools/tests/test_track_submissions.py

# From claudeboy-pr208
# I-01: tilde-expand $(WS) before the directory check. Make does NOT
# tilde-expand variable values, so `make audit WS=~/audits/foo` would fail
# the `[ -d "$(WS)" ]` test even when ~/audits/foo exists. We do the
# expansion in make (not the shell) so the resolved path is available to
# every shell line in the recipe.
# Q-01: `mkdir -p` the .audit_logs/ directory so any downstream redirect
# (operator-driven `tee` etc.) doesn't fail silently on a fresh workspace.
#
# Tilde shape table (post-fix):
#   WS=~/foo     -> $(HOME)/foo                (the canonical case)
#   WS=~         -> $(HOME)                    (bare tilde)
#   WS=~user/foo -> ~user/foo  (LEFT AS-IS)    make has no getpwnam; the
#                                              downstream `[ -d ]` reports the
#                                              unresolvable path verbatim
#                                              instead of silently producing a
#                                              malformed `$(HOME)user/foo`.
#   WS=relative  -> relative                   (untouched)
#   WS=/abs/path -> /abs/path                  (untouched)
#
# Earlier shape used `filter ~%,...` which matched `~user/foo` too and then
# emitted `$(HOME)user/foo` (no slash) - Minimax flagged this in the PR #163
# review. Two-arm filter below restricts expansion to `~/...` and bare `~`.
_WS_RESOLVED = $(strip \
  $(if $(filter ~,$(WS)),$(HOME),\
  $(if $(filter ~/%,$(WS)),$(HOME)/$(patsubst ~/%,%,$(WS)),\
  $(WS))))

audit-fast:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-fast WS=<workspace> [TOP_N=50] [TRIAGER_PRECHECK_BUDGET=10] [STRICT=1] [JSON=1]'; \
	  echo 'Writes <ws>/docs/LIVE_TARGET_REPORT.{md,json} and <ws>/.auditooor/adversarial_hypothesis_top5.json'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make audit-fast" "$(_WS_RESOLVED)"
	@python3 tools/bug-bounty-oos-ingester.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --quiet
	@python3 tools/live-target-intelligence-report.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --output "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md" \
	  --output-json "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json" \
	  --top-n "$(if $(TOP_N),$(TOP_N),50)" \
	  --triager-precheck-budget "$(if $(TRIAGER_PRECHECK_BUDGET),$(TRIAGER_PRECHECK_BUDGET),10)" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json)
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@spg_rc=0 ; \
	  python3 tools/semantic-predicate-gate.py \
	    --input "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json" \
	    --workspace "$(_WS_RESOLVED)" \
	    --output "$(_WS_RESOLVED)/.auditooor/semantic_predicate_gate.json" \
	    --apply-to-report "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json" \
	    --report-markdown-output "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md" \
	    --max-calls "$(if $(SEMANTIC_GATE_MAX_CALLS),$(SEMANTIC_GATE_MAX_CALLS),50)" \
	    --max-report-cost-usd "$(if $(SEMANTIC_GATE_MAX_REPORT_COST_USD),$(SEMANTIC_GATE_MAX_REPORT_COST_USD),1.00)" \
	    $(if $(SEMANTIC_GATE_LIVE),--operator-live-network-consent,--dry-run) || spg_rc=$$? ; \
	  if [ $$spg_rc -ne 0 ]; then \
	    echo "[make audit-fast] WARN semantic-predicate-gate failed rc=$$spg_rc; continuing (semantic gate advisory)" >&2 ; \
	    if [ "$(STRICT)" = "1" ]; then exit $$spg_rc; fi ; \
	  fi
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@src_files="$$(find "$(_WS_RESOLVED)" -type f -name '*.sol' \
	    ! -path '*/node_modules/*' ! -path '*/lib/*' ! -path '*/cache/*' \
	    | sort | head -n 5)" ; \
	  if [ -n "$$src_files" ]; then \
	    python3 tools/adversarial-hypothesis-differential-hunter.py \
	      --out "$(_WS_RESOLVED)/.auditooor/adversarial_hypothesis_top5.json" \
	      --pretty --max-functions 5 $$src_files || ahdh_rc=$$? ; \
	  else \
	    python3 tools/adversarial-hypothesis-differential-hunter.py \
	      --out "$(_WS_RESOLVED)/.auditooor/adversarial_hypothesis_top5.json" \
	      --pretty --max-functions 5 || ahdh_rc=$$? ; \
	  fi ; \
	  if [ "$${ahdh_rc:-0}" -ne 0 ]; then \
	    echo "[make audit-fast] WARN AHDH top-5 sidecar failed rc=$$ahdh_rc; continuing (AHDH advisory)" >&2 ; \
	    if [ "$(STRICT)" = "1" ]; then exit $$ahdh_rc; fi ; \
	  fi
	@dns_rc=0 ; \
	  python3 tools/defender-narrative-simulator.py "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json" --pretty > "$(_WS_RESOLVED)/.auditooor/dns_advisory.json" || dns_rc=$$? ; \
	  if [ $$dns_rc -ne 0 ]; then \
	    echo "[make audit-fast] WARN defender-narrative-simulator failed rc=$$dns_rc; continuing (DNS advisory)" >&2 ; \
	    if [ "$(STRICT)" = "1" ]; then exit $$dns_rc; fi ; \
	  fi
	@pforpd_rc=0 ; \
	  python3 tools/post-filing-outcome-replay-pattern-distiller.py \
	    --out-json "$(_WS_RESOLVED)/.auditooor/pforpd_replay_patterns.json" || pforpd_rc=$$? ; \
	  if [ $$pforpd_rc -ne 0 ]; then \
	    echo "[make audit-fast] WARN post-filing-outcome-replay-pattern-distiller failed rc=$$pforpd_rc; continuing (PFORPD advisory)" >&2 ; \
	    if [ "$(STRICT)" = "1" ]; then exit $$pforpd_rc; fi ; \
	  fi
#
# V5-P0-05 / Gap 45 - silent-rerun guard.
# The recipe consults `tools/audit-completion-marker.py check` before
# executing the 32-stage chain. If the previous run completed within the
# freshness window (default 30 min, tunable via AUDIT_FRESHNESS_SECONDS)
# AND the workspace inventory + scope/config hashes are unchanged AND
# the audit toolchain fingerprint has not moved, the recipe short-circuits.
# Step-1c is a required native inter-procedural def-use slice. It writes
# <ws>/.auditooor/dataflow_paths.jsonl and fails on any router or timeout error.
# B-router:
# now calls tools/dataflow.py, the cross-language ROUTER that auto-detects every
# present language arm (solidity/rust/go/zk) - reusing make audit's own language
# detector - dispatches each, and language-scoped-MERGES them into ONE unified
# dataflow_paths.jsonl (no arm truncates another). --mode both = value-flow +
# storage-mediated def-use (solidity arm). Compile or engine failure is terminal.
# Language applicability is decided by the manifest before this target runs. If
# the router is absent (older tree) it falls back to the Solidity-only arm.
dataflow-slice:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make dataflow-slice WS=<workspace> [MODE=both|value-flow|storage]'; exit 2; fi
	# The OUTER wrapper timeout MUST exceed go-dataflow.py's INTERNAL run ceiling
	# (AUDITOOOR_GO_DATAFLOW_RUN_TIMEOUT default 3600s) plus headroom for the router's
	# Solidity/Rust arms. axelar-dlt 2026-07-13: the prior 1800s wrapper KILLED a heavy
	# cosmos-monorepo LoadAllSyntax+SSA slice at 30min - BEFORE the tool's own 3600s
	# budget - silently truncating to 0 paths -> fail-dataflow-substrate-starved. Kept in
	# sync by tools/tests/test_dataflow_timeout_wrapper_exceeds_tool.py.
	@set -eu; _df_to="$${AUDITOOOR_DATAFLOW_TIMEOUT:-4200}"; \
	test -f tools/dataflow.py || { echo "[dataflow-slice] ERROR: required cross-language router tools/dataflow.py is missing" >&2; exit 1; }; \
	timeout $$_df_to python3 tools/dataflow.py --workspace "$(_WS_RESOLVED)" --mode $(if $(MODE),$(MODE),both) --strict

# with a clear note and exits 0. `FORCE=1` always bypasses the guard.
# `DRY_RUN=1` ALSO bypasses (the operator wants to see the planned chain
# regardless of marker state). On a successful real run we write a fresh
# marker AFTER audit-progress.py exits 0.
audit:
	@python3 tools/audit-dispatch.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict,) $(if $(FORCE),--force,) $(if $(DRY_RUN),--dry-run,)

_audit-baseline:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit WS=<workspace> [DRY_RUN=1] [FORCE=1] [OUT=<dir>] [ENGAGE_EXTRA_ARGS=...] [REQUIRE_MEMORY_CONTEXT=1] [STRICT_MEMORY_CONTEXT=1] [MAX_FUNCTIONS=N]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit" "$(_WS_RESOLVED)"
	@if [ "$(AUDIT_NO_CONCURRENCY_GUARD)" != "1" ] && [ -f tools/audit-run-guard.sh ]; then \
	  bash tools/audit-run-guard.sh "$(_WS_RESOLVED)" audit_run; _g=$$?; \
	  if [ "$$_g" = "3" ]; then echo "[make audit] another audit run is active for this workspace; skipping (set AUDIT_NO_CONCURRENCY_GUARD=1 to force)"; exit 0; fi; \
	fi
	@mkdir -p "$(_WS_RESOLVED)/.audit_logs"
	@_acd_out="audit/corpus_tags/derived/attack_class_distribution.json"; \
	_acd_src="audit/corpus_tags/index/by_attack_class.jsonl"; \
	if [ -z "$(FORCE)" ] && [ -f "$$_acd_out" ] && [ -f "$$_acd_src" ] && [ "$$_acd_out" -nt "$$_acd_src" ]; then \
	  echo "[make audit] attack_class_distribution fresh (newer than corpus index); skip refresh" >&2 ; \
	else \
	  _acd_to=""; command -v timeout >/dev/null 2>&1 && _acd_to="timeout $${AUDITOOOR_CORPUS_REFRESH_TIMEOUT_S:-600}"; \
	  $$_acd_to python3 tools/hackerman-attack-class-distribution.py --mode full --json \
	    --out-json "$$_acd_out" >/dev/null 2>&1 \
	    || echo "[make audit] WARN attack_class_distribution refresh skipped/failed (advisory; R39 orphan gate degrades)" >&2 ; \
	fi
	@if [ "$(STRICT)" = "1" ]; then \
	  echo "[make audit] STRICT=1: refreshing prior-disclosure index before freshness guard" >&2 ; \
	  prior_rc=0 ; \
	  $(MAKE) --no-print-directory prior-disclosure-index WS="$(_WS_RESOLVED)" >/dev/null || prior_rc=$$? ; \
	  if [ $$prior_rc -ne 0 ]; then \
	    echo "[make audit] STRICT=1: prior-disclosure-index failed rc=$$prior_rc before audit work" >&2 ; \
	    exit $$prior_rc ; \
	  fi ; \
	  echo "[make audit] STRICT=1: checking operator-truth intake before freshness guard" >&2 ; \
	  intake_rc=0 ; \
	  python3 tools/intake-baseline.py "$(_WS_RESOLVED)" \
	    --strict-operator-truth \
	    --out-json "$(_WS_RESOLVED)/INTAKE_BASELINE.json" \
	    --out-md "$(_WS_RESOLVED)/INTAKE_BASELINE.md" >/dev/null || intake_rc=$$? ; \
	  if [ $$intake_rc -ne 0 ]; then \
	    echo "[make audit] STRICT=1: operator-truth intake failed before audit work; see $(_WS_RESOLVED)/INTAKE_BASELINE.md" >&2 ; \
	    exit $$intake_rc ; \
	  fi ; \
	fi
	@if [ -z "$(DRY_RUN)" ] && [ -z "$(AUDIT_COMMIT_MINING_SKIP)" ]; then \
	  cm_rc=0 ; \
	  $(MAKE) --no-print-directory audit-target-commit-mining WS="$(_WS_RESOLVED)" $(if $(FORCE),FORCE=1) $(if $(COMMIT_MINING_WINDOW),COMMIT_MINING_WINDOW="$(COMMIT_MINING_WINDOW)") || cm_rc=$$? ; \
	  if [ $$cm_rc -ne 0 ]; then \
	    echo "[make audit] WARN audit-target-commit-mining failed rc=$$cm_rc before audit work" >&2 ; \
	    if [ ! -s "$(_WS_RESOLVED)/targets.tsv" ]; then \
	      echo "[make audit] ERR audit-target-commit-mining prerequisite failed: targets.tsv missing/empty; populate it before audit" >&2 ; \
	      exit 2 ; \
	    fi ; \
	    echo "[make audit] NOTE targets.tsv is present so cm_rc=$$cm_rc is a per-target mining failure (advisory), NOT the targets.tsv-missing prerequisite. make audit is Step 1/5 ORIENT - the Step-2 engines + Step-5 closeout run AFTER it, so per-target commit-mining failures (e.g. a repo whose --since could not be derived) must NOT block the engines. Per-target status is in the commit_mining_manifest.json summary. Continuing so the engines can run." >&2 ; \
	  fi ; \
	fi
	@if [ "$(STRICT)" = "1" ]; then \
	  $(MAKE) --no-print-directory prior-history-prehunt-gate WS="$(_WS_RESOLVED)" STRICT=1 || { \
    _history_rc=$$?; echo "[make audit] STRICT=1: prior-history-prehunt-gate failed before candidate-producing audit work" >&2; exit $$_history_rc; }; \
	fi
	@# V5-P0-05 freshness guard + audit chain run + marker write are
	@# all in ONE recipe shell so an early `exit 0` from the guard
	@# actually short-circuits subsequent commands. (Each `@` line in
	@# make is a fresh shell - splitting these would let the chain
	@# silently re-run after a "short-circuit" message.)
	@# Minimax pre-review M3: `FORCE=` (empty string) is treated as
	@# "not set" by the Makefile-level `[ -z ]` test, AND by the
	@# audit-completion-marker.py FORCE-env check (only "1"/"true"/etc
	@# trigger force). Aligning both to the empty-string rule keeps
	@# operator behavior consistent across the two guard layers.
	@# Kimi pre-review K6: the freshness check is invoked exactly once
	@# (we capture stdout into a variable), so a hard error in the
	@# checker can't be masked by `|| true` on a second invocation.
	@if [ -z "$(DRY_RUN)" ] && [ -z "$(FORCE)" ] ; then \
	  marker_out=$$(python3 tools/audit-completion-marker.py check \
	    --workspace "$(_WS_RESOLVED)" 2>&1) ; \
	  marker_rc=$$? ; \
	  if [ $$marker_rc -eq 0 ] ; then \
	    printf '%s\n' "$$marker_out" ; \
	    mem_rc=0 ; \
	    python3 tools/memory-auto-link.py --workspace "$(_WS_RESOLVED)" --write >/dev/null 2>&1 || mem_rc=$$? ; \
	    if [ $$mem_rc -ne 0 ]; then \
	      echo "[make audit] WARN failed to refresh memory requirements during freshness short-circuit" >&2 ; \
	      if [ "$${REQUIRE_MEMORY_CONTEXT:-0}" = "1" ] || [ "$${STRICT_MEMORY_CONTEXT:-0}" = "1" ]; then exit $$mem_rc; fi ; \
	    fi ; \
	    mem_rc=0 ; \
	    python3 tools/memory-context-load.py --workspace "$(_WS_RESOLVED)" --from-requirements --write-receipt >/dev/null 2>&1 || mem_rc=$$? ; \
	    if [ $$mem_rc -ne 0 ]; then \
	      echo "[make audit] WARN failed to refresh memory context receipt during freshness short-circuit" >&2 ; \
	      if [ "$${REQUIRE_MEMORY_CONTEXT:-0}" = "1" ] || [ "$${STRICT_MEMORY_CONTEXT:-0}" = "1" ]; then exit $$mem_rc; fi ; \
	    fi ; \
	    bp_rc=0 ; \
	    if [ "$(BRAIN_PRIME_SKIP)" = "1" ]; then \
	      echo "[make audit] BRAIN_PRIME_SKIP=1 - skipping brain-prime during freshness short-circuit (advisory)" ; \
	    else \
	      $(if $(BRAIN_PRIME_TIMEOUT),timeout $(BRAIN_PRIME_TIMEOUT) )$(MAKE) --no-print-directory brain-prime WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT=1) || bp_rc=$$? ; \
	      if [ $$bp_rc -ne 0 ]; then \
	        echo "[make audit] WARN brain-prime failed/timed-out rc=$$bp_rc during freshness short-circuit; continuing (hacker context advisory)" >&2 ; \
	        if [ "$(STRICT)" = "1" ]; then \
	          echo "[make audit] NOTE brain-prime is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	          : ; \
	        fi ; \
	      fi ; \
	    fi ; \
		    cs_rc=0 ; \
		    $(MAKE) --no-print-directory cross-seed WS="$(_WS_RESOLVED)" $(if $(CROSS_SEED_LIMIT),LIMIT="$(CROSS_SEED_LIMIT)") || cs_rc=$$? ; \
		    if [ $$cs_rc -ne 0 ]; then \
		      echo "[make audit] WARN cross-seed failed rc=$$cs_rc during freshness short-circuit; continuing (cross-workspace seed advisory)" >&2 ; \
		    fi ; \
		    cross_seed_md="$(_WS_RESOLVED)/.auditooor/cross_workspace_seed.md" ; \
		    hb_rc=0 ; \
		    brief_files="$(_WS_RESOLVED)/SCOPE.md reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md reports/v3_iter_2026-05-24/consolidated_roadmap_state.json reports/v3_iter_2026-05-24/lane_PHASE_II5_PREDICATE_COVERAGE/dydx_phase_ii5_predicate_coverage.json reports/v3_iter_2026-05-24/lane_PHASE_II5_PREDICATE_COVERAGE/hyperbridge_phase_ii5_predicate_coverage.json reports/v3_iter_2026-05-24/lane_PHASE_II5_PREDICATE_COVERAGE/hyperbridge_pre_phase_ii5_predicate_coverage.json tools/adversarial-hypothesis-differential-hunter.py" ; \
		    if [ -f "$$cross_seed_md" ]; then brief_files="$$brief_files $$cross_seed_md" ; fi ; \
		    $(MAKE) --no-print-directory hacker-brief WS="$(_WS_RESOLVED)" LANE="canonical-audit" FILES="$$brief_files" || hb_rc=$$? ; \
	    if [ $$hb_rc -ne 0 ]; then \
	      echo "[make audit] WARN hacker-brief failed rc=$$hb_rc during freshness short-circuit; continuing (hacker context advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE hacker-brief is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    bridge_rc=0 ; \
	    $(MAKE) --no-print-directory audit-hacker-logic-bridge WS="$(_WS_RESOLVED)" STRICT="$(STRICT)" || bridge_rc=$$? ; \
	    if [ $$bridge_rc -ne 0 ]; then \
	      echo "[make audit] WARN audit-hacker-logic-bridge failed rc=$$bridge_rc during freshness short-circuit; continuing because bridge output is advisory" >&2 ; \
	      python3 tools/proof-queue-freshness-marker.py \
	        --workspace "$(_WS_RESOLVED)" \
	        --mode mark-stale \
	        --bridge-rc "$$bridge_rc" \
	        --reason "audit-hacker-logic-bridge failed during make audit freshness short-circuit" >/dev/null || \
	        echo "[make audit] WARN failed to mark proof queue freshness after short-circuit bridge failure" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE audit-hacker-logic-bridge is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    else \
	      python3 tools/proof-queue-freshness-marker.py \
	        --workspace "$(_WS_RESOLVED)" \
	        --mode mark-fresh \
	        --bridge-rc 0 \
	        --reason "audit-hacker-logic-bridge completed during make audit freshness short-circuit" >/dev/null || \
	        echo "[make audit] WARN failed to mark proof queue freshness after short-circuit bridge success" >&2 ; \
		    fi ; \
		    phase_be_rc=0 ; \
		    $(MAKE) --no-print-directory phase-b-e-measurement-report JSON=1 || phase_be_rc=$$? ; \
		    if [ $$phase_be_rc -ne 0 ]; then \
		      echo "[make audit] WARN phase-b-e-measurement-report failed rc=$$phase_be_rc during freshness short-circuit; continuing (measurement refresh advisory)" >&2 ; \
		      if [ "$(STRICT)" = "1" ]; then \
		        echo "[make audit] NOTE phase-b-e-measurement-report is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
		        : ; \
		      fi ; \
		    fi ; \
		    if [ -f "$(_WS_RESOLVED)/.auditooor/invariant_ledger.json" ]; then \
	      xbridge_rc=0 ; \
	      $(MAKE) --no-print-directory high-impact-execution-bridge WS="$(_WS_RESOLVED)" || xbridge_rc=$$? ; \
	      if [ $$xbridge_rc -ne 0 ]; then \
	        echo "[make audit] WARN high-impact-execution-bridge failed rc=$$xbridge_rc during freshness short-circuit" >&2 ; \
	      fi ; \
	    fi ; \
	    prior_rc=0 ; \
	    $(MAKE) --no-print-directory prior-disclosure-index WS="$(_WS_RESOLVED)" || prior_rc=$$? ; \
	    if [ $$prior_rc -ne 0 ]; then \
	      echo "[make audit] WARN prior-disclosure-index failed rc=$$prior_rc during freshness short-circuit; continuing (prior-disclosure index is advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE prior-disclosure-index is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    mined_bridge_rc=0 ; \
	    $(MAKE) --no-print-directory mined-findings-hunter-bridge WS="$(_WS_RESOLVED)" LIMIT="$(if $(MINED_HUNTER_LIMIT),$(MINED_HUNTER_LIMIT),500)" MAX_CORPUS_RECORDS="$(if $(MINED_HUNTER_MAX_CORPUS),$(MINED_HUNTER_MAX_CORPUS),2500)" JSON=1 || mined_bridge_rc=$$? ; \
	    if [ $$mined_bridge_rc -ne 0 ]; then \
	      echo "[make audit] WARN mined-findings-hunter-bridge failed rc=$$mined_bridge_rc during freshness short-circuit; continuing (mined hunter obligations advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE mined-findings-hunter-bridge is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    sc_wp_rc=0 ; \
	    $(MAKE) --no-print-directory v3-worker-packet WS="$(_WS_RESOLVED)" SEVERITY=High STRICT="$(STRICT)" || sc_wp_rc=$$? ; \
	    if [ $$sc_wp_rc -ne 0 ]; then \
	      echo "[make audit] WARN v3-worker-packet failed rc=$$sc_wp_rc during freshness short-circuit; continuing (worker packet advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE v3-worker-packet is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    sc_eq_rc=0 ; \
	    $(MAKE) --no-print-directory exploit-queue WS="$(_WS_RESOLVED)" JSON=1 || sc_eq_rc=$$? ; \
	    if [ $$sc_eq_rc -ne 0 ]; then \
	      echo "[make audit] WARN exploit-queue failed rc=$$sc_eq_rc during freshness short-circuit; continuing (exploit queue is advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE exploit-queue is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    sc_ptl_rc=0 ; \
	    $(MAKE) --no-print-directory prove-top-leads WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),10)" JSON=1 $(if $(filter 1,$(STRICT)),STRICT=1) || sc_ptl_rc=$$? ; \
	    if [ $$sc_ptl_rc -ne 0 ]; then \
	      echo "[make audit] WARN prove-top-leads failed rc=$$sc_ptl_rc during freshness short-circuit; continuing (candidate judgment/proof lead queue advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE prove-top-leads is advisory in make audit even under STRICT (G9 parity, freshness path): the deep engines that produce PoCs run AFTER make audit; the STRICT proof gate belongs at submission/closeout, not before the engine stage. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    lt_rc=0 ; \
	    $(MAKE) --no-print-directory live-target-intel WS="$(_WS_RESOLVED)" IF_STALE_ONLY=1 || lt_rc=$$? ; \
	    if [ $$lt_rc -ne 0 ]; then \
	      echo "[make audit] WARN live-target-intel failed rc=$$lt_rc during freshness short-circuit; continuing (live-target context advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE live-target-intel is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    sc_hs_rc=0 ; \
	    $(MAKE) --no-print-directory hunt-starter WS="$(_WS_RESOLVED)" IF_STALE_ONLY=1 STALE_TTL_MIN="$(if $(HUNT_STARTER_STALE_TTL_MIN),$(HUNT_STARTER_STALE_TTL_MIN),120)" || sc_hs_rc=$$? ; \
	    if [ $$sc_hs_rc -ne 0 ]; then \
	      echo "[make audit] WARN hunt-starter failed rc=$$sc_hs_rc during freshness short-circuit; continuing (hunt-starter is advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE hunt-starter is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    qphc_rc=0 ; \
	    $(MAKE) --no-print-directory queue-proof-hard-close WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT=1) || qphc_rc=$$? ; \
	    if [ $$qphc_rc -ne 0 ]; then \
	      echo "[make audit] WARN queue-proof-hard-close failed rc=$$qphc_rc during freshness short-circuit; continuing (proof closeout advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE queue-proof-hard-close is advisory in make audit even under STRICT (G9 parity, freshness path): the deep engines that produce the proofs run AFTER make audit; the proof-close gate belongs at closeout. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    fv_rc=0 ; \
	    $(MAKE) --no-print-directory field-validation-report WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT=1) || fv_rc=$$? ; \
	    if [ $$fv_rc -ne 0 ]; then \
	      echo "[make audit] WARN field-validation-report failed rc=$$fv_rc during freshness short-circuit; continuing (field validation advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE field-validation-report is advisory in make audit even under STRICT (G9 parity): finding-field completeness is a submission/closeout concern and runs BEFORE the deep engines (Step 2/5); the STRICT field-validation gate belongs at closeout/submission. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    v3_sidecar_rc=0 ; \
	    $(MAKE) --no-print-directory v3-roadmap-sidecars WS="$(_WS_RESOLVED)" || v3_sidecar_rc=$$? ; \
	    if [ $$v3_sidecar_rc -ne 0 ]; then \
	      echo "[make audit] WARN v3-roadmap-sidecars failed rc=$$v3_sidecar_rc during freshness short-circuit; continuing (roadmap sidecars advisory)" >&2 ; \
	      if [ "$(STRICT)" = "1" ]; then \
	        echo "[make audit] NOTE v3-roadmap-sidecars is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	        : ; \
	      fi ; \
	    fi ; \
	    pfd_rc=0 ; \
	    $(MAKE) --no-print-directory provider-fanout-discipline-check WS="$(_WS_RESOLVED)" ENFORCE_IF_ARTIFACTS=1 $(if $(JSON),JSON=1) || pfd_rc=$$? ; \
	    if [ $$pfd_rc -ne 0 ]; then \
	      echo "[make audit] ERR provider-fanout-discipline-check failed rc=$$pfd_rc during freshness short-circuit" >&2 ; \
	      exit $$pfd_rc ; \
	    fi ; \
	    echo "[make audit] short-circuit - fresh marker present; refreshed memory and hacker queue; rerun with FORCE=1 for baseline engage pass" ; \
	    exit 0 ; \
	  fi ; \
	  if [ $$marker_rc -ge 2 ] ; then \
	    echo "[make audit] WARN audit-completion-marker.py exited rc=$$marker_rc; ignoring marker and running baseline engage pass" >&2 ; \
	    printf '%s\n' "$$marker_out" >&2 ; \
	  fi ; \
	fi
	@# V3-gap-1 fresh-workspace guard: detect missing scaffolds before running the
	@# baseline engage chain so the operator gets a clear actionable message instead of
	@# a cryptic rc=2 from intake-baseline.
	@ws_check="$(_WS_RESOLVED)" ; \
	prep_needed="" ; \
	if ! ls "$$ws_check"/ASSET_PLAN_*.md >/dev/null 2>&1; then \
	  prep_needed="$${prep_needed}  - ASSET_PLAN_*.md: missing (run make audit-prep to scaffold)\n" ; \
	elif grep -qE '^- Plan status: (missing|placeholder|not_started|TBD)' "$$ws_check"/ASSET_PLAN_*.md 2>/dev/null; then \
	  prep_needed="$${prep_needed}  - ASSET_PLAN_*.md: Plan status not yet 'ready' (edit to set 'Plan status: ready')\n" ; \
	fi ; \
	if [ ! -f "$$ws_check/RUBRIC_COVERAGE.md" ]; then \
	  prep_needed="$${prep_needed}  - RUBRIC_COVERAGE.md: missing (run make audit-prep to scaffold)\n" ; \
	fi ; \
	if [ ! -f "$$ws_check/OOS_CHECKLIST.md" ]; then \
	  prep_needed="$${prep_needed}  - OOS_CHECKLIST.md: missing (run make audit-prep to scaffold)\n" ; \
	fi ; \
	if [ -n "$$prep_needed" ]; then \
	  echo "" >&2 ; \
	  echo "[make audit] ERR workspace is not ready for audit. Missing or incomplete scaffold artifacts:" >&2 ; \
	  printf '%b' "$$prep_needed" >&2 ; \
	  echo "" >&2 ; \
	  echo "Fix: run these commands in order:" >&2 ; \
	  echo "  1. make audit-prep WS=$$ws_check" >&2 ; \
	  echo "     (scaffolds RUBRIC_COVERAGE.md, ASSET_PLAN_*.md, OOS_CHECKLIST.md from SCOPE.md + SEVERITY.md)" >&2 ; \
	  echo "  2. Open each ASSET_PLAN_*.md, fill in strategy + roots, set 'Plan status: ready'" >&2 ; \
	  echo "  3. make audit WS=$$ws_check" >&2 ; \
	  echo "" >&2 ; \
	  exit 2 ; \
	fi
	@audit_progress_csv="$(_WS_RESOLVED)/.audit_logs/audit_progress.csv" ; \
	REQUIRE_MEMORY_CONTEXT="$(REQUIRE_MEMORY_CONTEXT)" \
	STRICT_MEMORY_CONTEXT="$(STRICT_MEMORY_CONTEXT)" \
	AUDITOOOR_STRICT_OPERATOR_TRUTH="$(if $(filter 1,$(STRICT)),1,0)" \
	python3 tools/audit-progress.py --workspace "$(_WS_RESOLVED)" \
	  --csv "$$audit_progress_csv" \
	  $(if $(DRY_RUN),--dry-run) \
	  -- \
	  $(if $(OUT),--out "$(OUT)") \
	  $(ENGAGE_EXTRA_ARGS) ; \
	rc=$$? ; \
	if [ $$rc -ne 0 ]; then \
	  echo "[make audit] HARD FAIL: ordered audit stage failed; no completion marker or downstream continuation is permitted" >&2 ; \
	  exit $$rc ; \
	fi ; \
	if [ -n "$(DRY_RUN)" ]; then exit $$rc; fi ; \
	canonical_strict=0 ; if [ "$${AUDITOOOR_CANONICAL_STRICT:-0}" = "1" ]; then canonical_strict=1; fi ; \
	require_canonical() { if [ "$$canonical_strict" = "1" ]; then echo "[make audit] HARD FAIL: canonical ordered execution cannot continue after $$2 (rc=$$1)" >&2; exit "$$1"; fi; }; \
	im_rc=0 ; \
	fork_rc=0 ; \
	python3 tools/resolve-fork-bases.py --workspace "$(_WS_RESOLVED)" >/dev/null 2>&1 || fork_rc=$$? ; \
	if [ $$fork_rc -ne 0 ]; then echo "[make audit] WARN fork-base resolution failed rc=$$fork_rc" >&2; require_canonical $$fork_rc "resolve-fork-bases"; fi ; \
	python3 tools/workspace-coverage-heatmap.py --emit-inscope-manifest --workspace-path "$(_WS_RESOLVED)" $(if $(FORCE),--force) >/dev/null 2>&1 || im_rc=$$? ; \
	if [ $$im_rc -ne 0 ]; then \
	  echo "[make audit] WARN inscope-manifest emit failed rc=$$im_rc; downstream orient/coverage tools fall back to heuristics and step-1 verify will lack .auditooor/inscope_units.jsonl" >&2 ; \
	  require_canonical $$im_rc "inscope-manifest" ; \
	else \
	  echo "[make audit] wrote .auditooor/inscope_units.jsonl (in-scope unit manifest for hunt/coverage)" >&2 ; \
	fi ; \
	_GC_TO_BIN="" ; if command -v gtimeout >/dev/null 2>&1; then _GC_TO_BIN="gtimeout --kill-after=15 -s TERM $${AUDITOOOR_GUARD_COMPLETENESS_TIMEOUT:-180}" ; elif command -v timeout >/dev/null 2>&1; then _GC_TO_BIN="timeout --kill-after=15 -s TERM $${AUDITOOOR_GUARD_COMPLETENESS_TIMEOUT:-180}" ; fi ; \
	guard_rc=0 ; $$_GC_TO_BIN python3 tools/guard-completeness-check.py --workspace "$(_WS_RESOLVED)" || guard_rc=$$? ; \
	if [ $$guard_rc -ne 0 ]; then echo "[audit] WARN guard-completeness-check failed rc=$$guard_rc" >&2; require_canonical $$guard_rc "guard-completeness-check"; fi ; \
	if [ "$(AUDITOOOR_DEFER_DATAFLOW_SLICE)" = "1" ]; then \
	  echo "[make audit] dataflow-slice deferred: ordered parent owns README step-1c" >&2 ; \
	else \
	  dataflow_rc=0 ; $(MAKE) --no-print-directory dataflow-slice WS="$(_WS_RESOLVED)" >/dev/null 2>&1 || dataflow_rc=$$? ; \
	  if [ $$dataflow_rc -ne 0 ]; then echo "[make audit] WARN dataflow-slice failed rc=$$dataflow_rc" >&2; require_canonical $$dataflow_rc "dataflow-slice"; fi ; \
	fi; \
	_ADV_TO_SECS="$${AUDITOOOR_ADVISORY_TAIL_TIMEOUT:-300}" ; \
	_ADV_TO_BIN="" ; \
	if command -v gtimeout >/dev/null 2>&1; then _ADV_TO_BIN="gtimeout --kill-after=30 -s TERM" ; \
	elif command -v timeout >/dev/null 2>&1; then _ADV_TO_BIN="timeout --kill-after=30 -s TERM" ; fi ; \
	if [ -n "$$_ADV_TO_BIN" ]; then \
	  _ADV_TO="$$_ADV_TO_BIN $$_ADV_TO_SECS" ; \
	  echo "[make audit] advisory-tail wall-clock cap: $$_ADV_TO_BIN $${_ADV_TO_SECS}s (set AUDITOOOR_ADVISORY_TAIL_TIMEOUT to change; a hung advisory sub-target DROPS its pack + continues, exit 0 preserved)" >&2 ; \
	else \
	  _ADV_TO="" ; \
	  echo "[make audit] NOTE no gtimeout/timeout binary found; advisory-tail sub-targets run UNWRAPPED (no wall-clock cap). Install coreutils (gtimeout) to bound the advisory tail." >&2 ; \
	fi ; \
	preflight_rc=0 ; \
	preflight_to="" ; if [ -n "$${AUDITOOOR_PREFLIGHT_TIMEOUT:-}" ]; then preflight_to="timeout $${AUDITOOOR_PREFLIGHT_TIMEOUT}" ; fi ; \
	: "$${AUDITOOOR_PREFLIGHT_TOTAL_BUDGET:=600}" ; export AUDITOOOR_PREFLIGHT_TOTAL_BUDGET ; \
	$$preflight_to $(MAKE) --no-print-directory audit-preflight WS="$(_WS_RESOLVED)" $(if $(STRICT),STRICT=1) $(if $(MAX_FUNCTIONS),MAX_FUNCTIONS="$(MAX_FUNCTIONS)") || preflight_rc=$$? ; \
	if [ $$preflight_rc -ne 0 ]; then \
	  echo "[make audit] WARN audit-preflight failed rc=$$preflight_rc; continuing (CAP-GAP-97 pre-flight packs are advisory). NOTE: preflight is UNBOUNDED by default for full per-fn coverage (per-call MCP_TIMEOUT already guards a single hung call); set AUDITOOOR_PREFLIGHT_TIMEOUT only if you deliberately want a wall-clock cap (silently drops packs for un-reached fns)." >&2 ; \
	  require_canonical $$preflight_rc "audit-preflight" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE audit-preflight is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	mem_rc=0 ; \
	python3 tools/memory-auto-link.py --workspace "$(_WS_RESOLVED)" --write >/dev/null 2>&1 || mem_rc=$$? ; \
	if [ $$mem_rc -ne 0 ]; then \
	  echo "[make audit] WARN memory-auto-link failed rc=$$mem_rc after audit" >&2 ; \
	  require_canonical $$mem_rc "memory-auto-link" ; \
	  if [ "$${REQUIRE_MEMORY_CONTEXT:-0}" = "1" ] || [ "$${STRICT_MEMORY_CONTEXT:-0}" = "1" ]; then exit $$mem_rc; fi ; \
	fi ; \
	mem_rc=0 ; \
	python3 tools/memory-context-load.py --workspace "$(_WS_RESOLVED)" --from-requirements --write-receipt >/dev/null 2>&1 || mem_rc=$$? ; \
	if [ $$mem_rc -ne 0 ]; then \
	  echo "[make audit] WARN memory-context-load failed rc=$$mem_rc after audit" >&2 ; \
	  require_canonical $$mem_rc "memory-context-load" ; \
	  if [ "$${REQUIRE_MEMORY_CONTEXT:-0}" = "1" ] || [ "$${STRICT_MEMORY_CONTEXT:-0}" = "1" ]; then exit $$mem_rc; fi ; \
	fi ; \
	bp_rc=0 ; \
	if [ "$(BRAIN_PRIME_SKIP)" = "1" ]; then \
	  echo "[make audit] BRAIN_PRIME_SKIP=1 - skipping brain-prime (advisory)" ; \
	  if [ "$$canonical_strict" = "1" ]; then echo "[make audit] HARD FAIL: canonical ordered execution forbids BRAIN_PRIME_SKIP" >&2; exit 2; fi ; \
	else \
	  $(if $(BRAIN_PRIME_TIMEOUT),timeout $(BRAIN_PRIME_TIMEOUT) )$(MAKE) --no-print-directory brain-prime WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT=1) || bp_rc=$$? ; \
	  if [ $$bp_rc -ne 0 ]; then \
	    echo "[make audit] WARN brain-prime failed/timed-out rc=$$bp_rc; continuing (hacker context advisory)" >&2 ; \
	    require_canonical $$bp_rc "brain-prime" ; \
	    if [ "$(STRICT)" = "1" ]; then \
	      echo "[make audit] NOTE brain-prime is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	      : ; \
	    fi ; \
	  fi ; \
	fi ; \
	cs_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory cross-seed WS="$(_WS_RESOLVED)" $(if $(CROSS_SEED_LIMIT),LIMIT="$(CROSS_SEED_LIMIT)") || cs_rc=$$? ; \
	if [ $$cs_rc -ne 0 ]; then \
	  echo "[make audit] WARN cross-seed timed out/failed rc=$$cs_rc; continuing (cross-workspace seed advisory)" >&2 ; \
	  require_canonical $$cs_rc "cross-seed" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE cross-seed is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	cross_seed_md="$(_WS_RESOLVED)/.auditooor/cross_workspace_seed.md" ; \
	hb_rc=0 ; \
	brief_files="$(_WS_RESOLVED)/SCOPE.md reports/v3_iter_2026-05-24/CONSOLIDATED_ROADMAP_FOR_CODEX_2026-05-24.md reports/v3_iter_2026-05-24/consolidated_roadmap_state.json reports/v3_iter_2026-05-24/lane_PHASE_II5_PREDICATE_COVERAGE/dydx_phase_ii5_predicate_coverage.json reports/v3_iter_2026-05-24/lane_PHASE_II5_PREDICATE_COVERAGE/hyperbridge_phase_ii5_predicate_coverage.json reports/v3_iter_2026-05-24/lane_PHASE_II5_PREDICATE_COVERAGE/hyperbridge_pre_phase_ii5_predicate_coverage.json tools/adversarial-hypothesis-differential-hunter.py" ; \
	if [ -f "$$cross_seed_md" ]; then brief_files="$$brief_files $$cross_seed_md" ; fi ; \
	$$_ADV_TO $(MAKE) --no-print-directory hacker-brief WS="$(_WS_RESOLVED)" LANE="canonical-audit" FILES="$$brief_files" || hb_rc=$$? ; \
	if [ $$hb_rc -ne 0 ]; then \
	  echo "[make audit] WARN hacker-brief timed out/failed rc=$$hb_rc; continuing (hacker context advisory)" >&2 ; \
	  require_canonical $$hb_rc "hacker-brief" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE hacker-brief is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	phase_be_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory phase-b-e-measurement-report JSON=1 || phase_be_rc=$$? ; \
	if [ $$phase_be_rc -ne 0 ]; then \
	  echo "[make audit] WARN phase-b-e-measurement-report timed out/failed rc=$$phase_be_rc; continuing (measurement refresh advisory)" >&2 ; \
	  require_canonical $$phase_be_rc "phase-b-e-measurement-report" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE phase-b-e-measurement-report is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	bridge_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory audit-hacker-logic-bridge WS="$(_WS_RESOLVED)" STRICT="$(STRICT)" || bridge_rc=$$? ; \
	if [ $$bridge_rc -ne 0 ]; then \
	  echo "[make audit] WARN audit-hacker-logic-bridge timed out/failed rc=$$bridge_rc; continuing because bridge output is advisory" >&2 ; \
	  python3 tools/proof-queue-freshness-marker.py \
	    --workspace "$(_WS_RESOLVED)" \
	    --mode mark-stale \
	    --bridge-rc "$$bridge_rc" \
	    --reason "audit-hacker-logic-bridge failed during make audit" >/dev/null || \
	    echo "[make audit] WARN failed to mark proof queue freshness after bridge failure" >&2 ; \
	  require_canonical $$bridge_rc "audit-hacker-logic-bridge" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE audit-hacker-logic-bridge is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	else \
	  python3 tools/proof-queue-freshness-marker.py \
	    --workspace "$(_WS_RESOLVED)" \
	    --mode mark-fresh \
	    --bridge-rc 0 \
	    --reason "audit-hacker-logic-bridge completed during make audit" >/dev/null || \
	    echo "[make audit] WARN failed to mark proof queue freshness after bridge success" >&2 ; \
	fi ; \
	mined_bridge_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory mined-findings-hunter-bridge WS="$(_WS_RESOLVED)" LIMIT="$(if $(MINED_HUNTER_LIMIT),$(MINED_HUNTER_LIMIT),500)" MAX_CORPUS_RECORDS="$(if $(MINED_HUNTER_MAX_CORPUS),$(MINED_HUNTER_MAX_CORPUS),2500)" JSON=1 || mined_bridge_rc=$$? ; \
	if [ $$mined_bridge_rc -ne 0 ]; then \
	  echo "[make audit] WARN mined-findings-hunter-bridge timed out/failed rc=$$mined_bridge_rc; continuing (mined hunter obligations advisory)" >&2 ; \
	  require_canonical $$mined_bridge_rc "mined-findings-hunter-bridge" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE mined-findings-hunter-bridge is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	wp_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory v3-worker-packet WS="$(_WS_RESOLVED)" SEVERITY=High STRICT="$(STRICT)" || wp_rc=$$? ; \
	if [ $$wp_rc -ne 0 ]; then \
	  echo "[make audit] WARN v3-worker-packet timed out/failed rc=$$wp_rc; continuing (worker packet advisory)" >&2 ; \
	  require_canonical $$wp_rc "v3-worker-packet" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE v3-worker-packet is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	if [ -f "$(_WS_RESOLVED)/.auditooor/invariant_ledger.json" ]; then \
	  xbridge_rc=0 ; \
	  $(MAKE) --no-print-directory high-impact-execution-bridge WS="$(_WS_RESOLVED)" || xbridge_rc=$$? ; \
	  if [ $$xbridge_rc -ne 0 ]; then \
	    echo "[make audit] WARN high-impact-execution-bridge failed rc=$$xbridge_rc" >&2 ; \
	    require_canonical $$xbridge_rc "high-impact-execution-bridge" ; \
	  fi ; \
	fi ; \
	prior_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory prior-disclosure-index WS="$(_WS_RESOLVED)" || prior_rc=$$? ; \
	if [ $$prior_rc -ne 0 ]; then \
	  echo "[make audit] WARN prior-disclosure-index timed out/failed rc=$$prior_rc; continuing (prior-disclosure index is advisory)" >&2 ; \
	  require_canonical $$prior_rc "prior-disclosure-index" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE prior-disclosure-index is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	eq_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory exploit-queue WS="$(_WS_RESOLVED)" JSON=1 || eq_rc=$$? ; \
	if [ $$eq_rc -ne 0 ]; then \
	  echo "[make audit] WARN exploit-queue timed out/failed rc=$$eq_rc; continuing (exploit queue is advisory)" >&2 ; \
	  require_canonical $$eq_rc "exploit-queue" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE exploit-queue is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	ptl_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory prove-top-leads WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),10)" JSON=1 $(if $(filter 1,$(STRICT)),STRICT=1) || ptl_rc=$$? ; \
	if [ $$ptl_rc -ne 0 ]; then \
	  echo "[make audit] WARN prove-top-leads timed out/failed rc=$$ptl_rc; continuing (candidate judgment/proof lead queue advisory)" >&2 ; \
	  require_canonical $$ptl_rc "prove-top-leads" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE prove-top-leads is advisory in make audit even under STRICT (G9 parity with audit-deep:4223): candidate judgment needs PoCs the deep engines produce in Step 2/5, which run AFTER make audit; the STRICT proof gate belongs at submission/closeout, not before the engine stage. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	qphc_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory queue-proof-hard-close WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT=1) || qphc_rc=$$? ; \
	if [ $$qphc_rc -ne 0 ]; then \
	  echo "[make audit] WARN queue-proof-hard-close timed out/failed rc=$$qphc_rc; continuing (proof closeout advisory)" >&2 ; \
	  require_canonical $$qphc_rc "queue-proof-hard-close" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE queue-proof-hard-close is advisory in make audit even under STRICT (G9 parity): the proofs/counterexamples it hard-closes against come from the deep engines (Step 2/5) that run AFTER make audit; the STRICT proof-close gate belongs at closeout/submission, not before the engine stage. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	fv_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory field-validation-report WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT=1) || fv_rc=$$? ; \
	if [ $$fv_rc -ne 0 ]; then \
	  echo "[make audit] WARN field-validation-report timed out/failed rc=$$fv_rc; continuing (field validation advisory)" >&2 ; \
	  require_canonical $$fv_rc "field-validation-report" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE field-validation-report is advisory in make audit even under STRICT (G9 parity): it validates finding-field completeness, a submission/closeout concern, and runs BEFORE the deep engines (Step 2/5); the STRICT field-validation gate belongs at closeout/submission, not before the engine stage. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	v3_sidecar_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory v3-roadmap-sidecars WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT_HACKERMAN_V3=1) || v3_sidecar_rc=$$? ; \
	if [ $$v3_sidecar_rc -ne 0 ]; then \
	  echo "[make audit] WARN v3-roadmap-sidecars timed out/failed rc=$$v3_sidecar_rc; continuing (roadmap sidecars advisory)" >&2 ; \
	  require_canonical $$v3_sidecar_rc "v3-roadmap-sidecars" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE v3-roadmap-sidecars is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	pfd_rc=0 ; \
	$(MAKE) --no-print-directory provider-fanout-discipline-check WS="$(_WS_RESOLVED)" ENFORCE_IF_ARTIFACTS=1 $(if $(JSON),JSON=1) || pfd_rc=$$? ; \
	if [ $$pfd_rc -ne 0 ]; then \
	  echo "[make audit] ERR provider-fanout-discipline-check failed rc=$$pfd_rc" >&2 ; \
	  exit $$pfd_rc ; \
	fi ; \
	if [ -f tools/exploit-queue-schema-check.py ]; then \
	  schema_rc=0 ; python3 tools/exploit-queue-schema-check.py --workspace "$(_WS_RESOLVED)" || schema_rc=$$? ; \
	  if [ $$schema_rc -ne 0 ]; then echo "[make audit] WARN exploit-queue schema check failed rc=$$schema_rc" >&2; require_canonical $$schema_rc "exploit-queue-schema-check"; fi ; \
	fi ; \
	lt_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory live-target-intel WS="$(_WS_RESOLVED)" IF_STALE_ONLY=1 || lt_rc=$$? ; \
	if [ $$lt_rc -ne 0 ]; then \
	  echo "[make audit] WARN live-target-intel timed out/failed rc=$$lt_rc; continuing (live-target context advisory)" >&2 ; \
	  require_canonical $$lt_rc "live-target-intel" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE live-target-intel is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	hs_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory hunt-starter WS="$(_WS_RESOLVED)" || hs_rc=$$? ; \
	if [ $$hs_rc -ne 0 ]; then \
	  echo "[make audit] WARN hunt-starter timed out/failed rc=$$hs_rc; continuing (hunt-starter is advisory)" >&2 ; \
	  require_canonical $$hs_rc "hunt-starter" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE hunt-starter is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	acc_rc=0 ; \
	$$_ADV_TO $(MAKE) --no-print-directory auto-coverage-close WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) || acc_rc=$$? ; \
	if [ $$acc_rc -ne 0 ]; then \
	  echo "[make audit] WARN auto-coverage-close timed out/failed rc=$$acc_rc; continuing (generic coverage self-close is advisory: per-unit deterministic verdicts + rubric-class briefs + residual worker queue are advisory; the hunt-coverage gate is the load-bearing gate)" >&2 ; \
	  require_canonical $$acc_rc "auto-coverage-close" ; \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[make audit] NOTE auto-coverage-close is advisory in make audit even under STRICT (G9 parity): make audit is Step 1/5 ORIENT - the deep engines (Step 2/5) and the STRICT proof/validation closeout gate (Step 5/5) run AFTER it, so a Step-1 orientation/scaffolding stage must not block the engines. Continuing so the engines can run." >&2 ; \
	    : ; \
	  fi ; \
	fi ; \
	staging="$(_WS_RESOLVED)/submissions/staging" ; \
	packaged="$(_WS_RESOLVED)/submissions/packaged" ; \
	n_draft=$$(ls -1 "$$staging"/*.md 2>/dev/null | wc -l | tr -d ' ') ; \
	n_pack=$$(ls -1d "$$packaged"/*/ 2>/dev/null | wc -l | tr -d ' ') ; \
	echo "" ; \
	echo "[make audit] SUMMARY" ; \
	echo "  drafts staged:         $$n_draft   ($$staging/*.md)" ; \
	echo "  packaged bundles:      $$n_pack   ($$packaged/*/)" ; \
	echo "  MCP receipt:           $(_WS_RESOLVED)/.auditooor/memory_context_receipt.json" ; \
	echo "  MCP engage clusters:   make engage-report-mcp-feed WS=\"$(_WS_RESOLVED)\"" ; \
	echo "  hacker proof queue:    $(_WS_RESOLVED)/.auditooor/proof_obligation_queue.json" ; \
	echo "  high-impact bridge:    $(_WS_RESOLVED)/.auditooor/high_impact_execution_bridge.json" ; \
	echo "  proof queue freshness: $(_WS_RESOLVED)/.auditooor/proof_obligation_queue.freshness.json" ; \
	echo "  prior disclosures:     $(_WS_RESOLVED)/.auditooor/prior_disclosure_index.json" ; \
	echo "  exploit queue:         $(_WS_RESOLVED)/.auditooor/exploit_queue.json" ; \
	echo "  queue proof closeout:  $(_WS_RESOLVED)/.auditooor/queue_proof_hard_close.json" ; \
	echo "  field validation:      $(_WS_RESOLVED)/.auditooor/field_validation_report.json" ; \
	echo "  brain-prime receipt:   $(_WS_RESOLVED)/.auditooor/brain_prime_receipt.json" ; \
	echo "  hacker brief:          $(_WS_RESOLVED)/.auditooor/hacker_brief.md" ; \
	echo "  live-target report:    $(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.{md,json}" ; \
	echo "  source-mined queue:    $(_WS_RESOLVED)/.auditooor/exploit_queue.source_mined.json" ; \
	echo "  impact contracts:      $(_WS_RESOLVED)/.auditooor/impact_contracts.json" ; \
	echo "  hunt-starter ranked:   $(_WS_RESOLVED)/.auditooor/hunt_candidates_ranked.{json,md}" ; \
	echo "  (these are DRAFTS ready for packaging/triage, not accepted findings)" ; \
	echo "  next: review $$staging, then run pre-submit + submission workflow"
	@# G15.2: warn-grade hunt-coverage gate by default; STRICT=1 promotes to hard-fail.
	@if [ "$(AUDITOOOR_DEFER_HUNT_COVERAGE)" = "1" ]; then \
		echo '[make audit] DEFER hunt-coverage-gate: canonical pipeline enforces G15 after pre-hunt, deep, and hunt stages'; \
		python3 tools/hunt-coverage-gate.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) || echo '[make audit] WARN deferred hunt-coverage measurement failed'; \
		printf '%s\n' '{"schema":"auditooor.hunt_coverage_deferred.v1","status":"deferred","reason":"canonical ordered driver must run substrate and pre-hunt reasoners before strict G15","strict_gate":"audit-complete"}' > "$(_WS_RESOLVED)/.auditooor/hunt_coverage_deferred.json"; \
	else \
		python3 tools/hunt-coverage-gate.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) || { rc=$$?; echo '[make audit] WARN hunt-coverage-gate failed'; if [ "$(STRICT)" = "1" ]; then exit $$rc; fi; }; \
	fi
	@marker_rc=0 ; \
	python3 tools/audit-completion-marker.py write --workspace "$(_WS_RESOLVED)" >/dev/null || marker_rc=$$? ; \
	if [ $$marker_rc -ne 0 ]; then \
	  echo "[make audit] ERROR completion marker write failed rc=$$marker_rc" >&2 ; \
	  if [ "$${AUDITOOOR_CANONICAL_STRICT:-0}" = "1" ] || [ "$(STRICT)" = "1" ]; then exit $$marker_rc; fi ; \
	fi

.PHONY: live-target-intel
# live-target-intel (P5 MVP3): generate the P1/P3/P4-composed live-target
# context pack consumed by hunt-starter and MCP prebriefing. Non-strict by
# default so `make audit` can run on partially scaffolded workspaces without
# turning a context gap into a hard failure; STRICT=1 promotes missing/empty
# engage_report to fail-closed.
live-target-intel:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-target-intel WS=<workspace> [TOP_N=50] [TRIAGER_PRECHECK_BUDGET=10] [IF_STALE_ONLY=1] [STRICT=1] [JSON=1]'; \
	  echo 'Writes <ws>/docs/LIVE_TARGET_REPORT.{md,json}'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make live-target-intel" "$(_WS_RESOLVED)"
	@python3 tools/bug-bounty-oos-ingester.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --quiet
	@python3 tools/live-target-intelligence-report.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --output "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md" \
	  --output-json "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json" \
	  --top-n "$(if $(TOP_N),$(TOP_N),50)" \
	  --triager-precheck-budget "$(if $(TRIAGER_PRECHECK_BUDGET),$(TRIAGER_PRECHECK_BUDGET),10)" \
	  $(if $(IF_STALE_ONLY),--if-stale-only) \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json)
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@spg_rc=0 ; \
	  python3 tools/semantic-predicate-gate.py \
	    --input "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json" \
	    --workspace "$(_WS_RESOLVED)" \
	    --output "$(_WS_RESOLVED)/.auditooor/semantic_predicate_gate.json" \
	    --apply-to-report "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json" \
	    --report-markdown-output "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md" \
	    --max-calls "$(if $(SEMANTIC_GATE_MAX_CALLS),$(SEMANTIC_GATE_MAX_CALLS),50)" \
	    --max-report-cost-usd "$(if $(SEMANTIC_GATE_MAX_REPORT_COST_USD),$(SEMANTIC_GATE_MAX_REPORT_COST_USD),1.00)" \
	    $(if $(SEMANTIC_GATE_LIVE),--operator-live-network-consent,--dry-run) || spg_rc=$$? ; \
	  if [ $$spg_rc -ne 0 ]; then \
	    echo "[make live-target-intel] WARN semantic-predicate-gate failed rc=$$spg_rc; continuing (semantic gate advisory)" >&2 ; \
	    if [ "$(STRICT)" = "1" ]; then exit $$spg_rc; fi ; \
	  fi
	@dns_rc=0 ; \
	  python3 tools/defender-narrative-simulator.py "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json" --pretty > "$(_WS_RESOLVED)/.auditooor/dns_advisory.json" || dns_rc=$$? ; \
	  if [ $$dns_rc -ne 0 ]; then \
	    echo "[make live-target-intel] WARN defender-narrative-simulator failed rc=$$dns_rc; continuing (DNS advisory)" >&2 ; \
	    if [ "$(STRICT)" = "1" ]; then exit $$dns_rc; fi ; \
	  fi
	@pforpd_rc=0 ; \
	  python3 tools/post-filing-outcome-replay-pattern-distiller.py \
	    --out-json "$(_WS_RESOLVED)/.auditooor/pforpd_replay_patterns.json" || pforpd_rc=$$? ; \
	  if [ $$pforpd_rc -ne 0 ]; then \
	    echo "[make live-target-intel] WARN post-filing-outcome-replay-pattern-distiller failed rc=$$pforpd_rc; continuing (PFORPD advisory)" >&2 ; \
	    if [ "$(STRICT)" = "1" ]; then exit $$pforpd_rc; fi ; \
	  fi

# hunt-starter (Phase -1 A / WF-3 REC-1): pre-screen hunt candidates
# against the existing R-rule gates BEFORE worker dispatch. Reads
# <ws>/engage_report.md + <ws>/.auditooor/exploit_queue.json +
# <ws>/.auditooor/exploit_queue.source_mined.json +
# <ws>/.auditooor/mined_findings_obligations.json +
# <ws>/docs/LIVE_TARGET_REPORT.json and runs R45 / R47 / R52 / R53 / L31
# against each candidate via a synthetic draft. Emits
# <ws>/.auditooor/hunt_candidates_ranked.{json,md}.
#
# Optional restored tools (pattern-migration-alert.py and
# scan-report-thicken.py) are detected at runtime; absent => graceful no-op.
#
# `make audit` invokes this target as the last step before the completion
# marker write so hunt candidates are ranked before the next dispatch.
hunt-starter:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt-starter WS=<workspace> [LIMIT=N] [IF_STALE_ONLY=1] [STALE_TTL_MIN=45] [JSON=1]'; \
	  echo 'Writes <ws>/.auditooor/hunt_candidates_ranked.{json,md}'; \
	  echo 'IF_STALE_ONLY=1 skips regeneration when the ranked artifact is younger than STALE_TTL_MIN minutes.'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make hunt-starter" "$(_WS_RESOLVED)"
	@python3 tools/hunt-starter.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(LIMIT),--limit $(LIMIT)) \
	  $(if $(IF_STALE_ONLY),--if-stale-only) \
	  $(if $(STALE_TTL_MIN),--stale-ttl-min $(STALE_TTL_MIN)) \
	  $(if $(JSON),--json)

hunt-starter-test:
	@python3 -m unittest tools.tests.test_hunt_starter -v

# Build the UNIVERSAL body-pack hunt batch: per-function, ALL languages (sol/go/rust), any
# workspace. Refreshes the scope-correct per-function list, then emits one task per in-scope
# function with the REAL body embedded inline (token-efficient, R76-clean) + corpus-pack priming
# + a read-for-context instruction. Output = <ws>/.auditooor/hunt_batch_bodypack.jsonl, consumable
# by the Step-3 hunt dispatch. See README "PRE_FLIGHT_PACKS doctrine" (body-carrying packs).
hunt-batch-bodypack:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt-batch-bodypack WS=<workspace> [LANG=solidity|go|rust] [ONLY_UNCOVERED=1] [LIMIT=N]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make hunt-batch-bodypack" "$(_WS_RESOLVED)"
	@python3 tools/function-coverage-completeness.py --workspace "$(_WS_RESOLVED)" --write --json >/dev/null 2>&1 || true
	@python3 tools/inscope-hunt-batch-builder.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --per-function --with-pack-intel \
	  $(if $(LANG),--lang $(LANG)) \
	  $(if $(ONLY_UNCOVERED),--only-uncovered) \
	  $(if $(LIMIT),--limit $(LIMIT)) \
	  --out "$(_WS_RESOLVED)/.auditooor/hunt_batch_bodypack.jsonl"

hunt-batch-bodypack-test:
	@python3 -m pytest tools/tests/test_function_source_extractor.py tools/tests/test_sibling_scan_extractor.py tools/tests/test_inscope_hunt_pack_intel.py -q

# hunt-batch-bodypack-dispatch: token-saving batch dispatch.
# 1. Runs hunt-batch-bodypack to produce the per-function body-carrying task JSONL.
# 2. Pipes the JSONL through haiku-fanout-dispatcher.py plan (batch-size 10 by default,
#    safe ceiling 25) to produce Agent-ready prompt files in --output-dir.
# 3. Runs the sidecar count guard: FAILS loudly if emitted sidecar count < expected.
# Usage: make hunt-batch-bodypack-dispatch WS=<workspace> [LANG=solidity|go|rust]
#        [ONLY_UNCOVERED=1] [LIMIT=N] [BATCH=10] [MODEL=sonnet]
.PHONY: hunt-batch-bodypack-dispatch
hunt-batch-bodypack-dispatch:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt-batch-bodypack-dispatch WS=<workspace> [LANG=solidity|go|rust] [ONLY_UNCOVERED=1] [LIMIT=N] [BATCH=10] [MODEL=sonnet]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make hunt-batch-bodypack-dispatch" "$(_WS_RESOLVED)"
	@$(MAKE) --no-print-directory hunt-batch-bodypack WS="$(WS)" \
	  $(if $(LANG),LANG=$(LANG)) \
	  $(if $(ONLY_UNCOVERED),ONLY_UNCOVERED=$(ONLY_UNCOVERED)) \
	  $(if $(LIMIT),LIMIT=$(LIMIT))
	@_wsname=$$(basename "$(_WS_RESOLVED)"); \
	  _batch_size="$${BATCH:-10}"; \
	  _bodypack="$(_WS_RESOLVED)/.auditooor/hunt_batch_bodypack.jsonl"; \
	  _outdir="$$PWD/audit/corpus_tags/derived/hunt_bodypack_dispatch_$${_wsname}"; \
	  _expected=$$(wc -l < "$$_bodypack" 2>/dev/null | tr -d ' '); \
	  mkdir -p "$$_outdir"; \
	  echo "[hunt-batch-bodypack-dispatch] $$_expected tasks -> batch-size $${_batch_size} -> $$_outdir"; \
	  python3 tools/haiku-fanout-dispatcher.py plan \
	    --task-batch "$$_bodypack" \
	    --output-dir "$$_outdir" \
	    --batch-size "$${_batch_size}" \
	    --model "$${MODEL:-sonnet}"; \
	  echo "[hunt-batch-bodypack-dispatch] dispatch plan written to $$_outdir/_haiku_plan/"; \
	  echo "[hunt-batch-bodypack-dispatch] sidecar guard (expected=$$_expected, sidecar-dir=$$_outdir)..."; \
	  python3 tools/hunt-batch-sidecar-guard.py \
	    --expected "$$_expected" \
	    --sidecar-dir "$$_outdir" \
	    --warn-only; \
	  echo "[hunt-batch-bodypack-dispatch] DONE. Dispatch each $$_outdir/_haiku_plan/agent_batch_*.md via Agent(model=$${MODEL:-sonnet}), then: make mimo-corpus-mine WS=$(WS)"

bug-bounty-oos-ingest:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make bug-bounty-oos-ingest WS=<workspace> [JSON=1]'; \
	  echo 'Writes <ws>/.auditooor/bug_bounty_oos_index.json'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make bug-bounty-oos-ingest" "$(_WS_RESOLVED)"
	@python3 tools/bug-bounty-oos-ingester.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--json)

# hunt: operator convenience target - 1-command entry point for an audit session.
# Composes: audit-fast (refresh LIVE_TARGET_REPORT) + MCP brain-prime recall +
# MCP exploit-queue recall + MCP known-dead-ends check, then prints a
# hunter-friendly top-10 candidate summary to stdout.
# Usage: make hunt WS=~/audits/<project> [TOP_N=10] [STRICT=1]
hunt:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt WS=<workspace> [TOP_N=10] [STRICT=1]'; \
	  echo ''; \
	  echo 'hunt bundles the 4-command workflow into one target:'; \
	  echo '  1. make audit-fast WS=<ws>              -- refresh LIVE_TARGET_REPORT.md'; \
	  echo '  2. vault_brain_prime_context (MCP)       -- ranked hacker-mindset context'; \
	  echo '  3. vault_exploit_queue_context (MCP)     -- top exploit-queue candidates'; \
	  echo '  4. vault_known_dead_ends (MCP)           -- skip already-dropped paths'; \
	  echo ''; \
	  echo 'USE when: you want fresh ranked candidates fast (most common daily use).'; \
	  echo 'DON'"'"'T use when: you need a full closeout (use make audit or make v3-source-first-audit).'; \
	  exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make hunt" "$(_WS_RESOLVED)"
	@echo "############################################################################"
	@echo "## [make hunt] WARNING: this is the FAST ranked-candidate surface, NOT the ##"
	@echo "## gated full hunt. It does NOT run the dedup-first + completeness gate +  ##"
	@echo "## fork-divergence auto-wire pipeline. A green 'make hunt' is NOT proof    ##"
	@echo "## the workspace was fully hunted. For the GATED deterministic hunt run:   ##"
	@echo "##     make hunt-deterministic WS=$(_WS_RESOLVED)"
	@echo "## (loop / closeout paths call hunt-deterministic, never bare make hunt).  ##"
	@echo "############################################################################"
	@if [ -d "$(_WS_RESOLVED)/src/hyperbridge/modules/ismp/core" ] || \
	    [ -d "$(_WS_RESOLVED)/src/hyperbridge/modules/ismp" ] || \
	    [ -d "$(_WS_RESOLVED)/src/hyperbridge/tesseract" ] || \
	    [ -d "$(_WS_RESOLVED)/src/hyperbridge/parachain" ]; then \
	  echo "[make hunt] Advisory pre-step - hyperbridge workspace detected; running hyperbridge-cargo-patch before audit-fast..."; \
	  hb_rc=0; \
	  $(MAKE) --no-print-directory hyperbridge-cargo-patch WS="$(_WS_RESOLVED)" || hb_rc=$$?; \
	  if [ $$hb_rc -ne 0 ]; then \
	    echo "[make hunt] WARN hyperbridge-cargo-patch failed rc=$$hb_rc; continuing (hyperbridge advisory)" >&2; \
	  fi; \
	fi
	@echo "[make hunt] Step 1/4 - refreshing LIVE_TARGET_REPORT via audit-fast..."
	@$(MAKE) --no-print-directory audit-fast WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),50)" $(if $(STRICT),STRICT=1) || { echo "[make hunt] ERR audit-fast failed; cannot produce candidate list"; exit 1; }
	@_lr="$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md"; \
	if [ ! -f "$$_lr" ]; then \
	  echo "[make hunt] ERR LIVE_TARGET_REPORT.md not found after audit-fast; check workspace setup"; \
	  exit 1; \
	fi
	@echo ""
	@echo "[make hunt] Step 2/4 - brain-prime MCP recall..."
	@_bp_out=$$(python3 tools/vault-mcp-server.py --call vault_brain_prime_context \
	  --args "{\"workspace_path\":\"$(_WS_RESOLVED)\",\"limit\":8}" 2>&1) ; \
	_bp_rc=$$? ; \
	if [ $$_bp_rc -ne 0 ]; then \
	  echo "[make hunt] WARN brain-prime MCP call failed rc=$$_bp_rc (continuing)" ; \
	  _bp_summary="(unavailable - MCP call failed)" ; \
	else \
	  _bp_summary=$$(echo "$$_bp_out" | python3 -c \
	    'import sys,json; d=json.load(sys.stdin); \
	     rows=d.get("lanes",[]) or d.get("hunt_lanes",[]) or []; \
	     print(f"{len(rows)} ranked hunt lanes returned by brain-prime")' 2>/dev/null \
	    || echo "(brain-prime receipt received)") ; \
	fi ; \
	echo "[make hunt] brain-prime: $$_bp_summary"
	@echo ""
	@echo "[make hunt] Step 3/4 - exploit-queue MCP recall..."
	@_eq_out=$$(python3 tools/vault-mcp-server.py --call vault_exploit_queue_context \
	  --args "{\"workspace_path\":\"$(_WS_RESOLVED)\",\"limit\":10}" 2>&1) ; \
	_eq_rc=$$? ; \
	if [ $$_eq_rc -ne 0 ]; then \
	  echo "[make hunt] WARN exploit-queue MCP call failed rc=$$_eq_rc (continuing)" ; \
	  _eq_count=0 ; \
	else \
	  _eq_count=$$(echo "$$_eq_out" | python3 -c \
	    'import sys,json; d=json.load(sys.stdin); \
	     items=d.get("exploit_queue",[]) or d.get("items",[]) or []; \
	     print(len(items))' 2>/dev/null || echo "?") ; \
	fi ; \
	echo "[make hunt] exploit-queue: $$_eq_count candidates returned"
	@echo ""
	@echo "[make hunt] Step 4/4 - known-dead-ends MCP check..."
	@_ws_name=$$(basename "$(_WS_RESOLVED)") ; \
	_de_out=$$(python3 tools/vault-mcp-server.py --call vault_known_dead_ends \
	  --args "{\"workspace\":\"$$_ws_name\",\"limit\":5}" 2>&1) ; \
	_de_rc=$$? ; \
	if [ $$_de_rc -ne 0 ]; then \
	  echo "[make hunt] WARN known-dead-ends MCP call failed rc=$$_de_rc (continuing)" ; \
	  _de_count=0 ; \
	else \
	  _de_count=$$(echo "$$_de_out" | python3 -c \
	    'import sys,json; d=json.load(sys.stdin); print(d.get("matching_records",0))' 2>/dev/null || echo "?") ; \
	fi ; \
	echo "[make hunt] known-dead-ends: $$_de_count known dead-end paths for workspace $$_ws_name"
	@echo ""
	@echo "=========================================================================="
	@echo "  Hunter, here are your top-$(if $(TOP_N),$(TOP_N),10) candidates for $(_WS_RESOLVED)"
	@echo "=========================================================================="
	@python3 tools/hunt-reporter.py \
	  --report "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md" \
	  --top-n "$(if $(TOP_N),$(TOP_N),10)"
	@echo "=========================================================================="
	@echo "[make hunt] LIVE_TARGET_REPORT: $(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md"
	@echo "[make hunt] Next: pick a candidate above, then run:"
	@echo "  make hacker-brief WS=$(_WS_RESOLVED) LANE=<cluster-slug>"
	@echo "  make exploit-conversion-loop WS=$(_WS_RESOLVED) TOP_N=10"
	@echo "  make hunt-full WS=$(_WS_RESOLVED)         # default-full orientation workflow (audit + audit-deep-full)"
	@echo "=========================================================================="

# r36-rebuttal: lane-CAPABILITY-WORKFLOW-FULLNESS pathspec registered to agent_pathspec.json
# Gap #39 / operator anchor 2026-05-26: "whatever we analyze and audit, we do it full".
# `make hunt-full` is the default-full orientation alias for the daily workflow.
# It runs the 32+-stage `make audit`, then the live-engine `make audit-deep-full`
# profile, then the standard hunt-reporter top-N candidate surface. Optional
# depth-tools-orchestrator is skip-if-missing.
#
# Use `make hunt-full WS=<ws>` when the operator wants broad orientation. Use
# `make audit-run-full WS=<ws>` when the operator wants the fail-closed current-
# run deep-freshness completion gate. Use `make hunt WS=<ws>` (unchanged) when
# fast ranked candidates are enough.
hunt-full:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt-full WS=<workspace> [TOP_N=10] [STRICT=1] [MAX_FUNCTIONS=N]'; \
	  echo ''; \
	  echo 'hunt-full is the DEFAULT-FULL daily orientation workflow (Gap #39):'; \
	  echo '  1. make audit WS=<ws>           -- 32+ stages including regex detectors, brain-prime'; \
	  echo '  2. make audit-deep-full WS=<ws> -- live halmos (900s) + medusa (1800s) + echidna (1800s)'; \
	  echo '  3. depth-tools-orchestrator.py  -- (skip if sibling-lane tool missing)'; \
	  echo '  4. make hunt WS=<ws>            -- standard hunt-reporter top-N surface'; \
	  echo ''; \
	  echo 'USE when: operator wants broad orientation ("whatever we analyze, we do it full").'; \
	  echo 'NOTE: standalone hunt-full is not a completion certificate; use audit-run-full for fail-closed current-run deep freshness.'; \
	  echo 'DON'"'"'T use when: you want fast ranked candidates only (use make hunt).'; \
	  exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make hunt-full" "$(_WS_RESOLVED)"
	@echo "[make hunt-full] Step 1/5 - make audit WS=$(_WS_RESOLVED) (32+ stages)..."
	@$(MAKE) --no-print-directory audit WS="$(_WS_RESOLVED)" $(if $(STRICT),STRICT=1) $(if $(MAX_FUNCTIONS),MAX_FUNCTIONS="$(MAX_FUNCTIONS)") || { \
	  echo "[make hunt-full] ERR make audit failed; cannot continue"; exit 1; }
	@echo ""
	@echo "[make hunt-full] Step 2/5 - make audit-deep-full WS=$(_WS_RESOLVED) (live engines)..."
	@AUDIT_COMMIT_MINING_SKIP=1 $(MAKE) --no-print-directory audit-deep-full WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),25)" || { \
	  echo "[make hunt-full] WARN audit-deep-full returned non-zero; continuing to depth-tools"; }
	@echo ""
	@echo "[make hunt-full] Step 3/5 - depth-tools-orchestrator (sibling-lane tool; skip-if-missing)..."
	@_dto="tools/depth-tools-orchestrator.py"; \
	if [ -f "$$_dto" ]; then \
	  python3 "$$_dto" --workspace "$(_WS_RESOLVED)" || \
	    echo "[make hunt-full] WARN depth-tools-orchestrator returned non-zero; continuing" >&2; \
	else \
	  echo "[make hunt-full] NOTE depth-tools-orchestrator.py not yet present (sibling lane in flight); skipping"; \
	fi
	@echo ""
	@echo "[make hunt-full] Step 4/5 - GATED deterministic hunt (dedup-first + fork-divergence auto-wire + completeness gate)..."
	@echo "[make hunt-full]   hunt-full is the broad orientation workflow; it goes through make hunt-deterministic,"
	@echo "[make hunt-full]   NOT the bare fast 'make hunt' surface, so the completeness gate + fork-divergence"
	@echo "[make hunt-full]   artifact are generated before the orientation workflow returns."
	@HUNT_ORCHESTRATE_SKIP_AUDIT_STAGES=1 $(MAKE) --no-print-directory hunt-deterministic WS="$(_WS_RESOLVED)" $(if $(NO_MCP),NO_MCP=1) || { \
	  echo "[make hunt-full] ERR hunt-deterministic FAILED-CLOSED (dedup / fork-divergence / completeness gate non-zero)"; exit 1; }
	@echo ""
	@echo "[make hunt-full] Step 4b/5 - fast ranked-candidate top-N surface (make hunt)..."
	@$(MAKE) --no-print-directory hunt WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),0)" $(if $(STRICT),STRICT=1) || { \
	  echo "[make hunt-full] WARN fast ranked-candidate surface returned non-zero; continuing because hunt-deterministic is the gated completion path" >&2; }
	@echo ""
	@echo "[make hunt-full] Step 5/5 - zk-hunt (ZK verifier surface; skip if not ZK)..."
	@$(MAKE) --no-print-directory zk-hunt WS="$(_WS_RESOLVED)" SKIP_PREFLIGHT=1 \
	  || echo "[hunt-full] WARN zk-hunt non-zero / not ZK ws; continuing"
	@echo ""
	@echo "=========================================================================="
	@echo "[make hunt-full] Full orientation workflow complete."
	@echo "[make hunt-full] NOTE this is not a fresh deep-engine completion certificate; use audit-run-full for that gate."
	@echo "[make hunt-full] Workflow invocation log: $(_WS_RESOLVED)/.auditooor/workflow_invocation_log.jsonl"
	@echo "[make hunt-full] Audit-deep report:       $(_WS_RESOLVED)/.audit_logs/audit_deep_report.md"
	@echo "=========================================================================="

_AUDIT_RUN_FULL_MCP_SCOPE = $(if $(MCP_SCOPE),$(MCP_SCOPE),read)
_AUDIT_RUN_FULL_SHORT_FLAGS = $(filter-out --%,$(firstword $(MAKEFLAGS)))
_AUDIT_RUN_FULL_JUST_PRINT = $(or $(filter -n --just-print --dry-run --recon,$(MAKEFLAGS)),$(findstring n,$(_AUDIT_RUN_FULL_SHORT_FLAGS)))
_AUDIT_RUN_FULL_RUN_ID := $(if $(_AUDIT_RUN_FULL_JUST_PRINT),auditrun-dry-run,$(shell python3 -c 'import uuid; print("auditrun-" + uuid.uuid4().hex)'))
_AUDIT_RUN_FULL_MAX_FUNCTIONS = $(if $(MAX_FUNCTIONS),$(MAX_FUNCTIONS),0)
AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION ?= 0
AUDIT_RUN_FULL_MIN_FREE_MB ?= 25600

audit-run-full: export AUDIT_RUN_FULL_MAKE := $(MAKE)
audit-run-full: export ENFORCE_AUTONOMOUS_PROOF_CONVERSION := $(AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION)
audit-run-full: export AUDITOOOR_AUDIT_RUN_FULL_ID := $(_AUDIT_RUN_FULL_RUN_ID)
audit-run-full: export AUDITOOOR_MCP_SESSION_TOKEN := $(if $(_AUDIT_RUN_FULL_JUST_PRINT),$(AUDITOOOR_MCP_SESSION_TOKEN),$(if $(strip $(AUDITOOOR_MCP_SESSION_TOKEN)),$(AUDITOOOR_MCP_SESSION_TOKEN),$(if $(strip $(WS)),$(shell python3 tools/auditooor_mcp_token.py issue --workspace "$(_WS_RESOLVED)" --scope "$(_AUDIT_RUN_FULL_MCP_SCOPE)" 2>/dev/null),)))
audit-run-full:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-run-full WS=<workspace> [STRICT=1] [EXECUTE_READY=1] [TOP_N=10] [MAX_FUNCTIONS=0] [AUDIT_RUN_FULL_MIN_FREE_MB=25600] [AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=0|1] [JSON=1]'; \
	  echo 'Runs the staged full-scope audit workflow. Positive MAX_FUNCTIONS is bounded smoke only; proof conversion is advisory unless audit-run-full proof enforcement is set to 1.'; \
	  exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make audit-run-full" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"start","run_id":"%s","workspace":"%s","strict":"%s","execute_ready":"%s","top_n":"%s","max_functions":"%s","min_free_mb":"%s","enforce_autonomous_proof_conversion":"%s","timestamp_utc":"%s"}\n' \
	  "$(_AUDIT_RUN_FULL_RUN_ID)" "$(_WS_RESOLVED)" "$(STRICT)" "$(EXECUTE_READY)" "$(if $(TOP_N),$(TOP_N),10)" "$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)" "$(AUDIT_RUN_FULL_MIN_FREE_MB)" "$(AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION)" "$$ts" >> "$$manifest"; \
	min_free_mb="$(AUDIT_RUN_FULL_MIN_FREE_MB)"; \
	case "$$min_free_mb" in \
	  ''|*[!0-9]*) \
	    ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	    printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"fail","run_id":"%s","stage":"preflight","reason":"invalid minimum free disk space","min_free_mb":"%s","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$min_free_mb" "$$ts" >> "$$manifest"; \
	    echo "[make audit-run-full] ERR AUDIT_RUN_FULL_MIN_FREE_MB must be a nonnegative integer, got '$$min_free_mb'"; \
	    exit 2; \
	    ;; \
	esac; \
	if [ "$${#min_free_mb}" -gt 9 ]; then \
	  ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"fail","run_id":"%s","stage":"preflight","reason":"invalid minimum free disk space","min_free_mb":"%s","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$min_free_mb" "$$ts" >> "$$manifest"; \
	  echo "[make audit-run-full] ERR AUDIT_RUN_FULL_MIN_FREE_MB is too large for shell-safe comparison, got '$$min_free_mb'"; \
	  exit 2; \
	fi; \
	if [ "$$min_free_mb" != "0" ]; then \
	  free_mb="$$(df -Pm "$(_WS_RESOLVED)" 2>/dev/null | awk 'NR==2 {print $$4}')"; \
	  if [ -z "$$free_mb" ]; then \
	    ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	    printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"fail","run_id":"%s","stage":"preflight","reason":"disk free space unavailable","min_free_mb":"%s","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$min_free_mb" "$$ts" >> "$$manifest"; \
	    echo "[make audit-run-full] ERR cannot determine free disk space for $(_WS_RESOLVED)"; \
	    exit 2; \
	  fi; \
	  if [ "$$free_mb" -lt "$$min_free_mb" ]; then \
	    ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	    printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"fail","run_id":"%s","stage":"preflight","reason":"insufficient free disk space","free_mb":"%s","min_free_mb":"%s","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$free_mb" "$$min_free_mb" "$$ts" >> "$$manifest"; \
	    echo "[make audit-run-full] ERR insufficient free disk space: $$free_mb MiB available, $$min_free_mb MiB required. Set AUDIT_RUN_FULL_MIN_FREE_MB=0 to bypass after operator approval."; \
	    exit 2; \
	  fi; \
	fi; \
	if [ -n "$(filter 1 true yes,$(STRICT))" ] && [ "$${ENFORCE_AUTONOMOUS_PROOF_CONVERSION:-}" = "1" ] && [ -z "$(filter 1 true yes,$(EXECUTE_READY))" ]; then \
	  ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"fail","run_id":"%s","stage":"preflight","reason":"AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 requires EXECUTE_READY=1","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	  echo "[make audit-run-full] ERR AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 requires EXECUTE_READY=1 so proof conversion executes instead of no-run"; \
	  exit 2; \
	fi
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"mcp-preflight","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	python3 tools/audit-mcp-preflight.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --scope "$(_AUDIT_RUN_FULL_MCP_SCOPE)" \
	  $(if $(filter 0 false no,$(REQUIRE_RECENT_RECALL)),,--require-recent-recall) \
	  $(if $(JSON),--json) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"mcp-preflight","deep_engine_skip_reason":"mcp_preflight_failed","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"mcp-preflight","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"intake-truth","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory prior-disclosure-index WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"intake-truth","step":"prior-disclosure-index","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	python3 tools/intake-baseline.py "$(_WS_RESOLVED)" \
	  --strict-operator-truth \
	  --out-json "$(_WS_RESOLVED)/INTAKE_BASELINE.json" \
	  --out-md "$(_WS_RESOLVED)/INTAKE_BASELINE.md" \
	  $(if $(JSON),--json) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"intake-truth","step":"intake-baseline","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"intake-truth","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"hunt-full","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory hunt-full WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),0)" MAX_FUNCTIONS="$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)" $(if $(STRICT),STRICT=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"hunt-full","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
		hunt_deep_prov="$$(mktemp "$(_WS_RESOLVED)/.auditooor/hunt-full-deep-provenance.XXXXXX")"; \
		python3 tools/audit-deep-manifest.py --workspace "$(_WS_RESOLVED)" --check-fresh --require-full-invariant-denominator --tolerate-build-class-partial --audit-run-manifest "$$manifest" --run-id "$(_AUDIT_RUN_FULL_RUN_ID)" --emit-provenance-stage-pass hunt-full --json > "$$hunt_deep_prov" || { \
		  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
			  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"hunt-full","step":"deep-freshness-after-hunt-full","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
		  exit $$rc; \
		}; \
		python3 -c 'import json, sys; payload = json.load(open(sys.argv[1], encoding="utf-8")); print(json.dumps(payload["provenance_stage_pass"], sort_keys=True))' "$$hunt_deep_prov" >> "$$manifest"; \
		rm -f "$$hunt_deep_prov"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"novel-chain-hunt","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory novel-chain-hunt WS="$(_WS_RESOLVED)" MAX_FUNCTIONS="$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)" $(if $(STRICT),STRICT=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"novel-chain-hunt","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"novel-chain-hunt","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"corpus-driven-hunt","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory corpus-driven-hunt WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),0)" MAX_FUNCTIONS="$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)" EMIT_PROOF_QUEUE=1 $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"corpus-driven-hunt","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"corpus-driven-hunt","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"coverage-to-hunt-seed","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory coverage-to-hunt-seed WS="$(_WS_RESOLVED)" REBUILD_REPORT=1 RUN_ID="$(_AUDIT_RUN_FULL_RUN_ID)" $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"coverage-to-hunt-seed","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"coverage-to-hunt-seed","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"mechanism-to-exploit-queue","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory mechanism-to-exploit-queue WS="$(_WS_RESOLVED)" RUN_ID="$(_AUDIT_RUN_FULL_RUN_ID)" $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"mechanism-to-exploit-queue","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"mechanism-to-exploit-queue","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
			printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"coverage-source-scan","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory exploit-queue-source-mine WS="$(_WS_RESOLVED)" TOP_N=0 INCLUDE_OPEN_UNHUNTED=1 REVIEW_ONLY=1 UPDATE_QUEUE=1 RUN_ID="$(_AUDIT_RUN_FULL_RUN_ID)" $(if $(JSON),JSON=1) || { \
		  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"coverage-source-scan","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
		  exit $$rc; \
		}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
			printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"coverage-source-scan","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"auto-coverage-close","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory auto-coverage-close WS="$(_WS_RESOLVED)" RUN_ID="$(_AUDIT_RUN_FULL_RUN_ID)" $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  echo "[audit-run-full] NOTE auto-coverage-close non-fatal (advisory generic coverage-closer): per-unit deterministic verdicts + rubric-class briefs + residual worker queue are advisory; the hunt-coverage gate that follows is the load-bearing gate. Continuing." >&2; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-warn","run_id":"%s","stage":"auto-coverage-close","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"auto-coverage-close","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"hunt-coverage","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory hunt-coverage-gate WS="$(_WS_RESOLVED)" MIN_COVERAGE=1.0 STRICT=1 RUN_ID="$(_AUDIT_RUN_FULL_RUN_ID)" $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"hunt-coverage","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"hunt-coverage","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"post-coverage-chain-synth","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	AUDITOOOR_AUDIT_RUN_FULL_STAGE=post-coverage-chain-synth $${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory chain-synth WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  if [ "$${ENFORCE_AUTONOMOUS_PROOF_CONVERSION:-}" = "1" ]; then \
	    printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"post-coverage-chain-synth","step":"chain-synth","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	    exit $$rc; \
	  fi; \
	  echo "[audit-deep] NOTE STRICT post-coverage-chain-synth (make chain-synth) non-fatal (G9 parity with exploit-conversion-loop + prove-top-leads): chain synthesis found 0 INV-* ids / 0 chains - the honest result when the deep-engine harnesses are advisory/empty (no real invariants to synthesize from). The deep-engine cert + hunt-coverage gate are the load-bearing gates. Set ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 to hard-fail. Continuing." >&2; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-warn","run_id":"%s","stage":"post-coverage-chain-synth","step":"chain-synth","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	}; \
	cs_out="$$(python3 tools/chain-synth-report-check.py --workspace "$(_WS_RESOLVED)" --run-id "$(_AUDIT_RUN_FULL_RUN_ID)" --stage post-coverage-chain-synth --manifest "$$manifest" $(if $(JSON),--json) 2>&1)"; cs_rc=$$?; \
	printf '%s\n' "$$cs_out"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	if [ $$cs_rc -eq 0 ]; then \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"post-coverage-chain-synth","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	elif [ "$${ENFORCE_AUTONOMOUS_PROOF_CONVERSION:-}" = "1" ]; then \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"post-coverage-chain-synth","step":"chain-synth-semantic-check","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$cs_rc" "$$ts" >> "$$manifest"; \
		exit $$cs_rc; \
	else \
		echo "[audit-deep] NOTE STRICT post-coverage-chain-synth non-fatal (G9 parity with exploit-conversion-loop + prove-top-leads + v3-roadmap-sidecars): chain synthesis is a downstream proof/quality layer; the deep-engine cert + hunt-coverage gate are the load-bearing gates; an empty/partial synthesis (no chains/invariants under advisory or budget-bounded deep-engine coverage) does not invalidate the audit. Set ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 to hard-fail. Continuing." >&2; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-warn","run_id":"%s","stage":"post-coverage-chain-synth","step":"chain-synth-semantic-check","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$cs_rc" "$$ts" >> "$$manifest"; \
	fi
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"exploit-conversion-loop","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	if $${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory exploit-conversion-loop WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),10)" $(if $(STRICT),STRICT=1) $(if $(EXECUTE_READY),EXECUTE_READY="$(EXECUTE_READY)") $(if $(JSON),JSON=1); then \
	  ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"exploit-conversion-loop","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	else \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  proof_enforce="$${ENFORCE_AUTONOMOUS_PROOF_CONVERSION:-}"; \
	  if [ "$$proof_enforce" = "1" ]; then \
	    printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"exploit-conversion-loop","rc":%s,"enforce_autonomous_proof_conversion":"1","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	    exit $$rc; \
	  fi; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-warn","run_id":"%s","stage":"exploit-conversion-loop","rc":%s,"enforce_autonomous_proof_conversion":"0","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	fi
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"prove-top-leads","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	if $${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory prove-top-leads WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),10)" $(if $(STRICT),STRICT=1) $(if $(EXECUTE_READY),EXECUTE_READY="$(EXECUTE_READY)") $(if $(JSON),JSON=1); then \
	  ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"prove-top-leads","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	else \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  proof_enforce="$${ENFORCE_AUTONOMOUS_PROOF_CONVERSION:-}"; \
	  if [ "$$proof_enforce" = "1" ]; then \
	    printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"prove-top-leads","rc":%s,"enforce_autonomous_proof_conversion":"1","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	    exit $$rc; \
	  fi; \
	  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-warn","run_id":"%s","stage":"prove-top-leads","rc":%s,"enforce_autonomous_proof_conversion":"0","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	fi
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"cvl-spec-risk-scan","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory cvl-spec-risk-scan WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"cvl-spec-risk-scan","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"cvl-spec-risk-scan","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"audit-complete","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory audit-complete WS="$(_WS_RESOLVED)" $(if $(STRICT),STRICT=1) $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"audit-complete","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"audit-complete","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"
	@# r36-rebuttal: registered lane reweighter-persist-fix in .auditooor/agent_pathspec.json
	@# Advisory self-learning closeout (G9-parity): per-workspace agent-learning-compiler
	@# + global hacker-q-reweight so durable learning fires automatically at audit
	@# closeout. Advisory - a failure WARNs and continues (does NOT block the
	@# production-pipeline-check / deep-freshness gates), mirroring the cross-seed /
	@# brain-prime advisory closeout stages.
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"learning-closeout","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	if $${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory learning-closeout WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1); then \
		ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"learning-closeout","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	else \
		ls_rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-warn","run_id":"%s","stage":"learning-closeout","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ls_rc" "$$ts" >> "$$manifest"; \
		echo "[make audit-run-full] WARN learning-closeout failed rc=$$ls_rc; continuing (self-learning advisory, G9-parity)" >&2; \
	fi
	@set -e; \
	manifest="$(_WS_RESOLVED)/.auditooor/audit_run_full_manifest.jsonl"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","run_id":"%s","stage":"production-pipeline-check","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory production-pipeline-check WS="$(_WS_RESOLVED)" $(if $(STRICT),STRICT=1) $(if $(JSON),JSON=1) || { \
	  rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		  printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","run_id":"%s","stage":"production-pipeline-check","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	  exit $$rc; \
	}; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-pass","run_id":"%s","stage":"production-pipeline-check","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-start","stage":"deep-freshness","run_id":"%s","timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$ts" >> "$$manifest"; \
	if [ "$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)" = "0" ]; then \
	  python3 tools/audit-deep-manifest.py --workspace "$(_WS_RESOLVED)" --check-fresh --require-full-invariant-denominator --tolerate-build-class-partial --audit-run-manifest "$$manifest" --run-id "$(_AUDIT_RUN_FULL_RUN_ID)" --append-audit-run-success-events $(if $(JSON),--json) || { \
	    rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	    printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","stage":"deep-freshness","run_id":"%s","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	    exit $$rc; \
	  }; \
	  echo "[make audit-run-full] complete. Manifest: $$manifest"; \
	else \
	  python3 tools/audit-deep-manifest.py --workspace "$(_WS_RESOLVED)" --check-fresh --require-full-invariant-denominator --tolerate-build-class-partial --audit-run-manifest "$$manifest" --run-id "$(_AUDIT_RUN_FULL_RUN_ID)" --append-audit-run-bounded-success-events --bounded-max-functions "$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)" $(if $(JSON),--json) || { \
	    rc=$$?; ts="$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	    printf '{"schema":"auditooor.audit_run_full_manifest.v1","event":"stage-fail","stage":"deep-freshness","run_id":"%s","rc":%s,"timestamp_utc":"%s"}\n' "$(_AUDIT_RUN_FULL_RUN_ID)" "$$rc" "$$ts" >> "$$manifest"; \
	    exit $$rc; \
	  }; \
	  echo "[make audit-run-full] bounded complete (MAX_FUNCTIONS=$(_AUDIT_RUN_FULL_MAX_FUNCTIONS)). Manifest: $$manifest"; \
	fi

audit-run-full-serial-board:
	@python3 tools/audit-run-full-serial-board.py \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)",--audits-root "$(if $(AUDITS_ROOT),$(AUDITS_ROOT),$(HOME)/audits)") \
	  $(if $(INCLUDE_NO_MANIFEST),--include-no-manifest) \
	  $(if $(LIVE_STATUS),--live-status) \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(JSON),--json)

audit-run-full-status:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-run-full-status WS=<workspace> [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-run-full-status" "$(_WS_RESOLVED)"
	@python3 tools/audit-run-full-status.py "$(_WS_RESOLVED)" $(if $(JSON),--json)

cvl-spec-risk-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make cvl-spec-risk-scan WS=<workspace> [JSON=1] [OUT=<path>]'; \
	  exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "cvl-spec-risk-scan" "$(_WS_RESOLVED)"
	@out="$(if $(OUT),$(OUT),$(_WS_RESOLVED)/.auditooor/cvl_coverage_audit.json)"; \
	python3 tools/cvl-spec-risk-scan.py "$(_WS_RESOLVED)" --out "$$out" $(if $(JSON),--json)

cvl-spec-risk-scan-test:
	@python3 -m unittest tools.tests.test_cvl_spec_risk_scan -v

# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
# hunt-deterministic (L36): the DETERMINISTIC `make hunt` orchestrator. Runs the
# canonical hunt pipeline IN ORDER via tools/hunt-orchestrate.py, hard-failing on
# any non-zero step. Step 0 is the MANDATORY dedup-first skip-set load; step 8 is
# the BLOCKING hunt-completeness-check. Use this when the loop must guarantee
# dedup-first + completeness (vs `make hunt` which is the fast ranked-candidate
# convenience surface).
# Usage: make hunt-deterministic WS=<ws> [PLAN=1] [DRY_RUN=1] [NO_MCP=1]
hunt-deterministic:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt-deterministic WS=<workspace> [PLAN=1] [DRY_RUN=1] [NO_MCP=1]'; \
	  echo ''; \
	  echo 'Deterministic L36 hunt orchestrator - runs IN ORDER, hard-fails on non-zero:'; \
	  echo '  0 DEDUP-LOAD (mandatory, FIRST)  4 Tier-6 bidirectional mining'; \
	  echo '  1 ensure-full-clone              5 emit per-cluster briefs (skip-set embedded)'; \
	  echo '  2 make audit                     6 sidecar->corpus learn ETL (+append dead-ends)'; \
	  echo '  3 make audit-deep                7 build CAPABILITY_COVERAGE_MATRIX'; \
	  echo '                                   8 FINAL hunt-completeness-check (BLOCKING)'; \
	  exit 2; \
	fi
	@python3 tools/hunt-orchestrate.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(PLAN),--plan) $(if $(DRY_RUN),--dry-run) $(if $(NO_MCP),--no-mcp)

# ============================================================================
# MVP2/MVP3 capability targets (2026-05-27 AGI plan)
# ============================================================================

# hunt-time-falsify: wrap fuzzers (echidna/medusa/halmos/fuzz-runner.sh) with
# 60s cap per candidate hypothesis. Produces JSON sidecar per candidate.
# Usage: make hunt-time-fuzz WS=<ws> HYPS=<hyp-file.jsonl> [TIMEOUT=60] [OUT=<dir>]
hunt-time-fuzz:
	@if [ -z "$(WS)" ] || [ -z "$(HYPS)" ]; then \
	  echo 'Usage: make hunt-time-fuzz WS=<workspace> HYPS=<hyp-file.jsonl> [TIMEOUT=60] [OUT=<dir>]'; \
	  exit 2; \
	fi
	@python3 tools/hunt-time-falsify.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --hypothesis-file "$(HYPS)" \
	  --timeout-s "$(if $(TIMEOUT),$(TIMEOUT),60)" \
	  --output "$(if $(OUT),$(OUT),$(_WS_RESOLVED)/.auditooor/hunt_time_fuzz)"

# dollar-impact: estimate per-candidate expected-bounty via DefiLlama TVL +
# rubric severity. Output drives R74 gate (Check #124).
# Usage: make dollar-impact WS=<ws> CANDIDATE=<id> [OUT=<file>]
dollar-impact:
	@if [ -z "$(WS)" ] || [ -z "$(CANDIDATE)" ]; then \
	  echo 'Usage: make dollar-impact WS=<workspace> CANDIDATE=<id> [OUT=<file>]'; \
	  exit 2; \
	fi
	@python3 tools/dollar-impact-model.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --candidate-id "$(CANDIDATE)" \
	  --output "$(if $(OUT),$(OUT),$(_WS_RESOLVED)/audit/corpus_tags/derived/dollar_impact/$(CANDIDATE).json)"

# mimo-harness-hunt: MIMO bulk hunt with full MCP context grounding.
# Default (SCOPED): if <ws>/.auditooor/per_fn_hacker_questions.jsonl exists and N
#   is not explicitly set, uses per-fn-mimo-batch-gen.py with the ranked per-fn
#   questions (N = actual line count, e.g. 285). Avoids the N=2007 generic corpus
#   blunt default and fires only the ranked, source-grounded workspace units.
# CORPUS fallback: if per_fn_hacker_questions.jsonl is absent OR N=<n> is passed,
#   falls back to mimo-harness-batch-gen.py with hacker_questions_library (N=2007).
# Usage: make mimo-harness-hunt WS=<ws> [N=2007] [CONC=20] [LANE=<id>]
#         N=<n>  forces corpus mode with N generic questions even if per_fn file exists.
mimo-harness-hunt:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make mimo-harness-hunt WS=<workspace> [N=2007] [CONC=20]'; \
	  exit 2; \
	fi
	@_wsname=$$(basename "$(_WS_RESOLVED)"); \
	  _lane="$${LANE:-$$_wsname-HARNESS-$$(date +%Y-%m-%d)}"; \
	  _conc="$${CONC:-20}"; \
	  if [ -z "$(N)" ]; then \
	    python3 tools/ensure-per-fn-questions.py --workspace "$(_WS_RESOLVED)" \
	      || echo "[mimo-harness-hunt] WARN: per-fn worklist could not be auto-built; falling back to blunt corpus mode (see .auditooor/per_fn_questions_generation_defect.json)" >&2; \
	  fi; \
	  _per_fn_base="$(_WS_RESOLVED)/.auditooor/per_fn_hacker_questions.jsonl"; \
	  if [ -f "$${_per_fn_base}.ranked.jsonl" ]; then _per_fn="$${_per_fn_base}.ranked.jsonl"; else _per_fn="$${_per_fn_base}"; fi; \
	  if [ -z "$(N)" ] && [ -f "$$_per_fn" ]; then \
	    _n=$$(wc -l < "$$_per_fn" | tr -d ' '); \
	    _batch="/tmp/mimo_harness_$${_wsname}_scoped_n$${_n}_batch.jsonl"; \
	    _outdir="$$PWD/audit/corpus_tags/derived/mimo_harness_$${_wsname}_scoped_n$${_n}"; \
	    echo "[mimo-harness-hunt] SCOPED mode: per_fn_hacker_questions.jsonl exists with $${_n} ranked units (pass N=2007 to force corpus mode)"; \
	    python3 tools/per-fn-mimo-batch-gen.py \
	      --ranked-questions "$$_per_fn" --workspace "$(_WS_RESOLVED)" \
	      --output "$$_batch" --max-tasks "$$_n"; \
	  else \
	    _n="$${N:-2007}"; \
	    _batch="/tmp/mimo_harness_$${_wsname}_n$${_n}_batch.jsonl"; \
	    _outdir="$$PWD/audit/corpus_tags/derived/mimo_harness_$${_wsname}_n$${_n}"; \
	    echo "[mimo-harness-hunt] CORPUS mode: N=$${_n} generic questions from hacker_questions_library (per_fn_hacker_questions.jsonl absent or N override)"; \
	    python3 tools/mimo-harness-batch-gen.py \
	      --workspace-name "$$_wsname" --workspace-path "$(_WS_RESOLVED)" \
	      --num-questions "$$_n" --lane-id "$$_lane" --output "$$_batch"; \
	  fi; \
	  mkdir -p "$$_outdir"; \
	  echo "[mimo-harness-hunt] firing dispatcher (conc=$$_conc) ..."; \
	  KEY=$$(grep '^KEY4=' /Users/wolf/.auditooor/mimo_keys.env | cut -d= -f2-); \
	  URL=$$(grep '^MIMO_BASE_URL_KEY4=' /Users/wolf/.auditooor/mimo_keys.env | cut -d= -f2-); \
	  MIMO_API_KEY=$$KEY MIMO_BASE_URL=$$URL \
	    AUDITOOOR_LLM_NETWORK_CONSENT=1 AUDITOOOR_UNIVERSAL_BYPASS=1 \
	    AUDITOOOR_MIMO_DISABLE_THINKING=1 \
	    python3 tools/llm-fanout-dispatcher.py \
	      --provider "$${PROVIDER:-local-cli}" --task-batch "$$_batch" --concurrency "$$_conc" \
	      --output-dir "$$_outdir" --overwrite-existing \
	      --monitor-jsonl "/tmp/mimo_harness_$${_wsname}_n$${_n}_monitor.jsonl" \
	      --retry-max 3 --backoff-base-s 30 --per-task-timeout-s 180

# r36-rebuttal: lane bug-fix-and-haiku-2026-05-28
# haiku-harness-plan: build Agent-tool-ready batch prompts for Haiku-via-OAuth
# mining. Replaces MIMO when KEY5 is rate-limited / API key unavailable.
# Default (SCOPED): if <ws>/.auditooor/per_fn_hacker_questions.jsonl exists and N
#   is not explicitly set, uses per-fn-mimo-batch-gen.py with the ranked per-fn
#   questions (N = actual line count). Avoids N=2007 generic corpus blunt default.
# CORPUS fallback: per_fn_hacker_questions.jsonl absent OR N=<n> explicit.
# Operator workflow:
#   1. make haiku-harness-plan WS=<workspace> [N=2007] [BATCH=25]
#      N=<n> forces corpus mode even when per_fn file exists.
#   2. orchestrator Claude session dispatches Agent(model='haiku') on each
#      audit/corpus_tags/derived/haiku_harness_<ws>/_haiku_plan/agent_batch_*.md
#   3. After all batches complete, run learning loop:
#      make mimo-corpus-mine (consumes haiku_harness_<ws>/<task_id>.json sidecars)
.PHONY: scoped-hunt-plan haiku-harness-plan
# scoped-hunt-plan is the MODEL-neutral canonical name (default model = sonnet);
# haiku-harness-plan is a retained back-compat alias (the model is NOT haiku).
scoped-hunt-plan haiku-harness-plan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make haiku-harness-plan WS=<workspace> [N=2007] [BATCH=25]'; \
	  exit 2; \
	fi
	@_wsname=$$(basename "$(_WS_RESOLVED)"); \
	  _lane="$${LANE:-$$_wsname-HAIKU-$$(date +%Y-%m-%d)}"; \
	  _batch_size="$${BATCH:-25}"; \
	  if [ -z "$(N)" ]; then \
	    python3 tools/ensure-per-fn-questions.py --workspace "$(_WS_RESOLVED)" \
	      || echo "[scoped-hunt-plan] WARN: per-fn worklist could not be auto-built; falling back to blunt corpus mode (see .auditooor/per_fn_questions_generation_defect.json)" >&2; \
	  fi; \
	  _per_fn_base="$(_WS_RESOLVED)/.auditooor/per_fn_hacker_questions.jsonl"; \
	  if [ -f "$${_per_fn_base}.ranked.jsonl" ]; then _per_fn="$${_per_fn_base}.ranked.jsonl"; else _per_fn="$${_per_fn_base}"; fi; \
	  if [ -z "$(N)" ] && [ -f "$$_per_fn" ]; then \
	    if [ -n "$(AUDITOOOR_HUNT_FULL)" ] || [ -n "$(HUNT_FULL)" ]; then \
	      _per_fn_scoped="$$_per_fn"; \
	      echo "[haiku-harness-plan] AUDITOOOR_HUNT_FULL set: FULL re-hunt over the entire ranked worklist (residual-scoping DISABLED)"; \
	    else \
	      _per_fn_scoped="$${_per_fn}.residual.jsonl"; \
	      python3 tools/residual-scope-per-fn.py --workspace "$(_WS_RESOLVED)" \
	        --ranked "$$_per_fn" --output "$$_per_fn_scoped" \
	        || { echo "[haiku-harness-plan] WARN residual-scope-per-fn failed; falling back to FULL worklist" >&2; _per_fn_scoped="$$_per_fn"; }; \
	      if [ ! -s "$$_per_fn_scoped" ]; then _per_fn_scoped="$$_per_fn"; fi; \
	    fi; \
	    _per_fn="$$_per_fn_scoped"; \
	    _n=$$(wc -l < "$$_per_fn" | tr -d ' '); \
	    _batch="/tmp/haiku_harness_$${_wsname}_scoped_n$${_n}_batch.jsonl"; \
	    _outdir="$$PWD/audit/corpus_tags/derived/haiku_harness_$${_wsname}_scoped_n$${_n}"; \
	    echo "[haiku-harness-plan] SCOPED mode: hunting $${_n} residual-scoped units (set AUDITOOOR_HUNT_FULL=1 to re-hunt all, or N=2007 for corpus mode)"; \
	    python3 tools/per-fn-mimo-batch-gen.py \
	      --ranked-questions "$$_per_fn" --workspace "$(_WS_RESOLVED)" \
	      --output "$$_batch" --max-tasks "$$_n"; \
	  else \
	    _n="$${N:-2007}"; \
	    _batch="/tmp/haiku_harness_$${_wsname}_n$${_n}_batch.jsonl"; \
	    _outdir="$$PWD/audit/corpus_tags/derived/haiku_harness_$${_wsname}_n$${_n}"; \
	    echo "[haiku-harness-plan] CORPUS mode: N=$${_n} generic questions from hacker_questions_library (per_fn_hacker_questions.jsonl absent or N override)"; \
	    python3 tools/mimo-harness-batch-gen.py \
	      --workspace-name "$$_wsname" --workspace-path "$(_WS_RESOLVED)" \
	      --num-questions "$$_n" --lane-id "$$_lane" --output "$$_batch"; \
	  fi; \
	  mkdir -p "$$_outdir"; \
	  echo "[haiku-harness-plan] building Agent dispatch plan (batch-size $${_batch_size})..."; \
	  python3 tools/haiku-fanout-dispatcher.py plan \
	    --task-batch "$$_batch" \
	    --output-dir "$$_outdir" \
	    --batch-size "$$_batch_size" \
	    --model "$${MODEL:-sonnet}"; \
	  echo ""; \
	  echo "Operator next: dispatch each $$_outdir/_haiku_plan/agent_batch_*.md via Agent(model=$${MODEL:-sonnet}) (per-fn hunt defaults to sonnet; haiku was low-signal/hallucination-prone - pass MODEL=haiku to override)"

.PHONY: hunt-scoped hunt-haiku
# hunt-scoped: canonical per-function scoped-hunt entry (MODEL-neutral name).
# Use when the API providers (deepseek / mimo) are unavailable - the hunt runs on
# the operator's Claude sub via the Agent tool (OAuth), NOT a subprocess, so it
# cannot be an auto subprocess fallback. DEFAULT MODEL = sonnet (haiku was
# low-signal / hallucination-prone; pass MODEL=haiku to override). This target
# generates the Agent-ready batch plan (scoped-hunt-plan, alias haiku-harness-plan)
# and records a typed obligation so audit-run-full / audit-complete report
# 'orchestrator-dispatch-required' instead of a silent 0-records hunt. The
# orchestrator (Claude session / a Workflow of model lanes) then dispatches
# Agent(model=$(MODEL:-sonnet)) on each batch and runs `make mimo-corpus-mine`.
# `hunt-haiku` is a retained back-compat alias - the model is NOT haiku by default.
# _PREHUNT_ENUM_ON is non-empty ONLY when AUDITOOOR_PREHUNT_MATRIX or
# AUDITOOOR_PLANE_DRAIN is set to a truthy value (present and not 0/false/no).
# Gating at the MAKE level (not a runtime shell `if`) means the enumeration
# sub-target dispatch is literally ABSENT from `make -n hunt-scoped` when the env
# is unset, so env-unset is byte-identical to the legacy hunt-scoped (the
# byte-parity contract). The complex shell body lives in the _hunt-prehunt-enum
# sub-target so the outer $(if ...) argument stays a single simple token (no
# commas / nested $(if ...) to confuse Make's function-argument parser).
_PREHUNT_ENUM_ON := $(strip $(filter-out 0 false no,$(or $(AUDITOOOR_PREHUNT_MATRIX),1)) $(filter-out 0 false no,$(AUDITOOOR_PLANE_DRAIN)))
# In the ordered strict driver, every pre-hunt reasoner is load-bearing.  Keep
# the existing per-reasoner switches, but provide one generic fan-out so a new
# workspace cannot silently consume a degraded reasoner result.
_PREHUNT_FAILCLOSED_VARS := \
  AUDITOOOR_PREHUNT_ACCTCONFUSION_FAILCLOSED \
  AUDITOOOR_PREHUNT_AMMSTRUCT_FAILCLOSED \
  AUDITOOOR_PREHUNT_ARITHHALT_FAILCLOSED \
  AUDITOOOR_PREHUNT_ATOMICSEQ_FAILCLOSED \
  AUDITOOOR_PREHUNT_AUTHZEXHAUST_FAILCLOSED \
  AUDITOOOR_PREHUNT_COMPNOVELTY_FAILCLOSED \
  AUDITOOOR_PREHUNT_COUPLEDSTATE_FAILCLOSED \
  AUDITOOOR_PREHUNT_CROSSIMPL_FAILCLOSED \
  AUDITOOOR_PREHUNT_DEGENVERDICT_FAILCLOSED \
  AUDITOOOR_PREHUNT_DIRM_FAILCLOSED \
  AUDITOOOR_PREHUNT_DIRROUNDING_FAILCLOSED \
  AUDITOOOR_PREHUNT_EPOCHREPLAY_FAILCLOSED \
  AUDITOOOR_PREHUNT_FREEZEDOS_FAILCLOSED \
  AUDITOOOR_PREHUNT_GOBITCOIN_FAILCLOSED \
  AUDITOOOR_PREHUNT_GOROUTINERACE_FAILCLOSED \
  AUDITOOOR_PREHUNT_HAIRCUT_FAILCLOSED \
  AUDITOOOR_PREHUNT_INGEST_FAILCLOSED \
  AUDITOOOR_PREHUNT_MPCPROOF_FAILCLOSED \
  AUDITOOOR_PREHUNT_MSPANIC_FAILCLOSED \
  AUDITOOOR_PREHUNT_NONDETDESER_FAILCLOSED \
  AUDITOOOR_PREHUNT_NUMBOUNDARY_FAILCLOSED \
  AUDITOOOR_PREHUNT_ORACLESPOT_FAILCLOSED \
  AUDITOOOR_PREHUNT_PUSHPAY_FAILCLOSED \
  AUDITOOOR_PREHUNT_RETURNALIAS_FAILCLOSED \
  AUDITOOOR_PREHUNT_ROR_FAILCLOSED \
  AUDITOOOR_PREHUNT_SETDIFF_FAILCLOSED \
  AUDITOOOR_PREHUNT_SLICEOOB_FAILCLOSED \
  AUDITOOOR_PREHUNT_STALEACCRUAL_FAILCLOSED \
  AUDITOOOR_PREHUNT_TCCEI_FAILCLOSED \
  AUDITOOOR_PREHUNT_TRUSTGRAPH_FAILCLOSED \
  AUDITOOOR_PREHUNT_UNBOUNDEDALLOC_FAILCLOSED \
  AUDITOOOR_PREHUNT_XCHAINFORGERY_FAILCLOSED \
  AUDITOOOR_PREHUNT_ZKCONSTRAINT_FAILCLOSED
_PREHUNT_FAILCLOSED_ARGS := $(if $(filter 1 true yes,$(AUDITOOOR_PIPELINE_STRICT) $(STRICT)),$(foreach v,$(_PREHUNT_FAILCLOSED_VARS),$(v)=1))
# B2: audit-deep is a PREREQUISITE of the canonical scoped-hunt entry so a cold/
# stale ws cannot reach a reasoner (LOGIC #4 atomic-sequence / DIRM / composition
# / assumption-negation) over ABSENT/STALE substrate (value_moving_functions,
# oracle_reachability, state_coupling_edges, PISVS derived invariants). audit-deep
# + its own `audit` prereq are freshness-gated, so a WARM ws short-circuits
# cheaply; a COLD ws materializes the substrate first. The prereq is gated on
# HUNT_SKIP_DEEP_PREREQ: a driver that ALREADY ran audit-deep THIS pass (audit-
# pipeline-full STEP 2) sets HUNT_SKIP_DEEP_PREREQ=1 to avoid a redundant re-run,
# while a STANDALONE `make hunt-scoped` (var unset) keeps the prereq so
# `make -n hunt-scoped` shows audit-deep. No cycle: audit-deep -> audit only, and
# `audit` has no hunt-scoped prereq.
_HUNT_SCOPED_DEEP_PREREQ := $(if $(HUNT_SKIP_DEEP_PREREQ),,audit-deep)
hunt-scoped hunt-haiku: $(_HUNT_SCOPED_DEEP_PREREQ)
	@# === PRE-HUNT ENUMERATION (A1/A2/B* rewire; DEFAULT-ON, opt-OUT) ==========
	@# THE GAP this closes: the enumerate-BEFORE-hunt producers only ran inside
	@# `make audit-pipeline-full` STEP 2.9 (audit-deep materializes coverage_plane
	@# via tools/coverage-plane-build.py). The canonical loop entry `make hunt-scoped`
	@# never ran them, so on a cold / stale workspace the A2 plane-drain in
	@# per-fn-mimo-batch-gen.py / inscope-hunt-batch-builder.py had NO
	@# .auditooor/coverage_plane.jsonl to drain -> the hunt scoped only to the
	@# coverage-RESIDUAL units instead of the FULL (in-scope unit x impact-frame)
	@# not-enumerated surface (Primacy-of-Impact). The _hunt-prehunt-enum sub-target
	@# MATERIALIZES the plane + completeness worklist + mechanism sidecars BEFORE the
	@# plan build so the A2 drain seeds the full surface across ALL in-scope assets.
	@# Gate: DEFAULT-ON; opt-OUT via AUDITOOOR_PREHUNT_MATRIX=0 (or false/no). An
	@# unset AUDITOOOR_PREHUNT_MATRIX now defaults to 1 (see _PREHUNT_ENUM_ON above,
	@# via $(or ...,1)), so the make-if below dispatches _hunt-prehunt-enum by
	@# default; only an explicit 0/false/no expands it to nothing. AUDITOOOR_PLANE_DRAIN
	@# behavior is unchanged (still opt-in and additive).
	$(if $(_PREHUNT_ENUM_ON),@set -eu; \
	  _prehunt_log="$(_WS_RESOLVED)/.auditooor/prehunt_strict.log"; \
	  $(MAKE) --no-print-directory _hunt-prehunt-enum WS="$(WS)" $(_PREHUNT_FAILCLOSED_ARGS) $(if $(JSON),JSON=1) >"$$_prehunt_log" 2>&1 || { \
	    _rc=$$?; cat "$$_prehunt_log"; exit "$$_rc"; \
	  }; \
	  cat "$$_prehunt_log"; \
	  if [ -n "$(_PREHUNT_FAILCLOSED_ARGS)" ] && grep -Eq '(^|[[:space:]])WARN|compile-DEGRADED|advisory' "$$_prehunt_log"; then \
	    echo "[hunt-scoped] ERROR: strict pre-hunt rejected warning/degraded output; see $$_prehunt_log" >&2; exit 1; \
	  fi)
	@# FORK-DELTA MATERIALIZE: for a FORK target, unmodified-upstream code is OOS.
	@# Materialize <ws>/.auditooor/fork_modified/<name>.json ONCE (git-clone ->
	@# go-mod-cache fallback -> unresolved keep-all) so residual-scope-per-fn.py can
	@# DROP unmodified-upstream units from the residual (they never reach an agent)
	@# and per-fn-mimo-batch-gen.py can hand each fork unit a fork_delta_status.
	@# Only (re)runs when fork_bases.json exists AND the artifact is absent/stale
	@# (older than fork_bases.json); non-fatal (advisory, keep-all on any failure).
	@if [ -f "$(_WS_RESOLVED)/.auditooor/fork_bases.json" ]; then \
	  _fmdir="$(_WS_RESOLVED)/.auditooor/fork_modified"; \
	  _fresh=1; \
	  if [ ! -d "$$_fmdir" ] || [ -z "$$(ls -A "$$_fmdir" 2>/dev/null)" ]; then _fresh=0; \
	  else for _a in "$$_fmdir"/*.json; do \
	         [ -f "$$_a" ] || continue; \
	         if [ "$(_WS_RESOLVED)/.auditooor/fork_bases.json" -nt "$$_a" ]; then _fresh=0; fi; \
	       done; fi; \
	  if [ "$$_fresh" = "0" ]; then \
	    echo "[hunt-scoped] fork-delta: materializing .auditooor/fork_modified/*.json (unmodified-upstream OOS drop)"; \
	    python3 tools/materialize-fork-modified.py --workspace "$(_WS_RESOLVED)" \
	      || echo "[hunt-scoped] WARN materialize-fork-modified failed; KEEP-ALL fork units (completeness-safe, no under-scope)" >&2; \
	  else \
	    echo "[hunt-scoped] fork-delta: fork_modified artifacts fresh (newer than fork_bases.json); reusing"; \
	  fi; \
	fi
	@$(MAKE) --no-print-directory haiku-harness-plan WS="$(WS)" $(if $(N),N="$(N)") BATCH="$(if $(BATCH),$(BATCH),10)" LANE="$(if $(LANE),$(LANE),)"

.PHONY: _hunt-prehunt-enum
# _hunt-prehunt-enum: pre-hunt ENUMERATION producers (internal; dispatched from
# hunt-scoped ONLY when AUDITOOOR_PREHUNT_MATRIX / AUDITOOOR_PLANE_DRAIN is truthy).
# Materializes the FULL (in-scope unit x impact-frame) surface so the A2 plane-drain
# has a plane to read. Only (re)runs the producers when the plane is ABSENT or STALE
# (older than inscope_units.jsonl) so a warm re-run is cheap. Non-fatal (advisory,
# mirrors audit-deep) - each producer failure warns-and-continues. Producers reuse
# the SAME invocations the drivers already call:
#   coverage-plane-build.py --workspace          (audit-deep ~L5070; writes the plane)
#   completeness-matrix-build.py --enumerate-only (STEP 2.9 ~L6775; worklist + matrix)
#   mechanism-scan-run.py --workspace            (mechanism sidecars; best-effort)
_hunt-prehunt-enum:
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@_plane="$(_WS_RESOLVED)/.auditooor/coverage_plane.jsonl"; \
	  _inscope="$(_WS_RESOLVED)/.auditooor/inscope_units.jsonl"; \
	  if [ ! -f "$$_plane" ] || { [ -f "$$_inscope" ] && [ "$$_inscope" -nt "$$_plane" ]; }; then \
	    echo "[hunt-scoped] pre-hunt ENUMERATION: plane absent/stale -> materializing the FULL (in-scope unit x impact-frame) surface BEFORE the plan build (A1/A2)"; \
	    python3 tools/coverage-plane-build.py --workspace "$(_WS_RESOLVED)" || \
	      echo "[hunt-scoped] WARN coverage-plane-build failed; continuing (advisory)" >&2; \
	    python3 tools/completeness-matrix-build.py --workspace "$(_WS_RESOLVED)" --enumerate-only $(if $(JSON),--json) || \
	      echo "[hunt-scoped] WARN completeness-matrix --enumerate-only failed; continuing (advisory)" >&2; \
	    python3 tools/mechanism-scan-run.py --workspace "$(_WS_RESOLVED)" || \
	      echo "[hunt-scoped] WARN mechanism-scan-run failed; continuing (advisory)" >&2; \
	  else \
	    echo "[hunt-scoped] pre-hunt ENUMERATION: coverage_plane.jsonl fresh (newer than inscope_units.jsonl); reusing materialized plane (warm re-run)"; \
	  fi
	@# ORDER-rewire (LOGIC_ARSENAL_ROADMAP "ORDER"): the guard-negative-space
	@# worklist + sibling-path guard-asymmetry index + INVARIANT_LEDGER ingest used
	@# to run ONLY inside `make audit-depth`, which the pipeline runs AFTER the
	@# scoped hunt - so the per-fn hunt could never STEER on them. This staleness-
	@# gated ingest MOVES them into the pre-hunt window so the negspace/asym index
	@# is populated BEFORE the plan build (they feed the OPEN-OBLIGATIONS block).
	@# Advisory-first: an empty negspace/asym index only WARNs today; flip to
	@# fail-closed next wave via AUDITOOOR_PREHUNT_INGEST_FAILCLOSED=1. Non-fatal
	@# (echo-warn-and-continue) so it never blocks the scoped-hunt recipe.
	@python3 tools/prehunt-negspace-asym-ingest.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_INGEST_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN prehunt-negspace-asym-ingest non-zero (advisory unless AUDITOOOR_PREHUNT_INGEST_FAILCLOSED=1); continuing" >&2
	@# LOGIC #3 (Euler donateToReserves set-difference): compute the SET-DIFFERENCE
	@# {downward-mutation entrypoints} \ {those whose fwd closure reaches a
	@# post-state solvency/health check} over the OWNED go-dataflow/slither closure
	@# (dataflow_paths.jsonl, auto-unioning any scoped dataflow_paths.*.jsonl) and
	@# emit each survivor as an unguarded-mutation-entrypoint obligation. Runs
	@# BEFORE the plan build so exploit-queue.py
	@# (_gather_from_unguarded_mutation_obligations) ingests it into the queue that
	@# per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block. Advisory-first:
	@# a fully-degraded dataflow substrate only WARNs today; flip to fail-closed
	@# next wave via AUDITOOOR_PREHUNT_SETDIFF_FAILCLOSED=1. Non-fatal.
	@python3 tools/callgraph-set-difference-hunter.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_SETDIFF_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN callgraph-set-difference-hunter non-zero (advisory unless AUDITOOOR_PREHUNT_SETDIFF_FAILCLOSED=1); continuing" >&2
	@# CROSS-CHAIN FORGERY (Nomad $$190M / Wormhole $$325M set-difference): compute
	@# the SET-DIFFERENCE {inbound cross-chain message handlers whose closure acts
	@# on the inbound payload (mint/release/execute)} \ {those whose closure reaches
	@# an authenticity-binding node - verified merkle root / signature-quorum verify
	@# / replay-nonce-receipt guard / source-chain lookup} over the OWNED
	@# go-dataflow/slither closure (dataflow_paths.jsonl, auto-unioning any scoped
	@# dataflow_paths.*.jsonl) and emit each survivor as a crosschain-message-forgery
	@# obligation. Runs BEFORE the plan build so exploit-queue.py
	@# (_gather_from_crosschain_forgery_obligations) ingests it into the queue that
	@# per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block. Advisory-first: a
	@# fully-absent dataflow substrate only WARNs today; flip to fail-closed next
	@# wave via AUDITOOOR_PREHUNT_XCHAINFORGERY_FAILCLOSED=1. Non-fatal.
	@python3 tools/crosschain-message-authenticity-reasoner.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_XCHAINFORGERY_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN crosschain-message-authenticity-reasoner non-zero (advisory unless AUDITOOOR_PREHUNT_XCHAINFORGERY_FAILCLOSED=1); continuing" >&2
	@# ORACLE SPOT-PRICE MANIPULATION (Mango $$114M / Cheese / Inverse set-difference):
	@# compute {entrypoints whose value-decision (borrow/mint/liquidation/withdraw) is
	@# priced by a SPOT single-block read - getReserves/slot0/balance-ratio/
	@# instantaneous NAV} \ {those whose fwd closure reaches a TWAP / cumulative-price
	@# / independent-second-source / deviation-bound node} over the OWNED go-dataflow/
	@# slither closure (dataflow_paths.jsonl, auto-unioning any scoped
	@# dataflow_paths.*.jsonl) and emit each survivor as an oracle-spot-price-
	@# manipulation obligation. Runs BEFORE the plan build so exploit-queue.py
	@# (_gather_from_oracle_spot_price_obligations) ingests it into the queue that
	@# per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block. Advisory-first: a
	@# fully-degraded dataflow substrate only WARNs today; flip to fail-closed next
	@# wave via AUDITOOOR_PREHUNT_ORACLESPOT_FAILCLOSED=1. Non-fatal.
	@python3 tools/oracle-spot-price-manipulation-reasoner.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_ORACLESPOT_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN oracle-spot-price-manipulation-reasoner non-zero (advisory unless AUDITOOOR_PREHUNT_ORACLESPOT_FAILCLOSED=1); continuing" >&2
	@# READ-ONLY VIEW REENTRANCY (Curve get_virtual_price LP-oracle / Valantis
	@# VLTS3-13 set-difference COMPOSED_ACROSS_WINDOW\GUARDED): over the OWNED Slither
	@# CFG/IR backend, compute {view getters composing >=2 mutable state components a
	@# callback-window mutator (write -> untrusted-extcall -> write) rewrites, carrying
	@# NO nonReentrant/lock guard}, JOINED to the dataflow_paths.jsonl value-release
	@# consumer reading G, and emit each survivor as a read-only-view-reentrancy
	@# obligation. Runs BEFORE the plan build so exploit-queue.py
	@# (_gather_from_readonly_view_reentrancy_obligations) ingests it into the queue
	@# that per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block. A pure
	@# Go/Cosmos workspace is a clean language-not-applicable no-op. Advisory-first: a
	@# DEGRADED (uncompilable) sol substrate only WARNs today; flip to fail-closed next
	@# wave via AUDITOOOR_PREHUNT_ROR_FAILCLOSED=1. Non-fatal.
	@python3 tools/read-only-view-reentrancy-unguarded-composite-getter.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_ROR_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN read-only-view-reentrancy-unguarded-composite-getter non-zero (advisory unless AUDITOOOR_PREHUNT_ROR_FAILCLOSED=1); continuing" >&2
	@# STALE LAZY-ACCRUAL (RFIN-26 / FNG-11 / FNG-17 set-difference
	@# READERS\DOMINATED): build the intra-repo call graph and emit each entrypoint
	@# that reads a lazily-materialized accumulator Q (debt/health/exchangeRate/NAV/
	@# accruedInterest/pendingReward) to authorize a fund move but whose fwd closure
	@# calls NO accrual/checkpoint fn before the read. Runs BEFORE the plan build so
	@# exploit-queue.py (_gather_from_stale_accrual_obligations) ingests it into the
	@# queue that per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block.
	@# Advisory-first: a vacuous (0-fn) source substrate only WARNs today; flip to
	@# fail-closed next wave via AUDITOOOR_PREHUNT_STALEACCRUAL_FAILCLOSED=1. Non-fatal.
	@python3 tools/stale-accrual-before-value-gate-dominance.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_STALEACCRUAL_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN stale-accrual-before-value-gate-dominance non-zero (advisory unless AUDITOOOR_PREHUNT_STALEACCRUAL_FAILCLOSED=1); continuing" >&2
	@# COUPLED-STATE COMPLETENESS (Aptos struct-hijack / ERC-4626 desync set-diff
	@# FLUSHED(P) proper-subset FULL(G)): a mutating path flushes only a SUBSET of a
	@# coupled must-move-together state group (cache+source / mirrored balance /
	@# index<->value / totalShares<->totalAssets) while a SIBLING path flushes the
	@# FULL set - the un-flushed member(s) are left STALE (desync / type-confusion).
	@# Runs BEFORE the plan build so exploit-queue.py
	@# (_gather_from_coupled_state_completeness_obligations) ingests it into the
	@# queue that per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block.
	@# Advisory-first: a vacuous (0-fn) substrate only WARNs today; flip to fail-
	@# closed via AUDITOOOR_PREHUNT_COUPLEDSTATE_FAILCLOSED=1. Non-fatal.
	@python3 tools/coupled-state-completeness-graph.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_COUPLEDSTATE_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN coupled-state-completeness-graph non-zero (advisory unless AUDITOOOR_PREHUNT_COUPLEDSTATE_FAILCLOSED=1); continuing" >&2
	@# ASYMMETRIC ROUNDING-DIRECTION (ERC-4626 preview/convert rounding-direction /
	@# share-price-truncation directional dataflow-difference mode(V) VIOLATES the
	@# protocol-favoring owed-direction D(V)): a fixed-point value conversion rounds
	@# AGAINST the protocol (in the user's favor) on a value leg (owes-out rounds up
	@# / takes-in rounds down) OR a mirror pair rounds the SAME direction on both
	@# legs - the sub-wei residual COMPOUNDS over a batch / repeated call -> drain.
	@# Runs BEFORE the plan build so exploit-queue.py
	@# (_gather_from_directional_rounding_obligations) ingests it into the queue that
	@# per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block. Advisory-first: a
	@# vacuous (0-fn) substrate only WARNs today; flip to fail-closed via
	@# AUDITOOOR_PREHUNT_DIRROUNDING_FAILCLOSED=1. Non-fatal.
	@python3 tools/directional-rounding-asymmetry.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_DIRROUNDING_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN directional-rounding-asymmetry non-zero (advisory unless AUDITOOOR_PREHUNT_DIRROUNDING_FAILCLOSED=1); continuing" >&2
	@# GO CONSENSUS-HALT (must-succeed panic reachability): JOIN the go-dataflow
	@# `-panic-sinks` records (attacker-param -> panic-capable SSA node) with the
	@# go_entrypoint_surface MUST-SUCCEED ABCI/module-lifecycle family, emitting each
	@# attacker-tainted panic node reachable from a non-recover-wrapped consensus
	@# entrypoint as a mustsucceed-panic-reachability obligation. Runs BEFORE the plan
	@# build so exploit-queue.py (_gather_from_mustsucceed_panic_obligations) ingests
	@# it into the queue that per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS
	@# block. Advisory-first: a starved panic substrate only WARNs today; flip to
	@# fail-closed next wave via AUDITOOOR_PREHUNT_MSPANIC_FAILCLOSED=1. Non-fatal.
	@python3 tools/go-mustsucceed-panic-reachability.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_MSPANIC_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN go-mustsucceed-panic-reachability non-zero (advisory unless AUDITOOOR_PREHUNT_MSPANIC_FAILCLOSED=1); continuing" >&2
	@# LOGIC #7 (cross-contract privilege-trust graph): compute the SET-DIFFERENCE
	@# {dispatcher/verifier TARGETS the trust graph shows are trusted} \ {targets
	@# that are IMMUTABLE or membership/authz-VALIDATED before trust} over the OWNED
	@# arch-delegation-trust-closure Solidity backend + the go-dataflow closure, and
	@# emit each payload-derived, non-immutable, unvalidated trusted target as a
	@# payload-derived-trusted-dispatch obligation. Runs BEFORE the plan build so
	@# exploit-queue.py (_gather_from_payload_derived_trusted_dispatch) ingests it
	@# into the queue that per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS
	@# block. Advisory-first: a fully-absent trust substrate only WARNs today; flip
	@# to fail-closed next wave via AUDITOOOR_PREHUNT_TRUSTGRAPH_FAILCLOSED=1. Non-fatal.
	@python3 tools/cross-contract-privilege-trust-graph.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_TRUSTGRAPH_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN cross-contract-privilege-trust-graph non-zero (advisory unless AUDITOOOR_PREHUNT_TRUSTGRAPH_FAILCLOSED=1); continuing" >&2
	@# ACCOUNT CONFUSION (Solana/Rust owner/signer/key set-difference): compute the
	@# SET-DIFFERENCE {caller-supplied account params reaching an authority-use
	@# sink} \ {those whose flow closure carries an owner/signer/key-equality
	@# check} over the OWNED rust-dataflow/go-dataflow/slither closure
	@# (dataflow_paths.jsonl, auto-unioning any scoped dataflow_paths.*.jsonl) and
	@# emit each survivor as an account-owner-signer-confusion obligation (an
	@# attacker substitutes a look-alike account the program trusts as the
	@# authority). Runs BEFORE the plan build so exploit-queue.py
	@# (_gather_from_account_confusion_obligations) ingests it into the queue that
	@# per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block. Advisory-first:
	@# a fully-degraded dataflow substrate only WARNs today; flip to fail-closed
	@# next wave via AUDITOOOR_PREHUNT_ACCTCONFUSION_FAILCLOSED=1. Non-fatal.
	@python3 tools/rust-account-owner-signer-confusion.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_ACCTCONFUSION_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN rust-account-owner-signer-confusion non-zero (advisory unless AUDITOOOR_PREHUNT_ACCTCONFUSION_FAILCLOSED=1); continuing" >&2
	@# LOGIC #8 (adversarial numeric boundary): DERIVE, per fixed-point/tick/
	@# amount math (fn,param) in the OWNED go-dataflow/slither closure, the exact
	@# numeric-domain boundary set (type extrema + guard partition points +-1 +
	@# fixed-point scale / tick edges), EMIT executable fuzz seeds, and emit the
	@# SET-DIFFERENCE {math fns with a derived boundary domain} \ {those already
	@# exercised by a mutation-verified boundary seed} as an unseeded-numeric-
	@# boundary obligation. Runs BEFORE the plan build so exploit-queue.py
	@# (_gather_from_numeric_boundary_obligations) ingests it into the queue that
	@# per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block. Advisory-first:
	@# flip to fail-closed via AUDITOOOR_PREHUNT_NUMBOUNDARY_FAILCLOSED=1.
	@python3 tools/adversarial-numeric-boundary-seeder.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_NUMBOUNDARY_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN adversarial-numeric-boundary-seeder non-zero (advisory unless AUDITOOOR_PREHUNT_NUMBOUNDARY_FAILCLOSED=1); continuing" >&2
	@# RUST value-overflow (unchecked-arith): compute the MIR-taint SET-DIFFERENCE
	@# {arith over an untrusted-param operand reaching a value/threshold use} \
	@# {checked arith (checked_/saturating_/*WithOverflow+assert/bound-guarded)} and
	@# emit each survivor as an unchecked-arith-value-overflow obligation. Runs
	@# BEFORE the plan build so exploit-queue.py
	@# (_gather_from_rust_unchecked_arith_obligations) ingests it into the queue that
	@# per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block. Rust-only; a
	@# no-Rust-crate workspace degrades to a harmless cited-empty marker (exit 0).
	@python3 tools/rust-unchecked-arith-value-overflow.py --workspace "$(_WS_RESOLVED)" --emit \
	  || echo "[hunt-scoped] WARN rust-unchecked-arith-value-overflow non-zero (advisory); continuing" >&2
	@# LOGIC #6 (verification-gate degenerate-input set-difference): compute the
	@# SET-DIFFERENCE {verification/proof/status/root admission gates} \ {those
	@# whose validated closure branches on the verified input's zero/empty/default
	@# value} over the OWNED go-dataflow/slither closure (dataflow_paths.jsonl,
	@# auto-unioning any scoped dataflow_paths.*.jsonl) and emit each survivor as a
	@# degenerate-input-unverdicted-gate obligation (ecrecover(0) / empty-proof /
	@# empty-signer-set admission bypass). Runs BEFORE the plan build so
	@# exploit-queue.py (_gather_from_degenerate_input_verdict_obligations) ingests
	@# it into the queue that per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS
	@# block. Advisory-first: a fully-degraded dataflow substrate only WARNs today;
	@# flip to fail-closed next wave via AUDITOOOR_PREHUNT_DEGENVERDICT_FAILCLOSED=1.
	@# Non-fatal.
	@python3 tools/default-degenerate-input-verdict-reasoner.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_DEGENVERDICT_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN default-degenerate-input-verdict-reasoner non-zero (advisory unless AUDITOOOR_PREHUNT_DEGENVERDICT_FAILCLOSED=1); continuing" >&2
	@# LOGIC #5 (value-realization-without-haircut set-difference): compute
	@# {value-release entrypoints: borrow/withdraw/quote paths over an external value}
	@# \ {those whose fwd closure applies a HAIRCUT (LTV/collateral-factor/discount)
	@# OR a SECOND-SOURCE cross-check (oracle deviation/TWAP-vs-spot/two-oracle
	@# min|max/pre-post balance-snapshot conservation)} over the OWNED
	@# go-dataflow/slither closure (dataflow_paths.jsonl, auto-unioning any scoped
	@# dataflow_paths.*.jsonl), JOINED to the conservation/haircut invariant family in
	@# invariant_ledger.json, and emit each survivor as a conservation-haircut-
	@# realization obligation. Runs BEFORE the plan build so exploit-queue.py
	@# (_gather_from_conservation_haircut_obligations) ingests it into the queue that
	@# per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block. Advisory-first: a
	@# fully-degraded dataflow substrate only WARNs today; flip to fail-closed next
	@# wave via AUDITOOOR_PREHUNT_HAIRCUT_FAILCLOSED=1. Non-fatal.
	@python3 tools/conservation-haircut-realization-check.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_HAIRCUT_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN conservation-haircut-realization-check non-zero (advisory unless AUDITOOOR_PREHUNT_HAIRCUT_FAILCLOSED=1); continuing" >&2
	@# ========================================================================
	@# B2 SUBSTRATE HOIST: the reasoners that follow read substrate that was
	@# previously materialized LATER (state_coupling_edges only inside audit-deep;
	@# .auditooor/pisvs/derived_invariants.jsonl only LAZILY, via composition-novelty
	@# / assumption-negation --autorun-producers which run AFTER DIRM at ~L4941). On
	@# a cold/stale ws the LOGIC #4 atomic-sequencer (reads state_coupling_edges +
	@# value_moving_functions shared-ledger fields), DIRM (reads InvariantsOf(target)
	@# from the PISVS derivation), and the oracle-manipulation lanes (read
	@# oracle_reachability_hypotheses) all ran over ABSENT substrate -> SUBSTRATE_
	@# VACUOUS. Materialize ALL THREE producers HERE, ahead of atomic-sequence (LOGIC
	@# #4) + DIRM, so every downstream reasoner reads a durable, fresh substrate.
	@# Non-fatal (advisory, echo-warn-and-continue; mirrors the audit-deep house
	@# style + the readme step-2b-pisvs SUBSTRATE-PRODUCER ordering fix).
	@if [ "$${AUDITOOOR_PREHUNT_PRODUCERS_READY:-0}" = "1" ]; then \
	  echo "[hunt-scoped] substrate producers already completed by ordered Step 1d; reusing fresh outputs"; \
	else \
	  python3 tools/state-coupling-graph.py --workspace "$(_WS_RESOLVED)" --emit \
	    || echo "[hunt-scoped] WARN state-coupling-graph emit failed; continuing (advisory)" >&2; \
	  python3 tools/oracle-reachability-lane.py "$(_WS_RESOLVED)" \
	    || echo "[hunt-scoped] WARN oracle-reachability-lane failed; continuing (advisory)" >&2; \
	  python3 tools/protocol-invariant-synth-violation-search.py "$(_WS_RESOLVED)" \
	    || echo "[hunt-scoped] WARN PISVS (protocol-invariant-synth-violation-search) failed; continuing (advisory)" >&2; \
	fi
	@# LOGIC #4 (atomic economic sequence): a PATH query over the OWNED state-edge
	@# graph (state_coupling_edges + value_moving_functions shared-ledger fields).
	@# Emits ordered (borrowed-source -> coupled value-cell mutation -> spend)
	@# triples that carry NO atomicity guard (borrow->pump->withdraw /
	@# deposit->donate->liquidate). Runs BEFORE the plan build so exploit-queue.py
	@# (_gather_from_atomic_sequence_obligations) ingests it into the queue that
	@# per-fn-mimo-batch-gen turns into the OPEN-OBLIGATIONS block on the SPEND fn.
	@# Advisory-first: absent state-edge backends only WARN today; flip to
	@# fail-closed next wave via AUDITOOOR_PREHUNT_ATOMICSEQ_FAILCLOSED=1. Non-fatal.
	@python3 tools/atomic-sequence-economic-sequencer.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_ATOMICSEQ_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN atomic-sequence-economic-sequencer non-zero (advisory unless AUDITOOOR_PREHUNT_ATOMICSEQ_FAILCLOSED=1); continuing" >&2
	@# WIRING WAVE (8 SHIP-verified pre-hunt reasoners). Each emits its obligation
	@# ledger which exploit-queue.py ingests + per-fn-mimo-batch-gen folds into the
	@# OPEN-OBLIGATIONS block. Advisory-first; flip fail-closed per the named env knob.
	@# GO must-succeed arith overflow/div-zero consensus-halt (step-2e-go-arith-halt).
	@python3 tools/go-mustsucceed-arith-overflow-halt.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_ARITHHALT_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN go-mustsucceed-arith-overflow-halt non-zero (advisory unless AUDITOOOR_PREHUNT_ARITHHALT_FAILCLOSED=1); continuing" >&2
	@# PERMANENT-FREEZE DoS: exit-fn dominance + no-sibling-bypass (step-2d-permanent-freeze).
	@python3 tools/permanent-freeze-dos.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_FREEZEDOS_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN permanent-freeze-dos non-zero (advisory unless AUDITOOOR_PREHUNT_FREEZEDOS_FAILCLOSED=1); continuing" >&2
	@# AUTHZ type-exhaustiveness: dispatch type-universe vs handled-set (step-2d-authz-exhaustiveness).
	@python3 tools/authz-type-exhaustiveness.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_AUTHZEXHAUST_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN authz-type-exhaustiveness non-zero (advisory unless AUDITOOOR_PREHUNT_AUTHZEXHAUST_FAILCLOSED=1); continuing" >&2
	@# TCCEI transitive cross-contract CEI / read-only reentrancy (step-2d-transitive-cei).
	@python3 tools/transitive-crosscontract-cei.py --workspace "$(_WS_RESOLVED)" --emit \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_TCCEI_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN transitive-crosscontract-cei non-zero (advisory unless AUDITOOOR_PREHUNT_TCCEI_FAILCLOSED=1); continuing" >&2
	@# AMM structural-accounting coupled-update desync (step-2d-amm-structural).
	@python3 tools/amm-structural-manipulation.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_AMMSTRUCT_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN amm-structural-manipulation non-zero (advisory unless AUDITOOOR_PREHUNT_AMMSTRUCT_FAILCLOSED=1); continuing" >&2
	@# GOROUTINE shared-mutable-state race (lock-set difference) (step-2d-goroutine-race).
	@python3 tools/goroutine-shared-state-race.py --workspace "$(_WS_RESOLVED)" --emit \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_GOROUTINERACE_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN goroutine-shared-state-race non-zero (advisory unless AUDITOOOR_PREHUNT_GOROUTINERACE_FAILCLOSED=1); continuing" >&2
	@# ZK constraint-coverage (5 predicates; honest no-op on non-zk) (step-2f-zk-constraint).
	@python3 tools/zk-constraint-coverage.py --workspace "$(_WS_RESOLVED)" --predicate all --emit \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_ZKCONSTRAINT_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN zk-constraint-coverage non-zero (advisory unless AUDITOOOR_PREHUNT_ZKCONSTRAINT_FAILCLOSED=1); continuing" >&2
	@# DIRM differential invariant residual (runs AFTER PISVS which supplies target invariants) (step-2g-differential-residual).
	@python3 tools/differential-invariant-residual-miner.py --workspace "$(_WS_RESOLVED)" --emit \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_DIRM_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN differential-invariant-residual-miner non-zero (advisory unless AUDITOOOR_PREHUNT_DIRM_FAILCLOSED=1); continuing" >&2
	@# WIRING WAVE (4 reasoners + assumption-negation novelty engine). Each emits its
	@# obligation ledger which exploit-queue.py ingests + per-fn-mimo-batch-gen folds
	@# into the OPEN-OBLIGATIONS block. Advisory-first; flip fail-closed per env knob.
	@# CROSS-IMPL consensus divergence (lenient vs strict acceptance-set) (step-2d-crossimpl-divergence).
	@python3 tools/crossimpl-consensus-divergence.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_CROSSIMPL_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN crossimpl-consensus-divergence non-zero (advisory unless AUDITOOOR_PREHUNT_CROSSIMPL_FAILCLOSED=1); continuing" >&2
	@# SLICE-OOB untrusted length/offset -> OOB slice/copy/pointer taint (step-2d-slice-oob).
	@python3 tools/slice-oob-bounds-taint.py --workspace "$(_WS_RESOLVED)" --emit --json \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_SLICEOOB_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN slice-oob-bounds-taint non-zero (advisory unless AUDITOOOR_PREHUNT_SLICEOOB_FAILCLOSED=1); continuing" >&2
	@# EPOCH/nonce/key uniqueness-replay set-difference (step-2d-epoch-replay).
	@python3 tools/epoch-restake-replay.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_EPOCHREPLAY_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN epoch-restake-replay non-zero (advisory unless AUDITOOOR_PREHUNT_EPOCHREPLAY_FAILCLOSED=1); continuing" >&2
	@# COMPOSITION-NOVELTY op-pair search reuses ordered Step 1d substrates and is bounded (step-2g-composition-novelty).
	@_comp_to=""; if command -v gtimeout >/dev/null 2>&1; then _comp_to="gtimeout --kill-after=30 -s TERM $${AUDITOOOR_PREHUNT_COMPNOVELTY_TIMEOUT:-900}"; elif command -v timeout >/dev/null 2>&1; then _comp_to="timeout --kill-after=30 -s TERM $${AUDITOOOR_PREHUNT_COMPNOVELTY_TIMEOUT:-900}"; fi; \
	  if [ -z "$$_comp_to" ]; then echo "[hunt-scoped] ERROR composition-novelty-search requires gtimeout/timeout; refusing an unbounded pre-hunt reasoner" >&2; exit 1; fi; \
	  _comp_autorun="--autorun-producers"; if [ "$${AUDITOOOR_PREHUNT_PRODUCERS_READY:-0}" = "1" ]; then _comp_autorun=""; echo "[hunt-scoped] composition-novelty-search reusing ordered Step 1d substrates"; fi; \
	  $$_comp_to python3 tools/composition-novelty-search.py --workspace "$(_WS_RESOLVED)" --emit $$_comp_autorun \
	    $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_COMPNOVELTY_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN composition-novelty-search non-zero (advisory unless AUDITOOOR_PREHUNT_COMPNOVELTY_FAILCLOSED=1); continuing" >&2
	@# ASSUMPTION-NEGATION reachability novelty engine #3 reuses ordered substrates and is bounded (step-2g-assumption-negation).
	@_assump_to=""; if command -v gtimeout >/dev/null 2>&1; then _assump_to="gtimeout --kill-after=30 -s TERM $${AUDITOOOR_PREHUNT_ASSUMPTION_TIMEOUT:-900}"; elif command -v timeout >/dev/null 2>&1; then _assump_to="timeout --kill-after=30 -s TERM $${AUDITOOOR_PREHUNT_ASSUMPTION_TIMEOUT:-900}"; fi; \
	  if [ -z "$$_assump_to" ]; then echo "[hunt-scoped] ERROR assumption-negation-reachability requires gtimeout/timeout; refusing an unbounded pre-hunt reasoner" >&2; exit 1; fi; \
	  _assump_autorun="--autorun-producers"; if [ "$${AUDITOOOR_PREHUNT_PRODUCERS_READY:-0}" = "1" ]; then _assump_autorun=""; echo "[hunt-scoped] assumption-negation-reachability reusing ordered Step 1d substrates"; fi; \
	  $$_assump_to python3 tools/assumption-negation-reachability.py --workspace "$(_WS_RESOLVED)" $$_assump_autorun --fail-closed \
	  || { echo "[hunt-scoped] ERROR assumption-negation-reachability failed; repair the required pre-hunt producer before continuing" >&2; exit 1; }
	@# IMPACT-FIRST BACKWARD SEARCH: mega-impact sink reached via unguarded path + unguarded backward entrypoint (novelty engine #3, impact-first modality). Advisory-first (step-2g-impact-first).
	@python3 tools/impact-first-backward-search.py --workspace "$(_WS_RESOLVED)" \
	  || echo "[hunt-scoped] WARN impact-first-backward-search non-zero (advisory); continuing" >&2
	@# WIRING WAVE (6 SHIP-verified reasoners). Each emits its obligation ledger
	@# which exploit-queue.py ingests (+ per-fn-mimo-batch-gen folds into the
	@# OPEN-OBLIGATIONS block). Runs BEFORE the plan build so step-3 is steered.
	@# PUSH-PAYMENT MISROUTE recipient-provenance vs recorded-owner set-diff (step-2d-push-payment).
	@python3 tools/push-payment-misroute.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_PUSHPAY_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN push-payment-misroute non-zero (advisory unless AUDITOOOR_PREHUNT_PUSHPAY_FAILCLOSED=1); continuing" >&2
	@# RETURN-ALIASING ESCAPE returned ref aliases persistent state, no defensive copy (step-2d-return-aliasing).
	@python3 tools/return-aliasing-escape.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_RETURNALIAS_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN return-aliasing-escape non-zero (advisory unless AUDITOOOR_PREHUNT_RETURNALIAS_FAILCLOSED=1); continuing" >&2
	@# UNBOUNDED-ALLOC resource-exhaustion untrusted-size-taint minus bound-dominance (step-2d-unbounded-alloc).
	@python3 tools/unbounded-alloc-resource-exhaustion.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_UNBOUNDEDALLOC_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN unbounded-alloc-resource-exhaustion non-zero (advisory unless AUDITOOOR_PREHUNT_UNBOUNDEDALLOC_FAILCLOSED=1); continuing" >&2
	@# NONDET-DESERIALIZATION on consensus path (Go-only) (step-2d-nondet-deser).
	@python3 tools/nondeterministic-deserialization.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_NONDETDESER_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN nondeterministic-deserialization non-zero (advisory unless AUDITOOOR_PREHUNT_NONDETDESER_FAILCLOSED=1); continuing" >&2
	@# GO-BITCOIN SPV-bridge validation-obligation set-difference (Go-only, CRIT) (step-2d-go-bitcoin).
	@python3 tools/go-bitcoin-protocol-validation.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_GOBITCOIN_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN go-bitcoin-protocol-validation non-zero (advisory unless AUDITOOOR_PREHUNT_GOBITCOIN_FAILCLOSED=1); continuing" >&2
	@# MPC per-round proof-obligation (rust/tofn GG20 CONSUME minus PROVEN, CRIT) (step-2d-mpc-proof).
	@python3 tools/mpc-round-proof-obligation.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PREHUNT_MPCPROOF_FAILCLOSED)),--fail-closed) \
	  || echo "[hunt-scoped] WARN mpc-round-proof-obligation non-zero (advisory unless AUDITOOOR_PREHUNT_MPCPROOF_FAILCLOSED=1); continuing" >&2
	@# NOVELTY FLYWHEEL: mint NEW corpus classes from corpus_class=null NOVEL
	@# invariant-violation candidates (grounded file:line); runs AFTER the novelty
	@# engines (PISVS/DIRM/composition/assumption) so the VCIS candidate set exists.
	@# EMITS .auditooor/novelty/{new_classes,burndown_feed}.jsonl; the minted classes
	@# are folded into the corpus-coverage-burndown build-queue as uncovered
	@# build-obligations, and the underlying NOVEL obligation blocks via
	@# logic-obligation-resolution (step-2g-novelty-flywheel). Advisory-first: a ws
	@# with 0 derived-invariant candidates fail-louds (non-fatal here).
	@python3 tools/novelty-gate-flywheel.py "$(_WS_RESOLVED)" --json \
	  || echo "[hunt-scoped] WARN novelty-gate-flywheel non-zero (0 candidates / no VCIS = nothing to mint); continuing" >&2
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@# FIX C.2: the obligation carries the coverage-gate RESIDUAL (residual_surface_units
	@# + a residual-reflecting status: 'residual-hunt-required' when uncovered units
	@# remain, 'complete' when the coverage gate is green) instead of the old flat
	@# 'orchestrator-dispatch-required' (which read like 'not planned').
	@python3 tools/residual-scope-per-fn.py --workspace "$(_WS_RESOLVED)" \
	  --emit-obligation "$(_WS_RESOLVED)/.auditooor/hunt_provider_obligation.json" \
	  || printf '%s\n' '{"schema":"auditooor.hunt_provider_obligation.v1","hunt_provider":"agent-via-orchestrator","model_default":"sonnet","status":"residual-unknown-dispatch-required","residual_surface_units":0,"reason":"residual-scope-per-fn.py failed; the per-function hunt runs via the orchestrator Agent tool (defaults to model=sonnet), not a subprocess","next":["dispatch each _haiku_plan/agent_batch_*.md via Agent(model=sonnet) (route through tools/spawn-worker.sh)","make mimo-corpus-mine WS=<ws>"]}' > "$(_WS_RESOLVED)/.auditooor/hunt_provider_obligation.json"
	@echo "[hunt-scoped] batch plan generated + obligation recorded (with coverage residual) -> orchestrator dispatches Agent(model=$(if $(MODEL),$(MODEL),sonnet)) per batch, then: make mimo-corpus-mine WS=$(_WS_RESOLVED)"
	@# anchor-lead pipeline (advisory, non-fatal): commit-anchor-lead-emit.py turns
	@# OOS security-shaped fix-commits into in-scope anchor leads
	@# (<ws>/.auditooor/anchor_leads.jsonl); anchor-lead-to-hunt-task.py then turns
	@# every lead with >=1 in-scope sibling into a scoped hunt task
	@# (<ws>/.auditooor/anchor_hunt_tasks.jsonl). Both were previously standalone
	@# capabilities nothing in hunt-scoped ever called, so the emitted tasks sat
	@# unread. Wired here, in order, non-fatal (echo-warn-and-continue) so this
	@# never blocks the scoped-hunt recipe.
	@python3 tools/commit-anchor-lead-emit.py --workspace "$(_WS_RESOLVED)" || echo "[hunt-scoped] WARN commit-anchor-lead-emit.py failed (non-fatal, advisory); continuing"
	@python3 tools/anchor-lead-to-hunt-task.py --workspace "$(_WS_RESOLVED)" || echo "[hunt-scoped] WARN anchor-lead-to-hunt-task.py failed (non-fatal, advisory); continuing"
	@_anchor_tasks="$(_WS_RESOLVED)/.auditooor/anchor_hunt_tasks.jsonl"; \
	  if [ -f "$$_anchor_tasks" ]; then \
	    _anchor_n=$$(grep -c . "$$_anchor_tasks" 2>/dev/null || echo 0); \
	  else \
	    _anchor_n=0; \
	  fi; \
	  echo "[hunt-scoped] $$_anchor_n anchor hunt task(s) written to $$_anchor_tasks - dispatch via spawn-worker.sh, one per task"

.PHONY: hunt-dispatch
# hunt-dispatch: CANONICAL step-3 dispatch wrapper (the Rule-3 path). Routes EVERY
# batch of the current scoped-hunt plan through tools/spawn-worker.sh so each
# dispatch is LOGGED to .auditooor/spawn_worker_log.jsonl (ledger + prior-lane-scan
# + RANDOM-DISPATCH-GUARD) - which the hunt-dispatch-provenance guard requires. A
# raw Agent/Workflow fan-out over the batch files BYPASSES that ledger (the slip
# this target prevents). Uses --no-prebriefing because haiku-fanout-dispatcher
# already embedded the META-1 block in each batch, so spawn-worker logs+guards
# WITHOUT double-enriching. Emits a manifest of prompt paths; the orchestrator then
# dispatches Agent(model) on each. Run `make hunt-scoped` first to build the plan.
hunt-dispatch:
	@if [ -z "$(WS)" ]; then echo 'Usage: make hunt-dispatch WS=<workspace> [MODEL=sonnet]'; exit 2; fi
	@_wsname=$$(basename "$(_WS_RESOLVED)"); \
	  _plandir=$$(ls -dt "$$PWD"/audit/corpus_tags/derived/haiku_harness_$${_wsname}_scoped_n*/_haiku_plan 2>/dev/null | head -1); \
	  if [ -z "$$_plandir" ] || [ ! -d "$$_plandir" ]; then \
	    echo "[hunt-dispatch] ERROR: no scoped-hunt plan for $$_wsname (run: make hunt-scoped WS=$(_WS_RESOLVED))"; exit 2; fi; \
	  _manifest="$(_WS_RESOLVED)/.auditooor/hunt_dispatch_manifest.txt"; : > "$$_manifest"; \
	  _n=0; _fail=0; \
	  for b in "$$_plandir"/agent_batch_*.md; do \
	    [ -f "$$b" ] || continue; \
	    _bn=$$(basename "$$b" .md | sed 's/agent_batch_//'); \
	    _ep=$$(SPAWN_WORKER_BYPASS_REASON="batch pre-enriched by haiku-fanout-dispatcher (META-1 present); spawn-worker for ledger+guard" \
	      bash tools/spawn-worker.sh --no-prebriefing --no-use-worktree --lane-id "$${_wsname}-hunt-b$${_bn}" --lane-type hunt --severity HIGH \
	      --workspace "$(_WS_RESOLVED)" --prompt-file "$$b" 2>/dev/null | tail -1); \
	    if [ -n "$$_ep" ] && [ -f "$$_ep" ]; then echo "$$_ep" >> "$$_manifest"; _n=$$((_n+1)); else _fail=$$((_fail+1)); fi; \
	  done; \
	  echo "[hunt-dispatch] logged $$_n batch dispatch(es) to spawn_worker_log.jsonl ($$_fail failed); manifest: $$_manifest"; \
	  echo "[hunt-dispatch] provenance now LEDGER-backed -> orchestrator: Agent(model=$(if $(MODEL),$(MODEL),sonnet)) on each path in the manifest, then make mimo-corpus-mine WS=$(_WS_RESOLVED)"

.PHONY: hunt-sidecar-reconcile
# Reconcile the current scoped-hunt plan against canonical provider sidecars.
# This emits the provider receipt only when every planned task has an exact,
# parseable sidecar. A nonzero exit is a hard blocker for downstream stages.
hunt-sidecar-reconcile:
	@if [ -z "$(WS)" ]; then echo 'Usage: make hunt-sidecar-reconcile WS=<workspace> [PROVIDER=sonnet-via-agent]'; exit 2; fi
	@_wsname=$$(basename "$(_WS_RESOLVED)"); \
	  _plandir=$$(ls -dt "$$PWD"/audit/corpus_tags/derived/haiku_harness_$${_wsname}_scoped_n*/_haiku_plan 2>/dev/null | head -1); \
	  if [ -z "$$_plandir" ]; then echo "[hunt-sidecar-reconcile] ERROR: no scoped plan for $$_wsname"; exit 2; fi; \
	  python3 tools/hunt-provider-sidecar-reconcile.py \
	    --workspace "$(_WS_RESOLVED)" --plan-dir "$$_plandir" \
	    --sidecar-dir "$(_WS_RESOLVED)/.auditooor/hunt_findings_sidecars" \
	    --provider "$${PROVIDER:-sonnet-via-agent}" \
	    --receipt "$(_WS_RESOLVED)/.auditooor/provider_dispatch_receipt.json"

.PHONY: hunt-residual-llm-depth
# hunt-residual-llm-depth: residual-scoped LLM-depth hunt. Reads the residual
# worker queue (<ws>/.auditooor/coverage_residual_worker_queue.json, written by
# auto-coverage-closer.py) and runs an LLM hunt sized to the residual surface
# units the deterministic pass left UNRESOLVED, then bridges the sidecars back.
# Mirrors the body of mimo-harness-hunt (batch-gen -> llm-fanout-dispatcher
# -> hunt-sidecar-bridge) but scopes N to the residual unit count instead of the
# full 2007-question corpus, so we only spend LLM budget on the surface that
# still needs depth.
#
# CONSENT-GATED: an actual provider call only happens when the operator opts in
# via AUDITOOOR_LLM_HUNT=1 (or LIVE=1). Without consent the target writes the
# typed hunt_provider_obligation.json (mirroring hunt-haiku) so audit-complete
# reports 'residual-llm-depth-consent-required' instead of a silent 0-records
# hunt. Advisory: never fatal here; the HARD authority is L37 at audit-complete.

.PHONY: hunt-followup-leads
# hunt-followup-leads: generic, language-agnostic closer for agent-flagged
# "maybe"/follow-up-worthy hunt leads (SEI 2026-07-05). Scans
# <ws>/.auditooor/hunt_findings_sidecars/*.json for applies_to_target=maybe
# or notes-field follow-up language, dedupes by (file, function), and emits
# a scoped hunt task per open lead. Run after the complete hunt wave so every
# flagged lead is either resolved with evidence or blocks the ordered pipeline.
hunt-followup-leads:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt-followup-leads WS=<workspace>'; exit 2; fi
	python3 tools/hunt-followup-lead-scanner.py --workspace "$(_WS_RESOLVED)" --emit
	python3 tools/followup-lead-completeness-check.py --workspace "$(_WS_RESOLVED)" --strict

hunt-residual-llm-depth:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt-residual-llm-depth WS=<workspace> [AUDITOOOR_LLM_HUNT=1|LIVE=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "hunt-residual-llm-depth" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@_queue="$(_WS_RESOLVED)/.auditooor/coverage_residual_worker_queue.json"; \
	  if [ ! -f "$$_queue" ]; then \
	    echo "[hunt-residual-llm-depth] NOTE no residual queue ($$_queue); nothing to hunt (run make audit / auto-coverage-closer first). Skipping."; \
	    exit 0; \
	  fi; \
	  _resid=$$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(int(d.get("residual_surface_units") or 0))' "$$_queue" 2>/dev/null || echo 0); \
	  if [ "$$_resid" -le 0 ]; then \
	    echo "[hunt-residual-llm-depth] residual_surface_units=0; deterministic pass left no unresolved units. Skipping."; \
	    exit 0; \
	  fi; \
	  _wsname=$$(basename "$(_WS_RESOLVED)"); \
	  _lane="$${LANE:-$$_wsname-RESIDUAL-LLM-$$(date +%Y-%m-%d)}"; \
	  _n="$$_resid"; _conc="$${CONC:-10}"; \
	  if [ -z "$(AUDITOOOR_LLM_HUNT)$(LIVE)" ]; then \
	    printf '%s\n' '{"schema":"auditooor.hunt_provider_obligation.v1","hunt_provider":"residual-llm-depth","status":"consent-required","reason":"residual_surface_units left unresolved by the deterministic pass; an LLM-depth hunt needs operator consent (AUDITOOOR_LLM_HUNT=1 or LIVE=1)","residual_surface_units":'"$$_resid"',"next":["make hunt-residual-llm-depth WS=<ws> AUDITOOOR_LLM_HUNT=1","python3 tools/hunt-sidecar-bridge.py --workspace <ws>"]}' > "$(_WS_RESOLVED)/.auditooor/hunt_provider_obligation.json"; \
	    echo "[hunt-residual-llm-depth] residual_surface_units=$$_resid but no consent -> wrote hunt_provider_obligation.json (set AUDITOOOR_LLM_HUNT=1 or LIVE=1 to run). Advisory; continuing."; \
	    exit 0; \
	  fi; \
	  _batch="/tmp/residual_llm_$${_wsname}_n$${_n}_batch.jsonl"; \
	  _outdir="$$PWD/audit/corpus_tags/derived/residual_llm_$${_wsname}_n$${_n}"; \
	  echo "[hunt-residual-llm-depth] residual_surface_units=$$_resid -> generating scoped batch ($$_n tasks)..."; \
	  _batch_to=""; if command -v gtimeout >/dev/null 2>&1; then _batch_to="gtimeout --kill-after=30 -s TERM $${AUDITOOOR_MIMO_BATCH_TIMEOUT:-900}"; elif command -v timeout >/dev/null 2>&1; then _batch_to="timeout --kill-after=30 -s TERM $${AUDITOOOR_MIMO_BATCH_TIMEOUT:-900}"; fi; \
	  $$_batch_to python3 tools/mimo-harness-batch-gen.py \
	    --workspace-name "$$_wsname" --workspace-path "$(_WS_RESOLVED)" \
	    --num-questions "$$_n" --lane-id "$$_lane" --output "$$_batch" || { \
	      _batch_rc=$$?; echo "[hunt-residual-llm-depth] WARN batch-gen failed or exceeded $${AUDITOOOR_MIMO_BATCH_TIMEOUT:-900}s (rc=$$_batch_rc)" >&2; \
	      if [ "$(STRICT)" = "1" ]; then echo "[hunt-residual-llm-depth] STRICT=1: refusing to continue after incomplete residual-hunt obligations" >&2; exit $$_batch_rc; fi; exit 0; }; \
	  mkdir -p "$$_outdir"; \
	  echo "[hunt-residual-llm-depth] firing dispatcher (conc=$$_conc) ..."; \
	  KEY=$$(grep '^KEY4=' /Users/wolf/.auditooor/mimo_keys.env 2>/dev/null | cut -d= -f2-); \
	  URL=$$(grep '^MIMO_BASE_URL_KEY4=' /Users/wolf/.auditooor/mimo_keys.env 2>/dev/null | cut -d= -f2-); \
	  MIMO_API_KEY=$$KEY MIMO_BASE_URL=$$URL \
	    AUDITOOOR_LLM_NETWORK_CONSENT=1 AUDITOOOR_UNIVERSAL_BYPASS=1 \
	    AUDITOOOR_MIMO_DISABLE_THINKING=1 \
	    python3 tools/llm-fanout-dispatcher.py \
	      --provider "$${PROVIDER:-local-cli}" --task-batch "$$_batch" --concurrency "$$_conc" \
	      --output-dir "$$_outdir" --overwrite-existing \
	      --monitor-jsonl "/tmp/residual_llm_$${_wsname}_n$${_n}_monitor.jsonl" \
	      --retry-max 3 --backoff-base-s 30 --per-task-timeout-s 180 || { \
	      echo "[hunt-residual-llm-depth] WARN dispatcher failed; advisory, continuing" >&2; exit 0; }; \
	  python3 tools/hunt-sidecar-bridge.py --workspace "$(_WS_RESOLVED)" || \
	    echo "[hunt-residual-llm-depth] WARN hunt-sidecar-bridge failed; continuing (advisory)" >&2

# Test-only helper: print the make-resolved $(WS) (post tilde-expansion) on a
# single stdout line and exit. Used by tools/tests/test_makefile_tilde.sh to
# assert make-level path resolution WITHOUT coupling to audit-progress.py /
# engage.py log formats (Kimi K3 review of PR #171). Output shape:
#     [print-ws-resolved] <resolved-path>
# `<resolved-path>` is exactly what audit: would feed into `[ -d ... ]`.
# No filesystem side effects; safe to run with any WS value.
print-ws-resolved:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make print-ws-resolved WS=<workspace>'; exit 2; fi
	@printf '[print-ws-resolved] %s\n' "$(_WS_RESOLVED)"

control-status:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make control-status WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/auditooorctl.py status "$(_WS_RESOLVED)" $(if $(JSON),--json)

control-snapshot:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make control-snapshot WS=<workspace> [OUT=<path>]'; exit 2; fi
	@python3 tools/auditooorctl.py snapshot "$(_WS_RESOLVED)" $(if $(OUT),--out "$(OUT)")

control-handoff:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make control-handoff WS=<workspace> [AUDIENCE=claude|codex]'; exit 2; fi
	@python3 tools/auditooorctl.py handoff "$(_WS_RESOLVED)" --audience "$(if $(AUDIENCE),$(AUDIENCE),claude)"

control-plan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make control-plan WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/auditooorctl.py plan "$(_WS_RESOLVED)" $(if $(JSON),--json)

control-report:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make control-report WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/auditooorctl.py report "$(_WS_RESOLVED)" $(if $(JSON),--json)

control-gaps:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make control-gaps WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/auditooorctl.py gaps "$(_WS_RESOLVED)" $(if $(JSON),--json)

control-providers:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make control-providers WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/auditooorctl.py providers "$(_WS_RESOLVED)" $(if $(JSON),--json)

control-workpacks:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make control-workpacks WS=<workspace> [JSON=1] [OUT=<path>]'; exit 2; fi
	@python3 tools/auditooorctl.py workpacks "$(_WS_RESOLVED)" $(if $(OUT),--out "$(OUT)") $(if $(JSON),--json)

control-plane-ready:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make control-plane-ready WS=<workspace> [JSON=1] [STRICT=1] [OUT=<path>]'; exit 2; fi
	@python3 tools/control-plane-ready-preflight.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json) $(if $(OUT),--out "$(OUT)")

control-plane-ready-test:
	@python3 -m unittest tools.tests.test_control_plane_ready_preflight -v

# v3 Slice 4 - opt-in escalation atop `make audit`.
# Runs `make audit` first, then opportunistically invokes Halmos / Medusa /
# Echidna / Slither full-IR via tools/audit-deep.sh - gracefully skipping
# any tool not on PATH. See docs/TOOL_COST_BENEFIT.md for the cost-benefit
# rubric and per-tool tier (always-run / opt-in / debug-only).
#
# Critical contract: `audit-deep` MUST NOT break for users who have neither
# halmos nor medusa installed. The aggregator script always exits 0 unless
# the workspace argument itself is invalid. Guarded by
# tools/tests/test_audit_deep_target.sh.
#
# V5-P0-05 / Gap 45 note: the `audit` prerequisite carries its own
# completion-marker guard, so back-to-back `make audit && make audit-deep`
# does NOT silently re-run the 32-stage chain. The deep tools always run
# (they have their own per-profile artifacts). Use FORCE=1 to bust the
# audit chain freshness guard.
#
# L23 (ABG-deferred → ABK fix): `AUDIT_DEEP_SKIP_AUDIT_PREREQ=1` escape hatch.
# Some workspaces are driven outside the canonical engage loop (e.g. paste-
# ready engagements like ~/audits/spark where SESSION_LOG iteration rows are
# never populated because the canonical engage.py iteration loop was bypassed).
# For those workspaces the `audit` prerequisite HARD STOPs at
# `pre-iter-check.sh` ("SESSION_LOG.md has no iteration index table"), which
# makes `make audit-deep` unreachable even though the deep aggregator itself
# runs cleanly when invoked directly. The escape hatch lets operators
# explicitly bypass the audit prerequisite WHILE all other audit-deep gates
# (Go/DLT advisory scanner gate, invariant ledger gate, etc.) still fire
# inside `tools/audit-deep.sh`. Default-OFF; only fires with explicit env-var.
# See docs/next-loop/audit_deep_session_log_bootstrap_fix_l23_2026-05-08.md.
_AUDIT_MCP_TRUE_VALUES := 1 true TRUE True yes YES Yes on ON On
_AUDIT_DEEP_MCP_PREFLIGHT_ENABLED := $(if $(filter $(_AUDIT_MCP_TRUE_VALUES),$(strip $(AUDIT_DEEP_REQUIRE_MCP_PREFLIGHT)))$(filter $(_AUDIT_MCP_TRUE_VALUES),$(strip $(REQUIRE_MCP_CONTEXT))),1,)
_AUDIT_DEEP_PREREQ := $(if $(_AUDIT_DEEP_MCP_PREFLIGHT_ENABLED),,$(if $(AUDIT_DEEP_SKIP_AUDIT_PREREQ),,audit))

.PHONY: audit-mcp-preflight audit-mcp-preflight-test
audit-mcp-preflight:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-mcp-preflight WS=<workspace> [MCP_SCOPE=read] [REQUIRE_RECENT_RECALL=0] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-mcp-preflight" "$(_WS_RESOLVED)"
	@python3 tools/audit-mcp-preflight.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --scope "$(if $(MCP_SCOPE),$(MCP_SCOPE),read)" \
	  $(if $(filter 0 false no,$(REQUIRE_RECENT_RECALL)),,--require-recent-recall) \
	  $(if $(JSON),--json)

audit-mcp-preflight-test:
	@python3 -m unittest tools.tests.test_audit_mcp_preflight -v

audit-preflight:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-preflight WS=<workspace> [CONTRACT=<name-or-file>] [FUNCTION=<name>] [OUT_DIR=<path>] [LLM_ENRICH=1] [MCP_TIMEOUT=<seconds>] [MAX_FUNCTIONS=N] [DRY_RUN=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-preflight" "$(_WS_RESOLVED)"
	@python3 tools/per-function-preflight-orchestrator.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(CONTRACT),--contract "$(CONTRACT)") \
	  $(if $(FUNCTION),--function "$(FUNCTION)") \
	  $(if $(OUT_DIR),--output-dir "$(OUT_DIR)") \
	  $(if $(LLM_ENRICH),--llm-enrich) \
	  $(if $(MCP_TIMEOUT),--mcp-timeout "$(MCP_TIMEOUT)") \
	  $(if $(MAX_FUNCTIONS),--max-functions "$(MAX_FUNCTIONS)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

audit-preflight-test:
	@python3 -m unittest tools.tests.test_per_function_preflight_orchestrator -v

audit-deep: $(_AUDIT_DEEP_PREREQ)
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep WS=<workspace> [AUDIT_DEEP_SKIP_AUDIT_PREREQ=1] [AUDIT_DEEP_RUN_COMMIT_MINING=1] [AUDIT_DEEP_REQUIRE_MCP_PREFLIGHT=1|REQUIRE_MCP_CONTEXT=1]'; exit 2; fi
ifneq ($(_AUDIT_DEEP_MCP_PREFLIGHT_ENABLED),)
	@python3 tools/audit-mcp-preflight.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --scope "$(if $(MCP_SCOPE),$(MCP_SCOPE),read)" \
	  $(if $(filter 0 false no,$(REQUIRE_RECENT_RECALL)),,--require-recent-recall) \
	  $(if $(JSON),--json)
ifeq ($(AUDIT_DEEP_SKIP_AUDIT_PREREQ),)
	@$(MAKE) --no-print-directory audit WS="$(_WS_RESOLVED)"
endif
endif
	@if [ -n "$(AUDIT_DEEP_SKIP_AUDIT_PREREQ)" ]; then \
	  echo "[audit-deep] AUDIT_DEEP_SKIP_AUDIT_PREREQ=$(AUDIT_DEEP_SKIP_AUDIT_PREREQ) - bypassing 'audit' prerequisite."; \
	  echo "[audit-deep]   Use only for paste-ready-driven workspaces where the canonical"; \
	  echo "[audit-deep]   engage.py iteration loop was intentionally bypassed."; \
	  echo "[audit-deep]   All audit-deep internal gates (advisory scanner gate, invariant"; \
	  echo "[audit-deep]   ledger gate, etc.) STILL fire inside tools/audit-deep.sh."; \
	  if [ "$(AUDIT_DEEP_ALLOW_STALE_AUDIT_PREREQ)" != "1" ]; then \
	    marker_tool="tools/audit-completion-marker.py"; \
	    if command -v python3 >/dev/null 2>&1 && [ -f "$$marker_tool" ]; then \
	      fresh_rc=0; \
	      fresh_out="$$(env FORCE=0 python3 "$$marker_tool" check --workspace "$(_WS_RESOLVED)" 2>&1)" || fresh_rc=$$?; \
	      if [ $$fresh_rc -eq 0 ]; then \
	        echo "[audit-deep] freshness gate: PASS ($$fresh_out)"; \
	      else \
	        echo "[audit-deep] ERR AUDIT_DEEP_SKIP_AUDIT_PREREQ requires fresh audit_completion.json unless AUDIT_DEEP_ALLOW_STALE_AUDIT_PREREQ=1" >&2; \
	        echo "[audit-deep] freshness gate output: $$fresh_out" >&2; \
	        exit $$fresh_rc; \
	      fi; \
	    else \
	      echo "[audit-deep] WARN freshness gate unavailable (python3 or $$marker_tool missing); continuing" >&2; \
	    fi; \
	  else \
	    echo "[audit-deep] AUDIT_DEEP_ALLOW_STALE_AUDIT_PREREQ=1 - accepting stale/missing audit marker for explicit operator bypass."; \
	  fi; \
	fi
	@if [ -z "$(AUDIT_COMMIT_MINING_SKIP)" ] && { [ -n "$(AUDIT_DEEP_SKIP_AUDIT_PREREQ)" ] || [ "$(AUDIT_DEEP_RUN_COMMIT_MINING)" = "1" ]; }; then \
	  cm_rc=0 ; \
	  $(MAKE) --no-print-directory audit-target-commit-mining WS="$(_WS_RESOLVED)" $(if $(FORCE),FORCE=1) $(if $(COMMIT_MINING_WINDOW),COMMIT_MINING_WINDOW="$(COMMIT_MINING_WINDOW)") || cm_rc=$$? ; \
	  if [ $$cm_rc -ne 0 ]; then \
	    echo "[audit-deep] WARN audit-target-commit-mining failed rc=$$cm_rc before deep work" >&2 ; \
	    if [ $$cm_rc -eq 2 ]; then \
	      echo "[audit-deep] ERR audit-target-commit-mining prerequisite failed; populate targets.tsv before audit-deep" >&2 ; \
	      exit $$cm_rc ; \
	    fi ; \
	    if [ "$(STRICT)" = "1" ]; then \
	      echo "[audit-deep] NOTE audit-target-commit-mining is advisory under STRICT (commit-mining is scaffolding/intel that runs BEFORE the deep engines; the rc==2 targets.tsv prerequisite above still hard-fails). Continuing so the engines can run." >&2 ; \
	      : ; \
	    fi ; \
	  fi ; \
	elif [ -z "$(AUDIT_COMMIT_MINING_SKIP)" ]; then \
	  echo "[audit-deep] audit-target-commit-mining skipped because make audit already owns the default pre-deep mining step; set AUDIT_DEEP_RUN_COMMIT_MINING=1 only for an explicit deep-only re-run."; \
	fi
	@set -u; \
	ws="$(_WS_RESOLVED)"; \
	has_hardhat=0; has_foundry=0; has_sol_src=0; has_generic_src=0; \
	if find "$$ws" -maxdepth 2 -type f -name 'hardhat.config.*' -print -quit 2>/dev/null | grep -q .; then has_hardhat=1; fi; \
	if find "$$ws" -maxdepth 2 -type f -name 'foundry.toml' -print -quit 2>/dev/null | grep -q .; then has_foundry=1; fi; \
	if [ -d "$$ws/src" ] && find "$$ws/src" -type f -name '*.sol' -print -quit 2>/dev/null | grep -q .; then has_sol_src=1; fi; \
	if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' \) -prune -o \( -type f \( -name '*.rs' -o -name '*.go' -o -name 'go.mod' -o -name 'Cargo.toml' \) -print -quit \) 2>/dev/null | grep -q .; then has_generic_src=1; fi; \
	if [ "$$has_hardhat$$has_foundry$$has_sol_src" != "000" ]; then \
	  echo "[audit-deep] Solidity workspace detected; routing to audit-deep-solidity"; \
	  make --no-print-directory audit-deep-solidity WS="$$ws" || \
	  { _sol_rc=$$?; echo "[audit-deep] WARN audit-deep-solidity failed rc=$$_sol_rc" >&2; \
	    if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] STRICT=1: audit-deep-solidity is a load-bearing engine stage; exiting rc=$$_sol_rc" >&2; exit $$_sol_rc; fi; }; \
	  if { [ "$(LIVE)" = "1" ] || [ "$${AUDITOOOR_AUDIT_DEEP_LIVE:-}" = "1" ]; } && [ "$(DEEP_PROFILE)" = "all" ]; then \
	    echo "[audit-deep] Full live Solidity profile: executing generated per-function Halmos denominator"; \
	    make --no-print-directory audit-deep-solidity-per-function-harnesses WS="$$ws" $(if $(STRICT),STRICT=1); \
	    echo "[audit-deep] Full live Solidity profile: executing all engine harness roots"; \
	    make --no-print-directory audit-deep-solidity-all-harnesses WS="$$ws" $(if $(STRICT),STRICT=1); \
	  fi; \
	  make --no-print-directory audit-deep-ccia-attack-angles WS="$$ws" || \
	    echo "[audit-deep] WARN ccia-attack-angles failed; continuing (CCIA attack-angle output is advisory)" >&2; \
	  if [ "$$has_generic_src" = "1" ]; then \
	    echo "[audit-deep] Mixed-language workspace detected; running generic Rust/Go deep profile after Solidity engines"; \
	    bash tools/audit-deep.sh $(if $(LIVE),--live) $(if $(DEEP_PROFILE),--profile "$(DEEP_PROFILE)") $(if $(PROJECT_ROOT),--project-root "$(PROJECT_ROOT)") "$$ws" || \
	    { _ads_rc=$$?; echo "[audit-deep] WARN audit-deep.sh (mixed-lang) failed rc=$$_ads_rc" >&2; \
	      if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] STRICT=1: audit-deep.sh is a load-bearing engine stage; exiting rc=$$_ads_rc" >&2; exit $$_ads_rc; fi; }; \
	    python3 tools/fork-replay-cosmos-go.py --dry-run --workspace "$$ws" --finding-id AUDIT_DEEP || true; \
	    make --no-print-directory defimon-staleness-check || true; \
	    make --no-print-directory wave3-fp-runner WS="$$ws" || true; \
	    make --no-print-directory exploit-queue WS="$$ws" JSON=1 || \
	      echo "[audit-deep] WARN exploit-queue failed; continuing (exploit queue is advisory)" >&2; \
	    _has_go=0; _has_rust=0; \
	    if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/vendor' \) -prune -o \( -type f -name 'go.mod' -print -quit \) 2>/dev/null | grep -q .; then _has_go=1; fi; \
	    if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' \) -prune -o \( -type f -name 'Cargo.toml' -print -quit \) 2>/dev/null | grep -q .; then _has_rust=1; fi; \
	    if [ "$$_has_go" = "1" ]; then \
	      echo "[audit-deep] Mixed Sol+Go workspace: running Go native deep-engine + genuine-coverage producer (E-fix 2026-07-05: previously reached ONLY in the non-Solidity branch, so any Sol+Go monorepo silently skipped its Go engine)"; \
	      make --no-print-directory audit-deep-go-engine WS="$$ws" $(if $(STRICT),STRICT=1) $(if $(LIVE),LIVE=1) || \
	        echo "[audit-deep] WARN Go deep-engine returned non-zero; continuing (offline-safe)" >&2; \
	      make --no-print-directory _audit-deep-perlang-genuine-coverage WS="$$ws" LANG_HINT=go $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") $(if $(STRICT),STRICT=1) || \
	        { _pl_rc=$$?; if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] STRICT=1: Go genuine-coverage producer failed rc=$$_pl_rc; refusing to continue with incomplete substrate" >&2; exit $$_pl_rc; fi; echo "[audit-deep] WARN Go genuine-coverage producer returned non-zero; continuing (advisory)" >&2; }; \
	    fi; \
	    if [ "$$_has_rust" = "1" ]; then \
	      echo "[audit-deep] Mixed Sol+Rust workspace: running Rust proptest deep-engine + genuine-coverage producer (E-fix parity)"; \
	      make --no-print-directory audit-deep-rust-engine WS="$$ws" $(if $(STRICT),STRICT=1) $(if $(LIVE),LIVE=1) || \
	        echo "[audit-deep] WARN Rust deep-engine returned non-zero; continuing (offline-safe)" >&2; \
	      make --no-print-directory _audit-deep-perlang-genuine-coverage WS="$$ws" LANG_HINT=rust $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") $(if $(STRICT),STRICT=1) || \
	        { _pl_rc=$$?; if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] STRICT=1: Rust genuine-coverage producer failed rc=$$_pl_rc; refusing to continue with incomplete substrate" >&2; exit $$_pl_rc; fi; echo "[audit-deep] WARN Rust genuine-coverage producer returned non-zero; continuing (advisory)" >&2; }; \
	    fi; \
	  fi; \
	else \
	  bash tools/audit-deep.sh $(if $(LIVE),--live) $(if $(DEEP_PROFILE),--profile "$(DEEP_PROFILE)") $(if $(PROJECT_ROOT),--project-root "$(PROJECT_ROOT)") "$$ws" || \
	  { _ads_rc=$$?; echo "[audit-deep] WARN audit-deep.sh (non-solidity) failed rc=$$_ads_rc" >&2; \
	    if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] STRICT=1: audit-deep.sh is a load-bearing engine stage; exiting rc=$$_ads_rc" >&2; exit $$_ads_rc; fi; }; \
	  python3 tools/fork-replay-cosmos-go.py --dry-run --workspace "$$ws" --finding-id AUDIT_DEEP || true; \
	  make --no-print-directory defimon-staleness-check || true; \
	  make --no-print-directory wave3-fp-runner WS="$$ws" || true; \
	  make --no-print-directory exploit-queue WS="$$ws" JSON=1 || \
	    echo "[audit-deep] WARN exploit-queue failed; continuing (exploit queue is advisory)" >&2; \
	  has_go=0; has_rust=0; has_zk=0; has_move=0; has_cairo=0; has_cadence=0; \
	  if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/vendor' \) -prune -o \( -type f -name 'go.mod' -print -quit \) 2>/dev/null | grep -q .; then has_go=1; fi; \
	  if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' \) -prune -o \( -type f -name 'Cargo.toml' -print -quit \) 2>/dev/null | grep -q .; then has_rust=1; fi; \
	  if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' \) -prune -o \( -type f \( -name '*.circom' -o -name '*.zok' -o -name '*.nr' \) -print -quit \) 2>/dev/null | grep -q .; then has_zk=1; fi; \
	  if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/build' \) -prune -o \( -type f -name '*.move' -print -quit \) 2>/dev/null | grep -q .; then has_move=1; fi; \
	  if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' \) -prune -o \( -type f -name '*.cairo' -print -quit \) 2>/dev/null | grep -q .; then has_cairo=1; fi; \
	  if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' \) -prune -o \( -type f -name '*.cdc' -print -quit \) 2>/dev/null | grep -q .; then has_cadence=1; fi; \
	  if [ "$$has_zk" = "0" ] && [ "$$has_rust" = "1" ] && find "$$ws" \( -path '*/.git' -o -path '*/target' \) -prune -o \( -type f -name 'Cargo.toml' -print \) 2>/dev/null | xargs grep -lEi 'halo2|plonky2|arkworks|bellman|nova-snark|risc0|zk' 2>/dev/null | grep -q .; then has_zk=1; fi; \
	  if [ "$$has_go" = "1" ]; then \
	    echo "[audit-deep] Go workspace detected; running Go deep-engine + per-language genuine-coverage producer"; \
	    make --no-print-directory audit-deep-go-engine WS="$$ws" $(if $(STRICT),STRICT=1) $(if $(LIVE),LIVE=1) || \
	      echo "[audit-deep] WARN Go deep-engine returned non-zero; continuing (offline-safe)" >&2; \
	    make --no-print-directory _audit-deep-perlang-genuine-coverage WS="$$ws" LANG_HINT=go $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") $(if $(STRICT),STRICT=1) || \
	      { _pl_rc=$$?; if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] STRICT=1: Go genuine-coverage producer failed rc=$$_pl_rc; refusing to continue with incomplete substrate" >&2; exit $$_pl_rc; fi; echo "[audit-deep] WARN Go genuine-coverage producer returned non-zero; continuing (advisory)" >&2; }; \
	  fi; \
	  if [ "$$has_rust" = "1" ]; then \
	    echo "[audit-deep] Rust workspace detected; running Rust proptest deep-engine + per-language genuine-coverage producer"; \
	    make --no-print-directory audit-deep-rust-engine WS="$$ws" $(if $(STRICT),STRICT=1) $(if $(LIVE),LIVE=1) || \
	      echo "[audit-deep] WARN Rust deep-engine returned non-zero; continuing (offline-safe)" >&2; \
	    make --no-print-directory _audit-deep-perlang-genuine-coverage WS="$$ws" LANG_HINT=rust $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") $(if $(STRICT),STRICT=1) || \
	      { _pl_rc=$$?; if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] STRICT=1: Rust genuine-coverage producer failed rc=$$_pl_rc; refusing to continue with incomplete substrate" >&2; exit $$_pl_rc; fi; echo "[audit-deep] WARN Rust genuine-coverage producer returned non-zero; continuing (advisory)" >&2; }; \
	    echo "[audit-deep] running zkvm-detect (proof-system-native detectors; self-gate on FS/field/sumcheck/tweak signals)"; \
	    python3 tools/zkvm-detect.py --workspace "$$ws" || \
	      echo "[audit-deep] WARN zkvm-detect returned non-zero; continuing (advisory)" >&2; \
	  fi; \
	  if [ "$$has_zk" = "1" ]; then \
	    echo "[audit-deep] ZK workspace detected (circom/.zok/.nr/halo2-via-Cargo); running zk-hunt as a certifying deep stage"; \
	    make --no-print-directory zk-hunt WS="$$ws" SKIP_PREFLIGHT=1 || \
	      echo "[audit-deep] WARN zk-hunt returned non-zero / not ZK; continuing (offline-safe)" >&2; \
	  fi; \
	  if [ "$$has_move" = "1" ]; then \
	    echo "[audit-deep] Move workspace detected (.move; Aptos/Sui); generating per-function Move harness scaffolds (--lang move)"; \
	    if [ -f tools/per-function-invariant-gen.py ]; then \
	      python3 tools/per-function-invariant-gen.py --workspace "$$ws" --lang move --output-dir "$$ws/.auditooor/per_function_invariants" --overwrite $(if $(JSON),--json) || \
	        echo "[audit-deep] WARN per-function-invariant-gen --lang move returned non-zero; continuing (offline-safe; tool may not yet support --lang move on this revision)" >&2; \
	    else \
	      echo "[audit-deep] SKIP tools/per-function-invariant-gen.py absent (Move per-function scaffolds not produced this run)" >&2; \
	    fi; \
	  fi; \
	  if [ "$$has_cairo" = "1" ]; then \
	    echo "[audit-deep] Cairo workspace detected (.cairo; Starknet); generating per-function Cairo harness scaffolds (--lang cairo)"; \
	    if [ -f tools/per-function-invariant-gen.py ]; then \
	      python3 tools/per-function-invariant-gen.py --workspace "$$ws" --lang cairo --output-dir "$$ws/.auditooor/per_function_invariants" --overwrite $(if $(JSON),--json) || \
	        echo "[audit-deep] WARN per-function-invariant-gen --lang cairo returned non-zero; continuing (offline-safe; tool may not yet support --lang cairo on this revision)" >&2; \
	    else \
	      echo "[audit-deep] SKIP tools/per-function-invariant-gen.py absent (Cairo per-function scaffolds not produced this run)" >&2; \
	    fi; \
	  fi; \
	  if [ "$$has_cadence" = "1" ]; then \
	    echo "[audit-deep] Cadence workspace detected (.cdc; Flow); generating per-function Cadence harness scaffolds (--lang cadence)"; \
	    if [ -f tools/per-function-invariant-gen.py ]; then \
	      python3 tools/per-function-invariant-gen.py --workspace "$$ws" --lang cadence --output-dir "$$ws/.auditooor/per_function_invariants" --overwrite $(if $(JSON),--json) || \
	        echo "[audit-deep] WARN per-function-invariant-gen --lang cadence returned non-zero; continuing (offline-safe)" >&2; \
	    else \
	      echo "[audit-deep] SKIP tools/per-function-invariant-gen.py absent (Cadence per-function scaffolds not produced this run)" >&2; \
	    fi; \
	  fi; \
	fi; \
	mkdir -p "$$ws/.auditooor"; \
	make --no-print-directory audit-deep-novel-vectors WS="$$ws" LIMIT="$(if $(NOVEL_VECTOR_LIMIT),$(NOVEL_VECTOR_LIMIT),20)" MAX_TARGETS="$(if $(NOVEL_VECTOR_MAX_TARGETS),$(NOVEL_VECTOR_MAX_TARGETS),50)" $(if $(TARGET_REPO),TARGET_REPO="$(TARGET_REPO)") || \
	  echo "[audit-deep] WARN audit-deep-novel-vectors failed; continuing (novel vectors are advisory)" >&2; \
	make --no-print-directory chained-attack-plans WS="$$ws" MAX_PLANS="$(if $(TOP_N),$(TOP_N),10)" || \
	  echo "[audit-deep] WARN chained-attack-plans failed; continuing (chain plans are advisory)" >&2; \
	if [ "$(AUDIT_DEEP_DEFER_DRIVE)" = "1" ]; then \
	  echo "[audit-deep] downstream drive deferred to audit-pipeline-full; Step 4b/2c/4d must run before proof conversion"; \
	elif [ -n "$(STRICT)" ]; then \
	  make --no-print-directory prove-top-leads WS="$$ws" TOP_N="$(if $(TOP_N),$(TOP_N),10)" STRICT=1 JSON=1 || \
	    echo "[audit-deep] WARN STRICT prove-top-leads failed; continuing because the deep engines (halmos/medusa/echidna) already ran in audit-deep-solidity ABOVE this line and the STRICT proof gate belongs at submission, not before/after the engine stage (G9 fix)" >&2; \
	  make --no-print-directory exploit-conversion-loop WS="$$ws" TOP_N="$(if $(TOP_N),$(TOP_N),10)" STRICT=1 JSON=1 > "$$ws/.auditooor/exploit_conversion_loop_audit_deep.json" || \
	    echo "[audit-deep] WARN STRICT exploit-conversion-loop failed; continuing (engine artifacts already written; conversion loop is advisory)" >&2; \
	  make --no-print-directory queue-proof-hard-close WS="$$ws" STRICT=1 || \
	    echo "[audit-deep] NOTE STRICT queue-proof-hard-close non-fatal: the deep engines (halmos/medusa/echidna) already ran ABOVE this line; the STRICT proof-close gate belongs at submission/closeout (v3-source-first post + row gates), not inside the engine stage (G9 parity with prove-top-leads ~line 4223). Continuing." >&2; \
	  make --no-print-directory field-validation-report WS="$$ws" STRICT=1 || \
	    echo "[audit-deep] NOTE STRICT field-validation-report non-fatal: finding-field completeness is a submission/closeout concern enforced at the v3-source-first gates, not inside the engine stage (G9 parity). Continuing." >&2; \
	  make --no-print-directory v3-roadmap-sidecars WS="$$ws" STRICT_HACKERMAN_V3=1 || \
	    echo "[audit-deep] NOTE STRICT v3-roadmap-sidecars non-fatal: roadmap sidecars are advisory; the engines already ran (G9 parity). Continuing." >&2; \
	else \
	  make --no-print-directory prove-top-leads WS="$$ws" TOP_N="$(if $(TOP_N),$(TOP_N),10)" JSON=1 || \
	    echo "[audit-deep] WARN prove-top-leads failed; continuing (proof lead queue is advisory)" >&2; \
	  make --no-print-directory exploit-conversion-loop WS="$$ws" TOP_N="$(if $(TOP_N),$(TOP_N),10)" JSON=1 > "$$ws/.auditooor/exploit_conversion_loop_audit_deep.json" || \
	    echo "[audit-deep] WARN exploit-conversion-loop failed; continuing (conversion loop is advisory)" >&2; \
	  make --no-print-directory queue-proof-hard-close WS="$$ws" || \
	    echo "[audit-deep] WARN queue-proof-hard-close failed; continuing (proof closeout advisory)" >&2; \
	  make --no-print-directory field-validation-report WS="$$ws" || \
	    echo "[audit-deep] WARN field-validation-report failed; continuing (field validation advisory)" >&2; \
	  make --no-print-directory v3-roadmap-sidecars WS="$$ws" || \
	    echo "[audit-deep] WARN v3-roadmap-sidecars failed; continuing (roadmap sidecars advisory)" >&2; \
	fi; \
	lt_rc=0; \
	make --no-print-directory live-target-intel WS="$$ws" IF_STALE_ONLY=1 $(if $(STRICT),STRICT=1) || lt_rc=$$?; \
	if [ $$lt_rc -ne 0 ]; then \
	  echo "[audit-deep] WARN live-target-intel failed rc=$$lt_rc; continuing (live-target context advisory)" >&2; \
	  if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] NOTE live-target-intel advisory under STRICT (post-engine context refresh; engines already ran). Continuing." >&2; : ; fi; \
	fi; \
	phase_be_rc=0; \
	make --no-print-directory phase-b-e-measurement-report JSON=1 || phase_be_rc=$$?; \
	if [ $$phase_be_rc -ne 0 ]; then \
	  echo "[audit-deep] WARN phase-b-e-measurement-report failed rc=$$phase_be_rc; continuing (measurement refresh advisory)" >&2; \
	  if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] NOTE phase-b-e-measurement-report advisory under STRICT (post-engine measurement refresh; engines already ran). Continuing." >&2; : ; fi; \
	fi; \
	if [ "$(AUDIT_DEEP_DEFER_DRIVE)" != "1" ]; then \
	  depth_rc=0; \
	  make --no-print-directory audit-depth WS="$$ws" $(if $(STRICT),STRICT=1) || depth_rc=$$?; \
	  if [ $$depth_rc -ne 0 ]; then \
	    echo "[audit-deep] FAIL audit-depth (R81 per-guard negative-space + sibling-path guard-diff + depth-certificate) rc=$$depth_rc; ordered pipeline stopped" >&2; \
	    exit $$depth_rc; \
	  fi; \
	else \
	  echo "[audit-deep] audit-depth deferred to audit-pipeline-full after the ordered drive gates"; \
	fi
	@# Advisory L37 originality producer: workspace-level originality scan
	@# (candidate terms vs prior_audits/ + corpus) -> .auditooor/originality_report.json.
	@# Emits the artifact the L37 'originality' gate requires; 0 dupe hits is a
	@# passing scan. Advisory here (engines already ran); the HARD gate is L37.
	@python3 tools/workspace-originality-scan.py "$(_WS_RESOLVED)" || \
	  echo "[audit-deep] WARN workspace-originality-scan failed; continuing (advisory; L37 originality gate reads .auditooor/originality_report.json)" >&2
	@# Advisory L37 advisory-corpus producer: query OSV.dev for each in-scope
	@# package -> .auditooor/advisory_corpus_parity.json (published vs corpus
	@# parity). Honest: writes nothing if OSV is unreachable. Advisory here; the
	@# HARD gate is L37 audit-complete.
	@python3 tools/workspace-advisory-corpus-scan.py "$(_WS_RESOLVED)" || \
	  echo "[audit-deep] WARN workspace-advisory-corpus-scan failed/unreachable; continuing (advisory; L37 advisory-corpus gate reads .auditooor/advisory_corpus_parity.json)" >&2
	@# Advisory L36 coverage-matrix producer: build HUNT_CAPABILITY_COVERAGE_MATRIX.md
	@# from per-function-manifest + hunt coverage (cluster COVERED iff the hunt
	@# processed >=1 of its functions; 0 -> DARK). Satisfies hunt-completeness
	@# cluster-coverage + dark-families. Advisory here; hard gate is hunt-complete.
	@python3 tools/capability-coverage-matrix-build.py "$(_WS_RESOLVED)" || \
	  echo "[audit-deep] WARN capability-coverage-matrix-build failed; continuing (advisory)" >&2
	@# Advisory coverage-plane producer: materialize the (in-scope unit x
	@# applicable impact-frame) cross-product as a durable per-cell artifact
	@# (<ws>/.auditooor/coverage_plane.jsonl + coverage_plane_summary.json), one
	@# row per cell, reusing completeness-matrix-build.py's own JOIN/derivation
	@# helpers. Runs here because inscope_units.jsonl (make audit, step above
	@# audit-deep in _AUDIT_DEEP_PREREQ) and the completeness-matrix artifacts
	@# this tool imports are already on disk by this point in the recipe.
	@# Non-fatal (no --strict): a workspace run without opting in never regresses
	@# a prior PASS to a FAIL from this artifact alone.
	@python3 tools/coverage-plane-build.py --workspace "$(_WS_RESOLVED)" || \
	  echo "[audit-deep] WARN coverage-plane-build failed; continuing (advisory)" >&2
	@# Advisory serving-join credit-plane lint (P26): read the narrow-waist
	@# credit-evidence record (tools/lib/credit_evidence.py) and WARN if genuine
	@# evidence is on disk (mutation-verified mvc sidecar / ws-owned hunt sidecar)
	@# but a downstream reader never credited it (the #1 audit-complete false-red).
	@# WAVE-1 READ-ONLY ADVISORY: NO --strict here (STRICT does NOT elevate this to
	@# FAIL inside audit-deep), NOT wired into audit-done-guard. The lint is WARN +
	@# rc 0 by default; only an explicit AUDITOOOR_CREDIT_PLANE_STRICT / --strict
	@# invocation (never issued here) elevates. Non-fatal - never regresses a PASS.
	@python3 tools/credit-plane-lint.py --workspace "$(_WS_RESOLVED)" || \
	  echo "[audit-deep] WARN credit-plane-lint (serving-join advisory) reported/failed; continuing (advisory; wave-1 read-only, not in audit-done-guard)" >&2
	@# Materialize the FUZZ-TARGET WORKLIST (needs-fuzz obligations, one row per
	@# value-moving in-scope asset+fn cluster) so fuzz-target-completeness-check has
	@# something to gate on. Without this the worklist was never generated by any
	@# driver (fuzz-quick only runs the campaign-TAGGING mode), so the whole
	@# fuzz-target capability was dead-on-arrival. --from-inscope + non-fatal.
	@python3 tools/fuzz-target-corpus.py --from-inscope --workspace "$(_WS_RESOLVED)" || \
	  echo "[audit-deep] WARN fuzz-target worklist (--from-inscope) failed; continuing (advisory)" >&2
	@# Advisory residual-scoped LLM-depth hunt: read the residual worker queue
	@# (coverage_residual_worker_queue.json) and, IF the operator consented
	@# (AUDITOOOR_LLM_HUNT=1 / LIVE=1), run an LLM hunt sized to the residual
	@# surface units the deterministic pass left unresolved. Without consent it
	@# only records the typed hunt_provider_obligation.json (never a provider
	@# call). Runs BEFORE hunt-sidecar-bridge below so any sidecars it produces
	@# get bridged in this same audit-deep run. Advisory; HARD gate is L37.
	@make --no-print-directory hunt-residual-llm-depth WS="$(_WS_RESOLVED)" $(if $(LIVE),LIVE=1) $(if $(STRICT),STRICT=1) || \
	  { _hr_rc=$$?; if [ "$(STRICT)" = "1" ]; then echo "[audit-deep] STRICT=1: residual-hunt obligation generation failed rc=$$_hr_rc; refusing to continue" >&2; exit $$_hr_rc; fi; echo "[audit-deep] WARN hunt-residual-llm-depth failed; continuing (advisory)" >&2; }
	@# WAVE-1 ENFORCE (advisory-first): before the bridge trusts fan-out coverage,
	@# assert every dispatched worklist unit actually wrote a sidecar back (the silent
	@# "7-of-24 partial-batch" pattern). pass-no-worklist when nothing was dispatched -
	@# never-false-pass. HARD promotion (L37 prereq of hunt-coverage-gate) is wave-2.
	@python3 tools/fanout-writeback-completeness-check.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) || \
	  echo "[audit-deep] WARN fanout-writeback-completeness reported/failed (some dispatched units wrote no sidecar); continuing (advisory)" >&2
	@# WIRE the State-Coupling Graph (Aptos coupled-state axis) into the pipeline: emit the
	@# SCG here so state_coupling_edges.jsonl EXISTS during the hunt phase and its promotable
	@# semantic-ssa edges feed exploit-queue._gather_from_state_coupling. Without this the SCG
	@# was an ORPHAN (nothing ran --emit; 0 SCG rows reached the queue on a real audit).
	@# Advisory here; the fail-closed gate is check_state_coupling in audit-complete (L37).
	@python3 tools/state-coupling-graph.py --workspace "$(_WS_RESOLVED)" --emit || \
	  echo "[audit-deep] WARN state-coupling-graph emit failed; continuing (advisory)" >&2
	@# WIRE the WSITB B1 enforcement-plane (increment-1 CONSERVATION class) into the pipeline:
	@# recompose the conserved-with coupled sets into ENFORCEMENT POINTS so
	@# wsitb_enforcement_plane.json EXISTS during the hunt phase. Advisory here; the
	@# fail-closed gate is check_enforcement_point in audit-complete (L37).
	@python3 tools/wsitb-enforcement-plane.py --workspace "$(_WS_RESOLVED)" --emit-plane >/dev/null || \
	  echo "[audit-deep] WARN wsitb-enforcement-plane emit failed; continuing (advisory)" >&2
	@# Advisory: bridge this workspace's hunt sidecars (written by the per-function
	@# LLM hunt under the repo derived dir, matched by workspace_path) into
	@# <ws>/.auditooor/hunt_findings_sidecars/ so hunt-completeness artifact-mining
	@# sees them. Copies nothing if the hunt produced none for this ws.
	@python3 tools/hunt-sidecar-bridge.py --workspace "$(_WS_RESOLVED)" || \
	  echo "[audit-deep] WARN hunt-sidecar-bridge failed; continuing (advisory)" >&2
	@# SERVING-JOIN: propagate GENUINE source-cited terminal verdicts (agent_mechanism_
	@# verdicts + terminal exploit_queue rows) onto the logic-reasoner obligations they
	@# adjudicate, so logic-obligation-resolution-check credits an already-driven
	@# obligation (it reads logic_obligation_resolutions.jsonl, which NO tool wrote until
	@# this bridge). Anti-fabrication: only emits for obligations whose OWN key matches a
	@# source-cited terminal verdict; the un-adjudicated tail stays OPEN (real hunt work).
	@python3 tools/logic-obligation-resolution-bridge.py --workspace "$(_WS_RESOLVED)" --apply >/dev/null 2>&1 || \
	  echo "[audit-deep] WARN logic-obligation-resolution-bridge failed; continuing (advisory)" >&2
	@# WAVE-1 ENFORCE (advisory-first): after the bridge, assert the hunt PLAN residual
	@# and the GATE residual agree (the 1644-vs-57 balloon + function='' empty-enumeration).
	@# pass-insufficient-inputs when either universe is absent - never-false-pass. HARD
	@# promotion (L37 prereq of hunt-coverage-gate) is wave-2.
	@python3 tools/enumeration-universe-consistency-check.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) || \
	  echo "[audit-deep] WARN enumeration-universe-consistency reported/failed (plan residual vs gate residual disagree); continuing (advisory)" >&2
	@# Reconcile abandoned unhunted-surface leads against the coverage/fuzz/scope
	@# evidence -> evidence-grounded terminal verdicts ledger (the follow-through
	@# gate credits only ledger entries whose evidence_ref is a real file; leads
	@# with no genuine basis stay OPEN). Reconciliation step, NOT the gate itself.
	@python3 tools/unhunted-surface-adjudicate.py --workspace "$(_WS_RESOLVED)" || \
	  echo "[audit-deep] WARN unhunted-surface-adjudicate failed; continuing (advisory)" >&2
	@# Recompute + stamp the honest-0 from real evidence (un-fakeable; the
	@# done-guard re-verifies regardless). Non-zero just means "not a 0 yet".
	@python3 tools/honest-zero-verify.py --workspace "$(_WS_RESOLVED)" --stamp >/dev/null 2>&1 || \
	  echo "[audit-deep] NOTE honest-zero-verify: not a verifiable honest-0 yet (advisory)" >&2
	@# Scaffold the exploit-class disposition ledger if absent so the operator is
	@# prompted to address each hard exploit class (the gate fails until filled).
	@python3 tools/exploit-class-coverage.py --workspace "$(_WS_RESOLVED)" --scaffold >/dev/null 2>&1 || true
	@# P-WIRE-SCANNER-INTEGRITY: surface any scanner that recorded ok/completed but never
	@# actually ran (empty output + 0 findings + 0 files = silent-0 false-green, e.g. Slither
	@# on a non-building Solidity tree). Advisory: warns unmissably, never fail-closes (the
	@# affected arm is simply NOT-statically-scanned, which the coverage gates already model).
	@python3 tools/scanner-ran-integrity.py --workspace "$(_WS_RESOLVED)" --check || \
	  echo "[audit-deep] WARN scanner-ran-integrity flagged a silent-0 scanner (a language arm recorded clean but never analyzed the code); do NOT treat it as statically scanned" >&2
	@# P-WIRE-STEP-INTEGRITY: surface any canonical README step that silently ran in a
	@# degraded/fallback mode (e.g. commit-mining in local-git-only without GitHub auth, so
	@# upstream post-pin security fixes were never mined). Advisory: warns unmissably so a
	@# degraded step cannot masquerade as "done". Promote to a hard signal once detection
	@# globs are confirmed per-workspace.
	@python3 tools/readme-step-integrity.py --workspace "$(_WS_RESOLVED)" --strict || \
	  echo "[audit-deep] WARN readme-step-integrity flagged a canonical step that ran DEGRADED or was SKIPPED (see .auditooor/readme_step_integrity.json); a degraded step is unfinished work, not done" >&2
	@# P-WIRE-HONESTY: audit-honesty-check gates at the END of audit-deep.
	@# Advisory by default (warn unmissably, do NOT fail-close the whole audit-deep run
	@# when engines are hollow - the user can still iterate). Fail-closed under STRICT=1
	@# so audit-run-full + audit-deep STRICT=1 catch hollow workspaces before closeout.
	@honesty_rc=0; \
	python3 tools/audit-honesty-check.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) || honesty_rc=$$?; \
	if [ $$honesty_rc -ne 0 ]; then \
	  if [ "$(STRICT)" = "1" ]; then \
	    echo "[audit-deep] FAIL audit-honesty-check (R80: fail-fake-coverage / fail-hollow-engines / fail-stub-harnesses / fail-depth-not-run); halting under STRICT=1" >&2; \
	    exit $$honesty_rc; \
	  else \
	    echo "[audit-deep] WARN audit-honesty-check returned rc=$$honesty_rc (hollow workspace or stub-only harnesses); re-run with STRICT=1 to fail-close. Set LIVE=1 and re-run audit-deep to produce real engine evidence." >&2; \
	  fi; \
	fi

# --------------------------------------------------------------------------
# audit-depth (R81): the per-UNIT depth layer that runs inside audit-deep
# alongside the per-function-invariant + exploit-queue stages. It runs the
# depth tools in order:
#   1. guard-negative-space-analyzer --emit-worklist : per-guard "what does this
#      guard NOT check?" worklist (emits negative_space_worklist.jsonl).
#   2. sibling-path-guard-diff --check : proactive sibling-path guard-asymmetry
#      enumeration (emits sibling_guard_asymmetries.jsonl; productionizes the
#      L30 missing-guard enumerator).
#   3. depth-certificate-build : the SINGLE cert writer - rolls the per-row JSONL
#      the two passes above emit up into .auditooor/depth_certificate.json. The
#      passes themselves do NOT write the cert; this producer does. With only the
#      mechanical passes run (no agentic probe/validate), the producer writes a
#      depth-pending cert (NOT depth-audited).
#   4. depth-certificate-check : reads the cert the producer wrote and certifies
#      the depth layer ran with evidence ("0 findings = smell, not success"). A
#      depth-pending cert does NOT pass - the workspace must reach depth-audited.
# The depth stage is a hard ordered gate. A non-passing certificate stops the
# pipeline at this step; closeout must not be the first place that discovers
# missing depth evidence.
# --------------------------------------------------------------------------
.PHONY: audit-guard-triage
# audit-guard-triage: EARLY structural guard pass (the guards-early rewire). Runs
# the cheap, no-fuzz guard analyzers + guard-triage right after step-1 so the hunt
# (step-3) can prioritize guard-risky functions FIRST instead of spending the first
# agents on view proxies. ADDITIVE: the step-4 audit-depth guard pass still runs;
# this just makes the guard signal available early + feeds per-function-attack-
# worklist's ranking (which reads .auditooor/guard_triage.json). Fast + idempotent.
audit-guard-triage:
	@if [ -z "$(WS)" ]; then echo 'Usage: make audit-guard-triage WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "audit-guard-triage" "$(_WS_RESOLVED)"
	@set -u; ws="$(_WS_RESOLVED)"; \
	python3 tools/workspace-coverage-heatmap.py --emit-inscope-manifest --workspace-path "$$ws" >/dev/null 2>&1 || true; \
	python3 tools/guard-negative-space-analyzer.py --workspace "$$ws" --emit-worklist >/dev/null 2>&1 || \
	  echo "[audit-guard-triage] WARN guard-negative-space-analyzer non-zero (advisory)" >&2; \
	python3 tools/sibling-path-guard-diff.py --workspace "$$ws" --check >/dev/null 2>&1 || true; \
	python3 tools/guard-triage.py --workspace "$$ws" || \
	  echo "[audit-guard-triage] WARN guard-triage non-zero (advisory)" >&2; \
	echo "[audit-guard-triage] wrote $$ws/.auditooor/guard_triage.json (hunt will prioritize guard-risk fns)"

audit-depth:
	$(call _require_pipeline_phase_token,audit-depth)
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-depth WS=<workspace> [STRICT=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-depth" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor/depth"
	@python3 tools/resolve-fork-bases.py --workspace "$(_WS_RESOLVED)" >/dev/null 2>&1 || true
	@im_rc=0; \
	python3 tools/workspace-coverage-heatmap.py --emit-inscope-manifest --workspace-path "$(_WS_RESOLVED)" $(if $(FORCE),--force) $(if $(JSON),--json) || im_rc=$$?; \
	if [ $$im_rc -ne 0 ]; then \
	  echo "[audit-depth] WARN inscope-manifest emit failed rc=$$im_rc; guard-negative-space-analyzer may have a thinner in-scope unit set (manifest precondition is advisory)" >&2; \
	else \
	  echo "[audit-depth] inscope_units.jsonl precondition ready (idempotent: kept fresh existing unless FORCE=1)" >&2; \
	fi
	@ns_rc=0; \
	python3 tools/guard-negative-space-analyzer.py --workspace "$(_WS_RESOLVED)" --emit-worklist $(if $(JSON),--json) || ns_rc=$$?; \
	if [ $$ns_rc -ne 0 ]; then \
	  echo "[audit-depth] WARN guard-negative-space-analyzer --emit-worklist failed rc=$$ns_rc; continuing (negative-space worklist is advisory; the depth-certificate gate is the authority)" >&2; \
	fi
	@# Discovery scanners (advisory; the HARD gates are at audit-done-guard / L37):
	@# (Gap B) in-tree self-acknowledgement (FIXME/TODO/skip-return co-located with
	@# a guard/sink) and developer-confessed skipped/disabled tests. Both emit a
	@# <ws>/.auditooor/ artifact that the corresponding fail-closed gate reads; a
	@# missing artifact is a FAIL there (silent-0 != clean), so the scan MUST run.
	@igal_rc=0; \
	python3 tools/incomplete-guard-acknowledgement-scanner.py --workspace "$(_WS_RESOLVED)" --emit $(if $(JSON),--json) || igal_rc=$$?; \
	if [ $$igal_rc -ne 0 ]; then \
	  echo "[audit-depth] WARN incomplete-guard-acknowledgement-scanner failed rc=$$igal_rc; continuing (IGAL hypotheses advisory; the incomplete-guard-ack gate is the authority)" >&2; \
	fi
	@stm_rc=0; \
	python3 tools/skipped-test-marker-scan.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) || stm_rc=$$?; \
	if [ $$stm_rc -ne 0 ] && [ $$stm_rc -ne 1 ]; then \
	  echo "[audit-depth] WARN skipped-test-marker-scan failed rc=$$stm_rc; continuing (skipped-test markers advisory; the skipped-test-disposition gate is the authority)" >&2; \
	fi
	@sd_rc=0; \
	python3 tools/sibling-path-guard-diff.py --workspace "$(_WS_RESOLVED)" --check $(if $(JSON),--json) || sd_rc=$$?; \
	if [ $$sd_rc -ne 0 ]; then \
	  echo "[audit-depth] WARN sibling-path-guard-diff --check returned non-zero rc=$$sd_rc (found-asymmetries or tooling); continuing (asymmetries are surfaced to the cert; the depth-certificate gate is the authority)" >&2; \
	fi
	@# Advisory complementary pass: drive the reactive L30 missing-guard
	@# enumerator over the STANDARD naming pairs (claim/finalize, deposit/withdraw,
	@# mint/burn, lock/unlock) and fold UNGUARDED candidate rows into the SAME
	@# sibling_guard_asymmetries.jsonl the structural sibling-diff above writes, so
	@# the downstream asymmetry-context-extract/probe/cert pipeline picks them up.
	@# Language-agnostic (the enumerator auto-detects sol/go/rs/ts/py). Idempotent
	@# (content-stable gap ids de-dup against what is already on disk). Advisory
	@# (rc-tolerant WARN); the HARD authority is L37 at make audit-complete.
	@mgpf_rc=0; \
	python3 tools/missing-guard-pairs-fold.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) || mgpf_rc=$$?; \
	if [ $$mgpf_rc -ne 0 ]; then \
	  echo "[audit-depth] WARN missing-guard-pairs-fold failed rc=$$mgpf_rc; standard-pair asymmetry candidates may be missing (the structural sibling-diff above still ran; the depth-certificate gate is the authority)" >&2; \
	fi
	@# --- extract -> probe -> ingest (R81 negative-space depth, compact-packet path) ---
	@# Ordering is load-bearing: this MUST land negative_space_gaps.jsonl BEFORE
	@# depth-certificate-build (below) reads BOTH negative_space_worklist.jsonl AND
	@# negative_space_gaps.jsonl. If the ingest does not run first, the cert reflects
	@# only stub rows (-> fail-survivors-unvalidated / fail-zero-findings-smell at L37).
	@# Each sub-step is advisory (rc-tolerant WARN), matching the ns_rc/sd_rc/db_rc
	@# pattern; the HARD authority is L37 at `make audit-complete`.
	@# (2a) Mechanically extract one compact probe packet per guard (Python reads
	@#      source ONCE; ~100x cheaper than per-guard LLM file reads).
	@# NOTE source-root: the depth tools default source-root to the workspace root.
	@# Do NOT pass --source-root src when the worklist file_line hints already carry
	@# a leading src/ (e.g. Zebra: src/zebra-rpc/src/methods.rs) - that double-prefixes
	@# to src/src/... and the R76 source-exists grep fails (proven on Zebra 2026-06-04:
	@# --source-root src -> 8/8 R76-drop; default workspace-root -> 8/8 R76-pass).
	@gce_rc=0; \
	python3 tools/guard-context-extract.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) || gce_rc=$$?; \
	if [ $$gce_rc -ne 0 ]; then \
	  echo "[audit-depth] WARN guard-context-extract failed rc=$$gce_rc; guard_probe_packets.jsonl may be missing/stale (probe step then has no compact packets; the depth-certificate gate is the authority)" >&2; \
	fi
	@# (2a') Asymmetry analog of guard-context-extract: mechanically filter the
	@#       sibling-path asymmetries (sibling_guard_asymmetries.jsonl, emitted by
	@#       sibling-path-guard-diff above) down to the real candidate pairs and
	@#       emit one compact 'asymmetry packet' per survivor -> asymmetry_probe_
	@#       packets.jsonl, so the downstream probe never re-reads source. Advisory
	@#       (rc-tolerant WARN), matching the gce_rc/sd_rc/dpi_rc pattern; the HARD
	@#       authority is L37 at `make audit-complete`.
	@ace_rc=0; \
	python3 tools/asymmetry-context-extract.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) || ace_rc=$$?; \
	if [ $$ace_rc -ne 0 ]; then \
	  echo "[audit-depth] WARN asymmetry-context-extract failed rc=$$ace_rc; asymmetry_probe_packets.jsonl may be missing/stale (probe step then has no compact packets; the depth-certificate gate is the authority)" >&2; \
	fi
	@# (2b) PROBE STEP: depth-probe-runner.py consumes guard_probe_packets.jsonl
	@#      (compact packets, NO source re-read) and writes per-batch *.jsonl files
	@#      into <ws>/.auditooor/depth_probes/.  Without DEPTH_PROBE_LIVE=1 it
	@#      writes dry-run stubs so the pipeline always advances; the anti-stub gate
	@#      in depth-probe-ingest drops the stubs and the depth cert shows
	@#      'depth-pending', which is the honest signal that a live probe run is
	@#      still needed.  With DEPTH_PROBE_LIVE=1 (requires network consent +
	@#      AUDITOOOR_LLM_NETWORK_CONSENT=1) it calls the LLM and produces genuine
	@#      gap verdicts.  --skip-existing lets a re-run skip already-landed batches.
	@#
	@#      After the runner, depth-probe-ingest.py --probes-dir combines the batch
	@#      files, R76-verifies + anti-stub-filters the rows, and merges the genuine
	@#      ones into .auditooor/negative_space_gaps.jsonl.  This is the step that
	@#      was previously missing: the runner was absent so negative_space_gaps.jsonl
	@#      was never produced from the compact packets (FIX #3 wiring, 2026-06-07).
	@dpr_rc=0; \
	python3 tools/depth-probe-runner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --probes-dir "$(_WS_RESOLVED)/.auditooor/depth_probes" \
	  --skip-existing \
	  $(if $(or $(DEPTH_PROBE_LIVE),$(AUDITOOOR_AUDIT_DEEP_LIVE)),--live) \
	  $(if $(DEPTH_PROBE_BATCH_SIZE),--batch-size "$(DEPTH_PROBE_BATCH_SIZE)") \
	  $(if $(DEPTH_PROBE_PROVIDER),--provider "$(DEPTH_PROBE_PROVIDER)") \
	  $(if $(DEPTH_PROBE_MODEL),--model "$(DEPTH_PROBE_MODEL)") \
	  $(if $(JSON),--json) || dpr_rc=$$?; \
	if [ $$dpr_rc -ne 0 ]; then \
	  echo "[audit-depth] WARN depth-probe-runner failed rc=$$dpr_rc; some batches may be missing - re-run with DEPTH_PROBE_LIVE=1 --skip-existing to retry failed batches (the depth-certificate gate is the authority)" >&2; \
	  if [ "$(STRICT)" = "1" ]; then exit $$dpr_rc; fi; \
	fi
	@# (2c) Mechanically R76-verify + distinctness-check + ingest the probe records
	@#      from the batch directory, writing genuine rows into negative_space_gaps.jsonl.
	@dpi_rc=0; \
	if [ -d "$(_WS_RESOLVED)/.auditooor/depth_probes" ]; then \
	  python3 tools/depth-probe-ingest.py --workspace "$(_WS_RESOLVED)" --probes-dir "$(_WS_RESOLVED)/.auditooor/depth_probes" $(if $(JSON),--json) || dpi_rc=$$?; \
	  if [ $$dpi_rc -ne 0 ]; then \
	    echo "[audit-depth] WARN depth-probe-ingest failed rc=$$dpi_rc; negative_space_gaps.jsonl may be incomplete (the depth-certificate gate is the authority)" >&2; \
	    if [ "$(STRICT)" = "1" ]; then exit $$dpi_rc; fi; \
	  fi; \
	else \
	  echo "[audit-depth] NOTE depth_probes dir missing after depth-probe-runner; skipping ingest" >&2; \
	fi
	@# (2d) ASYMMETRY PROBE PASS (FIX #P1-asym wiring, 2026-06-07). The guard pass
	@#      above (2b/2c) only ever drove guard_probe_packets.jsonl; the sibling
	@#      asymmetries (asymmetry_probe_packets.jsonl, emitted by
	@#      asymmetry-context-extract at 2a') were NEVER probed, so
	@#      asymmetry_probes.jsonl was never written and every sibling-asymmetry row
	@#      passed through the cert UNDISPOSED. This second depth-probe-runner +
	@#      ingest pass closes that gap: the runner is packet-shape-aware (it emits
	@#      records keyed by asym_id with the under-guarded side's code_excerpt /
	@#      file_line), and the ingest writes the genuine rows into
	@#      asymmetry_probes.jsonl via --output, which is exactly what
	@#      depth-certificate-build.py reads for _apply_asymmetry_dispositions.
	@#      Advisory (rc-tolerant WARN), matching the dpr_rc/dpi_rc pattern; the HARD
	@#      authority is L37 at `make audit-complete`.
	@if [ -f "$(_WS_RESOLVED)/.auditooor/asymmetry_probe_packets.jsonl" ]; then \
	  adpr_rc=0; \
	  python3 tools/depth-probe-runner.py \
	    --workspace "$(_WS_RESOLVED)" \
	    --packets "$(_WS_RESOLVED)/.auditooor/asymmetry_probe_packets.jsonl" \
	    --probes-dir "$(_WS_RESOLVED)/.auditooor/asymmetry_probes" \
	    --skip-existing \
	    $(if $(or $(DEPTH_PROBE_LIVE),$(AUDITOOOR_AUDIT_DEEP_LIVE)),--live) \
	    $(if $(DEPTH_PROBE_BATCH_SIZE),--batch-size "$(DEPTH_PROBE_BATCH_SIZE)") \
	    $(if $(DEPTH_PROBE_PROVIDER),--provider "$(DEPTH_PROBE_PROVIDER)") \
	    $(if $(DEPTH_PROBE_MODEL),--model "$(DEPTH_PROBE_MODEL)") \
	    $(if $(JSON),--json) || adpr_rc=$$?; \
	  if [ $$adpr_rc -ne 0 ]; then \
	    echo "[audit-depth] WARN asymmetry depth-probe-runner failed rc=$$adpr_rc; some asymmetry batches may be missing - re-run with DEPTH_PROBE_LIVE=1 --skip-existing (the depth-certificate gate is the authority)" >&2; \
	    if [ "$(STRICT)" = "1" ]; then exit $$adpr_rc; fi; \
	  fi; \
	  adpi_rc=0; \
	  if [ -d "$(_WS_RESOLVED)/.auditooor/asymmetry_probes" ]; then \
	    python3 tools/depth-probe-ingest.py \
	      --workspace "$(_WS_RESOLVED)" \
	      --probes-dir "$(_WS_RESOLVED)/.auditooor/asymmetry_probes" \
	      --combined-name "asymmetry_probes_combined.jsonl" \
	      --output "$(_WS_RESOLVED)/.auditooor/asymmetry_probes.jsonl" \
	      $(if $(JSON),--json) || adpi_rc=$$?; \
	    if [ $$adpi_rc -ne 0 ]; then \
	      echo "[audit-depth] WARN asymmetry depth-probe-ingest failed rc=$$adpi_rc; asymmetry_probes.jsonl may be incomplete (the depth-certificate gate is the authority)" >&2; \
	      if [ "$(STRICT)" = "1" ]; then exit $$adpi_rc; fi; \
	    fi; \
	  else \
	    echo "[audit-depth] NOTE asymmetry_probes batch dir missing after runner; skipping asymmetry ingest" >&2; \
	  fi; \
	else \
	  echo "[audit-depth] NOTE no asymmetry_probe_packets.jsonl (asymmetry-context-extract found no real sibling pairs); skipping asymmetry probe pass" >&2; \
	fi
	@db_rc=0; \
	python3 tools/depth-certificate-build.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json) || db_rc=$$?; \
	if [ $$db_rc -ne 0 ]; then \
	  echo "[audit-depth] WARN depth-certificate-build failed rc=$$db_rc; the cert may be missing/stale (the depth-certificate gate will then fail-no-depth-certificate)" >&2; \
	else \
	  echo "[audit-depth] depth-certificate-build wrote .auditooor/depth_certificate.json (mechanical-only run leaves a depth-pending cert; reach depth-audited via the agentic probe/validate + Certify phase)" >&2; \
	fi
	python3 tools/depth-certificate-check.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json)

# depth-probe-run: convenience target to run ONLY the cheap-LLM probe step +
# ingest, without re-running the worklist/extract/cert stages.  Use this when
# guard_probe_packets.jsonl is already fresh and you just need to (re-)run the
# LLM pass and update negative_space_gaps.jsonl.
#
#   make depth-probe-run WS=~/audits/<project>           # dry-run stubs
#   make depth-probe-run WS=~/audits/<project> DEPTH_PROBE_LIVE=1  # real LLM
#   make depth-probe-run WS=~/audits/<project> DEPTH_PROBE_LIVE=1 DEPTH_PROBE_PROVIDER=kimi
#   make depth-probe-run WS=~/audits/<project> DEPTH_PROBE_LIVE=1 DEPTH_PROBE_MODEL=deepseek-v4-flash
depth-probe-run:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make depth-probe-run WS=<workspace> [DEPTH_PROBE_LIVE=1] [DEPTH_PROBE_PROVIDER=kimi|minimax|anthropic|deepseek-flash] [DEPTH_PROBE_MODEL=<id>] [DEPTH_PROBE_BATCH_SIZE=N] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make depth-probe-run" "$(_WS_RESOLVED)"
	@dpr_rc=0; \
	python3 tools/depth-probe-runner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --probes-dir "$(_WS_RESOLVED)/.auditooor/depth_probes" \
	  --skip-existing \
	  $(if $(or $(DEPTH_PROBE_LIVE),$(AUDITOOOR_AUDIT_DEEP_LIVE)),--live) \
	  $(if $(DEPTH_PROBE_BATCH_SIZE),--batch-size "$(DEPTH_PROBE_BATCH_SIZE)") \
	  $(if $(DEPTH_PROBE_PROVIDER),--provider "$(DEPTH_PROBE_PROVIDER)") \
	  $(if $(DEPTH_PROBE_MODEL),--model "$(DEPTH_PROBE_MODEL)") \
	  $(if $(JSON),--json) || dpr_rc=$$?; \
	if [ $$dpr_rc -ne 0 ]; then \
	  echo "[depth-probe-run] WARN depth-probe-runner failed rc=$$dpr_rc; partial batches written - re-run to retry" >&2; \
	fi
	@dpi_rc=0; \
	if [ -d "$(_WS_RESOLVED)/.auditooor/depth_probes" ]; then \
	  python3 tools/depth-probe-ingest.py --workspace "$(_WS_RESOLVED)" --probes-dir "$(_WS_RESOLVED)/.auditooor/depth_probes" $(if $(JSON),--json) || dpi_rc=$$?; \
	  if [ $$dpi_rc -ne 0 ]; then \
	    echo "[depth-probe-run] WARN depth-probe-ingest failed rc=$$dpi_rc" >&2; \
	  fi; \
	else \
	  echo "[depth-probe-run] NOTE depth_probes dir absent after runner; nothing to ingest" >&2; \
	fi
	@# REBUILD the cert after ingest - else depth-probe-run leaves a STALE cert
	@# (the depth-certificate-check freshness gate would then flag it). audit-depth
	@# already rebuilds; depth-probe-run did not.
	@db_rc=0; \
	python3 tools/depth-certificate-build.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json) || db_rc=$$?; \
	if [ $$db_rc -ne 0 ]; then \
	  echo "[depth-probe-run] WARN depth-certificate-build failed rc=$$db_rc; cert may be stale" >&2; \
	fi

audit-deep-medium:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-medium WS=<workspace> [TOP_N=10] [PROJECT_ROOT=<path>] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-medium" "$(_WS_RESOLVED)"
	@$(MAKE) --no-print-directory audit-deep \
	  WS="$(_WS_RESOLVED)" \
	  DEEP_PROFILE=medium \
	  LIVE=1 \
	  TOP_N="$(if $(TOP_N),$(TOP_N),0)" \
	  $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") \
	  $(if $(STRICT),STRICT=1) \
	  $(if $(JSON),JSON=1)

audit-deep-ccia-attack-angles:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-ccia-attack-angles WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-ccia-attack-angles" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/ccia.py "$(_WS_RESOLVED)" --attack-angles --out "$(_WS_RESOLVED)/.auditooor/ccia_attack_angles.json"

audit-deep-overnight:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-overnight WS=<workspace> [TOP_N=25] [PROJECT_ROOT=<path>] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-overnight" "$(_WS_RESOLVED)"
	@echo "[audit-deep-overnight] delegating to audit-deep-full for canonical full-profile timeouts"
	@$(MAKE) --no-print-directory audit-deep-full \
	  WS="$(_WS_RESOLVED)" \
	  TOP_N="$(if $(TOP_N),$(TOP_N),25)" \
	  $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") \
	  $(if $(JSON),JSON=1)

audit-deep-full:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-full WS=<workspace> [TOP_N=25] [PROJECT_ROOT=<path>] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-full" "$(_WS_RESOLVED)"
	@echo "[audit-deep-full] 3-tier ladder: medium triage -> strict deep profile -> live engines"
	@echo "[audit-deep-full] timeouts: halmos 900s; medusa 1800s; echidna 1800s"
	@bash tools/auditooor-session-start.sh "$(_WS_RESOLVED)" >/dev/null
	@AUDIT_DEEP_REQUIRE_MCP_PREFLIGHT=1 REQUIRE_RECENT_RECALL=1 \
	  AUDIT_DEEP_SKIP_AUDIT_PREREQ=1 \
	  AUDITOOOR_AUDIT_DEEP_LIVE=1 \
	  HALMOS_TIMEOUT=900 MEDUSA_TIMEOUT=1800 ECHIDNA_TIMEOUT=1800 \
	  $(MAKE) --no-print-directory audit-deep \
	    WS="$(_WS_RESOLVED)" \
	    LIVE=1 \
	    DEEP_PROFILE=all \
	    TOP_N="$(if $(TOP_N),$(TOP_N),25)" \
	    STRICT=1 \
	    $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") \
	    $(if $(JSON),JSON=1)

v3-source-first-audit:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make v3-source-first-audit WS=<workspace> [TOP_N=25] [PROJECT_ROOT=<path>] [QUEUE=<path>] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make v3-source-first-audit" "$(_WS_RESOLVED)"
	@if [ -n "$(AUDIT_COMMIT_MINING_SKIP)" ] && [ "$(SOURCE_FIRST_ALLOW_COMMIT_MINING_SKIP)" != "1" ]; then \
	  echo "[make v3-source-first-audit] ERR AUDIT_COMMIT_MINING_SKIP is not allowed for source-first audit unless SOURCE_FIRST_ALLOW_COMMIT_MINING_SKIP=1"; exit 2; fi
	@$(MAKE) --no-print-directory v3-source-first-prereq-gate \
	  WS="$(_WS_RESOLVED)" \
	  PHASE=pre \
	  STRICT=1 \
	  $(if $(JSON),JSON=1)
	@$(MAKE) --no-print-directory audit-deep-overnight \
	  WS="$(_WS_RESOLVED)" \
	  TOP_N="$(if $(TOP_N),$(TOP_N),25)" \
	  $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") \
	  $(if $(JSON),JSON=1)
	@$(MAKE) --no-print-directory v3-source-first-prereq-gate \
	  WS="$(_WS_RESOLVED)" \
	  PHASE=post \
	  STRICT=1 \
	  $(if $(JSON),JSON=1)
	@$(MAKE) --no-print-directory v3-source-first-prior-audit-dupe-gate \
	  WS="$(_WS_RESOLVED)" \
	  TOP_N="$(if $(TOP_N),$(TOP_N),25)" \
	  STRICT=1 \
	  $(if $(QUEUE),QUEUE="$(QUEUE)") \
	  $(if $(JSON),JSON=1)
	@$(MAKE) --no-print-directory v3-source-first-row-gate \
	  WS="$(_WS_RESOLVED)" \
	  STRICT=1 \
	  $(if $(QUEUE),QUEUE="$(QUEUE)") \
	  PRIOR_AUDIT_DUPE="$(_WS_RESOLVED)/.auditooor/source_first_prior_audit_dupe_gate.json" \
	  $(if $(JSON),JSON=1)

v3-source-first-prereq-gate:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make v3-source-first-prereq-gate WS=<workspace> PHASE=<pre|post> [STRICT=1] [OUT_JSON=<path>] [OUT_MD=<path>]'; exit 2; fi
	@if [ -z "$(PHASE)" ]; then \
	  echo 'Usage: make v3-source-first-prereq-gate WS=<workspace> PHASE=<pre|post> [STRICT=1] [OUT_JSON=<path>] [OUT_MD=<path>]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make v3-source-first-prereq-gate" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/v3-source-first-prereq-gate.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --phase "$(PHASE)" \
	  --out-json "$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/v3_source_first_prereq_gate_$(PHASE).json)" \
	  --out-md "$(if $(OUT_MD),$(OUT_MD),$(_WS_RESOLVED)/.auditooor/v3_source_first_prereq_gate_$(PHASE).md)" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--print-json)

v3-source-first-prereq-gate-test:
	@python3 -m unittest tools.tests.test_v3_source_first_prereq_gate -v

v3-source-first-prior-audit-dupe-gate:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make v3-source-first-prior-audit-dupe-gate WS=<workspace> [TOP_N=25] [QUEUE=<path>] [OUT_JSON=<path>] [STRICT=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make v3-source-first-prior-audit-dupe-gate" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@queue="$(if $(QUEUE),$(QUEUE),$(_WS_RESOLVED)/.auditooor/exploit_queue.source_mined.json)"; \
	if [ ! -f "$$queue" ] && [ -z "$(QUEUE)" ]; then queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.json"; fi; \
	out="$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/source_first_prior_audit_dupe_gate.json)"; \
	mkdir -p "$$(dirname "$$out")"; \
	tmp="$$out.tmp"; \
	rc=0; \
	python3 tools/prior-audit-dupe-gate.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --queue "$$queue" \
	  --top-n "$(if $(TOP_N),$(TOP_N),25)" \
	  $(if $(STRICT),--strict) \
	  --json > "$$tmp" || rc=$$?; \
	if [ $$rc -eq 3 ] || { [ $$rc -ne 0 ] && [ $$rc -ne 1 ] && [ $$rc -ne 2 ]; }; then \
	  rm -f "$$tmp"; exit $$rc; \
	fi; \
	mv "$$tmp" "$$out"; \
	if [ -n "$(JSON)" ]; then cat "$$out"; fi

v3-source-first-row-gate:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make v3-source-first-row-gate WS=<workspace> [STRICT=1] [JSON=1] [QUEUE=<path>] [PRIOR_AUDIT_DUPE=<path>] [OUT_JSON=<path>] [OUT_MD=<path>]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make v3-source-first-row-gate" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/v3-source-first-row-gate.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  --prior-audit-dupe "$(if $(PRIOR_AUDIT_DUPE),$(PRIOR_AUDIT_DUPE),$(_WS_RESOLVED)/.auditooor/source_first_prior_audit_dupe_gate.json)" \
	  --out-json "$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/v3_source_first_row_gate.json)" \
	  --out-md "$(if $(OUT_MD),$(OUT_MD),$(_WS_RESOLVED)/.auditooor/v3_source_first_row_gate.md)" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--print-json)

v3-source-first-row-gate-test:
	@python3 -m unittest tools.tests.test_v3_source_first_row_gate -v

# LANE W5-D1 - hermetic deep-engine provisioning.
# Installs pinned halmos/medusa/echidna into tools/deep-engine-bin/ so the
# runners (halmos-runner.sh / medusa-fuzz.sh / echidna-campaign.sh) actually
# execute. Until this runs, the runners skip gracefully (tool-unavailable
# artifact, exit 0) - no regression for un-provisioned / offline environments.
#   make deep-engines-provision               install all three engines
#   make deep-engines-provision ENGINE=halmos  install one engine
#   make deep-engines-provision-check          offline-safe status print
deep-engines-provision:
	@bash tools/provision-deep-engines.sh $(if $(ENGINE),--engine $(ENGINE))

deep-engines-provision-check:
	@bash tools/provision-deep-engines.sh --check

audit-deep-solidity:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-solidity WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-solidity" "$(_WS_RESOLVED)"
	@set -u; \
	ws="$(_WS_RESOLVED)"; \
	out="$(if $(SOLIDITY_DEEP_OUT_DIR),$(SOLIDITY_DEEP_OUT_DIR),$$ws/.auditooor/solidity-deep-audit)"; \
	repo_root="$$PWD"; \
	contract_rel=""; contract_name=""; contract_project_root=""; \
	if [ -n "$(CONTRACT_FILE)" ]; then \
	  contract_info="$$(python3 -c 'import sys; exec("from pathlib import Path\nws=Path(sys.argv[1]).resolve()\nraw=Path(sys.argv[2])\npath=(raw if raw.is_absolute() else ws/raw).resolve()\nif not path.is_relative_to(ws):\n    sys.stderr.write(\"CONTRACT_FILE must be inside workspace\\n\")\n    sys.exit(2)\nif not path.is_file():\n    sys.stderr.write(\"CONTRACT_FILE not found: %s\\n\" % path)\n    sys.exit(2)\nroot=ws\ncur=path.parent\nwhile True:\n    if any(cur.glob(\"hardhat.config.*\")) or (cur/\"foundry.toml\").is_file():\n        root=cur\n        break\n    if cur == ws:\n        break\n    cur=cur.parent\nprint(str(path.relative_to(ws)).replace(\"\\\\\\\\\",\"/\")+\"\\t\"+path.stem+\"\\t\"+str(root))")' "$$ws" "$(CONTRACT_FILE)")" || exit $$?; \
	  contract_rel="$$(printf '%s' "$$contract_info" | cut -f1)"; \
	  contract_name="$$(printf '%s' "$$contract_info" | cut -f2)"; \
	  contract_project_root="$$(printf '%s' "$$contract_info" | cut -f3-)"; \
	fi; \
	mkdir -p "$$out"; \
	if [ -f "$$repo_root/tools/forge-deps-checker.py" ]; then \
	  echo "[audit-deep-solidity] forge-deps-checker (--fix) - repairing foundry build prerequisites before harness authoring/engines"; \
	  python3 "$$repo_root/tools/forge-deps-checker.py" "$$ws" --fix >> "$$out/forge-deps-checker.stdout.log" 2>> "$$out/forge-deps-checker.stderr.log" || \
	    echo "[audit-deep-solidity] WARN forge-deps-checker reported issues; continuing (engine steps emit skip artifacts when build prerequisites are unmet)" >&2; \
	else \
	  echo "[audit-deep-solidity] WARN tools/forge-deps-checker.py absent; skipping foundry dependency repair" >&2; \
	fi; \
	if [ -f "$$repo_root/tools/forge-build-readiness-check.py" ]; then \
	  if ! python3 "$$repo_root/tools/forge-build-readiness-check.py" "$$ws" --check > "$$out/_early_build_readiness.log" 2>&1; then \
	    echo "[audit-deep-solidity] *** BUILD-READINESS (EARLY GUARD): production test tree does NOT compile ***" >&2; \
	    echo "[audit-deep-solidity]   This fires at step-2 START (right after forge-deps-checker), NOT at the late genuine-coverage gate." >&2; \
	    echo "[audit-deep-solidity]   The harness authoring + halmos/echidna/medusa engines below will be VACUOUS on a broken build (the 0/N-phantom class)." >&2; \
	    echo "[audit-deep-solidity]   Fix remappings / pragma conflict / stray test file FIRST. Diagnostic tail:" >&2; \
	    tail -15 "$$out/_early_build_readiness.log" >&2 || true; \
	    python3 -c 'import json,sys,os; from datetime import datetime,timezone; from pathlib import Path; Path(sys.argv[1]).write_text(json.dumps({"schema":"auditooor.early_build_readiness.v1","status":"build-broken","stage":"audit-deep-solidity-start","note":"production tree does not compile at step-2 start; authoring+engines will be vacuous until fixed","generated_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z")},indent=2)+"\n")' "$$ws/.auditooor/early_build_readiness.json" 2>/dev/null || true; \
	  else \
	    echo "[audit-deep-solidity] early build-readiness OK: production tree compiles - proceeding to authoring + engines"; \
	    rm -f "$$ws/.auditooor/early_build_readiness.json" 2>/dev/null || true; \
	  fi; \
	fi; \
	has_hardhat=0; has_foundry=0; has_sol_src=0; \
	if find "$$ws" \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'lib' -o -name 'out' -o -name 'artifacts' -o -name 'cache' -o -name 'poc-tests' -o -name 'poc_execution' -o -name 'reference' -o -name 'prior_audits' -o -name 'submissions' -o -name 'agent_outputs' -o -name 'mining_rounds' -o -name 'scanners' -o -name 'swarm' \) -prune \) -o -type f -name 'hardhat.config.*' -print -quit 2>/dev/null | grep -q .; then has_hardhat=1; fi; \
	if find "$$ws" \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'lib' -o -name 'out' -o -name 'artifacts' -o -name 'cache' -o -name 'poc-tests' -o -name 'poc_execution' -o -name 'reference' -o -name 'prior_audits' -o -name 'submissions' -o -name 'agent_outputs' -o -name 'mining_rounds' -o -name 'scanners' -o -name 'swarm' \) -prune \) -o -type f -name 'foundry.toml' -print -quit 2>/dev/null | grep -q .; then has_foundry=1; fi; \
	if [ -d "$$ws/src" ] && find "$$ws/src" -type f -name '*.sol' -print -quit 2>/dev/null | grep -q .; then has_sol_src=1; fi; \
	write_artifact() { \
	  artifact="$$1"; tool="$$2"; status="$$3"; reason="$$4"; rc="$$5"; cmd="$$6"; stdout_path="$${7:-}"; stderr_path="$${8:-}"; \
	  python3 -c 'import json, os, sys; from datetime import datetime, timezone; from pathlib import Path; artifact=Path(sys.argv[1]); stdout=Path(sys.argv[7]) if sys.argv[7] else None; stderr=Path(sys.argv[8]) if sys.argv[8] else None; read=lambda p: p.read_text(encoding="utf-8", errors="replace")[-4000:] if p and p.exists() else ""; payload={"schema":"auditooor.solidity_deep_audit.step.v1","generated_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"workspace":sys.argv[9],"run_id":os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or None,"tool":sys.argv[2],"status":sys.argv[3],"reason":sys.argv[4],"returncode":None if sys.argv[5] == "" else int(sys.argv[5]),"command":sys.argv[6],"stdout_log":str(stdout) if stdout else None,"stderr_log":str(stderr) if stderr else None,"stdout_tail":read(stdout),"stderr_tail":read(stderr)}; artifact.write_text(json.dumps(payload, indent=2, sort_keys=True)+"\n", encoding="utf-8")' "$$artifact" "$$tool" "$$status" "$$reason" "$$rc" "$$cmd" "$$stdout_path" "$$stderr_path" "$$ws"; \
	}; \
	run_step() { \
	  name="$$1"; shift; stdout_path="$$out/$$name.stdout.log"; stderr_path="$$out/$$name.stderr.log"; cmd="$$*"; \
	  _step_to="" ; if command -v gtimeout >/dev/null 2>&1; then _step_to="gtimeout --kill-after=30 -s TERM $${AUDITOOOR_DEEP_STEP_TIMEOUT:-1800}" ; elif command -v timeout >/dev/null 2>&1; then _step_to="timeout --kill-after=30 -s TERM $${AUDITOOOR_DEEP_STEP_TIMEOUT:-1800}" ; fi ; \
	  if $$_step_to "$$@" >"$$stdout_path" 2>"$$stderr_path"; then rc=0; status="ok"; reason="completed"; else rc=$$?; if [ "$$rc" = "124" ] || [ "$$rc" = "137" ]; then status="timeout"; reason="deep-engine step exceeded $${AUDITOOOR_DEEP_STEP_TIMEOUT:-1800}s wall-clock cap (bounded skip - a hung engine can no longer stall audit-deep; raise AUDITOOOR_DEEP_STEP_TIMEOUT for genuine long fuzz campaigns)"; else status="blocked"; reason="command exited $$rc"; fi; fi; \
	  write_artifact "$$out/$$name.json" "$$name" "$$status" "$$reason" "$$rc" "$$cmd" "$$stdout_path" "$$stderr_path"; \
	}; \
	skip_step() { \
	  name="$$1"; reason="$$2"; cmd="$$3"; \
	  write_artifact "$$out/$$name.json" "$$name" "skipped" "$$reason" "" "$$cmd" "" ""; \
	}; \
	render_cmd() { \
	  printf '%s' "$$1"; shift; \
	  for arg in "$$@"; do printf ' %s' "$$arg"; done; \
	}; \
	run_in_project() { \
	  proj="$$1"; shift; \
	  (cd "$$proj" && \
	    if [ -z "$${PRIVATE_KEY:-}" ] && find . -maxdepth 1 -type f -name 'hardhat.config.*' -print -quit 2>/dev/null | grep -q .; then \
	      export PRIVATE_KEY="0x59c6995e998f97a5a0044966f094538880e6e10f2e0f5b8680f7abf9e6e3e8e0"; \
	    fi; \
	    "$$@"); \
	}; \
	first_hardhat_root() { \
	  find "$$ws" \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'lib' -o -name 'out' -o -name 'artifacts' -o -name 'cache' -o -name 'poc-tests' -o -name 'poc_execution' -o -name 'reference' -o -name 'prior_audits' -o -name 'submissions' -o -name 'agent_outputs' -o -name 'mining_rounds' -o -name 'scanners' -o -name 'swarm' \) -prune \) -o -type f -name 'hardhat.config.*' -print 2>/dev/null | while read -r cfg; do \
	    root="$${cfg%/*}"; rel="$${root#$$ws/}"; depth="$$(printf '%s\n' "$$rel" | awk -F/ '{print NF}')"; pref=1; \
	    if [ -f "$$root/echidna.yaml" ] || [ -f "$$root/echidna.yml" ]; then pref=0; fi; \
	    printf '%s\t%s\t%s\n' "$$pref" "$$depth" "$$root"; \
	  done | sort -t "	" -k1,1n -k2,2n -k3,3 | head -1 | cut -f3-; \
	}; \
	first_foundry_root() { \
	  find "$$ws" \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'lib' -o -name 'out' -o -name 'artifacts' -o -name 'cache' -o -name 'poc-tests' -o -name 'poc_execution' -o -name 'reference' -o -name 'prior_audits' -o -name 'submissions' -o -name 'agent_outputs' -o -name 'mining_rounds' -o -name 'scanners' -o -name 'swarm' \) -prune \) -o -type f -name 'foundry.toml' -print 2>/dev/null | while read -r cfg; do \
	    root="$${cfg%/*}"; rel="$${root#$$ws/}"; depth="$$(printf '%s\n' "$$rel" | awk -F/ '{print NF}')"; \
	    printf '%s\t%s\n' "$$depth" "$$root"; \
	  done | sort -t "	" -k1,1n -k2,2 | head -1 | cut -f2-; \
	}; \
	first_engine_harness_root() { \
	  if [ ! -d "$$ws/poc-tests" ]; then return 0; fi; \
	  find "$$ws/poc-tests" -mindepth 1 -maxdepth 1 -type d -name '*-engine-harness' -print 2>/dev/null | while read -r root; do \
	    if { find "$$root" -maxdepth 1 -type f -name 'foundry.toml' -print -quit 2>/dev/null; find "$$root" -maxdepth 1 -type f -name 'hardhat.config.*' -print -quit 2>/dev/null; } | grep -q .; then \
	      printf '%s\n' "$$root"; \
	    fi; \
	  done | sort | head -1; \
	}; \
	first_fuzz_props_contract() { \
	  if [ ! -d "$$project_root/test" ]; then return 0; fi; \
	  find "$$project_root/test" -maxdepth 1 -type f -name '*_FuzzProps.sol' -print 2>/dev/null | sort | head -1 | while read -r fuzz; do \
	    base="$${fuzz##*/}"; \
	    printf '%s\n' "$${base%.sol}"; \
	  done; \
	}; \
	hardhat_root="$$(first_hardhat_root)"; \
	foundry_root="$$(first_foundry_root)"; \
	engine_harness_root="$$(first_engine_harness_root)"; \
	if [ -n "$(PROJECT_ROOT)" ]; then \
	  project_root="$(PROJECT_ROOT)"; \
	elif [ -n "$$contract_project_root" ]; then \
	  project_root="$$contract_project_root"; \
	elif [ -n "$$engine_harness_root" ]; then \
	  project_root="$$engine_harness_root"; \
	elif [ -n "$$hardhat_root" ]; then \
	  project_root="$$hardhat_root"; \
	elif [ -n "$$foundry_root" ]; then \
	  project_root="$$foundry_root"; \
	else \
	  project_root="$$ws"; \
	fi; \
	project_has_hardhat=0; \
	if find "$$project_root" -maxdepth 1 -type f -name 'hardhat.config.*' -print -quit 2>/dev/null | grep -q .; then project_has_hardhat=1; fi; \
	project_has_foundry=0; \
	if [ -f "$$project_root/foundry.toml" ]; then project_has_foundry=1; fi; \
	foundry_engine_root="$$project_root"; foundry_engine_has="$$project_has_foundry"; \
	if [ "$$project_has_foundry" != "1" ] && [ -n "$$foundry_root" ] && [ -f "$$foundry_root/foundry.toml" ]; then \
	  foundry_engine_root="$$foundry_root"; foundry_engine_has=1; \
	  echo "[audit-deep-solidity] NOTE project_root ($$project_root) lacks foundry.toml; foundry engines (halmos/foundry-invariant) will use nested foundry project $$foundry_root" >&2; \
	fi; \
	project_kind="unknown"; \
	if [ "$$project_has_hardhat" = "1" ]; then project_kind="hardhat"; elif [ "$$project_has_foundry" = "1" ]; then project_kind="foundry"; fi; \
	if [ -n "$$engine_harness_root" ]; then \
	  if find "$$engine_harness_root" -maxdepth 1 -type f -name 'hardhat.config.*' -print -quit 2>/dev/null | grep -q .; then has_hardhat=1; fi; \
	  if [ -f "$$engine_harness_root/foundry.toml" ]; then has_foundry=1; fi; \
	fi; \
	echidna_config=""; \
	if [ -f "$$foundry_engine_root/echidna.yaml" ]; then echidna_config="echidna.yaml"; elif [ -f "$$foundry_engine_root/echidna.yml" ]; then echidna_config="echidna.yml"; \
	elif [ -f "$$project_root/echidna.yaml" ]; then echidna_config="echidna.yaml"; elif [ -f "$$project_root/echidna.yml" ]; then echidna_config="echidna.yml"; fi; \
	echidna_contract=""; \
	if [ -f "$$foundry_engine_root/contracts/echidna/EchidnaTest.sol" ] || [ -f "$$foundry_engine_root/contracts/EchidnaTest.sol" ]; then echidna_contract="EchidnaTest"; \
	elif [ -f "$$project_root/contracts/echidna/EchidnaTest.sol" ] || [ -f "$$project_root/contracts/EchidnaTest.sol" ]; then echidna_contract="EchidnaTest"; fi; \
	if [ -z "$$echidna_contract" ]; then echidna_contract="$$(first_fuzz_props_contract)"; fi; \
	medusa_target_contract="$$echidna_contract"; \
	if [ "$$has_hardhat$$has_foundry$$has_sol_src" = "000" ]; then \
	  skip_step "workspace-detection" "no hardhat.config.*, foundry.toml, or src/**/*.sol marker found" "detect Solidity workspace"; \
	else \
	  write_artifact "$$out/workspace-detection.json" "workspace-detection" "ok" "Solidity workspace marker found" "0" "detect Solidity workspace" "" ""; \
	fi; \
	if [ -f tools/foundry-scaffold-verified-source.py ]; then \
	  fsvs_stdout="$$out/foundry-scaffold-verified-source.stdout.log"; fsvs_stderr="$$out/foundry-scaffold-verified-source.stderr.log"; \
	  fsvs_cmd="python3 tools/foundry-scaffold-verified-source.py $$ws --fix --solc-install"; \
	  if python3 tools/foundry-scaffold-verified-source.py "$$ws" --fix --solc-install --json >"$$fsvs_stdout" 2>"$$fsvs_stderr"; then \
	    write_artifact "$$out/foundry-scaffold-verified-source.json" "foundry-scaffold-verified-source" "ok" "verified-source scaffold complete (NO-OP when foundry/hardhat present)" "0" "$$fsvs_cmd" "$$fsvs_stdout" "$$fsvs_stderr"; \
	  else \
	    echo "[audit-deep-solidity] ADVISORY foundry-scaffold-verified-source non-zero; continuing (engines emit their own skip/error artifacts)" >&2; \
	    write_artifact "$$out/foundry-scaffold-verified-source.json" "foundry-scaffold-verified-source" "blocked" "scaffolder exited non-zero (advisory; non-blocking)" "1" "$$fsvs_cmd" "$$fsvs_stdout" "$$fsvs_stderr"; \
	  fi; \
	else \
	  skip_step "foundry-scaffold-verified-source" "tools/foundry-scaffold-verified-source.py missing" "python3 tools/foundry-scaffold-verified-source.py $$ws --fix"; \
	fi; \
	if [ -f "$$project_root/foundry.toml" ]; then project_has_foundry=1; fi; \
	if [ -f "$$ws/foundry.toml" ]; then has_foundry=1; fi; \
	if [ -n "$$engine_harness_root" ] && [ -f "$$engine_harness_root/foundry.toml" ]; then has_foundry=1; fi; \
	if [ "$$project_has_foundry" = "1" ] && [ "$$project_kind" = "unknown" ]; then project_kind="foundry"; fi; \
	if [ -f tools/hackerman-brief-for-lane.py ]; then \
	  if [ -n "$$contract_rel" ]; then scope_files="$$contract_rel"; else scope_files="$$(find "$$ws" -path '*/.git' -prune -o -type f -name '*.sol' -print 2>/dev/null | head -20 | paste -sd, -)"; fi; \
	  if [ -z "$$scope_files" ]; then scope_files="$$ws/SCOPE.md"; fi; \
	  run_step "hackerman-brief" make --no-print-directory hacker-brief WS="$$ws" LANE="solidity-deep-audit" FILES="$$scope_files"; \
	else \
	  skip_step "hackerman-brief" "tools/hackerman-brief-for-lane.py missing" "make hacker-brief WS=$$ws LANE=solidity-deep-audit"; \
	fi; \
	if [ -x tools/slither-resilient.sh ] && command -v slither >/dev/null 2>&1; then \
	  run_step "slither-resilient" bash tools/slither-resilient.sh --timeout 120 -- "$$ws"; \
	else \
	  skip_step "slither-resilient" "slither not found on PATH or tools/slither-resilient.sh not executable" "bash tools/slither-resilient.sh --timeout 120 -- $$ws"; \
	fi; \
	if [ -f tools/regex-detectors-orchestrator.py ]; then \
	  run_step "regex-detectors-solidity" python3 tools/regex-detectors-orchestrator.py --workspace "$$ws" --output "$$out/regex-detectors-solidity.output.json" --output-jsonl "$$out/regex-detectors-solidity.findings.jsonl" --json; \
	else \
	  skip_step "regex-detectors-solidity" "tools/regex-detectors-orchestrator.py missing" "python3 tools/regex-detectors-orchestrator.py --workspace $$ws"; \
	fi; \
	if [ -f tools/economic-invariant-detectors.py ]; then \
	  run_step "economic-invariant-detectors" python3 tools/economic-invariant-detectors.py --workspace "$$ws" --json; \
	else \
	  skip_step "economic-invariant-detectors" "tools/economic-invariant-detectors.py missing" "python3 tools/economic-invariant-detectors.py --workspace $$ws --json"; \
	fi; \
	if [ -f tools/aderyn-orchestrator.py ]; then \
	  run_step "aderyn-solidity" python3 tools/aderyn-orchestrator.py --workspace "$$ws" --output "$$out/aderyn-solidity.output.json" --json; \
	else \
	  skip_step "aderyn-solidity" "tools/aderyn-orchestrator.py missing" "python3 tools/aderyn-orchestrator.py --workspace $$ws"; \
	fi; \
	if [ -f tools/semgrep-orchestrator.py ]; then \
	  run_step "semgrep-solidity" python3 tools/semgrep-orchestrator.py --workspace "$$ws" --output "$$out/semgrep-solidity.output.json" --json; \
	else \
	  skip_step "semgrep-solidity" "tools/semgrep-orchestrator.py missing" "python3 tools/semgrep-orchestrator.py --workspace $$ws"; \
	fi; \
	if [ -f detectors/run_custom.py ]; then \
	  w14_stdout="$$out/wave14-slither-ast.stdout.log"; w14_stderr="$$out/wave14-slither-ast.stderr.log"; \
	  w14_target="$$project_root"; \
	  w14_cmd="python3 detectors/run_custom.py $$project_root"; \
	  if python3 detectors/run_custom.py "$$w14_target" >"$$w14_stdout" 2>"$$w14_stderr"; then \
	    write_artifact "$$out/wave14-slither-ast.json" "wave14-slither-ast" "ok" "completed" "0" "$$w14_cmd" "$$w14_stdout" "$$w14_stderr"; \
	  else \
	    _w14_rc=$$?; \
	    if [ $$_w14_rc -eq 2 ]; then \
	      echo "[audit-deep-solidity] PREREQ NOTICE wave14-slither-ast rc=2: run make slither-cache-warm or fix Solidity compile prerequisites" >&2; \
	      write_artifact "$$out/wave14-slither-ast.json" "wave14-slither-ast" "skipped" "PREREQ NOTICE: run make slither-cache-warm or fix Solidity compile prerequisites" "$$_w14_rc" "$$w14_cmd" "$$w14_stdout" "$$w14_stderr"; \
	    else \
	      write_artifact "$$out/wave14-slither-ast.json" "wave14-slither-ast" "blocked" "command exited $$_w14_rc" "$$_w14_rc" "$$w14_cmd" "$$w14_stdout" "$$w14_stderr"; \
	    fi; \
	  fi; \
	else \
	  skip_step "wave14-slither-ast" "detectors/run_custom.py missing (wave14 887 AST patterns + every other wave*/ Slither AbstractDetector)" "python3 detectors/run_custom.py $$ws"; \
	fi; \
	if [ -f tools/changelog-source-drift-miner.py ]; then \
	  run_step "changelog-source-drift-miner" python3 tools/changelog-source-drift-miner.py --workspace "$$ws" --json --output "$$out/changelog-source-drift-miner.output.json"; \
	else \
	  skip_step "changelog-source-drift-miner" "tools/changelog-source-drift-miner.py missing" "python3 tools/changelog-source-drift-miner.py --workspace $$ws"; \
	fi; \
	if [ -f tools/reverted-guard-mine.py ]; then \
	  run_step "reverted-guard-mine" python3 tools/reverted-guard-mine.py --workspace "$$ws" --lang sol --out "$$out/reverted-guard-mine.output.json"; \
	else \
	  skip_step "reverted-guard-mine" "tools/reverted-guard-mine.py missing" "python3 tools/reverted-guard-mine.py --workspace $$ws --lang sol"; \
	fi; \
	if [ -f tools/mine-solidity-fork-patterns.py ]; then \
	  run_step "mine-solidity-fork-patterns" python3 tools/mine-solidity-fork-patterns.py --workspace "$$ws" --reports-dir "$$out" --patterns-dir "$$out/patterns" --replay --no-network --json; \
	else \
	  skip_step "mine-solidity-fork-patterns" "tools/mine-solidity-fork-patterns.py missing" "python3 tools/mine-solidity-fork-patterns.py --workspace $$ws --replay"; \
	fi; \
	if [ -f tools/gen-composition-fixtures.py ]; then \
	  run_step "composition-fixtures" python3 tools/gen-composition-fixtures.py --workspace "$$ws" --out-dir "$$out/composition-fixtures" --max-pairs "$(if $(COMPOSITION_MAX_PAIRS),$(COMPOSITION_MAX_PAIRS),2)" --plan-only --json; \
	else \
	  skip_step "composition-fixtures" "tools/gen-composition-fixtures.py missing" "python3 tools/gen-composition-fixtures.py --workspace $$ws"; \
	fi; \
	if [ -f tools/per-function-invariant-gen.py ]; then \
	  run_step "per-function-invariant-gen" python3 tools/per-function-invariant-gen.py --workspace "$$ws" --output-dir "$$ws/.auditooor/per_function_invariants" --overwrite; \
	else \
	  skip_step "per-function-invariant-gen" "tools/per-function-invariant-gen.py missing" "python3 tools/per-function-invariant-gen.py --workspace $$ws"; \
	fi; \
	if [ -f tools/chimera-echidna-emit.py ] && [ -d "$$ws/chimera_harnesses" ]; then \
	  run_step "chimera-echidna-emit" python3 tools/chimera-echidna-emit.py --workspace "$$ws" --json; \
	else \
	  skip_step "chimera-echidna-emit" "no chimera_harnesses/ dir (nothing to make echidna-ready)" "python3 tools/chimera-echidna-emit.py --workspace $$ws"; \
	fi; \
	if { [ "$${AUDITOOOR_AUDIT_DEEP_LIVE:-}" = "1" ] || [ "$(LIVE)" = "1" ]; } && [ -f tools/evm-engine-harness-author.py ]; then \
	  _eha_max="$${HARNESS_AUTHOR_MAX_CONTRACTS:-10}"; \
	  _eha_authored=0; _eha_skipped=0; _eha_first_new=""; \
	  _eha_stdout="$$out/evm-engine-harness-author.stdout.log"; _eha_stderr="$$out/evm-engine-harness-author.stderr.log"; \
	  : > "$$_eha_stdout"; : > "$$_eha_stderr"; \
	  if [ -d "$$ws/src" ]; then \
	    { if python3 "$$repo_root/tools/inscope-source-files.py" "$$ws" --ext .sol --exists-only 2>/dev/null; then :; \
	      else \
	        find "$$ws/src" -type f -name '*.sol' \
	          ! -path '*/test/*' ! -path '*/tests/*' ! -path '*/mock*' ! -path '*/Mock*' \
	          ! -path '*/interfaces/*' ! -path '*/interface/*' \
	          ! -path '*/.git/*' \
	          ! -path '*/lib/*' ! -path '*/node_modules/*' ! -path '*/out/*' \
	          ! -path '*/cache/*' ! -path '*/script/*' ! -path '*/forge-std/*' \
	          ! -path '*/dependencies/*' \
	          ! -path '*/.auditooor/*' \
	          -print 2>/dev/null; \
	      fi; } | { if [ -f "$$repo_root/tools/rank-paths-by-guard-triage.py" ] && [ -f "$$ws/.auditooor/guard_triage.json" ]; then \
	          python3 "$$repo_root/tools/rank-paths-by-guard-triage.py" --workspace "$$ws" 2>/dev/null || sort -u; \
	        else sort -u; fi; } | head -n "$$_eha_max" | \
	    while IFS= read -r _sol; do \
	      _cname="$$(basename "$$_sol" .sol)"; \
	      _hdir="$$ws/poc-tests/$${_cname}-engine-harness"; \
	      if [ -d "$$_hdir" ] && [ -f "$$_hdir/foundry.toml" ]; then \
	        printf '[evm-engine-harness-author] skip %s (already exists: %s)\n' "$$_cname" "$$_hdir" >> "$$_eha_stdout"; \
	        _eha_skipped=$$(($$_eha_skipped + 1)); \
	        continue; \
	      fi; \
	      if python3 "$$repo_root/tools/evm-engine-harness-author.py" "$$ws" "$$_sol" \
	            >> "$$_eha_stdout" 2>> "$$_eha_stderr"; then \
	        _eha_authored=$$(($$_eha_authored + 1)); \
	        if [ -z "$$_eha_first_new" ] && [ -d "$$_hdir" ]; then \
	          _eha_first_new="$$_hdir"; \
	        fi; \
	      else \
	        _rc=$$?; \
	        if [ "$$_rc" = "2" ]; then \
	          printf '[evm-engine-harness-author] skip %s (no mutating surface / interface)\n' "$$_cname" >> "$$_eha_stdout"; \
	        else \
	          printf '[evm-engine-harness-author] WARN %s exited %s\n' "$$_cname" "$$_rc" >> "$$_eha_stderr"; \
	        fi; \
	      fi; \
	    done; \
	    _eha_authored=$$(grep -c '\[evm-engine-harness-author\] skip\|evm_engine_harness_author' "$$_eha_stdout" 2>/dev/null || echo 0) || true; \
	  fi; \
	  _eha_new_count="$$(find "$$ws/poc-tests" -mindepth 1 -maxdepth 1 -type d -name '*-engine-harness' 2>/dev/null | wc -l | tr -d ' ')"; \
	  write_artifact "$$out/evm-engine-harness-author.json" "evm-engine-harness-author" "ok" \
	    "harness-author ran (LIVE=1); poc-tests/*-engine-harness count=$$_eha_new_count" "0" \
	    "python3 tools/evm-engine-harness-author.py $$ws <contract>" "$$_eha_stdout" "$$_eha_stderr"; \
	  if [ -z "$$engine_harness_root" ] || [ ! -d "$$engine_harness_root" ]; then \
	    _first_authored="$$(find "$$ws/poc-tests" -mindepth 1 -maxdepth 1 -type d -name '*-engine-harness' 2>/dev/null | sort | head -1)"; \
	    if [ -n "$$_first_authored" ] && [ -f "$$_first_authored/foundry.toml" ]; then \
	      engine_harness_root="$$_first_authored"; \
	      project_root="$$engine_harness_root"; \
	      foundry_engine_root="$$engine_harness_root"; foundry_engine_has=1; \
	      echo "[audit-deep-solidity] evm-engine-harness-author: engine_harness_root now $$engine_harness_root" >&2; \
	    fi; \
	  fi; \
	else \
	  if [ ! -f tools/evm-engine-harness-author.py ]; then \
	    skip_step "evm-engine-harness-author" "tools/evm-engine-harness-author.py missing" \
	      "python3 tools/evm-engine-harness-author.py $$ws <contract>"; \
	  else \
	    skip_step "evm-engine-harness-author" \
	      "offline mode: set AUDITOOOR_AUDIT_DEEP_LIVE=1 (or LIVE=1) to author engine harnesses from corpus invariants" \
	      "AUDITOOOR_AUDIT_DEEP_LIVE=1 make audit-deep-solidity WS=$$ws"; \
	  fi; \
	fi; \
	if [ -f tools/foundry-harness-dep-resolve.py ]; then \
	  echo "[audit-deep-solidity] resolving authored-harness build deps (forge-std/solady/oz remappings)"; \
	  python3 tools/foundry-harness-dep-resolve.py --workspace "$$ws" $(if $(JSON),--json) || \
	    echo "[audit-deep-solidity] WARN foundry-harness-dep-resolve returned non-zero; continuing (offline-safe; authored harnesses may have unresolved deps)" >&2; \
	else \
	  echo "[audit-deep-solidity] SKIP tools/foundry-harness-dep-resolve.py absent (authored-harness deps not resolved this run)" >&2; \
	fi; \
	_exec_harness_count=0; \
	_exec_harness_results="[]"; \
	if command -v forge >/dev/null 2>&1 && [ -d "$$ws/poc-tests" ]; then \
	  _ehe_json_parts=""; \
	  for _ehdir in $$(find "$$ws/poc-tests" -mindepth 1 -maxdepth 1 -type d -name '*-engine-harness' 2>/dev/null | sort); do \
	    if [ ! -f "$$_ehdir/foundry.toml" ]; then continue; fi; \
	    _ehe_log="$$out/engine-harness-execution-$$(basename $$_ehdir).log"; \
	    _ehe_pass=0; _ehe_fail=0; \
	    (cd "$$_ehdir" && forge test 2>&1) | tee "$$_ehe_log"; _ehe_rc=$${PIPESTATUS[0]:-1}; \
	    _ehe_pass=$$(grep -c '\[PASS\]' "$$_ehe_log" 2>/dev/null); _ehe_pass=$${_ehe_pass:-0}; \
	    _ehe_fail=$$(grep -c '\[FAIL\]' "$$_ehe_log" 2>/dev/null); _ehe_fail=$${_ehe_fail:-0}; \
	    _ehe_status="fail"; \
	    if [ "$$_ehe_pass" -gt 0 ] && [ "$$_ehe_rc" = "0" ]; then _ehe_status="pass"; _exec_harness_count=$$(($$_exec_harness_count + 1)); \
	    elif [ "$$_ehe_pass" -gt 0 ]; then _ehe_status="pass-with-failures"; _exec_harness_count=$$(($$_exec_harness_count + 1)); fi; \
	    _ehe_part="{\"root\":\"$$_ehdir\",\"status\":\"$$_ehe_status\",\"tests_passed\":$$_ehe_pass,\"tests_failed\":$$_ehe_fail,\"exit_code\":$$_ehe_rc}"; \
	    if [ -z "$$_ehe_json_parts" ]; then _ehe_json_parts="$$_ehe_part"; else _ehe_json_parts="$$_ehe_json_parts,$$_ehe_part"; fi; \
	  done; \
	  _exec_harness_results="[$$_ehe_json_parts]"; \
	  printf '{"schema":"auditooor.engine_harness_execution.v1","executed_engine_harness_count":%d,"harnesses":%s}\n' "$$_exec_harness_count" "$$_exec_harness_results" > "$$out/engine-harness-execution.json"; \
	  echo "[audit-deep-solidity] engine-harness-execution: $$_exec_harness_count harness(es) with >=1 passing test" >&2; \
	elif [ -d "$$ws/poc-tests" ]; then \
	  _eha_dirs=$$(find "$$ws/poc-tests" -mindepth 1 -maxdepth 1 -type d -name '*-engine-harness' -exec test -f "{}/foundry.toml" \; -print 2>/dev/null | wc -l | tr -d ' '); \
	  echo "[audit-deep-solidity] engine-harness-execution: forge not on PATH; $$_eha_dirs authored harness(es) not executed" >&2; \
	fi; \
	if [ -f "$$repo_root/tools/forge-build-readiness-check.py" ]; then \
	  if ! python3 "$$repo_root/tools/forge-build-readiness-check.py" "$$ws" --check > "$$out/_postauthor_build_readiness.log" 2>&1; then \
	    echo "[audit-deep-solidity] *** BUILD-READINESS (POST-AUTHOR GUARD): test tree does NOT compile AFTER harness authoring ***" >&2; \
	    echo "[audit-deep-solidity]   This fires right after evm-engine-harness-author, BEFORE the halmos/echidna/medusa engines run." >&2; \
	    echo "[audit-deep-solidity]   An authored harness does not compile (e.g. arg-synth / array-param / import corruption); the engines below would be VACUOUS (0/N-phantom)." >&2; \
	    echo "[audit-deep-solidity]   Diagnostic tail:" >&2; tail -15 "$$out/_postauthor_build_readiness.log" >&2 || true; \
	    python3 -c 'import json,sys; from datetime import datetime,timezone; from pathlib import Path; Path(sys.argv[1]).write_text(json.dumps({"schema":"auditooor.postauthor_build_readiness.v1","status":"build-broken","stage":"post-harness-author","note":"authored test tree does not compile; engines below will be vacuous until fixed","generated_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z")},indent=2)+"\n")' "$$ws/.auditooor/postauthor_build_readiness.json" 2>/dev/null || true; \
	  else \
	    rm -f "$$ws/.auditooor/postauthor_build_readiness.json" 2>/dev/null || true; \
	  fi; \
	fi; \
	. tools/lib/deep-engine-resolve.sh; \
	run_deep_engines=1; \
	if [ "$${AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE:-}" = "1" ] && [ "$${AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE_RUN_DEEP_ENGINES:-}" != "1" ]; then run_deep_engines=0; fi; \
	halmos_cmd="$$(render_cmd run_in_project "$$foundry_engine_root" bash "$$repo_root/tools/halmos-runner.sh" "$$ws")"; \
	if [ "$$run_deep_engines" = "1" ] && [ "$$foundry_engine_has" = "1" ] && [ -x tools/halmos-runner.sh ] && { [ "$${AUDITOOOR_DEEP_SKIP_HALMOS:-}" = "1" ] || deep_engine_available halmos; }; then \
	  run_step "halmos-runner" run_in_project "$$foundry_engine_root" bash "$$repo_root/tools/halmos-runner.sh" "$$ws"; \
	elif [ "$$run_deep_engines" != "1" ]; then \
	  skip_step "halmos-runner" "smoke mode skips deep engines (set AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE_RUN_DEEP_ENGINES=1 to run)" "$$halmos_cmd"; \
	elif [ "$$foundry_engine_has" != "1" ]; then \
	  skip_step "halmos-runner" "incompatible_project_type: foundry.toml missing at project root" "$$halmos_cmd"; \
	else \
	  skip_step "halmos-runner" "halmos not provisioned (run: make deep-engines-provision)" "$$halmos_cmd"; \
	fi; \
	set -- run_in_project "$$foundry_engine_root" bash "$$repo_root/tools/echidna-campaign.sh" "$$ws" "."; \
	if [ -n "$$echidna_config" ]; then set -- "$$@" --config "$$echidna_config"; fi; \
	if [ -n "$$echidna_contract" ]; then set -- "$$@" --contract "$$echidna_contract"; fi; \
	echidna_cmd="$$(render_cmd "$$@")"; \
	if [ "$$project_has_hardhat$$project_has_foundry$$foundry_engine_has" = "000" ]; then \
	  skip_step "echidna-campaign" "incompatible_project_type: project root missing hardhat.config.* or foundry.toml" "$$echidna_cmd"; \
	elif [ "$$run_deep_engines" != "1" ]; then \
	  skip_step "echidna-campaign" "smoke mode skips deep engines (set AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE_RUN_DEEP_ENGINES=1 to run)" "$$echidna_cmd"; \
	elif [ -x tools/echidna-campaign.sh ] && { [ "$${AUDITOOOR_DEEP_SKIP_ECHIDNA:-}" = "1" ] || deep_engine_available echidna; }; then \
	  run_step "echidna-campaign" "$$@"; \
	else \
	  skip_step "echidna-campaign" "echidna not provisioned (run: make deep-engines-provision)" "$$echidna_cmd"; \
	fi; \
	medusa_config=""; \
	for _mc_root in "$$foundry_engine_root" "$$engine_harness_root" "$$project_root"; do \
	  if [ -n "$$_mc_root" ] && [ -f "$$_mc_root/medusa.json" ] && \
	     python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); t=(d.get("compilation",{}).get("platformConfig",{}) or {}).get("target"); sys.exit(0 if (isinstance(t,str) and t.strip()) else 1)' "$$_mc_root/medusa.json" 2>/dev/null; then \
	    medusa_config="$$_mc_root/medusa.json"; break; \
	  fi; \
	done; \
	if [ -n "$$medusa_config" ]; then \
	  set -- run_in_project "$$foundry_engine_root" bash "$$repo_root/tools/medusa-fuzz.sh" "$$ws" fuzz --config "$$medusa_config"; \
	else \
	  set -- run_in_project "$$foundry_engine_root" bash "$$repo_root/tools/medusa-fuzz.sh" "$$ws" fuzz --compilation-target "."; \
	fi; \
	if [ -n "$$medusa_target_contract" ]; then set -- "$$@" --target-contracts "$$medusa_target_contract"; fi; \
	medusa_cmd="$$(render_cmd "$$@")"; \
	if [ "$$project_has_hardhat$$project_has_foundry$$foundry_engine_has" = "000" ]; then \
	  skip_step "medusa-fuzz" "incompatible_project_type: project root missing hardhat.config.* or foundry.toml" "$$medusa_cmd"; \
	elif [ "$$run_deep_engines" != "1" ]; then \
	  skip_step "medusa-fuzz" "smoke mode skips deep engines (set AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE_RUN_DEEP_ENGINES=1 to run)" "$$medusa_cmd"; \
	elif [ -x tools/medusa-fuzz.sh ] && { [ "$${AUDITOOOR_DEEP_SKIP_MEDUSA:-}" = "1" ] || deep_engine_available medusa; }; then \
	  run_step "medusa-fuzz" "$$@"; \
	else \
	  skip_step "medusa-fuzz" "medusa not provisioned (run: make deep-engines-provision)" "$$medusa_cmd"; \
	fi; \
	if [ -f tools/deep-engine-output-parse.py ]; then \
	  run_step "deep-engine-output-parse" python3 tools/deep-engine-output-parse.py --workspace "$$ws"; \
	else \
	  skip_step "deep-engine-output-parse" "tools/deep-engine-output-parse.py missing" "python3 tools/deep-engine-output-parse.py --workspace $$ws"; \
	fi; \
	foundry_cmd="$$(render_cmd run_in_project "$$foundry_engine_root" forge test --match-test "invariant|Invariant" -vvv)"; \
	if [ "$$run_deep_engines" != "1" ]; then \
	  skip_step "foundry-invariant-runner" "smoke mode skips deep engines (set AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE_RUN_DEEP_ENGINES=1 to run)" "$$foundry_cmd"; \
	elif [ "$$foundry_engine_has" = "1" ] && command -v forge >/dev/null 2>&1; then \
	  run_step "foundry-invariant-runner" run_in_project "$$foundry_engine_root" forge test --match-test "invariant|Invariant" -vvv; \
	elif [ "$$foundry_engine_has" != "1" ]; then \
	  skip_step "foundry-invariant-runner" "incompatible_project_type: foundry.toml missing at project root" "$$foundry_cmd"; \
	else \
	  skip_step "foundry-invariant-runner" "forge not found on PATH" "$$foundry_cmd"; \
	fi; \
	if [ -f tools/audit/universal_fp_runner.py ]; then \
	  run_step "universal-fp-runner" python3 tools/audit/universal_fp_runner.py --workspace "$$ws" --output "$$out/universal-fp-runner.output.json" --markdown-output "$$out/universal-fp-runner.report.md"; \
	else \
	  skip_step "universal-fp-runner" "tools/audit/universal_fp_runner.py missing" "python3 tools/audit/universal_fp_runner.py --workspace $$ws"; \
	fi; \
	python3 -c 'import json, os, sys; from collections import Counter; from datetime import datetime, timezone; from pathlib import Path; out=Path(sys.argv[1]); ws=sys.argv[2]; detection={"hardhat":sys.argv[3]=="1","foundry":sys.argv[4]=="1","src_solidity":sys.argv[5]=="1","is_solidity_workspace":sys.argv[3:6] != ["0","0","0"]}; contract_scope=None if not sys.argv[6] else {"contract_file":sys.argv[6],"contract_name":sys.argv[7],"project_root":sys.argv[8]}; selected_project_root=sys.argv[8]; selected_engine_harness_root=sys.argv[9] if len(sys.argv) > 9 else ""; per_fn_manifest=next((q for q in [Path(ws)/".auditooor"/"per_function_invariants"/"manifest.json", Path(ws)/"poc-tests"/"per_function_invariants"/"manifest.json"] if q.is_file()), Path(ws)/".auditooor"/"per_function_invariants"/"manifest.json"); per_fn_payload=json.loads(per_fn_manifest.read_text(encoding="utf-8")) if per_fn_manifest.is_file() else None; fn_count=per_fn_payload.get("function_count") if isinstance(per_fn_payload, dict) else None; generated_harness_count=fn_count if isinstance(fn_count, int) else (len(per_fn_payload.get("functions") or []) if isinstance(per_fn_payload, dict) else None); harness_root_base=Path(ws)/"poc-tests"; available_engine_harness_roots=[str(root) for root in sorted(harness_root_base.glob("*-engine-harness")) if root.is_dir() and (root.joinpath("foundry.toml").is_file() or any(root.glob("hardhat.config.*")))]; available_engine_harness_count=len(available_engine_harness_roots); executed_engine_harness_count=int(sys.argv[10]) if len(sys.argv) > 10 and sys.argv[10].isdigit() else (1 if selected_engine_harness_root else 0); executed_generated_harness_count=0; invariant_denominator_status="partial-selected-engine-root-only" if executed_engine_harness_count <= 1 else "multi-harness-executed"; order={name:i for i,name in enumerate(["workspace-detection","hackerman-brief","slither-resilient","regex-detectors-solidity","economic-invariant-detectors","aderyn-solidity","semgrep-solidity","wave14-slither-ast","changelog-source-drift-miner","reverted-guard-mine","mine-solidity-fork-patterns","composition-fixtures","per-function-invariant-gen","halmos-runner","echidna-campaign","medusa-fuzz","deep-engine-output-parse","foundry-invariant-runner","universal-fp-runner"])}; loaded=[(p,json.loads(p.read_text(encoding="utf-8"))) for p in sorted(out.glob("*.json")) if p.name != "manifest.json"]; items=sorted([(p,data) for p,data in loaded if data.get("schema") == "auditooor.solidity_deep_audit.step.v1"], key=lambda item: order.get(item[1].get("tool",""), 999)); rows=[{"tool":data.get("tool"),"status":data.get("status"),"artifact":str(p)} for p,data in items]; counts=Counter(data.get("status","unknown") for _,data in items); payload={"schema":"auditooor.solidity_deep_audit.v1","generated_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"workspace":ws,"run_id":os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or None,"artifact_dir":str(out),"detection":detection,"contract_scope":contract_scope,"status_counts":dict(sorted(counts.items())),"artifacts":rows,"generated_per_function_manifest":str(per_fn_manifest),"generated_per_function_harness_count":generated_harness_count,"available_engine_harness_roots":available_engine_harness_roots,"available_engine_harness_count":available_engine_harness_count,"selected_project_root":selected_project_root,"selected_engine_harness_root":selected_engine_harness_root or None,"executed_engine_harness_count":executed_engine_harness_count,"executed_generated_harness_count":executed_generated_harness_count,"invariant_denominator_status":invariant_denominator_status}; (out/"manifest.json").write_text(json.dumps(payload, indent=2, sort_keys=True)+"\n", encoding="utf-8")' "$$out" "$$ws" "$$has_hardhat" "$$has_foundry" "$$has_sol_src" "$$contract_rel" "$$contract_name" "$$project_root" "$$engine_harness_root" "$$_exec_harness_count" || exit $$?; \
	echo "[audit-deep-solidity] wrote $$out/manifest.json"; \
	$(MAKE) --no-print-directory _audit-deep-solidity-genuine-coverage WS="$$ws" SOLIDITY_DEEP_OUT_DIR="$$out" PROJECT_ROOT="$$project_root" || \
	  echo "[audit-deep-solidity] WARN genuine-coverage mutation-verify pass returned non-zero; continuing (advisory; manifest already written)" >&2; \
	$(MAKE) --no-print-directory _audit-deep-perlang-genuine-coverage WS="$$ws" LANG_HINT=solidity PROJECT_ROOT="$$project_root" $(if $(STRICT),STRICT=1) || \
	  { _pl_rc=$$?; if [ "$(STRICT)" = "1" ]; then echo "[audit-deep-solidity] STRICT=1: cross-function/per-function producer failed rc=$$_pl_rc; refusing to continue with incomplete substrate" >&2; exit $$_pl_rc; fi; echo "[audit-deep-solidity] WARN cross-function/per-function producer returned non-zero; continuing (advisory)" >&2; }; \
	python3 tools/hollow-engine-check.py "$$ws" "$$out" || \
	  echo "[audit-deep-solidity] WARN hollow-engine-check returned non-zero; continuing (advisory)" >&2

# ---------------------------------------------------------------------------
# Per-language genuine-coverage PRODUCER (ADDITIVE - Rule R80/R81 closure, the
# cross-function + per-function half).
#
# WHY: the gates tools/function-coverage-completeness.py and
# tools/cross-function-invariant-coverage.py BOTH read the ONE canonical file
# <ws>/.auditooor/mutation_verify_coverage.json. Nothing PRODUCED that file with
# BOTH per-function AND cross-function mutation verdicts, so L37
# 'fully audited' could only pass vacuously (gate skips when the file is absent)
# or never (file never written). This producer runs the cross-function harness
# producer tool (tools/cross-function-harness-producer.py) which:
#   - runs mutation-verify on whatever per-function + cross-function harnesses
#     exist for the workspace language,
#   - AGGREGATES the per-function AND cross-function verdicts into the canonical
#     {per_function:[...], cross_function:[...], generated_at, run_id} schema,
#   - writes them to <ws>/.auditooor/mutation_verify_coverage.json (the EXACT
#     path both gates read).
# The result: L37 becomes REACHABLE when the real harnesses exist (gate sees
# genuine non-vacuous verdicts), and still FAILS (never vacuously passes) when
# the harnesses are absent / vacuous.
#
# GENERIC + LANGUAGE-AWARE: LANG_HINT routes (solidity/go/rust); the producer
# tool itself is language-aware and discovers harnesses per language.
# OFFLINE-SAFE for advisory runs: if the producer tool or language toolchain is
# absent, the step records a skip. STRICT=1 is fail-closed: a missing, timed-out,
# or failed producer is an incomplete load-bearing substrate and must stop the
# ordered pipeline before any later phase consumes partial evidence.
# ---------------------------------------------------------------------------
_audit-deep-perlang-genuine-coverage:
	@set -u; \
	ws="$(_WS_RESOLVED)"; \
	lang_hint="$(if $(LANG_HINT),$(LANG_HINT),auto)"; \
	prod_tool="tools/cross-function-harness-producer.py"; \
	if [ ! -f "$$prod_tool" ]; then \
	  echo "[perlang-genuine-coverage] SKIP $$prod_tool absent (offline-safe; canonical mutation_verify_coverage.json not produced this run)" >&2; \
	  if [ "$(STRICT)" = "1" ]; then echo "[perlang-genuine-coverage] STRICT=1: required producer is absent; refusing to continue" >&2; exit 1; fi; \
	  exit 0; \
	fi; \
	mkdir -p "$$ws/.auditooor"; \
	echo "[perlang-genuine-coverage] aggregating per-function + cross-function mutation verdicts (lang=$$lang_hint) -> $$ws/.auditooor/mutation_verify_coverage.json"; \
	_plc_to="" ; if command -v gtimeout >/dev/null 2>&1; then _plc_to="gtimeout --kill-after=30 -s TERM $${AUDITOOOR_PERLANG_PRODUCER_TIMEOUT:-1200}" ; elif command -v timeout >/dev/null 2>&1; then _plc_to="timeout --kill-after=30 -s TERM $${AUDITOOOR_PERLANG_PRODUCER_TIMEOUT:-1200}" ; fi ; \
	$$_plc_to python3 "$$prod_tool" \
	  --workspace "$$ws" \
	  --lang "$$lang_hint" \
	  $(if $(PROJECT_ROOT),--project-root "$(PROJECT_ROOT)") \
	  --out "$$ws/.auditooor/mutation_verify_coverage.json" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json) ; _plc_rc=$$? ; \
	if [ "$$_plc_rc" = "124" ] || [ "$$_plc_rc" = "137" ]; then \
	  echo "[perlang-genuine-coverage] WARN mutation-verify producer exceeded $${AUDITOOOR_PERLANG_PRODUCER_TIMEOUT:-1200}s wall-clock cap; mutation_verify_coverage.json may be partial." >&2 ; \
	  if [ "$(STRICT)" = "1" ]; then echo "[perlang-genuine-coverage] STRICT=1: refusing to continue with partial mutation evidence" >&2; exit "$$_plc_rc"; fi; \
	elif [ "$$_plc_rc" != "0" ]; then \
	  echo "[perlang-genuine-coverage] WARN producer returned non-zero rc=$$_plc_rc (offline-safe; see stderr)" >&2 ; \
	  if [ "$(STRICT)" = "1" ]; then echo "[perlang-genuine-coverage] STRICT=1: refusing to continue with incomplete mutation evidence" >&2; exit "$$_plc_rc"; fi; \
	fi

# ---------------------------------------------------------------------------
# audit-deep-go-engine (ADDITIVE): the Go DYNAMIC deep-engine arm + the Go
# per-function producer half.
#   (1) tools/go-dynamic-engine-runner.sh : `go test ./...` smoke + native
#       `go test -fuzz` on discovered FuzzXxx targets + staticcheck/govulncheck
#       (when on PATH) + cosmos production-harness; emits fuzz_runs/<ts>/manifest.json
#       that audit-completeness-check.py (L37 signal c2) credits.
#   (2) tools/per-function-invariant-gen.py --lang go : per-function harness
#       scaffolds for the Go in-scope surface (feeds the per-language producer
#       which mutation-verifies them into mutation_verify_coverage.json).
# OFFLINE-SAFE: every sub-step degrades to a skip when its tool / toolchain is
# absent; this target never breaks audit-deep.
# ---------------------------------------------------------------------------
audit-deep-go-engine:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-go-engine WS=<workspace> [STRICT=1] [LIVE=1] [GO_FUZZTIME=30s]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "audit-deep-go-engine" "$(_WS_RESOLVED)"
	@set -u; \
	ws="$(_WS_RESOLVED)"; \
	if [ -f tools/go-dynamic-engine-runner.sh ]; then \
	  echo "[audit-deep-go-engine] running Go dynamic engine (go test + go test -fuzz + staticcheck)"; \
	  bash tools/go-dynamic-engine-runner.sh "$$ws" \
	    $(if $(GO_FUZZTIME),--fuzztime "$(GO_FUZZTIME)") \
	    $(if $(STRICT),--strict) || \
	    echo "[audit-deep-go-engine] WARN go-dynamic-engine-runner returned non-zero; continuing (offline-safe)" >&2; \
	else \
	  echo "[audit-deep-go-engine] SKIP tools/go-dynamic-engine-runner.sh absent (offline-safe)" >&2; \
	fi; \
	if [ -f tools/per-function-invariant-gen.py ]; then \
	  echo "[audit-deep-go-engine] generating per-function Go harness scaffolds (--lang go)"; \
	  python3 tools/per-function-invariant-gen.py --workspace "$$ws" --lang go --output-dir "$$ws/.auditooor/per_function_invariants" --overwrite $(if $(JSON),--json) || \
	    echo "[audit-deep-go-engine] WARN per-function-invariant-gen --lang go returned non-zero; continuing (offline-safe; tool may not yet support --lang go on this revision)" >&2; \
	else \
	  echo "[audit-deep-go-engine] SKIP tools/per-function-invariant-gen.py absent" >&2; \
	fi; \
	if { [ "$${AUDITOOOR_AUDIT_DEEP_LIVE:-}" = "1" ] || [ "$(LIVE)" = "1" ]; } && [ "$${AUDITOOOR_GO_HARNESS_AUTHOR:-0}" = "1" ] && [ -f tools/go-engine-harness-author.py ]; then \
	  echo "[audit-deep-go-engine] AUTHOR opt-in (AUDITOOOR_GO_HARNESS_AUTHOR=1): authoring Go harnesses. WARNING: emits scaffold/vacuous bodies + writes auditooor_*_test.go INTO the CUT source dirs - use only for author-quality dev; the native 'go test -fuzz'+staticcheck engine (above) is the genuine coverage source."; \
	  _gha_max="$${HARNESS_AUTHOR_MAX_PACKAGES:-8}"; \
	  _gha_n=0; \
	  _scope_roots="$$(python3 -c "import json,os; p=os.path.join('$$ws','scope.json'); d=json.load(open(p)) if os.path.exists(p) else {}; print('\n'.join(os.path.join('$$ws',r) for r in d.get('in_scope',[])))" 2>/dev/null)"; \
	  if [ -n "$$_scope_roots" ]; then _gha_find_roots="$$_scope_roots"; echo "[audit-deep-go-engine] scope.json in-scope roots -> authoring only within them (no OOS/scratch leak)"; else _gha_find_roots="$$ws"; echo "[audit-deep-go-engine] no scope.json in_scope; falling back to whole-workspace enumeration"; fi; \
	  for _gpkg in $$(printf '%s\n' "$$_gha_find_roots" | while IFS= read -r _root; do [ -d "$$_root" ] && find "$$_root" -type f -name '*.go' \
	      ! -name '*_test.go' \
	      ! -path '*/vendor/*' ! -path '*/mock*' ! -path '*/Mock*' \
	      ! -path '*/.git/*' ! -path '*/.auditooor/*' \
	      -print 2>/dev/null; done | sed 's:/[^/]*$$::' | sort -u | head -n "$$_gha_max"); do \
	    _gname="$$(basename "$$_gpkg")"; \
	    echo "[audit-deep-go-engine] go-engine-harness-author: package $$_gname ($$_gpkg)"; \
	    python3 tools/go-engine-harness-author.py "$$ws" "$$_gname" --max-fns 8 $(if $(JSON),--json) || \
	      echo "[audit-deep-go-engine] WARN go-engine-harness-author for package $$_gname returned non-zero; continuing (offline-safe)" >&2; \
	    _gha_n=$$(($$_gha_n + 1)); \
	  done; \
	  echo "[audit-deep-go-engine] go-engine-harness-author: authored across $$_gha_n in-scope package(s)" >&2; \
	elif [ ! -f tools/go-engine-harness-author.py ]; then \
	  echo "[audit-deep-go-engine] SKIP tools/go-engine-harness-author.py absent (real Go harnesses not authored this run)" >&2; \
	else \
	  echo "[audit-deep-go-engine] NATIVE-FIRST: genuine Go coverage comes from the project's OWN suite (go test -fuzz + staticcheck, run above). The CUT-polluting harness-author is opt-in only (set AUDITOOOR_GO_HARNESS_AUTHOR=1 for author-quality dev)." >&2; \
	fi; \
	if [ -f tools/go-detector-runner.py ]; then \
	  _go_files="$$(find "$(_WS_RESOLVED)" -name '*.go' ! -path '*/vendor/*' ! -path '*/.git/*' 2>/dev/null | head -1)"; \
	  if [ -n "$$_go_files" ]; then \
	    echo "[audit-deep-go-engine] running go-detector-runner --fire-only (advisory needs-fuzz candidates; NO gate promotion)"; \
	    timeout 300 python3 tools/go-detector-runner.py \
	        --workspace "$(_WS_RESOLVED)" \
	        --fire-only \
	        || echo "[audit-deep-go-engine] WARN go-detector-runner --fire-only non-zero; continuing (offline-safe)" >&2; \
	    if [ -f "$(_WS_RESOLVED)/.auditooor/go_findings.json" ]; then \
	      python3 -c "\
import json, sys; \
findings = json.load(open('$(_WS_RESOLVED)/.auditooor/go_findings.json')); \
lines = []; \
[lines.append(json.dumps({'source':'go-detector-runner-fire','pattern_id':pid,'file':h['file'],'line':h['line'],'advisory':'needs-fuzz'})) \
 for pid, v in findings['patterns'].items() for h in v['hits']]; \
out = '$(_WS_RESOLVED)/.auditooor/needs_fuzz_candidates.jsonl'; \
open(out, 'a').write('\n'.join(lines) + ('\n' if lines else '')); \
print(f'[audit-deep-go-engine] fire-only: {len(lines)} candidate(s) -> {out}') \
" 2>&1 || echo "[audit-deep-go-engine] WARN needs_fuzz_candidates.jsonl write non-zero; continuing (offline-safe)" >&2; \
	    fi; \
	  else \
	    echo "[audit-deep-go-engine] SKIP go-detector-runner: no *.go files found (non-Go workspace)" >&2; \
	  fi; \
	else \
	  echo "[audit-deep-go-engine] SKIP tools/go-detector-runner.py absent" >&2; \
	fi

# ---------------------------------------------------------------------------
# audit-deep-rust-engine (ADDITIVE): the Rust DYNAMIC deep-engine arm + the Rust
# per-function producer half.
#   (1) tools/rust-proptest-engine-runner.sh : the project's OWN proptest suite
#       (a property-based fuzzer) under a bounded PROPTEST_CASES budget; emits
#       fuzz_runs/<ts>/manifest.json that audit-completeness-check.py credits.
#   (2) tools/per-function-invariant-gen.py --lang rust : per-function harness
#       scaffolds for the Rust in-scope surface (feeds the per-language producer
#       which mutation-verifies them into mutation_verify_coverage.json).
# OFFLINE-SAFE: every sub-step degrades to a skip when its tool / toolchain is
# absent; this target never breaks audit-deep.
# ---------------------------------------------------------------------------
audit-deep-rust-engine:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-rust-engine WS=<workspace> [STRICT=1] [LIVE=1] [RUST_CASES=64]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "audit-deep-rust-engine" "$(_WS_RESOLVED)"
	@set -u; \
	ws="$(_WS_RESOLVED)"; \
	if [ -f tools/rust-proptest-engine-runner.sh ]; then \
	  echo "[audit-deep-rust-engine] running Rust proptest dynamic engine"; \
	  bash tools/rust-proptest-engine-runner.sh "$$ws" \
	    $(if $(RUST_CASES),--cases "$(RUST_CASES)") \
	    $(if $(PROJECT_ROOT),--project-root "$(PROJECT_ROOT)") || \
	    echo "[audit-deep-rust-engine] WARN rust-proptest-engine-runner returned non-zero; continuing (offline-safe)" >&2; \
	else \
	  echo "[audit-deep-rust-engine] SKIP tools/rust-proptest-engine-runner.sh absent (offline-safe)" >&2; \
	fi; \
	if [ -f tools/per-function-invariant-gen.py ]; then \
	  echo "[audit-deep-rust-engine] generating per-function Rust harness scaffolds (--lang rust)"; \
	  python3 tools/per-function-invariant-gen.py --workspace "$$ws" --lang rust --output-dir "$$ws/.auditooor/per_function_invariants" --overwrite $(if $(JSON),--json) || \
	    echo "[audit-deep-rust-engine] WARN per-function-invariant-gen --lang rust returned non-zero; continuing (offline-safe; tool may not yet support --lang rust on this revision)" >&2; \
	else \
	  echo "[audit-deep-rust-engine] SKIP tools/per-function-invariant-gen.py absent" >&2; \
	fi; \
	if { [ "$${AUDITOOOR_AUDIT_DEEP_LIVE:-}" = "1" ] || [ "$(LIVE)" = "1" ]; } && [ "$${AUDITOOOR_RUST_HARNESS_AUTHOR:-0}" = "1" ] && [ -f tools/rust-engine-harness-author.py ]; then \
	  echo "[audit-deep-rust-engine] AUTHOR opt-in (AUDITOOOR_RUST_HARNESS_AUTHOR=1): authoring Rust harnesses. WARNING: the author currently emits scaffold/vacuous bodies AND can modify CUT Cargo.toml - use only for author-quality dev; the native suite (above) is the genuine coverage source."; \
	  _rha_max="$${HARNESS_AUTHOR_MAX_CRATES:-8}"; \
	  _rha_n=0; \
	  _rscope_roots="$$(python3 -c "import json,os; p=os.path.join('$$ws','scope.json'); d=json.load(open(p)) if os.path.exists(p) else {}; print('\n'.join(os.path.join('$$ws',r) for r in d.get('in_scope',[])))" 2>/dev/null)"; \
	  if [ -n "$$_rscope_roots" ]; then _rha_find_roots="$$_rscope_roots"; echo "[audit-deep-rust-engine] scope.json in-scope roots -> authoring only within them (no OOS/scratch leak)"; else _rha_find_roots="$$ws"; echo "[audit-deep-rust-engine] no scope.json in_scope; falling back to whole-workspace enumeration"; fi; \
	  for _rmanifest in $$(printf '%s\n' "$$_rha_find_roots" | while IFS= read -r _rroot; do [ -d "$$_rroot" ] && find "$$_rroot" -type f \( -name 'Cargo.toml' -o -path '*/src/lib.rs' \) \
	      ! -path '*/vendor/*' ! -path '*/mock*' ! -path '*/Mock*' \
	      ! -path '*/target/*' ! -path '*/.git/*' ! -path '*/.auditooor/*' \
	      -print 2>/dev/null; done | sed -e 's:/Cargo.toml$$::' -e 's:/src/lib.rs$$::' | sort -u | head -n "$$_rha_max"); do \
	    _rname="$$(basename "$$_rmanifest")"; \
	    echo "[audit-deep-rust-engine] rust-engine-harness-author: crate $$_rname ($$_rmanifest)"; \
	    python3 tools/rust-engine-harness-author.py "$$ws" "$$_rname" --max-fns 8 $(if $(JSON),--json) || \
	      echo "[audit-deep-rust-engine] WARN rust-engine-harness-author for crate $$_rname returned non-zero; continuing (offline-safe)" >&2; \
	    _rha_n=$$(($$_rha_n + 1)); \
	  done; \
	  echo "[audit-deep-rust-engine] rust-engine-harness-author: authored across $$_rha_n in-scope crate(s)" >&2; \
	elif [ ! -f tools/rust-engine-harness-author.py ]; then \
	  echo "[audit-deep-rust-engine] SKIP tools/rust-engine-harness-author.py absent (real Rust harnesses not authored this run)" >&2; \
	else \
	  echo "[audit-deep-rust-engine] NATIVE-FIRST: genuine Rust coverage comes from the project's OWN test/proptest suite (run above via rust-proptest-engine-runner, scope-restricted to in_scope crates). The CUT-polluting harness-author is opt-in only (set AUDITOOOR_RUST_HARNESS_AUTHOR=1 for author-quality dev)." >&2; \
	fi

# ---------------------------------------------------------------------------
# Genuine-coverage PRODUCTION pass (Rule R80/R81 closure).
#
# WHY: `make audit-deep` already GENERATES per-function harnesses
# (tools/per-function-invariant-gen.py + the halmos/echidna engines), but it
# never asks whether those harnesses actually CHECK anything. On morpho the
# generated per-function Halmos scaffolds were 61/78 vacuous (`assert(true)`
# bodies that pass on every mutant). The function-coverage GATE
# (tools/function-coverage-completeness.py) + mutation-verify (R80/R81 L37
# signals) DETECT this hollowness at gate time, but nothing CAUGHT it at
# PRODUCTION time. This step closes the loop: immediately after per-function
# harness generation, every generated harness is MUTATION-VERIFIED
# (tools/mutation-verify-coverage.py - the R80/R81 oracle half) and classified
# genuine(non-vacuous) / vacuous / no-baseline / error / skipped. The result is
# written to <ws>/.auditooor/genuine_coverage_manifest.json so audit-deep
# itself REPORTS "X/Y functions have mutation-verified harnesses, Z vacuous".
#
# GENERIC + LANGUAGE-AWARE: keyed on the per-function-invariant manifest
# (Solidity today) but the inner verifier (mutation-verify-coverage.py) is
# language-aware (solidity/rust/go/move/cairo); when a per-function manifest for
# another language exists at the same conventional path it is consumed without
# change. ZERO workspace hardcoding (all paths derive from WS).
#
# OFFLINE-SAFE: if the per-function manifest, mutation-verify-coverage.py, or
# the forge/test toolchain is absent, this step writes a `skipped` /
# `tool-absent` manifest and exits 0 - it never breaks `make audit-deep`.
#
# BUDGET: bounded by GENUINE_COVERAGE_MAX_FUNCTIONS (default 40) and
# GENUINE_COVERAGE_MAX_MUTANTS (default 6 mutants/function) so the pass stays
# within the deep-engine wall-clock envelope; raise via env for an exhaustive
# overnight sweep. Set GENUINE_COVERAGE_SKIP=1 to skip entirely.
# ---------------------------------------------------------------------------
_audit-deep-solidity-genuine-coverage:
	@set -u; \
	ws="$(_WS_RESOLVED)"; \
	out="$(if $(SOLIDITY_DEEP_OUT_DIR),$(SOLIDITY_DEEP_OUT_DIR),$$ws/.auditooor/solidity-deep-audit)"; \
	repo_root="$$PWD"; \
	project_root="$(if $(PROJECT_ROOT),$(PROJECT_ROOT),$$ws)"; \
	gc_manifest="$(if $(GENUINE_COVERAGE_OUT),$(GENUINE_COVERAGE_OUT),$$ws/.auditooor/genuine_coverage_manifest.json)"; \
	per_fn_manifest="$(if $(PER_FN_MANIFEST),$(PER_FN_MANIFEST),$$(test -f "$$ws/.auditooor/per_function_invariants/manifest.json" && echo "$$ws/.auditooor/per_function_invariants/manifest.json" || echo "$$ws/poc-tests/per_function_invariants/manifest.json"))"; \
	max_fns="$(if $(GENUINE_COVERAGE_MAX_FUNCTIONS),$(GENUINE_COVERAGE_MAX_FUNCTIONS),40)"; \
	max_mutants="$(if $(GENUINE_COVERAGE_MAX_MUTANTS),$(GENUINE_COVERAGE_MAX_MUTANTS),6)"; \
	mutant_timeout="$(if $(GENUINE_COVERAGE_TIMEOUT),$(GENUINE_COVERAGE_TIMEOUT),120)"; \
	mkdir -p "$${gc_manifest%/*}" "$$out"; \
	verdict_dir="$$out/genuine-coverage"; \
	mkdir -p "$$verdict_dir"; \
	write_gc() { \
	  python3 -c 'import json,os,sys; from datetime import datetime,timezone; from pathlib import Path; p=Path(sys.argv[1]); payload=json.loads(sys.argv[2]); payload["schema"]="auditooor.genuine_coverage_manifest.v1"; payload["generated_at"]=datetime.now(timezone.utc).isoformat().replace("+00:00","Z"); payload["workspace"]=sys.argv[3]; payload["run_id"]=os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or None; p.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8")' "$$gc_manifest" "$$1" "$$ws"; \
	}; \
	if [ "$${GENUINE_COVERAGE_SKIP:-}" = "1" ]; then \
	  echo "[genuine-coverage] GENUINE_COVERAGE_SKIP=1 - skipping mutation-verify pass"; \
	  write_gc '{"status":"skipped","reason":"GENUINE_COVERAGE_SKIP=1","verdicts":[],"counts":{}}'; \
	  echo "[genuine-coverage] wrote $$gc_manifest (skipped)"; exit 0; \
	fi; \
	if [ ! -f "$$repo_root/tools/mutation-verify-coverage.py" ]; then \
	  echo "[genuine-coverage] tools/mutation-verify-coverage.py missing - writing tool-absent manifest" >&2; \
	  write_gc '{"status":"tool-absent","reason":"tools/mutation-verify-coverage.py missing","verdicts":[],"counts":{}}'; \
	  echo "[genuine-coverage] wrote $$gc_manifest (tool-absent)"; exit 0; \
	fi; \
	if [ ! -f "$$per_fn_manifest" ]; then \
	  echo "[genuine-coverage] per-function manifest absent ($$per_fn_manifest) - no generated harnesses to verify" >&2; \
	  write_gc '{"status":"no-per-function-manifest","reason":"per-function-invariant manifest absent (no generated harnesses)","verdicts":[],"counts":{}}'; \
	  echo "[genuine-coverage] wrote $$gc_manifest (no-per-function-manifest)"; exit 0; \
	fi; \
	have_forge=0; if command -v forge >/dev/null 2>&1; then have_forge=1; fi; \
	if [ "$$have_forge" != "1" ]; then \
	  echo "[genuine-coverage] forge not on PATH - cannot mutation-verify Solidity harnesses; writing toolchain-absent manifest (offline-safe)" >&2; \
	  python3 -c 'import json,os,sys; from datetime import datetime,timezone; from pathlib import Path; \
gc=Path(sys.argv[1]); ws=sys.argv[2]; pf=sys.argv[3]; cap=int(sys.argv[4]); \
m=json.loads(Path(pf).read_text(encoding="utf-8")); fns=[f for f in (m.get("functions") or []) if f.get("source")][:cap]; \
verdicts=[{"function":f.get("function"),"source":f.get("source"),"harness_contract":f.get("harness_contract"),"verdict":"skipped","reason":"forge not on PATH (toolchain absent)"} for f in fns]; \
counts={"total":len(fns),"non_vacuous_genuine":0,"vacuous":0,"no_baseline":0,"error":0,"skipped":len(fns)}; \
payload={"schema":"auditooor.genuine_coverage_manifest.v1","generated_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"workspace":ws,"run_id":os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or None,"status":"toolchain-absent","per_function_manifest":pf,"counts":counts,"mutation_verified_genuine_count":0,"vacuous_count":0,"checkable_count":0,"summary":("0/%d generated per-function harnesses mutation-verified (forge absent; toolchain-absent)"%len(fns)),"verdicts":verdicts}; \
gc.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8"); \
print("[genuine-coverage] "+payload["summary"])' "$$gc_manifest" "$$ws" "$$per_fn_manifest" "$$max_fns"; \
	  echo "[genuine-coverage] wrote $$gc_manifest (toolchain-absent)"; exit 0; \
	fi; \
	if [ -f "$$repo_root/tools/cut-pristine-guard.py" ] && \
	   ! python3 "$$repo_root/tools/cut-pristine-guard.py" "$$ws" --check >"$$verdict_dir/_cut_pristine.log" 2>&1; then \
	  echo "[genuine-coverage] *** CUT NOT PRISTINE *** audited source has uncommitted edits vs HEAD (likely leftover mutation-test operators from an interrupted/concurrent mutation run); a baseline/mutation result against this tree is INVALID. Restore the pin (the tool prints the exact git checkout) BEFORE step-4b:" >&2; \
	  tail -8 "$$verdict_dir/_cut_pristine.log" >&2 || true; \
	  python3 -c 'import json,os,sys; from datetime import datetime,timezone; from pathlib import Path; \
gc=Path(sys.argv[1]); ws=sys.argv[2]; pf=sys.argv[3]; cap=int(sys.argv[4]); \
m=json.loads(Path(pf).read_text(encoding="utf-8")); fns=[f for f in (m.get("functions") or []) if f.get("source")][:cap]; \
verdicts=[{"function":f.get("function"),"source":f.get("source"),"harness_contract":f.get("harness_contract"),"verdict":"error","reason":"CUT not pristine - audited source mutated vs HEAD; restore the pin before mutation-verify"} for f in fns]; \
counts={"total":len(fns),"non_vacuous_genuine":0,"vacuous":0,"no_baseline":0,"error":len(fns),"skipped":0}; \
payload={"schema":"auditooor.genuine_coverage_manifest.v1","generated_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"workspace":ws,"run_id":os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or None,"status":"cut-not-pristine","per_function_manifest":pf,"counts":counts,"mutation_verified_genuine_count":0,"vacuous_count":0,"checkable_count":0,"summary":("CUT NOT PRISTINE - audited source mutated vs HEAD; %d harness(es) uncheckable until the pin is restored"%len(fns)),"verdicts":verdicts}; \
gc.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8"); \
print("[genuine-coverage] "+payload["summary"])' "$$gc_manifest" "$$ws" "$$per_fn_manifest" "$$max_fns"; \
	  echo "[genuine-coverage] wrote $$gc_manifest (cut-not-pristine)"; exit 0; \
	fi; \
	if [ -f "$$repo_root/tools/forge-build-readiness-check.py" ] && \
	   ! python3 "$$repo_root/tools/forge-build-readiness-check.py" "$$ws" --check >"$$verdict_dir/_build_readiness.log" 2>&1; then \
	  echo "[genuine-coverage] *** FORGE BUILD BROKEN *** test tree does not compile; per-fn mutation-verify would SILENTLY record no-execution on every harness (the 0/N-phantom class). Fix the build (remappings / pragma conflict / stray test file) BEFORE step-4b:" >&2; \
	  tail -12 "$$verdict_dir/_build_readiness.log" >&2 || true; \
	  python3 -c 'import json,os,sys; from datetime import datetime,timezone; from pathlib import Path; \
gc=Path(sys.argv[1]); ws=sys.argv[2]; pf=sys.argv[3]; cap=int(sys.argv[4]); \
m=json.loads(Path(pf).read_text(encoding="utf-8")); fns=[f for f in (m.get("functions") or []) if f.get("source")][:cap]; \
verdicts=[{"function":f.get("function"),"source":f.get("source"),"harness_contract":f.get("harness_contract"),"verdict":"error","reason":"forge build broken - test tree does not compile (fix before mutation-verify)"} for f in fns]; \
counts={"total":len(fns),"non_vacuous_genuine":0,"vacuous":0,"no_baseline":0,"error":len(fns),"skipped":0}; \
payload={"schema":"auditooor.genuine_coverage_manifest.v1","generated_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"workspace":ws,"run_id":os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or None,"status":"build-broken","per_function_manifest":pf,"counts":counts,"mutation_verified_genuine_count":0,"vacuous_count":0,"checkable_count":0,"summary":("forge build BROKEN - test tree does not compile; %d harness(es) uncheckable until fixed"%len(fns)),"verdicts":verdicts}; \
gc.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8"); \
print("[genuine-coverage] "+payload["summary"])' "$$gc_manifest" "$$ws" "$$per_fn_manifest" "$$max_fns"; \
	  echo "[genuine-coverage] wrote $$gc_manifest (status=build-broken; loud-fail, not a phantom 0/N)"; exit 0; \
	fi; \
	echo "[genuine-coverage] mutation-verifying generated per-function harnesses (max $$max_fns fns, $$max_mutants mutants/fn, forge=$$have_forge)"; \
	rows_tsv="$$verdict_dir/_targets.tsv"; \
	python3 -c 'import json,sys; from pathlib import Path; US=chr(31); m=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")); fns=m.get("functions") or []; cap=int(sys.argv[2]); rows=[]; \
[rows.append(US.join([str(f.get("function") or ""),str(f.get("source") or ""),str(f.get("harness_contract") or ""),str(f.get("harness_path") or ""),str(f.get("halmos_root") or "")])) for f in fns[:cap] if f.get("source")]; \
sys.stdout.write("\n".join(rows)+("\n" if rows else ""))' "$$per_fn_manifest" "$$max_fns" > "$$rows_tsv" || { \
	  echo "[genuine-coverage] ERR could not parse per-function manifest" >&2; \
	  write_gc '{"status":"manifest-parse-error","reason":"could not parse per-function manifest functions[]","verdicts":[],"counts":{}}'; \
	  echo "[genuine-coverage] wrote $$gc_manifest (manifest-parse-error)"; exit 0; \
	}; \
	total=0; genuine=0; vacuous=0; nobaseline=0; errored=0; skipped=0; nomutants=0; \
	: > "$$verdict_dir/_verdicts.jsonl"; \
	US="$$(printf '\037')"; \
	while IFS="$$US" read -r fn_name fn_source harness_contract harness_path halmos_root; do \
	  [ -n "$$fn_source" ] || continue; \
	  total=$$((total+1)); \
	  src_file="$${fn_source%%:*}"; \
	  abs_src="$$src_file"; \
	  case "$$src_file" in /*) abs_src="$$src_file";; *) abs_src="$$ws/$$src_file";; esac; \
	  slug="$$(printf '%s' "$$harness_contract" | tr -c 'A-Za-z0-9_.-' '_')"; \
	  verdict_out="$$verdict_dir/$$slug.json"; \
	  if [ ! -f "$$abs_src" ]; then \
	    skipped=$$((skipped+1)); \
	    python3 -c 'import json,sys; from pathlib import Path; Path(sys.argv[1]).write_text(json.dumps({"function":sys.argv[2],"source":sys.argv[3],"verdict":"skipped","reason":"source file not found"})+"\n")' "$$verdict_out" "$$fn_name" "$$fn_source"; \
	    cat "$$verdict_out" >> "$$verdict_dir/_verdicts.jsonl"; \
	    continue; \
	  fi; \
	  if [ "$$have_forge" != "1" ] || [ -z "$$harness_contract" ]; then \
	    skipped=$$((skipped+1)); \
	    reason="forge absent"; [ -z "$$harness_contract" ] && reason="no harness_contract in manifest"; \
	    python3 -c 'import json,sys; from pathlib import Path; Path(sys.argv[1]).write_text(json.dumps({"function":sys.argv[2],"source":sys.argv[3],"harness_contract":sys.argv[4],"verdict":"skipped","reason":sys.argv[5]})+"\n")' "$$verdict_out" "$$fn_name" "$$fn_source" "$$harness_contract" "$$reason"; \
	    cat "$$verdict_out" >> "$$verdict_dir/_verdicts.jsonl"; \
	    continue; \
	  fi; \
	  build_root="$$halmos_root"; [ -n "$$build_root" ] || build_root="$$project_root"; [ -n "$$build_root" ] || build_root="$$ws"; \
	  harness_cmd="cd $$build_root && forge test --match-contract $$harness_contract"; \
	  : ; (cd "$$repo_root" && python3 tools/mutation-verify-coverage.py \
	        --workspace "$$ws" \
	        --function "$$abs_src:$${fn_source#*:}" \
	        --source "$$abs_src" \
	        --harness "$$harness_cmd" \
	        --language solidity \
	        --max "$$max_mutants" \
	        --timeout "$$mutant_timeout" \
	        --out "$$verdict_out" >/dev/null 2>"$$verdict_dir/$$slug.stderr.log") || true; \
	  : "mutation-verify-coverage exits 1=vacuous / 2=no-mutants (non-zero is NORMAL, a SIGNAL not a failure); it WRITES the real verdict to --out regardless. Read the verdict from the slug FILE, never derive it from the exit code (the old if/then/else hard-pinned v=error for every vacuous+no-mutants row -> false-RED 40-error counts)." ; \
	  v="$$(python3 -c 'import json,sys; from pathlib import Path; p=Path(sys.argv[1]); raw=(p.read_text(encoding="utf-8") if p.exists() else ""); d=(json.loads(raw) if raw.strip().startswith("{") else {}); print((d.get("verdict") or "error") if isinstance(d,dict) else "error")' "$$verdict_out")"; \
	  if [ ! -f "$$verdict_out" ]; then \
	    python3 -c 'import json,sys; from pathlib import Path; p=Path(sys.argv[1]); p.write_text(json.dumps({"function":sys.argv[2],"source":sys.argv[3],"verdict":"error"})+"\n")' "$$verdict_out" "$$fn_name" "$$fn_source" 2>/dev/null || true; \
	  fi; \
	  case "$$v" in \
	    non-vacuous) genuine=$$((genuine+1));; \
	    vacuous) vacuous=$$((vacuous+1));; \
	    no-baseline) nobaseline=$$((nobaseline+1));; \
	    skipped) skipped=$$((skipped+1));; \
	    no-mutants) nomutants=$$((nomutants+1));; \
	    *) errored=$$((errored+1));; \
	  esac; \
	  python3 -c 'import json,sys; from pathlib import Path; p=Path(sys.argv[1]); raw=(p.read_text(encoding="utf-8") if p.exists() else "").strip(); sys.stdout.write(json.dumps(json.loads(raw))+"\n") if raw.startswith("{") else None' "$$verdict_out" >> "$$verdict_dir/_verdicts.jsonl" 2>/dev/null || true; \
	done < "$$rows_tsv"; \
	python3 -c 'import json,os,sys; from datetime import datetime,timezone; from pathlib import Path; \
gc=Path(sys.argv[1]); ws=sys.argv[2]; vfile=Path(sys.argv[3]); \
total,genuine,vacuous,nobaseline,errored,skipped,nomutants=(int(x) for x in sys.argv[4:11]); \
verdicts=[]; \
[verdicts.append(json.loads(l)) for l in (vfile.read_text(encoding="utf-8").splitlines() if vfile.exists() else []) if l.strip()]; \
counts={"total":total,"non_vacuous_genuine":genuine,"vacuous":vacuous,"no_baseline":nobaseline,"error":errored,"skipped":skipped,"no_mutants":nomutants}; \
verified=genuine; checkable=genuine+vacuous; \
payload={"schema":"auditooor.genuine_coverage_manifest.v1","generated_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"workspace":ws,"run_id":os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or None,"status":"ok","per_function_manifest":sys.argv[11],"counts":counts,"mutation_verified_genuine_count":genuine,"vacuous_count":vacuous,"checkable_count":checkable,"summary":("%d/%d generated per-function harnesses are mutation-verified genuine, %d vacuous, %d no-mutants" % (genuine,total,vacuous,nomutants)),"verdicts":verdicts}; \
gc.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8"); \
print("[genuine-coverage] %s" % payload["summary"])' \
	  "$$gc_manifest" "$$ws" "$$verdict_dir/_verdicts.jsonl" "$$total" "$$genuine" "$$vacuous" "$$nobaseline" "$$errored" "$$skipped" "$$nomutants" "$$per_fn_manifest"; \
	if [ -f "$$repo_root/tools/genuine-coverage-sidecar-merge.py" ]; then \
	  python3 "$$repo_root/tools/genuine-coverage-sidecar-merge.py" --workspace "$$ws" --manifest "$$gc_manifest" \
	    || echo "[genuine-coverage] WARN sidecar-merge returned non-zero (advisory; manifest already written)" >&2; \
	fi; \
	echo "[genuine-coverage] wrote $$gc_manifest"

# ---------------------------------------------------------------------------
# genuine-coverage: the operator-facing PRODUCTION DRIVER.
#
# This is the stage that PRODUCES what tools/function-coverage-completeness.py
# DEMANDS (mutation-verified, non-vacuous per-function coverage). It:
#   (1) emits the per-function REAL-attack worklist
#       (tools/per-function-attack-worklist.py --emit) - one row per in-scope
#       function with the attack topics a hunter / agentic harness-builder must
#       work through;
#   (2) writes a dispatch brief telling the agentic harness-builder to turn each
#       vacuous / untouched function into a GENUINE mutation-verified harness;
#   (3) re-runs the mutation-verify pass so the genuine_coverage_manifest.json
#       reflects any newly-built genuine harnesses.
#
# GENERIC: --workspace only; no workspace hardcoding; language-aware via the
# reused tools. OFFLINE-SAFE: each sub-step degrades to a skip artifact when its
# tool / toolchain is absent.
#   make genuine-coverage WS=~/audits/<project> [GENUINE_COVERAGE_MAX_FUNCTIONS=40]
# ---------------------------------------------------------------------------
genuine-coverage:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make genuine-coverage WS=<workspace> [GENUINE_COVERAGE_MAX_FUNCTIONS=40] [GENUINE_COVERAGE_MAX_MUTANTS=6]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make genuine-coverage" "$(_WS_RESOLVED)"
	@set -u; \
	ws="$(_WS_RESOLVED)"; \
	brief_dir="$$ws/.auditooor/genuine-coverage"; \
	mkdir -p "$$brief_dir"; \
	echo "[genuine-coverage] (1/3) emitting per-function REAL-attack worklist ..."; \
	if [ -f tools/per-function-attack-worklist.py ]; then \
	  python3 tools/per-function-attack-worklist.py --workspace "$$ws" --emit $(if $(JSON),--json) > "$$brief_dir/per_function_attack_worklist.json" 2>"$$brief_dir/worklist.stderr.log" && \
	    echo "[genuine-coverage]   wrote $$brief_dir/per_function_attack_worklist.json" || \
	    echo "[genuine-coverage]   WARN per-function-attack-worklist emit returned non-zero (see $$brief_dir/worklist.stderr.log); continuing" >&2; \
	else \
	  echo "[genuine-coverage]   WARN tools/per-function-attack-worklist.py missing; skipping worklist emit" >&2; \
	fi; \
	echo "[genuine-coverage] (2/3) writing agentic harness-build dispatch brief ..."; \
	python3 tools/genuine-coverage-dispatch-brief.py --workspace "$$ws" || \
	  echo "[genuine-coverage]   WARN dispatch-brief emit returned non-zero; continuing" >&2; \
	echo "[genuine-coverage] (3/3) re-running mutation-verify pass ..."; \
	$(MAKE) --no-print-directory _audit-deep-solidity-genuine-coverage WS="$$ws" \
	  $(if $(GENUINE_COVERAGE_MAX_FUNCTIONS),GENUINE_COVERAGE_MAX_FUNCTIONS="$(GENUINE_COVERAGE_MAX_FUNCTIONS)") \
	  $(if $(GENUINE_COVERAGE_MAX_MUTANTS),GENUINE_COVERAGE_MAX_MUTANTS="$(GENUINE_COVERAGE_MAX_MUTANTS)") || \
	  echo "[genuine-coverage]   WARN mutation-verify re-run returned non-zero; see $$ws/.auditooor/genuine_coverage_manifest.json" >&2; \
	echo "[genuine-coverage] done. Manifest: $$ws/.auditooor/genuine_coverage_manifest.json"

audit-deep-solidity-per-function-harnesses:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-solidity-per-function-harnesses WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-solidity-per-function-harnesses" "$(_WS_RESOLVED)"
	@python3 tools/solidity-per-function-halmos-runner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --out "$(_WS_RESOLVED)/.audit_logs/solidity_per_function_halmos_manifest.json" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json)

audit-deep-solidity-all-harnesses:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-solidity-all-harnesses WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-solidity-all-harnesses" "$(_WS_RESOLVED)"
	@if [ -n "$(PROJECT_ROOT)" ]; then \
	  echo '[make audit-deep-solidity-all-harnesses] ERR PROJECT_ROOT is owned by the all-harness loop'; exit 2; fi
	@set -u; \
	ws="$(_WS_RESOLVED)"; \
	roots_file="$$ws/.auditooor/solidity-deep-audit/all-harness-roots.txt"; \
	agg="$$ws/.audit_logs/solidity_deep_all_harnesses_manifest.json"; \
	mkdir -p "$${roots_file%/*}" "$${agg%/*}"; \
	if [ -f tools/discover-engine-harness-roots.py ]; then \
	  python3 tools/discover-engine-harness-roots.py --workspace "$$ws" --out "$$roots_file" >/dev/null 2>&1 || : > "$$roots_file"; \
	elif [ ! -d "$$ws/poc-tests" ]; then \
	  : > "$$roots_file"; \
	else \
	  find "$$ws/poc-tests" -mindepth 1 -maxdepth 1 -type d -name '*-engine-harness' -print 2>/dev/null | while read -r root; do \
	    if { find "$$root" -maxdepth 1 -type f -name 'foundry.toml' -print -quit 2>/dev/null; find "$$root" -maxdepth 1 -type f -name 'hardhat.config.*' -print -quit 2>/dev/null; } | grep -q .; then \
	      printf '%s\n' "$$root"; \
	    fi; \
	  done | sort > "$$roots_file"; \
	fi; \
	rc=0; \
	while IFS= read -r root; do \
	  [ -n "$$root" ] || continue; \
	  slug="$${root##*/}"; \
	  out_dir="$$ws/.auditooor/solidity-deep-audit/by-harness/$$slug"; \
	  engine_root="$$ws/.auditooor/deep-engine-runs/by-harness/$$slug"; \
	  echo "[audit-deep-solidity-all-harnesses] $$slug"; \
	  if ! AUDITOOOR_DEEP_ARTIFACT_ROOT="$$engine_root" $(MAKE) --no-print-directory audit-deep-solidity WS="$$ws" PROJECT_ROOT="$$root" SOLIDITY_DEEP_OUT_DIR="$$out_dir"; then \
	    rc=1; \
	  fi; \
	done < "$$roots_file"; \
	python3 tools/solidity-deep-all-harnesses-manifest.py --workspace "$$ws" --roots-file "$$roots_file" --out "$$agg" --sync-primary $(if $(STRICT),--strict); \
	manifest_rc=$$?; \
	if [ $$manifest_rc -ne 0 ]; then rc=$$manifest_rc; fi; \
	exit $$rc

# G10 fix - run ONLY the symbolic/fuzz engine stage on a COMPILED workspace,
# bypassing prove-top-leads / prefiling-stress-test / STRICT proof gates and
# the `make audit` / audit_completion.json freshness prerequisites entirely.
# The STRICT proof gate belongs at submission, NOT before the engines. This
# target lets a fresh, compiling workspace fire halmos/medusa/echidna directly.
#   make audit-deep-engines-only WS=<ws> [PROJECT_ROOT=<path>] [CONTRACT_FILE=<rel>]
# Requires a passing forge build (forge-deps-checker runs first, --fix to
# repair the local solc symlink etc.); on a failing build it warns and still
# routes to audit-deep-solidity, whose engine steps emit skip artifacts so the
# manifest is always produced.
audit-deep-engines-only:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-engines-only WS=<workspace> [PROJECT_ROOT=<path>] [CONTRACT_FILE=<rel>]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-engines-only" "$(_WS_RESOLVED)"
	@echo "[audit-deep-engines-only] engine-stage-only run (no prove-top-leads / no STRICT proof gate / no make-audit prereq)"
	@if [ -f tools/forge-deps-checker.py ]; then \
	  echo "[audit-deep-engines-only] forge-deps-checker (--fix) ..."; \
	  python3 tools/forge-deps-checker.py "$(_WS_RESOLVED)" --fix || \
	    echo "[audit-deep-engines-only] WARN forge-deps-checker reported issues; continuing (engine steps emit skip artifacts when build prerequisites are unmet)" >&2; \
	else \
	  echo "[audit-deep-engines-only] WARN tools/forge-deps-checker.py missing; skipping foundry dependency repair" >&2; \
	fi
	@ws="$(_WS_RESOLVED)"; \
	has_go=0; has_rust=0; has_sol=0; \
	if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/vendor' \) -prune -o \( -type f -name 'go.mod' -print -quit \) 2>/dev/null | grep -q .; then has_go=1; fi; \
	if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' \) -prune -o \( -type f -name 'Cargo.toml' -print -quit \) 2>/dev/null | grep -q .; then has_rust=1; fi; \
	if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' \) -prune -o \( -type f -name '*.sol' -print -quit \) 2>/dev/null | grep -q .; then has_sol=1; fi; \
	ran_engine=0; \
	if [ "$$has_sol" = "1" ]; then \
	  echo "[audit-deep-engines-only] Solidity detected; running audit-deep-solidity"; \
	  $(MAKE) --no-print-directory audit-deep-solidity WS="$$ws" $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") $(if $(CONTRACT_FILE),CONTRACT_FILE="$(CONTRACT_FILE)") || echo "[audit-deep-engines-only] WARN audit-deep-solidity non-zero; continuing" >&2; ran_engine=1; \
	fi; \
	if [ "$$has_rust" = "1" ]; then \
	  echo "[audit-deep-engines-only] Rust detected; running audit-deep-rust-engine (per-function + proptest)"; \
	  $(MAKE) --no-print-directory audit-deep-rust-engine WS="$$ws" $(if $(STRICT),STRICT=1) $(if $(LIVE),LIVE=1) || echo "[audit-deep-engines-only] WARN audit-deep-rust-engine non-zero; continuing (offline-safe)" >&2; ran_engine=1; \
	fi; \
	if [ "$$has_go" = "1" ]; then \
	  echo "[audit-deep-engines-only] Go detected; running audit-deep-go-engine (per-function + fuzz)"; \
	  $(MAKE) --no-print-directory audit-deep-go-engine WS="$$ws" $(if $(STRICT),STRICT=1) $(if $(LIVE),LIVE=1) || echo "[audit-deep-engines-only] WARN audit-deep-go-engine non-zero; continuing (offline-safe)" >&2; ran_engine=1; \
	fi; \
	if [ "$$ran_engine" = "0" ]; then echo "[audit-deep-engines-only] WARN no Solidity/Rust/Go engine matched this workspace" >&2; fi; \
	echo "[audit-deep-engines-only] running audit-depth (R81 per-guard negative-space + sibling-diff)"; \
	$(MAKE) --no-print-directory audit-depth WS="$$ws" $(if $(STRICT),STRICT=1) $(if $(JSON),JSON=1) || echo "[audit-deep-engines-only] WARN audit-depth non-zero; continuing" >&2

audit-deep-per-contract:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-per-contract WS=<workspace> [LIVE=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-per-contract" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/audit-deep-per-contract.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --out "$(_WS_RESOLVED)/.auditooor/per_contract_audit_deep_plan.json" \
	  $(if $(LIVE),--live) \
	  $(if $(JSON),--json)

audit-deep-per-contract-test:
	@python3 -m unittest tools.tests.test_audit_deep_per_contract -v

audit-deep-per-fn-invariant:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-per-fn-invariant WS=<workspace> [CONTRACT=<name-or-file>] [FUNCTION=<name>] [OUT_DIR=<path>] [PRE_FLIGHT_DIR=<path>] [JSON=1] [DRY_RUN=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-deep-per-fn-invariant" "$(_WS_RESOLVED)"
	@python3 tools/per-function-invariant-gen.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(CONTRACT),--contract "$(CONTRACT)") \
	  $(if $(FUNCTION),--function "$(FUNCTION)") \
	  $(if $(OUT_DIR),--output-dir "$(OUT_DIR)") \
	  $(if $(PRE_FLIGHT_DIR),--preflight-dir "$(PRE_FLIGHT_DIR)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

audit-deep-per-fn-invariant-test:
	@python3 -m unittest tools.tests.test_per_function_invariant_gen -v

gen-composition-fixtures:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make gen-composition-fixtures WS=<workspace> [OUT_DIR=<path>] [MAX_PAIRS=2] [PLAN_ONLY=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make gen-composition-fixtures" "$(_WS_RESOLVED)"
	@python3 tools/gen-composition-fixtures.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),$(_WS_RESOLVED)/.auditooor/composition-fixtures)" \
	  --max-pairs "$(if $(MAX_PAIRS),$(MAX_PAIRS),2)" \
	  $(if $(PLAN_ONLY),--plan-only) \
	  $(if $(JSON),--json)

gen-composition-fixtures-test:
	@python3 -m unittest tools.tests.test_gen_composition_fixtures -v

econ-fuzzer-scaffold:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make econ-fuzzer-scaffold WS=<workspace> [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make econ-fuzzer-scaffold" "$(_WS_RESOLVED)"
	@python3 tools/econ-fuzzer-scaffold.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--json)

econ-fuzzer-scaffold-test:
	@python3 -m unittest tools.tests.test_econ_fuzzer_scaffold -v

# Regression test for the audit-deep target. Lives next to test_makefile_tilde.sh
# and follows the same shape: sandbox HOME, scaffold a fake workspace, run
# the target with DRY_RUN, assert exit 0 + report file shape.
audit-deep-test:
	@bash tools/tests/test_audit_deep_target.sh

# I12 (#327) + I13 (#328) + I15 (#331) + I16 (#332) regression tests:
# the deep-runner wrappers CWD into the forge project root, audit-deep
# --live drops --dry-run, and both wrappers auto-pick `--contract` /
# `--test-contract` from <ws>/swarm/mining_priorities.json (with a
# title-regex fallback for the empty `contracts: []` shape).
audit-deep-live-test:
	@bash tools/tests/test_audit_deep_live_flag.sh
	@bash tools/tests/test_deep_runner_project_root.sh
	@bash tools/tests/test_deep_runner_auto_pick.sh
	@bash tools/tests/test_audit_deep_scaffold.sh
	@bash tools/tests/test_gen_state_root_parity.sh

audit-deep-manifest:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-manifest WS=<workspace> [JSON=1] [OUT=<path>]'; exit 2; fi
	@python3 tools/audit-deep-manifest.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) $(if $(OUT),--out "$(OUT)")

audit-deep-manifest-test:
	@python3 -m unittest tools.tests.test_audit_deep_manifest -v

# Hydra-runner: multi-engine aggregator (slither + halmos + medusa) +
# cross-lane-correlate. Replaces the prior "tools/hydra-runner.sh
# exists today" doc claim that was wrong. Set LIVE=1 to actually
# invoke the engines (default: dry-run plan).
hydra:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hydra WS=<workspace> [LIVE=1] [CONTRACT=<Name>] [TEST_CONTRACT=<Name>]'; exit 2; \
	fi
	@bash tools/hydra-runner.sh "$(_WS_RESOLVED)" \
	  $(if $(LIVE),,--dry-run) \
	  $(if $(CONTRACT),--contract $(CONTRACT)) \
	  $(if $(TEST_CONTRACT),--test-contract $(TEST_CONTRACT)) \
	  $(if $(SYMBOLIC_TIMEOUT),--symbolic-timeout $(SYMBOLIC_TIMEOUT)) \
	  $(if $(FUZZ_TIMEOUT),--fuzz-timeout $(FUZZ_TIMEOUT)) \
	  $(if $(PROJECT_ROOT),--project-root $(PROJECT_ROOT)) \
	  $(if $(ENGINES),--engines $(ENGINES))

hydra-test:
	@bash tools/tests/test_hydra_runner.sh

# V5-P0-05 / Gap 45 - completion-marker freshness guard regression tests.
audit-completion-marker-test:
	@python3 -m unittest tools.tests.test_audit_completion_marker

# Codex P0 #1 follow-up - close-out gate (V5 Gap-23/24).
#
# `make audit-closeout WS=<workspace>` answers a single question: did the
# audit actually run? It reads the artifact tree a real `make audit` /
# `make audit-deep` invocation leaves behind, prints a PASS/WARN/FAIL
# table, and exits non-zero on hard close-out failures. Stdlib-only,
# offline-safe, deterministic. NEVER calls live LLM providers by default.
#
# Run after `make audit` (and optionally `DEEP_PROFILE=all make audit-deep`)
# and before opening a submission PR. See docs/STAGE_REFERENCE.md and
# tools/audit-closeout-check.py for the full check list.
hunt-complete:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt-complete WS=<workspace> [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make hunt-complete" "$(_WS_RESOLVED)"
	@python3 tools/hunt-completeness-check.py "$(_WS_RESOLVED)" $(if $(JSON),--json)

hunt-complete-test:
	@python3 -m unittest tools.tests.test_hunt_completeness_check -v

# r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json
# L37 audit-completeness gate: the AUDIT-level peer of `make hunt-complete`.
# hunt-complete (L35/L36) certifies the HUNT half; audit-complete (L37) certifies
# the WHOLE documented pipeline ran with evidence: Tier-6 mining, the
# language-correct live engines, audit-preflight, exploit-queue, chain-synth,
# exploit-conversion + prove-top-leads, originality-vs-advisory-set, 7-artifact
# learning, and the cross-workspace seed. NO workspace may be declared
# audited/done without `make audit-complete WS=<ws>` returning rc=0.
audit-complete:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-complete WS=<workspace> [STRICT=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-complete" "$(_WS_RESOLVED)"
	@python3 tools/workspace-coverage-heatmap.py --coverage-report --workspace-path "$(_WS_RESOLVED)" || true
	@python3 tools/rubric-coverage-workspace-check.py "$(_WS_RESOLVED)" --write-report || true
	@python3 tools/hunt-run-health-check.py --workspace "$(_WS_RESOLVED)" --json > "$(_WS_RESOLVED)/.auditooor/hunt_run_health_report.json" 2>/dev/null || true
	@# STRICT=1 propagation (generic, all-workspace): three real fail-closed gates -
	@# commit-adjudication-completeness-check.py, manual-step-preflight.py, and
	@# fuzz-target-completeness-check.py - are wired and consumed by audit-done-guard.py
	@# but stay ADVISORY forever unless their own env var is exported, because no driver
	@# ever set it. Mirror the existing AUDITOOOR_L37_STRICT propagation below: when the
	@# caller passes STRICT=1, export all four STRICT env vars into the shell BEFORE any
	@# gate script/python call in this recipe (and for any subsequent audit-done-guard.py
	@# run in the same shell session) so they actually enforce. When STRICT is unset/0,
	@# nothing is exported and every gate stays advisory (purely additive; never bricks a
	@# prior audit unless the operator opts in with STRICT=1).
	@if [ -n "$(STRICT)" ] && [ "$(STRICT)" != "0" ]; then \
	  . tools/lib/strict-all-envs.sh; \
	  export AUDITOOOR_COMMIT_ADJUDICATION_STRICT=1; \
	  export AUDITOOOR_MANUAL_STEP_STRICT=1; \
	  export AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT=1; \
	  export AUDITOOOR_FUZZ_TARGET_STRICT=1; \
	  export AUDITOOOR_MATRIX_PERFILE_STRICT=1; \
	  export AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT=1; \
	  export AUDITOOOR_MECHANISM_AXIS_ENFORCE=1; \
	  export AUDITOOOR_RUBRIC_ATTEMPT_STRICT=1; \
	  export AUDITOOOR_SWEPT_TERMINAL_STRICT=1; \
	  export AUDITOOOR_ESCALATE_FIRST_STRICT=1; \
	  export AUDITOOOR_DISPOSITION_PROOF_STRICT=1; \
	  export ENFORCE_AUTONOMOUS_PROOF_CONVERSION=$${ENFORCE_AUTONOMOUS_PROOF_CONVERSION:-1}; \
	  export AUDITOOOR_INVARIANT_FUZZ_ENFORCE=$${AUDITOOOR_INVARIANT_FUZZ_ENFORCE:-1}; \
	  export AUDITOOOR_FCC_MUTATION_VERIFY=$${AUDITOOOR_FCC_MUTATION_VERIFY:-1}; \
	  AUDITOOOR_L37_STRICT=$${AUDITOOOR_L37_STRICT:-1} python3 tools/audit-completeness-check.py "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json); rc=$$?; \
	  python3 tools/review_attribution.py from-audit-complete --workspace "$(_WS_RESOLVED)" >/dev/null 2>&1 || true; \
	  python3 tools/review_attribution.py from-missed-findings --workspace "$(_WS_RESOLVED)" >/dev/null 2>&1 || true; \
	  python3 tools/business_flow_decompose.py --workspace "$(_WS_RESOLVED)" --write --coverage >/dev/null 2>&1 || true; \
	  exit $$rc; \
	else \
	  AUDITOOOR_L37_STRICT=$${AUDITOOOR_L37_STRICT:-1} python3 tools/audit-completeness-check.py "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json); rc=$$?; \
	  python3 tools/review_attribution.py from-audit-complete --workspace "$(_WS_RESOLVED)" >/dev/null 2>&1 || true; \
	  python3 tools/review_attribution.py from-missed-findings --workspace "$(_WS_RESOLVED)" >/dev/null 2>&1 || true; \
	  python3 tools/business_flow_decompose.py --workspace "$(_WS_RESOLVED)" --write --coverage >/dev/null 2>&1 || true; \
	  exit $$rc; \
	fi

audit-complete-test:
	@python3 -m unittest tools.tests.test_audit_completeness_check -v

audit-honesty:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-honesty WS=<workspace> [STRICT=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-honesty" "$(_WS_RESOLVED)"
	@python3 tools/audit-honesty-check.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) $(if $(STRICT),,--report)

# scanner-integrity: silent-0 false-green monitor. Flags any static analyzer / pattern
# scanner that recorded ok/completed but never actually ran (empty output + 0 findings +
# 0 files scanned, e.g. Slither on a non-building Solidity tree). STRICT=1 fails closed.
scanner-integrity:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make scanner-integrity WS=<workspace> [STRICT=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make scanner-integrity" "$(_WS_RESOLVED)"
	@python3 tools/scanner-ran-integrity.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) $(if $(STRICT),--check)

# step-integrity: fail-closed verifier that every canonical README audit step ran in FULL
# mode (not silently degraded/skipped). Catches the class that hid for 6 days: commit-mining
# silently running in local-git-only mode (no GitHub auth) so upstream post-pin security
# fixes were never mined. STRICT=1 fails closed on any DEGRADED/SKIPPED step.
step-integrity:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make step-integrity WS=<workspace> [STRICT=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make step-integrity" "$(_WS_RESOLVED)"
	@python3 tools/readme-step-integrity.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) $(if $(STRICT),--strict)

# audit-pipeline-full: canonical receipt-driven execution of every row in
# tools/readme_runbook_steps.json. The executor owns order, applicability,
# retries, invalidation, artifact joins, and run credit. A helper command may
# still be invoked directly for development, but it has no executor step token
# and therefore cannot satisfy this target or strict closeout.
.PHONY: pipeline-intake-coverage-plane
pipeline-intake-coverage-plane:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make pipeline-intake-coverage-plane WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "pipeline-intake-coverage-plane" "$(_WS_RESOLVED)"
	@python3 tools/workspace-coverage-heatmap.py \
	  --emit-inscope-manifest --workspace-path "$(_WS_RESOLVED)"
	@python3 tools/inscope-manifest-validate.py \
	  --workspace-path "$(_WS_RESOLVED)"
	@python3 tools/language-capability-contract.py validate
	@python3 tools/language-capability-contract.py query \
	  --inventory "$(_WS_RESOLVED)/.auditooor/inscope_units.jsonl" \
	  --phase source --json \
	  --out "$(_WS_RESOLVED)/.auditooor/language_capability_source.json"
	@python3 tools/coverage-plane-build.py \
	  --workspace "$(_WS_RESOLVED)" --check --strict

.PHONY: audit-deep-engine-substrates audit-deep-depth-probe audit-deep-drive

audit-deep-engine-substrates:
	@if [ -z "$(WS)" ]; then echo 'Usage: make audit-deep-engine-substrates WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "audit-deep-engine-substrates" "$(_WS_RESOLVED)"
	@python3 tools/audit-deep-phase-runner.py \
	  --workspace "$(_WS_RESOLVED)" --mode engine-substrates

audit-deep-depth-probe:
	@if [ -z "$(WS)" ]; then echo 'Usage: make audit-deep-depth-probe WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "audit-deep-depth-probe" "$(_WS_RESOLVED)"
	@python3 tools/audit-deep-phase-runner.py \
	  --workspace "$(_WS_RESOLVED)" --mode depth-probe

audit-deep-drive:
	@if [ -z "$(WS)" ]; then echo 'Usage: make audit-deep-drive WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "audit-deep-drive" "$(_WS_RESOLVED)"
	@python3 tools/audit-deep-phase-runner.py \
	  --workspace "$(_WS_RESOLVED)" --mode drive

#
# Usage:
#   make audit-pipeline-full WS=<workspace>
#   make audit-pipeline-full WS=<workspace> AUDITOOOR_LLM_HUNT=1 AUDITOOOR_LLM_NETWORK_CONSENT=1
#
# There are no advisory or obligation-only outcomes in the canonical run.
# Applicability is machine-decided from the in-scope inventory. Every applicable
# row must succeed and every inapplicable row must carry a validated N/A receipt.
# r36-rebuttal: funnel-generic-fixes-wave3
audit-pipeline-full:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-pipeline-full WS=<workspace> [SOURCE_ONLY=1|GITHUB_ONLY=1] [AUDITOOOR_LLM_HUNT=1] [AUDITOOOR_LLM_NETWORK_CONSENT=1] [PIPELINE_FORCE=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "audit-pipeline-full" "$(_WS_RESOLVED)"
	@_hunt_consent=$$(printf '%s' "$(AUDITOOOR_LLM_HUNT)" | tr '[:upper:]' '[:lower:]'); \
	_network_consent=$$(printf '%s' "$(AUDITOOOR_LLM_NETWORK_CONSENT)" | tr '[:upper:]' '[:lower:]'); \
	case "$$_hunt_consent:$$_network_consent" in \
	  1:*|true:*|yes:*|*:1|*:true|*:yes) ;; \
	  *) echo "[audit-pipeline-full] ERROR: an affirmative LLM hunt or network consent value is required; false/0/empty cannot authorize drive-phase dispatch" >&2; exit 2 ;; \
	esac
	@python3 tools/pipeline-manifest-validate.py --manifest tools/readme_runbook_steps.json
	@PIPELINE_STRICT=1 \
	  STRICT=1 \
	  SOURCE_ONLY="$(SOURCE_ONLY)" \
	  GITHUB_ONLY="$(GITHUB_ONLY)" \
	  AUDITOOOR_LLM_HUNT="$(AUDITOOOR_LLM_HUNT)" \
	  AUDITOOOR_LLM_NETWORK_CONSENT="$(AUDITOOOR_LLM_NETWORK_CONSENT)" \
	  PIPELINE_FORCE="$(PIPELINE_FORCE)" \
	  python3 tools/pipeline-executor.py \
	    --workspace "$(_WS_RESOLVED)" \
	    --manifest tools/readme_runbook_steps.json \
	    run-all

# Retired legacy shell driver. It cannot receive executor authority or emit
# canonical receipts. Keep the historical recipe below for diffability, but
# reject direct invocation before any legacy stage can run.
_audit-pipeline-full:
	@echo "[audit-pipeline-full] ERROR: _audit-pipeline-full is retired; use make audit-pipeline-full so the 69-step receipt executor owns order and credit" >&2; exit 2
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-pipeline-full WS=<workspace> [AUDITOOOR_LLM_HUNT=1] [AUDITOOOR_LLM_NETWORK_CONSENT=1] [PIPELINE_FORCE=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "audit-pipeline-full" "$(_WS_RESOLVED)"
	@if [ "$(AUDITOOOR_PREHUNT_MATRIX)" = "0" ] || [ "$(AUDITOOOR_PREHUNT_MATRIX)" = "false" ] || [ "$(AUDITOOOR_PREHUNT_MATRIX)" = "no" ]; then \
	  echo "[audit-pipeline-full] ERROR: AUDITOOOR_PREHUNT_MATRIX opt-out is forbidden in the full ordered driver" >&2; exit 2; \
	fi
	@if [ -z "$(AUDITOOOR_LLM_HUNT)$(AUDITOOOR_LLM_NETWORK_CONSENT)" ]; then \
	  echo "[audit-pipeline-full] ERROR: LLM hunt and network consent are required; full driver cannot skip drive-phase steps" >&2; exit 2; \
	fi
	@echo "[audit-pipeline-full] === STEP 1/8: audit (engage + detectors + coverage) ==="
	@_step_rc=0; \
	AUDITOOOR_DEFER_HUNT_COVERAGE=1 AUDITOOOR_DEFER_DRIVE=1 AUDITOOOR_DEFER_DATAFLOW_SLICE=1 $(MAKE) --no-print-directory audit WS="$(_WS_RESOLVED)" $(if $(PIPELINE_FORCE),FORCE=$(PIPELINE_FORCE),) STRICT=1 $(if $(JSON),JSON=1) || _step_rc=$$?; \
	if [ "$$_step_rc" -ne 0 ]; then exit "$$_step_rc"; fi; \
	_progress="$(_WS_RESOLVED)/.audit_logs/audit_progress.csv"; \
	if [ ! -f "$$_progress" ]; then \
		echo "[audit-pipeline-full] ERROR: Step 1 produced no audit progress manifest" >&2; exit 1; \
	fi; \
	if awk -F, 'NR > 1 && $$2 == "failed" { found=1 } END { exit(found ? 0 : 1) }' "$$_progress"; then \
		echo "[audit-pipeline-full] ERROR: Step 1 progress manifest contains failed stages; repair Step 1 before continuing" >&2; \
		awk -F, 'NR > 1 && $$2 == "failed" { print "  failed: " $$1 }' "$$_progress" >&2; exit 1; \
	fi
	@echo "[audit-pipeline-full] === STEP 1b/8: prior-history-prehunt-gate (strict reconciliation before pre-hunt/hunt promotion) ==="
	@$(MAKE) --no-print-directory prior-history-prehunt-gate WS="$(_WS_RESOLVED)" STRICT=1
	@echo "[audit-pipeline-full] === STEP 1c/8: dataflow-slice (README step-1c: native inter-proc def-use slice) ==="
	@set -eu; \
	ws="$(_WS_RESOLVED)"; \
	if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' \) -prune -o -type f -name '*.sol' -print -quit 2>/dev/null | grep -q .; then \
	  $(MAKE) --no-print-directory dataflow-slice WS="$(_WS_RESOLVED)" $(if $(PIPELINE_FORCE),FORCE=$(PIPELINE_FORCE),) $(if $(MODE),MODE=$(MODE)); \
	else \
	  echo "[audit-pipeline-full] STEP 1c N/A: no Solidity source in the workspace"; \
	fi
	@# ========================================================================
	@# B3 RE-SEQUENCE: PHASE-1 substrate + PHASE-2 reasoners run BEFORE STEP 2
	@# audit-deep's harness/fuzz half. Previously the atomic-sequence / DIRM /
	@# composition / assumption reasoners only ran inside STEP 3 hunt (_hunt-prehunt-
	@# enum), i.e. AFTER audit-deep authored + fuzzed harnesses - so the harness/fuzz
	@# half never benefited from the reasoner obligations, and the reasoners could run
	@# over substrate audit-deep had not durably emitted. Hoisting PHASE-1 (dataflow
	@# already ran at STEP 1c; here: value-moving-functions + state-coupling-graph +
	@# oracle-reachability + PISVS) then PHASE-2 (_hunt-prehunt-enum reasoners) ahead
	@# of STEP 2 makes the substrate + reasoner obligations available to the harness/
	@# fuzz half. Applicable producers and reasoners are required and fail closed;
	@# language-conditional N/A is the only permitted non-execution outcome.
	@echo "[audit-pipeline-full] === STEP 1d/8: PHASE-1 substrate producers (value-moving-functions + state-coupling-graph + oracle-reachability + PISVS) BEFORE audit-deep's harness/fuzz half ==="
	@python3 tools/value-moving-functions.py "$(_WS_RESOLVED)"
	@python3 tools/state-coupling-graph.py --workspace "$(_WS_RESOLVED)" --emit
	@python3 tools/oracle-reachability-lane.py "$(_WS_RESOLVED)"
	@_pisvs_to=""; \
	if command -v gtimeout >/dev/null 2>&1; then \
	  _pisvs_to="gtimeout --kill-after=30 -s TERM $${AUDITOOOR_PISVS_TIMEOUT:-900}"; \
	elif command -v timeout >/dev/null 2>&1; then \
	  _pisvs_to="timeout --kill-after=30 -s TERM $${AUDITOOOR_PISVS_TIMEOUT:-900}"; \
	else \
	  echo "[audit-pipeline-full] ERROR: PISVS requires gtimeout/timeout; refusing an unbounded Step 1d producer" >&2; \
	  exit 127; \
	fi; \
	$$_pisvs_to python3 tools/protocol-invariant-synth-violation-search.py "$(_WS_RESOLVED)"
	@echo "[audit-pipeline-full] === STEP 1e/8: PHASE-2 pre-hunt reasoners (_hunt-prehunt-enum) over the fresh PHASE-1 substrate, BEFORE audit-deep's harness/fuzz half (default-ON; opt-OUT AUDITOOOR_PREHUNT_MATRIX=0) ==="
	@AUDITOOOR_PREHUNT_PRODUCERS_READY=1 $(MAKE) --no-print-directory _hunt-prehunt-enum WS="$(_WS_RESOLVED)" STRICT=1 $(if $(JSON),JSON=1)
	@# Step 1e can refresh or discover toolchain inputs after the nested audit's
	@# early marker. Refresh the parent-owned marker before audit-deep's strict
	@# freshness handoff so a valid completed Step 1 is not rejected as stale.
	@python3 tools/audit-completion-marker.py write --workspace "$(_WS_RESOLVED)"
	@echo "[audit-pipeline-full] === STEP 2/8: audit-deep (engines + invariant-ledger + hunt-bridge) ==="
	@# Step 1 has just completed in this same invocation. Preserve audit-deep's
	@# freshness check while preventing a second Step-1 execution.
	@$(MAKE) --no-print-directory audit-deep WS="$(_WS_RESOLVED)" $(if $(PIPELINE_FORCE),FORCE=$(PIPELINE_FORCE),) STRICT=1 AUDIT_DEEP_SKIP_AUDIT_PREREQ=1 AUDIT_DEEP_DEFER_DRIVE=1 $(if $(JSON),JSON=1)
	@echo "[audit-pipeline-full] === STEP 2b/8: auto-coverage-close (DAG-ORDER FIX: fold the advisory hypotheses STEP 2 audit-deep JUST emitted into the hunt corpus THIS pass) ==="
	@# DAG-order fix: the ONLY other auto-coverage-close in this driver is embedded in STEP 1 `make audit`, which
	@# runs BEFORE STEP 2 `make audit-deep` emits the advisory *_hypotheses.jsonl (Go G2/G4/G5/G6/G7/G8/G11/G12/G13 at
	@# audit-deep.sh Step 5b + Solidity SADL/CRC/SIDL/ORL/RDL/MOL/ACL-COV/IUL at Steps 22-29). Without this
	@# post-audit-deep fold, emit-this-pass is never folded-this-pass (only picked up one run STALE on the next
	@# pass's STEP 1). Mirrors audit-run-full, whose auto-coverage-close already runs AFTER audit-deep. Advisory.
	@$(MAKE) --no-print-directory auto-coverage-close WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) || \
	  echo "[audit-pipeline-full] STEP 2b WARN: auto-coverage-close returned non-zero (advisory generic coverage-closer; the hunt-coverage gate that follows is the load-bearing gate). Continuing."
	@echo "[audit-pipeline-full] === STEP 3.5/8: corpus-driven-hunt (F1: INV-ground exploit_queue BEFORE hunt + chain-synth read it) ==="
	@$(MAKE) --no-print-directory corpus-driven-hunt WS="$(_WS_RESOLVED)" EMIT_PROOF_QUEUE=1 MAX_FUNCTIONS="$(if $(MAX_FUNCTIONS),$(MAX_FUNCTIONS),0)" $(if $(JSON),JSON=1)
	@echo "[audit-pipeline-full] === STEP 2.9/8: pre-hunt ENUMERATION (A1/A4/B4; mandatory in the full ordered driver) ==="
	@if true; then \
	  echo "[audit-pipeline-full] STEP 2.9: enumerate the completeness matrix + worklist BEFORE the hunt so uncovered cells drive it (A1)"; \
	  python3 tools/completeness-matrix-build.py --workspace "$(_WS_RESOLVED)" --enumerate-only $(if $(JSON),--json); \
	  echo "[audit-pipeline-full] STEP 2.9: fold OPEN mechanism findings into exploit_queue BEFORE the hunt (A4)"; \
	  $(MAKE) --no-print-directory mechanism-to-exploit-queue WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1); \
	  echo "[audit-pipeline-full] STEP 2.9: seed undriven cross-module flows + uncovered surface into exploit_queue BEFORE the hunt (B4)"; \
	  $(MAKE) --no-print-directory coverage-to-hunt-seed WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1); \
	fi
	@echo "[audit-pipeline-full] === STEP 3/8: hunt (README step-3, runs BEFORE audit-depth; CONSENT-GATED: set AUDITOOOR_LLM_HUNT=1 to run) ==="
	@AUDITOOOR_PREHUNT_PRODUCERS_READY=1 AUDITOOOR_PIPELINE_STRICT=1 $(MAKE) --no-print-directory hunt-haiku WS="$(_WS_RESOLVED)" $(if $(PIPELINE_FORCE),FORCE=$(PIPELINE_FORCE),) HUNT_SKIP_DEEP_PREREQ=1 $(if $(JSON),JSON=1)
	@echo "[audit-pipeline-full] === STEP 4/8: audit-depth (README step-4, runs AFTER hunt: guard-negative-space + sibling-diff + depth-cert) ==="
	@AUDITOOOR_PIPELINE_PHASE_TOKEN=audit-depth $(MAKE) --no-print-directory audit-depth WS="$(_WS_RESOLVED)" STRICT=1 \
	  $(if $(AUDITOOOR_LLM_HUNT)$(AUDITOOOR_LLM_NETWORK_CONSENT),DEPTH_PROBE_LIVE=1 AUDITOOOR_AUDIT_DEEP_LIVE=1) \
	  $(if $(JSON),JSON=1)
	@echo "[audit-pipeline-full] === STEP 4b/8: protocol-specific economic invariants (required manual step) ==="
	@set -eu; \
	ws="$(_WS_RESOLVED)"; \
	if [ ! -s "$$ws/INVARIANT_LEDGER.md" ] || [ ! -f "$$ws/.auditooor/attestations/step-4b.json" ]; then \
	  echo "[audit-pipeline-full] ERROR: Step 4b is incomplete; author a non-stub INVARIANT_LEDGER.md and its step-4b attestation before continuing" >&2; \
	  exit 1; \
	fi; \
	echo "[audit-pipeline-full] STEP 4b PASS: invariant ledger and attestation are present"
	@echo "[audit-pipeline-full] === STEP 2c-input/8: materialize the fuzz-target worklist ==="
	@python3 tools/fuzz-target-corpus.py --from-inscope --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json)
	@echo "[audit-pipeline-full] === STEP 2c/8: real mutation-verified invariant fuzzing evidence ==="
	@set -eu; \
	ws="$(_WS_RESOLVED)"; \
	if find "$$ws" \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' \) -prune -o \( -type f -name 'foundry.toml' -o -type f -name 'hardhat.config.*' -o -type f -name '*.sol' \) -print -quit 2>/dev/null | grep -q .; then \
	  if [ ! -d "$$ws/chimera_harnesses" ] || [ ! -f "$$ws/.auditooor/attestations/step-2c.json" ]; then \
	    echo "[audit-pipeline-full] ERROR: Step 2c is incomplete; no Chimera/Recon harness plus step-2c attestation is present" >&2; \
	    exit 1; \
	  fi; \
	  if [ ! -f "$$ws/.auditooor/fuzz_campaign_receipt.json" ] && [ ! -f "$$ws/.auditooor/medusa_campaign_receipt.json" ]; then \
	    echo "[audit-pipeline-full] ERROR: Step 2c has no credited >=1M campaign receipt" >&2; \
	    exit 1; \
	  fi; \
	  AUDITOOOR_FUZZ_CAMPAIGN_ENUM_STRICT=1 python3 tools/step2c-campaign.py verify --workspace "$$ws"; \
	  echo "[audit-pipeline-full] STEP 2c PASS: EVM harness, attestation, and campaign receipt are present"; \
	else \
	  echo "[audit-pipeline-full] STEP 2c N/A: no EVM/Solidity workspace detected"; \
	fi
	@echo "[audit-pipeline-full] === STEP 4d/8: executed-depth conversion obligations ==="
	@python3 tools/executed-depth-conversion.py emit-obligations --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json)
	@echo "[audit-pipeline-full] === STEP 5/8: chain-synth (CONSENT-GATED: multi-step exploit chain synthesis) ==="
	@AUDITOOOR_PIPELINE_PHASE_TOKEN=chain-synth $(MAKE) --no-print-directory chain-synth WS="$(_WS_RESOLVED)" STRICT=1 $(if $(PIPELINE_FORCE),FORCE=$(PIPELINE_FORCE),) $(if $(JSON),JSON=1)
	@echo "[audit-pipeline-full] === STEP 6/8: prove-top-leads (CONSENT-GATED: source-mine + proof-task queue) ==="
	@AUDITOOOR_PIPELINE_PHASE_TOKEN=prove-top-leads $(MAKE) --no-print-directory prove-top-leads WS="$(_WS_RESOLVED)" STRICT=1 REQUIRE_STRICT_WIRING=1 $(if $(PIPELINE_FORCE),FORCE=$(PIPELINE_FORCE),) TOP_N="$(if $(TOP_N),$(TOP_N),10)" $(if $(JSON),JSON=1)
	@echo "[audit-pipeline-full] === STEP 7/8: exploit-conversion-loop (CONSENT-GATED) ==="
	@AUDITOOOR_PIPELINE_PHASE_TOKEN=exploit-conversion-loop $(MAKE) --no-print-directory exploit-conversion-loop WS="$(_WS_RESOLVED)" STRICT=1 $(if $(PIPELINE_FORCE),FORCE=$(PIPELINE_FORCE),) EXECUTE_READY=1 $(if $(JSON),JSON=1)
	@echo "[audit-pipeline-full] === STEP 8/8: audit-complete STRICT=1 (L37 hard gate) ==="
	@$(MAKE) --no-print-directory audit-complete WS="$(_WS_RESOLVED)" STRICT=1 $(if $(JSON),JSON=1)
	@echo "[audit-pipeline-full] DONE. All 8 stages complete (LLM steps were $(if $(AUDITOOOR_LLM_HUNT)$(AUDITOOOR_LLM_NETWORK_CONSENT),ACTIVE,OBLIGATION-RECORDED-only))."

# r36-rebuttal: lane-PR10-PRODUCTION-PIPELINE registered in .auditooor/agent_pathspec.json
# PR10 FINAL gate orchestrator. production-pipeline-check evaluates EVERY
# required pipeline stage signal (delegating to L37's signal authority), writes
# a per-stage manifest to <ws>/.auditooor/production_pipeline_manifest.json, and
# FAIL-CLOSES on any missing required REAL artifact - not just rc=0 from a
# sub-tool. STRICT=1 threads through to PR4's engine-harness PROOF gate so
# engines are only credited when every counted harness is a real target-call
# harness. A production audit MUST run `make production-pipeline-check WS=<ws>
# STRICT=1` and get rc=0 before the workspace is certified.
.PHONY: production-pipeline-check production-pipeline-check-test
production-pipeline-check:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make production-pipeline-check WS=<workspace> [STRICT=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make production-pipeline-check" "$(_WS_RESOLVED)"
	@python3 tools/production-pipeline-check.py "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json)

production-pipeline-check-test:
	@python3 -m unittest tools.tests.test_production_pipeline_check -v

# r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json
# PR4 engine-harness proof gate front-door. The proof gate
# (tools/engine-harness-proof-check.py, owned by PR4a) classifies each counted
# engine harness as a REAL target-call harness or a fake/tautological stub,
# reading the EVM proof manifest at
# <ws>/.auditooor/evm_engine_proof/engine_harness_proof.json. L37
# (`make audit-complete`) CALLS this gate for the engine-harness signal: it
# credits the engines iff harness count > 0 AND every counted harness passes
# here. Run it standalone to see the per-harness proof verdicts; rc=1 when any
# counted harness is unproven, so it fail-closes a stub harness and passes a
# real one.
.PHONY: engine-proof-gate
engine-proof-gate:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make engine-proof-gate WS=<workspace> [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make engine-proof-gate" "$(_WS_RESOLVED)"
	@if [ ! -f tools/engine-harness-proof-check.py ]; then \
	  echo "[make engine-proof-gate] ERR proof gate tool tools/engine-harness-proof-check.py is not on disk (PR4a)"; exit 2; fi
	@python3 tools/engine-harness-proof-check.py "$(_WS_RESOLVED)" $(if $(JSON),--json)

# DELTA-1 closure: r_rules_inventory.jsonl MUST track every wired rule-family
# gate in pre-submit-check.sh. This standing parity gate fails-closed if the
# doc-of-record ever drifts below the actual enforcement surface again.
.PHONY: r-rule-inventory-parity-check r-rule-inventory-parity-test
r-rule-inventory-parity-check:
	@python3 tools/r-rule-inventory-parity-check.py $(if $(JSON),--json)

r-rule-inventory-parity-test:
	@python3 -m unittest tools.tests.test_r_rule_inventory_parity_check -v

audit-closeout:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-closeout WS=<workspace> [REQUIRE_DEEP=1] [STRICT=1] [JSON=1] [WRITE_MANIFEST=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-closeout" "$(_WS_RESOLVED)"
	@$(MAKE) --no-print-directory queue-proof-hard-close WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) $(if $(STRICT),STRICT=1)
	@$(MAKE) --no-print-directory field-validation-report WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) $(if $(STRICT),STRICT=1)
	@$(MAKE) --no-print-directory v3-roadmap-sidecars WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) $(if $(STRICT),STRICT_HACKERMAN_V3=1)
	@python3 tools/hackerman-etl-from-our-submissions.py --workspace "$(_WS_RESOLVED)" --json-summary \
	  || echo "[audit-closeout] WARN own-findings->corpus ETL failed (advisory; findings still on disk)" >&2
	@$(MAKE) --no-print-directory ranker-learn-surface \
	  || echo "[audit-closeout] WARN ranker-learn-surface (own-findings seed + corpus reindex) failed (advisory; never auto-applies weights)" >&2
	@python3 tools/hackerman-etl-from-prior-audits.py --workspace "$(_WS_RESOLVED)" --out-dir audit/corpus_tags/tags/auditooor_prior_audits --verification-tier tier-2-verified-public-archive --json-summary \
	  || echo "[audit-closeout] WARN prior-audits->corpus ETL failed (advisory)" >&2
	@python3 tools/hackerman-etl-from-depth-ledgers.py --workspace "$(_WS_RESOLVED)" --json-summary \
	  || echo "[audit-closeout] WARN depth-ledgers->corpus ETL failed (advisory; wave2 #12 cross-ws guard-gap banking)" >&2
	@python3 tools/audit-closeout-check.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(REQUIRE_DEEP),--require-deep) \
	  $(if $(STRICT),--require-strict-wiring) \
	  $(if $(STRICT),--require-pr560-artifacts) \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json) \
	  $(if $(WRITE_MANIFEST),--write-manifest)
	@pfd_json="$(_WS_RESOLVED)/.auditooor/provider_fanout_discipline_check.json"; \
	  backfill_json="$(_WS_RESOLVED)/.auditooor/provider_keep_verification_backfill.json"; \
	  backfill_queue_json="$(_WS_RESOLVED)/.auditooor/provider_keep_verification_backfill_queue.json"; \
	  backfill_result_json="$(_WS_RESOLVED)/.auditooor/provider_keep_verification_backfill_result.json"; \
	  pfd_rc=0; \
	  $(MAKE) --no-print-directory provider-fanout-discipline-check WS="$(_WS_RESOLVED)" ENFORCE_IF_ARTIFACTS=1 JSON=1 > "$$pfd_json" || pfd_rc=$$?; \
	  $(MAKE) --no-print-directory provider-keep-verification-backfill WS="$(_WS_RESOLVED)" INPUT_JSON="$$pfd_json" SCAN_WORKSPACE=1 $(if $(JSON),JSON=1) || \
	    echo "[audit-closeout] WARN provider-keep-verification-backfill failed; continuing (backfill packets advisory)" >&2; \
	  if [ -f "$$backfill_json" ]; then \
	    $(MAKE) --no-print-directory v3-provider-local-verification-queue WORKSPACE="$(_WS_RESOLVED)" BACKFILL_JSON="$$backfill_json" OUT_JSON="$$backfill_queue_json" OUT_MD="$(_WS_RESOLVED)/.auditooor/provider_keep_verification_backfill_queue.md" $(if $(JSON),JSON=1) || \
	      echo "[audit-closeout] WARN backfill local-verification queue generation failed; continuing (advisory)" >&2; \
	    if [ -f "$$backfill_queue_json" ]; then \
	      $(MAKE) --no-print-directory v3-provider-local-verify WORKSPACE="$(_WS_RESOLVED)" QUEUE="$$backfill_queue_json" OUT_JSON="$$backfill_result_json" OUT_MD="$(_WS_RESOLVED)/.auditooor/provider_keep_verification_backfill_result.md" $(if $(JSON),JSON=1) || \
	        echo "[audit-closeout] WARN backfill local verification failed; continuing (advisory)" >&2; \
	    fi; \
	  fi; \
	  if [ "$$pfd_rc" -ne 0 ]; then \
	    echo "[audit-closeout] ERR provider-fanout-discipline-check failed rc=$$pfd_rc; wrote $$pfd_json and generated backfill packets" >&2; \
	    exit "$$pfd_rc"; \
	  fi
	@if [ -n "$(STRICT)" ]; then \
	  $(MAKE) --no-print-directory audit-v3-enforcement-gate WS="$(_WS_RESOLVED)" OUT_JSON="$(_WS_RESOLVED)/.auditooor/audit_v3_enforcement_gate.json" $(if $(JSON),JSON=1); \
	  $(MAKE) --no-print-directory hacker-question-workflow-audit WS="$(_WS_RESOLVED)" JSON=1 STRICT=1; \
	  $(MAKE) --no-print-directory agent-artifact-mine WS="$(_WS_RESOLVED)" JSON=1; \
	  $(MAKE) --no-print-directory agent-learning-compiler WS="$(_WS_RESOLVED)" JSON=1; \
	  $(MAKE) --no-print-directory agent-learning-gate WS="$(_WS_RESOLVED)" STRICT=1 $(if $(JSON),JSON=1); \
	fi
	@# Advisory: refresh agent-artifact-mining report so vault_agent_artifact_mining_context
	@# stays fresh.  Runs unconditionally (non-STRICT too); never fails closeout on error.
	@$(MAKE) --no-print-directory agent-artifact-mine WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) || \
	  echo "[audit-closeout] WARN agent-artifact-mine failed (advisory); continuing" >&2
	@# Also refresh the repo-root copy consumed by the MCP server when no WS is given.
	@python3 tools/agent-artifact-miner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --out "$(CURDIR)/agent_artifact_mining_report.json" \
	  $(if $(JSON),--json) || \
	  echo "[audit-closeout] WARN repo-root agent-artifact-mining report refresh failed (advisory); continuing" >&2
	@# G15.2: strict hunt-coverage gate under STRICT=1 (fail-closed on
	@# below-threshold unlogged coverage); warn-grade otherwise.
	@$(MAKE) --no-print-directory hunt-coverage-gate WS="$(_WS_RESOLVED)" $(if $(STRICT),STRICT=1) $(if $(JSON),JSON=1)
	@$(MAKE) --no-print-directory audit-closeout-case-study WS="$(WS)"
	@echo "[audit-closeout] W5-A2 FP verdict capture:"
	@python3 tools/audit/fp_verdict_capture.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(AUTO_NEGATIVE),--auto-negative) || true

audit-closeout-case-study:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-closeout-case-study WS=<workspace> [VAULT_DIR=<path>] [ROUND=<N>] [FORCE=1] [DRY_RUN=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make audit-closeout-case-study" "$(_WS_RESOLVED)"
	@python3 tools/case-study-emitter.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(VAULT_DIR),--vault-dir "$(VAULT_DIR)") \
	  $(if $(ROUND),--round $(ROUND)) \
	  $(if $(FORCE),--force) \
	  $(if $(DRY_RUN),--dry-run)

audit-closeout-test:
	@python3 -m unittest tools.tests.test_audit_closeout_check tools.tests.test_case_study_emitter

# G15.2: hunt-coverage gate. Warn-grade in `make audit`, strict in
# `make audit-closeout`. Reuses workspace-coverage-heatmap internals.
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
hunt-coverage-gate:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hunt-coverage-gate WS=<workspace> [MIN_COVERAGE=0.80] [STRICT=1] [JSON=1] [RUN_ID=<audit-run-id>]'; exit 2; fi
	@python3 tools/hunt-coverage-gate.py --workspace "$(WS)" \
	  $(if $(MIN_COVERAGE),--min-coverage-pct $(MIN_COVERAGE)) \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json) \
	  $(if $(RUN_ID),--run-id "$(RUN_ID)")

.PHONY: unhunted-adjudicate
# unhunted-adjudicate: drive abandoned unhunted-surface leads to evidence-grounded
# terminal verdicts (interface-decl / vendored-lib / covered-in-scope /
# solvency-invariant-fuzzed-clean). Writes .auditooor/unhunted_terminal_verdicts.json;
# the follow-through gate credits ONLY entries whose evidence_ref is a real file.
# Leads with no genuine basis stay OPEN (a real gap is never hidden).
unhunted-adjudicate:
	@if [ -z "$(WS)" ]; then echo 'Usage: make unhunted-adjudicate WS=<workspace> [DRY_RUN=1]'; exit 2; fi
	@python3 tools/unhunted-surface-adjudicate.py --workspace "$(_WS_RESOLVED)" $(if $(DRY_RUN),--dry-run)

.PHONY: exploit-class-coverage
# exploit-class-coverage: the ENFORCED manual-authoring checklist. Every systemic /
# compositional exploit class tooling cannot auto-find (multi-step-economic,
# system-invariant, stateful-history, cross-chain, upgradability, oracle, governance,
# donation, rounding, access-composition) must carry a backed disposition in
# .auditooor/exploit_class_coverage.json. `--scaffold` writes the template to fill in.
exploit-class-coverage:
	@if [ -z "$(WS)" ]; then echo 'Usage: make exploit-class-coverage WS=<workspace> [SCAFFOLD=1]'; exit 2; fi
	@python3 tools/exploit-class-coverage.py --workspace "$(_WS_RESOLVED)" $(if $(SCAFFOLD),--scaffold) $(if $(JSON),--json)

.PHONY: invariant-fuzz-completeness
# invariant-fuzz-completeness: enforce that every invariant harness in the workspace
# is multi-invariant + mutation-verified + ACTUALLY FUZZED by a coverage-guided engine
# (medusa/echidna corpus / deep-engine artifact). A built-but-never-fuzzed harness FAILS.
# Wired as the L37 `invariant-fuzz` signal so it cannot be skipped per workspace.
invariant-fuzz-completeness:
	@if [ -z "$(WS)" ]; then echo 'Usage: make invariant-fuzz-completeness WS=<workspace>'; exit 2; fi
	@python3 tools/invariant-fuzz-completeness.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json)

.PHONY: invariant-fuzz-credit-audit
# invariant-fuzz-credit-audit: ADVISORY cross-cutting VISIBILITY net for the
# invariant-fuzz DEPTH-false-credit class. A sidecar can be mutation_verified
# (harness QUALITY) yet carry NO coverage-guided campaign meeting its call floor
# (fuzz DEPTH) - a shallow forge-invariant runs:256=128k or manual-mutant-harness
# then false-credits a >=1M asset-gap. This scanner FLAGS those suspects per
# workspace (or --all for the retroactive roll-up). It does NOT hard-fail (the
# hard-fail lives in invariant-fuzz-completeness.py); this is visibility only.
invariant-fuzz-credit-audit:
	@if [ -z "$(WS)" ] && [ -z "$(ALL)" ]; then echo 'Usage: make invariant-fuzz-credit-audit WS=<workspace>  (or ALL=1)'; exit 2; fi
	@python3 tools/invariant-fuzz-credit-audit.py $(if $(ALL),--all,--workspace "$(_WS_RESOLVED)") $(if $(JSON),--json)

.PHONY: honest-zero-verify
# honest-zero-verify: RECOMPUTE a genuine honest-0 from real evidence (fresh
# pass-audit-complete STRICT + unhunted-clean + nothing-fileable + real deep
# evidence). Un-fakeable: a hand-written honest_zero.json cannot satisfy it; the
# audit-done-guard calls this directly. `--stamp` writes the auditable record.
honest-zero-verify:
	@if [ -z "$(WS)" ]; then echo 'Usage: make honest-zero-verify WS=<workspace> [STAMP=1]'; exit 2; fi
	@python3 tools/honest-zero-verify.py --workspace "$(_WS_RESOLVED)" $(if $(STAMP),--stamp)

coverage-to-hunt-seed:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make coverage-to-hunt-seed WS=<workspace> [REBUILD_REPORT=1] [DRY_RUN=1] [RUN_ID=<audit-run-id>] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make coverage-to-hunt-seed" "$(_WS_RESOLVED)"
	@python3 tools/coverage-to-hunt-seed.py --workspace-path "$(_WS_RESOLVED)" \
	  $(if $(REBUILD_REPORT),--rebuild-report) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(RUN_ID),--run-id "$(RUN_ID)") \
	  $(if $(JSON),--json)

# mechanism-to-exploit-queue: the ACT half of the completeness-matrix MECHANISM
# axis. Turns every OPEN (un-dispositioned) mechanism finding
# (.auditooor/mechanism_scan/*.json finding_count>0 + agent_mechanism_verdicts
# verdict==finding rows) into a mechanism-finding exploit_queue row, so a fired
# detector (e.g. a chain-halt) flows into the SAME exploit-conversion input the
# rest of the pipeline consumes instead of dead-ending at the completeness gate.
mechanism-to-exploit-queue:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make mechanism-to-exploit-queue WS=<workspace> [DRY_RUN=1] [RUN_ID=<audit-run-id>] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make mechanism-to-exploit-queue" "$(_WS_RESOLVED)"
	@python3 tools/mechanism-findings-to-exploit-queue.py --workspace-path "$(_WS_RESOLVED)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(RUN_ID),--run-id "$(RUN_ID)") \
	  $(if $(JSON),--json)

# rehunt-uncovered (B1 pre-hunt rewire): drain the NOT-ENUMERATED completeness
# cells the matrix already wrote to
# .auditooor/completeness_enumeration_worklist.jsonl by FANNING them out into N
# CONCURRENT canonical spawn-worker hunt lanes (one lane per uncovered cell), so
# enumeration actually feeds the hunt instead of dead-ending as a WARN nobody
# acts on. Composes tools/spawn-worker-fanout.py (which composes spawn-worker.sh)
# - never forks either. Prints one enriched-prompt path per line for the
# orchestrator to hand to N concurrent Agent calls in ONE message.
#
# DEFAULT-OFF: gated behind AUDITOOOR_REHUNT_UNCOVERED (unset/0/false/no => a
# SKIPPED no-op that mutates nothing), so no pipeline that does not opt in ever
# changes behavior. Runs --dry-run unless AUDITOOOR_REHUNT_UNCOVERED_DISPATCH=1
# is ALSO set (dry-run renders per-lane prompts + manifest but never invokes
# spawn-worker / registers lanes / touches git), so a routine opt-in run is still
# side-effect-light until the operator explicitly asks to dispatch.
# Tunables: LANE_TYPE (default hunt), SEVERITY (default HIGH), LANE_PREFIX
# (default rehunt), FILTER_AXIS (optional axis filter), MAX (lane cap),
# PROMPT_TEMPLATE (override the canonical rehunt template).
rehunt-uncovered:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rehunt-uncovered WS=<workspace> AUDITOOOR_REHUNT_UNCOVERED=1 [AUDITOOOR_REHUNT_UNCOVERED_DISPATCH=1] [LANE_TYPE=hunt] [SEVERITY=HIGH] [LANE_PREFIX=rehunt] [FILTER_AXIS=function] [MAX=16] [PROMPT_TEMPLATE=<path>]'; exit 2; \
	elif ! bash tools/ws-resolve-guard.sh "make rehunt-uncovered" "$(_WS_RESOLVED)"; then \
	  exit 2; \
	elif [ -z "$(AUDITOOOR_REHUNT_UNCOVERED)" ] || [ "$(AUDITOOOR_REHUNT_UNCOVERED)" = "0" ] || [ "$(AUDITOOOR_REHUNT_UNCOVERED)" = "false" ] || [ "$(AUDITOOOR_REHUNT_UNCOVERED)" = "no" ]; then \
	  echo "[make rehunt-uncovered] SKIPPED (default): opt-in only; set AUDITOOOR_REHUNT_UNCOVERED=1 to fan the completeness worklist into concurrent hunt lanes"; \
	else \
	  _wl="$(_WS_RESOLVED)/.auditooor/completeness_enumeration_worklist.jsonl"; \
	  if [ ! -f "$$_wl" ]; then \
	    echo "[make rehunt-uncovered] no worklist at $$_wl; run the pre-hunt enumerate step first (AUDITOOOR_PREHUNT_MATRIX=1 make audit-pipeline-full, or make completeness-matrix WS=<ws>)"; \
	  else \
	    _tmpl="$(if $(PROMPT_TEMPLATE),$(PROMPT_TEMPLATE),reference/dispatch-templates/rehunt_uncovered_cell.md.tmpl)"; \
	    python3 tools/spawn-worker-fanout.py \
	      --worklist "$$_wl" \
	      --lane-type "$(if $(LANE_TYPE),$(LANE_TYPE),hunt)" \
	      --severity "$(if $(SEVERITY),$(SEVERITY),HIGH)" \
	      --workspace "$(_WS_RESOLVED)" \
	      --lane-prefix "$(if $(LANE_PREFIX),$(LANE_PREFIX),rehunt)" \
	      --prompt-template "$$_tmpl" \
	      $(if $(FILTER_AXIS),--filter-axis "$(FILTER_AXIS)") \
	      $(if $(MAX),--max "$(MAX)") \
	      $(if $(AUDITOOOR_REHUNT_UNCOVERED_DISPATCH),,--dry-run); \
	  fi; \
	fi

rehunt-uncovered-test:
	@python3 -m unittest tools.tests.test_rehunt_uncovered_makefile -v

# auto-coverage-close (Rule G15 follow-on): generic bounded ORCHESTRATOR that
# drives BOTH coverage axes (SURFACE units + RUBRIC impact classes) to closure.
# It runs a per-unit deterministic hunt (honest no-finding / needs-llm verdicts),
# seeds an impact-class hunt brief per UNATTEMPTED rubric row, loops bounded
# (fixpoint / max-iters), and emits a residual worker-dispatch queue. Advisory:
# never re-implements coverage-to-hunt-seed / hunt-coverage-gate / rubric tools -
# it shells / imports them.
auto-coverage-close:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make auto-coverage-close WS=<workspace> [MAX_ITERS=3] [COVERAGE_THRESHOLD=1.0] [UNIT_CAP=400] [RUN_ID=<audit-run-id>] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make auto-coverage-close" "$(_WS_RESOLVED)"
	@python3 tools/auto-coverage-closer.py --workspace "$(_WS_RESOLVED)" \
	  --max-iters $(if $(MAX_ITERS),$(MAX_ITERS),3) \
	  --coverage-threshold $(if $(COVERAGE_THRESHOLD),$(COVERAGE_THRESHOLD),1.0) \
	  --unit-cap $(if $(UNIT_CAP),$(UNIT_CAP),400) \
	  $(if $(RUN_ID),--run-id "$(RUN_ID)") \
	  $(if $(JSON),--json)

evidence-class-validator:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make evidence-class-validator WS=<workspace> [STRICT=1] [JSON=1] [OUT_JSON=<path>]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make evidence-class-validator" "$(_WS_RESOLVED)"
	@python3 tools/evidence-class-validator.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json) \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

evidence-class-validator-test:
	@python3 -m unittest tools.tests.test_evidence_class_validator

evidence-class-legacy-backfill:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make evidence-class-legacy-backfill WS=<workspace> [DRY_RUN=1] [OUT_JSON=<path>]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make evidence-class-legacy-backfill" "$(_WS_RESOLVED)"
	@python3 tools/evidence-class-legacy-backfill.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

evidence-class-legacy-backfill-test:
	@python3 -m unittest tools.tests.test_evidence_class_legacy_backfill

# Thin aliases for TOOL_STATUS-documented PR560 / Foundry helpers. These
# wrappers intentionally only forward to existing stdlib tools; they do not
# install dependencies, mutate toolchains, or promote advisory rows to proof.
impact-miss-offset-benchmark:
	@python3 tools/impact-miss-offset-benchmark.py \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(PREDICTIONS),--predictions "$(PREDICTIONS)") \
	  $(if $(DERIVE_PREDICTIONS),--derive-predictions) \
	  $(if $(DEMO_FIXTURE),--demo-fixture) \
	  $(if $(EMIT_HARNESS_BLOCKERS),--emit-harness-blockers) \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

impact-miss-harness-blocker-executor:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-miss-harness-blocker-executor WS=<workspace> [EXECUTE_SAFE=1] [QUEUE=<json>] [LIMIT=<n>] [JSON=1]'; exit 2; fi
	@python3 tools/impact-miss-harness-blocker-executor.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(EXECUTE_SAFE),--execute-safe) \
	  $(if $(JSON),--print-json)

source-proof-impact-bridge:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make source-proof-impact-bridge WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/source-proof-impact-bridge.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(MIN_ITEMS),--min-items "$(MIN_ITEMS)") \
	  $(if $(MAX_ITEMS),--max-items "$(MAX_ITEMS)") \
	  $(if $(JSON),--print-json)

impact-proof-requirement-manifests:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-proof-requirement-manifests WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/impact-proof-requirement-manifests.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(MIN_ITEMS),--min-items "$(MIN_ITEMS)") \
	  $(if $(MAX_ITEMS),--max-items "$(MAX_ITEMS)") \
	  $(if $(NO_ROW_MANIFESTS),--no-row-manifests) \
	  $(if $(JSON),--print-json)

impact-proof-source-citation-backfill:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-proof-source-citation-backfill WS=<workspace> [MANIFEST=<json>] [JSON=1]'; exit 2; fi
	@python3 tools/impact-proof-source-citation-backfill.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(MANIFEST),--manifest "$(MANIFEST)") \
	  $(if $(HINT_LIMIT),--hint-limit "$(HINT_LIMIT)") \
	  $(if $(NO_ROW_MANIFESTS),--no-row-manifests) \
	  $(if $(JSON),--print-json)

impact-proof-project-evidence-executor:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-proof-project-evidence-executor WS=<workspace> [BACKFILL=<json>] [EXECUTION=<json>] [JSON=1]'; exit 2; fi
	@python3 tools/impact-proof-project-evidence-executor.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(BACKFILL),--backfill "$(BACKFILL)") \
	  $(if $(EXECUTION),--execution "$(EXECUTION)") \
	  $(if $(NO_ROW_MANIFESTS),--no-row-manifests) \
	  $(if $(JSON),--print-json)

high-impact-execution-bridge:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make high-impact-execution-bridge WS=<workspace> [ROW=<row_id>] [FORCE=1] [JSON=1]'; exit 2; fi
	@python3 tools/high-impact-execution-bridge.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(ROW),--row "$(ROW)") \
	  $(if $(FORCE),--force) \
	  $(if $(JSON),--print-json)

foundry-version-report:
	@python3 tools/foundry-version-report.py \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(TIMEOUT),--timeout "$(TIMEOUT)") \
	  $(if $(JSON),--print-json)

foundry-v17-trial-plan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make foundry-v17-trial-plan WS=<workspace> [INVENTORY_JSON=<json>] [JSON=1]'; exit 2; fi
	@python3 tools/foundry-v17-trial-plan.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(INVENTORY_JSON),--inventory-json "$(INVENTORY_JSON)") \
	  $(if $(JSON),--print-json)

foundry-v17-normalization-plan:
	@python3 tools/foundry-v17-normalization-plan.py \
	  $(if $(ROOT),--root "$(ROOT)") \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(SEED),--seed "$(SEED)") \
	  $(if $(JSON),--print-json)

foundry-v17-trial-executor:
	@python3 tools/foundry-v17-trial-executor.py \
	  $(if $(ROOT),--root "$(ROOT)") \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(MANIFEST),--manifest "$(MANIFEST)") \
	  $(if $(TARGET_BIN),--target-bin "$(TARGET_BIN)") \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(STRICT),--strict-exit) \
	  $(if $(JSON),--print-json)

foundry-v17-blocker-closure:
	@python3 tools/foundry-v17-blocker-closure.py \
	  $(if $(PREFLIGHT_JSON),--preflight-json "$(PREFLIGHT_JSON)") \
	  $(if $(TARGET_BIN),--target-bin "$(TARGET_BIN)") \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(JSON),--print-json)

# PR #511 Slice 2 - invariant ledger: workspace bridge between scope/spec
# understanding and runnable harnesses. Idempotent. stdlib-only.
invariant-ledger:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make invariant-ledger WS=<workspace>'; exit 2; fi
	@python3 tools/invariant-ledger.py --workspace "$(_WS_RESOLVED)" --init

invariant-ledger-check:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make invariant-ledger-check WS=<workspace> [REQUIRE_HIGH_IMPACT_INVARIANTS=1]'; exit 2; fi
	@if [ -n "$(REQUIRE_HIGH_IMPACT_INVARIANTS)" ]; then \
	  python3 tools/invariant-ledger.py --workspace "$(_WS_RESOLVED)" --require-high-impact-harness; \
	else \
	  python3 tools/invariant-ledger.py --workspace "$(_WS_RESOLVED)" --check; \
	fi

invariant-ledger-test:
	@python3 -m unittest tools.tests.test_invariant_ledger

invariant-discovery-adoption:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make invariant-discovery-adoption WS=<workspace> [ADOPT_LEDGER=1] [JSON=1]'; exit 2; fi
	@python3 tools/invariant-discovery-adoption.py --workspace "$(_WS_RESOLVED)" $(if $(ADOPT_LEDGER),--adopt-ledger) $(if $(JSON),--print-json)

invariant-discovery-adoption-test:
	@python3 -m unittest tools.tests.test_invariant_discovery_adoption

invariant-adoption-fresh-metrics:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make invariant-adoption-fresh-metrics WS=<workspace> [SOURCE_WS=<fresh-workspace>] [MANIFEST=<json>] [JSON=1]'; exit 2; fi
	@python3 tools/invariant-adoption-fresh-metrics.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(SOURCE_WS),--source-workspace "$(SOURCE_WS)") \
	  $(if $(MANIFEST),--manifest "$(MANIFEST)") \
	  $(if $(JSON),--print-json)

invariant-adoption-fresh-metrics-test:
	@python3 -m unittest tools.tests.test_invariant_adoption_fresh_metrics

invariant-adoption-closure-readiness:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make invariant-adoption-closure-readiness WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/invariant-adoption-closure-readiness.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json)

invariant-adoption-closure-readiness-test:
	@python3 -m unittest tools.tests.test_invariant_adoption_closure_readiness

# PR #526 gap 3 - invariant-to-harness planner. Reads the workspace
# ledger and emits per-row plans (harness family, fixtures, target
# entrypoint, compile command, negative control, expected log,
# stop condition). stdlib-only, idempotent.
harness-plan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make harness-plan WS=<workspace> [ROW=<id>] [ALL=1] [OUT=<path>]'; exit 2; fi
	@python3 tools/invariant-harness-planner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(ROW),--row "$(ROW)") \
	  $(if $(ALL),--all) \
	  $(if $(OUT),--out "$(OUT)")

harness-plan-test:
	@python3 -m unittest tools.tests.test_invariant_harness_planner

# PR #535 / Wave 8 JJ2 - harness-plan -> executable scaffold bridge.
# Runs the planner first to refresh harness_plans.json, then the emitter
# to drop a per-row scaffold tree under <ws>/poc-tests/<row>/ (Rust /
# live-check) or <ws>/poc-tests-<row>/ (forge_invariant profile dir).
# The scaffold route also writes <ws>/.auditooor/harness_binding_manifest.json
# so every plan row is either a ready binding or a schema-valid blocked binding.
# A failed-attempt manifest (`status: blocked`) is always written so
# future agents do not re-walk dead paths.
harness-scaffold:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make harness-scaffold WS=<workspace> [ROW=<id>] [ALL=1] [FORCE=1]'; exit 2; fi
	@python3 tools/invariant-harness-planner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(ROW),--row "$(ROW)") \
	  $(if $(ALL),--all)
	@python3 tools/harness-scaffold-emitter.py \
	  --plan "$(_WS_RESOLVED)/.auditooor/harness_plans.json" \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(ROW),--row "$(ROW)") \
	  $(if $(FORCE),--force)

harness-scaffold-test:
	@python3 -m unittest tools.tests.test_harness_scaffold_emitter

# W4.6 - baseline invariant/property fuzz-harness generator. Scaffolds an
# echidna/medusa-compatible harness + configs for a workspace with no
# hand-written invariant contract.
invariant-harness-gen:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make invariant-harness-gen WS=<workspace> [CONTRACT=<name>] [FORCE=1]'; exit 2; fi
	@python3 tools/audit/invariant-harness-generator.py "$(_WS_RESOLVED)" \
	  $(if $(CONTRACT),--contract "$(CONTRACT)") \
	  $(if $(FORCE),--force)

invariant-harness-gen-test:
	@python3 -m unittest tools.tests.test_invariant_harness_generator

# L29-Disc-6 / S4 - bitcoind regtest harness for Spark CRIT-1 network-level evidence.
# Template: reference/harness-fixture-kits/spark_bitcoind_regtest_multiso/PLAN.md
# PoC reuse: ~/audits/spark/poc-tests/lead_commit_resume/regtest_harness/
#
# Spinup: make spark-regtest-harness WS=~/audits/spark
#   - Idempotent: if regtest already running, skips spinup and refreshes state JSON.
#   - Emits <WS>/.auditooor/regtest_state.json with RPC creds + funded address.
#   - Requires: bitcoind 25+ in PATH (brew install bitcoin / apt-get install bitcoind).
#
# Teardown: make spark-regtest-teardown WS=~/audits/spark
#   - Stops the daemon and removes the pidfile; data_dir preserved for replay.
spark-regtest-harness:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make spark-regtest-harness WS=<workspace>  (e.g. WS=~/audits/spark)'; exit 2; fi
	@bash tools/spark-regtest-harness.sh --ws="$(_WS_RESOLVED)"

spark-regtest-teardown:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make spark-regtest-teardown WS=<workspace>'; exit 2; fi
	@bash tools/spark-regtest-harness.sh --teardown --ws="$(_WS_RESOLVED)"

# Smoke test: exercises --check mode (validates prerequisites, no daemon spawned).
spark-regtest-harness-test:
	@python3 -m unittest tools.tests.test_spark_regtest_harness

semantic-graph:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-graph WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/semantic-graph.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json)

semantic-graph-test:
	@python3 -m unittest tools.tests.test_semantic_graph_and_critical_hunt tools.tests.test_production_path_dossier

semantic-graph-query:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-graph-query WS=<workspace> [JSON=1] [TASK_ID=<id>] [LIMIT=50] [IMPACT_WORKLIST=1]'; exit 2; fi
	@python3 tools/semantic-graph-query.py --workspace "$(_WS_RESOLVED)" $(if $(IMPACT_WORKLIST),--impact-worklist "$(_WS_RESOLVED)/.auditooor/impact_family_worklists.json") $(if $(JSON),--print-json) $(if $(TASK_ID),--task-id "$(TASK_ID)") $(if $(LIMIT),--limit "$(LIMIT)")

semantic-graph-query-test:
	@python3 -m unittest tools.tests.test_semantic_graph_query

semantic-detector-worklist:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-detector-worklist WS=<workspace> [JSON=1] [GENERATE_GRAPH=1]'; exit 2; fi
	@python3 tools/semantic-detector-worklist.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(GENERATE_GRAPH),--generate-graph)

semantic-detector-worklist-test:
	@python3 -m unittest tools.tests.test_semantic_detector_worklist

callgraph-limitation-queue:
	@python3 tools/callgraph-limitation-queue.py $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)")

callgraph-limitation-queue-test:
	@python3 -m unittest tools.tests.test_callgraph_limitation_queue

callgraph-terminal-conversion:
	@python3 tools/callgraph-terminal-conversion.py $(if $(JSON),--print-json) $(if $(EXECUTION),--execution "$(EXECUTION)") $(if $(QUEUE),--queue "$(QUEUE)") $(if $(SMOKE_LOG_DIR),--smoke-log-dir "$(SMOKE_LOG_DIR)")

callgraph-terminal-conversion-test:
	@python3 -m unittest tools.tests.test_callgraph_terminal_conversion

semantic-detector-adjudication:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-detector-adjudication WS=<workspace> [JSON=1] [LIMIT=50]'; exit 2; fi
	@python3 tools/semantic-detector-adjudication.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)")

semantic-detector-adjudication-test:
	@python3 -m unittest tools.tests.test_semantic_detector_adjudication

semantic-detector-argument-resolver:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-detector-argument-resolver WS=<workspace> [JSON=1] [LIMIT=500] [TASKS=<path>]'; exit 2; fi
	@python3 tools/semantic-detector-argument-resolver.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)") $(if $(TASKS),--tasks "$(TASKS)")

semantic-detector-argument-resolver-test:
	@python3 -m unittest tools.tests.test_semantic_detector_argument_resolver

semantic-scanner-inventory:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-scanner-inventory WS=<workspace> [JSON=1] [LIMIT=50] [GENERATE_GRAPH=1]'; exit 2; fi
	@python3 tools/semantic-scanner-inventory.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)") $(if $(GENERATE_GRAPH),--generate-graph)

semantic-scanner-inventory-test:
	@python3 -m unittest tools.tests.test_semantic_scanner_inventory

semantic-fixture-smoke-gate:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-fixture-smoke-gate WS=<workspace> [JSON=1] [LIMIT=50] [STRICT=1]'; exit 2; fi
	@python3 tools/semantic-fixture-smoke-gate.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)") $(if $(STRICT),--strict)

semantic-fixture-smoke-gate-test:
	@python3 -m unittest tools.tests.test_semantic_fixture_smoke_gate

semantic-fixture-smoke-tasks:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-fixture-smoke-tasks WS=<workspace> [JSON=1] [LIMIT=50] [STRICT=1] [SMOKE_RESULTS=<path>] [NO_WRITE_INGESTED=1] [MATERIALIZE_MANIFESTS=1]'; exit 2; fi
	@python3 tools/semantic-fixture-smoke-tasks.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)") $(if $(STRICT),--strict) $(if $(SMOKE_RESULTS),--smoke-results "$(SMOKE_RESULTS)") $(if $(NO_WRITE_INGESTED),--no-write-ingested) $(if $(MATERIALIZE_MANIFESTS),--materialize-manifests)

semantic-fixture-smoke-tasks-test:
	@python3 -m unittest tools.tests.test_semantic_fixture_smoke_tasks

semantic-live-depth-blockers:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-live-depth-blockers WS=<workspace> [JSON=1] [LIMIT=400]'; exit 2; fi
	@python3 tools/semantic-live-depth-blockers.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)")

semantic-live-depth-blockers-test:
	@python3 -m unittest tools.tests.test_semantic_live_depth_blockers

semantic-live-depth-queue:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-live-depth-queue WS=<workspace> [JSON=1] [LIMIT=400]'; exit 2; fi
	@python3 tools/semantic-live-depth-queue.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)")

semantic-live-depth-queue-test:
	@python3 -m unittest tools.tests.test_semantic_live_depth_queue

live-topology-proof-requirements:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-proof-requirements WS=<workspace> [JSON=1] [LIMIT=400]'; exit 2; fi
	@python3 tools/live-topology-proof-requirements.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)")

live-topology-proof-requirements-test:
	@python3 -m unittest tools.tests.test_live_topology_proof_requirements

live-topology-proof-executor:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-proof-executor WS=<workspace> [JSON=1] [LIMIT=400] [DEMO_FIXTURE=1]'; exit 2; fi
	@python3 tools/live-topology-proof-executor.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)") $(if $(DEMO_FIXTURE),--demo-fixture)

live-topology-proof-executor-test:
	@python3 -m unittest tools.tests.test_live_topology_proof_executor

live-topology-proof-ingest:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-proof-ingest WS=<workspace> [JSON=1] [LIMIT=400] [WRITE_CANONICAL_SKELETON=1] [FORCE=1]'; exit 2; fi
	@python3 tools/live-topology-proof-ingest.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)") $(if $(WRITE_CANONICAL_SKELETON),--write-canonical-skeleton) $(if $(FORCE),--force)

live-topology-proof-ingest-test:
	@python3 -m unittest tools.tests.test_live_topology_proof_ingest

live-topology-manual-proof-plan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-manual-proof-plan WS=<workspace> [JSON=1] [NO_WRITE_TEMPLATES=1]'; exit 2; fi
	@python3 tools/live-topology-manual-proof-plan.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(NO_WRITE_TEMPLATES),--no-write-templates)

live-topology-manual-proof-plan-test:
	@python3 -m unittest tools.tests.test_live_topology_manual_proof_plan

live-topology-terminalization:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-terminalization WS=<workspace> [FD_PLAN=<json>] [FD_TEMPLATE_DIR=<dir>] [EW_RESOLUTION=<json>] [LIVE_TOPOLOGY=<json>] [CLOSURE_GLOB=<glob>] [OUT_JSON=<json>] [OUT_MD=<md>] [JSON=1]'; exit 2; fi
	@python3 tools/live-topology-terminalization.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(FD_PLAN),--fd-plan "$(FD_PLAN)") \
	  $(if $(FD_TEMPLATE_DIR),--fd-template-dir "$(FD_TEMPLATE_DIR)") \
	  $(if $(EW_RESOLUTION),--ew-resolution "$(EW_RESOLUTION)") \
	  $(if $(LIVE_TOPOLOGY),--live-topology "$(LIVE_TOPOLOGY)") \
	  $(if $(CLOSURE_GLOB),--closure-glob "$(CLOSURE_GLOB)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(JSON),--print-json)

live-topology-terminalization-test:
	@python3 -m unittest tools.tests.test_live_topology_terminalization

live-topology-addressable-followup:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-addressable-followup WS=<workspace> [FJ_GROUP=<json>] [EW_RESOLUTION=<json>] [DEPLOYMENT_TOPOLOGY=<json>] [TEMPLATE_DIR=<dir>] [OUT_JSON=<json>] [OUT_MD=<md>] [REQUIREMENT_DIR=<dir>] [NO_WRITE_REQUIREMENTS=1] [JSON=1]'; exit 2; fi
	@python3 tools/live-topology-addressable-followup.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(FJ_GROUP),--fj-group "$(FJ_GROUP)") \
	  $(if $(EW_RESOLUTION),--ew-resolution "$(EW_RESOLUTION)") \
	  $(if $(DEPLOYMENT_TOPOLOGY),--deployment-topology "$(DEPLOYMENT_TOPOLOGY)") \
	  $(if $(TEMPLATE_DIR),--template-dir "$(TEMPLATE_DIR)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(REQUIREMENT_DIR),--requirement-dir "$(REQUIREMENT_DIR)") \
	  $(if $(NO_WRITE_REQUIREMENTS),--no-write-requirements) \
	  $(if $(JSON),--print-json)

live-topology-addressable-followup-test:
	@python3 -m unittest tools.tests.test_live_topology_addressable_followup

live-topology-proof-readiness:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-proof-readiness WS=<workspace> [REQUIREMENTS=<json>] [TEMPLATE_DIR=<dir>] [LIVE_TOPOLOGY=<json>] [MANUAL_PROOFS=<dir>] [ADDRESSABLE_FOLLOWUP=<json>] [OUT_JSON=<json>] [OUT_MD=<md>] [BUNDLE_DIR=<dir>] [NO_WRITE_BUNDLES=1] [JSON=1]'; exit 2; fi
	@python3 tools/live-topology-proof-readiness.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(REQUIREMENTS),--requirements "$(REQUIREMENTS)") \
	  $(if $(TEMPLATE_DIR),--template-dir "$(TEMPLATE_DIR)") \
	  $(if $(LIVE_TOPOLOGY),--live-topology "$(LIVE_TOPOLOGY)") \
	  $(if $(MANUAL_PROOFS),--manual-proofs "$(MANUAL_PROOFS)") \
	  $(if $(ADDRESSABLE_FOLLOWUP),--addressable-followup "$(ADDRESSABLE_FOLLOWUP)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(BUNDLE_DIR),--bundle-dir "$(BUNDLE_DIR)") \
	  $(if $(NO_WRITE_BUNDLES),--no-write-bundles) \
	  $(if $(JSON),--print-json)

live-topology-proof-readiness-test:
	@python3 -m unittest tools.tests.test_live_topology_proof_readiness

live-topology-proof-input-bridge:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-proof-input-bridge WS=<workspace> [READINESS=<json>] [OUT_JSON=<json>] [OUT_MD=<md>] [BUNDLE_DIR=<dir>] [NO_WRITE_BUNDLES=1] [JSON=1]'; exit 2; fi
	@python3 tools/live-topology-proof-input-bridge.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(READINESS),--readiness "$(READINESS)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(BUNDLE_DIR),--bundle-dir "$(BUNDLE_DIR)") \
	  $(if $(NO_WRITE_BUNDLES),--no-write-bundles) \
	  $(if $(JSON),--print-json)

live-topology-proof-input-bridge-test:
	@python3 -m unittest tools.tests.test_live_topology_proof_input_bridge

live-topology-proof-input-validator:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-proof-input-validator WS=<workspace> [BRIDGE=<json>] [MANUAL_PROOFS=<dir>] [OUT_JSON=<json>] [OUT_MD=<md>] [BUNDLE_DIR=<dir>] [NO_WRITE_BUNDLES=1] [JSON=1]'; exit 2; fi
	@python3 tools/live-topology-proof-input-validator.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(BRIDGE),--bridge "$(BRIDGE)") \
	  $(if $(MANUAL_PROOFS),--manual-proofs "$(MANUAL_PROOFS)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(BUNDLE_DIR),--bundle-dir "$(BUNDLE_DIR)") \
	  $(if $(NO_WRITE_BUNDLES),--no-write-bundles) \
	  $(if $(JSON),--print-json)

live-topology-proof-input-validator-test:
	@python3 -m unittest tools.tests.test_live_topology_proof_input_validator

live-topology-real-proof-input-router:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-real-proof-input-router WS=<workspace> [BRIDGE=<json>] [INPUT_DIR=<dir>] [PROVIDED_DIR=<dir>] [OUT_JSON=<json>] [OUT_MD=<md>] [BUNDLE_DIR=<dir>] [DRY_RUN=1] [NO_WRITE_BUNDLES=1] [JSON=1]'; exit 2; fi
	@python3 tools/live-topology-real-proof-input-router.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(BRIDGE),--bridge "$(BRIDGE)") \
	  $(if $(INPUT_DIR),--input-dir "$(INPUT_DIR)") \
	  $(if $(PROVIDED_DIR),--provided-dir "$(PROVIDED_DIR)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(BUNDLE_DIR),--bundle-dir "$(BUNDLE_DIR)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(NO_WRITE_BUNDLES),--no-write-bundles) \
	  $(if $(JSON),--print-json)

live-topology-real-proof-input-router-test:
	@python3 -m unittest tools.tests.test_live_topology_real_proof_input_router

live-topology-manual-proof-materializer:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-topology-manual-proof-materializer WS=<workspace> [VALIDATOR=<json>] [PROVIDED_DIR=<dir>] [MANUAL_PROOFS=<dir>] [OUT_JSON=<json>] [OUT_MD=<md>] [DRY_RUN=1] [JSON=1]'; exit 2; fi
	@python3 tools/live-topology-manual-proof-materializer.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(VALIDATOR),--validator "$(VALIDATOR)") \
	  $(if $(PROVIDED_DIR),--provided-dir "$(PROVIDED_DIR)") \
	  $(if $(MANUAL_PROOFS),--manual-proofs "$(MANUAL_PROOFS)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--print-json)

live-topology-manual-proof-materializer-test:
	@python3 -m unittest tools.tests.test_live_topology_manual_proof_materializer

codex-worker-launcher:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make codex-worker-launcher WS=<workspace> PROMPTS="<prompt.md ...>" [MODEL=auto] [DRY_RUN=1] [PRINT_JSON=1]'; exit 2; fi
	@if [ -z "$(PROMPTS)" ]; then \
	  echo 'Usage: make codex-worker-launcher WS=<workspace> PROMPTS="<prompt.md ...>" [MODEL=auto] [DRY_RUN=1] [PRINT_JSON=1]'; exit 2; fi
	@python3 tools/codex-worker-launcher.py --workspace "$(_WS_RESOLVED)" $(foreach prompt,$(PROMPTS),--prompt "$(prompt)") $(if $(MODEL),--model "$(MODEL)") $(if $(DRY_RUN),--dry-run) $(if $(PRINT_JSON),--print-json)

codex-worker-launcher-test:
	@python3 -m unittest tools.tests.test_codex_worker_launcher

rust-runtime-semantic-blockers:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-runtime-semantic-blockers WS=<workspace> [JSON=1] [LIMIT=50] [GENERATE=1]'; exit 2; fi
	@python3 tools/rust-runtime-semantic-blockers.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json) $(if $(LIMIT),--limit "$(LIMIT)") $(if $(GENERATE),--generate-graphs)

rust-runtime-semantic-blockers-test:
	@python3 -m unittest tools.tests.test_rust_runtime_semantic_blockers

runtime-dlt-execution-evidence:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make runtime-dlt-execution-evidence WS=<workspace> [JSON=1] [DEMO_FIXTURE=1]'; exit 2; fi
	@python3 tools/runtime-dlt-execution-evidence-validator.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(DEMO_FIXTURE),--demo-fixture) \
	  $(if $(JSON),--print-json)

runtime-dlt-execution-evidence-test:
	@python3 -m unittest tools.tests.test_runtime_dlt_execution_evidence_validator

critical-hunt:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make critical-hunt WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/critical-hunt.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--print-json)

critical-hunt-test: semantic-graph-test

# PR #544 Lane H - Base critical-candidate matrix generator. Default-to-kill
# semantics: rows without one exact rubric-listed Critical impact sentence are
# flagged `kill_or_reframe`; severity is derived only from that selected row.
# An execution manifest is not enough unless `listed_impact_proven=true`.
base-critical-matrix:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make base-critical-matrix WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make base-critical-matrix" "$(_WS_RESOLVED)"
	@python3 tools/base-critical-candidate-matrix.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

base-critical-matrix-test:
	@python3 -m unittest tools.tests.test_base_critical_candidate_matrix

# PR #544 Lane H - full Base critical-hunt orchestrator. Runs:
#   1) base-critical-candidate-matrix
#   2) severity-claim-guard exact-impact proof gate
#   3) invariant-ledger --check
#   4) program-impact-mapping --check
#   5) audit-closeout
#   6) candidate queue summary (Markdown printed to stdout)
# In strict mode, advisory rows propagate non-zero exits. The matrix and
# severity-claim guard always enforce default-to-kill / exact-impact proof.
base-critical-hunt:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make base-critical-hunt WS=<workspace> [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make base-critical-hunt" "$(_WS_RESOLVED)"
	@python3 tools/base-critical-hunt.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(STRICT),--strict)

base-critical-hunt-test:
	@python3 -m unittest tools.tests.test_base_critical_candidate_matrix tools.tests.test_base_critical_hunt

# PR #560 - generic impact/coverage/inventory closure targets. These are
# intentionally workspace-generic wrappers around tools/automation-closure.py;
# Base-specific convenience target below uses the same implementation.
base-lessons-inventory:
	@python3 tools/automation-closure.py --mode base-lessons-inventory $(if $(JSON),--json) $(if $(STRICT),--strict)

corpus-mining-inventory:
	@python3 tools/automation-closure.py --mode corpus-mining-inventory $(if $(JSON),--json) $(if $(STRICT),--strict)

impact-matrix:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-matrix WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode impact-matrix $(if $(JSON),--json) $(if $(STRICT),--strict)

impact-contract-check:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-contract-check WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode impact-contract-check $(if $(JSON),--json) $(if $(STRICT),--strict)

impact-family-worklist:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-family-worklist WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/impact-family-worklist.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json)

impact-family-worklist-test:
	@python3 -m unittest tools.tests.test_impact_family_worklist -v

impact-worklist:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-worklist WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode impact-worklist $(if $(JSON),--json) $(if $(STRICT),--strict)

coverage-inventory:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make coverage-inventory WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode coverage-inventory $(if $(JSON),--json) $(if $(STRICT),--strict)

agent-output-inventory:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make agent-output-inventory WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode agent-output-inventory $(if $(JSON),--json) $(if $(STRICT),--strict)

agent-output-verify-record:
	@if [ -z "$(WS)" ] || [ -z "$(TERMINAL_STATE)" ] || [ -z "$(EVIDENCE_PATH)" ]; then \
	  echo 'Usage: make agent-output-verify-record WS=<workspace> TERMINAL_STATE=<verified_local|killed_duplicate_or_oos|routed_to_impact_analysis|routed_to_source_proof|routed_to_harness_task|detectorized|archived_no_claims> EVIDENCE_PATH=<path> [VERIFICATION_TASK_ID=<id>|STABLE_SOURCE_PATH=<path>|AGENT_OUTPUT=<path>|SOURCE_PATH=<path>] [NOTE=<text>] [NEXT_COMMAND=<cmd>] [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode agent-output-verify-record \
	  --terminal-state "$(TERMINAL_STATE)" \
	  --evidence-path "$(EVIDENCE_PATH)" \
	  $(if $(VERIFICATION_TASK_ID),--verification-task-id "$(VERIFICATION_TASK_ID)") \
	  $(if $(STABLE_SOURCE_PATH),--stable-source-path "$(STABLE_SOURCE_PATH)") \
	  $(if $(AGENT_OUTPUT),--agent-output "$(AGENT_OUTPUT)") \
	  $(if $(SOURCE_PATH),--source-path "$(SOURCE_PATH)") \
	  $(if $(NOTE),--note "$(NOTE)") \
	  $(if $(NEXT_COMMAND),--next-command "$(NEXT_COMMAND)") \
	  $(if $(JSON),--json) $(if $(STRICT),--strict)

agent-recall:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make agent-recall WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode agent-recall $(if $(JSON),--json) $(if $(STRICT),--strict)

impact-analysis-queue:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-analysis-queue WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode impact-analysis-queue $(if $(JSON),--json) $(if $(STRICT),--strict)

harness-task-queue:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make harness-task-queue WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode harness-task-queue $(if $(JSON),--json) $(if $(STRICT),--strict)

source-proof-task-queue:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make source-proof-task-queue WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode source-proof-task-queue $(if $(JSON),--json) $(if $(STRICT),--strict)

high-impact-impact-contract-skeletons:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make high-impact-impact-contract-skeletons WS=<workspace> [QUEUE=<json>] [OUT_JSON=<json>] [ROW=<id>] [VALIDATE_EXISTING=1] [JSON=1]'; exit 2; fi
	@python3 tools/high-impact-impact-contract-skeletons.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(ROW),--row "$(ROW)") \
	  $(if $(VALIDATE_EXISTING),--validate-existing) \
	  $(if $(JSON),--print-json)

pr560-next-actions:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make pr560-next-actions WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode pr560-next-actions $(if $(JSON),--json) $(if $(STRICT),--strict)

pr560-local-progress:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make pr560-local-progress WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode pr560-local-progress $(if $(JSON),--json) $(if $(STRICT),--strict)

tool-coverage-inventory:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make tool-coverage-inventory WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode tool-coverage-inventory $(if $(JSON),--json) $(if $(STRICT),--strict)

automation-closure:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make automation-closure WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode automation-closure $(if $(JSON),--json) $(if $(STRICT),--strict)

base-automation-closure:
	@_BASE_WS="$(if $(WS),$(_WS_RESOLVED),/Users/wolf/audits/base-azul)"; \
	if [ ! -d "$$_BASE_WS" ]; then \
	  echo 'Usage: make base-automation-closure WS=<workspace> [JSON=1] [STRICT=1] (default /Users/wolf/audits/base-azul missing)'; exit 2; \
	fi; \
	python3 tools/automation-closure.py --workspace "$$_BASE_WS" --mode base-automation-closure $(if $(JSON),--json) $(if $(STRICT),--strict)

known-limitations-burndown:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make known-limitations-burndown WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@python3 tools/automation-closure.py --workspace "$(_WS_RESOLVED)" --mode known-limitations-burndown $(if $(JSON),--json) $(if $(STRICT),--strict)

automation-closure-test:
	@python3 -m unittest tools.tests.test_automation_closure

pr560-closure-inventory-test: automation-closure-test

# PR #546 Wave-10 Lane F - A8 RPC-crash probe. Walks Rust RPC crates under
# declared project_source_roots (fallback: external/base RPC crates) and emits unbounded-input /
# OOM-path / panic-on-input / blocking-IO candidates with default-to-kill
# semantics. Also installs the five synthetic-request fixtures + the
# expected-outcomes doc under <ws>/critical_hunt/rpc_crash/.
base-rpc-crash-probe:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make base-rpc-crash-probe WS=<workspace> [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make base-rpc-crash-probe" "$(_WS_RESOLVED)"
	@python3 tools/base-rpc-crash-probe.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(STRICT),--strict)

base-rpc-crash-probe-test:
	@python3 -m unittest tools.tests.test_base_rpc_crash_probe

# PR #546 Wave 10 Lane B - OP1 ("Unauthorized verifier / dispute-game
# implementation upgrade") harness. Default-to-kill: rows stay at
# kill_or_reframe until operator confirms listed Critical impact mapping.
verifier-upgrade-surface:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make verifier-upgrade-surface WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make verifier-upgrade-surface" "$(_WS_RESOLVED)"
	@python3 tools/verifier-upgrade-surface.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

verifier-upgrade-surface-test:
	@python3 -m unittest tools.tests.test_verifier_upgrade_surface

# Live verifier-config check spec emitter. Reads deployment_topology.json /
# addresses.json, emits an EIP-1967 storage + owner() probe spec per target,
# and appends to live_topology_checks.json. Cross-RPC required per POLY-14.
live-verifier-config-check:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make live-verifier-config-check WS=<workspace> [BLOCK=<hex>] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make live-verifier-config-check" "$(_WS_RESOLVED)"
	@python3 tools/live-verifier-config-check.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(BLOCK),--pinned-block $(BLOCK)) \
	  $(if $(STRICT),--strict)

live-verifier-config-check-test:
	@python3 -m unittest tools.tests.test_live_verifier_config_check

verifier-upgrade-kit-forge-test:
	@bash tools/tests/test_verifier_upgrade_invariant_kit_forge.sh

# PR #546 Wave 10 Lane G - A11 (EVM/precompile differential surface).
# Wave 9 lane-G triage flagged A11 as zero-coverage. This target enumerates
# Base-specific precompiles, gas tables, hardfork activations, and EVM
# config overrides versus the upstream revm/reth pin recorded in the
# workspace's Cargo.toml(s). It writes the matrix + a candidate seed file
# that `make base-critical-matrix` then picks up automatically.
#
# W4.11 upgrade: a11-precompile-diff is no longer staging-only. After the
# config scan + input staging, when the operator points UPSTREAM=<revm-tree>
# and FORK=<base-azul-tree> at two real Rust source trees, the target now
# invokes the real precompile differential engine
# (tools/audit/precompile-differential-engine.py). The engine mines a
# precompile registry from each tree, classifies every divergence
# (added/removed/security-relevant/behavior-changing), and cross-checks the
# staged bs_*/pc_* differential test inputs against the discovered diff,
# emitting a real divergence report at
# <ws>/critical_hunt/precompile_diff/a11_differential_report.json.
# When UPSTREAM/FORK are not supplied the target degrades gracefully to the
# legacy scan + staging behaviour (back-compat).
a11-precompile-diff:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make a11-precompile-diff WS=<workspace> [UPSTREAM=<revm-tree> FORK=<base-azul-tree>] [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make a11-precompile-diff" "$(_WS_RESOLVED)"
	@python3 tools/base-evm-config-coverage.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)
	@mkdir -p "$(_WS_RESOLVED)/critical_hunt/precompile_diff/differential_test_inputs"
	@cp -n tools/baselines/a11_precompile_diff/differential_test_inputs/*.json \
	      tools/baselines/a11_precompile_diff/differential_test_inputs/README.md \
	      "$(_WS_RESOLVED)/critical_hunt/precompile_diff/differential_test_inputs/" 2>/dev/null || true
	@echo "[make a11-precompile-diff] differential test inputs available under $(_WS_RESOLVED)/critical_hunt/precompile_diff/differential_test_inputs/"
	@if [ -n "$(UPSTREAM)" ] && [ -n "$(FORK)" ]; then \
	  echo "[make a11-precompile-diff] running real differential engine: UPSTREAM=$(UPSTREAM) FORK=$(FORK)"; \
	  python3 tools/audit/precompile-differential-engine.py \
	    --upstream "$(UPSTREAM)" --fork "$(FORK)" \
	    --inputs "$(_WS_RESOLVED)/critical_hunt/precompile_diff/differential_test_inputs" \
	    --out "$(_WS_RESOLVED)/critical_hunt/precompile_diff/a11_differential_report.json" \
	    $(if $(AUDIT_PIN),--audit-pin "$(AUDIT_PIN)") \
	    $(if $(STRICT),--strict); \
	  echo "[make a11-precompile-diff] differential report written to $(_WS_RESOLVED)/critical_hunt/precompile_diff/a11_differential_report.json"; \
	else \
	  echo "[make a11-precompile-diff] UPSTREAM/FORK not supplied; staged inputs only. Pass UPSTREAM=<revm-tree> FORK=<base-azul-tree> to run the real differential exec."; \
	fi

a11-precompile-diff-test:
	@python3 -m unittest tools.tests.test_base_evm_config_coverage tools.tests.test_precompile_differential_engine

# PR #546 Wave 10 / Lane H - A6 block-delay candidate probe. Scans an audit
# workspace's external Rust tree for validation paths whose CPU/IO cost can
# scale with attacker-controlled input (Vec<u8> decode loops, recursive proof
# verification, unbounded RPC iter, derivation loops, expensive trie walks)
# and emits matrix-compatible candidate rows plus an operator-driven Cargo
# benchmark scaffold. Threshold = 10s wall-clock (= 5x the 2s Base block
# time) per the A6 rubric.
base-block-delay-probe:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make base-block-delay-probe WS=<workspace> [SCAN_ROOT=<path>] [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make base-block-delay-probe" "$(_WS_RESOLVED)"
	@python3 tools/base-block-delay-probe.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(SCAN_ROOT),--scan-root "$(SCAN_ROOT)") \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

base-block-delay-probe-test:
	@python3 -m unittest tools.tests.test_base_block_delay_probe

# PR #556 Wave 6 Worker G - generic Rust decode-bomb scanner. Generalises the
# Wave 5 Worker O snappy `decompress_vec` finding into a corpus-wide attacker-
# controlled-length allocation detector. Default scope: declared Rust
# project_source_roots (fallback: external/base/crates and crates). Patterns: snappy decompress_vec, unbounded zstd/brotli/lz4
# decompress, Vec::with_capacity(<attacker-len>), vec![<v>; <attacker-len>],
# read_uXX -> with_capacity, SSZ/RLP read_length -> alloc.
rust-decode-bomb-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-decode-bomb-scan WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make rust-decode-bomb-scan" "$(_WS_RESOLVED)"
	@python3 tools/rust-decode-bomb-scan.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

rust-decode-bomb-scan-test:
	@python3 -m unittest tools.tests.test_rust_decode_bomb_scan

# Wave H-3B: 5 new patch-coverage detectors (base/base post-rc.28 patches).
# Each scanner + test target closes one detector coverage gap found in H-2B
# fresh-patch-mining.
#
# From<u8> panic on untrusted input (patch 4839aea3):
#   make rust-from-u8-panic-on-untrusted-input-scan WS=<workspace> [STRICT=1]
rust-from-u8-panic-on-untrusted-input-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-from-u8-panic-on-untrusted-input-scan WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make rust-from-u8-panic-on-untrusted-input-scan" "$(_WS_RESOLVED)"
	@python3 tools/rust-from-u8-panic-on-untrusted-input-scan.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

rust-from-u8-panic-on-untrusted-input-scan-test:
	@python3 -m unittest tools.tests.test_rust_from_u8_panic_on_untrusted_input_scan

# Non-exact EIP-2718 decode trailing bytes (patch 6a1333dd):
#   make rust-non-exact-decode-trailing-bytes-scan WS=<workspace> [STRICT=1]
rust-non-exact-decode-trailing-bytes-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-non-exact-decode-trailing-bytes-scan WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make rust-non-exact-decode-trailing-bytes-scan" "$(_WS_RESOLVED)"
	@python3 tools/rust-non-exact-decode-trailing-bytes-scan.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

rust-non-exact-decode-trailing-bytes-scan-test:
	@python3 -m unittest tools.tests.test_rust_non_exact_decode_trailing_bytes_scan

# Discarded verify-bool from KZG/crypto verify function (patch a974aa35):
#   make rust-discarded-verify-bool-scan WS=<workspace> [STRICT=1]
rust-discarded-verify-bool-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-discarded-verify-bool-scan WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make rust-discarded-verify-bool-scan" "$(_WS_RESOLVED)"
	@python3 tools/rust-discarded-verify-bool-scan.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

rust-discarded-verify-bool-scan-test:
	@python3 -m unittest tools.tests.test_rust_discarded_verify_bool_scan

# Existence-only cache gate (patch 6ab29cf0):
#   make rust-existence-only-cache-gate-scan WS=<workspace> [STRICT=1]
rust-existence-only-cache-gate-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-existence-only-cache-gate-scan WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make rust-existence-only-cache-gate-scan" "$(_WS_RESOLVED)"
	@python3 tools/rust-existence-only-cache-gate-scan.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

rust-existence-only-cache-gate-scan-test:
	@python3 -m unittest tools.tests.test_rust_existence_only_cache_gate_scan

# Hardfork precompile address mismatch (patch 56381928):
#   make rust-hardfork-precompile-address-mismatch-scan WS=<workspace> [STRICT=1]
rust-hardfork-precompile-address-mismatch-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-hardfork-precompile-address-mismatch-scan WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make rust-hardfork-precompile-address-mismatch-scan" "$(_WS_RESOLVED)"
	@python3 tools/rust-hardfork-precompile-address-mismatch-scan.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

rust-hardfork-precompile-address-mismatch-scan-test:
	@python3 -m unittest tools.tests.test_rust_hardfork_precompile_address_mismatch_scan

# Wave H-3F: Host-controlled length cast → unbounded Vec alloc (swival-rust-stdlib-192, -196).
# Catches preimage-oracle / hint-channel read_exact + from_be_bytes(u64/u32) →
# vec![0; length] without an upper-bound cap.
# Promoted candidates: oracle.rs:33-55 and hint.rs:78-95 (Wave 6 Worker F).
#   make rust-host-length-cast-unbounded-alloc-scan WS=<workspace> [STRICT=1]
rust-host-length-cast-unbounded-alloc-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-host-length-cast-unbounded-alloc-scan WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make rust-host-length-cast-unbounded-alloc-scan" "$(_WS_RESOLVED)"
	@python3 tools/rust-host-length-cast-unbounded-alloc-scan.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

rust-host-length-cast-unbounded-alloc-scan-test:
	@python3 -m unittest tools.tests.test_rust_host_length_cast_unbounded_alloc_scan

# Wave H-3F: Numeric overflow/underflow scanner (swival-rust-stdlib-132, -181).
# Catches usize len()-1 underflow without empty guard, u8/u16 field + N overflow,
# and checked_add().unwrap() panic paths.
# Promoted candidate: frame_queue.rs:68 (usize underflow) and :75 (u16 overflow).
#   make rust-numeric-overflow-underflow-scan WS=<workspace> [STRICT=1]
rust-numeric-overflow-underflow-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-numeric-overflow-underflow-scan WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make rust-numeric-overflow-underflow-scan" "$(_WS_RESOLVED)"
	@python3 tools/rust-numeric-overflow-underflow-scan.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --profile-wrap-silent \
	  --emit-hypotheses "$(_WS_RESOLVED)/.auditooor/rust_numeric_overflow_obligations.jsonl" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

rust-numeric-overflow-underflow-scan-test:
	@python3 -m unittest tools.tests.test_rust_numeric_overflow_underflow_scan

# Wave I-1D / G-v01 - Option<Vec<T>>::iter().all/.any misclassifier scanner.
# Detects: .iter().all/any where closure indexes only the first Vec element
# instead of iterating over individual elements (audit-snapshot: attributes.rs:65-70).
#
#   make rust-option-iter-misclassifier-scan WS=~/audits/base-azul
#   make rust-option-iter-misclassifier-scan WS=~/audits/base-azul STRICT=1
rust-option-iter-misclassifier-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-option-iter-misclassifier-scan WS=<workspace> [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "rust-option-iter-misclassifier-scan" "$(_WS_RESOLVED)"
	@python3 tools/rust-option-iter-misclassifier-scan.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict)

rust-option-iter-misclassifier-scan-test:
	@python3 -m unittest tools.tests.test_rust_option_iter_misclassifier_scan

# Swival rust-stdlib mining slice - Base-native Rust shape scanner.
# Candidate-only: emits harness tasks for integer truncation, length-prefix
# allocation, and unguarded decode/version paths.
base-rust-swival-shape-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make base-rust-swival-shape-scan WS=<workspace> [JSON=1] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make base-rust-swival-shape-scan" "$(_WS_RESOLVED)"
	@python3 tools/base-rust-swival-shape-scan.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json) \
	  $(if $(STRICT),--strict)

base-rust-swival-shape-scan-test:
	@python3 -m unittest tools.tests.test_base_rust_swival_shape_scan

source-proof-record:
	@if [ -z "$(WS)" ] || [ -z "$(CANDIDATE)" ]; then \
	  echo 'Usage: make source-proof-record WS=<workspace> CANDIDATE=<id> [CITATION=<path:line[-line]> OOS=<in_scope|oos|unknown|not_checked> VERDICT=<proved_source_only|killed|blocked_missing_impact_contract> NOTE=<text>]'; exit 2; fi
	@python3 tools/source-proof-record.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --candidate "$(CANDIDATE)" \
	  $(if $(CITATION),--citation "$(CITATION)") \
	  --oos-status "$(if $(OOS),$(OOS),not_checked)" \
	  --verdict "$(if $(VERDICT),$(VERDICT),blocked_missing_impact_contract)" \
	  $(if $(NOTE),--notes "$(NOTE)") \
	  $(if $(JSON),--print-json)

source-proof-record-test:
	@python3 -m unittest tools.tests.test_source_proof_record

poc-execution-record:
	@if [ -z "$(WS)" ] || [ -z "$(BRIEF)" ]; then \
	  echo 'Usage: make poc-execution-record WS=<workspace> BRIEF=<brief.md> [CANDIDATE_ID=<id>] [MODEL=<model>] [CMD=<cmd>] [RESULT=<result>] [IMPACT=<impact>] [BRIDGE_ROW=<id>] [PROOF_TASK_ID=<id>] [DETECTOR=<slug>] [DETECTOR_OBLIGATION=<id>] [DETECTOR_ACTION_GRAPH=<path>]'; exit 2; fi
	@python3 tools/poc-execution-record.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --brief "$(BRIEF)" \
	  $(if $(CANDIDATE_ID),--candidate-id "$(CANDIDATE_ID)") \
	  $(if $(MODEL),--assigned-model "$(MODEL)") \
	  $(if $(PROOF_TASK_ID),--proof-task-id "$(PROOF_TASK_ID)") \
	  $(if $(BRIDGE_ROW),--bridge-row-id "$(BRIDGE_ROW)") \
	  $(if $(DETECTOR),--detector-slug "$(DETECTOR)") \
	  $(if $(DETECTOR_OBLIGATION),--detector-obligation "$(DETECTOR_OBLIGATION)") \
	  $(if $(DETECTOR_ACTION_GRAPH),--detector-action-graph "$(DETECTOR_ACTION_GRAPH)") \
	  $(if $(CMD),--run "$(CMD)") \
	  --final-result "$(if $(RESULT),$(RESULT),needs_human)" \
	  --impact-assertion "$(if $(IMPACT),$(IMPACT),unknown)" \
	  $(if $(JSON),--print-json)

poc-execution-record-test:
	@python3 -m unittest tools.tests.test_poc_execution_record tools.tests.test_audit_closeout_check

# poc-revert-selector-check: flag a Foundry PoC vm.expectRevert(X.selector) whose
# custom error X is declared in MORE THAN ONE contract/file (esp. in-scope + a
# test/mock/OOS mock). A selector-only expectRevert cannot disambiguate which
# contract reverted, so the PoC may assert the WRONG contract's guard and
# mis-measure severity (operator-caught: strata MIN_SHARES, MinSharesViolation
# declared in in-scope IErrors.sol + 2 OOS mocks). Exit 1 on any ambiguity.
#   make poc-revert-selector-check POC=<poc.t.sol> [SRC_ROOT=<dir>] [JSON=1]
#   make poc-revert-selector-check SRC_ROOT=<project-dir>        (scan all *.t.sol)
poc-revert-selector-check:
	@if [ -z "$(POC)" ] && [ -z "$(SRC_ROOT)" ]; then \
	  echo 'Usage: make poc-revert-selector-check POC=<poc.t.sol> [SRC_ROOT=<dir>] [JSON=1]'; exit 2; fi
	@python3 tools/poc-revert-selector-soundness-check.py \
	  $(if $(POC),"$(POC)") \
	  $(if $(SRC_ROOT),--src-root "$(SRC_ROOT)") \
	  $(if $(JSON),--json)

poc-revert-selector-check-test:
	@python3 -m unittest tools.tests.test_poc_revert_selector_soundness_check

deep-counterexample-record:
	@if [ -z "$(WS)" ] || [ -z "$(ENGINE)" ] || [ -z "$(TARGET)" ] || [ -z "$(INVARIANT)" ] || [ -z "$(VIOLATION)" ]; then \
	  echo 'Usage: make deep-counterexample-record WS=<workspace> ENGINE=<engine> TARGET=<function> INVARIANT=<text> VIOLATION=<text> [REPLAY=<cmd> FORGE_TEST=<path> | IMPOSSIBLE=<reason>]'; exit 2; fi
	@python3 tools/deep-counterexample-record.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --engine "$(ENGINE)" \
	  --target-function "$(TARGET)" \
	  --expected-invariant "$(INVARIANT)" \
	  --observed-violation "$(VIOLATION)" \
	  $(if $(SETUP),--setup "$(SETUP)") \
	  $(if $(INPUT_SEQUENCE),--input-sequence "$(INPUT_SEQUENCE)") \
	  $(if $(REPLAY),--replay-command "$(REPLAY)") \
	  $(if $(FORGE_TEST),--generated-forge-test-path "$(FORGE_TEST)") \
	  $(if $(IMPOSSIBLE),--replay-impossible-reason "$(IMPOSSIBLE)") \
	  $(if $(JSON),--print-json)

deep-counterexample-record-test:
	@python3 -m unittest tools.tests.test_deep_counterexample_record

deep-counterexample-collect:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make deep-counterexample-collect WS=<workspace> [FORGE_TEST=<path>] [JSON=1]'; exit 2; fi
	@python3 tools/deep-counterexample-collect.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(FORGE_TEST),--generated-forge-test-path "$(FORGE_TEST)") \
	  $(if $(JSON),--print-json)

deep-counterexample-collect-test:
	@python3 -m unittest tools.tests.test_deep_counterexample_collect

deep-counterexample-replay-scaffold:
	@if [ -z "$(RECORD)" ]; then \
	  echo 'Usage: make deep-counterexample-replay-scaffold RECORD=<deep_counterexample.v1.json> [WS=<workspace>] [OUT=<path>]'; exit 2; fi
	@python3 tools/deep-counterexample-replay-scaffold.py "$(RECORD)" \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(OUT),--out "$(OUT)") \
	  --print-path

deep-counterexample-replay-scaffold-test:
	@python3 -m unittest tools.tests.test_deep_counterexample_replay_scaffold

deep-counterexample-queue:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make deep-counterexample-queue WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/deep-counterexample-queue.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json)

deep-counterexample-queue-test:
	@python3 -m unittest tools.tests.test_deep_counterexample_queue

chimera-scaffold:
	@if [ -z "$(WS)" ] || [ -z "$(ROW)" ]; then \
	  echo 'Usage: make chimera-scaffold WS=<workspace> ROW=<ledger-row> [OUT=<dir>] [REQUIRE_SOURCE_BINDING=1] [REQUIRE_CONCRETE_BINDING=1] [STRICT_HANDLERS=1] [DRY_RUN=1] [JSON=1]'; exit 2; fi
	@python3 tools/chimera-scaffold.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --row-id "$(ROW)" \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(REQUIRE_SOURCE_BINDING),--require-source-binding) \
	  $(if $(REQUIRE_CONCRETE_BINDING),--require-concrete-binding) \
	  $(if $(STRICT_HANDLERS),--strict-handlers) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--print-json)

chimera-scaffold-test:
	@python3 -m unittest tools.tests.test_chimera_scaffold tools.tests.test_chimera_ledger_scaffold

chimera-ledger-scaffold:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make chimera-ledger-scaffold WS=<workspace> [OUT=<dir>] [MANIFEST=<path>] [DRY_RUN=1] [REQUIRE_CONCRETE_BINDING=1] [STRICT_HANDLERS=1] [MAX_ROWS=<n>] [JSON=1]'; exit 2; fi
	@python3 tools/chimera-ledger-scaffold.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(MANIFEST),--manifest "$(MANIFEST)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(REQUIRE_CONCRETE_BINDING),--require-concrete-binding) \
	  $(if $(STRICT_HANDLERS),--strict-handlers) \
	  $(if $(MAX_ROWS),--max-rows "$(MAX_ROWS)") \
	  $(if $(JSON),--print-json)

recon-log-bridge:
	@if [ -z "$(WS)" ] || [ -z "$(ENGINE)" ] || [ -z "$(LOG)" ]; then \
	  echo 'Usage: make recon-log-bridge WS=<workspace> ENGINE=<medusa|echidna|halmos> LOG=<path> [ROW=<ledger-row>] [OUT=<dir>] [FORGE_TEST=<path>] [JSON=1]'; exit 2; fi
	@python3 tools/recon-log-bridge.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --engine "$(ENGINE)" \
	  --log "$(LOG)" \
	  $(if $(ROW),--row-id "$(ROW)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(FORGE_TEST),--forge-test-out "$(FORGE_TEST)") \
	  $(if $(JSON),--print-json)

recon-log-bridge-test:
	@python3 -m unittest tools.tests.test_recon_log_bridge

# LANE W4.5 - parse deep-engine runner artifacts (halmos/medusa/echidna)
# into a structured auditooor.deep_engine_findings.v1 summary so failing
# properties / counterexamples are consumable downstream instead of being
# dumped to a log. Wired into `make audit-deep-solidity` after the runners.
deep-engine-output-parse:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make deep-engine-output-parse WS=<workspace>'; exit 2; fi
	@python3 tools/deep-engine-output-parse.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json)

deep-engine-output-parse-test:
	@python3 -m unittest tools.tests.test_deep_engine_output_parse

# V5 Gap-46 / Codex P0 #3 - coverage-introspect deep profile.
# OPT-IN ONLY - Codex's PR #253 final-pass: gate on 3-5 real-workspace runs
# proving signal before promoting to `DEEP_PROFILE=all`. Unlike `audit-deep`
# this target does NOT chain `make audit` first; it is a standalone surface
# enumerator + library cross-check + bounded LLM gap-surfacing pass.
# See docs/V5_CAPABILITY_GAPS_2026-04-26.md Gap 46.
coverage-introspect:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make coverage-introspect WS=<workspace>'; exit 2; \
	fi
	@DEEP_PROFILE=coverage-gaps bash tools/audit-deep.sh "$(_WS_RESOLVED)"

# Hermetic unittest for tools/coverage-introspect.py (stdlib-only, no
# network). Mirrors the audit-deep-test shape.
coverage-introspect-test:
	@python3 -m unittest tools.tests.test_coverage_introspect

# Issue #311 - turn fixture-less P1 pattern/source inventory into explicit
# extractor commands. This target never runs an LLM and never fabricates a
# missing workspace; it only emits queue rows for local/archive-backed source
# groups discovered by tools/p1-source-archive-map.py.
p1-extraction-queue:
	@mkdir -p "$(if $(OUT),$(OUT),.audit_logs/p1_fixture_extraction)"
	@python3 tools/p1-source-archive-map.py \
	  --top "$(if $(TOP),$(TOP),60)" \
	  --max-depth "$(if $(MAX_DEPTH),$(MAX_DEPTH),6)" \
	  $(if $(SEARCH_ROOTS),$(foreach root,$(SEARCH_ROOTS),--search-root "$(root)")) \
	  --queue-max-patterns-per-group "$(if $(QUEUE_MAX),$(QUEUE_MAX),1)" \
	  --out-json "$(if $(OUT),$(OUT),.audit_logs/p1_fixture_extraction)/archive_map.json" \
	  --out-md "$(if $(OUT),$(OUT),.audit_logs/p1_fixture_extraction)/archive_map.md" \
	  --out-queue-json "$(if $(OUT),$(OUT),.audit_logs/p1_fixture_extraction)/extraction_queue.json" \
	  --out-queue-md "$(if $(OUT),$(OUT),.audit_logs/p1_fixture_extraction)/extraction_queue.md"

p1-extraction-queue-test:
	@python3 -m unittest tools.tests.test_p1_source_archive_map

p1-extraction-run:
	@python3 tools/p1-extraction-queue-runner.py \
	  --queue "$(if $(QUEUE),$(QUEUE),.audit_logs/p1_fixture_extraction/extraction_queue.json)" \
	  --out "$(if $(OUT),$(OUT),.audit_logs/p1_fixture_extraction/execution_manifest.json)" \
	  --out-md "$(if $(OUT_MD),$(OUT_MD),.audit_logs/p1_fixture_extraction/execution_report.md)" \
	  $(if $(PATTERN),--pattern "$(PATTERN)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(ACCEPT),--accept) \
	  $(if $(FAIL_FAST),--fail-fast) \
	  $(if $(MOCK_DISPATCHER),--mock-dispatcher "$(MOCK_DISPATCHER)") \
	  $(if $(RUNNER),--runner "$(RUNNER)") \
	  $(if $(DSL_DIR),--dsl-dir "$(DSL_DIR)") \
	  $(if $(FIXTURE_DIR),--fixture-dir "$(FIXTURE_DIR)") \
	  $(if $(RUN_TESTS),--run-tests "$(RUN_TESTS)") \
	  $(if $(SKIP_SOLC),--skip-solc) \
	  $(if $(NO_MINIMAX_REVIEW),--no-minimax-review) \
	  $(if $(JSON),--print-json)

p1-extraction-run-test:
	@python3 -m unittest tools.tests.test_p1_extraction_queue_runner

# ZK corpus farming - import a local zksecurity/zkbugs checkout into ranked
# bug records and model-ready briefs. This target never clones or scrapes by
# itself, so review artifacts are reproducible from the operator's corpus copy.
zkbugs-ingest:
	@if [ -z "$(ZKBUGS_ROOT)" ]; then \
	  echo 'Usage: make zkbugs-ingest ZKBUGS_ROOT=/path/to/zksecurity/zkbugs [OUT=.audit_logs/zkbugs_farming]'; exit 2; \
	fi
	@python3 tools/zkbugs-ingest.py \
	  --zkbugs-root "$(ZKBUGS_ROOT)" \
	  --out-dir "$(if $(OUT),$(OUT),.audit_logs/zkbugs_farming)" \
	  --brief-limit "$(if $(BRIEF_LIMIT),$(BRIEF_LIMIT),40)" \
	  --index-limit "$(if $(INDEX_LIMIT),$(INDEX_LIMIT),80)" \
	  $(if $(JSON),--print-json)

zkbugs-ingest-test:
	@python3 -m unittest tools.tests.test_zkbugs_ingest

# Ingest 0xPARC/zk-bug-tracker (CC-BY-SA 4.0) as a second source alongside zksecurity/zkbugs.
# Usage:
#   make zkbugs-ingest-0xparc                              # fetch from upstream GitHub
#   make zkbugs-ingest-0xparc REPO_PATH=/path/to/clone    # read from local clone
#   make zkbugs-ingest-0xparc MERGE=1                      # merge with zksecurity index too
zkbugs-ingest-0xparc:
	@python3 tools/zkbugs-0xparc-ingest.py \
	  $(if $(REPO_PATH),--repo-path "$(REPO_PATH)") \
	  --out "$(if $(OUT),$(OUT),audit/zkbugs/0xparc_index.json)" \
	  $(if $(MERGE),--merge-with "$(if $(MERGE_WITH),$(MERGE_WITH),audit/zkbugs/zkbugs_index.json)") \
	  $(if $(JSON),--print-summary)

zkbugs-ingest-0xparc-test:
	@python3 -m unittest tools.tests.test_zkbugs_0xparc_ingest

# Ingest both sources and produce a unified index.
# Requires zkbugs-ingest to have run first (produces audit/zkbugs/zkbugs_index.json).
zkbugs-ingest-all: zkbugs-ingest-0xparc
	@python3 tools/zkbugs-ingest.py \
	  --zkbugs-root "$(if $(ZKBUGS_ROOT),$(ZKBUGS_ROOT),/Users/wolf/audits/base-azul/external/zkbugs)" \
	  --out-dir "$(if $(OUT),$(OUT),.audit_logs/zkbugs_farming)" \
	  --brief-limit "$(if $(BRIEF_LIMIT),$(BRIEF_LIMIT),40)" \
	  --index-limit "$(if $(INDEX_LIMIT),$(INDEX_LIMIT),80)" \
	  $(if $(JSON),--print-json)
	@python3 tools/zkbugs-0xparc-ingest.py \
	  $(if $(REPO_PATH),--repo-path "$(REPO_PATH)") \
	  --merge-with "$(if $(OUT),$(OUT),.audit_logs/zkbugs_farming)/zkbugs_index.json" \
	  --out "audit/zkbugs/zkbugs_index_unified.json" \
	  $(if $(JSON),--print-summary)

# Build provider prompts from zkBugs briefs. Use after `make zkbugs-ingest`.
zkbugs-brief-queue:
	@python3 tools/zkbugs-brief-queue.py \
	  --brief-dir "$(if $(BRIEF_DIR),$(BRIEF_DIR),.audit_logs/zkbugs_farming/briefs)" \
	  --out-dir "$(if $(OUT),$(OUT),.audit_logs/zkbugs_farming/provider_queue)" \
	  --limit "$(if $(LIMIT),$(LIMIT),20)" \
	  $(if $(JSON),--print-json)

zkbugs-brief-queue-test:
	@python3 -m unittest tools.tests.test_zkbugs_brief_queue

# Route normalized zkBugs repo-content rows into detector/invariant/replay work.
zkbugs-task-map:
	@python3 tools/zkbugs-task-map.py \
	  --index "$(if $(INDEX),$(INDEX),.audit_logs/zkbugs_farming/zkbugs_index.json)" \
	  --provider-queue "$(if $(QUEUE),$(QUEUE),.audit_logs/zkbugs_farming/provider_queue/zkbugs_provider_queue.json)" \
	  --out-json "$(if $(OUT_JSON),$(OUT_JSON),.audit_logs/zkbugs_farming/zkbugs_task_map.json)" \
	  --out-md "$(if $(OUT_MD),$(OUT_MD),.audit_logs/zkbugs_farming/zkbugs_task_map.md)" \
	  --queue-dir "$(if $(QUEUE_DIR),$(QUEUE_DIR),.audit_logs/zkbugs_farming/task_queues)" \
	  $(if $(JSON),--print-json)

zkbugs-task-map-test:
	@python3 -m unittest tools.tests.test_zkbugs_task_map

# Persist provider outputs from a zkBugs Kimi/Minimax pass.
zkbugs-provider-result:
	@if [ -z "$(BRIEF)" ] || [ -z "$(KIMI)" ] || [ -z "$(MINIMAX)" ] || [ -z "$(OUT)" ]; then \
	  echo 'Usage: make zkbugs-provider-result BRIEF=<brief.md> KIMI=<kimi.out> MINIMAX=<minimax.out> OUT=<result.json> [OUT_MD=<result.md>]'; exit 2; \
	fi
	@python3 tools/zkbugs-provider-result.py \
	  --brief "$(BRIEF)" \
	  --kimi-output "$(KIMI)" \
	  --minimax-output "$(MINIMAX)" \
	  --out "$(OUT)" \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(JSON),--print-json)

zkbugs-provider-result-test:
	@python3 -m unittest tools.tests.test_zkbugs_provider_result

# Run live provider farming from a zkBugs provider queue. Requires
# AUDITOOOR_LLM_NETWORK_CONSENT=1 and configured provider keys.
zkbugs-provider-loop:
	@python3 tools/zkbugs-provider-loop.py \
	  --queue "$(if $(QUEUE),$(QUEUE),.audit_logs/zkbugs_farming/provider_queue/zkbugs_provider_queue.json)" \
	  --out-dir "$(if $(OUT),$(OUT),.audit_logs/zkbugs_farming/provider_results)" \
	  --limit "$(if $(LIMIT),$(LIMIT),0)" \
	  --start-index "$(if $(START_INDEX),$(START_INDEX),1)" \
	  --print-json

zkbugs-provider-loop-test:
	@python3 -m unittest tools.tests.test_zkbugs_provider_loop

# Wave 3 pipeline wiring - single-shot full zkBugs pipeline.
#
# Runs ingest -> brief-queue -> provider-loop (--limit 1, single pass) ->
# the provider-result step is implicit because provider-loop calls
# zkbugs-provider-result.py per row.
#
# Safety:
#   - DRY_RUN=1 prints the planned commands and exits 0 without invoking any
#     provider. This is the DEFAULT mode: invoking `make zkbugs-pull` with no
#     LIVE=1 flag refuses to call LLM providers.
#   - LIVE=1 is REQUIRED to actually dispatch to Kimi/Minimax. The recipe
#     also forwards AUDITOOOR_LLM_NETWORK_CONSENT=1 which the provider-loop
#     itself enforces as a second safety belt.
#
# After a LIVE run, the recipe writes a UTC timestamp to
# `<repo>/.auditooor/zkbugs_last_pull` so audit-deep.sh Step 9 can recommend
# refreshing the corpus when it goes stale (>14 days).
zkbugs-pull:
	@if [ -z "$(ZKBUGS_ROOT)" ]; then \
	  echo 'Usage: make zkbugs-pull ZKBUGS_ROOT=/path/to/zksecurity/zkbugs [LIVE=1] [DRY_RUN=1] [LIMIT=1]'; exit 2; \
	fi
	@_dry="$(if $(DRY_RUN),1,0)"; \
	_live="$(if $(LIVE),1,0)"; \
	_out_dir="$(if $(OUT),$(OUT),.audit_logs/zkbugs_farming)"; \
	_queue="$$_out_dir/provider_queue/zkbugs_provider_queue.json"; \
	_results="$$_out_dir/provider_results"; \
	_limit="$(if $(LIMIT),$(LIMIT),1)"; \
	_ingest="python3 tools/zkbugs-ingest.py --zkbugs-root $(ZKBUGS_ROOT) --out-dir $$_out_dir --brief-limit 40 --index-limit 80"; \
	_queue_cmd="python3 tools/zkbugs-brief-queue.py --brief-dir $$_out_dir/briefs --out-dir $$_out_dir/provider_queue --limit $$_limit"; \
	_loop_args="--queue $$_queue --out-dir $$_results --limit $$_limit"; \
	if [ "$$_live" != "1" ]; then \
	  _loop_args="$$_loop_args --dry-run"; \
	fi; \
	_loop="python3 tools/zkbugs-provider-loop.py $$_loop_args"; \
	if [ "$$_dry" = "1" ] || [ "$$_live" != "1" ]; then \
	  echo "[zkbugs-pull] DRY-RUN - no provider calls will be made."; \
	  echo "[zkbugs-pull] step 1/3: $$_ingest"; \
	  echo "[zkbugs-pull] step 2/3: $$_queue_cmd"; \
	  echo "[zkbugs-pull] step 3/3: $$_loop"; \
	  if [ "$$_live" != "1" ]; then \
	    echo "[zkbugs-pull] refusing to call providers without LIVE=1 (set LIVE=1 to dispatch)"; \
	  fi; \
	  exit 0; \
	fi; \
	echo "[zkbugs-pull] LIVE - provider calls will be dispatched."; \
	$$_ingest && \
	$$_queue_cmd && \
	AUDITOOOR_LLM_NETWORK_CONSENT=1 $$_loop && \
	mkdir -p .auditooor && \
	date -u +"%Y-%m-%dT%H:%M:%SZ" > .auditooor/zkbugs_last_pull && \
	echo "[zkbugs-pull] OK - last-pull timestamp: $$(cat .auditooor/zkbugs_last_pull)"

# Wave 3 pipeline wiring - corpus / queue / freshness report.
#
# Always exits 0 even when the corpus has never been pulled (zero records,
# zero queue rows, no timestamp). Intended to be cheap enough to call from
# CI / dashboards.
zkbugs-status:
	@_out_dir="$(if $(OUT),$(OUT),.audit_logs/zkbugs_farming)"; \
	_index="$$_out_dir/zkbugs_index.json"; \
	_queue="$$_out_dir/provider_queue/zkbugs_provider_queue.json"; \
	_ts=".auditooor/zkbugs_last_pull"; \
	echo "## zkBugs Pipeline Status"; \
	if [ -f "$$_index" ]; then \
	  _total=$$(python3 -c "import json,sys; print(json.load(open('$$_index'))['summary']['total'])" 2>/dev/null || echo "?"); \
	  echo "- corpus index: $$_index ($$_total bug records)"; \
	else \
	  echo "- corpus index: MISSING ($$_index) - run \`make zkbugs-pull ZKBUGS_ROOT=...\` to populate"; \
	fi; \
	if [ -f "$$_queue" ]; then \
	  _depth=$$(python3 -c "import json,sys; print(json.load(open('$$_queue'))['count'])" 2>/dev/null || echo "?"); \
	  echo "- provider queue: $$_queue (depth=$$_depth)"; \
	else \
	  echo "- provider queue: MISSING ($$_queue)"; \
	fi; \
	if [ -f "$$_ts" ]; then \
	  echo "- last-pull timestamp: $$(cat $$_ts)"; \
	else \
	  echo "- last-pull timestamp: NEVER (file $$_ts absent)"; \
	fi; \
	exit 0

# Wave 3 pipeline wiring - hermetic regression suite for the new pull/status
# targets and audit-deep.sh Step 9 freshness check. No live provider calls.
zkbugs-pipeline-wiring-test:
	@bash tools/tests/test_zkbugs_pipeline_wiring.sh

# Wave-6 K-zkBugs: coverage table - corpus size vs detectors shipped per ZK framework.
# Run after zkbugs-ingest-all to get accurate corpus counts.
zkbugs-coverage-by-framework:
	@python3 tools/zkbugs-coverage-by-framework.py

# ---------------------------------------------------------------------------
# ZK verifier hunt pipeline - wires the 6 orphaned ZK caps into a 5-stage
# durable hunt (mirror of novel-chain-hunt). Targets:
#   zk-engagement-probe-surface : Stage 1 - surface with verifier detection
#   zk-verifier-bugclass-checklist : Stage 2 - 8-item bug-class queue
#   zk-function-mindset-honk : Stage 3 - per-fn drill (extends zk-function-mindset)
#   zk-per-function-preflight : Stage 3b - per-verifier-function preflight packs
#   zk-verify-persist : Stage 4+5 - R76 verify + learn-back
#   zk-chain-synth : Stage 6 - forged-proof-acceptance exploit-chain synthesis
#   zk-hunt : orchestrator (stages 1-6)
#   zkbugs-readiness-check : orphan wire
#   zkbugs-detectorization-map-run : orphan wire
#   zkbugs-prior-audit-class-check : orphan wire
#   zk-etl-verifier : new ETL miner for verifier-side bug classes
# ---------------------------------------------------------------------------

.PHONY: zk-engagement-probe-surface zk-verifier-bugclass-checklist zk-function-mindset-honk zk-verify-persist zk-hunt zkbugs-readiness-check zkbugs-detectorization-map-run zkbugs-prior-audit-class-check zk-etl-verifier zk-verifier-bugclass-checklist-test

# Stage 1: surface probe + emit zk_surface.json with verifier-file classification
zk-engagement-probe-surface: ## STAGE 1: ZK surface probe (circuit + verifier). WS=<workspace>
	@if [ -z "$(WS)" ]; then echo "[zk-engagement-probe-surface] ERROR WS=<workspace> required"; exit 1; fi
	@ws=$$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$(WS)"); \
	if [ ! -d "$$ws" ]; then echo "[zk-engagement-probe-surface] ERROR workspace not found: $$ws"; exit 1; fi; \
	python3 tools/zk-engagement-probe.py "$$ws" --emit-surface; \
	echo "[zk-engagement-probe-surface] surface written -> $$ws/.auditooor/zk_surface.json"

# Stage 2: per-function bug-class checklist -> zk_hunt_queue.jsonl
zk-verifier-bugclass-checklist: ## STAGE 2: ZK verifier bug-class checklist. WS=<workspace>
	@if [ -z "$(WS)" ]; then echo "[zk-verifier-bugclass-checklist] ERROR WS=<workspace> required"; exit 1; fi
	@ws=$$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$(WS)"); \
	if [ ! -d "$$ws" ]; then echo "[zk-verifier-bugclass-checklist] ERROR workspace not found: $$ws"; exit 1; fi; \
	python3 tools/zk-verifier-bugclass-checklist.py --workspace "$$ws" $(if $(DRY_RUN),--dry-run) $(if $(JSON),--json)

zk-verifier-bugclass-checklist-test: ## Test Stage 2
	@python3 -m unittest tools.tests.test_zk_verifier_bugclass_checklist -v

# Stage 3: per-fn mindset drill for Solidity-Honk (extends zk-function-mindset)
zk-function-mindset-honk: ## STAGE 3: ZK function mindset drill (solidity-honk). WS=<workspace>
	@if [ -z "$(WS)" ]; then echo "[zk-function-mindset-honk] ERROR WS=<workspace> required"; exit 1; fi
	@ws=$$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$(WS)"); \
	queue="$$ws/.auditooor/zk_hunt_queue.jsonl"; \
	if [ ! -f "$$queue" ]; then echo "[zk-function-mindset-honk] WARN queue not found; run zk-verifier-bugclass-checklist first"; exit 0; fi; \
	while IFS= read -r line; do \
	  fn=$$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('fn',''))" "$$line" 2>/dev/null); \
	  fl=$$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('file_line','').rsplit(':',1)[0])" "$$line" 2>/dev/null); \
	  if [ -n "$$fn" ] && [ -f "$$fl" ]; then \
	    python3 tools/zk-function-mindset.py "$$fl" --template "$$fn" --framework solidity-honk --workspace "$$ws" 2>/dev/null || true; \
	  fi; \
	done < "$$queue"; \
	echo "[zk-function-mindset-honk] DONE - briefs under $$ws/.auditooor/zk_function_mindset_solidity_*"

# Stage 4+5: R76 verify + learn-back
zk-verify-persist: ## STAGE 4+5: ZK verify + learn-back. WS=<workspace> [PERSIST=1]
	@if [ -z "$(WS)" ]; then echo "[zk-verify-persist] ERROR WS=<workspace> required"; exit 1; fi
	@ws=$$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$(WS)"); \
	if [ ! -d "$$ws" ]; then echo "[zk-verify-persist] ERROR workspace not found: $$ws"; exit 1; fi; \
	python3 tools/zk-verify-persist.py --workspace "$$ws" $(if $(PERSIST),--persist) $(if $(DRY_RUN),--dry-run) $(if $(JSON),--json)

# Full orchestrator: Stages 1-5
zk-hunt: ## CAPABILITY: durable ZK verifier hunt (stages 1-6). WS=<workspace> [DRY_RUN=1] [SKIP_PREFLIGHT=1] [PERSIST=1] [NO_CHAIN=1] [MOCK_LLM=1]
	@if [ -z "$(WS)" ]; then echo "[zk-hunt] ERROR WS=<workspace> required"; echo "Usage: make zk-hunt WS=/path/to/ws [DRY_RUN=1] [SKIP_PREFLIGHT=1] [PERSIST=1] [NO_CHAIN=1] [MOCK_LLM=1]"; exit 1; fi
	@ws=$$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$(WS)"); \
	if [ ! -d "$$ws" ]; then echo "[zk-hunt] ERROR workspace not found: $$ws"; exit 1; fi; \
	echo "[zk-hunt] === STAGE 1 SURFACE (zk-engagement-probe) ==="; \
	if [ -n "$(SKIP_PREFLIGHT)" ]; then echo "[zk-hunt] skipping surface probe (SKIP_PREFLIGHT=1)"; else $(MAKE) --no-print-directory zk-engagement-probe-surface WS="$$ws" || echo "[zk-hunt] WARN surface probe non-zero; continuing with existing surface"; fi; \
	echo "[zk-hunt] === STAGE 2 CHECKLIST (zk-verifier-bugclass-checklist) ==="; \
	$(MAKE) --no-print-directory zk-verifier-bugclass-checklist WS="$$ws" $(if $(DRY_RUN),DRY_RUN=1) || echo "[zk-hunt] WARN checklist non-zero"; \
	echo "[zk-hunt] === STAGE 3 SYNTH (zk-function-mindset-honk) ==="; \
	$(MAKE) --no-print-directory zk-function-mindset-honk WS="$$ws" || echo "[zk-hunt] WARN mindset non-zero"; \
	echo "[zk-hunt] === STAGE 3b PREFLIGHT (zk-per-function-preflight) ==="; \
	python3 tools/zk-per-function-preflight.py --workspace "$$ws" --framework solidity-honk $(if $(DRY_RUN),--dry-run) || echo "[zk-hunt] WARN preflight non-zero"; \
	echo "[zk-hunt] === STAGE 4+5 VERIFY + PERSIST + LEARN (zk-verify-persist) ==="; \
	$(MAKE) --no-print-directory zk-verify-persist WS="$$ws" $(if $(DRY_RUN),DRY_RUN=1) $(if $(PERSIST),PERSIST=1) || echo "[zk-hunt] WARN verify-persist non-zero"; \
	if [ -z "$(NO_CHAIN)" ]; then \
	  echo "[zk-hunt] === STAGE 6 CHAIN SYNTH (zk-chain-synth) ==="; \
	  python3 tools/zk-chain-synth.py --workspace "$$ws" $(if $(DRY_RUN),--dry-run) $(if $(MOCK_LLM),--mock-llm) || echo "[zk-hunt] WARN chain-synth non-zero"; \
	else echo "[zk-hunt] skipping chain synth (NO_CHAIN=1)"; fi; \
	echo "[zk-hunt] DONE. Confirmed -> $$ws/.auditooor/zk_candidates_*.jsonl + anti-patterns/. Preflight -> $$ws/.auditooor/zk_preflight_packs/. Chains -> $$ws/.auditooor/zk_chains_*. Refuted -> reports/known_dead_ends.jsonl"

# Orphan wires
zkbugs-readiness-check: ## Wire orphaned zkbugs-readiness cap
	@python3 tools/zkbugs-readiness.py $(if $(OUT),--out-dir "$(OUT)")

zkbugs-detectorization-map-run: ## Wire orphaned zkbugs-detectorization-map cap. INGEST=<path>
	@if [ -z "$(INGEST)" ]; then echo "[zkbugs-detectorization-map-run] Usage: make zkbugs-detectorization-map-run INGEST=<zkbugs_index.json>"; exit 1; fi
	@python3 tools/zkbugs-detectorization-map.py --ingest "$(INGEST)" $(if $(OUT),--out "$(OUT)") $(if $(JSON),--json)

zkbugs-prior-audit-class-check: ## Wire orphaned zkbugs-prior-audit-class-verifier cap. FINDING=<path>
	@if [ -z "$(FINDING)" ]; then echo "[zkbugs-prior-audit-class-check] Usage: make zkbugs-prior-audit-class-check FINDING=<finding.md>"; exit 1; fi
	@python3 tools/zkbugs-prior-audit-class-verifier.py --classify "$(FINDING)" $(if $(FW),--framework "$(FW)") $(if $(THRESHOLD),--threshold "$(THRESHOLD)")

# New ETL miner for verifier-side bug classes
zk-etl-verifier: ## ETL miner: Solidity ZK verifier bug classes -> hackerman_record corpus
	@python3 tools/hackerman-etl-from-zk-verifier-reports.py \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

circom-detect:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make circom-detect WS=/path/to/circom/project [ONLY=detector_name] [LOG=/tmp/circom.log]'; exit 2; \
	fi
	@python3 tools/circom-detect.py "$(WS)" \
	  $(if $(ONLY),--only "$(ONLY)") \
	  $(if $(LOG),--log "$(LOG)")

circom-detect-test:
	@python3 -m unittest \
	  tools.tests.test_zkbugs_circom_num2bits_detector \
	  tools.tests.test_zkbugs_blake3novatreepath_checkdepth_comparator_range \
	  tools.tests.test_zkbugs_circom_babyjubjub_suborder_tag \
	  tools.tests.test_darkforest_bit_length_check \
	  tools.tests.test_sha256_template_zero \
	  tools.tests.test_zkbugs_erc20_sum_input_keyed_outflow \
	  tools.tests.test_zkbugs_unirep_comparison_range_checks \
	  tools.tests.test_zkbugs_zswap_nullifier_verification_disabled \
	  detectors.circom_wave1.test_base64decodedlength_unconstrained_output

# W6-7 capability uplift - Solana / SVM detector batch bootstrap.
# detectors/solana_wave1/ holds 10 engine-first detectors for canonical
# Solana bug classes (missing signer/owner/is_writable check, account type
# cosplay, missing rent-exemption, unchecked CPI program id, lamport math
# overflow, non-canonical PDA bump, close-without-zeroing, sysvar spoofing).
# Source language is Rust; tools/solana-detect.py is a thin engine-first
# orchestrator that points the AstEngine("rust", ...) loop at solana_wave1
# (lang-detect.py would resolve --lang rust to the unrelated rust_wave1).
solana-detect:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make solana-detect WS=/path/to/solana/program [ONLY=detector_name] [LOG=/tmp/solana.log]'; exit 2; \
	fi
	@python3 tools/solana-detect.py "$(WS)" \
	  $(if $(ONLY),--only "$(ONLY)") \
	  $(if $(LOG),--log "$(LOG)")

solana-detect-test:
	@bash detectors/solana_wave1/test_fixtures/test_detectors.sh

# Wave 2 capability uplift - first executor for `backend: cosmos` DSL rows.
# PR #460 added the schema slot for non-Solidity backends but ZERO executors
# existed for cosmos/anchor/geth_runtime/circom (rust_wave1 was the lone
# Wave 1 executor). This target ships the cosmos one. The runner self-skips
# when there are no `.go` files, no cosmos-sdk go.mod, or zero DSL rows
# carrying `backend: cosmos`, so it is safe to invoke unconditionally
# inside audit-deep. See docs/COSMOS_BACKEND.md for schema, supported
# predicates, and output schema.
cosmos-detect:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make cosmos-detect WS=/path/to/go/project [ONLY=pattern-id] [OUT=<path>]'; exit 2; \
	fi
	@python3 tools/cosmos-detector-runner.py "$(WS)" \
	  $(if $(ONLY),--only "$(ONLY)") \
	  $(if $(OUT),--out "$(OUT)")

cosmos-detect-test:
	@python3 -m unittest tools.tests.test_cosmos_detector_runner

.PHONY: cosmos-production-harness-plan cosmos-production-harness-plan-test cosmos-production-harness-tasks cosmos-production-harness-tasks-test cosmos-production-harness-exec cosmos-production-harness-exec-test cosmos-production-harness-evidence-pack cosmos-production-harness-evidence-pack-test
cosmos-production-harness-plan:
	@python3 tools/cosmos-production-harness-plan.py \
	  $(if $(POC_DIR),--poc-dir "$(POC_DIR)") \
	  $(if $(CLAIM_FILE),--claim-file "$(CLAIM_FILE)") \
	  $(if $(CLAIM_TEXT),--claim-text "$(CLAIM_TEXT)") \
	  $(if $(NETWORK_CLAIM),--network-claim)

cosmos-production-harness-plan-test:
	@python3 -m unittest tools.tests.test_cosmos_production_harness_plan -v

cosmos-production-harness-tasks:
	@python3 tools/cosmos-production-harness-tasks.py \
	  $(if $(PLAN),--plan "$(PLAN)") \
	  $(if $(POC_DIR),--poc-dir "$(POC_DIR)") \
	  $(if $(CLAIM_FILE),--claim-file "$(CLAIM_FILE)") \
	  $(if $(CLAIM_TEXT),--claim-text "$(CLAIM_TEXT)") \
	  $(if $(NETWORK_CLAIM),--network-claim) \
	  $(if $(FORMAT),--format "$(FORMAT)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(ARTIFACT_DIR),--artifact-dir "$(ARTIFACT_DIR)") \
	  $(if $(CANDIDATE_ID),--candidate-id "$(CANDIDATE_ID)")

cosmos-production-harness-tasks-test:
	@python3 -m unittest tools.tests.test_cosmos_production_harness_tasks -v

cosmos-production-harness-exec:
	@python3 tools/cosmos-production-harness-exec.py \
	  --workspace "$(WS)" \
	  --poc-dir "$(POC_DIR)" \
	  --candidate-id "$(CANDIDATE_ID)" \
	  --command "$(CMD)" \
	  $(if $(CWD),--cwd "$(CWD)") \
	  $(if $(CLAIM_FILE),--claim-file "$(CLAIM_FILE)") \
	  $(if $(CLAIM_TEXT),--claim-text "$(CLAIM_TEXT)") \
	  $(if $(NETWORK_CLAIM),--network-claim) \
	  $(if $(REQUIRE_RUNTIME_MARKERS),--require-runtime-markers) \
	  $(if $(TARGET_APP_CHAIN),--target-app-chain "$(TARGET_APP_CHAIN)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(PRINT_JSON),--print-json)

cosmos-production-harness-exec-test:
	@python3 -m unittest tools.tests.test_cosmos_production_harness_exec -v

cosmos-production-harness-evidence-pack:
	@python3 tools/cosmos-production-harness-evidence-pack.py \
	  --exec-record "$(EXEC_RECORD)" \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(PRINT_JSON),--print-json)

cosmos-production-harness-evidence-pack-test:
	@python3 -m unittest tools.tests.test_cosmos_production_harness_evidence_pack -v

# Advisory-only Go txid/chain-truth scanner (seed detector). This target is
# intentionally non-gating and only runs for Go workspaces.
# Default output artifact follows the workspace audit artifact shape.
go-txid-chain-truth-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make go-txid-chain-truth-scan WS=/path/to/go/project [OUT=<path>]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "go-txid-chain-truth-scan" "$(_WS_RESOLVED)"
	@set -eu; \
	if ! find "$(_WS_RESOLVED)" -type f -name '*.go' -not -path '*/vendor/*' -print -quit | grep -q .; then \
	  echo "[go-txid-chain-truth-scan] SKIP no non-vendor .go files under $(_WS_RESOLVED)"; \
	  exit 0; \
	fi; \
	out_path="$(if $(OUT),$(OUT),$(_WS_RESOLVED)/audit/go-txid-chain-truth-scan.json)"; \
	mkdir -p "$$(dirname "$$out_path")"; \
	python3 tools/go-txid-chain-truth-scan.py "$(_WS_RESOLVED)" > "$$out_path"; \
	echo "[go-txid-chain-truth-scan] wrote $$out_path"

go-txid-chain-truth-scan-test:
	@python3 -m unittest tools.tests.test_go_txid_chain_truth_scan -v

go-refund-tweak-survivability-scan:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make go-refund-tweak-survivability-scan WS=/path/to/go/project [OUT=<path>]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "go-refund-tweak-survivability-scan" "$(_WS_RESOLVED)"
	@set -eu; \
	if ! find "$(_WS_RESOLVED)" -type f -name '*.go' -not -path '*/vendor/*' -print -quit | grep -q .; then \
	  echo "[go-refund-tweak-survivability-scan] SKIP no non-vendor .go files under $(_WS_RESOLVED)"; \
	  exit 0; \
	fi; \
	out_path="$(if $(OUT),$(OUT),$(_WS_RESOLVED)/audit/go-refund-tweak-survivability-scan.json)"; \
	mkdir -p "$$(dirname "$$out_path")"; \
	python3 tools/go-refund-tweak-survivability-scan.py "$(_WS_RESOLVED)" --json > "$$out_path"; \
	echo "[go-refund-tweak-survivability-scan] wrote $$out_path"

go-refund-tweak-survivability-scan-test:
	@python3 -m unittest tools.tests.test_go_refund_tweak_survivability_scan -v

# V5 PR-G / Gap-27 - pattern-name taxonomy clusterer.
# Reads reference/patterns.dsl/*.yaml, clusters pattern names by token
# co-occurrence, writes reference/pattern_taxonomy.json. Used by
# tools/llm-pr-review.py (detector-tier-b task-type) and the LISA mining
# dispatcher to send LLMs a bucket-relevant pattern sample instead of a
# random 60-name sample. See docs/V5_CAPABILITY_GAPS_2026-04-26.md Gap 27.
# Stdlib-only; <100ms over 1.4k yaml files.
pattern-taxonomy:
	@python3 tools/pattern-taxonomy-cluster.py

pattern-taxonomy-test:
	@python3 -m unittest tools.tests.test_findings_to_pattern

# G1 helper: advisory-only corpus-first worklist for accounting/value-flow
# logic-flow bypass subcases. This never claims detector closure or promotion.
logic-flow-bypass-accounting-worklist:
	@python3 tools/logic-flow-bypass-accounting-worklist.py \
	  $(if $(SPEC_DIR),--spec-dir "$(SPEC_DIR)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(JSON),--print-json)

# G1 helper: advisory-only extractor for uncategorized Solodit blindspot rows
# that still need a concrete bug-class taxonomy before detector work.
solodit-taxonomy-triage:
	@python3 tools/solodit-taxonomy-triage.py \
	  $(if $(INPUT),"$(INPUT)") \
	  $(if $(FORMAT),--format "$(FORMAT)") \
	  $(if $(OUTPUT),--output "$(OUTPUT)")

solodit-rest-direct:
	@python3 tools/solodit-rest-direct.py \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/solodit_freshness_backfill_$(shell date -u +%Y%m%d))" \
	  --max-pages "$(if $(MAX_PAGES),$(MAX_PAGES),10)" \
	  --page-size "$(if $(PAGE_SIZE),$(PAGE_SIZE),100)" \
	  --min-severity "$(if $(MIN_SEVERITY),$(MIN_SEVERITY),HIGH)" \
	  $(if $(MIN_REQUEST_INTERVAL),--min-request-interval "$(MIN_REQUEST_INTERVAL)") \
	  $(if $(SORT_FIELD),--sort-field "$(SORT_FIELD)") \
	  $(if $(SORT_DIRECTION),--sort-direction "$(SORT_DIRECTION)") \
	  $(if $(LANGUAGE),--language "$(LANGUAGE)") \
	  $(if $(KEYWORD),--keyword "$(KEYWORD)") \
	  $(if $(KEYWORD_FIELD),--keyword-field "$(KEYWORD_FIELD)") \
	  $(if $(JSON_ONLY),--json-only) \
	  $(if $(NO_UPDATE_CURSOR),--no-update-cursor)

solodit-language-refresh-test:
	@python3 -m unittest \
	  tools.tests.test_solodit_rest_direct \
	  tools.tests.test_hackerman_etl_from_solodit_specs \
	  tools.tests.test_solodit_ingest_language_filter \
	  -v

# V5 PR-G / Gap-24 / Gap-34 - convert a finding markdown into a CANDIDATE
# pattern + TODO fixture scaffolds. Never auto-promotes; promotion requires
# paired vulnerable + clean fixtures (run `python3 tools/findings-to-pattern.py
# --promote <name>`). See docs/V5_CAPABILITY_GAPS_2026-04-26.md Gap 24/34.
findings-to-pattern:
	@if [ -z "$(FINDING)" ] && [ -z "$(NAME)" ]; then \
	  echo 'usage: make findings-to-pattern FINDING=<path-to-md> [NAME=<override>]'; \
	  echo '   or: make findings-to-pattern NAME=<kebab-case> BUG_CLASS=<x> SEVERITY=<x>'; \
	  exit 2; \
	fi
	@python3 tools/findings-to-pattern.py \
	  $(if $(FINDING),$(FINDING)) \
	  $(if $(NAME),--name $(NAME)) \
	  $(if $(BUG_CLASS),--bug-class $(BUG_CLASS)) \
	  $(if $(SEVERITY),--severity $(SEVERITY)) \
	  $(if $(CONFIDENCE),--confidence $(CONFIDENCE))

# From claudeboy-pr208
audit-orchestrator-test:
	@python3 tools/tests/test_audit_orchestrator.py

# PR 204 - Adversarial Co-pilot skeleton (offline)
# Real swarm dispatch is gated by the --live flag on the tool itself; tests
# always run with the default --dry-run path via mocked dispatch.
adversarial-copilot-test:
	@python3 tools/tests/test_adversarial_copilot.py

# Capability v3 iter-001 T5 - submission factory (Codex #6).
# Produces operator-facing `cantina_ready.md` per packaged bundle. No
# platform API calls, no ledger writes. Pattern-matching triager-risk
# classifier derived verbatim from docs/TRIAGER_OUTCOMES_POST_ITER13.md.
submission-factory:
	@if [ -z "$(BUNDLE)" ]; then \
	  echo "usage: make submission-factory BUNDLE=<path> [PLATFORM=<name>]"; exit 2; fi
	@python3 tools/submission-factory.py --bundle "$(BUNDLE)" \
	  $(if $(PLATFORM),--platform $(PLATFORM))

submission-factory-test:
	@python3 tools/tests/test_submission_factory.py

# Wave 7 ww2 (PR #526 gap 2) - Paste-ready generator. Takes a staging
# draft + workspace and emits a clean Immunefi paste-ready file. Refuses
# if pre-submit-check.sh hard-fails, if `## Program Impact Mapping` is
# missing, if `## Production Path` is absent, or if the dossier has
# unresolved blockers. Stdlib-only.
paste-ready:
	@if [ -z "$(WS)" ] || [ -z "$(DRAFT)" ]; then \
	  echo "usage: make paste-ready WS=<workspace> DRAFT=<draft.md>"; exit 2; fi
	@# K6/H2: run agent-learning-gate before generating paste-ready output for High/Critical drafts.
	@_sev=$$(python3 -c "import re,sys; t=open('$(DRAFT)',encoding='utf-8',errors='replace').read(); m=re.search(r'(?:severity|impact|risk)\s*[:=]\s*(critical|high)\b',t,re.IGNORECASE); print(m.group(1).lower() if m else '')" 2>/dev/null || true); \
	if [ "$$_sev" = "high" ] || [ "$$_sev" = "critical" ]; then \
	  echo "[paste-ready] K6: High/Critical draft detected (severity=$$_sev); running agent-learning-gate ..."; \
	  _gate_rc=0; \
	  python3 tools/agent-learning-gate.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json) || _gate_rc=$$?; \
	  if [ "$$_gate_rc" -ne 0 ] && [ "$(STRICT)" = "1" ]; then \
	    echo "[paste-ready] ERR: agent-learning-gate failed (rc=$$_gate_rc) and STRICT=1; refusing to generate paste-ready output until unclassified artifacts are resolved. Run \`make agent-artifact-mine WS=$(WS)\` then \`make agent-learning-compiler WS=$(WS)\`." >&2; \
	    exit "$$_gate_rc"; \
	  elif [ "$$_gate_rc" -ne 0 ]; then \
	    echo "[paste-ready] WARN: agent-learning-gate failed (rc=$$_gate_rc); continuing (set STRICT=1 to block)" >&2; \
	  fi; \
	fi
	@python3 tools/paste-ready-generator.py "$(WS)" "$(DRAFT)" \
	  $(if $(SKIP_PRE_SUBMIT),--skip-pre-submit) \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)")

paste-ready-test:
	@python3 -m unittest tools.tests.test_paste_ready_generator

# PR #729 / Wave-3 item #5 - end-to-end finding-lifecycle orchestrator.
# Walks: cluster -> hacker brief -> PoC scaffold -> operator gate ->
# originality scan -> paste-ready. See tools/wave3-e2e-pipeline.py for
# the schema (auditooor.wave3_e2e_pipeline.v1).
.PHONY: wave3-e2e-pipeline wave3-e2e-pipeline-test
wave3-e2e-pipeline:
	@if [ -z "$(WS)" ] || [ -z "$(CLUSTER)" ] || [ -z "$(PLATFORM)" ] || [ -z "$(PROTOCOL)" ]; then \
	  echo "usage: make wave3-e2e-pipeline WS=<workspace> CLUSTER=<name> PLATFORM=<cantina|immunefi|sherlock|code4rena> PROTOCOL=<name>"; \
	  echo "       optional: OUT_DIR=<path> STEPS=1,2,3,4,5 STRICT=1 RESUME=1"; \
	  exit 2; fi
	@python3 tools/wave3-e2e-pipeline.py \
	  --workspace "$(WS)" \
	  --cluster "$(CLUSTER)" \
	  --target-platform "$(PLATFORM)" \
	  --target-protocol "$(PROTOCOL)" \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(STEPS),--steps "$(STEPS)") \
	  $(if $(STRICT),--strict) \
	  $(if $(RESUME),--resume)

wave3-e2e-pipeline-test:
	@python3 -m unittest tools.tests.test_wave3_e2e_pipeline

# V5-P0-16 (Gap 28 + Gap 41) - automated source-citation audit for
# the detector library. Stdlib-only, hermetic by default. Writes
# tools/calibration/library_source_coverage_<date>.json. Pass JSON=1
# to also emit JSON to stdout, NO_CROSS_CHECK=1 to skip the
# ~/audits/<ws>/engage_report.md cross-check (CI / no-FS mode).
library-source-coverage:
	@python3 tools/library-source-coverage.py \
	  $(if $(JSON),--json) \
	  $(if $(NO_CROSS_CHECK),--no-cross-check) \
	  $(if $(AUDITS_ROOT),--audits-root "$(AUDITS_ROOT)") \
	  $(if $(OUT),--out "$(OUT)")

library-source-coverage-test:
	@python3 -m unittest tools.tests.test_library_source_coverage

# V5-P0-18 (Gap 26) - durable per-campaign mining manifest. The tool
# is invocation-shaped (write/validate), so this Make target only
# wires up the test runner. Operators call the tool directly:
#   python3 tools/mining-manifest.py write --workspace … --date … …
mining-manifest-test:
	@python3 -m unittest tools.tests.test_mining_manifest

# V5 CAMPAIGN PR 3 - source-mining campaign wrapper. Wraps existing
# tools/llm-dispatch.py with packet creation + Kimi candidate pass +
# Minimax red-team pass + artifact summary. Never auto-promotes a
# candidate to a finding.
#
# Usage:
#   make source-mine WS=~/audits/<project>
#   make source-mine WS=~/audits/<project> OUT=~/audits/<project>/source_mining/2026-04-26
#   make source-mine WS=~/audits/<project> PROVIDERS=kimi,minimax DRY_RUN=1
source-mine:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make source-mine WS=<workspace> [OUT=<out-dir>] [PROVIDERS=kimi,minimax] [DRY_RUN=1]'; exit 2; \
	fi
	@python3 tools/source-mining-campaign.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --providers "$(if $(PROVIDERS),$(PROVIDERS),kimi,minimax)" \
	  --out "$(if $(OUT),$(OUT),$(_WS_RESOLVED)/source_mining/$(shell date -u +%Y-%m-%d))" \
	  $(if $(PACKET_BUDGET),--packet-budget $(PACKET_BUDGET)) \
	  $(if $(MAX_TOKENS),--max-tokens $(MAX_TOKENS)) \
	  $(if $(TIMEOUT),--timeout $(TIMEOUT)) \
	  $(if $(DRY_RUN),--dry-run)

source-mine-test:
	@python3 -m unittest tools.tests.test_source_mining_campaign

contest-fix-mine:
	@test -n "$(CONTEST_ID)" || { echo 'Usage: make contest-fix-mine CONTEST_ID=<contest_id> [OUT=<out-dir>]'; exit 2; }
	@python3 tools/contest-fix-mine.py --contest-id "$(CONTEST_ID)" $(if $(OUT),--output-dir "$(OUT)") $(if $(JSON),--json)

contest-fix-mine-test:
	@python3 -m unittest tools.tests.test_contest_fix_mine -v

provider-capacity-report:
	@python3 tools/provider-capacity-report.py \
	  --out-dir "$(if $(OUT),$(OUT),.audit_logs/provider_capacity)" \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(LIVE_PROBE),--live-probe) \
	  $(if $(TIMEOUT),--timeout $(TIMEOUT)) \
	  $(if $(JSON),--print-json)

semantic-provider-batch:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make semantic-provider-batch WS=<workspace> [LIMIT=22] [MOCK=1|DRY_RUN=1] [OUT=<out-dir>]'; exit 2; \
	fi
	@python3 tools/semantic-provider-batch.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --out-dir "$(if $(OUT),$(OUT),$(_WS_RESOLVED)/.auditooor/provider_assist/semantic_batch)" \
	  --limit "$(if $(LIMIT),$(LIMIT),22)" \
	  $(if $(WORKLIST),--worklist "$(WORKLIST)") \
	  $(if $(GENERATE_WORKLIST),--generate-worklist) \
	  $(if $(TIMEOUT),--timeout "$(TIMEOUT)") \
	  $(if $(KIMI_MAX_TOKENS),--kimi-max-tokens "$(KIMI_MAX_TOKENS)") \
	  $(if $(MINIMAX_MAX_TOKENS),--minimax-max-tokens "$(MINIMAX_MAX_TOKENS)") \
	  $(if $(KIMI_PACKETS_PER_LOOP),--kimi-packets-per-loop "$(KIMI_PACKETS_PER_LOOP)") \
	  $(if $(MINIMAX_PACKETS_PER_LOOP),--minimax-packets-per-loop "$(MINIMAX_PACKETS_PER_LOOP)") \
	  $(if $(LARGE_BATCH),--large-batch) \
	  $(if $(LARGE_BATCH_SIZE),--large-batch-size "$(LARGE_BATCH_SIZE)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(MOCK),--mock) \
	  $(if $(JSON),--print-json)

rust-corpus-ingest:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-corpus-ingest WS=<workspace> [RUST_CORPUS_ROOT=/path/to/local/rustbugs] [OUT=<out-dir>] [JSON=1]'; exit 2; \
	fi
	@python3 tools/rust-corpus-ingest.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(RUST_CORPUS_ROOT),--corpus-root "$(RUST_CORPUS_ROOT)") \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(JSON),--print-json)

rust-corpus-ingest-test:
	@python3 -m unittest tools.tests.test_rust_corpus_ingest

rust-corpus-validate:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-corpus-validate WS=<workspace> [RUST_CORPUS_INDEX=<json>] [OUT=<out-dir>] [STRICT=1] [JSON=1]'; exit 2; \
	fi
	@python3 tools/rust-corpus-validate.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(RUST_CORPUS_INDEX),--index "$(RUST_CORPUS_INDEX)") \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--print-json)

rust-corpus-validate-test:
	@python3 -m unittest tools.tests.test_rust_corpus_validate

rust-corpus-fixture-tasks:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-corpus-fixture-tasks WS=<workspace> [RUST_CORPUS_INDEX=<json>] [OUT=<out-dir>] [JSON=1]'; exit 2; \
	fi
	@python3 tools/rust-corpus-fixture-tasks.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(RUST_CORPUS_INDEX),--rust-corpus-index "$(RUST_CORPUS_INDEX)") \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(NO_HERMETIC_FIXTURE),--no-hermetic-fixture) \
	  $(if $(JSON),--print-json)

rust-corpus-fixture-tasks-test:
	@python3 -m unittest tools.tests.test_rust_corpus_fixture_tasks

rust-swival-route-evidence:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-swival-route-evidence WS=<workspace> [SWIVAL_ROUTE_INPUT=<json>] [OUT=<out-dir>] [EXPECTED_TOTAL=151] [JSON=1]'; exit 2; \
	fi
	@python3 tools/rust-swival-route-evidence.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(SWIVAL_ROUTE_INPUT),--input "$(SWIVAL_ROUTE_INPUT)") \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(EXPECTED_TOTAL),--expected-total "$(EXPECTED_TOTAL)") \
	  $(if $(JSON),--print-json)

rust-swival-route-evidence-test:
	@python3 -m unittest tools.tests.test_rust_swival_route_evidence

corpus-detectorization-inventory:
	@python3 tools/corpus-detectorization-inventory.py \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(SWIVAL_JSON),--swival-json "$(SWIVAL_JSON)") \
	  $(if $(RUST_CORPUS_INDEX),--rust-corpus-index "$(RUST_CORPUS_INDEX)") \
	  $(if $(ZKBUGS_INDEX),--zkbugs-index "$(ZKBUGS_INDEX)") \
	  $(if $(RECON_JSON),--recon-json "$(RECON_JSON)") \
	  $(if $(SOURCE_MINING_JSON),--source-mining-json "$(SOURCE_MINING_JSON)") \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(JSON),--print-json)

corpus-detectorization-inventory-test:
	@python3 -m unittest tools.tests.test_corpus_detectorization_inventory

# Wave 7 zz2 (gap 6 - provider dispatch quality).
# Pre-dispatch validator for Kimi/Minimax/Claude prompts. Reads a YAML
# template under reference/dispatch-templates/<TEMPLATE>.yaml and refuses
# (exit 1) if the prompt file misses any required input. See
# docs/PROVIDER_DISPATCH_TEMPLATES.md for the rendered templates.
#
# Usage:
#   make dispatch-validate TEMPLATE=source-extract PROMPT=path/to/prompt.txt
#   make dispatch-validate-list
#   make dispatch-validate-test
dispatch-validate:
	@if [ -z "$(TEMPLATE)" ] || [ -z "$(PROMPT)" ]; then \
	  echo 'Usage: make dispatch-validate TEMPLATE=<name> PROMPT=<file>'; \
	  echo 'Templates: $(shell python3 tools/dispatch-template.py --list 2>/dev/null | tr "\n" " ")'; \
	  exit 2; \
	fi
	@python3 tools/dispatch-template.py --template "$(TEMPLATE)" --validate "$(PROMPT)" \
	  $(if $(JSON),--json)

dispatch-validate-list:
	@python3 tools/dispatch-template.py --list

dispatch-validate-test:
	@python3 -m unittest tools.tests.test_dispatch_template

# Wave 8 §8 (PR #535) - provider dispatch becomes MANDATORY for the 5
# expensive task types. `dispatch-preflight` wraps `llm-dispatch.py`
# behind the validator so a sloppy prompt cannot reach the model.
# Audits every attempt to <workspace>/.auditooor/dispatch_audit.jsonl.
#
# Usage:
#   make dispatch-preflight TEMPLATE=source-extract PROMPT=path/to/prompt.md \
#       [WORKSPACE=~/audits/<project>] [PROVIDER=kimi] \
#       [SEVERITY=<level>] [LOCAL_JUDGMENT_BUNDLE=<path>]
#
# Emergency override (audited):
#   BYPASS_DISPATCH_PREFLIGHT=1 BYPASS_DISPATCH_PREFLIGHT_REASON='pager fire' \
#       make dispatch-preflight TEMPLATE=... PROMPT=...
dispatch-preflight:
	@if [ -z "$(TEMPLATE)" ] || [ -z "$(PROMPT)" ]; then \
	  echo 'Usage: make dispatch-preflight TEMPLATE=<name> PROMPT=<file> [WORKSPACE=<dir>] [PROVIDER=<auto|kimi|minimax|anthropic>] [SEVERITY=<level>] [LOCAL_JUDGMENT_BUNDLE=<path>]'; \
	  echo 'Mandatory templates: source-extract adversarial-kill harness-plan fixture-map paste-ready-review'; \
	  exit 2; \
	fi
	@python3 tools/dispatch-preflight.py \
	  --template "$(TEMPLATE)" \
	  --prompt-file "$(PROMPT)" \
	  $(if $(WORKSPACE),--workspace "$(WORKSPACE)") \
	  $(if $(REQUIRE_MCP_CONTEXT),--require-mcp-context) \
	  $(if $(SEVERITY),--severity "$(SEVERITY)") \
	  $(if $(LOCAL_JUDGMENT_BUNDLE),--require-local-judgment-bundle "$(LOCAL_JUDGMENT_BUNDLE)") \
	  $(if $(PROVIDER),--provider "$(PROVIDER)") \
	  $(if $(FORWARD),--forward "$(FORWARD)") \
	  $(if $(DRY_RUN),--dry-run)

dispatch-preflight-test:
	@python3 -m unittest tools.tests.test_dispatch_preflight

worker-brief-check:
	@if [ -z "$(BRIEF)" ]; then \
	  echo 'Usage: make worker-brief-check BRIEF=<brief.md> [STRICT_RECALL=1] [JSON=1]'; \
	  exit 2; \
	fi
	@python3 tools/worker-brief-completeness-check.py "$(BRIEF)" \
	  $(if $(STRICT_RECALL),--strict-recall) \
	  $(if $(JSON),--json)

worker-brief-check-test:
	@python3 -m unittest tools.tests.test_worker_brief_completeness_check

v3-worker-packet:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make v3-worker-packet WS=<workspace> [SEVERITY=High] [PACKET_ID=<id>] [TITLE=<title>] [STRICT=1]'; \
	  exit 2; \
	fi
	@mkdir -p "$(_WS_RESOLVED)/.auditooor/worker_packets"
	@$(MAKE) --no-print-directory system-model WS="$(_WS_RESOLVED)" >/dev/null
	@python3 tools/v3-worker-packet-builder.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --packet-id "$(if $(PACKET_ID),$(PACKET_ID),canonical-audit-worker-packet)" \
	  --title "$(if $(TITLE),$(TITLE),Canonical Audit Worker Packet)" \
	  --severity "$(if $(SEVERITY),$(SEVERITY),High)" \
	  --auto-workspace-receipts \
	  --source-file ".auditooor/system_model.json" \
	  $(if $(NO_LESSON_PACK_REASON),--no-lesson-pack-reason "$(NO_LESSON_PACK_REASON)",--no-lesson-pack-reason "NO_LESSON_PACK_REASON:canonical-audit-scaffold-packet - lesson packs are curated per High/Critical FINDING at dispatch time, not attached to the generic workspace audit scaffold; set NO_LESSON_PACK_REASON= or attach a lesson-pack receipt to override") \
	  $(if $(wildcard $(_WS_RESOLVED)/.auditooor/hacker_question_obligations.jsonl),--hacker-questions-file "$(_WS_RESOLVED)/.auditooor/hacker_question_obligations.jsonl") \
	  --out-json "$(_WS_RESOLVED)/.auditooor/worker_packets/$(if $(PACKET_ID),$(PACKET_ID),canonical-audit-worker-packet).json" \
	  --out-md "$(_WS_RESOLVED)/.auditooor/worker_packets/$(if $(PACKET_ID),$(PACKET_ID),canonical-audit-worker-packet).md" \
	  --out-mcp-evidence-receipt "$(_WS_RESOLVED)/.auditooor/worker_packets/$(if $(PACKET_ID),$(PACKET_ID),canonical-audit-worker-packet).mcp_evidence_receipt.json" \
	  $(if $(filter 1,$(STRICT)),--strict)
	@if [ "$(STRICT)" = "1" ]; then \
	  python3 tools/system-model-dispatch-gate.py \
	    --packet "$(_WS_RESOLVED)/.auditooor/worker_packets/$(if $(PACKET_ID),$(PACKET_ID),canonical-audit-worker-packet).json" \
	    --strict; \
	  python3 tools/worker-delivery-contract.py \
	    "$(_WS_RESOLVED)/.auditooor/worker_packets/$(if $(PACKET_ID),$(PACKET_ID),canonical-audit-worker-packet).json" \
	    --strict; \
	fi

# Hackerman V3 - build exactly 8 Kimi + 8 MiniMax preflight-gated provider
# prompts. This target never calls providers; it emits queue artifacts and
# per-row dispatch-preflight commands that require a fresh MCP context receipt.
v3-provider-fanout-queue:
	@python3 tools/v3-provider-fanout-queue.py \
	  --workspace "$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))" \
	  --campaign-id "$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-8kimi-8minimax)" \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(PLAN),--plan "$(PLAN)") \
	  $(if $(JSON),--print-json)

v3-provider-followup-queue:
	@python3 tools/v3-provider-fanout-queue.py \
	  --workspace "$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))" \
	  --campaign-id "$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-followup)" \
	  --mode followup \
	  $(if $(RESULT),--followup-source-result "$(RESULT)",$(error RESULT is required for v3-provider-followup-queue)) \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(PLAN),--plan "$(PLAN)") \
	  $(if $(JSON),--print-json)

v3-provider-prefiling-backfill-queue:
	@python3 tools/v3-provider-fanout-queue.py \
	  --workspace "$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))" \
	  --campaign-id "$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-prefiling-backfill)" \
	  --mode prefiling-backfill \
	  --prefiling-source-result "$(if $(RESULT),$(RESULT),$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))/.auditooor/prefiling_stress_test.json)" \
	  $(if $(SOURCE_ARTIFACT_DIR),--prefiling-source-artifact-dir "$(SOURCE_ARTIFACT_DIR)") \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(PLAN),--plan "$(PLAN)") \
	  $(if $(JSON),--print-json)

# Run a V3 Kimi/MiniMax fanout queue through dispatch-preflight. LIVE=1 is
# required for real provider calls; DRY_RUN=1 or MOCK_DISPATCHER=<path> is safe
# for local validation. MiniMax rows are phased after Kimi outputs exist.
v3-provider-fanout-run:
	@python3 tools/v3-provider-fanout-runner.py \
	  --workspace "$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))" \
	  --campaign-id "$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-8kimi-8minimax)" \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(OUT),--out-dir "$(OUT)") \
	  $(if $(RUN_ID),--run-id "$(RUN_ID)") \
	  $(if $(PROVIDER),--provider "$(PROVIDER)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(START_INDEX),--start-index "$(START_INDEX)") \
	  $(if $(PARALLEL),--parallel "$(PARALLEL)") \
	  $(if $(KIMI_PARALLEL),--kimi-parallel "$(KIMI_PARALLEL)") \
	  $(if $(MINIMAX_PARALLEL),--minimax-parallel "$(MINIMAX_PARALLEL)") \
	  $(if $(TIMEOUT),--timeout "$(TIMEOUT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(MOCK_DISPATCHER),--mock-dispatcher "$(MOCK_DISPATCHER)") \
	  $(if $(LIVE),--operator-live-network-consent) \
	  $(if $(MINIMAX_STANDALONE_ADVISORY),--minimax-standalone-advisory) \
	  $(if $(REFRESH_MCP),--refresh-mcp-before-row) \
	  $(if $(NO_REFRESH_MCP),--no-refresh-mcp-before-row) \
	  $(if $(JSON),--print-json)

v3-provider-fanout-closeout:
	@python3 tools/v3-provider-fanout-closeout.py \
	  --workspace "$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))" \
	  --campaign-id "$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-8kimi-8minimax)" \
	  $(if $(RUN),--run "$(RUN)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(APPEND_LEDGER),--append-learning-ledger) \
	  $(if $(JSON),--print-json)

v3-provider-local-verification-queue:
	@python3 tools/v3-provider-local-verification-queue.py \
	  --workspace "$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))" \
	  --campaign-id "$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-8kimi-8minimax)" \
	  $(if $(CLOSEOUT),--closeout "$(CLOSEOUT)") \
	  $(if $(BACKFILL_JSON),--backfill-json "$(BACKFILL_JSON)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(JSON),--print-json)

v3-provider-local-verify:
	@python3 tools/v3-provider-local-verify.py \
	  --workspace "$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))" \
	  --campaign-id "$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-8kimi-8minimax)" \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(TERMINAL_JUDGMENTS),--terminal-judgments "$(TERMINAL_JUDGMENTS)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(JSON),--print-json)

v3-provider-learning-compiler:
	@python3 tools/v3-provider-learning-compiler.py \
	  --workspace "$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))" \
	  --campaign-id "$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-8kimi-8minimax)" \
	  $(if $(RESULT),--result "$(RESULT)") \
	  $(if $(LEDGER),--ledger "$(LEDGER)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(JSON),--print-json)

v3-provider-campaign-completeness-gate:
	@python3 tools/v3-provider-campaign-completeness-gate.py \
	  --workspace "$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))" \
	  --campaign-id "$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-8kimi-8minimax)" \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(RUN),--run "$(RUN)") \
	  $(if $(CLOSEOUT),--closeout "$(CLOSEOUT)") \
	  $(if $(LOCAL_VERIFICATION),--local-verification "$(LOCAL_VERIFICATION)") \
	  $(if $(CLOSURE_QUEUE),--closure-queue "$(CLOSURE_QUEUE)") \
	  $(if $(EXPECTED_KIMI),--expected-kimi "$(EXPECTED_KIMI)") \
	  $(if $(EXPECTED_MINIMAX),--expected-minimax "$(EXPECTED_MINIMAX)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json)

# Single-command V3 provider fanout slice. Defaults to dry-run execution;
# LIVE=1 is the only path that forwards live provider consent.
v3-provider-fanout-slice:
	@if [ -z "$(WS)" ] && [ -z "$(WORKSPACE)" ]; then \
	  echo 'Usage: make v3-provider-fanout-slice WS=<workspace> [LIVE=1] [CAMPAIGN_ID=<id>] [JSON=1]'; exit 2; \
	fi
	@set -e; \
	ws="$(if $(WORKSPACE),$(WORKSPACE),$(_WS_RESOLVED))"; \
	campaign="$(if $(CAMPAIGN_ID),$(CAMPAIGN_ID),hackerman-v3-8kimi-8minimax)"; \
	echo "[v3-provider-fanout-slice] queue campaign=$$campaign workspace=$$ws"; \
	$(MAKE) --no-print-directory v3-provider-fanout-queue WORKSPACE="$$ws" CAMPAIGN_ID="$$campaign" $(if $(JSON),JSON=1); \
	if [ "$(LIVE)" = "1" ]; then \
	  echo "[v3-provider-fanout-slice] run mode=live"; \
	  $(MAKE) --no-print-directory v3-provider-fanout-run WORKSPACE="$$ws" CAMPAIGN_ID="$$campaign" LIVE=1 $(if $(JSON),JSON=1); \
	else \
	  echo "[v3-provider-fanout-slice] run mode=dry-run"; \
	  $(MAKE) --no-print-directory v3-provider-fanout-run WORKSPACE="$$ws" CAMPAIGN_ID="$$campaign" DRY_RUN=1 $(if $(JSON),JSON=1); \
	fi; \
	echo "[v3-provider-fanout-slice] closeout"; \
	$(MAKE) --no-print-directory v3-provider-fanout-closeout WORKSPACE="$$ws" CAMPAIGN_ID="$$campaign" $(if $(JSON),JSON=1); \
	echo "[v3-provider-fanout-slice] local verification queue"; \
	$(MAKE) --no-print-directory v3-provider-local-verification-queue WORKSPACE="$$ws" CAMPAIGN_ID="$$campaign" $(if $(JSON),JSON=1); \
	echo "[v3-provider-fanout-slice] local verify"; \
	$(MAKE) --no-print-directory v3-provider-local-verify WORKSPACE="$$ws" CAMPAIGN_ID="$$campaign" $(if $(JSON),JSON=1); \
	echo "[v3-provider-fanout-slice] learning compiler"; \
	$(MAKE) --no-print-directory v3-provider-learning-compiler WORKSPACE="$$ws" CAMPAIGN_ID="$$campaign" $(if $(JSON),JSON=1); \
	echo "[v3-provider-fanout-slice] campaign completeness gate"; \
	if [ "$(LIVE)" = "1" ]; then \
	  $(MAKE) --no-print-directory v3-provider-campaign-completeness-gate WORKSPACE="$$ws" CAMPAIGN_ID="$$campaign" STRICT=1 OUT_JSON="$$ws/.auditooor/v3_provider_campaign_completeness_gate.json" $(if $(JSON),JSON=1); \
	else \
	  $(MAKE) --no-print-directory v3-provider-campaign-completeness-gate WORKSPACE="$$ws" CAMPAIGN_ID="$$campaign" OUT_JSON="$$ws/.auditooor/v3_provider_campaign_completeness_gate.json" $(if $(JSON),JSON=1) || \
	    echo "[v3-provider-fanout-slice] WARN campaign completeness failed in dry-run mode; continuing" >&2; \
	fi; \
	echo "[v3-provider-fanout-slice] discipline check"; \
	$(MAKE) --no-print-directory provider-fanout-discipline-check WS="$$ws" ENFORCE_IF_ARTIFACTS=1 $(if $(JSON),JSON=1)

v3-provider-fanout-queue-test:
	@python3 -m unittest tools.tests.test_v3_provider_fanout_queue tools.tests.test_v3_provider_local_verification_queue tools.tests.test_v3_provider_local_verify tools.tests.test_v3_provider_learning_compiler

v3-provider-campaign-completeness-gate-test:
	@python3 -m unittest tools.tests.test_v3_provider_campaign_completeness_gate -v

# PR #658 Tier-B item #14 - operator-facing pre-source-read injection entrypoint.
# Worker-facing hook and function-mindset docs now standardize on the Wave-6
# injector (`tools/auditooor-pre-source-read-injector.py`). Keep the published
# `SOURCE=... [WS=...|WORKSPACE=...]` make surface stable by resolving relative
# source paths against the workspace before invoking the newer injector.
#
# Usage:
#   make pre-source-read-inject SOURCE=<path/to/file.sol>
#   make pre-source-read-inject SOURCE=<path/to/file.go> [WS=<dir>|WORKSPACE=<dir>] [TARGET_REPO=owner/repo]
#
# Legacy markdown/index-only workflows can use:
#   make pre-source-read-inject-legacy SOURCE=<path/to/file.sol> [WORKSPACE=<dir>]
#
# Run smoke test suite:
#   make pre-source-read-inject-test
pre-source-read-inject:
	@if [ -z "$(SOURCE)" ]; then \
	  echo 'Usage: make pre-source-read-inject SOURCE=<source-file-path> [WS=<dir>|WORKSPACE=<dir>]'; \
	  exit 2; \
	fi
	@SOURCE_PATH="$(SOURCE)"; \
	WORKSPACE_PATH="$(if $(WS),$(WS),$(WORKSPACE))"; \
	if [ ! -f "$$SOURCE_PATH" ] && [ -n "$$WORKSPACE_PATH" ] && [ -f "$$WORKSPACE_PATH/$(SOURCE)" ]; then \
	  SOURCE_PATH="$$WORKSPACE_PATH/$(SOURCE)"; \
	fi; \
	python3 tools/auditooor-pre-source-read-injector.py \
	  "$$SOURCE_PATH" \
	  --workspace "$$WORKSPACE_PATH" \
	  $(if $(TARGET_REPO),--target-repo "$(TARGET_REPO)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(MIN_CONFIDENCE),--min-confidence "$(MIN_CONFIDENCE)") \
	  $(if $(MAX_FUNCTIONS),--max-functions "$(MAX_FUNCTIONS)") \
	  $(if $(filter 1,$(STRICT)),--strict-persistence) \
	  $(if $(JSON),--json)

pre-source-read-inject-legacy:
	@if [ -z "$(SOURCE)" ]; then \
	  echo 'Usage: make pre-source-read-inject-legacy SOURCE=<source-file-path> [WORKSPACE=<dir>]'; \
	  exit 2; \
	fi
	@python3 tools/pre-source-read-inject.py \
	  --source-path "$(SOURCE)" \
	  $(if $(WORKSPACE),--workspace "$(WORKSPACE)")

pre-source-read-inject-test:
	@python3 -m unittest tools.tests.test_pre_source_read_injector

# Wave 6 Worker L (PR #556 §Priority 4) - workspace-driven driver for the
# Wave 5 snappy/decode-bomb PoC. The PoC lives under the workspace
# (`<ws>/critical_hunt/node_resource_wave5/snappy_oom_poc`) - auditooor
# never carries third-party Cargo workspaces. This target only resolves
# the workspace path and shells into the PoC; failure to find the PoC
# directory exits rc=2 (operator-fixable, not a CI hard fail). This is
# component-behavior evidence only: it is not Critical/direct-submit-ready
# unless a later impact contract proves an exact listed Base Azul impact
# sentence with measured >=30% node-resource consumption under realistic
# non-bruteforce conditions or a quantified node-shutdown threshold. Snappy
# gossip decode is not mempool impact.
base-snappy-bomb-test:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make base-snappy-bomb-test WS=<workspace>'; exit 2; fi
	@if [ ! -d "$(_WS_RESOLVED)/critical_hunt/node_resource_wave5/snappy_oom_poc" ]; then \
	  echo "[base-snappy-bomb-test] PoC not found at $(_WS_RESOLVED)/critical_hunt/node_resource_wave5/snappy_oom_poc"; exit 2; fi
	@cd "$(_WS_RESOLVED)/critical_hunt/node_resource_wave5/snappy_oom_poc" && cargo run --release 2>&1

# Wave 6 Worker L (PR #556 §Priority 4) - pre-submit severity-claim guard.
# Scans the candidate matrix and refuses to pass if ANY reportable-severity row
# lacks one exact selected Base Azul impact sentence plus
# `listed_impact_proven == true`. Snappy Critical/direct-submit-ready claims
# also require measured >=30% resource consumption or node-shutdown proof.
# No triage-ask escape hatch for missing proof. Strictly additive to existing
# pre-submit checks.
#
# Usage:
#   make severity-claim-guard WS=<workspace>
#   make severity-claim-guard-test
severity-claim-guard:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make severity-claim-guard WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "severity-claim-guard" "$(_WS_RESOLVED)"
	@python3 tools/severity-claim-guard.py --workspace "$(_WS_RESOLVED)"

severity-claim-guard-test:
	@python3 -m unittest tools.tests.test_severity_claim_guard

# --- upstream-equivalent-gate (Wave J-1A / Check #33) ----------------------
# 5-check candidate promotion gate. Catches the 3 over-claim patterns that
# hit the overnight loop (H-1 G-v01 / I-1A KZG-verify / I-2 N8+N9 oracle-trie
# decode) by verifying:
#   1. audit-tree existence (cited path exists in external/<asset>/)
#   2. line content match (quoted line matches cited line number)
#   3. SCOPE.md OOS check (path not in OOS clause)
#   4. SEVERITY.md verbatim (impact appears under correct tier section)
#   5. upstream equivalent (gh api search/code across kona/reth/op-stack/sp1)
#
# Usage:
#   make upstream-equivalent-gate WS=<workspace> CANDIDATE=<path-to-candidates.json>
#   make upstream-equivalent-gate-test
#
# Optional: add STRICT=1 to exit 1 if any candidate is walked back.
upstream-equivalent-gate:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make upstream-equivalent-gate WS=<workspace> CANDIDATE=<path>'; exit 2; fi
	@if [ -z "$(CANDIDATE)" ]; then \
	  echo 'Usage: make upstream-equivalent-gate WS=<workspace> CANDIDATE=<path>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "upstream-equivalent-gate" "$(_WS_RESOLVED)"
	@python3 tools/upstream-equivalent-gate.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --candidate "$(CANDIDATE)" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--print-json)

upstream-equivalent-gate-test:
	@python3 -m unittest tools.tests.test_upstream_equivalent_gate

# --- disposition-distinctness-guard (anti-false-negative on KILLS) -----------
# Inverts the reflexive-dedup asymmetry: a finding-KILL (dup/OOS/known-issue/
# R47/R53/upstream) is permitted ONLY with a four-axis all-`match` proof; a
# shallow (keyword/mention-only) kill FAILS OPEN (finding stays live).
#   make disposition-sweep WS=<workspace> [JSON=1]   # retro-sweep shallow kills
# WARN-level by default (surfaces shallow kills without mass-bricking existing
# workspaces); exit 1 when shallow kills exist so a caller can gate on it.
.PHONY: disposition-sweep disposition-guard-test
disposition-sweep:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make disposition-sweep WS=<workspace> [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "disposition-sweep" "$(_WS_RESOLVED)"
	@python3 tools/disposition-distinctness-guard.py --sweep "$(_WS_RESOLVED)" $(if $(JSON),--json) || true

disposition-guard-test:
	@python3 -m pytest tools/tests/test_disposition_distinctness_guard.py -q

# --- sanity-gate (Wave O-E / Gap #5) ----------------------------------------
# Cheap pre-filter: Steps 1 (audit-tree existence) + 3 (SCOPE.md OOS) only.
# Filesystem-only, ~10ms per candidate. Run BEFORE upstream-equivalent-gate.
#
# Pipeline:
#   scanner output → sanity-gate → upstream-equivalent-gate → M14-trap
#
# Usage:
#   make sanity-gate WS=<workspace> CAND=<promotion_candidates.json> [OUT=<path>]
#   make sanity-gate-test
.PHONY: sanity-gate sanity-gate-test
sanity-gate:
	@if [ -z "$(WS)" ] || [ -z "$(CAND)" ]; then \
	  echo "Usage: make sanity-gate WS=<workspace> CAND=<promotion_candidates.json> [OUT=<path>]"; \
	  exit 2; \
	fi
	python3 tools/promotion-candidate-sanity-gate.py --workspace $(WS) --candidate $(CAND) --output $(if $(OUT),$(OUT),/tmp/sanity_gate_out.json) --print-json

sanity-gate-test:
	@python3 -m unittest tools.tests.test_promotion_candidate_sanity_gate

# --- deployment-timeline (Wave O-C / Gap #3) --------------------------------
#   Answer "was commit X ever deployed to a live network at time T?"
#   Closes Gap #3 (rc-history / deployment-timeline lookup).
#
#   Usage:
#     make deployment-timeline ASSET=<repo> DEPLOY=<dir> COMMIT=<sha> [NETWORK=<name>]
#   Example:
#     make deployment-timeline ASSET=/path/to/base DEPLOY=/path/to/contract-deployments \
#       COMMIT=162f87c5 NETWORK=sepolia
.PHONY: deployment-timeline
deployment-timeline:
	@if [ -z "$(ASSET)" ] || [ -z "$(DEPLOY)" ] || [ -z "$(COMMIT)" ]; then \
	  echo "Usage: make deployment-timeline ASSET=<repo> DEPLOY=<dir> COMMIT=<sha> [NETWORK=<name>]"; \
	  exit 2; \
	fi
	python3 tools/deployment-timeline.py --asset-repo $(ASSET) --deployments-dir $(DEPLOY) --commit $(COMMIT) $(if $(NETWORK),--network $(NETWORK)) --print-json

deployment-timeline-test:
	@python3 -m unittest tools.tests.test_deployment_timeline

impact-binding-next-input:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-binding-next-input WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/impact-binding-next-input-validator.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json)

impact-binding-next-input-test:
	@python3 -m unittest tools.tests.test_impact_binding_next_input_validator

impact-binding-source-harness-discovery:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-binding-source-harness-discovery WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/impact-binding-source-harness-discovery.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json)

impact-binding-source-harness-discovery-test:
	@python3 -m unittest tools.tests.test_impact_binding_source_harness_discovery

impact-binding-source-import-readiness:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make impact-binding-source-import-readiness WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/impact-binding-source-import-readiness.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json)

impact-binding-source-import-readiness-test:
	@python3 -m unittest tools.tests.test_impact_binding_source_import_readiness

execution-manifest-proof-readiness:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make execution-manifest-proof-readiness WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/execution-manifest-proof-readiness.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--print-json)

execution-manifest-proof-readiness-test:
	@python3 -m unittest tools.tests.test_execution_manifest_proof_readiness

project-source-sample-to-proof-workflow-test:
	@python3 -m unittest tools.tests.test_project_source_sample_to_proof_workflow

project-source-root-readiness:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make project-source-root-readiness WS=<workspace> [ROOT=<path>] [JSON=1]'; exit 2; fi
	@python3 tools/project-source-root-readiness.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(ROOT),--root "$(ROOT)") \
	  $(if $(JSON),--print-json)

project-source-root-readiness-test:
	@python3 -m unittest tools.tests.test_project_source_root_readiness

project-source-root-declaration:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make project-source-root-declaration WS=<workspace> ENTRY=<label=path> [REPLACE=1] [JSON=1]'; exit 2; fi
	@if [ -z "$(ENTRY)" ]; then \
	  echo 'Usage: make project-source-root-declaration WS=<workspace> ENTRY=<label=path> [REPLACE=1] [JSON=1]'; exit 2; fi
	@python3 tools/project-source-root-declaration.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --entry "$(ENTRY)" \
	  $(if $(REPLACE),--replace) \
	  $(if $(JSON),--print-json)

project-source-root-declaration-test:
	@python3 -m unittest tools.tests.test_project_source_root_declaration

harness-binding-manifest:
	@if [ -z "$(INPUT)" ] || [ -z "$(OUT)" ]; then \
	  echo 'Usage: make harness-binding-manifest INPUT=<plan.{json,jsonl}> OUT=<manifest.json> [WS=<workspace>]'; exit 2; fi
	@python3 tools/harness-binding-manifest.py \
	  --input "$(INPUT)" \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  --out "$(OUT)"

source-ref-replay-manifest:
	@if [ -z "$(INPUT)" ] || [ -z "$(OUT)" ]; then \
	  echo 'Usage: make source-ref-replay-manifest INPUT=<findings.{json,jsonl}> OUT=<manifest.json> [NAMED_REF_LOCKFILE=<path>] [LOCAL_SOURCE_ROOT=<path>] [LOCAL_PROOF=<path>]'; exit 2; fi
	@python3 tools/source-ref-replay-manifest.py \
	  --input "$(INPUT)" \
	  --out "$(OUT)" \
	  $(if $(NAMED_REF_LOCKFILE),--named-ref-lockfile "$(NAMED_REF_LOCKFILE)") \
	  $(if $(LOCAL_SOURCE_ROOT),--local-source-root "$(LOCAL_SOURCE_ROOT)") \
	  $(if $(LOCAL_PROOF),--local-proof "$(LOCAL_PROOF)")

source-ref-replay-manifest-fixture:
	@python3 tools/source-ref-replay-manifest.py \
	  --input "tools/tests/fixtures/source_ref_replay_manifest/findings.json" \
	  --named-ref-lockfile "tools/tests/fixtures/source_ref_replay_manifest/named_ref_locks.json" \
	  --local-source-root "tools/tests/fixtures/source_ref_replay_manifest/source_root" \
	  --local-proof "tools/tests/fixtures/source_ref_replay_manifest/local_proofs.json" \
	  --out "reports/source_ref_replay_manifest_fixture.json"

source-root-blocker-emitter:
	@if [ -z "$(INPUT)" ] || [ -z "$(OUT)" ]; then \
	  echo 'Usage: make source-root-blocker-emitter INPUT=<locator.json> OUT=<blockers.{json,jsonl}> [JSONL=1] [OCCURRED_AT=<iso8601>] [SOURCE_PATH=<path>]'; exit 2; fi
	@python3 tools/source-root-blocker-emitter.py \
	  --input "$(INPUT)" \
	  --out "$(OUT)" \
	  $(if $(JSONL),--jsonl) \
	  $(if $(OCCURRED_AT),--occurred-at "$(OCCURRED_AT)") \
	  $(if $(SOURCE_PATH),--source-path "$(SOURCE_PATH)")

local-corpus-commit-ref-inventory:
	@if [ -z "$(INPUTS)" ] || [ -z "$(OUT)" ]; then \
	  echo 'Usage: make local-corpus-commit-ref-inventory INPUTS="<paths...>" OUT=<inventory.json> [MAX_FILES=<n>] [MAX_BYTES_PER_FILE=<n>] [MAX_ROWS=<n>]'; exit 2; fi
	@python3 tools/local-corpus-commit-ref-inventory.py \
	  $(INPUTS) \
	  --out "$(OUT)" \
	  $(if $(MAX_FILES),--max-files "$(MAX_FILES)") \
	  $(if $(MAX_BYTES_PER_FILE),--max-bytes-per-file "$(MAX_BYTES_PER_FILE)") \
	  $(if $(MAX_ROWS),--max-rows "$(MAX_ROWS)")

scanner-wiring-truth-inventory:
	@if [ -z "$(OUT)" ]; then \
	  echo 'Usage: make scanner-wiring-truth-inventory OUT=<inventory.json> [REPO_ROOT=<path>] [LIMIT=<n>]'; exit 2; fi
	@python3 tools/scanner-wiring-truth-inventory.py \
	  "$(if $(REPO_ROOT),$(REPO_ROOT),.)" \
	  --json-out "$(OUT)" \
	  $(if $(LIMIT),--limit "$(LIMIT)")

base-scan-preflight:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make base-scan-preflight WS=<workspace> [SMART_CONTRACT_ROOT=<path>] [RUST_DLT_ROOT=<path>] [JSON=1]'; exit 2; fi
	@python3 tools/base-scan-preflight.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(SMART_CONTRACT_ROOT),--smart-contract-root "$(SMART_CONTRACT_ROOT)") \
	  $(if $(RUST_DLT_ROOT),--rust-dlt-root "$(RUST_DLT_ROOT)") \
	  $(if $(JSON),--print-json)

base-scan-preflight-test:
	@python3 -m unittest tools.tests.test_base_scan_preflight

rust-scan-readiness:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-scan-readiness WS=<workspace> [STRICT=1] [OUT=<dir>]'; exit 2; fi
	@bash tools/rust-scan-runner.sh "$(_WS_RESOLVED)" \
	  --readiness \
	  $(if $(STRICT),--strict) \
	  $(if $(OUT),--out "$(OUT)")

# SPARK-GAP-001 - Go-source pattern scanner (Phase B seed: 3 of 10 patterns).
# Skips cleanly when no .go files are present (no foot-gun for non-Go ws).
.PHONY: scan-go scan-go-test
scan-go:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make scan-go WS=<workspace> [GUARD=<name>] [PRINT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "scan-go" "$(_WS_RESOLVED)"
	@python3 tools/go-detector-runner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(GUARD),--guard-name "$(GUARD)") \
	  $(if $(PRINT),--print)

scan-go-test:
	@python3 -m unittest tools.tests.test_go_detector_runner -v

# L13 - Rust-source pattern scanner. Bootstraps two Frost detectors
# (PoI-eligible per CLAUDE.md "Spark Primacy of Impact"): DKG self-identifier
# in round packages, and aggregate under-threshold signature shares.
# Skips cleanly when no .rs files are present (no foot-gun for non-Rust ws).
.PHONY: scan-rust scan-rust-test rust-scan-ingest rust-scan-ingest-test
scan-rust:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make scan-rust WS=<workspace> [STRICT=1] [PRINT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "scan-rust" "$(_WS_RESOLVED)"
	@python3 tools/rust-detector-runner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(PRINT),--print)
	@if [ -n "$(STRICT)" ]; then \
	  hits=$$(python3 -c "import json,sys; d=json.load(open('$(_WS_RESOLVED)/.auditooor/rust_findings.json')); print(d['totals']['hits'])"); \
	  if [ "$$hits" != "0" ]; then \
	    echo "[scan-rust] STRICT=1 fail: $$hits rust pattern hit(s)"; exit 1; \
	  fi; \
	fi

scan-rust-test:
	@python3 -m unittest tools.tests.test_rust_detector_runner -v

# rust-proptest-engine - Rust DYNAMIC deep-engine layer (the non-EVM half).
# Runs the target's OWN proptest suite (proptest-impl feature) as a bounded
# property-based fuzzer and emits a fuzz_runs/<ts>/manifest.json. A proptest
# FAILURE = counterexample = Critical-class candidate. On Rust consensus/crypto
# targets (Zebra, FROST, near-vm) this is the engine that makes a "no Critical"
# verdict trustworthy instead of detectors-found-nothing. Mirrors the EVM
# medusa/echidna runner (tools/fuzz-runner.sh) for non-Solidity targets.
.PHONY: rust-proptest-engine rust-proptest-engine-test
rust-proptest-engine:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-proptest-engine WS=<workspace> [PACKAGE=<crate>] [CASES=64] [TIMEOUT=1800] [FEATURE=proptest-impl] [DRY=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "rust-proptest-engine" "$(_WS_RESOLVED)"
	@bash tools/rust-proptest-engine-runner.sh "$(_WS_RESOLVED)" \
	  $(if $(PACKAGE),--package $(PACKAGE)) \
	  $(if $(CASES),--cases $(CASES)) \
	  $(if $(TIMEOUT),--timeout $(TIMEOUT)) \
	  $(if $(FEATURE),--feature $(FEATURE)) \
	  $(if $(DRY),--dry-run)

rust-proptest-engine-test:
	@bash tools/tests/test_rust_proptest_engine_runner.sh

# rust-scan-ingest - unified Rust findings ingest (Wave-5 Track K-Rust step 3).
#
# Chains: rust-scan.sh (7 layers) -> rust-detector-runner.py (wave1)
#         -> rust-scanner-ingest.py (unified JSON)
#
# Usage:
#   make rust-scan-ingest WS=<workspace>
#
# Output: <ws>/.auditooor/rust_findings_unified.json
rust-scan-ingest:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-scan-ingest WS=<workspace>'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "rust-scan-ingest" "$(_WS_RESOLVED)"
	@bash tools/rust-scan.sh "$(_WS_RESOLVED)"
	@python3 tools/rust-detector-runner.py --workspace "$(_WS_RESOLVED)"
	@python3 tools/rust-scanner-ingest.py --workspace "$(_WS_RESOLVED)" $(if $(NO_ENRICH),--no-enrich)

rust-scan-ingest-test:
	@python3 -m unittest tools.tests.test_rust_scanner_ingest -v

rust-base-readiness:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make rust-base-readiness WS=<workspace> [BASE_ROOT=<path>] [SMART_CONTRACT_ROOT=<path>] [RUST_ROOT=<path>] [RETH_ROOT=<path>] [TEE_ROOT=<path>] [ZK_ROOT=<path>] [RUSTBUGS_ROOT=<path>] [ZKBUGS_ROOT=<path>] [JSON=1]'; exit 2; fi
	@python3 tools/rust-base-readiness.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(BASE_ROOT),--base-root "$(BASE_ROOT)") \
	  $(if $(SMART_CONTRACT_ROOT),--smart-contract-root "$(SMART_CONTRACT_ROOT)") \
	  $(if $(RUST_ROOT),--rust-root "$(RUST_ROOT)") \
	  $(if $(RETH_ROOT),--reth-root "$(RETH_ROOT)") \
	  $(if $(TEE_ROOT),--tee-root "$(TEE_ROOT)") \
	  $(if $(ZK_ROOT),--zk-root "$(ZK_ROOT)") \
	  $(if $(RUSTBUGS_ROOT),--rustbugs-root "$(RUSTBUGS_ROOT)") \
	  $(if $(ZKBUGS_ROOT),--zkbugs-root "$(ZKBUGS_ROOT)") \
	  $(if $(JSON),--print-json)

rust-base-readiness-test:
	@python3 -m unittest tools.tests.test_rust_base_readiness

big-loss-template-compose:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make big-loss-template-compose WS=<workspace> [ROW=<id>] [TEMPLATE=<id>] [STRICT=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "big-loss-template-compose" "$(_WS_RESOLVED)"
	@python3 tools/big-loss-template-compose.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(ROW),--row "$(ROW)") $(if $(TEMPLATE),--template "$(TEMPLATE)") $(if $(STRICT),--strict)

big-loss-template-compose-test:
	@python3 -m unittest tools.tests.test_big_loss_template_compose

# Phase F - big-loss-template-runner
# Usage: make big-loss-template-runner WS=<workspace> [TEMPLATE=<id>]
.PHONY: big-loss-template-runner big-loss-template-runner-test
big-loss-template-runner:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make big-loss-template-runner WS=<workspace> [TEMPLATE=<id>]'; exit 2; fi
	@python3 tools/big-loss-template-runner.py --workspace "$(WS)" \
	  $(if $(TEMPLATE),--template "$(TEMPLATE)")

big-loss-template-runner-test:
	@python3 -m unittest tools.tests.test_big_loss_template_runner

.PHONY: draft-rust-dlt-filing
draft-rust-dlt-filing:
	@if [ -z "$(WS)" ] || [ -z "$(CAND)" ] || [ -z "$(OUT)" ]; then \
	  echo "Usage: make draft-rust-dlt-filing WS=<workspace> CAND=<candidate.json> OUT=<draft.md>"; \
	  exit 2; \
	fi
	python3 tools/draft-rust-dlt-filing.py --workspace $(WS) --candidate $(CAND) --template reference/big_loss_templates/rust_dlt_state_divergence.json --output $(OUT)

draft-rust-dlt-filing-test:
	@python3 -m unittest tools.tests.test_draft_rust_dlt_filing

# ─── Lane 9 corpus-mining commitments (PR #658 Tier-B #15) ──────────────────
# defimon staleness check: reports fresh/stale; exit 1 if stale (soft-dep via || true)
defimon-staleness-check:
	@python3 tools/defimon-staleness-check.py \
	  --registry reference/corpus_registry.json \
	  --slug defimon

# emit/update big_loss_templates registry row for a workspace
big-loss-template-emit:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make big-loss-template-emit WS=<workspace> [WRITE_MANIFEST=1]'; exit 2; fi
	@python3 tools/big-loss-template-registry-emit.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --apply \
	  $(if $(WRITE_MANIFEST),--write-manifest)

# regression tests for Lane 9 deliverables
lane9-commitments-test:
	@python3 -m unittest tools.tests.test_lane9_commitments -v

audit-asset-test:
	@if [ -z "$(ASSET)" ] || [ -z "$(INSERT_INTO)" ] || [ -z "$(MARKER)" ] || [ -z "$(TEST_FILE)" ] || [ -z "$(RUN)" ] || [ -z "$(CAPTURE)" ]; then \
	  echo "Usage: make audit-asset-test ASSET=... INSERT_INTO=... MARKER=... TEST_FILE=... RUN=... CAPTURE=..."; \
	  exit 2; \
	fi
	python3 tools/audit-asset-test-runner.py --asset-repo $(ASSET) --insert-into $(INSERT_INTO) --insert-marker $(MARKER) --test-file $(TEST_FILE) --run $(RUN) --capture $(CAPTURE)

audit-asset-test-test:
	@python3 -m unittest tools.tests.test_audit_asset_test_runner

# Worker-DD Phase A - Go-language findings corpus validator
# (CODEX_SPARK_HANDOFF_PLAN_2026-05-06.md addendum, Phase A).
findings-go-validate:
	@python3 tools/findings-go-corpus.py $(if $(JSON),--json) $(if $(PATH_OVERRIDE),--path $(PATH_OVERRIDE))

findings-go-validate-test:
	@python3 -m unittest tools.tests.test_findings_go_corpus -v

findings-solidity-validate:
	@python3 tools/findings-solidity-corpus.py $(if $(JSON),--json) $(if $(PATH_OVERRIDE),--path $(PATH_OVERRIDE))

findings-solidity-validate-test:
	@python3 -m unittest tools.tests.test_findings_solidity_corpus -v

# Worker-KK loop-8 - Tier-6 GitHub-commits mining smoke check.
# Validates the schema of the curated centrifuge-v3 git-mining report.
# Stdlib-only; no network calls (the JSON file was produced by a prior
# `gh api` run committed to reports/).
git-commits-mining-test:
	@python3 -m unittest tools.tests.test_git_commits_mining -v

# DETECTOR-CODIFY-1 Pattern 1 - Tier-6 backward-mine class (b) detector.
# Mines the workspace's upstream repo for revert-class commits whose body
# contains a `Revert "..."` header AND whose diff removes a function or
# modifier definition that does not exist at the audit pin. Surfaces the
# RG-N6-S1 pattern (Reserve Governor optimistic-veto bypass) mechanically.
.PHONY: reverted-guard-mine reverted-guard-mine-test
reverted-guard-mine:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make reverted-guard-mine WS=<workspace> [PIN=<sha>] [WINDOW=60] [REPO_DIR=<dir>] [OUT=<json>]'; exit 2; fi
	@python3 tools/reverted-guard-mine.py \
	  --workspace "$(WS)" \
	  $(if $(PIN),--audit-pin "$(PIN)",) \
	  $(if $(WINDOW),--backward-window "$(WINDOW)",) \
	  $(if $(REPO_DIR),--repo-dir "$(REPO_DIR)",) \
	  $(if $(OUT),--out "$(OUT)",) \
	  --print-summary

reverted-guard-mine-test:
	@python3 -m unittest tools.tests.test_reverted_guard_mine -v

# ─── corpus-registry ─────────────────────────────────────────────────────────
# Indexes all reference/patterns.dsl.r94_solodit_* corpus directories into
# reference/corpus_registry.json so tools can query corpus inventory without
# re-scanning the filesystem.
.PHONY: section-sources-collision-check corpus-registry corpus-registry-test
corpus-registry:
	@python3 tools/corpus-registry-build.py

corpus-registry-test:
	@python3 -m unittest tools.tests.test_corpus_registry_build -v

# ─── agent-recall-detector-loop ──────────────────────────────────────────────
# 5-stage orchestrator: agent-found bug → queue → dispatcher → detector-authoring
# brief → fixture skeleton → wave-promotion check (ROADMAP item #9,
# docs/MCP_HARNESS_REVIEW_2026-05-09_FINAL.md row 136).
.PHONY: agent-recall-detector-loop agent-recall-detector-loop-test

agent-recall-detector-loop:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make agent-recall-detector-loop WS=<workspace> [DRY_RUN=1] [LANG=solidity] [STAGE=1-5]'; exit 2; fi
	@python3 tools/agent-recall-detector-loop.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(LANG),--lang "$(LANG)") \
	  $(if $(STAGE),--stage "$(STAGE)") \
	  $(if $(SEED_FIXTURES),--seed-fixtures) \
	  $(if $(JSON),--json) \
	  ; rc=$$?; if [ $$rc -eq 1 ]; then echo '[agent-recall-detector-loop] no detector tasks (rc=1 is nominal)'; exit 0; else exit $$rc; fi

agent-recall-detector-loop-test:
	@python3 -m unittest tools.tests.test_agent_recall_detector_loop -v

.PHONY: cross-ws-ledger-emit cross-ws-ledger-emit-test spark-cargo-fork-status

# Tier-C #5 (PR #658) - Spark FROST signer Cargo fork-ancestry wrapper (L28-E).
# Runs cargo-fork-ancestry-check against ~/audits/spark/external/spark/signer
# and classifies diverged deps by crypto-primitive / RPC / DB crate family.
# Usage:
#   make spark-cargo-fork-status
#   make spark-cargo-fork-status WS=<alt-signer-path>
#   make spark-cargo-fork-status STRICT=1
spark-cargo-fork-status: ## Run cargo-fork-ancestry against Spark FROST workspace + classify
	@python3 tools/spark-cargo-fork-status.py \
	  $(if $(WS),--workspace $(WS)) \
	  $(if $(filter 1,$(STRICT)),--strict) \
	  $(if $(AUDIT_PIN),--audit-pin $(AUDIT_PIN)) \
	  $(if $(filter 1,$(JSON)),--json)

# ─── defihack-match ───────────────────────────────────────────────────────────
# Phase G (corpus-mining plan 2026-05-08): DeFiHackLabs catalog → candidate
# detector seeds via grep_predicates scan.
# Usage:
#   make defihack-match WS=.
#   make defihack-match WS=~/audits/spark
#   make defihack-match WS=. CATALOG=defihacklabs/catalog.yaml
.PHONY: defihack-match defihack-match-test audit-pdf-mining audit-pdf-mining-test
defihack-match: ## Scan workspace against DeFiHackLabs attack-class catalog
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make defihack-match WS=<workspace> [CATALOG=<path>] [QUIET=1]'; exit 2; fi
	@python3 tools/defihack-class-matcher.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(CATALOG),--catalog "$(CATALOG)") \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(filter 1,$(QUIET)),--quiet)

defihack-match-test:
	@python3 -m unittest tools.tests.test_defihack_class_matcher -v

# ─── attack-class-rank ────────────────────────────────────────────────────────
# Local advisory attack-class hypothesis ranker. This is the operator-facing
# wrapper for tools/attack-class-ranker.py; it uses only checked-in local corpus
# metadata unless PATTERNS_DIR or DEFIHACK_CATALOG is explicitly supplied.
# Usage:
#   make attack-class-rank DETECTOR=<slug> FILE=<path> FUNC=<name> CONTEXT='<notes>' PRETTY=1
#   make attack-class-rank FILE=src/Vault.sol FUNC_SIG='function withdraw(uint256)' CONTEXT='shares rounding' TOP_N=5 OUT=/tmp/ac.json
.PHONY: attack-class-rank
attack-class-rank:
	@if [ -z "$(DETECTOR)$(FILE)$(FUNC_SIG)$(FUNC)$(LANGUAGE)$(CONTEXT)" ]; then \
	  echo 'Usage: make attack-class-rank [DETECTOR=<slug>] [FILE=<path>] [FUNC=<name>] [FUNC_SIG=<signature>] [LANGUAGE=<language>] [CONTEXT="<notes>"] [TOP_N=<n>] [OUT=<path>] [PRETTY=1]'; exit 2; \
	fi
	@if [ -n "$(OUT)" ]; then mkdir -p "$$(dirname "$(OUT)")"; fi
	@python3 tools/attack-class-ranker.py \
	  $(if $(DETECTOR),--detector-slug "$(DETECTOR)") \
	  $(if $(FILE),--file-path "$(FILE)") \
	  $(if $(LANGUAGE),--language "$(LANGUAGE)") \
	  $(if $(FUNC_SIG),--function-signature "$(FUNC_SIG)") \
	  $(if $(FUNC),--function-name "$(FUNC)") \
	  $(if $(CONTEXT),--context "$(CONTEXT)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(PATTERNS_DIR),--patterns-dir "$(PATTERNS_DIR)") \
	  $(if $(DEFIHACK_CATALOG),--defihack-catalog "$(DEFIHACK_CATALOG)") \
	  $(if $(PRETTY),--pretty) \
	  $(if $(OUT),> "$(OUT)")
	@if [ -n "$(OUT)" ]; then echo "[make attack-class-rank] wrote $(OUT)"; fi

# Local advisory detector-hit -> attacker action graph bridge. This is the
# operator-facing wrapper for tools/detector-hit-action-graph.py. It consumes a
# single detector hit or the first matching engage_report.json cluster and emits
# attacker steps plus proof obligations. It never claims exploitability.
# Usage:
#   make detector-hit-action-graph WS=<workspace> DETECTOR=<slug> FILE=<path> CONTEXT='<notes>' PRETTY=1
#   make detector-hit-action-graph WS=<workspace> HIT_INDEX=0 OUT=<workspace>/.auditooor/detector_action_graph.json
.PHONY: detector-hit-action-graph
detector-hit-action-graph:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make detector-hit-action-graph WS=<workspace> [DETECTOR=<slug>] [HIT_INDEX=<n>] [FILE=<path>] [FUNC=<name>] [FUNC_SIG=<signature>] [LANGUAGE=<language>] [CONTEXT="<notes>"] [OUT=<path>] [PRETTY=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make detector-hit-action-graph" "$(_WS_RESOLVED)"
	@if [ -n "$(OUT)" ]; then mkdir -p "$$(dirname "$(OUT)")"; fi
	@python3 tools/detector-hit-action-graph.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(ENGAGE_REPORT),--engage-report "$(ENGAGE_REPORT)") \
	  $(if $(HIT_INDEX),--hit-index "$(HIT_INDEX)") \
	  $(if $(DETECTOR),--detector-slug "$(DETECTOR)") \
	  $(if $(FILE),--file-path "$(FILE)") \
	  $(if $(LANGUAGE),--language "$(LANGUAGE)") \
	  $(if $(FUNC_SIG),--function-signature "$(FUNC_SIG)") \
	  $(if $(FUNC),--function-name "$(FUNC)") \
	  $(if $(CONTEXT),--context "$(CONTEXT)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(PRETTY),--pretty) \
	  $(if $(PRINT_JSON),--print-json)
	@if [ -n "$(OUT)" ]; then echo "[make detector-hit-action-graph] wrote $(OUT)"; fi

.PHONY: audit-hacker-logic-bridge
audit-hacker-logic-bridge:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-hacker-logic-bridge WS=<workspace> [HIT_INDEX=<n>] [MAX_HITS=<n>] [MAX_TASKS=<n>] [PRIORITY_MODE=auto|input|dydx] [TARGET_REPO=owner/repo] [LANGUAGE=go]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make audit-hacker-logic-bridge" "$(_WS_RESOLVED)"
	@python3 tools/audit-hacker-logic-bridge.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(HIT_INDEX),--hit-index "$(HIT_INDEX)") \
	  $(if $(MAX_HITS),--max-hits "$(MAX_HITS)") \
	  $(if $(MAX_TASKS),--max-tasks "$(MAX_TASKS)") \
	  $(if $(PRIORITY_MODE),--priority-mode "$(PRIORITY_MODE)") \
	  $(if $(TARGET_REPO),--target-repo "$(TARGET_REPO)") \
	  $(if $(LANGUAGE),--language "$(LANGUAGE)") \
	  $(if $(filter 1 true TRUE yes YES,$(STRICT)),--strict)
	@if [ -s "$(_WS_RESOLVED)/.auditooor/audit_hacker_logic_bridge.json" ]; then \
	  echo "[make audit-hacker-logic-bridge] wrote $(_WS_RESOLVED)/.auditooor/audit_hacker_logic_bridge.json"; \
	fi
	@python3 tools/proof-queue-freshness-marker.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --mode mark-fresh \
	  --bridge-rc 0 \
	  --reason "audit-hacker-logic-bridge completed directly" >/dev/null || \
	  echo "[make audit-hacker-logic-bridge] WARN failed to mark proof queue freshness" >&2

.PHONY: mined-findings-hunter-bridge mined-findings-hunter-bridge-test
mined-findings-hunter-bridge:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make mined-findings-hunter-bridge WS=<workspace> [GENERATED_AT=<iso8601>] [LIMIT=50] [MAX_CORPUS_RECORDS=2500] [JSON=1|PRINT_JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make mined-findings-hunter-bridge" "$(_WS_RESOLVED)"
	@if [ ! -f tools/mined-findings-hunter-bridge.py ]; then \
	  echo "[make mined-findings-hunter-bridge] ERR missing tools/mined-findings-hunter-bridge.py; coordinator must land the standalone CLI before this target can run"; exit 2; \
	fi
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@set -e; \
	bridge_out="$(_WS_RESOLVED)/.auditooor/mined_findings_hunter_bridge.json"; \
	obligations_out="$(_WS_RESOLVED)/.auditooor/mined_findings_hunter_obligations.jsonl"; \
	python3 tools/mined-findings-hunter-bridge.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(MAX_CORPUS_RECORDS),--max-corpus-records "$(MAX_CORPUS_RECORDS)") \
	  $(if $(MIN_CORPUS_RELEVANCE),--min-corpus-relevance "$(MIN_CORPUS_RELEVANCE)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)") \
	  $(if $(or $(JSON),$(PRINT_JSON)),--json); \
	if [ -s "$(_WS_RESOLVED)/.auditooor/hacker_question_obligations.jsonl" ]; then \
	  echo "[make mined-findings-hunter-bridge] updated $(_WS_RESOLVED)/.auditooor/hacker_question_obligations.jsonl"; \
	fi ; \
	if [ -s "$$bridge_out" ]; then echo "[make mined-findings-hunter-bridge] wrote $$bridge_out"; fi; \
	if [ -s "$$obligations_out" ]; then echo "[make mined-findings-hunter-bridge] wrote $$obligations_out"; fi

mined-findings-hunter-bridge-test:
	@python3 -m unittest tools.tests.test_mined_findings_hunter_bridge -v

# Local advisory detector provenance resolver. Maps a detector id to its local
# implementation path, source refs, fixture manifests, and focused tests using
# only checked-in repo metadata.
# Usage:
#   make detector-provenance-v2 DETECTOR=<id>
#   make detector-provenance-v2 DETECTOR=rust.frost.wave2.nonce_reuse_risk_unscoped_secret REPO_ROOT=. OUT=/tmp/prov.json PRETTY=1
.PHONY: detector-provenance-v2
detector-provenance-v2:
	@if [ -z "$(DETECTOR)" ]; then \
	  echo 'Usage: make detector-provenance-v2 DETECTOR=<id> [REPO_ROOT=<path>] [OUT=<path>] [PRETTY=1]'; exit 2; \
	fi
	@if [ -n "$(OUT)" ]; then mkdir -p "$$(dirname "$(OUT)")"; fi
	@repo_root="$(if $(REPO_ROOT),$(REPO_ROOT),.)"; \
	if [ -n "$(OUT)" ]; then \
	  python3 tools/detector-provenance-v2.py --repo-root "$$repo_root" --detector-id "$(DETECTOR)" > "$(OUT)"; \
	  echo "[make detector-provenance-v2] wrote $(OUT)"; \
	elif [ -n "$(PRETTY)" ]; then \
	  python3 tools/detector-provenance-v2.py --repo-root "$$repo_root" --detector-id "$(DETECTOR)" | python3 -m json.tool; \
	else \
	  python3 tools/detector-provenance-v2.py --repo-root "$$repo_root" --detector-id "$(DETECTOR)"; \
	fi

# ─── case-study-class-match ───────────────────────────────────────────────────
# Phase E1 (corpus-mining plan 2026-05-08): case_study/*.md frontmatter →
# class-matcher predicates for a given workspace asset class.
# Usage:
#   make case-study-class-match CLASS=bridge
#   make case-study-class-match CLASS=lending TOP=5
#   make case-study-class-match CLASS=prediction-market JSON=1
.PHONY: case-study-class-match case-study-class-match-test
case-study-class-match: ## Match case studies to a workspace asset class (Phase E1 corpus mining)
	@if [ -z "$(CLASS)" ]; then \
	  echo 'Usage: make case-study-class-match CLASS=<class> [TOP=N] [JSON=1] [CASE_STUDY_DIR=<path>]'; exit 2; fi
	@python3 tools/case-study-class-matcher.py \
	  --class "$(CLASS)" \
	  $(if $(TOP),--top $(TOP)) \
	  $(if $(filter 1,$(JSON)),--json) \
	  $(if $(CASE_STUDY_DIR),--case-study-dir "$(CASE_STUDY_DIR)")

case-study-class-match-test:
	@python3 -m unittest tools.tests.test_case_study_class_matcher -v

# ─── audit-pdf-mining ─────────────────────────────────────────────────────────
# Phase D (corpus-mining plan 2026-05-08): mine audit PDFs / pre-extracted .txt
# siblings across ~/audits/*/prior_audits/ and adjacent dirs, emitting
# *.yaml.candidate files under reference/patterns.dsl/r99_pdf_mined/.
# Operator graduates candidates manually (never auto-promoted to .yaml).
# Usage:
#   make audit-pdf-mining
#   make audit-pdf-mining INPUT_DIR=~/audits/morpho MIN_PDFS=0 MIN_CANDS=0
.PHONY: audit-pdf-mining audit-pdf-mining-test
audit-pdf-mining: ## Mine audit PDFs/TXTs → *.yaml.candidate (Phase D corpus mining)
	@python3 tools/audit-pdf-to-patterns.py \
	  $(if $(INPUT_DIR),--input-dir "$(INPUT_DIR)") \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(MIN_PDFS),--min-pdfs $(MIN_PDFS)) \
	  $(if $(MIN_CANDS),--min-candidates $(MIN_CANDS)) \
	  $(if $(filter 1,$(QUIET)),--quiet)

audit-pdf-mining-test:
	@python3 -m unittest tools.tests.test_audit_pdf_to_patterns -v

# ─── W2 plan 07 §11a - discoverability + adversarial + brief targets ─────────
# Added by spark-hunt iter 19 SP-C lane. Wraps existing tools where present;
# discoverability-refresh warns-and-noops until tools/mcp-search-index-rebuild.py
# ships.

.PHONY: hackerman-refresh hackerman-etl hackerman-index hackerman-refresh-test hackerman-etl-wave-1-3-4
hackerman-refresh: hackerman-etl-wave-1-3-4
	@python3 tools/hackerman-etl-refresh.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(INDEX_DIR),--index-dir "$(INDEX_DIR)") \
	  $(if $(QUALITY_OUT),--quality-out "$(QUALITY_OUT)") \
	  $(if $(CROSS_LANGUAGE_OUT),--cross-language-out "$(CROSS_LANGUAGE_OUT)") \
	  $(if $(REPORTS_DIR),--reports-dir "$(REPORTS_DIR)") \
	  $(if $(CORPUS_DIR),--corpus-dir "$(CORPUS_DIR)") \
	  $(if $(AUDITS_ROOT),--audits-root "$(AUDITS_ROOT)") \
	  $(foreach dir,$(PATTERNS_DIRS),--patterns-dir "$(dir)") \
	  $(foreach dir,$(PATTERN_DSL_DIRS),--dsl-dir "$(dir)") \
	  $(foreach dir,$(SOLODIT_SPEC_DIRS),--solodit-spec-dir "$(dir)") \
	  $(foreach path,$(FINDINGS_GO_PATHS),--findings-go-path "$(path)") \
	  $(foreach ws,$(WORKSPACES),--workspace "$(ws)") \
	  $(if $(STAGE_DIR),--stage-dir "$(STAGE_DIR)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(NO_PRESERVE),--no-preserve-existing) \
	  $(if $(SKIP_VERDICT_TAGS),--skip-verdict-tags) \
	  $(if $(SKIP_GIT_MINING),--skip-git-mining) \
	  $(if $(SKIP_CORPUS_MINED),--skip-corpus-mined) \
	  $(if $(SKIP_SOLODIT_SPECS),--skip-solodit-specs) \
	  $(if $(SKIP_FINDINGS_GO),--skip-findings-go) \
	  $(if $(SKIP_SOLIDITY_FORK_PATTERNS),--skip-solidity-fork-patterns) \
	  $(if $(INCLUDE_PATTERN_DSL),--include-pattern-dsl) \
	  $(if $(SKIP_PRIOR_AUDITS),--skip-prior-audits) \
	  $(if $(SKIP_FINDINGS_TO_INVARIANTS),--skip-findings-to-invariants) \
	  $(if $(FINDINGS_INVARIANTS_ROOT),--findings-invariants-root "$(FINDINGS_INVARIANTS_ROOT)")

hackerman-etl: hackerman-refresh

# ─── findings -> invariant fuel lift (FIX: findings-to-invariant-fuel-wiring)
# Standalone wrapper for the 2-step CHAIN that turns NEW corpus findings into
# per-fn invariant fuel (the file corpus-driven-hunt.py loads at :123):
#   1. tools/llm-extract-invariants.py --mode hand-extract --incremental
#      (deterministic, watermark-scoped to findings newer than the last run)
#      -> appends to audit/corpus_tags/derived/invariants_extracted.jsonl
#   2. tools/lane-invariant-audit-ext.py -> lifts the audited (non-quarantine)
#      rows into invariants_pilot_audited.jsonl (the fuel). The audit-ext
#      quarantine classifier is the R80 guard: vacuous/malformed invariants are
#      marked FALSE-POSITIVE and never become fuel.
# hackerman-refresh runs this same chain automatically after the index rebuild;
# this target re-runs it on demand without a full ETL pass.
# Override the index via INDEX=<path> and the fuel root via ROOT=<path>.
.PHONY: findings-to-invariants
findings-to-invariants:
	@index="$(if $(INDEX),$(INDEX),audit/corpus_tags/index/by_attack_class.jsonl)"; \
	root="$(if $(ROOT),$(ROOT),.)"; \
	derived="$$root/audit/corpus_tags/derived"; \
	records="$(if $(RECORDS_CAP),$(RECORDS_CAP),50000)"; \
	echo "[findings-to-invariants] index=$$index derived=$$derived records_cap=$$records"; \
	python3 tools/llm-extract-invariants.py \
	  --mode hand-extract --incremental \
	  --records "$$records" \
	  --index "$$index" \
	  --output "$$derived/invariants_extracted.jsonl" \
	  --failed "$$derived/invariants_failed_extract.jsonl" \
	  --watermark "$$derived/.invariant_extract_watermark" || exit $$?; \
	python3 tools/lane-invariant-audit-ext.py --root "$$root" || exit $$?; \
	echo "[findings-to-invariants] DONE"

.PHONY: findings-to-invariants-test
findings-to-invariants-test:
	@python3 -m unittest tools.tests.test_findings_to_invariant_fuel_wiring -v

# ─── Wave-1 / Wave-3 / Wave-4 ETL miners (PR #726, wired by EXEC-WAVE7-MAKE-AUDIT-DEEP-WIRING)
# Runs the 17 ETL miners shipped in PR #726 in sequence. Default is DRY-RUN
# (--dry-run flag passed); set APPLY=1 to actually write YAML records.
# Output directory defaults to audit/corpus_tags/tags (matches hackerman-etl-refresh.py
# DEFAULT_TAG_DIR); override via OUT_DIR=<path>.
# Two miners (starknet-cairo, platforms) require additional inputs:
#   STARKNET_WORKSPACES="ws1 ws2"      passes each as --workspace
#   STARKNET_SOURCE_FILES="f1 f2"      passes each as --source-file
#   PLATFORM_MIRRORS="cantina=PATH cyfrin=PATH ..."   passes each as --platform-mirror
# When no inputs are supplied, those two miners are skipped (printed as
# "SKIP - no inputs"). All other miners run unconditionally.
# Per-miner LIMIT override available via WAVE_ETL_LIMIT=<n>.
hackerman-etl-wave-1-3-4:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags)"; \
	mkdir -p "$$out_dir"; \
	dry_flag="$(if $(APPLY),,--dry-run)"; \
	limit_flag="$(if $(WAVE_ETL_LIMIT),--limit $(WAVE_ETL_LIMIT),)"; \
	echo "[hackerman-etl-wave-1-3-4] out_dir=$$out_dir mode=$(if $(APPLY),APPLY,dry-run) limit=$(if $(WAVE_ETL_LIMIT),$(WAVE_ETL_LIMIT),unbounded)"; \
	rc=0; \
	for miner in \
	  hackerman-etl-from-vyper-cve.py \
	  hackerman-etl-from-sui-move.py \
	  hackerman-etl-from-aptos-move.py \
	  hackerman-etl-from-eth-client-rust.py \
	  hackerman-etl-from-l2-zkrollup.py \
	  hackerman-etl-from-substrate-cosmwasm-frost.py \
	  hackerman-etl-from-mev-flashloan.py \
	  hackerman-etl-from-zkbugs-catalog.py \
	  hackerman-etl-from-zk-auditor-reports.py \
	  hackerman-etl-from-zk-contests.py \
	  hackerman-etl-from-evm-proxy-upgrade.py \
	  hackerman-etl-from-bridge-attacks.py \
	  hackerman-etl-from-near-ink.py \
	  hackerman-etl-from-graph-protocol-sources.py \
	  hackerman-go-cosmos-expand.py \
	  hackerman-etl-from-sig-extracts.py \
	  hackerman-etl-from-substrate-fix-history.py \
	  hackerman-etl-from-substrate-cosmwasm.py \
	  hackerman-etl-from-vyper-compiler-fix-history.py ; do \
	  echo "[hackerman-etl-wave-1-3-4] RUN tools/$$miner"; \
	  python3 tools/$$miner --out-dir "$$out_dir" $$dry_flag $$limit_flag || { echo "[hackerman-etl-wave-1-3-4] FAIL tools/$$miner rc=$$?"; rc=1; }; \
	done; \
	if [ -n "$(STARKNET_WORKSPACES)$(STARKNET_SOURCE_FILES)" ]; then \
	  ws_args=""; for ws in $(STARKNET_WORKSPACES); do ws_args="$$ws_args --workspace $$ws"; done; \
	  sf_args=""; for sf in $(STARKNET_SOURCE_FILES); do sf_args="$$sf_args --source-file $$sf"; done; \
	  echo "[hackerman-etl-wave-1-3-4] RUN tools/hackerman-etl-from-starknet-cairo.py"; \
	  python3 tools/hackerman-etl-from-starknet-cairo.py --out-dir "$$out_dir" $$dry_flag $$limit_flag $$ws_args $$sf_args || { echo "[hackerman-etl-wave-1-3-4] FAIL hackerman-etl-from-starknet-cairo.py rc=$$?"; rc=1; }; \
	else \
	  echo "[hackerman-etl-wave-1-3-4] SKIP tools/hackerman-etl-from-starknet-cairo.py - no STARKNET_WORKSPACES / STARKNET_SOURCE_FILES inputs"; \
	fi; \
	if [ -n "$(PLATFORM_MIRRORS)" ]; then \
	  pm_args=""; for pm in $(PLATFORM_MIRRORS); do pm_args="$$pm_args --platform-mirror $$pm"; done; \
	  echo "[hackerman-etl-wave-1-3-4] RUN tools/hackerman-etl-from-platforms.py"; \
	  python3 tools/hackerman-etl-from-platforms.py --out-dir "$$out_dir" $$dry_flag $$limit_flag $$pm_args || { echo "[hackerman-etl-wave-1-3-4] FAIL hackerman-etl-from-platforms.py rc=$$?"; rc=1; }; \
	else \
	  echo "[hackerman-etl-wave-1-3-4] SKIP tools/hackerman-etl-from-platforms.py - no PLATFORM_MIRRORS inputs"; \
	fi; \
	zkbugs_ds="$(if $(ZKBUGS_DATASET_ROOT),$(ZKBUGS_DATASET_ROOT),tools/tests/fixtures/hackerman_etl_from_zkbugs_dataset)"; \
	echo "[hackerman-etl-wave-1-3-4] RUN tools/hackerman-etl-from-zkbugs-dataset.py (dataset-root=$$zkbugs_ds)"; \
	python3 tools/hackerman-etl-from-zkbugs-dataset.py --dataset-root "$$zkbugs_ds" --out-root "$$out_dir" $$dry_flag $$limit_flag || { echo "[hackerman-etl-wave-1-3-4] FAIL hackerman-etl-from-zkbugs-dataset.py rc=$$?"; rc=1; }; \
	echo "[hackerman-etl-wave-1-3-4] RUN tools/hackerman-etl-from-zebra-advisories.py"; \
	python3 tools/hackerman-etl-from-zebra-advisories.py --corpus-dir "$$out_dir" $$dry_flag || { echo "[hackerman-etl-wave-1-3-4] FAIL hackerman-etl-from-zebra-advisories.py rc=$$?"; rc=1; }; \
	echo "[hackerman-etl-wave-1-3-4] DONE rc=$$rc"; \
	exit $$rc

.PHONY: hackerman-etl-graph-protocol hackerman-etl-graph-protocol-test
# CAP-D4 lane: Graph Protocol detector-seed miner (real-source-only).
# Walks the past N commits of graphprotocol/* via `gh api` and emits
# tier-1/tier-2 hackerman records. Defaults to dry-run; pass APPLY=1 to
# write records. Out dir defaults to audit/corpus_tags/tags.
hackerman-etl-graph-protocol:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags)"; \
	mkdir -p "$$out_dir"; \
	dry_flag="$(if $(APPLY),,--dry-run)"; \
	limit_flag="$(if $(WAVE_ETL_LIMIT),--limit $(WAVE_ETL_LIMIT),)"; \
	echo "[hackerman-etl-graph-protocol] out_dir=$$out_dir mode=$(if $(APPLY),APPLY,dry-run)"; \
	python3 tools/hackerman-etl-from-graph-protocol-sources.py \
	  --out-dir "$$out_dir" $$dry_flag $$limit_flag --json-summary

hackerman-etl-graph-protocol-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_graph_protocol_sources

.PHONY: hackerman-etl-go-vuln-db hackerman-etl-go-vuln-db-test
# Wave-5 L1 lane: Go vulnerability database miner (vuln.go.dev), the
# direct RustSec analog for the Go ecosystem. NETWORK-DEPENDENT - requires
# --fetch for live I/O; without it (and without --cache-file) the miner
# emits BLOCKED-NO-REAL-SOURCE and zero records (honest-zero discipline).
# Deliberately NOT part of the offline hackerman-etl-wave-1-3-4 loop.
# Every emitted record carries verification_tier=tier-1-officially-disclosed
# and a canonical vuln.go.dev/ID/<GO-ID>.json record_source_url.
# Defaults to dry-run; pass APPLY=1 to write records. Pass FETCH=1 for the
# live pull, LIMIT_IDS=<n> to cap per-GO-ID fetches.
hackerman-etl-go-vuln-db:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags)"; \
	mkdir -p "$$out_dir"; \
	dry_flag="$(if $(APPLY),,--dry-run)"; \
	limit_flag="$(if $(WAVE_ETL_LIMIT),--limit $(WAVE_ETL_LIMIT),)"; \
	echo "[hackerman-etl-go-vuln-db] out_dir=$$out_dir mode=$(if $(APPLY),APPLY,dry-run) fetch=$(if $(FETCH),yes,no)"; \
	python3 tools/hackerman-etl-from-go-vuln-db.py \
	  --out-dir "$$out_dir" $$dry_flag $$limit_flag \
	  $(if $(FETCH),--fetch) $(if $(LIMIT_IDS),--limit-ids $(LIMIT_IDS)) --json-summary

hackerman-etl-go-vuln-db-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_go_vuln_db

.PHONY: hackerman-etl-swc-registry hackerman-etl-swc-registry-test
# Wave-5 L2 lane: SWC registry miner (SmartContractSecurity/SWC-registry),
# the canonical 37-entry Solidity weakness-class taxonomy. NETWORK-DEPENDENT
# - requires --fetch for live I/O; without it (and without --cache-file)
# the miner emits BLOCKED-NO-REAL-SOURCE and zero records (honest-zero
# discipline). Deliberately NOT part of the offline hackerman-etl-wave-1-3-4
# loop. Every emitted record carries
# verification_tier=tier-3-synthetic-taxonomy-anchored (the SWC registry is
# a taxonomy, not an individual-incident archive - tier-3 is honest) and a
# canonical github.com/SmartContractSecurity/SWC-registry blob
# record_source_url. Defaults to dry-run; pass APPLY=1 to write records,
# FETCH=1 for the live pull.
hackerman-etl-swc-registry:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags)"; \
	mkdir -p "$$out_dir"; \
	dry_flag="$(if $(APPLY),,--dry-run)"; \
	limit_flag="$(if $(WAVE_ETL_LIMIT),--limit $(WAVE_ETL_LIMIT),)"; \
	echo "[hackerman-etl-swc-registry] out_dir=$$out_dir mode=$(if $(APPLY),APPLY,dry-run) fetch=$(if $(FETCH),yes,no)"; \
	python3 tools/hackerman-etl-from-swc-registry.py \
	  --out-dir "$$out_dir" $$dry_flag $$limit_flag \
	  $(if $(FETCH),--fetch) --json-summary

hackerman-etl-swc-registry-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_swc_registry
.PHONY: hackerman-etl-onchain-traces hackerman-etl-onchain-traces-test
# Wave-5 L3 lane: on-chain exploit transaction trace miner. Real exploit
# call traces are the highest-signal corpus data - they show the actual
# attack call path, not a prose summary. NETWORK-DEPENDENT - requires
# --fetch for live I/O; without it (and without --cache-file) the miner
# emits BLOCKED-NO-REAL-SOURCE and zero records (honest-zero discipline).
# Seed tx hashes come ONLY from TX_HASHES=<file>, SEED_CORPUS=<dir>, or
# TX=<hash> (no training-data-recalled hashes). There is no key-free
# public decoded-trace API; a live run MUST pass API_BASE=<reachable
# trace endpoint>. Every emitted record carries
# verification_tier=tier-2-verified-public-archive and a resolvable trace
# URL. Defaults to dry-run; pass APPLY=1 to write records, FETCH=1 for
# the live pull.
hackerman-etl-onchain-traces:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/onchain_exploit_traces)"; \
	mkdir -p "$$out_dir"; \
	echo "[hackerman-etl-onchain-traces] out_dir=$$out_dir mode=$(if $(APPLY),APPLY,dry-run) fetch=$(if $(FETCH),yes,no)"; \
	python3 tools/hackerman-etl-from-onchain-traces.py \
	  --out-dir "$$out_dir" \
	  $(if $(APPLY),--apply) \
	  $(if $(TX),--tx $(TX)) \
	  $(if $(TX_HASHES),--tx-hashes $(TX_HASHES)) \
	  $(if $(SEED_CORPUS),--seed-corpus $(SEED_CORPUS)) \
	  $(if $(API_BASE),--api-base $(API_BASE)) \
	  $(if $(CACHE_FILE),--cache-file $(CACHE_FILE)) \
	  $(if $(WRITE_CACHE_FILE),--write-cache-file $(WRITE_CACHE_FILE)) \
	  $(if $(WAVE_ETL_LIMIT),--limit $(WAVE_ETL_LIMIT)) \
	  $(if $(FETCH),--fetch) --json-summary

hackerman-etl-onchain-traces-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_onchain_traces

.PHONY: hackerman-etl-audit-firm-blog hackerman-etl-audit-firm-blog-test
# W4.4 lane: audit-firm engineering-blog ETL into tier-2 records.
# NETWORK-DEPENDENT scraper - requires --source/--cache-dir/--fetch and
# --i-acknowledge-tos; deliberately NOT part of the offline wave-1-3-4
# loop. Run with SOURCE=<tob|spearbit|...> CACHE_DIR=<dir>.
hackerman-etl-audit-firm-blog:
	@if [ -z "$(SOURCE)" ] || [ -z "$(CACHE_DIR)" ]; then \
	  echo 'Usage: make hackerman-etl-audit-firm-blog SOURCE=<tob|spearbit|openzeppelin|chainsecurity|halborn|certik|cyfrin> CACHE_DIR=<dir> [OUT_DIR=<dir>] [FETCH=1]'; \
	  exit 2; \
	fi
	@python3 tools/hackerman-etl-from-audit-firm-blog.py \
	  --source "$(SOURCE)" --cache-dir "$(CACHE_DIR)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags)" \
	  $(if $(FETCH),--fetch --i-acknowledge-tos) --dry-run --json-summary

hackerman-etl-audit-firm-blog-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_blog

.PHONY: wave4-all-pairs-fp-matrix wave4-all-pairs-fp-matrix-test
# W4.3 lane: cross-workspace all-pairs FP transfer matrix. Derives
# FP-01..FP-06 seed sets per workspace and runs the universal FP runner
# against every target workspace. Defaults to ~/audits/* workspaces.
wave4-all-pairs-fp-matrix:
	@python3 tools/wave4-cross-workspace-all-pairs-fp-matrix.py \
	  $(if $(WORKSPACES_GLOB),--workspaces-glob "$(WORKSPACES_GLOB)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-markdown "$(OUT_MD)") \
	  $(if $(DRY_RUN),--dry-run)

wave4-all-pairs-fp-matrix-test:
	@python3 -m unittest tools.tests.test_wave4_cross_workspace_all_pairs_fp_matrix

.PHONY: validate-hackerman predicate-yaml-lint
# Validate hackerman_record YAMLs against the appropriate schema (v1 or v1.1).
# Auto-dispatches per record's `schema_version` field. Override TAG_DIR to
# point at a non-default corpus directory. Pass STRICT_ALL=1 to also validate
# non-hackerman YAML files (default skips them).
validate-hackerman:
	@python3 tools/hackerman-record-validate.py \
	  $(if $(TAG_DIR),--validate-dir "$(TAG_DIR)") \
	  $(if $(STRICT_ALL),--strict-all) \
	  $(if $(QUIET),--quiet)

# Advisory predicate YAML lint for DSL pattern keys/shapes. Defaults to
# reference/patterns.dsl and writes a markdown report; STRICT=1 promotes
# warnings to a nonzero exit for explicit cleanup gates.
predicate-yaml-lint:
	@python3 tools/predicate-yaml-lint.py \
	  $(if $(PATHS),$(PATHS),reference/patterns.dsl) \
	  $(if $(DIR),--dir "$(DIR)") \
	  --report "$(if $(REPORT),$(REPORT),reports/predicate_yaml_lint_phase_b_2026-05-17.md)" \
	  $(if $(filter 1 true yes on,$(STRICT)),--strict) \
	  $(PREDICATE_YAML_LINT_ARGS)

.PHONY: schema-tier-enum-validate
# Wave-2 W2.7.a (2026-05-16) gate: verifies the hackerman_record schemas
# accept `tier-2-verified-public-archive` as a record_tier enum value and
# that the RECORD_TIER_WEIGHTS mirror in tools/hackerman_query_common.py
# is in sync. Also re-runs the full record validator against the corpus
# so any regression introduced by an enum mistake surfaces immediately.
schema-tier-enum-validate:
	@python3 -m unittest tools.tests.test_schema_enum_tier_2_public_archive
	@python3 tools/hackerman-record-validate.py --quiet

.PHONY: schema-tier-1-enum-validate
# Wave-2 PR-A follow-up (2026-05-16) gate: verifies the hackerman_record
# schemas (v1 and v1.1) accept `tier-1-officially-disclosed` as a
# record_tier enum value AND that the v1.1 schema accepts it as a
# verification_tier enum value. Mirrors `schema-tier-enum-validate` for
# the sibling `tier-2-verified-public-archive` extension. Closes the
# Vyper-CVE rebuilder (commit a428d287c4) record_extensions.verification_label
# workaround. Also re-runs the full record validator so any regression
# surfaces immediately.
schema-tier-1-enum-validate:
	@python3 -m unittest tools.tests.test_schema_enum_tier_1_officially_disclosed
	@python3 tools/hackerman-record-validate.py --quiet

hackerman-index:
	@python3 tools/hackerman-index-build.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(INDEX_DIR),--index-dir "$(INDEX_DIR)") \
	  $(if $(NO_PRESERVE),--no-preserve-existing)
	@python3 tools/hackerman-record-quality.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(QUALITY_OUT),--out "$(QUALITY_OUT)",--out audit/corpus_tags/derived/record_quality.jsonl) \
	  --json-summary >/dev/null
	@python3 tools/hackerman-proof-hardening.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(PROOF_HARDENING_OUT),--out "$(PROOF_HARDENING_OUT)",--out audit/corpus_tags/derived/proof_hardening.jsonl) \
	  --json-summary >/dev/null
	@python3 tools/hackerman-cross-language-analogues.py \
	  $(if $(TAG_DIR),--tags-dir "$(TAG_DIR)") \
	  $(if $(CROSS_LANGUAGE_OUT),--out "$(CROSS_LANGUAGE_OUT)",--out audit/corpus_tags/derived/cross_language_analogues.jsonl)

.PHONY: hackerman-reclassify-catchall
# Re-classify the two coarse catch-all attack classes (protocol-invariant-bypass,
# state-accounting-drift; ~14k records) into fine-grained exploit shapes.
# Dry-run by default: emits a CANDIDATE diff sidecar only, NEVER flips
# attack_class: in any pipeline without explicit operator review. Pass APPLY=1
# to flip in-place (writes a rollback sidecar) and then chain hackerman-index
# per the tool's hard-rule docstring (index rebuild is mandatory after --apply).
hackerman-reclassify-catchall:
	@python3 tools/hackerman-reclassify-catchall.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(CANDIDATES_PATH),--candidates-path "$(CANDIDATES_PATH)") \
	  $(if $(MIN_CONFIDENCE),--min-confidence "$(MIN_CONFIDENCE)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(filter 1 true yes on,$(APPLY)),--apply,--dry-run) \
	  $(if $(JSON),--json-summary)
	$(if $(filter 1 true yes on,$(APPLY)),@$(MAKE) hackerman-index $(if $(TAG_DIR),TAG_DIR="$(TAG_DIR)"),)

.PHONY: hackerman-chain-candidates-sidecar hackerman-chain-candidates-sidecar-test hackerman-chain-unify-sidecar hackerman-chain-unify-sidecar-test hackerman-detector-relationships-sidecar hackerman-detector-relationships-sidecar-test hackerman-sidecar-refresh-check hackerman-sidecar-refresh-check-test hackerman-chain-candidates hackerman-chain-unify hackerman-exploit-predicates hackerman-predicate-compose hackerman-novel-vector-gen audit-deep-novel-vectors audit-deep-novel-vectors-test hackerman-detector-relationships hackerman-go-cosmos-inventory hackerman-go-cosmos-stage-imports hackerman-audit-firm-report-class-backfill hackerman-audit-firm-report-class-backfill-test hackerman-solodit-date-enrichment-queue hackerman-solodit-date-enrichment-queue-test hackerman-backfill-proof-artifact-path hackerman-proof-artifact-index hackerman-proof-artifact-accepted-writeback hackerman-proof-artifact-promotion-review hackerman-proof-artifact-status-only-review hackerman-proof-artifact-status-only-reconciliation hackerman-proof-artifact-status-only-promotion-review hackerman-proof-artifact-import-queue hackerman-proof-artifact-import-queue-test hackerman-proof-artifact-record-proposals hackerman-proof-artifact-record-proposals-test realworld-recall-drilldown realworld-recall-drilldown-test realworld-recall-work-queue realworld-recall-work-queue-test external-recall-manifest external-recall-select
hackerman-audit-firm-report-class-backfill:
	@python3 tools/hackerman-backfill-audit-firm-report-class.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(ROLLBACK_OUT),--rollback-out "$(ROLLBACK_OUT)") \
	  $(if $(MIN_CONFIDENCE),--min-confidence "$(MIN_CONFIDENCE)") \
	  $(if $(APPLY),--apply) \
	  $(if $(JSON),--json-summary)

hackerman-audit-firm-report-class-backfill-test:
	@python3 -m unittest tools.tests.test_hackerman_backfill_audit_firm_report_class -v

hackerman-chain-candidates-sidecar:
	@if [ "$(CHECK)" = "1" ]; then \
		python3 tools/hackerman-chain-candidates-sidecar.py --check; \
	else \
		python3 tools/hackerman-chain-candidates-sidecar.py; \
	fi

hackerman-chain-candidates-sidecar-test:
	@python3 -m unittest tools.tests.test_hackerman_chain_candidates_sidecar -v

hackerman-chain-unify-sidecar:
	@if [ "$(CHECK)" = "1" ]; then \
		python3 tools/hackerman-chain-unify-sidecar.py --check \
		  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
		  $(if $(CHAIN_SIDECAR),--chain-sidecar "$(CHAIN_SIDECAR)") \
		  $(if $(CHAIN_UNIFY_SIDECAR),--out "$(CHAIN_UNIFY_SIDECAR)") \
		  $(if $(MAX_HOPS),--max-hops "$(MAX_HOPS)") \
		  $(if $(PREDICATES),--predicates "$(PREDICATES)") \
		  $(if $(JSON),--json); \
	else \
		python3 tools/hackerman-chain-unify-sidecar.py \
		  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
		  $(if $(CHAIN_SIDECAR),--chain-sidecar "$(CHAIN_SIDECAR)") \
		  $(if $(CHAIN_UNIFY_SIDECAR),--out "$(CHAIN_UNIFY_SIDECAR)") \
		  $(if $(MAX_HOPS),--max-hops "$(MAX_HOPS)") \
		  $(if $(CACHE_LIMIT),--cache-limit "$(CACHE_LIMIT)") \
		  $(if $(PREDICATES),--predicates "$(PREDICATES)") \
		  $(if $(JSON),--json); \
	fi

hackerman-chain-unify-sidecar-test:
	@python3 -m unittest tools.tests.test_hackerman_chain_unify_sidecar -v

hackerman-detector-relationships-sidecar:
	@if [ "$(CHECK)" = "1" ]; then \
		python3 tools/hackerman-detector-relationships-sidecar.py --check; \
	else \
		python3 tools/hackerman-detector-relationships-sidecar.py; \
	fi

hackerman-detector-relationships-sidecar-test:
	@python3 -m unittest tools.tests.test_hackerman_detector_relationships_sidecar -v

.PHONY: hackerman-corpus-coverage hackerman-corpus-walker-test hackerman-regen-chain-candidates hackerman-regen-detector-relationships
hackerman-corpus-coverage:
	@python3 tools/hackerman-corpus-walker.py \
	  --compare-sidecar audit/corpus_tags/derived/exploit_predicates.manifest.json --json

hackerman-corpus-walker-test:
	@python3 -m unittest tools.tests.test_hackerman_corpus_walker -v

hackerman-regen-chain-candidates:
	@python3 tools/hackerman-chain-candidates-sidecar.py \
	  --sidecar audit/corpus_tags/derived/chain_candidates.jsonl

hackerman-regen-detector-relationships:
	@python3 tools/hackerman-detector-relationships-sidecar.py \
	  --sidecar audit/corpus_tags/derived/detector_relationship_records.jsonl

hackerman-sidecar-refresh-check:
	@python3 tools/hackerman-sidecar-refresh-check.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(TARGETS),--targets "$(TARGETS)") \
	  $(if $(CHECK),--check) \
	  $(if $(MAX_REBUILDS),--max-rebuilds "$(MAX_REBUILDS)") \
	  $(if $(DETECTOR_SIDECAR),--detector-sidecar "$(DETECTOR_SIDECAR)") \
	  $(if $(CHAIN_SIDECAR),--chain-sidecar "$(CHAIN_SIDECAR)") \
	  $(if $(CHAIN_UNIFY_SIDECAR),--chain-unify-sidecar "$(CHAIN_UNIFY_SIDECAR)") \
	  $(if $(MAX_HOPS),--max-hops "$(MAX_HOPS)") \
	  $(if $(JSON),--json)

hackerman-sidecar-refresh-check-test:
	@python3 -m unittest tools.tests.test_hackerman_sidecar_refresh_check -v

hackerman-chain-candidates:
	@python3 tools/hackerman-chain-candidates.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(JSON),--json) \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(INCLUDE_GENERIC),--include-generic)

hackerman-chain-unify:
	@python3 tools/hackerman-chain-unify.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(MAX_HOPS),--max-hops "$(MAX_HOPS)") \
	  $(if $(JSON),--json) \
	  $(if $(OUT),--out "$(OUT)")

hackerman-exploit-predicates:
	@python3 tools/hackerman-exploit-predicates.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(JSON),--json)

hackerman-predicate-compose:
	@python3 tools/hackerman-predicate-compose.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(QUERY_REQUIRES),--query-requires "$(QUERY_REQUIRES)") \
	  $(if $(QUERY_YIELDS),--query-yields "$(QUERY_YIELDS)") \
	  $(if $(JSON),--json) \
	  $(if $(OUT),--out "$(OUT)")

hackerman-novel-vector-gen:
	@python3 tools/hackerman-novel-vector-gen.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(TARGET_REPO),--target-repo "$(TARGET_REPO)") \
	  $(if $(LANGUAGE),--language "$(LANGUAGE)") \
	  $(if $(DOMAIN),--domain "$(DOMAIN)") \
	  $(if $(MIN_SHAPE_OVERLAP),--min-shape-overlap "$(MIN_SHAPE_OVERLAP)") \
	  $(if $(MAX_TARGETS),--max-targets "$(MAX_TARGETS)") \
	  $(if $(ALL_TARGETS),--all-targets) \
	  $(if $(SAME_CLASS_VARIANTS),--same-class-variants) \
	  $(if $(JSON),--json) \
	  $(if $(JSONL),--out "$(if $(OUT),$(OUT),-)",$(if $(OUT),--out "$(OUT)"))

audit-deep-novel-vectors:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make audit-deep-novel-vectors WS=<workspace> [TARGET_REPO=owner/repo] [LIMIT=20] [MAX_TARGETS=50]'; exit 2; \
	fi
	@python3 tools/audit-deep-novel-vectors.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(TARGET_REPO),--target-repo "$(TARGET_REPO)") \
	  $(if $(LANGUAGE),--language "$(LANGUAGE)") \
	  $(if $(DOMAIN),--domain "$(DOMAIN)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(MAX_TARGETS),--max-targets "$(MAX_TARGETS)") \
	  $(if $(ALL_TARGETS),--all-targets) \
	  $(if $(SAME_CLASS_VARIANTS),--same-class-variants) \
	  $(if $(MIN_SHAPE_OVERLAP),--min-shape-overlap "$(MIN_SHAPE_OVERLAP)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(SUMMARY_OUT),--summary-out "$(SUMMARY_OUT)") \
	  $(if $(CONTEXT_OUT),--context-out "$(CONTEXT_OUT)") \
	  $(if $(SKIP_MCP_CONTEXT),--skip-mcp-context) \
	  $(if $(JSON),--json)

audit-deep-novel-vectors-test:
	@python3 -m unittest tools.tests.test_audit_deep_novel_vectors -v

hackerman-detector-relationships:
	@python3 tools/hackerman-detector-relationships.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(ENGAGE_REPORT),--engage-report "$(ENGAGE_REPORT)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(JSON),--json) \
	  $(if $(OUT),--out "$(OUT)")

hackerman-go-cosmos-inventory:
	@python3 tools/hackerman-go-cosmos-inventory.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(REFERENCE_ROOT),--reference-root "$(REFERENCE_ROOT)") \
	  $(if $(JSON),--json) \
	  $(if $(OUT),--out "$(OUT)")

hackerman-go-cosmos-stage-imports:
	@python3 tools/hackerman-go-cosmos-stage-imports.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(REFERENCE_ROOT),--reference-root "$(REFERENCE_ROOT)") \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(SOURCE_FAMILY),--source-family "$(SOURCE_FAMILY)") \
	  $(foreach path,$(SOURCE_FILES),--source-file "$(path)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(STAGE_ARTIFACT_OUT),--stage-artifact-out "$(STAGE_ARTIFACT_OUT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json-summary)

hackerman-solodit-date-enrichment-queue:
	@python3 tools/hackerman-solodit-date-enrichment-queue.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(SUMMARY_OUT),--summary-out "$(SUMMARY_OUT)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(STATUS_FILTER),--status-filter "$(STATUS_FILTER)") \
	  $(if $(JSON),--json-summary)

hackerman-solodit-date-enrichment-queue-test:
	@python3 -m unittest tools.tests.test_hackerman_solodit_date_enrichment_queue -v

hackerman-backfill-proof-artifact-path:
	@python3 tools/hackerman-backfill-proof-artifact-path.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(CANDIDATE_LIMIT),--candidate-limit "$(CANDIDATE_LIMIT)") \
	  $(if $(MISSING_RECORD_IMPORT_QUEUE),--missing-record-import-queue "$(MISSING_RECORD_IMPORT_QUEUE)") \
	  $(if $(JSON),--json-summary)

hackerman-proof-artifact-index:
	@python3 tools/hackerman-proof-artifact-index.py \
	  $(if $(ROOTS),--roots $(foreach root,$(ROOTS),"$(root)")) \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(REPORT),--report "$(REPORT)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json-summary)

hackerman-proof-artifact-accepted-writeback:
	@python3 tools/proof-artifact-accepted-writeback.py \
	  $(if $(OUTCOMES),--outcomes "$(OUTCOMES)") \
	  $(if $(OUT),--output "$(OUT)") \
	  $(if $(INCLUDE_MISSING),--include-missing)

hackerman-proof-artifact-promotion-review:
	@python3 tools/hackerman-backfill-proof-artifact-path.py \
	  --review-proof-artifact-index \
	  $(if $(INCLUDE_BLOCKED),--include-blocked-index-rows) \
	  $(if $(PROOF_ARTIFACT_INDEX),--proof-artifact-index "$(PROOF_ARTIFACT_INDEX)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(MISSING_RECORD_IMPORT_QUEUE),--missing-record-import-queue "$(MISSING_RECORD_IMPORT_QUEUE)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(JSON),--json-summary)

hackerman-proof-artifact-status-only-review:
	@python3 tools/hackerman-backfill-proof-artifact-path.py \
	  --status-only-blocker-review \
	  $(if $(PROOF_ARTIFACT_INDEX),--proof-artifact-index "$(PROOF_ARTIFACT_INDEX)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(JSON),--json-summary)

hackerman-proof-artifact-status-only-reconciliation:
	@python3 tools/hackerman-backfill-proof-artifact-path.py \
	  --status-only-reconciliation-queue \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(PROOF_ARTIFACT_INDEX),--proof-artifact-index "$(PROOF_ARTIFACT_INDEX)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json-summary)

hackerman-proof-artifact-status-only-promotion-review:
	@python3 tools/hackerman-backfill-proof-artifact-path.py \
	  --status-only-resolved-promotion-review \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(STATUS_ONLY_RECONCILIATION),--status-only-reconciliation "$(STATUS_ONLY_RECONCILIATION)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json-summary)

hackerman-proof-artifact-import-queue:
	@python3 tools/hackerman-proof-artifact-import-queue.py \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(AUDITS_ROOT),--audits-root "$(AUDITS_ROOT)") \
	  $(if $(REPO_ROOT),--repo-root "$(REPO_ROOT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json-summary)

hackerman-proof-artifact-import-queue-test:
	@python3 -m unittest tools.tests.test_hackerman_proof_artifact_import_queue -v

hackerman-proof-artifact-record-proposals:
	@python3 tools/hackerman-proof-artifact-record-proposals.py \
	  $(if $(PACKETS),--packets "$(PACKETS)") \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(OVERWRITE),--overwrite) \
	  $(if $(JSON),--json-summary)

hackerman-proof-artifact-record-proposals-test:
	@python3 -m unittest tools.tests.test_hackerman_proof_artifact_record_proposals -v

realworld-recall-work-queue:
	@python3 tools/audit/realworld-recall-work-queue.py \
	  $(if $(PRIORITIES),--priorities "$(PRIORITIES)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(INCLUDE_TAXONOMY),--include-taxonomy) \
	  $(foreach q,$(QUALITY_REPORTS),--quality-report "$(q)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json-summary)

realworld-recall-work-queue-test:
	@python3 -m unittest tools.tests.test_realworld_recall_work_queue -v

realworld-recall-drilldown:
	@python3 tools/audit/realworld-recall-drilldown.py \
	  $(if $(PRIORITIES),--priorities "$(PRIORITIES)") \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(ATTACK_CLASS),--attack-class "$(ATTACK_CLASS)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(MISS_LIMIT),--miss-limit "$(MISS_LIMIT)") \
	  $(if $(QUEUE_LIMIT),--queue-limit "$(QUEUE_LIMIT)") \
	  $(if $(JSON),--json)

realworld-recall-drilldown-test:
	@python3 -m unittest tools.tests.test_realworld_recall_drilldown -v

external-recall-manifest:
	@if [ -z "$(REPO_ROOT)" ] || [ -z "$(REPO_ID)" ] || [ -z "$(ATTACK_CLASS)" ] || [ -z "$(OUT)" ]; then \
	  echo 'Usage: make external-recall-manifest REPO_ROOT=/path/to/repo REPO_ID=owner/repo ATTACK_CLASS=<class> OUT=<manifest.json> [SEVERITY=High] [SOURCE=<source>] [EXCLUDE_DETECTOR_SLUG=<slug>] [INCLUDE="**/*.sol"] [SAMPLES="a.sol b.sol"] [JSON=1]'; exit 2; \
	fi
	@python3 tools/audit/external-recall-manifest.py build \
	  --repo-root "$(REPO_ROOT)" \
	  --repo-id "$(REPO_ID)" \
	  --attack-class "$(ATTACK_CLASS)" \
	  $(if $(SEVERITY),--severity "$(SEVERITY)") \
	  $(if $(SOURCE),--source "$(SOURCE)") \
	  $(if $(EXCLUDE_DETECTOR_SLUG),--exclude-detector-slug "$(EXCLUDE_DETECTOR_SLUG)") \
	  $(if $(INCLUDE),--include "$(INCLUDE)") \
	  $(foreach path,$(SAMPLES),--sample "$(path)") \
	  --out "$(OUT)" \
	  $(if $(JSON),--json)

external-recall-select:
	@if [ -z "$(REPO_ROOT)" ] || [ -z "$(REPO_ID)" ] || [ -z "$(ATTACK_CLASS)" ]; then \
	  echo 'Usage: make external-recall-select REPO_ROOT=/path/to/repo REPO_ID=owner/repo ATTACK_CLASS=<class> [OUT=reports/external_recall_samples.json] [LIMIT=5] [SEVERITY=High] [SOURCE=<source>] [EXCLUDE_DETECTOR_SLUG=<slug>] [INCLUDE="**/*.sol"] [SAMPLES="a.sol b.sol"] [JSON=1]'; exit 2; \
	fi
	@python3 tools/audit/external-recall-manifest.py select \
	  --repo-root "$(REPO_ROOT)" \
	  --repo-id "$(REPO_ID)" \
	  --attack-class "$(ATTACK_CLASS)" \
	  $(if $(SEVERITY),--severity "$(SEVERITY)") \
	  $(if $(SOURCE),--source "$(SOURCE)") \
	  $(if $(EXCLUDE_DETECTOR_SLUG),--exclude-detector-slug "$(EXCLUDE_DETECTOR_SLUG)") \
	  $(if $(INCLUDE),--include "$(INCLUDE)") \
	  $(foreach path,$(SAMPLES),--sample "$(path)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(JSON),--json)

hackerman-refresh-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_refresh tools.tests.test_hackerman_index_build -v

# ─── PR #726 wave-1 capability-lift: Hackerman ETL miner registry ────────────
# `hackerman-etl-registry-build` regenerates one JSON descriptor per miner
# under `tools/audit/etl_miner_registry/` plus `_manifest.json`. The
# `-check` companion runs the builder in dry-run mode and exits 1 on drift,
# making the registry safe to gate in CI.
#
# `-test` runs the >=8-case unit harness that enforces registry schema,
# manifest consistency, one-to-one tool/test mapping, and honest-zero
# discipline (no fabricated subtrees).
.PHONY: hackerman-etl-registry-build hackerman-etl-registry-check hackerman-etl-registry-test
hackerman-etl-registry-build:
	@python3 tools/hackerman-etl-miner-registry-build.py $(if $(QUIET),--quiet)

hackerman-etl-registry-check:
	@python3 tools/hackerman-etl-miner-registry-build.py --check

hackerman-etl-registry-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_miner_registry -v

# ─── PR #726 Tier-S: 5 high-yield ETL miners wired as first-class targets ────
# Per docs/HACKERMAN_MAKEFILE_TARGET_AUDIT_2026-05-16.md §"Tier S (ship now in
# PR #726, < 1 hour wiring)". Each miner gets a primary target + a -test
# companion. The composite `hackerman-etl-tier-s` runs all 5 in sequence.
#
# Common env knobs (every target honours these):
#   OUT_DIR=<path>        emitted-YAML output directory (default
#                         audit/corpus_tags/tags/<miner-slug>)
#   TAGS_DIR=<path>       alias for OUT_DIR (compat with audit-doc phrasing)
#   APPLY=1               write records (default: --dry-run)
#   LIMIT=<n>             cap records-emitted per miner
#   JSON=1                emit --json-summary
# Miner-specific extras documented per-target below.

.PHONY: hackerman-etl-from-contest-platforms hackerman-etl-from-contest-platforms-test \
        hackerman-etl-from-immunefi-public hackerman-etl-from-immunefi-public-test \
        hackerman-etl-from-solodit-critical-platforms hackerman-etl-from-solodit-critical-platforms-test \
        hackerman-etl-from-github-advisory hackerman-etl-from-github-advisory-test \
        hackerman-etl-from-cve-db hackerman-etl-from-cve-db-test \
        hackerman-etl-tier-s hackerman-etl-tier-s-test

# S1. Code4rena / Sherlock contest-platform findings ETL.
#   Extra env: PLATFORM=code4rena|sherlock  (passed as --filter-platform)
#              SAMPLE_SIZE=<n>, PER_CONTEST_CAP=<n>, MAX_CONTESTS=<n>
#              CACHE_FILE=<path>, WRITE_CACHE_FILE=<path>, ALL=1, SKIP_MINED=1
hackerman-etl-from-contest-platforms:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),$(if $(TAGS_DIR),$(TAGS_DIR),audit/corpus_tags/tags/contest_platforms))"; \
	mkdir -p "$$out_dir"; \
	echo "[hackerman-etl-from-contest-platforms] out_dir=$$out_dir mode=$(if $(APPLY),APPLY,dry-run)"; \
	python3 tools/hackerman-etl-from-contest-platforms.py \
	  --out-dir "$$out_dir" \
	  $(if $(APPLY),,--dry-run) \
	  $(if $(LIMIT),--limit $(LIMIT)) \
	  $(if $(JSON),--json-summary) \
	  $(if $(PLATFORM),--filter-platform $(PLATFORM)) \
	  $(if $(SAMPLE_SIZE),--sample-size $(SAMPLE_SIZE)) \
	  $(if $(PER_CONTEST_CAP),--per-contest-cap $(PER_CONTEST_CAP)) \
	  $(if $(MAX_CONTESTS),--max-contests $(MAX_CONTESTS)) \
	  $(if $(CACHE_FILE),--cache-file "$(CACHE_FILE)") \
	  $(if $(WRITE_CACHE_FILE),--write-cache-file "$(WRITE_CACHE_FILE)") \
	  $(if $(ALL),--all) \
	  $(if $(SKIP_MINED),--skip-already-mined)

hackerman-etl-from-contest-platforms-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_contest_platforms -v

# S2. Immunefi public audit-competition disclosures ETL.
#   Extra env: CACHE_DIR=<path>          (REQUIRED by miner; default cache/immunefi)
#              FETCH=1                    enable gh-api download into cache
#              MAX_COMPETITIONS=<n>, MAX_FILES_PER_COMPETITION=<n>
#              BRANCH=<git-branch>        upstream branch (default: main)
#              SEVERITY_FILTER=critical|high|medium|low|insight
hackerman-etl-from-immunefi-public:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),$(if $(TAGS_DIR),$(TAGS_DIR),audit/corpus_tags/tags/immunefi_public))"; \
	cache_dir="$(if $(CACHE_DIR),$(CACHE_DIR),cache/immunefi-public)"; \
	mkdir -p "$$out_dir" "$$cache_dir"; \
	echo "[hackerman-etl-from-immunefi-public] out_dir=$$out_dir cache_dir=$$cache_dir mode=$(if $(APPLY),APPLY,dry-run) fetch=$(if $(FETCH),1,0)"; \
	python3 tools/hackerman-etl-from-immunefi-public.py \
	  --out-dir "$$out_dir" \
	  --cache-dir "$$cache_dir" \
	  $(if $(APPLY),,--dry-run) \
	  $(if $(LIMIT),--limit $(LIMIT)) \
	  $(if $(JSON),--json-summary) \
	  $(if $(FETCH),--fetch) \
	  $(if $(MAX_COMPETITIONS),--max-competitions $(MAX_COMPETITIONS)) \
	  $(if $(MAX_FILES_PER_COMPETITION),--max-files-per-competition $(MAX_FILES_PER_COMPETITION)) \
	  $(if $(BRANCH),--branch $(BRANCH)) \
	  $(if $(SEVERITY_FILTER),--severity-filter $(SEVERITY_FILTER))

hackerman-etl-from-immunefi-public-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_immunefi_public -v

# S3. Solodit Critical-class (Sherlock + C4 + Cantina HIGH bucket) ETL.
#   Extra env: INPUT=<path>   pre-extracted Solodit MCP JSON (optional)
hackerman-etl-from-solodit-critical-platforms:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),$(if $(TAGS_DIR),$(TAGS_DIR),audit/corpus_tags/tags/solodit_critical_platforms))"; \
	mkdir -p "$$out_dir"; \
	echo "[hackerman-etl-from-solodit-critical-platforms] out_dir=$$out_dir mode=$(if $(APPLY),APPLY,dry-run)"; \
	python3 tools/hackerman-etl-from-solodit-critical-platforms.py \
	  --out-dir "$$out_dir" \
	  $(if $(APPLY),,--dry-run) \
	  $(if $(LIMIT),--limit $(LIMIT)) \
	  $(if $(JSON),--json-summary) \
	  $(if $(INPUT),--input "$(INPUT)")

hackerman-etl-from-solodit-critical-platforms-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_solodit_critical_platforms -v

# S4. GitHub Security Advisories (GHSA) ETL.
#   Extra env: CACHE_FILE=<path>, WRITE_CACHE_FILE=<path>, FILTER_REPO=<owner/repo>
hackerman-etl-from-github-advisory:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),$(if $(TAGS_DIR),$(TAGS_DIR),audit/corpus_tags/tags/github_advisory))"; \
	mkdir -p "$$out_dir"; \
	echo "[hackerman-etl-from-github-advisory] out_dir=$$out_dir mode=$(if $(APPLY),APPLY,dry-run)"; \
	python3 tools/hackerman-etl-from-github-advisory.py \
	  --out-dir "$$out_dir" \
	  $(if $(APPLY),,--dry-run) \
	  $(if $(LIMIT),--limit $(LIMIT)) \
	  $(if $(JSON),--json-summary) \
	  $(if $(CACHE_FILE),--cache-file "$(CACHE_FILE)") \
	  $(if $(WRITE_CACHE_FILE),--write-cache-file "$(WRITE_CACHE_FILE)") \
	  $(if $(FILTER_REPO),--filter-repo "$(FILTER_REPO)")

hackerman-etl-from-github-advisory-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_github_advisory -v

# S5. CVE/NVD database ETL (largest orphan, 1,100 LOC; full CVE coverage).
#   Extra env: EXTRA_JSON=<path>   additional seed JSON
#              CACHE_DIR=<path>    pre-fetched NVD/GHSA JSON cache dir
#              SKIP_VALIDATION=1   bypass schema validation
hackerman-etl-from-cve-db:
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),$(if $(TAGS_DIR),$(TAGS_DIR),audit/corpus_tags/tags/cve_db))"; \
	mkdir -p "$$out_dir"; \
	echo "[hackerman-etl-from-cve-db] out_dir=$$out_dir mode=$(if $(APPLY),APPLY,dry-run)"; \
	python3 tools/hackerman-etl-from-cve-db.py \
	  --out-dir "$$out_dir" \
	  $(if $(APPLY),,--dry-run) \
	  $(if $(LIMIT),--limit $(LIMIT)) \
	  $(if $(JSON),--json-summary) \
	  $(if $(EXTRA_JSON),--extra-json "$(EXTRA_JSON)") \
	  $(if $(CACHE_DIR),--cache-dir "$(CACHE_DIR)") \
	  $(if $(SKIP_VALIDATION),--skip-validation)

hackerman-etl-from-cve-db-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_cve_db -v

# Composite Tier-S runner: runs S1..S5 in sequence, honouring shared env knobs.
# Continues past per-miner failures and reports the aggregate rc at the end.
# Per-miner OUT_DIR routing: each miner gets its own sub-directory under
# audit/corpus_tags/tags/<miner-slug> so records don't collide.
hackerman-etl-tier-s:
	@base_dir="$(if $(OUT_DIR),$(OUT_DIR),$(if $(TAGS_DIR),$(TAGS_DIR),audit/corpus_tags/tags))"; \
	mkdir -p "$$base_dir"; \
	echo "[hackerman-etl-tier-s] base_dir=$$base_dir mode=$(if $(APPLY),APPLY,dry-run) limit=$(if $(LIMIT),$(LIMIT),unbounded)"; \
	rc=0; \
	for slug in contest_platforms immunefi_public solodit_critical_platforms github_advisory cve_db; do \
	  mkdir -p "$$base_dir/$$slug"; \
	done; \
	echo "[hackerman-etl-tier-s] S1 contest-platforms"; \
	OUT_DIR="$$base_dir/contest_platforms" $(MAKE) --no-print-directory hackerman-etl-from-contest-platforms \
	  $(if $(APPLY),APPLY=1) $(if $(LIMIT),LIMIT=$(LIMIT)) $(if $(JSON),JSON=1) || { echo "[hackerman-etl-tier-s] FAIL S1 rc=$$?"; rc=1; }; \
	echo "[hackerman-etl-tier-s] S2 immunefi-public"; \
	OUT_DIR="$$base_dir/immunefi_public" $(MAKE) --no-print-directory hackerman-etl-from-immunefi-public \
	  $(if $(APPLY),APPLY=1) $(if $(LIMIT),LIMIT=$(LIMIT)) $(if $(JSON),JSON=1) || { echo "[hackerman-etl-tier-s] FAIL S2 rc=$$?"; rc=1; }; \
	echo "[hackerman-etl-tier-s] S3 solodit-critical-platforms"; \
	OUT_DIR="$$base_dir/solodit_critical_platforms" $(MAKE) --no-print-directory hackerman-etl-from-solodit-critical-platforms \
	  $(if $(APPLY),APPLY=1) $(if $(LIMIT),LIMIT=$(LIMIT)) $(if $(JSON),JSON=1) || { echo "[hackerman-etl-tier-s] FAIL S3 rc=$$?"; rc=1; }; \
	echo "[hackerman-etl-tier-s] S4 github-advisory"; \
	OUT_DIR="$$base_dir/github_advisory" $(MAKE) --no-print-directory hackerman-etl-from-github-advisory \
	  $(if $(APPLY),APPLY=1) $(if $(LIMIT),LIMIT=$(LIMIT)) $(if $(JSON),JSON=1) || { echo "[hackerman-etl-tier-s] FAIL S4 rc=$$?"; rc=1; }; \
	echo "[hackerman-etl-tier-s] S5 cve-db"; \
	OUT_DIR="$$base_dir/cve_db" $(MAKE) --no-print-directory hackerman-etl-from-cve-db \
	  $(if $(APPLY),APPLY=1) $(if $(LIMIT),LIMIT=$(LIMIT)) $(if $(JSON),JSON=1) || { echo "[hackerman-etl-tier-s] FAIL S5 rc=$$?"; rc=1; }; \
	echo "[hackerman-etl-tier-s] DONE rc=$$rc"; \
	exit $$rc

# Composite test target: runs all 5 -test companions in sequence.
hackerman-etl-tier-s-test: \
	hackerman-etl-from-contest-platforms-test \
	hackerman-etl-from-immunefi-public-test \
	hackerman-etl-from-solodit-critical-platforms-test \
	hackerman-etl-from-github-advisory-test \
	hackerman-etl-from-cve-db-test

.PHONY: hackerman-corpus-stats hackerman-corpus-stats-test
hackerman-corpus-stats:
	@python3 tools/hackerman-corpus-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(JSON),--json) \
	  $(if $(SKIP_GATES),--skip-gates) \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

hackerman-corpus-stats-test:
	@python3 -m unittest tools.tests.test_hackerman_corpus_stats -v

.PHONY: hackerman-tag-wave-close hackerman-tag-wave-close-test
# PR #726 Wave-1: create an annotated git tag marking the close of a Wave.
# Default WAVE=wave-1-final. Operator decides whether to push (`git push
# origin <tag>`); this target NEVER pushes. Idempotent on same-SHA, refuses
# different-SHA without FORCE=1. Annotation body bundles a deterministic
# corpus-stats snapshot (shape histogram, total_records, hackerman_v1_total,
# quarantine total) plus a Wave-2 readiness verdict (READY / NOT-READY /
# UNKNOWN) so `git show <tag>` is self-describing forever.
hackerman-tag-wave-close:
	@python3 tools/hackerman-tag-wave-close.py \
	  $(if $(WAVE),--wave-name "$(WAVE)") \
	  $(if $(REPO),--repo "$(REPO)") \
	  $(if $(PR_REF),--pr-ref "$(PR_REF)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)") \
	  $(if $(FORCE),--force) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SKIP_CORPUS),--skip-corpus) \
	  $(if $(JSON),--json)

hackerman-tag-wave-close-test:
	@python3 -m unittest tools.tests.test_hackerman_tag_wave_close -v

.PHONY: hackerman-corpus-snapshot-html hackerman-corpus-snapshot-html-test
# PR #726 Wave-1: static HTML / inline-SVG snapshot of the hackerman corpus
# state for embedding in PR descriptions / handoff docs. Self-contained
# single-file output (<1MB). No external dependencies. Pass STDOUT=1 to
# write HTML to stdout instead of --out.
hackerman-corpus-snapshot-html:
	@python3 tools/hackerman-corpus-snapshot-html.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)") \
	  $(if $(STDOUT),--stdout)

hackerman-corpus-snapshot-html-test:
	@python3 -m unittest tools.tests.test_hackerman_corpus_snapshot_html -v

.PHONY: hackerman-tier-history-snapshot hackerman-tier-history-list hackerman-tier-history-snapshot-test
# PR #726 Wave-1: versioned snapshot of the hackerman corpus tier
# distribution (tier-1..tier-5 / no-tier) for tracking growth over time.
# Writes to audit/wave1_snapshots/tier_history/<YYYY-MM-DDTHH-MM-SSZ>.json
# and maintains a rolling _manifest.json. Idempotent on same-second.
hackerman-tier-history-snapshot:
	@python3 tools/hackerman-tier-history-snapshot.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)") \
	  $(if $(JSON),--json)

hackerman-tier-history-list:
	@python3 tools/hackerman-tier-history-snapshot.py \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  --list \
	  --limit $(if $(LIMIT),$(LIMIT),10) \
	  $(if $(JSON),--json)

hackerman-tier-history-snapshot-test:
	@python3 -m unittest tools.tests.test_hackerman_tier_history_snapshot -v

.PHONY: hackerman-baseline-freeze hackerman-baseline-freeze-test
# PR #726 Wave-1: freeze a baseline snapshot of the hackerman corpus -
# deterministic SHA256 over all record.{yaml,json} files (alphabetic by
# relpath; content + path) + total records + tier distribution + per-
# top-level-subtree record counts. Used as the immutable reference for
# Wave-2 diff comparisons.
# Pass CHECK=1 to verify-only (no write); JSON=1 for parse-friendly verdict.
# Default output: audit/wave1_snapshots/baseline_freeze/<baseline-label>.json
# (default label: 2026-05-16-wave1-final).
hackerman-baseline-freeze:
	@python3 tools/hackerman-baseline-freeze.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(OUT_DIR),--out-dir "$(OUT_DIR)") \
	  $(if $(OUT_PATH),--out-path "$(OUT_PATH)") \
	  $(if $(BASELINE_LABEL),--baseline-label "$(BASELINE_LABEL)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)") \
	  $(if $(CHECK),--check) \
	  $(if $(JSON),--json)

hackerman-baseline-freeze-test:
	@python3 -m unittest tools.tests.test_hackerman_baseline_freeze -v

.PHONY: hackerman-gates-status hackerman-gates-status-json hackerman-gates-status-test
# Aggregate verdicts from all registered hackerman pre-submit-check gates
# (Check #72 record verification-tier + corpus-subdir acceptance + future
# gates self-registered via tools/hackerman-gates-status.py::register_gate).
# Pass STRICT=1 to exit non-zero when any gate verdict != pass.
hackerman-gates-status:
	@python3 tools/hackerman-gates-status.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(GATE),--gate "$(GATE)") \
	  $(if $(STRICT),--strict) \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

# Machine-consumable JSON envelope (auditooor.hackerman_gates_status.v1).
hackerman-gates-status-json:
	@python3 tools/hackerman-gates-status.py \
	  --json \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(GATE),--gate "$(GATE)") \
	  $(if $(STRICT),--strict) \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

hackerman-gates-status-test:
	@python3 -m unittest tools.tests.test_hackerman_gates_status -v

.PHONY: hackerman-all hackerman-all-json hackerman-all-test
# Wave-1 hackerman capability lift (PR #726) - one-shot aggregator that runs
# the full hackerman test + lint + gate suite (schema / tier / acceptance /
# unit-tests / vault-tests / stats / integrity) in a single command and emits
# a combined per-stage verdict plus an overall PASS/FAIL.
#
# Default invocation (human report, strict gating, full corpus):
#     make hackerman-all
#
# Knobs:
#   TAGS_DIR=<path>          override tags directory
#   VALIDATE_ALL_TAGS=1      forward --strict-all to the schema validator
#   FAIL_FAST=1              stop after the first fail / error stage
#   STAGE=<id>               restrict to one stage (repeatable: STAGE="schema tier")
#   TIMEOUT=<seconds>        per-stage subprocess timeout (default 900)
#   GENERATED_AT=<iso>       pin envelope timestamp (reproducible builds)
hackerman-all:
	@python3 tools/hackerman-all.py \
	  --strict \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(VALIDATE_ALL_TAGS),--validate-all-tags) \
	  $(if $(FAIL_FAST),--fail-fast) \
	  $(foreach s,$(STAGE),--stage $(s)) \
	  $(if $(TIMEOUT),--timeout "$(TIMEOUT)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

# Machine-consumable envelope (auditooor.hackerman_all.v1).
hackerman-all-json:
	@python3 tools/hackerman-all.py \
	  --json --strict \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(VALIDATE_ALL_TAGS),--validate-all-tags) \
	  $(if $(FAIL_FAST),--fail-fast) \
	  $(foreach s,$(STAGE),--stage $(s)) \
	  $(if $(TIMEOUT),--timeout "$(TIMEOUT)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

hackerman-all-test:
	@python3 -m unittest tools.tests.test_hackerman_all -v

.PHONY: hackerman-pr-merge-checklist hackerman-pr-merge-checklist-json hackerman-pr-merge-checklist-test \
        hackerman-pr726-merge-checklist hackerman-pr726-merge-checklist-json hackerman-pr726-merge-checklist-test
# Hackerman capability-lift PR (PR #726 wave-1, PR #728 wave-2-corpus-
# migration, and successors) - operator-runnable final pre-merge
# checklist. Aggregates `make hackerman-all-json`, `make docs-check`,
# origin-sync, `gh pr view <N> --json mergeable`, and a bounded MCP
# smoke-test set into a single GO / YELLOW / NO-GO verdict.
# Companion doc: docs/HACKERMAN_PR726_MERGE_CHECKLIST_2026-05-16.md.
#
# Target PR + branch auto-discovered (CLI > env > `gh pr status` >
# git current-branch). Override only when discovery fails.
#
# Knobs:
#   PR_NUMBER=<n>            override PR number (auto-discovered otherwise)
#   BRANCH=<name>            override expected branch (auto-discovered otherwise)
#   EXEMPT_STAGE=<stage_id>  hackerman-all stage to treat as YELLOW
#                            instead of FAIL (repeatable via spaces)
#   SKIP_STEP=<step_id>      step to skip entirely (repeatable)
#   STRICT=1                 exit non-zero on YELLOW (not just NO-GO)
#
# Back-compat: `hackerman-pr726-*` targets remain as aliases that
# delegate to the generic targets WITHOUT forcing PR #726 specifically;
# the underlying tool's discovery picks up the branch the operator is
# actually on. This unblocks PR #728 squash-merge.
hackerman-pr-merge-checklist:
	@python3 tools/hackerman-pr-merge-checklist.py \
	  $(if $(PR_NUMBER),--pr-number $(PR_NUMBER)) \
	  $(if $(BRANCH),--branch $(BRANCH)) \
	  $(foreach s,$(EXEMPT_STAGE),--exempt-stage $(s)) \
	  $(foreach s,$(SKIP_STEP),--skip-step $(s)) \
	  $(if $(STRICT),--strict) \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-pr-merge-checklist-json:
	@python3 tools/hackerman-pr-merge-checklist.py --json \
	  $(if $(PR_NUMBER),--pr-number $(PR_NUMBER)) \
	  $(if $(BRANCH),--branch $(BRANCH)) \
	  $(foreach s,$(EXEMPT_STAGE),--exempt-stage $(s)) \
	  $(foreach s,$(SKIP_STEP),--skip-step $(s)) \
	  $(if $(STRICT),--strict) \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-pr-merge-checklist-test:
	@python3 -m unittest tools.tests.test_hackerman_pr_merge_checklist_discovery tools.tests.test_hackerman_pr726_merge_checklist -v

# Back-compat aliases (Wave-1 callsites delegate to the generic targets).
hackerman-pr726-merge-checklist: hackerman-pr-merge-checklist

hackerman-pr726-merge-checklist-json: hackerman-pr-merge-checklist-json

hackerman-pr726-merge-checklist-test: hackerman-pr-merge-checklist-test

.PHONY: hackerman-pre-merge hackerman-pre-merge-test
# Wave-1 hackerman capability lift (PR #726) - composite pre-merge runner.
# Executes the full pre-merge gate suite sequentially, captures each step's
# exit code, and emits a final aggregate verdict:
#   PASS          - every step exited 0
#   NEEDS-CHANGES - at least one non-critical step failed (docs-check or
#                   cross-link-audit), but core gates (hackerman-all,
#                   merge-checklist, mcp-smoke-test, unit-tests) all passed
#   FAIL          - one or more core gates failed
#
# Every step runs under `|| true` so a single failure does not short-circuit
# the rest of the suite; the operator sees a complete picture of where the
# branch stands relative to merge readiness. Per-step verdicts are echoed
# in order plus tabulated in the final summary block.
#
# Knobs:
#   PRE_MERGE_OUT=<path>     write JSON summary to <path> (optional)
#   STRICT=1                 exit non-zero on NEEDS-CHANGES (default: only
#                            FAIL exits non-zero)
hackerman-pre-merge:
	@python3 tools/hackerman-pre-merge.py \
	  $(if $(PRE_MERGE_OUT),--out-json "$(PRE_MERGE_OUT)") \
	  $(if $(STRICT),--strict)

hackerman-pre-merge-test:
	@python3 -m unittest tools.tests.test_hackerman_pre_merge -v

# Wave-2 PR-A (PR #728) close-readiness cache contract.
# Runs the full pre-merge composite (30-45 min on the 36k-yaml corpus)
# and persists the JSON envelope at `.auditooor/cache/pre_merge_result.json`
# (override via PRE_MERGE_OUT=<path>) so subsequent close-readiness
# invocations can read the cached verdict via
# `tools/wave2-a-close-readiness.py --use-pre-merge-cache <path>` instead
# of re-running the 30+ min gate inline.  The envelope includes
# `overall_status`, `exit_code`, `timestamp`, `runtime_seconds`, and
# `sub_check_breakdown` fields the close-readiness cache reader expects.
#
# Operator workflow:
#   make hackerman-pre-merge-cached          # once, ~30-45 min
#   make wave2-a-close-readiness             # many, ~seconds each
#
# Knobs:
#   PRE_MERGE_OUT=<path>     destination JSON envelope path (default:
#                            .auditooor/cache/pre_merge_result.json)
#   STRICT=1                 exit non-zero on NEEDS-CHANGES (default:
#                            only FAIL exits non-zero)
.PHONY: hackerman-pre-merge-cached
hackerman-pre-merge-cached:
	@PRE_MERGE_CACHE_OUT="$${PRE_MERGE_OUT:-.auditooor/cache/pre_merge_result.json}"; \
	  mkdir -p "$$(dirname "$$PRE_MERGE_CACHE_OUT")"; \
	  echo "[hackerman-pre-merge-cached] writing envelope to $$PRE_MERGE_CACHE_OUT"; \
	  python3 tools/hackerman-pre-merge.py \
	    --out-json "$$PRE_MERGE_CACHE_OUT" \
	    $(if $(STRICT),--strict)

.PHONY: wave2-a-pre-merge-preflight wave2-a-pre-merge-preflight-test
# Wave-2-A PR-A diagnostic. Lower-level than wave2-a-close-readiness.py
# (criteria 1-6) and lower-level than hackerman-pre-merge.py (heavy gate).
# Audits the sub-checks pre-merge invokes for stale-fixture references
# (PR #726 vs #728, wave-1 vs wave-2 branch defaults) and flags which
# currently-failing sub-checks are expected to flip PASS post-Phase-3.
# Companion doc: docs/WAVE2_A_PRE_MERGE_AUDIT_2026-05-16.md.
wave2-a-pre-merge-preflight:
	@python3 tools/wave2-a-pre-merge-preflight.py \
	  --workspace "$(CURDIR)" \
	  $(if $(JSON),--json) \
	  $(if $(STRICT),--strict)

wave2-a-pre-merge-preflight-test:
	@python3 -m unittest tools.tests.test_wave2_a_pre_merge_preflight -v

.PHONY: wave2-a-pre-squash-final-check wave2-a-pre-squash-final-check-test
# Wave-2-A PR-A final composite sanity check before squash-merge of PR #728.
# Invokes every per-tool verification script and aggregates their JSON
# verdicts into a single READY_TO_SQUASH_MERGE / DEGRADED / BLOCKED signal.
# Documented-acceptable WARNINGs (referenced to Wave-3 follow-up doc
# commit 69cebeb750) are routed away from blocking; only genuine FAILs
# fall into blocking_findings. See
# tools/wave2-a-pre-squash-final-check.py and
# docs/WAVE3_FOLLOWUPS_FROM_WAVE2_2026-05-16.md.
wave2-a-pre-squash-final-check:
	@python3 tools/wave2-a-pre-squash-final-check.py \
	  --workspace "$(CURDIR)" \
	  $(if $(JSON),--json) \
	  $(if $(STRICT),--strict)

wave2-a-pre-squash-final-check-test:
	@python3 -m unittest tools.tests.test_wave2_a_pre_squash_final_check -v

.PHONY: hackerman-attack-class-distribution hackerman-attack-class-distribution-full hackerman-attack-class-distribution-json hackerman-attack-class-distribution-test
# Wave-1 hackerman capability lift (PR #726) - per-subtree x per-class matrix
# surfacing concentration / orphan patterns across audit/corpus_tags/tags/.
# Default mode (dense) shows top-20 classes by global count; -full mode emits
# every class. Pair with hackerman-attack-class-distribution-json for the
# auditooor.hackerman_attack_class_distribution.v1 envelope.
hackerman-attack-class-distribution:
	@python3 tools/hackerman-attack-class-distribution.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  --mode dense \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-attack-class-distribution-full:
	@python3 tools/hackerman-attack-class-distribution.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  --mode full \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-attack-class-distribution-json:
	@python3 tools/hackerman-attack-class-distribution.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  --mode $(if $(MODE),$(MODE),dense) \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-attack-class-distribution-test:
	@python3 -m unittest tools.tests.test_hackerman_attack_class_distribution -v

.PHONY: hackerman-corpus-diff hackerman-corpus-diff-json hackerman-corpus-diff-test
# Wave-1 hackerman capability lift (PR #726) - per-subtree corpus diff
# between two git refs (e.g. origin/main vs HEAD). Walks
# audit/corpus_tags/tags/ via git ls-tree at each ref and emits
# added / modified / deleted counts per first-level subtree.
hackerman-corpus-diff:
	@python3 tools/hackerman-corpus-diff.py \
	  $(if $(FROM_REF),--from "$(FROM_REF)") \
	  $(if $(TO_REF),--to "$(TO_REF)") \
	  $(if $(TAGS_PREFIX),--tags-prefix "$(TAGS_PREFIX)") \
	  $(if $(REPO),--repo "$(REPO)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-corpus-diff-json:
	@python3 tools/hackerman-corpus-diff.py \
	  $(if $(FROM_REF),--from "$(FROM_REF)") \
	  $(if $(TO_REF),--to "$(TO_REF)") \
	  $(if $(TAGS_PREFIX),--tags-prefix "$(TAGS_PREFIX)") \
	  $(if $(REPO),--repo "$(REPO)") \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-corpus-diff-test:
	@python3 -m unittest tools.tests.test_hackerman_corpus_diff -v

.PHONY: hackerman-language-stats hackerman-language-stats-json hackerman-language-stats-test
# Wave-1 hackerman capability lift (PR #726) - per-target-language
# distribution stats across audit/corpus_tags/tags/. Sibling of
# hackerman-attack-class-distribution but on the orthogonal target-language
# axis (solidity / vyper / cairo / move / rust / go / circom / ts / python /
# etc.). Pair with -json for the auditooor.hackerman_language_stats.v1
# envelope.
hackerman-language-stats:
	@python3 tools/hackerman-language-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-language-stats-json:
	@python3 tools/hackerman-language-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-language-stats-test:
	@python3 -m unittest tools.tests.test_hackerman_language_stats -v

.PHONY: hackerman-severity-stats hackerman-severity-stats-json hackerman-severity-stats-test
# Wave-1 hackerman capability lift (PR #726) - per-severity distribution
# stats across audit/corpus_tags/tags/ (critical / high / medium / low /
# info / etc.). Sibling of hackerman-language-stats and
# hackerman-domain-stats on the orthogonal severity_at_finding axis.
# Pair with -json for the auditooor.hackerman_severity_stats.v1 envelope.
hackerman-severity-stats:
	@python3 tools/hackerman-severity-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-severity-stats-json:
	@python3 tools/hackerman-severity-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-severity-stats-test:
	@python3 -m unittest tools.tests.test_hackerman_severity_stats -v

.PHONY: hackerman-attack-class-severity-matrix hackerman-attack-class-severity-matrix-json hackerman-attack-class-severity-matrix-test
# Wave-1 hackerman capability lift (PR #726) - per-attack-class severity
# histogram matrix across audit/corpus_tags/tags/. For each attack_class
# emits histogram (critical / high / medium / low / info / etc.) plus the
# severity-mode + tier-1+2-only severity-mode (cross-validation knob) to
# aid Rule-14 upside-asymmetric filing decisions. Sibling of
# hackerman-attack-class-distribution (orthogonal subtree axis) and
# hackerman-severity-stats (orthogonal aggregate axis). Pair with -json
# for the auditooor.hackerman_attack_class_severity_matrix.v1 envelope.
hackerman-attack-class-severity-matrix:
	@python3 tools/hackerman-attack-class-severity-matrix.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-attack-class-severity-matrix-json:
	@python3 tools/hackerman-attack-class-severity-matrix.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-attack-class-severity-matrix-test:
	@python3 -m unittest tools.tests.test_hackerman_attack_class_severity_matrix -v

.PHONY: hackerman-domain-stats hackerman-domain-stats-json hackerman-domain-stats-test
# Wave-1 hackerman capability lift (PR #726) - target_domain distribution
# across audit/corpus_tags/tags/ (vault / dex / lending / oracle / bridge /
# governance / staking / etc.). Sibling of hackerman-attack-class-distribution
# but on the orthogonal protocol-domain axis. Pair with -json for the
# auditooor.hackerman_domain_stats.v1 envelope.
hackerman-domain-stats:
	@python3 tools/hackerman-domain-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-domain-stats-json:
	@python3 tools/hackerman-domain-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-domain-stats-test:
	@python3 -m unittest tools.tests.test_hackerman_domain_stats -v

.PHONY: hackerman-stats-all hackerman-stats-all-json hackerman-stats-all-test
# Wave-1 hackerman capability lift (PR #726) - master composite that runs all
# six Wave-1 stats panels in sequence:
#   1) hackerman-corpus-stats             (shape histogram + tier/acceptance gates)
#   2) hackerman-language-stats           (target_language distribution)
#   3) hackerman-domain-stats             (target_domain distribution)
#   4) hackerman-severity-stats           (severity_at_finding distribution)
#   5) hackerman-attack-class-distribution (per-subtree x per-class matrix, dense)
#   6) hackerman-tier-history-snapshot    (versioned tier snapshot for trend
#                                          tracking; writes to
#                                          audit/wave1_snapshots/tier_history/)
#
# Each panel is delimited with a visible banner so the combined output can be
# scanned without piping through additional formatting. Panels are independent;
# a failure in one does not short-circuit subsequent panels (the operator gets
# a complete report even if a single stat tool errors). Pair with
# hackerman-stats-all-json to run every panel in --json mode for downstream
# tooling, or hackerman-stats-all-test to run each panel's unit-test module.
#
# Knobs:
#   TAGS_DIR=<path>       forwarded to every panel (override corpus root)
#   GENERATED_AT=<iso>    forwarded to panels that accept --generated-at
#                         (corpus-stats / tier-history-snapshot) for
#                         reproducible builds
hackerman-stats-all:
	@echo "=== [1/6] hackerman-corpus-stats ==="
	@$(MAKE) --no-print-directory hackerman-corpus-stats \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") \
	  $(if $(GENERATED_AT),GENERATED_AT="$(GENERATED_AT)") || true
	@echo
	@echo "=== [2/6] hackerman-language-stats ==="
	@$(MAKE) --no-print-directory hackerman-language-stats \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") || true
	@echo
	@echo "=== [3/6] hackerman-domain-stats ==="
	@$(MAKE) --no-print-directory hackerman-domain-stats \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") || true
	@echo
	@echo "=== [4/6] hackerman-severity-stats ==="
	@$(MAKE) --no-print-directory hackerman-severity-stats \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") || true
	@echo
	@echo "=== [5/6] hackerman-attack-class-distribution ==="
	@$(MAKE) --no-print-directory hackerman-attack-class-distribution \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") || true
	@echo
	@echo "=== [6/6] hackerman-tier-history-snapshot ==="
	@$(MAKE) --no-print-directory hackerman-tier-history-snapshot \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") \
	  $(if $(GENERATED_AT),GENERATED_AT="$(GENERATED_AT)") || true
	@echo
	@echo "=== hackerman-stats-all DONE (6 panels) ==="

# JSON-mode composite: run every panel with JSON=1 / --json so the combined
# stdout is a sequence of JSON envelopes (one per panel) delimited by banners
# on stderr. Useful for downstream tooling that wants machine-readable output
# for every Wave-1 stat axis in a single shell.
hackerman-stats-all-json:
	@echo "=== [1/6] hackerman-corpus-stats --json ===" >&2
	@$(MAKE) --no-print-directory hackerman-corpus-stats JSON=1 \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") \
	  $(if $(GENERATED_AT),GENERATED_AT="$(GENERATED_AT)") || true
	@echo "=== [2/6] hackerman-language-stats-json ===" >&2
	@$(MAKE) --no-print-directory hackerman-language-stats-json \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") || true
	@echo "=== [3/6] hackerman-domain-stats-json ===" >&2
	@$(MAKE) --no-print-directory hackerman-domain-stats-json \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") || true
	@echo "=== [4/6] hackerman-severity-stats-json ===" >&2
	@$(MAKE) --no-print-directory hackerman-severity-stats-json \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") || true
	@echo "=== [5/6] hackerman-attack-class-distribution-json ===" >&2
	@$(MAKE) --no-print-directory hackerman-attack-class-distribution-json \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") || true
	@echo "=== [6/6] hackerman-tier-history-snapshot JSON=1 ===" >&2
	@$(MAKE) --no-print-directory hackerman-tier-history-snapshot JSON=1 \
	  $(if $(TAGS_DIR),TAGS_DIR="$(TAGS_DIR)") \
	  $(if $(GENERATED_AT),GENERATED_AT="$(GENERATED_AT)") || true
	@echo "=== hackerman-stats-all-json DONE (6 panels) ===" >&2

# Test composite: run every panel's unit-test module in sequence. Each
# panel test is independent; a failure in one module does not abort the
# subsequent modules (the operator sees the full pass/fail matrix).
hackerman-stats-all-test:
	@echo "=== [1/6] test_hackerman_corpus_stats ==="
	@$(MAKE) --no-print-directory hackerman-corpus-stats-test || true
	@echo "=== [2/6] test_hackerman_language_stats ==="
	@$(MAKE) --no-print-directory hackerman-language-stats-test || true
	@echo "=== [3/6] test_hackerman_domain_stats ==="
	@$(MAKE) --no-print-directory hackerman-domain-stats-test || true
	@echo "=== [4/6] test_hackerman_severity_stats ==="
	@$(MAKE) --no-print-directory hackerman-severity-stats-test || true
	@echo "=== [5/6] test_hackerman_attack_class_distribution ==="
	@$(MAKE) --no-print-directory hackerman-attack-class-distribution-test || true
	@echo "=== [6/6] test_hackerman_tier_history_snapshot ==="
	@$(MAKE) --no-print-directory hackerman-tier-history-snapshot-test || true
	@echo "=== hackerman-stats-all-test DONE (6 modules) ==="

.PHONY: hackerman-target-repo-stats hackerman-target-repo-stats-json hackerman-target-repo-stats-test
# Wave-1 hackerman capability lift (PR #726) - target_repo distribution
# across audit/corpus_tags/tags/ with tier-1/2/3 (verification_tier)
# breakdown. Sibling of hackerman-language-stats / hackerman-domain-stats
# / hackerman-severity-stats on the orthogonal target_repo axis. Top-50
# repos by record count is the human panel default; -json envelope
# (auditooor.hackerman_target_repo_stats.v1) carries the full distribution.
hackerman-target-repo-stats:
	@python3 tools/hackerman-target-repo-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-target-repo-stats-json:
	@python3 tools/hackerman-target-repo-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-target-repo-stats-test:
	@python3 -m unittest tools.tests.test_hackerman_target_repo_stats -v

.PHONY: hackerman-year-stats hackerman-year-stats-json hackerman-year-stats-test
# Wave-1 hackerman capability lift (PR #726) - per-year distribution
# across audit/corpus_tags/tags/ with tier-1/2/3 (verification_tier) and
# subtree breakdowns. Sibling of hackerman-language-stats /
# hackerman-domain-stats / hackerman-severity-stats /
# hackerman-target-repo-stats on the orthogonal calendar-year axis.
# Year extracted (precedence): top-level ``year:`` / ``incident_date`` /
# ``disclosure_date`` / ``Published-at`` precondition substring /
# ``source_audit_ref`` URL regex (20\d{2}). Chronological table is the
# human panel default; -json envelope
# (auditooor.hackerman_year_stats.v1) carries the full distribution.
hackerman-year-stats:
	@python3 tools/hackerman-year-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-year-stats-json:
	@python3 tools/hackerman-year-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-year-stats-test:
	@python3 -m unittest tools.tests.test_hackerman_year_stats -v

.PHONY: hackerman-contest-contributor-stats hackerman-contest-contributor-stats-json hackerman-contest-contributor-stats-test
# Wave-1 hackerman capability lift (PR #726) - per-contributor (warden /
# submitter handle) finding-count distribution across
# audit/corpus_tags/tags/contest_platform_findings/. Code4rena handles
# parsed from "Reported by handle <name>" in required_preconditions;
# Sherlock handles parsed from the "<title>. <Warden> <severity> #" prefix
# in attacker_action_sequence. Top-50 by count and by severity-weighted
# score (critical=5, high=3, medium=1, low=0.3, info=0.1) + cross-platform
# list of contributors active on both code4rena AND sherlock. -json emits
# the auditooor.hackerman_contest_contributor_stats.v1 envelope.
hackerman-contest-contributor-stats:
	@python3 tools/hackerman-contest-contributor-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

hackerman-contest-contributor-stats-json:
	@python3 tools/hackerman-contest-contributor-stats.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  --json \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

hackerman-contest-contributor-stats-test:
	@python3 -m unittest tools.tests.test_hackerman_contest_contributor_stats -v

.PHONY: hackerman-pr726-density-analyzer hackerman-pr726-density-analyzer-json hackerman-pr726-density-analyzer-test
# Wave-1 hackerman capability lift (PR #726) - commit-density analyzer.
# Reads `git log origin/wave-1-hackerman-capability-lift --since 2026-05-08`
# and aggregates commits per day, per author, per lane (regex on subject),
# and per hour-of-day landing. -json emits the
# auditooor.hackerman_pr726_density_analyzer.v1 envelope. Supports
# --log-file <path> for deterministic test fixtures.
hackerman-pr726-density-analyzer:
	@python3 tools/hackerman-pr726-density-analyzer.py \
	  $(if $(REPO),--repo "$(REPO)") \
	  $(if $(BRANCH),--branch "$(BRANCH)") \
	  $(if $(SINCE),--since "$(SINCE)") \
	  $(if $(LOG_FILE),--log-file "$(LOG_FILE)") \
	  $(if $(OUT_REPORT),--out-report "$(OUT_REPORT)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

hackerman-pr726-density-analyzer-json:
	@python3 tools/hackerman-pr726-density-analyzer.py \
	  $(if $(REPO),--repo "$(REPO)") \
	  $(if $(BRANCH),--branch "$(BRANCH)") \
	  $(if $(SINCE),--since "$(SINCE)") \
	  $(if $(LOG_FILE),--log-file "$(LOG_FILE)") \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

hackerman-pr726-density-analyzer-test:
	@python3 -m unittest tools.tests.test_hackerman_pr726_density_analyzer -v

.PHONY: hackerman-audit-firm-coverage-matrix hackerman-audit-firm-coverage-matrix-json hackerman-audit-firm-coverage-matrix-test
# Wave-1 hackerman capability lift (PR #726) - per-firm x per-project
# coverage matrix for the audit_firm_public_reports subtree (1681
# records / 8 firms shipped at 5985377e03). Surfaces 3+-firm projects
# (high-confidence cross-validation anchors) vs 1-firm-only projects
# (lower-confidence; potential audit-firm-bias). Pair with -json for the
# auditooor.hackerman_audit_firm_coverage_matrix.v1 envelope.
hackerman-audit-firm-coverage-matrix:
	@python3 tools/hackerman-audit-firm-coverage-matrix.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-audit-firm-coverage-matrix-json:
	@python3 tools/hackerman-audit-firm-coverage-matrix.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  --json \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)")

hackerman-audit-firm-coverage-matrix-test:
	@python3 -m unittest tools.tests.test_hackerman_audit_firm_coverage_matrix -v

.PHONY: hackerman-etl-from-audit-firm-public-reports hackerman-etl-from-audit-firm-public-reports-test hackerman-etl-from-audit-firm-pdf-pashov hackerman-etl-from-audit-firm-pdf-pashov-test hackerman-etl-from-audit-firm-pdf-sb-security hackerman-etl-from-audit-firm-pdf-sb-security-test
hackerman-etl-from-audit-firm-public-reports:
	@python3 tools/hackerman-etl-from-audit-firm-public-reports.py \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  $(if $(TREES_CACHE),--trees-cache "$(TREES_CACHE)") \
	  $(if $(WRITE_TREES_CACHE),--write-trees-cache "$(WRITE_TREES_CACHE)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-public-reports-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_public_reports -v

hackerman-etl-from-audit-firm-pdf-pashov:
	@python3 tools/hackerman-etl-from-audit-firm-pdf-pashov.py \
	  --listings-dir "$(if $(LISTINGS_DIR),$(LISTINGS_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),.auditooor/audit_firm_pdf_cache)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_findings_pashov)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(NO_FETCH),--no-fetch) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SUMMARY),--summary-path "$(SUMMARY)") \
	  $(if $(MAX_PDF_BYTES),--max-pdf-bytes "$(MAX_PDF_BYTES)") \
	  $(if $(RATE_LIMIT_PER_SEC),--rate-limit-per-sec "$(RATE_LIMIT_PER_SEC)") \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-pdf-pashov-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_pdf_pashov -v

hackerman-etl-from-audit-firm-pdf-sb-security:
	@python3 tools/hackerman-etl-from-audit-firm-pdf-sb-security.py \
	  --listings-dir "$(if $(LISTINGS_DIR),$(LISTINGS_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),.auditooor/audit_firm_pdf_cache)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_findings_sb_security)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(NO_FETCH),--no-fetch) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SUMMARY),--summary-path "$(SUMMARY)") \
	  $(if $(MAX_PDF_BYTES),--max-pdf-bytes "$(MAX_PDF_BYTES)") \
	  $(if $(RATE_LIMIT_PER_SEC),--rate-limit-per-sec "$(RATE_LIMIT_PER_SEC)") \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-pdf-sb-security-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_pdf_sb_security -v

# --- Wave-2 W2.4 deep-mine ETLs: the 7 remaining audit-firm PDF parsers ---
# These were shipped (tools/hackerman-etl-from-audit-firm-pdf-<firm>.py) and
# unit-tested but never wired to a Makefile producer, so the corpus sat at 0
# records (registry makefile_target=null). Each stanza clones the pashov shape
# exactly (identical flag set, confirmed in each firm's argparse). The
# public-reports listings producer (make hackerman-etl-from-audit-firm-public-reports)
# must run first to populate audit_firm_public_reports/ - the umbrella
# hackerman-etl-from-audit-firm-pdf-all target chains that ordering.
.PHONY: hackerman-etl-from-audit-firm-pdf-zellic hackerman-etl-from-audit-firm-pdf-zellic-test
hackerman-etl-from-audit-firm-pdf-zellic:
	@python3 tools/hackerman-etl-from-audit-firm-pdf-zellic.py \
	  --listings-dir "$(if $(LISTINGS_DIR),$(LISTINGS_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),.auditooor/audit_firm_pdf_cache)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_findings_zellic)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(NO_FETCH),--no-fetch) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SUMMARY),--summary-path "$(SUMMARY)") \
	  $(if $(MAX_PDF_BYTES),--max-pdf-bytes "$(MAX_PDF_BYTES)") \
	  $(if $(RATE_LIMIT_PER_SEC),--rate-limit-per-sec "$(RATE_LIMIT_PER_SEC)") \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-pdf-zellic-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_pdf_zellic -v

.PHONY: hackerman-etl-from-audit-firm-pdf-tob hackerman-etl-from-audit-firm-pdf-tob-test
hackerman-etl-from-audit-firm-pdf-tob:
	@python3 tools/hackerman-etl-from-audit-firm-pdf-tob.py \
	  --listings-dir "$(if $(LISTINGS_DIR),$(LISTINGS_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),.auditooor/audit_firm_pdf_cache)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_findings_tob)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(NO_FETCH),--no-fetch) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SUMMARY),--summary-path "$(SUMMARY)") \
	  $(if $(MAX_PDF_BYTES),--max-pdf-bytes "$(MAX_PDF_BYTES)") \
	  $(if $(RATE_LIMIT_PER_SEC),--rate-limit-per-sec "$(RATE_LIMIT_PER_SEC)") \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-pdf-tob-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_pdf_tob -v

.PHONY: hackerman-etl-from-audit-firm-pdf-chainsecurity hackerman-etl-from-audit-firm-pdf-chainsecurity-test
hackerman-etl-from-audit-firm-pdf-chainsecurity:
	@python3 tools/hackerman-etl-from-audit-firm-pdf-chainsecurity.py \
	  --listings-dir "$(if $(LISTINGS_DIR),$(LISTINGS_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),.auditooor/audit_firm_pdf_cache)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_findings_chainsecurity)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(NO_FETCH),--no-fetch) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SUMMARY),--summary-path "$(SUMMARY)") \
	  $(if $(MAX_PDF_BYTES),--max-pdf-bytes "$(MAX_PDF_BYTES)") \
	  $(if $(RATE_LIMIT_PER_SEC),--rate-limit-per-sec "$(RATE_LIMIT_PER_SEC)") \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-pdf-chainsecurity-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_pdf_chainsecurity -v

.PHONY: hackerman-etl-from-audit-firm-pdf-cyfrin hackerman-etl-from-audit-firm-pdf-cyfrin-test
hackerman-etl-from-audit-firm-pdf-cyfrin:
	@python3 tools/hackerman-etl-from-audit-firm-pdf-cyfrin.py \
	  --listings-dir "$(if $(LISTINGS_DIR),$(LISTINGS_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),.auditooor/audit_firm_pdf_cache)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_findings_cyfrin)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(NO_FETCH),--no-fetch) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SUMMARY),--summary-path "$(SUMMARY)") \
	  $(if $(MAX_PDF_BYTES),--max-pdf-bytes "$(MAX_PDF_BYTES)") \
	  $(if $(RATE_LIMIT_PER_SEC),--rate-limit-per-sec "$(RATE_LIMIT_PER_SEC)") \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-pdf-cyfrin-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_pdf_cyfrin -v

.PHONY: hackerman-etl-from-audit-firm-pdf-openzeppelin hackerman-etl-from-audit-firm-pdf-openzeppelin-test
hackerman-etl-from-audit-firm-pdf-openzeppelin:
	@python3 tools/hackerman-etl-from-audit-firm-pdf-openzeppelin.py \
	  --listings-dir "$(if $(LISTINGS_DIR),$(LISTINGS_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),.auditooor/audit_firm_pdf_cache)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_findings_openzeppelin)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(NO_FETCH),--no-fetch) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SUMMARY),--summary-path "$(SUMMARY)") \
	  $(if $(MAX_PDF_BYTES),--max-pdf-bytes "$(MAX_PDF_BYTES)") \
	  $(if $(RATE_LIMIT_PER_SEC),--rate-limit-per-sec "$(RATE_LIMIT_PER_SEC)") \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-pdf-openzeppelin-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_pdf_openzeppelin -v

.PHONY: hackerman-etl-from-audit-firm-pdf-sherlock hackerman-etl-from-audit-firm-pdf-sherlock-test
hackerman-etl-from-audit-firm-pdf-sherlock:
	@python3 tools/hackerman-etl-from-audit-firm-pdf-sherlock.py \
	  --listings-dir "$(if $(LISTINGS_DIR),$(LISTINGS_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),.auditooor/audit_firm_pdf_cache)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_findings_sherlock)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(NO_FETCH),--no-fetch) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SUMMARY),--summary-path "$(SUMMARY)") \
	  $(if $(MAX_PDF_BYTES),--max-pdf-bytes "$(MAX_PDF_BYTES)") \
	  $(if $(RATE_LIMIT_PER_SEC),--rate-limit-per-sec "$(RATE_LIMIT_PER_SEC)") \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-pdf-sherlock-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_pdf_sherlock -v

.PHONY: hackerman-etl-from-audit-firm-pdf-spearbit hackerman-etl-from-audit-firm-pdf-spearbit-test
hackerman-etl-from-audit-firm-pdf-spearbit:
	@python3 tools/hackerman-etl-from-audit-firm-pdf-spearbit.py \
	  --listings-dir "$(if $(LISTINGS_DIR),$(LISTINGS_DIR),audit/corpus_tags/tags/audit_firm_public_reports)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),.auditooor/audit_firm_pdf_cache)" \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/audit_firm_findings_spearbit)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(NO_FETCH),--no-fetch) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SUMMARY),--summary-path "$(SUMMARY)") \
	  $(if $(MAX_PDF_BYTES),--max-pdf-bytes "$(MAX_PDF_BYTES)") \
	  $(if $(RATE_LIMIT_PER_SEC),--rate-limit-per-sec "$(RATE_LIMIT_PER_SEC)") \
	  $(if $(JSON),--json-summary)

hackerman-etl-from-audit-firm-pdf-spearbit-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_audit_firm_pdf_spearbit -v

# Umbrella: run all 9 firm PDF deep-mine ETLs in sequence (listings first),
# giving the corpus loop a single entry point.
.PHONY: hackerman-etl-from-audit-firm-pdf-all
hackerman-etl-from-audit-firm-pdf-all:
	@$(MAKE) hackerman-etl-from-audit-firm-public-reports
	@$(MAKE) hackerman-etl-from-audit-firm-pdf-pashov
	@$(MAKE) hackerman-etl-from-audit-firm-pdf-sb-security
	@$(MAKE) hackerman-etl-from-audit-firm-pdf-zellic
	@$(MAKE) hackerman-etl-from-audit-firm-pdf-tob
	@$(MAKE) hackerman-etl-from-audit-firm-pdf-chainsecurity
	@$(MAKE) hackerman-etl-from-audit-firm-pdf-cyfrin
	@$(MAKE) hackerman-etl-from-audit-firm-pdf-openzeppelin
	@$(MAKE) hackerman-etl-from-audit-firm-pdf-sherlock
	@$(MAKE) hackerman-etl-from-audit-firm-pdf-spearbit

.PHONY: hackerman-integrity-check hackerman-integrity-check-json hackerman-integrity-check-test
# Wave-1 hackerman capability lift (PR #726) - end-to-end aggregator that
# runs every hackerman stage in sequence (schema, tier, acceptance, dupes,
# stats, distribution) and emits a single overall verdict. Pass STRICT=1 to
# exit non-zero when any stage fails OR any non-exempt dupe group exists.
hackerman-integrity-check:
	@python3 tools/hackerman-integrity-check.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(DUPES_JSONL),--dupes-jsonl-out "$(DUPES_JSONL)") \
	  $(if $(STAGE),--stage "$(STAGE)") \
	  $(if $(STRICT),--strict) \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

# Machine-consumable JSON envelope (auditooor.hackerman_integrity_check.v1).
hackerman-integrity-check-json:
	@python3 tools/hackerman-integrity-check.py \
	  --json \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(DUPES_JSONL),--dupes-jsonl-out "$(DUPES_JSONL)") \
	  $(if $(STAGE),--stage "$(STAGE)") \
	  $(if $(STRICT),--strict) \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)")

hackerman-integrity-check-test:
	@python3 -m unittest tools.tests.test_hackerman_integrity_check -v

.PHONY: hackerman-health-dashboard hackerman-health-dashboard-json hackerman-health-dashboard-test
# Wave-1 hackerman capability lift (PR #726) - compact one-shot health
# dashboard that aggregates the four Wave-1 axes (corpus-stats,
# gates-status, integrity-check, mcp-smoke-test) into a single coloured
# status surface (<=80 lines of human output by default). Each upstream
# tool is invoked once in --json mode; the aggregator does NOT re-derive
# any underlying corpus / gate state. One axis failure does not
# short-circuit the others.
#
# Knobs:
#   STRICT=1                 exit non-zero when overall verdict != pass
#   AXIS=<name>              restrict to one axis (corpus / gates /
#                            integrity / mcp-smoke); repeatable via DASH_ARGS
#   MCP_SMOKE_TIMEOUT=<s>    per-callable timeout for the mcp-smoke axis
#                            (default 10)
#   MAX_LINES=<n>            hard cap on rendered human-output lines
#   GENERATED_AT=<iso>       pin generated_at for reproducible builds
#   DASH_ARGS=<...>          extra args (e.g. --no-color, --force-color)
hackerman-health-dashboard:
	@python3 tools/hackerman-health-dashboard.py \
	  $(if $(AXIS),--axis "$(AXIS)") \
	  $(if $(MCP_SMOKE_TIMEOUT),--mcp-smoke-timeout "$(MCP_SMOKE_TIMEOUT)") \
	  $(if $(MAX_LINES),--max-lines "$(MAX_LINES)") \
	  $(if $(STRICT),--strict) \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)") \
	  $(DASH_ARGS)

# Machine-consumable JSON envelope
# (auditooor.hackerman_health_dashboard.v1).
hackerman-health-dashboard-json:
	@python3 tools/hackerman-health-dashboard.py \
	  --json \
	  $(if $(AXIS),--axis "$(AXIS)") \
	  $(if $(MCP_SMOKE_TIMEOUT),--mcp-smoke-timeout "$(MCP_SMOKE_TIMEOUT)") \
	  $(if $(STRICT),--strict) \
	  $(if $(GENERATED_AT),--generated-at "$(GENERATED_AT)") \
	  $(DASH_ARGS)

hackerman-health-dashboard-test:
	@python3 -m unittest tools.tests.test_hackerman_health_dashboard -v

.PHONY: hackerman-help hackerman-help-json hackerman-help-test
# Wave-1 hackerman capability lift (PR #726) - navigable index of all
# hackerman-* make targets defined in this Makefile. One-shot lookup tool
# (not deeply interactive). Pairs hackerman-help (human format, default)
# with hackerman-help-json (auditooor.hackerman_help.v1 envelope).
# Knobs:
#   MAKEFILE=<path>     scan a different Makefile (default: repo-root)
#   OUT=<path>          write to file instead of stdout
hackerman-help:
	@python3 tools/hackerman-help.py \
	  $(if $(MAKEFILE),--makefile "$(MAKEFILE)") \
	  $(if $(OUT),--out "$(OUT)")

hackerman-help-json:
	@python3 tools/hackerman-help.py \
	  --json \
	  $(if $(MAKEFILE),--makefile "$(MAKEFILE)") \
	  $(if $(OUT),--out "$(OUT)")

hackerman-help-test:
	@python3 -m unittest tools.tests.test_hackerman_help -v

.PHONY: vault-mcp-help vault-mcp-help-json vault-mcp-help-test
# Wave-1 hackerman capability lift (PR #726) - navigable index of all
# vault_* MCP callables exposed by tools/vault-mcp-server.py. Companion
# to `hackerman-help` (which indexes Makefile targets). For each callable
# emits: name, schema id, one-line description, input/required fields,
# best-effort output fields, source lineno. Pairs the human index
# (default) with a JSON envelope (`auditooor.vault_mcp_help.v1`).
# Knobs:
#   SERVER=<path>       scan a different vault-mcp-server.py (default: repo tools/)
#   OUT=<path>          write to file instead of stdout
vault-mcp-help:
	@python3 tools/vault-mcp-help.py \
	  $(if $(SERVER),--server "$(SERVER)") \
	  $(if $(OUT),--out "$(OUT)")

vault-mcp-help-json:
	@python3 tools/vault-mcp-help.py \
	  --json \
	  $(if $(SERVER),--server "$(SERVER)") \
	  $(if $(OUT),--out "$(OUT)")

vault-mcp-help-test:
	@python3 -m unittest tools.tests.test_vault_mcp_help -v

.PHONY: hackerman-provenance-audit hackerman-provenance-audit-json hackerman-provenance-audit-test
# Wave-1 hackerman capability lift (PR #726) - provenance audit across
# four axes (source_audit_ref well-formedness, required_preconditions
# URL citations, verification_tier:tier-N-* tag, tier-1 re-fetchability).
# Walks audit/corpus_tags/tags/ and emits .auditooor/provenance_audit.jsonl
# (gitignored). Pairs the human report (default) with the JSON envelope.
# Knobs:
#   TAGS_DIR=<path>     scan a different tags dir (default: repo audit/corpus_tags/tags)
#   OUT_JSONL=<path>    override the per-record ledger output path
#   LIMIT=<n>           cap scanned files (smoke/CI)
#   STRICT=1            exit non-zero on any record with gaps
hackerman-provenance-audit:
	@python3 tools/hackerman-record-provenance-audit.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(OUT_JSONL),--out-jsonl "$(OUT_JSONL)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(STRICT),--strict)

hackerman-provenance-audit-json:
	@python3 tools/hackerman-record-provenance-audit.py \
	  --json \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(OUT_JSONL),--out-jsonl "$(OUT_JSONL)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(STRICT),--strict)

hackerman-provenance-audit-test:
	@python3 -m unittest tools.tests.test_hackerman_record_provenance_audit -v

.PHONY: hacker-brief
hacker-brief:
	@if [ -z "$(WS)" ]; then echo "ERROR: WS=<workspace> required"; exit 2; fi
	@if [ -z "$(LANE)" ]; then echo "ERROR: LANE=<lane-id> required"; exit 2; fi
	@mkdir -p $(WS)/.auditooor
	python3 tools/agent-prompt-hacker-augmenter.py --workspace $(WS) --lane-id $(LANE) --files "$(if $(FILES),$(FILES),$(WS)/SCOPE.md)" --out $(WS)/.auditooor/hacker_brief.md --json-out
	@if [ -f tools/hackerman-brief-for-lane.py ]; then \
	  brief="$(WS)/.auditooor/hacker_brief.md"; \
	  hackerman_json="$(WS)/.auditooor/hacker_brief.hackerman.json"; \
	  python3 tools/hackerman-brief-for-lane.py --workspace "$(WS)" --lane-id "$(LANE)" --files "$(if $(FILES),$(FILES),$(WS)/SCOPE.md)" --limit "$(if $(LIMIT),$(LIMIT),20)" --json > "$$hackerman_json"; \
	  python3 -c 'import json, sys; from pathlib import Path; brief=Path(sys.argv[1]); payload=json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")); markdown=(payload.get("brief_markdown") or "").strip(); brief.write_text(brief.read_text(encoding="utf-8").rstrip() + "\n\n---\n\n" + markdown + "\n", encoding="utf-8") if markdown else None' "$$brief" "$$hackerman_json"; \
	fi

.PHONY: loop-finalization-check
loop-finalization-check:
	@_mf="$(MANIFEST)"; \
	if [ -z "$$_mf" ] && [ -n "$(WS)" ]; then \
	  _mf="$(_WS_RESOLVED)/.auditooor/finalization/current_manifest.json"; \
	fi; \
	if [ -z "$$_mf" ]; then \
	  echo "Usage: make loop-finalization-check MANIFEST=<manifest.json> | WS=<workspace> [ALLOW_NO_ARTIFACT=1] [JSON=1]"; \
	  echo "  WS=<workspace> resolves MANIFEST to <ws>/.auditooor/finalization/current_manifest.json"; \
	  exit 2; \
	fi; \
	python3 tools/loop-finalization-check.py \
	  --manifest "$$_mf" \
	  $(if $(ALLOW_NO_ARTIFACT),--allow-no-artifact) \
	  $(if $(JSON),--json)

.PHONY: agent-cycle-close
agent-cycle-close:
	@if [ -z "$(WS)" ]; then echo "Usage: make agent-cycle-close WS=<workspace> MANIFEST=<manifest.json> [AGENT=codex] [TASK=<slice>] [NOTE=<text>]"; exit 2; fi
	@if [ -z "$(MANIFEST)" ]; then echo "Usage: make agent-cycle-close WS=<workspace> MANIFEST=<manifest.json> [AGENT=codex] [TASK=<slice>] [NOTE=<text>]"; exit 2; fi
	@python3 tools/agent-cycle-log.py append \
	  --workspace "$(WS)" \
	  --event close \
	  --manifest "$(MANIFEST)" \
	  --agent "$(if $(AGENT),$(AGENT),codex)" \
	  $(if $(TASK),--task "$(TASK)") \
	  $(if $(NOTE),--note "$(NOTE)")

.PHONY: adversarial-sweep
adversarial-sweep:
	@if [ -z "$(WS)" ]; then echo "ERROR: WS=<workspace> required"; exit 2; fi
	@for f in $(WS)/submissions/paste_ready/*.md $(WS)/submissions/staging/*.md; do \
		[ -f "$$f" ] || continue; \
		echo "=== $$f ==="; \
		python3 tools/adversarial-copilot.py --draft "$$f" --workspace $(WS) --dry-run || true; \
	done

.PHONY: discoverability-refresh
discoverability-refresh:
	@_TOOL=tools/mcp-search-index-rebuild.py; \
	if [ -f "$$_TOOL" ]; then \
		python3 "$$_TOOL"; \
	else \
		echo "WARN: $$_TOOL not yet implemented (W2 plan 07 §11a backlog)"; \
		echo "Synonym map at reference/vault_search_synonyms.yaml ($$(grep -c '^- canonical:' reference/vault_search_synonyms.yaml 2>/dev/null || echo 0) rows) - refresh is a no-op until tool ships."; \
	fi

.PHONY: audit-question-burndown
audit-question-burndown:
	@if [ -z "$(WS)" ]; then echo "ERROR: WS=<workspace> required"; exit 2; fi
	python3 tools/audit-question-burndown.py --workspace $(WS)

.PHONY: chained-attack-plans
chained-attack-plans:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make chained-attack-plans WS=<workspace> [MAX_PLANS=<n>] [OUT=<path>] [MD_OUT=<path>] [PRINT_JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make chained-attack-plans" "$(_WS_RESOLVED)"
	@set -e; \
	json_out="$(if $(OUT),$(OUT),$(_WS_RESOLVED)/swarm/chained_attack_plans.json)"; \
	md_out="$(if $(MD_OUT),$(MD_OUT),$(_WS_RESOLVED)/swarm/chained_attack_plans.md)"; \
	python3 tools/chained-attack-planner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --emit-chain-synth-source-links \
	  $(if $(EXPLOIT_JSON),--exploit-json "$(EXPLOIT_JSON)") \
	  $(if $(BRIEF_CANDIDATES),--brief-candidates "$(BRIEF_CANDIDATES)") \
	  $(if $(SWARM_MANIFEST),--swarm-manifest "$(SWARM_MANIFEST)") \
	  $(if $(BIG_LOSS_JSON),--big-loss-json "$(BIG_LOSS_JSON)") \
	  --out "$$json_out" \
	  --markdown-out "$$md_out" \
	  $(if $(MAX_PLANS),--max-plans "$(MAX_PLANS)") \
	  $(if $(PRINT_JSON),--print-json); \
	echo "[make chained-attack-plans] wrote $$json_out"; \
	echo "[make chained-attack-plans] wrote $$md_out"; \
	echo "[make chained-attack-plans] advisory-only rows remain candidate_not_submit_ready"

.PHONY: proof-obligation-queue
proof-obligation-queue:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make proof-obligation-queue WS=<workspace> [HACKER_BRIEF_JSON="<path> [<path> ...]"] [HACKER_BRIEF_MD="<path> [<path> ...]"] [CHAINED_PLANS=<path>] [DETECTOR_ACTION_GRAPH="<path> [<path> ...]"] [OUT=<path>] [MAX_TASKS=<n>] [PRINT_JSON=1]'; \
	  echo 'Default detector graph discovery: audit_hacker_logic_bridge.json graphs, then .auditooor/detector_action_graphs/*.json, then legacy detector_action_graph.json'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make proof-obligation-queue" "$(_WS_RESOLVED)"
	@set -e; \
	out_path="$(if $(OUT),$(OUT),$(_WS_RESOLVED)/.auditooor/proof_obligation_queue.json)"; \
	python3 tools/proof-obligation-queue.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(foreach path,$(HACKER_BRIEF_JSON),--hacker-brief-json "$(path)") \
	  $(foreach path,$(HACKER_BRIEF_MD),--hacker-brief-md "$(path)") \
	  $(if $(CHAINED_PLANS),--chained-plans "$(CHAINED_PLANS)") \
	  $(foreach path,$(DETECTOR_ACTION_GRAPH),--detector-action-graph "$(path)") \
	  --out "$$out_path" \
	  $(if $(MAX_TASKS),--max-tasks "$(MAX_TASKS)") \
	  $(if $(PRINT_JSON),--print-json); \
	python3 tools/proof-queue-freshness-marker.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --mode mark-fresh \
	  --bridge-rc 0 \
	  --proof-queue "$$out_path" \
	  --reason "proof-obligation-queue completed directly" >/dev/null || \
	  echo "[make proof-obligation-queue] WARN failed to mark proof queue freshness" >&2; \
	echo "[make proof-obligation-queue] wrote $$out_path"; \
	echo "[make proof-obligation-queue] advisory-only rows require concrete source/PoC proof before submission"

.PHONY: proof-queue-freshness-marker-test
proof-queue-freshness-marker-test:
	@python3 -m unittest tools.tests.test_proof_queue_freshness_marker -v

.PHONY: exploit-queue exploit-queue-test exploit-queue-source-mine exploit-queue-source-mine-test source-mined-impact-contracts source-mined-impact-contracts-test corpus-driven-hunt corpus-driven-hunt-test prove-top-leads exploit-conversion-loop exploit-conversion-loop-test evm-0day-proof evm-0day-proof-test fresh-target-forward-test fresh-target-forward-test-test current-to-exploit-conversion-gate exploit-severity-scope-oracle poc-falsification-runner prior-disclosure-index prior-disclosure-index-test prefiling-stress-test prefiling-stress-test-test candidate-judgment-packet candidate-judgment-packet-test
exploit-queue:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make exploit-queue WS=<workspace> [JSON=1] [TOP_N=<n>]'; \
	  echo 'Writes <ws>/.auditooor/exploit_queue.json and exploit_queue.md'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make exploit-queue" "$(_WS_RESOLVED)"
	@python3 tools/exploit-queue.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--json) \
	  $(if $(TOP_N),--top-n "$(TOP_N)")

exploit-queue-test:
	@python3 -m unittest tools.tests.test_exploit_queue -v

exploit-queue-source-mine:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make exploit-queue-source-mine WS=<workspace> [TOP_N=10] [INCLUDE_OPEN_UNHUNTED=1] [REVIEW_ONLY=1] [UPDATE_QUEUE=1] [RUN_ID=<audit-run-id>] [JSON=1]'; \
	  echo 'Writes <ws>/.auditooor/source_artifacts/*.source_artifact.json and exploit_queue.source_mined.json'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make exploit-queue-source-mine" "$(_WS_RESOLVED)"
	@python3 tools/exploit-queue-source-miner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(INCLUDE_OPEN_UNHUNTED),--include-open-unhunted) \
	  $(if $(REVIEW_ONLY),--review-only) \
	  $(if $(UPDATE_QUEUE),--update-queue) \
	  $(if $(RUN_ID),--run-id "$(RUN_ID)") \
	  $(if $(JSON),--json)

exploit-queue-source-mine-test:
	@python3 -m unittest tools.tests.test_exploit_queue_source_miner -v

source-mined-impact-contracts:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make source-mined-impact-contracts WS=<workspace> [QUEUE=<json>] [OUT_JSON=<json>] [ROW=<id>] [UPDATE_QUEUE=1] [JSON=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make source-mined-impact-contracts" "$(_WS_RESOLVED)"
	@python3 tools/source-mined-impact-contracts.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(ROW),--row "$(ROW)") \
	  $(if $(UPDATE_QUEUE),--update-queue) \
	  $(if $(JSON),--print-json)

source-mined-impact-contracts-test:
	@python3 -m unittest tools.tests.test_source_mined_impact_contracts -v

corpus-driven-hunt:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make corpus-driven-hunt WS=<workspace> [TOP_N=25] [MAX_FUNCTIONS=all] [EMIT_PROOF_QUEUE=1] [MIMO=1] [JSON=1]'; \
	  echo 'Writes <ws>/.auditooor/corpus_driven_hunt.json and .md, and optionally UPSERTs proof obligations into exploit_queue.json'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make corpus-driven-hunt" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@if [ "$(STRICT)" = "1" ]; then \
	  python3 tools/zero-day-freeze-compiler.py --workspace "$(_WS_RESOLVED)" --write-identity-map \
	    --identity-map-out "$(_WS_RESOLVED)/.auditooor/zero_day_identity_map.jsonl"; \
	fi
	@python3 tools/corpus-driven-hunt.py "$(_WS_RESOLVED)" \
	  $(if $(SOURCE),--source "$(SOURCE)") \
	  $(if $(INVARIANT_CORPUS),--invariant-corpus "$(INVARIANT_CORPUS)") \
	  --top "$(if $(TOP_N),$(TOP_N),$(if $(TOP),$(TOP),25))" \
	  --max-functions "$(if $(MAX_FUNCTIONS),$(MAX_FUNCTIONS),all)" \
	  $(if $(STRICT),--strict) \
	  $(if $(filter 1 true yes,$(MIMO)),--mimo) \
	  $(if $(MIMO_OUT),--mimo-out "$(MIMO_OUT)") \
	  $(if $(MIMO_CONCURRENCY),--mimo-concurrency "$(MIMO_CONCURRENCY)") \
	  $(if $(filter 1 true yes,$(EMIT_PROOF_QUEUE)),--emit-proof-queue) \
	  $(if $(PROOF_QUEUE),--proof-queue-path "$(PROOF_QUEUE)") \
	  $(if $(filter 1 true yes,$(PROOF_QUEUE_DRY_RUN)),--proof-queue-dry-run) \
	  $(if $(BRAIN_PRIME_RECEIPT),--brain-prime-receipt "$(BRAIN_PRIME_RECEIPT)") \
	  $(if $(filter 1 true yes,$(NO_BRAIN_PRIME_GATE)),--no-brain-prime-gate) \
	  $(if $(HACKER_QUESTIONS),--hacker-questions "$(HACKER_QUESTIONS)") \
	  $(if $(filter 1 true yes,$(NO_HACKER_QUESTIONS)),--no-hacker-questions) \
	  $(if $(STRICT),--zero-day-fuel-out "$(_WS_RESOLVED)/.auditooor/zero_day_fuel_step-4c.jsonl") \
	  $(if $(STRICT),--zero-day-identity-map "$(_WS_RESOLVED)/.auditooor/zero_day_identity_map.jsonl") \
	  $(if $(STRICT),--awareness-ledger "$(_WS_RESOLVED)/.auditooor/awareness_ledger.json") \
	  --out "$(if $(OUT),$(OUT),$(_WS_RESOLVED)/.auditooor/corpus_driven_hunt.json)" \
	  --md-out "$(if $(MD_OUT),$(MD_OUT),$(_WS_RESOLVED)/.auditooor/corpus_driven_hunt.md)" \
	  $(if $(JSON),--json)

corpus-driven-hunt-test:
	@python3 -m unittest tools.tests.test_corpus_driven_hunt -v

# entrypoint-corpus-bridge: DRY-RUN report of corpus-INV `blocked_missing_truth`
# exploit-queue rows that are terminal-closable as closed_negative because the function
# is PROVABLY a non-entry-point (authoritative go_entrypoint_surface classifier) AND
# carries a missing:permissionless_trigger / missing:attacker_actor marker. Default is
# dry-run; pass WRITE=1 to APPLY the closures (never auto-runs with --write).
entrypoint-corpus-bridge:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make entrypoint-corpus-bridge WS=<workspace> [WRITE=1] [JSON=1]'; \
	  echo 'Reports corpus-INV blocked_missing_truth rows closable as closed_negative (non-entry-point helper + missing-trigger marker). DRY-RUN by default.'; exit 2; \
	fi
	@python3 tools/entrypoint-corpus-bridge.py --workspace "$(_WS_RESOLVED)" $(if $(WRITE),--write) $(if $(JSON),--json)

entrypoint-corpus-bridge-test:
	@python3 -m pytest tools/tests/test_entrypoint_corpus_bridge.py -q

prove-top-leads:
ifeq ($(AUDITOOOR_DEFER_DRIVE),1)
	@echo "[prove-top-leads] deferred: parent ordered driver has not reached the drive phase"
else
	$(call _require_pipeline_phase_token,prove-top-leads)
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make prove-top-leads WS=<workspace> [TOP_N=10] [EXECUTE_READY=1] [MAX_EXECUTE=5] [EXECUTION_TIMEOUT=300] [STRICT=1] [REQUIRE_STRICT_WIRING=1] [JSON=1]'; \
	  echo 'Runs source mining, builds a harness binding manifest from exploit_queue.source_mined.json, and emits/optionally executes the harness execution queue.'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make prove-top-leads" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@$(MAKE) --no-print-directory exploit-queue-source-mine WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),10)" JSON=1 > "$(_WS_RESOLVED)/.auditooor/prove_top_leads_source_mine.json"
	@$(MAKE) --no-print-directory source-mined-impact-contracts WS="$(_WS_RESOLVED)" UPDATE_QUEUE=1 JSON=1 > "$(_WS_RESOLVED)/.auditooor/prove_top_leads_source_mined_impact_contracts.json"
	@# Re-apply terminal-join from the persistent hunt sidecars onto the JUST-REBUILT
	@# source_mined queue BEFORE prefiling reads it. Without this the source-mine
	@# rebuild wipes prior closed_negative marks, so a fully-refuted top lead reappears
	@# as non-terminal every run (NUVA serving-join false-red: hunt done, gate blind).
	@python3 tools/exploit-queue-terminal-join.py --workspace "$(_WS_RESOLVED)" --apply >/dev/null 2>&1 || true
	@set -e; \
	queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.source_mined.json"; \
	if [ ! -f "$$queue" ]; then queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.json"; fi; \
	out="$(_WS_RESOLVED)/.auditooor/prove_top_leads_prefiling_stress_test.json"; \
	$(MAKE) --no-print-directory prefiling-stress-test \
	  WS="$(_WS_RESOLVED)" \
	  QUEUE="$$queue" \
	  TOP_N="$(if $(TOP_N),$(TOP_N),10)" \
	  JSON=1 $(if $(filter 1 true yes,$(STRICT)),STRICT=1,) > "$$out" || { \
	    rc=$$?; \
	    if [ -n "$(filter 1 true yes,$(STRICT))" ]; then \
	      echo "[prove-top-leads] STRICT=1: prefiling-stress-test blocked proof work; see $$out" >&2; \
	      exit $$rc; \
	    fi; \
	    echo "[prove-top-leads] WARN prefiling-stress-test found blockers; continuing because prefiling stress is advisory without STRICT=1; see $$out" >&2; \
	  }
	@# Regenerate the no-leads manifest against the LIVE queue AFTER the final
	@# source_mined rebuild + terminal-join + prefiling-stress, so its declared
	@# current_queue_rows matches what the completeness validator reads. Without
	@# this the manifest goes STALE the moment a rebuild changes the row count
	@# (NUVA: declared 7829 vs live 7826 after terminal-join settled the queue),
	@# and the freshness check false-reds an otherwise all-terminal honest-0. The
	@# producer is anti-fabrication safe: it REFUSES (writes nothing) unless the
	@# queue is empty OR the prefiling artifact just written confirms all-terminal,
	@# so this can never green the gate when real open leads remain.
	@python3 tools/prove-top-leads-no-leads-manifest.py --workspace "$(_WS_RESOLVED)" >/dev/null 2>&1 || true
	@# Refresh lesson/source inventories before candidate judgment. High-severity
	@# packets require a source-read receipt; generating these after the packet
	@# made the packet consume an empty predecessor and block valid downstream work.
	@set -e; \
		lessons_dir="$(_WS_RESOLVED)/.auditooor"; \
		python3 tools/agent-artifact-lesson-candidates.py \
		  --workspace "$(_WS_RESOLVED)" \
		  --out "$$lessons_dir/agent_artifact_lesson_candidates.json" >/dev/null || { \
		    rc=$$?; \
		    echo "[prove-top-leads] lesson candidate refresh failed; see $$lessons_dir/agent_artifact_lesson_candidates.json" >&2; \
		    exit $$rc; \
		  }; \
		python3 tools/lesson-source-inventory.py \
		  --root . \
		  --workspace "$(_WS_RESOLVED)" \
		  --out-json "$$lessons_dir/lesson_source_inventory.json" >/dev/null || { \
		    rc=$$?; \
		    echo "[prove-top-leads] lesson source inventory refresh failed; see $$lessons_dir/lesson_source_inventory.json" >&2; \
		    exit $$rc; \
		  }; \
		python3 tools/lesson-enforcement-inventory.py \
		  --out-json "$$lessons_dir/lesson_enforcement_inventory.json" >/dev/null || { \
		    rc=$$?; \
		    echo "[prove-top-leads] lesson enforcement inventory refresh failed; see $$lessons_dir/lesson_enforcement_inventory.json" >&2; \
		    exit $$rc; \
		  }
	@set -e; \
	queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.source_mined.json"; \
	if [ ! -f "$$queue" ]; then queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.json"; fi; \
	prefiling="$(_WS_RESOLVED)/.auditooor/prove_top_leads_prefiling_stress_test.json"; \
	packet="$(_WS_RESOLVED)/.auditooor/prove_top_leads_candidate_judgment_packet.json"; \
	packet_md="$(_WS_RESOLVED)/.auditooor/prove_top_leads_candidate_judgment_packet.md"; \
	$(MAKE) --no-print-directory candidate-judgment-packet \
	  WS="$(_WS_RESOLVED)" \
	  QUEUE="$$queue" \
	  PREFILING="$$prefiling" \
	  OUT_JSON="$$packet" \
	  OUT_MD="$$packet_md" \
		  $(if $(filter 1 true yes,$(STRICT)),STRICT=1) >/dev/null || { \
		    rc=$$?; \
		    echo "[prove-top-leads] candidate-judgment-packet failed; see $$packet" >&2; \
		    exit $$rc; \
		  }
	@set -e; \
		queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.source_mined.json"; \
		if [ ! -f "$$queue" ]; then queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.json"; fi; \
		inv="$(_WS_RESOLVED)/.auditooor/lesson_enforcement_inventory.json"; \
		if [ ! -f "$$inv" ]; then inv=".auditooor/lesson_enforcement_inventory.json"; fi; \
		src_inv="$(_WS_RESOLVED)/.auditooor/lesson_source_inventory.json"; \
		if [ ! -f "$$src_inv" ]; then src_inv=".auditooor/lesson_source_inventory.json"; fi; \
		out="$(_WS_RESOLVED)/.auditooor/prove_top_leads_outcome_lesson_gate.json"; \
		python3 tools/outcome-lesson-gate.py \
		  --candidate-json "$$queue" \
		  --inventory "$$inv" \
		  --source-inventory "$$src_inv" \
		  --out-json "$$out" \
		  $(if $(filter 1 true yes,$(STRICT)),--strict) \
		  --format json >/dev/null || { \
	    rc=$$?; \
	    if [ -n "$(filter 1 true yes,$(STRICT))" ]; then \
	      echo "[prove-top-leads] STRICT=1: outcome-lesson-gate blocked proof work; see $$out" >&2; \
	      exit $$rc; \
	    fi; \
	    echo "[prove-top-leads] WARN outcome-lesson-gate found blockers; continuing because proof lesson gate is advisory without STRICT=1; see $$out" >&2; \
	  }
	@python3 tools/harness-binding-manifest.py \
	  --input "$(_WS_RESOLVED)/.auditooor/exploit_queue.source_mined.json" \
	  --workspace "$(_WS_RESOLVED)" \
	  --candidate-judgment-packet "$(_WS_RESOLVED)/.auditooor/candidate_judgment_packet.json" \
	  --out "$(_WS_RESOLVED)/.auditooor/harness_binding_manifest_from_exploit_queue.json"
	@python3 tools/harness-execution-queue.py \
	  --input "$(_WS_RESOLVED)/.auditooor/harness_binding_manifest_from_exploit_queue.json" \
	  --workspace "$(_WS_RESOLVED)" \
	  --out "$(_WS_RESOLVED)/.auditooor/harness_execution_queue_from_exploit_queue.json" \
	  $(if $(filter 1 true yes,$(EXECUTE_READY)),--execute-ready) \
	  $(if $(MAX_EXECUTE),--max-execute "$(MAX_EXECUTE)") \
	  $(if $(EXECUTION_TIMEOUT),--execution-timeout "$(EXECUTION_TIMEOUT)") \
	  $(if $(FAIL_ON_EXECUTION_FAILURE),--fail-on-execution-failure) \
	  $(if $(JSON),--print-json)
	@set -e; \
	  queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.source_mined.json"; \
	  if [ ! -f "$$queue" ]; then queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.json"; fi; \
	  out="$(_WS_RESOLVED)/.auditooor/prove_top_leads_queue_semantics.json"; \
	  strict_semantics=""; \
	  if [ "$${ENFORCE_AUTONOMOUS_PROOF_CONVERSION:-}" = "1" ] || [ -n "$(filter 1 true yes,$(REQUIRE_STRICT_WIRING))" ]; then strict_semantics=1; fi; \
	  ptl_semantics_rc=0; \
	  python3 tools/prove-top-leads.py \
	    --workspace "$(_WS_RESOLVED)" \
	    --queue "$$queue" \
	    --harness-queue "$(_WS_RESOLVED)/.auditooor/harness_execution_queue_from_exploit_queue.json" \
	    --top-n "$(if $(TOP_N),$(TOP_N),10)" \
	    --out "$$out" \
	    $${strict_semantics:+--strict} \
	    $(if $(JSON),--json) || ptl_semantics_rc=$$?; \
	  if [ $$ptl_semantics_rc -ne 0 ]; then \
	    if [ "$$strict_semantics" = "1" ]; then \
	      echo "[prove-top-leads] strict queue semantics validator failed; see $$out" >&2; \
	      exit $$ptl_semantics_rc; \
	    fi; \
	    echo "[prove-top-leads] WARN queue semantics validator failed; continuing because standalone proof conversion semantics are advisory unless the child target receives ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 or REQUIRE_STRICT_WIRING=1; audit-run-full users should set AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1; see $$out" >&2; \
	  fi

endif

exploit-conversion-loop:
	$(call _require_pipeline_phase_token,exploit-conversion-loop)
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make exploit-conversion-loop WS=<workspace> [TOP_N=10] [EXECUTE_READY=1] [MAX_EXECUTE=5] [EXECUTION_TIMEOUT=300] [STRICT=1] [JSON=1]'; \
	  echo 'Runs the V3 conversion loop: gate, chain planner, artifact mining, queue refresh, source mining, harness queue, severity oracle, falsification, benchmark.'; \
	  echo 'D2 (advisory-first): TOP_N=0 makes the conversion stages a silent no-op (0 rows processed). The loop self-reports empty_topn_advisory when the queue still holds open non-vacuous rows; set AUDITOOOR_CONVERSION_EMPTY_TOPN_STRICT=1 to hard-fail that condition.'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make exploit-conversion-loop" "$(_WS_RESOLVED)"
	@# D2 advisory: warn when the resolved TOP_N is 0 (the silent-no-op trigger).
	@# The Python loop is the load-bearing self-report (fires for every caller,
	@# including upstream targets that pass TOP_N=0); this echo is a heads-up only.
	@if [ "$(if $(TOP_N),$(TOP_N),10)" = "0" ]; then \
	  echo "[make exploit-conversion-loop] WARN TOP_N=0: conversion stages will process 0 rows (silent no-op). Raise TOP_N above 0 to convert leads; set AUDITOOOR_CONVERSION_EMPTY_TOPN_STRICT=1 to hard-fail if the queue has open non-vacuous rows." >&2; \
	fi
	@python3 tools/exploit-conversion-loop.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --top-n "$(if $(TOP_N),$(TOP_N),10)" \
	  $(if $(filter 1 true yes,$(EXECUTE_READY)),--execute-ready) \
	  --max-execute "$(if $(MAX_EXECUTE),$(MAX_EXECUTE),5)" \
	  --execution-timeout "$(if $(EXECUTION_TIMEOUT),$(EXECUTION_TIMEOUT),300)" \
	  --step-timeout "$(if $(STEP_TIMEOUT),$(STEP_TIMEOUT),900)" \
	  $(if $(filter 1 true yes,$(STRICT)),--strict) \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(JSON),--json)
	@# K6: run agent-learning-gate after conversion loop to classify new artifacts.
	@# Keep this stdout clean when JSON=1 because audit-deep redirects the
	@# conversion-loop JSON into exploit_conversion_loop_audit_deep.json.
	@k6_json="$(_WS_RESOLVED)/.auditooor/exploit_conversion_loop_agent_learning_gate.json"; \
	  k6_compiler_json="$(_WS_RESOLVED)/.auditooor/exploit_conversion_loop_agent_learning_compiler.json"; \
	  echo "[exploit-conversion-loop] K6: running agent-learning-gate to classify new artifacts ..." >&2; \
	  k6_rc=0; \
	  compiler_rc=0; \
	  python3 tools/agent-learning-compiler.py --workspace "$(_WS_RESOLVED)" --out-json "$$k6_compiler_json" || compiler_rc=$$?; \
	  if [ "$$compiler_rc" -ne 0 ]; then \
	    echo "[exploit-conversion-loop] ERR: agent-learning-compiler failed (rc=$$compiler_rc); see $$k6_compiler_json" >&2; \
	    if [ -n "$(STRICT)" ]; then exit "$$compiler_rc"; fi; \
	  fi; \
	  if [ -n "$(JSON)" ]; then \
	    python3 tools/agent-learning-gate.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) --json > "$$k6_json" || k6_rc=$$?; \
	  else \
	    python3 tools/agent-learning-gate.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) || k6_rc=$$?; \
	  fi; \
	  if [ "$$k6_rc" -ne 0 ]; then \
	    echo "[exploit-conversion-loop] ERR: agent-learning-gate failed (rc=$$k6_rc); see $$k6_json; run \`make agent-artifact-mine WS=$(WS)\` then \`make agent-learning-compiler WS=$(WS)\` to classify" >&2; \
	    if [ -n "$(STRICT)" ]; then exit "$$k6_rc"; fi; \
	  fi

exploit-conversion-loop-test:
	@python3 -m unittest tools.tests.test_exploit_conversion_loop -v

evm-0day-proof:
	@if [ -z "$(WS)" ] || { [ -z "$(CANDIDATE)" ] && [ -z "$(QUEUE)" ]; }; then \
	  echo 'Usage: make evm-0day-proof WS=<workspace> CANDIDATE=<candidate-or-row.json>|QUEUE=<exploit_queue.json> [LEAD_ID=<id>|QUEUE_INDEX=<n>] [OUT=<dir>] [NO_RUN=1] [JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make evm-0day-proof" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/evm-0day-proof-pipeline.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(QUEUE),--queue-json "$(QUEUE)",--candidate-json "$(CANDIDATE)") \
	  $(if $(LEAD_ID),--lead-id "$(LEAD_ID)") \
	  $(if $(QUEUE_INDEX),--queue-index "$(QUEUE_INDEX)") \
	  --out-dir "$(if $(OUT),$(OUT),$(_WS_RESOLVED)/.auditooor/evm_0day_proof)" \
	  --out-json "$(_WS_RESOLVED)/.auditooor/evm_0day_proof.json" \
	  $(if $(filter 1 true yes,$(NO_RUN)),--no-run) \
	  $(if $(JSON),--json)

evm-0day-proof-test:
	@python3 -m unittest tools.tests.test_evm_0day_proof_pipeline -v

fresh-target-forward-test:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make fresh-target-forward-test WS=<workspace> REPO=github.com/Owner/Repo PIN=<sha> [CANDIDATE=<row.json>] [NO_RUN_STAGES=1] [JSON=1]'; exit 2; \
	fi
	@if [ -z "$(REEMIT_PRB_PROXY)" ] && { [ -z "$(REPO)" ] || [ -z "$(PIN)" ]; }; then \
	  echo 'Usage: make fresh-target-forward-test WS=<workspace> REPO=github.com/Owner/Repo PIN=<sha> [CANDIDATE=<row.json>] [NO_RUN_STAGES=1] [JSON=1]'; exit 2; \
	fi
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/fresh-target-forward-test.py \
	  $(if $(REPO),--repo "$(REPO)") \
	  $(if $(PIN),--pin "$(PIN)") \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(TARGET_NAME),--target-name "$(TARGET_NAME)") \
	  $(if $(filter 1 true yes,$(NO_RUN_STAGES)),--no-run-stages) \
	  --stage-timeout "$(if $(STAGE_TIMEOUT),$(STAGE_TIMEOUT),1800)" \
	  $(if $(CANDIDATE),--evm-proof-candidate "$(CANDIDATE)") \
	  $(if $(filter 1 true yes,$(REEMIT_PRB_PROXY)),--reemit-prb-proxy) \
	  $(if $(JSON),--json)

fresh-target-forward-test-test:
	@python3 -m unittest tools.tests.test_fresh_target_forward_test -v

current-to-exploit-conversion-gate:
	@mkdir -p reports
	@python3 tools/current-to-exploit-conversion-gate.py \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(SLICE),--slice "$(SLICE)") \
	  $(if $(BURNDOWN),--burndown "$(BURNDOWN)") \
	  $(if $(MD),--md) \
	  $(if $(JSON),--json)

exploit-severity-scope-oracle:
	@if [ -z "$(ROW)" ] && [ -z "$(DRAFT)" ]; then \
	  echo 'Usage: make exploit-severity-scope-oracle ROW=<row.json>|DRAFT=<draft.md> [WS=<workspace>] [OUT=<path>] [JSON=1]'; exit 2; \
	fi
	@set -e; \
	out="$(if $(OUT),$(OUT),reports/exploit_severity_scope_oracle.json)"; \
	mkdir -p "$$(dirname "$$out")"; \
	python3 tools/exploit-severity-scope-oracle.py \
	  $(if $(ROW),--queue-row "$(ROW)",--draft "$(DRAFT)") \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(SEVERITY_MD),--severity-md "$(SEVERITY_MD)") \
	  --json > "$$out"; \
	if [ -n "$(JSON)" ]; then cat "$$out"; else echo "[make exploit-severity-scope-oracle] wrote $$out"; fi

poc-falsification-runner:
	@if [ -z "$(ROW)" ] && [ -z "$(DRAFT)" ]; then \
	  echo 'Usage: make poc-falsification-runner ROW=<row.json>|DRAFT=<draft.md> [WS=<workspace>] [CMD=<harness command>] [ORACLE=<oracle.json>] [OUT=<path>] [JSON=1]'; exit 2; \
	fi
	@set -e; \
	out="$(if $(OUT),$(OUT),reports/poc_falsification_runner.json)"; \
	mkdir -p "$$(dirname "$$out")"; \
	python3 tools/poc-falsification-runner.py \
	  $(if $(ROW),--queue-row "$(ROW)") \
	  $(if $(DRAFT),--draft "$(DRAFT)") \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(CMD),--cmd "$(CMD)") \
	  $(if $(ORACLE),--severity-oracle "$(ORACLE)") \
	  $(if $(POC_DIR),--poc-dir "$(POC_DIR)") \
	  --json > "$$out"; \
	if [ -n "$(JSON)" ]; then cat "$$out"; else echo "[make poc-falsification-runner] wrote $$out"; fi

prior-disclosure-index:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make prior-disclosure-index WS=<workspace> [TARGET=<name>] [JSON=1] [QUERY=<text>]'; \
	  echo 'Writes <ws>/.auditooor/prior_disclosure_index.json'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make prior-disclosure-index" "$(_WS_RESOLVED)"
	@python3 tools/prior-disclosure-index.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(TARGET),--target "$(TARGET)") \
	  $(if $(QUERY),--query "$(QUERY)") \
	  $(if $(JSON),--json)

prior-disclosure-index-test:
	@python3 -m unittest tools.tests.test_prior_disclosure_index -v

prefiling-stress-test:
	@if [ -z "$(ROW)" ] && [ -z "$(DRAFT)" ] && [ -z "$(QUEUE)" ]; then \
	  echo 'Usage: make prefiling-stress-test WS=<workspace> ROW=<candidate.json> [JSON=1]'; \
	  echo '   or: make prefiling-stress-test WS=<workspace> DRAFT=<draft.md> [JSON=1]'; \
	  echo '   or: make prefiling-stress-test WS=<workspace> QUEUE=<exploit_queue.json> [TOP_N=10] [JSON=1]'; \
	  echo 'Writes <ws>/.auditooor/prefiling_stress_tests/<candidate>.prefiling_stress_test.json'; exit 2; \
	fi
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make prefiling-stress-test WS=<workspace> ROW=<candidate.json>|DRAFT=<draft.md>|QUEUE=<exploit_queue.json> [JSON=1]'; exit 2; \
	fi
	@python3 tools/prefiling-stress-test.py \
	  $(if $(ROW),--candidate-row "$(ROW)",$(if $(DRAFT),--draft "$(DRAFT)",--exploit-queue "$(QUEUE)")) \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(TOP_N),--top-n "$(TOP_N)") \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json)

prefiling-stress-test-test:
	@python3 -m unittest tools.tests.test_prefiling_stress_test -v

candidate-judgment-packet:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make candidate-judgment-packet WS=<workspace> [QUEUE=<exploit_queue.json>] [PREFILING=<prefiling.json>] [ORACLE=<oracle.json>] [FALSIFICATION=<falsification.json>] [OUT_JSON=<path>] [OUT_MD=<path>] [STRICT=1] [JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make candidate-judgment-packet" "$(_WS_RESOLVED)"
	@python3 tools/candidate-judgment-packet.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(QUEUE),--queue "$(QUEUE)") \
	  $(if $(PREFILING),--prefiling "$(PREFILING)") \
	  $(if $(ORACLE),--severity-oracle "$(ORACLE)") \
	  $(if $(FALSIFICATION),--falsification "$(FALSIFICATION)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(filter 1 true yes,$(STRICT)),--strict) \
	  $(if $(JSON),--json)

candidate-judgment-packet-test:
	@python3 -m unittest tools.tests.test_candidate_judgment_packet -v

.PHONY: agent-artifact-mine agent-artifact-mine-all agent-artifact-mine-test agent-artifact-mine-all-test agent-outputs-gc agent-outputs-gc-test agent-learning-compiler agent-learning-compiler-test agent-learning-gate agent-learning-gate-test
agent-artifact-mine:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make agent-artifact-mine WS=<workspace> [JSON=1]'; \
	  echo 'Writes <ws>/agent_artifact_mining_report.json'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make agent-artifact-mine" "$(_WS_RESOLVED)"
	@python3 tools/agent-artifact-miner.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --out "$(_WS_RESOLVED)/agent_artifact_mining_report.json" \
	  $(if $(JSON),--json)

agent-artifact-mine-all:
	@AUDITS_ROOT_PATH="$(if $(AUDITS_ROOT),$(AUDITS_ROOT),$(HOME)/audits)"; \
	python3 tools/agent-artifact-mine-all.py \
	  --audits-root "$$AUDITS_ROOT_PATH" \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

agent-artifact-mine-test:
	@python3 -m unittest tools.tests.test_agent_artifact_miner -v

agent-artifact-mine-all-test:
	@python3 -m unittest tools.tests.test_agent_artifact_mine_all -v

agent-outputs-gc:
	@python3 tools/agent-outputs-gc.py --root . --older "$(if $(OLDER),$(OLDER),30d)" $(if $(DRY_RUN),--dry-run) $(if $(JSON),--json)

agent-outputs-gc-test:
	@python3 -m unittest tools.tests.test_agent_outputs_namespace -v

agent-learning-compiler:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make agent-learning-compiler WS=<workspace> [REPORT=<path>] [LEDGER=<path>] [CHECK=1] [JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make agent-learning-compiler" "$(_WS_RESOLVED)"
	@python3 tools/agent-learning-compiler.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(REPORT),--report "$(REPORT)") \
	  $(if $(LEDGER),--ledger "$(LEDGER)") \
	  $(if $(CHECK),--check) \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(JSON),--print-json)

agent-learning-compiler-test:
	@python3 -m unittest tools.tests.test_agent_learning_compiler -v

agent-learning-gate:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make agent-learning-gate WS=<workspace> [STRICT=1] [JSON=1] [REPORT=<path>]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make agent-learning-gate" "$(_WS_RESOLVED)"
	@python3 tools/agent-learning-gate.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(REPORT),--report "$(REPORT)") \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json)

agent-learning-gate-test:
	@python3 -m unittest tools.tests.test_agent_learning_gate -v

.PHONY: agent-learning-metrics agent-learning-metrics-test method-attribution method-attribution-test
agent-learning-metrics: ## Lane K8: emit agent-learning metric set + health gate
	@if [ -z "$(WS)" ]; then echo 'Usage: make agent-learning-metrics WS=<workspace> [STRICT=1] [JSON=1]'; exit 2; fi
	@python3 tools/agent-learning-metrics.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json)

agent-learning-metrics-test:
	@python3 -m unittest tools.tests.test_agent_learning_metrics -v

method-attribution: ## Lane K9: per-method attribution + reweighted next-dispatch budget
	@if [ -z "$(RECORDS)" ]; then echo 'Usage: make method-attribution RECORDS=<records.jsonl> ENGAGEMENT=<id> [JSON=1]'; exit 2; fi
	@python3 tools/method-attribution.py --records "$(RECORDS)" $(if $(ENGAGEMENT),--engagement "$(ENGAGEMENT)") $(if $(JSON),--json)

method-attribution-test:
	@python3 -m unittest tools.tests.test_method_attribution -v

.PHONY: exploit-conversion-benchmark exploit-conversion-benchmark-test
exploit-conversion-benchmark:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make exploit-conversion-benchmark WS=<workspace> [JSON=1]'; \
	  echo 'Writes reports/exploit_conversion_benchmark.{json,md}'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make exploit-conversion-benchmark" "$(_WS_RESOLVED)"
	@python3 tools/audit/exploit-conversion-benchmark.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--json)

exploit-conversion-benchmark-test:
	@python3 -m unittest tools.tests.test_exploit_conversion_benchmark -v

.PHONY: provider-fanout-discipline-check provider-fanout-discipline-check-test external-intel-refresh external-intel-refresh-test external-intel-sources-test queue-proof-hard-close queue-proof-hard-close-test source-scope-live-proof-guard source-scope-live-proof-guard-test field-validation-report field-validation-report-test field-validation-platform-id-gaps field-validation-platform-id-gaps-test audit-workflow-coverage-map audit-workflow-coverage-map-test mining-coverage-dashboard mining-coverage-dashboard-test source-miner-backlog-actions source-miner-backlog-actions-test lesson-source-inventory lesson-source-inventory-test lesson-promotion-review-queue lesson-promotion-review-queue-test lesson-enforcement-inventory lesson-enforcement-inventory-test phase-b-e-measurement-report phase-b-e-measurement-report-test phase-iii-auto-unblock-watchdog phase-iii-auto-unblock-watchdog-test p4-provider-readiness-probe p4-provider-readiness-probe-test triager-pre-filing-simulator triager-pre-filing-simulator-test agent-artifact-lesson-candidates agent-artifact-lesson-candidates-test anti-pattern-corpus-bootstrap anti-pattern-corpus-bootstrap-test hackerman-sidecar-coverage-report hackerman-sidecar-coverage-report-test audit-v3-enforcement-gate audit-v3-enforcement-gate-test v3-roadmap-sidecars v3-roadmap-progress-report v3-roadmap-progress-report-test outcome-lesson-gate outcome-lesson-gate-test outcome-ledger-gate-check outcome-ledger-gate-check-test provider-keep-verification-backfill provider-keep-verification-backfill-test v3-provider-campaign-completeness-gate v3-provider-campaign-completeness-gate-test v3-provider-source-collection-queue v3-provider-source-collection-queue-test hacker-question-workflow-audit hacker-question-workflow-audit-test darknavy-web3-plan darknavy-web3-plan-test darknavy-web3-mine darknavy-web3-mine-test
provider-fanout-discipline-check:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make provider-fanout-discipline-check WS=<workspace> [JSON=1] [ENFORCE_IF_ARTIFACTS=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make provider-fanout-discipline-check" "$(_WS_RESOLVED)"
	@python3 tools/provider-fanout-discipline-check.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(CALIBRATION_LOG),--calibration-log "$(CALIBRATION_LOG)") \
	  $(if $(DISPATCH_AUDIT_DIR),--dispatch-audit-dir "$(DISPATCH_AUDIT_DIR)") \
	  $(if $(ENFORCE_IF_ARTIFACTS),--enforce-if-provider-artifacts) \
	  $(if $(JSON),--json)

provider-fanout-discipline-check-test:
	@python3 -m unittest tools.tests.test_provider_fanout_discipline_check -v
	@bash tools/tests/test_provider_fanout_discipline_makefile.sh

external-intel-sources-test:
	@python3 -m unittest tools.tests.test_external_intel_sources_registry -v

external-intel-refresh:
	@python3 tools/external-intel-refresh.py \
	  $(if $(REGISTRY),--registry "$(REGISTRY)") \
	  $(foreach source,$(SOURCE),--source "$(source)") \
	  $(if $(DATE),--date "$(DATE)") \
	  $(if $(LIST),--list-sources) \
	  $(if $(VALIDATE),--validate-registry) \
	  $(if $(JSON),--json-summary) \
	  $(if $(ALLOW_LIVE_FETCH),--allow-live-fetch) \
	  $(if $(FETCH_SINGLE_INCIDENT),--fetch-single-incident) \
	  $(if $(CACHE_DIR),--cache-dir "$(CACHE_DIR)") \
	  $(if $(FIXTURE_DIR),--fixture-dir "$(FIXTURE_DIR)") \
	  $(if $(MAX_PAGES),--max-pages "$(MAX_PAGES)") \
	  $(if $(TIMEOUT_SECONDS),--timeout-seconds "$(TIMEOUT_SECONDS)") \
	  $(if $(OUT),--output "$(OUT)")

external-intel-refresh-test:
	@python3 -m unittest tools.tests.test_external_intel_refresh tools.tests.test_external_intel_sources_registry -v

queue-proof-hard-close:
ifeq ($(AUDITOOOR_DEFER_DRIVE),1)
	@echo "[queue-proof-hard-close] deferred: parent ordered driver has not reached the drive phase"
else
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make queue-proof-hard-close WS=<workspace> [JSON=1] [STRICT=1] [OUT_JSON=<path>] [OUT_MD=<path>]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make queue-proof-hard-close" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/queue-proof-hard-close.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --out-json "$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/queue_proof_hard_close.json)" \
	  --out-md "$(if $(OUT_MD),$(OUT_MD),$(_WS_RESOLVED)/.auditooor/queue_proof_hard_close.md)" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--print-json)
	@$(MAKE) --no-print-directory source-scope-live-proof-guard WS="$(_WS_RESOLVED)" JSON= $(if $(STRICT),STRICT=1)

endif

queue-proof-hard-close-test:
	@python3 -m unittest tools.tests.test_queue_proof_hard_close -v

.PHONY: auto-stage
# auto-stage: stage submission drafts for PROOF-BACKED hard-close rows only.
# Reads <ws>/.auditooor/queue_proof_hard_close.json (from queue-proof-hard-close).
# A row is proof-backed iff closeout_status=="proved" AND proof_counted is true;
# blocked/blocked_with_obligation/missing_evidence/disproved/killed are excluded.
# On a 0-proof-backed workspace this stages NOTHING and exits 0 (never manufactures
# a draft). Read-only on the queue; only writes submissions/staging/<draft>.md.
auto-stage:
	@if [ -z "$(WS)" ]; then echo 'Usage: make auto-stage WS=<workspace> [DRY_RUN=1] [WITH_POC=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make auto-stage" "$(_WS_RESOLVED)"
	@hc="$(_WS_RESOLVED)/.auditooor/queue_proof_hard_close.json"; \
	if [ ! -f "$$hc" ]; then echo "[make auto-stage] no $$hc -> 0 proof-backed -> nothing staged"; exit 0; fi; \
	rows="$$(mktemp)"; \
	python3 tools/proof-backed-select.py "$$hc" > "$$rows" 2>/dev/null; \
	_n=0; \
	while IFS="$$(printf '\t')" read -r rid icid title; do \
	  [ -z "$$rid" ] && continue; \
	  _n=$$(( _n + 1 )); \
	  echo "[make auto-stage] staging proof-backed row: $$rid (impact_contract=$$icid)"; \
	  python3 tools/auto-draft-generator.py "$(_WS_RESOLVED)" --angle-id "$$rid" --impact-contract-id "$$icid" $(if $(WITH_POC),--with-poc) $(if $(DRY_RUN),--dry-run) || echo "[make auto-stage] WARN draft gen failed for $$rid (continuing)" >&2; \
	done < "$$rows"; \
	rm -f "$$rows"; \
	if [ "$$_n" = "0" ]; then echo "[make auto-stage] 0 proof-backed rows -> nothing staged (exit 0)"; fi; \
	exit 0

source-scope-live-proof-guard:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make source-scope-live-proof-guard WS=<workspace> [JSON=1] [STRICT=1] [OUT_JSON=<path>]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make source-scope-live-proof-guard" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/source-scope-live-proof-guard.py \
	  --workspace "$(_WS_RESOLVED)" \
	  --out-json "$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/source_scope_live_proof_guard.json)" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--print-json)

source-scope-live-proof-guard-test:
	@python3 -m unittest tools.tests.test_source_scope_live_proof_guard -v

field-validation-report:
ifeq ($(AUDITOOOR_DEFER_DRIVE),1)
	@echo "[field-validation-report] deferred: parent ordered driver has not reached the drive phase"
else
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make field-validation-report WS=<workspace> [JSON=1] [STRICT=1] [CAMPAIGN_ID=<id>] [OUT_JSON=<path>] [OUT_MD=<path>]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make field-validation-report" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/field-validation-report.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(CAMPAIGN_ID),--campaign-id "$(CAMPAIGN_ID)") \
	  --outcomes "$(if $(OUTCOMES),$(OUTCOMES),$(if $(wildcard $(_WS_RESOLVED)/reference/outcomes.jsonl),$(_WS_RESOLVED)/reference/outcomes.jsonl,$(CURDIR)/reference/outcomes.jsonl))" \
	  --out "$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/field_validation_report.json)" \
	  --md-out "$(if $(OUT_MD),$(OUT_MD),$(_WS_RESOLVED)/.auditooor/field_validation_report.md)" \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--print-json)

endif

field-validation-report-test:
	@python3 -m unittest tools.tests.test_field_validation_report -v

field-validation-platform-id-gaps:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make field-validation-platform-id-gaps WS=<workspace> [SUBMISSIONS=<path>] [OUTCOMES=<path>] [PENDING=<path>] [OUT_JSON=<path>] [OUT_MD=<path>] [JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make field-validation-platform-id-gaps" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/field-validation-platform-id-gaps.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(SUBMISSIONS),--submissions "$(SUBMISSIONS)") \
	  $(if $(OUTCOMES),--outcomes "$(OUTCOMES)") \
	  $(if $(PENDING),--pending "$(PENDING)") \
	  --out-json "$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/field_validation_platform_id_gaps.json)" \
	  --out-md "$(if $(OUT_MD),$(OUT_MD),$(_WS_RESOLVED)/.auditooor/field_validation_platform_id_gaps.md)" \
	  $(if $(JSON),--json)

field-validation-platform-id-gaps-test:
	@python3 -m unittest tools.tests.test_field_validation_platform_id_gaps -v

audit-workflow-coverage-map:
	@python3 tools/audit-workflow-coverage-map.py \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(JSON),--json)

audit-workflow-coverage-map-test:
	@python3 -m unittest tools.tests.test_audit_workflow_coverage_map tools.tests.test_v3_makefile_wiring -v

mining-coverage-dashboard:
	@python3 tools/mining-coverage-dashboard.py \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(JSON),--json) \
	  $(if $(MARKDOWN),--markdown)

mining-coverage-dashboard-test:
	@python3 -m unittest tools.tests.test_mining_coverage_dashboard -v

source-miner-backlog-actions:
	@mkdir -p "$(if $(OUT_DIR),$(OUT_DIR),reports/v3_iter_2026-05-24/lane_V3_SOURCE_MINER_BACKLOG_ACTIONS)"
	@python3 tools/source-miner-backlog-actions.py \
	  --closure-summary "$(if $(CLOSURE_SUMMARY),$(CLOSURE_SUMMARY),reports/v3_iter_2026-05-24/lane_V3_REMAINING_SOURCE_MINERS_CLOSURE/summary.json)" \
	  --dashboard "$(if $(DASHBOARD),$(DASHBOARD),.auditooor/mining_coverage_dashboard.json)" \
	  --out "$(if $(OUT_JSON),$(OUT_JSON),$(if $(OUT_DIR),$(OUT_DIR),reports/v3_iter_2026-05-24/lane_V3_SOURCE_MINER_BACKLOG_ACTIONS)/summary.json)" \
	  --markdown-out "$(if $(OUT_MD),$(OUT_MD),$(if $(OUT_DIR),$(OUT_DIR),reports/v3_iter_2026-05-24/lane_V3_SOURCE_MINER_BACKLOG_ACTIONS)/results.md)" \
	  $(if $(GENERATED_ON),--generated-on "$(GENERATED_ON)") \
	  $(if $(JSON),--json)

source-miner-backlog-actions-test:
	@python3 -m unittest tools.tests.test_source_miner_backlog_actions -v

lesson-source-inventory:
	@python3 tools/lesson-source-inventory.py \
	  --root . \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(MAX_COMPILE_FILES),--max-compile-files "$(MAX_COMPILE_FILES)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(JSON),--json)

lesson-source-inventory-test:
	@python3 -m unittest tools.tests.test_lesson_source_inventory -v

lesson-promotion-review-queue:
	@mkdir -p .auditooor
	@python3 tools/lesson-source-inventory.py \
	  --root . \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(MAX_COMPILE_FILES),--max-compile-files "$(MAX_COMPILE_FILES)") \
	  --decisions /dev/null \
	  --out-json "$(if $(INVENTORY),$(INVENTORY),.auditooor/lesson_source_inventory.json)" >/dev/null
	@python3 tools/lesson-promotion-review-queue.py \
	  --root . \
	  --inventory "$(if $(INVENTORY),$(INVENTORY),.auditooor/lesson_source_inventory.json)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(OUT_DECISIONS),--out-decisions "$(OUT_DECISIONS)") \
	  $(if $(JSON),--json)
	@python3 tools/lesson-source-inventory.py \
	  --root . \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(MAX_COMPILE_FILES),--max-compile-files "$(MAX_COMPILE_FILES)") \
	  --decisions "$(if $(OUT_DECISIONS),$(OUT_DECISIONS),.auditooor/lesson_source_decisions.json)" \
	  --out-json "$(if $(INVENTORY),$(INVENTORY),.auditooor/lesson_source_inventory.json)" >/dev/null

lesson-promotion-review-queue-test:
	@python3 -m unittest tools.tests.test_lesson_promotion_review_queue -v

lesson-enforcement-inventory:
	@python3 tools/lesson-enforcement-inventory.py \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(JSON),--json) \
	  $(INPUTS)

lesson-enforcement-inventory-test:
	@python3 -m unittest tools.tests.test_prose_to_lesson_compiler tools.tests.test_lesson_enforcement_inventory -v

phase-b-e-measurement-report:
	@python3 tools/phase-b-e-measurement-report.py \
	  $(if $(P1_TRIAGE),--p1-triage "$(P1_TRIAGE)") \
	  $(if $(P3_MEASUREMENT),--p3-measurement "$(P3_MEASUREMENT)") \
	  $(if $(PRQS_COMPARATOR),--prqs-comparator "$(PRQS_COMPARATOR)") \
	  $(if $(PHASE_E_ROWS),--phase-e-rows "$(PHASE_E_ROWS)") \
	  $(if $(OUT_DIR),--output-dir "$(OUT_DIR)") \
	  $(if $(JSON),--json)

phase-b-e-measurement-report-test:
	@python3 -m unittest tools.tests.test_phase_b_e_measurement_report -v

phase-iii-auto-unblock-watchdog:
	@python3 tools/phase-iii-auto-unblock-watchdog.py \
	  $(if $(MEASUREMENT_SUMMARY),--measurement-summary "$(MEASUREMENT_SUMMARY)") \
	  $(if $(PHASE_E_ROWS),--phase-e-rows "$(PHASE_E_ROWS)") \
	  $(if $(PRQS_COMPARATOR),--prqs-comparator "$(PRQS_COMPARATOR)") \
	  $(if $(REQUIRED_FUTURE_ENGAGEMENTS),--required-future-engagements "$(REQUIRED_FUTURE_ENGAGEMENTS)") \
	  $(if $(REQUIRED_VALID_FUTURE_MATCHED_PAIRS),--required-valid-future-matched-pairs "$(REQUIRED_VALID_FUTURE_MATCHED_PAIRS)") \
	  $(if $(OUT_JSON),--out "$(OUT_JSON)") \
	  $(if $(ADVISORY),--advisory) \
	  $(if $(JSON),--json)

phase-iii-auto-unblock-watchdog-test:
	@python3 -m unittest tools.tests.test_phase_iii_auto_unblock_watchdog -v

p4-provider-readiness-probe:
	@python3 tools/p4-provider-readiness-probe.py \
	  --root "$(if $(ROOT),$(ROOT),$(CURDIR))" \
	  $(foreach preflight,$(PREFLIGHT_JSON),--preflight-json "$(preflight)") \
	  $(if $(OUT_JSON),--out "$(OUT_JSON)") \
	  $(if $(OUT_MD),--markdown-out "$(OUT_MD)") \
	  $(if $(GENERATED_AT_UTC),--generated-at-utc "$(GENERATED_AT_UTC)") \
	  $(if $(JSON),--print-json)

p4-provider-readiness-probe-test:
	@python3 -m unittest tools.tests.test_p4_provider_readiness_probe -v

triager-pre-filing-simulator:
	@if [ -z "$(WS)" ] || [ -z "$(DRAFT)" ]; then \
	  echo 'Usage: make triager-pre-filing-simulator WS=<workspace> DRAFT=<draft.md> [SEVERITY=<level>] [OUT_JSON=<path>] [JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make triager-pre-filing-simulator" "$(_WS_RESOLVED)"
	@if [ ! -f "$(DRAFT)" ]; then \
	  echo "[make triager-pre-filing-simulator] ERR draft not found: $(DRAFT)"; exit 2; \
	fi
	@set -e; \
	if [ -n "$(OUT_JSON)" ]; then \
	  mkdir -p "$$(dirname "$(OUT_JSON)")"; \
	  python3 tools/triager-pre-filing-simulator.py \
	    --draft "$(DRAFT)" \
	    --workspace "$(_WS_RESOLVED)" \
	    $(if $(SEVERITY),--severity "$(SEVERITY)") \
	    > "$(OUT_JSON)"; \
	  if [ -n "$(JSON)" ]; then cat "$(OUT_JSON)"; else echo "[triager-pre-filing-simulator] wrote $(OUT_JSON)"; fi; \
	else \
	  python3 tools/triager-pre-filing-simulator.py \
	    --draft "$(DRAFT)" \
	    --workspace "$(_WS_RESOLVED)" \
	    $(if $(SEVERITY),--severity "$(SEVERITY)"); \
	fi

triager-pre-filing-simulator-test:
	@python3 -m unittest tools.tests.test_triager_pre_filing_simulator -v

agent-artifact-lesson-candidates:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make agent-artifact-lesson-candidates WS=<workspace> [JSON=1] [OUT=<path>] [LIMIT=<n>]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make agent-artifact-lesson-candidates" "$(_WS_RESOLVED)"
	@python3 tools/agent-artifact-lesson-candidates.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(JSON),--json)

agent-artifact-lesson-candidates-test:
	@python3 -m unittest tools.tests.test_agent_artifact_lesson_candidates -v

anti-pattern-corpus-bootstrap:
	@python3 tools/anti-pattern-corpus-bootstrap.py \
	  --repo-root . \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(DRY_RUN),--dry-run)

anti-pattern-corpus-bootstrap-test:
	@python3 -m unittest tools.tests.test_anti_pattern_corpus_bootstrap tools.tests.test_vault_anti_pattern_corpus -v

hackerman-sidecar-coverage-report:
	@python3 tools/hackerman-sidecar-coverage-report.py \
	  $(if $(TAG_DIR),--tag-dir "$(TAG_DIR)") \
	  $(if $(DERIVED_DIR),--derived-dir "$(DERIVED_DIR)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(STRICT),--strict) \
	  $(if $(MIN_FILE_COVERAGE),--min-file-coverage "$(MIN_FILE_COVERAGE)") \
	  $(if $(SIZE_WARN_MB),--size-warn-mb "$(SIZE_WARN_MB)") \
	  $(if $(SIZE_HARD_MB),--size-hard-mb "$(SIZE_HARD_MB)") \
	  $(if $(JSON),--json)

hackerman-sidecar-coverage-report-test:
	@python3 -m unittest tools.tests.test_hackerman_sidecar_coverage_report tools.tests.test_hackerman_query_common_corpus_walker -v

audit-v3-enforcement-gate:
	@python3 tools/audit-v3-enforcement-gate.py \
	  --root . \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(PROGRESS),--progress "$(PROGRESS)") \
	  $(if $(DOCUMENTED_BLOCKERS),--documented-blockers "$(DOCUMENTED_BLOCKERS)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(JSON),--json)

.PHONY: hot-function-receipt hot-function-receipt-test
hot-function-receipt: ## V3 hot-function/hacker-question receipt: BUILD=1 to generate, default CHECK
	@if [ -z "$(WS)" ]; then echo 'Usage: make hot-function-receipt WS=<workspace> [BUILD=1] [STRICT=1] [JSON=1]'; exit 2; fi
	@python3 tools/hot-function-hacker-question-receipt.py --workspace "$(_WS_RESOLVED)" $(if $(BUILD),--build) $(if $(STRICT),--strict) $(if $(JSON),--print-json)

hot-function-receipt-test:
	@python3 -m unittest tools.tests.test_hot_function_hacker_question_receipt -v

audit-v3-enforcement-gate-test:
	@python3 -m unittest tools.tests.test_audit_v3_enforcement_gate -v

v3-roadmap-sidecars:
ifeq ($(AUDITOOOR_DEFER_DRIVE),1)
	@echo "[v3-roadmap-sidecars] deferred: parent ordered driver has not reached the drive phase"
else
	@mkdir -p .auditooor reports docs
	@python3 tools/audit-workflow-coverage-map.py --json --out .auditooor/audit_workflow_coverage_map.json
	@python3 tools/mining-coverage-dashboard.py \
	  --out-json .auditooor/mining_coverage_dashboard.json \
	  --out-md .auditooor/mining_coverage_dashboard.md \
	  --quiet
	@if [ -n "$(WS)" ]; then \
	  $(MAKE) --no-print-directory agent-artifact-lesson-candidates WS="$(_WS_RESOLVED)" OUT="$(_WS_RESOLVED)/.auditooor/agent_artifact_lesson_candidates.json" >/dev/null || \
	    echo "[v3-roadmap-sidecars] WARN agent-artifact-lesson-candidates failed for $(_WS_RESOLVED)" >&2; \
	fi
	@python3 tools/lesson-source-inventory.py --root . $(if $(WS),--workspace "$(_WS_RESOLVED)") --out-json .auditooor/lesson_source_inventory.json >/dev/null
	@python3 tools/lesson-enforcement-inventory.py --out-json .auditooor/lesson_enforcement_inventory.json >/dev/null
	@$(MAKE) --no-print-directory anti-pattern-corpus-bootstrap >/dev/null
	@if [ -n "$(WS)" ] && [ -z "$(GLOBAL_HACKERMAN_SIDECAR)" ]; then \
	  echo "[v3-roadmap-sidecars] skipping global hackerman-sidecar-coverage-report for workspace audit; set GLOBAL_HACKERMAN_SIDECAR=1 to refresh it"; \
	else \
	  python3 tools/hackerman-sidecar-coverage-report.py --out-json .auditooor/hackerman_sidecar_coverage_report.json >/dev/null || \
	    echo "[v3-roadmap-sidecars] WARN hackerman-sidecar-coverage-report found extraction gaps; continuing (strict promotion must handle blockers)" >&2; \
	fi
	@$(MAKE) --no-print-directory v3-provider-campaign-completeness-gate WORKSPACE="$(if $(WS),$(_WS_RESOLVED),.)" OUT_JSON="$(if $(WS),$(_WS_RESOLVED),.)/.auditooor/v3_provider_campaign_completeness_gate.json" >/dev/null || \
	  echo "[v3-roadmap-sidecars] WARN v3-provider-campaign-completeness-gate found campaign blockers; continuing (strict provider slices must close blockers)" >&2
	@if [ -n "$(WS)" ]; then \
	  $(MAKE) --no-print-directory field-validation-report WS="$(_WS_RESOLVED)" >/dev/null || \
	    echo "[v3-roadmap-sidecars] WARN field-validation-report failed for $(_WS_RESOLVED)" >&2; \
	fi
	@python3 tools/v3-roadmap-progress-report.py \
	  --root . \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  --json > reports/v3_roadmap_progress_report.json
	@if [ -n "$(STRICT_HACKERMAN_V3)" ]; then \
	  python3 tools/audit-v3-enforcement-gate.py \
	    --root . \
	    $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	    --out-json .auditooor/audit_v3_enforcement_gate.json >/dev/null; \
	fi
	@if [ -n "$(JSON)" ]; then cat reports/v3_roadmap_progress_report.json; else echo "[v3-roadmap-sidecars] refreshed .auditooor/audit_workflow_coverage_map.json .auditooor/mining_coverage_dashboard.json .auditooor/lesson_source_inventory.json .auditooor/lesson_enforcement_inventory.json reports/v3_roadmap_progress_report.json"; fi

endif

v3-roadmap-progress-report:
	@mkdir -p reports
	@python3 tools/v3-roadmap-progress-report.py \
	  --root . \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  --json > "$(if $(OUT),$(OUT),reports/v3_roadmap_progress_report.json)"
	@if [ -n "$(JSON)" ]; then cat "$(if $(OUT),$(OUT),reports/v3_roadmap_progress_report.json)"; else echo "[v3-roadmap-progress-report] wrote $(if $(OUT),$(OUT),reports/v3_roadmap_progress_report.json)"; fi

v3-roadmap-progress-report-test:
	@python3 -m unittest tools.tests.test_v3_roadmap_progress_report -v

outcome-lesson-gate:
	@if [ -z "$(DRAFT)" ] && [ -z "$(WS)" ]; then \
	  echo 'Usage: make outcome-lesson-gate DRAFT=<draft.md>|WS=<workspace> [STRICT=1] [JSON=1] [OUT_JSON=<path>]'; exit 2; \
	fi
	@python3 tools/outcome-lesson-gate.py \
	  $(if $(DRAFT),--draft "$(DRAFT)") \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(INVENTORY),--inventory "$(INVENTORY)") \
	  $(if $(SOURCE_INVENTORY),--source-inventory "$(SOURCE_INVENTORY)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(STRICT),--strict) \
	  --format json \
	  $(if $(JSON),,>/dev/null)

outcome-lesson-gate-test:
	@python3 -m unittest tools.tests.test_outcome_lesson_gate -v

# Outcome ledger gate: enforce new_rule_codified population on rejected rows.
# WIRING-COMPLETENESS-V3 GAP-10 / LEARNING-LOOP GAP-3.
# Advisory (non-blocking) when run standalone; gated by --strict in paste-ready path.
.PHONY: outcome-ledger-gate-check outcome-ledger-gate-check-test
outcome-ledger-gate-check:
	@if [ -z "$(WS)" ] && [ -z "$(OUTCOMES)" ]; then \
	  echo 'Usage: make outcome-ledger-gate-check WS=<workspace> [STRICT=1] [JSON=1] [OUT_JSON=<path>]'; \
	  echo '       make outcome-ledger-gate-check OUTCOMES=<path/to/outcomes.jsonl> [STRICT=1]'; \
	  echo '       make outcome-ledger-gate-check ALL_WS=1 [STRICT=1]'; \
	  exit 2; \
	fi
	@python3 tools/outcome-ledger-gate.py \
	  $(if $(OUTCOMES),--outcomes "$(OUTCOMES)") \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(ALL_WS),--all-workspaces) \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json)

outcome-ledger-gate-check-test:
	@python3 -m unittest tools.tests.test_outcome_ledger_gate -v

provider-keep-verification-backfill:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make provider-keep-verification-backfill WS=<workspace> [INPUT_JSON=<path>] [SCAN_WORKSPACE=1] [JSON=1] [OUT_JSON=<path>] [OUT_MD=<path>]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make provider-keep-verification-backfill" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@python3 tools/provider-keep-verification-backfill.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(INPUT_JSON),--input-json "$(INPUT_JSON)") \
	  $(if $(SCAN_WORKSPACE),--scan-workspace) \
	  --out-json "$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/provider_keep_verification_backfill.json)" \
	  --out-md "$(if $(OUT_MD),$(OUT_MD),$(_WS_RESOLVED)/.auditooor/provider_keep_verification_backfill.md)" \
	  $(if $(JSON),--json)

provider-keep-verification-backfill-test:
	@python3 -m unittest tools.tests.test_provider_keep_verification_backfill -v

v3-provider-source-collection-queue:
	@python3 tools/v3-provider-source-collection-queue.py \
	  --root "$(if $(ROOT),$(ROOT),.)" \
	  $(foreach result,$(RESULT),--result "$(result)") \
	  $(if $(ALL_RESULTS),--include-all-results) \
	  $(if $(REGISTRY),--registry "$(REGISTRY)") \
	  $(if $(OUT_JSON),--out-json "$(OUT_JSON)") \
	  $(if $(OUT_MD),--out-md "$(OUT_MD)") \
	  $(if $(JSON),--json)

v3-provider-closure-queue:
	@set -e; \
	root="$(if $(ROOT),$(ROOT),.)"; \
	python3 tools/v3-provider-source-collection-queue.py \
	  --root "$$root" \
	  $(foreach result,$(RESULT),--result "$(result)") \
	  $(if $(ALL_RESULTS),--include-all-results) \
	  $(if $(REGISTRY),--registry "$(REGISTRY)") \
	  --out-json "$(if $(OUT_JSON),$(OUT_JSON),$$root/.auditooor/provider_closure_packet_queue.json)" \
	  --out-md "$(if $(OUT_MD),$(OUT_MD),$$root/.auditooor/provider_closure_packet_queue.md)" \
	  $(if $(JSON),--json)

v3-provider-source-collection-queue-test:
	@python3 -m unittest tools.tests.test_v3_provider_source_collection_queue -v

hacker-question-workflow-audit:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hacker-question-workflow-audit WS=<workspace> [JSON=1] [STRICT=1] [OUT_JSON=<path>] [OUT_MD=<path>]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make hacker-question-workflow-audit" "$(_WS_RESOLVED)"
	@mkdir -p "$(_WS_RESOLVED)/.auditooor"
	@set -e; \
	json_out="$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/hacker_question_workflow_audit.json)"; \
	md_out="$(if $(OUT_MD),$(OUT_MD),$(_WS_RESOLVED)/.auditooor/hacker_question_workflow_audit.md)"; \
	rc=0; \
	python3 tools/hacker-question-workflow-audit.py --workspace "$(_WS_RESOLVED)" --format json $(if $(STRICT),--strict) > "$$json_out" || rc=$$?; \
	python3 tools/hacker-question-workflow-audit.py --workspace "$(_WS_RESOLVED)" --format markdown > "$$md_out"; \
	if [ "$$rc" -ne 0 ]; then exit "$$rc"; fi; \
	if [ -n "$(JSON)" ]; then cat "$$json_out"; else echo "[hacker-question-workflow-audit] wrote $$json_out"; fi

hacker-question-workflow-audit-test:
	@python3 -m unittest tools.tests.test_hacker_question_workflow_audit -v

darknavy-web3-plan:
	@python3 tools/darknavy-web3-planner.py \
	  --out "$(if $(OUT),$(OUT),reports/darknavy_web3_plan.json)" \
	  $(if $(LOCAL_HTML_DIR),--local-html-dir "$(LOCAL_HTML_DIR)") \
	  $(if $(FETCH),--fetch) \
	  $(if $(JSON),--json)

darknavy-web3-plan-test:
	@python3 -m unittest tools.tests.test_darknavy_web3_planner -v

darknavy-web3-mine:
	@python3 tools/hackerman-etl-from-darknavy-web3.py \
	  --out-dir "$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/darknavy_web3_incidents)" \
	  --cache-dir "$(if $(CACHE_DIR),$(CACHE_DIR),cache/darknavy-web3)" \
	  $(if $(FETCH),--fetch) \
	  $(if $(APPLY),,--dry-run) \
	  $(if $(START_PAGE),--start-page "$(START_PAGE)") \
	  $(if $(END_PAGE),--end-page "$(END_PAGE)") \
	  $(if $(MAX_PAGES),--max-pages "$(MAX_PAGES)") \
	  $(if $(MAX_ARTICLES),--max-articles "$(MAX_ARTICLES)") \
	  $(if $(RATE_LIMIT_MS),--rate-limit-ms "$(RATE_LIMIT_MS)") \
	  $(if $(JSON),--json-summary)

darknavy-web3-mine-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_darknavy_web3 -v

.PHONY: promote-exploit-queue-to-ledger promote-exploit-queue-to-ledger-test
promote-exploit-queue-to-ledger:
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make promote-exploit-queue-to-ledger WS=<workspace> [JSON=1] [DRY_RUN=1]'; \
	  echo 'Maps <ws>/.auditooor/exploit_queue.json rows into the invariant ledger'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make promote-exploit-queue-to-ledger" "$(_WS_RESOLVED)"
	@python3 tools/exploit-queue-to-invariant-ledger.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(JSON),--json) \
	  $(if $(DRY_RUN),--dry-run)

promote-exploit-queue-to-ledger-test:
	@python3 -m unittest tools.tests.test_exploit_queue_to_invariant_ledger -v

.PHONY: promote-mined-canonical promote-mined-canonical-test
promote-mined-canonical: ## Promote mined records (incl. *_advisories.jsonl) into canonical MCP-readable corpus; DRY_RUN=1 to preview, JSON=1 for machine output
	@python3 tools/promote-mined-to-canonical.py \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json) \
	  $(if $(MIN_CONFIDENCE),--min-confidence $(MIN_CONFIDENCE)) \
	  $(if $(ONLY_ROUTER),--only-router $(ONLY_ROUTER))

promote-mined-canonical-test:
	@python3 -m unittest tools.tests.test_promote_mined_to_canonical -v

.PHONY: engage-report-mcp-feed
engage-report-mcp-feed:
	@if [ -z "$(WS)" ]; then echo "ERROR: WS=<workspace> required"; exit 2; fi
	python3 tools/vault-mcp-server.py --call vault_engage_report_context --args "$$(python3 -c 'import json,sys; print(json.dumps({"workspace_path": sys.argv[1], "limit": 20}))' "$(WS)")" | python3 -m json.tool | head -50

.PHONY: pre-source-read-injection-smoke
pre-source-read-injection-smoke: ## Smoke-test Wave-6 Phase C pre-source-read injector
	@WS=$$(git rev-parse --show-toplevel); \
	 echo "== Smoke 1: non-existent file (expects functions_analyzed=0 + skipped_reasons) =="; \
	 python3 $$WS/tools/auditooor-pre-source-read-injector.py \
	     $$WS/audit/sig_extracts/dydx-v4-chain.jsonl.sample \
	     --target-repo dydxprotocol/v4-chain --top-n 3 --json | head -25; \
	 echo "== Smoke 2: real fixture (expects functions_analyzed>=1) =="; \
	 python3 $$WS/tools/auditooor-pre-source-read-injector.py \
	     $$WS/tools/tests/fixtures/fn_sig_extractor_go/sample.go \
	     --target-repo dydxprotocol/v4-chain --top-n 3 --json | head -30

# --- Wave-6 Phase E: ranker continuous-learning loop ---
.PHONY: ranker-learn ranker-learn-batch ranker-learn-surface ranker-apply-weights

ranker-learn: ## Phase E: ingest single triager outcome
	@if [ -z "$(FILING)" ] || [ -z "$(OUTCOME)" ]; then \
	  echo "Usage: make ranker-learn FILING=cantina-NNN OUTCOME=ACCEPTED [SEVERITY=CRITICAL]"; \
	  exit 2; \
	fi
	@python3 tools/ranker-learn.py --filing-id $(FILING) --outcome $(OUTCOME) \
	  $(if $(SEVERITY),--severity-final $(SEVERITY))

ranker-learn-batch: ## Phase E: aggregate triager outcomes since N hours
	@python3 tools/ranker-learn.py --batch-mode --since $(or $(SINCE),24h)

ranker-learn-surface: ## Phase E: seed confirmed own-findings as TP, then surface a weight snapshot for the operator (NEVER auto-applies)
	@python3 tools/ranker-learn.py --batch-mode --seed-from-own-findings \
	  --since $(or $(SINCE),100000h)
	@echo "[ranker] snapshot surfaced. Review audit/ranker_weight_diff.md, then run \`make ranker-apply-weights SHA=<sha8>\` to apply (operator gate)."

ranker-apply-weights: ## Phase E: operator-approved apply of weight snapshot
	@if [ -z "$(SHA)" ]; then \
	  echo "Usage: make ranker-apply-weights SHA=<sha8> [FORCE=1]"; \
	  exit 2; \
	fi
	@python3 tools/ranker-apply-weights.py --sha $(SHA) $(if $(FORCE),--force)

# --- Wave-7 BIG_PLAN A5: regression-sentinel auto-firing pipeline ---
.PHONY: regression-sentinels regression-sentinels-test

regression-sentinels: ## A5: evaluate registered regression sentinels for WS
	@if [ -z "$(WS)" ]; then \
	  echo "Usage: make regression-sentinels WS=~/audits/<engagement>"; \
	  exit 2; \
	fi
	@python3 tools/regression-sentinel-runner.py --workspace $(WS) \
	  $(if $(NO_RERUN),--no-rerun) $(if $(JSON),--json)

regression-sentinels-test: ## A5: unit tests for the sentinel runner
	@python3 -m unittest tools.tests.test_regression_sentinel_runner

# --- Wave-7 BIG_PLAN A6: cross-engagement pattern fanout pipeline ---
.PHONY: cross-engagement-fanout cross-engagement-fanout-test

cross-engagement-fanout: ## A6: fanout filed shapes from SOURCE engagement onto DEST
	@if [ -z "$(SOURCE)" ] || [ -z "$(DEST)" ]; then \
	  echo "Usage: make cross-engagement-fanout SOURCE=dydx DEST=spark [BUG_CLASS=admin-bypass]"; \
	  exit 2; \
	fi
	@python3 tools/cross-engagement-fanout.py \
	  --source-engagement $(SOURCE) --dest-engagement $(DEST) \
	  $(if $(BUG_CLASS),--bug-class $(BUG_CLASS))

cross-engagement-fanout-test: ## A6: unit tests for the fanout tool
	@python3 -m unittest tools.tests.test_cross_engagement_fanout

# --- Wave-8 BIG_PLAN: brain-prime user-facing payoff ---
.PHONY: system-model system-model-test brain-prime brain-prime-dry-run brain-prime-test

system-model: ## Lane L1: scaffold per-workspace system model (run after operator-truth + commit-mining, before High/Critical dispatch)
	@if [ -z "$(WS)" ]; then \
	  echo "Usage: make system-model WS=<workspace>"; \
	  exit 2; \
	fi
	@python3 tools/system-model.py --workspace $(WS) $(if $(JSON),--json)

system-model-test:
	@python3 -m unittest tools.tests.test_system_model -v

.PHONY: state-config-diff state-config-diff-test fork-divergence-probe fork-divergence-probe-test fork-pseudo-version-check peripheral-first-workpack peripheral-first-workpack-test
fork-pseudo-version-check: ## D5: scan WS go.mod for mislabeled fork pseudo-versions (wired into audit-deep Step 15b)
	@if [ -z "$(WS)" ]; then echo "Usage: make fork-pseudo-version-check WS=<workspace> [UPSTREAM_CLONE=<dir>]"; exit 2; fi
	@_gomod=""; for g in "$(WS)/go.mod" "$(WS)/src/go.mod"; do [ -f "$$g" ] && { _gomod="$$g"; break; }; done; \
	  if [ -z "$$_gomod" ]; then echo "no go.mod under $(WS)"; exit 0; fi; \
	  python3 tools/fork-pseudo-version-mislabel.py "$$_gomod" \
	    --out $(WS)/.auditooor/fork_pseudo_version_mislabel.json \
	    $(if $(UPSTREAM_CLONE),--verify --upstream-clone $(UPSTREAM_CLONE))

state-config-diff: ## Lane G1: per-asset live-state/config divergence read-plan / probe-diff
	@if [ -z "$(WS)" ]; then echo "Usage: make state-config-diff WS=<workspace> [BLOCK=<n>] [RPC=<url>]"; exit 2; fi
	@python3 tools/state-config-diff.py --workspace $(WS) $(if $(BLOCK),--block $(BLOCK)) $(if $(RPC),--rpc-url $(RPC))

state-config-diff-test:
	@python3 -m unittest tools.tests.test_state_config_diff -v

fork-divergence-probe: ## Lane G2: probe forked/pinned deps for upstream-lag leads
	@if [ -z "$(WS)" ]; then echo "Usage: make fork-divergence-probe WS=<workspace>"; exit 2; fi
	@python3 tools/fork-divergence-prober.py --workspace $(WS) \
	  --out $(WS)/.auditooor/fork_divergence_prober_plan.json

fork-divergence-probe-test:
	@python3 -m unittest tools.tests.test_fork_divergence_prober -v

peripheral-first-workpack: ## Lane G3: ranked under-audited-peripheral cold-read workpack
	@if [ -z "$(WS)" ]; then echo "Usage: make peripheral-first-workpack WS=<workspace>"; exit 2; fi
	@python3 tools/peripheral-first-workpack.py $(WS)

peripheral-first-workpack-test:
	@python3 -m unittest tools.tests.test_peripheral_first_workpack -v

.PHONY: lesson-adoption-benchmark lesson-adoption-benchmark-test primary-source-downgrade primary-source-downgrade-test hunter-packet-outcome-join hunter-packet-outcome-join-test clean-control-finder clean-control-finder-test fork-pinned-witness fork-pinned-witness-test
lesson-adoption-benchmark: ## Lane J7: measure whether mined lessons changed worker decisions
	@if [ -z "$(WS)" ]; then echo 'Usage: make lesson-adoption-benchmark WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/lesson-adoption-benchmark.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json)

lesson-adoption-benchmark-test:
	@python3 -m unittest tools.tests.test_lesson_adoption_benchmark -v

primary-source-downgrade: ## Lane I3a: classify external-mined source_type, cap secondary-only proof confidence
	@python3 tools/primary-source-downgrade.py $(if $(SUBTREES),--subtrees $(SUBTREES)) $(if $(STRICT),--strict) $(if $(JSON),--json)

primary-source-downgrade-test:
	@python3 -m unittest tools.tests.test_primary_source_downgrade -v

hunter-packet-outcome-join: ## Lane B9: join corpus/triager/OOS/artifact/proof into bounded hunter block
	@if [ -z "$(WS)" ]; then echo 'Usage: make hunter-packet-outcome-join WS=<workspace> [ATTACK_CLASS=<c>] [BUG_CLASS=<c>] [JSON=1]'; exit 2; fi
	@python3 tools/hunter-packet-outcome-join.py --workspace "$(_WS_RESOLVED)" $(if $(ATTACK_CLASS),--attack-class $(ATTACK_CLASS)) $(if $(BUG_CLASS),--bug-class $(BUG_CLASS)) $(if $(JSON),--json)

hunter-packet-outcome-join-test:
	@python3 -m unittest tools.tests.test_hunter_packet_outcome_join -v

clean-control-finder: ## Lane C6: check High/Critical proof artifacts carry clean-control comparison
	@if [ -z "$(WS)" ]; then echo 'Usage: make clean-control-finder WS=<workspace> [STRICT=1] [JSON=1]'; exit 2; fi
	@python3 tools/clean-control-finder.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json)

clean-control-finder-test:
	@python3 -m unittest tools.tests.test_clean_control_finder -v

fork-pinned-witness: ## Lane C5: check/scaffold triager-grade witness bundle for proved High/Critical rows
	@if [ -z "$(WS)" ]; then echo 'Usage: make fork-pinned-witness WS=<workspace> [STRICT=1] [JSON=1] [SCAFFOLD=<row-id>]'; exit 2; fi
	@python3 tools/fork-pinned-witness.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json) $(if $(SCAFFOLD),--scaffold $(SCAFFOLD))

fork-pinned-witness-test:
	@python3 -m unittest tools.tests.test_fork_pinned_witness -v

.PHONY: temporal-state-provenance temporal-state-provenance-test dispatch-receipt-check dispatch-receipt-check-test corpus-quality-routing corpus-quality-routing-test worker-delivery-contract worker-delivery-contract-test
temporal-state-provenance: ## Lane G5: build/check temporal live-state timeline for High/Critical candidates
	@if [ -z "$(WS)" ]; then echo 'Usage: make temporal-state-provenance WS=<workspace> [STRICT=1] [JSON=1] [SCAFFOLD=1]'; exit 2; fi
	@python3 tools/temporal-state-provenance.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json) $(if $(SCAFFOLD),--scaffold)

temporal-state-provenance-test:
	@python3 -m unittest tools.tests.test_temporal_state_provenance -v

dispatch-receipt-check: ## Lane B5: enforce machine-readable MCP receipts in High/Critical worker packets
	@if [ -z "$(WS)" ]; then echo 'Usage: make dispatch-receipt-check WS=<workspace> [STRICT=1] [JSON=1]'; exit 2; fi
	@python3 tools/dispatch-receipt-check.py --workspace "$(_WS_RESOLVED)" $(if $(STRICT),--strict) $(if $(JSON),--json)

dispatch-receipt-check-test:
	@python3 -m unittest tools.tests.test_dispatch_receipt_check -v

corpus-quality-routing: ## Lane J3: route corpus rows to usable/advisory/blocked work queues
	@python3 tools/corpus-quality-routing.py $(if $(SUBTREES),--subtrees $(SUBTREES)) $(if $(LIMIT),--limit $(LIMIT)) $(if $(JSON),--json)

corpus-quality-routing-test:
	@python3 -m unittest tools.tests.test_corpus_quality_routing -v

# --- Phase 1: trusted-corpus index + quarantine -----------------------------
corpus-trust-build: ## Phase 1: build trusted-corpus index + ledgers. SUBTREES=<a,b>, LIMIT=<n>, REPLAY=<manifest> optional.
	@python3 tools/trusted-corpus-index-build.py $(if $(SUBTREES),--subtrees $(SUBTREES)) $(if $(LIMIT),--limit $(LIMIT)) $(if $(REPLAY),--replay-manifest $(REPLAY)) $(if $(JSON),--json)

trusted-corpus-index: corpus-trust-build ## Phase 1: alias - rebuild the trusted-corpus index.

trusted-corpus-check: ## Phase 1: validate the trusted-corpus index against schemas + definition-of-done.
	@python3 tools/trusted-corpus-index-check.py $(if $(STRICT),--strict) $(if $(JSON),--json)

corpus-trust-report: ## Phase 1: print the trusted-corpus report (reports/corpus_trust/latest.md).
	@cat reports/corpus_trust/latest.md 2>/dev/null || echo "no report yet - run make corpus-trust-build"

corpus-trust-ci: ## Phase 1: CI gate - build (dry-run) then check the trusted-corpus index.
	@python3 tools/trusted-corpus-index-build.py --dry-run --json >/dev/null
	@python3 tools/trusted-corpus-index-check.py

corpus-trust-test:
	@python3 -m unittest tools.tests.test_trusted_corpus_index -v

worker-delivery-contract: ## Lane J4: check/assemble bounded lesson pack for High/Critical worker packets
	@python3 tools/worker-delivery-contract.py $(if $(TARGET),$(TARGET)) $(if $(ASSEMBLE),--assemble) $(if $(SEVERITY),--severity $(SEVERITY)) $(if $(STRICT),--strict) $(if $(JSON),--json)

worker-delivery-contract-test:
	@python3 -m unittest tools.tests.test_worker_delivery_contract -v

.PHONY: source-read-parity-check source-read-parity-check-test cross-protocol-dependency-graph cross-protocol-dependency-graph-test proof-artifact-promotion proof-artifact-promotion-test derived-artifact-size-budget derived-artifact-size-budget-test
source-read-parity-check: ## Lane B6: non-Claude source-read hacker-question parity gate
	@if [ -z "$(WS)" ] && [ -z "$(MANIFEST)" ] && [ -z "$(SOURCE)" ]; then echo 'Usage: make source-read-parity-check [WS=<ws>] [MANIFEST=<f>] [SOURCE=<f>] [STRICT=1] [JSON=1]'; exit 2; fi
	@python3 tools/source-read-parity-check.py $(if $(WS),--workspace "$(_WS_RESOLVED)") $(if $(MANIFEST),--manifest $(MANIFEST)) $(if $(SOURCE),--source $(SOURCE)) $(if $(STRICT),--strict) $(if $(JSON),--json)

source-read-parity-check-test:
	@python3 -m unittest tools.tests.test_source_read_parity_check -v

cross-protocol-dependency-graph: ## Lane D5: static cross-protocol dependency graph for chain prerequisites
	@if [ -z "$(WS)" ]; then echo 'Usage: make cross-protocol-dependency-graph WS=<workspace> [JSON=1]'; exit 2; fi
	@python3 tools/cross-protocol-dependency-graph.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json)

cross-protocol-dependency-graph-test:
	@python3 -m unittest tools.tests.test_cross_protocol_dependency_graph -v

proof-artifact-promotion: ## Lane J3a: promote proof-ready candidates, audit blocked, check outcome linkage
	@python3 tools/proof-artifact-promotion.py $(if $(PROMOTE),--promote) $(if $(UNBLOCK),--unblock-audit) $(if $(STRICT),--strict) $(if $(JSON),--json)

proof-artifact-promotion-test:
	@python3 -m unittest tools.tests.test_proof_artifact_promotion -v

derived-artifact-size-budget: ## Lane J3e: enforce repo size budget on generated derived sidecars
	@python3 tools/derived-artifact-size-budget.py --root audit/corpus_tags/derived $(if $(STRICT),--strict) $(if $(JSON),--json)

derived-artifact-size-budget-test:
	@python3 -m unittest tools.tests.test_derived_artifact_size_budget -v

.PHONY: sidecar-staleness-gate sidecar-staleness-gate-test analogue-provenance analogue-provenance-test pre-poc-lesson-gate pre-poc-lesson-gate-test
sidecar-staleness-gate: ## Lane J3b: gate stale derived sidecars; require SIDECAR_STALE_REASON
	@python3 tools/sidecar-staleness-gate.py $(if $(STRICT),--strict) $(if $(JSON),--json)

sidecar-staleness-gate-test:
	@python3 -m unittest tools.tests.test_sidecar_staleness_gate -v

analogue-provenance: ## Lane J3c: enrich cross-language analogues with provenance + usage class
	@python3 tools/analogue-provenance.py $(if $(LIMIT),--limit $(LIMIT)) $(if $(STRICT),--strict) $(if $(JSON),--json)

analogue-provenance-test:
	@python3 -m unittest tools.tests.test_analogue_provenance -v

pre-poc-lesson-gate: ## Lane J5b: candidate-aware pre-PoC lesson gate over top-N High/Critical rows
	@if [ -z "$(WS)" ]; then echo 'Usage: make pre-poc-lesson-gate WS=<workspace> [TOP_N=10] [CONTEXT=prove-top-leads] [STRICT=1] [JSON=1]'; exit 2; fi
	@python3 tools/pre-poc-lesson-gate.py --workspace "$(_WS_RESOLVED)" --top-n $(if $(TOP_N),$(TOP_N),10) --context $(if $(CONTEXT),$(CONTEXT),prove-top-leads) $(if $(STRICT),--strict) $(if $(JSON),--json)

pre-poc-lesson-gate-test:
	@python3 -m unittest tools.tests.test_pre_poc_lesson_gate -v

brain-prime: ## Wave-8: generate Brain Priming Report for a workspace
	@if [ -z "$(WS)" ]; then \
	  echo "Usage: make brain-prime WS=<workspace> [TARGET_REPO=owner/repo]"; \
	  exit 2; \
	fi
	@python3 tools/brain-prime.py --workspace $(WS) \
	  $(if $(TARGET_REPO),--target-repo $(TARGET_REPO)) \
	  $(if $(LANGUAGE),--language $(LANGUAGE)) \
	  $(if $(SCOPE_GLOBS),--scope-globs "$(SCOPE_GLOBS)") \
	  $(if $(MAX_FILES),--max-files $(MAX_FILES)) \
	  $(if $(MIN_CONFIDENCE),--min-confidence $(MIN_CONFIDENCE)) \
	  $(if $(filter 1,$(STRICT)),--strict)

brain-prime-dry-run: ## Wave-8: small-scope dry run (5 files / 2 fn each)
	@if [ -z "$(WS)" ]; then \
	  echo "Usage: make brain-prime-dry-run WS=<workspace>"; \
	  exit 2; \
	fi
	@python3 tools/brain-prime.py --workspace $(WS) \
	  --max-files 5 --top-functions-per-file 2

brain-prime-test: ## Wave-8: unit tests for the brain-prime orchestrator
	@python3 -m unittest tools.tests.test_brain_prime

.PHONY: detector-action-graph-mcp-feed
detector-action-graph-mcp-feed:
	@if [ -z "$(WS)" ]; then echo "ERROR: WS=<workspace> required"; exit 2; fi
	@if [ -z "$(DETECTOR)$(HIT_INDEX)" ]; then echo "ERROR: DETECTOR=<slug> or HIT_INDEX=<n> required"; exit 2; fi
	python3 tools/vault-mcp-server.py --call vault_detector_action_graph_context --args "$$(python3 -c 'import json,sys; print(json.dumps({"workspace_path": sys.argv[1], "detector_slug": sys.argv[2] if len(sys.argv) > 2 else "", "hit_index": int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else 0, "file_path": sys.argv[4] if len(sys.argv) > 4 else "", "function_name": sys.argv[5] if len(sys.argv) > 5 else "", "language": sys.argv[6] if len(sys.argv) > 6 else "", "context": sys.argv[7] if len(sys.argv) > 7 else "", "top_n": 3}))' "$(_WS_RESOLVED)" "$(DETECTOR)" "$(HIT_INDEX)" "$(FILE)" "$(FUNC)" "$(LANGUAGE)" "$(CONTEXT)")" | python3 -m json.tool | head -120

.PHONY: chained-attack-plan-mcp-feed
chained-attack-plan-mcp-feed:
	@if [ -z "$(WS)" ]; then echo "ERROR: WS=<workspace> required"; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make chained-attack-plan-mcp-feed" "$(_WS_RESOLVED)"
	@chain_plan="$(if $(CHAIN_PLAN_PATH),$(CHAIN_PLAN_PATH),$(CHAIN_PLAN))"; \
	python3 tools/vault-mcp-server.py --call vault_chained_attack_plan_context --args "$$(python3 -c 'import json,sys; payload={"workspace_path": sys.argv[1], "max_plans": int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else 5}; chain_plan=sys.argv[3] if len(sys.argv) > 3 else ""; payload.update({"chain_plan_path": chain_plan} if chain_plan else {}); print(json.dumps(payload))' "$(_WS_RESOLVED)" "$(MAX_PLANS)" "$$chain_plan")" | python3 -m json.tool | head -160

.PHONY: detector-proof-context
detector-proof-context:
	@if [ -z "$(WS)" ]; then echo "ERROR: WS=<workspace> required"; exit 2; fi
	@bash tools/ws-resolve-guard.sh "make detector-proof-context" "$(_WS_RESOLVED)"
	@if [ -z "$(DETECTOR)$(ALL)" ]; then echo "[make detector-proof-context] ERR DETECTOR=<slug> or ALL=1 required; broad proof-context reads are intentionally explicit"; exit 2; fi
	@echo "[make detector-proof-context] ADVISORY READ-ONLY CONTEXT: no commands executed; not proof, not impact, not severity, not OOS/dupe clearance, not submission readiness" >&2
	@python3 -c 'import json,sys; from pathlib import Path; p=Path(sys.argv[1]); allow=sys.argv[2].lower() in {"1","true","yes","on"}; data=json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}; status=str(data.get("status") or "missing_freshness_marker"); stale=bool(data.get("stale", True)); q=data.get("proof_queue") if isinstance(data.get("proof_queue"), dict) else {}; queue_exists=bool(q.get("exists", False)); print(f"[make detector-proof-context] freshness_status={status} stale={stale} queue_exists={queue_exists} marker={p}", file=sys.stderr); print("[make detector-proof-context] WARN freshness marker is not fresh; rerun make audit-hacker-logic-bridge or make proof-obligation-queue before routing workers" if (stale or status in {"missing_freshness_marker","stale_existing_proof_queue"}) and not allow else "[make detector-proof-context] freshness marker accepted for read-only preview", file=sys.stderr)' \
	  "$(_WS_RESOLVED)/.auditooor/proof_obligation_queue.freshness.json" "$(ALLOW_STALE)"
	@preview_lines="$(if $(PREVIEW_LINES),$(PREVIEW_LINES),200)"; \
	python3 tools/vault-mcp-server.py --call vault_solidity_detector_proof_context --args "$$(python3 -c 'import json,sys; payload={"workspace_path": sys.argv[1], "limit": int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else 8}; detector=sys.argv[3] if len(sys.argv) > 3 else ""; status=sys.argv[4] if len(sys.argv) > 4 else ""; proof_only=sys.argv[5] if len(sys.argv) > 5 else ""; payload.update({"detector_slug": detector} if detector else {}); payload.update({"status": status} if status else {}); payload.update({"proof_only": proof_only.lower() not in {"", "0", "false", "no", "off"}} if proof_only else {}); print(json.dumps(payload))' "$(_WS_RESOLVED)" "$(LIMIT)" "$(DETECTOR)" "$(STATUS)" "$(PROOF_ONLY)")" | python3 -m json.tool | head -n "$$preview_lines"; \
	echo "[make detector-proof-context] advisory-only: reads existing MCP/proof artifacts; does not run PoCs, prove impact, or indicate submission readiness" >&2

.PHONY: chained-attack-plan-mcp-feed-test
chained-attack-plan-mcp-feed-test:
	@python3 -m unittest \
	  tools.tests.test_make_hacker_brief_chained_attack_plans.MakeHackerBriefChainedAttackPlansTest.test_chained_attack_plan_mcp_feed_dry_run_calls_vault_context \
	  tools.tests.test_make_hacker_brief_chained_attack_plans.MakeHackerBriefChainedAttackPlansTest.test_chained_attack_plan_mcp_feed_requires_workspace -v

.PHONY: detector-proof-context-test
detector-proof-context-test:
	@python3 -m unittest \
	  tools.tests.test_make_hacker_brief_chained_attack_plans.MakeHackerBriefChainedAttackPlansTest.test_detector_proof_context_dry_run_calls_vault_context \
	  tools.tests.test_make_hacker_brief_chained_attack_plans.MakeHackerBriefChainedAttackPlansTest.test_detector_proof_context_requires_workspace \
	  tools.tests.test_make_hacker_brief_chained_attack_plans.MakeHackerBriefChainedAttackPlansTest.test_detector_proof_context_requires_detector_or_all -v

# Wave-2 PR-A (PR #728): post-migration validator. Asserts the
# hackerman_record v1 -> v1.1 corpus sweep landed cleanly. See
# tools/wave2-w21-post-migration-validator.py for the full schema.
.PHONY: wave2-w21-validate
wave2-w21-validate: ## Wave-2 PR-A: assert hackerman v1->v1.1 migration is complete and indexes are healthy
	@python3 tools/wave2-w21-post-migration-validator.py --workspace . --strict --json

.PHONY: wave2-w21-validate-test
wave2-w21-validate-test:
	@python3 -m unittest tools.tests.test_wave2_w21_post_migration_validator -v

# Wave-2 PR-A (PR #728): Rule 37 emit-time tier audit. Drills deeper than
# wave2-w21-validate on the verification_tier-population invariant by
# emitting a per-prefix breakdown so a follow-up batch can isolate which
# corpus section regressed Rule 37 compliance. See
# tools/wave2-rule-37-emit-time-tier-audit.py.
.PHONY: wave2-r37-audit
wave2-r37-audit: ## Wave-2 PR-A: Rule 37 emit-time tier audit with per-prefix breakdown
	@python3 tools/wave2-rule-37-emit-time-tier-audit.py --workspace . --json

.PHONY: wave2-r37-audit-test
wave2-r37-audit-test:
	@python3 -m unittest tools.tests.test_wave2_rule_37_emit_time_tier_audit -v

# Wave-2 PR-A (PR #728): W2.5 tier-3 -> tier-2 promotion independent verifier.
# Re-derives the 2098-record promotion claim from commit d0e3722d0b against
# the live corpus state. See tools/wave2-w25-tier3-promotion-verify.py.
.PHONY: wave2-w25-verify
wave2-w25-verify: ## Wave-2 PR-A: independently verify the W2.5 tier-3 -> tier-2 promotion (commit d0e3722d0b)
	@python3 tools/wave2-w25-tier3-promotion-verify.py --workspace . --strict --json

.PHONY: wave2-w25-verify-test
wave2-w25-verify-test:
	@python3 -m unittest tools.tests.test_wave2_w25_tier3_promotion_verify -v

# Wave-2 PR-A (PR #728) capability-gap #3: arbitrary-path YAML schema probe.
# Operator drops a YAML at any path and asks "what schema is this?"; see
# tools/auditooor-yaml-schema-detect.py for the detection rubric.
# Usage:
#   make auditooor-yaml-schema-detect FILE=/tmp/foo.yaml
#   make auditooor-yaml-schema-detect DIR=/path/to/dir
# Optional: STRICT=1 (exit non-zero on any unknown), JSON=1 (JSON output).
.PHONY: auditooor-yaml-schema-detect
auditooor-yaml-schema-detect: ## Wave-2 PR-A: probe a YAML file/dir for its auditooor schema family
	@python3 tools/auditooor-yaml-schema-detect.py \
	  $(if $(FILE),--file $(FILE)) \
	  $(if $(DIR),--dir $(DIR)) \
	  $(if $(JSON),--json) \
	  $(if $(STRICT),--strict)

.PHONY: auditooor-yaml-schema-detect-test
auditooor-yaml-schema-detect-test:
	@python3 -m unittest tools.tests.test_auditooor_yaml_schema_detect -v

# Wave-2 PR-A (PR #728): structural CVE/GHSA provenance verification sweep.
# Post-Wave-1-Vyper-CVE-fabrication follow-up. Scans the additive indexes
# by_cve_id.jsonl + by_ghsa_id.jsonl and flags any record whose CVE/GHSA
# claim lacks a trusted source URL (nvd.nist.gov / cve.mitre.org /
# github.com/.../security/advisories). Structural-only (no network);
# see tools/hackerman-nvd-verification-sweep.py for live-API validation.
# See tools/wave2-cve-ghsa-verification-sweep.py.
.PHONY: wave2-cve-ghsa-verify
wave2-cve-ghsa-verify: ## Wave-2 PR-A: structural CVE/GHSA provenance sweep (no network)
	@python3 tools/wave2-cve-ghsa-verification-sweep.py --workspace . --json

.PHONY: wave2-cve-ghsa-verify-test
wave2-cve-ghsa-verify-test:
	@python3 -m unittest tools.tests.test_wave2_cve_ghsa_verification_sweep -v

# Wave-2 PR-A (PR #728): W2.6 cosmos-sdk dupe-canonicalization independent verifier.
# Re-derives the REDIRECT_MANIFEST.json structural & coverage claims from
# commit 8fa397589f against live corpus state. Emits the
# auditooor.wave2_w26_cosmos_dedup_verify.v1 JSON envelope on stdout.
# See tools/wave2-w26-cosmos-dedup-verify.py.
.PHONY: wave2-w26-verify
wave2-w26-verify: ## Wave-2 PR-A: independently verify the W2.6 cosmos-sdk dupe canonicalization (commit 8fa397589f)
	@python3 tools/wave2-w26-cosmos-dedup-verify.py --workspace . --strict --json

.PHONY: wave2-w26-verify-test
wave2-w26-verify-test:
	@python3 -m unittest tools.tests.test_wave2_w26_cosmos_dedup_verify -v

# --------------------------------------------------------------------------
# Wave-2 PR-A: PR #728 close-readiness verdict (auditooor.wave2_a_close_readiness.v1)
# --------------------------------------------------------------------------
# Single-command verdict across the six Wave-2-A close criteria defined in
# `~/.claude/scheduled-tasks/auditooor-loops-hourly/SKILL.md`.  Emits the
# `auditooor.wave2_a_close_readiness.v1` JSON envelope on stdout.  Use
# `--strict` to make BLOCKED/PARTIAL non-zero exit; use
# `--run-pre-merge` to actually invoke `make hackerman-pre-merge`
# (criterion 5) instead of reading the cached verdict.
.PHONY: wave2-a-close-readiness wave2-a-close-readiness-test
wave2-a-close-readiness: ## Wave-2 PR-A: PR #728 close-readiness verdict (JSON)
	@python3 tools/wave2-a-close-readiness.py --workspace . --json

wave2-a-close-readiness-test:
	@python3 -m unittest tools.tests.test_wave2_a_close_readiness -v

# --------------------------------------------------------------------------
# Wave-2 PR-A: hackerman corpus dual-form record audit
# --------------------------------------------------------------------------
# Addresses the W2.5 verifier WARNING (commit 803c97f9e4): some corpus
# prefixes (bridge-incident, mev-exploits, movebit, solana-svm, zkbugs,
# zkbugtracker) emit records in both record.yaml AND record.json sibling
# forms. The indexer canonicalises by record_id (dedupe), but a naive
# file walker doubles the count. This target surfaces an explicit per-
# prefix dual-form census, verifies record_id consistency across the
# two forms, and quantifies any inflation in the 5 additive indexes
# (by_cve_id, by_ghsa_id, by_firm, by_verification_tier, by_incident_date).
.PHONY: wave2-index-dual-form-audit wave2-index-dual-form-audit-test
wave2-index-dual-form-audit: ## Wave-2 PR-A: audit corpus for dual-form record duplication + index inflation
	@python3 tools/wave2-index-dual-form-audit.py --workspace . --json

wave2-index-dual-form-audit-test:
	@python3 -m unittest tools.tests.test_wave2_index_dual_form_audit -v

# --------------------------------------------------------------------------
# Wave-2 PR-A: PR #728 changelog generator (auditooor.hackerman_pr_changelog.v1)
# --------------------------------------------------------------------------
# Walks `git log main..wave-2-corpus-migration` and produces a structured
# markdown changelog (top summary table, per-lane sections, close-criteria
# coverage, unique MCP context_pack_ids).  Use the JSON variant for
# downstream consumers; use `--output <path>` to write to disk.
.PHONY: wave2-a-changelog wave2-a-changelog-json wave2-a-changelog-test
wave2-a-changelog: ## Wave-2 PR-A: emit markdown changelog for PR #728
	@python3 tools/hackerman-pr-changelog-generator.py \
	    --branch wave-2-corpus-migration --base main --format markdown

wave2-a-changelog-json: ## Wave-2 PR-A: emit JSON changelog for PR #728
	@python3 tools/hackerman-pr-changelog-generator.py \
	    --branch wave-2-corpus-migration --base main --format json

wave2-a-changelog-test:
	@python3 -m unittest tools.tests.test_hackerman_pr_changelog_generator -v

# --------------------------------------------------------------------------
# Wave-3 W2.2 Phase-2 detector roster smoke driver
# --------------------------------------------------------------------------
# Loads the W2.2 detector roster via tools/audit/wave2_w22_detector_loader.py
# and counts shape-literal file hits against the workspace under WS=...
# Both env flags default OFF; set AUDITOOOR_W22_PHASE1_ENABLED=1 and
# AUDITOOOR_W22_PHASE2_ENABLED=1 to load the broader roster.
#
# Examples:
#   make wave3-w22-phase2-smoke WS=/Users/wolf/audits/centrifuge-v3
#   AUDITOOOR_W22_PHASE1_ENABLED=1 AUDITOOOR_W22_PHASE2_ENABLED=1 \
#     make wave3-w22-phase2-smoke WS=/Users/wolf/audits/centrifuge-v3
#
# The driver is for smoke validation only; the load-bearing detector
# runner is `tools/audit/run-autogen-detectors.py` (per spec section 8).
.PHONY: wave3-w22-phase2-smoke wave3-w22-phase2-smoke-test
wave3-w22-phase2-smoke: ## Wave-3 W2.2: Phase-2 smoke driver (WS=<workspace>)
	@if [ -z "$(WS)" ]; then \
	  echo "[wave3-w22-phase2-smoke] ERROR: WS=<workspace> required" >&2; \
	  exit 2; \
	fi
	@python3 tools/audit/wave2_w22_phase2_smoke.py --workspace "$(WS)"

wave3-w22-phase2-smoke-test:
	@python3 -m unittest tools.tests.test_wave2_w22_phase2_loader -v

.PHONY: wave2-cross-firm-dedup-detect
wave2-cross-firm-dedup-detect: ## Wave-2 PR-B: surface candidate cross-firm duplicate findings under audit/corpus_tags/tags/firm-*-audits/
	@workspace="$(if $(WS),$(WS),.)"; \
	min_sim="$(if $(MIN_SIMILARITY),$(MIN_SIMILARITY),0.6)"; \
	min_size="$(if $(MIN_CLUSTER_SIZE),$(MIN_CLUSTER_SIZE),2)"; \
	cap="$(if $(CLUSTER_CAP),$(CLUSTER_CAP),50)"; \
	firms_arg=""; \
	if [ -n "$(FIRMS)" ]; then firms_arg="--firms $(FIRMS)"; fi; \
	verbose_arg=""; \
	if [ -n "$(VERBOSE)" ]; then verbose_arg="--verbose"; fi; \
	json_arg=""; \
	if [ -n "$(JSON)" ]; then json_arg="--json"; fi; \
	python3 tools/wave2-cross-firm-dedup-detector.py \
	  --workspace "$$workspace" \
	  --min-similarity "$$min_sim" \
	  --min-cluster-size "$$min_size" \
	  --cluster-cap "$$cap" \
	  $$firms_arg $$verbose_arg $$json_arg

.PHONY: wave2-cross-firm-dedup-detect-test
wave2-cross-firm-dedup-detect-test: ## Wave-2 PR-B: unit tests for the cross-firm dedup detector
	@python3 -m unittest tools.tests.test_wave2_cross_firm_dedup_detector -v

.PHONY: wave2-firm-parser-coverage-matrix
wave2-firm-parser-coverage-matrix: ## Wave-2 PR-B: aggregate W2.4 firm parsers into a firm x bug-class coverage matrix. JSON=1 emits JSON; MARKDOWN=1 forces markdown; VERBOSE=1 prints per-firm detail.
	@workspace="$(if $(WS),$(WS),.)"; \
	json_flag="$(if $(JSON),--json,)"; \
	md_flag="$(if $(MARKDOWN),--markdown,)"; \
	verbose_flag="$(if $(VERBOSE),--verbose,)"; \
	python3 tools/wave2-firm-parser-coverage-matrix.py \
	  --workspace "$$workspace" \
	  $$json_flag $$md_flag $$verbose_flag

.PHONY: wave2-firm-parser-coverage-matrix-test
wave2-firm-parser-coverage-matrix-test: ## Wave-2 PR-B: unit tests for the firm-parser coverage-matrix tool
	@python3 -m unittest tools.tests.test_wave2_firm_parser_coverage_matrix -v

.PHONY: cross-workspace-smoke-test
cross-workspace-smoke-test: ## Wave-2 PR-B (PR #729): cross-workspace CI smoke fixture - regression guard ensuring the Wave-2 toolchain stays workspace-agnostic (cap-gap fixes aa7a71912b / 9c57fa7127 / 4c55b265a0 / 93de4c3721).
	@python3 -m unittest tools.tests.test_cross_workspace_smoke -v

.PHONY: wave2-vyper-cve-real-source-emit
wave2-vyper-cve-real-source-emit: ## Wave-2 PR-B: emit real-source Vyper-CVE hackerman records (CVE-2023-39363/GHSA-5824-cm3x-3c38). Use APPLY=1 to write; default is dry-run. OUT=<dir> overrides default output dir. JSON=1 emits JSON summary. NO_INCIDENT=1 skips the Curve 2023-07-30 incident roll-up record.
	@out_arg=""; \
	if [ -n "$(OUT)" ]; then out_arg="--out $(OUT)"; fi; \
	dry_flag="$(if $(APPLY),,--dry-run)"; \
	json_flag="$(if $(JSON),--json-summary,)"; \
	no_incident_flag="$(if $(NO_INCIDENT),--no-incident,)"; \
	python3 tools/hackerman-etl-from-vyper-cve-real-source.py $$out_arg $$dry_flag $$json_flag $$no_incident_flag

.PHONY: wave2-vyper-cve-real-source-emit-test
wave2-vyper-cve-real-source-emit-test: ## Wave-2 PR-B: unit tests for the real-source Vyper-CVE miner
	@python3 -m unittest tools.tests.test_hackerman_etl_from_vyper_cve_real_source -v

.PHONY: wave2-b-close-readiness
wave2-b-close-readiness: ## Wave-2 PR-B: single-command close-readiness verdict for PR #729 (wave-2-capability-expansion). STRICT=1 returns non-zero unless READY_TO_MERGE. JSON=1 emits JSON. RUN_REGRESSION=1 opts into live firm-parser unittest invocation.
	@workspace="$(if $(WS),$(WS),.)"; \
	strict_arg=""; \
	if [ -n "$(STRICT)" ]; then strict_arg="--strict"; fi; \
	json_arg=""; \
	if [ -n "$(JSON)" ]; then json_arg="--json"; fi; \
	run_regression_arg=""; \
	if [ -n "$(RUN_REGRESSION)" ]; then run_regression_arg="--run-regression"; fi; \
	python3 tools/wave2-b-close-readiness.py \
	  --workspace "$$workspace" \
	  $$strict_arg $$json_arg $$run_regression_arg

.PHONY: wave2-b-close-readiness-test
wave2-b-close-readiness-test: ## Wave-2 PR-B: unit tests for the close-readiness automator
	@python3 -m unittest tools.tests.test_wave2_b_close_readiness -v

.PHONY: wave2-mcp-inventory-healthcheck
wave2-mcp-inventory-healthcheck: ## Wave-2 PR-B (PR #729): MCP callable inventory + parity + test-coverage healthcheck. STRICT=1 fails non-zero on FAIL. LIST_UNTESTED=1 prints full untested list. WORKSPACE=<path> overrides workspace root.
	@workspace="$(if $(WORKSPACE),$(WORKSPACE),$(CURDIR))"; \
	strict_flag="$(if $(STRICT),--strict,)"; \
	list_flag="$(if $(LIST_UNTESTED),--list-untested,)"; \
	python3 tools/wave2-mcp-callable-inventory-healthcheck.py \
	  --workspace "$$workspace" \
	  $$strict_flag $$list_flag

.PHONY: wave2-mcp-inventory-healthcheck-test
wave2-mcp-inventory-healthcheck-test: ## Wave-2 PR-B (PR #729): unit tests for the MCP callable inventory healthcheck
	@python3 -m unittest tools.tests.test_wave2_mcp_callable_inventory_healthcheck -v

.PHONY: wave3-poc-scaffold
wave3-poc-scaffold: ## Wave-3 PR-C: emit a Rule-30 / Rule-18 / Rule-19 compliant PoC scaffold. Pass AUDIT_PIN, TARGET_REPO, TARGET_CONTRACT, CLUSTER_NAME, ATTACK_CLASS, SEVERITY (Low|Medium|High|Critical), WS, and optionally LANG, OUT_DIR, RUBRIC_LINE.
	@if [ -z "$(AUDIT_PIN)" ] || [ -z "$(TARGET_REPO)" ] || [ -z "$(TARGET_CONTRACT)" ] || [ -z "$(CLUSTER_NAME)" ] || [ -z "$(ATTACK_CLASS)" ] || [ -z "$(SEVERITY)" ] || [ -z "$(WS)" ]; then \
	  echo "usage: make wave3-poc-scaffold AUDIT_PIN=<sha> TARGET_REPO=<owner/repo> TARGET_CONTRACT=<path> CLUSTER_NAME=<name> ATTACK_CLASS=<class> SEVERITY=<Low|Medium|High|Critical> WS=<workspace> [LANG=solidity|go|rust] [OUT_DIR=<path>] [RUBRIC_LINE='...']"; \
	  exit 2; \
	fi; \
	lang_arg=""; \
	if [ -n "$(LANG)" ]; then lang_arg="--target-language $(LANG)"; fi; \
	out_dir_arg=""; \
	if [ -n "$(OUT_DIR)" ]; then out_dir_arg="--out-dir $(OUT_DIR)"; fi; \
	rubric_arg=""; \
	if [ -n "$(RUBRIC_LINE)" ]; then rubric_arg="--rubric-line $(RUBRIC_LINE)"; fi; \
	python3 tools/wave3-poc-scaffold-generator.py \
	  --audit-pin $(AUDIT_PIN) \
	  --target-repo $(TARGET_REPO) \
	  --target-contract $(TARGET_CONTRACT) \
	  --cluster-name $(CLUSTER_NAME) \
	  --attack-class $(ATTACK_CLASS) \
	  --severity $(SEVERITY) \
	  --workspace $(WS) \
	  $$lang_arg $$out_dir_arg $$rubric_arg

.PHONY: wave3-poc-scaffold-test
wave3-poc-scaffold-test: ## Wave-3 PR-C: unit tests for the PoC scaffold generator
	@python3 -m unittest tools.tests.test_wave3_poc_scaffold_generator -v

.PHONY: wave3-cluster-to-hacker-brief
wave3-cluster-to-hacker-brief: ## Wave-3 (PR #729): convert engage_report.md clusters to Hacker Briefs. WS=<ws> required. CLUSTER=<name> OR ALL=1. FORMAT=markdown|json. OUT=<dir> overrides default <ws>/hacker_briefs/. ALLOW_BLOCKED=1 emits briefs even when PRIOR_CONCERNS flags ack-by-design.
	@if [ -z "$(WS)" ]; then echo "error: WS=<workspace> is required"; exit 2; fi; \
	cluster_arg=""; if [ -n "$(CLUSTER)" ]; then cluster_arg="--cluster $(CLUSTER)"; fi; \
	all_flag="$(if $(ALL),--all,)"; \
	out_arg=""; if [ -n "$(OUT)" ]; then out_arg="--out-dir $(OUT)"; fi; \
	fmt_arg="--format $(if $(FORMAT),$(FORMAT),markdown)"; \
	allow_flag="$(if $(ALLOW_BLOCKED),--allow-blocked,)"; \
	json_flag="$(if $(JSON),--json,)"; \
	python3 tools/wave3-cluster-to-hacker-brief.py --workspace $(WS) \
	  $$cluster_arg $$all_flag $$out_arg $$fmt_arg $$allow_flag $$json_flag

.PHONY: wave3-cluster-to-hacker-brief-test
wave3-cluster-to-hacker-brief-test: ## Wave-3 (PR #729): unit tests for tools/wave3-cluster-to-hacker-brief.py
	@python3 -m unittest tools.tests.test_wave3_cluster_to_hacker_brief -v

.PHONY: wave3-originality-scan
wave3-originality-scan: ## Wave-3 PR-C (PR #729): published-source originality scanner. Required: DRAFT=<path> TARGET=<protocol-slug>. Optional: WS=<workspace> CVE=<id> GHSA=<id> DISCLOSURE_URL=<url> SOURCES=<comma-list> CACHE_DIR=<path> STRICT=1 JSON=1. NOTE: only checks PUBLIC sources; private Cantina/Immunefi/Sherlock/Code4rena submissions are NOT checkable.
	@if [ -z "$(DRAFT)" ]; then echo "error: DRAFT=<finding-draft.md> required" >&2; exit 2; fi; \
	if [ -z "$(TARGET)" ]; then echo "error: TARGET=<protocol-slug> required" >&2; exit 2; fi; \
	ws_arg=""; \
	if [ -n "$(WS)" ]; then ws_arg="--workspace $(WS)"; fi; \
	cve_arg=""; \
	if [ -n "$(CVE)" ]; then cve_arg="--cve-id $(CVE)"; fi; \
	ghsa_arg=""; \
	if [ -n "$(GHSA)" ]; then ghsa_arg="--ghsa-id $(GHSA)"; fi; \
	disclosure_arg=""; \
	if [ -n "$(DISCLOSURE_URL)" ]; then disclosure_arg="--disclosure-url $(DISCLOSURE_URL)"; fi; \
	sources_arg=""; \
	if [ -n "$(SOURCES)" ]; then sources_arg="--sources $(SOURCES)"; fi; \
	cache_arg=""; \
	if [ -n "$(CACHE_DIR)" ]; then cache_arg="--cache-dir $(CACHE_DIR)"; fi; \
	strict_arg="$(if $(STRICT),--strict,)"; \
	json_arg="$(if $(JSON),--json,)"; \
	python3 tools/wave3-published-source-originality-scanner.py \
	  --finding-draft $(DRAFT) \
	  --target-protocol $(TARGET) \
	  $$ws_arg $$cve_arg $$ghsa_arg $$disclosure_arg $$sources_arg $$cache_arg $$strict_arg $$json_arg

.PHONY: wave3-originality-scan-test
wave3-originality-scan-test: ## Wave-3 PR-C (PR #729): unit tests for the published-source originality scanner
	@python3 -m unittest tools.tests.test_wave3_published_source_originality_scanner -v

.PHONY: wave3-capability-dashboard
wave3-capability-dashboard: ## Wave-3 (PR #729): single-command capability state snapshot across detectors, MCP callables, workspaces, Wave-2 close criteria, and Wave-3 lane progress. WS=<workspace> overrides --workspace. INCLUDE=<csv> overrides --include-workspaces (default morpho-midnight,hyperbridge,near,dydx,zebra). JSON=1 emits JSON; MARKDOWN=1 emits Markdown. INCLUDE_TESTS=1 runs the bounded fast-subset unittest invocation.
	@ws_arg=""; \
	if [ -n "$(WS)" ]; then ws_arg="--workspace $(WS)"; fi; \
	include_arg=""; \
	if [ -n "$(INCLUDE)" ]; then include_arg="--include-workspaces $(INCLUDE)"; fi; \
	json_arg="$(if $(JSON),--json,)"; \
	markdown_arg="$(if $(MARKDOWN),--markdown,)"; \
	tests_arg="$(if $(INCLUDE_TESTS),--include-test-failures,)"; \
	python3 tools/wave3-capability-dashboard.py $$ws_arg $$include_arg $$json_arg $$markdown_arg $$tests_arg

.PHONY: wave3-capability-dashboard-test
wave3-capability-dashboard-test: ## Wave-3 (PR #729): unit tests for tools/wave3-capability-dashboard.py
	@python3 -m unittest tools.tests.test_wave3_capability_dashboard -v

# ---------------------------------------------------------------------------
# Wave-4: universal FP runner (tools/audit/universal_fp_runner.py)
#
# Loads dsl_pattern_universal_fp_*.yaml records from
# audit/corpus_tags/tags/ and fires per-FP regex strategies against
# the target workspace source tree. Wires into `make audit-deep` so
# the 6 universal fingerprints (FP-01..FP-06) actively detect on
# every audit-deep invocation rather than sitting as corpus seeds.
.PHONY: wave3-fp-runner wave3-fp-runner-test
wave3-fp-runner: ## Wave-4: fire universal-FP YAMLs against WS=<workspace>
	@if [ -z "$(WS)" ]; then \
	  echo "[wave3-fp-runner] ERROR: WS=<workspace> required" >&2; \
	  exit 2; \
	fi
	@ws="$(_WS_RESOLVED)"; \
	out="$$ws/.auditooor/wave3-fp-runner"; \
	mkdir -p "$$out"; \
	python3 tools/audit/universal_fp_runner.py \
	  --workspace "$$ws" \
	  $(if $(FPS),--fps $(FPS)) \
	  $(if $(TARGET_LANGUAGE),--target-language $(TARGET_LANGUAGE)) \
	  --output "$$out/universal-fp-runner.output.json" \
	  --markdown-output "$$out/universal-fp-runner.report.md"; \
	echo "[wave3-fp-runner] wrote $$out/universal-fp-runner.output.json"; \
	echo "[wave3-fp-runner] wrote $$out/universal-fp-runner.report.md"

wave3-fp-runner-test:
	@python3 -m unittest tools.tests.test_universal_fp_runner -v

# Lane W4.11 YELLOW gap closure: FP/TP feedback learning loop. Scores
# universal-FP shapes by precision against a verdict ledger and emits a
# tuning report. Wires tools/audit/fp_tp_feedback_loop.py into make.
.PHONY: fp-tp-feedback-loop fp-tp-feedback-loop-test
fp-tp-feedback-loop: ## Lane W4.7: score universal-FP shapes by precision vs verdict ledger. LEDGER=<jsonl> required; RUNNER_OUTPUT=<json>, OUT=<path>, MD_OUT=<path>, STRICT=1 optional.
	@if [ -z "$(LEDGER)" ]; then \
	  echo "[fp-tp-feedback-loop] ERROR: LEDGER=<verdict-ledger.jsonl> required" >&2; \
	  exit 2; \
	fi
	@python3 tools/audit/fp_tp_feedback_loop.py \
	  --ledger "$(LEDGER)" \
	  $(if $(RUNNER_OUTPUT),--runner-output "$(RUNNER_OUTPUT)") \
	  $(if $(OUT),--output "$(OUT)") \
	  $(if $(MD_OUT),--markdown-output "$(MD_OUT)") \
	  $(if $(STRICT),--strict)

fp-tp-feedback-loop-test:
	@python3 -m unittest tools.tests.test_fp_tp_feedback_loop -v

# Wave-5 lane W5-A2: capture FP-runner triage verdicts into the verdict
# ledger at hunt closeout. The feedback loop above is a consumer; this is
# the missing producer. Honest-empty when a workspace has no triage data.
# Wires tools/audit/fp_verdict_capture.py into make.
.PHONY: fp-verdict-capture fp-verdict-capture-test
fp-verdict-capture: ## Lane W5-A2: append FP-runner triage verdicts to audit/fp_verdict_ledger.jsonl. WS=<workspace> required; TRIAGE=<jsonl>, RUNNER_OUTPUT=<json>, LEDGER=<jsonl>, AUTO_NEGATIVE=1, DRY_RUN=1 optional.
	@if [ -z "$(WS)" ]; then \
	  echo "[fp-verdict-capture] ERROR: WS=<workspace> required" >&2; \
	  exit 2; \
	fi
	@python3 tools/audit/fp_verdict_capture.py \
	  --workspace "$(_WS_RESOLVED)" \
	  $(if $(TRIAGE),--triage "$(TRIAGE)") \
	  $(if $(RUNNER_OUTPUT),--runner-output "$(RUNNER_OUTPUT)") \
	  $(if $(LEDGER),--ledger "$(LEDGER)") \
	  $(if $(AUTO_NEGATIVE),--auto-negative) \
	  $(if $(DRY_RUN),--dry-run)

fp-verdict-capture-test:
	@python3 -m unittest tools.tests.test_fp_verdict_capture -v
# Lane W5-A3: run the universal FP runner against the known-clean
# calibration corpus (released OZ/Solady/Solmate library source) and seed
# the FP verdict ledger with one FP row per hit. Gives the W4.7 feedback
# loop real day-one FP-rate data per FP shape. CORPUS=, LEDGER=, OUT=,
# NO_APPEND=1, DEDUPE_PRUNE=1, STRICT=1, MAX_CLEAN_HITS=N all optional.
fp-calibration-clean-corpus: ## Lane W5-A3: seed FP verdict ledger from the known-clean library corpus.
	@python3 tools/audit/fp-calibration-clean-corpus.py \
	  $(if $(CORPUS),--corpus "$(CORPUS)") \
	  $(if $(LEDGER),--ledger "$(LEDGER)") \
	  $(if $(OUT),--output "$(OUT)") \
	  $(if $(NO_APPEND),--no-append) \
	  $(if $(DEDUPE_PRUNE),--dedupe-prune) \
	  $(if $(STRICT),--strict) \
	  $(if $(MAX_CLEAN_HITS),--max-clean-hits "$(MAX_CLEAN_HITS)")

fp-calibration-clean-corpus-test:
	@python3 -m unittest tools.tests.test_fp_calibration_clean_corpus -v

# Lane W4.11 YELLOW gap closure: corpus record tier stratification. Scans
# hackerman YAML records and reports the Rule 37 verification-tier
# distribution. Wires tools/hackerman-stratify-verification-tier.py.
.PHONY: tier-stratify tier-stratify-test
tier-stratify: ## Rule 37: stratify hackerman corpus records by verification tier. TAGS_DIR=<dir>, OUT=<jsonl>, LIMIT=<n>, DRY_RUN=1 optional.
	@python3 tools/hackerman-stratify-verification-tier.py \
	  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \
	  $(if $(OUT),--output "$(OUT)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(DRY_RUN),--dry-run,--write)

tier-stratify-test:
	@python3 -m unittest tools.tests.test_hackerman_stratify_verification_tier -v

# Lane W4.11: capability-readiness dashboard. Single view of "what can this
# toolchain do right now, and is it wired in" - GREEN/YELLOW/RED per
# capability across exists / wired / tested / exercised axes.
.PHONY: capability-readiness capability-readiness-test
capability-readiness: ## Lane W4.11: GREEN/YELLOW/RED capability-readiness dashboard. JSON=1 emits JSON; OUT=<path>/MD_OUT=<path> write to file; STRICT=1 exits non-zero on any RED.
	@python3 tools/audit/capability-readiness-dashboard.py \
	  $(if $(JSON),--json) \
	  $(if $(OUT),--output "$(OUT)") \
	  $(if $(MD_OUT),--markdown-output "$(MD_OUT)") \
	  $(if $(STRICT),--strict)

capability-readiness-test:
	@python3 -m unittest tools.tests.test_capability_readiness_dashboard -v

# ---------------------------------------------------------------------------
# DeepSeek monitoring dashboard (lane DEEPSEEK-MONITORING, 2026-05-26).
# Real-time spend + budget alerts + verification_tier gate.
# Inputs:
#   WS=<workspace>                       (default: ROOT)
#   SINCE="1h|1d|1w|2026-05-26"          (default 1d)
#   PROVIDER=all|deepseek|deepseek-flash|deepseek-pro  (default all)
#   TASK_TYPE=all|TOK-A|TOK-B|TOK-C|TOK-D|TOK-F|OTHER   (default all)
#   CAP_USD=<float>                      (default 100)
#   ALERT_USD=<float>                    (default 80)
#   WATCH=1                              poll loop every WATCH_INTERVAL secs
#   WATCH_INTERVAL=<n>                   (default 5)
#   JSON=1                               JSON output instead of markdown
.PHONY: deepseek-monitor deepseek-monitor-test
deepseek-monitor: ## Real-time DeepSeek spend dashboard + budget alerts + anomaly detection. See tools/deepseek-monitor.py.
	@python3 tools/deepseek-monitor.py \
	  --workspace "$(or $(WS),$(CURDIR))" \
	  --since "$(or $(SINCE),1d)" \
	  --provider "$(or $(PROVIDER),all)" \
	  --task-type "$(or $(TASK_TYPE),all)" \
	  --cap-usd "$(or $(CAP_USD),100)" \
	  --alert-threshold-usd "$(or $(ALERT_USD),80)" \
	  $(if $(WATCH),--watch --watch-interval $(or $(WATCH_INTERVAL),5)) \
	  $(if $(JSON),--json)

deepseek-monitor-test:
	@python3 -m unittest tools.tests.test_deepseek_monitor -v

# ---------------------------------------------------------------------------
# DeepSeek batch generators (lane DEEPSEEK-BATCH-GEN, 2026-05-26).
# Per-task generators that convert canonical sources into JSONL batches
# for tools/llm-fanout-dispatcher.py. Conservative top-5 default.
.PHONY: deepseek-batch-tok-a deepseek-batch-tok-b deepseek-batch-tok-c \
        deepseek-batch-tok-d deepseek-batch-tok-g deepseek-batch \
        deepseek-batch-gen-test

deepseek-batch-tok-a: ## TOK-A rationale-mining batch (corpus_mined slices -> DeepSeek JSONL).
	@python3 tools/deepseek-batch-gen-tok-a.py \
	  --source "$(or $(SOURCE),reference/corpus_mined)" \
	  --workspace "$(or $(WS),$(CURDIR))" \
	  $(if $(OUT_DIR),--output-dir "$(OUT_DIR)") \
	  --max-batch-size "$(or $(MAX_BATCH_SIZE),50)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

deepseek-batch-tok-b: ## TOK-B invariant-lift batch (invariants_pilot.jsonl -> DeepSeek JSONL). TARGET_LANG=rust|solidity|go|move|any.
	@python3 tools/deepseek-batch-gen-tok-b.py \
	  --source "$(or $(SOURCE),audit/corpus_tags/derived/invariants_pilot.jsonl)" \
	  --workspace "$(or $(WS),$(CURDIR))" \
	  $(if $(OUT_DIR),--output-dir "$(OUT_DIR)") \
	  --target-lang "$(or $(TARGET_LANG),rust)" \
	  --max-batch-size "$(or $(MAX_BATCH_SIZE),50)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

deepseek-batch-tok-c: ## TOK-C hypothesis-gen batch (attack_class_taxonomy.json -> DeepSeek JSONL). MIN_RECORDS=<N> filters orphans.
	@python3 tools/deepseek-batch-gen-tok-c.py \
	  --source "$(or $(SOURCE),audit/corpus_tags/derived/attack_class_taxonomy.json)" \
	  --workspace "$(or $(WS),$(CURDIR))" \
	  $(if $(OUT_DIR),--output-dir "$(OUT_DIR)") \
	  --min-records "$(or $(MIN_RECORDS),20)" \
	  --max-batch-size "$(or $(MAX_BATCH_SIZE),50)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

deepseek-batch-tok-d: ## TOK-D adversarial-persona batch (attacker_frames/*.yaml -> DeepSeek JSONL).
	@python3 tools/deepseek-batch-gen-tok-d.py \
	  --source "$(or $(SOURCE),reference/attacker_frames)" \
	  --workspace "$(or $(WS),$(CURDIR))" \
	  $(if $(OUT_DIR),--output-dir "$(OUT_DIR)") \
	  --max-batch-size "$(or $(MAX_BATCH_SIZE),50)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

deepseek-batch-tok-g: ## TOK-G anti-pattern-expand batch (anti_patterns.md -> DeepSeek JSONL).
	@python3 tools/deepseek-batch-gen-tok-g.py \
	  --source "$(or $(SOURCE),reference/anti_patterns.md)" \
	  --workspace "$(or $(WS),$(CURDIR))" \
	  $(if $(OUT_DIR),--output-dir "$(OUT_DIR)") \
	  --max-batch-size "$(or $(MAX_BATCH_SIZE),50)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

deepseek-batch: ## Run all 5 batch generators in sequence (TOK-A/B/C/D/G).
	@$(MAKE) --no-print-directory deepseek-batch-tok-a
	@$(MAKE) --no-print-directory deepseek-batch-tok-b
	@$(MAKE) --no-print-directory deepseek-batch-tok-c
	@$(MAKE) --no-print-directory deepseek-batch-tok-d
	@$(MAKE) --no-print-directory deepseek-batch-tok-g

deepseek-batch-gen-test: ## DEEPSEEK-BATCH-GEN: 45 unittest cases across 5 generators.
	@python3 -m unittest \
	  tools.tests.test_deepseek_batch_gen_tok_a \
	  tools.tests.test_deepseek_batch_gen_tok_b \
	  tools.tests.test_deepseek_batch_gen_tok_c \
	  tools.tests.test_deepseek_batch_gen_tok_d \
	  tools.tests.test_deepseek_batch_gen_tok_g -v

# ---------------------------------------------------------------------------
# Wave-4 P0 W4.2: post-mortem ETL miner.
#
# Sources: rekt | defillama | samczsun | pcaversaccio | hackmd.
# Env knobs:
#   SOURCE=<name>        (required) one of the SUPPORTED_SOURCES.
#   URL=<single-url>     single-page mode (overrides URL_LIST).
#   URL_LIST=<path>      batch URL list (one per line).
#   INDEX_URL=<url>      override the source's default index URL.
#   OUT_DIR=<path>       output dir (default audit/corpus_tags/tags/post_mortem).
#   CACHE_DIR=<path>     web cache dir (default cache/post-mortem).
#   APPLY=1              write records (default: --dry-run).
#   FETCH=1              allow live network (default: offline).
#   MAX_PAGES=<n>        cap records-emitted per run.
#   JSON=1               emit --json-summary.
.PHONY: hackerman-etl-post-mortem hackerman-etl-post-mortem-test
hackerman-etl-post-mortem: ## Wave-4 W4.2: mine post-mortems into tier-2 records
	@if [ -z "$(SOURCE)" ]; then \
	  echo "[hackerman-etl-post-mortem] ERROR: SOURCE=<name> required (rekt|defillama|samczsun|pcaversaccio|hackmd)" >&2; \
	  exit 2; \
	fi
	@out_dir="$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/post_mortem)"; \
	cache_dir="$(if $(CACHE_DIR),$(CACHE_DIR),cache/post-mortem)"; \
	mkdir -p "$$out_dir" "$$cache_dir"; \
	echo "[hackerman-etl-post-mortem] source=$(SOURCE) out_dir=$$out_dir cache_dir=$$cache_dir mode=$(if $(APPLY),APPLY,dry-run) fetch=$(if $(FETCH),1,0)"; \
	python3 tools/hackerman-etl-from-post-mortem.py \
	  --source $(SOURCE) \
	  --out-dir "$$out_dir" \
	  --cache-dir "$$cache_dir" \
	  $(if $(APPLY),,--dry-run) \
	  $(if $(URL),--url $(URL)) \
	  $(if $(URL_LIST),--url-list $(URL_LIST)) \
	  $(if $(INDEX_URL),--index-url $(INDEX_URL)) \
	  $(if $(MAX_PAGES),--max-pages $(MAX_PAGES)) \
	  $(if $(JSON),--json-summary) \
	  $(if $(FETCH),--fetch)

hackerman-etl-post-mortem-test:
	@python3 -m unittest tools.tests.test_hackerman_etl_from_post_mortem -v

# ─── Wave-4 P0 W4.1 ───────────────────────────────────────────────────────
# Real-time CVE/GHSA delta watcher (Wave-4 capability roadmap, commit
# 91ed239131). Polls NVD + GitHub Security Advisories REST endpoints,
# scope-filters against audit/corpus_scope_keywords.txt, and emits
# hackerman_record v1.1 YAML with verification_tier =
# tier-1-officially-disclosed. Live mode requires ALLOW_LIVE=1.
.PHONY: hackerman-cve-ghsa-delta-watch hackerman-cve-ghsa-delta-watch-test
hackerman-cve-ghsa-delta-watch: ## Wave-4 W4.1: poll NVD/GHSA, emit tier-1 delta records
	@since="$(if $(SINCE_ISO),$(SINCE_ISO),)"; \
	until="$(if $(UNTIL_ISO),$(UNTIL_ISO),)"; \
	src="$(if $(SOURCE),$(SOURCE),both)"; \
	out="$(if $(OUT_DIR),$(OUT_DIR),audit/corpus_tags/tags/cve_ghsa_delta_watcher)"; \
	dry="$(if $(APPLY),,--dry-run)"; \
	live="$(if $(ALLOW_LIVE),--allow-live,)"; \
	respect="$(if $(RESPECT_RATE_LIMIT),--respect-rate-limit,)"; \
	max_flag="$(if $(MAX_RESULTS),--max-results $(MAX_RESULTS),)"; \
	since_flag="$$( [ -n "$$since" ] && echo --since-iso "$$since" )"; \
	until_flag="$$( [ -n "$$until" ] && echo --until-iso "$$until" )"; \
	echo "[hackerman-cve-ghsa-delta-watch] source=$$src dry=$(if $(APPLY),no,yes) live=$(if $(ALLOW_LIVE),yes,no) out=$$out"; \
	python3 tools/hackerman-cve-ghsa-delta-watcher.py \
	  --source "$$src" \
	  --out-dir "$$out" \
	  $$dry $$live $$respect $$max_flag $$since_flag $$until_flag \
	  --json-summary

hackerman-cve-ghsa-delta-watch-test:
	@python3 -m unittest tools.tests.test_hackerman_cve_ghsa_delta_watcher -v

# ─── Wave-16: Detector FP shape lint (wired by wave-16 agent 4) ────────────
# Advisory run: emits JSON report of over-broad FP shapes; always exits 0.
# Strict gate: exits non-zero if any flags found; opt-in only because 40
# pre-existing detectors are flagged (wave-15 worklist); run after triage.
.PHONY: detector-fp-shape-lint detector-fp-shape-lint-strict
detector-fp-shape-lint: ## Wave-16: advisory FP shape lint - emit JSON report (always exits 0)
	@mkdir -p reports
	@python3 tools/detector-fp-shape-lint.py --json > reports/detector_fp_shape_lint_latest.json; \
	  flags=$$(python3 -c "import json,sys; d=json.load(open('reports/detector_fp_shape_lint_latest.json')); print(d.get('total_flags',0))" 2>/dev/null || echo '?'); \
	  echo "[detector-fp-shape-lint] advisory scan complete - flags=$$flags (see reports/detector_fp_shape_lint_latest.json)"

detector-fp-shape-lint-strict: ## Wave-16: strict FP shape lint gate - exits non-zero on any flags (opt-in)
	@python3 tools/detector-fp-shape-lint.py --strict --json

# --- R43: Load-Bearing Bytes Attribution check --------------------------------
.PHONY: r43-check r43-check-all
r43-check: ## R43: Check one draft for Load-Bearing Bytes Attribution section
	@if [ -z "$(DRAFT)" ]; then echo 'Usage: make r43-check WS=<workspace> DRAFT=<path/to/draft.md> [SEVERITY=Medium]'; exit 2; fi
	@python3 tools/load-bearing-bytes-attribution-check.py "$(DRAFT)" \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r43-check-all: ## R43: Run check over all staging + paste_ready drafts in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r43-check-all WS=<workspace>'; exit 2; fi
	@found=0; fails=0; \
	for dir in "$(WS)/submissions/staging" "$(WS)/submissions/paste_ready"; do \
	  [ -d "$$dir" ] || continue; \
	  for draft in "$$dir"/**/*.md "$$dir"/*.md; do \
	    [ -f "$$draft" ] || continue; \
	    found=$$((found + 1)); \
	    echo "[r43-check-all] $$draft"; \
	    python3 tools/load-bearing-bytes-attribution-check.py "$$draft" --strict --json || fails=$$((fails + 1)); \
	  done; \
	done; \
	echo "[r43-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

# --- R44: Opposed-Trace Actor Separation check --------------------------------
.PHONY: r44-check r44-check-all
r44-check: ## R44: Check a single PoC dir/file for actor separation assertions
	@if [ -z "$(POC)" ]; then echo 'Usage: make r44-check WS=<workspace> POC=<path/to/poc-dir-or-file> [SEVERITY=High]'; exit 2; fi
	@python3 tools/opposed-trace-actor-separation-check.py "$(POC)" \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r44-check-all: ## R44: Run check over all poc-tests dirs in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r44-check-all WS=<workspace>'; exit 2; fi
	@found=0; fails=0; \
	poc_base="$(WS)/poc-tests"; \
	if [ ! -d "$$poc_base" ]; then echo "[r44-check-all] no poc-tests dir at $$poc_base; skipping"; exit 0; fi; \
	for pocdir in "$$poc_base"/*/; do \
	  [ -d "$$pocdir" ] || continue; \
	  found=$$((found + 1)); \
	  echo "[r44-check-all] $$pocdir"; \
	  python3 tools/opposed-trace-actor-separation-check.py "$$pocdir" --strict --json || fails=$$((fails + 1)); \
	done; \
	echo "[r44-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

# --- R45: Designed-As-Intended Precheck --------------------------------------
.PHONY: r45-check r45-check-all
r45-check: ## R45: Check one HIGH+ draft for designed-as-intended omission (Check #93)
	@if [ -z "$(DRAFT)" ]; then echo 'Usage: make r45-check WS=<workspace> DRAFT=<path/to/draft.md> [SEVERITY=High]'; exit 2; fi
	@if [ ! -f tools/designed-as-intended-precheck.py ]; then \
	  echo '[r45-check] WARN: tools/designed-as-intended-precheck.py not found - tool absent (proposal only)'; exit 1; fi
	@python3 tools/designed-as-intended-precheck.py "$(DRAFT)" \
	  --workspace "$(WS)" \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r45-check-all: ## R45: Run Check #93 over all staging + paste_ready drafts in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r45-check-all WS=<workspace>'; exit 2; fi
	@if [ ! -f tools/designed-as-intended-precheck.py ]; then \
	  echo '[r45-check-all] WARN: tools/designed-as-intended-precheck.py not found - tool absent (proposal only)'; exit 1; fi
	@found=0; fails=0; \
	for dir in "$(WS)/submissions/staging" "$(WS)/submissions/paste_ready"; do \
	  [ -d "$$dir" ] || continue; \
	  for draft in "$$dir"/**/*.md "$$dir"/*.md; do \
	    [ -f "$$draft" ] || continue; \
	    found=$$((found + 1)); \
	    echo "[r45-check-all] $$draft"; \
	    python3 tools/designed-as-intended-precheck.py "$$draft" \
	      --workspace "$(WS)" --strict --json || fails=$$((fails + 1)); \
	  done; \
	done; \
	echo "[r45-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

# --- R29: Commitment-vs-Validation-Gap check ----------------------------------
.PHONY: r29-check r29-check-all
r29-check: ## R29: Check one HIGH+ draft for Commitment & Protection Analysis (Check #94)
	@if [ -z "$(DRAFT)" ]; then echo 'Usage: make r29-check WS=<workspace> DRAFT=<path/to/draft.md> [SEVERITY=High]'; exit 2; fi
	@if [ ! -f tools/commitment-vs-validation-check.py ]; then \
	  echo '[r29-check] WARN: tools/commitment-vs-validation-check.py not found - tool absent (proposal only)'; exit 1; fi
	@python3 tools/commitment-vs-validation-check.py "$(DRAFT)" \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r29-check-all: ## R29: Run Check #94 over all staging + paste_ready drafts in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r29-check-all WS=<workspace>'; exit 2; fi
	@if [ ! -f tools/commitment-vs-validation-check.py ]; then \
	  echo '[r29-check-all] WARN: tools/commitment-vs-validation-check.py not found - tool absent (proposal only)'; exit 1; fi
	@found=0; fails=0; \
	for dir in "$(WS)/submissions/staging" "$(WS)/submissions/paste_ready"; do \
	  [ -d "$$dir" ] || continue; \
	  for draft in "$$dir"/**/*.md "$$dir"/*.md; do \
	    [ -f "$$draft" ] || continue; \
	    found=$$((found + 1)); \
	    echo "[r29-check-all] $$draft"; \
	    python3 tools/commitment-vs-validation-check.py "$$draft" \
	      --strict --json || fails=$$((fails + 1)); \
	  done; \
	done; \
	echo "[r29-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

# --- R46: Trusted-Infrastructure-Compromise check -----------------------------
.PHONY: r46-check r46-check-all
r46-check: ## R46: Check one HIGH+ draft for trusted-infra compromise precondition (Check #95)
	@if [ -z "$(DRAFT)" ]; then echo 'Usage: make r46-check WS=<workspace> DRAFT=<path/to/draft.md> [SEVERITY=High]'; exit 2; fi
	@if [ ! -f tools/trusted-infrastructure-compromise-check.py ]; then \
	  echo '[r46-check] WARN: tools/trusted-infrastructure-compromise-check.py not found - tool absent (proposal only)'; exit 1; fi
	@python3 tools/trusted-infrastructure-compromise-check.py "$(DRAFT)" \
	  --workspace "$(WS)" \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r46-check-all: ## R46: Run Check #95 over all staging + paste_ready drafts in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r46-check-all WS=<workspace>'; exit 2; fi
	@if [ ! -f tools/trusted-infrastructure-compromise-check.py ]; then \
	  echo '[r46-check-all] WARN: tools/trusted-infrastructure-compromise-check.py not found - tool absent (proposal only)'; exit 1; fi
	@found=0; fails=0; \
	for dir in "$(WS)/submissions/staging" "$(WS)/submissions/paste_ready"; do \
	  [ -d "$$dir" ] || continue; \
	  for draft in "$$dir"/**/*.md "$$dir"/*.md; do \
	    [ -f "$$draft" ] || continue; \
	    found=$$((found + 1)); \
	    echo "[r46-check-all] $$draft"; \
	    python3 tools/trusted-infrastructure-compromise-check.py "$$draft" \
	      --workspace "$(WS)" --strict --json || fails=$$((fails + 1)); \
	  done; \
	done; \
	echo "[r46-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

# --- R47: Acknowledged-Wont-Fix check -----------------------------------------
.PHONY: r47-check r47-check-all
r47-check: ## R47: Check one HIGH+ draft for acknowledged-wont-fix status (Check #96)
	@if [ -z "$(DRAFT)" ]; then echo 'Usage: make r47-check WS=<workspace> DRAFT=<path/to/draft.md> [SEVERITY=High]'; exit 2; fi
	@if [ ! -f tools/acknowledged-wont-fix-check.py ]; then \
	  echo '[r47-check] WARN: tools/acknowledged-wont-fix-check.py not found - tool absent (proposal only)'; exit 1; fi
	@python3 tools/acknowledged-wont-fix-check.py "$(DRAFT)" \
	  --workspace "$(WS)" \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r47-check-all: ## R47: Run Check #96 over all staging + paste_ready drafts in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r47-check-all WS=<workspace>'; exit 2; fi
	@if [ ! -f tools/acknowledged-wont-fix-check.py ]; then \
	  echo '[r47-check-all] WARN: tools/acknowledged-wont-fix-check.py not found - tool absent (proposal only)'; exit 1; fi
	@found=0; fails=0; \
	for dir in "$(WS)/submissions/staging" "$(WS)/submissions/paste_ready"; do \
	  [ -d "$$dir" ] || continue; \
	  for draft in "$$dir"/**/*.md "$$dir"/*.md; do \
	    [ -f "$$draft" ] || continue; \
	    found=$$((found + 1)); \
	    echo "[r47-check-all] $$draft"; \
	    python3 tools/acknowledged-wont-fix-check.py "$$draft" \
	      --workspace "$(WS)" --strict --json || fails=$$((fails + 1)); \
	  done; \
	done; \
	echo "[r47-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

# --- R52: Rubric-Row-Coverage check -------------------------------------------
.PHONY: r52-check r52-check-all
r52-check: ## R52: Check one draft for verbatim rubric row coverage (Check #97)
	@if [ -z "$(DRAFT)" ]; then echo 'Usage: make r52-check WS=<workspace> DRAFT=<path/to/draft.md> [SEVERITY=Medium]'; exit 2; fi
	@if [ ! -f tools/rubric-row-coverage-check.py ]; then \
	  echo '[r52-check] WARN: tools/rubric-row-coverage-check.py not found - tool absent (proposal only)'; exit 1; fi
	@python3 tools/rubric-row-coverage-check.py "$(DRAFT)" \
	  --workspace "$(WS)" \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r52-check-all: ## R52: Run Check #97 over all staging + paste_ready drafts in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r52-check-all WS=<workspace>'; exit 2; fi
	@if [ ! -f tools/rubric-row-coverage-check.py ]; then \
	  echo '[r52-check-all] WARN: tools/rubric-row-coverage-check.py not found - tool absent (proposal only)'; exit 1; fi
	@found=0; fails=0; \
	for dir in "$(WS)/submissions/staging" "$(WS)/submissions/paste_ready"; do \
	  [ -d "$$dir" ] || continue; \
	  for draft in "$$dir"/**/*.md "$$dir"/*.md; do \
	    [ -f "$$draft" ] || continue; \
	    found=$$((found + 1)); \
	    echo "[r52-check-all] $$draft"; \
	    python3 tools/rubric-row-coverage-check.py "$$draft" \
	      --workspace "$(WS)" --strict --json || fails=$$((fails + 1)); \
	  done; \
	done; \
	echo "[r52-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

.PHONY: r48-check r48-check-all
r48-check: ## R48: Check one HIGH+ draft for deployment-topology restriction (Check #98)
	@if [ -z "$(DRAFT)" ]; then echo 'Usage: make r48-check WS=<workspace> DRAFT=<path/to/draft.md> [SEVERITY=High]'; exit 2; fi
	@if [ ! -f tools/deployment-topology-vs-attack-surface-check.py ]; then \
	  echo '[r48-check] WARN: tools/deployment-topology-vs-attack-surface-check.py not found'; exit 1; fi
	@python3 tools/deployment-topology-vs-attack-surface-check.py "$(DRAFT)" \
	  --workspace "$(WS)" \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r48-check-all: ## R48: Run Check #98 over all staging + paste_ready HIGH+ drafts in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r48-check-all WS=<workspace>'; exit 2; fi
	@if [ ! -f tools/deployment-topology-vs-attack-surface-check.py ]; then \
	  echo '[r48-check-all] WARN: tools/deployment-topology-vs-attack-surface-check.py not found'; exit 1; fi
	@found=0; fails=0; \
	for dir in "$(WS)/submissions/staging" "$(WS)/submissions/paste_ready"; do \
	  [ -d "$$dir" ] || continue; \
	  for draft in "$$dir"/**/*.md "$$dir"/*.md; do \
	    [ -f "$$draft" ] || continue; \
	    found=$$((found + 1)); \
	    echo "[r48-check-all] $$draft"; \
	    python3 tools/deployment-topology-vs-attack-surface-check.py "$$draft" \
	      --workspace "$(WS)" --strict --json || fails=$$((fails + 1)); \
	  done; \
	done; \
	echo "[r48-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

.PHONY: r53-check r53-check-all
r53-check: ## R53: Check one HIGH+ draft for prior-audit finding supersede (Check #99)
	@if [ -z "$(DRAFT)" ]; then echo 'Usage: make r53-check WS=<workspace> DRAFT=<path/to/draft.md> [SEVERITY=High]'; exit 2; fi
	@if [ ! -f tools/prior-audit-finding-supersede-check.py ]; then \
	  echo '[r53-check] WARN: tools/prior-audit-finding-supersede-check.py not found'; exit 1; fi
	@python3 tools/prior-audit-finding-supersede-check.py "$(DRAFT)" \
	  --workspace "$(WS)" \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r53-check-all: ## R53: Run Check #99 over all staging + paste_ready HIGH+ drafts in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r53-check-all WS=<workspace>'; exit 2; fi
	@if [ ! -f tools/prior-audit-finding-supersede-check.py ]; then \
	  echo '[r53-check-all] WARN: tools/prior-audit-finding-supersede-check.py not found'; exit 1; fi
	@found=0; fails=0; \
	for dir in "$(WS)/submissions/staging" "$(WS)/submissions/paste_ready"; do \
	  [ -d "$$dir" ] || continue; \
	  for draft in "$$dir"/**/*.md "$$dir"/*.md; do \
	    [ -f "$$draft" ] || continue; \
	    found=$$((found + 1)); \
	    echo "[r53-check-all] $$draft"; \
	    python3 tools/prior-audit-finding-supersede-check.py "$$draft" \
	      --workspace "$(WS)" --strict --json || fails=$$((fails + 1)); \
	  done; \
	done; \
	echo "[r53-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

# --- R28: Multi-path-escalation-merge check ---------------------------------
.PHONY: r28-check r28-check-all
r28-check: ## R28: Check one HIGH+ draft for multi-path escalation merge (Check #100)
	@if [ -z "$(DRAFT)" ]; then echo 'Usage: make r28-check WS=<workspace> DRAFT=<path/to/draft.md> [SEVERITY=High]'; exit 2; fi
	@if [ ! -f tools/multi-path-escalation-merge-check.py ]; then \
	  echo '[r28-check] WARN: tools/multi-path-escalation-merge-check.py not found - tool absent (proposal only)'; exit 1; fi
	@python3 tools/multi-path-escalation-merge-check.py "$(DRAFT)" \
	  $(if $(WS),--workspace "$(WS)",) \
	  --strict --json \
	  $(if $(SEVERITY),--severity $(SEVERITY),)

r28-check-all: ## R28: Run Check #100 over all staging + paste_ready drafts in WS
	@if [ -z "$(WS)" ]; then echo 'Usage: make r28-check-all WS=<workspace>'; exit 2; fi
	@if [ ! -f tools/multi-path-escalation-merge-check.py ]; then \
	  echo '[r28-check-all] WARN: tools/multi-path-escalation-merge-check.py not found - tool absent (proposal only)'; exit 1; fi
	@found=0; fails=0; \
	for dir in "$(WS)/submissions/staging" "$(WS)/submissions/paste_ready"; do \
	  [ -d "$$dir" ] || continue; \
	  for draft in "$$dir"/**/*.md "$$dir"/*.md; do \
	    [ -f "$$draft" ] || continue; \
	    found=$$((found + 1)); \
	    echo "[r28-check-all] $$draft"; \
	    python3 tools/multi-path-escalation-merge-check.py "$$draft" \
	      --workspace "$(WS)" --strict --json || fails=$$((fails + 1)); \
	  done; \
	done; \
	echo "[r28-check-all] done: found=$$found fails=$$fails"; \
	[ "$$fails" -eq 0 ]

# --- Agent briefs refresh + R39 coverage ------------------------------------
.PHONY: refresh-agent-briefs briefs-r39-coverage-check
refresh-agent-briefs: ## Freshness audit + selective regeneration for agent_briefs/
	@if [ ! -f tools/agent-briefs-refresh.py ]; then \
	  echo '[refresh-agent-briefs] WARN: tools/agent-briefs-refresh.py not found'; exit 1; fi
	@python3 tools/agent-briefs-refresh.py \
	  $(if $(WS),--workspace "$(WS)",) \
	  $(if $(BRIEFS_DIR),--briefs-dir "$(BRIEFS_DIR)",) \
	  $(if $(FRESH_SKIP_DAYS),--fresh-skip-days $(FRESH_SKIP_DAYS),) \
	  $(if $(WARN_DAYS),--warn-days $(WARN_DAYS),) \
	  $(if $(FAIL_DAYS),--fail-days $(FAIL_DAYS),) \
	  $(if $(NO_REGENERATE),--no-regenerate,) \
	  $(if $(STRICT),--strict,) \
	  $(if $(JSON),--json,)

briefs-r39-coverage-check: ## R39: Walk agent_briefs/*.md and report attack_class anchor coverage
	@if [ ! -f tools/agent-briefs-r39-coverage-check.py ]; then \
	  echo '[briefs-r39-coverage-check] WARN: tools/agent-briefs-r39-coverage-check.py not found'; exit 1; fi
	@python3 tools/agent-briefs-r39-coverage-check.py \
	  $(if $(BRIEFS_DIR),--briefs-dir "$(BRIEFS_DIR)",) \
	  $(if $(VERBOSE),--verbose,) \
	  $(if $(STRICT),--strict,) \
	  $(if $(JSON),--json,)

# --- WIRE-1: hunt-tool wiring (Phase MINUS-1 lane-WIRE-1) -------------------
# Wires the 13 RESTORE-1 tools restored at b7c6ac7d5b into make targets so they
# actually GET USED. WF-10's "no caller in 60 days" measured wiring failure,
# not value failure. Each target below is dependency-free (tools live in
# tools/ already; just invoke). Cron + agent_briefs wiring documented in
# reports/v3_iter_2026-05-23_iter18_phase_minus_1/lane_WIRE_1/results.md.
.PHONY: pattern-migration-alert pattern-migration-alert-test \
        refresh-corpus-clusters refresh-corpus-clusters-status \
        scan-report-thicken \
        boost-classifier digest-to-patterns \
        reactivate-graveyard reactivate-graveyard-dry \
        glider-transpile-all \
        forge-test detector-detect detector-wizard

pattern-migration-alert: ## WIRE-1: cross-engagement PAID-finding match alerter (P5)
	@if [ ! -f tools/pattern-migration-alert.py ]; then \
	  echo '[pattern-migration-alert] WARN: tools/pattern-migration-alert.py not found'; exit 1; fi
	@mkdir -p "$(if $(WS),$(_WS_RESOLVED),$(HOME)/audits)/.auditooor" 2>/dev/null || true
	@python3 tools/pattern-migration-alert.py \
	  $(if $(AUDITS_DIR),--audits-dir "$(AUDITS_DIR)",--audits-dir "$(HOME)/audits") \
	  $(if $(MIN_SCORE),--min-score $(MIN_SCORE)) \
	  $(if $(OUT),--out "$(OUT)",--out "$(HOME)/audits/.auditooor/pattern_migration_alerts.md") \
	  $(if $(JSON),--json)

refresh-corpus-clusters: ## WIRE-1: weekly Solodit corpus embed + cluster refresh (P1)
	@if [ ! -f tools/cluster-corpus.py ]; then \
	  echo '[refresh-corpus-clusters] WARN: tools/cluster-corpus.py not found'; exit 1; fi
	@python3 tools/cluster-corpus.py --embed --cluster

refresh-corpus-clusters-status: ## WIRE-1: report whether reference/solodit_clusters.yaml is >14d stale
	@if [ -f reference/solodit_clusters.yaml ]; then \
	  age_s=$$(( $$(date +%s) - $$(stat -f %m reference/solodit_clusters.yaml 2>/dev/null || stat -c %Y reference/solodit_clusters.yaml) )); \
	  age_d=$$((age_s / 86400)); \
	  echo "[refresh-corpus-clusters-status] reference/solodit_clusters.yaml age: $$age_d days"; \
	  if [ $$age_d -gt 14 ]; then \
	    echo "[refresh-corpus-clusters-status] WARN: cluster file is >14d stale; run 'make refresh-corpus-clusters'"; \
	  fi; \
	else \
	  echo "[refresh-corpus-clusters-status] reference/solodit_clusters.yaml NOT FOUND; run 'make refresh-corpus-clusters'"; \
	fi

scan-report-thicken: ## WIRE-1: enrich scan-hits log with classifier scores (P5)
	@if [ -z "$(LOG)" ]; then echo 'Usage: make scan-report-thicken LOG=<path/to/scan-hits.txt> [OUT=<path>]'; exit 2; fi
	@if [ ! -f tools/scan-report-thicken.py ]; then \
	  echo '[scan-report-thicken] WARN: tools/scan-report-thicken.py not found'; exit 1; fi
	@if [ -n "$(OUT)" ]; then \
	  python3 tools/scan-report-thicken.py "$(LOG)" > "$(OUT)"; \
	  echo "[scan-report-thicken] wrote $(OUT)"; \
	else \
	  python3 tools/scan-report-thicken.py "$(LOG)"; \
	fi

boost-classifier: ## WIRE-1: P4 training-data pipeline from Solodit corpus
	@if [ ! -f tools/boost-classifier-from-solodit.py ]; then \
	  echo '[boost-classifier] WARN: tools/boost-classifier-from-solodit.py not found'; exit 1; fi
	@python3 tools/boost-classifier-from-solodit.py \
	  $(if $(OUT),--out "$(OUT)",--out reference/triager_disposition_classifier.json)

digest-to-patterns: ## WIRE-1: extract canonical bug patterns from prior_audits/DIGEST_*.md (P1)
	@if [ -z "$(WS)" ]; then echo 'Usage: make digest-to-patterns WS=<workspace> [DRY_RUN=1] [SIMILARITY=0.45]'; exit 2; fi
	@if [ ! -f tools/digest-to-patterns.py ]; then \
	  echo '[digest-to-patterns] WARN: tools/digest-to-patterns.py not found'; exit 1; fi
	@python3 tools/digest-to-patterns.py "$(_WS_RESOLVED)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(SIMILARITY),--similarity $(SIMILARITY))

reactivate-graveyard: ## WIRE-1: apply R54 graveyard-audit verdicts (~75 detector recovery)
	@if [ ! -f tools/reactivate-graveyard.py ]; then \
	  echo '[reactivate-graveyard] WARN: tools/reactivate-graveyard.py not found'; exit 1; fi
	@python3 tools/reactivate-graveyard.py \
	  $(if $(INCLUDE_REWORK),--include-rework)

reactivate-graveyard-dry: ## WIRE-1: dry-run of reactivate-graveyard (no file writes)
	@if [ ! -f tools/reactivate-graveyard.py ]; then \
	  echo '[reactivate-graveyard-dry] WARN: tools/reactivate-graveyard.py not found'; exit 1; fi
	@python3 tools/reactivate-graveyard.py --dry-run \
	  $(if $(INCLUDE_REWORK),--include-rework)

glider-transpile-all: ## WIRE-1: P3 Glider->DSL transpile chain (3 tools sequenced)
	@if [ ! -f tools/glider-queries-to-dsl.py ]; then \
	  echo '[glider-transpile-all] WARN: tools/glider-queries-to-dsl.py not found'; exit 1; fi
	@echo "[glider-transpile-all] 1/3: glider-queries-to-dsl.py"
	@python3 tools/glider-queries-to-dsl.py $(if $(WRITE),--write) $(if $(LIMIT),--limit $(LIMIT))
	@echo "[glider-transpile-all] 2/3: glider-ast-to-detector.py"
	@python3 tools/glider-ast-to-detector.py || echo "[glider-transpile-all] WARN: glider-ast-to-detector returned non-zero"
	@echo "[glider-transpile-all] 3/3: glider-ast-to-specs.py"
	@python3 tools/glider-ast-to-specs.py
	@echo "[glider-transpile-all] done; output: detectors/_specs/drafts_glider* and reference/patterns.dsl/r76_glider/"

forge-test: ## WIRE-1: operator-friendly Foundry test runner wrapper
	@if [ -z "$(TEST)" ]; then echo 'Usage: make forge-test TEST=<path/to/Test.t.sol> [WS=<workspace>] [VERBOSE=1] [JSON=1] [NO_BUILD=1]'; exit 2; fi
	@if [ ! -f tools/forge-test-runner.py ]; then \
	  echo '[forge-test] WARN: tools/forge-test-runner.py not found'; exit 1; fi
	@python3 tools/forge-test-runner.py "$(TEST)" \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(VERBOSE),--verbose) \
	  $(if $(JSON),--json) \
	  $(if $(NO_BUILD),--no-build)

detector-detect: ## WIRE-1: one-command auto-detect language + run matching detectors
	@if [ -z "$(TARGET)" ]; then echo 'Usage: make detector-detect TARGET=<path/to/file.{rs,sol}|<dir>> [WAVE=rust_wave1|wave17] [DETECTOR=<stem>] [JSON=1]'; exit 2; fi
	@if [ ! -f tools/detector-auto-detect.py ]; then \
	  echo '[detector-detect] WARN: tools/detector-auto-detect.py not found'; exit 1; fi
	@python3 tools/detector-auto-detect.py "$(TARGET)" \
	  $(if $(WAVE),--wave $(WAVE)) \
	  $(if $(DETECTOR),--detector $(DETECTOR)) \
	  $(if $(JSON),--json)

detector-wizard: ## WIRE-1: scaffold all 4 artifacts for a new canonical bug class
	@if [ -z "$(CLASS)" ] || [ -z "$(FN_NAME_REGEX)" ] || [ -z "$(BAD_HINT)" ] || [ -z "$(SAFE_HINT)" ] || [ -z "$(SOURCE_URL)" ]; then \
	  echo 'Usage: make detector-wizard CLASS=<kebab-name> FN_NAME_REGEX=<regex> BAD_HINT=<text> SAFE_HINT=<text> SOURCE_URL=<url> [DRY_RUN=1]'; \
	  exit 2; fi
	@if [ ! -f tools/new-detector-wizard.py ]; then \
	  echo '[detector-wizard] WARN: tools/new-detector-wizard.py not found'; exit 1; fi
	@python3 tools/new-detector-wizard.py \
	  --class "$(CLASS)" \
	  --fn-name-regex "$(FN_NAME_REGEX)" \
	  --bad-hint "$(BAD_HINT)" \
	  --safe-hint "$(SAFE_HINT)" \
	  --source-url "$(SOURCE_URL)" \
	  $(if $(DRY_RUN),--dry-run)

# --- Rule Injection Sync ----------------------------------------------------
.PHONY: rule-sync rule-sync-check

rule-sync: ## Write all rule digest sync targets from ~/.claude/CLAUDE.md
	python3 tools/rule-injection-sync.py --sync

rule-sync-check: ## Validate rule digest sync targets are up-to-date (exit 1 if drift)
	python3 tools/rule-injection-sync.py --check

# ---------------------------------------------------------------------------
# CAPABILITY-GAP-6-SP1-BEEFY-PATCHES (2026-05-25): unblock cargo metadata
# for hyperbridge workspaces by stubbing the polytope-labs/sp1-beefy.git
# ssh:// dep. See docs/EXTERNAL_INTEL_REFRESH.md "Hyperbridge sp1-beefy
# patches" section. Implementation: tools/workspace-bootstrap.py
# --hyperbridge-patches. Tests: tools/tests/test_hyperbridge_workspace_patches.py.
# Block appended at end of Makefile to avoid R36 conflicts with parallel
# lanes editing the middle of the file.
# ---------------------------------------------------------------------------

.PHONY: hyperbridge-cargo-patch hyperbridge-cargo-patch-test

hyperbridge-cargo-patch: ## CAPABILITY-GAP-6: stub-and-rewrite the sp1-beefy ssh dep block (idempotent)
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make hyperbridge-cargo-patch WS=<workspace> [DRY_RUN=1]'; \
	  echo ''; \
	  echo 'CAPABILITY-GAP-6: stub-and-rewrite the polytope-labs/sp1-beefy.git ssh://'; \
	  echo 'dep in tesseract/consensus/beefy/zk/Cargo.toml so cargo metadata succeeds.'; \
	  echo ''; \
	  echo 'USE when: any cargo-based capability lane needs to read the hyperbridge'; \
	  echo '  dependency graph (predicate runner, dep-graph audit, etc).'; \
	  echo 'NO-OP when: workspace does not contain a hyperbridge tree (refuses exit 2).'; \
	  echo 'Idempotent: re-running on an already-patched workspace is a no-op.'; \
	  exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make hyperbridge-cargo-patch" "$(_WS_RESOLVED)"
	@python3 tools/workspace-bootstrap.py --hyperbridge-patches "$(_WS_RESOLVED)" $(if $(DRY_RUN),--dry-run)

hyperbridge-cargo-patch-test: ## CAPABILITY-GAP-6 unit tests (15 cases, offline)
	@python3 -m unittest tools.tests.test_hyperbridge_workspace_patches -v

# ---------------------------------------------------------------------------
# CAPABILITY-GAP-7-POC-TESTS-TAGGER (2026-05-25): write .poc-status
# sentinel files into each ~/audits/<ws>/poc-tests/<slug>/ dir so future
# agents and the operator can classify PoC retention without re-walking
# submissions/<status>/. Status enum: filed-evidence | engineering-record
# | dropped | superseded. Tests: tools/tests/test_poc_tests_tagger.py.
# Block appended at end of Makefile to avoid R36 conflicts with parallel
# lanes editing the middle of the file.
# ---------------------------------------------------------------------------

.PHONY: poc-tests-tag poc-tests-gc poc-tests-tagger-test

poc-tests-tag: ## CAPABILITY-GAP-7: classify every poc-tests/ dir and write .poc-status sentinels
	@if [ -z "$(WS)" ]; then \
		echo "error: WS=<workspace path> required (e.g. WS=~/audits/hyperbridge)" >&2; \
		exit 1; \
	fi
	@python3 tools/poc-tests-tagger.py --workspace "$(WS)" --auto-classify

poc-tests-gc: ## CAPABILITY-GAP-7: dry-run GC for poc-tests/ dirs tagged dropped + older-than (default 30d)
	@if [ -z "$(WS)" ]; then \
		echo "error: WS=<workspace path> required (e.g. WS=~/audits/hyperbridge)" >&2; \
		exit 1; \
	fi
	@python3 tools/poc-tests-tagger.py --workspace "$(WS)" --gc-dropped --older-than "$(or $(OLDER),30d)"

poc-tests-tagger-test: ## CAPABILITY-GAP-7 unit tests (24 cases, offline)
	@python3 -m unittest tools.tests.test_poc_tests_tagger -v

# ---------------------------------------------------------------------------
# Gap #52 hunt-lane emit handshake (codified 2026-05-26)
# Before a hunt-lane declares an exhaustion-class verdict (EXHAUSTED /
# NEGATIVE-CLOSED / DROP-CONFIRMED / NOT-SALVAGEABLE-CONFIRMED /
# KILLED-CONFIRMED), this target runs Check #109
# (exhaustion-verdict-tools-attempt-required-check.py) AND
# salvage-negation-verdict-check.py against the lane's results.md and
# refuses the emit with fail-lane-emit-gate-fail when either sub-check
# fails and no <!-- gap52-rebuttal: <reason> --> marker is present.
# ---------------------------------------------------------------------------
.PHONY: lane-emit lane-emit-test

lane-emit: ## Gap #52: hunt-lane emit handshake gate. RESULTS=<results.md>
	@if [ -z "$(RESULTS)" ]; then \
	  echo "Usage: make lane-emit RESULTS=<path/to/results.md> [WS=<workspace>] [STRICT=1]" >&2; \
	  echo "  Gap #52: hunt-lane emit handshake. Refuses emit on" >&2; \
	  echo "  exhaustion-class verdicts that fail Check #109 or the" >&2; \
	  echo "  salvage-negation-verdict-check." >&2; \
	  exit 2; \
	fi
	@PYTHONPATH=$(CURDIR) python3 tools/lane-integrator.py \
	  --lane-emit-handshake "$(RESULTS)" \
	  $(if $(WS),--lane-emit-handshake-workspace "$(WS)") \
	  $(if $(STRICT),--strict) \
	  --json

lane-emit-test: ## Gap #52 unit tests (lane-emit handshake)
	@PYTHONPATH=$(CURDIR) python3 -m unittest tools.tests.test_lane_emit_handshake -v

# ---------------------------------------------------------------------------
# Lane volume guard - mechanical no-over-flag check (codified 2026-06-13)
#
# Reads existing lane JSONL sidecars (never re-runs lanes) and enforces:
#   1. Verdict purity - no confirmed/proven/severity records in lane output.
#   2. Flood guard   - a lane emitting >threshold records is flagged FLOOD.
#
# rc=1 on any FAIL condition; rc=0 on clean pass.
# Usage: make lane-volume-guard [WS=<workspace>] [JSON=1]
#        If WS is unset the tool scans its default workspace set.
# ---------------------------------------------------------------------------
.PHONY: lane-volume-guard lane-volume-guard-test

lane-volume-guard: ## Mechanical no-over-flag check: lane floods -> rc=1. WS=<workspace> [JSON=1]
	@python3 tools/lane-volume-guard.py \
	  $(if $(WS),--workspace "$(WS)") \
	  $(if $(JSON),--json)

lane-volume-guard-test: ## Unit tests for lane-volume-guard (verdict purity + flood guard)
	@PYTHONPATH=$(CURDIR) python3 -m unittest tools.tests.test_lane_volume_guard -v

# ---------------------------------------------------------------------------
# DeepSeek ingest pipeline (lane DEEPSEEK-INGEST, codified 2026-05-26)
#
# Consumes per-task result JSON files emitted by llm-fanout-dispatcher.py
# and ingests them into the canonical corpus tree under
# audit/corpus_tags/derived/<subtree>/<batch-id>/ with schema validation +
# R37 verification_tier discipline + L34 v2 path-bucket safety.
#
# Usage:
#   make deepseek-ingest TASK=TOK-A DIR=<fanout-output-dir> \
#        [TARGET=<target-dir>] [WS=<workspace>] [BATCH=<batch-id>] [DRY=1] [STRICT=1]
# ---------------------------------------------------------------------------
.PHONY: deepseek-ingest deepseek-ingest-test

deepseek-ingest: ## Ingest DeepSeek fanout output into canonical corpus with schema + tier discipline. TASK= DIR= [TARGET=] [WS=] [BATCH=] [DRY=1] [STRICT=1]
	@if [ -z "$(TASK)" ] || [ -z "$(DIR)" ]; then \
	  echo "Usage: make deepseek-ingest TASK=<TOK-A|TOK-B|TOK-C|TOK-D|TOK-G> DIR=<fanout-out> [TARGET=<dir>] [WS=<ws>] [BATCH=<id>] [DRY=1] [STRICT=1]" >&2; \
	  echo "" >&2; \
	  echo "  Lane DEEPSEEK-INGEST (codified 2026-05-26): consumes per-task" >&2; \
	  echo "  result JSON files emitted by llm-fanout-dispatcher.py (was llm-fanout-dispatcher.py)" >&2; \
	  echo "  and emits schema-validated, tier-stamped YAML/JSON records" >&2; \
	  echo "  to audit/corpus_tags/derived/<subtree>/<batch-id>/." >&2; \
	  exit 2; \
	fi
	@python3 tools/deepseek-ingest-results.py \
	  --fanout-output-dir "$(DIR)" \
	  --task-type "$(TASK)" \
	  $(if $(TARGET),--target-dir "$(TARGET)") \
	  $(if $(WS),--workspace "$(WS)") \
	  $(if $(BATCH),--batch-id "$(BATCH)") \
	  $(if $(DRY),--dry-run) \
	  $(if $(STRICT),--strict) \
	  --json

deepseek-ingest-test: ## Lane DEEPSEEK-INGEST unit tests
	@PYTHONPATH=$(CURDIR) python3 -m unittest tools.tests.test_deepseek_ingest_results -v

# ---------------------------------------------------------------------------
# R65: model-routing-calibration-required-before-full-budget-spend
#
# Lane RULE-65-CALIBRATION (codified 2026-05-26). Two-step discipline for
# any budget > $1 LLM dispatch:
#
#   1. make deepseek-calibrate TASK=<TOK-X> [BUDGET=<usd>] [SAMPLE=10] [MOCK=1]
#      -> Runs paired-comparison sub-batch (Flash vs Pro), spawns a
#         Claude verifier sub-agent that scores outputs against the
#         per-task-class rubric, persists to
#         reference/deepseek_task_routing.json.
#
#   2. make deepseek-fire TASK=<TOK-X> [BUDGET=<usd>] [DRY=1]
#      -> Pre-checks the routing.json entry via deepseek-task-router.py
#         with --require-fresh-calibration. Refuses if missing/stale.
#         On pass, proceeds to the actual fanout dispatch.
#
# See docs/RULE_65_MODEL_ROUTING_CALIBRATION_2026-05-26.md.
# ---------------------------------------------------------------------------
.PHONY: deepseek-calibrate deepseek-calibrate-test deepseek-fire deepseek-router-test r65-rubrics-test

deepseek-calibrate: ## R65: run paired-comparison calibration for TASK=<TOK-X>. SAMPLE=10 MOCK=1 DRY=1
	@if [ -z "$(TASK)" ]; then \
	  echo "Usage: make deepseek-calibrate TASK=<TOK-X> [SAMPLE=10] [BUDGET=1] [MOCK=1] [DRY=1]" >&2; \
	  echo "" >&2; \
	  echo "  Lane RULE-65-CALIBRATION (codified 2026-05-26): runs a paired" >&2; \
	  echo "  sub-batch (Flash vs Pro), scores outputs 1-5 against the" >&2; \
	  echo "  per-task-class rubric, writes reference/deepseek_task_routing.json." >&2; \
	  echo "  Use MOCK=1 for offline canned-output mode." >&2; \
	  exit 2; \
	fi
	@python3 tools/deepseek-calibrate.py \
	  --task-id "$(TASK)" \
	  --sample-size $(or $(SAMPLE),10) \
	  --max-cost-usd $(or $(BUDGET),1.0) \
	  $(if $(MOCK),--mock) \
	  $(if $(DRY),--dry-run) \
	  --json

deepseek-fire: ## R65: gated full-budget dispatch. TASK=<TOK-X> BUDGET=<usd> [DRY=1]
	@if [ -z "$(TASK)" ]; then \
	  echo "Usage: make deepseek-fire TASK=<TOK-X> BUDGET=<usd> [DRY=1]" >&2; \
	  echo "" >&2; \
	  echo "  R65 gate: refuses dispatch when routing.json entry for TASK is" >&2; \
	  echo "  missing or stale (>90 days). Run 'make deepseek-calibrate TASK=X'" >&2; \
	  echo "  first, or set AUDITOOOR_R65_BYPASS=1 with explicit rationale." >&2; \
	  exit 2; \
	fi
	@python3 tools/deepseek-task-router.py \
	  --task-id "$(TASK)" \
	  --budget-usd $(or $(BUDGET),11.0) \
	  --require-fresh-calibration \
	  --json || { \
	    echo "" >&2; \
	    echo "  R65 router refused dispatch. Either:" >&2; \
	    echo "    (a) make deepseek-calibrate TASK=$(TASK) [MOCK=1] # bootstrap" >&2; \
	    echo "    (b) AUDITOOOR_R65_BYPASS=1 make deepseek-fire TASK=$(TASK) BUDGET=$(BUDGET)" >&2; \
	    exit 1; \
	  }
	@echo ""
	@echo "  R65 gate PASSED. (Actual fanout dispatch wired in a sibling target -"
	@echo "  this target is the R65 gate-only entry; full dispatch composes via"
	@echo "  tools/llm-fanout-dispatcher.py.)"

deepseek-calibrate-test: ## R65: unit tests for deepseek-calibrate.py
	@PYTHONPATH=$(CURDIR) python3 -m unittest tools.tests.test_deepseek_calibrate -v

deepseek-router-test: ## R65: unit tests for deepseek-task-router.py
	@PYTHONPATH=$(CURDIR) python3 -m unittest tools.tests.test_deepseek_task_router -v

r65-rubrics-test: ## R65: verify all per-task-class rubrics present + parseable
	@PYTHONPATH=$(CURDIR) python3 -m unittest tools.tests.test_deepseek_rubrics_present -v

# ============================================================================
# MIMO-build wave 2026-05-27: 7 new tools (3 capability-gap closers + 4 stubs)
# ============================================================================

r76-check: ## R76: scan a draft or MIMO sidecar dir for hallucinations
	@if [ -z "$(DRAFT)$(DIR)" ]; then \
	  echo "Usage: make r76-check DRAFT=<path.md> [WS=<ws>]" >&2; \
	  echo "  or:  make r76-check DIR=<mimo_sidecar_dir> [WS=<ws>]" >&2; \
	  exit 2; \
	fi
	@if [ -n "$(DIR)" ]; then \
	  python3 tools/r76-hallucination-guard.py --scan-mimo-dir "$(DIR)" $(if $(WS),--workspace $(WS)) $(if $(WRITE_FEEDBACK),--write-feedback) $(if $(STRICT_PROMOTION),--strict-promotion) --json; \
	else \
	  python3 tools/r76-hallucination-guard.py "$(DRAFT)" $(if $(WS),--workspace $(WS)) $(if $(STRICT_PROMOTION),--strict-promotion) --json; \
	fi

active-hunt-routing-check: ## PR2b: verify hunt/originality/backtest consumers route via the trusted-corpus resolver
	@python3 tools/trusted-corpus-consumer-check.py --json

coverage-heatmap: ## Per-contract MIMO hypothesis-density heatmap. WS=<workspace>
	@if [ -z "$(WS)" ]; then \
	  python3 tools/workspace-coverage-heatmap.py --all-workspaces --json; \
	else \
	  python3 tools/workspace-coverage-heatmap.py --workspace "$(WS)" --json; \
	fi

hacker-q-reweight: ## Auto-deprioritize high-NO-rate hacker questions; emit reweight ledger
	@python3 tools/hacker-q-reweighter.py --json --out audit/corpus_tags/derived/hacker_q_reweight_latest.jsonl

triage-kill-promote: ## Flow killed candidates -> reports/known_dead_ends.jsonl
	@if [ -n "$(DRY)" ]; then \
	  python3 tools/triage-kill-promoter.py --dry-run --json; \
	else \
	  python3 tools/triage-kill-promoter.py --json; \
	fi

fix-reach-spread: ## Auto-feed missing-guard-callsite enumeration from prior_audits/
	@if [ -z "$(WS)" ]; then \
	  echo "Usage: make fix-reach-spread WS=<workspace> [OUT=<path.jsonl>]" >&2; \
	  exit 2; \
	fi
	@python3 tools/fix-semantic-reach-spreader.py \
	  --workspace "$(WS)" \
	  --prior-audits-dir "$(WS)/prior_audits" \
	  --output $(or $(OUT),reports/fix_reach_audit_$(notdir $(WS))_$(shell date -u +%Y-%m-%d).jsonl) \
	  --json

invariant-synth: ## Synthesize per-function invariant candidates. WS=<workspace>
	@if [ -z "$(WS)" ]; then \
	  echo "Usage: make invariant-synth WS=<workspace> [OUT=<path.jsonl>]" >&2; \
	  exit 2; \
	fi
	@python3 tools/invariant-auto-synth.py \
	  --workspace "$(WS)" \
	  --output $(or $(OUT),reports/invariants_$(notdir $(WS))_$(shell date -u +%Y-%m-%d).jsonl) \
	  --json

per-fn-questions: ## Emit adversarial hacker questions from invariants. INV=<invariants.jsonl> [WS=<ws> feeds payable SEVERITY.md rows]
	@if [ -z "$(INV)" ]; then \
	  echo "Usage: make per-fn-questions INV=<invariants.jsonl> [OUT=<path.jsonl>] [WS=<ws>]" >&2; \
	  exit 2; \
	fi
	@# B3 PRECONDITION: gen_flow_seeded_questions reads <ws>/.auditooor/dataflow_paths
	@# .jsonl via --workspace auto-discovery. On a cold/stale ws that slice is ABSENT,
	@# so the questions silently degrade to the no-flow path (no dataflow_path_id / no
	@# sink-kind provenance). Surface it: WARN (advisory) when the slice is absent or
	@# empty so the operator materializes it (make dataflow-slice) BEFORE steering the
	@# hunt. Flip fail-closed via AUDITOOOR_PERFNQ_DATAFLOW_FAILCLOSED=1 (then an empty
	@# slice refuses to emit non-flow-seeded questions).
	@if [ -n "$(_WS_RESOLVED)" ] && [ ! -s "$(_WS_RESOLVED)/.auditooor/dataflow_paths.jsonl" ]; then \
	  echo "[per-fn-questions] WARN dataflow_paths.jsonl absent/empty ($(_WS_RESOLVED)/.auditooor/dataflow_paths.jsonl) -> flow-seeded hacker questions will be ABSENT; run 'make dataflow-slice WS=$(_WS_RESOLVED)' (or audit step-1c) first" >&2; \
	  $(if $(filter-out 0 false no,$(AUDITOOOR_PERFNQ_DATAFLOW_FAILCLOSED)),echo "[per-fn-questions] FAIL AUDITOOOR_PERFNQ_DATAFLOW_FAILCLOSED=1 + empty dataflow slice -> refusing to emit non-flow-seeded questions" >&2 && exit 3,:); \
	fi
	@# B3: --workspace is ALWAYS passed (was $(if $(WS),...)) via _WS_RESOLVED so the
	@# dataflow-slice auto-discovery + SEVERITY.md payable-row feed fire even when WS
	@# is resolved through the pipeline default rather than an explicit WS= override.
	@python3 tools/per-function-hacker-questions.py \
	  --invariants "$(INV)" \
	  --output $(or $(OUT),reports/hacker_qs_$(shell date -u +%Y-%m-%d).jsonl) \
	  --workspace "$(_WS_RESOLVED)" \
	  --json

mvp23-pipeline: ## Run the full MVP3 pipeline for WS=<ws>: invariants -> questions -> prefilter -> reweight
	@if [ -z "$(WS)" ]; then \
	  echo "Usage: make mvp23-pipeline WS=<workspace>" >&2; \
	  exit 2; \
	fi
	@$(MAKE) invariant-synth WS="$(WS)" OUT=/tmp/inv_$(notdir $(WS)).jsonl
	@$(MAKE) per-fn-questions INV=/tmp/inv_$(notdir $(WS)).jsonl OUT=/tmp/qs_$(notdir $(WS)).jsonl WS="$(WS)"
	@$(MAKE) mimo-prefilter WS="$(WS)" QS=/tmp/qs_$(notdir $(WS)).jsonl OUT=/tmp/qs_$(notdir $(WS))_prefiltered.jsonl
	@echo ""
	@echo "  Invariants:   /tmp/inv_$(notdir $(WS)).jsonl"
	@echo "  Questions:    /tmp/qs_$(notdir $(WS)).jsonl"
	@echo "  Prefiltered:  /tmp/qs_$(notdir $(WS))_prefiltered.jsonl (use this for MIMO dispatch)"
	@echo "  Feed PREFILTERED questions into llm-fanout-dispatcher / MIMO harness."

# r36-rebuttal: lane mega-learn-2026-05-28 prefilter target
mimo-prefilter: ## Pre-MIMO class-keyword surface check. WS=<ws> QS=<ranked-questions.jsonl> OUT=<out.jsonl>
	@if [ -z "$(WS)" ] || [ -z "$(QS)" ] || [ -z "$(OUT)" ]; then \
	  echo "Usage: make mimo-prefilter WS=<ws> QS=<ranked-questions.jsonl> OUT=<out.jsonl> [KEEP_UNKNOWN=1]" >&2; \
	  exit 2; \
	fi
	@python3 tools/mimo-class-keyword-prefilter.py \
	  --workspace "$(WS)" \
	  --questions "$(QS)" \
	  --output "$(OUT)" \
	  $(if $(KEEP_UNKNOWN),--keep-unknown-class) \
	  --json

# ============================================================================
# MIMO learning loop (mimo-corpus-mining-wave-2026-05-28)
# ============================================================================

mimo-corpus-mine: ## Walk all MIMO sidecars -> update derived corpora (signal scores, chain candidates, predicates, yield matrix)
	@python3 tools/mimo-corpus-miner.py $(if $(WS),--workspace $(WS)) --json
	@# Post-hunt: if a per-function-hunt obligation is open and genuine verdict
	@# sidecars now exist for this workspace, mark it completed (earned, with
	@# embedded evidence). A queued-but-never-dispatched hunt has 0 sidecars and
	@# stays dispatch-required - so this cannot false-green the hunt-complete gate.
	@if [ -n "$(WS)" ]; then \
	  python3 tools/hunt-obligation-resolve.py --workspace "$(WS)" || \
	    echo "[mimo-corpus-mine] NOTE hunt obligation still dispatch-required (not enough genuine sidecars yet); advisory" >&2 ; \
	fi

triage-feedback: ## Promote triage verdicts -> workspace OOS extensions + anti-pattern catalog + exploit queue. DIR=<triage-dir>
	@if [ -z "$(DIR)" ]; then \
	  echo "Usage: make triage-feedback DIR=/tmp/triage_<wave>_yes" >&2; \
	  exit 2; \
	fi
	@python3 tools/triage-verdict-feedback.py --triage-dir $(DIR) --json

mimo-learning-loop: ## Run the full loop: corpus-mine (emits brain_prime_priors_<ws>) + triage-feedback + reweight
	@$(MAKE) mimo-corpus-mine
	@$(MAKE) hacker-q-reweight
	@if [ -d /tmp/triage_46_yes ]; then $(MAKE) triage-feedback DIR=/tmp/triage_46_yes; fi
	@echo ""
	@echo "  Learning loop complete. Verify via:"
	@echo "    python3 tools/vault-mcp-server.py --call vault_mimo_corpus_intelligence --args '{\"workspace_path\":\"$(or $(WS),/Users/wolf/audits/hyperbridge)\"}'"
	@echo ""
	@echo "  Next brain-prime run will auto-consume audit/corpus_tags/derived/brain_prime_priors_<ws>.json"
	@echo "  (Phase E.1 wired 2026-05-28; AUTO-BOOST + AUTO-DEPRIORITIZE cells applied to per-fn ranker)"

# r36-rebuttal: registered lane reweighter-persist-fix in .auditooor/agent_pathspec.json
# learning-closeout: the per-workspace self-learning durable-persist stage wired
# into `make audit-run-full` (advisory / G9-parity). Runs the per-workspace
# agent-learning-compiler (mines this run's artifacts into terminal ledger rows)
# then refreshes the global hacker-q reweight scores (durable ledger via the
# canonical --out path). Unlike `mimo-learning-loop` (manual, full corpus-mine),
# this is the lean closeout pair that every audit triggers automatically so the
# learning loop is never print-only and never skipped per-workspace.
learning-closeout: ## Per-workspace audit-closeout learning: agent-learning-compiler + hacker-q-reweight (durable). WS=<ws>
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make learning-closeout WS=<workspace> [JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "learning-closeout" "$(_WS_RESOLVED)"
	@$(MAKE) --no-print-directory agent-learning-compiler WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1)
	@$(MAKE) --no-print-directory hacker-q-reweight
	@# --- FIX 1: fold 3 orphan feedback/learning tools (each advisory, gated, persisting) ---
	@# outcome-feedback-loop: outcome telemetry -> detector tier calibration.
	@# Persists reports/outcome_feedback_<date>.json + vault promotion-candidates.md.
	@# Run live (NOT --dry-run) so closeout actually persists; tolerate absent outcomes.
	@if [ -f reference/outcomes.jsonl ] || [ -f tools/outcomes.json ]; then \
	  python3 tools/outcome-feedback-loop.py >/dev/null 2>&1 \
	    && echo "[learning-closeout] outcome-feedback-loop persisted (reports/outcome_feedback_<date>.json)" \
	    || echo "[learning-closeout] WARN outcome-feedback-loop failed; continuing (advisory)"; \
	else \
	  echo "[learning-closeout] SKIP outcome-feedback-loop (no reference/outcomes.jsonl)"; \
	fi
	@# triage-feedback-collector: refresh the triager-pattern DB from markdown.
	@# --sync-from-md persists reference/triager_patterns.json. Skip if the md absent.
	@if [ -f reference/triager_patterns.md ]; then \
	  python3 tools/triage-feedback-collector.py --sync-from-md >/dev/null 2>&1 \
	    && echo "[learning-closeout] triage-feedback-collector synced (reference/triager_patterns.json)" \
	    || echo "[learning-closeout] WARN triage-feedback-collector failed; continuing (advisory)"; \
	else \
	  echo "[learning-closeout] SKIP triage-feedback-collector (no reference/triager_patterns.md)"; \
	fi
	@# triage-verdict-feedback: promote this workspace's triage verdicts -> derived
	@# corpora (OOS extensions, anti-patterns, exploit queues). Skip cleanly when the
	@# workspace has no triage_v2_results.jsonl.
	@if [ -f "$(_WS_RESOLVED)/.auditooor/triage_v2_results.jsonl" ]; then \
	  python3 tools/triage-verdict-feedback.py --triage-dir "$(_WS_RESOLVED)/.auditooor" --json >/dev/null 2>&1 \
	    && echo "[learning-closeout] triage-verdict-feedback promoted (derived corpora)" \
	    || echo "[learning-closeout] WARN triage-verdict-feedback failed; continuing (advisory)"; \
	else \
	  echo "[learning-closeout] SKIP triage-verdict-feedback (no $(_WS_RESOLVED)/.auditooor/triage_v2_results.jsonl)"; \
	fi
	@# --- FIX 2: aggregate this workspace's learning ledger into the shared corpus ---
	@# Lifts <ws>/.auditooor/agent_artifacts/learning_ledger.jsonl into
	@# audit/corpus_tags/derived/agent_learning_ledger_aggregated.jsonl (registered in
	@# obsidian-vault-sync SECTION_SOURCES["mining"]) so recall surfaces it cross-workspace.
	@python3 tools/learning-ledger-aggregate.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) \
	  || echo "[learning-closeout] WARN learning-ledger-aggregate failed; continuing (advisory)"
	@# --- FIX 3: produce the canonical mined-landed parity ledger from CURRENT
	@# finding-sidecars (closes the funnel gap where the audit-completeness
	@# mined-landed gate (i2) demanded mined_landed_parity.json that no step
	@# produced -> it went stale/hand-maintained). Lands each genuine
	@# finding-sidecar's outcome (refuted->known_dead_ends, confirmed->
	@# learning_staged) and asserts ACCURATE parity; undecided sidecars are
	@# reported honestly (never faked). Advisory: a non-zero rc means real
	@# un-landed debt, surfaced to the gate (not a closeout failure).
	@python3 tools/mined-landed-parity-build.py --workspace "$(_WS_RESOLVED)" $(if $(JSON),--json) \
	  && echo "[learning-closeout] mined-landed parity ledger refreshed (.auditooor/mined_landed_parity.json)" \
	  || echo "[learning-closeout] WARN mined-landed parity has un-landed/undecided sidecars (honest debt; see ledger unaccounted[])"
	@echo "[learning-closeout] durable learning persisted (compiler ledger + hacker_q_reweight + 3 feedback tools + aggregated corpus + mined-landed parity)"

# ============================================================================
# PLAN_FULL_WIRING_2026-05-28 P8: safe orphan-tool entrypoints
# ============================================================================

.PHONY: orient-prefilter global-chain-template-library-build chain-templates chain-synth workflow-fullness-check depth-tools agent-output-synth exploit-chain-correlator causal-chain-extract hackerman-function-shapes always-escalate-platform-oos-check

orient-prefilter: ## P8: advisory ORIENT kill-risk prefilter. WS=<ws> [CANDIDATES=<orient.json>] [AUDIT_PIN=<sha>] [COMPOSITION=1] [JSON=1]
	@set -e; \
	if [ -z "$(WS)" ]; then \
	  echo "[orient-prefilter] NOTE WS=<workspace> not supplied; no-op."; \
	  echo "Usage: make orient-prefilter WS=<workspace> CANDIDATES=<orient.json> [AUDIT_PIN=<sha>] [COMPOSITION=1] [JSON=1]"; \
	  exit 0; \
	fi; \
	if [ ! -d "$(_WS_RESOLVED)" ]; then \
	  echo "[orient-prefilter] NOTE workspace not found: $(_WS_RESOLVED); no-op."; \
	  exit 0; \
	fi; \
	candidates="$(CANDIDATES)"; \
	if [ -z "$$candidates" ]; then \
	  for p in \
	    "$(_WS_RESOLVED)/.auditooor/orient_candidates.json"; do \
	    if [ -f "$$p" ]; then candidates="$$p"; break; fi; \
	  done; \
	fi; \
	if [ -z "$$candidates" ] || [ ! -f "$$candidates" ]; then \
	  echo "[orient-prefilter] NOTE candidates JSON not found; no-op."; \
	  echo "[orient-prefilter] Pass CANDIDATES=<orient-output.json> or create $(_WS_RESOLVED)/.auditooor/orient_candidates.json."; \
	  exit 0; \
	fi; \
	echo "[orient-prefilter] candidates=$$candidates workspace=$(_WS_RESOLVED)"; \
	python3 tools/orient-prefilter.py \
	  --candidates "$$candidates" \
	  --workspace "$(_WS_RESOLVED)" \
	  --audit-pin "$(AUDIT_PIN)" \
	  $(if $(DAYS),--days "$(DAYS)") \
	  $(if $(COMPOSITION),--composition) \
	  $(if $(JSON),--json)

global-chain-template-library-build: ## P8: rebuild global chain-template corpus. No-op if invariant input is missing.
	@invariants="$(or $(INVARIANTS),audit/corpus_tags/derived/invariants_pilot_audited.jsonl)"; \
	predicates="$(or $(PREDICATES),audit/corpus_tags/derived/exploit_predicates.jsonl)"; \
	output="$(or $(OUT),audit/corpus_tags/derived/global_chain_templates.jsonl)"; \
	manifest="$(or $(MANIFEST),$${output%.jsonl}.manifest.json)"; \
	summary="$(SUMMARY)"; \
	if [ ! -f "$$invariants" ]; then \
	  echo "[global-chain-template-library-build] NOTE invariants input missing: $$invariants; no-op."; \
	  exit 0; \
	fi; \
	if [ ! -f "$$predicates" ]; then \
	  echo "[global-chain-template-library-build] NOTE predicates input missing: $$predicates; continuing (tool treats predicates as optional)."; \
	fi; \
	echo "[global-chain-template-library-build] output=$$output manifest=$$manifest"; \
	python3 tools/global-chain-template-library-build.py \
	  --invariants-jsonl "$$invariants" \
	  --predicates-jsonl "$$predicates" \
	  --output "$$output" \
	  --manifest "$$manifest" \
	  $(if $(ANTI_PATTERNS_DIR),--anti-patterns-dir "$(ANTI_PATTERNS_DIR)") \
	  $(if $(INCIDENT_DIRS),--incident-corpus-dirs "$(INCIDENT_DIRS)") \
	  $(if $(ZETACHAIN_ANCHORS_DIR),--zetachain-anchors-dir "$(ZETACHAIN_ANCHORS_DIR)") \
	  $(if $(MAX_TUPLE_SIZE),--max-tuple-size "$(MAX_TUPLE_SIZE)") \
	  $(if $(MIN_COMPOSITION_SCORE),--min-composition-score "$(MIN_COMPOSITION_SCORE)") \
	  $(if $(MAX_INCIDENTS),--max-incidents "$(MAX_INCIDENTS)") \
	  $(if $(MAX_INVARIANTS),--max-invariants "$(MAX_INVARIANTS)") \
	  $(if $(NO_MANUAL_ANCHOR),--no-manual-anchor) \
	  $(if $(SUMMARY),--json-summary "$(SUMMARY)")

chain-templates: ## CHAIN-LIFT: alias for global-chain-template-library-build. WS param unused (global corpus). Use when templates are stale.
	$(MAKE) global-chain-template-library-build

chain-synth: ## CHAIN-LIFT: synthesize novel multi-step exploit chains for WS. WS=<workspace> [DRY_RUN=1] [JSON=1]
	$(call _require_pipeline_phase_token,chain-synth)
	@set -e; 	if [ -z "$(WS)" ]; then 	  echo "[chain-synth] ERROR WS=<workspace> is required"; 	  echo "Usage: make chain-synth WS=/path/to/workspace [DRY_RUN=1] [JSON=1]"; 	  exit 1; 	fi; 	ws_resolved="$(WS)"; 	if [ ! -d "$$ws_resolved" ]; then 	  echo "[chain-synth] ERROR workspace not found: $$ws_resolved"; exit 1; 	fi; 	echo "[chain-synth] workspace=$$ws_resolved dry_run=$(if $(DRY_RUN),yes,no)"; 	python3 tools/chain-synth-driver.py 	  --workspace "$$ws_resolved" 	  $(if $(DRY_RUN),--dry-run) 	  $(if $(JSON),--json) 	  $(if $(MAX_CHAINS),--max-chains "$(MAX_CHAINS)")

novel-chain-hunt: ## CAPABILITY: durable novel-chain hunt (stages 1-5: preflight->fuel->synth->verify->persist+learn). WS=<workspace> [DRY_RUN=1] [SKIP_PREFLIGHT=1] [STRICT=1] [MAX_FUNCTIONS=N]
	@set -e; \
	if [ -z "$(WS)" ]; then echo "[novel-chain-hunt] ERROR WS=<workspace> required"; echo "Usage: make novel-chain-hunt WS=/path/to/ws [DRY_RUN=1] [SKIP_PREFLIGHT=1] [STRICT=1] [MAX_FUNCTIONS=N]"; exit 1; fi; \
	ws="$(WS)"; \
	if [ ! -d "$$ws" ]; then echo "[novel-chain-hunt] ERROR workspace not found: $$ws"; exit 1; fi; \
	echo "[novel-chain-hunt] === STAGE 1 SURFACE (audit-preflight) ==="; \
	if [ -n "$(SKIP_PREFLIGHT)" ]; then echo "[novel-chain-hunt] skipping preflight (SKIP_PREFLIGHT=1)"; else $(MAKE) --no-print-directory audit-preflight WS="$$ws" $(if $(MAX_FUNCTIONS),MAX_FUNCTIONS="$(MAX_FUNCTIONS)") || { rc=$$?; if [ -n "$(filter 1 true yes,$(STRICT))" ]; then echo "[novel-chain-hunt] STRICT=1: preflight failed"; exit $$rc; fi; echo "[novel-chain-hunt] WARN preflight non-zero; continuing with existing packs"; }; fi; \
	echo "[novel-chain-hunt] === STAGE 2 FUEL (preflight packs -> exploit_queue broken_invariant_ids) ==="; \
	python3 tools/preflight-to-exploit-queue.py --workspace "$$ws" $(if $(DRY_RUN),--dry-run) || { rc=$$?; if [ -n "$(filter 1 true yes,$(STRICT))" ]; then echo "[novel-chain-hunt] STRICT=1: fuel bridge failed"; exit $$rc; fi; echo "[novel-chain-hunt] WARN fuel bridge non-zero"; }; \
	echo "[novel-chain-hunt] === STAGE 3 SYNTH (chain-synth-driver) ==="; \
	$(MAKE) --no-print-directory chain-synth WS="$$ws" $(if $(DRY_RUN),DRY_RUN=1) || { rc=$$?; if [ -n "$(filter 1 true yes,$(STRICT))" ]; then echo "[novel-chain-hunt] STRICT=1: chain-synth failed"; exit $$rc; fi; echo "[novel-chain-hunt] WARN chain-synth non-zero"; }; \
	echo "[novel-chain-hunt] === STAGE 4+5 VERIFY + PERSIST + LEARN (chain-verify-persist) ==="; \
	python3 tools/chain-verify-persist.py --workspace "$$ws" $(if $(DRY_RUN),--dry-run,--persist) || { rc=$$?; if [ -n "$(filter 1 true yes,$(STRICT))" ]; then echo "[novel-chain-hunt] STRICT=1: verify-persist failed"; exit $$rc; fi; echo "[novel-chain-hunt] WARN verify-persist non-zero"; }; \
	echo "[novel-chain-hunt] DONE. Confirmed chains -> $$ws/.auditooor/chain_verdicts_*.json + global_chain_templates corpus (self-improving). Refuted -> known_dead_ends."

workflow-fullness-check: ## P8: run Gap #39 fullness gate directly. DRAFT=<draft.md> [WS=<workspace>] [STRICT=1] [JSON=1]
	@set -e; \
	if [ -z "$(DRAFT)" ]; then \
	  echo "[workflow-fullness-check] NOTE DRAFT=<draft.md> not supplied; no-op."; \
	  echo "Usage: make workflow-fullness-check DRAFT=<draft.md> [WS=<workspace>] [STRICT=1] [JSON=1]"; \
	  echo "Note: tools/pre-submit-check.sh already runs this as Check #110."; \
	  exit 0; \
	fi; \
	if [ ! -f "$(DRAFT)" ]; then \
	  echo "[workflow-fullness-check] NOTE draft not found: $(DRAFT); no-op."; \
	  exit 0; \
	fi; \
	python3 tools/workflow-fullness-check.py "$(DRAFT)" \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json)

depth-tools: ## P8: safe wrapper for depth-tools-orchestrator. WS=<ws> [ALL=1] [DRY_RUN=1] [JSON=1]
	@set -e; \
	tool="tools/depth-tools-orchestrator.py"; \
	if [ ! -f "$$tool" ]; then \
	  echo "[depth-tools] NOTE $$tool not found; no-op."; \
	  exit 0; \
	fi; \
	if [ -z "$(WS)" ]; then \
	  echo "[depth-tools] NOTE WS=<workspace> not supplied; no-op."; \
	  echo "Usage: make depth-tools WS=<workspace> [ALL=1] [DRY_RUN=1] [JSON=1]"; \
	  exit 0; \
	fi; \
	if [ ! -d "$(_WS_RESOLVED)" ]; then \
	  echo "[depth-tools] NOTE workspace not found: $(_WS_RESOLVED); no-op."; \
	  exit 0; \
	fi; \
	python3 "$$tool" --workspace "$(_WS_RESOLVED)" \
	  $(if $(HALMOS),--halmos "$(HALMOS)") \
	  $(if $(FOUNDRY_FUZZ_1M),--foundry-fuzz-1m "$(FOUNDRY_FUZZ_1M)") \
	  $(if $(RUNS),--runs "$(RUNS)") \
	  $(if $(MYTHRIL),--mythril "$(MYTHRIL)") \
	  $(if $(MANTICORE),--manticore "$(MANTICORE)") \
	  $(if $(DIFFERENTIAL_FUZZ),--differential-fuzz "$(DIFFERENTIAL_FUZZ)") \
	  $(if $(REFERENCE),--reference "$(REFERENCE)") \
	  $(if $(SOAK_FUZZ),--soak-fuzz "$(SOAK_FUZZ)") \
	  $(if $(HOURS),--hours "$(HOURS)") \
	  $(if $(RULE14_DEEP_INTEGRATE),--rule14-deep-integrate) \
	  $(if $(HEVM),--hevm "$(HEVM)") \
	  $(if $(HEVM_CONTRACT),--hevm-contract "$(HEVM_CONTRACT)") \
	  $(if $(HEVM_FUNCTION),--hevm-function "$(HEVM_FUNCTION)") \
	  $(if $(HEVM_TIMEOUT),--hevm-timeout "$(HEVM_TIMEOUT)") \
	  $(if $(KONTROL),--kontrol "$(KONTROL)") \
	  $(if $(ALL),--all) \
	  $(if $(JSON),--json) \
	  $(if $(DRY_RUN),--dry-run)

agent-output-synth: ## P8: safe wrapper for agent-output-synthesizer. WS=<ws> [OUT=<path>] [FORMAT=json|markdown] [BRIEF_CANDIDATES=1]
	@set -e; \
	tool="tools/agent-output-synthesizer.py"; \
	if [ ! -f "$$tool" ]; then \
	  echo "[agent-output-synth] NOTE $$tool not found; no-op."; \
	  exit 0; \
	fi; \
	if [ -z "$(WS)" ]; then \
	  echo "[agent-output-synth] NOTE WS=<workspace> not supplied; no-op."; \
	  echo "Usage: make agent-output-synth WS=<workspace> [OUT=<path>] [FORMAT=json|markdown] [BRIEF_CANDIDATES=1]"; \
	  exit 0; \
	fi; \
	if [ ! -d "$(_WS_RESOLVED)" ]; then \
	  echo "[agent-output-synth] NOTE workspace not found: $(_WS_RESOLVED); no-op."; \
	  exit 0; \
	fi; \
	out="$(or $(OUT),$(_WS_RESOLVED)/.auditooor/agent_output_synthesis.json)"; \
	mkdir -p "$$(dirname "$$out")"; \
	python3 "$$tool" "$(_WS_RESOLVED)" \
	  --out "$$out" \
	  --format "$(or $(FORMAT),json)" \
	  $(if $(BRIEF_CANDIDATES),--brief-candidates)

exploit-chain-correlator: ## P8: safe wrapper for exploit-chain-correlator. SOURCE=<postmortem.md|url> [CHAIN=1] [GAP_SURFACE=1] [EXPORT_JSON=1]
	@set -e; \
	tool="tools/exploit-chain-correlator.py"; \
	if [ ! -f "$$tool" ]; then \
	  echo "[exploit-chain-correlator] NOTE $$tool not found; no-op."; \
	  exit 0; \
	fi; \
	if [ -z "$(SOURCE)" ]; then \
	  echo "[exploit-chain-correlator] NOTE SOURCE=<path-or-url> not supplied; no-op."; \
	  echo "Usage: make exploit-chain-correlator SOURCE=<postmortem.md|url> [TOP=10] [CHAIN=1] [GAP_SURFACE=1] [EXPORT_JSON=1]"; \
	  exit 0; \
	fi; \
	case "$(SOURCE)" in http://*|https://*) source_arg="$(SOURCE)" ;; *) \
	  if [ ! -f "$(SOURCE)" ]; then \
	    echo "[exploit-chain-correlator] NOTE source file not found: $(SOURCE); no-op."; \
	    exit 0; \
	  fi; \
	  source_arg="$(SOURCE)" ;; \
	esac; \
	python3 "$$tool" "$$source_arg" \
	  $(if $(TOP),--top "$(TOP)") \
	  $(if $(DUMP_TEXT),--dump-text) \
	  $(if $(CHAIN),--chain) \
	  $(if $(ANALOGICAL),--analogical "$(ANALOGICAL)") \
	  $(if $(GAP_SURFACE),--gap-surface) \
	  $(if $(EXPORT_JSON),--export-json)

causal-chain-extract: ## P8: safe wrapper for causal-chain-extract. [INPUT=<jsonl>] [OUTPUT=<jsonl>] [CANONICAL=1]
	@set -e; \
	tool="tools/causal-chain-extract.py"; \
	input="$(or $(INPUT),audit/corpus_tags/derived/exploit_predicates.jsonl)"; \
	if [ ! -f "$$tool" ]; then \
	  echo "[causal-chain-extract] NOTE $$tool not found; no-op."; \
	  exit 0; \
	fi; \
	if [ ! -f "$$input" ]; then \
	  echo "[causal-chain-extract] NOTE input not found: $$input; no-op."; \
	  exit 0; \
	fi; \
	output="$(or $(OUTPUT),audit/corpus_tags/derived/causal_chains.jsonl)"; \
	index_json="$(or $(INDEX_JSON),$${output%.jsonl}.index.json)"; \
	report_md="$(REPORT_MD)"; \
	mkdir -p "$$(dirname "$$output")"; \
	python3 "$$tool" \
	  --input "$$input" \
	  --output "$$output" \
	  --index-json "$$index_json" \
	  $(if $(REVERSE_SQLITE),--reverse-sqlite "$(REVERSE_SQLITE)") \
	  $(if $(NO_REVERSE_SQLITE),--no-reverse-sqlite) \
	  $(if $(STRICT_PROJECTION_OUTPUT),--strict-projection-output "$(STRICT_PROJECTION_OUTPUT)") \
	  $(if $(NO_STRICT_PROJECTION),--no-strict-projection) \
	  $(if $(STRICT_PROJECTION_LIMIT),--strict-projection-limit "$(STRICT_PROJECTION_LIMIT)") \
	  $(if $(REPORT_MD),--report-md "$$report_md") \
	  $(if $(CANONICAL),--canonical) \
	  $(if $(QUALITY_PROFILE),--quality-profile "$(QUALITY_PROFILE)") \
	  $(if $(LIMIT),--limit "$(LIMIT)") \
	  $(if $(PRETTY),--pretty)

hackerman-function-shapes: ## P8: safe wrapper for Solodit function-shape backfill. [APPLY=1] [JSON=1]
	@set -e; \
	tool="tools/hackerman-backfill-solodit-function-shapes.py"; \
	tag_dir="$(or $(TAG_DIR),audit/corpus_tags/tags)"; \
	index_dir="$(or $(INDEX_DIR),audit/corpus_tags/derived)"; \
	if [ ! -f "$$tool" ]; then \
	  echo "[hackerman-function-shapes] NOTE $$tool not found; no-op."; \
	  exit 0; \
	fi; \
	if [ ! -d "$$tag_dir" ]; then \
	  echo "[hackerman-function-shapes] NOTE tag dir not found: $$tag_dir; no-op."; \
	  exit 0; \
	fi; \
	python3 "$$tool" \
	  --tag-dir "$$tag_dir" \
	  --index-dir "$$index_dir" \
	  $(if $(APPLY),,--dry-run) \
	  $(if $(REBUILD_INDEX),--rebuild-index) \
	  $(if $(JSON),--json-summary)

always-escalate-platform-oos-check: ## P8: Gap #30 platform-OOS check wrapper. WS=<ws> FRAMING=<text>|FRAMING_FILE=<path> [JSON=1]
	@set -e; \
	tool="tools/always-escalate-platform-oos-check.py"; \
	if [ ! -f "$$tool" ]; then \
	  echo "[always-escalate-platform-oos-check] NOTE $$tool not found; no-op."; \
	  exit 0; \
	fi; \
	if [ -z "$(WS)" ]; then \
	  echo "[always-escalate-platform-oos-check] NOTE WS=<workspace> not supplied; no-op."; \
	  echo "Usage: make always-escalate-platform-oos-check WS=<workspace> FRAMING=<text>|FRAMING_FILE=<path> [REBUTTAL=<text>|REBUTTAL_FILE=<path>] [JSON=1]"; \
	  exit 0; \
	fi; \
	if [ ! -d "$(_WS_RESOLVED)" ]; then \
	  echo "[always-escalate-platform-oos-check] NOTE workspace not found: $(_WS_RESOLVED); no-op."; \
	  exit 0; \
	fi; \
	if [ -z "$(FRAMING)" ] && [ -z "$(FRAMING_FILE)" ]; then \
	  echo "[always-escalate-platform-oos-check] NOTE FRAMING or FRAMING_FILE not supplied; no-op."; \
	  exit 0; \
	fi; \
	if [ -n "$(FRAMING_FILE)" ] && [ ! -f "$(FRAMING_FILE)" ]; then \
	  echo "[always-escalate-platform-oos-check] NOTE framing file not found: $(FRAMING_FILE); no-op."; \
	  exit 0; \
	fi; \
	python3 "$$tool" --workspace "$(_WS_RESOLVED)" \
	  $(if $(FRAMING),--candidate-framing "$(FRAMING)") \
	  $(if $(FRAMING_FILE),--framing-file "$(FRAMING_FILE)") \
	  $(if $(REBUTTAL),--rebuttal-text "$(REBUTTAL)") \
	  $(if $(REBUTTAL_FILE),--rebuttal-file "$(REBUTTAL_FILE)") \
	  $(if $(JSON),--json)

.PHONY: zk-hacker-questions zk-preflight zk-chain-synth zk-external-tool
## --- ZK make targets for the orchestrator to add to the Makefile ---
## All four wrap tools that exist on disk and run today via python3.
## Style matches existing targets ($(_WS_RESOLVED), usage-guard, @python3).

zk-hacker-questions: ## ZK per-function soundness/completeness questions. TARGET=<file-or-dir>
	@if [ -z "$(TARGET)" ]; then \
	  echo 'Usage: make zk-hacker-questions TARGET=<verifier/circuit file or dir> [JSON=1]'; exit 2; \
	fi
	@python3 tools/zk-hacker-questions.py "$(TARGET)" $(if $(JSON),--json)

zk-preflight: ## ZK per-verifier-function pre-flight packs. WS=<workspace>
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make zk-preflight WS=<workspace> [HONK_DIR=<dir>] [OUT=<dir>] [FRAMEWORK=solidity-honk] [NO_MCP=1] [DRY_RUN=1] [JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make zk-preflight" "$(_WS_RESOLVED)"
	@python3 tools/zk-per-function-preflight.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(HONK_DIR),--honk-dir "$(HONK_DIR)") \
	  $(if $(OUT),--output-dir "$(OUT)") \
	  $(if $(FRAMEWORK),--framework "$(FRAMEWORK)") \
	  $(if $(NO_MCP),--no-mcp) \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json)

zk-chain-synth: ## ZK soundness exploit-chain synthesis. WS=<workspace>
	@if [ -z "$(WS)" ]; then \
	  echo 'Usage: make zk-chain-synth WS=<workspace> [DRY_RUN=1] [MAX_GAPS=N] [MOCK_LLM=1] [JSON=1]'; exit 2; \
	fi
	@bash tools/ws-resolve-guard.sh "make zk-chain-synth" "$(_WS_RESOLVED)"
	@python3 tools/zk-chain-synth.py --workspace "$(_WS_RESOLVED)" \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(MAX_GAPS),--max-gaps "$(MAX_GAPS)") \
	  $(if $(MOCK_LLM),--mock-llm) \
	  $(if $(JSON),--json)

zk-external-tool: ## Invoke external ZK analyzer (circomspect/picus/zkhydra). TOOL=<t> TARGET=<path>
	@if [ -z "$(TOOL)" ] || [ -z "$(TARGET)" ]; then \
	  echo 'Usage: make zk-external-tool TOOL={circomspect,picus,zkhydra} TARGET=<circom-or-r1cs path> [WS=<workspace>] [OUT=<file>] [TIMEOUT=300] [JSON=1]'; exit 2; \
	fi
	@python3 tools/zk-external-tool-adapter.py --tool "$(TOOL)" --target "$(TARGET)" \
	  $(if $(WS),--workspace "$(_WS_RESOLVED)") \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(TIMEOUT),--timeout "$(TIMEOUT)") \
	  $(if $(JSON),--json)

## --- swivel-hunt: NOT PROVIDED ---
## The task asked for a `swivel-hunt` target and "swivel-go/rust" application,
## but no `swivel` tool/asset exists anywhere in the repo (grep -rni swivel over
## tools/ docs/ Makefile returns 0 hits). The only near-match is the unrelated
## `base-rust-swival-shape-scan` (different spelling, a Base RPC Rust shape scan).
## No target authored to avoid an aspirational/dead target. Confirm the intended
## tool name/path if swivel support is real.

## --- Folding zk-hunt into hunt-full (ACTIVATED 2026-05-29) ---
## zk-hunt is now wired as Step 5/5 inside the hunt-full recipe (after the
## `make hunt` call, before the final summary echo), guarded so non-ZK
## workspaces are unaffected. SKIP_PREFLIGHT=1 avoids the surface-probe cost on
## non-ZK trees; zk-hunt's inner stages already WARN-and-continue when no
## verifier surface is found. See the hunt-full recipe above for the live wiring.

# --- Find-All-Bugs plan: PR6 Go dynamic engine + PR7 differential-seed targets ---
.PHONY: go-dynamic-engine go-dynamic-engine-test go-engine-harness-author-test differential-seed
go-dynamic-engine:
	@if [ -z "$(WS)" ]; then echo 'Usage: make go-dynamic-engine WS=<workspace> [MODULE=<dir>] [FUZZTIME=30s] [TIMEOUT=1800] [DRY=1]'; exit 2; fi
	@bash tools/ws-resolve-guard.sh "go-dynamic-engine" "$(_WS_RESOLVED)"
	@bash tools/go-dynamic-engine-runner.sh "$(_WS_RESOLVED)" $(if $(MODULE),--module-root $(MODULE)) $(if $(FUZZTIME),--fuzztime $(FUZZTIME)) $(if $(TIMEOUT),--timeout $(TIMEOUT)) $(if $(DRY),--dry-run)
go-dynamic-engine-test:
	@bash tools/tests/test_go_dynamic_engine_runner.sh
go-engine-harness-author-test:
	@python3 -m unittest tools.tests.test_go_engine_harness_author
differential-seed:
	@if [ -z "$(WS)" ]; then echo 'Usage: make differential-seed WS=<workspace> [K=<n>] [MERGE=1]'; exit 2; fi
	@python3 tools/cross-workspace-differential-seed.py --workspace "$(_WS_RESOLVED)" $(if $(K),--k $(K)) $(if $(MERGE),--merge-proof-queue)

# ----------------------------------------------------------------------------
# PR12: capability orphan-closure gate + adoption of the fork-divergence ETL.
# ----------------------------------------------------------------------------
.PHONY: hackerman-etl-fork-divergence capability-inventory-rebuild \
        capability-orphan-closure-check capability-orphan-closure-check-test

# Adopt tools/hackerman-etl-from-fork-divergence.py (PR8). Its CLI differs from
# the wave-1-3-4 miners (no --out-dir), so it gets its own target rather than
# joining the wave loop. Wiring it here makes it WIRED for the orphan-closure
# gate. Ingests dYdX fork-divergence audit learnings (upstream-fix-not-
# backported-to-fork technique) into the corpus as tier-2 invariants + seeds.
hackerman-etl-fork-divergence: ## ETL miner: fork-divergence audit learnings -> corpus. [DRY_RUN=1] [VERDICTS_DIR=...]
	@python3 tools/hackerman-etl-from-fork-divergence.py \
	  $(if $(VERDICTS_DIR),--verdicts-dir "$(VERDICTS_DIR)") \
	  $(if $(INVARIANTS_OUT),--invariants-out "$(INVARIANTS_OUT)") \
	  $(if $(DETECTOR_SEEDS_OUT),--detector-seeds-out "$(DETECTOR_SEEDS_OUT)") \
	  $(if $(DRY_RUN),--dry-run) \
	  $(if $(JSON),--json-summary)

# Rebuild the capability inventory artifact (reference/capability_inventory.jsonl
# + canonical_flows + the two generated docs).
capability-inventory-rebuild: ## Rebuild reference/capability_inventory.jsonl + docs
	@python3 tools/capability-inventory-build.py --json | tail -n +2 || true

# PR12 orphan-closure gate. STRICT=1 fails closed if any landed capability is an
# unexplained orphan (none of WIRED/ADVISORY/HELPER/DEPRECATED/BLOCKED).
capability-orphan-closure-check: ## Classify every capability; STRICT=1 fails on unexplained orphans
	@python3 tools/capability-orphan-closure-check.py \
	  $(if $(STRICT),--strict) \
	  $(if $(JSON),--json) \
	  $(if $(REPORT),--report "$(REPORT)") \
	  $(if $(DECLARATIONS),--declarations "$(DECLARATIONS)")

capability-orphan-closure-check-test:
	@python3 -m unittest tools.tests.test_capability_orphan_closure_check

# Ingest OUR OWN confirmed findings (submissions/) into the cross-workspace
# hackerman corpus as tier-1 records. THE missing feeder (audit-the-audits 2026-06-18):
# a win in one workspace now primes the hunt/dedup/originality gates in all siblings.
etl-our-findings:
	@python3 tools/hackerman-etl-from-our-submissions.py \
	  $(if $(WS),--workspace "$(WS)",--audits-root "$(if $(AUDITS_ROOT),$(AUDITS_ROOT),$(HOME)/audits)") \
	  $(if $(OUT),--out-dir "$(OUT)") $(if $(DRY_RUN),--dry-run) --json-summary

# Ingest a workspace's prior_audits/ into the cross-workspace corpus (public-archive tier).
# The tool existed but nothing called it; this wires it. Backfilled 2026-06-18.
etl-prior-audits:
	@if [ -z "$(WS)" ]; then echo 'Usage: make etl-prior-audits WS=<workspace>'; exit 2; fi
	@python3 tools/hackerman-etl-from-prior-audits.py --workspace "$(_WS_RESOLVED)" \
	  --out-dir audit/corpus_tags/tags/auditooor_prior_audits \
	  --verification-tier tier-2-verified-public-archive --json-summary \
	  || echo "[etl-prior-audits] WARN prior-audits ETL failed (advisory)" >&2

# Canonical step-2c credited-campaign finalizer (strata 2026-06-30 lessons baked in:
# Total-calls emit + forge-std artifact exclusion + v1 receipt merge). emit-config +
# the actual medusa run stay explicit (operator/agent controls the long campaign), this
# target bridges a finished medusa log into the credited fuzz_campaign_receipt.json.
.PHONY: step2c-campaign-finalize
step2c-campaign-finalize:
	@if [ -z "$(WS)" ] || [ -z "$(HARNESS)" ] || [ -z "$(LOG)" ]; then \
	  echo 'Usage: make step2c-campaign-finalize WS=<ws> HARNESS=<Name> CONTRACT=<Name> LOG=<medusa-log> [MIN_CALLS=1000000]'; exit 2; fi
	@python3 tools/step2c-campaign.py finalize --workspace "$(WS)" --harness "$(HARNESS)" \
	  --contract "$(if $(CONTRACT),$(CONTRACT),$(HARNESS))" --log "$(LOG)" \
	  $(if $(MIN_CALLS),--min-calls $(MIN_CALLS),)

# --- finding-target-scope-check (OOS-dependency root-cause gate) --------------
# Flags a finding whose ROOT-CAUSE file is an in-repo OOS dependency (not one of
# the enumerated in-scope targets) with no in-scope primary impact - the strata
# SharesCooldown class. Anti-false-negative: flags for review, never hard-kills.
.PHONY: finding-target-scope-check finding-target-scope-check-test
finding-target-scope-check:
	@if [ -z "$(WS)" ] || [ -z "$(FINDING)" ]; then \
	  echo 'Usage: make finding-target-scope-check WS=<ws> FINDING=<finding.md> [JSON=1]'; exit 2; fi
	@python3 tools/finding-target-scope-check.py --workspace "$(_WS_RESOLVED)" --finding "$(FINDING)" $(if $(JSON),--json)

finding-target-scope-check-test:
	@python3 -m pytest tools/tests/test_finding_target_scope_check.py -q

# --- anomaly-escalation-guard (R80: no close on an unexplained anomaly) -------
# Blocks a not-fileable / down-tier verdict that rests on a mechanism the analysis
# ADMITTED it could not explain. Run on the finding's ANALYSIS text / worker report
# (where the admission lives), not the sanitized disposition row.
.PHONY: anomaly-escalation-guard anomaly-escalation-guard-test
anomaly-escalation-guard:
	@if [ -z "$(FINDING)" ]; then echo 'Usage: make anomaly-escalation-guard FINDING=<finding.md|report> [JSON=1]'; exit 2; fi
	@python3 tools/anomaly-escalation-guard.py --finding "$(FINDING)" $(if $(JSON),--json)

anomaly-escalation-guard-test:
	@python3 -m pytest tools/tests/test_anomaly_escalation_guard.py -q

.PHONY: prior-audit-resolved-reverify
prior-audit-resolved-reverify:
	@if [ -z "$(WS)" ]; then echo 'Usage: make prior-audit-resolved-reverify WS=<ws> [STRICT=1]'; exit 2; fi
	@python3 tools/prior-audit-resolved-reverify-gate.py "$(_WS_RESOLVED)" $(if $(JSON),--json) $(if $(filter 1,$(STRICT)),--strict)

# Ordered pre-hunt history gate. This composes existing workspace/draft checks
# and validates the GitHub evidence artifact emitted by audit-target-commit-mining.
# No applicable prior or GitHub history is an explicit pass; an applicable but
# missing/unknown history disposition fails closed under STRICT=1.
.PHONY: source-comment-reconciliation prior-audit-context-reconciliation prior-history-prehunt-gate
source-comment-reconciliation:
	@if [ -z "$(WS)" ]; then echo 'Usage: make source-comment-reconciliation WS=<ws>'; exit 2; fi
	@python3 tools/acknowledged-wont-fix-check.py --workspace "$(_WS_RESOLVED)" --scan-workspace-comments $(if $(JSON),--json)

prior-audit-context-reconciliation:
	@if [ -z "$(WS)" ]; then echo 'Usage: make prior-audit-context-reconciliation WS=<ws>'; exit 2; fi
	@python3 tools/prior-audit-resolved-reverify-gate.py "$(_WS_RESOLVED)" --context-review $(if $(JSON),--json)

prior-history-prehunt-gate:
	@if [ -z "$(WS)" ]; then echo 'Usage: make prior-history-prehunt-gate WS=<ws> [STRICT=1]'; exit 2; fi
	@$(MAKE) --no-print-directory prior-audit-context-reconciliation WS="$(_WS_RESOLVED)" STRICT=1 $(if $(JSON),JSON=1)
	@$(MAKE) --no-print-directory prior-audit-resolved-reverify WS="$(_WS_RESOLVED)" STRICT=1 $(if $(JSON),JSON=1)
	@$(MAKE) --no-print-directory r47-check-all WS="$(_WS_RESOLVED)"
	@$(MAKE) --no-print-directory source-comment-reconciliation WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1)
	@python3 tools/audit-target-commit-mining.py --workspace "$(_WS_RESOLVED)" --validate-history $(if $(JSON),--json)

# 2026-07-08: rebuild the impact-escalation chain-template library from the LINKAGE-BEARING
# causal_chains corpus (not the raw per-fn fuel that clobbered invariants_pilot_audited.jsonl).
# Additive: writes invariants_pilot_audited_enriched.jsonl (new) + rebuilds behind the
# 50%-shrink safety guard. Raw fuel file + its 9 per-fn consumers untouched.
.PHONY: corpus-chain-enriched-rebuild
corpus-chain-enriched-rebuild:
	@python3 tools/enrich-chains-from-causal.py
	@python3 tools/global-chain-template-library-build.py \
	  --invariants-jsonl audit/corpus_tags/derived/invariants_pilot_audited_enriched.jsonl \
	  --max-incidents 8 --max-tuple-size 3
	# --max-incidents 8 caps per-template incident refs so the library stays under
	# GitHub's 100MB limit as causal_chains grows (uncapped = 112MB at 12216 chains,
	# 19429 templates). The incident cap trims each template's evidence list; the
	# template COUNT is unaffected. tuple-size 3 keeps multi-hop escalations.
