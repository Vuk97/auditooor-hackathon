# Engage Stage Reference

`tools/engage.py` is the canonical orchestrator. This file maps each stage to
the scripts it calls and the artifacts an operator or agent should expect.

Use this when a stage fails, when adding a new stage, or when updating docs
after tool behavior changes.
For tools that exist but are not part of this canonical stage map, see
[`TOOL_STATUS.md`](TOOL_STATUS.md).

## Invocation Model

```bash
# recommended full canonical chain
make audit WS=~/audits/<project>

# lower-level full stage chain
make engage WORKSPACE=~/audits/<project>

# equivalent direct command
python3 tools/engage.py --workspace ~/audits/<project> --stage all --summary

# dry-run the exact stage plan and artifact paths
python3 tools/engage.py --workspace ~/audits/<project> --dry-run --summary
```

`--stage all` runs 32 canonical stages. `engage.py` exposes 34 stage tokens in
total because `rejection-learn` is standalone and `all` is also accepted as a
stage token. Gap E added `scan-rust` as an asset-conditional stage: it runs
**before** `mine-prioritize` (PR #116, Codex review round 2) only when
`INTAKE_BASELINE.json` reports Blockchain/DLT assets or Rust roots in scope,
and it SKIPs otherwise. The earlier ordering (`scan-rust` after `scan`)
deadlocked fresh BDL/Rust workspaces because `mine-prioritize` gates on the
artifact `scan-rust` writes.

Validate this file after changing stages:

```bash
make stage-reference-check
```

## Asset-Coverage Gating (Gap E)

`intake-baseline.py` writes `assets_in_scope[]` and `asset_coverage_plan{}`
into `INTAKE_BASELINE.json`. Each entry in the plan follows this schema:

```json
{
  "roots": ["path/to/root"],
  "strategy": "free text",
  "estimated_hours": 30,
  "agent_hour_quota_pct": 60,
  "plan_status": "ready|missing|placeholder|not_started"
}
```

`engage.py` enforces asset coverage at three points:

- `orient` — blocks with exit 2 when any in-scope asset has
  `plan_status != ready` and no `ASSET_WAIVER_<Asset_Slug>.md` waiver.
- `mine-prioritize` and `mine-briefs` — same plan-status gate plus a
  dedicated scan-rust evidence gate that requires
  `scanners/rust/SCAN_RUST_SUMMARY.md` / `.json` (legacy fallback:
  `audit/rust-scan/summary.md`) or the matching waiver when Rust roots
  are detected.
- `engagement-retro` — fails closed when an in-scope asset has zero
  `agent_outputs/dispatch_*.md` traces referencing any of its roots and no
  waiver is present.

Operators author `ASSET_PLAN_<Asset_Slug>.md` files (one per asset) with the
schema fields above. Waivers must be explicit markdown files so the close-out
can cite them.

## Stage Map

| # | Stage | Primary tool(s) | Main artifact(s) | Notes |
|---:|---|---|---|---|
| 1 | `intake-baseline` | `intake-baseline.py` | `INTAKE_BASELINE.json`, `INTAKE_BASELINE.md` | mechanical first pass over workspace files, known intel, PDF extraction state, severity/rubric-coverage readiness, scanner artifact readiness, and recommended deterministic order before agents/manual synthesis |
| 2 | `orient` | `orient-from-audits.sh`, `skill-state.sh`, `ccia.py`, `deployment-topology-builder.py`, `live-check-spec-synthesizer.py` | `PRIOR_CONCERNS.md`, `.skill_state.yaml`, `ccia_report.md`, `deployment_topology.json`, `deployment_topology.md`, `monitoring/live_checks.generated.json` | primes prior-audit context, skill state, cross-contract analysis, deployment/config topology evidence, and a generated angle-linked live-check spec with heuristic provenance for generated relation checks; returns `SUCCESS_WARN` when topology evidence stays partial |
| 3 | `live-checks` | `live-check-runner.py`, `live-state-checker.py`, `deploy-state-lookup.sh` | `live_topology_checks.json`, `LIVE_TOPOLOGY.md` | runs declarative live config / role / deploy-state checks from the generated or manual workspace spec; preserves generated heuristic provenance and reports blocked/dry-run evidence truthfully |
| 4 | `env-check` | `solc-version-manager.py`, `forge-deps-checker.py`; `tools/foundry-version-report.py` when available | `<ws>/.auditooor/foundry_version_inventory.{json,md}` plus stdout | records offline Foundry inventory before any environment mutation, then skips Foundry dependency check when no Foundry project is detected |
| 5 | `scan-rust` | `rust-scan-runner.sh` (fallback: `rust-scan.sh`) | `scanners/rust/SCAN_RUST_SUMMARY.md` (PR #115) or `audit/rust-scan/summary.md` (legacy) | Gap E: asset-conditional Rust scan. SKIPs unless `INTAKE_BASELINE.json` lists Blockchain/DLT or Rust roots in scope; emits the scan-rust evidence required before `mine-prioritize` / `mine-briefs`. Runs BEFORE `mine-prioritize` (PR #116) so a fresh BDL/Rust workspace can produce evidence in the same chain run. Multi-root workspaces with only the legacy `rust-scan.sh` fallback FAIL LOUDLY — operators must install `rust-scan-runner.sh` (PR #115) or add `ASSET_WAIVER_Blockchain_DLT.md` |
| 6 | `scan-go` | `go-detector-runner.py` | `.auditooor/go_findings.json` (alias `.auditooor/SCAN_GO_SUMMARY.json`) | SPARK-GAP-001 Phase B seed. Pure-Python regex+brace-balanced scan over `*.go` files. Three patterns: `go.bitcoin.txid_equality_without_utxo_spend_check`, `go.statemachine.guard_only_on_one_path`, `go.statemachine.self_heal_on_unexpected_status`. SKIPs cleanly when no `.go` files are present so non-Go workspaces are unaffected. Sequenced after `scan-rust` and before `mine-prioritize` |
| 7 | `mine-prioritize` | `mining-prioritizer.py` | `swarm/mining_priorities.json` | reads `ccia_report.json`/`ccia_report.md`, or `ccia_rust_report.json` when Solidity CCIA has no angles; also reads the active submission ledger (nested or root), `deployment_topology.json`, and `live_topology_checks.json`; live-check bonuses only apply when the dossier rows are angle-linked or otherwise explicitly relevant |
| 8 | `scan` | `flow-gate.sh`, `workspace-scan-orchestrator.py`, `scan.sh` | `run_custom.log`, `apply_queries.log`, `rust-detect.log`, `circom-detect.log`; `SCAN_REPORT.md`, `detector_environment_manifest.json`, `PATTERN_HITS.md`, `static-analysis-summary.md`, `custom-detectors.log`, `SOLODIT_SEARCH_PLAN.md`, `HYPOTHESIS_PROMPT.md` | the canonical scan stage now combines parseable Solidity/Rust/Circom detector logs with the broader workspace scan facade; Rust-only workspaces produce a Rust `SCAN_REPORT.md` facade and `PATTERN_HITS.md` against `.rs` files; it writes detector environment/tool-skip metadata and hard-stops the run on scan failure. `vault_semantic_match_verify` is the advisory semantic gate for those matches, not proof or submission clearance |
| 9 | `correlate` | `reverse-correlator.py` | in-memory enrichment | feeds `engage_report.md`; missing tool degrades to skipped enrichment |
| 10 | `dedupe` | `dupe-risk.sh` | in-memory enrichment | creates scratch drafts for per-hit duplicate classification |
| 11 | `cross-ws-patterns` | `cross-ws-pattern-mapper.py` | `cross_ws_patterns.md` | workspace-level replacement for archived per-hit cross-workspace lookup |
| 12 | `pattern-migration` | `pattern-migration-alert.py` | `pattern_migration_alert.md` | highlights paid patterns that may migrate into this workspace |
| 13 | `mine-briefs` | `mining-brief-generator.py` | `swarm/mining_briefs/*.md` | produces focused investigation briefs for top targets; uses `ccia_rust_report.json` fallback on Rust/Soroban workspaces when Solidity CCIA is empty |
| 14 | `adversarial-read` | `adversarial-read.sh` | `adversarial_<contract>.md` | contrarian read of the top-hit contract |
| 15 | `attack-tree` | `attack-tree.sh` | `ATTACK_TREE_<Contract>.md` | STRIDE-style expansion for the top-hit contract |
| 16 | `invariants` | `gen-invariants.sh`, fallback `invariant-hunt.sh` | `<resolved-test-dir>/Invariant_<Contract>.t.sol` (test dir resolved from `foundry.toml`; defaults to `test/`) | scaffolds a Foundry invariant harness |
| 17 | `economic-hypotheses` | `economic-hypotheses.sh` | `economic_hypotheses.md` | enumerates economic attack paths around the top target |
| 18 | `report` | built into `engage.py` | `engage_report.md` | clusters hits and prints actionable next steps |
| 19 | `dispatch-brief` | `agent-dispatch-enforced.sh`, fallback `dispatch-brief.sh` | `agent_outputs/dispatch_<slug>.md` | capped to avoid flooding agent output directories |
| 20 | `capture-intel` | `capture-intel.sh` | `EXTERNAL_INTEL.md` | appends an engagement checkpoint, even when no new intel is queued |
| 21 | `record-triage` | `record-triage.sh` | audit ledger append | records `UNKNOWN` rows for mining candidates |
| 22 | `agent-synthesize` | `agent-output-synthesizer.py` | `swarm/agent_verdicts.json` + `swarm/brief_candidates.json` | extracts verdicts, citations, attack paths, and proof-rich candidate findings / PoC plans from agent outputs and swarm briefs |
| 23 | `quality-score` | `finding-quality-scorer.py` | stdout scores | scores each candidate draft without blocking the run |
| 24 | `auto-fix` | `auto-fix-draft.py` | in-place draft edits | applies common submission hygiene fixes |
| 25 | `package` | `submission-packager.py` | `submissions/packaged/` | bundles ready submissions with supporting artifacts |
| 26 | `pre-submit` | `pre-submit-check.sh` | stdout only | runs the deterministic Check #106+ submission gate over clean submissions; Check #27 is the V4 Phase P1 production-path gate plus branch/precondition reachability (High/Critical drafts fail on missing production path, un-replaced mock/prose/OOS gaps, local PoC paths, or branch preconditions with no externally reachable in-scope path); Check #28 verifies explicit `<!-- claim-precondition: ... -->` live-state assumptions when present and fails contradictions; Check #29 requires a per-finding OOS review when `OOS_PASTED.md` exists; Check #30 is OOS-DUPE-FILTER (PR #511 Slice 4 follow-up) — reads encoded rejected/OOS classes from `<ws>/.auditooor/invariant_ledger.json` (row with `invariant_family: oos_duplicate_filter`) and flags drafts that re-claim a class without a `<!-- oos-dupe-rebuttal: <CLASS-ID> <reason> -->` comment; Check #31 is PROGRAM-IMPACT-MAPPING for Critical/High/Medium exact listed-impact mapping; Check #32 is SEVERITY-CLAIM-GUARD for candidate-matrix over-claim and Snappy regression blocking; later R/L gates now extend through Check #106+, so do not quote the legacy Wave-1 count. Verify the current max marker with `rg -n "Check #106|Check #[0-9]+" tools/pre-submit-check.sh`. Medium drafts keep conservative warnings where appropriate. The shared production-path parser lives at `tools/lib/production_path.py` and is reused by `submission-packager.py` to populate the `production_path` manifest field |
| 27 | `pre-submit-llm-review` | `llm-scope-triage.py` (delegates to `llm-dispatch.py` Kimi + Minimax + `llm-calibration-log.py`) | `submissions/llm_review/draft_*.json`, scope-triage artefacts under `submissions/llm_review/_triage/`, calibration rows (task-type `scope-triage`, verdict `INDETERMINATE` until human-verified) in `tools/calibration/llm_calibration_log.jsonl` | dual-LLM scope+severity review of every staging draft via `tools/llm-scope-triage.py` (single source of truth — uses the engagement's `OOS_CHECKLIST.md` + `SEVERITY_CAPS.md`). Standalone-tool consensus is mapped into the engage vocabulary: `AGREED-IN-SCOPE` (HIGH/MEDIUM confidence, `IN_SCOPE` tag), `AGREED-OFF-SCOPE` (HIGH/MEDIUM confidence, `OOS_*` tag), `DISAGREED` (LOW or DISAGREED confidence), `LLM-FAILURE` (both providers errored). Idempotent: prompt-hashed for dedup, re-running on an unchanged workspace coalesces in `_dedupe_keep_latest`. Status: `SUCCESS` when every draft is `AGREED-IN-SCOPE`, `SUCCESS_WARN` on any `DISAGREED`, `SUCCESS_WARN` on any `AGREED-OFF-SCOPE` (advisory until scope-triage calibration matures; future opt-in hard-block via the `PRE_SUBMIT_LLM_HARD_BLOCK_AGREED_OFF_SCOPE` constant in `tools/engage.py` — keep advisory until enough verified-no-false-blocking `scope-triage` ledger rows accumulate), `SKIPPED` when `llm-scope-triage.py` is missing or every invocation fails (offline-safe degrade for test envs without API keys). Runs AFTER `pre-submit` (deterministic Check #106+ gate; source of truth: `tools/pre-submit-check.sh`) and BEFORE `track-submissions` |
| 28 | `track-submissions` | `submissions-tracker.py` | managed draft section in `submissions/SUBMISSIONS.md` | updates an opt-in managed draft tracker; curated submission ledgers are left untouched |
| 29 | `engagement-retro` | `engagement-retro.sh` | `RETROSPECTIVE.md` | records engagement-level lessons and pattern updates |
| 30 | `adversarial-copilot` | `adversarial-copilot.py --per-engagement` | `agent_outputs/adversarial_*.md` (break artifacts), `reference/patterns.dsl/_novelty/<slug>.yaml` (promotions) | Kimi 20/10 Step 5: dispute NOT-A-BUG verdicts in `agent_outputs/`; on `break` verdicts, emit candidate DSL pattern. SKIPPED when `adversarial-copilot.py` is missing or `agent_outputs/` is absent/empty (PR #202) |
| 31 | `post-audit-review` | `post-audit-review.sh`, `submission-sync.sh --apply-status` | stdout summary, refreshed `STATUS.md` header | prints submission-derived status and reconciles the confirmed-findings header when `STATUS.md` exists; degrades to `SUCCESS_WARN` when the review table runs but the follow-up `STATUS.md` sync still fails or has nothing to update |
| 32 | `corpus-detectorization` | `corpus-detectorization-inventory.py` | `<ws>/.auditooor/corpus_detectorization_inventory.{json,md}` | advisory PR #560 corpus inventory over mined corpora such as Swival, ZKBugs, Recon/Chimera, prior audit ingestion, and source-mining providers. Rows are impact-neutral detector/harness/source-review candidates until an exact impact contract proves a listed program-impact sentence |
| 33 | `campaign-source-mine` | `source-mining-campaign.py` | `source_mining/engage-latest/manifest.json`, `source_mining/engage-latest/survivors.json`, `source_mining/engage-latest/typed_candidate_promotions.{json,md}`, `source_mining/engage-latest/production_path_dossiers/*.json`, `source_mining/engage-latest/poc_tasks.{json,md}`, `source_mining/engage-latest/poc_task_briefs/*.md`, `deep_candidates/*.json` | expensive V5 G1 long-context source-mining hook. Part of the canonical stage table but **opt-in/no-op** unless `CAMPAIGN_SOURCE_MINE=1`; when enabled it requires `AUDITOOOR_LLM_NETWORK_CONSENT=1` and fails loudly without consent so operators do not misread a no-provider run as "0 survivors". Kimi extracts candidates, Minimax red-teams, the 4-step gate emits typed `deep_candidate.v1` records, and the campaign writes an immediate advisory promotion work queue, per-candidate production-path dossiers, PoC task queue, and dispatch briefs for downstream triage. Source-mining promotions require line citations and candidate-level production-path proof before `poc_ready`; missing production path stays `needs_poc` and privileged/mock/project-inaction paths become `unsafe_to_submit` with blocker categories and next actions |
| standalone | `rejection-learn` | `rejection-learn.sh` | classifier corpus update | not part of `--stage all`; use after real triager outcomes exist |
| standalone | `semantic-graph` (`make semantic-graph`) | `tools/semantic-graph.py --workspace <ws>` | `<ws>/.auditooor/semantic_graph.{json,md}` | advisory v1 workspace graph: Solidity entrypoints, caller role hints, state writes, external calls, value movement, test anchors, and scope/OOS annotations. Use before production-path adjudication, source-mining promotion, and critical-hunt. Conservative extractor, not a compiler proof. |
| standalone | `critical-hunt` (`make critical-hunt`) | `tools/critical-hunt.py --workspace <ws>` | `<ws>/.auditooor/critical_candidates.{json,md}` | opt-in high-impact surface shortlist over the semantic graph. Rows start as `needs_production_path`, carry `severity_claim=none`, and cannot be pasted as findings without a production-path dossier plus runnable PoC/replay. |
| standalone | `base-critical-matrix` / `base-critical-hunt` (`make base-critical-matrix`, `make base-critical-hunt`) | `tools/base-critical-candidate-matrix.py` / `tools/base-critical-hunt.py` | `<ws>/critical_hunt/base_critical_candidate_matrix.{json,md}`, `<ws>/critical_hunt/hunt_run.json`, `<ws>/critical_hunt/queue_summary.md` | Base-only critical-candidate wrapper. Exact selected listed-impact proof is required before a row can be executable: severity derives only from `listed_impact_selected`, `listed_impact_proven` must be true, and component-only Snappy/gossip evidence stays `NOT_SUBMIT_READY` / `kill_or_reframe`. Not part of `--stage all`. |
| standalone | `rust-decode-bomb-scan` (`make rust-decode-bomb-scan`) | `tools/rust-decode-bomb-scan.py --workspace <ws>` | `<ws>/critical_hunt/decode_bomb_scan/decode_bomb_candidates.{json,md}` | generic Rust/DLT advisory scanner for decode-bomb behavior candidates. Emits behavior rows only; every row needs an impact contract selecting one exact program-impact sentence before harness/report work. Snappy mempool impact is invalid. Not part of `--stage all`. |
| standalone | `base-rust-swival-shape-scan` (`make base-rust-swival-shape-scan`) | `tools/base-rust-swival-shape-scan.py --workspace <ws>` | `<ws>/critical_hunt/swival_shape_scan/base_rust_swival_shape_scan.{json,md}` | Base-only Swival-shape smoke wrapper. Rows start `NOT_SUBMIT_READY` and require exact-impact proof before PoC/harness/report promotion. Split into a workspace-neutral scanner before documenting it as generic. Not part of `--stage all`. |
| standalone | `severity-claim-guard` (`make severity-claim-guard`) | `tools/severity-claim-guard.py --workspace <ws>` | stdout gate over `<ws>/critical_hunt/base_critical_candidate_matrix.json` | candidate-matrix over-claim guard. Refuses Critical/High/Medium/direct-ready rows without exact selected-impact proof and blocks Snappy mempool/resource-threshold regressions. Integrated into pre-submit as Check #32; standalone target is useful after matrix edits. |
| standalone | `runtime-dlt-execution-evidence` (`make runtime-dlt-execution-evidence`) | `tools/runtime-dlt-evidence-validator.py --workspace <ws>` | `<ws>/.auditooor/runtime_dlt_execution_evidence_validator.{json,md}` | Runtime/DLT proof-accounting validator. Ingests explicit runtime records, Loop 5 evidence summaries, and impact-miss blocker queues; keeps terminal kills and blocked rows durable without promoting them. Rows require exact program-impact mapping plus a strict `poc_execution` manifest (`final_result=proved`, `impact_assertion=exploit_impact`, `evidence_class=executed_with_manifest`, and structured passing command evidence: `status=pass`, `exit_code=0`, non-empty `command`) before they can support a filing. Base Azul cleanup state is `NOT_SUBMIT_READY` despite non-zero rows. Not part of `--stage all`. |
| standalone | `high-impact-execution-bridge` (`make high-impact-execution-bridge`) | `tools/high-impact-execution-bridge.py --workspace <ws>` | `<ws>/.auditooor/high_impact_execution_bridge.{json,md}`, `<ws>/.auditooor/high_impact_execution_bridge/briefs/*.md` | Bridges High/Critical invariant-ledger rows into scaffold attempts, handoff briefs, and exact `make poc-execution-record ... RESULT=needs_human IMPACT=unknown` commands. Conditional `post-audit-review` follow-on when `<ws>/.auditooor/invariant_ledger.json` exists. Advisory readiness only: output is `NOT_SUBMIT_READY` and never proves impact without a real execution manifest. |
| standalone | `poc-execution-record` (`make poc-execution-record`) | `tools/poc-execution-record.py --workspace <ws> --brief <md>` | `<ws>/poc_execution/<candidate>/execution_manifest.json`, captured stdout/stderr logs for `--run` commands | records execution evidence for generated PoC task briefs. Includes candidate id, assigned model, workspace commit, semantic graph hash, commands attempted, artifact paths, impact assertion, and final result. Refuses `final_result=proved` unless `impact_assertion=exploit_impact`; downstream proof-readiness still requires `evidence_class=executed_with_manifest` plus structured passing command evidence (`status=pass`, `exit_code=0`, non-empty `command`). |
| standalone | `source-proof-record` (`make source-proof-record`) | `tools/source-proof-record.py --workspace <ws> --candidate <id>` | `<ws>/source_proofs/<candidate>/source_proof.json` | records source-only terminal evidence for candidates resolved by source review rather than a runnable PoC. Requires exact impact-contract linkage, source citations, and OOS status; `proved_source_only` is rewritten fail-closed unless the candidate has an exact impact contract, at least one valid citation, and `OOS=in_scope`. |
| standalone | `deep-counterexample-record` (`make deep-counterexample-record`) | `tools/deep-counterexample-record.py --workspace <ws>` | `<ws>/deep_counterexamples/*.deep_counterexample.v1.json` | common replayability schema for fuzz/symbolic/econ/math/crypto deep leads. Requires engine, target function, expected invariant, observed violation, and either replay command plus generated Forge test path or explicit replay-impossible reason. Deep leads without this stay advisory. |
| standalone | `deep-counterexample-collect` (`make deep-counterexample-collect`) | `tools/deep-counterexample-collect.py --workspace <ws>` | `<ws>/deep_counterexamples/*.deep_counterexample.v1.json`, `<ws>/deep_counterexamples/collection_manifest.json` | collects fuzz/symbolic runner `status=counterexample` manifests into the common schema. If the runner's `counterexample_path` file exists, its content is preserved as `input_sequence`; without `FORGE_TEST=<path>`, collected records remain advisory because the runner trace is not yet a generated Forge replay. |
| standalone | `deep-counterexample-replay-scaffold` (`make deep-counterexample-replay-scaffold`) | `tools/deep-counterexample-replay-scaffold.py <record>` | `<ws>/poc-tests/*_DeepCounterexampleReplay.t.sol` by default | generates a forge-std replay scaffold with engine, target, invariant, observed violation, input sequence, source replay command, and low-level replay call-block templates for simple Solidity-like trace lines. The test is intentionally `vm.skip(true)`; proof requires wired setup/target binding/assertions plus `make poc-execution-record RESULT=proved IMPACT=exploit_impact`. |
| standalone | `deep-counterexample-queue` (`make deep-counterexample-queue`) | `tools/deep-counterexample-queue.py --workspace <ws>` | `<ws>/deep_counterexamples/execution_queue.{json,md}` | turns normalized deep counterexamples into model-routed execution work: Kimi/Minimax for missing replay paths, Claude for skipped scaffold wiring, and Codex for final execution-manifest verification. Queue rows are not proof. |
| standalone | `p1-extraction-queue` (`make p1-extraction-queue`) | `tools/p1-source-archive-map.py --out-queue-json ... --out-queue-md ...` | `.audit_logs/p1_fixture_extraction/archive_map.{json,md}`, `.audit_logs/p1_fixture_extraction/extraction_queue.{json,md}` by default | issue #311 helper that converts fixture-less P1 source/archive inventory into concrete `p1-fixture-extractor.py` commands. Emits rows only for local/archive-backed source groups; missing-source groups stay inventory-only so agents cannot fabricate workspaces. Queue rows still require smoke-fire (`vulnerable >= 1`, `clean == 0`) before fixture promotion. |
| standalone | `p1-extraction-run` (`make p1-extraction-run`) | `tools/p1-extraction-queue-runner.py --queue <json>` | `.audit_logs/p1_fixture_extraction/execution_manifest.json`, `.audit_logs/p1_fixture_extraction/execution_report.md`, `.audit_logs/p1_fixture_extraction/p1_extraction_logs/*.txt` by default | issue #311 execution evidence helper. Reads queue rows, rejects rows that do not target `tools/p1-fixture-extractor.py`, executes without shell eval, captures stdout/stderr per row, writes JSON plus operator-readable Markdown, and records result counts. `ACCEPT=1` passes fixture promotion through to the extractor but should only be used after manifest/report review. The extractor smoke gate defaults to `--smoke-tier=ALL` so D-tier P1 archive rows are not rejected before their smoke-fire pair can prove them. |
| standalone | `zkbugs-ingest` (`make zkbugs-ingest`) | `tools/zkbugs-ingest.py --zkbugs-root <local-checkout>` | `.audit_logs/zkbugs_farming/zkbugs_index.{json,md}`, `.audit_logs/zkbugs_farming/briefs/*.md` by default | external corpus farming helper for `zksecurity/zkbugs` / `zkbugs.com`. Parses local `dataset/**/zkbugs_config.json`, cross-links local report PDFs/Markdown from `reports/reports.json`, recognizes extracted report `.txt` siblings created by `make extract DIR=<zkbugs-root>/reports/documents`, ranks those readable-report rows higher, and emits model-ready briefs. It never clones, scrapes, parses PDFs itself, or promotes findings; Kimi/Minimax/Claude use the briefs for bounded root-cause mining, while Codex requires smoke fixtures or replayable counterexamples before detector/PoC promotion. |
| standalone | `zkbugs-brief-queue` (`make zkbugs-brief-queue`) | `tools/zkbugs-brief-queue.py --brief-dir <briefs>` | `.audit_logs/zkbugs_farming/provider_queue/zkbugs_provider_queue.{json,md}`, `.audit_logs/zkbugs_farming/provider_queue/prompts/*.kimi.md`, `.audit_logs/zkbugs_farming/provider_queue/prompts/*.minimax.template.md` by default | builds provider-ready prompt packets from zkBugs briefs without making live provider calls. Kimi extracts one root-cause predicate per brief; Minimax receives a template that must include Kimi output and tries to kill broad/duplicate/toy-only candidates. Codex promotion still requires smoke-fire or replayable counterexample. |
| standalone | `zkbugs-provider-result` (`make zkbugs-provider-result`) | `tools/zkbugs-provider-result.py --brief <md> --kimi-output <out> --minimax-output <out>` | caller-selected result JSON and optional Markdown | records one live Kimi/Minimax zkBugs triage pass. Parses fenced JSON, preserves verdicts, and classifies the row as blocked, candidate-needing-Codex-evidence, rejected, or needs-human. This is provider evidence only; detector/PoC promotion still requires smoke-fire or replayable counterexample. |
| standalone | `zkbugs-provider-loop` (`make zkbugs-provider-loop`) | `tools/zkbugs-provider-loop.py --queue <zkbugs_provider_queue.json>` | `.audit_logs/zkbugs_farming/provider_results/zkbugs_provider_loop.json`, plus per-row Kimi/Minimax outputs, concrete Minimax prompts, and recorded provider-result JSON/Markdown | live resumable farming loop for the zkBugs provider queue. Requires explicit network consent and provider credentials, skips completed rows by default, continues past per-row failures, and records every completed Kimi→Minimax pair through `zkbugs-provider-result.py`. It is not a promotion gate; survivors still need Codex-produced smoke-fire or replayable counterexamples. |
| standalone | `circom-detect` (`make circom-detect`) | `tools/circom-detect.py <workspace>` | `<workspace>/audit/circom-detect.log` by default | lightweight `.circom` text detector lane for ZK circuit bug classes that do not yet have a stable parser-backed scanner. Detectors live under `detectors/circom_wave1/`, must expose `run_text(source, filepath)`, and should ship positive/negative fixtures plus unit tests before being used in mining. |
| standalone | `invariant-ledger` (`make invariant-ledger` / `make invariant-ledger-check`) | `tools/invariant-ledger.py --workspace <ws>` | `<workspace>/INVARIANT_LEDGER.md`, `<workspace>/.auditooor/invariant_ledger.json`, `<workspace>/.audit_logs/invariant_ledger_manifest.json` | **REQUIRED for High/Critical impact subsystems.** Sits between scope review (intake-baseline / orient / live-checks / `OOS_CHECKLIST.md` / `SEVERITY_CAPS.md`) and deep engines (`audit-deep`). A scoped subsystem capable of High/Critical impact must map to at least one invariant row before `make audit-deep` is treated as material coverage; for every High/Critical row, either a runnable harness/replay exists or a blocker is explicit (missing source, missing RPC, missing harness target, optional tool absent, OOS ambiguity, or source path not reachable). The shipped tool provides the schema plus `--check`, strict high-impact harness validation, generated invariant diffing via `--from-scope`, and closeout manifests. NOT part of `--stage all`. |
| standalone | `chimera-ledger-scaffold` (`make chimera-ledger-scaffold`) | `tools/chimera-ledger-scaffold.py --workspace <ws>` | `<workspace>/.audit_logs/chimera_scaffold_manifest.json`, optional `<workspace>/chimera_harnesses/<row>/...` | PR #524 Recon/Chimera bridge. Converts Solidity-shaped invariant-ledger rows into advisory Chimera-compatible harness scaffolds by calling `tools/chimera-scaffold.py` per row. `audit-deep` Step 0c exposes this as an opt-in bridge only when `AUDIT_DEEP_SCAFFOLD=1` or `--scaffold` is set; default `audit-deep` does not generate harness files. The audit-deep bridge defaults to strict handler-collision failure and supports `AUDIT_DEEP_CHIMERA_MAX_ROWS=<n>`. All outputs remain `scaffolded_unverified` until an execution manifest proves impact. NOT part of `--stage all`. |
| standalone | `audit-closeout` (`make audit-closeout`) | `tools/audit-closeout-check.py --workspace <ws>` | `<ws>/.audit_logs/audit_closeout_manifest.json` (when `WRITE_MANIFEST=1`) | **Codex P0 #1 follow-up (V5 Gap-23/24), V5-P0-17 detector-corpus wiring, and PR #560 artifact closeout.** Close-out gate: deterministic post-flight that asks "did the audit actually run?" Reads the artifact tree of a real `make audit` / `make audit-deep` invocation and prints PASS/WARN/FAIL rows. PR #560 coverage/worklist artifacts distinguish `blocked_missing_required_artifacts` from `open_impact_family_work`, so no verified candidate for a Critical/High row remains visible with concrete `impact_family_source_mining_queue` rows instead of being conflated with missing scan/graph artifacts. It includes `pr560-artifact-closure`, which summarizes unresolved blocked rows from `impact_contracts`, `harness_tasks`, `impact_analysis_queue`, `source_proof_tasks`, `source_proofs`, `corpus_detectorization_inventory`, and `known_limitations_burndown`; unresolved queue rows include representative exact `next_command` values in the human closeout table. Advisory rows stay WARN by default; `make audit-closeout WS=<ws> STRICT=1`, `REQUIRE_PR560_ARTIFACTS=1`, or `--require-pr560-artifacts` promotes missing/unresolved PR560 artifacts to FAIL. Stdlib-only, offline-safe. Run after `make audit` and (optionally) `DEEP_PROFILE=all make audit-deep`, before opening a submission PR. Front door: `make audit-closeout WS=<ws>`. NOT part of `--stage all`. |
| standalone | `audit-deep` (`--profile all`) | `tools/audit-deep.sh --profile all` | `<ws>/.audit_logs/audit_deep_all_manifest.json`, `<ws>/.audit_logs/audit_deep_all_report.md`, `<ws>/.audit_logs/cross_lane_correlations.json`, `<ws>/.audit_logs/typed_candidate_promotions.json`, `<ws>/.audit_logs/production_path_dossiers/*.json`, `<ws>/deep_counterexamples/collection_manifest.json`, `<ws>/deep_counterexamples/execution_queue.json` | bounded handoff sweep for Kimi/Minimax. Runs `default -> math -> econ -> crypto`, preserves child logs/reports, writes a manifest packet, then runs the cheap/default-on cross-lane file-overlap correlation, typed-candidate promotion report with `--require-production-path`, per-candidate production-path dossiers, deep-counterexample collector, and model-routed execution queue over fuzz/symbolic manifests. Tier B / advisory; not proof and not part of `--stage all`. Budget guard: `AUDIT_DEEP_ALL_MAX_SECONDS` (default 1800, `0` disables). |
| standalone | `audit-deep` (`--profile default`) | `tools/audit-deep.sh` | `<ws>/.audit_logs/audit_deep_report.md`, `<ws>/deep_counterexamples/collection_manifest.json`, `<ws>/deep_counterexamples/execution_queue.json` | v3 Slice 4 opt-in deep aggregator (halmos / medusa / echidna / slither). Not part of `--stage all`. Invoked via `make audit-deep WS=...` after `make audit`. Graceful-skip on missing tools, then auto-collects any fuzz/symbolic `status=counterexample` manifests into advisory records and writes a model-routed execution queue. See `docs/TOOL_COST_BENEFIT.md` |
| standalone | `audit-deep` (`--profile econ`) | `tools/audit-deep.sh --profile econ`, `tools/econ-actor-modeler.py` | `<ws>/.audit_logs/ACTORS.md`, `<ws>/.audit_logs/STATE_MACHINE.md`, `<ws>/.audit_logs/actors.json`, `<ws>/.audit_logs/state_machine.json`, `<ws>/.audit_logs/econ_deep_report.md` | **V4 P4** economic-security profile. **Tier B / advisory.** Reads `<ws>/economic_hypotheses/*.md` (output of stage 16) and emits an actor model + state machine + advisory report. The report explicitly distinguishes "economic plausibility" (always declarable) from "exploit proven" (requires PoC + concrete params); do NOT cite as exploit evidence. Invoke via `DEEP_PROFILE=econ make audit-deep WS=...` or `bash tools/audit-deep.sh --profile econ <ws>`. Per V4 §3.2 the new gate is submission-bound when used as evidence — Codex review is required when promoting `econ_deep_report.md` from advisory to submission-citable |
| standalone | `audit-deep` (`--profile math`) | `tools/audit-deep.sh --profile math`, `tools/math-invariant-miner.py` | `<ws>/math_invariants/MATH_SPEC.md`, `<ws>/math_invariants/math_spec.json` | **V4 P2** math-invariant mining profile. **Tier B / advisory.** Extracts accounting variables, conservation candidates, monotonicity hints, rounding hints, user inputs, and one-sided mutation candidates from Solidity sources. The report is mining guidance only; do NOT cite as exploit evidence without a downstream PoC or invariant proof. Invoke via `DEEP_PROFILE=math make audit-deep WS=...` or `bash tools/audit-deep.sh --profile math <ws>` |
| standalone | `audit-deep` (`--profile crypto`) | `tools/audit-deep.sh --profile crypto`, `tools/crypto-deep-runner.py` | `<ws>/.audit_logs/crypto_work_packet.json`, `<ws>/.audit_logs/crypto_deep_report.md` | **V4 P3** verifier / proof-system review profile (Workstream C). **Tier B / advisory.** Detects verifier-shaped contracts (Plonk/Groth/Risc0/SP1/Aggregate/Snark markers) under `<ws>/contracts` (or `<ws>` when no `contracts/` exists), classifies each section of `templates/crypto_verifier_review.md` against the V4 status vocabulary (`OPEN`, `RULED_OUT_WITH_LINES`, `DEFENSE_IN_DEPTH_ONLY`, `OOS_DEPENDENT`, `NEEDS_SPECIALIST`), and writes the rendered Tier-B advisory report. The runner NEVER emits `RULED_OUT_WITH_LINES` or `NEEDS_SPECIALIST` itself — those tokens are reserved for human review. Sections without verifier markers default to OPEN; sections with markers are classified as DEFENSE_IN_DEPTH_ONLY. Do NOT cite as exploit evidence. Invoke via `DEEP_PROFILE=crypto make audit-deep WS=...` or `bash tools/audit-deep.sh --profile crypto <ws>`. Per V4 §3.2 Codex review is required when promoting `crypto_deep_report.md` from advisory to submission-citable |
| standalone | `rejection-learn` | `rejection-learn.sh` | classifier corpus update | not part of `--stage all`; use after real triager outcomes exist |

## Failure Model

- Missing helper scripts usually produce `SKIPPED` and return success.
- `scan` is strict because downstream stages need detector logs.
- `--fail-fast` makes non-scan failures stop the chain instead of degrading.
- `--summary` prints the final stage table and is on by default.
- `--dry-run --summary` is the fastest way to confirm the current chain after
  editing `tools/engage.py`.

## Pre-Engage Workspace Bootstrap (V5-P0-06 / V5-P0-07)

Before the canonical chain, a fresh workspace must hold the small set of
operator files that downstream stages read. To avoid hand-editing 9+ stub
files (Monetrix-style failure mode), `tools/workspace-bootstrap.py` now
exposes an idempotent stub-seeding mode and `tools/skill-state.sh init`
itself is idempotent:

```bash
# Idempotent: re-running is a no-op when stubs already exist.
python3 tools/workspace-bootstrap.py --engage-stubs ~/audits/<project>

# Already idempotent on the orient stage: re-running succeeds when
# `.skill_state.yaml` carries the `auditooor.skill_state.v1` marker;
# unmarked / corrupt files are backed up to `.bak.<unix-ts>`.
bash tools/skill-state.sh ~/audits/<project> init
```

Engage-stubs seeded by `--engage-stubs`:

| Path | Consumed by |
|---|---|
| `SCOPE.md` | operator review, `dispatch-brief`, `llm-scope-triage` |
| `AUDIT.md`, `SESSION_LOG.md` | operator notes |
| `FINDINGS.md`, `SEVERITY.md`, `RUBRIC_COVERAGE.md` | operator review, severity gate |
| `targets.tsv` | engage stage 6+ contract enumeration |
| `SEVERITY_CAPS.md`, `OOS_CHECKLIST.md` | `extract-oos.sh`, `dispatch-brief.sh`, `llm-scope-triage.py` |
| `concolic/SUMMARY.md` | concolic / symbolic deep profile |
| `economic_hypotheses.md` | engage stage 16 (`economic-hypotheses`) |

Each stub carries `auditooor.bootstrap-version: 1`. Curated operator
content (no marker) is never overwritten on re-run; existing stubs are
left untouched whether or not they carry a marker.

## Out-of-Stage Deep Profiles

`tools/engage.py` is the canonical 32-stage orchestrator. Some advisory
work is NOT part of that chain on purpose. The opt-in `DEEP_PROFILE=...`
modes on `make audit-deep` (e.g. `DEEP_PROFILE=crypto` per V4 Workstream C
and `DEEP_PROFILE=math` per V4 Workstream B / P2) are Tier-B advisory and
intentionally excluded from `engage.py --stage all`. They are documented in
`docs/ENGAGE.md` ("When to use what") and `docs/TOOL_COST_BENEFIT.md`
("Opt-in deep profiles").

## Updating This File

When stage behavior changes, update these files together:

- `tools/engage.py` stage constants and docstring
- `docs/STAGE_REFERENCE.md`
- `docs/ENGAGE.md`
- `docs/WORKFLOW.md`
- `AGENTS.md` if agent operating instructions changed
