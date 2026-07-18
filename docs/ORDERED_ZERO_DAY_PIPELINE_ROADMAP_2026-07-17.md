# Ordered Zero-Day Pipeline Roadmap - 2026-07-17

## Purpose

This roadmap turns the current audit pipeline into a manifest-driven, fail-closed
system that can demonstrate three things mechanically:

1. Every applicable canonical step ran exactly when it was allowed to run.
2. Every producer fed fresh, typed evidence to every declared downstream consumer.
3. Every in-scope obligation reached an evidence-backed terminal verdict.

The objective is not to add another broad scanner wave. The objective is to make the
existing engines, substrates, reasoners, hacker questions, hunts, harnesses, fuzzing,
proof conversion, originality checks, and closeout gates operate as one auditable
zero-day discovery system.

The canonical step manifest currently contains 69 entries with `order_index` values
`0..68`. Index 68 is the final index, not the step count.

## Scope Of This Work

This is a generic control-plane and capability project. It must work unchanged across
new workspaces, languages, program rules, and repository layouts.

The workspaces below are read-only case studies and regression fixtures:

| Workspace | Main value as a fixture | Failure classes to reproduce |
|---|---|---|
| Obyte | JavaScript, Oscript, Solidity, cross-chain and heterogeneous repository layout | False language N/A, stale artifact credit, overloaded exploit queue, source-binding loss, chain synthesis starvation |
| Nuva | Go/Cosmos plus EVM and consensus-hook behavior | Repeated failed reruns, prior-audit and accepted-risk reconciliation, liveness-impact classification, executed-depth closure |
| Sei | Go, Rust, and Solidity in one workspace | Missing language reasoners, reasoner registry drift, stale source references, large blocked harness queues |
| Intuition | Solidity/EVM-focused control workspace | Clean applicability behavior, Solidity depth/fuzz ordering, GitHub-history reconciliation, current versus stale source-reference handling |

These workspaces are not to be re-audited as part of roadmap implementation. The
implementation may read existing manifests, receipts, logs, queues, and artifacts. It
must not start hunts, heavy engines, harness execution, fuzzing, or exploit conversion
unless a later operator instruction explicitly starts a workspace audit.

### Case-Study Operating Contract

The active focus set is exactly Nuva, Sei, and Obyte. This keeps roadmap work bounded
to three cross-language evidence sources rather than creating parallel audit campaigns.
Sei supplies the primary Go/Rust/Solidity cross-language control, while Obyte supplies
a second Solidity surface in a heterogeneous repository. Intuition is a dormant
Solidity-focused control fixture: use it only when its existing artifact shape is
needed to validate a generic behavior that the active three cannot demonstrate. They
are evidence sources for generic implementation decisions, not parallel audit targets.

Selection rule for each workpack:

1. Start with the one active workspace whose existing artifact most directly exposes
   the generic failure.
2. Cross-check with one of the other two active workspaces when compatible fixture
   evidence exists.
3. Consult Intuition only for a Solidity-specific gap that cannot be represented by
   Sei or Obyte artifacts.
4. Convert the minimal required metadata into a sanitized repository fixture, then
   stop. Do not progress any case-study audit stage to collect more evidence.

For each implementation slice, the coordinator must first state the generic invariant
being added, then select only the minimum case-study artifacts that demonstrate the
failure. The resulting repository test must use sanitized fixture data and must prove
the invariant without depending on a live workspace path, a current lead, or provider
output. A workspace artifact may establish that a defect existed; it may not become a
hard-coded production exception.

Permitted case-study actions:

- read committed workspace metadata, receipts, manifests, logs, and already-produced
  queue/history records;
- extract minimal synthetic fixtures with hashes and source identifiers redacted where
  necessary;
- run repository unit, integration, manifest, and fixture tests;
- compare a fixture's expected rejection or acceptance against the generic pipeline
  contract.

Prohibited case-study actions during roadmap implementation:

- `make audit`, `make audit-deep`, `make audit-pipeline-full`, `make audit-complete`, or
  any equivalent audit-stage command against a case-study workspace;
- LLM hunts, agent dispatches for source auditing, harness authoring, fuzzing, symbolic
  execution, exploit conversion, or submission work;
- workspace-specific patches, lead labels, verdicts, or artificial receipts used to
  force a generic test green.

The case-study matrix is intentionally cross-language:

| Generic control-plane property | Primary evidence fixture | Cross-check fixture |
|---|---|---|
| Ordered receipts, stale invalidation, heterogeneous applicability | Obyte | Sei |
| Known issue, accepted risk, fixed-versus-live distinction | Nuva | Obyte |
| Go/Rust/Solidity reasoner and consumer parity | Sei | Intuition |
| Solidity producer -> reasoner -> depth -> drive order | Intuition | Obyte Solidity surface |
| GitHub and source-comment awareness routing | Nuva | Sei |
| Queue separation and exact obligation closure | Obyte | Sei |

This matrix exists to prevent a local repair for one repository from being mistaken for
a generic capability. Every shipped control-plane fix needs one direct regression and
one cross-workspace regression whenever the relevant fixture data exists.

## Non-Negotiable Rules

1. Nothing in the canonical flow is optional or advisory.
2. An inapplicable step requires a machine-generated, evidence-backed N/A receipt.
3. A failed or missing step blocks every downstream step.
4. A producer rerun invalidates every downstream receipt that consumed its previous output.
5. Artifact presence is not proof that a step ran in the current run.
6. Console text is not a state transition or completion receipt.
7. Provider output is an input to local verification, never terminal proof.
8. `TOP_N` may prioritize scheduling but may not reduce the all-obligations closure denominator.
9. A terminal negative requires evidence and an exact immutable obligation identity.
10. No workspace-specific lead, path, contract, or project name may be embedded in generic tooling.

## Current Architecture Findings

### 1. Two Orders Exist But Are Not Executably Reconciled

The run order and conformance order are intentionally different concepts:

- Run order describes when commands execute.
- Conformance order describes the canonical numbered step inventory.
- Verdict precedence only controls failure-report presentation.

The current implementation does not encode the relationship between the first two as a
validated execution graph. The runbook stores `depends_on`, `reads`, `feeds`, and
`emit_artifact`, but those fields are mainly descriptive. The Makefile implements a
handwritten macro sequence instead of iterating 69 executable contracts.

Relevant sources:

- [`readme_runbook_steps.json`](../tools/readme_runbook_steps.json)
- [`Makefile`](../Makefile)
- [`readme-conformance-check.py`](../tools/readme-conformance-check.py)

### 2. `audit-deep` Crosses Phase Boundaries

The correct architecture requires the deep engine and substrate-producing portion before
reasoning, while harness authoring, drive work, and fuzz-related execution must happen
after reasoning, hunts, guards, and protocol invariants.

The current target is too broad. Reasoners can run before fresh deep outputs, and a later
deep pass can replace a substrate after its consumer reasoners already ran. The declared
reasoner regeneration step is not a mandatory, receipted transition.

Required correction:

```text
audit-deep-engine-substrates
  -> substrate producers
  -> reasoners
  -> reasoner freshness/regeneration gate
  -> hunt and depth
  -> protocol invariants
  -> harness and fuzz drive
```

### 3. Conformance Can Lose Applicable Steps

The conformance checker currently blocks only red steps with `required:true`. Seventeen
manifest entries are nonblocking even if their applicability conditions hold and their
artifacts are absent.

Language detection stops after a bounded filesystem walk. On Obyte, this produced an
empty language set and falsely classified 27 steps as N/A despite relevant source being
present.

Unknown artifact-check types also soft-pass. The manifest currently uses check types that
the checker does not implement.

### 4. Current-Run Freshness Is Not Proven

Artifact checks generally validate path presence, file size, or selected JSON fields.
They do not prove that the artifact was generated by the current run, from the current
scope, severity rules, pin, source snapshot, manifest, tool version, and upstream inputs.

This permits stale evidence to be reused or restamped after unrelated stages rerun.

### 5. Step-Order Enforcement Is A Partial Hook

The existing step-order hook recognizes only a small curated target set. It accepts one
nearest artifact-bearing predecessor, skips several classes of steps, and fails open on
missing workspace or parse context. It is useful only as defense in depth.

Order must be enforced inside the executor, not inferred from arbitrary shell text.

Relevant source:

- [`auditooor-step-order-gate.py`](../tools/hooks/auditooor-step-order-gate.py)

### 6. Reasoner Registries And Consumers Drift

The following sets are not mechanically equal:

```text
manifest reasoner steps
Makefile producer invocations
reasoner ledger registry
exploit-queue gatherers
hacker-question prompt routes
harness-plan routes
terminal-resolution registry
```

Some reasoners declared in the runbook are absent from the pre-hunt producer path. Other
registered ledgers are not represented in the runbook or exploit-queue consumers.

### 7. Obligation Closure Is Too Loose

Terminal resolution currently permits broad key fallback and weak terminal strings. One
function-level negative can therefore close several attack-class obligations without one
evidence record per obligation.

Required correction:

- Every obligation has one immutable `obligation_id`.
- Every terminal verdict names that exact ID.
- Every terminal verdict carries typed evidence.
- Group closure requires an explicit group manifest and per-member coverage.
- Provider prose, ungrounded text, or a bare status value cannot close work.

### 8. One Queue Carries Incompatible Row Types

The exploit queue currently mixes:

- corpus hunting fuel;
- unattempted coverage cells;
- reasoner obligations;
- generic hacker questions;
- source-grounded candidates;
- non-proof rows;
- terminal negatives;
- proof-ready candidates.

Existing workspace evidence shows the result. Thousands of rows reach binding, while zero
rows have executable proof contracts. This is repeated in Obyte, Sei, and Nuva, which
means the defect is generic rather than workspace-specific.

### 9. Originality And Awareness Are Not Strong Enough

Prior-audit novelty, GitHub-history reconciliation, and outcome learning still contain
lexical or weakly bound paths. Reviews can be credited across pin changes, partial prior
history can be labeled novel, and keyword-derived outcomes can influence unrelated
programs or languages.

Team awareness must be established before candidate promotion by semantic review of:

- prior audit findings;
- commits and diffs;
- pull requests and their comments;
- open and closed issues;
- discussions and maintainers' comments;
- source-code comments and TODOs;
- program-provided known-issue lists.

The classification rule is:

| Awareness state | Downstream treatment |
|---|---|
| Team aware, TODO, will wire, acknowledged, risk accepted, or intentionally deferred | Out of scope for filing; retained as exclusion evidence |
| Marked fixed and verified fixed at the audit pin | Closed known issue; retained as exclusion and regression evidence |
| Marked fixed but bypassable, incomplete, reverted, or absent at the audit pin | Eligible live-fix-bypass hypothesis requiring exact exploit proof |
| Review incomplete or source set partial | Unknown; blocks novelty and filing promotion |

Extraction may be automated with structured parsers. Awareness classification must be a
semantic review with source IDs and receipts, not regex-only classification.

### 10. Corpus Size Is Not The Main Constraint

The local corpus contains roughly 133,000 records and occupies roughly 2.4 GB. More rows
will not automatically improve zero-day yield. The main problems are record quality,
semantic deduplication, applicability, proof grounding, and delivery into the correct
reasoner and hunter context.

### 11. Existing Layered Logic Must Be Migrated, Not Reimplemented

The repository already contains useful layered logic from earlier audit workflows. The
ordered pipeline must consume these sources through typed adapters and receipts rather
than rebuild a second question library or exploit queue.

| Existing capability | Current source | Required ordered-pipeline role |
|---|---|---|
| Structured hacker-question library | `vault_hacker_questions` over `audit/corpus_tags/derived/hacker_questions_library.jsonl` | Q0-Q8 augmentation input, never terminal evidence |
| Per-function question composition | `vault_per_function_hunter_brief`, `per-function-hacker-questions.py`, `hacker_question_renderer.py` | Bind questions to a unit, obligation ID, revision ID, and source snapshot before dispatch |
| Detector-to-substrate bridge | `audit-hacker-logic-bridge.py`, `proof-obligation-queue.py` | Produce current-run, typed pre-hunt inputs from fresh substrates only |
| Reasoner obligations | `*_obligations.jsonl`, `logic-obligation-resolution-check.py` | Require one exact terminal disposition per immutable obligation |
| Existing queue and lane bus | `exploit-queue.py`, `lane-verdict-bus.py` | Consume typed projections only; do not allow raw mixed queue rows to become proof tasks |
| Provider hunting | `ordered-llm-hunt.py` and the existing provider dispatch adapters | Consume frozen questions after Phase 2; provider output remains nonterminal hunt evidence |
| Proof conversion and closeout | `current-to-exploit-conversion-gate.py`, `exploit-conversion-loop.py`, `audit-completeness-check.py` | Run only after the ordered drive prerequisites and require executable proof or an evidence-backed terminal negative |

The following are explicitly non-authoritative until migrated behind the canonical
executor: planning-only chain output and standalone V3 provider-fanout campaigns. They
may supply evidence to a typed input adapter but cannot create a step receipt, satisfy a
closure denominator, or weaken a failed canonical gate.

### 12. Legacy Soft Paths Are A Removal Target

The repository still has direct Makefile routes that print warnings and continue after
some chain-synthesis, conversion, or obligation-bridge failures. Those routes must not
be reachable from `audit-pipeline-full`, and their legacy targets must either delegate to
the canonical executor or fail with a clear migration error. A hard pipeline cannot be
made dependable while an alternate public target can credit a later stage after an
earlier producer or consumer failed.

Required migration tests:

- invoke each public audit-stage target with a deliberately failed dependency and verify
  that it exits nonzero without creating a later-step receipt;
- verify direct targets cannot write canonical receipts unless the executor issued the
  current run token;
- verify a legacy queue, provider, or chain-planning artifact is rejected unless a typed
  adapter binds it to the current obligation and revision identities.

## Target Pipeline

```text
PHASE 0 - Intake truth
  scope + severity + pin + toolchain + program rules + awareness history

PHASE 1 - Fresh substrates
  audit mechanics + deep engine outputs + dataflow + value flow + state coupling
  + authority/trust + deployment/config + PISVS + oracle reachability

PHASE 2 - Reasoning
  typed reasoners + novelty + assumption negation + flow-fed hacker questions

PHASE 3 - Drive
  source hunt + follow-up hunt + guard/depth analysis + protocol invariants
  + obligation-driven harness authoring + mutation-verified fuzzing
  + executed-depth and exploit conversion

PHASE 4 - Verification
  depth planes + all-obligations terminal closure + proof-quality validation

PHASE 5 - Close
  audit-complete STRICT=1 + audit-done-guard
```

## Workstream 0 - Manifest V2

Extend the canonical manifest so every step declares an executable contract:

```json
{
  "step_id": "step-...",
  "order_index": 0,
  "run_sequence": 0,
  "phase": "reasoning",
  "execution_target": ["python3", "tools/example.py"],
  "applicability_probe": "probe-id",
  "depends_on": ["step-id"],
  "consumes": ["artifact-contract-id"],
  "produces": ["artifact-contract-id"],
  "validators": ["validator-id"],
  "invalidates": ["downstream-step-id"],
  "terminal_output": false
}
```

Build a static manifest validator that fails on:

- unknown artifact checks or validators;
- missing execution targets;
- missing or forward-invalid dependencies;
- undeclared producer or consumer edges;
- orphan outputs without `terminal_output:true`;
- duplicate producers without merge semantics;
- cycles;
- mismatched order indexes;
- missing applicability probes;
- a reasoner ledger absent from any registry or consumer.

Acceptance:

- All 69 entries validate.
- Every applicable step has an executable target.
- Every conditional step has a deterministic applicability probe.
- Every output has at least one declared consumer or is explicitly terminal.

## Workstream 1 - Receipt-Driven State Machine

Create one executor that owns pipeline state. Valid states are:

```text
pending
running
succeeded
not_applicable
failed
invalidated
```

Each receipt must include:

```text
run_id
manifest_sha256
workspace_identity_sha256
source_snapshot_sha256
scope_sha256
severity_sha256
targets_sha256
program_rules_sha256
step_id and order_index
attempt
status
applicability probe, inputs, result, and hash
exact argv and selected environment
start and finish timestamps
exit code
upstream receipt IDs
input artifact paths and hashes
output artifact paths, hashes, sizes, and semantic validator results
stdout and stderr hashes
tool and toolchain versions
```

Transition rules:

1. A step starts only after every required predecessor has a current terminal receipt.
2. `not_applicable` is terminal only when its applicability receipt validates.
3. A failed step blocks all later run-sequence entries.
4. A retry increments the attempt for that step.
5. Changed inputs invalidate the step and its transitive consumers.
6. Resume is permitted only when workspace, source, scope, manifest, and pin hashes match.
7. Closeout requires exactly 69 terminal receipts.

Direct helper targets may remain available for development, but their outputs cannot earn
canonical run credit without a valid executor-issued step token and receipt.

## Workstream 2 - Split `audit-deep`

Create explicit targets with disjoint ownership:

| Target | Runs before reasoning | Runs after reasoning |
|---|---:|---:|
| `audit-deep-engine-substrates` | Yes | No |
| `audit-deep-depth-probe` | No | Yes |
| `audit-deep-drive` | No | Yes |
| Manifest steps `step-3e` through `step-3k` | No | Yes |

The engine/substrate target produces only static, formal, semantic, dataflow, and graph
evidence. It must not author harnesses or run fuzz campaigns.

The drive target consumes reasoner obligations, hunt verdicts, guards, depth evidence, and
the protocol invariant ledger. It may author harnesses and execute the appropriate proof
engines.

A mandatory freshness gate runs between phase 2 and phase 3. If any substrate changed
after its reasoner ran, the reasoner is invalidated and rerun before hunt begins.

## Workstream 3 - Typed Artifact And Obligation Bus

Replace free-form `reads`, `feeds`, and queue joins with stable artifact contracts.

Minimum substrate families:

| Substrate | Required information |
|---|---|
| Scope/deployment | In-scope units, pin, deployed components, authorities, live configuration |
| Dataflow/control | Entry points, call edges, def-use, guard dominance, sinks |
| Value flow | Assets, balances, credits, debits, mint, burn, transfer, settlement |
| State coupling | Variables and contracts that must update together |
| Lifecycle | State machines, transitions, queues, retries, timeout, pause, cleanup |
| Authority/trust | Roles, delegation, upgrade rights, message authenticity, trust boundaries |
| Oracle/economics | Price sources, update windows, liquidity, capital, fees, timing |
| Differential | Multiple implementations, versions, encoders, validators, and specs |
| History/awareness | Prior findings, issues, comments, fixes, reverts, accepted risks |

Every reasoning output uses one schema containing:

```text
obligation_id
producer_step_id
reasoner_id and version
substrate receipt IDs and hashes
target unit, file, function, contract, and source references
attacker and victim actors
preconditions
transition sequence
expected invariant
suspected violation
impact rubric row and severity cap
OOS and team-awareness references
proof task kind
required positive assertions
required negative controls
kill condition
consumer routes
```

Add a parity gate that proves equality across manifest reasoners, producer invocations,
ledger registry, obligation adapters, hacker-question routing, proof planning, and terminal
resolution.

## Workstream 4 - Awareness And Originality Ledger

Build one pin-bound semantic ledger for prior audits, GitHub history, and code comments.

Each reviewed source has:

```text
source_type
repository and pinned commit
stable source ID or URL
source snapshot hash
reviewer/provider receipt
root cause
affected component and code anchor
impact
status
team awareness
fix reference
fix verification state at pin
dedup class
required remediation primitive
```

Candidate originality is decided using a finding-level triple:

```text
root cause
affected execution path
required fix
```

An impact escalation alone does not establish novelty when the same root cause and fix are
already known. A partial source review cannot emit `novel`; it emits `unknown` and blocks
promotion.

## Workstream 5 - Hacker Questions As Proof Specifications

Generate one falsifiable question per obligation. A question must include:

- exact target and source slice;
- upstream substrate path;
- attacker-controlled inputs;
- relevant guards and why they may be insufficient;
- exact state transition sequence;
- expected invariant;
- impact rubric and severity cap;
- known-issue and OOS context;
- proof method;
- kill condition;
- required evidence for a positive or negative verdict.

Generic corpus questions may enrich an obligation, but they may not replace target-specific
questions derived from current substrates.

Each question terminates as one of:

```text
proved_exploitable
source_refuted
execution_refuted
duplicate_or_known
out_of_scope
not_applicable
failed_missing_required_evidence
```

The final state is deliberately not `advisory`, `maybe`, or `follow-up`. Missing evidence
keeps the step failed and blocks closeout.

## Workstream 6 - Separate Queues

Replace the overloaded exploit queue with typed stores or typed projections:

| Queue | Admission requirement | Terminal requirement |
|---|---|---|
| Coverage obligations | In-scope unit and impact/mechanism frame | Driven or machine N/A |
| Hunt obligations | Typed reasoner or coverage obligation | Evidence-backed hunt verdict |
| Candidate leads | Current source refs and plausible impact path | Killed, known/OOS, or promoted |
| Proof tasks | Runnable proof contract and exact assertions | Executed proof or executed/source refutation |
| Findings | Executed proof plus scope, impact, and originality clearance | Paste-ready gate result |
| Terminal negatives | Exact obligation ID plus evidence | Immutable terminal receipt |

Scheduling priority is independent from closure accounting. Processing the top ten tasks
does not remove the remaining tasks from the denominator.

## Workstream 7 - Harness And Fuzz Drive

Fuzzing remains late in phase 3. It runs only after:

1. Intake and history reconciliation are current.
2. Substrates are fresh.
3. Reasoners and hacker questions emitted obligations.
4. The source hunt resolved reachability and guard questions.
5. Depth analysis identified reachable or unresolved paths.
6. Protocol-specific economic invariants were authored.

The harness-plan schema contains:

```text
source obligation ID
real code under test
setup and fixture requirements
attacker actions
sequence constraints
guard assertions
invariant assertions
exploit-impact assertions
negative and clean controls
mutation description
engine and replay command
terminal receipt paths
```

Fuzz acceptance requires the existing real-coverage thresholds where applicable, including
mutation verification and campaign evidence. No-counterexample fuzz output does not close
an obligation whose claim requires source proof, symbolic proof, differential execution,
live-state proof, or multi-validator consensus evidence.

## Workstream 8 - New Zero-Day Substrates And Reasoners

Build new reasoners only after Workstreams 0-7 can prove their outputs are consumed.

Priority reasoner families:

1. Async queue and lifecycle state-machine completeness.
2. Pause, resume, retry, timeout, cancellation, cleanup, and backlog interactions.
3. Cross-chain finality, reorg, timeout, refund, replay, and acknowledgement ordering.
4. Governance proposal, veto, timelock, execution, and upgrade ordering.
5. Initialization, migration, storage-layout, and deployment/config divergence.
6. Multi-contract asset conservation and partial-commit recovery.
7. Share, debt, collateral, reward, and fee accounting conservation.
8. MEV-sensitive order-dependent settlement and execution-window feasibility.
9. Oracle manipulation with live liquidity, capital, timing, and unwind constraints.
10. Serialization, parser, and consensus-validation differentials.
11. Cross-implementation and implementation-versus-spec divergence.
12. Reverted, incomplete, stale, and bypassable fix reasoning.
13. Test-fixture assumptions versus production deployment state.
14. Error-handling, must-succeed, panic, resource, and permanent-state liveness.
15. Composition search over typed state transitions rather than keyword overlap.

Every new reasoner ships with:

- a declared substrate contract;
- vulnerable and clean fixtures;
- a mutation demonstrating the fixture detects the missing protection;
- an obligation adapter;
- a hacker-question renderer;
- a proof-plan route;
- terminal-resolution tests;
- cross-language applicability tests;
- a held-out regression case where possible.

## Workstream 9 - Corpus Quality And Learning

A hunting-grade corpus record must contain:

```text
exploit primitive
root cause
violated invariant
attacker and preconditions
transition sequence
affected component
impact
required fix
vulnerable evidence
clean or fixed control
language and protocol applicability
source provenance
verification tier
triager outcome and rationale
```

Records missing these fields remain intake material. They may generate review tasks but may
not establish novelty, severity, terminal negatives, or detector accuracy.

Learning is partitioned by exploit primitive, language, domain, program rules, and outcome
reason. Title-keyword counts do not directly reweight unrelated workspaces.

Every real terminal outcome updates at least one of:

- corpus record quality;
- reasoner prior;
- hacker-question template;
- detector fixture;
- proof-plan template;
- OOS/known-issue rule;
- negative control;
- regression test.

## Case-Study Validation Plan

### Obyte

Use existing artifacts to test:

- language detection without bounded-walk false N/A;
- JavaScript, Oscript, and Solidity applicability receipts;
- stale substrate invalidation;
- chain synthesis receiving typed invariant and source-link inputs;
- separation of 7,000-plus corpus-fuel rows from actual proof tasks;
- current source-reference normalization.

No new Obyte hunt, fuzz campaign, or proof conversion is part of this workstream.

### Nuva

Use existing artifacts to test:

- accepted-risk and known-issue semantic classification;
- marked-fixed re-verification at the audit pin;
- duplicate root-cause and remediation matching;
- blocker fingerprinting that prevents identical failed reruns;
- liveness impact distinctions and evidence requirements;
- executed-depth terminal closure.

No new Nuva vulnerability adjudication is part of this workstream.

### Sei

Use existing artifacts to test:

- one workspace containing Go, Rust, and Solidity;
- all applicable language reasoners represented in the parity gate;
- missing reasoners blocking before hunt;
- stale source-reference rejection at admission rather than proof binding;
- typed queue projection under a large candidate population.

No new Sei source hunt or submission review is part of this workstream.

### Intuition

Use existing artifacts as the Solidity-focused control:

- Solidity/EVM applicability and machine N/A for unrelated languages;
- engine/substrate reasoning before harness and fuzz drive;
- GitHub-history receipts bound to pin and target hashes;
- current versus stale source-reference behavior;
- invariant and fuzz worklist ordering.

No new Intuition fuzzing or audit progression is part of this workstream.

## Regression Fixtures

Extract minimal sanitized metadata fixtures from the workspaces rather than copying whole
audit directories into the repository. Fixtures should contain only the structures needed
to reproduce a control-plane defect:

- manifest rows;
- applicability inputs;
- artifact metadata and hashes;
- queue row schemas;
- receipt chains;
- source-reference examples;
- history-review records;
- expected gate verdicts.

Do not embed active lead names or workspace-specific finding text in generic production
logic. Workspace names may appear only in test fixture names and case-study documentation.

## Delivery Sequence

### Slice 1 - Execution truth

Files or ownership areas:

- manifest schema and validator;
- receipt schema;
- state-machine executor;
- applicability probes;
- current-run and invalidation tests.

Exit criteria:

- A synthetic 69-step fixture cannot skip, reorder, stale-credit, or falsely N/A a step.
- Unknown check types fail manifest validation.
- A changed producer hash invalidates all transitive consumers.

### Slice 2 - Pipeline split and parity

Files or ownership areas:

- `audit-deep` split targets;
- reasoner freshness gate;
- reasoner registry parity;
- direct-target canonical-credit restrictions.

Exit criteria:

- No harness or fuzz drive runs before reasoning and depth prerequisites.
- Every declared reasoner has producer, ledger, queue, question, and resolution routes.

### Slice 3 - Awareness and source identity

Files or ownership areas:

- semantic awareness ledger;
- GitHub/pin fingerprinting;
- prior-audit semantic decisions;
- source-reference normalization.

Exit criteria:

- Known/team-aware candidates cannot enter proof queues.
- Partial history cannot produce a novel verdict.
- Marked-fixed candidates require current-pin fix verification.

### Slice 4 - Queue and obligation migration

Files or ownership areas:

- obligation schema;
- queue projections;
- exact terminal joins;
- hacker-question proof specifications;
- all-obligations closure accounting.

Exit criteria:

- Corpus fuel never reaches harness binding.
- A bare terminal string cannot close an obligation.
- Priority limits do not change the closure denominator.

### Slice 5 - Proof drive

Files or ownership areas:

- harness-plan contracts;
- fuzz/symbolic/differential routing;
- proof-task admission;
- terminal evidence validators.

Exit criteria:

- Every proof task is runnable or the pipeline fails before proof dispatch.
- Every negative is tied to exact evidence and obligation identity.

### Slice 6 - Zero-day expansion

Files or ownership areas:

- new substrates;
- new reasoners;
- held-out exploit and mutation fixtures;
- corpus quality and learning updates.

Exit criteria:

- New reasoners improve held-out recall or proof conversion yield.
- No new reasoner ships without complete downstream routing.

## Acceptance Metrics

The roadmap is successful when all of the following are measured:

| Metric | Required result |
|---|---:|
| Canonical step receipts | 69 of 69 terminal |
| Applicable red steps ignored | 0 |
| Machine N/A receipts | 100% of inapplicable steps |
| Unknown manifest checks | 0 |
| Stale artifact credit | 0 |
| Orphan producer outputs | 0 |
| Reasoner registry parity | 100% |
| Obligation exact-ID terminalization | 100% |
| Unresolved applicable obligations at closeout | 0 |
| Corpus-fuel rows entering proof queues | 0 |
| Proof tasks missing source or command contracts | 0 |
| Candidate history reviews bound to current pin | 100% |
| Provider-only terminal verdicts | 0 |
| Workspace-specific branches in generic tools | 0 |

Quality metrics must also track:

- held-out exploit-class recall;
- mutation-fixture kill rate;
- source-grounded candidate precision;
- candidate-to-runnable-proof conversion;
- duplicate and known-issue rejection before proof spend;
- average reruns per unchanged blocker fingerprint;
- time spent per evidence-backed terminal verdict;
- accepted, duplicate, rejected, and paid outcome calibration by domain.

## Implementation State - 2026-07-17

This section is the current build ledger. It distinguishes merged control-plane work,
the active integration batch, and capabilities that remain deliberately blocked.

### Merged To Main

| Batch | Main merge | Result |
|---|---|---|
| Roadmap | `045a5fe309` | Added this generic implementation roadmap and read-only workspace fixture plan |
| Pipeline receipts | `34fb93f93d` | Added signed, self-hashed Step V2 receipts |
| Manifest validation | `be0899cc3a` | Added structural validation for steps, targets, probes, artifacts, and routes |
| Dispatch gate | `0fb06c15a1` | Preserved hard provider-dispatch failures instead of warning through them |
| State machine | `672a64a57e` | Added exact ordered state transitions, attempts, failure blocking, and invalidation |
| Applicability and conformance | `8fcc307af8` | Added canonical applicability, deterministic inventory, and strict conformance foundations |
| Typed proof handoff | `47993cad5c` | Materializes the Step 4e immutable envelope at the canonical persisted path consumed by terminal proof readers |
| Commit awareness intake | `c4889fe994` | Step 0d now produces bidirectional GitHub commit history before mandatory awareness discovery |
| Multi-repo awareness identity | `47e0a12b02` | Commit inventory IDs bind both upstream repository and SHA, preventing cross-repository provenance collisions |

### Active Integration Batch

The active batch makes the manifest executable rather than documentary:

1. `audit-pipeline-full` validates the V2 manifest and delegates only to
   `tools/pipeline-executor.py`.
2. All 69 manifest rows declare `required:true`; applicability is represented by a
   validated `not_applicable` receipt, never by optionality.
3. The executor enforces `run_sequence` 0 through 68, exact predecessor tokens,
   selected-environment allowlists, current-run output freshness, transitive
   invalidation, and source/tooling baseline restarts.
4. `validate_existing` is restricted to attested manual intake authorities. Mechanical
   producers must recreate or refresh their output during the current attempt.
5. Step 0a now produces `.auditooor/last_mcp_recall.json`; it no longer claims that a
   long-lived `reference/` directory proves current execution.
6. Step 0g precedes Step 1 and materializes the authoritative in-scope inventory and
   coverage plane.
7. Step 1c is all-language and strict. Missing inventory, unknown languages, degraded
   arms, truncation, stale rows, and zero claimed coverage block later steps.
8. Step 2, Step 4, and Step 2c have disjoint strict runner modes. The runner must not
   move harness authoring or fuzz campaigns before reasoning.
9. Step 2h no longer reruns reasoners by modification time. It freezes the current
   receipt graph into a typed obligation bus and Q0-Q8 question set.
10. Step 3 uses an ordered provider runner. `TOP_N` changes scheduling priority only;
    every typed question remains in the dispatch and closure denominator.
11. Strict README conformance revalidates every current receipt and rehashes its output
    artifacts from disk.
12. The canonical Step 1 environment sets `AUDITOOOR_CANONICAL_STRICT=1`. In that
    mode `audit-dispatch`, `audit-progress`, `engage`, and the Step 1 Make tail reject
    fail-fast overrides, malformed present JSON, warning-stage promotion, swallowed
    producer failures, and early completion-marker writes. Direct development targets
    retain their existing noncanonical diagnostics behavior.
13. The depth verification tools now run with `--strict` from their manifest rows.
    Starved semantic inputs, parser degradation, unresolved hypotheses, or uncited
    terminal dispositions cannot become a pass by producing a report file.
14. Step 4c and the novelty flywheel produce typed fuel only through a deterministic
    identity map derived from the current reasoner receipt graph. A fuel row must bind
    exactly to an obligation and revision before the Step 2h freeze can consume it.
15. Step 4c now emits two receipt-bound artifacts: a semantic hunt report and typed
    JSONL fuel. The freeze compiler rejects a mismatched report/fuel pair and rejects
    empty fuel unless the current report proves that no eligible corpus candidate or
    hacker question existed. A zero-byte fuel file alone cannot close a hunt stage.
16. A standalone fail-closed contract now exists for semantic awareness classification.
    The next slice must make it a canonical executor input; standalone validation is not
    a completion signal. Existing manifest validation remains the single route-parity
    authority rather than creating a second registry.
17. The retired `_audit-pipeline-full` shell transcript now rejects direct invocation
    before it can run any stage or create canonical executor state. The public
    `audit-pipeline-full` target remains the only full-run entrypoint and delegates to
    the 69-step manifest executor.
18. A typed proof-admission adapter now validates the current frozen Step 2h bus before
    it can create a separate Step 4e handoff queue. Every actionable row must name an
    exact current obligation and revision. The adapter preserves the established queue
    envelope for downstream migration, does not mutate the producer queue, and is not
    yet wired into conversion until every producer has an exact parent adapter.
19. A canonical proof-queue projection now derives one stable queue row per frozen
    obligation from the fully validated Step 3 Q0-Q8 sidecar set. It validates the
    complete current hunt denominator before projection, retains provider output only
    as nonterminal evidence, and never matches legacy queue rows by title, function,
    source location, or producer-local identifiers. Conversion wiring remains blocked
    until its mutating consumers preserve this immutable row envelope.
20. A typed proof-envelope verifier now derives a deterministic manifest from the
    admitted queue and compares every later queue by exact lead ID, obligation/revision
    parent, frozen receipt, source-row hash, selection ordinal, Q0-Q8 evidence hash,
    and admission identity. It rejects dropped, injected, or remapped rows. It permits
    additive local proof fields only. Consumer migration remains blocked until each
    mutating consumer invokes this verifier before handing work to the next stage.
21. `harness-binding-manifest` now validates an admitted typed queue through that
    verifier before conversion and carries the exact immutable envelope entry into
    each derived harness row. A malformed or mixed typed queue fails before harness
    planning; legacy queues remain discovery-only and cannot impersonate typed rows.
22. `candidate-judgment-packet` now validates an admitted typed queue before
    filtering it and carries each selected row's exact immutable envelope into the
    packet. Typed queues cannot include a second legacy `entries` bucket, preventing
    local judgment from silently mixing discovery rows into canonical proof work.
23. `source-mined-impact-contracts` now validates an admitted typed queue before
    enrichment and carries each exact immutable envelope into its impact-contract
    ledger. Its optional queue patch remains additive and cannot replace a typed
    parent with a source-mined identifier.
24. `exploit-queue-terminal-join` now detects admitted typed queues, rebuilds their
    immutable envelopes, and permits a negative terminalization only from a
    source-cited `zero_day_proof_terminal_verdict.v1` record whose parent pair and
    envelope ID exactly match the queue row. Title, function, contract, lead-ID,
    generated-code, and unanchorable fallbacks remain limited to legacy discovery
    queues and cannot close a typed proof obligation. It verifies the persisted
    admitted envelope before mutation and the additive terminal result before writing.
25. `prefiling-stress-test`, `prove-top-leads`, and `candidate-judgment-packet` now
    verify the persisted admitted envelope before they exclude a typed row as terminal.
    A bare terminal status is still sufficient for a legacy discovery row, but an
    admitted row must carry the exact parent pair, envelope ID, and source citation in
    its typed terminal record. A mixed typed/legacy queue is structurally rejected
    before any envelope lookup.
26. `audit-completeness-check` conversion throughput now verifies the persisted
    admitted envelope before it credits any terminal row. A malformed or stale typed
    queue hard-fails the signal, and a typed status token earns no terminal credit
    without an exact, source-cited terminal record. Legacy discovery queues retain
    their separate evidence-backed compatibility path.
27. The Step 2h freeze compiler now consumes reviewed awareness bindings as exact
    five-field obligation identities. It emits an auditable exclusion row for each
    team-aware/accepted/deferred obligation, never derives that binding from prose or
    similarity, and blocks when a novelty-blocking awareness candidate is unbound or
    does not map to a current obligation. Marked-fixed-but-live candidates remain in
    the bus for the separate fix-bypass proof path.
28. Step 4c now applies those reviewed awareness exclusions before it writes a proof
    queue, MIMO batch, or fuel row. Strict mode rejects an unlinked applicable corpus
    candidate before any downstream consumer can observe it.
29. The pre-freeze identity map now projects an explicit Step 4c binding edge only
    from a reasoner ledger's declared `broken_invariant_ids` and `function` fields.
    It produces separate hypothesis and hacker-question keys, rejects duplicate keys
    as ambiguous, and does not use titles, paths, or prose similarity to bind corpus
    work to an obligation.
30. A hacker-question record that names multiple invariant IDs is expanded into one
    proof obligation per declared invariant before filtering, queueing, MIMO, or fuel.
    An unlinked question is retained as an explicit strict failure rather than dropped.
31. Oscript now has an executable `ocore` parser adapter that obtains AA objects and
    formula ASTs from the real Nearley grammar. It emits parser-backed trigger-to-
    message records with syntactic confidence and degrades when the declared parser
    dependency is unavailable; it is not yet credited as semantic SSA coverage.
32. The dataflow router dispatches Oscript through that parser-backed adapter as a
    distinct language arm. The legacy JavaScript arm cannot overwrite Oscript rows,
    and the language contract records AST-backed evidence while continuing to block
    all semantic dataflow, reasoner, engine, depth, and fuzz credit.
33. The Step 0d awareness ledger is now a semantic executor-validated artifact and
    an explicit Step 4c input. The corpus-driven novelty filter cannot receive
    canonical credit without a current pin-bound ledger with complete source coverage
    and terminal reviewed candidate decisions; a JSON-shaped partial ledger fails.
34. Generic queue-to-ledger bridging now preserves a typed reasoner proof contract
    (`question`, invariant, falsification control, proof-task kind, and terminal
    condition) into prompts and harness plans. Advisory hypotheses retain that
    context for investigation but are blocked from harness and execution credit.
35. Awareness coverage is now instance-complete, not merely source-kind-complete.
    The current Step 0d ledger requires exact equality between the discovered,
    pin-bound source inventory and the semantically reviewed evidence rows; missing,
    extra, or mismatched records block Step 4c novelty credit.

The canonical manifest currently validates with all three split deep targets declared.
Focused manifest, executor, state, receipt, conformance, strict dataflow, and migrated
Makefile-order suites are green. No case-study workspace engine, hunt, harness, fuzz, or
exploit-conversion stage was run to obtain those results.

### Typed Zero-Day Bus

The active bus uses these immutable identities:

```text
obligation_id = H(target_unit, asset_invariant, violation_relation,
                  actor_model, impact_class)

revision_id = H(obligation_id, source_snapshot, substrate receipts,
                scope, severity, targets, program rules, tooling)
```

The bus is append-only. Two rows with the same logical obligation and different source
content are a conflict, not a last-writer-wins update. Every consumer must name the exact
`obligation_id` and `revision_id` it received.

The layered question cascade is:

| Axis | Question layer | Required outcome |
|---:|---|---|
| Q0 | Asset and invariant | Name the protected asset/state and the exact relation that must hold |
| Q1 | State transition | Identify the before state, action, and after state |
| Q2 | Adversarial sequence | Construct the attacker-controlled ordering and preconditions |
| Q3 | Assumption negation | Negate each trusted assumption and identify its enforcing guard |
| Q4 | Cross-module composition | Trace shared state, authority, callbacks, and partial commits across modules |
| Q5 | Production reachability | Prove the path exists at the audit pin without mock, test, or privileged shortcuts |
| Q6 | Economic or consensus impact | Measure the exact rewarded impact and all program thresholds |
| Q7 | Dedup, OOS, and awareness | Compare root cause, path, and fix against audits, GitHub, and source comments |
| Q8 | Executable falsification | Run the positive assertion and clean negative control |

No provider response can terminalize these questions. The provider produces hunt evidence;
local source, execution, live-state, differential, or proof evidence produces terminal
verdicts.

### Language Truth Matrix

The language contract records the minimum trustworthy capability rather than treating a
file extension as proof of analysis:

| Language | Parser/extractor | Dataflow | Reasoners | Depth and drive status |
|---|---|---|---|---|
| Solidity | Tree-sitter/Slither-capable | Slither-backed semantic paths when the strict backend receipt proves it | Several Solidity and cross-language reasoners exist | Real Foundry/Slither routes exist but must prove non-stub mutation and campaign evidence |
| Go | AST plus Go compiler tooling | `go/ssa` is semantic only when the receipt proves `semantic-ssa`; fallback output cannot earn semantic credit | Go consensus, arithmetic, replay, race, and protocol reasoners exist | Native test/fuzz routes exist; missing package/toolchain coverage blocks |
| Rust | AST plus Rust compiler tooling | `rustc` MIR is semantic; tree-sitter and regex fallbacks are shape-only and cannot earn semantic credit | Rust account, arithmetic, panic, and MPC reasoners exist | Native mutation/fuzz routes exist; fallback-only evidence blocks |
| JavaScript | Acorn AST | AST output is below the required semantic tier and cannot earn dataflow credit | No complete language-specific reasoner set yet | Applicable engine, depth, and fuzz roles block until production routes exist |
| Oscript | `ocore` parser and Nearley formula AST when the declared parser dependency is present | Parser-backed trigger-to-message paths are syntactic only, not semantic dataflow | No complete Oscript reasoner set | Applicable semantic engine, depth, and drive roles remain blocked pending a production interpreter or equivalent semantic route |

This blocking behavior is intentional. A truthful unsupported-applicable verdict is better
than silently treating lexical or enumerator output as a completed audit phase.

### Remaining Generic Work

1. Register and verify actual compiler or IR-backed semantic engine commands for
   Solidity, Go, and Rust. The deep phase now packages the current Slither, Go SSA,
   or rustc MIR receipt and matching semantic paths into a fresh per-language engine
   contract; stale source snapshots, AST/shape rows, and degraded records are rejected.
   The default registry now accepts the canonical strict-dataflow receipt schema
   end-to-end rather than a test-only spelling; it still needs workspace-level
   execution coverage against real compiler outputs. Strict receipts now bind the
   arm command and result digests to a deterministic semantic-row artifact hash;
   Step 2 rejects a semantic receipt without that execution provenance.
2. Finish semantic backend receipts for JavaScript, TypeScript, Vyper, and Oscript. The Oscript
   parser-backed substrate is now wired separately from the legacy enumerator, but it cannot satisfy
   semantic requirements. A
   fallback backend must be visible and must not satisfy a stronger tier.
3. Inventory and regression-test immutable-envelope verification across every remaining
   mutating queue consumer and closeout projection. The conversion loop now projects,
   admits, and materializes the typed queue before proof work, selects it over raw
   discovery ledgers, and verifies its envelope after impact enrichment and terminal
   joining. Legacy raw ledgers remain discovery inputs only.
4. Migrate any remaining terminal consumer and closeout projection to the exact
   terminal-verdict schema. `prove-top-leads`, `queue-proof-hard-close`, and the
   `prove_top_leads_no_leads` producer/completeness/closeout path and
   `logic-obligation-resolution-bridge` now enforce that rule for admitted queues;
   closeout delegates to the canonical completeness validator rather than keeping a
   second policy copy. Title, function-name, and lead-ID fallback joins are permitted
   only for legacy discovery queues and can never close typed obligations. Remaining
   terminal readers still need inventory-backed migration. Direct no-leads,
   completeness closeout, lead proving, and prefiling stress now also verify the
   persisted Step 4e immutable envelope, so a rebuilt post-mutation queue cannot
   receive terminal credit.
5. Split coverage, hunt, candidate, proof-task, finding, and terminal-negative stores.
   The canonical zero-day projection now declares `queue_role=proof_tasks`.
   Step 4e admission and the immutable envelope both reject every other role
   before it can become an admitted or verified proof queue. The remaining stores
   still need dedicated projections and readers.
6. Complete source-inventory producers across prior audits, commits, pull requests,
   open and closed issues, discussions, review comments, source comments, and
   known-issue lists. The pin-bound ledger now requires an exact discovered-to-reviewed
   inventory match. Step 0d now produces the bidirectional GitHub commit input,
   including every enumerated commit in a separate unclassified inventory, and
   repository-qualified source identities. GitHub discussion enumeration now includes
   every paginated top-level comment and reply. Remaining work is complete semantic
   review coverage for every discovered instance. Source comments remain contextual
   reviewer work; lexical matching can only select review work and cannot assign an
   OOS disposition.
7. Add sanitized Obyte, Nuva, Sei, and Solidity-control fixtures for applicability,
   invalidation, known-issue exclusion, and queue routing.
   The fixture matrix now executes the authoritative applicability evaluator and
   semantic awareness ledger for Obyte/Oscript, Go, Rust, and Solidity-control
   dispositions, then verifies the Step 2h immutable-obligation consumer removes
   only exact reviewed known issues. It also proves that a changed credited substrate
   invalidates the producer and all transitive reasoner, depth, and drive consumers
   before any rerun credit is granted.
8. Add universal lifecycle, conservation, authority, composition, fix-bypass, and
   differential reasoners only after the bus proves their outputs reach every consumer.

## Immediate Next Workpack

The first bounded implementation workpack should own only new execution-control files and
their focused tests. It should not modify workspace artifacts or run any workspace stage.

Suggested initial ownership:

```text
tools/pipeline-manifest-validate.py
tools/pipeline-receipt.py
tools/pipeline-state-machine.py
tools/tests/test_pipeline_manifest_validate.py
tools/tests/test_pipeline_receipt.py
tools/tests/test_pipeline_state_machine.py
tools/fixtures/pipeline_state_machine/
```

After that isolated slice passes, migrate the existing Makefile and conformance readers to
the new contracts in separate, reviewable commits. This avoids mixing execution truth,
reasoner dataflow, and workspace-specific artifact cleanup in one change.

## Definition Of Done For This Roadmap

This roadmap itself does not certify any workspace and does not change audit status.

The implementation is complete only when:

1. The manifest validator and receipt executor are the canonical execution authority.
2. Every current pipeline step is migrated to an executable contract.
3. Obyte, Nuva, Sei, and Intuition fixture tests reproduce and prevent the documented generic failures.
4. All producer-consumer and obligation-terminalization parity gates pass.
5. A clean, explicitly authorized workspace run produces 69 valid terminal receipts in order.
6. `make audit-complete WS=<workspace> STRICT=1` prints `pass-audit-complete`.
7. `python3 tools/audit-done-guard.py <workspace>` prints `DONE` with return code 0.
