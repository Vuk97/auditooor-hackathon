# auditooor

auditooor is an operator-run security research toolkit for smart contracts and
protocol code. It turns a scoped workspace into source-grounded obligations,
ranked attack surfaces, proof tasks, executable evidence, and fail-closed
submission checks.

It does not file reports automatically. The operator owns scope, severity,
toolchain setup, evidence review, and submission.

## Hackathon Build

This project was built and hardened with AI-assisted engineering:

- **Codex** implemented and reviewed control-plane changes, strict artifact
  contracts, pipeline ordering, test coverage, and repository integrations.
- **GPT-5.6** was used for deep reasoning over audit flow, cross-language
  threat models, reasoner design, and adversarial review of the evidence path.

AI output is never treated as proof. Every reportable result still requires
current source binding, scope and duplicate clearance, and executable or
source-grounded verification.

## Judge Mode

The repository is intended to be reviewable without the operator's private
Obsidian vault, prior-audit archive, API tokens, or local audit workspaces.
Those materials are not part of the hackathon deliverable.

This public checkout does not include the canonical historical tag corpus,
private prior-audit archives, generated corpus indexes, model sidecars,
operator reports, provider transcripts, or private target artifacts. Commands
therefore validate the control plane and public fixtures; a full production
audit additionally needs an operator-provided workspace and its own evidence.

The vault is optional operator memory. Judges can inspect the pipeline,
fixtures, tests, and generated workspace artifacts from this repository
without access to private notes. A missing private-memory source must remain a
visible capability gap, never become fabricated evidence or a hidden pass.

### What Judges Can Verify

| Available in this checkout | Deliberately not included |
| --- | --- |
| Ordered 69-step pipeline contracts, validators, and executors | Private Obsidian vault and operator memory |
| Offline fixtures and the judge test suite | Private audit workspaces and prior-audit downloads |
| Public detector definitions and offline fixtures | Historical corpus, API keys, provider transcripts, RPC credentials, and live-chain evidence |
| Documentation and fail-closed evidence rules | A target project's scope, severity rubric, pinned source, and toolchain |

The judge path proves the control-plane behavior: it validates all 69 required
step contracts for order and fail-closed evidence handling. Twenty-six steps
have a language applicability probe, but an inapplicable result still requires
a canonical receipt - it is not a skip. The path executes no meaningful audit
step without a target workspace, so it does not reproduce a production audit
or prove a vulnerability. That requires an operator-supplied workspace and the
target-specific inputs listed below.

## Pipeline

The canonical workflow is ordered:

1. **Intake**: scope, severity rubric, audit pin, toolchain, and coverage plane.
2. **Substrate**: inventory, dataflow, semantic engines, state coupling, PISVS,
   and oracle-reachability evidence.
3. **Reasoning**: typed obligations, Q0-Q8 adversarial questions, novelty, and
   awareness reconciliation.
4. **Drive**: hunt, depth, protocol invariants, real fuzzing, and exploit conversion.
5. **Verify and close**: terminal evidence, completeness gates, and strict status.

The machine-readable source of truth is
[tools/readme_runbook_steps.json](tools/readme_runbook_steps.json). The ordered
zero-day capability plan is
[docs/ORDERED_ZERO_DAY_PIPELINE_ROADMAP_2026-07-17.md](docs/ORDERED_ZERO_DAY_PIPELINE_ROADMAP_2026-07-17.md).

## Install

Requirements for the public review path are `git`, `bash`, `make`, and
`python3 >= 3.10`. `make bootstrap` creates a repository-local virtual
environment, installs Python dependencies,
and runs the read-only `make judge-check` sanity gate. It does not install
global packages or regenerate tracked detector artifacts.

~~~bash
git clone https://github.com/Vuk97/auditooor-hackathon.git auditooor-hackathon
cd auditooor-hackathon
make bootstrap
~~~

Target-specific tools are deliberately separate: Solidity projects need their
project compiler/test stack, Go projects need Go, Rust projects need Rust, and
Obyte AA runtime tests need Node/npm plus the workspace's installed
`aa-testkit` dependencies.

## Judge Test Path

After installation, this focused public suite validates the ordered pipeline
contract without needing an audit workspace, private vault, API key, or network
provider:

~~~bash
make judge-check
~~~

The expected result is a green test suite and a strict documentation check with
zero broken links. This verifies that all 69 canonical steps have executable,
ordered contracts; it does not claim that a target workspace has been audited.
The test path is offline after dependency installation and does not need the
private vault or the historical corpus.

## Five-Minute Judge Tour

Run the executable walkthrough after bootstrap:

~~~bash
make judge-demo
~~~

It validates the real manifest, summarizes all 69 required contracts by phase,
checks that Reasoning precedes Drive, then asks the real state machine to start
Drive early. The expected result is a visible
`earlier_run_sequence_blocks` rejection. This is an enforcement demonstration,
not a claim that any target was audited.

For the review sequence and the exact evidence boundary, read the
[judge walkthrough](docs/JUDGE_WALKTHROUGH.md).

## Run A Workspace

Create a workspace:

~~~bash
python3 tools/workspace-bootstrap.py \
  --name <project> \
  --platform <cantina|immunefi|sherlock|hackenproof|other> \
  --scope-url <program-scope-url>
~~~

Before starting, provide SCOPE.md, SEVERITY.md, a pinned src/ checkout, and
the target language toolchain.

Run the ordered pipeline:

~~~bash
make audit-pipeline-full WS=~/audits/<project>
~~~

For the public review path and focused verification commands, use the
[hackathon guide](docs/HACKATHON_GUIDE.md).

## Evidence Boundary

A candidate becomes fileable only when it proves:

- an in-scope, attacker-reachable production path;
- a concrete impact matching the program rubric;
- no duplicate, known, accepted, or out-of-scope disposition;
- an executable PoC or equally strong source-grounded evidence;
- clean negative controls and terminal evidence for the claimed behavior.

make audit-complete WS=<workspace> STRICT=1 is the strict closeout gate. Do not
claim completion without its pass-audit-complete verdict.

## Languages

Solidity, Go, and Rust receive semantic credit only from real language backends:
Slither/compiler-derived paths, Go SSA, and Rust MIR. Parser or AST-only output
is investigation evidence, not semantic proof.

JavaScript and Oscript remain explicitly blocked where no production semantic
backend, reasoner, depth route, or fuzz route exists. Unsupported-applicable is
safer than fabricated coverage.

For Obyte autonomous agents, `tools/oscript-aa-testkit-runner.py` discovers and
can execute existing workspace-local `aa-testkit` suites during the late proof
drive. Its receipt is runtime evidence only and does not grant semantic,
reasoner, depth, or fuzz credit.

## Useful Commands

~~~bash
bash tools/auditooor-session-start.sh ~/audits/<project>
make audit WS=~/audits/<project> STRICT=1
make audit-deep WS=~/audits/<project> STRICT=1
bash tools/pre-submit-check.sh <draft>.md --severity <Severity>
make docs-check
~~~

## Documentation

- [Hackathon guide](docs/HACKATHON_GUIDE.md)
- [Judge walkthrough](docs/JUDGE_WALKTHROUGH.md)
- [Ordered zero-day roadmap](docs/ORDERED_ZERO_DAY_PIPELINE_ROADMAP_2026-07-17.md)
- [Machine-readable 69-step runbook](tools/readme_runbook_steps.json)
- [Documentation index](docs/README.md)

The public repository contains only the maintained judge documentation. The
private canonical repository retains operational history and the full corpus.
