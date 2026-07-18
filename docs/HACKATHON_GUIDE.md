# Hackathon Guide

This page is the public review path for auditooor. It is intentionally small:
review the executable contracts, their tests, and the evidence boundaries before
reading the historical operator material in this repository.

## What This Demonstrates

auditooor is a fail-closed audit control plane for Solidity, Go, Rust, and
language-specific extensions. It turns an audit workspace into ordered,
source-bound work: substrates, reasoning obligations, hunt questions, proof
tasks, and terminal evidence.

The current design is defined by:

- [Ordered zero-day roadmap](ORDERED_ZERO_DAY_PIPELINE_ROADMAP_2026-07-17.md)
- [Machine-readable 69-step runbook](../tools/readme_runbook_steps.json)
- [Pipeline state machine](../tools/pipeline-state-machine.py)
- [Manifest validator](../tools/pipeline-manifest-validate.py)
- [Receipt contract](../tools/pipeline-receipt.py)

The pipeline's critical property is ordering: fuzzing and harness execution are
phase-3 proof-drive work. They cannot earn canonical credit before intake,
substrates, reasoning, history/awareness reconciliation, guards, and proof
contracts are current.

## Judge Review

The public repository is self-contained for control-plane code and test review.
It includes the pipeline implementation, detector definitions, and offline
fixtures. It does not include the canonical historical corpus, operator audit
workspaces, Obsidian memory, provider transcripts, API keys, prior-audit
archive, live-chain evidence, or a target project's source and scope package.

Useful checks:

```bash
make judge-demo
make judge-check
make docs-check
```

Start with `make judge-demo`: it validates the production manifest, summarizes
the required contracts and typed reasoning handoffs, and demonstrates that the
state machine blocks early Drive, empty closeout, and tampered state before
they can become credit. The [judge walkthrough](JUDGE_WALKTHROUGH.md) explains
the commands and the evidence boundary.

`make docs-check` is the portable documentation check for this public build.
It intentionally excludes private vault indexes, historical corpus maps, and
generated operator inventories that are not distributed to judges.

Private sources are optional operational memory only. If a required source is
not present, the pipeline must preserve that as a visible evidence gap rather
than inventing a pass, a novel finding, or a terminal verdict.

The suite verifies all 69 required pipeline contracts rather than finding
vulnerabilities. Twenty-six steps have language applicability probes, but an
inapplicable result still receives a canonical receipt rather than being
skipped. Without a target workspace the suite executes zero meaningful audit
steps. To run applicable steps, a reviewer must provide a workspace with a
scope and severity rubric, pinned source checkout, and relevant language
toolchain. Live claims also require the target's applicable access and evidence
configuration.

## AI-Assisted Engineering

- **Codex** implemented and reviewed control-plane integration, ordering,
  artifact contracts, tests, and repository hygiene.
- **GPT-5.6** was used for deep reasoning on cross-language threat models,
  reasoner structure, layered adversarial questions, and evidence review.

AI responses are inputs, not proof. A candidate must still clear scope,
originality, impact, production-path, and executable or source-grounded
evidence checks.

## Historical Material

The remaining dated playbooks, handoffs, campaign notes, and tool inventories
exist for provenance. They are not the public onboarding path and do not
override the roadmap or runbook above.
