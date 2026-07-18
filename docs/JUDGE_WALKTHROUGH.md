# Judge Walkthrough

This is a short, executable review of auditooor's control plane. It needs no
target workspace, private vault, historical corpus, API key, or live-chain
access.

## Run It

```bash
make bootstrap
make judge-demo
make judge-check
```

`make judge-demo` executes the production manifest validator and the production
pipeline state machine. It shows six concrete properties:

1. The manifest has 69 required, sequenced step contracts.
2. Reasoning contracts come before the hunt, depth, fuzz, and exploit-conversion
   drive contracts.
3. The real manifest contains typed artifact contracts and a reasoner route for
   every registered reasoner. Each route reaches a queue, hacker question,
   proof-conversion, and closeout-resolution consumer.
4. A direct attempt to start the first Drive contract is rejected with
   `earlier_run_sequence_blocks` before any earlier phase has a receipt.
5. Empty closeout is rejected because it has zero current receipts, rather than
   receiving a cosmetic pass.
6. A tampered durable state is rejected by its self-hash check.

`make judge-check` then runs the offline regression suite. It covers manifest
shape, receipt integrity, state transitions, executor authority, phase order,
semantic-backend admission for Solidity/Go/Rust fixtures, awareness-evidence
admission, reasoner-to-question generation, unsupported-applicable blocking,
and documentation links.

## What The Demo Is Not

The demo does not audit a target or claim a vulnerability. A production audit
still needs an in-scope target workspace, severity rubric, pinned source, and
applicable language toolchain. That boundary is deliberate: absent private or
target-specific evidence stays a visible gap and cannot become a pass.

## Capability Map

The public checkout exposes the control-plane implementation behind the audit
workflow:

| Capability | Public evidence |
| --- | --- |
| Ordered intake, substrate, reasoning, drive, verification, and close | 69-step manifest and state machine |
| Artifact provenance and freshness | receipt schema and state-machine tests |
| Fail-closed out-of-order prevention | `make judge-demo` blocked early-drive attempt |
| Reasoning-to-proof handoff | manifest-derived reasoner, queue, question, proof, and resolution route counts |
| Closeout and durable-state integrity | `make judge-demo` empty-closeout and tamper rejections |
| Solidity, Go, Rust, and language-specific extension routing | detector definitions and applicability contracts |
| Reproducible regression review | offline `make judge-check` suite |

The full historical corpus and private operator workspaces remain intentionally
outside this repository. They are inputs to real engagements, not prerequisites
for verifying the public control-plane claims.
