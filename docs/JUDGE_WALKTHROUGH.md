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
pipeline state machine. It shows three concrete properties:

1. The manifest has 69 required, sequenced step contracts.
2. Reasoning contracts come before the hunt, depth, fuzz, and exploit-conversion
   drive contracts.
3. A direct attempt to start the first Drive contract is rejected with
   `earlier_run_sequence_blocks` before any earlier phase has a receipt.

`make judge-check` then runs the offline regression suite. It covers manifest
shape, receipt integrity, state transitions, executor authority, phase order,
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
| Solidity, Go, Rust, and language-specific extension routing | detector definitions and applicability contracts |
| Reproducible regression review | offline `make judge-check` suite |

The full historical corpus and private operator workspaces remain intentionally
outside this repository. They are inputs to real engagements, not prerequisites
for verifying the public control-plane claims.
