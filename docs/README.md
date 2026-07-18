# Documentation

This directory contains the public technical documentation for auditooor.
Start at the repository [README](../README.md) for the hackathon overview and
quick-start path.

## Current Public Review Path

- [Hackathon guide](HACKATHON_GUIDE.md): public review path, evidence boundary,
  and focused verification commands.
- [Judge walkthrough](JUDGE_WALKTHROUGH.md): executable review sequence and
  control-plane capability map.
- [Ordered zero-day roadmap](ORDERED_ZERO_DAY_PIPELINE_ROADMAP_2026-07-17.md):
  current capability plan and strict phase ordering.
- [Machine-readable 69-step runbook](../tools/readme_runbook_steps.json):
  canonical step order and applicability bands.

## Public Boundary

The public export intentionally omits private operator memory, engagement
artifacts, provider transcripts, historical corpora, and generated reports.
It is sufficient to inspect the ordered control plane and execute its offline
judge suite. A real audit additionally requires a target workspace, scope,
severity rubric, pinned source, and applicable toolchain.
