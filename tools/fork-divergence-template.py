#!/usr/bin/env python3
"""fork-divergence-template.py — generate filing template for fork-vs-upstream
divergence findings.

Empirical anchor: dydx cantina-018 cometbft fork-lag blocksync verification —
dYdX cometbft fork at audit-pin SHA `904204b11c9e` lacked v0.38.22 silently-
shipped blocksync hardening patches (PRs #5757/#5753/#5711/#5629/#5718).
Pattern: pinned fork falls behind upstream security-fix series.

This tool generates a Markdown skeleton with the canonical sections required
by Rule 13 (advisory-ID scrub), L29-Filing (impact contract), and the
Cantina paste template.

CLI
---
    --fork-repo OWNER/REPO       (e.g. dydxprotocol/cometbft)
    --fork-pin SHA               (audit-pin SHA on fork)
    --upstream-repo OWNER/REPO   (e.g. cometbft/cometbft)
    --upstream-version VER       (e.g. v0.38.22)
    --component PATH             (e.g. blocksync/reactor.go)
    --bug-class STR              (e.g. "verification gap")
    --severity {LOW,MEDIUM,HIGH,CRITICAL}
    --out FILE                   (default stdout)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

TEMPLATE = """\
# {title}

- Severity: {severity}
- Asset: {asset_placeholder}
- Component: `{component}`
- Audit-pin fork SHA: `{fork_pin}` on `{fork_repo}`
- Upstream reference: `{upstream_version}` on `{upstream_repo}`

## Summary

The `{component}` path in `{fork_repo}` at audit-pin `{fork_pin}` lags upstream
`{upstream_repo}` `{upstream_version}` and is missing {bug_class} hardening
that upstream silently shipped in the referenced version. Result: the listed
impact below is reachable on the fork at audit-pin even though the upstream
codebase has closed it.

## Trigger

{trigger_placeholder}

## Impact

{impact_placeholder}

## Severity Justification

{severity_justification_placeholder}

## Likelihood

{likelihood_placeholder}

## Source-Only Justification

{source_only_placeholder}

## Real-Component Precondition

{precondition_placeholder}

## Impact Contract

- selected_impact: {selected_impact_placeholder}
- severity_tier: {severity}
- listed_impact_proven: {listed_impact_proven}
- evidence_class: {evidence_class}
- oos_traps: {oos_traps_placeholder}
- stop_condition: {stop_condition_placeholder}

## Scope and Originality

- In-scope: `{component}` exists at audit-pin `{fork_pin}`; verify by `git
  ls-tree {fork_pin} -- {component}` against the fork.
- Not previously filed: scope-check against engagement workspace
  `submissions/filed/` and `paste_ready/filed/` for substring overlap on
  `{component}`.
- Upstream divergence anchor: `{upstream_repo}` at `{upstream_version}` ships
  the protection (cite PR numbers + commit SHAs after enumeration).

## Proof of Concept

```go
// PoC test scaffold — replace with actual runtime-verified test against
// audit-pin fork via Go module replace.
package {component_pkg_placeholder}_test

func Test{bug_class_camel_placeholder}_ReachableAtAuditPin(t *testing.T) {{
    // 1. Pin fork-repo to {fork_pin} via replace directive
    // 2. Construct adversarial input that upstream {upstream_version} would reject
    // 3. Assert the fork accepts it (i.e. the hardening is missing)
}}
```

Suite result: REPLACE WITH ACTUAL `ok` LINE FROM `go test -v` RUN

### What the tests prove

REPLACE WITH 2-4 BULLET POINTS DESCRIBING WHAT THE PASSING TEST DEMONSTRATES.

## Recommended Fix

Cherry-pick the upstream protection from `{upstream_repo}` `{upstream_version}`
into the fork at the next release. Specifically, port the PRs that introduced
the {bug_class} hardening (enumerate after operator review).

---

<!--
fork-divergence-template version: 1.0
generated: {generated_iso}
empirical anchor: cantina-018 cometbft fork-lag (dydx 2026-05-08)
-->
"""


def slug(s: str) -> str:
    return "-".join(s.lower().split())


def title_case(s: str) -> str:
    return "".join(w.title() for w in s.split())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fork-repo", required=True)
    ap.add_argument("--fork-pin", required=True)
    ap.add_argument("--upstream-repo", required=True)
    ap.add_argument("--upstream-version", required=True)
    ap.add_argument("--component", required=True)
    ap.add_argument("--bug-class", required=True)
    ap.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    default="HIGH")
    ap.add_argument("--asset", default="<select Cantina/Immunefi asset row>",
                    help="asset selector to fill in")
    ap.add_argument("--out", default="-", help="output file or - for stdout")
    args = ap.parse_args()

    repo_short = args.fork_repo.split("/")[-1]
    title = (
        f"{args.bug_class.capitalize()} in {repo_short} fork at audit-pin "
        f"enables impact via {args.component} divergence from "
        f"{args.upstream_repo} {args.upstream_version}"
    )
    if len(title) > 120:
        # Trim long titles to ≤120 (Cantina template limit).
        title = title[:117].rstrip() + "..."

    component_pkg = Path(args.component).parent.name or "fork"
    rendered = TEMPLATE.format(
        title=title,
        severity=args.severity,
        asset_placeholder=args.asset,
        component=args.component,
        component_pkg_placeholder=component_pkg.replace("-", "_"),
        bug_class_camel_placeholder=title_case(args.bug_class),
        fork_pin=args.fork_pin,
        fork_repo=args.fork_repo,
        upstream_version=args.upstream_version,
        upstream_repo=args.upstream_repo,
        bug_class=args.bug_class,
        trigger_placeholder="REPLACE WITH ADVERSARIAL INPUT / CALL-SITE",
        impact_placeholder="REPLACE WITH RUBRIC-VERBATIM IMPACT SENTENCE",
        severity_justification_placeholder=(
            "REPLACE WITH RUBRIC-MATCH ARGUMENT + cluster-tier evidence cite"
        ),
        likelihood_placeholder="REPLACE WITH likelihood class + reasoning",
        source_only_placeholder=(
            "REPLACE WITH source-only-justification (if applicable)"
        ),
        precondition_placeholder="REPLACE WITH live deployment / operator-pin precondition",
        selected_impact_placeholder=(
            "REPLACE WITH rubric-verbatim impact phrase"
        ),
        listed_impact_proven=(
            "true" if args.severity in ("HIGH", "CRITICAL") else "false"
        ),
        evidence_class="fork-replay",
        oos_traps_placeholder="REPLACE WITH OOS-trap enumeration",
        stop_condition_placeholder=(
            "fix lands in fork (i.e. cherry-pick of upstream patch series)"
        ),
        generated_iso=_dt.datetime.now(_dt.timezone.utc).isoformat(),
    )

    if args.out == "-":
        sys.stdout.write(rendered)
    else:
        Path(args.out).write_text(rendered, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
