#!/usr/bin/env python3
# r36-rebuttal: lane escalate-first-gate-diag registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""escalate-first-required-check.py - Rule 14 / A7 escalate-first-then-narrow gate.

Closes the "max-escalate-then-fully-prove" loophole.

The problem
-----------
Rule 14 / A7 doctrine (CLAUDE.md) says: ALWAYS max-escalate to the higher tier
and attempt full end-to-end execution FIRST; only then narrow to the lower tier
if the higher-tier proof cannot be built. The upside-asymmetric calculus is:
worst case a CRITICAL filing is triager-amended down to HIGH = the same outcome
as filing HIGH directly, so attempting CRITICAL first is free.

But the mechanical enforcement never required the escalation ATTEMPT. R40
(tools/v3-grade-poc-check.py) returns ``pass-claim-narrowed`` as a clean PASS the
instant a draft contains honest-narrowing phrasing ("downstream tail is
source-traced, not separately executed", "claim narrowed to the source-level
gap", "severity walks back"). R42 (tools/configured-impact-trace-check.py)
likewise returns ``pass-claim-narrowed``. Neither gate asks "did you TRY the
higher tier and full execution first, or did you narrow on the first pass to
duck the work?" A draft that silently downgrades CRITICAL -> HIGH and writes the
narrowing prose sails through every gate.

Empirical anchor (hb-bsc-epoch-ancestry-validator-injection-HIGH, 2026-05-28)
----------------------------------------------------------------------------
The BSC epoch-ancestry validator-set injection finding installs an
attacker-chosen validator set into a production BSC light client - a
consensus trust-root compromise whose natural end state is theft of bridged
funds (CRITICAL "direct loss of funds"). The draft narrowed to HIGH with the
prose "the downstream forged-state-root -> unauthorized cross-chain asset
movement is source-traced, not separately executed". R40 returned
pass-claim-narrowed; R42 returned pass-claim-narrowed; the draft was filed at
HIGH. No artifact in the finding folder documents an ATTEMPT to execute the
downstream theft end-to-end against the real verifier + a downstream consumer,
nor a Rule-14 escalate-first decision. The escalate-first doctrine existed and
the advisory tool (triager-amend-asymmetry.py) existed, but nothing forced the
attempt before the narrowing was accepted.

What this gate does (it is a COMPANION to R40/R42, not a replacement)
---------------------------------------------------------------------
For a Medium+ draft whose narrowing demonstrably walks away from a HIGHER tier
(CRITICAL end-to-end / direct-loss / theft / fund-drain framing present in the
draft AND a tier-narrowing statement present), the draft MUST contain an
"Escalate-First Attempt" record proving the higher tier was attempted before
the narrowing was accepted. The record must show ONE of:

  (a) escalate-first-attempted: an explicit statement that the higher tier
      (CRITICAL / end-to-end) full execution was attempted, plus the concrete
      blocker that prevented it (what could not be built / executed / reached),
      so the narrowing is a forced fallback, not a first-pass duck; OR
  (b) escalate-first-asymmetry-cited: the Rule-14 upside-asymmetric calculus is
      explicitly cited for this finding (file-at-higher-tier-because-amend-down-
      is-free) AND the draft states WHY the higher tier is nonetheless not the
      filed tier (a platform-OOS clause for the higher framing, an
      evidence-class ceiling that bounds the executed step, etc.); OR
  (c) escalate-first-rebuttal: a bounded ``r-escalate-first-rebuttal`` marker.

A bare narrowing sentence with NO escalate-first record fails closed:
``fail-narrowed-without-escalate-first-attempt``. This is exactly the
bsc-epoch shape.

This gate does NOT force a CRITICAL filing. It forces the AUDIT TRAIL of the
escalate-first decision so a HIGH filing is provably a considered fallback, not
a silent first-pass downgrade.

Second loophole closed: reasoned (not measured) de-escalation
-------------------------------------------------------------
Empirical anchor (zebra getaddresstxids, 2026-06-02). A HIGH DoS/liveness
finding was walked back to MEDIUM with a purely ARCHITECTURAL reasoning
argument: "getaddresstxids runs on the spawn_blocking pool (512 threads), so a
single request cannot deny the node". No measurement, no harness, no executed
control run accompanied the walk-back. The original HIGHER_TIER_WALKED_RE was
funds/CRITICAL-class only (theft / drain / direct-loss); a DoS->MEDIUM
reasoning walk-back contains none of that vocabulary, so the gate exited
``pass-narrowed-no-higher-tier-walked`` and the unmeasured de-escalation was
invisible. The measured counter-case (the HIGH that DID hold) carried numbers:
control-query latency 0.156ms -> 225s, +2.3GiB RSS - an executed refutation
that the lower bound does NOT hold.

The strengthened rule: WHEN a draft de-escalates / walks back from a tier the
rubric supports (now including DoS/liveness HIGH->MEDIUM, not just funds class)
AND the walk-back rationale is REASONING-ONLY (capacity / architecture / pool-
size / thread-count prose) AND no MEASURED / EXECUTED refutation accompanies it
(numbers with units, a PASS test transcript, an explicit control run), the
draft FAILS CLOSED with ``fail-reasoned-walkback-not-measured``. A walk-back
that DOES cite measured evidence passes ``pass-walkback-measured``. The rare
legitimate reasoned case uses the bounded ``r-escalate-measure-rebuttal``
marker.

Verdict vocabulary
------------------
  pass-out-of-scope                       : severity below Medium.
  pass-no-narrowing                       : draft does not narrow away a tier.
  pass-narrowed-no-higher-tier-walked     : narrowing present but no higher-tier
                                            (CRITICAL/end-to-end/theft) framing is
                                            being walked away from - nothing to
                                            escalate-first.
  pass-escalate-first-attempted           : narrowing + a documented higher-tier
                                            execution attempt + blocker.
  pass-escalate-first-asymmetry-cited     : narrowing + Rule-14 asymmetry cited +
                                            stated reason higher tier is not filed.
  pass-walkback-measured                  : de-escalation walk-back IS backed by
                                            measured/executed evidence (numbers,
                                            PASS transcript, control run).
  ok-rebuttal                             : bounded r-escalate-first-rebuttal OR
                                            r-escalate-measure-rebuttal.
  fail-narrowed-without-escalate-first-attempt
                                          : narrowing walks away from a higher
                                            tier with no escalate-first record.
  fail-reasoned-walkback-not-measured     : de-escalation walk-back rests on
                                            reasoning-only prose (capacity /
                                            architecture / pool-size) with no
                                            measured/executed refutation.
  pass-impossibility-cited                : (STRICT only) draft walks away from a
                                            higher tier BUT cites a proven
                                            impossibility (code-guard file:line /
                                            numeric config-or-economic bound /
                                            named recovery mechanism) anchored to
                                            the higher-tier argument.
  fail-punt-without-cited-impossibility   : (STRICT only) draft walks away from a
                                            higher tier and its escalation blocker
                                            is a PUNT (single-process / cannot-
                                            model / would-require-a-testnet /
                                            considered-and-not-claimed) with NO
                                            cited PROOF-OF-IMPOSSIBILITY (code-
                                            guard file:line / numeric config-or-
                                            economic bound / named recovery
                                            mechanism). A bare rebuttal does NOT
                                            green it - the body must cite the
                                            impossibility.
  error                                   : IO / usage error.

PROVE-IMPOSSIBLE-OR-ESCALATE (operator directive 2026-07-02, STRICT-gated)
--------------------------------------------------------------------------
Advisory-first behind ``AUDITOOOR_ESCALATE_FIRST_STRICT`` (or ``--strict``). A
finding may NEVER fall to a lower tier via a punt. The ONLY valid fallback is a
PROVEN IMPOSSIBILITY of the higher tier - a source/config/economics-cited
argument. Absent STRICT the gate is byte-identical to the legacy behavior.
"Agents never give up - they prove not-possible."

CLI
---
    escalate-first-required-check.py <draft.md>
        [--workspace <ws>]
        [--severity {auto,LOW,MEDIUM,HIGH,CRITICAL}]
        [--json]
        [--no-asymmetry]   # skip the triager-amend-asymmetry advisory enrichment
        [--strict]         # prove-impossible-or-escalate (also AUDITOOOR_ESCALATE_FIRST_STRICT=1)

Exit codes
----------
  0 - pass / ok-rebuttal
  1 - fail-narrowed-without-escalate-first-attempt
      | fail-reasoned-walkback-not-measured
      | fail-punt-without-cited-impossibility (STRICT)
  2 - error

Schema: ``auditooor.r_escalate_first_required.v1``.

RELATED TOOLS (tool-duplication preflight, per CLAUDE.md anchor)
----------------------------------------------------------------
- tools/triager-amend-asymmetry.py - Rule 14 ADVISORY: computes historical
  triager escalate-vs-downgrade asymmetry for an engagement and recommends a
  default filing tier. It is an advisory, fired at brief time; it does NOT gate
  a specific draft's narrowing. This gate REUSES it (imports ``compute`` /
  ``_resolve_filed_dirs``) to enrich the failure message with the engagement's
  asymmetry verdict, and gates the per-draft decision the advisory could not.
- tools/v3-grade-poc-check.py - R40: emits ``pass-claim-narrowed`` (the
  loophole). This gate is the missing companion: it sits AFTER R40 and asks the
  escalate-first question R40 never asks. It does NOT re-implement R40's
  six-point PoC scan.
- tools/configured-impact-trace-check.py - R42: also emits
  ``pass-claim-narrowed``. Same relationship as R40.
- tools/always-escalate-platform-oos-check.py - Gap30: tells you whether the
  HIGHER framing matches a platform-OOS clause (the legitimate reason NOT to
  escalate). This gate's (b) path is satisfied by citing exactly that.
- tools/escalation-chain-precheck.py - advisory chain/escalation evidence
  checker (named primitive / attempted stronger impact / distinction). Adjacent
  but for chained-finding escalation, not tier-narrowing audit trail.
The gap this fills: NONE of the above forces a per-draft escalate-first record
before a tier-narrowing is accepted as a clean PASS.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.r_escalate_first_required.v1"
GATE = "R-ESCALATE-FIRST-REQUIRED"
TOOL_REL_PATH = "tools/escalate-first-required-check.py"

MAX_REBUTTAL_LEN = 200

# --- narrowing signals (shared shape with R40 NARROWED_RE, deliberately a
# superset so this gate fires on the SAME drafts R40 passes as narrowed) ------
NARROWED_RE = re.compile(
    r"claim (?:is )?narrow(?:ed)?|narrows? the claim|reasoned not executed|"
    r"not (?:separately )?executed|source[- ]traced,? not (?:separately )?executed|"
    r"downstream .{0,60}(?:is )?(?:reasoned|source[- ]traced)|source-level gap|"
    r"narrowed to the source|severity walks? back|"
    r"walk(?:ed)? back to (?:medium|high|low)|claim (?:is )?bounded to|"
    r"not (?:claimed|alleged|proven) (?:as|at) (?:high|critical)|"
    r"(?:critical|end[- ]to[- ]end) .{0,40}(?:framing )?(?:is )?(?:deliberately )?not claimed|"
    r"is deliberately not claimed|limited to the (?:source|logic) gap|"
    r"honest scope of the PoC|evidence[- ]class (?:supports|ceiling|caps?)|"
    # --- de-escalation narrowing vocabulary (DoS/liveness; zebra anchor) ------
    # A DoS / availability walk-back uses different narrowing phrasing than the
    # funds-class "source-traced not executed" idiom.
    r"walk(?:ed|s|ing)? (?:this|it|the (?:claim|finding|severity))? ?back|"
    r"walk(?:ed|s|ing)? back from (?:high|critical)|"
    r"de[- ]escalat(?:e|ed|es|ing|ion)|downgrad(?:e|ed|es|ing)|"
    r"settled? (?:at|on|to) (?:medium|low)|capp?ed (?:at|to) (?:medium|low)|"
    r"(?:does not|doesn't|cannot|can't) (?:support|hold) (?:high|critical|the higher)|"
    r"not supportable (?:at|as) (?:high|critical)|"
    r"the higher tier (?:is|does) not|reduced (?:to|the severity)|"
    r"rests? on the (?:pool|capacity|architecture|concurrency)|"
    r"blast radius (?:is )?bounded",
    re.IGNORECASE,
)

# --- higher-tier walk-away signals: the draft is walking AWAY from a CRITICAL /
# end-to-end / direct-loss / theft impact. If these are absent, the narrowing is
# not abandoning a higher tier and there is nothing to escalate-first. ---------
HIGHER_TIER_WALKED_RE = re.compile(
    r"end[- ]to[- ]end (?:fund|asset|theft|drain|loss)|"
    r"direct (?:loss|theft) of (?:funds|bridged|assets)|"
    r"(?:fund|asset)[- ]?(?:drain|theft)|stealing of (?:funds|bridged)|"
    r"unauthorized cross[- ]chain asset movement|"
    r"critical (?:end[- ]to[- ]end|impact|threshold|tier|severity)|"
    r"downstream .{0,60}(?:fund|asset|drain|theft|loss|message[- ]forgery)|"
    r"theft of bridged|drain (?:the )?(?:reserve|pool|vault|gateway)|"
    # --- DoS / liveness tier-drop (zebra getaddresstxids anchor) -------------
    # A HIGH DoS / liveness / availability claim walked back to MEDIUM contains
    # none of the funds vocabulary above; these patterns capture the tier-drop
    # framing itself so the gate fires on availability-class walk-backs too.
    r"(?:high|HIGH)\s*(?:to|->|->|/|down to)\s*(?:medium|MEDIUM|low|LOW)|"
    r"(?:critical|CRITICAL)\s*(?:to|->|->|/|down to)\s*(?:high|HIGH|medium|MEDIUM)|"
    r"walk(?:ed|s)? back (?:from|to) (?:high|critical|medium)|"
    r"de[- ]escalat(?:ed?|ing|ion) (?:from|to)? ?(?:high|critical|medium)|"
    r"downgrad(?:ed?|ing|e) (?:from|to)? ?(?:high|critical)|"
    r"(?:non[- ]distributed )?(?:dos|denial[- ]of[- ]service)\b.{0,80}"
    r"(?:walk|back|medium|reduced|downgrad|cap(?:ped)?|bounded|not\b.{0,20}high)|"
    r"(?:liveness|starvation|memory[- ]exhaustion|node[- ]availability|"
    r"thread[- ]pool|node halt|node stall)\b.{0,80}"
    r"(?:walk|back|medium|bounded|downgrad|cap(?:ped)?|not\b.{0,20}high)",
    re.IGNORECASE,
)

# --- reasoning-only walk-back rationale (zebra anchor) -----------------------
# The de-escalation rationale is a CAPACITY / ARCHITECTURE / POOL-SIZE argument:
# "the pool has 512 threads so one request cannot deny the node". This is prose
# reasoning, not an executed refutation. If the walk-back rests ONLY on this and
# carries no measured evidence, it fails closed.
REASONING_ONLY_WALKBACK_RE = re.compile(
    r"(?:spawn[_ ]?blocking|blocking|thread)[- ]?pool\b|"
    r"\bpool (?:of )?\d+\b|\b\d+ (?:os )?threads?\b|"
    r"pool (?:size|capacity|cap|has|of|bounds?|limits?|can handle)|"
    r"runs? on (?:a |the )?(?:[a-z_]+ )?pool|dispatched (?:via|on) (?:a |the )?[a-z_]*pool|"
    r"bounded by the pool|pool bounds (?:the )?impact|"
    r"(?:one|a single|single) (?:request|call|tx|message) (?:cannot|can't|won't|does not|will not)\b|"
    r"(?:cannot|can't|won't|does not|will not) (?:deny|exhaust|starve|block|halt|stall) (?:the )?node|"
    r"(?:architecture|design|model|concurrency model) (?:means|implies|ensures|prevents|guarantees)|"
    r"because (?:the )?(?:architecture|design|pool|model|concurrency)",
    re.IGNORECASE,
)

# --- measured / executed refutation evidence ---------------------------------
# Numbers with units, a PASS test transcript, an explicit control run, RSS /
# latency / throughput measurements. ANY of these present makes the walk-back a
# measured one (pass-walkback-measured).
MEASURED_EVIDENCE_RE = re.compile(
    r"\b\d+\.?\d*\s*(?:ms|us|µs|ns|s\b|sec|GiB|MiB|KiB|MB|GB|KB|TiB|"
    r"req/s|tx/s|ops/s|qps|rps)\b|"
    r"\bmeasured[:=]|\bMEASURED\b|\bAxis\s*\d|"
    r"control[- ]?(?:query|run|test|baseline)\b|"
    r"--- ?PASS:|test result: ok|Suite result: ok|^ok\s|finished in \d|"
    r"\bRSS\b|resident set|latency under load|throughput under load|"
    r"(?:before|baseline)\b.{0,40}(?:after|under load)\b.{0,40}\d|"
    r"\d+\s*(?:ms|s)\b.{0,20}(?:->|->|to)\s*\d+\s*(?:ms|s)\b|"
    r"\bp(?:50|90|95|99)\b|percentile|histogram|benchmark (?:result|output)|"
    r"harness transcript|poc[- ]?transcript|executed (?:harness|control|refutation)",
    re.IGNORECASE | re.MULTILINE,
)

# --- escalate-first ATTEMPT record (path a) ----------------------------------
ESCALATE_ATTEMPT_RE = re.compile(
    r"escalate[- ]first|attempted (?:the )?(?:critical|higher[- ]tier|end[- ]to[- ]end)|"
    r"critical .{0,40}(?:was )?attempted|"
    r"tried to (?:execute|build|prove) (?:the )?(?:critical|end[- ]to[- ]end|downstream)|"
    r"higher[- ]tier (?:execution )?attempt(?:ed)?|"
    r"end[- ]to[- ]end execution attempt(?:ed)?|"
    r"max[- ]escalate(?:d)?",
    re.IGNORECASE,
)
# A blocker that explains WHY the higher-tier execution could not land.
ESCALATE_BLOCKER_RE = re.compile(
    r"blocker[:=]|could not (?:be )?(?:executed|built|reached|proven|driven)|"
    r"prevented (?:the )?(?:execution|end[- ]to[- ]end|critical)|"
    r"no (?:reachable|in[- ]scope|deployed|configured) downstream (?:consumer|sink)|"
    r"downstream consumer (?:is )?(?:out[- ]of[- ]scope|not (?:in scope|reachable|deployed))|"
    r"requires .{0,40}out[- ]of[- ]scope|"
    r"forced (?:fallback|to narrow)|fallback (?:to|after) (?:the )?(?:critical|higher)",
    re.IGNORECASE,
)

# --- Rule-14 asymmetry cited (path b) ----------------------------------------
ASYMMETRY_CITED_RE = re.compile(
    r"rule[- ]?14|upside[- ]asymmetr|amend[- ]down is free|"
    r"triager[- ]amend|file[- ]at[- ]higher[- ]tier|"
    r"worst case .{0,40}(?:amend|downgrade) (?:to|down)|"
    r"asymmetr(?:ic|y) (?:calculus|filing)",
    re.IGNORECASE,
)
# Why the higher tier is nonetheless not the filed tier (the legitimate reason).
HIGHER_NOT_FILED_REASON_RE = re.compile(
    r"platform[- ]?OOS|out[- ]of[- ]scope (?:for|clause)|"
    r"evidence[- ]class (?:ceiling|caps?|bounds?|supports? (?:high|the executed))|"
    r"theoretical (?:without|vulnerabilit)|"
    r"would be (?:closed|triager[- ]closed) (?:as|for)|"
    r"higher (?:tier|framing) (?:is )?(?:OOS|out[- ]of[- ]scope|unprovable|not (?:in scope|executable))",
    re.IGNORECASE,
)

# ============================================================================
# PROVE-IMPOSSIBLE-OR-ESCALATE layer (operator directive 2026-07-02,
# lane generic-escalate-or-prove-impossible).
#
# The existing (a)/(b)/(c) paths accept an escalate-first record whose blocker
# is a PUNT ("attempted but could not build the evidence" / "single-process
# cannot model a consensus engine" / "would require a testnet"). The operator
# directive: a finding may NEVER fall to a lower tier via a punt. The ONLY valid
# fallback is a PROVEN IMPOSSIBILITY of the higher tier - a source/config/
# economics-cited argument (code-guard file:line, numeric config/economic bound,
# or a named in-protocol recovery mechanism that caps the impact).
#
# NUVA begin-blocker anchor (2026-07-02): the draft's "Escalation Consideration"
# says "a single-process in-tree measurement cannot model a consensus engine or
# its timeout, so neither leg is established" and carries a bare
# r-escalate-first-rebuttal. That is a PUNT with no cited impossibility. Under
# STRICT it MUST fail closed.
# ============================================================================

# PUNT patterns: an escalation blocker that is a measurement / tooling / process
# limitation, NOT a proof the higher impact cannot be reached.
PUNT_BLOCKER_RE = re.compile(
    r"single[- ]?process|can.?t model|cannot model|could not model|unable to model|"
    r"would require (?:a )?(?:testnet|instrumentation|multi[- ]?node|consensus|"
    r"validator[- ]set|live network|mainnet fork|devnet)|"
    r"(?:consensus|validator[- ]set|multi[- ]?node)[- ](?:level )?"
    r"(?:measurement|instrumentation|test|harness)|"
    r"not instrumented|lacks? instrumentation|harder evidence|"
    r"attempted but|considered (?:and )?(?:deliberately )?not claimed|"
    r"measurement limitation|beyond (?:the )?scope of this (?:test|poc|harness)|"
    r"in[- ]process (?:test|measurement) cannot|"
    r"held pending .{0,40}(?:instrumentation|measurement|testnet)|"
    r"a single[- ]process .{0,60}cannot",
    re.IGNORECASE,
)

# PROVEN-IMPOSSIBILITY patterns: a cited argument that the HIGHER tier is
# structurally UNREACHABLE. This is deliberately narrow - a bare `file:line`
# anywhere in the draft (the bug's OWN root-cause citations, sibling-guard
# descriptions, etc.) is NOT a proof-of-impossibility. The citation must be
# accompanied by impossibility semantics that argue the higher IMPACT cannot be
# reached / is capped / is recoverable. Three admissible forms:
#   (a) a code guard at file:line that structurally CAPS/BLOCKS the higher impact;
#   (b) a numeric config or economic bound (with units) making it UNREACHABLE;
#   (c) a named, in-protocol recovery mechanism that CAPS / REVERSES the loss.
IMPOSSIBILITY_CITED_RE = re.compile(
    # (a) a guard/cap at file:line that STRUCTURALLY caps/blocks the HIGHER
    #     impact. Requires a capping VERB whose OBJECT is the higher-impact
    #     vocabulary AND a file:line within the same clause. The object list is
    #     deliberately restricted to higher-tier nouns (freeze/halt/drain/loss/
    #     the higher tier itself) so a generic "over subsequent blocks" or
    #     sibling-guard description does NOT qualify.
    r"(?:cap(?:s|ped|ping)?|bound(?:s|ed)?|block(?:s|ed|ing)?|prevent(?:s|ed|ing)?|"
    r"revert(?:s|ed|ing)?|guard(?:s|ed|ing)?|clamp(?:s|ed|ing)?|reject(?:s|ed|ing)?|"
    r"limit(?:s|ed|ing)?)\s+(?:the\s+)?"
    r"(?:higher(?:[- ]tier)?|critical|escalat\w+|freeze|freezing|frozen|halt|"
    r"stall|drain|theft|(?:fund|asset)[- ]?loss|permanent[- ]loss|"
    r"consensus[- ](?:halt|timeout|round))"
    r"[^.\n]{0,120}\b[\w./-]+\.\w+:\d+\b|"
    r"\b[\w./-]+\.\w+:\d+\b[^.\n]{0,120}"
    r"(?:makes?|renders?|keeps?) (?:the )?"
    r"(?:higher(?:[- ]tier)?|critical|escalat\w+|freeze|freezing|halt|drain|theft) "
    r"(?:tier|impact)? ?(?:unreachable|impossible|structurally impossible)|"
    # (b) a numeric config / economic bound (with units) that makes the higher
    #     impact unreachable. Requires an unreachability/bound verb + a number+unit.
    r"(?:unreachable|impossible|cannot (?:exceed|reach|be reached)|capped at|"
    r"bounded (?:at|by)|hard[- ]cap(?:ped)? (?:at|to)?|economically "
    r"(?:infeasible|unprofitable|irrational)|cost (?:to|of) .{0,40}exceeds?)"
    r"[^.\n]{0,80}\b\d[\d,._]*\s*(?:%|wei|gwei|eth|usd|usdc|dai|tokens?|bps|"
    r"seconds?|blocks?|gas|units?|shares?|x\b)\b|"
    r"\b\d[\d,._]*\s*(?:%|wei|gwei|eth|usd|usdc|dai|bps|blocks?|gas|shares?)\b"
    r"[^.\n]{0,80}(?:so (?:the )?(?:higher|critical|freeze|halt|drain) "
    r"(?:tier|impact) (?:is )?(?:unreachable|impossible|capped|bounded))|"
    # (c) a NAMED, in-protocol recovery mechanism that caps / reverses the loss.
    r"in[- ]protocol (?:recovery|refund|rollback|cancel(?:lation)?|dispute) "
    r"(?:mechanism|path|window)|"
    r"(?:caps?|reverses?|refunds?|recovers?|reclaims?) the (?:loss|impact|funds|"
    r"frozen (?:funds|amount))\b[^.\n]{0,60}(?:via|through|by) (?:the )?[\w.]+|"
    r"funds (?:are|remain) recoverable (?:via|through|by) (?:the )?[\w.]+|"
    r"named recovery mechanism\b",
    re.IGNORECASE,
)

REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r[-_ ]?escalate[-_ ]first[-_ ]rebuttal\s*:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r[-_ ]?escalate[-_ ]first[-_ ]rebuttal\s*:\s*(.+?)\s*$",
)

# Separate rebuttal for the reasoned-walkback fail (the rare legitimate reasoned
# case where measurement is genuinely infeasible / unnecessary).
MEASURE_REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r[-_ ]?escalate[-_ ]measure[-_ ]rebuttal\s*:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
MEASURE_REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r[-_ ]?escalate[-_ ]measure[-_ ]rebuttal\s*:\s*(.+?)\s*$",
)

SEVERITY_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Severity(?:\*\*)?\s*[:=]\s*(?:\*\*)?\s*"
    r"(critical|high|medium|low|informational|info|none)",
)


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    payload.setdefault("schema", SCHEMA_VERSION)
    payload.setdefault("gate", GATE)
    payload.setdefault("tool", TOOL_REL_PATH)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        v = payload.get("verdict", "?")
        r = payload.get("reason", "")
        print(f"[{GATE}] verdict={v} reason={r}")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, OSError):
        return ""


def _line_hits(text: str, rx: re.Pattern[str], cap: int = 6) -> list[str]:
    hits: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if rx.search(line):
            hits.append(line[:200])
            if len(hits) >= cap:
                break
    return hits


def _line_hits_cooccur(
    text: str,
    rx: re.Pattern[str],
    guard_rx: re.Pattern[str],
    cap: int = 6,
) -> list[str]:
    """Like _line_hits but only counts a line that matches BOTH rx AND guard_rx.

    Used for proof-of-impossibility: a bare code guard file:line anywhere in the
    draft (the bug's OWN root-cause citations, sibling-guard descriptions) is NOT
    a proof the HIGHER tier is impossible. The impossibility citation only counts
    when the SAME line ALSO references the higher tier / escalation being walked
    away from (freeze / halt / critical / higher-tier / recovery vocabulary), so
    the citation is anchored to the escalation argument, not to the bug body.
    """
    hits: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if rx.search(line) and guard_rx.search(line):
            hits.append(line[:200])
            if len(hits) >= cap:
                break
    return hits


# Higher-tier / escalation anchor: an impossibility citation only counts as a
# proof-of-impossibility when it co-occurs with this vocabulary on the same line
# (or the recovery/unreachable idiom is self-anchoring). Ties the cited guard /
# bound / mechanism to the HIGHER tier being walked away from.
HIGHER_TIER_ANCHOR_RE = re.compile(
    r"higher (?:tier|impact|framing)|escalat\w+|"
    r"critical\b|freeze|freezing|frozen|halt|stall|"
    r"temporary freezing|consensus[- ](?:halt|level|timeout|round)|"
    r"drain|theft|direct[- ]loss|fund[- ]?(?:freeze|loss)|"
    r"recover(?:y|able|s)|refund|reversib|in[- ]protocol|"
    r"unreachable|impossible|economically (?:infeasible|unprofitable)",
    re.IGNORECASE,
)


def _detect_severity(text: str, override: str) -> str:
    o = (override or "auto").upper()
    if o in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return o
    m = SEVERITY_LINE_RE.search(text)
    if not m:
        return "UNKNOWN"
    tok = m.group(1).lower()
    if tok in {"info", "informational", "none"}:
        return "LOW"
    return tok.upper()


def _extract_rebuttal(text: str) -> str | None:
    if not text:
        return None
    m = REBUTTAL_HTML_RE.search(text) or REBUTTAL_LINE_RE.search(text)
    if not m:
        return None
    reason = (m.group(1) or "").strip()
    if not reason or len(reason) > MAX_REBUTTAL_LEN:
        return None
    return reason


def _extract_measure_rebuttal(text: str) -> str | None:
    if not text:
        return None
    m = MEASURE_REBUTTAL_HTML_RE.search(text) or MEASURE_REBUTTAL_LINE_RE.search(text)
    if not m:
        return None
    reason = (m.group(1) or "").strip()
    if not reason or len(reason) > MAX_REBUTTAL_LEN:
        return None
    return reason


def _asymmetry_advisory(workspace: Path | None) -> dict[str, Any] | None:
    """Reuse triager-amend-asymmetry.py to enrich the failure message.

    This is best-effort: if the import or the scan fails, the gate verdict is
    unchanged - the advisory is purely informational enrichment.
    """
    if workspace is None:
        return None
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "triager_amend_asymmetry",
            str(Path(__file__).resolve().parent / "triager-amend-asymmetry.py"),
        )
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        return None
    try:
        filed_dirs = mod._resolve_filed_dirs(workspace)  # type: ignore[attr-defined]
        if not filed_dirs:
            return {"verdict": "no-filed-dir", "asymmetry_score": None}
        res = mod.compute(filed_dirs)  # type: ignore[attr-defined]
        return {
            "verdict": res.get("verdict"),
            "asymmetry_score": res.get("asymmetry_score"),
            "recommendation": res.get("recommendation"),
        }
    except Exception:
        return None


def check(
    draft_path: Path,
    workspace: Path | None = None,
    severity_override: str = "auto",
    enrich_asymmetry: bool = True,
    strict: bool = False,
) -> dict[str, Any]:
    if not draft_path.exists():
        return {"verdict": "error", "reason": f"draft not found: {draft_path}", "exit": 2}

    text = _read_text(draft_path)
    if not text.strip():
        return {"verdict": "error", "reason": f"draft is empty: {draft_path}", "exit": 2}

    severity = _detect_severity(text, severity_override)
    payload: dict[str, Any] = {"draft": str(draft_path), "severity": severity}

    # R-escalate-first only fires Medium and above (same threshold as R40/R42).
    if severity in {"LOW", "UNKNOWN"}:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = f"severity {severity} is below Medium; escalate-first gate does not fire"
        payload["exit"] = 0
        return payload

    rebuttal = _extract_rebuttal(text)
    measure_rebuttal = _extract_measure_rebuttal(text)

    narrowing_hits = _line_hits(text, NARROWED_RE)
    higher_walked_hits = _line_hits(text, HIGHER_TIER_WALKED_RE)
    attempt_hits = _line_hits(text, ESCALATE_ATTEMPT_RE)
    blocker_hits = _line_hits(text, ESCALATE_BLOCKER_RE)
    asym_cited_hits = _line_hits(text, ASYMMETRY_CITED_RE)
    not_filed_reason_hits = _line_hits(text, HIGHER_NOT_FILED_REASON_RE)
    reasoning_only_hits = _line_hits(text, REASONING_ONLY_WALKBACK_RE)
    punt_blocker_hits = _line_hits(text, PUNT_BLOCKER_RE)
    # Impossibility only counts when the citation co-occurs with higher-tier /
    # escalation vocabulary on the SAME line (see _line_hits_cooccur). This is
    # what prevents the bug's own root-cause file:line citations and sibling-
    # guard descriptions from being mistaken for a proof the HIGHER tier is
    # unreachable.
    impossibility_cited_hits = _line_hits_cooccur(
        text, IMPOSSIBILITY_CITED_RE, HIGHER_TIER_ANCHOR_RE
    )
    # Measured-evidence scan is over the whole text (numbers can sit in a PoC
    # transcript block, not just on the narrowing line), so search the full body.
    measured_evidence_present = bool(MEASURED_EVIDENCE_RE.search(text))
    measured_evidence_hits = _line_hits(text, MEASURED_EVIDENCE_RE)
    impossibility_cited_present = bool(impossibility_cited_hits)

    payload["evidence"] = {
        "narrowing_hits": narrowing_hits,
        "higher_tier_walked_hits": higher_walked_hits,
        "escalate_attempt_hits": attempt_hits,
        "escalate_blocker_hits": blocker_hits,
        "asymmetry_cited_hits": asym_cited_hits,
        "higher_not_filed_reason_hits": not_filed_reason_hits,
        "reasoning_only_walkback_hits": reasoning_only_hits,
        "measured_evidence_hits": measured_evidence_hits,
    }
    # The prove-impossible-or-escalate evidence keys are STRICT-only so the
    # NON-strict JSON payload is byte-identical to the legacy gate (backward
    # compat requirement (d)). The tests always pass strict=True/False
    # explicitly, so they see the keys when they need them.
    if strict:
        payload["evidence"]["punt_blocker_hits"] = punt_blocker_hits
        payload["evidence"]["impossibility_cited_hits"] = impossibility_cited_hits
        payload["strict"] = True

    narrowed = bool(narrowing_hits)
    higher_walked = bool(higher_walked_hits)
    attempted = bool(attempt_hits) and bool(blocker_hits)
    asymmetry_cited = bool(asym_cited_hits) and bool(not_filed_reason_hits)
    reasoning_only = bool(reasoning_only_hits)

    if not narrowed:
        payload["verdict"] = "pass-no-narrowing"
        payload["reason"] = "draft does not narrow away a tier; escalate-first gate is moot"
        payload["exit"] = 0
        return payload

    if not higher_walked:
        payload["verdict"] = "pass-narrowed-no-higher-tier-walked"
        payload["reason"] = (
            "narrowing present but no higher-tier (CRITICAL/end-to-end/theft/"
            "direct-loss/DoS-tier-drop) framing is being walked away from; "
            "nothing to escalate-first"
        )
        payload["exit"] = 0
        return payload

    # ------------------------------------------------------------------------
    # PROVE-IMPOSSIBLE-OR-ESCALATE (operator directive 2026-07-02; NUVA anchor).
    # STRICT ONLY - advisory-first behind AUDITOOOR_ESCALATE_FIRST_STRICT so the
    # non-strict / legacy path is byte-identical.
    #
    # When the draft walks away from a higher tier AND its escalation blocker
    # matches a PUNT pattern (single-process / cannot-model / would-require-a-
    # testnet / considered-and-not-claimed / measurement-limitation), the ONLY
    # thing that greens it is a CITED PROOF-OF-IMPOSSIBILITY for the higher tier
    # (code-guard file:line / numeric config-or-economic bound / named recovery
    # mechanism). A bare escalate-first-rebuttal NO LONGER greens it - the marker
    # must ITSELF cite an impossibility (i.e. the body carries one). This fires
    # BEFORE the (a) attempt / (b) asymmetry / (c) rebuttal passes so it cannot
    # be ducked by an attempt-record whose blocker is the punt.
    if strict and impossibility_cited_present:
        # The operator-sanctioned fallback: a CITED proof-of-impossibility for
        # the higher tier (code-guard file:line / numeric config-or-economic
        # bound / named recovery mechanism) anchored to the higher-tier /
        # escalation argument. This is the ONLY clean way to fall to a lower
        # tier under STRICT. It greens even a punt blocker.
        payload["verdict"] = "pass-impossibility-cited"
        payload["reason"] = (
            "draft walks away from a higher tier BUT cites a "
            "PROOF-OF-IMPOSSIBILITY for it (code-guard file:line / numeric "
            "config-or-economic bound / named in-protocol recovery mechanism) "
            "anchored to the higher-tier / escalation argument. This is the "
            "operator-sanctioned fallback under STRICT."
        )
        payload["exit"] = 0
        return payload

    if strict and punt_blocker_hits and not impossibility_cited_present:
        payload["verdict"] = "fail-punt-without-cited-impossibility"
        payload["reason"] = (
            "draft walks away from a higher tier and its escalation blocker is a "
            "PUNT (measurement / tooling / process limitation - single-process / "
            "cannot-model-a-consensus-engine / would-require-a-testnet / "
            "considered-and-deliberately-not-claimed) with NO cited "
            "PROOF-OF-IMPOSSIBILITY for the higher tier. Under "
            "AUDITOOOR_ESCALATE_FIRST_STRICT the ONLY valid fallback to a lower "
            "tier is a proven impossibility: a code-guard at file:line that caps "
            "the higher impact, a numeric config/economic bound (with units) that "
            "makes it unreachable, or a named in-protocol recovery mechanism that "
            "caps the loss. 'Attempted but the evidence is too hard to build' is "
            "NOT valid - ESCALATE and prove the higher tier."
        )
        payload["exit"] = 1
        payload["remediation"] = (
            "Do ONE of: (a) ESCALATE - drive the higher-tier impact end-to-end "
            "and file at that tier; (b) cite a PROOF-OF-IMPOSSIBILITY for the "
            "higher tier: a code guard at file:line that structurally caps it, a "
            "numeric config/economic bound (with units) proving it unreachable, "
            "or a named in-protocol recovery mechanism that caps the loss. A bare "
            "r-escalate-first-rebuttal is INSUFFICIENT under STRICT - the body "
            "must cite the impossibility. 'Agents never give up - they prove "
            "not-possible.'"
        )
        if enrich_asymmetry:
            adv = _asymmetry_advisory(workspace)
            if adv is not None:
                payload["engagement_asymmetry_advisory"] = adv
        return payload

    # ------------------------------------------------------------------------
    # Reasoned-walkback-must-be-measured (zebra getaddresstxids anchor).
    # If the de-escalation rationale rests on reasoning-only prose (capacity /
    # architecture / pool-size) it MUST be accompanied by measured/executed
    # refutation. This fires BEFORE the escalate-first attempt/asymmetry paths
    # because a reasoned walk-back with numbers is the honest PASS, and a
    # reasoned walk-back without numbers is the fail this loophole closes - an
    # escalate-first attempt record does not substitute for the missing
    # measurement of the de-escalation itself.
    if reasoning_only:
        if measured_evidence_present:
            payload["verdict"] = "pass-walkback-measured"
            payload["reason"] = (
                "de-escalation walk-back rests on a capacity/architecture "
                "argument BUT is backed by measured/executed evidence (numbers "
                "with units / control run / PASS transcript) showing the higher "
                "impact does not reproduce"
            )
            payload["exit"] = 0
            return payload
        if measure_rebuttal:
            payload["verdict"] = "ok-rebuttal"
            payload["reason"] = f"r-escalate-measure-rebuttal accepted: {measure_rebuttal}"
            payload["exit"] = 0
            return payload
        payload["verdict"] = "fail-reasoned-walkback-not-measured"
        payload["reason"] = (
            "de-escalation walk-back rests ONLY on reasoning-only prose "
            "(capacity / architecture / pool-size / thread-count) with no "
            "measured or executed refutation. A reasoned walk-back from a "
            "rubric-supported higher tier MUST cite MEASURED evidence (numbers "
            "with units - RSS / latency / throughput / counts, a PASS test "
            "transcript, or an explicit control run) showing the higher-tier "
            "impact does NOT reproduce. Prose reasoning alone is not sufficient."
        )
        payload["exit"] = 1
        payload["remediation"] = (
            "Do ONE of: (a) run the higher-tier PoC/harness and paste the "
            "transcript with NUMBERS (e.g. control-query 0.156ms -> 225s, "
            "+2.3GiB RSS) showing the impact does not reproduce; (b) add an "
            "executed control run where the hypothesised cause is removed; "
            "(c) add `<!-- r-escalate-measure-rebuttal: <reason up to 200 "
            "chars> -->` for the rare case where measurement is genuinely "
            "infeasible."
        )
        if enrich_asymmetry:
            adv = _asymmetry_advisory(workspace)
            if adv is not None:
                payload["engagement_asymmetry_advisory"] = adv
        return payload

    # From here: the draft narrows AND walks away from a higher tier. An
    # escalate-first record is REQUIRED.
    if attempted:
        payload["verdict"] = "pass-escalate-first-attempted"
        payload["reason"] = (
            "narrowing walks away from a higher tier, but the draft documents a "
            "higher-tier/end-to-end execution attempt plus the concrete blocker "
            "that forced the fallback (Rule 14 / A7 satisfied)"
        )
        payload["exit"] = 0
        return payload

    if asymmetry_cited:
        payload["verdict"] = "pass-escalate-first-asymmetry-cited"
        payload["reason"] = (
            "narrowing walks away from a higher tier, but the draft cites the "
            "Rule-14 upside-asymmetric calculus AND states why the higher tier "
            "is nonetheless not the filed tier (platform-OOS / evidence-class ceiling)"
        )
        payload["exit"] = 0
        return payload

    if rebuttal:
        payload["verdict"] = "ok-rebuttal"
        payload["reason"] = f"r-escalate-first-rebuttal accepted: {rebuttal}"
        payload["exit"] = 0
        return payload

    # Fail-closed: this is the bsc-epoch shape - narrowed away a higher tier
    # with no escalate-first attempt record, no asymmetry citation, no rebuttal.
    fail: dict[str, Any] = {
        "verdict": "fail-narrowed-without-escalate-first-attempt",
        "reason": (
            "draft narrows away a higher tier (CRITICAL/end-to-end/theft/"
            "direct-loss) with no documented escalate-first attempt, no Rule-14 "
            "asymmetry citation, and no rebuttal. R40/R42 pass-claim-narrowed is "
            "NOT sufficient: the higher tier must be ATTEMPTED (or its omission "
            "justified) before the narrowing is accepted."
        ),
        "exit": 1,
        "remediation": (
            "Do ONE of: (a) attempt the higher-tier / end-to-end execution and "
            "record the result + concrete blocker in an '## Escalate-First "
            "Attempt' section; (b) cite the Rule-14 asymmetry AND the reason the "
            "higher tier is not filed (platform-OOS clause / evidence-class "
            "ceiling); (c) add `<!-- r-escalate-first-rebuttal: <reason up to "
            "200 chars> -->`."
        ),
    }
    if enrich_asymmetry:
        adv = _asymmetry_advisory(workspace)
        if adv is not None:
            fail["engagement_asymmetry_advisory"] = adv
            if adv.get("verdict") == "lean-upside":
                fail["reason"] += (
                    " NOTE: this engagement's triager history leans-upside "
                    "(triager escalates more than it downgrades) - attempting "
                    "the higher tier first is especially warranted here."
                )
    payload.update(fail)
    return payload


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("draft", help="path to the finding draft (.md)")
    ap.add_argument("--workspace", default=None, help="engagement workspace (for asymmetry enrichment)")
    ap.add_argument(
        "--severity",
        default="auto",
        choices=["auto", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="severity override (default: auto-detect from the draft)",
    )
    ap.add_argument("--no-asymmetry", action="store_true", help="skip triager-amend-asymmetry enrichment")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="enforce prove-impossible-or-escalate (fail-closed on a PUNT blocker "
        "with no cited impossibility). Also enabled by AUDITOOOR_ESCALATE_FIRST_STRICT=1.",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    draft = Path(args.draft).expanduser()
    ws = Path(args.workspace).expanduser() if args.workspace else None

    # Allow env override of severity (parity with sibling gates).
    sev = args.severity
    env_sev = os.environ.get("AUDITOOOR_ESCALATE_FIRST_SEVERITY", "")
    if env_sev and sev == "auto":
        sev = env_sev

    # Advisory-first: prove-impossible-or-escalate fires ONLY under STRICT
    # (CLI --strict OR the named env AUDITOOOR_ESCALATE_FIRST_STRICT truthy).
    # Absent STRICT the verdict is byte-identical to the legacy gate.
    env_strict = os.environ.get("AUDITOOOR_ESCALATE_FIRST_STRICT", "").strip().lower()
    strict = bool(args.strict) or env_strict in {"1", "true", "yes", "on"}

    result = check(
        draft_path=draft,
        workspace=ws,
        severity_override=sev,
        enrich_asymmetry=not args.no_asymmetry,
        strict=strict,
    )
    exit_code = int(result.pop("exit", 0))
    _emit(result, args.json)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
