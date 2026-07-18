#!/usr/bin/env python3
"""phase0-verdict-synthesizer.py - Phase 0 go/no-go verdict synthesis.

# Rule 36 + Rule 55: this tool emits no corpus record.

Ingests the four PLAN-X falsifiable counter-test results from Phase 0 of
the hacker-brain master plan (iter17 synthesis, 2026-05-23) and emits:

  1. A unified verdict matrix mapping each PHASE0 lane's verdict to the
     corresponding PLAN-X counter-test (L0.1 burndown / L0.2 META1-AB /
     L0.3 invariant pilot / L0.4 engagement pre-screen).
  2. An aggregate recommendation: pivot-to-pillar-build / bail-per-
     criterion-6 / needs-more-data, plus immediate bail-criterion trips.
  3. Optionally writes an operator-facing summary markdown to the path
     given by --output.

Counter-test mapping (per
`reports/v3_iter_2026-05-23_iter17/HACKER_BRAIN_MASTER_PLAN_2026-05-23.md`
sections 2 + 5 + 7):

  L0.1 (paste_ready burndown sprint)        -> tests PLAN-X dissent #4
                                              (operator-decision throughput
                                              bottleneck)
  L0.2 (META-1 A/B re-measurement)          -> tests PLAN-X dissent #3
                                              (META-1 INERT-AT-MEASUREMENT)
  L0.3 (hand-curated 100-invariant pilot)   -> tests PLAN-X dissent #5
                                              (prior-art LLM-invariant
                                              extraction failed)
  L0.4 (engagement-rate / pre-screen test)  -> tests PLAN-X dissent #7
                                              (engagement-rate ceiling)

Each per-counter-test resolves to ONE of:
  - PLAN-X-FALSIFIED   - counter-test PASSED, PLAN-X's pessimism on this
                         axis was WRONG. (e.g. L0.3 pilot delivered useful
                         match-rate -> P1 invariant pillar is worth building)
  - PLAN-X-SUPPORTED   - counter-test FAILED, PLAN-X's pessimism on this
                         axis was RIGHT. (e.g. L0.1 confirmed 129-item
                         operator-decision queue -> bottleneck is filing,
                         not hunt cognition)
  - INCONCLUSIVE       - lane landed but evidence is mixed / partial
                         (e.g. L0.2 brief-injection works but per-rule
                         fail-rate still insufficient_data)
  - NOT-YET-RUN        - lane has not landed (no results.md yet)

Aggregate verdict:
  - pivot-to-pillar-build       - >=3 of 4 PLAN-X-FALSIFIED
  - bail-per-criterion-6        - >=3 of 4 PLAN-X-SUPPORTED (master plan
                                  section 7 bail criterion #6: "PLAN-X
                                  counter-tests all flip negative")
  - bail-immediately            - ANY single result trips a bail criterion
                                  per section 7 (#1-#5) regardless of the
                                  aggregate score
  - needs-more-data             - mixed / inconclusive

CLI:
  python3 tools/phase0-verdict-synthesizer.py \\
    --inputs <path1> <path2> ... \\
    [--output <OPERATOR_PHASE0_SUMMARY.md>] \\
    [--json] [--strict]

Verdicts (schema `auditooor.phase0_verdict_synthesizer.v1`):
  - pivot-to-pillar-build
  - bail-per-criterion-6
  - bail-immediately
  - needs-more-data
  - error

Exit codes:
  0 - any aggregate verdict that completed cleanly (pivot / bail / needs-
      more-data); exit code does NOT distinguish pivot from bail because
      both are valid operator-decision states
  2 - input / runtime error (malformed inputs, missing required fields)

The tool is dependency-free (uses only stdlib). It is idempotent on the
same input set. It does NOT modify any input file; it ONLY reads
results.md files and OPTIONALLY writes the summary markdown.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_ID = "auditooor.phase0_verdict_synthesizer.v1"
TOOL_VERSION = "1.0.0"


# --- counter-test mapping (PLAN-X §2 + master plan §5) ---

# Each entry maps a lane-id substring (or filename pattern) to:
#   - counter_test_id : the PLAN-X falsifiable test ID
#   - plan_x_dissent  : the PLAN-X dissent number (1-7)
#   - claim           : what the counter-test claims to test
#   - pass_condition  : what counts as PLAN-X-FALSIFIED
COUNTER_TESTS: List[Dict[str, Any]] = [
    {
        "lane_pattern": "L01_BURNDOWN_AUDIT",
        "counter_test_id": "L0.1",
        "plan_x_dissent": 4,
        "claim": "Operator-decision throughput is the real bottleneck (not hunt cognition).",
        "pass_condition": (
            "Sprint actually produces <5 NEW filings (validates filings are bottleneck, not hunt-cognition). "
            "PLAN-X-FALSIFIED iff sprint produces >=5 new filings under same hunt cadence."
        ),
        "name": "Paste_ready burndown sprint",
    },
    {
        "lane_pattern": "L02_META1_AB",
        "counter_test_id": "L0.2",
        "plan_x_dissent": 3,
        "claim": "META-1 is INERT-AT-MEASUREMENT (KKKKK iter16); existing HUNT-time delivery mechanism is broken.",
        "pass_condition": (
            "VVVVV harness shows positive signal (cohort A > cohort B on R42-fail rate or finding-count) at N>=12. "
            "PLAN-X-FALSIFIED iff cohort A beats cohort B on per-rule fail-rate at properly powered N."
        ),
        "name": "META-1 A/B re-measurement",
    },
    {
        "lane_pattern": "L03_INVARIANT_PILOT",
        "counter_test_id": "L0.3",
        "plan_x_dissent": 5,
        "claim": "Prior LLM-invariant extraction efforts (Certora / OpenZeppelin) failed; market saturated.",
        "pass_condition": (
            "Hand-curated 100-invariant pilot delivers >5x ROI on a real hunt session. "
            "PLAN-X-FALSIFIED iff pilot delivers >=5 invariants flagged in the engage-report surface."
        ),
        "name": "Hand-curated 100-invariant pilot",
    },
    {
        "lane_pattern": "L04_ENGAGEMENT_PRESCREEN",
        "counter_test_id": "L0.4",
        "plan_x_dissent": 7,
        "claim": "Engagement-rate ceiling: <1 new bounty engagement/week caps demand-side throughput.",
        "pass_condition": (
            ">=4 new engagements per month sustained (proxy via pre-screen scoring tool on Cantina/Immunefi listings). "
            "PLAN-X-FALSIFIED iff observation shows >=1/week sustained for 1 month."
        ),
        "name": "Engagement-rate / pre-screen test",
    },
]


# Lane verdicts -> per-counter-test verdicts.
# Each pattern matched against the lane's verdict line.
# Order matters: first match wins.
VERDICT_MAPPINGS: Dict[str, List[Tuple[re.Pattern, str, str]]] = {
    # L0.1 verdict logic: 'bottleneck-confirmed' means the operator-paste queue
    # is large (129 items in this anchor). The PLAN-X dissent claimed
    # "filings are bottleneck, not hunt cognition." Confirming the bottleneck
    # SUPPORTS PLAN-X (the bottleneck exists; PLAN-X's pessimism is right).
    # NOTE: this is the inverse of how a hunt-side sprint would read.
    # PLAN-X says: if the queue is large, the real problem is filings - don't
    # build more META-tooling. So bottleneck-confirmed = PLAN-X-SUPPORTED.
    "L0.1": [
        (re.compile(r"\bbottleneck[- ]confirmed\b", re.IGNORECASE), "PLAN-X-SUPPORTED",
         "Operator-decision queue confirmed bottlenecked - PLAN-X dissent #4 is upheld; "
         "building more META-tooling won't help while >100 drafts await operator-paste decisions."),
        (re.compile(r"\bbottleneck[- ]not[- ]confirmed\b", re.IGNORECASE), "PLAN-X-FALSIFIED",
         "Operator-decision queue is manageable - PLAN-X dissent #4 is falsified; "
         "hunt-cognition is the bottleneck and meta-tooling investment is warranted."),
        (re.compile(r"\binconclusive\b", re.IGNORECASE), "INCONCLUSIVE",
         "Burndown audit shipped but verdict signal is mixed."),
    ],
    # L0.2 verdict logic: 'shifted-positively' on brief-injection pillars is
    # NECESSARY but NOT SUFFICIENT for falsifying PLAN-X dissent #3. The
    # KKKKK headline is per-rule fail-rate change in worker output, which
    # remained 'insufficient_data' at N=12 because no drafts were spawned.
    # Brief-injection working = PARTIAL signal -> INCONCLUSIVE.
    # The aggregator does not promote 'insufficient_data' to either
    # FALSIFIED or SUPPORTED.
    "L0.2": [
        (re.compile(r"\binsufficient[_ ]data\b", re.IGNORECASE), "INCONCLUSIVE",
         "META-1 brief-injection infrastructure verified-working at N=12 with disjoint 95% CIs on three "
         "brief-level pillars, but the headline per-rule fail-rate pillar is still insufficient_data "
         "(no drafts spawned). PLAN-X dissent #3 (META-1 INERT-AT-MEASUREMENT) neither falsified nor "
         "supported - the worker-output measurement gap remains structurally unresolved."),
        (re.compile(r"\bcohort[- ]a[- ]beats[- ]cohort[- ]b\b", re.IGNORECASE), "PLAN-X-FALSIFIED",
         "META-1 cohort A measurably beats cohort B on worker per-rule fail rate - PLAN-X dissent #3 falsified."),
        (re.compile(r"\bcohort[- ]a[- ]does[- ]not[- ]beat\b", re.IGNORECASE), "PLAN-X-SUPPORTED",
         "META-1 cohort A does not beat cohort B at N>=12 - PLAN-X dissent #3 (INERT-AT-MEASUREMENT) supported."),
    ],
    # L0.3 verdict logic: 'PILOT-USEFUL' means the hand-curated 100-invariant
    # pilot matched the master-plan pass threshold (>=5 invariants matched
    # against a real engage_report). That FALSIFIES PLAN-X dissent #5 (prior
    # LLM-invariant extraction failed) by showing the deliverable is real.
    "L0.3": [
        (re.compile(r"\bPILOT[- ]USEFUL\b", re.IGNORECASE), "PLAN-X-FALSIFIED",
         "Pilot delivered >=5 invariants matched against the freshest real engage_report - "
         "PLAN-X dissent #5 (LLM-invariant extraction effort historically failed) is falsified for "
         "the hand-curated form at this scale. ROI confirmed on the L0.3 anchor."),
        (re.compile(r"\bPILOT[- ]USELESS\b", re.IGNORECASE), "PLAN-X-SUPPORTED",
         "Pilot did not meet the >=5-match threshold - PLAN-X dissent #5 supported."),
        (re.compile(r"\bPILOT[- ]MARGINAL\b", re.IGNORECASE), "INCONCLUSIVE",
         "Pilot partial signal - some matches but below the 5-threshold."),
    ],
    # L0.4 verdict logic: not yet landed -> NOT-YET-RUN.
    "L0.4": [
        (re.compile(r"\bENGAGEMENT[- ]RATE[- ]ABOVE\b", re.IGNORECASE), "PLAN-X-FALSIFIED",
         "Observed engagement rate exceeds the >=1/week PLAN-X ceiling - dissent #7 falsified."),
        (re.compile(r"\bENGAGEMENT[- ]RATE[- ]BELOW\b", re.IGNORECASE), "PLAN-X-SUPPORTED",
         "Observed engagement rate confirms the <1/week ceiling - PLAN-X dissent #7 supported."),
        (re.compile(r"\binconclusive\b", re.IGNORECASE), "INCONCLUSIVE",
         "Pre-screen observation period too short to conclude."),
    ],
}


# Bail criteria 1-5 from master plan §7. Any of these single-fires should
# trigger bail-immediately regardless of aggregate score.
# (#6 is the aggregate "all flip negative" case handled by the aggregator.)
IMMEDIATE_BAIL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("bail-criterion-1-zero-invariant-hits",
     re.compile(r"\bzero invariant[- ]grounded passing hits\b", re.IGNORECASE)),
    ("bail-criterion-2-prqs-regression-over-5pt",
     re.compile(r"\bPRQS regression\b.{0,40}>.{0,10}5\s*points?\b", re.IGNORECASE | re.DOTALL)),
    ("bail-criterion-3-cost-overrun-1500",
     re.compile(r"\bcost (?:exceeds|exceeded)\b.{0,20}\$?1,?500\b", re.IGNORECASE | re.DOTALL)),
    ("bail-criterion-4-p1-quality-under-60",
     # No \b after 60% because % is not a word character; use lookahead instead.
     re.compile(r"\bP1 quality\b.{0,40}<.{0,10}60\s*%", re.IGNORECASE | re.DOTALL)),
    ("bail-criterion-5-p5-adoption-under-50",
     re.compile(r"\bP5 report adoption\b.{0,40}<.{0,10}50\s*%", re.IGNORECASE | re.DOTALL)),
]


@dataclass
class CounterTestResult:
    counter_test_id: str
    name: str
    plan_x_dissent: int
    claim: str
    pass_condition: str
    lane_id: Optional[str] = None
    input_path: Optional[str] = None
    verdict_string: Optional[str] = None
    key_evidence: Optional[str] = None
    classification: str = "NOT-YET-RUN"  # PLAN-X-FALSIFIED / -SUPPORTED / INCONCLUSIVE / NOT-YET-RUN
    classification_reason: Optional[str] = None
    diagnostics: List[str] = field(default_factory=list)


def _read_text(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _extract_lane_id(text: str) -> Optional[str]:
    """Pick lane id from a results.md.

    Priority order (most-canonical first):
      1. Backticked `lane-PHASE0-...` form (the registered R36 lane id).
      2. Backticked `PHASE0-L0X-...` (the lane-name without the prefix).
      3. A bullet line `- Lane: <id>` or `- Lanes: <id>` with a token that
         starts with `lane-` or `PHASE0`.
    Avoids matching prose like "Lane mix vs Trial 1".
    """
    m = re.search(r"`(lane-PHASE0[-_][A-Z0-9_\-]+)`", text)
    if m:
        return m.group(1)
    m = re.search(r"`(PHASE0[-_]L\d+[A-Z0-9_\-]+)`", text)
    if m:
        return m.group(1)
    m = re.search(
        r"^\s*[-*]?\s*`?Lane[s]?[:\s]+`?(lane-[A-Za-z0-9_\-]+|PHASE0[-_][A-Z0-9_\-]+)`?",
        text,
        re.MULTILINE,
    )
    if m:
        return m.group(1).strip()
    m = re.search(r"\b(PHASE0[-_]L\d+[A-Z0-9_\-]+)\b", text)
    if m:
        return m.group(1)
    return None


_VERDICT_LINE_RE = re.compile(
    # Matches things like:
    #   **Verdict**: **PILOT-USEFUL**
    #   Verdict: bottleneck-confirmed
    #   `Verdict`: `insufficient_data`
    #   Honest verdict (final): ...
    r"\*?\*?\s*(?:Honest\s+)?Verdict(?:\s*\([^)]*\))?\*?\*?\s*[:=]\s*"
    r"[`*]*\s*"
    r"(?P<value>[A-Za-z][A-Za-z0-9_\-]+(?:[- ][A-Za-z0-9_]+)*)",
    re.IGNORECASE,
)


def _extract_verdict_line(text: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (verdict_string, key_evidence_snippet) from a results.md body.

    Heuristic priority:
      1. Final/Honest verdict markers - prefer the LAST one if multiple
         (later verdicts in long lane reports tend to be the final
         classification).
      2. A "## Verdict" section heading body.
      3. Any "Verdict: <token>" line elsewhere in the file.

    We deliberately do NOT use the "first match wins" rule because
    long lane reports often contain interim status lines (e.g. "Verdict:
    clean - 12/12 matched pairs") well before the actual final verdict.
    """
    verdict_str: Optional[str] = None
    key_evidence: Optional[str] = None

    # Known-verdict-token vocabulary across all 4 counter-tests (used to
    # prefer a real classification token over a lane-name token).
    _KNOWN_VERDICT_TOKENS = {
        "bottleneck-confirmed", "bottleneck-not-confirmed",
        "cohort-a-beats-cohort-b", "cohort-a-does-not-beat",
        "insufficient_data", "insufficient-data",
        "pilot-useful", "pilot-useless", "pilot-marginal",
        "engagement-rate-above", "engagement-rate-below",
        "inconclusive",
    }

    def _pick_verdict_token(body: str) -> Optional[str]:
        # First, look for any known-vocabulary token (case-insensitive).
        lower_body = body.lower()
        for tok in _KNOWN_VERDICT_TOKENS:
            # word-boundary search, allowing - or _ at edges
            if re.search(r"(?<![A-Za-z0-9])" + re.escape(tok) + r"(?![A-Za-z0-9])", lower_body):
                # Return the original-cased form if we can find it.
                orig = re.search(r"(?<![A-Za-z0-9])(" + re.escape(tok).replace("_", "[_-]").replace("-", "[-_]") + r")(?![A-Za-z0-9])", body, re.IGNORECASE)
                if orig:
                    return orig.group(1)
                return tok
        # Next, look for the first ALL-CAPS multi-word bold token (but
        # SKIP lane-name shapes like PHASE0-L02-META1-AB-N12).
        for m in re.finditer(r"\*\*([A-Z][A-Z0-9_\-]+(?:[- ][A-Z0-9_]+)*)\*\*", body):
            cand = m.group(1)
            if cand.startswith("PHASE0") or cand.startswith("LANE") or cand.startswith("META1-TRIAL"):
                continue
            return cand.strip().rstrip("*` ")
        # Last resort: any all-caps token >= 4 chars.
        for m in re.finditer(r"\b([A-Z][A-Z0-9_\-]{3,})\b", body):
            cand = m.group(1)
            if cand.startswith("PHASE0") or cand.startswith("LANE") or cand.startswith("META1-TRIAL"):
                continue
            return cand
        return None

    # 1. "Honest verdict (final)" / "Final verdict" / final-verdict bold line.
    final_matches = list(re.finditer(
        r"(?:Honest\s+verdict(?:\s*\([^)]*\))?|Final\s+verdict)\s*[:=]?\s*[*`]*\s*"
        r"(?P<body>.+?)(?=\n\n|\Z)",
        text,
        re.IGNORECASE | re.DOTALL,
    ))
    if final_matches:
        m = final_matches[-1]
        body = m.group("body").strip()
        token = _pick_verdict_token(body)
        if token:
            verdict_str = token
            key_evidence = " ".join(body.split())[:360]

    # 2. "## Verdict" section.
    if not verdict_str:
        sec = re.search(
            r"^\s*##\s+(?:\d+\.\s+)?Verdict\s*\n+(?P<body>.+?)(?=^##\s|\Z)",
            text,
            re.MULTILINE | re.DOTALL,
        )
        if sec:
            body = sec.group("body").strip()
            # Look for **Verdict**: **TOKEN** or **TOKEN** at line start.
            inner = _VERDICT_LINE_RE.search(body)
            if inner:
                verdict_str = inner.group("value").strip().rstrip("*` ")
            else:
                token = _pick_verdict_token(body)
                if token:
                    verdict_str = token
                else:
                    # First non-empty line.
                    for line in body.splitlines():
                        line = line.strip().lstrip("*").rstrip("*").strip().strip("`")
                        if line and not line.startswith("#"):
                            verdict_str = line.split(" - ")[0].split(":")[-1].strip(" `*")
                            break
            key_evidence = " ".join(body.split())[:360]

    # 3. Any "Verdict: <token>" line elsewhere - prefer the LAST one.
    if not verdict_str:
        matches = list(_VERDICT_LINE_RE.finditer(text))
        if matches:
            m = matches[-1]
            verdict_str = m.group("value").strip().rstrip("*` ")
            start = max(0, m.start() - 120)
            end = min(len(text), m.end() + 240)
            key_evidence = " ".join(text[start:end].split())[:360]

    if verdict_str:
        verdict_str = verdict_str.strip().rstrip(".:,)*` ")
    return verdict_str, key_evidence


def _match_counter_test(input_path: Path) -> Optional[Dict[str, Any]]:
    """Identify which PLAN-X counter-test an input results.md maps to."""
    path_str = str(input_path)
    for ct in COUNTER_TESTS:
        if ct["lane_pattern"] in path_str.upper().replace("-", "_"):
            return ct
    return None


def _classify_verdict(counter_test_id: str, verdict_string: Optional[str], full_text: str) -> Tuple[str, str]:
    """Return (classification, reason)."""
    if not verdict_string:
        return ("INCONCLUSIVE", "No verdict line found in results.md.")
    mappings = VERDICT_MAPPINGS.get(counter_test_id, [])
    haystack = verdict_string + "\n" + full_text
    for pattern, classification, reason in mappings:
        if pattern.search(haystack):
            return (classification, reason)
    return ("INCONCLUSIVE", f"Verdict string '{verdict_string}' did not match any known mapping for {counter_test_id}.")


def _check_immediate_bail(text: str) -> List[str]:
    """Return list of bail criteria triggered by an immediate bail pattern."""
    triggered = []
    for criterion_id, pattern in IMMEDIATE_BAIL_PATTERNS:
        if pattern.search(text):
            triggered.append(criterion_id)
    return triggered


def synthesize(input_paths: List[Path], strict: bool = False) -> Dict[str, Any]:
    """Synthesize PLAN-X counter-test verdict matrix from input paths."""
    results: List[CounterTestResult] = []
    matched_lane_patterns = set()
    immediate_bails: List[str] = []
    diagnostics: List[str] = []

    # First, process every input path that exists.
    for input_path in input_paths:
        ct_meta = _match_counter_test(input_path)
        if ct_meta is None:
            diagnostics.append(f"WARN: input {input_path} does not match any known PLAN-X counter-test pattern; skipping")
            continue
        matched_lane_patterns.add(ct_meta["lane_pattern"])
        result = CounterTestResult(
            counter_test_id=ct_meta["counter_test_id"],
            name=ct_meta["name"],
            plan_x_dissent=ct_meta["plan_x_dissent"],
            claim=ct_meta["claim"],
            pass_condition=ct_meta["pass_condition"],
            input_path=str(input_path),
        )
        text = _read_text(input_path)
        if text is None:
            result.classification = "NOT-YET-RUN"
            result.classification_reason = "Input file missing or unreadable."
            result.diagnostics.append(f"missing-or-unreadable: {input_path}")
            results.append(result)
            continue
        result.lane_id = _extract_lane_id(text)
        verdict_string, key_evidence = _extract_verdict_line(text)
        result.verdict_string = verdict_string
        result.key_evidence = key_evidence
        cls, reason = _classify_verdict(ct_meta["counter_test_id"], verdict_string, text)
        result.classification = cls
        result.classification_reason = reason
        bails = _check_immediate_bail(text)
        if bails:
            immediate_bails.extend(bails)
            result.diagnostics.append(f"immediate-bail-triggered: {bails}")
        results.append(result)

    # Then, fill in NOT-YET-RUN entries for any counter-test pattern we
    # didn't see an input for.
    for ct in COUNTER_TESTS:
        if ct["lane_pattern"] not in matched_lane_patterns:
            results.append(CounterTestResult(
                counter_test_id=ct["counter_test_id"],
                name=ct["name"],
                plan_x_dissent=ct["plan_x_dissent"],
                claim=ct["claim"],
                pass_condition=ct["pass_condition"],
                classification="NOT-YET-RUN",
                classification_reason="No input results.md provided for this counter-test.",
            ))

    # Sort by counter_test_id for deterministic output.
    results.sort(key=lambda r: r.counter_test_id)

    # Compute aggregate.
    falsified_count = sum(1 for r in results if r.classification == "PLAN-X-FALSIFIED")
    supported_count = sum(1 for r in results if r.classification == "PLAN-X-SUPPORTED")
    inconclusive_count = sum(1 for r in results if r.classification == "INCONCLUSIVE")
    not_yet_run_count = sum(1 for r in results if r.classification == "NOT-YET-RUN")
    total = len(results)

    if immediate_bails:
        aggregate_verdict = "bail-immediately"
        aggregate_reason = (
            f"Immediate-bail criterion fired: {', '.join(sorted(set(immediate_bails)))}. "
            "Master plan section 7 criteria #1-#5 override aggregate verdict."
        )
    elif falsified_count >= 3:
        aggregate_verdict = "pivot-to-pillar-build"
        aggregate_reason = (
            f"{falsified_count}/{total} counter-tests resolved to PLAN-X-FALSIFIED. "
            "Operator decision: greenlight Phase A pillar build per master-plan checkpoint pivot dispatch plan "
            "(PILLAR-P1-MVP + PILLAR-P3-MVP + PILLAR-P4-MVP + PILLAR-P5-MVP-1)."
        )
    elif supported_count >= 3:
        aggregate_verdict = "bail-per-criterion-6"
        aggregate_reason = (
            f"{supported_count}/{total} counter-tests resolved to PLAN-X-SUPPORTED. "
            "Bail per master plan section 7 criterion #6 (PLAN-X counter-tests all flip negative). "
            "Kill pillar build; pivot to active hunt on Spark + Hyperbridge + dydx."
        )
    else:
        aggregate_verdict = "needs-more-data"
        aggregate_reason = (
            f"Counter-test resolution: FALSIFIED={falsified_count} / SUPPORTED={supported_count} / "
            f"INCONCLUSIVE={inconclusive_count} / NOT-YET-RUN={not_yet_run_count}. "
            "Neither pivot nor bail threshold (>=3 of 4) reached. "
            "Operator should either re-run inconclusive lanes with stronger evidence, "
            "wait for not-yet-run lanes to land, or run 1-3 additional probe lanes per master plan §5 Phase 0."
        )

    payload = {
        "schema": SCHEMA_ID,
        "tool_version": TOOL_VERSION,
        "aggregate_verdict": aggregate_verdict,
        "aggregate_reason": aggregate_reason,
        "counter_test_summary": {
            "total": total,
            "PLAN-X-FALSIFIED": falsified_count,
            "PLAN-X-SUPPORTED": supported_count,
            "INCONCLUSIVE": inconclusive_count,
            "NOT-YET-RUN": not_yet_run_count,
        },
        "immediate_bails_triggered": sorted(set(immediate_bails)),
        "counter_test_results": [asdict(r) for r in results],
        "diagnostics": diagnostics,
    }

    if strict and (inconclusive_count + not_yet_run_count) > 0:
        payload["strict_warning"] = (
            f"--strict was set and {inconclusive_count + not_yet_run_count} counter-tests are "
            "INCONCLUSIVE/NOT-YET-RUN. Aggregate verdict still computed but operator should not act on it "
            "until all 4 counter-tests resolve to FALSIFIED or SUPPORTED."
        )

    return payload


def render_summary_markdown(payload: Dict[str, Any]) -> str:
    """Render operator-facing OPERATOR_PHASE0_SUMMARY.md content."""
    lines: List[str] = []
    av = payload["aggregate_verdict"]
    summary = payload["counter_test_summary"]

    lines.append("# Phase 0 Sprint Result - Operator Decision Summary")
    lines.append("")
    lines.append(f"**Generated by:** `tools/phase0-verdict-synthesizer.py` (schema `{payload['schema']}`)")
    lines.append("")
    lines.append(f"## Phase 0 sprint result: **{av}**")
    lines.append("")
    lines.append(payload["aggregate_reason"])
    lines.append("")

    lines.append("## Counter-test summary")
    lines.append("")
    lines.append("| Classification | Count |")
    lines.append("|----------------|------:|")
    for k in ("PLAN-X-FALSIFIED", "PLAN-X-SUPPORTED", "INCONCLUSIVE", "NOT-YET-RUN"):
        lines.append(f"| {k} | {summary[k]} |")
    lines.append(f"| **TOTAL** | **{summary['total']}** |")
    lines.append("")

    if payload["immediate_bails_triggered"]:
        lines.append("## Immediate bail criteria fired")
        lines.append("")
        for crit in payload["immediate_bails_triggered"]:
            lines.append(f"- `{crit}`")
        lines.append("")
        lines.append("Master plan section 7 criteria #1-#5 override aggregate verdict. Bail immediately.")
        lines.append("")

    lines.append("## Per-counter-test verdict matrix")
    lines.append("")
    lines.append("| Counter-test | PLAN-X dissent | Classification | Verdict from results.md | Lane id |")
    lines.append("|---|---|---|---|---|")
    for r in payload["counter_test_results"]:
        vstr = r.get("verdict_string") or "(no verdict line)"
        lane = r.get("lane_id") or "(no lane)"
        lines.append(
            f"| **{r['counter_test_id']}** {r['name']} | #{r['plan_x_dissent']} | "
            f"**{r['classification']}** | `{vstr}` | `{lane}` |"
        )
    lines.append("")

    lines.append("### Per-counter-test detail")
    lines.append("")
    for r in payload["counter_test_results"]:
        lines.append(f"#### {r['counter_test_id']} - {r['name']}")
        lines.append("")
        lines.append(f"- **PLAN-X dissent tested:** #{r['plan_x_dissent']} - {r['claim']}")
        lines.append(f"- **Pass condition (falsifies PLAN-X):** {r['pass_condition']}")
        lines.append(f"- **Result classification:** **{r['classification']}**")
        if r.get("classification_reason"):
            lines.append(f"- **Classification reason:** {r['classification_reason']}")
        if r.get("input_path"):
            lines.append(f"- **Evidence anchor:** `{r['input_path']}`")
        if r.get("key_evidence"):
            lines.append(f"- **Key evidence snippet:** {r['key_evidence']}")
        lines.append("")

    lines.append("## Recommendation to operator")
    lines.append("")
    if av == "pivot-to-pillar-build":
        lines.append("**Pivot to Phase A pillar build.** Greenlight the 4 PILLAR-* lanes per master plan checkpoint:")
        lines.append("")
        lines.append("| Lane | Pillar | Source | Effort |")
        lines.append("|---|---|---|---|")
        lines.append("| PILLAR-P1-MVP | P1 invariant extraction | Hand-curated 100-invariant pilot (PLAN-X recommendation #5). NOT the $51 LLM sweep. Operator+agent collab. | 4-6 days, ~$0 |")
        lines.append("| PILLAR-P3-MVP | P3 anti-pattern catalog | Collapse 3K existing Solidity detectors -> 80-120 RECALL-tuned anti-patterns. AST queries via slither IR. | 4-week sprint, ~$14 |")
        lines.append("| PILLAR-P4-MVP | P4 triager mind model | 3-class MVP (G dupe + F no-fund-impact + E DoS-class). Few-shot prompt from 35 verbatim triager comments. | 2.5-4 days, ~$11 |")
        lines.append("| PILLAR-P5-MVP-1 | P5 live-target intel | Standalone MVP-1: entry-points + placeholder anti-pattern IDs + engage-severity ranking. Ships value DAY ONE per PLAN-P5 thesis. | 2-3 days, ~$0 (no LLM for MVP-1) |")
    elif av == "bail-per-criterion-6":
        lines.append("**Bail per master plan section 7 criterion #6.** Kill all pillar build.")
        lines.append("")
        lines.append("Pivot 100% to active hunt:")
        lines.append("")
        lines.append("- Spark post-pin commit-mining lanes (LLLLLL recon backlog).")
        lines.append("- Hyperbridge uncovered pallets (`ismp-*` Rust surface).")
        lines.append("- dydx paste_ready triage (12 paste_ready drafts; 5 disputes in flight; 1 disclosure-held).")
        lines.append("- Operator-decision burndown on the 129 paste_ready+disputes queue surfaced by L0.1.")
    elif av == "bail-immediately":
        lines.append("**Bail immediately.** A bail criterion fired regardless of aggregate classification.")
        lines.append("")
        lines.append("Document the bail evidence + lessons learned; halt pillar build dispatch.")
    else:  # needs-more-data
        lines.append("**Run 1-3 more probe lanes before any pivot decision.**")
        lines.append("")
        lines.append("Specifically:")
        lines.append("")
        for r in payload["counter_test_results"]:
            if r["classification"] == "NOT-YET-RUN":
                lines.append(f"- **{r['counter_test_id']} ({r['name']})**: re-dispatch the lane; no results.md ingested yet.")
            elif r["classification"] == "INCONCLUSIVE":
                lines.append(f"- **{r['counter_test_id']} ({r['name']})**: re-run with stronger evidence path. Anchor: `{r.get('input_path') or '(unknown)'}`.")
        lines.append("")
        lines.append("After re-runs land, re-invoke `tools/phase0-verdict-synthesizer.py` to refresh this summary.")
    lines.append("")

    lines.append("## Honest caveats")
    lines.append("")
    if summary["NOT-YET-RUN"] > 0:
        lines.append(
            f"- **INCOMPLETE-DATA:** {summary['NOT-YET-RUN']} of {summary['total']} counter-tests have NOT landed yet. "
            "Aggregate verdict above is **preliminary**. Operator should re-run the synthesizer after the missing lanes land before acting on the recommendation."
        )
    if summary["INCONCLUSIVE"] > 0:
        lines.append(
            f"- **INCONCLUSIVE-DATA:** {summary['INCONCLUSIVE']} of {summary['total']} counter-tests landed but did not produce a sharp pass/fail signal. "
            "Re-running these with stronger evidence paths is the recommended remediation."
        )
    if not (summary["NOT-YET-RUN"] or summary["INCONCLUSIVE"]):
        lines.append("- All 4 counter-tests landed with sharp classifications.")
    if payload.get("diagnostics"):
        lines.append("")
        lines.append("Diagnostics:")
        for d in payload["diagnostics"]:
            lines.append(f"  - {d}")
    lines.append("")

    lines.append("## Provenance")
    lines.append("")
    lines.append(f"- Tool: `tools/phase0-verdict-synthesizer.py` v{TOOL_VERSION}")
    lines.append(f"- Schema: `{payload['schema']}`")
    lines.append("- Inputs:")
    for r in payload["counter_test_results"]:
        ip = r.get("input_path") or "(missing)"
        lines.append(f"  - `{ip}` -> {r['counter_test_id']} ({r['classification']})")
    lines.append("")
    lines.append("Re-run with: `python3 tools/phase0-verdict-synthesizer.py --inputs <path1> ... --output <this-file>`")
    lines.append("")

    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase 0 verdict synthesis: map L0.1-L0.4 lane verdicts to PLAN-X counter-tests.",
    )
    parser.add_argument(
        "--inputs",
        nargs="+",
        required=True,
        help="One or more results.md paths from PHASE0 lane directories.",
    )
    parser.add_argument(
        "--output",
        help="Optional path to write OPERATOR_PHASE0_SUMMARY.md markdown.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON payload to stdout (default: human-readable summary).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Add a strict_warning when INCONCLUSIVE or NOT-YET-RUN counter-tests are present.",
    )
    args = parser.parse_args(argv)

    input_paths = [Path(p) for p in args.inputs]

    try:
        payload = synthesize(input_paths, strict=args.strict)
    except Exception as exc:  # pragma: no cover - defensive
        err = {
            "schema": SCHEMA_ID,
            "tool_version": TOOL_VERSION,
            "aggregate_verdict": "error",
            "aggregate_reason": f"Unhandled exception: {exc}",
        }
        if args.json:
            print(json.dumps(err, indent=2, sort_keys=True))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.output:
        try:
            md = render_summary_markdown(payload)
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(md, encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: could not write --output {args.output}: {exc}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        # Human-readable: print the markdown.
        print(render_summary_markdown(payload))

    return 0


if __name__ == "__main__":
    sys.exit(main())
