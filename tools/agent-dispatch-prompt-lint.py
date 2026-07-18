#!/usr/bin/env python3
"""agent-dispatch-prompt-lint.py — lint a prompt before dispatching to a subagent.

Background (2026-05-04 fp_repair_v2 incident, PR #607): an LLM dispatch
emitted 91/91 fake YAMLs because the prompt asked the LLM to "refine the
predicate so it distinguishes the two fixtures" — fixtures had a uniform
shape (vulnerable=no-require, clean=has-require), so the LLM correctly
emitted a fixture-shape-distinguishing predicate. This was a prompt-
engineering failure, not an LLM regression.

This tool catches the failure mode BEFORE dispatch. Reads a prompt (file
or stdin), applies rules, exits 0/1/2.

Rules (each fail-closed when --strict, warn-only by default):

  R1  fixture-shape-trick: prompt mentions "distinguish the fixtures" /
      "make the predicate stricter" / "refine the YAML" WITHOUT also
      requiring the LLM to "encode the bug class" / "match the audit
      finding semantics" / "self-check against correct implementations".

  R2  missing-acceptance: prompt has no explicit acceptance criteria
      section (must contain "## Acceptance" or "Acceptance:" or similar).

  R3  missing-deliverable: prompt has no concrete deliverable path
      (must reference a file path or PR branch name).

  R4  missing-m14-discipline: for tasks that mutate detector registry,
      promote findings, or run LLM dispatches at scale, prompt must
      mention "M14-trap" or "fail-closed" or "honest accounting".

  R5  missing-budget-cap: tasks involving real LLM dispatch must cap
      the budget (mention $/N tasks/--max-N).

  R6  missing-self-test: tools or fixes must include a self-test step.

  R7  branch-name-implicit: prompt should specify the branch name for
      the agent to push to (avoids agent improvising a colliding branch).

  R8  missing-truth-evidence: prompt asks the agent to infer missing
      scope/source/proof/rubric/protocol truth but does not require direct
      source evidence or KG refs.

  R9  missing-mcp-receipt-evidence: when --workspace points at an audit
      workspace with .auditooor/memory_context_receipt.json, the prompt must
      visibly carry that receipt and at least one loaded context id/hash.

  R10 missing-audit-agent-start-packet: audit/finding/detector/proof prompts
      must include the compact MCP/rules/hackermind start packet or an
      equivalent explicit memory + rule + hacker-context block.

  R11 empty-candidate-packet: provider packets that ask for candidate / queue
      row review must not dispatch an empty ``[]`` candidate list. This catches
      the slice26 Kimi failure mode where a wrong JSON field grouped a recall
      queue to zero rows and still produced plausible generic advice.

Usage:
  python3 tools/agent-dispatch-prompt-lint.py <prompt-file>
  cat prompt.txt | python3 tools/agent-dispatch-prompt-lint.py -
  python3 tools/agent-dispatch-prompt-lint.py <prompt> --strict --json-out report.json

Exit codes:
  0  all rules PASS (or warnings only)
  1  --strict and at least one rule FAILED
  2  bad input

This is HEURISTIC. False positives WILL happen. Use --strict only for
auto-gating in CI; keep warn-only for interactive dispatch (operator
reads warnings + decides).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"


@dataclass
class RuleResult:
    rule: str
    status: str
    message: str
    matched_phrase: str = ""


# Anti-pattern phrases that signal a fixture-shape prompt
FIXTURE_SHAPE_TRIGGERS = [
    r"distinguish.{0,20}fixtures?",
    r"make.{0,20}predicate.{0,20}stricter",
    r"refine.{0,20}yaml.{0,30}fires?.{0,20}vuln.{0,40}not.{0,20}clean",
    r"so.{0,10}it.{0,10}fires?.{0,30}vuln(erable)?.{0,40}(not|but).{0,20}clean",
    r"tighten.{0,30}predicate",
    r"make.{0,20}detector.{0,30}fire.{0,30}vulnerable.{0,30}not.{0,30}clean",
]

# Counterweight phrases that demonstrate the prompt understands bug-class semantics
BUG_CLASS_COUNTERWEIGHTS = [
    r"encode.{0,20}bug.{0,10}class",
    r"audit.{0,20}finding.{0,30}semantics",
    r"would.{0,10}fire.{0,30}correct.{0,20}implementation",
    r"semantic.{0,10}predicate",
    r"capture.{0,20}why.{0,30}vulnerable",
    r"bug.{0,10}class.{0,30}encod",
    r"anti.{0,10}pattern",
    r"self.check",
]

# Acceptance section markers
ACCEPTANCE_MARKERS = [
    r"##\s*acceptance",
    r"^acceptance\s*:",
    r"acceptance\s+criteria",
]

# Deliverable signals (file path or branch name)
DELIVERABLE_SIGNALS = [
    r"`[^`]*\.(md|py|sh|yaml|yml|json)`",
    r"branch\s*[`\"']\s*[\w-]+",
    r"open\s+pr",
    r"deliverable",
]

# M14-trap discipline markers
M14_DISCIPLINE_MARKERS = [
    r"m14.?trap",
    r"fail.closed",
    r"honest\s+(accounting|report|assessment)",
    r"don'?t\s+fabricate",
    r"do not fabricate",
    r"no fabrication",
    r"diversity.check",
]

# Tasks that need M14 discipline
M14_RISK_MARKERS = [
    r"register",
    r"promote",
    r"tier.?registry",
    r"verified",
    r"llm.?dispatch",
    r"bulk",
    r"smoke.?test",
]

# Budget cap markers
BUDGET_MARKERS = [
    r"\$\d+\s*budget",
    r"budget.{0,10}\$\d+",
    r"--max-\w+\s+\d+",
    r"max.{0,10}tasks?",
    r"cap.{0,20}spend",
    r"~\$\d+",
    r"<\$\d+",
]

# Real-LLM-dispatch markers (need budget)
LLM_DISPATCH_MARKERS = [
    r"llm.?dispatch",
    r"call.{0,20}(sonnet|opus|kimi|minimax|gpt|claude)",
    r"dispatch.{0,30}prompt",
    r"mcp__solodit",
]

# Self-test markers
SELF_TEST_MARKERS = [
    r"self.?test",
    r"unit.?test",
    r"smoke.?test",
    r"test plan",
    r"verify.{0,30}(works|passes|succeeds)",
    r"acceptance.{0,30}check",
]

# Tools or fixes (need self-test)
TOOL_OR_FIX_MARKERS = [
    r"build\s+`?tools/",
    r"new\s+tool",
    r"add.{0,20}tool",
    r"fix\s+(the|this|a)",
    r"rewrite",
    r"extend\s+`?tools/",
]

# Branch name explicit
BRANCH_NAME_PATTERNS = [
    r"branch\s*[`\"']\s*[\w/-]+[`\"']",
    r"push.{0,20}branch\s+[\w/-]+",
    r"new\s+branch\s+[`\"']\s*[\w/-]+",
]

# Missing-truth inference requires source evidence or explicit KG anchoring.
MISSING_TRUTH_TRIGGERS = [
    r"\b(infer|derive|determine|identify|resolve|backfill|fill(?: in)?|autofill|recover|reconstruct|map)\b.{0,100}\b(missing|unknown|not provided|not recorded|could not be determined|<TODO_OPERATOR>|TODO_OPERATOR)\b.{0,100}\b(scope|source|proof|rubric|protocol)\b",
    r"\b(missing|unknown|not provided|not recorded|could not be determined|<TODO_OPERATOR>|TODO_OPERATOR)\b.{0,100}\b(scope|source|proof|rubric|protocol)\b.{0,100}\b(infer|derive|determine|identify|resolve|backfill|fill(?: in)?|autofill|recover|reconstruct|map)\b",
]

TRUTH_EVIDENCE_MARKERS = [
    r"\bdirect\s+evidence\b",
    r"\bsource\s+evidence\b",
    r"\bsource\s+citations?\b",
    r"\bfile:line\b",
    r"\bfile[-: ]line(?:\s+citations?)?\b",
    r"\bline[- ]cited\b",
    r"\bline\s+citations?\b",
    r"\bexact\s+source\s+lines?\b",
    r"\bprovided\s+production\s+source\b",
    r"\bprovided\s+sources?\b",
    r"\bfrom\s+the\s+source\b",
    r"\bsource_refs?\b",
    r"\bcontext_pack_path\b",
    r"\bsemantic_graph\.json\b",
    r"\bscoped\s+semantic\s+graph\b",
    r"\bKG\s+refs?\b",
    r"\bknowledge\s+gap\s+refs?\b",
    r"\bkg://",
    r"\bKG-[0-9]{8}-[0-9]{3}\b",
]

R8_NEGATED_INFERENCE = [
    r"\b(?:do not|don't|never|must not)\s+(?:try\s+to\s+)?(?:infer|derive|determine|identify|resolve|backfill|fill(?: in)?|autofill|recover|reconstruct|map)\b.{0,120}\b(?:missing|unknown|not provided|not recorded|could not be determined|<TODO_OPERATOR>|TODO_OPERATOR)\b.{0,120}\b(?:scope|source|proof|rubric|protocol)\b",
    r"\bwithout\s+(?:infer(?:ring)?|deriv(?:e|ing)|determin(?:e|ing)|identif(?:y|ying)|resolv(?:e|ing)|backfill(?:ing)?|fill(?:ing| in)?|autofill(?:ing)?|recover(?:ing)?|reconstruct(?:ing)?|mapp(?:ing)?)\b.{0,120}\b(?:missing|unknown|not provided|not recorded|could not be determined|<TODO_OPERATOR>|TODO_OPERATOR)\b.{0,120}\b(?:scope|source|proof|rubric|protocol)\b",
    r"\bleave\s+`?<TODO_OPERATOR>`?.{0,120}\b(?:do not|don't|never|must not)\b.{0,80}\b(?:infer|derive|determine|identify|resolve|backfill|fill(?: in)?|autofill|recover|reconstruct|map)\b",
]

R8_SOURCE_SECTION_HEADERS = [
    r"^#+\s*(?:Finding Content|Production source|Context \(untrusted|Context \(untrusted candidate text\)|Evidence behind the gap call|Source paths)\b",
]

R8_INSTRUCTION_SECTION_HEADERS = [
    r"^#+\s*(?:Acceptance|Constraints|Step \d+|Output Format|Branch|Task|Critical Framing|Verification|Completion memory update)\b",
]

R8_GLOBAL_EVIDENCE_ANCHORS = [
    r"(?is)##\s+Mandatory Context Pack\b.*\bcontext_pack_path\b.*\bsource_refs\b.*\bknowledge_gap_refs\b",
]

AUDIT_AGENT_TASK_TRIGGERS = [
    r"\bmake\s+audit\b",
    r"\baudit[-_ ]deep\b",
    r"\bsubmission\b",
    r"\bpaste[-_ ]ready\b",
    r"\bfinding\b",
    r"\bdetector\b",
    r"\bPoC\b",
    r"\bproof\s+(?:artifact|lane|work|obligation|manifest|evidence)\b",
    r"\bdydx\b",
    r"\bcantina\b",
    r"\bimmunefi\b",
    r"\bhacker[-_ ]brief\b",
    r"\bsource[-_ ]extract\b",
    r"\badversarial[-_ ]kill\b",
    r"\bharness[-_ ]plan\b",
    r"\bfixture[-_ ]map\b",
    r"\bpaste[-_ ]ready[-_ ]review\b",
]

AGENT_START_PACKET_MARKERS = [
    r"\bMCP_AUDIT_AGENT_START\.md\b",
    r"(?is)\bauditooor\.v3_worker_packet\.v1\b.{0,600}\bpacket_hash\b.{0,600}\bcontext_pack_id\b.{0,400}\bcontext_pack_hash\b",
    r"(?is)\bworker_packet_path\b.{0,400}\bpacket_hash\b.{0,600}\bcontext_pack_id\b.{0,400}\bcontext_pack_hash\b",
    r"(?is)\bcontext_pack_id\b.{0,400}\bcontext_pack_hash\b.{0,800}\b(?:pre[-_ ]submit|L27|R18|R19|R20|R21|R22|R23|R24|R25|R26|R27|R30)\b.{0,800}\b(?:hacker|kill[_-]?rubric|vault_engage_report_context|vault_function_mindset)\b",
]

MCP_EVIDENCE_RECEIPT_SCHEMA_PAT = r"\b(?:auditooor\.)?mcp_evidence_receipt\.v1\b"
MCP_EVIDENCE_RECEIPT_PATH_PAT = (
    r"\b(?:mcp_evidence_receipt|receipt_path|sidecar_path|artifact_path|worker_packet_path)\b"
)
MCP_EVIDENCE_RECEIPT_CONTEXT_PATTERNS = [
    r"\bcontext_pack_id\b.{0,220}\S+",
    r"\bcontext_pack_hash\b.{0,120}[0-9a-f]{64}\b",
]

EMPTY_CANDIDATE_PACKET_PATTERNS = [
    r"(?im)^\s*(?:actual\s+)?(?:candidate|queue|real[- ]world recall queue)\s+rows?[^:\n]*:\s*\n\s*\[\s*\]\s*(?:\n|$)",
    r"(?im)^\s*candidate[_ -]?list\s*:\s*\n\s*\[\s*\]\s*(?:\n|$)",
    r"(?im)^\s*candidate[_ -]?list\s*:\s*(?:none|empty)\s*(?:\n|$)",
]

CANDIDATE_PACKET_MARKERS = [
    r"\bcandidate[_ -]?list\b",
    r"\bcandidate\s+rows?\b",
    r"\bqueue\s+rows?\b",
    r"\breal[- ]world recall queue\b",
]


def has_any(text: str, patterns: List[str]) -> tuple[bool, str]:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            return True, m.group(0)
    return False, ""


def first_match(text: str, patterns: List[str]):
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            return m
    return None


def has_mcp_evidence_receipt_sidecar(text: str) -> tuple[bool, str]:
    schema = re.search(MCP_EVIDENCE_RECEIPT_SCHEMA_PAT, text, re.IGNORECASE | re.MULTILINE)
    path = re.search(MCP_EVIDENCE_RECEIPT_PATH_PAT, text, re.IGNORECASE | re.MULTILINE)
    contexts = [
        re.search(pat, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        for pat in MCP_EVIDENCE_RECEIPT_CONTEXT_PATTERNS
    ]
    if schema and path and all(contexts):
        return True, schema.group(0)
    return False, ""


def r8_instruction_text(text: str) -> str:
    lines = []
    in_source_section = False
    for line in text.splitlines():
        if has_any(line, R8_SOURCE_SECTION_HEADERS)[0]:
            in_source_section = True
            continue
        if in_source_section and has_any(line, R8_INSTRUCTION_SECTION_HEADERS)[0]:
            in_source_section = False
        if not in_source_section:
            lines.append(line)
    return "\n".join(lines)


def r8_has_evidence_anchor(text: str, trigger_start: int, trigger_end: int) -> bool:
    if has_any(text, R8_GLOBAL_EVIDENCE_ANCHORS)[0]:
        return True
    start = max(0, trigger_start - 250)
    end = min(len(text), trigger_end + 350)
    return has_any(text[start:end], TRUTH_EVIDENCE_MARKERS)[0]


def r9_receipt_evidence_result(text: str, workspace: Path | None) -> RuleResult:
    if workspace is None:
        return RuleResult(
            "R9_mcp_receipt_evidence", PASS,
            "No workspace receipt check requested")
    receipt_path = workspace / ".auditooor" / "memory_context_receipt.json"
    if not receipt_path.is_file():
        return RuleResult(
            "R9_mcp_receipt_evidence", PASS,
            "No workspace memory_context_receipt.json present")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return RuleResult(
            "R9_mcp_receipt_evidence", FAIL,
            f"Workspace memory_context_receipt.json exists but is unreadable: {exc}")
    if not isinstance(receipt, dict):
        return RuleResult(
            "R9_mcp_receipt_evidence", FAIL,
            "Workspace memory_context_receipt.json exists but is not a JSON object")
    summary = receipt.get("summary")
    if not isinstance(summary, dict) or summary.get("strict_ready") is not True:
        return RuleResult(
            "R9_mcp_receipt_evidence", FAIL,
            "Workspace memory_context_receipt.json exists but summary.strict_ready is not true")
    loaded = [row for row in receipt.get("loaded_contexts", []) if isinstance(row, dict)]
    if not loaded:
        return RuleResult(
            "R9_mcp_receipt_evidence", FAIL,
            "Workspace memory_context_receipt.json has no loaded_contexts to cite")
    has_evidence_sidecar, sidecar_match = has_mcp_evidence_receipt_sidecar(text)
    if "memory_context_receipt.json" not in text and not has_evidence_sidecar:
        return RuleResult(
            "R9_mcp_receipt_evidence", FAIL,
            "Workspace memory_context_receipt.json exists but the prompt does not mention it "
            "or an auditooor.mcp_evidence_receipt.v1 sidecar")
    evidence_tokens: list[str] = []
    for row in loaded:
        for key in ("context_pack_hash", "context_pack_id", "pack_path"):
            value = row.get(key)
            if isinstance(value, str) and value:
                evidence_tokens.append(value)
    matched = next((token for token in evidence_tokens if token in text), "")
    if not matched:
        return RuleResult(
            "R9_mcp_receipt_evidence", FAIL,
            "Workspace memory_context_receipt.json exists but the prompt omits loaded MCP context ids/hashes")
    return RuleResult(
        "R9_mcp_receipt_evidence", PASS,
        "Workspace MCP receipt evidence is visible in the prompt",
        matched or sidecar_match)


def r10_agent_start_packet_result(text: str) -> RuleResult:
    triggered, matched = has_any(text, AUDIT_AGENT_TASK_TRIGGERS)
    if not triggered:
        return RuleResult(
            "R10_audit_agent_start_packet", PASS,
            "Prompt does not look like an audit/finding/detector/proof dispatch")
    has_packet, packet_match = has_any(text, AGENT_START_PACKET_MARKERS)
    has_evidence_sidecar, sidecar_match = has_mcp_evidence_receipt_sidecar(text)
    if has_packet or has_evidence_sidecar:
        return RuleResult(
            "R10_audit_agent_start_packet", PASS,
            "Prompt includes compact MCP/rules/hackermind start packet evidence",
            packet_match or sidecar_match)
    return RuleResult(
        "R10_audit_agent_start_packet", FAIL,
        "Audit/finding/detector/proof prompt is missing the compact MCP/rules/hackermind "
        "start packet. Add docs/MCP_AUDIT_AGENT_START.md, or include context_pack_id/hash, "
        "submission/pre-submit rules, and hacker-context pulls such as kill rubric, "
        "detector provenance, function mindset, dupe/rejection, and originality context.",
        matched)


def r11_empty_candidate_packet_result(text: str) -> RuleResult:
    has_candidate_packet, _ = has_any(text, CANDIDATE_PACKET_MARKERS)
    if not has_candidate_packet:
        return RuleResult(
            "R11_empty_candidate_packet", PASS,
            "Prompt does not claim to dispatch candidate or queue rows")
    empty_match = first_match(text, EMPTY_CANDIDATE_PACKET_PATTERNS)
    if empty_match:
        return RuleResult(
            "R11_empty_candidate_packet", FAIL,
            "Prompt dispatches an empty candidate/queue row set. Fail closed: "
            "fix the packet builder field mapping or write an explicit "
            "NO_CANDIDATES reason instead of sending an LLM a blank evidence set.",
            empty_match.group(0))
    return RuleResult(
        "R11_empty_candidate_packet", PASS,
        "Candidate/queue row packet is not visibly empty")


def lint(text: str, workspace: Path | None = None) -> List[RuleResult]:
    text_lower = text.lower()
    results: List[RuleResult] = []

    # R1 — fixture-shape-trick
    has_trigger, triggered = has_any(text, FIXTURE_SHAPE_TRIGGERS)
    if has_trigger:
        has_counter, _ = has_any(text, BUG_CLASS_COUNTERWEIGHTS)
        if has_counter:
            results.append(RuleResult(
                "R1_fixture_shape_trick", PASS,
                "Fixture-shape phrasing present BUT also bug-class counterweight",
                triggered))
        else:
            results.append(RuleResult(
                "R1_fixture_shape_trick", FAIL,
                "Prompt asks LLM to distinguish fixtures without requiring "
                "bug-class semantic anchoring. This is the fp_repair_v2 "
                "failure mode (PR #607). Add 'encode the bug class' / "
                "'audit finding semantics' / 'would your predicate fire on "
                "a correct implementation that happens to share fixture "
                "shape?' counterweights.",
                triggered))
    else:
        results.append(RuleResult(
            "R1_fixture_shape_trick", PASS,
            "No fixture-shape trigger phrases detected"))

    # R2 — acceptance
    has_acc, _ = has_any(text, ACCEPTANCE_MARKERS)
    results.append(RuleResult(
        "R2_acceptance", PASS if has_acc else FAIL,
        "Acceptance section present" if has_acc
        else "No '## Acceptance' or 'Acceptance:' section. Agent will "
             "not know what 'done' means."))

    # R3 — deliverable
    has_deliv, _ = has_any(text, DELIVERABLE_SIGNALS)
    results.append(RuleResult(
        "R3_deliverable", PASS if has_deliv else WARN,
        "Deliverable signal present" if has_deliv
        else "No file path or branch name reference. Agent may improvise "
             "an output location."))

    # R4 — M14 discipline (only required if task is M14-risk)
    has_risk, _ = has_any(text, M14_RISK_MARKERS)
    if has_risk:
        has_m14, _ = has_any(text, M14_DISCIPLINE_MARKERS)
        results.append(RuleResult(
            "R4_m14_discipline", PASS if has_m14 else FAIL,
            "M14 discipline mentioned for registry-mutating task" if has_m14
            else "Task involves registry/detector/promote/LLM keywords but "
                 "no M14-trap discipline / fail-closed / honest-accounting "
                 "language. Risk of #607-style fakes."))
    else:
        results.append(RuleResult(
            "R4_m14_discipline", PASS,
            "Task does not mutate registry; M14 discipline optional"))

    # R5 — budget cap (only required if real-LLM dispatch)
    has_llm_dispatch, _ = has_any(text, LLM_DISPATCH_MARKERS)
    if has_llm_dispatch:
        has_budget, _ = has_any(text, BUDGET_MARKERS)
        results.append(RuleResult(
            "R5_budget_cap", PASS if has_budget else WARN,
            "Budget cap mentioned" if has_budget
            else "Task involves real LLM dispatch but no $ or --max-N "
                 "budget cap. Agent may run unbounded."))
    else:
        results.append(RuleResult(
            "R5_budget_cap", PASS,
            "Task does not involve real LLM dispatch; budget optional"))

    # R6 — self-test (only for tools/fixes)
    has_tool_or_fix, _ = has_any(text, TOOL_OR_FIX_MARKERS)
    if has_tool_or_fix:
        has_self_test, _ = has_any(text, SELF_TEST_MARKERS)
        results.append(RuleResult(
            "R6_self_test", PASS if has_self_test else WARN,
            "Self-test mentioned" if has_self_test
            else "Task is a tool build or fix but no self-test step. "
                 "Agent may ship untested code."))
    else:
        results.append(RuleResult(
            "R6_self_test", PASS,
            "Task is not a tool/fix; self-test optional"))

    # R7 — branch name explicit
    has_branch, _ = has_any(text, BRANCH_NAME_PATTERNS)
    if "open pr" in text_lower or "open a pr" in text_lower:
        results.append(RuleResult(
            "R7_branch_name", PASS if has_branch else WARN,
            "Branch name specified" if has_branch
            else "Task asks to open a PR but no branch name specified. "
                 "Agent may pick a colliding branch."))
    else:
        results.append(RuleResult(
            "R7_branch_name", PASS,
            "Task does not require branch creation"))

    # R8 — missing truth must be evidence-anchored
    r8_text = r8_instruction_text(text)
    missing_truth_match = first_match(r8_text, MISSING_TRUTH_TRIGGERS)
    if missing_truth_match:
        negated_truth, _ = has_any(r8_text, R8_NEGATED_INFERENCE)
        has_truth_evidence = r8_has_evidence_anchor(
            r8_text,
            missing_truth_match.start(),
            missing_truth_match.end(),
        )
        results.append(RuleResult(
            "R8_missing_truth_evidence",
            PASS if has_truth_evidence or negated_truth else FAIL,
            "Missing-truth inference is explicitly forbidden or left to TODO_OPERATOR"
            if negated_truth else
            "Missing-truth inference is anchored to direct evidence or KG refs"
            if has_truth_evidence else
            "Prompt asks the agent to infer missing scope/source/proof/rubric/protocol truth "
            "without requiring direct evidence or KG refs. Add source citations, file:line, "
            "provided-source-only language, semantic_graph/KG refs, or leave TODO_OPERATOR.",
            missing_truth_match.group(0),
        ))
    else:
        results.append(RuleResult(
            "R8_missing_truth_evidence", PASS,
            "No missing-truth inference request detected"))

    # R9 -- workspace MCP receipt evidence must be visible when present.
    results.append(r9_receipt_evidence_result(text, workspace))

    # R10 -- audit workers need the compact MCP/rules/hackermind packet.
    results.append(r10_agent_start_packet_result(text))

    # R11 -- provider candidate packets must not silently dispatch empty rows.
    results.append(r11_empty_candidate_packet_result(text))

    return results



# ---------------------------------------------------------------------------
# Routing-manifest check (--check-routing, warn-only, never fail)
# ---------------------------------------------------------------------------

ROUTING_MANIFEST_DEFAULT = Path(__file__).parent / "calibration" / "routing_manifest.yaml"


def _load_routing_manifest(path: Path):
    """Load routing_manifest.yaml; return dict or None on error."""
    try:
        import yaml  # type: ignore
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except ImportError:
        try:
            text = path.read_text(encoding="utf-8")
            data: dict = {"task_types": {}}
            current = None
            for line in text.splitlines():
                m = re.match(r"^  (\w[\w-]*):\s*$", line)
                if m:
                    current = m.group(1)
                    data["task_types"][current] = {}
                if current and ":" in line:
                    key, _, val = line.strip().partition(":")
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and val and key != current:
                        data["task_types"][current][key] = val
            return data
        except Exception:
            return None
    except Exception:
        return None


def check_routing(text: str, manifest_path=None) -> List[RuleResult]:
    """Check prompt against routing manifest. All results are WARN-only."""
    if manifest_path is None:
        manifest_path = ROUTING_MANIFEST_DEFAULT

    results: List[RuleResult] = []

    if not manifest_path.exists():
        results.append(RuleResult(
            "RC0_manifest_missing", WARN,
            f"routing_manifest.yaml not found at {manifest_path}. "
            "Routing validation skipped."))
        return results

    manifest = _load_routing_manifest(manifest_path)
    if manifest is None:
        results.append(RuleResult(
            "RC0_manifest_parse_error", WARN,
            f"Could not parse routing_manifest.yaml at {manifest_path}."))
        return results

    task_types_map = manifest.get("task_types", {})

    task_type_match = re.search(
        r"task.type\s*[:=]\s*([\w-]+)", text, re.IGNORECASE)
    if not task_type_match:
        return results

    task_type = task_type_match.group(1).lower().replace("_", "-")

    if task_type not in task_types_map:
        results.append(RuleResult(
            "RC1_task_type_unknown", WARN,
            f"Task-type '{task_type}' not found in routing manifest. "
            "Treat as no-data (advisory-only)."))
        return results

    tt = task_types_map[task_type]
    status = tt.get("status", "no-data") if isinstance(tt, dict) else "no-data"

    if status == "do-not-route":
        results.append(RuleResult(
            "RC2_do_not_route", WARN,
            f"Task-type '{task_type}' is marked do-not-route in routing manifest "
            f"(TP rate below 70% floor for all providers). "
            "Use human review instead of LLM dispatch."))

    elif status in ("advisory-only", "no-data"):
        results.append(RuleResult(
            "RC4_advisory_only", WARN,
            f"Task-type '{task_type}' has status '{status}' — insufficient "
            "calibration data. Treat LLM output as preliminary guidance only."))

    elif status == "route-ok":
        preferred = tt.get("preferred") if isinstance(tt, dict) else None
        provider_match = re.search(
            r"provider\s*[:=]\s*([\w-]+)", text, re.IGNORECASE)
        if provider_match and preferred:
            specified = provider_match.group(1).lower()
            if specified != preferred.lower():
                results.append(RuleResult(
                    "RC3_non_preferred_provider", WARN,
                    f"Task-type '{task_type}' recommends '{preferred}' but "
                    f"prompt specifies '{specified}'."))

    if isinstance(tt, dict):
        mitigations = tt.get("mitigations", [])
        if status in ("do-not-route", "advisory-only", "no-data") and not mitigations:
            results.append(RuleResult(
                "RC5_no_mitigations", WARN,
                f"Task-type '{task_type}' has no mitigations in routing manifest."))

    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("prompt", help="path to prompt file, or '-' for stdin")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any rule FAILed")
    ap.add_argument("--json-out", default=None,
                    help="optional path to write JSON report")
    ap.add_argument("--check-routing", action="store_true",
                    help="validate task-type routing against routing_manifest.yaml (warn-only)")
    ap.add_argument("--workspace", default=None,
                    help="audit workspace root; if it has a memory context receipt, require prompt evidence")
    args = ap.parse_args()

    if args.prompt == "-":
        text = sys.stdin.read()
    else:
        path = Path(args.prompt)
        if not path.exists():
            print(f"prompt file not found: {path}", file=sys.stderr)
            return 2
        text = path.read_text(encoding="utf-8")

    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else None
    results = lint(text, workspace=workspace)

    if args.check_routing:
        routing_results = check_routing(text)
        results = results + routing_results

    fails = [r for r in results if r.status == FAIL]
    warns = [r for r in results if r.status == WARN]
    passes = [r for r in results if r.status == PASS]

    print(f"[agent-dispatch-prompt-lint]")
    print(f"  prompt-length: {len(text)} chars")
    print(f"  rules: {len(results)} ({len(passes)} PASS, {len(warns)} WARN, {len(fails)} FAIL)")
    print()

    for r in results:
        marker = {"PASS": "✓", "WARN": "⚠", "FAIL": "❌"}[r.status]
        print(f"  {marker} {r.rule}: {r.status}")
        if r.status != PASS:
            print(f"     → {r.message}")
            if r.matched_phrase:
                print(f"     matched: {r.matched_phrase!r}")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "schema": "auditooor.agent_dispatch_prompt_lint.v1",
            "prompt_length": len(text),
            "results": [
                {"rule": r.rule, "status": r.status,
                 "message": r.message, "matched_phrase": r.matched_phrase}
                for r in results
            ],
            "fail_count": len(fails),
            "warn_count": len(warns),
            "pass_count": len(passes),
        }, indent=2))

    if args.strict and fails:
        print()
        print("  STRICT MODE: failing due to ❌ rules above.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
