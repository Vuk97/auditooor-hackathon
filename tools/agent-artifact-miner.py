#!/usr/bin/env python3
"""agent-artifact-miner.py - Turn every worker output and failed PoC into future capability.

Scans a workspace for agent-produced artifacts and emits structured learning
records: candidate detector patterns, hacker questions, rejection/kill patterns,
harness template requests, proof-artifact mapping candidates, known limitations,
roadmap gaps, kill rubric entries, triager patterns, provider calibration rows,
and exploit queue enrichment records.

Input sources mined:
  - agent_outputs/*/REPORT.md (per-round worker reports)
  - agent_outputs/*_output.md (slice subagent final messages: kimi, minimax, codex)
  - agent_outputs/provider_outputs/*.txt (structured provider kill JSON)
  - agent_outputs/llm_dispatch_*.json (LLM dispatch logs)
  - agent_outputs/*.go.txt, *_test.go, poc_*.js (PoC files)
  - agent_outputs/*commit*mining*.json (commit mining JSON)
  - reports/provider_normalized_work_queue.jsonl (normalized provider output queue)
  - reports/slice_finalization_*.json (slice finalization manifests)
  - reports/*worker*.md, reports/*.md (worker/agent report MDs)
  - reports/git_commits_mining*.json (commit mining reports)
  - poc-tests/**/*.go, **/*.js (PoC test files)
  - submissions/**/*.md (filed, paste_ready, staging, rejected, superseded)
  - SUBMISSIONS.md (workspace submission index)
  - docs/archive/handoffs/*.md, docs/*handoff*.md (Claude/Codex handoff docs)
  - agent_outputs/*handoff*.md, agent_outputs/*handover*.md
  - .auditooor/commit_lifecycle_ledger.json

Rules:
  - Provider-only text is NOT a learning artifact unless local source proof verifies it.
  - Killed leads are valuable: mine the kill reason into FP calibration /
    detector precision / triager objection / harness blocker.
  - Failed PoCs feed falsification templates and negative-control patterns.
  - Filed/accepted/rejected submissions feed severity/scope oracle and
    proof-hardening rules.
  - Finalization manifests feed provider calibration rows and exploit queue enrichment.
  - Handoff docs feed hacker-question seeds and roadmap gaps.

Output artifact types:
  - candidate_detector_pattern: detector pattern seed from any source
  - falsification_template: failed PoC / negative control
  - kill_rubric_entry: structured kill reason from provider or REPORT (NEW)
  - triager_pattern: triager feedback / objection pattern (NEW)
  - provider_calibration_row: per-provider job result row for calibration (NEW)
  - exploit_queue_enrichment: attack class + local verification hint (NEW)
  - candidate_hacker_question: local-verification-required follow-up
  - proof_artifact_mapping_candidate: passing PoC or proof-hardening lesson
  - harness_template_request: harness-blocked lane needing harness template
  - known_limitation: capability lesson from REPORT or backfill
  - roadmap_gap: future work / follow-up / deferred item

Every emitted artifact carries a verification_tier per Rule 37:
  tier-1-verified-realtime-api, tier-1-officially-disclosed,
  tier-2-verified-public-archive, tier-3-synthetic-taxonomy-anchored,
  tier-4-bundled-fixture, tier-5-quarantine.

Usage:
    python3 tools/agent-artifact-miner.py --workspace ~/audits/<project> --out report.json
    python3 tools/agent-artifact-miner.py --workspace ~/audits/<project> --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.agent_artifact_mining.v2"


@dataclass(frozen=True)
class ArtifactInputSource:
    path: Path
    source_type: str
    scanner: str

# ---------------------------------------------------------------------------
# Regex patterns for signal extraction
# ---------------------------------------------------------------------------

# Verdict lines in REPORT.md files
VERDICT_RE = re.compile(
    r"VERDICT\s*[:=\-]\s*"
    r"(NEGATIVE-PROVIDER-ONLY|CRITICAL-CANDIDATE|HIGH-CANDIDATE|"
    r"MEDIUM-CANDIDATE|LOW-CANDIDATE|NEEDS-VERIFY|NO[_-]KILL|"
    r"NEGATIVE|CANDIDATE|KILL|DROP|POSITIVE|BLOCKED|FP|TP|SKIP)"
    r"(?=$|[^\w-])",
    re.IGNORECASE,
)

# Kill/drop reasoning patterns
KILL_RE = re.compile(
    r"(?:KILL|DROP|NEGATIVE|killed|dropped|out[- ]of[- ]scope|OOS)[:\s]+([^\n]{10,200})",
    re.IGNORECASE,
)

# Provider-only verdict (no local verification)
PROVIDER_ONLY_RE = re.compile(
    r"(?:provider[- ]only|llm[- ]text[- ]only|no local verification|"
    r"local_verification_required[\"']?\s*:\s*false|"
    r"NEGATIVE-PROVIDER-ONLY|unverified provider)",
    re.IGNORECASE,
)

# Local source proof signals. Keep generic test commands and broad PASS tokens
# outside this strong pattern; dependency/baseline tests should not promote a
# worker artifact without subject-specific proof context.
LOCAL_PROOF_RE = re.compile(
    r"(?:local_verification_required[\"']?\s*:\s*true|"
    r"source[- ]proof|local proof|PoC pass|poc_test\.go)",
    re.IGNORECASE | re.MULTILINE,
)
TEST_COMMAND_RE = re.compile(
    r"\b(?:forge\s+test|go\s+test)\b|(?:PASS|ok\s*$|test PASS|suite result: ok|TestRound|--- PASS:|_test\.go)",
    re.IGNORECASE | re.MULTILINE,
)
TEST_PROOF_CONTEXT_RE = re.compile(
    r"\b(?:PoC|proof|local verification|reproduc|exploit|candidate|"
    r"test transcript|expected output|PASS|--- PASS|suite result)\b",
    re.IGNORECASE,
)
NEGATIVE_TEST_CONTEXT_RE = re.compile(
    r"\b(?:unrelated|dependency|external dependency|baseline only|tooling test|"
    r"not the PoC|not this PoC|no local proof|without local proof|"
    r"no local verification)\b",
    re.IGNORECASE,
)

# PoC failure signals
POC_FAIL_RE = re.compile(
    r"(?:FAIL|panic|revert|assertion failed|--- FAIL:|test failed|"
    r"harness[- ]blocked|PoC blocked|not reproduc|could not reproduce|"
    r"negative[- ]control|falsif)",
    re.IGNORECASE,
)
REPRO_FAIL_RE = re.compile(
    r"(?:not reproduc|could not reproduce|failed reproduction|reproduction failed)",
    re.IGNORECASE,
)

# Capability lesson signals (explicit lesson blocks)
LESSON_RE = re.compile(
    r"##\s*Capability\s+[Ll]esson[s]?\s*\n((?:.|\n){30,1000}?)(?=\n##|\Z)",
    re.MULTILINE,
)

# Harness blocker signals
HARNESS_BLOCKER_RE = re.compile(
    r"(?:harness[- ]blocked|harness blocker|harness-blocked|"
    r"subagent REPORT\.md write was harness[- ]blocked|"
    r"missing harness|needs? harness|harness template)",
    re.IGNORECASE,
)

# Triager objection signals
TRIAGER_OBJECTION_RE = re.compile(
    r"(?:triager|triag(?:e|ing)|closed as|closed for|OOS closed|"
    r"rejected by triager|triager closed|triager comment)",
    re.IGNORECASE,
)

# Detector pattern signals
DETECTOR_SIGNAL_RE = re.compile(
    r"(?:detector pattern|detector seed|candidate detector|"
    r"derivable pattern|pattern shape|pattern fire|unguarded \w+|"
    r"missing guard|missing validation|missing reentrancy|"
    r"no overflow guard|no bounds check)",
    re.IGNORECASE,
)

# Roadmap gap signals
ROADMAP_GAP_RE = re.compile(
    r"(?:roadmap gap|future[- ]regression|future work|known limitation|"
    r"KNOWN_LIMITATION|TODO|follow[- ]?up|queued for|deferred|"
    r"next[- ]audit|next[- ]loop|future engagement)",
    re.IGNORECASE,
)

# Submission outcome signals
SUBMISSION_OUTCOME_RE = re.compile(
    r"(?:SUBMITTED|FILED|ACCEPTED|REJECTED|CLOSED|ESCALATED|IN_REVIEW|"
    r"Immunefi|Cantina|Sherlock|Code4rena)",
    re.IGNORECASE,
)

# Proof hardening / rule violation signals
PROOF_HARDENING_RE = re.compile(
    r"(?:keeper[- ]level proof|direct keeper|FundAccount|MemDB|"
    r"production[- ]profile|production reachability|"
    r"Rule 18|Rule 19|Rule 25|Rule 30|R18|R19|R25|R30|"
    r"in[- ]process[- ]only|node[- ]level|real ABCI|FinalizeBlock)",
    re.IGNORECASE,
)

# Provider calibration signals: verdicts + model names in provider outputs
PROVIDER_VERDICT_RE = re.compile(
    r"(?:KILL|WEAKEN|KEEP[-\s]NARROW|KEEP|NO[_\s-]KILL|POSITIVE|NEGATIVE|"
    r"provider_failure|candidate_detector_generalization|"
    r"kill_reason_pending_local_check|verified_source_fact_pending_local_check)",
    re.IGNORECASE,
)

# Triager pattern signals (specific triager-feedback language)
TRIAGER_FEEDBACK_RE = re.compile(
    r"(?:triager\s+(?:ask|comment|rationale|verdict|closed|flagged)|"
    r"OOS\s+(?:closed|rejected|closure)|closed\s+(?:as|for)\s+(?:OOS|generic|spam|"
    r"duplicate|informational)|triager\s+feedback|triager\s+raised|"
    r"triager\s+question|Ask\s+#\d|triager\s+pattern)",
    re.IGNORECASE,
)

# Handoff / next-session signals
HANDOFF_RE = re.compile(
    r"(?:handoff|handover|next[- ]session|next[- ]loop|next[- ]iteration|"
    r"pass[- ]to|relay[- ]to|pickup[- ]point|session[- ]pickup|"
    r"OPERATOR_HANDOFF|HANDOVER|for the next|continuing from)",
    re.IGNORECASE,
)

# Slice subagent output file name patterns (provider output MDs)
SLICE_OUTPUT_RE = re.compile(
    r"(?:slice\d+[a-z]?_(?:kimi|minimax|codex|claude|gpt|gemini|deepseek|mistral)_"
    r"(?:output|kill_output|source_output|analysis_output)|"
    r"(?:kimi|minimax|codex)_.*_output)",
    re.IGNORECASE,
)

# Exploit queue enrichment signals
EXPLOIT_QUEUE_RE = re.compile(
    r"(?:attack[_\s]class|attack_class|exploit[_\s]queue|proof[_\s]obligation|"
    r"hacker[_\s]question|chain[_\s]candidate|chained[_\s]attack|"
    r"local_verification_command|minimum_followup_check|"
    r"normalized_type.*candidate|disposition.*KEEP)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_text(path: Path) -> str:
    """Read file text, returning empty string on any error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _short_hash(text: str, length: int = 12) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:length]


def _provenance_ref(path: Path, ws: Path) -> str:
    """Return a workspace-relative path string for provenance."""
    try:
        return str(path.relative_to(ws))
    except ValueError:
        return str(path)


def _is_provider_only(text: str, path: Path) -> bool:
    """Return True if this artifact has no local-verification signal."""
    has_provider_only = bool(PROVIDER_ONLY_RE.search(text))
    has_local_proof = _has_local_proof(text)
    # JSON dispatch files from llm_dispatch_*.json are provider-only by nature
    is_dispatch_json = "llm_dispatch" in path.name and path.suffix == ".json"
    # Raw provider text files (no code signals at all)
    is_raw_provider_text = path.suffix == ".txt" and not has_local_proof
    if has_local_proof:
        return False
    if has_provider_only or is_dispatch_json or is_raw_provider_text:
        return True
    return False


def _extract_kill_reasons(text: str) -> list[str]:
    reasons = []
    for m in KILL_RE.finditer(text):
        r = m.group(1).strip()
        if r:
            reasons.append(r[:200])
    return reasons[:5]


def _extract_lesson(text: str) -> str | None:
    m = LESSON_RE.search(text)
    if m:
        return m.group(1).strip()[:600]
    return None


def _extract_verdict(text: str) -> str | None:
    m = VERDICT_RE.search(text)
    if m:
        verdict = m.group(1).upper()
        if verdict == "NO-KILL":
            return "NO_KILL"
        return verdict
    return None


def _has_local_proof(text: str) -> bool:
    """Return true only for local proof signals tied to the artifact subject."""
    direct = LOCAL_PROOF_RE.search(text)
    if direct:
        start = max(0, direct.start() - 180)
        end = min(len(text), direct.end() + 180)
        if not NEGATIVE_TEST_CONTEXT_RE.search(text[start:end]):
            return True
    if NEGATIVE_TEST_CONTEXT_RE.search(text) and not TEST_PROOF_CONTEXT_RE.search(text):
        return False
    if NEGATIVE_TEST_CONTEXT_RE.search(text) and not re.search(
        r"\b(?:PoC proof|local verification|reproduced|exploit proof|candidate proof)\b",
        text,
        re.IGNORECASE,
    ):
        return False
    if direct:
        return True
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if not TEST_COMMAND_RE.search(line):
            continue
        start = max(0, idx - 3)
        end = min(len(lines), idx + 4)
        window = "\n".join(lines[start:end])
        if NEGATIVE_TEST_CONTEXT_RE.search(window):
            continue
        if TEST_PROOF_CONTEXT_RE.search(window):
            return True
    return False


def _apply_provider_only_quarantine(artifacts: list[dict], provider_only: bool) -> None:
    """Mark report-derived provider-only artifacts as quarantine-only."""
    if not provider_only:
        return
    for artifact in artifacts:
        if artifact.get("source_has_local_proof") is True:
            continue
        artifact["verification_tier"] = "tier-5-quarantine"
        artifact["provider_only"] = True


def _sev_from_verdict(verdict: str | None) -> str:
    if not verdict:
        return "UNKNOWN"
    v = verdict.upper()
    if "CRITICAL" in v:
        return "CRITICAL"
    if "HIGH" in v:
        return "HIGH"
    if "MEDIUM" in v:
        return "MEDIUM"
    if "LOW" in v:
        return "LOW"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Artifact source scanners - each returns a list of raw artifact dicts
# ---------------------------------------------------------------------------

def _scan_report_md(path: Path, ws: Path) -> list[dict]:
    """Scan a REPORT.md file."""
    text = _read_text(path)
    if not text:
        return []

    verdict = _extract_verdict(text)
    sev = _sev_from_verdict(verdict)
    provider_only = _is_provider_only(text, path)
    kill_reasons = _extract_kill_reasons(text)
    lesson = _extract_lesson(text)
    has_poc_fail = bool(POC_FAIL_RE.search(text))
    has_harness_blocker = bool(HARNESS_BLOCKER_RE.search(text))
    has_triager_obj = bool(TRIAGER_OBJECTION_RE.search(text))
    has_detector_signal = bool(DETECTOR_SIGNAL_RE.search(text))
    has_roadmap_gap = bool(ROADMAP_GAP_RE.search(text))
    has_proof_hardening = bool(PROOF_HARDENING_RE.search(text))
    has_local_proof = _has_local_proof(text)

    artifacts = []
    prov = _provenance_ref(path, ws)

    # Capability lesson -> highest priority learning artifact
    if lesson:
        artifacts.append({
            "artifact_type": "known_limitation",
            "title": f"Capability lesson from {path.parent.name}",
            "content": lesson,
            "provenance_ref": prov,
            "verdict": verdict,
            "verification_tier": "tier-2-verified-public-archive" if has_local_proof else "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Killed/dropped leads -> rejection pattern + FP calibration
    if verdict in ("NEGATIVE", "KILL", "DROP", "FP") or (verdict and "NEGATIVE" in verdict):
        if kill_reasons:
            artifacts.append({
                "artifact_type": "rejection_pattern",
                "title": f"Kill/rejection reasons from {path.parent.name}",
                "content": "; ".join(kill_reasons),
                "provenance_ref": prov,
                "verdict": verdict,
                "verification_tier": "tier-2-verified-public-archive" if has_local_proof else "tier-3-synthetic-taxonomy-anchored",
                "source_has_local_proof": has_local_proof,
            })

    # Harness blocker -> harness template request
    if has_harness_blocker:
        artifacts.append({
            "artifact_type": "harness_template_request",
            "title": f"Harness blocker in {path.parent.name}",
            "content": f"REPORT at {prov} was harness-blocked; subagent could not write output. "
                       f"Verdict: {verdict}. Severity: {sev}.",
            "provenance_ref": prov,
            "verdict": verdict,
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Failed PoC signals -> falsification template
    if has_poc_fail and not has_harness_blocker:
        artifact_type = "failed_reproduction_attempt" if REPRO_FAIL_RE.search(text) else "falsification_template"
        artifacts.append({
            "artifact_type": artifact_type,
            "title": f"PoC failure/negative-control in {path.parent.name}",
            "content": f"REPORT at {prov} shows PoC failure or negative-control path. "
                       f"Verdict: {verdict}. Severity: {sev}. "
                       f"Kill reasons: {'; '.join(kill_reasons) if kill_reasons else 'none extracted'}.",
            "provenance_ref": prov,
            "verdict": verdict,
            "verification_tier": "tier-2-verified-public-archive" if has_local_proof else "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Detector pattern signals
    if has_detector_signal:
        artifacts.append({
            "artifact_type": "candidate_detector_pattern",
            "title": f"Detector pattern seed in {path.parent.name}",
            "content": f"REPORT at {prov} contains detector-pattern language. "
                       f"Verdict: {verdict}. Severity: {sev}.",
            "provenance_ref": prov,
            "verdict": verdict,
            "verification_tier": "tier-2-verified-public-archive" if has_local_proof else "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Triager objection -> triager precision learning
    if has_triager_obj:
        artifacts.append({
            "artifact_type": "rejection_pattern",
            "title": f"Triager objection pattern in {path.parent.name}",
            "content": f"REPORT at {prov} references triager feedback. "
                       f"Verdict: {verdict}.",
            "provenance_ref": prov,
            "verdict": verdict,
            "verification_tier": "tier-2-verified-public-archive" if has_local_proof else "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Proof-hardening signals
    if has_proof_hardening:
        artifacts.append({
            "artifact_type": "proof_artifact_mapping_candidate" if has_local_proof else "known_limitation",
            "title": f"Proof-hardening lesson in {path.parent.name}",
            "content": f"REPORT at {prov} contains proof-hardening or production-profile signals "
                       f"(Rule 18/19/25/30 family). Verdict: {verdict}. Severity: {sev}.",
            "provenance_ref": prov,
            "verdict": verdict,
            "verification_tier": "tier-2-verified-public-archive" if has_local_proof else "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Roadmap gap
    if has_roadmap_gap:
        artifacts.append({
            "artifact_type": "roadmap_gap",
            "title": f"Future-work / roadmap gap in {path.parent.name}",
            "content": f"REPORT at {prov} flags future work, follow-ups, or known limitations. "
                       f"Verdict: {verdict}.",
            "provenance_ref": prov,
            "verdict": verdict,
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    _apply_provider_only_quarantine(artifacts, provider_only)
    return artifacts


def _scan_provider_text(path: Path, ws: Path) -> list[dict]:
    """Scan provider output text files (*.txt in provider_outputs/)."""
    text = _read_text(path)
    if not text:
        return []

    # Parse JSON array if possible (kill files are JSON arrays)
    items: list[dict] = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
    except (json.JSONDecodeError, ValueError):
        pass

    prov = _provenance_ref(path, ws)
    artifacts = []

    if items:
        # Structured provider output (e.g. minimax kill JSON)
        for item in items:
            verdict_str = str(item.get("verdict", "")).upper()
            local_req = bool(item.get("local_verification_required", False))
            notes = str(item.get("notes", ""))
            followup = str(item.get("minimum_followup_check", ""))
            contradiction = item.get("contradiction_citation", "")
            cid = str(item.get("id", ""))

            if not local_req:
                # Provider-only: not a learning artifact on its own
                # BUT the kill reason is still valuable FP calibration
                if verdict_str in ("KILL", "NO KILL", "NO_KILL") and notes:
                    artifacts.append({
                        "artifact_type": "rejection_pattern",
                        "title": f"Provider kill verdict for {cid} (provider-only - no local verification)",
                        "content": f"Kill verdict: {verdict_str}. Notes: {notes}. "
                                   f"Contradiction: {contradiction}. "
                                   f"IMPORTANT: local_verification_required=false; "
                                   f"this is a PROVIDER-ONLY artifact. Do not promote to filing evidence.",
                        "provenance_ref": prov,
                        "verdict": verdict_str,
                        "verification_tier": "tier-5-quarantine",
                        "source_has_local_proof": False,
                        "provider_only": True,
                    })
            else:
                # local_verification_required=True: the provider flagged it needs local check
                # This is a candidate hacker question / follow-up candidate
                if followup:
                    artifacts.append({
                        "artifact_type": "candidate_hacker_question",
                        "title": f"Provider follow-up check for {cid} requires local verification",
                        "content": f"Minimum followup: {followup}. Notes: {notes}.",
                        "provenance_ref": prov,
                        "verdict": verdict_str,
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                        "source_has_local_proof": False,
                        "provider_only": False,
                    })
    else:
        # Raw unstructured text file from provider
        if not _is_provider_only(text, path):
            return []  # skip - provider only with no structure
        # Provider-only text with no local proof signal - skip per lane rules
        return []

    return artifacts


def _scan_provider_json(path: Path, ws: Path) -> list[dict]:
    """Scan LLM dispatch JSON files - provider-only, mine only kill reasons."""
    text = _read_text(path)
    if not text:
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    prov = _provenance_ref(path, ws)
    artifacts = []

    if not isinstance(data, dict):
        return []

    # Extract response content for kill-reason mining only
    response = data.get("response") or data.get("content") or data.get("output") or ""
    if isinstance(response, list):
        # Anthropic message content blocks
        parts = []
        for block in response:
            if isinstance(block, dict):
                parts.append(str(block.get("text", "")))
        response = " ".join(parts)

    if not response:
        return []

    kill_reasons = _extract_kill_reasons(str(response))
    if kill_reasons:
        artifacts.append({
            "artifact_type": "rejection_pattern",
            "title": f"Kill reasons from provider dispatch {path.name} (provider-only)",
            "content": "Kill reasons extracted from provider dispatch JSON (NOT local-verified). "
                       "Use for FP calibration only, not filing evidence. "
                       f"Reasons: {'; '.join(kill_reasons)}",
            "provenance_ref": prov,
            "verdict": "PROVIDER_ONLY",
            "verification_tier": "tier-5-quarantine",
            "source_has_local_proof": False,
            "provider_only": True,
        })

    return artifacts


def _scan_submission_file(path: Path, ws: Path) -> list[dict]:
    """Scan a submission markdown file (paste_ready, filed, staging, rejected)."""
    text = _read_text(path)
    if not text:
        return []

    prov = _provenance_ref(path, ws)
    artifacts = []

    # Determine submission status from path
    path_str = str(path)
    if "filed" in path_str or "paste_ready/filed" in path_str:
        status = "FILED"
        tier = "tier-2-verified-public-archive"
    elif "paste_ready" in path_str:
        status = "PASTE_READY"
        tier = "tier-2-verified-public-archive"
    elif "_oos_rejected" in path_str or "rejected" in path_str or "superseded" in path_str:
        status = "REJECTED_OR_OOS"
        tier = "tier-2-verified-public-archive"
    elif "staging" in path_str:
        status = "STAGING"
        tier = "tier-3-synthetic-taxonomy-anchored"
    else:
        status = "UNKNOWN"
        tier = "tier-3-synthetic-taxonomy-anchored"

    has_local_proof = bool(LOCAL_PROOF_RE.search(text))
    has_proof_hardening = bool(PROOF_HARDENING_RE.search(text))
    has_triager_obj = bool(TRIAGER_OBJECTION_RE.search(text))
    kill_reasons = _extract_kill_reasons(text)

    # Extract severity from filename or content
    sev = "UNKNOWN"
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if s.lower() in path.name.lower() or s in text[:500]:
            sev = s
            break

    # Every submission feeds the severity/scope oracle
    artifacts.append({
        "artifact_type": "proof_artifact_mapping_candidate" if has_local_proof else "known_limitation",
        "title": f"Submission {status} - severity oracle entry ({path.name})",
        "content": f"Submission at {prov} with status={status}, severity={sev}. "
                   f"Local proof present: {has_local_proof}. "
                   f"Proof hardening signals: {has_proof_hardening}.",
        "provenance_ref": prov,
        "verdict": status,
        "verification_tier": tier,
        "source_has_local_proof": has_local_proof,
    })

    # Rejected/OOS submissions feed scope oracle and rejection patterns
    if status == "REJECTED_OR_OOS" and kill_reasons:
        artifacts.append({
            "artifact_type": "rejection_pattern",
            "title": f"OOS/rejection scope oracle from {path.name}",
            "content": f"Status: {status}. Kill/OOS reasons: {'; '.join(kill_reasons)}.",
            "provenance_ref": prov,
            "verdict": status,
            "verification_tier": tier,
            "source_has_local_proof": has_local_proof,
        })

    # Proof hardening signals from any submission
    if has_proof_hardening:
        artifacts.append({
            "artifact_type": "proof_artifact_mapping_candidate" if has_local_proof else "known_limitation",
            "title": f"Proof-hardening rules captured in {path.name}",
            "content": f"Submission {prov} contains proof-hardening / production-profile language "
                       f"(Rule 18/19/25/30 family). Status: {status}.",
            "provenance_ref": prov,
            "verdict": status,
            "verification_tier": tier,
            "source_has_local_proof": has_local_proof,
        })

    return artifacts


def _scan_commit_mining_json(path: Path, ws: Path) -> list[dict]:
    """Scan git commit mining JSON files for detector seeds."""
    text = _read_text(path)
    if not text:
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    prov = _provenance_ref(path, ws)
    artifacts = []

    # Commit mining JSON typically has a "commits" or "results" array
    commits = []
    if isinstance(data, dict):
        commits = data.get("commits") or data.get("results") or data.get("records") or []
    elif isinstance(data, list):
        commits = data

    if not commits:
        return []

    shaped_commits = [c for c in commits if isinstance(c, dict) and c.get("shaped")]
    reverted_commits = [c for c in commits if isinstance(c, dict) and
                        (c.get("reverted") or "revert" in str(c.get("message", "")).lower())]

    if shaped_commits:
        artifacts.append({
            "artifact_type": "candidate_detector_pattern",
            "title": f"Commit mining: {len(shaped_commits)} shaped commits in {path.name}",
            "content": f"Commit mining file {prov} contains {len(shaped_commits)} shaped commits "
                       f"that may seed detector patterns. Total commits: {len(commits)}.",
            "provenance_ref": prov,
            "verdict": "COMMIT_MINING",
            "verification_tier": "tier-2-verified-public-archive",
            "source_has_local_proof": False,
        })

    if reverted_commits:
        artifacts.append({
            "artifact_type": "candidate_hacker_question",
            "title": f"Commit mining: {len(reverted_commits)} reverted commits in {path.name}",
            "content": f"Commit mining file {prov} contains {len(reverted_commits)} reverted "
                       f"commits - potential bug-class-still-live candidates per Tier-6 mining.",
            "provenance_ref": prov,
            "verdict": "COMMIT_MINING_REVERTED",
            "verification_tier": "tier-2-verified-public-archive",
            "source_has_local_proof": False,
        })

    return artifacts


def _scan_poc_file(path: Path, ws: Path) -> list[dict]:
    """Scan PoC files (*.go.txt, *_test.go, *.js, etc.)."""
    text = _read_text(path)
    if not text:
        return []

    prov = _provenance_ref(path, ws)
    has_pass = bool(re.search(r"(?:--- PASS:|PASS$|ok\s+\w|suite result: ok)", text, re.MULTILINE | re.IGNORECASE))
    has_fail = bool(re.search(r"(?:--- FAIL:|FAIL$|panic|assertion failed|revert)", text, re.IGNORECASE | re.MULTILINE))

    artifacts = []

    if has_fail and not has_pass:
        artifacts.append({
            "artifact_type": "falsification_template",
            "title": f"Failed PoC - negative control template ({path.name})",
            "content": f"PoC at {prov} shows failure/panic/revert with no PASS signal. "
                       f"Use as negative-control template for similar attack shapes.",
            "provenance_ref": prov,
            "verdict": "POC_FAIL",
            "verification_tier": "tier-4-bundled-fixture",
            "source_has_local_proof": False,
        })
    elif has_pass:
        artifacts.append({
            "artifact_type": "proof_artifact_mapping_candidate",
            "title": f"Passing PoC artifact ({path.name})",
            "content": f"PoC at {prov} has a PASS signal. "
                       f"Link to parent finding for proof-artifact mapping.",
            "provenance_ref": prov,
            "verdict": "POC_PASS",
            "verification_tier": "tier-2-verified-public-archive",
            "source_has_local_proof": True,
        })

    return artifacts


def _scan_slice_subagent_output(path: Path, ws: Path) -> list[dict]:
    """Scan a slice subagent final message (slice*_output.md, kimi/minimax/codex outputs).

    These are provider-generated but carry structured DSL patterns, FP analyses,
    and kill verdicts that are valuable as detector candidates and kill rubric entries.
    Provider-only text is quarantined (tier-5); structured content with DSL blocks
    or kill verdicts is mined as kill_rubric_entry or candidate_detector_pattern.
    """
    text = _read_text(path)
    if not text:
        return []

    prov = _provenance_ref(path, ws)
    artifacts = []
    has_local_proof = bool(LOCAL_PROOF_RE.search(text))
    has_detector_signal = bool(DETECTOR_SIGNAL_RE.search(text))

    # Detect if this is an adversarial-kill (MiniMax) or source-extract (Kimi) output
    is_kill_output = bool(re.search(
        r"(?:Verdict:\s*(KILL|WEAKEN|KEEP|NO[_\s]KILL)|"
        r"False\s+Positive\s+\d|Proposal\s+[A-Z]\s*[:]\s*(KILL|KEEP|WEAKEN))",
        text, re.IGNORECASE,
    ))
    is_source_extract = bool(re.search(
        r"(?:miss_pattern_id\s*:|source_backed\s*:|local_verify_cmd\s*:|"
        r"vulnerability_subtype\s*:|attacker_capability\s*:)",
        text, re.IGNORECASE,
    ))

    # Kill output -> kill_rubric_entry (with extracted kill reasons as FP calibration)
    if is_kill_output:
        kill_reasons = _extract_kill_reasons(text)
        # Extract individual proposal verdicts
        proposal_verdicts = re.findall(
            r"Proposal\s+([A-Z])\s*[:]\s*(KILL|WEAKEN|KEEP[^\n]{0,60}|NO[_\s]KILL)",
            text, re.IGNORECASE,
        )
        content_parts = []
        if proposal_verdicts:
            content_parts.append(
                "Proposal verdicts: " + "; ".join(
                    f"{p}: {v}" for p, v in proposal_verdicts
                )
            )
        if kill_reasons:
            content_parts.append("Kill reasons: " + "; ".join(kill_reasons))
        content = f"Adversarial-kill output at {prov}. " + " ".join(content_parts)

        artifacts.append({
            "artifact_type": "kill_rubric_entry",
            "title": f"Kill rubric from adversarial-kill output ({path.stem})",
            "content": content[:600],
            "provenance_ref": prov,
            "verdict": "PROVIDER_KILL_OUTPUT",
            # Provider-only unless local proof found - tier-3 (structured taxonomy) for
            # kill outputs since they have structured proposal/verdict blocks
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Source-extract output -> candidate_detector_pattern (DSL YAML blocks)
    if is_source_extract:
        # Count how many miss_pattern_id blocks exist
        pattern_count = len(re.findall(r"miss_pattern_id\s*:", text, re.IGNORECASE))
        # Count source_backed: true patterns (higher confidence)
        source_backed_count = len(re.findall(
            r"source_backed\s*:\s*true", text, re.IGNORECASE,
        ))
        artifacts.append({
            "artifact_type": "candidate_detector_pattern",
            "title": f"DSL pattern seeds from source-extract output ({path.stem})",
            "content": (
                f"Source-extract output at {prov} contains {pattern_count} pattern blocks "
                f"({source_backed_count} with source_backed=true). "
                f"Mine these for DSL pattern candidates."
            ),
            "provenance_ref": prov,
            "verdict": "PROVIDER_SOURCE_EXTRACT",
            # tier-3: provider-sourced taxonomy; requires local narrowing before promotion
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # General detector signal not already caught above
    if has_detector_signal and not is_kill_output and not is_source_extract:
        artifacts.append({
            "artifact_type": "candidate_detector_pattern",
            "title": f"Detector signal in slice output ({path.stem})",
            "content": f"Slice output at {prov} contains detector-pattern language.",
            "provenance_ref": prov,
            "verdict": "PROVIDER_DETECTOR_SIGNAL",
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    return artifacts


def _scan_provider_normalized_work_queue(path: Path, ws: Path) -> list[dict]:
    """Scan reports/provider_normalized_work_queue.jsonl.

    Each JSONL line is a normalized provider job result with disposition, normalized_type,
    local_verification_command, and output_path. Mine these as:
    - exploit_queue_enrichment: KEEP / SOURCE_NEEDED rows (attack class + local verify hint)
    - kill_rubric_entry: KILL rows (kill reason for FP calibration)
    - provider_calibration_row: every row regardless of disposition
    """
    text = _read_text(path)
    if not text:
        return []

    prov = _provenance_ref(path, ws)
    artifacts = []
    rows_processed = 0

    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(row, dict):
            continue

        rows_processed += 1
        disposition = str(row.get("disposition", "")).upper()
        normalized_type = str(row.get("normalized_type", ""))
        provider = str(row.get("provider", ""))
        model = str(row.get("model", ""))
        attack_class = str(row.get("attack_class", ""))
        local_cmd = str(row.get("local_verification_command", ""))
        output_path_str = str(row.get("output_path", ""))
        task_type = str(row.get("task_type", ""))
        schema = str(row.get("schema", ""))
        dedup_key = str(row.get("dedup_key", ""))

        # Every row is a provider_calibration_row (for model/provider quality tracking)
        artifacts.append({
            "artifact_type": "provider_calibration_row",
            "title": f"Provider job: {provider}/{model} {task_type} {disposition} ({normalized_type})",
            "content": (
                f"Provider={provider} model={model} task_type={task_type} "
                f"disposition={disposition} normalized_type={normalized_type} "
                f"output={output_path_str}"
            ),
            "provenance_ref": prov,
            "verdict": disposition or "UNKNOWN",
            # Provider-level rows: quarantine if no local verification; tier-3 if structured
            "verification_tier": "tier-5-quarantine",
            "source_has_local_proof": False,
            "provider_only": True,
        })

        # KEEP / SOURCE_NEEDED rows with a local verification command -> exploit queue enrichment
        if disposition in ("KEEP", "SOURCE_NEEDED") and local_cmd and local_cmd != "":
            artifacts.append({
                "artifact_type": "exploit_queue_enrichment",
                "title": (
                    f"Exploit queue enrichment: {attack_class or normalized_type} "
                    f"({provider})"
                ),
                "content": (
                    f"Disposition={disposition} normalized_type={normalized_type}. "
                    f"Attack class: {attack_class or 'unset'}. "
                    f"Local verification command: {local_cmd[:200]}. "
                    f"Output to verify: {output_path_str}."
                ),
                "provenance_ref": prov,
                "verdict": disposition,
                # Needs local check; tier-3 (has structure, not locally proven yet)
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "source_has_local_proof": False,
            })

        # KILL rows -> kill rubric entry (FP calibration)
        elif disposition == "KILL" and normalized_type:
            artifacts.append({
                "artifact_type": "kill_rubric_entry",
                "title": (
                    f"Kill rubric: {attack_class or normalized_type} "
                    f"killed by {provider}/{model}"
                ),
                "content": (
                    f"Kill disposition from normalized work queue. "
                    f"provider={provider} model={model} normalized_type={normalized_type}. "
                    f"Output path: {output_path_str}. "
                    f"Local verification cmd: {local_cmd[:200]}."
                ),
                "provenance_ref": prov,
                "verdict": "KILL",
                "verification_tier": "tier-5-quarantine",
                "source_has_local_proof": False,
                "provider_only": True,
            })

    return artifacts


def _scan_finalization_manifest(path: Path, ws: Path) -> list[dict]:
    """Scan reports/slice_finalization_*.json manifests.

    These capture:
    - provider_jobs array -> provider_calibration_row per job + kill_rubric_entry for kills
    - artifacts array -> candidate_detector_pattern for new DSL patterns
    - open_blockers -> roadmap_gap
    - next_slice -> roadmap_gap
    - tests pass/fail -> proof_artifact_mapping_candidate if passing
    """
    text = _read_text(path)
    if not text:
        return []

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(data, dict):
        return []

    prov = _provenance_ref(path, ws)
    artifacts = []
    slice_id = str(data.get("slice_id", path.stem))

    # --- provider_jobs ---
    provider_jobs = data.get("provider_jobs", [])
    if isinstance(provider_jobs, list):
        for job in provider_jobs:
            if not isinstance(job, dict):
                continue
            provider = str(job.get("provider", ""))
            model = str(job.get("model", ""))
            task_type = str(job.get("task_type", ""))
            status = str(job.get("status", ""))
            verdict_raw = str(job.get("verdict", ""))
            normalized_type = str(job.get("normalized_type", ""))
            output_path_str = str(job.get("output_path", ""))
            error = str(job.get("error", ""))

            # Every job -> provider_calibration_row
            artifacts.append({
                "artifact_type": "provider_calibration_row",
                "title": (
                    f"[{slice_id}] {provider}/{model} {task_type} "
                    f"status={status}"
                ),
                "content": (
                    f"Slice={slice_id} provider={provider} model={model} "
                    f"task_type={task_type} status={status} "
                    f"normalized_type={normalized_type} "
                    f"verdict={verdict_raw[:120]}. "
                    f"output={output_path_str}"
                    + (f" error={error}" if error else "")
                ),
                "provenance_ref": prov,
                "verdict": status.upper() or "UNKNOWN",
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "source_has_local_proof": False,
            })

            # KILL verdicts -> kill_rubric_entry
            if "KILL" in verdict_raw.upper() or normalized_type == "kill_reason_pending_local_check":
                artifacts.append({
                    "artifact_type": "kill_rubric_entry",
                    "title": f"[{slice_id}] Kill verdict: {provider}/{model} {task_type}",
                    "content": (
                        f"provider={provider} model={model} task_type={task_type}. "
                        f"Verdict: {verdict_raw[:200]}. "
                        f"normalized_type={normalized_type}. "
                        f"Output: {output_path_str}."
                    ),
                    "provenance_ref": prov,
                    "verdict": "KILL",
                    "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    "source_has_local_proof": False,
                })

            # Provider failures -> roadmap_gap (retry opportunity)
            if status == "provider_failure" or normalized_type == "provider_failure":
                artifacts.append({
                    "artifact_type": "roadmap_gap",
                    "title": (
                        f"[{slice_id}] Provider failure: {provider}/{model} "
                        f"{task_type} - retry opportunity"
                    ),
                    "content": (
                        f"provider={provider} model={model} task_type={task_type} "
                        f"failed. error={error}. output={output_path_str}. "
                        f"Re-dispatch in next slice."
                    ),
                    "provenance_ref": prov,
                    "verdict": "PROVIDER_FAILURE",
                    "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    "source_has_local_proof": False,
                })

    # --- artifacts (new DSL patterns, fixtures) ---
    manifest_artifacts = data.get("artifacts", [])
    if isinstance(manifest_artifacts, list):
        for art in manifest_artifacts:
            if not isinstance(art, dict):
                continue
            art_type = str(art.get("type", ""))
            art_path = str(art.get("path", ""))
            description = str(art.get("description", ""))
            attack_classes = art.get("attack_classes", [])
            confidence = str(art.get("confidence", ""))

            if art_type == "dsl_pattern":
                artifacts.append({
                    "artifact_type": "candidate_detector_pattern",
                    "title": f"[{slice_id}] New DSL pattern: {art_path}",
                    "content": (
                        f"DSL pattern at {art_path}. "
                        f"Attack classes: {attack_classes}. "
                        f"Confidence: {confidence}. "
                        f"Description: {description[:200]}."
                    ),
                    "provenance_ref": prov,
                    "verdict": "NEW_DSL_PATTERN",
                    "verification_tier": "tier-2-verified-public-archive",
                    "source_has_local_proof": True,
                })

    # --- open_blockers -> roadmap_gap ---
    open_blockers = data.get("open_blockers", [])
    if isinstance(open_blockers, list) and open_blockers:
        artifacts.append({
            "artifact_type": "roadmap_gap",
            "title": f"[{slice_id}] Open blockers ({len(open_blockers)} items)",
            "content": (
                f"Finalization manifest {prov} has {len(open_blockers)} open blockers: "
                + "; ".join(str(b)[:120] for b in open_blockers)
            )[:600],
            "provenance_ref": prov,
            "verdict": "OPEN_BLOCKERS",
            "verification_tier": "tier-2-verified-public-archive",
            "source_has_local_proof": False,
        })

    # --- next_slice -> roadmap_gap ---
    next_slice = data.get("next_slice", [])
    if isinstance(next_slice, list) and next_slice:
        artifacts.append({
            "artifact_type": "roadmap_gap",
            "title": f"[{slice_id}] Next-slice work items ({len(next_slice)} items)",
            "content": (
                f"Next-slice items from {prov}: "
                + "; ".join(str(n)[:120] for n in next_slice)
            )[:600],
            "provenance_ref": prov,
            "verdict": "NEXT_SLICE_QUEUE",
            "verification_tier": "tier-2-verified-public-archive",
            "source_has_local_proof": False,
        })

    # --- tests pass/fail -> proof_artifact_mapping_candidate (if passing) ---
    test_results = data.get("tests", [])
    if isinstance(test_results, list):
        for tr in test_results:
            if not isinstance(tr, dict):
                continue
            result_str = str(tr.get("result", "")).lower()
            if "ok" in result_str or "pass" in result_str:
                total = tr.get("total_tests", "") or tr.get("name", "")
                artifacts.append({
                    "artifact_type": "proof_artifact_mapping_candidate",
                    "title": (
                        f"[{slice_id}] Passing test suite: "
                        f"{tr.get('name', 'unnamed')} ({total})"
                    ),
                    "content": (
                        f"Slice {slice_id} test '{tr.get('name','?')}' PASS. "
                        f"command: {str(tr.get('command',''))[:120]}. "
                        f"result: {result_str[:80]}."
                    ),
                    "provenance_ref": prov,
                    "verdict": "TEST_PASS",
                    "verification_tier": "tier-2-verified-public-archive",
                    "source_has_local_proof": True,
                })

    # Handle dict-form tests (like the batch2 manifest)
    if isinstance(test_results, dict):
        overall = str(test_results.get("result", "")).lower()
        if "ok" in overall or "pass" in overall:
            artifacts.append({
                "artifact_type": "proof_artifact_mapping_candidate",
                "title": f"[{slice_id}] Passing test suite (combined)",
                "content": (
                    f"Slice {slice_id} combined tests PASS. "
                    f"Total: {test_results.get('total_tests','')}. "
                    f"result: {overall[:80]}."
                ),
                "provenance_ref": prov,
                "verdict": "TEST_PASS",
                "verification_tier": "tier-2-verified-public-archive",
                "source_has_local_proof": True,
            })

    return artifacts


def _scan_handoff_doc(path: Path, ws: Path) -> list[dict]:
    """Scan a Claude/Codex handoff doc for hacker questions and roadmap gaps."""
    text = _read_text(path)
    if not text:
        return []

    prov = _provenance_ref(path, ws)
    artifacts = []

    lesson = _extract_lesson(text)
    has_roadmap_gap = bool(ROADMAP_GAP_RE.search(text))
    has_detector_signal = bool(DETECTOR_SIGNAL_RE.search(text))
    has_local_proof = bool(LOCAL_PROOF_RE.search(text))

    # Capability lesson from handoff doc
    if lesson:
        artifacts.append({
            "artifact_type": "known_limitation",
            "title": f"Capability lesson from handoff doc ({path.stem})",
            "content": lesson,
            "provenance_ref": prov,
            "verdict": "HANDOFF_LESSON",
            "verification_tier": "tier-2-verified-public-archive" if has_local_proof else "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Roadmap / next-loop items from handoff doc
    if has_roadmap_gap:
        artifacts.append({
            "artifact_type": "roadmap_gap",
            "title": f"Next-session work items from handoff doc ({path.stem})",
            "content": (
                f"Handoff doc at {prov} contains future-work or next-session items. "
                f"Mine for deferred leads, queued follow-ups, and capability gaps."
            ),
            "provenance_ref": prov,
            "verdict": "HANDOFF_ROADMAP",
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Detector signals from handoff doc
    if has_detector_signal:
        artifacts.append({
            "artifact_type": "candidate_detector_pattern",
            "title": f"Detector signal in handoff doc ({path.stem})",
            "content": (
                f"Handoff doc at {prov} mentions detector patterns, missing guards, "
                f"or derivable pattern shapes."
            ),
            "provenance_ref": prov,
            "verdict": "HANDOFF_DETECTOR",
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    # Hacker questions: any local-verification-required followup in handoff
    if bool(re.search(
        r"(?:verify\s+(?:that|the|if)|check\s+(?:if|that|whether)|"
        r"confirm\s+(?:that|the)|needs?\s+(?:local\s+)?verification|"
        r"follow[- ]?up\s+(?:check|verification)|local[- ]verify[- ]cmd)",
        text, re.IGNORECASE,
    )):
        artifacts.append({
            "artifact_type": "candidate_hacker_question",
            "title": f"Hacker follow-up questions from handoff doc ({path.stem})",
            "content": (
                f"Handoff doc at {prov} contains verification follow-ups or "
                f"local-check requirements. Mine for candidate hacker questions."
            ),
            "provenance_ref": prov,
            "verdict": "HANDOFF_HACKER_QUESTION",
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    return artifacts


def _scan_report_md_with_triager(path: Path, ws: Path) -> list[dict]:
    """Extend _scan_report_md to also extract triager_pattern artifacts."""
    # Run base scanner first
    artifacts = _scan_report_md(path, ws)

    text = _read_text(path)
    if not text:
        return artifacts

    prov = _provenance_ref(path, ws)
    has_local_proof = bool(LOCAL_PROOF_RE.search(text))
    verdict = _extract_verdict(text)

    # Extract specific triager feedback patterns
    if bool(TRIAGER_FEEDBACK_RE.search(text)):
        # Try to extract triager verbatim quotes or structured asks
        triager_quotes = re.findall(
            r'"([^"]{20,300})"',
            text[max(0, text.lower().find("triager")):][:2000] if "triager" in text.lower() else "",
        )
        triager_asks = re.findall(
            r"Ask\s+#(\d+)[:\s]+([^\n]{10,200})",
            text, re.IGNORECASE,
        )
        content_parts = []
        if triager_quotes:
            content_parts.append(
                "Triager quotes: " + "; ".join(q[:120] for q in triager_quotes[:3])
            )
        if triager_asks:
            content_parts.append(
                "Triager asks: " + "; ".join(f"#{n}: {q}" for n, q in triager_asks[:3])
            )
        if not content_parts:
            content_parts.append(f"Triager feedback detected in {prov}.")

        artifacts.append({
            "artifact_type": "triager_pattern",
            "title": f"Triager feedback pattern from {path.parent.name}/{path.name}",
            "content": (" ".join(content_parts))[:600],
            "provenance_ref": prov,
            "verdict": verdict or "TRIAGER_FEEDBACK",
            "verification_tier": "tier-2-verified-public-archive" if has_local_proof else "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": has_local_proof,
        })

    return artifacts


def _scan_backfill_report(path: Path, ws: Path) -> list[dict]:
    """Scan backfill/submission report files for capability lessons."""
    text = _read_text(path)
    if not text:
        return []

    prov = _provenance_ref(path, ws)
    artifacts = []

    lesson = _extract_lesson(text)
    if lesson:
        artifacts.append({
            "artifact_type": "known_limitation",
            "title": f"Backfill capability lesson ({path.parent.name})",
            "content": lesson,
            "provenance_ref": prov,
            "verdict": "BACKFILL_LESSON",
            "verification_tier": "tier-2-verified-public-archive",
            "source_has_local_proof": True,
        })

    # Extract any proof-hardening rules
    if PROOF_HARDENING_RE.search(text):
        artifacts.append({
            "artifact_type": "proof_artifact_mapping_candidate",
            "title": f"Proof-hardening lesson from backfill report ({path.parent.name})",
            "content": f"Backfill report at {prov} documents proof evolution "
                       f"(production-profile upgrades, real message paths, multi-validator evidence).",
            "provenance_ref": prov,
            "verdict": "BACKFILL_PROOF_HARDENING",
            "verification_tier": "tier-2-verified-public-archive",
            "source_has_local_proof": True,
        })

    return artifacts


def _scan_exploit_conversion_loop_json(path: Path, ws: Path) -> list[dict]:
    """Scan exploit-conversion-loop manifests for proof/queue/roadmap learning."""
    text = _read_text(path)
    if not text:
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    prov = _provenance_ref(path, ws)
    artifacts: list[dict] = []
    steps = [row for row in data.get("steps", []) if isinstance(row, dict)]
    failed_steps = [row for row in steps if str(row.get("status", "")).lower() in {"fail", "error", "blocked"}]
    skipped_steps = [row for row in steps if str(row.get("status", "")).lower() == "skipped"]
    passed_steps = [row for row in steps if str(row.get("status", "")).lower() == "pass"]
    hard_failures = data.get("hard_failures") if isinstance(data.get("hard_failures"), list) else []

    if failed_steps or hard_failures:
        artifacts.append(
            {
                "artifact_type": "roadmap_gap",
                "title": f"Exploit conversion loop blockers ({path.name})",
                "content": (
                    f"Exploit conversion loop at {prov} has "
                    f"{len(failed_steps)} failed/blocked steps and {len(hard_failures)} hard failures. "
                    f"Strict stop reason: {data.get('strict_stop_reason') or ''}."
                )[:600],
                "provenance_ref": prov,
                "verdict": "EXPLOIT_CONVERSION_BLOCKED",
                "verification_tier": "tier-2-verified-public-archive",
                "source_has_local_proof": False,
            }
        )
    if skipped_steps:
        artifacts.append(
            {
                "artifact_type": "known_limitation",
                "title": f"Exploit conversion skipped steps ({path.name})",
                "content": (
                    f"Exploit conversion loop at {prov} skipped {len(skipped_steps)} steps. "
                    f"These are workflow gaps or typed deferrals, not exploit evidence."
                )[:600],
                "provenance_ref": prov,
                "verdict": "EXPLOIT_CONVERSION_SKIPPED",
                "verification_tier": "tier-2-verified-public-archive",
                "source_has_local_proof": False,
            }
        )
    if passed_steps and not failed_steps and not hard_failures:
        artifacts.append(
            {
                "artifact_type": "proof_artifact_mapping_candidate",
                "title": f"Exploit conversion completed local steps ({path.name})",
                "content": (
                    f"Exploit conversion loop at {prov} completed {len(passed_steps)} local tool steps. "
                    f"Use only as proof-artifact routing context; step pass is not exploit proof."
                )[:600],
                "provenance_ref": prov,
                "verdict": "EXPLOIT_CONVERSION_PASS",
                "verification_tier": "tier-2-verified-public-archive",
                "source_has_local_proof": True,
            }
        )
    return artifacts


def _scan_harness_execution_queue_json(path: Path, ws: Path) -> list[dict]:
    """Scan harness execution queues for reusable harness blockers/templates."""
    text = _read_text(path)
    if not text:
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    prov = _provenance_ref(path, ws)
    rows = [row for row in data.get("rows", []) if isinstance(row, dict)]
    if not rows:
        rows = [row for key in ("ready_rows", "blocked_rows", "queue") for row in data.get(key, []) if isinstance(row, dict)]
    ready = [row for row in rows if str(row.get("status") or row.get("execution_status") or "").lower() in {"ready", "runnable", "pass"}]
    blocked = [row for row in rows if str(row.get("status") or row.get("execution_status") or "").lower() in {"blocked", "missing", "fail"}]
    artifacts: list[dict] = []
    if ready:
        artifacts.append(
            {
                "artifact_type": "proof_artifact_mapping_candidate",
                "title": f"Harness execution ready rows ({path.name})",
                "content": f"Harness queue at {prov} has {len(ready)} ready/runnable rows.",
                "provenance_ref": prov,
                "verdict": "HARNESS_READY",
                "verification_tier": "tier-2-verified-public-archive",
                "source_has_local_proof": True,
            }
        )
    if blocked or rows:
        artifacts.append(
            {
                "artifact_type": "harness_template_request",
                "title": f"Harness execution queue blockers ({path.name})",
                "content": (
                    f"Harness queue at {prov} has {len(blocked)} blocked rows out of {len(rows)} rows. "
                    f"Mine missing binding fields into harness templates."
                )[:600],
                "provenance_ref": prov,
                "verdict": "HARNESS_QUEUE",
                "verification_tier": "tier-2-verified-public-archive",
                "source_has_local_proof": bool(ready),
            }
        )
    return artifacts


def _scan_source_artifact(path: Path, ws: Path) -> list[dict]:
    """Scan source-artifact sidecars produced during queue/source mining."""
    text = _read_text(path)
    if not text:
        return []
    prov = _provenance_ref(path, ws)
    artifacts: list[dict] = []
    has_source_complete = bool(re.search(r"source_artifacts_complete[\"']?\s*[:=]\s*true", text, re.IGNORECASE))
    has_proof = bool(LOCAL_PROOF_RE.search(text) or TEST_COMMAND_RE.search(text) or has_source_complete)
    has_blocker = bool(re.search(r"(?:blocked|missing|incomplete|needs[-_ ]source|source_artifacts_complete[\"']?\s*[:=]\s*false)", text, re.IGNORECASE))
    if has_proof:
        artifacts.append(
            {
                "artifact_type": "proof_artifact_mapping_candidate",
                "title": f"Source artifact proof context ({path.name})",
                "content": f"Source artifact {prov} carries local source/proof completion signals.",
                "provenance_ref": prov,
                "verdict": "SOURCE_ARTIFACT_COMPLETE",
                "verification_tier": "tier-2-verified-public-archive",
                "source_has_local_proof": True,
            }
        )
    if has_blocker:
        artifacts.append(
            {
                "artifact_type": "roadmap_gap",
                "title": f"Source artifact blocker ({path.name})",
                "content": f"Source artifact {prov} documents missing/incomplete source closure.",
                "provenance_ref": prov,
                "verdict": "SOURCE_ARTIFACT_BLOCKED",
                "verification_tier": "tier-2-verified-public-archive",
                "source_has_local_proof": False,
            }
        )
    if not artifacts:
        artifacts.append(
            {
                "artifact_type": "known_limitation",
                "title": f"Source artifact sidecar ({path.name})",
                "content": f"Source artifact {prov} should be reviewed before proof promotion.",
                "provenance_ref": prov,
                "verdict": "SOURCE_ARTIFACT_CONTEXT",
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "source_has_local_proof": False,
            }
        )
    return artifacts


def _scanner_for_source(source: ArtifactInputSource, ws: Path) -> list[dict]:
    scanner = source.scanner
    if scanner == "backfill_report":
        return _scan_backfill_report(source.path, ws)
    if scanner == "report_md":
        return _scan_report_md_with_triager(source.path, ws)
    if scanner == "slice_subagent_output":
        return _scan_slice_subagent_output(source.path, ws)
    if scanner == "handoff_doc":
        return _scan_handoff_doc(source.path, ws)
    if scanner == "provider_text":
        return _scan_provider_text(source.path, ws)
    if scanner == "provider_json":
        return _scan_provider_json(source.path, ws)
    if scanner == "poc_file":
        return _scan_poc_file(source.path, ws)
    if scanner == "commit_mining_json":
        return _scan_commit_mining_json(source.path, ws)
    if scanner == "provider_normalized_work_queue":
        return _scan_provider_normalized_work_queue(source.path, ws)
    if scanner == "finalization_manifest":
        return _scan_finalization_manifest(source.path, ws)
    if scanner == "submission_file":
        return _scan_submission_file(source.path, ws)
    if scanner == "exploit_conversion_loop":
        return _scan_exploit_conversion_loop_json(source.path, ws)
    if scanner == "harness_execution_queue":
        return _scan_harness_execution_queue_json(source.path, ws)
    if scanner == "source_artifact":
        return _scan_source_artifact(source.path, ws)
    return []


def _add_source(
    sources: list[ArtifactInputSource],
    path: Path,
    source_type: str,
    scanner: str,
    seen: set[str],
    ws: Path,
) -> None:
    if not path.is_file() or path.stat().st_size <= 0:
        return
    key = _provenance_ref(path, ws)
    if key in seen:
        return
    seen.add(key)
    sources.append(ArtifactInputSource(path=path, source_type=source_type, scanner=scanner))


def iter_artifact_input_sources(ws: Path) -> list[ArtifactInputSource]:
    """Return deterministic source files mined or inventoried as agent artifacts."""
    ws = ws.resolve()
    sources: list[ArtifactInputSource] = []
    seen: set[str] = set()

    agent_out = ws / "agent_outputs"
    if agent_out.is_dir():
        for report in sorted(agent_out.rglob("REPORT.md")):
            scanner = "backfill_report" if "backfill" in str(report.parent).lower() else "report_md"
            _add_source(sources, report, "agent_outputs", scanner, seen, ws)
        for md in sorted(agent_out.glob("*.md")):
            name_lower = md.name.lower()
            if re.search(
                r"(?:slice\d+[a-z]?_(?:kimi|minimax|codex|claude|gpt|gemini|deepseek|mistral)_"
                r"(?:output|kill_output|source_output|analysis_output)|"
                r"(?:kimi|minimax|codex)_[a-z_]+_output)\.md$",
                name_lower,
            ):
                _add_source(sources, md, "agent_outputs", "slice_subagent_output", seen, ws)
            if bool(HANDOFF_RE.search(md.stem)):
                _add_source(sources, md, "agent_outputs", "handoff_doc", seen, ws)
        for txt in sorted(agent_out.rglob("*.txt")):
            if "provider_output" in str(txt) or "provider_outputs" in str(txt.parent):
                _add_source(sources, txt, "agent_outputs", "provider_text", seen, ws)
        for jf in sorted(agent_out.rglob("llm_dispatch_*.json")):
            _add_source(sources, jf, "agent_outputs", "provider_json", seen, ws)
        for jf in sorted(agent_out.rglob("llm_preflight_*.json")):
            _add_source(sources, jf, "agent_outputs", "provider_json", seen, ws)
        for pattern in ("*.go.txt", "*_test.go", "poc_*.js"):
            for poc in sorted(agent_out.rglob(pattern)):
                _add_source(sources, poc, "agent_outputs", "poc_file", seen, ws)
        for pattern in ("*commit*mining*.json", "git_commits_mining*.json"):
            for jf in sorted(agent_out.rglob(pattern)):
                _add_source(sources, jf, "agent_outputs", "commit_mining_json", seen, ws)

    reports_dir = ws / "reports"
    if reports_dir.is_dir():
        for md in sorted(reports_dir.glob("*.md")):
            _add_source(sources, md, "reports", "report_md", seen, ws)
        for jf in sorted(reports_dir.glob("git_commits_mining*.json")):
            _add_source(sources, jf, "reports", "commit_mining_json", seen, ws)
        _add_source(sources, reports_dir / "provider_normalized_work_queue.jsonl", "reports", "provider_normalized_work_queue", seen, ws)
        for jf in sorted(reports_dir.glob("slice_finalization_*.json")):
            _add_source(sources, jf, "reports", "finalization_manifest", seen, ws)

    poc_dir = ws / "poc-tests"
    if poc_dir.is_dir():
        for pattern in ("*.go", "*.js"):
            for poc in sorted(poc_dir.rglob(pattern)):
                _add_source(sources, poc, "poc-tests", "poc_file", seen, ws)

    submissions_dir = ws / "submissions"
    if submissions_dir.is_dir():
        for sub in sorted(submissions_dir.rglob("*.md")):
            if sub.name != "SUBMISSIONS.md":
                _add_source(sources, sub, "submissions", "submission_file", seen, ws)
    _add_source(sources, ws / "SUBMISSIONS.md", "SUBMISSIONS.md", "submission_file", seen, ws)

    docs_dir = ws / "docs"
    if docs_dir.is_dir():
        handoffs_dir = docs_dir / "archive" / "handoffs"
        if handoffs_dir.is_dir():
            for md in sorted(handoffs_dir.glob("*.md")):
                _add_source(sources, md, "docs/archive/handoffs", "handoff_doc", seen, ws)
        for md in sorted(docs_dir.glob("*.md")):
            if bool(HANDOFF_RE.search(md.stem)):
                _add_source(sources, md, "docs", "handoff_doc", seen, ws)

    auditooor_dir = ws / ".auditooor"
    if auditooor_dir.is_dir():
        _add_source(sources, auditooor_dir / "commit_lifecycle_ledger.json", ".auditooor", "commit_mining_json", seen, ws)
        for jf in sorted((auditooor_dir / "finalization").rglob("*.json")) if (auditooor_dir / "finalization").is_dir() else []:
            _add_source(sources, jf, ".auditooor/finalization", "finalization_manifest", seen, ws)
        for jf in sorted(auditooor_dir.glob("exploit_conversion_loop*.json")):
            _add_source(sources, jf, ".auditooor/exploit_conversion_loop", "exploit_conversion_loop", seen, ws)
        for jf in sorted(auditooor_dir.glob("harness_execution_queue*.json")):
            _add_source(sources, jf, ".auditooor/harness_execution_queue", "harness_execution_queue", seen, ws)
        source_artifacts = auditooor_dir / "source_artifacts"
        if source_artifacts.is_dir():
            for path in sorted(source_artifacts.rglob("*")):
                if path.suffix.lower() in {".json", ".jsonl", ".md", ".txt"}:
                    _add_source(sources, path, ".auditooor/source_artifacts", "source_artifact", seen, ws)
        for jf in sorted(auditooor_dir.glob("provider_fanout/*/runs/*/fanout_closeout.json")):
            _add_source(sources, jf, ".auditooor/provider_fanout", "finalization_manifest", seen, ws)
        for jf in sorted(auditooor_dir.glob("provider_fanout/*/runs/*/v3_provider_local_verification_result.json")):
            _add_source(sources, jf, ".auditooor/provider_fanout", "finalization_manifest", seen, ws)

    return sorted(sources, key=lambda source: (source.source_type, _provenance_ref(source.path, ws)))


def artifact_input_summary(ws: Path) -> dict[str, Any]:
    ws = ws.resolve()
    rows: list[dict[str, Any]] = []
    for source in iter_artifact_input_sources(ws):
        stat = source.path.stat()
        rows.append(
            {
                "path": _provenance_ref(source.path, ws),
                "source_type": source.source_type,
                "scanner": source.scanner,
                "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).replace(microsecond=0).isoformat(),
            }
        )
    source_counts: dict[str, int] = {}
    for row in rows:
        source_type = str(row["source_type"])
        source_counts[source_type] = source_counts.get(source_type, 0) + 1
    latest = max(rows, key=lambda row: str(row["mtime"])) if rows else None
    return {
        "has_artifact_inputs": bool(rows),
        "input_file_count": len(rows),
        "latest_input_mtime": latest["mtime"] if latest else "",
        "latest_input_path": latest["path"] if latest else "",
        "source_counts": dict(sorted(source_counts.items())),
        "evidence_roots": sorted(source_counts),
        "scanner_counts": dict(sorted((scanner, sum(1 for row in rows if row["scanner"] == scanner)) for scanner in {str(row["scanner"]) for row in rows})),
    }


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def mine_workspace(ws: Path) -> dict[str, Any]:
    """Scan all relevant artifact locations in the workspace and return a report."""
    ws = ws.resolve()
    raw_artifacts: list[dict] = []

    for source in iter_artifact_input_sources(ws):
        raw_artifacts.extend(_scanner_for_source(source, ws))

    # --- Deduplicate by content hash ---
    seen: set[str] = set()
    artifacts: list[dict] = []
    for a in raw_artifacts:
        key = _short_hash(a.get("content", "") + a.get("provenance_ref", ""))
        if key not in seen:
            seen.add(key)
            a["artifact_id"] = f"aam-{key}"
            artifacts.append(a)

    # Sort for deterministic ordering: type then provenance_ref
    artifacts.sort(key=lambda a: (a.get("artifact_type", ""), a.get("provenance_ref", "")))

    # Summarize by type
    counts: dict[str, int] = {}
    for a in artifacts:
        t = a.get("artifact_type", "unknown")
        counts[t] = counts.get(t, 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(ws),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_artifacts": len(artifacts),
        "no_learning_reason": len(artifacts) == 0,
        "artifact_type_counts": counts,
        "artifacts": artifacts,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Mine agent outputs and failed PoCs for future capability artifacts.",
    )
    p.add_argument("--workspace", required=True, help="Path to the audit workspace root.")
    p.add_argument(
        "--out",
        metavar="FILE",
        help="Write JSON report to this file (default: stdout).",
    )
    p.add_argument(
        "--json",
        dest="emit_json",
        action="store_true",
        help="Emit JSON to stdout (same as omitting --out).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 2

    report = mine_workspace(ws)

    out_text = json.dumps(report, indent=2, ensure_ascii=False)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text + "\n", encoding="utf-8")
        print(f"agent-artifact-miner: wrote {report['total_artifacts']} artifacts to {out_path}",
              file=sys.stderr)
    else:
        print(out_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
