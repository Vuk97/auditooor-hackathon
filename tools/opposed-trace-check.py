#!/usr/bin/env python3
"""HACKERMAN_V3 opposed-trace proof gate (tiered: hard for HIGH+, advisory below).

A Direct Loss / Permanent Freeze / Insolvency / Theft / Unauthorized
Withdrawal / temporary-freeze claim must NOT be proved from an unopposed trace
(attacker vs empty world). The PoC or submission body must demonstrate the
attacker path AGAINST every protocol-owned defense that is supposed to race,
rescue, liquidate, slash, refund, pause, challenge, overwrite, finalize, or
otherwise neutralize the attack.

The opposed-trace QUESTION is asked at EVERY severity. "Attacker vs empty
world" is a proof fallacy at any tier - a Medium temporary-freeze claim is just
as unproven if a watchtower path would unfreeze it next block. ENFORCEMENT,
however, is tiered:

  - HIGH+ (High / Critical): HARD FAIL. The gate blocks the submission.
  - Medium / Low / below-High: MANDATORY ADVISORY. The gate emits a warning
    the reviewer must see and clear, but does NOT hard-block the filing. A
    lower-severity finding has a deliberately lower proof bar by rubric design.

Empirical anchor: Spark LEAD1 proved the chain-watcher accepted an unrelated
exit_txid, but the proof never simulated the lower-timelock connector refund,
post-claim lower-timelock refund, or watchtower paths. The watcher bug was real
but the Direct Loss impact was unproven.

Verdict vocabulary:
  pass-out-of-scope              -- no trigger keyword at all
  pass-defenses-covered          -- at least one defense is included AND attacker-wins signal
  pass-not-applicable            -- opposed_trace_coverage: not_applicable annotated
  ok-rebuttal                    -- explicit override marker present with non-empty reason
  fail-unopposed-trace           -- HIGH+: trigger present, no defense evidence, no rebuttal
  fail-defender-wins             -- HIGH+: defenses included but defender wins (cannot claim direct loss)
  warn-unopposed-trace           -- Medium/Low: trigger present, no defense evidence, no rebuttal (advisory)
  warn-defender-wins             -- Medium/Low: defenses included but defender wins (advisory)
  error                          -- input/file error

Exit codes:
  0 - pass / out-of-scope / not-applicable / rebuttal / warn-* (advisory, non-blocking)
  1 - gate violation (fail-unopposed-trace or fail-defender-wins) - HIGH+ only
  2 - input error
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.opposed_trace_check.v1"
GATE = "R-OPPOSED-TRACE"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# -------------------------------------------------------------------
# Trigger keywords - any HIGH+ draft that contains one of these is in-scope
# -------------------------------------------------------------------
TRIGGER_PATTERNS = [
    r"\bdirect loss\b",
    r"\bloss of funds\b",
    r"\btheft of funds\b",
    r"\bfund drain\b",
    r"\bdirect theft\b",
    r"\bunauthorized withdraw",
    r"\bunauthorized transfer\b",
    r"\bunauthorized debit\b",
    r"\bpermanent freeze\b",
    r"\bfreezing of funds\b",
    r"\bfunds frozen\b",
    r"\binsolvency\b",
    r"\bprotocol insolvency\b",
    r"\bdirect loss of funds\b",
    r"\btheft of user funds\b",
    r"\bloss or theft\b",
]
TRIGGER_RE = re.compile("|".join(TRIGGER_PATTERNS), re.IGNORECASE)

# -------------------------------------------------------------------
# Protocol defense presence signals
# -------------------------------------------------------------------
DEFENSE_SIGNALS = [
    # Watchtower / watcher as defense (must be paired with action verb or explicit defense role)
    r"\bwatchtower\s+(?:sweep|path|node|detects?|prevents?|fires?|catches?|monitors?)\b",
    r"\bwatchtower\s+(?:is\s+)?(?:simulated|included|considered|modeled)\b",
    r"\bchain[- ]?watcher\s+(?:detects?|prevents?|fires?|catches?|sweep|path|defense)\b",
    r"\bwatcher\s+(?:detects?|prevents?|fires?|catches?|sweep|path|defense|monitors?)\b",
    r"\bwatcher\s+(?:is\s+)?(?:simulated|included|considered|modeled)\b",
    r"\bwatcher\s+(?:fails?|is\s+bypassed?|cannot\s+prevent|misses?)\b",  # also attacker-wins signal
    r"(?:defense|Defence)[:\s]+watchtower\b",
    r"(?:defense|Defence)[:\s]+(?:chain[- ]?watcher|watcher)\b",
    # Liquidation / slash as active defense mechanisms
    r"\bliquidat(?:or|ion|e|ed|es|ing)\b",
    r"\bslash(?:ing|ed|er|ers)?\b",
    # Refund / clawback / rescue paths
    r"\brefund\s+(?:path|mechanism|succeeds?|fires?|fails?|blocked|unavailable|impossible|period)\b",
    r"\blower[- ]timelock\s+(?:refund|path|connector)\b",
    r"\btimelock\s+refund\b",
    r"\bconnector\s+refund\b",
    r"\bclawback\b",
    r"\brescue\s+path\b",
    r"\brescue\s+(?:mechanism|fund|vault)\b",
    # Challenge / dispute windows
    r"\bchallenge\s+period\b",
    r"\bchallenge\s+(?:window|mechanism|path|game)\b",
    r"\bdispute\s+(?:window|mechanism|path|game|period)\b",
    r"\boptimistic\s+(?:challenge|window|period|rollup)\b",
    # Pause / emergency stops
    r"\bpause\s+(?:mechanism|guard|function|check|path)\b",
    r"\bpaused\s+(?:state|check|guard)\b",
    r"\bemergency\s+(?:stop|pause|exit|withdraw)\b",
    # Insurance / backstop / bail-out
    r"\binsurance\s+fund\b",
    r"\bbackstop\b",
    r"\bbail[- ]?out\b",
    # HTLC cooperative paths
    r"\bHTLC\b",
    r"\bcoop(?:erative)?\s+exit\s+(?:refund|path|defense|mechanism)\b",
    # Finalization paths with defense meaning
    r"\bfinali[sz]e\s+(?:path|defense|mechanism|check)\b",
    r"\boverwrite\s+(?:protection|defense|guard)\b",
    r"\bcheckpoint\s+(?:defense|validation)\b",
    # Generic "protocol defense" prose - these are unambiguous
    r"\bprotocol[- ]owned\s+defenses?\b",
    r"\bdefense\s+simulated\b",
    r"\bdefender\s+(?:wins|loses|intervenes|acts)\b",
    r"\boutcome\s+if\s+(?:watcher|liquidator|watchtower|protocol)\s+(?:acts|fires|responds|intervenes)\b",
    # Mandatory section header - most unambiguous signal
    r"##\s+Protocol[- ]Owned Defenses? Considered",
    r"Protocol[- ]Owned Defenses? Considered",
]
DEFENSE_RE = re.compile("|".join(DEFENSE_SIGNALS), re.IGNORECASE)

# -------------------------------------------------------------------
# "Attacker still wins" signals (after defenses are described)
# -------------------------------------------------------------------
ATTACKER_WINS_SIGNALS = [
    r"\battacker\s+(?:still\s+)?wins\b",
    r"\bdefense\s+(?:fails|is\s+bypassed|is\s+insufficient)\b",
    r"\bwatcher\s+(?:fails|is\s+bypassed|cannot\s+prevent|misses)\b",
    r"\brefund\s+(?:blocked|fails|unavailable|impossible)\b",
    r"\bno\s+(?:rescue|refund|watchtower|watcher)\s+can\s+prevent\b",
    r"\beven\s+(?:with|after)\s+(?:the\s+)?(?:watcher|liquidator|refund|defense)\b",
    r"\bdefense\s+(?:does\s+not\s+fire|cannot\s+fire|cannot\s+activate)\b",
    r"\boutcome:\s+attacker\s+wins\b",
    r"\bResult:\s+attacker\s+wins\b",
    r"\battacker\s+path\s+wins\b",
]
ATTACKER_WINS_RE = re.compile("|".join(ATTACKER_WINS_SIGNALS), re.IGNORECASE)

# -------------------------------------------------------------------
# "Defender wins" signals
# -------------------------------------------------------------------
DEFENDER_WINS_SIGNALS = [
    r"\bdefender\s+wins\b",
    r"\bwatcher\s+(?:prevents|blocks|stops|catches)\b",
    r"\brefund\s+(?:succeeds|fires|covers)\b",
    r"\bprotocol\s+(?:prevents|blocks|stops|catches|recovers)\b",
    r"\bfunds\s+(?:are\s+)?recovered\b",
    r"\bloss\s+is\s+(?:fully\s+)?prevented\b",
    r"\bno\s+loss\b",
    r"\battacker\s+fails\b",
    r"\boutcome:\s+defender\s+wins\b",
    r"\bResult:\s+defender\s+wins\b",
]
DEFENDER_WINS_RE = re.compile("|".join(DEFENDER_WINS_SIGNALS), re.IGNORECASE)

# -------------------------------------------------------------------
# Impact contract field - "opposed_trace_coverage: not_applicable"
# -------------------------------------------------------------------
NOT_APPLICABLE_RE = re.compile(
    r"opposed[_ -]trace[_ -]coverage\s*:\s*not[_ -]applicable",
    re.IGNORECASE,
)

# -------------------------------------------------------------------
# Override rebuttal marker
# -------------------------------------------------------------------
REBUTTAL_RE = re.compile(
    r"<!--\s*opposed-trace-rebuttal:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)

REBUTTAL_MAX_CHARS = 200

# -------------------------------------------------------------------
# Shared remediation option lists (same advice for the hard and advisory tier)
# -------------------------------------------------------------------
_UNOPPOSED_REMEDIATION = [
    "Add '## Protocol-Owned Defenses Considered' table (see template).",
    "Enumerate every protocol defense (watchtower, refund, pause, liquidation, etc.).",
    "For each defense: state expected protection, whether it was included in the PoC, result, and why any omitted defense is safe to omit.",
    "If attacker wins despite all defenses, show 'Outcome: attacker wins' clearly.",
    "If no protocol defense exists for this attack surface, add 'opposed_trace_coverage: not_applicable' to Impact Contract and explain.",
    "For bounded source-backed exceptions: <!-- opposed-trace-rebuttal: <reason up to 200 chars> -->",
]
_DEFENDER_WINS_REMEDIATION = [
    "If the defense truly prevents the loss, walk severity back (not Direct Loss).",
    "If the defense has a gap that the attack exploits, show that gap explicitly and prove 'Outcome: attacker wins' despite the defense.",
    "If the defense is out-of-scope or inactive under the attack conditions, document why with an opposed-trace-rebuttal.",
]

# -------------------------------------------------------------------
# Severity detection (mirrors existing tools)
# -------------------------------------------------------------------
SEVERITY_HEADER_RE = re.compile(
    r"(?im)^\s*\**\s*Severity\s*[:\-]?\**\s*(Critical|High|Medium|Low)\b"
)
FILENAME_SEVERITY_RE = re.compile(
    r"(?:^|[-_])(critical|high|medium|low)(?:[-_.]|$)", re.IGNORECASE
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for m in SEVERITY_HEADER_RE.finditer(text):
        return m.group(1).lower(), "severity-header"
    m = FILENAME_SEVERITY_RE.search(path.name)
    if m:
        return m.group(1).lower(), "filename"
    return None, "unknown"


def _corpus(draft: Path, poc_dir: str | None) -> str:
    """Build the full text corpus: draft body + all PoC source files."""
    parts = [_read(draft)]
    search_dirs: list[Path] = []
    if poc_dir:
        d = Path(poc_dir).expanduser()
        if d.is_dir():
            search_dirs.append(d)
    # Also try to resolve relative poc paths from draft body
    for m in re.finditer(r"[`\"]?(poc[- _]tests?/[^\s`\"]+)[`\"]?", _read(draft), re.IGNORECASE):
        candidate = draft.parent.parent / m.group(1)
        if candidate.is_dir():
            search_dirs.append(candidate)
    CODE_SUFFIXES = {".go", ".rs", ".sol", ".ts", ".py", ".move", ".cairo", ".vy", ".txt", ".log"}
    for d in search_dirs:
        for f in sorted(d.rglob("*")):
            if f.is_file() and f.suffix in CODE_SUFFIXES:
                try:
                    parts.append(f.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    pass
    return "\n".join(parts)


def run(
    draft: Path,
    *,
    poc_dir: str | None = None,
    severity: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Run the gate and return (exit_code, payload)."""
    if not draft.is_file():
        return 2, {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "error",
            "reason": f"draft not found: {draft}",
            "evidence": {},
        }

    try:
        text = _read(draft)
    except Exception as exc:
        return 2, {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "error",
            "reason": f"cannot read draft: {exc}",
            "evidence": {},
        }

    sev, sev_src = _severity(text, draft, severity)
    high_plus = sev is not None and SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK["high"]
    # Tiered enforcement: HIGH+ hard-fails, Medium/Low/below-High is advisory.
    # The opposed-trace QUESTION is asked at every severity; "attacker vs empty
    # world" is a proof fallacy at any tier. Only the ENFORCEMENT scales.
    enforcement = "hard" if high_plus else "advisory"

    # Check trigger - asked at EVERY severity. Only a draft with no
    # direct-loss / freeze / theft / insolvency keyword at all is out of scope.
    trigger_hits = [m.group(0) for m in TRIGGER_RE.finditer(text)]
    has_trigger = bool(trigger_hits)

    if not has_trigger:
        return 0, {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "pass-out-of-scope",
            "severity": sev,
            "severity_source": sev_src,
            "enforcement": enforcement,
            "reason": "no direct-loss / freeze / theft / insolvency trigger keyword found",
            "evidence": {"trigger_hits": []},
        }

    # Build full corpus (draft + PoC sources if available)
    try:
        corpus = _corpus(draft, poc_dir)
    except Exception:
        corpus = text

    # Check rebuttal first
    rebuttal_match = REBUTTAL_RE.search(corpus)
    if rebuttal_match:
        reason = " ".join(rebuttal_match.group(1).split())
        if reason and len(reason) <= REBUTTAL_MAX_CHARS:
            return 0, {
                "schema": SCHEMA_VERSION,
                "gate": GATE,
                "verdict": "ok-rebuttal",
                "severity": sev,
                "severity_source": sev_src,
                "enforcement": enforcement,
                "reason": f"override accepted: {reason}",
                "evidence": {"rebuttal_reason": reason, "trigger_hits": trigger_hits[:4]},
            }
        # Empty or oversized rebuttal - fall through
        rebuttal_match = None

    # Check not_applicable annotation
    if NOT_APPLICABLE_RE.search(corpus):
        return 0, {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "pass-not-applicable",
            "severity": sev,
            "severity_source": sev_src,
            "enforcement": enforcement,
            "reason": "opposed_trace_coverage: not_applicable declared in impact contract",
            "evidence": {"trigger_hits": trigger_hits[:4]},
        }

    # Check for defense signals
    defense_hits = [m.group(0) for m in DEFENSE_RE.finditer(corpus)]
    has_defenses = bool(defense_hits)

    # Check defender/attacker wins signals
    attacker_wins_hits = [m.group(0) for m in ATTACKER_WINS_RE.finditer(corpus)]
    defender_wins_hits = [m.group(0) for m in DEFENDER_WINS_RE.finditer(corpus)]

    has_attacker_wins = bool(attacker_wins_hits)
    has_defender_wins = bool(defender_wins_hits)

    evidence: dict[str, Any] = {
        "trigger_hits": trigger_hits[:4],
        "defense_hits": defense_hits[:6],
        "attacker_wins_hits": attacker_wins_hits[:4],
        "defender_wins_hits": defender_wins_hits[:4],
    }

    if not has_defenses:
        # No defense mentioned at all - unopposed trace. HIGH+ hard-fails;
        # Medium/Low gets a mandatory advisory (warn) the reviewer must clear.
        if enforcement == "hard":
            return 1, {
                "schema": SCHEMA_VERSION,
                "gate": GATE,
                "verdict": "fail-unopposed-trace",
                "severity": sev,
                "severity_source": sev_src,
                "enforcement": "hard",
                "reason": (
                    "Direct Loss / Permanent Freeze / Theft / Insolvency claimed but "
                    "no protocol-owned defense (watchtower, refund, liquidation, slash, "
                    "pause, challenge, finalize) appears in the draft or PoC corpus. "
                    "Add a 'Protocol-Owned Defenses Considered' section and show that the "
                    "attacker wins despite each defense, OR add "
                    "<!-- opposed-trace-rebuttal: <reason up to 200 chars> -->."
                ),
                "remediation_options": _UNOPPOSED_REMEDIATION,
                "evidence": evidence,
            }
        # Medium / Low / below-High: advisory only, non-blocking (exit 0).
        return 0, {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "warn-unopposed-trace",
            "severity": sev,
            "severity_source": sev_src,
            "enforcement": "advisory",
            "reason": (
                "ADVISORY: a freeze / loss / theft claim is present but no "
                "protocol-owned defense (watchtower, refund, liquidation, slash, "
                "pause, challenge, finalize) appears in the draft or PoC corpus. "
                "At this severity tier the opposed trace is not hard-required, but "
                "the reviewer must confirm no protocol defense (e.g. a watchtower "
                "that unfreezes next block) neutralizes the claimed impact. Resolve "
                "by enumerating defenses, declaring 'opposed_trace_coverage: "
                "not_applicable', or adding "
                "<!-- opposed-trace-rebuttal: <reason up to 200 chars> -->."
            ),
            "remediation_options": _UNOPPOSED_REMEDIATION,
            "evidence": evidence,
        }

    # Defenses are present
    if has_defender_wins and not has_attacker_wins:
        # Protocol defenses succeed. HIGH+ hard-fails (cannot claim direct
        # loss); Medium/Low gets a mandatory advisory the reviewer must clear.
        if enforcement == "hard":
            return 1, {
                "schema": SCHEMA_VERSION,
                "gate": GATE,
                "verdict": "fail-defender-wins",
                "severity": sev,
                "severity_source": sev_src,
                "enforcement": "hard",
                "reason": (
                    "Protocol defenses are enumerated and the draft/PoC shows the defender "
                    "wins (funds recovered, attack prevented). Direct Loss cannot be claimed "
                    "when the protocol's own defense neutralizes the attack. Walk back severity "
                    "or restructure the PoC to prove the attacker wins DESPITE the defense."
                ),
                "remediation_options": _DEFENDER_WINS_REMEDIATION,
                "evidence": evidence,
            }
        # Medium / Low / below-High: advisory only, non-blocking (exit 0).
        return 0, {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "warn-defender-wins",
            "severity": sev,
            "severity_source": sev_src,
            "enforcement": "advisory",
            "reason": (
                "ADVISORY: protocol defenses are enumerated and the draft/PoC shows "
                "the defender wins (funds recovered, attack prevented). At this "
                "severity tier this is not a hard block, but the reviewer must "
                "confirm the claimed impact still holds despite the protocol's own "
                "defense, or walk back the claim."
            ),
            "remediation_options": _DEFENDER_WINS_REMEDIATION,
            "evidence": evidence,
        }

    # Defenses present AND (attacker wins OR neutral/unknown outcome)
    return 0, {
        "schema": SCHEMA_VERSION,
        "gate": GATE,
        "verdict": "pass-defenses-covered",
        "severity": sev,
        "severity_source": sev_src,
        "enforcement": enforcement,
        "reason": "Protocol-owned defenses are enumerated and attacker-wins outcome is demonstrated or defender-wins signal is absent",
        "evidence": evidence,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path, help="Path to the submission draft Markdown")
    parser.add_argument("--poc-dir", dest="poc_dir", help="Optional directory containing PoC source files")
    parser.add_argument("--severity", choices=("Critical", "High", "Medium", "Low",
                                                "critical", "high", "medium", "low"))
    parser.add_argument("--strict", action="store_true", help="Reserved for future use")
    parser.add_argument("--json", action="store_true", help="Emit JSON output (default)")
    args = parser.parse_args(argv)
    rc, payload = run(args.draft, poc_dir=args.poc_dir, severity=args.severity, strict=args.strict)
    print(json.dumps(payload, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
