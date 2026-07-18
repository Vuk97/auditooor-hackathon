#!/usr/bin/env python3
"""adversarial-candidate-verify.py - adversarial multi-perspective verification
panel for Medium+ candidate findings.

For a Medium+ candidate, run THREE INDEPENDENT refutation lenses, each of which
tries to KILL the candidate from a different angle:

  1. correctness               - is the alleged root cause technically correct,
                                 or is it a misread of the source / a logic error
                                 in the exploit reasoning?
  2. reachability-at-pin       - is the vulnerable path reachable from a real
                                 entrypoint at the audited commit pin, or is it
                                 dead code / behind a flag / unreachable by the
                                 attacker actor?
  3. defense-in-depth-traversal - does the attack payload survive EVERY defense
                                 layer between the bug and the impact, or is it
                                 categorically rejected somewhere on the path?

Each lens DEFAULTS TO REFUTED-IF-UNCERTAIN. A lens only votes "survives" when
the candidate carries explicit, source-cited evidence that closes that lens's
question. Absence of evidence is a refutation, not a pass.

Panel verdict:
  - If a MAJORITY (>= 2 of 3) of lenses refute, the candidate is KILLED.
  - A candidate can only reach FINAL_LEADS when it SURVIVES the panel (0 or 1
    refutations) OR every refuting lens is honestly source-ruled-out via an
    explicit rebuttal marker.

This is distinct from candidate-debate-dispatcher.py (attacker/defender/referee
narrative triad). Here the three perspectives are FIXED refutation lenses with
deterministic, evidence-gated, refuted-if-uncertain voting - no LLM dispatch,
no narrative free-text. The point is a mechanical kill-gate before FINAL_LEADS.

RELATED TOOLS:
  - tools/candidate-debate-dispatcher.py  : LLM-style attacker/defender/referee
    narrative triad; free-text verdicts; NOT evidence-gated.
  - tools/defense-in-depth-traversal-check.py : single-axis (defense traversal)
    pre-submit gate for HIGH+ drafts; this tool reuses the same conceptual axis
    as lens 3 but composes it with correctness + reachability into a panel and
    applies majority-kill semantics at the candidate (pre-FINAL_LEADS) stage.
  - tools/reachability-verification-check.py : single-axis reachability gate.
  This tool fills the gap of a 3-lens MAJORITY panel that fires at the
  candidate stage (before a draft exists) with refuted-if-uncertain defaults.

CLI:
  python3 tools/adversarial-candidate-verify.py <candidate.md|.json> \\
      [--severity {auto,Low,Medium,High,Critical}] [--strict] [--json]

Verdict vocabulary (panel_verdict):
  pass-out-of-scope                 - severity below Medium (panel does not fire)
  pass-survived-panel               - >= 2 lenses survive; candidate may proceed
  pass-refutations-ruled-out        - majority refuted but each refuting lens
                                      carries a valid rebuttal marker
  fail-killed-by-panel              - majority refuted, no rebuttal -> KILL
  error                             - bad input / unreadable candidate

Override markers (per-lens rebuttal, visible line or HTML comment, <=200 chars):
  acv-rebuttal-correctness: <reason>
  acv-rebuttal-reachability: <reason>
  acv-rebuttal-defense: <reason>
  <!-- acv-rebuttal-correctness: <reason> -->   (etc.)
A rebuttal only rules out the lens it names; it does not silence the others.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_ID = "auditooor.adversarial_candidate_verify.v1"

EXIT_OK = 0
EXIT_INPUT = 1

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Lens identities (order is stable).
LENS_CORRECTNESS = "correctness"
LENS_REACHABILITY = "reachability-at-pin"
LENS_DEFENSE = "defense-in-depth-traversal"
LENSES = (LENS_CORRECTNESS, LENS_REACHABILITY, LENS_DEFENSE)

REBUTTAL_KEY = {
    LENS_CORRECTNESS: "acv-rebuttal-correctness",
    LENS_REACHABILITY: "acv-rebuttal-reachability",
    LENS_DEFENSE: "acv-rebuttal-defense",
}

# -- Per-lens "survives" evidence patterns -----------------------------------
# A lens votes SURVIVES only if at least one of its evidence patterns matches.
# Refuted-if-uncertain: no match => refuted.

CORRECTNESS_EVIDENCE = [
    r"(?im)\broot[\s-]?cause\b.{0,120}\b(?:file|line|L\d|:\d)",          # root cause w/ file:line
    r"(?im)\b\w[\w./-]+\.(?:sol|go|rs|move|cairo|ts|py|vy):\d+",          # any file:line citation
    r"(?im)^\s*(?:correctness|technical[\s-]?correctness)[\s_-]*verified\b",
    r"(?im)\bnegative[\s-]control\b",                                     # negative control = correctness anchor
    r"(?im)\bpatched[\s-]?(?:code|behavior|baseline)\b.{0,80}\b(?:does not|no longer|prevents)\b",
]

REACHABILITY_EVIDENCE = [
    r"(?im)\breachab(?:le|ility)\b.{0,120}\b(?:from|via)\b.{0,120}\b(?:entrypoint|external|public|caller)\b",
    r"(?im)\b(?:real|live)\s+entrypoint\b",
    r"(?im)\bat\s+(?:the\s+)?(?:audit[\s-]?)?pin\b.{0,120}\breachab",
    r"(?im)\battacker\s+actor\b.{0,120}\b(?:exists|non-?empty|can\s+call|can\s+invoke)\b",
    r"(?im)^\s*reachability[\s_-]*(?:verified|confirmed)\b",
    r"(?im)\bcall[\s-]?(?:path|graph|chain)\b.{0,120}\b\w[\w./-]+\.(?:sol|go|rs|move|cairo|ts|py|vy):\d+",
]

DEFENSE_EVIDENCE = [
    r"(?im)\bdefense[\s-]in[\s-]depth\b.{0,120}\btravers",
    r"(?im)\bsurvives?\b.{0,80}\b(?:every|all|each)\b.{0,40}\bdefense",
    r"(?im)\bante[\s-]?(?:handler|decorator)\b.{0,80}\btravers",
    r"(?im)\b(?:reaches|reached)\b.{0,80}\b(?:impact|matching engine|FinalizeBlock|DeliverTx|settlement)\b",
    r"(?im)\b(?:no|zero)\s+(?:intervening|stacked)\s+defense",
    r"(?im)^\s*defense[\s_-]*travers(?:al|ed)[\s_-]*(?:verified|confirmed|complete)\b",
    # Honest walk-back / ceiling is also a valid SURVIVE signal: the candidate
    # has been honest about where the defense stops, so the lens has its answer.
    r"(?im)\bdefense[\s-]in[\s-]depth\s+ceiling\b",
    r"(?im)\b(?:structurally|categorically)\s+(?:rejected|blocked)\b",
]

LENS_EVIDENCE = {
    LENS_CORRECTNESS: CORRECTNESS_EVIDENCE,
    LENS_REACHABILITY: REACHABILITY_EVIDENCE,
    LENS_DEFENSE: DEFENSE_EVIDENCE,
}

LENS_QUESTION = {
    LENS_CORRECTNESS: (
        "Is the alleged root cause technically correct and source-anchored, "
        "or a misread / reasoning error?"
    ),
    LENS_REACHABILITY: (
        "Is the vulnerable path reachable from a real entrypoint at the audit "
        "pin by the attacker actor, or is it dead/unreachable?"
    ),
    LENS_DEFENSE: (
        "Does the payload survive every defense layer to the impact, or is it "
        "rejected somewhere on the path?"
    ),
}

LENS_REFUTED_REASON = {
    LENS_CORRECTNESS: (
        "No source-anchored root-cause evidence (file:line / negative control / "
        "patched-baseline). Refuted-if-uncertain: correctness unproven."
    ),
    LENS_REACHABILITY: (
        "No reachability-at-pin evidence (real entrypoint / attacker-actor "
        "existence / call path to file:line). Refuted-if-uncertain: path may be "
        "unreachable."
    ),
    LENS_DEFENSE: (
        "No defense-in-depth traversal evidence (and no honest ceiling/walk-back). "
        "Refuted-if-uncertain: a stacked defense may categorically reject the payload."
    ),
}


# ---------------------------------------------------------------------------
# Input loading
# ---------------------------------------------------------------------------

def _load_candidate(path: Path) -> tuple[str, dict[str, Any] | None]:
    """Return (text_body, parsed_json_or_None). For JSON candidates we flatten
    string-valued fields into the searchable text so the lens patterns still
    fire on structured candidates."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return raw, None
        chunks: list[str] = []

        def _walk(v: Any) -> None:
            if isinstance(v, str):
                chunks.append(v)
            elif isinstance(v, dict):
                for k, vv in v.items():
                    chunks.append(str(k))
                    _walk(vv)
            elif isinstance(v, list):
                for vv in v:
                    _walk(vv)

        _walk(obj)
        return "\n".join(chunks), (obj if isinstance(obj, dict) else None)
    return raw, None


def _severity(text: str, path: Path, override: str | None, obj: dict[str, Any] | None) -> tuple[str | None, str]:
    if override and override.strip().lower() != "auto":
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    if obj:
        for key in ("severity", "severity_tier", "severity_implied", "proposed_severity"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip().lower() in SEVERITY_RANK:
                return val.strip().lower(), f"json:{key}"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", path.name.lower()):
            return severity, "filename"
    return None, "missing"


# ---------------------------------------------------------------------------
# Rebuttal parsing
# ---------------------------------------------------------------------------

def _rebuttal(text: str, key: str) -> str | None:
    """Return a non-empty, <=200-char rebuttal reason for *key*, or None.
    Accepts the visible bounded line `<key>: <reason>` and the HTML-comment
    form `<!-- <key>: <reason> -->`."""
    patterns = [
        rf"(?im)<!--\s*{re.escape(key)}\s*:\s*(.+?)\s*-->",
        rf"(?im)^\s*{re.escape(key)}\s*:\s*(.+?)\s*$",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            reason = m.group(1).strip()
            if reason and len(reason) <= 200:
                return reason
    return None


# ---------------------------------------------------------------------------
# Lens evaluation
# ---------------------------------------------------------------------------

def _run_lens(lens: str, text: str) -> tuple[str, str | None]:
    """Return (vote, matched_pattern). vote in {"survives","refuted"}.
    refuted-if-uncertain: only "survives" if an evidence pattern matches."""
    for pat in LENS_EVIDENCE[lens]:
        if re.search(pat, text):
            return "survives", pat
    return "refuted", None


def evaluate(text: str, severity: str | None, severity_source: str,
             strict: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_id": SCHEMA_ID,
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "lenses": [],
        "refutation_count": 0,
        "panel_verdict": None,
        "reason": "",
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["medium"]:
        payload["panel_verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below Medium or missing; panel does not fire"
        return payload

    refutations = 0
    ruled_out = 0
    lens_results: list[dict[str, Any]] = []

    for lens in LENSES:
        vote, matched = _run_lens(lens, text)
        rebuttal = _rebuttal(text, REBUTTAL_KEY[lens])
        entry: dict[str, Any] = {
            "lens": lens,
            "question": LENS_QUESTION[lens],
            "vote": vote,
            "matched_evidence": matched,
            "rebuttal": rebuttal,
        }
        if vote == "refuted":
            refutations += 1
            if rebuttal:
                entry["effective"] = "ruled-out"
                entry["reason"] = f"refuted but ruled out via rebuttal: {rebuttal}"
                ruled_out += 1
            else:
                entry["effective"] = "refuted"
                entry["reason"] = LENS_REFUTED_REASON[lens]
        else:
            entry["effective"] = "survives"
            entry["reason"] = "evidence present; lens question answered"
        lens_results.append(entry)

    payload["lenses"] = lens_results
    payload["refutation_count"] = refutations
    payload["refutations_ruled_out"] = ruled_out

    # Strict mode: a refuted lens that carries a rebuttal still counts toward
    # the kill threshold unless the rebuttal is present (already handled) -
    # strict additionally requires that NO lens be merely "uncertain-survive";
    # i.e. in strict mode any refutation (even <2) that is not ruled out fails.
    unresolved = refutations - ruled_out

    if strict and unresolved >= 1:
        payload["panel_verdict"] = "fail-killed-by-panel"
        payload["reason"] = (
            f"strict mode: {unresolved} unresolved refutation(s) of "
            f"{len(LENSES)} lenses; candidate cannot reach FINAL_LEADS"
        )
        return payload

    if unresolved >= 2:
        payload["panel_verdict"] = "fail-killed-by-panel"
        payload["reason"] = (
            f"majority refuted: {unresolved}/{len(LENSES)} lenses refute with no "
            f"valid rebuttal; candidate KILLED before FINAL_LEADS"
        )
        return payload

    if refutations >= 2 and unresolved < 2:
        payload["panel_verdict"] = "pass-refutations-ruled-out"
        payload["reason"] = (
            f"{refutations} lenses refuted but {ruled_out} ruled out via rebuttal; "
            f"{unresolved} unresolved (< majority); candidate may proceed"
        )
        return payload

    payload["panel_verdict"] = "pass-survived-panel"
    payload["reason"] = (
        f"{len(LENSES) - refutations} lens(es) survive, {unresolved} unresolved "
        f"refutation(s) (< majority); candidate survives the panel"
    )
    return payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _render_human(payload: dict[str, Any], candidate: Path) -> str:
    lines = [
        f"adversarial-candidate-verify :: {candidate.name}",
        f"  severity      : {payload['severity']} ({payload['severity_source']})",
        f"  panel_verdict : {payload['panel_verdict']}",
        f"  refutations   : {payload['refutation_count']} "
        f"(ruled out: {payload.get('refutations_ruled_out', 0)})",
    ]
    for entry in payload["lenses"]:
        lines.append(
            f"    [{entry['effective']:>9}] {entry['lens']}: {entry['reason']}"
        )
    lines.append(f"  reason        : {payload['reason']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("candidate", help="path to candidate .md or .json")
    parser.add_argument(
        "--severity",
        default="auto",
        choices=["auto", "Low", "Medium", "High", "Critical",
                 "low", "medium", "high", "critical"],
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="any unresolved refutation (>=1) kills the candidate",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    candidate = Path(args.candidate)
    if not candidate.is_file():
        msg = {"schema_id": SCHEMA_ID, "panel_verdict": "error",
               "reason": f"candidate not found: {candidate}"}
        print(json.dumps(msg) if args.json else msg["reason"], file=sys.stderr)
        return EXIT_INPUT

    try:
        text, obj = _load_candidate(candidate)
    except OSError as exc:  # pragma: no cover - unreadable file
        msg = {"schema_id": SCHEMA_ID, "panel_verdict": "error",
               "reason": f"unreadable candidate: {exc}"}
        print(json.dumps(msg) if args.json else msg["reason"], file=sys.stderr)
        return EXIT_INPUT

    severity, severity_source = _severity(text, candidate, args.severity, obj)
    payload = evaluate(text, severity, severity_source, args.strict)
    payload["candidate"] = str(candidate)

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(_render_human(payload, candidate))

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
