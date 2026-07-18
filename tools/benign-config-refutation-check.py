#!/usr/bin/env python3
"""benign-config-refutation-check.py - R-ADVERSARIAL-CONFIG detector.

Operator directive (2026-07-04, NUVA donation lead): a KILL / REFUTED /
NOT-FILEABLE verdict may NEVER rest on the assumption that a security-relevant
value takes its BENIGN / documented / reference-deployment / test-fixture value
when that value is ATTACKER-SELECTABLE (permissionless create/configure, a
user-supplied arg, or self-admin of an attacker-owned resource). The NUVA
donation lane wrongly refuted "the underlying marker is restricted (per the
KYC/RWA program description + fixtures)" while ``CreateVault`` is PERMISSIONLESS
and never enforces a restricted marker in code - so the attacker instantiates the
adversarial config. Documentation / narrative / README / program-description /
test-fixtures are NOT enforced constraints.

This checker SCANS a workspace's verdict/lead sidecars for terminal-negative
verdicts whose REASON leans on a benign-config assumption WITHOUT a countervailing
code-guard / adversarial-reachability argument, and flags them for re-adjudication.

Generalizes far beyond NUVA: any protocol with permissionless pool / vault /
market / token creation (Uniswap pools, lending markets, ERC4626 vaults, denom
factories) where an auditor might wrongly assume "the deployed config uses safe
params" while an attacker can create an instance with adversarial params.

Verdicts:
  pass-no-benign-config-refutation  - no flagged verdict
  warn-benign-config-refutation     - >=1 flagged (advisory; rc 0)
  fail-benign-config-refutation     - >=1 flagged AND strict (rc 1)

STRICT: AUDITOOOR_ADVERSARIAL_CONFIG_STRICT in {1,true,yes} hard-fails; unset ->
enforced iff AUDITOOOR_L37_STRICT is truthy... NO: advisory-first for a NEW gate
(the standing doctrine). Default is ADVISORY (warn, rc 0) unless the per-gate env
is explicitly truthy. The operator may later graduate it default-on-under-L37.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.benign_config_refutation_check.v1"
_STRICT_ENV = "AUDITOOOR_ADVERSARIAL_CONFIG_STRICT"

# Terminal-negative verdicts (a refutation / kill / down-tier).
_NEGATIVE_RE = re.compile(
    r"\b(kill|killed|refute[d]?|not[-\s]?fileable|no[-\s]?finding|"
    r"applies_to_target\W+no|ruled[-\s]?out)\b", re.IGNORECASE)

# BENIGN-CONFIG refutation markers: language that leans on the documented /
# deployed / fixture configuration rather than a code-enforced guard.
_BENIGN_CONFIG_RE = re.compile(
    r"("
    r"realistic(?:ally)?\s+(?:deploy|config)"          # "realistic deployment/config"
    r"|deployed\s+config(?:uration)?"
    r"|reference\s+deployment"
    r"|not\s+evidenced\s+as\s+the\s+(?:real|deployed|actual|production)\s+config"
    r"|per\s+the\s+\w[\w\s]{0,40}?(?:program\s+description|whitepaper|readme|docs?|documentation)"
    r"|(?:kyc|rwa)\b[\w\s,/'-]{0,40}?(?:so|therefore|means|implies|restricted)"
    r"|test\s+fixtures?\b[\w\s,'-]{0,40}?(?:point|suggest|indicate|show|use)"
    r"|every\s+(?:realistic\s+)?(?:test\s+)?fixture"
    r"|intended\s+config(?:uration)?"
    r"|the\s+real\s+config(?:uration)?"
    r"|documented\s+(?:to\s+be\s+)?config"
    r"|assum\w+\s+the\s+\w+\s+is\s+(?:restricted|safe|trusted|benign)"
    r")", re.IGNORECASE)

# Countervailing signals: genuine ADVERSARIAL-REACHABILITY reasoning that shows the
# author did NOT just assume the benign config - they either proved the attacker
# cannot reach the adversarial config, cited a guard that STRUCTURALLY forbids it,
# or did the adversarial-config economic math. A bare file:line citation is
# DELIBERATELY NOT here: the NUVA donation lane cited send_restrictions.go while
# STILL concluding "restricted for the realistic deployment" - a code citation used
# to PROP UP a benign-config assumption must still be flagged. Only these
# attacker-reasoning signals exempt a verdict.
_CODE_GUARD_RE = re.compile(
    r"("
    r"attacker\s+can(?:not|'t|no?t)?\s+(?:create|set|choose|configure|reach|"
    r"instantiate|select|deploy|supply)"
    r"|(?:cannot|can't|unable\s+to)\s+(?:create|instantiate|reach)\s+"
    r"(?:an?\s+)?(?:adversarial|unrestricted|malicious|attacker)"
    r"|even\s+(?:if|with|when|for)\s+an?\s+(?:attacker|adversarial|unrestricted|"
    r"malicious)[-\s]\w+"
    r"|permissionless\w*\s+(?:creation|create)\b[\w\s,]{0,60}?"
    r"(?:but|still|however|does\s+not\s+help|no\s+net|self-)"
    r"|adversarial(?:ly)?[-\s]?(?:chosen|selected|created|configured|controlled)"
    r"|structurally\s+(?:forbid|prevent|foreclos)"
    r"|require\s*\(\s*\w*(?:marker\w*type|restricted|isrestricted)"       # a real config guard
    r"|self[-\s]?dilut\w+|break[-\s]?even"
    r"|no\s+net\s+(?:gain|extraction|profit)\b[\w\s]{0,50}?(?:because|since|:|pro[-\s]?rata)"
    r")", re.IGNORECASE)


def _iter_sidecar_reasons(ws: Path):
    """Yield (source, verdict_str, reason_str) for every verdict/lead artifact."""
    a = ws / ".auditooor"
    # per-question + hunt-finding sidecars
    for sub in ("hacker_question_verdicts", "hunt_findings_sidecars"):
        d = a / sub
        if not d.is_dir():
            continue
        for fp in sorted(d.glob("*.json")):
            try:
                rec = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(rec, dict):
                continue
            verdict = str(rec.get("verdict") or rec.get("state")
                          or rec.get("applies_to_target") or "")
            reason = " ".join(
                str(rec.get(k) or "") for k in
                ("reason", "reasoning", "rationale", "justification",
                 "kill_reason", "note", "notes", "result"))
            yield (str(fp), verdict, reason)
    # lead_verdicts.jsonl
    lv = a / "lead_verdicts.jsonl"
    if lv.is_file():
        for line in lv.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            verdict = str(rec.get("verdict") or "")
            reason = json.dumps(rec.get("reason") or rec.get("reasons")
                                or rec.get("refutation") or "")
            yield (f"{lv}::{rec.get('lead') or rec.get('lead_id') or '?'}",
                   verdict, reason)


def scan(ws: Path) -> dict:
    flagged = []
    scanned = 0
    for src, verdict, reason in _iter_sidecar_reasons(ws):
        scanned += 1
        if not reason.strip():
            continue
        if not _NEGATIVE_RE.search(verdict) and not _NEGATIVE_RE.search(reason[:200]):
            continue  # only terminal-negative verdicts can refute-by-config
        if not _BENIGN_CONFIG_RE.search(reason):
            continue  # no benign-config leaning
        if _CODE_GUARD_RE.search(reason):
            continue  # author already reasoned adversarial reachability / code guard
        m = _BENIGN_CONFIG_RE.search(reason)
        flagged.append({
            "source": src,
            "verdict": verdict[:40],
            "benign_config_phrase": m.group(0)[:80] if m else "",
        })
    return {"scanned": scanned, "flagged": flagged}


def _strict() -> bool:
    v = os.environ.get(_STRICT_ENV, "").strip().lower()
    return v in ("1", "true", "yes")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="R-ADVERSARIAL-CONFIG detector")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).expanduser()
    res = scan(ws)
    strict = _strict()
    n = len(res["flagged"])
    if n == 0:
        verdict = "pass-no-benign-config-refutation"
    elif strict:
        verdict = "fail-benign-config-refutation"
    else:
        verdict = "warn-benign-config-refutation"
    out = {"schema": SCHEMA, "verdict": verdict, "strict": strict,
           "strict_env": _STRICT_ENV, "scanned": res["scanned"],
           "flagged_count": n, "flagged": res["flagged"][:100]}
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"[R-ADVERSARIAL-CONFIG] verdict={verdict} scanned={res['scanned']} "
              f"flagged={n}")
        for f in res["flagged"][:25]:
            print(f"    - {f['source']} [{f['verdict']}] "
                  f"benign-config: {f['benign_config_phrase']!r}")
        if n and not strict:
            print("  (advisory: a refutation must cite a CODE guard / adversarial-config "
                  "math / access-control check - NOT the documented/deployed/fixture "
                  "config. Re-adjudicate assuming the attacker-selected config.)")
    return 1 if verdict.startswith("fail") else 0


if __name__ == "__main__":
    sys.exit(main())
