#!/usr/bin/env python3
"""impact-recovery-falsification-check.py - Rule 82 (impact-recovery-falsification-required).

The missing POST-impact axis. Every existing impact/defense gate (R24 non-self-impact,
R25 defense-in-depth-traversal, R29 commitment-vs-validation, R40 V3-grade-PoC, R44
opposed-trace-actor-separation, R57 exhaustive-defense-chain-enumeration) asserts a fact
AT OR BEFORE the impact commit - the attacker can act, and the named PRE-impact defenders
are traversed. NONE asks whether, AFTER the bad state is realized, the victim V can
restore themselves in-protocol, and whether the draft drove that recovery to FAILURE.

R82 owns that post-impact victim-recovery axis. For any Medium+ permanent loss/freeze/
theft/unauthorized-stuck-state claim, the draft must enumerate V's in-protocol recovery
entrypoints and show each FAILS (driven in PoC) or is unreachable (source-traced). A live
un-falsified recovery path makes the "permanent loss" claim false (the victim was made
whole). This is the inverse of R57's defender-table: R57 enumerates the defender's
pre-impact stop-the-attack paths; R82 enumerates the victim's post-impact self-cure paths.

Empirical anchor (honest): R82 is generalized from the Spark LEAD-1 saga, where a "direct
loss to the receiver" Critical was disputed v8..v12 before source verification showed the
receiver self-recovers (claim -> connector-less 1-input refund -> sweep). LEAD-1 is NOT
used as R82's victim-recovery anchor because that recovery runs partly through protocol/
watchtower mechanics (R57's defender axis); R82 ships anchored on generic fixtures + the
cosmos RemoveExpiredAllowances true-positive (re-grant does NOT restore consumed
sponsorship -> genuine permanent state -> passes R82).

RELATED TOOLS (checked before building, dedup discipline):
  - tools/exhaustive-defense-chain-enumeration-check.py (R57): structural twin, OPPOSITE
    target (defender pre-impact stoppers). R82 reuses its table+grep+citation shape.
  - tools/non-self-impact-check.py (R24): WHO is harmed. R82 takes R24's confirmed victim
    and falsifies their self-cure.
  - tools/v3-grade-poc-check.py (R40): PoC-construction honesty at impact. R82 asserts the
    magnitude SURVIVES recovery.
  - tools/commitment-vs-validation-check.py (R29): commitment point BEFORE impact. R82 is
    the bad-outcome-realized moment AFTER impact.

Usage:
  impact-recovery-falsification-check.py <draft.md> [--workspace <ws>] [--poc-dir <dir>]
      [--severity {auto,LOW,MEDIUM,HIGH,CRITICAL}] [--strict] [--json]
      [--emit-recovery-worklist <ws>]
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

SCHEMA = "auditooor.r82_impact_recovery_falsification.v1"
GATE = "R82-IMPACT-RECOVERY-FALSIFICATION"

_SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SRC_EXT = ("rs", "sol", "go", "move", "vy", "cairo", "ts")
FILE_LINE_RE = re.compile(r"\b([\w./-]+\.(?:" + "|".join(_SRC_EXT) + r"))[:#L]+(\d+)\b")
_SECTION_RE = re.compile(r"^#{1,6}\s*victim\s+recovery\s+enumeration\s*:?\s*$", re.I | re.M)

# Permanent-impact triggers (the harm is asserted to PERSIST). env-extendable.
_DEFAULT_IMPACT_PATTERNS = [
    r"permanent(?:ly)?\s+(?:loss|freez(?:e|ing)|lock(?:ed)?|theft|lost|frozen|unrecoverable|irrecoverable)",
    r"funds?\s+(?:are\s+|become\s+)?(?:permanently\s+)?(?:lost|frozen|locked|unrecoverable|stuck|stranded)",
    r"direct\s+(?:loss|theft)\s+of\s+(?:victim|receiver|user|depositor|lp|protocol)?\s*funds",
    r"irrecoverable|irreversible\s+loss|cannot\s+(?:be\s+)?recover(?:ed)?|no\s+way\s+to\s+recover",
    r"loss\s+of\s+funds|theft\s+of\s+funds|fund\s+drain|drained|stolen",
    r"freezing\s+of\s+funds|frozen\s+funds|stuck\s+funds|stranded\s+funds",
    r"hardfork\s+(?:required|to\s+recover)|governance\s+(?:required\s+)?to\s+(?:unfreeze|recover)",
    r"unauthorized\s+(?:state|status)\s+(?:transition|change|mutation)",
]

# Per-row falsification tokens: a recovery row must show the path FAILS for V.
_DEFAULT_FAIL_WORDS = [
    "fails", "fail", "reverts", "revert", "no-op", "noop", "still short", "leaves v short",
    "leaves the victim short", "unreachable", "blocked", "window closed", "burned",
    "insufficient", "cannot restore", "does not restore", "does not make whole",
    "rejected", "missingorspent", "zero", "== 0", "reverts(", "not restore",
]

# Per-target recovery-action libraries (env: AUDITOOOR_R82_RECOVERY_PATTERNS_<TARGET>).
TARGET_RECOVERY_LIBS = {
    "evm": [r"withdraw\w*", r"redeem\w*", r"claim\w*", r"emergencyWithdraw", r"rescue\w*",
            r"cancel\w*", r"recover\w*", r"escapeHatch", r"forceWithdraw", r"unstake",
            r"\bexit\(", r"reDeposit"],
    "cosmos_sdk": [r"MsgWithdraw\w*", r"MsgCancel\w*", r"MsgClaim\w*", r"Refund\w*",
                   r"\bUnbond", r"MsgExit", r"MsgSubmitProposal"],
    "substrate": [r"withdraw_unbonded", r"claim\w*", r"refund\w*", r"cancel\w*",
                  r"force_\w*", r"redeem\w*"],
    "l2_rollup": [r"forceWithdraw", r"forceInclude", r"escapeHatch", r"proveWithdrawal",
                  r"finalizeWithdrawal", r"challenge\w*"],
    "solana": [r"withdraw\w*", r"claim\w*", r"close_account", r"refund\w*", r"cancel\w*",
               r"reclaim\w*"],
    "bitcoin_lightning_spark": [r"claim\w*", r"refund\w*", r"sweep\w*", r"unilateral\w*exit",
                                r"force[- ]?close"],
}
_EXT_TO_TARGET = {"sol": "evm", "vy": "evm", "go": "cosmos_sdk", "rs": "substrate",
                  "move": "evm", "cairo": "l2_rollup", "ts": "evm"}

_ASSERT_RE = re.compile(r"\b(assert\w*|require|expect|EXPECT|ASSERT|vm\.expectRevert|"
                        r"\.unwrap_err|should\b|must\b|matches!)\b")
_R82_REBUTTAL_RE = re.compile(r"(?:<!--\s*)?r82-rebuttal:\s*(.+?)(?:\s*-->)?\s*$", re.I | re.M)

# --- Restart-based permanence must be EXECUTED (the Permanent/Critical-vs-Temporary/High hinge) ---
# When a CRITICAL permanent claim's recovery-falsification hinges on a restart/replay/
# state-resident leg ("a plain restart re-loads the flood and re-fails"), that leg is exactly
# what separates Permanent (Critical) from Temporary (High). Per SEVERITY.md's own permanence
# test ("if a restart/upgrade frees the funds it is Temporary") the "restart does NOT heal it"
# claim must be DEMONSTRATED by an EXECUTED close-and-reopen restart-survival PoC (round11
# discipline: FinalizeBlock+Commit -> close app -> reopen from disk -> re-fail), not
# source-traced prose. Source-tracing that "the queue is store-resident" is necessary but not
# sufficient for the Critical tier.
# _RESTART_LEG_RE (broad): does the permanence LEAN on a restart leg at all?
_RESTART_LEG_RE = re.compile(
    r"\brestart\b|\breboot\b|re-?load|re-?open|\breplay\b|state-?resident|store-?resident|"
    r"persisted\s+(?:flood|state|poison|queue|entr|keyset|due)", re.I)
# _RESTART_EXECUTED_RE (narrow): signatures that appear ONLY in an EXECUTED transcript / test
# code, never in prose - so a draft that merely SAYS "close-and-reopen is structural" fails.
_RESTART_EXECUTED_RE = re.compile(
    r"restart[- ]survival\s+confirmed"
    r"|\blifetime\s*2\b"
    r"|LoadLatestVersion|NewGoLevelDB|goleveldb\.OpenFile"
    r"|restarted\s+(?:node|app|validator)\b[^.\n]*\bre-?(?:panic|stall|fail)\w*"
    r"|---\s*PASS:\s*\w*[Rr]estart\w*"
    r"|func\s+Test\w*[Rr]estart\w*[Ss]urviv", re.I)
_R82_RESTART_EXECUTED_REBUTTAL_RE = re.compile(
    r"(?:<!--\s*)?r82-restart-executed-rebuttal:\s*(.+?)(?:\s*-->)?\s*$", re.I | re.M)


def _restart_executed_evidence(text, poc_dir):
    """True if an EXECUTED restart-survival demonstration exists - in the draft text or (chiefly)
    in a co-located PoC artifact (transcript / test file). Prose in the draft cannot satisfy this."""
    if _RESTART_EXECUTED_RE.search(text):
        return True
    if poc_dir and Path(poc_dir).is_dir():
        for f in Path(poc_dir).rglob("*"):
            try:
                if f.is_file() and f.suffix.lower() in (".txt", ".log", ".md", ".go", ".out") \
                        and f.stat().st_size < 4_000_000:
                    if _RESTART_EXECUTED_RE.search(f.read_text(encoding="utf-8", errors="replace")):
                        return True
            except OSError:
                continue
    return False


def _env_list(name, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    extra = [x.strip() for x in raw.splitlines() if x.strip()]
    return default + extra


def _severity(draft_text, override):
    if override and override != "auto":
        return override.upper()
    m = re.search(r"(?:^|\n)[-\s>*]*\**severity\**\s*[:=]\s*\**\s*(CRITICAL|HIGH|MEDIUM|LOW|CRIT-?1|CRIT-?2)",
                  draft_text, re.I)
    if m:
        v = m.group(1).upper().replace("-", "")
        if v.startswith("CRIT"):
            return "CRITICAL"
        return v
    for kw in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if re.search(r"\b" + kw + r"\b", draft_text):
            return kw
    return ""


def _has_section(text):
    return bool(_SECTION_RE.search(text))


def _table_rows(text):
    """Return markdown table data rows that look like recovery-entrypoint rows."""
    rows = []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("|") and s.count("|") >= 3 and not re.match(r"^\|[\s:|-]+\|?$", s):
            cells = [c.strip() for c in s.strip("|").split("|")]
            # skip header rows
            if any(re.search(r"recovery|entrypoint|mechanism|outcome|ruling|driven", c, re.I) for c in cells) \
               and not FILE_LINE_RE.search(s) and "excluded" not in s.lower():
                continue
            rows.append((s, cells))
    return rows


def _rebuttal(text):
    for m in _R82_REBUTTAL_RE.finditer(text):
        reason = (m.group(1) or "").strip().strip("-").strip()
        if 0 < len(reason) <= 200:
            return reason
    return None


def _candidate_source_roots(ws):
    roots = []
    for sub in ("external", "src"):
        p = ws / sub
        if p.is_dir():
            roots.append(p)
    if not roots:
        roots = [ws]
    return roots


def _iter_source_files(root):
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lstrip(".") in _SRC_EXT:
            sp = str(p)
            if "/test" in sp or "_test." in sp or "/mock" in sp or ".t.sol" in sp:
                continue
            yield p


def _recovery_grep(ws, limit=4000):
    """Layer 2: inverse-grep V-recovery surfaces across the in-scope src tree."""
    hits = []
    seen_ext = set()
    for root in _candidate_source_roots(ws):
        for f in _iter_source_files(root):
            ext = f.suffix.lstrip(".")
            seen_ext.add(ext)
            target = _EXT_TO_TARGET.get(ext, "evm")
            pats = _env_list(f"AUDITOOOR_R82_RECOVERY_PATTERNS_{target.upper()}",
                             TARGET_RECOVERY_LIBS.get(target, []))
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, ln in enumerate(lines, 1):
                # only count definition-ish sites (fn/func/def/pub fn) to reduce noise
                if not re.search(r"\b(fn|func|function|def|pub\s+fn|external|public)\b", ln):
                    continue
                for pat in pats:
                    if re.search(pat, ln):
                        hits.append(f"{f.name}:{i}")
                        break
            if len(hits) >= limit:
                return hits
    return hits


def _hit_accounted_for(hit, cited):
    hb, hl = hit.rsplit(":", 1)
    for c in cited:
        cb = c.rsplit(":", 1)[0]
        if Path(cb).name == Path(hb).name:
            try:
                if abs(int(c.rsplit(":", 1)[1]) - int(hl)) <= 8:
                    return True
            except (ValueError, IndexError):
                return True
    return False


def check(draft_path, workspace, poc_dir, severity_override, strict):
    text = draft_path.read_text(encoding="utf-8", errors="replace")
    sev = _severity(text, severity_override)
    out = {"schema": SCHEMA, "gate": GATE, "draft": str(draft_path), "severity": sev}

    if not sev or _SEV_RANK.get(sev, 0) < 2:
        out["verdict"] = "pass-out-of-scope"
        out["reason"] = "severity below Medium or undetected"
        return out

    reb = _rebuttal(text)
    impact_pats = _env_list("AUDITOOOR_R82_IMPACT_PATTERNS", _DEFAULT_IMPACT_PATTERNS)
    triggered = any(re.search(p, text, re.I) for p in impact_pats)
    has_section = _has_section(text)

    if not triggered and not has_section:
        out["verdict"] = "pass-not-permanent-impact-claim"
        out["reason"] = "no permanent-impact trigger and no Victim Recovery Enumeration section"
        return out

    # --- Layer 1 ---
    if not has_section:
        if reb:
            out["verdict"] = "ok-rebuttal"; out["reason"] = f"r82-rebuttal: {reb}"; return out
        out["verdict"] = "fail-no-recovery-enumeration-section"
        out["reason"] = ("permanent-impact claim lacks the required '## Victim Recovery "
                         "Enumeration' section (enumerate V's in-protocol recovery entrypoints "
                         "and falsify each).")
        return out

    # isolate the section body
    m = _SECTION_RE.search(text)
    body = text[m.end():]
    nxt = re.search(r"^#{1,6}\s+\S", body, re.M)
    section = body[:nxt.start()] if nxt else body

    if not re.search(r"impact[- ]lands?", section, re.I) or not FILE_LINE_RE.search(section):
        if reb:
            out["verdict"] = "ok-rebuttal"; out["reason"] = f"r82-rebuttal: {reb}"; return out
        out["verdict"] = "fail-no-impact-lands-citation"
        out["reason"] = "section missing the impact-lands file:line (where the bad state is committed for V)"
        return out

    # --- Restart-based permanence must be EXECUTED (Critical permanent-vs-temporary hinge) ---
    # Narrow: fires only when the claim is CRITICAL and its permanence LEANS on a restart/
    # state-resident leg. The generic r82-rebuttal (prose) does NOT buy this out; a genuinely
    # non-restart permanence (burned key, deleted mapping, unbounded-read OOG, etc.) uses the
    # dedicated r82-restart-executed-rebuttal to say WHY the permanence is not restart-based.
    _restart_strict = os.environ.get("AUDITOOOR_R82_RESTART_EXECUTED", "1").strip().lower() \
        not in ("0", "false", "no", "off")
    if _restart_strict and _SEV_RANK.get(sev, 0) >= _SEV_RANK["CRITICAL"] \
            and _RESTART_LEG_RE.search(section):
        if not _restart_executed_evidence(text, poc_dir):
            rre = _R82_RESTART_EXECUTED_REBUTTAL_RE.search(text)
            if rre and rre.group(1).strip():
                out["restart_permanence_rebuttal"] = rre.group(1).strip()[:200]
            else:
                out["verdict"] = "fail-restart-permanence-not-executed"
                out["reason"] = (
                    "CRITICAL permanent claim's permanence rests on a restart/state-resident recovery "
                    "leg but supplies NO executed restart-survival PoC. The 'a plain restart re-loads "
                    "the flood and re-fails' claim is the Permanent(Critical)-vs-Temporary(High) hinge "
                    "and must be DEMONSTRATED executably (round11 pattern: FinalizeBlock+Commit -> close "
                    "app -> reopen from a real disk store -> re-fail), not source-traced. Add the executed "
                    "close-and-reopen transcript to the PoC dir, or add "
                    "<!-- r82-restart-executed-rebuttal: <why permanence is not restart-based> -->.")
                return out

    rows = _table_rows(section)
    data_rows = [r for r in rows if FILE_LINE_RE.search(r[0]) or "excluded" in r[0].lower()
                 or "no-in-protocol" in r[0].lower() or "out-of-protocol" in r[0].lower()]
    verdict_line = re.search(r"verdict\s*:?\s*(all-recovery-paths-falsified|recovery-path-survives-claim-false|"
                             r"no-in-protocol-recovery-exists|out-of-protocol-recovery-only)", section, re.I)
    vfield = verdict_line.group(1).lower() if verdict_line else ""

    # out-of-protocol-only / no-recovery-exists short-circuit (strengthens the claim)
    if vfield in ("no-in-protocol-recovery-exists", "out-of-protocol-recovery-only") or \
       re.search(r"no\s+in-protocol\s+recovery|only\s+recovery\s+is\s+(?:a\s+)?(?:out-of-protocol|multisig|hardfork|social)",
                 section, re.I):
        out["verdict"] = ("pass-out-of-protocol-recovery-only"
                          if "out-of-protocol" in vfield else "pass-recovery-enumeration-complete")
        out["reason"] = f"verdict={vfield or 'no-in-protocol-recovery-exists'}; no in-protocol victim cure"
        out["recovery_rows"] = len(data_rows)
        return out

    if not data_rows:
        if reb:
            out["verdict"] = "ok-rebuttal"; out["reason"] = f"r82-rebuttal: {reb}"; return out
        out["verdict"] = "fail-recovery-row-without-citation"
        out["reason"] = "Victim Recovery Enumeration table has no recovery rows with file:line or excluded: justification"
        return out

    fail_words = _env_list("AUDITOOOR_R82_RECOVERY_FAIL_WORDS", _DEFAULT_FAIL_WORDS)
    fail_re = re.compile("|".join(re.escape(w) for w in fail_words), re.I)
    cited = []
    survives = []
    for raw, cells in data_rows:
        if "excluded" in raw.lower():
            continue
        flm = FILE_LINE_RE.search(raw)
        if flm:
            cited.append(f"{flm.group(1)}:{flm.group(2)}")
        # a live recovery row must carry a falsification token
        if not fail_re.search(raw):
            survives.append(raw[:120])

    if survives:
        if reb:
            out["verdict"] = "ok-rebuttal"; out["reason"] = f"r82-rebuttal: {reb}"; return out
        out["verdict"] = "fail-recovery-path-survives-claim-false"
        out["reason"] = ("a named in-protocol recovery entrypoint is not falsified (no FAILS/reverts/"
                         "unreachable token) - the 'permanent' claim is false because V can self-cure")
        out["unfalsified_rows"] = survives[:6]
        return out

    # --- Layer 2: inverse-grep (only if --workspace; degrade gracefully) ---
    registry = None
    if workspace:
        reg = workspace / ".auditooor" / "r82_recovery_modules.json"
        if reg.is_file():
            try:
                registry = json.loads(reg.read_text())
            except json.JSONDecodeError:
                registry = None
    if workspace:
        grep_hits = _recovery_grep(workspace)
        unaccounted = [h for h in grep_hits if not _hit_accounted_for(h, cited)]
        # excluded-family rows let the author drop whole families
        if "excluded" not in section.lower() and len(unaccounted) > max(2, len(cited)):
            out["verdict"] = "fail-recovery-path-not-enumerated"
            out["reason"] = (f"inverse-grep found {len(unaccounted)} V-callable recovery call sites not "
                             f"in the table and not excluded: (the author may have missed a recovery path)")
            out["unenumerated_sites"] = unaccounted[:12]
            return out
        out["grep_recovery_sites"] = len(grep_hits)
        out["unaccounted_after_grep"] = len(unaccounted)
    else:
        out["note"] = "no --workspace: Layer-2 inverse-grep skipped (Layer-1 trusted)"

    # --- Layer 3: strict PoC assertion ---
    scope_mode = ""
    sm = re.search(r"scope\s*mode\s*:?\s*(source-only|executed|mixed)", section, re.I)
    if sm:
        scope_mode = sm.group(1).lower()
    if strict:
        for c in cited:
            if workspace:
                base = c.rsplit(":", 1)[0]
                if not any((r / Path(base).name).exists() or list(r.rglob(Path(base).name))
                           for r in _candidate_source_roots(workspace)):
                    out["verdict"] = "fail-ruling-without-source-citation"
                    out["reason"] = f"cited recovery file:line does not resolve in workspace: {c}"
                    return out
        if scope_mode in ("executed", "mixed") and poc_dir and poc_dir.is_dir():
            poc_text = ""
            for f in poc_dir.rglob("*"):
                if f.is_file() and f.suffix.lstrip(".") in _SRC_EXT:
                    poc_text += f.read_text(encoding="utf-8", errors="replace") + "\n"
            has_recovery_assert = bool(_ASSERT_RE.search(poc_text)) and bool(fail_re.search(poc_text))
            if not has_recovery_assert:
                out["verdict"] = "fail-recovery-not-falsified-in-poc"
                out["reason"] = ("executed/mixed scope but PoC has no assertion that V stays short after "
                                 "driving recovery (need assert + a leaves-V-short/reverts token)")
                return out
        if scope_mode == "source-only":
            out["verdict"] = "pass-claim-narrowed"
            out["reason"] = "source-only scope: recovery falsified by source-trace; claim capped to the proven (non-executed) level"
            out["recovery_rows"] = len(data_rows)
            return out

    out["verdict"] = "pass-recovery-enumeration-complete"
    out["reason"] = f"verdict={vfield or 'all-recovery-paths-falsified'}; every recovery entrypoint falsified or excluded"
    out["recovery_rows"] = len(data_rows)
    return out


def emit_worklist(ws):
    hits = _recovery_grep(ws)
    return {"schema": "auditooor.vault_recovery_surface_worklist.v1", "workspace": str(ws),
            "recovery_surfaces": hits,
            "note": "Phase-1 (Rule 82): for each surface, try to PROVE the victim recovers after the impact. "
                    "Only build the attack PoC if every recovery hypothesis is falsified."}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("draft", nargs="?", type=Path)
    ap.add_argument("--workspace", type=Path)
    ap.add_argument("--poc-dir", type=Path)
    ap.add_argument("--severity", default="auto",
                    type=lambda s: s if s == "auto" else s.upper())
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--emit-recovery-worklist", type=Path)
    args = ap.parse_args(argv)

    if args.emit_recovery_worklist:
        ws = args.emit_recovery_worklist.expanduser().resolve()
        out = emit_worklist(ws)
        print(json.dumps(out, indent=2) if args.json else
              f"[R82 worklist] {len(out['recovery_surfaces'])} candidate V-recovery surfaces in {ws.name}")
        return 0

    if not args.draft or not args.draft.is_file():
        print(f"[R82] no such draft: {args.draft}"); return 2
    ws = args.workspace.expanduser().resolve() if args.workspace else None
    pd = args.poc_dir.expanduser().resolve() if args.poc_dir else None
    out = check(args.draft.expanduser().resolve(), ws, pd, args.severity, args.strict)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"[R82-IMPACT-RECOVERY-FALSIFICATION] verdict={out['verdict']} | {out.get('reason','')}")
    is_fail = out["verdict"].startswith("fail")
    return 1 if (is_fail and args.strict) else 0


if __name__ == "__main__":
    raise SystemExit(main())
