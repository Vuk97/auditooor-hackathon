#!/usr/bin/env python3
"""disposition-reframe-soundness-check.py - GEN-5A/5B/5C/5D: a KILL / OOS-rejection
that DOWNGRADES a confirmed primitive by REFRAMING its impact must carry the
specific SOUNDNESS PROOF that the reframe holds. If the reframe is asserted
WITHOUT its required proof, the disposition is UNSOUND -> emit a needs-fuzz REOPEN
row for that finding.

GENERAL LOGIC
-------------
A disposed finding (a subdir of submissions/_killed/ or submissions/_oos_rejected/
that carries a finding *.md, mirroring disposition-rationale-check.py discovery)
records its WHY in a rationale artifact (_KILL_RATIONALE.json / _KILL*.json /
_OOS_REJECTION.json / _OOS*REJECT*.json: verdict + rule + proof). This gate reads
the artifact + the finding .md, classifies the KILL REASON, and for each of four
impact-REFRAME downgrades checks that the reframe's REQUIRED soundness proof is
present (in verdict / rule / proof / the md). Missing -> REOPEN (fail-closed).

The four sub-checks (each fires a REOPEN when its reframe is invoked but the
required soundness proof is ABSENT):

  5A griefing / DoS-only / no-double-spend downgrade
     reframe words: griefing | dos-only | denial-of-service | liveness-only |
     no-double-spend | only-a-revert | just-reverts
     REQUIRES ALL of:
       (1) NOT-PERMANENT: a restart / recovery / redeploy path cited (else an
           R82 permanent-freeze = higher severity, not mere griefing);
       (2) rubric-threshold: a SEVERITY.md / SCOPE.md citation that the griefing
           cost / impact is BELOW the Medium+ line (floor / de-minimis / threshold);
       (3) composition: a sentence ENUMERATING the downstream impact incl what the
           primitive composes into.
     Missing any -> reopen (reason=5A-griefing-reframe-unsound).

  5B unreachable-by-single-deployment-constant
     reframe words: unreachable | cannot-reach | constant | immutable-config |
     deploy...constant | hardcoded | only-if...set
     REQUIRES: the gating constant is (a) genuinely IMMUTABLE (not a settable
     storage var / governance param), AND (b) covers ALL in-scope deployments
     (not just the reference one).
     Missing -> reopen (5B-deployment-constant-unsound).

  5C mathematically-impossible-single-step
     reframe words: impossible | cannot-happen | mathematically | single-step |
     single-tx | single-block | atomic
     REQUIRES: an explicit statement that NO multi-step / multi-block / multi-tx /
     cross-fn COMPOSITION reaches it (the sequenced path was considered).
     Missing -> reopen (5C-single-step-unsound).

  5D trusted-actor-only escape-hatch reachability
     reframe words: only-(owner|admin|governance|trusted) | privileged-only |
     access-control | onlyOwner | escape-hatch | trusted-actor
     REQUIRES: (a) the actor set is genuinely TRUSTED per SCOPE (not merely a role
     a lower-priv actor can OBTAIN), AND (b) no escape-hatch / self-grant /
     delegatecall lets a lower-priv actor reach it.
     Missing -> reopen (5D-actor-reachability-unsound).

FP-CONTROL
----------
  * A kill that DOES carry the required soundness proof stays SILENT (no reopen).
  * A kill that is NOT a reframe-downgrade - a genuine DEDUP / prior-art kill, a
    STALE-PIN kill, or an OUT-OF-SCOPE-BY-PATH kill - is out of this gate's scope
    -> SILENT (the reframe-word check is suppressed for those bases).
  * When uncertain whether the proof is present, prefer reopen=true (fail-closed
    toward re-examination is the correct bias for a disposition-soundness gate),
    BUT keep the gate advisory at RUN level (WARN unless strict).

ENFORCEMENT
-----------
Rows are written to <ws>/.auditooor/disposition_reframe_soundness_hypotheses.jsonl
(schema auditooor.disposition_reframe_soundness_hypotheses.v1). Because a reopen is
a disposition-integrity failure, the gate WARN-passes by default
(warn-disposition-reframe-unsound) but HARD-FAILS
(fail-disposition-reframe-unsound) under AUDITOOOR_DISPOSITION_REFRAME_STRICT or
AUDITOOOR_L37_STRICT - mirroring disposition-rationale-check.py exactly. A
`disposition-reframe-rebuttal` marker inside the finding .md clears one entry
(honest walk-back).

DEDUP (distinctness from sibling gates)
---------------------------------------
  * disposition-rationale-check.py Check #146 checks only that a WHY EXISTS
    (verdict/rule/proof non-empty) - NOT the SOUNDNESS of an impact reframe.
  * disposition-rationale-check.py E6 (#146a "e6-disposition-reopen") checks only
    that a guard/precondition kill carries a file:line at the guard site (presence
    of a code citation), NOT whether an impact-downgrade reframe is proven sound.
  * disposition-rationale-check.py E7 (#146b) checks claimed-vs-refuted property
    ALIGNMENT, not the reframe's own soundness elements.
  GEN-5A..5D is the net-new impact-REFRAME-soundness plane: for each of the four
  named impact-downgrade reframes, the reframe's specific soundness burden must be
  discharged. No sibling gate encodes those four burdens.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

SCHEMA = "auditooor.disposition_reframe_soundness_hypotheses.v1"
_REBUTTAL = "disposition-reframe-rebuttal"

# Discovery mirrors disposition-rationale-check.py exactly.
_DISPO = {
    "_killed": ("killed", ("_kill", "kill_rationale", "_killed")),
    "_oos_rejected": ("oos", ("_oos", "oos_reject", "rejection")),
}

# ---- BASIS-SUPPRESSION (FP-control): a NON-reframe kill is out of scope --------
# genuine dedup / prior-art kill (distinctness-guard's job).
_DEDUP_TOKENS = ("duplicate", "dedup", "disclosed", "disclosure", "prior audit",
                 "prior-audit", "known issue", "known-issue", "already reported",
                 "already-reported", "prior-art", "prior art")
# stale-pin kill (code no longer exists at the audited pin).
_STALE_PIN_TOKENS = ("stale target", "stale-pin", "stale pin", "removed code",
                     "cites removed", "no longer exists", "no longer exist",
                     "does not exist at the pin", "not exist at the pin",
                     "removed at the pin", "cites code that no longer",
                     "invalid (stale")
# out-of-scope-by-PATH kill (the file itself is outside the in-scope tree). NOTE:
# a bare "out-of-scope" is NOT enough - an OOS-by-IMPACT-REFRAME (griefing /
# below-floor) is exactly what this gate targets, so only explicit path-exclusion
# phrasing suppresses.
_OOS_BY_PATH_TOKENS = ("out-of-scope by path", "out of scope by path",
                       "oos-by-path", "not in the scope tree",
                       "outside the in-scope tree", "outside the scope tree",
                       "path exclusion", "not an in-scope file",
                       "file is out of scope", "file is out-of-scope",
                       "not in scope path", "excluded path")


def _re_dotted(*words: str) -> re.Pattern:
    """Build a case-insensitive alternation where a literal '.' in a token means
    'any single non-alphanumeric separator or nothing', and '...' (three) means a
    short gap of arbitrary chars. Word tokens are matched with a leading word
    boundary so 'cap' does not swallow 'capital'... (callers pass whole words)."""
    parts = []
    for w in words:
        # '...' -> up to a short gap; single '.' -> optional separator.
        w = re.escape(w)
        w = w.replace(r"\.\.\.", r".{0,24}?")
        w = w.replace(r"\.", r"[\s._/-]?")
        parts.append(w)
    return re.compile(r"(?i)(?:" + "|".join(parts) + r")")


# ---- 5A griefing / DoS-only downgrade ----------------------------------------
_5A_TRIGGER = _re_dotted("griefing", "dos.only", "denial.of.service",
                         "liveness.only", "no.double.spend", "only.a.revert",
                         "just.reverts", "just.a.revert", "only.reverts",
                         "temporary.dos", "temporary.denial")
_5A_NOT_PERMANENT = _re_dotted(
    "redeploy", "redeployable", "restart", "recover", "recovery", "recoverable",
    "non.permanent", "not.permanent", "not a permanent", "temporary",
    "self.heal", "auto.recover", "resets", "reset next", "next block", "next slot",
    "resolves on", "clears on", "unwinds", "atomically reverts", "no state change")
_5A_RUBRIC_FILE = _re_dotted("severity.md", "scope.md", "rubric")
_5A_THRESHOLD = _re_dotted("floor", "below", "under the", "de.minimis", "dust",
                           "threshold", "minimum", "min usd", "below the medium",
                           "under medium", "immaterial", "negligible", "$0", "zero",
                           "below.*line")
_5A_COMPOSITION = _re_dotted(
    "compos", "downstream", "leads to", "results in", "chains into",
    "does not compose", "cannot be chained", "not chainable", "no theft",
    "not theft", "only the attacker", "only affects the attacker", "no further",
    "no fund loss", "no funds lost", "self.donated", "self.inflicted",
    "attacker.only", "non.attacker loss", "no user funds", "no downstream")

# ---- 5B unreachable-by-single-deployment-constant ----------------------------
_5B_TRIGGER = _re_dotted("unreachable", "cannot.reach", "can not reach",
                         "constant", "immutable.config", "deploy...constant",
                         "hardcoded", "hard.coded", "only.if...set",
                         "gated by...constant", "compile.time constant")
_5B_IMMUTABLE = _re_dotted("immutable", "constant", "hardcoded", "hard.coded",
                           "compile.time", "not settable", "cannot be changed",
                           "cannot be set", "no setter", "final", "read.only",
                           "not a governance param", "not governance.settable",
                           "non.settable")
_5B_ALL_DEPLOYMENTS = _re_dotted(
    "all deployments", "every deployment", "all instances", "every instance",
    "across all", "all in.scope deployments", "not just the reference",
    "not only the reference", "for all networks", "every chain", "all chains",
    "all configurations", "all configs", "each deployment")

# ---- 5C mathematically-impossible-single-step --------------------------------
# The reframe is a claim of IMPOSSIBILITY *scoped to a single step* - so it fires
# only when an impossibility assertion AND a single-step scope BOTH appear. A bare
# "reverts atomically" (single-step word, no impossibility claim) is NOT a 5C
# reframe - it is a griefing/DoS argument (5A), so the compound trigger avoids
# that over-fire while still catching "mathematically impossible in a single tx".
_5C_IMPOSSIBILITY = _re_dotted("impossible", "cannot.happen", "can not happen",
                               "cannot occur", "mathematically", "infeasible",
                               "not possible", "no way to", "cannot be reached in")
_5C_SINGLESTEP = _re_dotted("single.step", "single.tx", "single.transaction",
                            "single.block", "atomic", "in one step",
                            "in a single", "one transaction", "one block",
                            "one.tx", "per.tx", "per.block", "within a block",
                            "within one")


def _5c_trigger(hay: str):
    """5C fires only on IMPOSSIBILITY + SINGLE-STEP co-occurrence. Returns the
    impossibility match (for the excerpt) or None."""
    if _5C_IMPOSSIBILITY.search(hay) and _5C_SINGLESTEP.search(hay):
        return _5C_IMPOSSIBILITY.search(hay)
    return None
_5C_COMPOSITION_CONSIDERED = _re_dotted(
    "multi.step", "multi.block", "multi.tx", "multi.transaction", "cross.fn",
    "cross.function", "sequenced", "sequence of", "composed path", "composition",
    "over multiple blocks", "over multiple tx", "across transactions",
    "across blocks", "multiple calls", "multiple transactions", "chained calls",
    "no sequence of", "no multi.step", "even across", "even with multiple",
    "considered the sequenced", "considered multi")

# ---- 5D trusted-actor-only escape-hatch reachability -------------------------
_5D_TRIGGER = _re_dotted("only.owner", "only.admin", "only.governance",
                         "only.trusted", "only the owner", "only the admin",
                         "only the governance", "only a trusted", "privileged.only",
                         "access.control", "onlyowner", "onlyadmin",
                         "escape.hatch", "trusted.actor", "operator.only",
                         "owner.only", "admin.only", "governance.only",
                         "permissioned.only")
_5D_ACTOR_TRUSTED = _re_dotted(
    "trusted per scope", "trusted per the scope", "scope.md", "trust model",
    "trust assumption", "trusted role per", "assumed trusted", "in the trust",
    "trusted set", "genuinely trusted", "trusted by design", "trusted actor per",
    "per the trust model", "trusted-actor exemption", "trusted role")
_5D_NO_ESCAPE = _re_dotted(
    "no escape.hatch", "no self.grant", "cannot self.grant", "no delegatecall",
    "no delegate.call", "cannot obtain the role", "cannot acquire the role",
    "cannot grant", "no role.grant path", "no privilege escalation",
    "no priv.escalation", "no lower.priv", "no way to obtain", "role cannot be",
    "no self.assign", "no backdoor", "no other path to the role")

# Reframe registry: kind -> (trigger, [(proof-name, proof-re), ...], reason).
_REFRAMES = {
    "5A": (_5A_TRIGGER,
           [("not-permanent", _5A_NOT_PERMANENT),
            ("rubric-threshold", None),   # special: file cite AND threshold word
            ("composition", _5A_COMPOSITION)],
           "5A-griefing-reframe-unsound"),
    "5B": (_5B_TRIGGER,
           [("immutable-constant", _5B_IMMUTABLE),
            ("all-deployments", _5B_ALL_DEPLOYMENTS)],
           "5B-deployment-constant-unsound"),
    "5C": (_5c_trigger,
           [("multi-step-considered", _5C_COMPOSITION_CONSIDERED)],
           "5C-single-step-unsound"),
    "5D": (_5D_TRIGGER,
           [("actor-trusted-per-scope", _5D_ACTOR_TRUSTED),
            ("no-escape-hatch", _5D_NO_ESCAPE)],
           "5D-actor-reachability-unsound"),
}


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _rationale_file(entry: Path, name_hints: tuple[str, ...]) -> Path | None:
    for p in sorted(entry.glob("*.json")):
        low = p.name.lower()
        if any(h in low for h in name_hints):
            return p
    return None


def _entry_has_rebuttal(entry: Path) -> bool:
    for md in entry.glob("*.md"):
        try:
            if _REBUTTAL in md.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def _md_text(entry: Path) -> str:
    chunks = []
    for md in sorted(entry.glob("*.md")):
        try:
            chunks.append(md.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n".join(chunks)


def _is_suppressed_basis(hay: str) -> str | None:
    low = hay.lower()
    if any(t in low for t in _DEDUP_TOKENS):
        return "dedup"
    if any(t in low for t in _STALE_PIN_TOKENS):
        return "stale-pin"
    if any(t in low for t in _OOS_BY_PATH_TOKENS):
        return "oos-by-path"
    return None


def _proof_present(name: str, rx, hay: str) -> bool:
    if name == "rubric-threshold":
        # 5A(2): a rubric FILE citation AND a below-the-line threshold word.
        return bool(_5A_RUBRIC_FILE.search(hay) and _5A_THRESHOLD.search(hay))
    return bool(rx.search(hay))


def _trigger_match(trigger, hay: str):
    """A trigger is either a compiled regex (use .search) or a callable that
    returns a match object / None (5C's compound impossibility+single-step)."""
    if callable(trigger) and not hasattr(trigger, "search"):
        return trigger(hay)
    return trigger.search(hay)


def _excerpt(trigger, hay: str, width: int = 90) -> str:
    m = _trigger_match(trigger, hay)
    if not m:
        return ""
    a = max(0, m.start() - width // 2)
    b = min(len(hay), m.end() + width // 2)
    return re.sub(r"\s+", " ", hay[a:b]).strip()


def check(ws: Path) -> dict:
    ws = ws.expanduser().resolve()
    sub = ws / "submissions"
    rows: list[dict] = []
    examined = 0
    for dispo_dir, (dispo_label, hints) in _DISPO.items():
        base = sub / dispo_dir
        if not base.is_dir():
            continue
        for entry in sorted(p for p in base.iterdir() if p.is_dir()):
            if not any(entry.glob("*.md")):
                continue  # only a disposed FINDING dir is in scope
            examined += 1
            if _entry_has_rebuttal(entry):
                continue
            rf = _rationale_file(entry, hints)
            obj = _load_json(rf) if rf else None
            verdict = rule = proof = ""
            if isinstance(obj, dict):
                verdict = str(obj.get("verdict") or "")
                rule = str(obj.get("rule") or "")
                proof = str(obj.get("proof") or "")
            md = _md_text(entry)
            # Trigger haystack = the disposition WHY (verdict/rule/proof) - the md
            # body is the FINDING's own claim, not the kill's reframe assertion, so
            # a griefing/impossible/constant/trusted word in the finding text must
            # NOT by itself invoke a reframe. Proof haystack = WHY + md (the
            # soundness evidence may live in either).
            why = f"{verdict}\n{rule}\n{proof}"
            proof_hay = f"{why}\n{md}"
            basis = _is_suppressed_basis(why)
            if basis is not None:
                continue  # FP-control: non-reframe kill is out of gate scope
            for kind, (trigger, required, reason) in _REFRAMES.items():
                if not _trigger_match(trigger, why):
                    continue
                missing = [name for (name, rx) in required
                           if not _proof_present(name, rx, proof_hay)]
                if not missing:
                    continue  # reframe carries its soundness proof -> SILENT
                rid = f"{reason}:{dispo_label}:{entry.name}"
                rows.append({
                    "schema": SCHEMA,
                    "id": rid,
                    "finding_dir": str(entry),
                    "disposition": dispo_label,
                    "reframe_kind": kind,
                    "missing_proof": missing,
                    "verdict": verdict[:200],
                    "excerpt": _excerpt(trigger, why),
                    "why": (f"{reason}: reframe invoked but soundness proof "
                            f"absent - missing {', '.join(missing)}"),
                    "reopen": True,
                })
    strict = _strict()
    if not rows:
        v = "pass-disposition-reframe-sound"
    elif strict:
        v = "fail-disposition-reframe-unsound"
    else:
        v = "warn-disposition-reframe-unsound"
    return {"workspace": str(ws), "verdict": v, "strict": strict,
            "examined_count": examined, "reopen_count": len(rows), "rows": rows}


def _strict() -> bool:
    for var in ("AUDITOOOR_DISPOSITION_REFRAME_STRICT", "AUDITOOOR_L37_STRICT"):
        if os.environ.get(var, "").strip().lower() not in ("", "0", "false", "no"):
            return True
    return False


def _emit_jsonl(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GEN-5A/5B/5C/5D disposition-reframe soundness gate")
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--emit", type=Path, default=None,
                    help="write the JSONL rows to this path (default: "
                         "<ws>/.auditooor/disposition_reframe_soundness_hypotheses.jsonl)")
    ap.add_argument("--no-emit", action="store_true",
                    help="do not write the sidecar (read-only)")
    a = ap.parse_args(argv)
    r = check(a.workspace)
    if not a.no_emit:
        emit = a.emit or (a.workspace.expanduser().resolve() / ".auditooor"
                          / "disposition_reframe_soundness_hypotheses.jsonl")
        _emit_jsonl(r["rows"], emit)
        r["sidecar"] = str(emit)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"disposition-reframe-soundness-check: {r['verdict']} "
              f"({r['reopen_count']} reopen / {r['examined_count']} examined)")
        for row in r["rows"]:
            print(f"  [{row['reframe_kind']}] {row['disposition']}/"
                  f"{Path(row['finding_dir']).name}  <-- {row['why']}")
    return 1 if r["verdict"] == "fail-disposition-reframe-unsound" else 0


if __name__ == "__main__":
    raise SystemExit(main())
