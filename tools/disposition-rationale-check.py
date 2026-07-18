#!/usr/bin/env python3
"""disposition-rationale-check.py - every KILLED / OOS-REJECTED finding must carry
a machine-recorded WHY.

Motivation (Strata 2026-07-07): a finding can be moved to `submissions/_killed/`
or `submissions/_oos_rejected/` with NO citable rationale on disk - the reason
lives only in an agent's memory / prose. When the operator later asks "why wasn't
this filed?", there is nothing to cite, and a stale/dupe/impossible disposition
cannot be audited. The `_oos_rejected/` path already had the convention
(`_OOS_REJECTION.json` with verdict + rule + proof); this gate makes it MANDATORY
for BOTH disposition dirs so every kill is self-documenting.

A disposed finding dir (a subdirectory of _killed/ or _oos_rejected/ that contains
a finding `*.md`) is COMPLIANT when it carries a rationale artifact:
  - _killed/       -> `_KILL_RATIONALE.json`   (or any `_KILL*.json`)
  - _oos_rejected/ -> `_OOS_REJECTION.json`     (or any `_OOS*REJECT*.json`)
and that artifact is a JSON object with the REQUIRED fields:
  - `verdict` : non-empty (e.g. "INVALID (stale target)", "OUT-OF-SCOPE (...)")
  - `rule`    : the rule/policy invoked (dedup / stale-pin / ONE_ASSET / scope ...)
  - `proof`   : a concrete, checkable justification (ideally citing a file:line,
                a prior-audit id, or a source-existence fact) - NOT empty prose.

ADVISORY-FIRST + NEVER-RETRO-RED: WARN (warn-disposition-missing-rationale) by
default; HARD FAIL (fail-disposition-missing-rationale) only under
AUDITOOOR_DISPOSITION_RATIONALE_STRICT (or AUDITOOOR_L37_STRICT). A dir with no
finding .md (bare artifacts) is ignored. `disposition-rationale-rebuttal` marker
inside the finding .md clears that one entry (honest walk-back).
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

_REQUIRED_FIELDS = ("verdict", "rule", "proof")
_DISPO = {
    "_killed": ("_KILL_RATIONALE.json", ("_kill", "kill_rationale", "_killed")),
    "_oos_rejected": ("_OOS_REJECTION.json", ("_oos", "oos_reject", "rejection")),
}
_REBUTTAL = "disposition-rationale-rebuttal"

# ---- E6: disposition SOUNDNESS (deeper than #146's field-non-empty) ---------
# When a NEGATIVE disposition is killed on a GUARD or PRECONDITION basis, the
# proof must cite a concrete file:line at the consumer/guard/override site - a
# bare "unreachable in practice" is unfalsifiable. Advisory-first, NO-AUTO-CREDIT
# (emitted rows carry verdict="needs-fuzz"), dedicated STRICT env, rebuttal clears.
_E6_REBUTTAL = "disposition-soundness-rebuttal"
_ONLYX_RE = re.compile(r"\bonly[A-Z][A-Za-z0-9_]+")
_FILE_LINE_RE = re.compile(
    r"[\w./-]+\.(?:sol|rs|go|vy|move|cairo|huff|fe|ts|js|py)\s*:\s*\d+")
_GUARD_TOKENS = ("gated", "onlyowner", "only owner", "only-owner", "trusted_relayer",
                 "trusted relayer", "modifier", "access control", "access-control",
                 "permissioned", "whitelist", "role-gated", "only-role")
_PRECOND_TOKENS = ("requires", "require(", "only-if", "only if", "unreachable",
                   "one_asset", "precondition", "not reachable", "cannot reach",
                   "never reached", "impossible in practice", "unreachable in practice")
# FP-guard: a DEDUP / prior-art / disclosure kill is validly proven by an id, not a
# code file:line - do NOT demand a guard-site citation from those.
_DEDUP_TOKENS = ("duplicate", "dedup", "disclosed", "disclosure", "prior audit",
                 "prior-audit", "known issue", "known-issue", "already reported",
                 "already-reported")


def _signal_kind(verdict: str, rule: str) -> str | None:
    hay = f"{verdict}\n{rule}"
    low = hay.lower()
    if _ONLYX_RE.search(hay) or any(t in low for t in _GUARD_TOKENS):
        return "guard-kill"
    if any(t in low for t in _PRECOND_TOKENS):
        return "precondition-dismissal"
    return None


def _is_dedup_basis(verdict: str, rule: str) -> bool:
    low = f"{verdict}\n{rule}".lower()
    return any(t in low for t in _DEDUP_TOKENS)


def _proof_has_file_line(proof: str) -> bool:
    return bool(_FILE_LINE_RE.search(proof or ""))


def _e6_strict() -> bool:
    for var in ("AUDITOOOR_DISPOSITION_SOUNDNESS_STRICT", "AUDITOOOR_L37_STRICT"):
        if os.environ.get(var, "").strip().lower() not in ("", "0", "false", "no"):
            return True
    return False


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


def _valid_rationale(obj) -> tuple[bool, str]:
    if not isinstance(obj, dict):
        return False, "rationale artifact is not a JSON object"
    missing = [f for f in _REQUIRED_FIELDS if not str(obj.get(f) or "").strip()]
    if missing:
        return False, f"rationale missing required field(s): {', '.join(missing)}"
    return True, ""


def check(ws: Path) -> dict:
    ws = ws.expanduser().resolve()
    sub = ws / "submissions"
    items: list[dict] = []
    for dispo, (canonical, hints) in _DISPO.items():
        base = sub / dispo
        if not base.is_dir():
            continue
        for entry in sorted(p for p in base.iterdir() if p.is_dir()):
            # only a disposed FINDING dir (carries a finding .md) is in scope
            if not any(entry.glob("*.md")):
                continue
            row = {"dispo": dispo, "entry": entry.name, "expected": canonical}
            if _entry_has_rebuttal(entry):
                row["status"] = "rebutted"
                items.append(row)
                continue
            rf = _rationale_file(entry, hints)
            if rf is None:
                row["status"] = "missing-rationale"
                row["detail"] = f"no {canonical} (or matching rationale JSON) in {dispo}/{entry.name}/"
                items.append(row)
                continue
            ok, why = _valid_rationale(_load_json(rf))
            row["rationale_file"] = rf.name
            row["status"] = "ok" if ok else "incomplete-rationale"
            if not ok:
                row["detail"] = why
            items.append(row)

    bad = [i for i in items if i["status"] in ("missing-rationale", "incomplete-rationale")]
    strict = (os.environ.get("AUDITOOOR_DISPOSITION_RATIONALE_STRICT", "").strip().lower()
              not in ("", "0", "false", "no")) or \
             (os.environ.get("AUDITOOOR_L37_STRICT", "").strip().lower()
              not in ("", "0", "false", "no"))
    if not bad:
        verdict = "pass-disposition-rationale"
    elif strict:
        verdict = "fail-disposition-missing-rationale"
    else:
        verdict = "warn-disposition-missing-rationale"
    return {"workspace": str(ws), "verdict": verdict, "strict": strict,
            "disposed_count": len(items), "noncompliant_count": len(bad),
            "items": items}


def soundness_check(ws: Path) -> dict:
    """E6: on top of #146, NEGATIVE dispositions killed on a guard/precondition
    basis must cite a file:line at the guard site. DEDUP boundary (A1): only
    entries #146 already deems 'ok' are examined - we do NOT re-derive #146's
    missing/incomplete signal, we dedup against it (covered rows are its job)."""
    ws = ws.expanduser().resolve()
    base = check(ws)  # reuse #146 as the covered_by source of truth
    status_by = {(i["dispo"], i["entry"]): i["status"] for i in base["items"]}
    sub = ws / "submissions"
    rows: list[dict] = []
    for dispo, (_canonical, hints) in _DISPO.items():
        bdir = sub / dispo
        if not bdir.is_dir():
            continue
        for entry in sorted(p for p in bdir.iterdir() if p.is_dir()):
            if not any(entry.glob("*.md")):
                continue
            # DEDUP: #146 owns missing/incomplete; E6 only looks past a clean #146.
            if status_by.get((dispo, entry.name)) != "ok":
                continue
            if _entry_has_e6_rebuttal(entry):
                continue
            rf = _rationale_file(entry, hints)
            obj = _load_json(rf) if rf else None
            if not isinstance(obj, dict):
                continue
            verdict = str(obj.get("verdict") or "")
            rule = str(obj.get("rule") or "")
            proof = str(obj.get("proof") or "")
            kind = _signal_kind(verdict, rule)
            if kind is None:
                continue  # not a guard/precondition kill -> out of E6 scope
            if _is_dedup_basis(verdict, rule):
                continue  # FP-guard: dedup/prior-art kill, id-proof is valid
            if _proof_has_file_line(proof):
                continue  # sound: guard-site file:line present
            rows.append({
                "dispo": dispo, "entry": entry.name, "signal": kind,
                "verdict": "needs-fuzz",  # NO-AUTO-CREDIT
                "rationale_file": rf.name if rf else None,
                "covered_by_146": False,  # net-new; #146 passed this entry
                "detail": (f"{kind} disposition proof lacks a file:line at the "
                           f"guard/consumer site (unfalsifiable)"),
            })
    strict = _e6_strict()
    if not rows:
        verdict = "pass-disposition-soundness"
    elif strict:
        verdict = "fail-disposition-unsound"
    else:
        verdict = "warn-disposition-unsound"
    return {"workspace": str(ws), "verdict": verdict, "strict": strict,
            "examined_ok_count": sum(1 for v in status_by.values() if v == "ok"),
            "unsound_count": len(rows), "rows": rows}


def _entry_has_e6_rebuttal(entry: Path) -> bool:
    for md in entry.glob("*.md"):
        try:
            if _E6_REBUTTAL in md.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


# ---- E7: disposition PROPERTY-ALIGNMENT (claimed-vs-refuted soundness) -------
# Deeper than #146 (fields non-empty) and E6 (guard-site file:line): for a
# NEGATIVE FALSIFICATION/mechanism kill on a severity-eligible finding, the
# property the kill REFUTES must be the SAME property the finding CLAIMS. A kill
# that soundly disproves property X while the finding claims a distinct property Y
# does NOT refute the finding - the nuva swapout mis-kill (prior falsification
# refuted "processPendingSwapOuts is capped at MaxSwapOutBatchSize=100 (bounded)"
# while the real bug is "paused entries BYPASS the cap => unbounded permanent
# chain-halt", a distinct property). Advisory-first, NO-AUTO-CREDIT (emitted rows
# carry verdict="needs-review"); GRADUATED to the L37 umbrella 2026-07-10
# (fleet-validated, real-fleet-FP-0) so the global AUDITOOOR_L37_STRICT now enforces
# alongside the two dedicated envs, rebuttal marker clears.
_E7_REBUTTAL = "disposition-property-alignment-rebuttal"

# Impact CLASSES (S2). Disjoint families => the kill disproves a different family
# than the finding claims.
_CLASS_TOKENS = {
    "DOS": ("dos", "denial of service", "denial-of-service", "freeze", "freezing",
            "frozen", "halt", "unbounded gas", "unbounded", "stall", "iteration-cost",
            "iteration cost", "liveness", "brick", "bricked", "griefing-dos",
            "griefing", "block-production", "chain-halt", "chain halt", "out-of-gas",
            "out of gas", "gas exhaustion", "non-draining"),
    "THEFT": ("theft", "drain", "drained", "overpay", "over-pay", "over pay",
              "overpayment", "insolvency", "insolvent", "steal", "stolen", "mint",
              "inflate", "inflation", "loss of funds", "loss-of-funds", "fund loss",
              "over-withdraw", "over-withdrawal", "double-spend", "double spend",
              "siphon"),
    "DIVERGENCE": ("chain-split", "chain split", "apphash", "app-hash",
                   "nondeterminism", "non-determinism", "nondeterministic", "fork",
                   "consensus divergence", "state divergence", "diverge", "divergent"),
}
# Subject CONCEPTS (S1/S3): a mismatch on the SAME subject with opposite polarity.
_SUBJECT_CONCEPTS = {
    "cap": ("cap", "capped", "uncapped", "batchsize", "batch size", "batch-size",
            "maxswapoutbatchsize", "maxbatch", "batch"),
    "limit": ("limit", "limited", "bound", "bounded", "unbounded", "upper bound",
              "upper-bound", "no cap", "no upper bound"),
    "guard": ("guard", "gated", "modifier", "onlyowner", "only-owner",
              "access control", "access-control", "permission", "permissioned",
              "require(", "precondition", "whitelist", "role-gated"),
    "isolation": ("isolation", "isolated", "error isolation", "error-isolation",
                  "per-vault", "per vault"),
    "reserve": ("reserve", "reserve check", "reserve-check", "collateral check"),
    "queue": ("queue", "pendingswapoutqueue", "walkdue", "walk", "iteration",
              "iterate"),
    "nav": ("nav", "phantom-nav", "phantom nav", "phantomnav", "splitvaluatednavout",
            "phantom", "valuation"),
    "allowance": ("allowance", "allowance-scale", "allowance scale", "approve"),
    "divergence": ("divergence", "diverge", "apphash", "nondeterminism", "fork",
                   "persist", "persisted", "persistence"),
}
# Premise/guard concepts the kill can lean on as SOUND (S1 anchor).
_PREMISE_CONCEPT_IDS = {"cap", "limit", "guard", "isolation", "reserve"}
# Bypass/negation markers in the FINDING body that defeat a premise (S1 anchor).
_BYPASS_TOKENS = ("bypass", "bypasses", "bypassed", "never reached", "not reached",
                  "skips the cap", "skip the cap", "skips the check", "exempt",
                  "exempts", "exempted", "does not apply", "doesn't apply",
                  "no upper bound", "no cap", "uncapped", "unbounded despite",
                  "circumvent", "circumvents", "sidestep", "sidesteps",
                  "before the cap check", "cap check never reached",
                  "cap check is never reached", "no upper bound from",
                  "defeats the cap", "escapes the cap", "skip the check")
# --- S1 premise CO-LOCATION model (over-flag fix) --------------------------
# The old S1 fired whenever the kill's premise CONCEPT bucket (cap/limit/...) was
# shared with the finding SUBJECT and the finding carried ANY bypass token. That
# cannot tell a MIS-KILL (kill leans on the SAME bound the finding's bypass
# clause targets -> SHOULD flag) from a legit SUPER-PROPERTY kill (kill
# introduces a strictly-OUTER bound the finding never names -> must NOT flag).
# The co-location model requires the kill's load-bearing premise noun to be the
# SAME specific noun the finding's bypass clause targets, and SUPPRESSES S1 when
# the kill asserts a super-ordinate/outer bound (a different premise noun, or an
# outer-scope marker) the finding never names.
#
# POSITIVE bound nouns per premise concept - the thing that IS a bound / guard.
# Negation/consequence forms ("unbounded", "no cap", "uncapped", "no upper
# bound") are DELIBERATELY excluded: they describe the bypass RESULT, not the
# bound being bypassed, so the consequence cannot masquerade as the target noun
# (that conflation is what let an OUTER-bound kill collide with the finding cap).
_PREMISE_POSITIVE_TOKENS = {
    "cap": ("cap", "capped", "batchsize", "batch size", "batch-size",
            "maxswapoutbatchsize", "maxbatch", "batch"),
    "limit": ("limit", "limited", "bound", "bounded", "upper bound", "upper-bound"),
    "guard": ("guard", "gated", "modifier", "onlyowner", "only-owner",
              "access control", "access-control", "permission", "permissioned",
              "precondition", "whitelist", "role-gated"),
    "isolation": ("isolation", "isolated", "error isolation", "error-isolation",
                  "per-vault", "per vault"),
    "reserve": ("reserve", "reserve check", "reserve-check", "collateral check"),
}
# Prefix word-boundary (\b before, none after) so "bound" matches
# "bound"/"bounded"/"boundary" but NOT "unbounded" (the "un" negation prefix),
# while "cap" still unifies "cap"/"capped". Positive tokens end in a word char.
_PREMISE_POSITIVE_RE = {
    cid: re.compile(r"\b(?:" + "|".join(re.escape(t) for t in toks) + r")")
    for cid, toks in _PREMISE_POSITIVE_TOKENS.items()
}
# Chars each side of a bypass token within which a positive premise noun is taken
# to be the TARGET of that bypass clause (co-location).
_BYPASS_COLOCATION_WINDOW = 70
# Outer-scope markers: a kill that leans on a strictly-OUTER / super-ordinate
# bound (applying more broadly than the specific bound the finding names, or
# enforced at a different/earlier site such as insertion) is a SUPER-PROPERTY
# kill, not a mis-kill on the finding's own premise. When such a marker is present
# in the kill but the finding never names it, S1 is SUPPRESSED.
_OUTER_BOUND_MARKERS = (
    "paused and active", "paused as well as active", "active and paused",
    "both paused and active", "applies to both", "applying to both",
    "applies to paused and active", "applying to paused and active",
    "regardless of pause", "regardless of paused", "whether or not paused",
    "for all entries", "for every entry", "all entries",
    "at insertion", "on insertion", "at insert", "on insert", "at enqueue",
    "on enqueue", "insertion-time", "insertion time", "enqueue-time",
    "enqueue time", "total queue length", "queue length", "length-bounded at",
    "bounded at insertion", "requirequeuespace", "queue-space", "queue space",
    "cannot accumulate", "at push time", "on push", "admission control",
    "admission-control",
)
# A kill is a FALSIFICATION/mechanism kill (in E7 scope) when it asserts the
# mechanism itself is FALSE / unreachable.
_FALSIFICATION_TOKENS = ("negative", "invalid", "false positive", "false-positive",
                         "structurally unreachable", "not reachable", "never reached",
                         "no fresh", "does not reproduce", "doesn't reproduce",
                         "refuted", "refute", "impossible", "cannot reach",
                         "unreachable", "disproved", "disproven", "no such")
# A kill that CONCEDES the mechanism (scope/OOS/by-design/USD-floor) is NOT
# refuting a property, so it cannot mis-refute one -> out of E7 scope.
_SCOPE_CONCESSION_TOKENS = ("out-of-scope", "out of scope", "oos", "mechanism real",
                            "mechanism is real", "by-design", "by design",
                            "privileged-only", "privileged only", "privileged key",
                            "usd floor", "usd-floor", "below the usd",
                            "under the usd floor", "min usd", "one_asset",
                            "acknowledged design")
_STOPWORDS = frozenset((
    "the", "and", "for", "with", "that", "this", "from", "have", "has", "not",
    "are", "was", "were", "will", "would", "could", "should", "which", "when",
    "where", "what", "into", "over", "under", "only", "also", "been", "being",
    "does", "done", "must", "then", "than", "such", "some", "more", "most",
    "less", "very", "each", "both", "same", "other", "there", "their", "them",
    "they", "because", "while", "after", "before", "cannot", "finding", "proof",
    "rule", "verdict", "impact", "severity", "summary", "mechanism", "reached",
    "reach", "entries", "entry", "block", "still", "about", "these", "those",
))
_SEV_ELIGIBLE = ("medium", "high", "critical")
# Severity/Impact label lines tolerate markdown decoration so real finding forms
# `**Severity:**` (bold) and `- Impact(s):` (list) are NOT silently skipped: an
# optional leading bullet ([-*+] + space) then optional bold/italic markers
# ([*_]{0,2}) before the label, and optional bold markers after the colon.
_SEV_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*+]\s+)?[*_]{0,2}\s*severity\s*:\s*[*_]{0,2}\s*([A-Za-z]+)")
_IMPACT_ELIG_RE = re.compile(
    r"(?im)^\s*(?:[-*+]\s+)?[*_]{0,2}\s*impact\(s\)\s*:\s*[*_]{0,2}\s*(\S.*)$")


def _prop_align_strict() -> bool:
    # R5 E7 GRADUATED to the L37 umbrella (fleet-validated, real-fleet-FP-0): the global
    # AUDITOOOR_L37_STRICT now enforces alongside the two dedicated envs, so `make
    # audit-complete STRICT=1` hard-fails a mismatched-hypothesis mis-kill (a NEGATIVE
    # kill that refutes property X while a severity-eligible finding at the same site
    # claims a distinct property Y). Mirrors check_state_coupling's umbrella policy.
    for var in ("AUDITOOOR_DISPOSITION_PROPERTY_ALIGN_STRICT",
                "AUDITOOOR_KILL_ANCHOR_SOUNDNESS",
                "AUDITOOOR_L37_STRICT"):
        if os.environ.get(var, "").strip().lower() not in ("", "0", "false", "no"):
            return True
    return False


def _is_falsification_basis(verdict: str, rule: str, proof: str) -> bool:
    low = f"{verdict}\n{rule}\n{proof}".lower()
    return any(t in low for t in _FALSIFICATION_TOKENS)


def _is_scope_concession(verdict: str, proof: str) -> bool:
    low = f"{verdict}\n{proof}".lower()
    return any(t in low for t in _SCOPE_CONCESSION_TOKENS)


# Class matching is WORD-BOUNDARY aware (unlike subject concepts, which stay
# substring so "cap" unifies with "capped"): otherwise the DOS liveness phrase
# "non-draining" would trip THEFT's "drain" and pollute the impact class.
_CLASS_RE = {cid: re.compile(r"\b(?:" + "|".join(re.escape(t) for t in toks) + r")\b")
             for cid, toks in _CLASS_TOKENS.items()}


def _impact_classes(text_low: str) -> set:
    return {cid for cid, rx in _CLASS_RE.items() if rx.search(text_low)}


def _subject_concepts(text_low: str) -> set:
    return {cid for cid, toks in _SUBJECT_CONCEPTS.items()
            if any(t in text_low for t in toks)}


def _norm_tokens(text: str) -> set:
    return {t for t in re.findall(r"[a-z0-9_]+", (text or "").lower())
            if len(t) >= 5 and t not in _STOPWORDS}


def _first_file_line(text: str) -> str:
    m = _FILE_LINE_RE.search(text or "")
    return m.group(0) if m else ""


def _finding_props(md_text: str) -> dict:
    low = md_text.lower()
    title = ""
    m = re.search(r"(?m)^\s*#\s+(.+)$", md_text)
    if m:
        title = m.group(1)
    impact_line = ""
    mi = re.search(r"(?im)^\s*impact\(s\)\s*:\s*(.+)$", md_text)
    if mi:
        impact_line = mi.group(1)
    attack = ""
    ma = re.search(r"(?im)^\s*attack_class\s*:\s*(.+)$", md_text)
    if ma:
        attack = ma.group(1)
    summ = ""
    ms = re.search(r"(?is)##\s*Summary\s*(.+?)(?:\n##|\Z)", md_text)
    if ms:
        summ = re.split(r"(?<=[.!?])\s", ms.group(1).strip(), maxsplit=1)[0]
    leads = " ".join(re.findall(r"(?i)(?:leads to|results in|causes)\s+[^.\n]+",
                                md_text))
    impact_text = " ".join([title, impact_line, attack, summ, leads]).lower()
    subject_text = " ".join([title, summ, impact_line]).lower()
    return {
        "classes": _impact_classes(impact_text),
        "concepts": _subject_concepts(subject_text),
        "norm": _norm_tokens(subject_text),
        "body_low": low,
        "impact_line": (impact_line.strip() or title.strip())[:120],
    }


def _kill_props(kill_text: str) -> dict:
    low = kill_text.lower()
    concepts = _subject_concepts(low)
    return {
        "classes": _impact_classes(low),
        "concepts": concepts,
        "premise_concepts": concepts & _PREMISE_CONCEPT_IDS,
        "norm": _norm_tokens(low),
    }


def _bypass_targeted_premise_concepts(body_low: str) -> set:
    """Premise concepts whose POSITIVE bound noun is co-located (within
    _BYPASS_COLOCATION_WINDOW chars) with a bypass token in the finding body -
    i.e. the specific bound the finding's bypass clause TARGETS. Consequence/
    negation forms ('unbounded', 'no cap') are not positive nouns, so the bypass
    RESULT does not masquerade as the bypassed bound."""
    spans: list[tuple[int, int]] = []
    for bt in _BYPASS_TOKENS:
        start = 0
        while True:
            i = body_low.find(bt, start)
            if i < 0:
                break
            spans.append((i - _BYPASS_COLOCATION_WINDOW,
                          i + len(bt) + _BYPASS_COLOCATION_WINDOW))
            start = i + len(bt)
    if not spans:
        return set()
    targeted: set = set()
    for cid, rx in _PREMISE_POSITIVE_RE.items():
        for m in rx.finditer(body_low):
            j = m.start()
            if any(s <= j <= e for (s, e) in spans):
                targeted.add(cid)
                break
    return targeted


def _kill_introduces_outer_bound(kill_low: str, finding_body_low: str) -> bool:
    """True when the kill carries an outer-scope marker (a strictly-OUTER /
    super-ordinate bound: applies to paused AND active, enforced at insertion,
    total-queue-length, ...) that the finding never names - the hallmark of a
    SUPER-PROPERTY kill rather than a mis-kill on the finding's own premise."""
    return any(mk in kill_low and mk not in finding_body_low
               for mk in _OUTER_BOUND_MARKERS)


def _evaluate_alignment(md_text: str, kill_text: str) -> tuple:
    """Return (emit, fired_signals, finding_props, kill_props). Fire when
    S1 (premise-bypass on a SHARED subject) OR (S2 impact-class-disjoint AND
    S3 subject-disjoint) - keeping a lone class-difference from over-firing."""
    fp = _finding_props(md_text)
    kp = _kill_props(kill_text)
    fired: list[str] = []
    # S1 PREMISE-BYPASS (co-location model): fire only when the kill's load-bearing
    # premise noun is the SAME specific noun the finding's bypass clause TARGETS,
    # i.e. (a) the finding co-locates a bypass token with a positive premise noun,
    # (b) the kill invokes THAT premise concept, and (c) the kill does not introduce
    # a strictly-OUTER bound the finding never names. This distinguishes a mis-kill
    # (leans on the finding's own bypassed bound) from a legit super-property kill
    # (introduces an outer bound the finding never names) - both used to emit S1.
    bypass_targeted = _bypass_targeted_premise_concepts(fp["body_low"])
    shared_premise = kp["premise_concepts"] & bypass_targeted
    kill_outer_bound = _kill_introduces_outer_bound(kill_text.lower(), fp["body_low"])
    if shared_premise and not kill_outer_bound:
        fired.append("S1")
    # S2 IMPACT-CLASS-DISJOINT: kill disproves a family disjoint from the claim.
    if kp["classes"] and fp["classes"] and not (kp["classes"] & fp["classes"]):
        fired.append("S2")
    # S3 SUBJECT-DISJOINT: kill's defended nouns and the finding's attacked nouns
    # have ~zero overlap (len>=5, stopword-filtered to suppress generic noise).
    overlap = kp["norm"] & fp["norm"]
    if kp["norm"] and fp["norm"] and not overlap:
        fired.append("S3")
    emit = ("S1" in fired) or ("S2" in fired and "S3" in fired)
    return emit, fired, fp, kp


def _prop_summary(props: dict) -> str:
    cls = "/".join(sorted(props["classes"])) or "?"
    subj = ",".join(sorted(props["concepts"])[:4]) or "?"
    return f"class={cls} subject~={subj}"


def _entry_has_property_align_rebuttal(entry: Path) -> bool:
    for md in entry.glob("*.md"):
        try:
            if _E7_REBUTTAL in md.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def _severity_eligible(md_text: str) -> bool:
    m = _SEV_LINE_RE.search(md_text)
    if m:
        return m.group(1).strip().lower() in _SEV_ELIGIBLE
    mi = _IMPACT_ELIG_RE.search(md_text)
    return bool(mi and mi.group(1).strip())


def _iter_negative_sidecars(ws: Path):
    scdir = ws / ".auditooor" / "hunt_findings_sidecars"
    if not scdir.is_dir():
        return
    for p in sorted(scdir.glob("*.json")):
        d = _load_json(p)
        if not isinstance(d, dict):
            continue
        inner = d.get("result")
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except ValueError:
                inner = None
        cf = fa = att = ""
        if isinstance(inner, dict):
            cf = str(inner.get("candidate_finding") or "")
            fa = str(inner.get("falsification_attempt") or "")
            att = str(inner.get("applies_to_target") or "")
        att_top = str(d.get("applies_to_target") or "")
        v_top = str(d.get("verdict") or "").strip().lower()
        reason = str(d.get("reason") or "")
        neg = (att.strip().lower() == "no" or att_top.strip().lower() == "no"
               or v_top in ("cleared", "negative", "killed"))
        refuted = fa or reason
        if not (neg and refuted):
            continue
        yield {"path": p, "anchor": d.get("function_anchor") or {},
               "candidate": cf, "refuted": refuted}


def _iter_live_findings(ws: Path):
    """One representative md per FILED/LIVE finding directory under paste_ready
    (prefer the md whose stem == dir name, else the largest) to avoid fanning a
    single finding out across its FILING.md / draft copies."""
    pr = ws / "submissions" / "paste_ready"
    if not pr.is_dir():
        return
    by_dir: dict[Path, Path] = {}
    for md in sorted(pr.rglob("*.md")):
        parts = set(md.parts)
        if "_killed" in parts or "_oos_rejected" in parts:
            continue
        d = md.parent
        cur = by_dir.get(d)
        if cur is None:
            by_dir[d] = md
            continue
        # prefer stem==dirname; else the larger file (primary submission body)
        if md.stem == d.name and cur.stem != d.name:
            by_dir[d] = md
        elif cur.stem != d.name:
            try:
                if md.stat().st_size > cur.stat().st_size:
                    by_dir[d] = md
            except OSError:
                pass
    for d, md in sorted(by_dir.items()):
        try:
            yield md, md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue


def _sidecar_rows(ws: Path) -> list[dict]:
    """Anchor-reproduction EXTENSION (default-off, unwired): cross-join a NEGATIVE
    hunt sidecar's falsification_attempt against a LIVE/FILED finding at the SAME
    concrete anchor (the sidecar fn must appear in the finding's TITLE - its
    declared defect site - AND the file basename must appear in the body) that
    claims a bypass of the SAME premise the sidecar leaned on (S1 only - the
    precise premise-bypass signal; S2/S3 alone are too noisy on the full-md
    cross-join). One row per (finding-dir, fn, basename)."""
    rows: list[dict] = []
    seen: set = set()
    live = list(_iter_live_findings(ws))
    if not live:
        return rows
    for sc in _iter_negative_sidecars(ws):
        anchor = sc["anchor"] if isinstance(sc["anchor"], dict) else {}
        fn = str(anchor.get("fn") or anchor.get("function") or "").strip()
        fpath = str(anchor.get("file") or "")
        base = os.path.basename(fpath) if fpath else ""
        if not (fn and base):
            continue  # need a concrete (function, file) anchor for a tight join
        if _is_scope_concession("", sc["refuted"]) or _is_dedup_basis("", sc["refuted"]):
            continue
        fn_l, base_l = fn.lower(), base.lower()
        for md_path, md_text in live:
            low = md_text.lower()
            mt = re.search(r"(?m)^\s*#\s+(.+)$", md_text)
            title_l = (mt.group(1).lower() if mt else "")
            # tight anchor: the sidecar fn must be the finding's DECLARED defect
            # site (in the title), and the file basename must appear in the body.
            if fn_l not in title_l or base_l not in low:
                continue
            if _entry_has_property_align_rebuttal(md_path.parent):
                continue
            if not _severity_eligible(md_text):
                continue
            key = (md_path.parent.name, fn_l, base_l)
            if key in seen:
                continue
            _emit, fired, fp, kp = _evaluate_alignment(md_text, sc["refuted"])
            if "S1" not in fired:  # precise premise-bypass only for the cross-join
                continue
            seen.add(key)
            cite = _first_file_line(sc["refuted"]) or _first_file_line(md_text) or ""
            rows.append({
                "dispo": "sidecar", "sidecar": sc["path"].name,
                "entry": md_path.parent.name,
                "function_anchor": f"{base}::{fn}",
                "signal": "+".join(fired), "verdict": "needs-review",
                "covered_by_146": False,
                "finding_claimed_property": _prop_summary(fp),
                "kill_refuted_property": _prop_summary(kp),
                "detail": (f"negative sidecar {sc['path'].name} refutes "
                           f"{_prop_summary(kp)} but filed finding "
                           f"{md_path.parent.name} claims {_prop_summary(fp)} at "
                           f"the same anchor {base}::{fn} ({cite}) - the "
                           f"falsification does not address the finding's property"),
            })
    return rows


def property_alignment_check(ws: Path, include_sidecars: bool = False) -> dict:
    """E7: claimed-vs-refuted property alignment. DEDUP boundary: only entries
    #146 deems 'ok' are examined (independent of E6). Runs ONLY on FALSIFICATION/
    mechanism kills - dedup/prior-art (distinctness-guard's job) and scope/OOS
    concession kills are skipped. Advisory-first, NO-AUTO-CREDIT."""
    ws = ws.expanduser().resolve()
    base = check(ws)  # reuse #146 as the covered_by source of truth
    status_by = {(i["dispo"], i["entry"]): i["status"] for i in base["items"]}
    sub = ws / "submissions"
    rows: list[dict] = []
    for dispo, (_canonical, hints) in _DISPO.items():
        bdir = sub / dispo
        if not bdir.is_dir():
            continue
        for entry in sorted(p for p in bdir.iterdir() if p.is_dir()):
            mds = list(entry.glob("*.md"))
            if not mds:
                continue
            if status_by.get((dispo, entry.name)) != "ok":
                continue  # #146 owns missing/incomplete; E7 looks past a clean #146
            if _entry_has_property_align_rebuttal(entry):
                continue
            rf = _rationale_file(entry, hints)
            obj = _load_json(rf) if rf else None
            if not isinstance(obj, dict):
                continue
            verdict = str(obj.get("verdict") or "")
            rule = str(obj.get("rule") or "")
            proof = str(obj.get("proof") or "")
            # KILL-BASIS FILTER: dedup/prior-art -> distinctness-guard's job.
            if _is_dedup_basis(verdict, rule):
                continue
            # scope/OOS/by-design concession -> concedes mechanism, cannot mis-refute.
            if _is_scope_concession(verdict, proof):
                continue
            # must be a FALSIFICATION/mechanism kill to have a refuted property.
            if not _is_falsification_basis(verdict, rule, proof):
                continue
            md_text = "\n".join(m.read_text(encoding="utf-8", errors="replace")
                                for m in mds)
            if not _severity_eligible(md_text):
                continue
            kill_text = f"{verdict}\n{rule}\n{proof}"
            emit, fired, fp, kp = _evaluate_alignment(md_text, kill_text)
            if not emit:
                continue
            cite = _first_file_line(proof) or _first_file_line(md_text) or ""
            rows.append({
                "dispo": dispo, "entry": entry.name, "signal": "+".join(fired),
                "verdict": "needs-review",  # NO-AUTO-CREDIT
                "rationale_file": rf.name if rf else None,
                "covered_by_146": False,  # net-new; #146 passed this entry
                "finding_claimed_property": _prop_summary(fp),
                "kill_refuted_property": _prop_summary(kp),
                "detail": (f"kill soundly refutes {_prop_summary(kp)} but finding "
                           f"claims {_prop_summary(fp)} at same site "
                           f"({cite or entry.name}) - kill does not refute the finding"),
            })
    if include_sidecars:
        rows.extend(_sidecar_rows(ws))
    strict = _prop_align_strict()
    if not rows:
        verdict = "pass-disposition-property-align"
    elif strict:
        verdict = "fail-disposition-property-misaligned"
    else:
        verdict = "warn-disposition-property-misaligned"
    return {"workspace": str(ws), "verdict": verdict, "strict": strict,
            "examined_ok_count": sum(1 for v in status_by.values() if v == "ok"),
            "misaligned_count": len(rows), "rows": rows}


def _emit_jsonl(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--soundness", action="store_true",
                    help="run the E6 disposition-soundness sub-check (advisory, off by default)")
    ap.add_argument("--property-align", dest="property_align", action="store_true",
                    help="run the E7 claimed-vs-refuted property-alignment sub-check (advisory, off by default)")
    ap.add_argument("--sidecars", action="store_true",
                    help="E7 only: also cross-join negative hunt sidecars vs live/filed findings")
    ap.add_argument("--emit", type=Path, default=None,
                    help="write the arm's JSONL rows to this path (read-only unless set)")
    a = ap.parse_args(argv)
    if a.property_align:
        r = property_alignment_check(a.workspace, include_sidecars=a.sidecars)
        if a.emit is not None:
            _emit_jsonl(r["rows"], a.emit)
        if a.json:
            print(json.dumps(r, indent=2))
        else:
            print(f"disposition-property-alignment-check: {r['verdict']} "
                  f"({r['misaligned_count']} misaligned / {r['examined_ok_count']} clean-#146 examined)")
            for row in r["rows"]:
                loc = f"{row.get('dispo','sidecar')}/{row.get('entry','')}"
                print(f"  [{row['signal']:8}] {loc}  <-- {row['detail']}")
        return 1 if r["verdict"] == "fail-disposition-property-misaligned" else 0
    if a.soundness:
        r = soundness_check(a.workspace)
        if a.emit is not None:
            _emit_jsonl(r["rows"], a.emit)
        if a.json:
            print(json.dumps(r, indent=2))
        else:
            print(f"disposition-soundness-check: {r['verdict']} "
                  f"({r['unsound_count']} unsound / {r['examined_ok_count']} clean-#146 examined)")
            for row in r["rows"]:
                print(f"  [{row['signal']:22}] {row['dispo']}/{row['entry']}  <-- {row['detail']}")
        return 1 if r["verdict"] == "fail-disposition-unsound" else 0
    r = check(a.workspace)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"disposition-rationale-check: {r['verdict']} "
              f"({r['noncompliant_count']}/{r['disposed_count']} noncompliant)")
        for i in r["items"]:
            flag = "" if i["status"] in ("ok", "rebutted") else "  <-- "
            print(f"  [{i['status']:20}] {i['dispo']}/{i['entry']}{flag}{i.get('detail','')}")
    return 1 if r["verdict"] == "fail-disposition-missing-rationale" else 0


if __name__ == "__main__":
    raise SystemExit(main())
