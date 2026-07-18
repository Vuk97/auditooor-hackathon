"""Disposition-quality gate: an N-A / cleared / dispositioned verdict is TERMINAL
only when its reason PROVES the impact UNREACHABLE - not when a keyword grep
found zero hits.

THE PROBLEM THIS CLOSES (operator-caught 2026-07-02)
----------------------------------------------------
The 100%-adjudication enforcement (audit-completeness-check.py swept-surface +
rubric-attempt axes, completeness-matrix-build.py mechanism axis) is greenable by
a SHALLOW disposition. `_load_terminal_dispositions` credited any row whose reason
is >= 8 chars; `_load_mechanism_dispositions` credited any row with a `mechanism`
field. So a rubric row can be marked N-A with a reason whose ONLY evidence is a
keyword grep:

    "N/A: grep for Proposal|castVote|VoteOption|Governor|Tally over src returns
     0 hits ... no vote-result to manipulate"

That is NOT a genuine attempt to prove the impact unreachable - it is a shape-
based keyword-absence note, the "killing easier than keeping" false-negative
anti-pattern (a disposition should be as hard as raising a finding). A governance
manipulation impact is NOT proven unreachable by "grep Governor = 0"; the deployed
protocol could reach that impact through a differently-named admin path, a Msg
handler, a param update, etc. Absence-of-a-keyword != absence-of-the-mechanism.

THE BAR (mirrors escalate-first-required-check.py's PROOF-OF-IMPOSSIBILITY forms)
--------------------------------------------------------------------------------
An N-A / cleared / dispositioned reason is admissible as TERMINAL only when it
carries a PROVEN-UNREACHABLE structure, one of:

  (a) CODE-GUARD / STRUCTURAL FACT at file:line making the impact unreachable
      (a require/guard/cap/revert cited with an in-tree `path.ext:NN` anchor); OR
  (b) MECHANISM-LEVEL ABSENCE ARGUMENT - names the mechanism by which the impact
      WOULD occur and argues why the DEPLOYED asset structurally cannot reach it
      (e.g. "no on-chain voting module is wired into any in-scope state-transition
      -> there is no tally to manipulate"). This is an argument about the
      protocol's STRUCTURE, not about a keyword's presence; OR
  (c) a NAMED in-protocol invariant / guard / recovery mechanism that caps it.

REJECTED: a reason whose evidence is ONLY a keyword-grep / "no X found" /
"not present" / "0 hits" with no structural mechanism argument and no file:line
guard. A grep line that is ACCOMPANIED by a genuine mechanism argument (as in
"grep returns 0 ... AND in-scope governance is admin-Msg only, authority-gated,
with NO vote/tally that could be manipulated <file:line>") PASSES on the strength
of the mechanism argument, not the grep.

ADVISORY-FIRST
--------------
This gate fires ONLY under ``AUDITOOOR_DISPOSITION_PROOF_STRICT`` (truthy) - which
the ``make audit-complete STRICT=1`` block exports alongside the other STRICT env
vars. Absent STRICT the classifier still runs (callers may inspect the verdict)
but callers MUST treat every disposition as admissible so behaviour is
byte-identical to the legacy gate. The two loaders enforce exactly this: they call
``reason_is_terminal_quality`` only when ``proof_strict_enabled()`` is True.

Pure stdlib, offline, no workspace name in any decision. This module REUSES the
same admissible-form doctrine as tools/escalate-first-required-check.py's
IMPOSSIBILITY_CITED_RE / PUNT_BLOCKER_RE (it does NOT edit that file).
"""
from __future__ import annotations

import os
import re

# --- a file:line source anchor (path.ext:NN) - the code-guard / structural-fact
# citation. Deliberately requires a dotted extension so a bare "SEVERITY.md:77"
# rubric pointer still counts as an anchor (it cites a real in-tree line). ------
FILE_LINE_RE = re.compile(r"\b[\w./-]+\.\w+:\d+\b")

# --- a code-guard / structural-fact verb: the reason describes an actual guard,
# cap, or state fact (not merely a keyword's absence). --------------------------
CODE_GUARD_RE = re.compile(
    r"\b(?:require|assert|revert(?:s|ed|ing)?|guard(?:s|ed|ing)?|"
    r"cap(?:s|ped|ping)?|clamp(?:s|ed|ing)?|bound(?:s|ed)?|"
    r"only[A-Z]\w+|authority[- ]gated|onlyOwner|onlyRole|whenNotPaused|"
    r"modifier|access[- ]control|nonReentrant|"
    r"reverts? (?:with|on|if)|is (?:reverted|blocked|rejected)|"
    r"insufficient (?:reserves|balance|funds))\b",
    re.IGNORECASE,
)

# --- a MECHANISM-LEVEL absence / structural-unreachability argument. This is the
# (b) form: the reason names the mechanism by which the impact WOULD occur and
# argues the deployed asset cannot STRUCTURALLY reach it. The load-bearing shape
# is "no <mechanism> is WIRED / IMPLEMENTED / REACHABLE ... so there is no
# <impact-object> to <act-on>" - an argument about protocol structure, not about
# a keyword count. ---------------------------------------------------------------
MECHANISM_ARGUMENT_RE = re.compile(
    # "no ... <mechanism-noun> ... (exists|is wired|is implemented|is reachable|
    #  is deployed|in scope)" where the mechanism noun is a real protocol
    # construct, not a bare identifier.
    r"no (?:on[- ]chain |in[- ]scope |deployed )?"
    r"(?:voting|vote|proposal|tally|governance|gas[- ]?(?:meter|refund|metering)|"
    r"module|mechanism|handler|path|circuit|oracle|price[- ]feed|"
    r"state[- ]transition|entry[- ]?point|call[- ]?path|dispatcher|queue|"
    r"mint(?:ing)?|burn(?:ing)?|escrow|bridge|nullifier|refund)"
    r"[- \w]{0,60}"
    r"(?:exists?|is (?:wired|implemented|reachable|deployed|present|in scope)|"
    r"is (?:not )?wired into|does not (?:exist|implement)|not implemented|"
    r"is (?:absent|missing) (?:from|in) (?:scope|the deployed|the module))|"
    # structural "does not implement its own X" / "X is metered by <external>
    # (out of scope)" - a positive statement about WHERE the mechanism lives that
    # places it structurally out of the in-scope reach.
    r"(?:does not|doesn't) implement (?:its own )?"
    r"(?:gas[- ]?meter|refund|voting|tally|proposal)|"
    r"(?:metered|handled|owned) by (?:the )?[\w.\- ]{0,40}"
    r"(?:out[- ]of[- ]scope|out of (?:module )?scope|OOS)|"
    # "so there is no <object> to <manipulate/steal/drain/reach>" - the impact
    # object structurally does not exist to be acted on.
    r"(?:so|therefore|hence)?[- \w,]{0,60}"
    r"no (?:vote[- ]?result|tally|proposal|reward|balance|escrow|value|funds?|"
    r"gas[- ]?(?:refund|price)|share)"
    r"[- \w]{0,40}to (?:manipulate|steal|drain|reach|reclaim|mint|deviate|"
    r"overpay|forge)|"
    # "structurally cannot / is structurally unreachable / no path to <impact>"
    r"structurally (?:cannot|un(?:reachable|able)|impossible)|"
    r"no (?:reachable |in[- ]scope )?(?:mechanism|path|call[- ]?path|handler)"
    r"[- \w]{0,40}(?:to|for) (?:'?(?:theft|freeze|halt|manipulat|drain|mint|"
    r"double[- ]spend|inflation)'?)",
    re.IGNORECASE,
)

# --- a NAMED in-protocol invariant / recovery / cap mechanism (the (c) form). --
NAMED_INVARIANT_RE = re.compile(
    r"in[- ]protocol (?:recovery|refund|rollback|cancel(?:lation)?|dispute|"
    r"invariant|cap|guard)|"
    r"(?:caps?|bounds?|reverses?|refunds?|recovers?|reclaims?|clamps?) "
    r"the (?:loss|impact|funds|amount|value|rate|movement)|"
    r"per[- ](?:issuer|caller|vault|epoch|asset) (?:cap|limit|bound)|"
    r"conservation invariant (?:holds?|is (?:enforced|preserved))|"
    r"self[- ]heals?|drains? to empty|re[- ]enqueued|does not accumulate",
    re.IGNORECASE,
)

# --- GREP-ONLY / ABSENCE-ONLY evidence. The reason leans on a keyword count. If
# this fires AND none of the (a)/(b)/(c) admissible forms co-occur, the
# disposition is grep-only and FAILs strict. -----------------------------------
GREP_ONLY_RE = re.compile(
    r"\bgrep\b|"
    r"returns? \d+ (?:in[- ]scope )?hits?|"
    r"\b\d+ (?:in[- ]scope )?hits?\b|"
    r"no (?:hits?|matches?|occurrences?|references?)|"
    r"(?:keyword|token|string|pattern|symbol) (?:absent|not (?:found|present))|"
    r"not (?:found|present) (?:in|anywhere)|"
    r"(?:zero|0) (?:hits?|matches?|occurrences?)|"
    r"search(?:ed|ing)? for .{0,60}(?:returns?|found|yields?) (?:0|zero|no)",
    re.IGNORECASE,
)

# --- N-A / cleared / dispositioned CLAIM markers. The quality bar ONLY applies to
# a reason that CLAIMS the impact does not apply / is cleared / is refuted (an
# assertion of ABSENCE). A CANDIDATE / covered / mapped disposition points at a
# REAL finding and is NOT a claim of unreachability, so it is exempt (it is not
# "killing" a cell, it is keeping it). ----------------------------------------
NA_CLAIM_RE = re.compile(
    r"\bN[/.-]?A\b|not applicable|does not apply|"
    r"\bcleared\b|\brefuted\b|\bno (?:impact|vuln|finding|path)\b|"
    r"nothing to (?:manipulate|steal|drain|reach)|"
    r"out[- ]of[- ]scope|OOS\b|not (?:reachable|exploitable)",
    re.IGNORECASE,
)
# A disposition that instead POINTS AT a real finding / candidate (keep, not kill)
# is exempt from the unreachability-proof bar.
CANDIDATE_CLAIM_RE = re.compile(
    r"\bCANDIDATE\b|\bcovered\b|\bmapped\b|maps? to (?:this|the|an?) (?:rubric|row|"
    r"finding)|points? to (?:the |an )?existing (?:draft|finding|submission)|"
    r"existing .{0,30}draft|source[- ]grounded path|filed as|reaches this rubric row",
    re.IGNORECASE,
)


def proof_strict_enabled() -> bool:
    """True iff AUDITOOOR_DISPOSITION_PROOF_STRICT is truthy. Absent/""/0/false/no
    => False (advisory-first; byte-identical legacy behaviour when off)."""
    v = os.environ.get("AUDITOOOR_DISPOSITION_PROOF_STRICT", "").strip().lower()
    return v not in ("", "0", "false", "no", "off")


def _split_clauses(text: str) -> list[str]:
    """Split a reason into clauses (sentence-ish / line-ish units) so a proof form
    can be checked for CO-OCCURRENCE with a file:line anchor on the SAME clause -
    the exact discipline escalate-first-required-check.py uses (``_line_hits_cooccur``)
    to stop a file:line elsewhere in the text (the OUT-OF-SCOPE simapp import path,
    a sibling-guard pointer) from being mistaken for a proof anchoring the
    structural claim."""
    parts: list[str] = []
    for line in text.splitlines():
        # split on sentence boundaries too, so a multi-clause line is decomposed.
        for seg in re.split(r"(?<=[.;])\s+", line):
            seg = seg.strip()
            if seg:
                parts.append(seg)
    return parts


def _cooccurs_with_file_line(text: str, rx: re.Pattern[str]) -> bool:
    """True iff at least one clause matches BOTH ``rx`` AND a file:line anchor. This
    is what makes a code-guard / mechanism / invariant claim a PROOF: the structural
    statement and its source citation sit in the SAME clause, not merely somewhere
    in the paragraph."""
    for clause in _split_clauses(text):
        if rx.search(clause) and FILE_LINE_RE.search(clause):
            return True
    return False


def classify_reason(reason: str) -> dict[str, object]:
    """Classify a disposition reason string. Returns a dict:
      {
        "admissible": bool,          # passes the terminal-quality bar
        "verdict": str,              # one of the vocabulary below
        "is_na_claim": bool,         # the reason CLAIMS unreachability / N-A
        "has_code_guard": bool,      # (a) code-guard/structural fact @ file:line
        "has_mechanism_arg": bool,   # (b) mechanism-level absence argument
        "has_named_invariant": bool, # (c) named in-protocol cap/recovery
        "grep_only": bool,           # leans on a keyword grep / absence count
      }

    Verdict vocabulary:
      exempt-not-na-claim          : reason points at a real finding / candidate
                                     (a KEEP, not a KILL) - the bar does not apply.
      pass-code-guard-cited        : (a) structural guard at file:line.
      pass-mechanism-argument      : (b) mechanism-level unreachability argument.
      pass-named-invariant         : (c) named in-protocol cap / recovery.
      fail-grep-only-absence       : the ONLY evidence is a keyword grep / "no X
                                     found" / absence count - NOT a proof of
                                     unreachability.
      fail-no-unreachability-proof : an N-A claim carrying NEITHER a grep NOR any
                                     admissible proof form (a bare assertion).
    """
    text = str(reason or "")
    is_na = bool(NA_CLAIM_RE.search(text))
    is_candidate = bool(CANDIDATE_CLAIM_RE.search(text))
    grep_only = bool(GREP_ONLY_RE.search(text))

    # A proof form is ADMISSIBLE only when its structural statement co-occurs with a
    # file:line anchor on the SAME clause (escalate-first _line_hits_cooccur
    # discipline). This is the load-bearing anti-false-negative rule: a governance
    # N-A that leads with "grep Governor = 0" and cites an OUT-OF-SCOPE simapp
    # import path (a file:line that anchors NOTHING about in-scope reachability)
    # does NOT get to pass on the strength of that stray citation - the structural
    # unreachability claim itself must be anchored to source.
    has_code_guard = _cooccurs_with_file_line(text, CODE_GUARD_RE)
    has_mechanism_arg = _cooccurs_with_file_line(text, MECHANISM_ARGUMENT_RE)
    has_named_invariant = _cooccurs_with_file_line(text, NAMED_INVARIANT_RE)

    out: dict[str, object] = {
        "is_na_claim": is_na,
        "has_code_guard": has_code_guard,
        "has_mechanism_arg": has_mechanism_arg,
        "has_named_invariant": has_named_invariant,
        "grep_only": grep_only,
    }

    # A disposition that POINTS AT a real finding / candidate is a KEEP not a KILL;
    # the unreachability-proof bar does not apply.
    if is_candidate and not is_na:
        out["admissible"] = True
        out["verdict"] = "exempt-not-na-claim"
        return out

    # The bar fires only for an N-A / cleared / unreachability claim. A reason that
    # is neither an N-A claim nor a candidate (e.g. a plain covered-with-reason
    # note) is admissible - the quality bar is specifically about NOT letting a
    # keyword-grep KILL a cell.
    if not is_na:
        out["admissible"] = True
        out["verdict"] = "exempt-not-na-claim"
        return out

    # From here: the reason CLAIMS unreachability / N-A. It MUST carry an ANCHORED
    # proof form (structural claim + file:line on the same clause).
    if has_code_guard:
        out["admissible"] = True
        out["verdict"] = "pass-code-guard-cited"
        return out
    if has_mechanism_arg:
        out["admissible"] = True
        out["verdict"] = "pass-mechanism-argument"
        return out
    if has_named_invariant:
        out["admissible"] = True
        out["verdict"] = "pass-named-invariant"
        return out

    # No ANCHORED admissible proof form. Distinguish grep-only from a bare assertion
    # for a clearer operator message. A reason that leans on a keyword grep with no
    # anchored structural proof is the exact operator-caught false-negative.
    out["admissible"] = False
    out["verdict"] = "fail-grep-only-absence" if grep_only else "fail-no-unreachability-proof"
    return out


def reason_is_terminal_quality(reason: str) -> bool:
    """True iff the reason is admissible as a TERMINAL disposition (proves the
    impact unreachable, or is a keep/candidate exempt from the bar). Grep-only /
    absence-only / bare-assertion N-A reasons return False.

    Callers gate on this ONLY when proof_strict_enabled() is True so the non-strict
    path is byte-identical to the legacy behaviour."""
    return bool(classify_reason(reason)["admissible"])
