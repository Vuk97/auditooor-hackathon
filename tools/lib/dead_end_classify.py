"""Shared drop-class classifier for ruled-out audit units (dead ends).

THE PROBLEM THIS FIXES: every lane that rules a unit OUT (hunt sidecars,
depth-probe negative-space, sibling-diff) writes a free-text ``reason`` /
``ruled_out_reason`` / ``why_no_gap_or_exploit`` string and (sometimes) cites an
R-code in prose. There was NO single place that turned that prose into a
canonical ``drop_class``, so the learning loop could not answer "how many units
did we drop as privileged-only this engagement?" without re-reading every
sidecar by hand. The drift cost: the same dead-end shape gets re-hunted next
engagement because nobody could query the prior verdict.

THE FIX: ONE pure-stdlib classifier. ``classify(reason, code_excerpt)`` maps the
free text onto a small, stable taxonomy of WHY-we-dropped buckets, and
``parse_rule_codes`` pulls every cited ``R\\d+`` (and a few canonical aliases)
out of the same text. Generic - no workspace name ever appears in a decision.

DESIGN INVARIANTS (enforced by the unit tests):
  - Deterministic + order-sensitive: the rule table is consulted top-to-bottom
    and the FIRST match wins, so a row that is both "upstream-unmodified" and
    mentions a DoS phrase classifies as the upstream OOS bucket (the stronger
    drop reason) rather than the weaker generic-dos one.
  - FAIL-SAFE / loud: an unrecognised reason returns ``ruled-out-other`` (the
    catch-all), never an empty string and never a crash - the learning loop can
    then surface the long tail of un-bucketed reasons for a human to taxonomise.
  - Case-insensitive substring matching over a NORMALISED (lower, ws-collapsed)
    join of reason + code_excerpt, so phrasing variants ("onlyOwner" vs
    "only owner", "msg.sender" vs "msgSender") still bucket.

Pure stdlib. No I/O. Safe to import from any tool.
"""
from __future__ import annotations

import re
from typing import List

# Canonical drop-class taxonomy. Keep this set stable - the ledger histogram
# and any downstream MCP recall key off these literal strings.
DROP_CLASSES = (
    "oos-unmodified-upstream",
    "privileged-only-R24",
    "generic-dos-R35",
    "struct-field-not-guard",
    "designed-as-intended-R47",
    "evm-cannot-spoof-msgsender",
    "view-only",
    "ruled-out-other",
)

# Ordered (first-match-wins) keyword rules. Each entry: (drop_class, [phrases]).
# The ORDER encodes precedence: a stronger / more-specific drop reason is listed
# ABOVE a weaker one so it claims an ambiguous row. Phrases are matched as
# case-insensitive substrings against the normalised text.
_RULES = (
    (
        "oos-unmodified-upstream",
        [
            "unmodified upstream",
            "upstream unmodified",
            "vanilla upstream",
            "stock upstream",
            "unmodified go-ethereum",
            "unmodified geth",
            "unmodified fork",
            "untouched upstream",
            "upstream library",
            "upstream dependency",
            "out of scope upstream",
            "oos upstream",
        ],
    ),
    (
        "evm-cannot-spoof-msgsender",
        [
            "cannot spoof msg.sender",
            "cannot spoof msgsender",
            "cannot forge msg.sender",
            "evm cannot spoof",
            "evm-enforced sender",
            "evm enforced sender",
            "msg.sender cannot be spoofed",
            "msgsender cannot be spoofed",
            "sender is evm-authenticated",
        ],
    ),
    (
        "privileged-only-R24",
        [
            "onlyowner",
            "only owner",
            "onlyadmin",
            "only admin",
            "onlyrole",
            "only role",
            "only governance",
            "onlygovernance",
            "privileged only",
            "privileged-only",
            "admin-only",
            "admin only",
            "owner-only",
            "owner only",
            "trusted role",
            "unprivileged cannot reach",
            "attacker is not privileged",
            "requires privileged",
            "access-controlled",
            "access controlled",
            "r24",
        ],
    ),
    (
        "designed-as-intended-R47",
        [
            "designed as intended",
            "designed-as-intended",
            "working as intended",
            "by design",
            "intended behavior",
            "intended behaviour",
            "acknowledged",
            "known issue",
            "known-issue",
            "wont-fix",
            "won't fix",
            "wontfix",
            "documented behavior",
            "documented behaviour",
            "r47",
        ],
    ),
    (
        "struct-field-not-guard",
        [
            "struct field not a guard",
            "struct-field not a guard",
            "is a struct field",
            "plain struct field",
            "data field not a check",
            "field not a guard",
            "not a guard - struct",
            "struct member not a guard",
        ],
    ),
    (
        "view-only",
        [
            "view-only",
            "view only",
            "pure function",
            "pure-function",
            "read-only function",
            "read only function",
            "no state change",
            "no state-change",
            "does not write state",
            "getter only",
            "getter-only",
        ],
    ),
    (
        "generic-dos-R35",
        [
            "generic dos",
            "generic-dos",
            "denial of service",
            "denial-of-service",
            "rate limit",
            "rate-limit",
            "cap exhaustion",
            "cap-exhaustion",
            "gas griefing",
            "gas-griefing",
            "out of scope dos",
            "oos dos",
            "r35",
        ],
    ),
)

# Recognise cited rule codes: R24, R-24, R 24, etc. Also a few canonical aliases
# that appear in prose without the bare R-code.
_RCODE_RE = re.compile(r"\bR[\s\-]?(\d{1,3})\b", re.IGNORECASE)
_ALIAS_RCODES = {
    "privileged-only": "R24",
    "non-self-impact": "R24",
    "generic dos": "R35",
    "generic-dos": "R35",
    "dos-class-reframe": "R35",
    "acknowledged": "R47",
    "wont-fix": "R47",
    "won't fix": "R47",
    "designed as intended": "R47",
}


def _normalise(text: str) -> str:
    """Lower-case + collapse whitespace; tolerate None."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", str(text)).strip().lower()


def classify(reason: str, code_excerpt: str = "") -> str:
    """Map a free-text drop reason (+ optional code excerpt) onto a drop_class.

    First-match-wins over the ordered ``_RULES`` table. Returns
    ``ruled-out-other`` for anything unrecognised (never empty, never raises).
    """
    hay = _normalise(reason)
    excerpt = _normalise(code_excerpt)
    combined = (hay + " " + excerpt).strip()
    if not combined:
        return "ruled-out-other"
    for drop_class, phrases in _RULES:
        for phrase in phrases:
            if phrase in combined:
                return drop_class
    return "ruled-out-other"


def parse_rule_codes(reason: str, code_excerpt: str = "") -> List[str]:
    """Pull every cited R-code (R24, R-35, ...) + canonical aliases from text.

    Returns a sorted, de-duplicated list of ``R\\d+`` strings (uppercased).
    Empty list if none cited.
    """
    combined = (_normalise(reason) + " " + _normalise(code_excerpt)).strip()
    codes = set()
    for m in _RCODE_RE.finditer(combined):
        codes.add("R" + m.group(1))
    for alias, code in _ALIAS_RCODES.items():
        if alias in combined:
            codes.add(code)
    return sorted(codes, key=lambda c: (len(c), c))


__all__ = ["classify", "parse_rule_codes", "DROP_CLASSES"]
