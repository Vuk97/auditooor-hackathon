"""Shared severity normalizer for W2.4 firm-specific PDF parsers.

Wave-2 capability-expansion (PR #729) shipped 8 firm-specific PDF parsers
(Trail of Bits, Sherlock, Pashov, Zellic, Cyfrin, Spearbit, ChainSecurity,
OpenZeppelin), each implementing its own ad-hoc severity-normalization
logic. This module consolidates those variants behind a small public
surface so NEW firm parsers (and future refactors of existing ones) can
share a single source of truth.

Design notes:

* ADDITIVE only - this module does NOT modify the 8 existing firm parsers
  on PR #729. They continue to ship with their inline severity logic
  which works for their fixtures. New parsers should import from here;
  existing parsers may be migrated in a separate refactor PR once their
  fixture suites cover the migration.
* No network IO, no file IO - pure-function helpers.
* No silent failures - ``normalize_severity`` returns ``None`` on no match
  so callers can fail closed or flag synthetic / malformed inputs.
* Synthetic fixtures used in this module's tests are explicitly marked
  ``synthetic_fixture: true`` in test comments.

Canonical severity tiers (ranked highest to lowest):

* ``Critical`` - direct fund-loss-class
* ``High`` - significant impact, exploitable
* ``Medium`` - meaningful risk, conditional exploitability
* ``Low`` - minor / informational risk
* ``Informational`` - notes, best-practice, code-quality
* ``Gas`` - gas-optimization suggestions (Cyfrin and similar tiers)

Firm-specific variants observed across the 8 parsers:

* Spearbit:        ``Critical Risk``, ``High Risk``, ``Medium Risk``, ``Low Risk``
* Cyfrin:          ``Gas Optimization`` (alias of ``Gas``), ``G-N`` finding IDs
* Zellic:          ``Best Practice`` (alias of ``Informational``)
* ChainSecurity:   ``Best Practice`` (alias of ``Informational``)
* OpenZeppelin:    ``Note`` / ``N-N`` finding IDs (alias of ``Informational``)
* Trail of Bits:   standard tiers + ``Undetermined`` (returns ``None``)
"""
from __future__ import annotations

import re
from typing import Optional


__all__ = [
    "CANONICAL_SEVERITIES",
    "SEVERITY_ALIASES",
    "SEVERITY_RANK",
    "normalize_severity",
    "infer_severity_from_id_prefix",
    "severity_rank",
    "is_gas_finding",
]


CANONICAL_SEVERITIES = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
    "Gas",
]


# Lower-cased alias map. ``normalize_severity`` lower-cases the input
# before lookup so all keys here must be lower-case.
SEVERITY_ALIASES = {
    # Spearbit "Risk"-suffixed tiers
    "critical risk": "Critical",
    "high risk": "High",
    "medium risk": "Medium",
    "low risk": "Low",
    # Zellic / ChainSecurity "Best Practice" tier
    "best practice": "Informational",
    "best practices": "Informational",
    # OpenZeppelin "Note" tier
    "note": "Informational",
    "notes": "Informational",
    # Cyfrin gas tier variants
    "gas optimization": "Gas",
    "gas optimizations": "Gas",
    "gas-optimization": "Gas",
    # Informal / shorthand variants
    "info": "Informational",
    "informational risk": "Informational",
    "crit": "Critical",
}


# Numeric rank used by ``severity_rank`` and ``is_gas_finding``.
# Higher rank = more severe. Gas is a sibling tier to Informational
# (advice-only) but ranked lowest so sort-desc puts findings-of-impact
# first.
SEVERITY_RANK = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
    "Gas": 0,
}


# Finding-ID prefix map. ``infer_severity_from_id_prefix`` recognises
# 1-3 letter prefixes followed by ``-`` and 1-3 digits.
# ``CS-N`` (ChainSecurity's generic finding prefix) intentionally maps
# to ``None`` because the firm assigns severity in a separate column
# rather than encoding it in the ID.
_ID_PREFIX_MAP = {
    "C": "Critical",
    "H": "High",
    "M": "Medium",
    "L": "Low",
    "I": "Informational",
    "N": "Informational",
    "G": "Gas",
}


_ID_PREFIX_RE = re.compile(r"^\s*([A-Za-z]{1,3})-(\d{1,3})\b")


_CANONICAL_LOWER = {sev.lower(): sev for sev in CANONICAL_SEVERITIES}


def normalize_severity(raw: Optional[str]) -> Optional[str]:
    """Normalize a free-form severity label to a canonical tier.

    Accepts firm-specific variants observed across W2.4 PDF parsers
    (e.g. ``"Critical Risk"``, ``"Best Practice"``, ``"Note"``,
    ``"Gas Optimization"``) plus trailing-word tolerance (e.g.
    ``"High Risk - exploitable"`` -> ``"High"``).

    Returns ``None`` if no canonical match is found, so callers can
    fail closed on malformed input.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower()
    if not s:
        return None

    # Exact canonical match (case-insensitive)
    if s in _CANONICAL_LOWER:
        return _CANONICAL_LOWER[s]

    # Exact alias match
    if s in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[s]

    # Trailing-word tolerance: the canonical/alias prefix is accepted
    # only when separated from the trailing rationale by a *non-space*
    # delimiter (``-``, ``/``, ``(``, ``,``, ``:``). Bare whitespace is
    # not enough - "Critical Bug Bonanza" must NOT match "Critical".
    # However a 2-3 token alias whose tokens are space-separated
    # ("Critical Risk", "Gas Optimization", "Best Practice") is still
    # accepted, and trailing rationale after a real delimiter is
    # stripped before the alias lookup.
    m = re.match(r"^([a-z][a-z\s]*?)\s*[\-/(,:][\s\S]*$", s)
    if m:
        head = m.group(1).strip()
        if head in SEVERITY_ALIASES:
            return SEVERITY_ALIASES[head]
        if head in _CANONICAL_LOWER:
            return _CANONICAL_LOWER[head]

    return None


def infer_severity_from_id_prefix(finding_id: Optional[str]) -> Optional[str]:
    """Infer a canonical severity from a finding-ID prefix.

    Recognises common single-letter prefixes (``C-N``, ``H-N``, ``M-N``,
    ``L-N``, ``I-N``, ``N-N``, ``G-N``) where ``N`` is a 1-3 digit
    sequence. Multi-letter prefixes such as ChainSecurity's ``CS-N``
    return ``None`` because severity is encoded in a separate column.
    """
    if finding_id is None or not isinstance(finding_id, str):
        return None
    m = _ID_PREFIX_RE.match(finding_id)
    if not m:
        return None
    prefix = m.group(1).upper()
    # Only single-letter prefixes carry severity in firm conventions.
    if len(prefix) != 1:
        return None
    return _ID_PREFIX_MAP.get(prefix)


def severity_rank(sev: Optional[str]) -> int:
    """Return the numeric rank for a canonical severity (higher = more severe).

    Unknown or ``None`` input returns ``-1`` so sort-desc by rank puts
    unknowns last without exception.
    """
    if sev is None:
        return -1
    canonical = normalize_severity(sev) if sev not in SEVERITY_RANK else sev
    if canonical is None:
        return -1
    return SEVERITY_RANK.get(canonical, -1)


def is_gas_finding(sev: Optional[str]) -> bool:
    """Return ``True`` iff ``sev`` normalizes to the ``Gas`` tier."""
    canonical = normalize_severity(sev) if sev not in SEVERITY_RANK else sev
    return canonical == "Gas"
