#!/usr/bin/env python3
"""per-finding-oos-check.py — apply persisted OOS clauses to ONE finding.

Wave-2 capability uplift (I24, closes #346). Reads
``<workspace>/OOS_PASTED.md`` (written by ``operator-oos-import.py``) and a
draft finding file, then runs each clause × finding through one of three
modes:

    Heuristic (default)
        First runs the program-specific semantic traps
        (economic-sequencing / natural-network-activity), then performs a
        narrower keyword scan over the draft. The keyword scan ignores
        OOS-inventory lines and avoids broad filler tokens, so a draft that
        lists "admin" or "test file" only as part of a rebuttal / PoC hygiene
        block does not become a hard OOS match.

    LLM (``--llm``)
        Dispatches a structured prompt to ``llm-dispatch.py`` per clause,
        asking "does THIS finding match THIS clause?". Each response is
        parsed into ``MATCH`` / ``NO_MATCH`` / ``INCONCLUSIVE``.

    Manual (``--manual``)
        Emits a per-clause checklist into the Markdown sidecar with
        ``[ ]`` boxes for the operator to tick. Verdict stays
        ``inconclusive`` until the operator re-runs with a real mode.

Outputs
-------
1. ``<workspace>/.auditooor/oos_check_<finding_sha>.json`` (canonical):

   .. code-block:: json

      {
        "schema": "auditooor.oos_check.v1",
        "date": "...",
        "workspace": "...",
        "finding": "...",
        "finding_sha256": "...",
        "mode": "heuristic|llm|manual",
        "oos_pasted_clauses_hash": "...",
        "clauses_checked": [
          {"id": "C1", "text": "...", "verdict": "MATCH|NO_MATCH|INCONCLUSIVE", "evidence": "..."},
          ...
        ],
        "verdict": "in-scope|matches-oos|inconclusive"
      }

2. Markdown sidecar next to the draft (``<draft>.OOS_CHECK.md`` or
   ``OOS_CHECK.md``) with the same content rendered for human review,
   including a top-level ``verdict:`` line (with the legacy
   ``SAFE_TO_FILE`` / ``NEEDS_REVIEW`` shorthand) so legacy pre-submit
   scrapers keep working.

The JSON artifact is the source of truth; pre-submit-check Check #29
prefers it.

Verdict resolution
------------------
- Any ``MATCH`` clause → top-level verdict ``matches-oos``.
- All ``NO_MATCH`` → top-level ``in-scope``.
- Any ``INCONCLUSIVE`` (and no ``MATCH``) → top-level ``inconclusive``.

Exit codes
----------
    0 — wrote artifacts; verdict is whatever it is (in-scope / matches-oos
        / inconclusive). Non-zero verdict still exits 0 because callers
        may want a soft warning; the pre-submit gate enforces the
        hard fail.
    1 — workspace missing, finding missing, or no OOS_PASTED.md present
        (caller should treat absence as "no operator paste, skip gate").
    2 — usage error
    3 — LLM dispatch refused (no key / no consent / transport error)
        when ``--llm`` was explicitly requested.
    4 — ``--require-real-oos`` set AND the workspace carries no real
        current bounty OOS text (OOS_CHECKLIST.md still TBD and no
        OOS_PASTED.md with clauses). This is a HARD FAIL: a missing OOS
        import must block a High/Critical paste-ready, not be a no-op.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.oos_check.v1"
MANIFEST_FENCE_OPEN = "<!-- OOS_PASTED_MANIFEST_BEGIN"
MANIFEST_FENCE_CLOSE = "OOS_PASTED_MANIFEST_END -->"

# Heuristic class table — each clause and finding is bag-of-tokens scanned;
# a clause "matches" the finding iff some class has a token in BOTH.
_HEURISTIC_CLASSES: list[tuple[str, list[str]]] = [
    (
        "privileged/admin",
        [
            "admin",
            "guardian",
            "owner",
            "governance",
            "multisig",
            "privileged",
            "onlyowner",
            "onlyadmin",
            "onlyrole",
            "trusted role",
        ],
    ),
    (
        "compromised key/proof",
        [
            "compromis",
            "leaked key",
            "stolen key",
            "invalid tee",
            "invalid zk",
            "forged proof",
            "soundness",
            "malicious signer",
        ],
    ),
    (
        "project inaction",
        [
            "will not",
            "blacklist",
            "retire",
            "project inaction",
            "team inaction",
            "manual restart",
            "operator inaction",
        ],
    ),
    (
        "best practice/feature",
        [
            "best practice",
            "feature request",
            "recommendation",
            "code style",
            "gas optimization",
        ],
    ),
    (
        "test/config only",
        [
            "test-only",
            "test only",
            "bug in test",
            "root cause in test",
            "configuration files",
            "config files",
            "configuration-only",
            "config-only",
            "root cause in config",
            "deployment script",
        ],
    ),
    (
        "centralization/economic",
        [
            "centralization",
            "economic risk",
            "governance attack",
            "oracle manipulation",
            "rebalanc",
        ],
    ),
    (
        "third-party/dependency",
        [
            "third party dependency",
            "third-party dependency",
            "third party oracle",
            "third-party oracle",
            "dependency",
            "external library",
            "out of project control",
        ],
    ),
    (
        "economic-sequencing/mev",
        [
            "front-run",
            "frontrun",
            "front run",
            "back-run",
            "backrun",
            "back run",
            "sandwich",
            "mev",
            "maximal extractable value",
            "transaction ordering",
            "order flow",
            "ordering manipulation",
            "reorder",
            "pre-position",
            "pre-positioning",
        ],
    ),
    (
        "natural-network-activity",
        [
            "curation",
            "signaling",
            "name signal",
            "staking",
            "delegation",
            "swapping",
            "providing liquidity",
            "liquidity provision",
            "lping",
            "permissionless market",
            "normal market activity",
            "natural network activity",
            "normal protocol activity",
        ],
    ),
    (
        # "Sybil attacks" is verbatim Immunefi/Cantina boilerplate (usually next to
        # "Centralization risks" + "Basic economic/governance attacks"). Added
        # 2026-07-09 (Obyte friend-aa "daily fresh-counterparty farming" case): a
        # finding written in sybil-NEUTRAL language ("fresh unprivileged addresses",
        # "disposable counterparty") could slip past the matcher even when the OOS
        # clause text was extracted, because no class carried the concept.
        "sybil/multi-identity",
        [
            "sybil",
            "multi-account",
            "multiple accounts",
            "multiple identities",
            "multiple wallets",
            "fake account",
            "fake identities",
            "fresh account",
            "fresh address each",
            "new address each",
            "disposable account",
            "disposable counterparty",
            "throwaway address",
            "throwaway account",
            "manufactured identities",
            "new user each day",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Rule: program-specific OOS semantic gate (Graph L2GNS OOS-closure anchor)
# ---------------------------------------------------------------------------
#
# Two named traps run IN ADDITION to the bag-of-tokens heuristic so a
# High/Critical paste-ready cannot ship when its exploit path matches a
# program OOS clause.
#
#   economic-sequencing trap
#       The exploit requires the attacker to PRE-POSITION (pre-seed /
#       pre-curate / pre-fund / take a position) BEFORE a victim/owner/
#       protocol action AND REDEEM/PROFIT AFTER that action. If the OOS
#       clause excludes frontrunning / backrunning / sandwiching / MEV /
#       transaction-ordering, the clause MATCHES the finding — unless the
#       draft carries an `<!-- oos-economic-sequencing-rebuttal: ... -->`
#       marker proving an alternate path without the excluded sequencing.
#
#   natural-network-activity trap
#       The bug's prerequisite is a permissionless action the program
#       treats as normal activity (curation / staking / swapping / LPing /
#       signaling). If the OOS clause names that activity as normal /
#       expected / permissionless, the clause MATCHES — unless the draft
#       proves the bug is independent of the allowed activity (rebuttal
#       marker `<!-- oos-natural-activity-rebuttal: ... -->`).
#
# Anti-overgeneralization: a clause that only excludes generic MEV does
# NOT match a finding that has NO pre-position-then-redeem sequence. The
# trap requires BOTH halves of the sequence in the finding text.

_SEQ_PREPOSITION_RE = re.compile(
    r"\b(pre[\- ]?position\w*|pre[\- ]?seed\w*|pre[\- ]?curat\w*|pre[\- ]?fund\w*|"
    r"seed\w*\s+(the\s+|a\s+)?(pool|deployment|position|signal)|"
    r"attacker\s+(first|pre)\w*\s+(seed|curat|fund|position|create)\w*|"
    r"create\w*\s+the\s+(future|target)\s+(deployment|pool)|"
    r"inflate\w*\s+(that\s+|the\s+)?(same\s+)?(pool|reserve|deployment))\b",
    re.IGNORECASE,
)
_SEQ_VICTIM_ACTION_RE = re.compile(
    r"\b(wait\w*\s+for\s+(the\s+)?(legitimate\s+)?(owner|victim|user|protocol)|"
    r"before\s+the\s+(owner|victim|user)\s+(publish|call|act|transact|migrat)|"
    r"(owner|victim|user)\s+(later\s+|then\s+)?(publish\w*|call\w*|migrat\w*|transact\w*)|"
    r"legitimate\s+(owner|user|subgraph\s+owner)\s+(later\s+)?(publish\w*|call\w*)|"
    r"(after|once)\s+(the\s+)?(owner|victim|user)\s+(publish|migrat|call|act))\b",
    re.IGNORECASE,
)
_SEQ_REDEEM_RE = re.compile(
    r"\b(redeem\w*|burn\w*\s+.{0,40}(signal|position|target)|withdraw\w*|drain\w*|"
    r"extract\w*\s+(the\s+)?(reserve|value|funds|profit)|"
    r"profit\w*|receives?\s+the\s+(entire|full|whole)\s+(reserve|pool))\b",
    re.IGNORECASE,
)
# A clause that excludes ordering-around-another-party / MEV.
_CLAUSE_SEQUENCING_RE = re.compile(
    r"\b(front[\- ]?run\w*|back[\- ]?run\w*|sandwich\w*|\bmev\b|"
    r"maximal\s+extractable\s+value|transaction\s+ordering|order(ing)?[\- ]flow|"
    r"reorder\w*|pre[\- ]?position\w*|generic\s+market\s+activity|"
    r"permissionless\s+market\s+(activity|action))\b",
    re.IGNORECASE,
)
# A clause that names a permissionless action as normal/expected activity.
_CLAUSE_NATURAL_ACTIVITY_RE = re.compile(
    r"\b(curation|signaling|signal\w*|staking|delegation|swapping|"
    r"providing\s+liquidity|liquidity\s+provision|lp(ing)?|"
    r"natural\s+network\s+activity|normal\s+(market\s+|network\s+|protocol\s+)?activity|"
    r"permissionless\s+(action|activity|participation)|"
    r"expected\s+(market|network|protocol)\s+behaviour|expected\s+behavior)\b",
    re.IGNORECASE,
)
# Finding text uses curation/staking/etc as an exploit prerequisite.
_FINDING_NATURAL_ACTIVITY_RE = re.compile(
    r"\b(curat\w*\s+(fee|the\s+pool|the\s+deployment|reserve)|"
    r"route\w*\s+(curation\s+)?fees?|fee[\- ]?inflat\w*|"
    r"curation[\- ]?fee\s+(collection|reserve|inflation)|"
    r"production\s+curation[\- ]?fee|"
    r"inflate\w*\s+.{0,40}(pool|reserve)\s+through\s+.{0,40}(curation|staking|fee)|"
    r"prerequisite\s+is\s+.{0,40}(curation|signaling|staking|swap|liquidity))\b",
    re.IGNORECASE,
)

_ECON_SEQ_REBUTTAL_RE = re.compile(
    r"<!--\s*oos-economic-sequencing-rebuttal:\s*(.+?)-->",
    re.IGNORECASE | re.DOTALL,
)
_NAT_ACT_REBUTTAL_RE = re.compile(
    r"<!--\s*oos-natural-activity-rebuttal:\s*(.+?)-->",
    re.IGNORECASE | re.DOTALL,
)


def _has_rebuttal(text: str, rebuttal_re: re.Pattern) -> bool:
    """A rebuttal marker counts only when it carries a non-empty reason."""
    m = rebuttal_re.search(text)
    if not m:
        return False
    return bool((m.group(1) or "").strip())


_NEGATION_RE = re.compile(
    r"\b(no|not|never|without|does\s+not|do\s+not|is\s+not|are\s+not|"
    r"there\s+is\s+no|there\s+are\s+no|free\s+of|absent|lacks?)\b",
    re.IGNORECASE,
)


def _has_unnegated_match(text: str, compiled: re.Pattern) -> bool:
    """True iff `compiled` matches in `text` outside a negated clause.

    Anti-overgeneralization guard for the two OOS traps: a draft that
    explicitly disclaims a sequencing/MEV term ("there is no
    pre-positioning", "does not front-run") must not be treated as if it
    relied on that term. We look back ~96 chars within the same sentence
    for a negation token, mirroring `_has_unnegated_token`.
    """
    for m in compiled.finditer(text):
        prefix = text[max(0, m.start() - 96) : m.start()]
        sentence_prefix = re.split(r"[\n.;:!?]", prefix)[-1]
        if _NEGATION_RE.search(sentence_prefix):
            continue
        return True
    return False


def economic_sequencing_trap(
    clause_text: str, finding_text: str
) -> tuple[str, str] | None:
    """Return (verdict, evidence) when the trap fires, else None.

    Fires only when (a) the OOS clause excludes ordering-around-another-
    party / MEV AND (b) the finding text contains BOTH a pre-position
    step AND a profit/redeem step AND a victim/owner action between them.
    This three-part requirement is the anti-overgeneralization guard: a
    plain slippage/rounding bug with no victim-tx sequencing does NOT
    match a generic 'MEV is OOS' clause.
    """
    if not _CLAUSE_SEQUENCING_RE.search(clause_text):
        return None
    has_pre = _has_unnegated_match(finding_text, _SEQ_PREPOSITION_RE)
    has_victim = _has_unnegated_match(finding_text, _SEQ_VICTIM_ACTION_RE)
    has_redeem = _has_unnegated_match(finding_text, _SEQ_REDEEM_RE)
    if not (has_pre and has_victim and has_redeem):
        return None
    if _has_rebuttal(finding_text, _ECON_SEQ_REBUTTAL_RE):
        return (
            "NO_MATCH",
            "economic-sequencing trap fired but draft carries a non-empty "
            "oos-economic-sequencing-rebuttal marker proving an alternate path",
        )
    return (
        "MATCH",
        "economic-sequencing OOS trap: exploit pre-positions before a "
        "victim/owner action and redeems after it; clause excludes "
        "frontrunning/backrunning/sandwich/MEV/ordering",
    )


def natural_network_activity_trap(
    clause_text: str, finding_text: str
) -> tuple[str, str] | None:
    """Return (verdict, evidence) when the trap fires, else None.

    Fires when (a) the OOS clause names a permissionless action as
    normal/expected activity AND (b) the finding uses that activity
    (curation fees / staking / signaling / LPing) as an exploit
    prerequisite. The draft clears it with an
    `<!-- oos-natural-activity-rebuttal: ... -->` marker proving the bug
    is independent of the allowed activity.
    """
    if not _CLAUSE_NATURAL_ACTIVITY_RE.search(clause_text):
        return None
    if not _has_unnegated_match(finding_text, _FINDING_NATURAL_ACTIVITY_RE):
        return None
    if _has_rebuttal(finding_text, _NAT_ACT_REBUTTAL_RE):
        return (
            "NO_MATCH",
            "natural-network-activity trap fired but draft carries a "
            "non-empty oos-natural-activity-rebuttal marker proving the bug "
            "is independent of the allowed permissionless activity",
        )
    return (
        "MATCH",
        "natural-network-activity OOS trap: exploit prerequisite is a "
        "permissionless action (curation/staking/signaling/swapping/LPing) "
        "the program treats as normal network activity",
    )


def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _extract_oos_bullet_clauses(text: str) -> list[dict[str, str]]:
    """Extract plain Markdown bullets from an Out-of-Scope section.

    Operator-pasted Cantina prompts often carry a manifest fence with useful
    metadata but no normalized ``clauses`` array. Treat the human-readable OOS
    bullets as clauses so the per-finding gate can still produce an artifact.
    """
    heading_re = re.compile(
        r"^#{1,6}\s+.*\bout\s+of\s+scope\b.*$",
        re.IGNORECASE | re.MULTILINE,
    )
    match = heading_re.search(text)
    if not match:
        return []
    section = text[match.end() :]
    next_heading = re.search(r"^#{1,6}\s+\S", section, re.MULTILINE)
    if next_heading:
        section = section[: next_heading.start()]

    clauses: list[dict[str, str]] = []
    current: str | None = None
    for line in section.splitlines():
        bullet = re.match(r"^\s*[-*]\s+(.+?)\s*$", line)
        if bullet:
            if current:
                clauses.append({"id": f"C{len(clauses) + 1}", "text": current})
            current = bullet.group(1).strip()
            continue
        if current and re.match(r"^\s+\S", line):
            current = f"{current} {line.strip()}"
            continue
        if current and not line.strip():
            clauses.append({"id": f"C{len(clauses) + 1}", "text": current})
            current = None
    if current:
        clauses.append({"id": f"C{len(clauses) + 1}", "text": current})
    return clauses


_TBD_OOS_RE = re.compile(
    r"\bTBD\b|operator\s+edit|<operator\s+edit>|"
    r"OOS-1:\s*TBD",
    re.IGNORECASE,
)


def real_oos_text_status(workspace: Path) -> dict[str, Any]:
    """Decide whether the workspace carries real, current bounty OOS text.

    Rule step 1: the full current bounty OOS text must be imported into a
    scope artifact. If `OOS_CHECKLIST.md` is still a TBD bootstrap stub
    and no `OOS_PASTED.md` with real clauses exists, that ABSENCE is
    itself the failure (this is the Graph workspace state that turned
    pre-submit Check #29 into a no-op).

    Returns a dict:
        {"real_oos": bool, "reason": str, "checked": [<path str>, ...]}
    """
    checked: list[str] = []
    # 1. OOS_PASTED.md with a usable manifest / legacy clause list.
    pasted = workspace / "OOS_PASTED.md"
    if pasted.is_file():
        checked.append(str(pasted))
        manifest = _read_pasted_manifest(workspace)
        if manifest and manifest.get("clauses"):
            return {
                "real_oos": True,
                "reason": f"OOS_PASTED.md has {len(manifest['clauses'])} clause(s)",
                "checked": checked,
            }
    # 2. OOS_CHECKLIST.md — accept only when it carries non-TBD bullets.
    checklist = workspace / "OOS_CHECKLIST.md"
    if checklist.is_file():
        checked.append(str(checklist))
        try:
            ctext = checklist.read_text(encoding="utf-8", errors="replace")
        except OSError:
            ctext = ""
        bullets = [
            ln.strip()
            for ln in ctext.splitlines()
            if re.match(r"^\s*-\s+\S", ln)
        ]
        real_bullets = [b for b in bullets if not _TBD_OOS_RE.search(b)]
        if real_bullets:
            return {
                "real_oos": True,
                "reason": (
                    f"OOS_CHECKLIST.md has {len(real_bullets)} non-TBD bullet(s)"
                ),
                "checked": checked,
            }
        if bullets:
            return {
                "real_oos": False,
                "reason": (
                    "OOS_CHECKLIST.md present but every bullet is a TBD "
                    "bootstrap stub — real bounty OOS text was never imported"
                ),
                "checked": checked,
            }
    return {
        "real_oos": False,
        "reason": (
            "no OOS_PASTED.md with clauses and no non-TBD OOS_CHECKLIST.md — "
            "the full current bounty OOS text was never imported into the "
            "workspace"
        ),
        "checked": checked,
    }


def _read_pasted_manifest(workspace: Path) -> dict[str, Any] | None:
    pasted = workspace / "OOS_PASTED.md"
    if not pasted.is_file():
        return None
    try:
        text = pasted.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if MANIFEST_FENCE_OPEN in text and MANIFEST_FENCE_CLOSE in text:
        try:
            block = text.split(MANIFEST_FENCE_OPEN, 1)[1].split(
                MANIFEST_FENCE_CLOSE, 1
            )[0].strip()
            manifest = json.loads(block)
            clauses = manifest.get("clauses") or []
            if not clauses:
                clauses = _extract_oos_bullet_clauses(text)
                if clauses:
                    manifest["clauses"] = clauses
                    manifest["clauses_hash"] = _sha256_text(
                        "\n".join(
                            f"{c.get('id', '')}\t{c.get('text', '')}"
                            for c in clauses
                        )
                    )
            return manifest
        except (IndexError, json.JSONDecodeError):
            pass
    # Legacy fallback: parse `- OOS-N: ...` and `- **Cn**: ...` lines.
    legacy_clauses: list[dict[str, str]] = []
    legacy_re = re.compile(
        r"^-\s+(?:\*\*)?(C\d+|OOS-\d+)(?:\*\*)?\s*(?:/\s*OOS-\d+)?\s*:\s*(.+)$",
        re.MULTILINE,
    )
    seen_ids: set[str] = set()
    counter = 0
    for m in legacy_re.finditer(text):
        raw_id = m.group(1)
        body = m.group(2).strip()
        if raw_id.startswith("OOS-"):
            cid = "C" + raw_id.split("-", 1)[1]
        else:
            cid = raw_id
        if cid in seen_ids:
            continue
        seen_ids.add(cid)
        counter += 1
        legacy_clauses.append({"id": cid, "text": body})
    if not legacy_clauses:
        legacy_clauses = _extract_oos_bullet_clauses(text)
    if not legacy_clauses:
        return None
    return {
        "schema": "auditooor.oos_pasted.legacy",
        "date": "",
        "source_url": "",
        "project": "",
        "note": "",
        "clauses_hash": _sha256_text(
            "\n".join(
                f"{c.get('id', '')}\t{c.get('text', '')}" for c in legacy_clauses
            )
        ),
        "clauses": legacy_clauses,
    }


def _manifest_from_text(text: str) -> dict[str, Any] | None:
    """Build an OOS manifest dict from raw Markdown text.

    Tries, in order: a fenced machine-readable manifest block, legacy
    `- OOS-N:` / `- **Cn**:` lines, then plain Out-of-Scope bullets.
    """
    if MANIFEST_FENCE_OPEN in text and MANIFEST_FENCE_CLOSE in text:
        try:
            block = text.split(MANIFEST_FENCE_OPEN, 1)[1].split(
                MANIFEST_FENCE_CLOSE, 1
            )[0].strip()
            manifest = json.loads(block)
            clauses = manifest.get("clauses") or []
            if not clauses:
                clauses = _extract_oos_bullet_clauses(text)
                if clauses:
                    manifest["clauses"] = clauses
            if manifest.get("clauses"):
                manifest["clauses_hash"] = _sha256_text(
                    "\n".join(
                        f"{c.get('id', '')}\t{c.get('text', '')}"
                        for c in manifest["clauses"]
                    )
                )
                return manifest
        except (IndexError, json.JSONDecodeError):
            pass
    legacy_re = re.compile(
        r"^-\s+(?:\*\*)?(C\d+|OOS-\d+)(?:\*\*)?\s*(?:/\s*OOS-\d+)?\s*:\s*(.+)$",
        re.MULTILINE,
    )
    legacy_clauses: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for m in legacy_re.finditer(text):
        raw_id = m.group(1)
        body = m.group(2).strip()
        cid = ("C" + raw_id.split("-", 1)[1]) if raw_id.startswith("OOS-") else raw_id
        if cid in seen_ids:
            continue
        seen_ids.add(cid)
        legacy_clauses.append({"id": cid, "text": body})
    if not legacy_clauses:
        legacy_clauses = _extract_oos_bullet_clauses(text)
    if not legacy_clauses:
        return None
    return {
        "schema": "auditooor.oos_pasted.from_file",
        "date": "",
        "source_url": "",
        "project": "",
        "note": "",
        "clauses_hash": _sha256_text(
            "\n".join(
                f"{c.get('id', '')}\t{c.get('text', '')}" for c in legacy_clauses
            )
        ),
        "clauses": legacy_clauses,
    }


def _read_manifest_from_file(oos_file: Path) -> dict[str, Any] | None:
    """Read OOS clauses from an explicit file (the --oos-file override)."""
    try:
        text = oos_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return _manifest_from_text(text)


# Forward refutation cues: phrasing that, when it FOLLOWS the token within the
# same clause, explicitly refutes the token's applicability ("<token> ... is
# refuted / does not apply / is out of scope"). Narrow to refutation verbs so a
# genuine reliance sentence ("... relies on the guardian to ...") is NOT
# suppressed just because it later contains an unrelated "not".
_FORWARD_REFUTATION_RE = re.compile(
    r"(?i)\b(?:is|are|was|were|be)\s+(?:not|refuted|excluded)\b"
    r"|\brefut(?:e[sd]?|ing|ation)\b"
    r"|\bdoes\s+not\s+(?:apply|hold|rely|depend)\b"
    r"|\bdo\s+not\s+(?:apply|hold|rely|depend)\b"
    r"|\bout[- ]of[- ]scope\b"
    r"|\bnot\s+applicable\b",
)


def _has_unnegated_token(text: str, token: str) -> bool:
    negation_re = re.compile(
        r"\b(?:no|not|never|without|does\s+not|do\s+not|is\s+not|are\s+not|not\s+a|not\s+an|not\s+claiming|not\s+framed?|do\s+not\s+frame)\b",
        re.IGNORECASE,
    )
    for match in re.finditer(re.escape(token), text, re.IGNORECASE):
        prefix = text[max(0, match.start() - 96) : match.start()]
        sentence_prefix = re.split(r"[\n.;:!?]", prefix)[-1]
        if negation_re.search(sentence_prefix):
            continue
        # Forward refutation-cue window ONLY: look at the remainder of the same
        # clause after the token; if it explicitly refutes the token, skip.
        suffix = text[match.end() : match.end() + 96]
        sentence_suffix = re.split(r"[\n.;:!?]", suffix)[0]
        if _FORWARD_REFUTATION_RE.search(sentence_suffix):
            continue
        return True
    return False


_OOS_INVENTORY_LINE_RE = re.compile(
    r"(?im)^\s*(?:(?:[-*+]|\d+[.)])\s*)?(?:oos[_ -]?traps|scope exclusions checked|"
    r"out[- ]of[- ]scope checked|oos checked)\s*:",
)

_SELF_CREATED_PRIVILEGE_RE = re.compile(
    r"\b(?:"
    r"self[- ]grant(?:ed|s)?|attacker[- ]created|creates\s+(?:its|their)\s+own\s+"
    r"(?:vault|pool|market|resource)|fresh\s+(?:non[- ]privileged\s+)?account\s+"
    r"(?:that\s+)?creates\s+(?:its|their)\s+own|not\s+(?:a\s+)?(?:pre[- ]existing\s+)?"
    r"privileged\s+(?:key|address|role)|does\s+not\s+require\s+"
    r"(?:a\s+)?pre[- ]existing\s+privileged"
    r")\b",
    re.IGNORECASE,
)


def _strip_oos_inventory_lines(text: str) -> str:
    """Drop lines that merely enumerate OOS classes already reviewed.

    Impact-contract fields like ``oos_traps: centralization-risk`` are an
    inventory of checked exclusions, not evidence that the exploit depends on
    centralization. Counting them as positive OOS tokens creates false hard
    blocks on otherwise valid filings.
    """
    return "\n".join(
        ln for ln in text.splitlines() if not _OOS_INVENTORY_LINE_RE.search(ln)
    )


def _has_self_created_privilege_boundary(text: str) -> bool:
    return bool(_SELF_CREATED_PRIVILEGE_RE.search(text))


def heuristic_check(clause_text: str, finding_text: str) -> tuple[str, str]:
    # Rule: program-specific OOS semantic gate. The two named traps run
    # FIRST so a High/Critical paste-ready whose exploit path matches an
    # OOS clause is caught even when the bag-of-tokens classes do not
    # share a token. A trap MATCH is authoritative for this clause.
    seq = economic_sequencing_trap(clause_text, finding_text)
    if seq is not None and seq[0] == "MATCH":
        return seq
    nat = natural_network_activity_trap(clause_text, finding_text)
    if nat is not None and nat[0] == "MATCH":
        return nat

    c = clause_text.lower()
    f = _strip_oos_inventory_lines(finding_text).lower()
    self_created_privilege = _has_self_created_privilege_boundary(f)
    matched_classes: list[str] = []
    matched_tokens: list[str] = []
    for label, tokens in _HEURISTIC_CLASSES:
        c_hit = next((t for t in tokens if t in c), None)
        f_hit = next((t for t in tokens if _has_unnegated_token(f, t)), None)
        if c_hit and f_hit:
            if label == "privileged/admin" and self_created_privilege:
                continue
            if label == "centralization/economic" and c_hit == "centralization" and self_created_privilege:
                continue
            if (
                label == "privileged/admin"
                and c_hit in {"privileged", "trusted role"}
                and f_hit in {"guardian", "governance"}
                and not any(
                    _has_unnegated_token(f, strong)
                    for strong in (
                        "admin",
                        "privileged",
                        "onlyowner",
                        "onlyadmin",
                        "onlyrole",
                        "trusted role",
                    )
                )
            ):
                continue
            matched_classes.append(label)
            matched_tokens.append(f"{c_hit!r}/{f_hit!r}")
    if matched_classes:
        evidence = (
            f"shared OOS class(es): {', '.join(matched_classes)}; "
            f"tokens: {', '.join(matched_tokens)}"
        )
        return "MATCH", evidence
    return "NO_MATCH", "no shared OOS-class token in clause and finding"


# ---------------------------------------------------------------------------
# LLM mode
# ---------------------------------------------------------------------------


def _llm_dispatch_path(repo_root: Path) -> Path | None:
    candidate = repo_root / "tools" / "llm-dispatch.py"
    if candidate.is_file():
        return candidate
    return None


def llm_check(
    *,
    clause: dict[str, str],
    finding_text: str,
    repo_root: Path,
    dispatch_runner: Any = None,
    timeout: int = 60,
) -> tuple[str, str]:
    """Ask an LLM whether the clause matches the finding.

    ``dispatch_runner`` is an optional callable used by tests to mock the
    real dispatch. It receives ``(prompt: str)`` and returns ``str`` or
    raises. When ``None``, we shell out to ``tools/llm-dispatch.py``.
    """
    prompt = (
        "You are auditing whether a smart-contract security finding falls "
        "under an out-of-scope (OOS) clause from the bounty program.\n\n"
        f"OOS CLAUSE ({clause.get('id', '?')}):\n"
        f"{clause.get('text', '').strip()}\n\n"
        "FINDING TEXT (truncated):\n"
        f"{finding_text[:6000].strip()}\n\n"
        "Decide: does the finding match this OOS clause?\n"
        "Respond with EXACTLY one of three lines (no other text):\n"
        "  VERDICT: MATCH — <one-sentence reason>\n"
        "  VERDICT: NO_MATCH — <one-sentence reason>\n"
        "  VERDICT: INCONCLUSIVE — <one-sentence reason>\n"
    )

    if dispatch_runner is not None:
        try:
            response = dispatch_runner(prompt)
        except Exception as e:  # pragma: no cover - defensive
            return "INCONCLUSIVE", f"llm runner error: {e}"
        return _parse_llm_response(response)

    dispatch = _llm_dispatch_path(repo_root)
    if dispatch is None:
        return "INCONCLUSIVE", "llm-dispatch.py not found"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".prompt.txt", delete=False
    ) as tf:
        tf.write(prompt)
        prompt_path = tf.name
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(dispatch),
                "--prompt-file",
                prompt_path,
                "--max-tokens",
                "256",
                "--timeout",
                str(timeout),
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        os.unlink(prompt_path)
        return "INCONCLUSIVE", f"llm dispatch failed: {e}"
    finally:
        try:
            os.unlink(prompt_path)
        except OSError:
            pass

    if proc.returncode != 0:
        return (
            "INCONCLUSIVE",
            f"llm dispatch rc={proc.returncode}: {proc.stderr.strip()[:200]}",
        )
    return _parse_llm_response(proc.stdout)


def _parse_llm_response(response: str) -> tuple[str, str]:
    if not response:
        return "INCONCLUSIVE", "empty llm response"
    for line in response.splitlines():
        line = line.strip()
        m = re.match(
            r"^VERDICT:\s*(MATCH|NO_MATCH|INCONCLUSIVE)\b\s*[—:\-]?\s*(.*)$",
            line,
            re.IGNORECASE,
        )
        if m:
            verdict = m.group(1).upper()
            reason = m.group(2).strip() or "(no reason given)"
            return verdict, f"llm: {reason}"
    return "INCONCLUSIVE", f"unparseable llm response: {response[:120]!r}"


# ---------------------------------------------------------------------------
# Manual mode
# ---------------------------------------------------------------------------


def manual_check(clause: dict[str, str]) -> tuple[str, str]:
    return (
        "INCONCLUSIVE",
        "manual mode: operator must mark the checkbox below and re-run.",
    )


# ---------------------------------------------------------------------------
# Top-level verdict resolution
# ---------------------------------------------------------------------------


def resolve_top_verdict(per_clause: list[dict[str, str]]) -> str:
    has_match = any(r["verdict"] == "MATCH" for r in per_clause)
    has_inc = any(r["verdict"] == "INCONCLUSIVE" for r in per_clause)
    if has_match:
        return "matches-oos"
    if has_inc:
        return "inconclusive"
    return "in-scope"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(payload: dict[str, Any]) -> str:
    rows: list[str] = []
    for r in payload.get("clauses_checked", []):
        rows.append(
            "| {id} | {verdict} | {text} | {evidence} |".format(
                id=r["id"],
                verdict=r["verdict"],
                text=r["text"].replace("|", "/"),
                evidence=r["evidence"].replace("|", "/"),
            )
        )
    legacy_verdict = "SAFE_TO_FILE"
    if payload["verdict"] == "matches-oos":
        legacy_verdict = "NEEDS_REVIEW"
    elif payload["verdict"] == "inconclusive":
        legacy_verdict = "NEEDS_REVIEW"
    out = [
        f"# Per-Finding OOS Check: {Path(payload['finding']).name}",
        "",
        f"- generated_at_utc: {payload['date']}",
        f"- workspace: `{payload['workspace']}`",
        f"- finding: `{payload['finding']}`",
        f"- finding_sha256: `{payload['finding_sha256']}`",
        f"- mode: `{payload['mode']}`",
        f"- verdict: `{legacy_verdict}` (machine: `{payload['verdict']}`)",
        "",
        "| Clause | Verdict | Text | Evidence |",
        "|---|---|---|---|",
        *rows,
        "",
        "## Operator Action",
        "",
        "- `in-scope` → SAFE to proceed to pre-submit-check.",
        "- `matches-oos` → mark draft `_oos_rejected/` or add a concrete distinction.",
        "- `inconclusive` → re-run with `--llm` or `--manual` and tick the checklist.",
        "",
    ]
    if payload["mode"] == "manual":
        out.append("## Manual checklist")
        out.append("")
        for r in payload.get("clauses_checked", []):
            out.append(f"- [ ] **{r['id']}**: {r['text']}")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="per-finding-oos-check.py",
        description="Apply pasted OOS clauses to a single draft finding.",
    )
    parser.add_argument(
        "workspace_pos", nargs="?", default=None, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "finding_pos", nargs="?", default=None, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--workspace", dest="workspace", default=None,
        help="Workspace root (must contain OOS_PASTED.md).",
    )
    parser.add_argument(
        "--finding", dest="finding", default=None,
        help="Path to the draft finding (Markdown).",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--heuristic", action="store_true",
        help="Run the keyword/regex heuristic (default).",
    )
    mode_group.add_argument(
        "--llm", action="store_true",
        help="Dispatch the check through tools/llm-dispatch.py.",
    )
    mode_group.add_argument(
        "--manual", action="store_true",
        help="Emit a manual checklist; verdict stays inconclusive.",
    )
    parser.add_argument(
        "--out", dest="out", default=None,
        help="Override Markdown sidecar path (default: <draft>.OOS_CHECK.md).",
    )
    parser.add_argument(
        "--print-paths", action="store_true",
        help="Print absolute paths of the JSON + Markdown artifacts.",
    )
    parser.add_argument(
        "--oos-file", dest="oos_file", default=None,
        help=(
            "Explicit OOS clause source (Markdown). Overrides the default "
            "<workspace>/OOS_PASTED.md. Used by the pre-submit gate to point "
            "the semantic check at a representative OOS fixture when the "
            "workspace import is the operator action still pending."
        ),
    )
    parser.add_argument(
        "--require-real-oos", action="store_true",
        help=(
            "Program-specific OOS semantic gate (Graph L2GNS anchor). When "
            "set, the tool HARD-FAILS (exit 4) if the workspace carries no "
            "real current bounty OOS text (OOS_CHECKLIST.md still TBD AND no "
            "OOS_PASTED.md with clauses). Intended for High/Critical drafts "
            "where a missing OOS import must block paste-ready, not be a "
            "silent no-op."
        ),
    )

    args = parser.parse_args(argv)

    workspace = args.workspace or args.workspace_pos
    finding = args.finding or args.finding_pos
    if not workspace or not finding:
        _eprint(
            "[per-finding-oos-check] usage: --workspace <ws> --finding <draft>"
        )
        return 2

    ws_path = Path(workspace).expanduser()
    finding_path = Path(finding).expanduser()
    if not ws_path.is_dir():
        _eprint(f"[per-finding-oos-check] workspace not found: {ws_path}")
        return 1
    if not finding_path.is_file():
        _eprint(f"[per-finding-oos-check] finding not found: {finding_path}")
        return 1

    # Program-specific OOS semantic gate, step 1: real OOS text must exist.
    # `--require-real-oos` turns the absence of imported bounty OOS text
    # into a HARD FAIL (exit 4) rather than the legacy silent no-op.
    if args.require_real_oos and not args.oos_file:
        oos_status = real_oos_text_status(ws_path)
        if not oos_status["real_oos"]:
            _eprint(
                "[per-finding-oos-check] require-real-oos HARD FAIL: "
                f"{oos_status['reason']}"
            )
            print(
                "[per-finding-oos-check] verdict=missing-real-oos "
                f"workspace={ws_path}"
            )
            print(f"  reason: {oos_status['reason']}")
            print(
                "  operator action: import the current bounty Out-of-Scope "
                "text into OOS_PASTED.md (operator-oos-import.py) or fill "
                "OOS_CHECKLIST.md with real non-TBD bullets."
            )
            return 4

    # Explicit --oos-file override: point the semantic check at a given
    # OOS clause source (e.g. a representative fixture) instead of
    # <workspace>/OOS_PASTED.md.
    if args.oos_file:
        oos_file_path = Path(args.oos_file).expanduser()
        if not oos_file_path.is_file():
            _eprint(
                f"[per-finding-oos-check] --oos-file not found: {oos_file_path}"
            )
            return 1
        manifest = _read_manifest_from_file(oos_file_path)
    else:
        manifest = _read_pasted_manifest(ws_path)
    if manifest is None:
        # No operator paste → there is nothing for this tool to do; the
        # pre-submit gate is conditional on OOS_PASTED.md existing.
        pasted_path = ws_path / "OOS_PASTED.md"
        if pasted_path.exists():
            _eprint(
                f"[per-finding-oos-check] OOS_PASTED.md under {ws_path} has no "
                "machine-readable manifest block; import the pasted clauses with "
                "operator-oos-import.py or use a manual sidecar"
            )
            return 1
        _eprint(
            f"[per-finding-oos-check] no OOS_PASTED.md under {ws_path}; "
            "nothing to check"
        )
        return 1

    clauses = manifest.get("clauses", [])
    if not clauses:
        _eprint("[per-finding-oos-check] OOS_PASTED.md has no clauses")
        return 1

    finding_text = finding_path.read_text(encoding="utf-8", errors="replace")
    finding_sha = _sha256_text(finding_text)

    repo_root = Path(__file__).resolve().parents[1]

    if args.llm:
        mode = "llm"
    elif args.manual:
        mode = "manual"
    else:
        mode = "heuristic"

    per_clause: list[dict[str, str]] = []
    for clause in clauses:
        if mode == "heuristic":
            verdict, evidence = heuristic_check(clause["text"], finding_text)
        elif mode == "llm":
            verdict, evidence = llm_check(
                clause=clause,
                finding_text=finding_text,
                repo_root=repo_root,
            )
        else:  # manual
            verdict, evidence = manual_check(clause)
        per_clause.append({
            "id": clause["id"],
            "text": clause["text"],
            "verdict": verdict,
            "evidence": evidence,
        })

    top_verdict = resolve_top_verdict(per_clause)

    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "date": _utc_now_iso(),
        "workspace": str(ws_path),
        "finding": str(finding_path),
        "finding_sha256": finding_sha,
        "mode": mode,
        "oos_pasted_clauses_hash": manifest.get("clauses_hash", ""),
        "clauses_checked": per_clause,
        "verdict": top_verdict,
    }

    # JSON canonical artifact under <ws>/.auditooor/
    auditooor_dir = ws_path / ".auditooor"
    auditooor_dir.mkdir(parents=True, exist_ok=True)
    json_path = auditooor_dir / f"oos_check_{finding_sha}.json"
    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Markdown sidecar
    if args.out:
        md_path = Path(args.out).expanduser()
    else:
        md_path = finding_path.with_name("OOS_CHECK.md")
    md_path.write_text(render_markdown(payload), encoding="utf-8")

    if args.print_paths:
        print(str(json_path))
        print(str(md_path))
    print(
        f"[per-finding-oos-check] verdict={top_verdict} "
        f"clauses={len(per_clause)} mode={mode}"
    )
    print(f"  json: {json_path}")
    print(f"  md:   {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
