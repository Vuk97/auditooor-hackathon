#!/usr/bin/env python3
# r36-rebuttal: LIFT-12 lane pathspec registered via
# tools/agent-pathspec-register.py for agent_id
# LIFT-12-CHAIN-CANDIDATES-GLOBAL-SEED; entry lives in
# .auditooor/agent_pathspec.json with TTL 2h.
"""LIFT-12 helpers: seed ``vault_hackerman_chain_candidates`` from the
2550-entry ``audit/corpus_tags/derived/global_chain_templates.jsonl``
corpus (Phase 3, task #179) by intersecting each template's
``member_invariant_ids`` with the workspace's broken-invariant set.

The MCP callable already surfaces per-workspace candidates from the
``swarm/chain_unify_payload.json`` sidecar. The Phase-3 global library
was never wired into the callable, so the operator's cross-target chain
templates (2550 records covering FRE / CUS / CON / BND / AUT / ATM /
UNI / ORD / MON / DET / BRIDGE families) remained invisible to the
hackerman recall surface.

This module is the read-only intersection layer. It does not write any
state and does not depend on the MCP server module so it can be unit-
tested in isolation.

Public surface:

* ``WS_FAMILY_TO_GLOBAL_PREFIX`` - mapping from workspace short-form
  family tokens (AUTH, CUST, FRESH) to global long-form prefixes
  (AUT, CUS, FRE).
* ``extract_invariant_ids_from_text(text) -> set[str]``
* ``load_workspace_broken_invariants(workspace_path) -> dict``
* ``expand_workspace_family_prefixes(invariant_ids) -> set[str]``
* ``load_global_chain_templates(templates_path, invariant_ids,
  family_prefixes, limit) -> dict``

Backward compatibility:

* All functions return empty results gracefully on any I/O or parse
  error. They never raise.
* The MCP server's existing per-WS sidecar behavior is untouched. The
  global-template surface is additive (the server appends a
  ``global_template_candidates`` list to its response).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


# Family prefix mapping (workspace short-form -> global long-form).
# The workspace's invariant ledger / semantic_predicate_gate uses
# legacy short forms (INV-AUTH-001) AND new long forms (INV-CON-EX-0006).
# The global_chain_templates.jsonl uses long-form prefixes only:
# AUT, ATM, BND, BRIDGE, CON, CUS, DET, FRE, MON, ORD, UNI.
WS_FAMILY_TO_GLOBAL_PREFIX = {
    "AUT": "AUT",
    "AUTH": "AUT",
    "ATM": "ATM",
    "BND": "BND",
    "BOUNDS": "BND",
    "BRIDGE": "BRIDGE",
    "CON": "CON",
    "CUS": "CUS",
    "CUST": "CUS",
    "CUSTODY": "CUS",
    "DET": "DET",
    "FRE": "FRE",
    "FRESH": "FRE",
    "FRESHNESS": "FRE",
    "MON": "MON",
    "ORD": "ORD",
    "UNI": "UNI",
}


# Valid global long-form family prefixes (the only families the corpus's
# member_invariant_ids actually use). Used to validate keyword/ledger
# classifications before they are emitted as INV-<PREFIX> fallbacks.
GLOBAL_FAMILY_PREFIXES = frozenset(WS_FAMILY_TO_GLOBAL_PREFIX.values())


# Keyword -> global family prefix classifier. Maps domain keywords found
# in a workspace-local invariant id token OR its ledger family/category/
# description field to one or more global families. Many invariants map to
# more than one family (e.g. a withdrawal-finalization invariant is both a
# CUStody and a FREshness concern), so each keyword yields a set.
#
# Source of the mapping (per the lane spec):
#   withdrawal / finalize -> custody + freshness
#   bridge / lock-mint    -> bridge + conservation
#   anchor / resolve      -> freshness
#   replay / double       -> atomicity
# plus the obvious direct-family keywords (auth, custody, conservation, ...).
WS_KEYWORD_TO_GLOBAL_PREFIXES: dict[str, tuple[str, ...]] = {
    # withdrawal / finalization -> custody + freshness
    "withdraw": ("CUS", "FRE"),
    "withdrawal": ("CUS", "FRE"),
    "finalize": ("CUS", "FRE"),
    "finalization": ("CUS", "FRE"),
    "finalized": ("CUS", "FRE"),
    "finalise": ("CUS", "FRE"),
    # bridge / lock-mint -> bridge + conservation
    "bridge": ("BRIDGE", "CON"),
    "lockmint": ("BRIDGE", "CON"),
    "lock_mint": ("BRIDGE", "CON"),
    "lockandmint": ("BRIDGE", "CON"),
    "mint": ("BRIDGE", "CON"),
    "burn": ("BRIDGE", "CON"),
    "deposit": ("BRIDGE", "CON"),
    # anchor / resolve -> freshness
    "anchor": ("FRE",),
    "resolve": ("FRE",),
    "resolution": ("FRE",),
    "stale": ("FRE",),
    "staleness": ("FRE",),
    "fresh": ("FRE",),
    "freshness": ("FRE",),
    "timestamp": ("FRE",),
    "expiry": ("FRE",),
    "expire": ("FRE",),
    # replay / double -> atomicity
    "replay": ("ATM",),
    "double": ("ATM",),
    "doublespend": ("ATM",),
    "atomic": ("ATM",),
    "atomicity": ("ATM",),
    "reentrancy": ("ATM",),
    "reentrant": ("ATM",),
    # direct-family keywords
    "custody": ("CUS",),
    "custodial": ("CUS",),
    "balance": ("CUS",),
    "solvency": ("CUS",),
    "auth": ("AUT",),
    "authorize": ("AUT",),
    "authorization": ("AUT",),
    "permission": ("AUT",),
    "access": ("AUT",),
    "owner": ("AUT",),
    "conservation": ("CON",),
    "conserve": ("CON",),
    "supply": ("CON",),
    "bound": ("BND",),
    "bounds": ("BND",),
    "overflow": ("BND",),
    "underflow": ("BND",),
    "cap": ("BND",),
    "order": ("ORD",),
    "ordering": ("ORD",),
    "sequence": ("ORD",),
    "nonce": ("ORD",),
    "monoton": ("MON",),
    "increasing": ("MON",),
    "determinism": ("DET",),
    "deterministic": ("DET",),
    "unique": ("UNI",),
    "uniqueness": ("UNI",),
}


_INV_ID_RE = re.compile(r"INV-[A-Z]{2,8}-(?:EX-)?\d{2,5}")

# Workspace-local namespaced invariant id shape, e.g. ``OPTIMISM-INV-01``
# or ``MEZO-INV-7`` or bare ``INV-02``. These carry NO global family tag in
# the id itself; the family must be derived from a ledger field or a
# keyword classifier. Group 1 = workspace token (optional), group 2 = index.
_WS_NAMESPACED_INV_RE = re.compile(
    r"^(?:([A-Z][A-Z0-9_]*)-)?INV-(\d{1,6})$",
    re.IGNORECASE,
)


def classify_text_to_global_prefixes(text: str) -> set[str]:
    """Keyword-classify free text (an invariant name / family / category /
    description token) into a set of global family prefixes (``INV-CUS``,
    ``INV-FRE``, ...). Returns empty set when nothing matches.

    Substring match on a lowercased, separator-stripped form so that
    ``withdrawal_finalized`` and ``finalize-withdrawal`` both hit the
    ``withdraw`` + ``finalize`` keywords."""
    if not text or not isinstance(text, str):
        return set()
    norm = re.sub(r"[^a-z0-9]", "", text.lower())
    if not norm:
        return set()
    out: set[str] = set()
    for kw, prefixes in WS_KEYWORD_TO_GLOBAL_PREFIXES.items():
        if kw in norm:
            for p in prefixes:
                if p in GLOBAL_FAMILY_PREFIXES:
                    out.add(f"INV-{p}")
    return out


def classify_workspace_invariant_families(
    invariant_ids: set[str],
    ledger_meta: dict[str, dict[str, Any]] | None = None,
) -> set[str]:
    """Map a set of (possibly workspace-local-namespaced) invariant ids to
    global family prefixes (``INV-CUS`` ...).

    Resolution per id (first non-empty wins, then union):
      1. Direct family token in the id (``INV-CUST-001`` -> CUS via
         ``WS_FAMILY_TO_GLOBAL_PREFIX``). This preserves the legacy
         short/long-form behavior.
      2. Workspace-local namespace shape (``<WS>-INV-NN`` / ``INV-NN``):
         the id has NO family token, so classify via the ledger row's
         ``family`` / ``category`` / ``invariant_family`` field, else the
         ledger row's ``name`` / ``title`` / ``description`` text, else
         the id string itself - all through the keyword classifier.

    ``ledger_meta`` is an optional ``{invariant_id: row_dict}`` map (the
    raw invariant_ledger row) used to read family/category/description.
    Returns empty set when nothing resolves. Never raises."""
    ledger_meta = ledger_meta or {}
    prefixes: set[str] = set()
    for iid in invariant_ids:
        if not isinstance(iid, str) or not iid:
            continue
        # (1) direct family token, e.g. INV-CUST-001 / INV-CON-EX-0006.
        parts = iid.split("-")
        if len(parts) >= 2:
            mapped = WS_FAMILY_TO_GLOBAL_PREFIX.get(parts[1].upper())
            if mapped:
                prefixes.add(f"INV-{mapped}")
                continue
        # (2) workspace-local namespace shape (<WS>-INV-NN / INV-NN): no
        # family token in the id. Classify via ledger meta then keywords.
        if _WS_NAMESPACED_INV_RE.match(iid):
            row = ledger_meta.get(iid) or {}
            resolved: set[str] = set()
            if isinstance(row, dict):
                # ledger family / category fields first
                for field in (
                    "family", "invariant_family", "category",
                    "family_tag", "class", "attack_class",
                ):
                    val = row.get(field)
                    if isinstance(val, str) and val.strip():
                        direct = WS_FAMILY_TO_GLOBAL_PREFIX.get(
                            val.strip().upper()
                        )
                        if direct:
                            resolved.add(f"INV-{direct}")
                        resolved |= classify_text_to_global_prefixes(val)
                # ledger descriptive text (additive - an invariant is
                # often multi-family, e.g. a withdrawal-double-spend row is
                # custody AND atomicity).
                for field in (
                    "name", "title", "description", "predicate",
                    "statement", "summary",
                ):
                    val = row.get(field)
                    if isinstance(val, str) and val.strip():
                        resolved |= classify_text_to_global_prefixes(val)
            # last resort: keyword-classify the id token itself (e.g. a
            # workspace token like WITHDRAWAL-INV-01).
            if not resolved:
                resolved = classify_text_to_global_prefixes(iid)
            prefixes |= resolved
            continue
        # (3) FINAL fallback: ids that match neither the family-token form (1)
        # nor the strict <WS>-INV-NN namespace (2) - e.g. the broken-feed/driver
        # form `INV-02-portal-no-double-spend` (digits + descriptive slug, which
        # the anchored namespace regex rejects). The slug carries the family
        # keywords, so keyword-classify the whole id. Without this, the
        # chain-synth-driver -> vault_global_chain_template_match handoff yields 0
        # matches even though both fixes are correct in isolation (the id strings
        # never align). Verified: INV-02-portal-no-double-spend -> INV-ATM,
        # INV-04-bridge-lock-mint-conservation -> INV-BRIDGE+INV-CON.
        prefixes |= classify_text_to_global_prefixes(iid)
    return prefixes


def extract_invariant_ids_from_text(text: str) -> set[str]:
    """Regex-extract every ``INV-*`` id from text. Returns empty set on
    falsy or unparseable input."""
    if not text:
        return set()
    try:
        return set(_INV_ID_RE.findall(text))
    except Exception:  # noqa: BLE001 - bounded regex
        return set()


def load_workspace_broken_invariants(workspace_path: Path) -> dict[str, Any]:
    """Load the workspace's broken-invariant set.

    Source order:
      1. ``<ws>/.auditooor/invariant_ledger.json`` rows with status
         in {"broken", "fail", "failed", "violated"} or
         ``broken=True``.
      2. ``<ws>/.auditooor/semantic_predicate_gate.json`` verdicts
         with verdict in {"BROKEN", "FAIL", "VIOLATED", "FAILED",
         "TOPICAL"}. "TOPICAL" is included because the gate's
         dry-run only emits TOPICAL for predicates the scanner
         considered worth investigating (advisory-broken).
      3. Fallback regex sweep of every JSON / JSONL / MD file under
         ``<ws>/.auditooor/`` for ``INV-*`` tokens (only when 1 + 2
         yielded zero ids).

    Returns ``{"invariant_ids": set[str], "source": str,
    "raw_count": int}``. ``source`` is one of ``invariant_ledger`` /
    ``semantic_predicate_gate`` / ``regex_sweep`` / ``none``.
    """
    invariant_ids: set[str] = set()
    source = "none"
    workspace_path = Path(workspace_path).expanduser().resolve()

    # Source 1: invariant_ledger.json
    ledger_path = workspace_path / ".auditooor" / "invariant_ledger.json"
    try:
        if ledger_path.is_file():
            with ledger_path.open("r", encoding="utf-8") as fh:
                ledger = json.load(fh)
            rows = (
                ledger.get("rows") or []
                if isinstance(ledger, dict)
                else []
            )
            for row in rows:
                if not isinstance(row, dict):
                    continue
                iid = (
                    row.get("invariant_id")
                    or row.get("id")
                    or row.get("predicate_id")
                )
                if not iid or not isinstance(iid, str):
                    continue
                status = str(
                    row.get("status") or row.get("verdict") or ""
                ).strip().lower()
                broken_flag = bool(row.get("broken"))
                if broken_flag or status in {
                    "broken", "fail", "failed", "violated", "false",
                }:
                    invariant_ids.add(iid)
            if invariant_ids:
                source = "invariant_ledger"
    except Exception:  # noqa: BLE001 - best-effort
        pass

    # Source 2: semantic_predicate_gate.json verdicts
    if not invariant_ids:
        gate_path = (
            workspace_path / ".auditooor" / "semantic_predicate_gate.json"
        )
        try:
            if gate_path.is_file():
                with gate_path.open("r", encoding="utf-8") as fh:
                    gate = json.load(fh)
                verdicts = (
                    gate.get("verdicts") or []
                    if isinstance(gate, dict)
                    else []
                )
                advisory_verdict_values = {
                    "broken", "fail", "failed", "violated", "topical",
                }
                for v in verdicts:
                    if not isinstance(v, dict):
                        continue
                    pid = v.get("predicate_id") or v.get("invariant_id")
                    if not pid or not isinstance(pid, str):
                        continue
                    verdict_val = str(v.get("verdict") or "").strip().lower()
                    if verdict_val in advisory_verdict_values:
                        invariant_ids.add(pid)
                if invariant_ids:
                    source = "semantic_predicate_gate"
        except Exception:  # noqa: BLE001
            pass

    # Source 3: fallback regex sweep
    if not invariant_ids:
        ws_dir = workspace_path / ".auditooor"
        try:
            if ws_dir.is_dir():
                for root, _dirs, files in os.walk(str(ws_dir)):
                    for fn in files:
                        if not (
                            fn.endswith(".json")
                            or fn.endswith(".jsonl")
                            or fn.endswith(".md")
                        ):
                            continue
                        fp = Path(root) / fn
                        try:
                            with fp.open(
                                "r", encoding="utf-8", errors="ignore"
                            ) as fh:
                                txt = fh.read(2_000_000)  # 2MB cap per file
                        except Exception:  # noqa: BLE001
                            continue
                        invariant_ids.update(
                            extract_invariant_ids_from_text(txt)
                        )
                if invariant_ids:
                    source = "regex_sweep"
        except Exception:  # noqa: BLE001
            pass

    return {
        "invariant_ids": invariant_ids,
        "source": source,
        "raw_count": len(invariant_ids),
    }


def expand_workspace_family_prefixes(
    invariant_ids: set[str],
    ledger_meta: dict[str, dict[str, Any]] | None = None,
) -> set[str]:
    """Derive global-form family prefixes (``INV-AUT``, ``INV-CUS``,
    ...) from the workspace's invariant ids. Used as fallback when no
    exact-id intersection exists between workspace and global
    templates.

    Handles both the legacy family-tagged shape (``INV-CUST-001`` -> CUS)
    AND the workspace-local namespaced shape (``OPTIMISM-INV-01`` /
    ``INV-02``) that carries no family token. For the latter the family is
    classified from the optional ``ledger_meta`` row (family / category /
    description) or, as a last resort, the id token itself.

    Backward compatible: when ``ledger_meta`` is omitted the legacy
    family-tagged ids resolve exactly as before; only the previously
    silently-dropped namespaced ids gain a keyword-classifier fallback."""
    return classify_workspace_invariant_families(invariant_ids, ledger_meta)


def _make_candidate_row(
    rec: dict[str, Any],
    matched_ids: set[str],
    match_mode: str,
    tuple_size: int,
) -> dict[str, Any]:
    """Build the candidate row payload for one matched template."""
    member_ids = sorted(
        {str(m) for m in (rec.get("member_invariant_ids") or [])}
    )
    return {
        "chain_template_id": rec.get("chain_template_id") or "",
        "member_invariant_ids": member_ids,
        "matched_ids": sorted(matched_ids),
        "matched_count": len(matched_ids),
        "match_density": (
            len(matched_ids) / max(tuple_size, 1)
        ),
        "match_mode": match_mode,
        "tuple_size": tuple_size,
        "evidence_incidents": list(
            rec.get("evidence_incidents") or []
        )[:8],
        "verification_tier": rec.get("verification_tier") or "",
        "composition_score": rec.get("composition_score"),
        "member_categories": list(
            rec.get("member_categories") or []
        )[:10],
    }


def load_global_chain_templates(
    templates_path: Path,
    invariant_ids: set[str],
    family_prefixes: set[str],
    limit: int,
) -> dict[str, Any]:
    """Scan ``global_chain_templates.jsonl`` for templates whose
    ``member_invariant_ids`` intersect the workspace's broken-invariant
    set. Prefers exact-id intersection; falls back to family-prefix
    intersection when no exact matches exist.

    Returns ``{candidates: list[dict], total_scanned: int,
    templates_path_label: str, match_mode: "exact"|"family"|"none",
    exact_match_count: int, family_match_count: int}``.
    """
    templates_path = Path(templates_path).expanduser().resolve()
    candidates_exact: list[dict[str, Any]] = []
    candidates_family: list[dict[str, Any]] = []
    total = 0

    if not templates_path.is_file():
        return {
            "candidates": [],
            "total_scanned": 0,
            "templates_path_label": str(templates_path),
            "match_mode": "none",
            "reason": "templates_jsonl_missing",
            "exact_match_count": 0,
            "family_match_count": 0,
        }

    try:
        with templates_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    rec = json.loads(line)
                except Exception:  # noqa: BLE001 - skip malformed
                    continue
                if not isinstance(rec, dict):
                    continue
                member_ids = rec.get("member_invariant_ids") or []
                if not isinstance(member_ids, list):
                    continue
                member_set = {
                    str(m) for m in member_ids if isinstance(m, str)
                }
                if not member_set:
                    continue
                tuple_size = int(
                    rec.get("tuple_size") or len(member_set) or 1
                )
                exact_match = (
                    member_set & invariant_ids if invariant_ids else set()
                )
                if exact_match:
                    candidates_exact.append(
                        _make_candidate_row(
                            rec, exact_match, "exact", tuple_size
                        )
                    )
                    continue
                if family_prefixes:
                    family_hits = {
                        m for m in member_set
                        if any(
                            m.startswith(p + "-") for p in family_prefixes
                        )
                    }
                    if family_hits:
                        candidates_family.append(
                            _make_candidate_row(
                                rec, family_hits, "family", tuple_size
                            )
                        )
    except Exception as exc:  # noqa: BLE001 - bounded I/O
        return {
            "candidates": [],
            "total_scanned": total,
            "templates_path_label": str(templates_path),
            "match_mode": "none",
            "reason": f"scan_error: {exc}",
            "exact_match_count": 0,
            "family_match_count": 0,
        }

    if candidates_exact:
        candidates_exact.sort(
            key=lambda r: (
                -r["matched_count"],
                -r["match_density"],
                r.get("chain_template_id") or "",
            )
        )
        return {
            "candidates": candidates_exact[:limit],
            "total_scanned": total,
            "templates_path_label": str(templates_path),
            "match_mode": "exact",
            "exact_match_count": len(candidates_exact),
            "family_match_count": len(candidates_family),
        }

    if candidates_family:
        candidates_family.sort(
            key=lambda r: (
                -r["matched_count"],
                -r["match_density"],
                r.get("chain_template_id") or "",
            )
        )
        return {
            "candidates": candidates_family[:limit],
            "total_scanned": total,
            "templates_path_label": str(templates_path),
            "match_mode": "family",
            "exact_match_count": 0,
            "family_match_count": len(candidates_family),
        }

    return {
        "candidates": [],
        "total_scanned": total,
        "templates_path_label": str(templates_path),
        "match_mode": "none",
        "exact_match_count": 0,
        "family_match_count": 0,
    }


__all__ = [
    "WS_FAMILY_TO_GLOBAL_PREFIX",
    "GLOBAL_FAMILY_PREFIXES",
    "WS_KEYWORD_TO_GLOBAL_PREFIXES",
    "extract_invariant_ids_from_text",
    "load_workspace_broken_invariants",
    "expand_workspace_family_prefixes",
    "classify_text_to_global_prefixes",
    "classify_workspace_invariant_families",
    "load_global_chain_templates",
]
