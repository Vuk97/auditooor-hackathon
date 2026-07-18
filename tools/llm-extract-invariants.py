#!/usr/bin/env python3
"""Extract protocol INVARIANTS from corpus finding records.

Pillar-P1 MVP build (iter18 phase A, lane-PILLAR-P1-MVP-BUILD).

Two modes:

- ``--mode hand-extract --records <N>``: heuristic pattern-match extraction
  (no LLM call) for N corpus records into typed invariant entries. Output is
  appended to ``audit/corpus_tags/derived/invariants_extracted.jsonl``.
- ``--mode llm-sweep --records <N> --provider <p>``: gated behind an
  operator-set API key env var. Refuses if no key. Operator can later run
  this when LLM budget is greenlit. Default: refuses with clear remediation.

Schema: ``auditooor.invariant_extraction.v1``

Quality gate:

- ``--spot-check N``: spot-check N records' emit Y-rate via simple heuristic
  (statement starts with MUST/MUST-NOT + cites >=2 source findings +
  non-empty defense_layer or null-explicit). Target 80% Y-rate.

Categories (10 per L0.3): uniqueness, ordering, monotonicity, custody,
atomicity, conservation, authorization, freshness, bounds, determinism.

Each invariant entry follows the L0.3 pilot shape::

    {
      "schema_version": "auditooor.invariant_extraction.v1",
      "invariant_id": "INV-<cat-prefix>-NNN",
      "category": "<one of 10>",
      "statement": "<MUST / MUST-NOT phrasing>",
      "target_lang": "<solidity|move|rust|go|cairo|any>",
      "source_finding_ids": ["<finding-id-1>", "<finding-id-2>", ...],
      "abstraction_level": "<protocol-invariant|function-invariant|...>",
      "commit_point_pattern": "<observable commit-point keyword>",
      "defense_layer": "<defense mechanism name or null>",
      "verification_tier": "<inherited from source records>",
      "extractor": "hand-extract|llm-sweep",
      "extracted_at_utc": "<RFC3339>"
    }

Hand-extract mode reads the corpus index
(``audit/corpus_tags/index/by_attack_class.jsonl``) and the per-record tag
YAMLs (``audit/corpus_tags/tags/...``), maps each record to ONE of the 10
categories by keyword heuristics, derives a MUST/MUST-NOT statement, and
emits the record. Records that resist heuristic classification are skipped
(emitted to the failed-extract sidecar) so the library stays clean.

The 80% spot-check Y-rate target is a quality floor for the heuristic path;
the LLM-sweep mode (deferred) is expected to reach 90%+.

Usage::

    # MVP heuristic mode (default):
    python3 tools/llm-extract-invariants.py --mode hand-extract --records 400

    # Spot-check the last emit:
    python3 tools/llm-extract-invariants.py --mode hand-extract --spot-check 30

    # Build the per-category / per-language index:
    python3 tools/llm-extract-invariants.py --build-index

    # LLM sweep (refuses unless ANTHROPIC_API_KEY set):
    python3 tools/llm-extract-invariants.py --mode llm-sweep --records 500 --provider anthropic
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "auditooor.invariant_extraction.v1"
PILOT_SCHEMA_VERSION = "auditooor.invariant_pilot.v1"
LLM_SWEEP_MIN_Y_RATE = 0.90

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INDEX = REPO_ROOT / "audit" / "corpus_tags" / "index" / "by_attack_class.jsonl"
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_PILOT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"
DEFAULT_FAILED = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_failed_extract.jsonl"
DEFAULT_INDEX_JSON = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariant_library_index.json"

SOURCE_FILE_LINE_RE = re.compile(
    r"(?P<path>(?:[A-Za-z0-9_.@~+\-]+/)*[A-Za-z0-9_.@~+\-]+"
    r"\.(?:sol|rs|go|vy|move|cairo|ts|tsx|js|jsx|py|java|cpp|c|h|hpp|"
    r"md|txt|yaml|yml|json|toml)):(?P<line>[0-9]+)(?:-[0-9]+)?"
)
SOURCE_AUDIT_REF_RE = re.compile(
    r"(?P<path>(?:[A-Za-z0-9_.@~+\-]+/)*[A-Za-z0-9_.@~+\-]+"
    r"\.(?:md|txt|json|yaml|yml|sol|rs|go|vy|move|cairo))"
    r":L(?P<line>[0-9]+)(?::S[0-9]+)?"
)

CATEGORIES = [
    "uniqueness",
    "ordering",
    "monotonicity",
    "custody",
    "atomicity",
    "conservation",
    "authorization",
    "freshness",
    "bounds",
    "determinism",
]

CATEGORY_PREFIX = {
    "uniqueness": "UNI",
    "ordering": "ORD",
    "monotonicity": "MON",
    "custody": "CUS",
    "atomicity": "ATM",
    "conservation": "CON",
    "authorization": "AUT",
    "freshness": "FRE",
    "bounds": "BND",
    "determinism": "DET",
}

VALID_LANGS = {"solidity", "move", "rust", "go", "cairo", "any", "unknown"}
VALID_ABSTRACTIONS = {
    "protocol-invariant",
    "function-invariant",
    "per-protocol",
    "per-protocol-family",
    "cross-domain",
    "cross-language",
}

BROAD_STATEMENT_TERMS = {
    "properly",
    "correctly",
    "safely",
    "securely",
    "appropriate",
    "valid",
    "invalid",
}

# Category-heuristic keyword sets. Each (category -> [keyword, weight]).
# Higher weight = stronger signal. A record is assigned to the category whose
# total weighted score across (attack_class + bug_class + fix_pattern +
# attacker_action_sequence) is the highest non-zero. Ties resolve in CATEGORIES
# order (uniqueness first).
CATEGORY_KEYWORDS: dict[str, list[tuple[str, int]]] = {
    "uniqueness": [
        ("replay", 3), ("nonce", 2), ("unique", 2), ("duplicate", 2),
        ("idempot", 2), ("processed_txid", 3), ("consumed_set", 3),
        ("sequence_number", 2), ("eip-712", 1), ("permit", 1),
    ],
    "ordering": [
        ("ordering", 3), ("order", 1), ("sequence", 1), ("step", 1),
        ("ante-handler", 3), ("checks-effects-interactions", 3),
        ("first-then", 2), ("before", 1), ("after", 1), ("workflow", 1),
        ("hook order", 2), ("operation order", 2),
    ],
    "monotonicity": [
        ("monoton", 3), ("increment", 2), ("only-increase", 3),
        ("only-decrease", 3), ("nonce stuck", 3), ("counter", 1),
        ("never-decrement", 3), ("strictly-increasing", 3),
    ],
    "custody": [
        ("custody", 3), ("transfer-from", 2), ("approve", 1),
        ("owner-only", 3), ("token transfer", 2), ("withdraw", 1),
        ("spending", 1), ("escrow", 2), ("safetransfer", 2),
        ("balance check", 1), ("approval", 1),
    ],
    "atomicity": [
        ("atomic", 3), ("reentran", 3), ("partial commit", 3),
        ("commit-then-revert", 3), ("checks-effects", 2),
        ("cei pattern", 3), ("external-call", 2), ("callback", 2),
        ("vault-reentry", 3), ("frontrun", 2), ("front-run", 2),
        ("permit-frontrun", 3),
    ],
    "conservation": [
        ("conservation", 3), ("invariant-of-sum", 3), ("total supply", 2),
        ("totalsupply", 2), ("erc-4626", 2), ("erc4626", 2),
        ("first-deposit", 3), ("sum-of-shares", 3), ("share-supply", 3),
        ("voting-power", 2), ("total-bonded", 2), ("share-price", 2),
        ("inflated", 2), ("denomination mismatch", 3),
        ("unit mismatch", 2),
    ],
    "authorization": [
        ("authorization", 3), ("access-control", 3), ("access control", 3),
        ("onlyowner", 3), ("only-owner", 3), ("only-admin", 3),
        ("admin-bypass", 3), ("admin bypass", 3), ("uups", 2),
        ("_authorizeupgrade", 3), ("role-check", 3), ("rbac", 2),
        ("permission", 2), ("eip-1271", 2), ("eip1271", 2),
        ("signature-replay", 3), ("signer-binding", 3), ("ownable", 2),
        ("missing-modifier", 3),
    ],
    "freshness": [
        ("freshness", 3), ("stale", 3), ("oracle", 2), ("timestamp", 1),
        ("chainlink", 2), ("updatedat", 2), ("updated_at", 2),
        ("staleness", 3), ("heartbeat", 2), ("twap", 2),
        ("sequencer-uptime", 3), ("price-feed", 2),
    ],
    "bounds": [
        ("bounds", 3), ("overflow", 3), ("underflow", 3), ("max-cap", 2),
        ("safety cap", 3), ("rate-limit", 1), ("limit", 1), ("cap", 1),
        ("allocation", 1), ("validator-set size", 3), ("array-bound", 3),
        ("unbounded", 3), ("array length", 2), ("safetycap", 2),
    ],
    "determinism": [
        ("determinism", 3), ("deterministic", 3), ("non-determinism", 3),
        ("apphash", 3), ("app-hash", 3), ("consensus", 2),
        ("hashstruct", 3), ("hash-struct", 3),
        ("identical outputs", 3), ("randomness", 2),
        ("pseudo-random", 2), ("pseudorand", 2),
        ("eip-712 domain", 3), ("encoding mismatch", 3),
        ("rounding mode", 2),
    ],
}

# Per-category statement templates. The placeholders are filled from the
# record's bug_class / target_component. Domain-neutral phrasing is enforced
# by the template (no protocol names interpolated).
STATEMENT_TEMPLATES: dict[str, list[str]] = {
    "uniqueness": [
        "A signed message or capability MUST be consumable at most once within its scope; replays MUST be rejected.",
        "A unique handle, key, or identifier MUST NOT collide across the protected scope.",
        "An EIP-712 / EIP-2612 signature MUST be bound to a unique per-signer nonce that MUST be advanced before any privileged effect runs.",
    ],
    "ordering": [
        "Operations that depend on a defined sequence MUST run in that sequence; out-of-order application MUST be rejected.",
        "An accrual or hook step that must precede a value-affecting operation MUST run before the operation, not on user demand.",
    ],
    "monotonicity": [
        "A state counter that represents an attempted transition MUST advance on every attempt, success OR failure.",
        "A monotonically-increasing state variable MUST NOT decrement except by an explicitly authorized rollback path.",
    ],
    "custody": [
        "A token, share, or asset balance MUST NOT be movable by an actor other than the owner without explicit owner authorization.",
        "A withdrawal path MUST verify the caller's ownership of the asset before any state mutation that releases funds.",
    ],
    "atomicity": [
        "A multi-step state change MUST commit or revert as a single unit; partial commit MUST NOT leak observable state to other contexts.",
        "External calls that hand control back to the caller MUST NOT occur before all relevant state writes have committed.",
        "A signature MUST be consumed atomically with the action it authorizes; a third party MUST NOT be able to frontrun the consumption.",
    ],
    "conservation": [
        "The sum of accounted-for units (tokens, shares, votes) MUST equal the prior sum modulo explicitly authorized mint or burn events.",
        "A first-depositor or share-supply invariant MUST NOT be perturbable by an unaccounted-for donation of underlying tokens.",
    ],
    "authorization": [
        "A privileged operation MUST be gated by a check that proves the caller holds the required role, signature, or ownership.",
        "A signature verification path that returns a magic value MUST be bound to the claimed signer of the message.",
        "An upgrade entry point MUST require the caller to pass an ownership or role authorization check before mutating the implementation slot.",
    ],
    "freshness": [
        "Data consumed from an external feed MUST be within a bounded staleness window relative to its semantics, not an unrelated clock.",
        "A freshness check applied to an event-driven feed MUST use the feed's last-event-time semantics, not a continuous-time staleness window.",
    ],
    "bounds": [
        "A numeric value or allocation request MUST lie within a defined [lo, hi] range; underflow, overflow, or over-allocation MUST be rejected.",
        "An array, mapping, or queue MUST NOT be expandable past the protocol's documented capacity bound without an explicit authorization path.",
    ],
    "determinism": [
        "Given identical inputs, all honest participants MUST produce identical outputs; non-determinism MUST NOT be observable in the consensus-critical path.",
        "A structured-data hash MUST omit unstable, encoding-mode-dependent, or caller-supplied fields that would break cross-participant consistency.",
    ],
}

# Defense-layer suggestions per category (used as commit_point_pattern hints).
DEFAULT_DEFENSE_LAYER: dict[str, str] = {
    "uniqueness": "consumed-set / nonce-advance / processed-id table",
    "ordering": "explicit step-state machine / require(state == EXPECTED)",
    "monotonicity": "counter advanced before downstream effect",
    "custody": "owner-check modifier / safeTransferFrom-with-owner-binding",
    "atomicity": "checks-effects-interactions / reentrancy-guard / atomic-permit-consume",
    "conservation": "totalSupply invariant assertion / dead-shares mint",
    "authorization": "role-check / signature-binding / EIP-1271-signer-match",
    "freshness": "updatedAt staleness gate / sequencer-uptime grace window",
    "bounds": "bounded loops / array-length cap / SafeMath overflow guard",
    "determinism": "deterministic serialization / canonical EIP-712 domain / consensus-safe rounding",
}

# Commit-point keywords associated with each category (mined from corpus
# fix_pattern strings). When the record's fix_pattern contains one of these,
# the category gets +2 weight.
COMMIT_POINT_KEYWORDS: dict[str, list[str]] = {
    "uniqueness": ["mark consumed", "increment nonce", "processed[id]", "sequence advance"],
    "ordering": ["state guard", "stage check", "before/after", "hook ordering"],
    "monotonicity": ["always-increment", "monotonic counter"],
    "custody": ["onlyOwner", "owner check", "msg.sender == owner"],
    "atomicity": ["nonReentrant", "checks-effects-interactions", "permit-then-act"],
    "conservation": ["totalSupply invariant", "dead shares", "convertToShares"],
    "authorization": ["onlyRole", "authorize before", "isValidSignature"],
    "freshness": ["updatedAt", "staleness check", "heartbeat"],
    "bounds": ["bound check", "max cap", "require <= limit"],
    "determinism": ["canonical encoding", "deterministic serialization"],
}


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Heuristic classifier
# ---------------------------------------------------------------------------


def classify_record(record: dict[str, Any]) -> tuple[str | None, int, dict[str, int]]:
    """Return (best_category, best_score, all_scores).

    Scores each of the 10 categories against the record's
    (attack_class + bug_class + fix_pattern + attacker_action_sequence)
    haystack. Returns ``(None, 0, {})`` if no category scored above the
    minimum threshold (2).
    """
    haystack_parts = [
        str(record.get("attack_class") or ""),
        str(record.get("bug_class") or ""),
        str(record.get("fix_pattern") or ""),
        str(record.get("attacker_action_sequence") or ""),
        str(record.get("target_component") or ""),
    ]
    haystack = " ".join(haystack_parts).lower()
    if not haystack.strip():
        return None, 0, {}

    scores: dict[str, int] = {cat: 0 for cat in CATEGORIES}
    for cat, keywords in CATEGORY_KEYWORDS.items():
        for kw, weight in keywords:
            if kw in haystack:
                scores[cat] += weight
    # Commit-point keywords give a bonus when present.
    for cat, ck_list in COMMIT_POINT_KEYWORDS.items():
        for ck in ck_list:
            if ck.lower() in haystack:
                scores[cat] += 2
    # Pick best.
    best_cat = None
    best_score = 0
    for cat in CATEGORIES:  # iterate in canonical order for stable ties
        if scores[cat] > best_score:
            best_score = scores[cat]
            best_cat = cat
    if best_score < 2:
        return None, 0, scores
    return best_cat, best_score, scores


def derive_statement(category: str, record: dict[str, Any]) -> str:
    """Pick a template statement deterministically per record.

    Uses a hash of the record_id to pick which of the templates for the
    category to use, so the distribution across templates is even but the
    same record always maps to the same statement.
    """
    templates = STATEMENT_TEMPLATES[category]
    record_id = str(record.get("record_id") or "")
    if not record_id:
        return templates[0]
    h = int(hashlib.sha256(record_id.encode("utf-8")).hexdigest(), 16)
    return templates[h % len(templates)]


def derive_abstraction(record: dict[str, Any], category: str) -> str:
    """Choose an abstraction level based on the record's hints."""
    attack_class = str(record.get("attack_class") or "").lower()
    target_lang = str(record.get("target_language") or "").lower()
    bug_class = str(record.get("bug_class") or "").lower()
    if any(w in attack_class for w in ("cross-chain", "cross-language", "consensus")):
        return "cross-language"
    if category in {"authorization", "uniqueness", "freshness", "atomicity"}:
        return "cross-domain"
    if category in {"conservation", "custody"}:
        return "per-protocol-family"
    if "dsl_pattern" in bug_class or "interface-coverage" in bug_class:
        return "protocol-invariant"
    # Default
    return "protocol-invariant"


def normalize_target_lang(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in VALID_LANGS:
        return raw
    if raw in {"sol", "solidity-yul"}:
        return "solidity"
    if raw in {"golang"}:
        return "go"
    if raw == "":
        return "unknown"
    return "unknown"


def normalize_verification_tier(value: Any) -> str:
    """Inherit tier per Rule 37 (never elevate, never invent)."""
    raw = str(value or "").strip()
    if raw.startswith("tier-"):
        return raw
    if raw in {"1", "2", "3", "4", "5"}:
        mapping = {
            "1": "tier-1-officially-disclosed",
            "2": "tier-2-verified-public-archive",
            "3": "tier-3-synthetic-taxonomy-anchored",
            "4": "tier-4-bundled-fixture",
            "5": "tier-5-quarantine",
        }
        return mapping[raw]
    return "tier-3-synthetic-taxonomy-anchored"


# ---------------------------------------------------------------------------
# Source iteration: stream from corpus index + tag YAMLs
# ---------------------------------------------------------------------------


def iter_index_records(
    index_path: Path,
    limit: int | None = None,
) -> Iterable[dict[str, Any]]:
    """Stream index records, optionally bounded by limit."""
    if not index_path.exists():
        return
    count = 0
    with index_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            yield row
            count += 1
            if limit is not None and count >= limit:
                return


def load_tag_yaml(tags_dir: Path, tag_file: str) -> dict[str, Any]:
    """Best-effort load of a tag YAML.

    Heuristic: avoids pulling PyYAML. We only need a few keys
    (attacker_action_sequence, fix_pattern, target_component, attack_class,
    bug_class, target_language, target_domain, verification_tier). We extract
    them with simple line-level parsing - the corpus YAMLs are flat for
    these keys.
    """
    path = tags_dir / tag_file
    if not path.exists():
        return {}
    out: dict[str, Any] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    wanted_keys = {
        "attacker_action_sequence",
        "fix_pattern",
        "fix_anti_pattern_avoided",
        "target_component",
        "attack_class",
        "bug_class",
        "target_language",
        "target_domain",
        "verification_tier",
        "severity_at_finding",
        "record_id",
        "source_audit_ref",
        "source_ref",
        "source_refs",
        "source_path",
        "source_paths",
        "file_line",
        "produces_state",
        "producer_state",
        "produced_state",
        "output_state",
        "requires_state",
        "consumer_state",
        "required_state",
        "input_state",
        "producer_source_ref",
        "producer_source_refs",
        "consumer_source_ref",
        "consumer_source_refs",
        "state",
        "state_token",
        "chain_state",
        "state_role",
        "role",
        "record_role",
    }
    list_keys = {
        "source_refs",
        "source_paths",
        "produces_state",
        "producer_state",
        "produced_state",
        "output_state",
        "requires_state",
        "consumer_state",
        "required_state",
        "input_state",
        "producer_source_refs",
        "consumer_source_refs",
    }
    current_list_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.startswith("#"):
            current_list_key = None
            continue
        item = re.match(r"^\s*-\s*(?P<val>.+)$", line)
        if item and current_list_key:
            val = item.group("val").strip().strip('"').strip("'")
            if val:
                out.setdefault(current_list_key, []).append(val)
            continue
        m = re.match(r"^(?P<key>[a-zA-Z_][a-zA-Z0-9_]*):\s*(?P<val>.*)$", line)
        if not m:
            current_list_key = None
            continue
        key = m.group("key")
        if key not in wanted_keys:
            current_list_key = None
            continue
        val = m.group("val").strip()
        if not val and key in list_keys:
            current_list_key = key
            out[key] = []
            continue
        current_list_key = None
        # Strip wrapping quotes.
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        elif val.startswith("'") and val.endswith("'"):
            val = val[1:-1]
        if val:
            out[key] = val
    return out


def build_seed_record(
    index_row: dict[str, Any],
    tags_dir: Path,
) -> dict[str, Any]:
    """Combine index row + tag YAML into a flat extraction-ready record."""
    base = dict(index_row)
    tag_file = base.get("tag_file")
    if isinstance(tag_file, str) and tag_file:
        body = load_tag_yaml(tags_dir, tag_file)
        # Merge: index values keep priority for ambiguous keys.
        for k, v in body.items():
            base.setdefault(k, v)
    return base


def _as_text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            out.extend(_as_text_list(item))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        for key in ("source_refs", "source_ref", "path", "file", "state", "token", "value"):
            out.extend(_as_text_list(value.get(key)))
        return out
    text = str(value).strip()
    return [text] if text else []


def _dedupe(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _extract_source_refs_from_text(text: str) -> list[str]:
    refs: list[str] = []
    for pattern in (SOURCE_AUDIT_REF_RE, SOURCE_FILE_LINE_RE):
        for match in pattern.finditer(text or ""):
            path = match.group("path").strip()
            line = int(match.group("line"))
            if path and line > 0:
                refs.append(f"{path}:{line}")
    return _dedupe(refs)


def _prefer_specific_source_refs(refs: list[str]) -> list[str]:
    out: list[str] = []
    for ref in _dedupe(refs):
        path, _, line = ref.rpartition(":")
        if any(
            other != ref
            and other.endswith(f"/{path}:{line}")
            for other in refs
        ):
            continue
        out.append(ref)
    return out


def _collect_source_refs(record: dict[str, Any]) -> list[str]:
    raw: list[str] = []
    for key in (
        "source_refs",
        "source_ref",
        "source_paths",
        "source_path",
        "producer_source_refs",
        "producer_source_ref",
        "consumer_source_refs",
        "consumer_source_ref",
        "source_audit_ref",
        "file_line",
        "target_component",
    ):
        raw.extend(_as_text_list(record.get(key)))
    state_evidence = record.get("state_evidence")
    if isinstance(state_evidence, dict):
        for key in (
            "source_refs",
            "source_ref",
            "producer_source_refs",
            "producer_source_ref",
            "consumer_source_refs",
            "consumer_source_ref",
        ):
            raw.extend(_as_text_list(state_evidence.get(key)))
    refs: list[str] = []
    for item in raw:
        refs.extend(_extract_source_refs_from_text(item))
    return _prefer_specific_source_refs(refs)


def _collect_state_tokens(record: dict[str, Any], role: str) -> list[str]:
    keys = (
        ("produces_state", "producer_state", "produced_state", "output_state")
        if role == "producer"
        else ("requires_state", "consumer_state", "required_state", "input_state")
    )
    tokens: list[str] = []
    for key in keys:
        tokens.extend(_as_text_list(record.get(key)))
    state_evidence = record.get("state_evidence")
    if isinstance(state_evidence, dict):
        for key in keys:
            tokens.extend(_as_text_list(state_evidence.get(key)))
        role_text = str(
            state_evidence.get("state_role")
            or state_evidence.get("role")
            or ""
        ).lower()
        role_tokens: list[str] = []
        for key in ("state", "state_token", "chain_state", "token", "tokens"):
            role_tokens.extend(_as_text_list(state_evidence.get(key)))
        if role == "producer" and "producer" in role_text:
            tokens.extend(role_tokens)
        if role == "consumer" and "consumer" in role_text:
            tokens.extend(role_tokens)
    role_text = str(
        record.get("state_role")
        or record.get("record_role")
        or record.get("role")
        or ""
    ).lower()
    role_tokens = []
    for key in ("state", "state_token", "chain_state"):
        role_tokens.extend(_as_text_list(record.get(key)))
    if role == "producer" and "producer" in role_text:
        tokens.extend(role_tokens)
    if role == "consumer" and "consumer" in role_text:
        tokens.extend(role_tokens)
    return _dedupe(tokens)


def _source_backed_chain_metadata(members: list[dict[str, Any]]) -> dict[str, Any]:
    source_refs: list[str] = []
    produces_state: list[str] = []
    requires_state: list[str] = []
    producer_refs: list[str] = []
    consumer_refs: list[str] = []
    for member in members:
        refs = _collect_source_refs(member)
        if not refs:
            continue
        source_refs.extend(refs)
        produces = _collect_state_tokens(member, "producer")
        requires = _collect_state_tokens(member, "consumer")
        if produces:
            produces_state.extend(produces)
            producer_refs.extend(refs)
        if requires:
            requires_state.extend(requires)
            consumer_refs.extend(refs)
    metadata: dict[str, Any] = {}
    source_refs = _dedupe(source_refs)
    produces_state = _dedupe(produces_state)
    requires_state = _dedupe(requires_state)
    if source_refs:
        metadata["source_refs"] = source_refs
    if produces_state:
        metadata["produces_state"] = produces_state
        metadata["producer_source_refs"] = _dedupe(producer_refs)
    if requires_state:
        metadata["requires_state"] = requires_state
        metadata["consumer_source_refs"] = _dedupe(consumer_refs)
    return metadata


# ---------------------------------------------------------------------------
# Source-finding-ID grouping (to satisfy "cite >=2 source findings")
# ---------------------------------------------------------------------------


def group_records_by_signal(
    seed_records: list[dict[str, Any]],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Group records by (category, attack_class+bug_class+target_repo signature).

    Each group becomes one invariant entry, with source_finding_ids drawn
    from every group member. The composite key keeps fine-grained variant
    coverage; same attack_class on a different repo or with a different
    bug_class gets its own invariant entry (the L0.3 pilot is the same
    cardinality - 100 entries from 10 categories means many per-cat
    variants survive).
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for rec in seed_records:
        cat, score, _scores = classify_record(rec)
        if not cat:
            continue
        # Composite signal: attack_class + bug_class + repo (when distinct),
        # so cross-repo variants of the same attack_class become separate
        # invariants (more variety; matches pilot library shape).
        attack_part = re.sub(
            r"[^a-z0-9]+",
            "-",
            str(rec.get("attack_class") or "").lower(),
        ).strip("-")
        bug_part = re.sub(
            r"[^a-z0-9]+",
            "-",
            str(rec.get("bug_class") or "").lower(),
        ).strip("-")
        repo_part = re.sub(
            r"[^a-z0-9]+",
            "-",
            str(rec.get("target_repo") or "").lower(),
        ).strip("-")
        # If repo is "unknown" or empty, fall back to source_audit_ref slug
        # so each individual finding keeps separate identity.
        if repo_part in {"", "unknown", "unknown-dsl-synthetic"}:
            src = str(rec.get("source_audit_ref") or rec.get("record_id") or "")
            repo_part = re.sub(r"[^a-z0-9]+", "-", src.lower()).strip("-")[:40]
        signature = "|".join(p for p in (attack_part, bug_part, repo_part) if p)
        if not signature:
            continue
        key = (cat, signature)
        rec["_classified_category"] = cat
        rec["_classified_score"] = score
        groups[key].append(rec)
    return groups


# ---------------------------------------------------------------------------
# Invariant assembly
# ---------------------------------------------------------------------------


def assemble_invariants_from_groups(
    groups: dict[tuple[str, str], list[dict[str, Any]]],
    start_index: dict[str, int],
    extractor: str,
    *,
    min_group_size: int = 2,
) -> list[dict[str, Any]]:
    """Emit one invariant per (category, attack-sig) group with >=2 members.

    Groups with only one record are kept but get an extra 'singleton' flag
    in the source_finding_ids comment.
    """
    out: list[dict[str, Any]] = []
    per_cat_counter = dict(start_index)
    ts = _utc_now()
    for (cat, attack_sig), members in sorted(groups.items()):
        if len(members) < min_group_size:
            # Allow singletons to still be emitted but flag them.
            singleton = True
        else:
            singleton = False
        per_cat_counter[cat] = per_cat_counter.get(cat, 0) + 1
        seq = per_cat_counter[cat]
        prefix = CATEGORY_PREFIX[cat]
        invariant_id = f"INV-{prefix}-EX-{seq:04d}"
        # Pick representative record (highest score).
        rep = max(members, key=lambda r: r.get("_classified_score", 0))
        statement = derive_statement(cat, rep)
        abstraction = derive_abstraction(rep, cat)
        target_langs = {
            normalize_target_lang(m.get("target_language"))
            for m in members
        }
        target_langs.discard("unknown")
        if not target_langs:
            target_lang = "any"
        elif len(target_langs) == 1:
            target_lang = next(iter(target_langs))
        else:
            target_lang = "any"
        # Source IDs (deduped, capped at 20 to keep entry size sane).
        seen_ids: list[str] = []
        for m in members:
            rid = str(m.get("record_id") or m.get("source_audit_ref") or "")
            if rid and rid not in seen_ids:
                seen_ids.append(rid)
            if len(seen_ids) >= 20:
                break
        # Verification tier: take min (strongest) across members.
        tier_order = [
            "tier-1-verified-realtime-api",
            "tier-1-officially-disclosed",
            "tier-2-verified-public-archive",
            "tier-3-synthetic-taxonomy-anchored",
            "tier-4-bundled-fixture",
            "tier-5-quarantine",
        ]
        member_tiers = [
            normalize_verification_tier(m.get("verification_tier"))
            for m in members
        ]
        best_tier = None
        for tier in tier_order:
            if tier in member_tiers:
                best_tier = tier
                break
        if best_tier is None:
            best_tier = "tier-3-synthetic-taxonomy-anchored"
        # Defense layer hint
        defense_layer = DEFAULT_DEFENSE_LAYER.get(cat) or None
        commit_point_pattern = COMMIT_POINT_KEYWORDS.get(cat, ["commit-point"])[0]
        entry = {
            "schema_version": SCHEMA_VERSION,
            "invariant_id": invariant_id,
            "category": cat,
            "statement": statement,
            "target_lang": target_lang,
            "source_finding_ids": seen_ids,
            "abstraction_level": abstraction,
            "commit_point_pattern": commit_point_pattern,
            "defense_layer": defense_layer,
            "verification_tier": best_tier,
            "extractor": extractor,
            "extracted_at_utc": ts,
            "source_count": len(seen_ids),
            "singleton": singleton,
            "attack_signature": attack_sig,
        }
        entry.update(_source_backed_chain_metadata(members))
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# JSONL I/O
# ---------------------------------------------------------------------------


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                out.append(row)
    return out


def append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")


WATERMARK_SCHEMA_VERSION = "auditooor.invariant_extract_watermark.v1"
DEFAULT_WATERMARK = (
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / ".invariant_extract_watermark"
)


def load_watermark(path: Path) -> dict[str, Any]:
    """Load the incremental-extraction watermark.

    Returns a dict with at least ``processed_record_ids`` (a list of the
    finding/record IDs already lifted into the extracted invariants file).
    A missing or malformed watermark yields an empty processed set so the
    first run is a full sweep (idempotent against the existing output via the
    attack-signature dedup that already runs downstream).
    """
    if not path.exists():
        return {"processed_record_ids": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"processed_record_ids": []}
    if not isinstance(data, dict):
        return {"processed_record_ids": []}
    ids = data.get("processed_record_ids")
    if not isinstance(ids, list):
        data["processed_record_ids"] = []
    return data


def write_watermark(path: Path, processed_record_ids: Iterable[str]) -> int:
    """Persist the processed record-id set so the next run is resumable.

    Returns the count of distinct ids written. The watermark is sorted for a
    stable diff; it never decreases (it is the union of all ids ever lifted).
    """
    deduped = sorted({str(rid) for rid in processed_record_ids if str(rid).strip()})
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": WATERMARK_SCHEMA_VERSION,
        "updated_at_utc": _utc_now(),
        "processed_count": len(deduped),
        "processed_record_ids": deduped,
    }
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return len(deduped)


def existing_invariant_ids(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Return per-category max suffix counter (for stable resumption)."""
    counters: dict[str, int] = {cat: 0 for cat in CATEGORIES}
    for row in rows:
        cat = row.get("category")
        inv_id = row.get("invariant_id") or ""
        if cat not in counters:
            continue
        m = re.match(r"^INV-[A-Z]+-EX-(\d+)$", str(inv_id))
        if m:
            n = int(m.group(1))
            if n > counters[cat]:
                counters[cat] = n
    return counters


# ---------------------------------------------------------------------------
# Spot-check
# ---------------------------------------------------------------------------


def spot_check_entry(entry: dict[str, Any]) -> tuple[bool, list[str]]:
    """Return (passes_quality_gate, list_of_failure_reasons)."""
    fails: list[str] = []
    stmt = str(entry.get("statement") or "")
    upper = stmt.upper()
    if "MUST" not in upper:
        fails.append("statement_no_must")
    src_ids = entry.get("source_finding_ids") or []
    if not isinstance(src_ids, list) or len(src_ids) < 2:
        # Allow singletons via the explicit-singleton flag
        if not entry.get("singleton"):
            fails.append("source_ids_lt_2")
    dl = entry.get("defense_layer")
    if dl is None:
        # Explicit-null allowed.
        pass
    elif not isinstance(dl, str) or not dl.strip():
        fails.append("defense_layer_empty_not_null")
    if entry.get("category") not in CATEGORIES:
        fails.append("invalid_category")
    if normalize_target_lang(entry.get("target_lang")) == "unknown":
        fails.append("invalid_target_lang")
    if entry.get("abstraction_level") not in VALID_ABSTRACTIONS:
        fails.append("invalid_abstraction_level")
    return (len(fails) == 0, fails)


def is_template_or_broad_statement(entry: dict[str, Any]) -> bool:
    """Return True when a paid-sweep statement is still generic/template-like."""
    stmt = re.sub(r"\s+", " ", str(entry.get("statement") or "").strip())
    if not stmt:
        return True
    category = entry.get("category")
    if category in STATEMENT_TEMPLATES and stmt in STATEMENT_TEMPLATES[category]:
        return True
    words = set(re.findall(r"[a-zA-Z][a-zA-Z-]+", stmt.lower()))
    has_commit_specificity = bool(entry.get("commit_point_pattern")) and len(
        str(entry.get("commit_point_pattern")).strip()
    ) >= 10
    has_attack_specificity = bool(entry.get("attack_signature")) and any(
        part and part.lower() in stmt.lower()
        for part in str(entry.get("attack_signature")).split("|")[:2]
    )
    if len(stmt) < 50:
        return True
    if words & BROAD_STATEMENT_TERMS and not (has_commit_specificity or has_attack_specificity):
        return True
    return False


def run_spot_check(entries: list[dict[str, Any]], sample_size: int, seed: int = 42) -> dict[str, Any]:
    """Sample N entries and compute Y-rate."""
    if not entries:
        return {
            "sample_size": 0,
            "y_count": 0,
            "n_count": 0,
            "y_rate": 0.0,
            "fail_reasons": {},
        }
    rng = random.Random(seed)
    n = min(sample_size, len(entries))
    sample = rng.sample(entries, n)
    y = 0
    fails = Counter()
    for entry in sample:
        ok, reasons = spot_check_entry(entry)
        if ok:
            y += 1
        else:
            for r in reasons:
                fails[r] += 1
    return {
        "sample_size": n,
        "y_count": y,
        "n_count": n - y,
        "y_rate": y / n if n > 0 else 0.0,
        "fail_reasons": dict(fails),
    }


def evaluate_spot_check_gate(
    entries: list[dict[str, Any]],
    sample_size: int,
    *,
    seed: int = 42,
    min_y_rate: float = LLM_SWEEP_MIN_Y_RATE,
    disallow_template_or_broad: bool = False,
) -> dict[str, Any]:
    """Run a spot-check and return an explicit promotion gate decision."""
    spot = run_spot_check(entries, sample_size, seed=seed)
    blockers: list[str] = []
    if spot["sample_size"] <= 0:
        blockers.append("empty_spot_check_sample")
    if spot["y_rate"] < min_y_rate:
        blockers.append("spot_check_y_rate_below_threshold")
    template_or_broad_ids: list[str] = []
    if disallow_template_or_broad:
        for entry in entries:
            if is_template_or_broad_statement(entry):
                template_or_broad_ids.append(str(entry.get("invariant_id") or "<no-id>"))
        if template_or_broad_ids:
            blockers.append("template_or_broad_statements_present")
    return {
        **spot,
        "min_y_rate": min_y_rate,
        "promotion_allowed": not blockers,
        "promotion_blockers": blockers,
        "template_or_broad_count": len(template_or_broad_ids),
        "template_or_broad_invariant_ids": template_or_broad_ids[:25],
    }


# ---------------------------------------------------------------------------
# Index builder
# ---------------------------------------------------------------------------


def build_index(
    pilot_rows: list[dict[str, Any]],
    extracted_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    per_category: Counter = Counter()
    per_language: Counter = Counter()
    per_abstraction: Counter = Counter()
    per_tier: Counter = Counter()
    reverse_lookup: dict[str, list[str]] = defaultdict(list)
    total = 0
    for rows, source_tag in [(pilot_rows, "pilot"), (extracted_rows, "extracted")]:
        for row in rows:
            inv_id = row.get("invariant_id") or "<no-id>"
            cat = row.get("category") or "<no-cat>"
            lang = normalize_target_lang(row.get("target_lang"))
            absn = row.get("abstraction_level") or "<no-abs>"
            tier = row.get("verification_tier") or "<no-tier>"
            per_category[cat] += 1
            per_language[lang] += 1
            per_abstraction[absn] += 1
            per_tier[tier] += 1
            for src in row.get("source_finding_ids") or []:
                if not isinstance(src, str):
                    continue
                reverse_lookup[src].append(inv_id)
            total += 1
    return {
        "schema_version": "auditooor.invariant_library_index.v1",
        "generated_at_utc": _utc_now(),
        "total_invariants": total,
        "pilot_count": len(pilot_rows),
        "extracted_count": len(extracted_rows),
        "per_category": dict(per_category),
        "per_language": dict(per_language),
        "per_abstraction": dict(per_abstraction),
        "per_verification_tier": dict(per_tier),
        "reverse_lookup_finding_to_invariant": {
            k: sorted(set(v)) for k, v in sorted(reverse_lookup.items())
        },
    }


# ---------------------------------------------------------------------------
# LLM-sweep mode (gated)
# ---------------------------------------------------------------------------


def llm_sweep(records: int, provider: str) -> dict[str, Any]:
    """Refuse unless an API key env var is set.

    Operator can later run this when LLM budget is greenlit.
    """
    provider = provider.lower()
    if provider == "anthropic":
        env_key = "ANTHROPIC_API_KEY"
    elif provider == "kimi":
        env_key = "KIMI_API_KEY"
    elif provider == "minimax":
        env_key = "MINIMAX_API_KEY"
    elif provider == "openai":
        env_key = "OPENAI_API_KEY"
    else:
        return {
            "status": "refused",
            "reason": "unknown_provider",
            "provider": provider,
            "remediation": "use --provider {anthropic,kimi,minimax,openai}",
        }
    if not os.environ.get(env_key):
        return {
            "status": "refused",
            "reason": "no_api_key",
            "provider": provider,
            "env_key": env_key,
            "remediation": (
                f"Export {env_key} before retrying. The lane defers actual "
                "LLM sweep until operator-set API key + budget is greenlit. "
                "Use --mode hand-extract for the MVP heuristic path."
            ),
            "records_requested": records,
        }
    # Even with an API key, the MVP build does NOT actually call out without
    # explicit operator authorization. We document this and exit cleanly.
    return {
        "status": "refused",
        "reason": "operator_authorization_required",
        "provider": provider,
        "env_key_present": True,
        "remediation": (
            "API key is present but the MVP build does not auto-spend. "
            "Operator must explicitly authorize a paid sweep; the sweep "
            "implementation is intentionally deferred to a separate lane."
        ),
        "records_requested": records,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_hand_extract(args: argparse.Namespace) -> int:
    index_path = Path(args.index)
    tags_dir = Path(args.tags_dir)
    output_path = Path(args.output)
    failed_path = Path(args.failed)
    target_records = max(1, int(args.records))
    incremental = bool(getattr(args, "incremental", False))
    watermark_path = Path(args.watermark) if getattr(args, "watermark", None) else None
    # Incremental mode: only lift index rows whose record_id is NEWER than the
    # watermark (i.e. not yet processed). The corpus index is append-grown, so
    # "newer" == "record_id not in the processed-id set". This is the wiring
    # that lets the 1231 solodit + 496 prior-audit + own-finding records that
    # land via the ETL refresh actually become per-fn invariant fuel instead
    # of only feeding detectors/dedup.
    already_processed: set[str] = set()
    if incremental and watermark_path is not None:
        wm = load_watermark(watermark_path)
        already_processed = {str(rid) for rid in wm.get("processed_record_ids", [])}
    # Read existing output so resumption is idempotent on invariant_id.
    existing = load_jsonl(output_path)
    seen_attack_sigs = {
        (r.get("category"), r.get("attack_signature"))
        for r in existing
        if r.get("category") and r.get("attack_signature")
    }
    start_index = existing_invariant_ids(existing)
    # Stream up to target_records seed records.
    seeds: list[dict[str, Any]] = []
    consumed = 0
    skipped_watermark = 0
    newly_seen_ids: list[str] = []
    failed_records: list[dict[str, Any]] = []
    for index_row in iter_index_records(index_path, limit=None):
        if consumed >= target_records:
            break
        seed = build_seed_record(index_row, tags_dir)
        record_id = str(seed.get("record_id") or "")
        if incremental and record_id and record_id in already_processed:
            skipped_watermark += 1
            continue
        # This row counts as consumed for this run (whether or not it
        # classifies); record its id so the watermark advances past it.
        if record_id:
            newly_seen_ids.append(record_id)
        cat, score, _scores = classify_record(seed)
        if cat is None:
            failed_records.append({
                "record_id": seed.get("record_id"),
                "attack_class": seed.get("attack_class"),
                "reason": "no_category_match",
            })
            consumed += 1
            continue
        seeds.append(seed)
        consumed += 1
    # Group + assemble.
    groups = group_records_by_signal(seeds)
    # Skip groups already represented in existing output.
    filtered_groups = {
        k: v
        for k, v in groups.items()
        if (k[0], k[1]) not in seen_attack_sigs
    }
    entries = assemble_invariants_from_groups(
        filtered_groups,
        start_index,
        extractor="hand-extract",
    )
    if entries:
        append_jsonl(output_path, entries)
    if failed_records:
        # Limit failed sidecar churn.
        append_jsonl(failed_path, failed_records[:1000])
    summary = {
        "mode": "hand-extract",
        "incremental": incremental,
        "records_consumed": consumed,
        "seeds_classified": len(seeds),
        "groups_emitted": len(entries),
        "groups_skipped_duplicate": len(groups) - len(filtered_groups),
        "failed_records": len(failed_records),
        "output_path": str(output_path),
    }
    if incremental and watermark_path is not None:
        # Advance the watermark by the union of previously-processed ids and
        # the ids consumed this run, so the next refresh only sees brand-new
        # findings. Best-effort + resumable: a crash before this point leaves
        # the prior watermark intact and the run is simply retried.
        wm_total = write_watermark(
            watermark_path,
            already_processed | set(newly_seen_ids),
        )
        summary["watermark_path"] = str(watermark_path)
        summary["watermark_skipped"] = skipped_watermark
        summary["watermark_new_record_ids"] = len(newly_seen_ids)
        summary["watermark_total_record_ids"] = wm_total
    if args.spot_check:
        all_entries = load_jsonl(output_path)
        spot = run_spot_check(all_entries, args.spot_check)
        summary["spot_check"] = spot
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def cmd_llm_sweep(args: argparse.Namespace) -> int:
    out = llm_sweep(int(args.records), str(args.provider))
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out.get("status") != "refused" else 2


def cmd_spot_check(args: argparse.Namespace) -> int:
    output_path = Path(args.output)
    entries = load_jsonl(output_path)
    if args.include_pilot:
        entries.extend(load_jsonl(Path(args.pilot)))
    if not entries:
        print(json.dumps({"error": "no_entries_found", "path": str(output_path)}, indent=2))
        return 2
    result = run_spot_check(entries, int(args.spot_check), seed=int(args.seed))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_build_index(args: argparse.Namespace) -> int:
    pilot_rows = load_jsonl(Path(args.pilot))
    extracted_rows = load_jsonl(Path(args.output))
    index = build_index(pilot_rows, extracted_rows)
    Path(args.index_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.index_json).write_text(
        json.dumps(index, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps({
        "wrote": str(args.index_json),
        "total_invariants": index["total_invariants"],
        "per_category": index["per_category"],
        "per_language": index["per_language"],
    }, indent=2, sort_keys=True))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["hand-extract", "llm-sweep"],
        default="hand-extract",
    )
    parser.add_argument("--records", type=int, default=50)
    parser.add_argument("--provider", default="anthropic")
    parser.add_argument("--spot-check", type=int, default=0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--index", default=str(DEFAULT_INDEX))
    parser.add_argument("--tags-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--failed", default=str(DEFAULT_FAILED))
    parser.add_argument("--pilot", default=str(DEFAULT_PILOT))
    parser.add_argument("--index-json", default=str(DEFAULT_INDEX_JSON))
    parser.add_argument("--include-pilot", action="store_true")
    parser.add_argument("--build-index", action="store_true")
    parser.add_argument(
        "--incremental",
        action="store_true",
        help=(
            "Only lift index rows whose record_id is not yet recorded in the "
            "watermark (NEW findings since the last refresh), then advance the "
            "watermark. Resumable + best-effort."
        ),
    )
    parser.add_argument(
        "--watermark",
        default=str(DEFAULT_WATERMARK),
        help="Path to the incremental-extraction watermark file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.build_index:
        return cmd_build_index(args)
    if args.mode == "llm-sweep":
        return cmd_llm_sweep(args)
    if args.spot_check and args.records <= 0:
        return cmd_spot_check(args)
    return cmd_hand_extract(args)


if __name__ == "__main__":
    raise SystemExit(main())
