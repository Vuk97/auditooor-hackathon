#!/usr/bin/env python3
"""hackerman-chain-unify.py - precondition/postcondition exploit-chain unifier.

Upgrades the co-location grouping of `hackerman-chain-candidates.py` into a real
multi-hop chain constructor. Lane W5-F2 / plan H5-2.

Model
-----
Each corpus record is treated as one exploit STEP with two token sets:

  * postconditions - state / capability tokens the step PRODUCES once it fires.
    Derived deterministically from `attack_class`, `impact_class`, and
    `attacker_action_sequence`.
  * preconditions  - state / capability tokens the step REQUIRES before it can
    fire. Derived from `required_preconditions` free text, `attacker_role`, and
    `attack_class`.

An edge A->B exists when A's postcondition set intersects B's precondition set;
the intersection is the named "unifying state". A chain is a path
step_1 -> step_2 -> ... -> step_N (N >= 2) where each consecutive pair has an
edge and all steps share a scope (repo or workspace). Chains are scored by hop
count, severity, outcome, and the distinctness of the unifying states.

Conservatism
------------
Token derivation uses a FIXED vocabulary and FIXED keyword rules. Where a record
carries no usable precondition/postcondition signal it is marked `unchainable`
and excluded from edge construction - it is never given fabricated tokens. The
tool is deterministic and stdlib-only (no LLM, no network).

Usage
-----
    hackerman-chain-unify.py --tag-dir audit/corpus_tags/tags --limit 20
    hackerman-chain-unify.py --tag-dir <dir> --limit 20 --json
    hackerman-chain-unify.py --tag-dir <dir> --max-hops 4 --json
    hackerman-chain-unify.py --tag-dir <dir> --out agent_outputs/chains.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
SCHEMA = "auditooor.hackerman.chain_unify.v1"
MAX_LIMIT = 100
MAX_HOPS_CAP = 6
MAX_STEPS_PER_SCOPE = 400  # bound graph search blast radius per scope
MAX_CHAINS_PER_SCOPE_CAP = 10_000


# --- token vocabulary -------------------------------------------------------
# Fixed capability/state tokens. A token names a piece of attacker-controlled
# state or capability. Postconditions PRODUCE tokens; preconditions REQUIRE
# them. The vocabulary is closed - no token is invented from corpus free text.

TOKEN_PRIV_CALLER = "state:privileged-caller-context"
TOKEN_UNVETTED_CALL = "state:unvetted-call-reaches-target"
TOKEN_STALE_STATE = "state:stale-or-desynced-state"
TOKEN_FORGED_AUTH = "state:forged-or-replayed-authorization"
TOKEN_PRICE_CONTROL = "state:attacker-controlled-price-input"
TOKEN_FUNDS_MOVED = "state:protocol-funds-displaced"
TOKEN_ACCOUNTING_SKEW = "state:accounting-invariant-broken"
TOKEN_GOV_CONTROL = "state:governance-control-acquired"
TOKEN_LIVENESS_DEGRADED = "state:liveness-or-availability-degraded"
TOKEN_PROOF_ACCEPTED = "state:invalid-proof-accepted"
TOKEN_REENTRANT_CTX = "state:reentrant-execution-context"

ALL_TOKENS = (
    TOKEN_PRIV_CALLER,
    TOKEN_UNVETTED_CALL,
    TOKEN_STALE_STATE,
    TOKEN_FORGED_AUTH,
    TOKEN_PRICE_CONTROL,
    TOKEN_FUNDS_MOVED,
    TOKEN_ACCOUNTING_SKEW,
    TOKEN_GOV_CONTROL,
    TOKEN_LIVENESS_DEGRADED,
    TOKEN_PROOF_ACCEPTED,
    TOKEN_REENTRANT_CTX,
)

# attack_class slug fragment -> postcondition tokens it PRODUCES.
ATTACK_POSTCONDITIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("reentr", (TOKEN_REENTRANT_CTX, TOKEN_ACCOUNTING_SKEW)),
    ("access-control", (TOKEN_PRIV_CALLER, TOKEN_UNVETTED_CALL)),
    ("auth", (TOKEN_PRIV_CALLER, TOKEN_FORGED_AUTH)),
    ("privilege", (TOKEN_PRIV_CALLER,)),
    ("role", (TOKEN_PRIV_CALLER,)),
    ("signature", (TOKEN_FORGED_AUTH,)),
    ("replay", (TOKEN_FORGED_AUTH,)),
    ("permit", (TOKEN_FORGED_AUTH,)),
    ("approval", (TOKEN_FORGED_AUTH, TOKEN_UNVETTED_CALL)),
    ("oracle", (TOKEN_PRICE_CONTROL, TOKEN_ACCOUNTING_SKEW)),
    ("price", (TOKEN_PRICE_CONTROL,)),
    ("manipulation", (TOKEN_PRICE_CONTROL, TOKEN_ACCOUNTING_SKEW)),
    ("rounding", (TOKEN_ACCOUNTING_SKEW,)),
    ("precision", (TOKEN_ACCOUNTING_SKEW,)),
    ("inflation", (TOKEN_ACCOUNTING_SKEW,)),
    ("donation", (TOKEN_ACCOUNTING_SKEW,)),
    ("governance", (TOKEN_GOV_CONTROL, TOKEN_PRIV_CALLER)),
    ("dos", (TOKEN_LIVENESS_DEGRADED,)),
    ("griefing", (TOKEN_LIVENESS_DEGRADED,)),
    ("freeze", (TOKEN_LIVENESS_DEGRADED, TOKEN_FUNDS_MOVED)),
    ("proof", (TOKEN_PROOF_ACCEPTED, TOKEN_FORGED_AUTH)),
    ("zk", (TOKEN_PROOF_ACCEPTED,)),
    ("bridge", (TOKEN_FORGED_AUTH, TOKEN_FUNDS_MOVED)),
    ("cross-chain", (TOKEN_FORGED_AUTH,)),
    ("desync", (TOKEN_STALE_STATE,)),
    ("stale", (TOKEN_STALE_STATE,)),
    ("toctou", (TOKEN_STALE_STATE,)),
    ("front-run", (TOKEN_STALE_STATE, TOKEN_PRICE_CONTROL)),
)

# impact_class slug -> additional postcondition tokens it PRODUCES.
IMPACT_POSTCONDITIONS: dict[str, tuple[str, ...]] = {
    "theft": (TOKEN_FUNDS_MOVED,),
    "freeze": (TOKEN_LIVENESS_DEGRADED, TOKEN_FUNDS_MOVED),
    "dos": (TOKEN_LIVENESS_DEGRADED,),
    "griefing": (TOKEN_LIVENESS_DEGRADED,),
    "governance-takeover": (TOKEN_GOV_CONTROL, TOKEN_PRIV_CALLER),
    "privilege-escalation": (TOKEN_PRIV_CALLER,),
    "precision-loss": (TOKEN_ACCOUNTING_SKEW,),
    "yield-redistribution": (TOKEN_ACCOUNTING_SKEW, TOKEN_FUNDS_MOVED),
}

# free-text keyword -> precondition token it REQUIRES. Scanned against
# `required_preconditions` lines plus `attacker_action_sequence`.
PRECONDITION_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("privileged", TOKEN_PRIV_CALLER),
    ("owner", TOKEN_PRIV_CALLER),
    ("admin", TOKEN_PRIV_CALLER),
    ("role", TOKEN_PRIV_CALLER),
    ("governance", TOKEN_GOV_CONTROL),
    ("governor", TOKEN_GOV_CONTROL),
    ("proposal", TOKEN_GOV_CONTROL),
    ("reachable", TOKEN_UNVETTED_CALL),
    ("callable", TOKEN_UNVETTED_CALL),
    ("external call", TOKEN_UNVETTED_CALL),
    ("callback", TOKEN_REENTRANT_CTX),
    ("hook", TOKEN_REENTRANT_CTX),
    ("reenter", TOKEN_REENTRANT_CTX),
    ("stale", TOKEN_STALE_STATE),
    ("desync", TOKEN_STALE_STATE),
    ("outdated", TOKEN_STALE_STATE),
    ("not updated", TOKEN_STALE_STATE),
    ("signature", TOKEN_FORGED_AUTH),
    ("valid proof", TOKEN_PROOF_ACCEPTED),
    ("proof", TOKEN_PROOF_ACCEPTED),
    ("oracle", TOKEN_PRICE_CONTROL),
    ("price", TOKEN_PRICE_CONTROL),
    ("liquidity", TOKEN_PRICE_CONTROL),
    ("balance", TOKEN_FUNDS_MOVED),
    ("funds", TOKEN_FUNDS_MOVED),
    ("accounting", TOKEN_ACCOUNTING_SKEW),
    ("share", TOKEN_ACCOUNTING_SKEW),
)

# attacker_role slug -> precondition token implied by the role.
ROLE_PRECONDITIONS: dict[str, tuple[str, ...]] = {
    "privileged": (TOKEN_PRIV_CALLER,),
    "privileged-compromised": (TOKEN_PRIV_CALLER,),
    "admin": (TOKEN_PRIV_CALLER,),
    "governance": (TOKEN_GOV_CONTROL,),
    "compromised-operator": (TOKEN_PRIV_CALLER,),
}


def yaml_load(text: str) -> Any:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except Exception as exc:  # pragma: no cover - depends on local deps
        raise RuntimeError("PyYAML is required to read Hackerman tag YAML files") from exc


def slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")


def stable_hash(payload: Any, length: int = 16) -> str:
    data = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:length]


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _severity_weight(value: str) -> float:
    return {
        "critical": 5.0,
        "high": 4.0,
        "medium": 2.5,
        "low": 1.0,
        "info": 0.25,
    }.get(slug(value), 0.5)


def _outcome_weight(value: str) -> float:
    outcome = _text(value).upper()
    if outcome in {"ACCEPTED", "FILED", "SUBMITTED"}:
        return 1.0
    if outcome in {"CANDIDATE", "STAGING"}:
        return 0.25
    if outcome in {"REJECTED", "DUPLICATE", "NOT_A_BUG", "OOS", "DROPPED"}:
        return -0.75
    return 0.0


# attacker_role slug -> attacker capability cost. Lower = cheaper/easier for an
# attacker to satisfy. A chain whose steps require monotonically NON-INCREASING
# privilege (you keep privilege you already have) is more plausible than one
# that demands the attacker re-acquire privilege at a later hop.
ROLE_COST: dict[str, float] = {
    "arbitrary-user": 1.0,
    "unprivileged": 1.0,
    "anyone": 1.0,
    "external": 1.0,
    "user": 1.5,
    "lp": 2.0,
    "liquidity-provider": 2.0,
    "operator": 3.0,
    "compromised-operator": 3.0,
    "privileged": 4.0,
    "privileged-compromised": 4.0,
    "admin": 4.5,
    "governance": 5.0,
}


def _role_cost(value: str) -> float:
    return ROLE_COST.get(slug(value), 2.0)


def _repo_is_specific(repo: str) -> bool:
    lowered = repo.lower()
    return bool(repo) and lowered not in {"unknown", "unknown/dsl-synthetic", "unknown/unknown"}


def _workspace_from_source(source_ref: str, tag_file: str) -> str:
    text = source_ref or tag_file
    for prefix in ("prior-audit:", "audit:"):
        if text.startswith(prefix):
            return slug(text[len(prefix):].split(":", 1)[0])
    if text.startswith("staging_"):
        return slug(text[len("staging_"):].split("-", 1)[0])
    if text.startswith("prior-audit-"):
        return slug(text[len("prior-audit-"):].split("-", 1)[0])
    if text.startswith("git-mining-"):
        parts = text.split("-")
        if len(parts) >= 4:
            return slug(parts[2])
    return ""


# --- token derivation -------------------------------------------------------

def derive_postconditions(attack_classes: Iterable[str], impact_class: str) -> set[str]:
    """State/capability tokens this step PRODUCES once it fires."""
    out: set[str] = set()
    for cls in attack_classes:
        cls_slug = slug(cls)
        for fragment, tokens in ATTACK_POSTCONDITIONS:
            if fragment in cls_slug:
                out.update(tokens)
    for token in IMPACT_POSTCONDITIONS.get(slug(impact_class), ()):  # noqa: B007
        out.add(token)
    return out


def derive_preconditions(
    precondition_lines: Iterable[str],
    attacker_role: str,
    attack_classes: Iterable[str],
) -> set[str]:
    """State/capability tokens this step REQUIRES before it can fire."""
    out: set[str] = set()
    blob = " ".join(_text(line).lower() for line in precondition_lines)
    for keyword, token in PRECONDITION_KEYWORDS:
        if keyword in blob:
            out.add(token)
    for token in ROLE_PRECONDITIONS.get(slug(attacker_role), ()):  # noqa: B007
        out.add(token)
    # An access/auth step inherently requires an unvetted call to even reach.
    for cls in attack_classes:
        cls_slug = slug(cls)
        if "access-control" in cls_slug or cls_slug.startswith("auth"):
            out.add(TOKEN_UNVETTED_CALL)
    return out


@dataclass
class ExploitStep:
    tag_file: str
    record_id: str
    repo: str
    workspace: str
    scope_type: str
    scope: str
    language: str
    bug_class: str
    attack_classes: tuple[str, ...]
    impact_class: str
    severity: str
    outcome: str
    quality: float
    action_summary: str
    attacker_role: str = ""
    is_predicate: bool = False  # W6-9: composable-predicate node, not a finding
    preconditions: frozenset[str] = field(default_factory=frozenset)
    postconditions: frozenset[str] = field(default_factory=frozenset)

    @property
    def chainable(self) -> bool:
        # A step participates in a chain only if it can be the producer of an
        # edge (has postconditions) or the consumer (has preconditions). A step
        # with neither carries no usable signal and is marked unchainable.
        return bool(self.preconditions or self.postconditions)

    def step_strength(self) -> float:
        return (
            _severity_weight(self.severity)
            + _outcome_weight(self.outcome)
            + min(self.quality, 5.0) * 0.35
        )

    def brief(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "tag_file": self.tag_file,
            "bug_class": self.bug_class,
            "attack_classes": list(self.attack_classes),
            "impact_class": self.impact_class,
            "severity": self.severity,
            "attacker_role": self.attacker_role,
            "node_kind": "predicate" if self.is_predicate else "finding",
            "preconditions": sorted(self.preconditions),
            "postconditions": sorted(self.postconditions),
        }


def _attack_classes(doc: dict[str, Any]) -> tuple[str, ...]:
    values: list[Any] = []
    for field_name in ("attack_class", "attack_classes", "attack_classes_to_try"):
        values.extend(_as_list(doc.get(field_name)))
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _text(value)
        key = slug(text)
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return tuple(out)


def normalize_step(path: Path, doc: dict[str, Any]) -> ExploitStep | None:
    record_id = _text(doc.get("record_id") or doc.get("verdict_id") or path.stem)
    if not record_id:
        return None
    source_ref = _text(doc.get("source_audit_ref") or doc.get("verdict_id") or record_id)
    repo = _text(doc.get("target_repo"))
    workspace = _workspace_from_source(source_ref, path.name)
    if _repo_is_specific(repo):
        scope_type, scope = "repo", repo
    elif workspace:
        scope_type, scope = "workspace", workspace
    else:
        scope_type, scope = "repo", repo or "unknown"
    attack_classes = _attack_classes(doc)
    bug_class = _text(doc.get("bug_class"))
    if not (bug_class or attack_classes):
        return None
    impact_class = _text(doc.get("impact_class"))
    precondition_lines = [_text(x) for x in _as_list(doc.get("required_preconditions"))]
    action = _text(doc.get("attacker_action_sequence") or doc.get("notes"))
    if action:
        precondition_lines.append(action)
    attacker_role = _text(doc.get("attacker_role"))
    pre = derive_preconditions(precondition_lines, attacker_role, attack_classes)
    post = derive_postconditions(attack_classes, impact_class)
    return ExploitStep(
        tag_file=path.name,
        record_id=record_id,
        repo=repo or "unknown",
        workspace=workspace,
        scope_type=scope_type,
        scope=scope,
        language=_text(doc.get("target_language") or doc.get("language")),
        bug_class=bug_class,
        attack_classes=attack_classes,
        impact_class=impact_class,
        severity=_text(
            doc.get("severity_at_finding")
            or doc.get("severity_final")
            or doc.get("severity_claimed")
        ),
        outcome=_text(doc.get("triager_outcome") or doc.get("verdict_class")),
        quality=_safe_float(doc.get("record_quality_score")),
        action_summary=action[:280],
        attacker_role=attacker_role,
        preconditions=frozenset(pre),
        postconditions=frozenset(post),
    )


def _safe_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


CACHE_SCHEMA = "auditooor.hackerman.chain_unify.cache.v1"


def _step_to_cache(step: ExploitStep) -> dict[str, Any]:
    return {
        "tag_file": step.tag_file,
        "record_id": step.record_id,
        "repo": step.repo,
        "workspace": step.workspace,
        "scope_type": step.scope_type,
        "scope": step.scope,
        "language": step.language,
        "bug_class": step.bug_class,
        "attack_classes": list(step.attack_classes),
        "impact_class": step.impact_class,
        "severity": step.severity,
        "outcome": step.outcome,
        "quality": step.quality,
        "action_summary": step.action_summary,
        "attacker_role": step.attacker_role,
        "is_predicate": step.is_predicate,
        "preconditions": sorted(step.preconditions),
        "postconditions": sorted(step.postconditions),
    }


def _step_from_cache(data: dict[str, Any]) -> ExploitStep:
    return ExploitStep(
        tag_file=data["tag_file"],
        record_id=data["record_id"],
        repo=data["repo"],
        workspace=data["workspace"],
        scope_type=data["scope_type"],
        scope=data["scope"],
        language=data["language"],
        bug_class=data["bug_class"],
        attack_classes=tuple(data["attack_classes"]),
        impact_class=data["impact_class"],
        severity=data["severity"],
        outcome=data["outcome"],
        quality=data["quality"],
        action_summary=data["action_summary"],
        attacker_role=data.get("attacker_role", ""),
        is_predicate=data.get("is_predicate", False),
        preconditions=frozenset(data["preconditions"]),
        postconditions=frozenset(data["postconditions"]),
    )


def load_steps(
    tag_dir: Path, cache_path: Path | None = None
) -> tuple[list[ExploitStep], list[dict[str, str]]]:
    """Load + normalize every tag YAML into an ExploitStep.

    W6-9 incremental mode: when `cache_path` is given, each file's normalized
    step is cached keyed by (path, mtime_ns, size). On the next run only files
    whose mtime/size changed are re-parsed - unchanged files skip the costly
    YAML parse entirely. The cache is rewritten atomically at the end so a
    crashed run never leaves a corrupt cache.
    """
    cache: dict[str, Any] = {}
    if cache_path is not None and cache_path.is_file():
        try:
            loaded = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and loaded.get("schema") == CACHE_SCHEMA:
                cache = loaded.get("entries", {})
        except Exception:
            cache = {}  # corrupt cache - fall back to full parse

    steps: list[ExploitStep] = []
    skipped: list[dict[str, str]] = []
    new_cache: dict[str, Any] = {}
    cache_hits = 0
    cache_misses = 0
    for path in sorted(list(tag_dir.rglob("*.yaml")) + list(tag_dir.rglob("*.yml"))):
        key = str(path.relative_to(tag_dir))
        try:
            stat = path.stat()
            fp = f"{stat.st_mtime_ns}:{stat.st_size}"
        except OSError:
            fp = ""
        cached = cache.get(key)
        if cache_path is not None and cached and cached.get("fp") == fp:
            cache_hits += 1
            new_cache[key] = cached
            if cached.get("step") is not None:
                steps.append(_step_from_cache(cached["step"]))
            elif cached.get("skip"):
                skipped.append({"tag_file": path.name, "reason": cached["skip"]})
            continue
        cache_misses += 1
        try:
            doc = yaml_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            reason = f"yaml_parse_error: {exc}"
            skipped.append({"tag_file": path.name, "reason": reason})
            new_cache[key] = {"fp": fp, "step": None, "skip": reason}
            continue
        if not isinstance(doc, dict):
            reason = "top_level_not_mapping"
            skipped.append({"tag_file": path.name, "reason": reason})
            new_cache[key] = {"fp": fp, "step": None, "skip": reason}
            continue
        step = normalize_step(path, doc)
        if step is None:
            reason = "missing_step_signals"
            skipped.append({"tag_file": path.name, "reason": reason})
            new_cache[key] = {"fp": fp, "step": None, "skip": reason}
            continue
        steps.append(step)
        new_cache[key] = {"fp": fp, "step": _step_to_cache(step), "skip": None}

    if cache_path is not None:
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache_path.with_suffix(cache_path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(
                    {"schema": CACHE_SCHEMA, "tag_dir": str(tag_dir), "entries": new_cache},
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            tmp.replace(cache_path)
        except OSError:
            pass
    load_steps.last_cache_stats = {"cache_hits": cache_hits, "cache_misses": cache_misses}  # type: ignore[attr-defined]
    return steps, skipped


def load_predicate_steps(predicate_jsonl: Path) -> tuple[list[ExploitStep], list[dict[str, str]]]:
    """Load W5-F4 composable predicate nodes as additional chain steps.

    `hackerman-predicate-compose.py --out <file>` writes one composable
    predicate node per line. Those nodes carry `requires_state` /
    `yields_state` token sets drawn from the EXACT SAME vocabulary as this
    unifier, so a predicate node can sit on a chain edge between two
    findings. We map requires_state -> preconditions and yields_state ->
    postconditions and tag the step `is_predicate=True` so the ranking and
    output can distinguish a predicate hop from a real finding hop.

    Predicate nodes are scope-keyed by `target_repo` exactly like findings,
    so a predicate only joins a chain inside the same repo - the cross-scope
    isolation guarantee is preserved.
    """
    steps: list[ExploitStep] = []
    skipped: list[dict[str, str]] = []
    for lineno, raw in enumerate(predicate_jsonl.read_text(encoding="utf-8").splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            node = json.loads(raw)
        except Exception as exc:
            skipped.append({"tag_file": f"predicate:line-{lineno}", "reason": f"json_error: {exc}"})
            continue
        if not isinstance(node, dict) or not node.get("composable"):
            continue
        record_id = _text(node.get("predicate_id") or node.get("record_id"))
        if not record_id:
            continue
        repo = _text(node.get("target_repo"))
        scope_type, scope = ("repo", repo) if _repo_is_specific(repo) else ("repo", repo or "unknown")
        pre = frozenset(_text(t) for t in (node.get("requires_state") or []) if _text(t))
        post = frozenset(_text(t) for t in (node.get("yields_state") or []) if _text(t))
        if not (pre or post):
            continue
        steps.append(
            ExploitStep(
                tag_file=_text(node.get("tag_file")) or f"predicate:{record_id}",
                record_id=record_id,
                repo=repo or "unknown",
                workspace="",
                scope_type=scope_type,
                scope=scope,
                language=_text(node.get("target_language")),
                bug_class=_text(node.get("bug_class")) or "composable-predicate",
                attack_classes=(_text(node.get("attack_class")),) if node.get("attack_class") else (),
                impact_class=_text(node.get("impact_class")),
                severity="",  # predicates carry no severity of their own
                outcome="",
                quality=0.0,
                action_summary="composable predicate node (W5-F4)",
                attacker_role=_text(node.get("attacker_role")),
                is_predicate=True,
                preconditions=pre,
                postconditions=post,
            )
        )
    return steps, skipped


# --- chain construction -----------------------------------------------------

def _scope_key(step: ExploitStep) -> tuple[str, str]:
    return (step.scope_type, step.scope)


def build_edges(steps: list[ExploitStep]) -> dict[str, list[tuple[str, frozenset[str]]]]:
    """Adjacency map: producer record_id -> [(consumer record_id, unifying tokens)].

    An edge A->B exists when A.postconditions intersects B.preconditions and the
    two steps share a scope. Self-edges are excluded.

    Depth (W6-9): the prior implementation was O(n^2) per scope - every producer
    rescanned every consumer. This builds a token->consumers inverted index once,
    then each producer only visits consumers that require one of its actual
    postcondition tokens. Complexity drops to O(sum of producer postcond fan-out)
    which is near-linear for the fixed 11-token vocabulary. Output is identical
    to the brute-force version (verified by tests).
    """
    edges: dict[str, list[tuple[str, frozenset[str]]]] = {}
    # token -> consumers (steps with that precondition token), grouped per scope.
    requires_index: dict[str, dict[tuple[str, str], list[ExploitStep]]] = {}
    for consumer in steps:
        if not consumer.preconditions:
            continue
        scope = _scope_key(consumer)
        for tok in consumer.preconditions:
            requires_index.setdefault(tok, {}).setdefault(scope, []).append(consumer)

    for producer in steps:
        if not producer.postconditions:
            continue
        scope = _scope_key(producer)
        # candidate consumers: union of consumers requiring any producer token.
        candidates: dict[str, ExploitStep] = {}
        for tok in producer.postconditions:
            for consumer in requires_index.get(tok, {}).get(scope, ()):
                if consumer.record_id != producer.record_id:
                    candidates[consumer.record_id] = consumer
        for consumer in candidates.values():
            unifying = producer.postconditions & consumer.preconditions
            if unifying:
                edges.setdefault(producer.record_id, []).append(
                    (consumer.record_id, frozenset(unifying))
                )
    # deterministic ordering
    for key in edges:
        edges[key].sort(key=lambda item: (item[0],))
    return edges


def enumerate_chains(
    steps: list[ExploitStep],
    edges: dict[str, list[tuple[str, frozenset[str]]]],
    max_hops: int,
    max_paths: int | None = None,
) -> list[list[tuple[str, frozenset[str]]]]:
    """DFS enumerate simple paths (no repeated record) of >= 2 steps.

    Returns each chain as [(record_id, unifying_tokens_into_this_step)] where the
    first entry's unifying token set is empty (it is the chain head).
    """
    chains: list[list[tuple[str, frozenset[str]]]] = []

    def dfs(path: list[tuple[str, frozenset[str]]], visited: set[str]) -> None:
        if max_paths is not None and len(chains) >= max_paths:
            return
        if len(path) >= 2:
            chains.append(list(path))
            if max_paths is not None and len(chains) >= max_paths:
                return
        if len(path) >= max_hops:
            return
        last = path[-1][0]
        for nxt, unifying in edges.get(last, ()):
            if nxt in visited:
                continue
            visited.add(nxt)
            path.append((nxt, unifying))
            dfs(path, visited)
            path.pop()
            visited.discard(nxt)

    for step in sorted(steps, key=lambda s: s.record_id):
        if max_paths is not None and len(chains) >= max_paths:
            break
        if step.record_id not in edges:
            continue
        dfs([(step.record_id, frozenset())], {step.record_id})
    return chains


def _is_prefix(short: list[str], long: list[str]) -> bool:
    return len(short) < len(long) and long[: len(short)] == short


def _dedup_subsumed(chains: list[list[tuple[str, frozenset[str]]]]) -> list[list[tuple[str, frozenset[str]]]]:
    """Drop chains that are a strict prefix of a longer enumerated chain."""
    as_ids = [[node[0] for node in chain] for chain in chains]
    keep: list[list[tuple[str, frozenset[str]]]] = []
    for idx, chain in enumerate(chains):
        ids = as_ids[idx]
        subsumed = any(
            other_idx != idx and _is_prefix(ids, as_ids[other_idx])
            for other_idx in range(len(chains))
        )
        if not subsumed:
            keep.append(chain)
    return keep


def score_chain_detailed(
    chain: list[tuple[str, frozenset[str]]], by_id: dict[str, ExploitStep]
) -> dict[str, Any]:
    """Richer W6-9 chain ranking.

    Beyond hop-count / strength / token-diversity, this rewards three
    structural properties of a *plausible* exploit chain:

      * severity escalation - a chain whose severity rises (or holds) toward
        the final step is a real escalation path; one that de-escalates is a
        weaker hypothesis. We add a bonus per non-decreasing hop and a final
        bonus when the last step is the most severe.
      * attacker-cost monotonicity - the attacker should not need to *gain*
        privilege mid-chain. A chain whose per-step role cost is
        non-increasing (attacker keeps or sheds privilege) scores higher than
        one that demands privilege re-acquisition.
      * outcome-confirmed weighting - steps with an ACCEPTED/FILED triager
        outcome are real, reproduced bugs; a chain built from confirmed steps
        is far more credible than one built from raw candidates. Rejected /
        duplicate steps are penalised.
    """
    hop_count = len(chain) - 1
    members = [by_id[node[0]] for node in chain]
    n = max(len(members), 1)
    strength = sum(m.step_strength() for m in members) / n
    distinct_tokens = {tok for node in chain for tok in node[1]}

    severities = [_severity_weight(m.severity) for m in members]
    escalating_hops = sum(
        1 for i in range(1, len(severities)) if severities[i] >= severities[i - 1]
    )
    escalation_bonus = escalating_hops * 0.9
    if len(severities) >= 2 and severities[-1] == max(severities):
        escalation_bonus += 1.2

    costs = [_role_cost(m.attacker_role) for m in members]
    monotone_hops = sum(
        1 for i in range(1, len(costs)) if costs[i] <= costs[i - 1]
    )
    cost_monotonicity = monotone_hops / max(len(costs) - 1, 1)
    cost_bonus = round(cost_monotonicity * 1.8, 3)

    confirmed = sum(1 for m in members if _outcome_weight(m.outcome) > 0)
    rejected = sum(1 for m in members if _outcome_weight(m.outcome) < 0)
    outcome_bonus = confirmed * 1.1 - rejected * 0.8

    hop_score = hop_count * 2.4
    strength_score = strength * 0.75
    token_diversity = len(distinct_tokens) * 0.6
    score = round(
        hop_score
        + strength_score
        + token_diversity
        + escalation_bonus
        + cost_bonus
        + outcome_bonus,
        3,
    )
    return {
        "score": score,
        "hop_score": round(hop_score, 3),
        "strength_score": round(strength_score, 3),
        "token_diversity_score": round(token_diversity, 3),
        "escalation_bonus": round(escalation_bonus, 3),
        "escalating_hops": escalating_hops,
        "cost_monotonicity": round(cost_monotonicity, 3),
        "cost_bonus": cost_bonus,
        "confirmed_steps": confirmed,
        "rejected_steps": rejected,
        "outcome_bonus": round(outcome_bonus, 3),
    }


def score_chain(chain: list[tuple[str, frozenset[str]]], by_id: dict[str, ExploitStep]) -> float:
    return score_chain_detailed(chain, by_id)["score"]


def build_chain_record(
    chain: list[tuple[str, frozenset[str]]],
    by_id: dict[str, ExploitStep],
) -> dict[str, Any]:
    members = [by_id[node[0]] for node in chain]
    head = members[0]
    hops: list[dict[str, Any]] = []
    for idx in range(1, len(chain)):
        producer = members[idx - 1]
        consumer = members[idx]
        unifying = sorted(chain[idx][1])
        hops.append(
            {
                "from_record": producer.record_id,
                "to_record": consumer.record_id,
                "unifying_state": unifying,
                "narrative": (
                    f"{producer.bug_class or 'step'} produces "
                    f"{', '.join(unifying)} which satisfies the precondition of "
                    f"{consumer.bug_class or 'the next step'}."
                ),
            }
        )
    score_detail = score_chain_detailed(chain, by_id)
    chain_id = "unify:" + stable_hash({"members": [m.record_id for m in members]}, 12)
    return {
        "chain_id": chain_id,
        "score": score_detail["score"],
        "score_breakdown": score_detail,
        "hop_count": len(chain) - 1,
        "scope_type": head.scope_type,
        "scope": head.scope,
        "severities": sorted({slug(m.severity) for m in members if slug(m.severity)}),
        "impact_classes": sorted({m.impact_class for m in members if m.impact_class}),
        "node_kinds": sorted({"predicate" if m.is_predicate else "finding" for m in members}),
        "predicate_steps": sum(1 for m in members if m.is_predicate),
        "steps": [m.brief() for m in members],
        "hops": hops,
        "chain_narrative": " -> ".join(
            f"[{m.bug_class or (m.attack_classes[0] if m.attack_classes else 'step')}]"
            for m in members
        ),
    }


def normalize_step_from_chain_candidate_row(row: dict[str, Any]) -> ExploitStep | None:
    """Build an `ExploitStep` from one chain-candidates sidecar row.

    This lets the unifier reuse the cached rows from
    `hackerman-chain-candidates-sidecar.py` instead of reparsing every YAML.
    """
    record_id = _text(row.get("record_id"))
    if not record_id:
        return None
    attack_classes = tuple(_text(value) for value in _as_list(row.get("attack_classes")) if _text(value))
    bug_class = _text(row.get("bug_class"))
    if not (bug_class or attack_classes):
        return None
    repo = _text(row.get("repo")) or "unknown"
    workspace = _text(row.get("workspace"))
    scope_type = _text(row.get("scope_type"))
    scope = _text(row.get("scope"))
    if not scope_type or not scope:
        if _repo_is_specific(repo):
            scope_type, scope = "repo", repo
        elif workspace:
            scope_type, scope = "workspace", workspace
        else:
            scope_type, scope = "repo", repo or "unknown"
    attacker_role = _text(row.get("attacker_role"))
    precondition_lines = [_text(v) for v in _as_list(row.get("required_preconditions")) if _text(v)]
    action = _text(row.get("action_summary"))
    if action:
        precondition_lines.append(action)
    pre = derive_preconditions(precondition_lines, attacker_role, attack_classes)
    post = derive_postconditions(attack_classes, _text(row.get("impact_class")))
    return ExploitStep(
        tag_file=_text(row.get("tag_file")) or f"sidecar:{record_id}",
        record_id=record_id,
        repo=repo,
        workspace=workspace,
        scope_type=scope_type,
        scope=scope,
        language=_text(row.get("language")),
        bug_class=bug_class,
        attack_classes=attack_classes,
        impact_class=_text(row.get("impact_class")),
        severity=_text(row.get("severity")),
        outcome=_text(row.get("outcome")),
        quality=_safe_float(row.get("quality")),
        action_summary=action[:280],
        attacker_role=attacker_role,
        preconditions=frozenset(pre),
        postconditions=frozenset(post),
    )


def load_steps_from_chain_candidate_rows(
    rows: list[dict[str, Any]],
) -> tuple[list[ExploitStep], list[dict[str, str]]]:
    steps: list[ExploitStep] = []
    skipped: list[dict[str, str]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            skipped.append(
                {
                    "tag_file": f"sidecar:line-{index + 2}",
                    "reason": "row_not_mapping",
                }
            )
            continue
        step = normalize_step_from_chain_candidate_row(row)
        if step is None:
            skipped.append(
                {
                    "tag_file": _text(row.get("tag_file")) or f"sidecar:line-{index + 2}",
                    "reason": "missing_step_signals",
                }
            )
            continue
        steps.append(step)
    return steps, skipped


def _build_payload_from_steps(
    *,
    tag_dir: Path,
    limit: int,
    max_hops: int,
    steps: list[ExploitStep],
    skipped: list[dict[str, str]],
    cache_hits: int,
    cache_misses: int,
    predicate_steps_loaded: int,
    max_chains_per_scope: int | None = None,
) -> dict[str, Any]:
    chainable = [s for s in steps if s.chainable]
    unchainable = [s for s in steps if not s.chainable]

    # group by scope; bound per-scope blast radius for deterministic runtime.
    by_scope: dict[tuple[str, str], list[ExploitStep]] = {}
    for step in chainable:
        by_scope.setdefault(_scope_key(step), []).append(step)

    all_chains: list[dict[str, Any]] = []
    by_id: dict[str, ExploitStep] = {s.record_id: s for s in chainable}
    scopes_searched = 0
    scopes_truncated = 0
    chain_search_truncated_scopes = 0
    for scope_key in sorted(by_scope):
        scope_steps = sorted(by_scope[scope_key], key=lambda s: s.record_id)
        if len(scope_steps) > MAX_STEPS_PER_SCOPE:
            scope_steps = scope_steps[:MAX_STEPS_PER_SCOPE]
            scopes_truncated += 1
        scopes_searched += 1
        edges = build_edges(scope_steps)
        if not edges:
            continue
        raw_chains = enumerate_chains(
            scope_steps,
            edges,
            max_hops,
            max_paths=max_chains_per_scope,
        )
        if max_chains_per_scope is not None and len(raw_chains) >= max_chains_per_scope:
            chain_search_truncated_scopes += 1
        for chain in _dedup_subsumed(raw_chains):
            all_chains.append(build_chain_record(chain, by_id))

    all_chains.sort(
        key=lambda c: (
            -float(c["score"]),
            -int(c["hop_count"]),
            c["scope"],
            c["chain_id"],
        )
    )
    chains = all_chains[:limit]
    for rank, chain in enumerate(chains, start=1):
        chain["rank"] = rank

    digest = stable_hash(
        {
            "schema": SCHEMA,
            "tag_dir": str(tag_dir),
            "chains": [(c["chain_id"], c["score"]) for c in chains],
        },
        64,
    )
    return {
        "schema": SCHEMA,
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "source_tag_dir": str(tag_dir),
        "total_records_loaded": len(steps),
        "predicate_steps_loaded": predicate_steps_loaded,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "chainable_steps": len(chainable),
        "unchainable_steps": len(unchainable),
        "unchainable_sample": [s.record_id for s in unchainable[:20]],
        "total_files_skipped": len(skipped),
        "skipped_sample": skipped[:20],
        "scopes_searched": scopes_searched,
        "scopes_truncated": scopes_truncated,
        "chain_search_truncated_scopes": chain_search_truncated_scopes,
        "max_chains_per_scope": max_chains_per_scope,
        "max_hops": max_hops,
        "total_chains": len(all_chains),
        "limit": limit,
        "chains": chains,
    }


def build_payload(
    tag_dir: Path,
    limit: int,
    max_hops: int,
    cache_path: Path | None = None,
    predicate_jsonl: Path | None = None,
    max_chains_per_scope: int | None = None,
) -> dict[str, Any]:
    steps, skipped = load_steps(tag_dir, cache_path)
    cache_stats = getattr(load_steps, "last_cache_stats", {"cache_hits": 0, "cache_misses": 0})
    predicate_steps_loaded = 0
    if predicate_jsonl is not None and predicate_jsonl.is_file():
        pred_steps, pred_skipped = load_predicate_steps(predicate_jsonl)
        # de-dup against any finding sharing the same record_id
        known_ids = {s.record_id for s in steps}
        pred_steps = [p for p in pred_steps if p.record_id not in known_ids]
        predicate_steps_loaded = len(pred_steps)
        steps.extend(pred_steps)
        skipped.extend(pred_skipped)
    return _build_payload_from_steps(
        tag_dir=tag_dir,
        limit=limit,
        max_hops=max_hops,
        steps=steps,
        skipped=skipped,
        cache_hits=int(cache_stats.get("cache_hits") or 0),
        cache_misses=int(cache_stats.get("cache_misses") or 0),
        predicate_steps_loaded=predicate_steps_loaded,
        max_chains_per_scope=max_chains_per_scope,
    )


def build_payload_from_chain_candidate_rows(
    tag_dir: Path,
    rows: list[dict[str, Any]],
    limit: int,
    max_hops: int,
    predicate_jsonl: Path | None = None,
    max_chains_per_scope: int | None = None,
) -> dict[str, Any]:
    """Build unified chains from pre-normalized chain-candidate sidecar rows."""
    steps, skipped = load_steps_from_chain_candidate_rows(rows)
    predicate_steps_loaded = 0
    if predicate_jsonl is not None and predicate_jsonl.is_file():
        pred_steps, pred_skipped = load_predicate_steps(predicate_jsonl)
        known_ids = {s.record_id for s in steps}
        pred_steps = [p for p in pred_steps if p.record_id not in known_ids]
        predicate_steps_loaded = len(pred_steps)
        steps.extend(pred_steps)
        skipped.extend(pred_skipped)
    return _build_payload_from_steps(
        tag_dir=tag_dir,
        limit=limit,
        max_hops=max_hops,
        steps=steps,
        skipped=skipped,
        cache_hits=0,
        cache_misses=0,
        predicate_steps_loaded=predicate_steps_loaded,
        max_chains_per_scope=max_chains_per_scope,
    )


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Hackerman Exploit-Chain Unifier",
        "",
        f"- Schema: `{payload['schema']}`",
        f"- Source tag dir: `{payload['source_tag_dir']}`",
        f"- Records loaded: {payload['total_records_loaded']}",
        f"- Chainable steps: {payload['chainable_steps']}",
        f"- Predicate steps loaded (W5-F4): {payload.get('predicate_steps_loaded', 0)}",
        f"- Cache hits / misses: {payload.get('cache_hits', 0)} / {payload.get('cache_misses', 0)}",
        f"- Unchainable steps (no precond/postcond signal): {payload['unchainable_steps']}",
        f"- Scopes searched: {payload['scopes_searched']}",
        f"- Chains found: {payload['total_chains']} (showing top {len(payload['chains'])})",
        f"- Max hops: {payload['max_hops']}",
        "",
        "Each chain is a sequence step_1 -> ... -> step_N where step K's "
        "postconditions satisfy step K+1's preconditions. Tokens are derived "
        "deterministically from a fixed vocabulary; steps with no usable "
        "precondition/postcondition signal are marked unchainable and excluded.",
        "",
        "These are offline corpus-derived hypotheses. Treat each chain as a "
        "lead until source-level control/data-flow proves the unification.",
    ]
    if not payload.get("chains"):
        lines.extend(["", "No multi-step exploit chains were found."])
        return "\n".join(lines) + "\n"
    for chain in payload["chains"]:
        lines.extend(
            [
                "",
                f"## {chain['rank']}. {chain['chain_id']} score={chain['score']} "
                f"hops={chain['hop_count']}",
                "",
                f"- Scope: `{chain['scope_type']}` `{chain['scope']}`",
                f"- Severities: {', '.join(chain['severities']) or 'n/a'}",
                f"- Impact classes: {', '.join(chain['impact_classes']) or 'n/a'}",
                f"- Node kinds: {', '.join(chain.get('node_kinds', [])) or 'n/a'} "
                f"(predicate steps: {chain.get('predicate_steps', 0)})",
                f"- Score breakdown: escalation={chain['score_breakdown']['escalation_bonus']} "
                f"cost-monotonicity={chain['score_breakdown']['cost_monotonicity']} "
                f"confirmed-steps={chain['score_breakdown']['confirmed_steps']}",
                f"- Chain: {chain['chain_narrative']}",
                "- Hops:",
            ]
        )
        for hop in chain["hops"]:
            lines.append(
                f"  - `{hop['from_record']}` -> `{hop['to_record']}` "
                f"via {', '.join(hop['unifying_state']) or 'n/a'}"
            )
            lines.append(f"    {hop['narrative']}")
        lines.append("- Steps:")
        for step in chain["steps"]:
            lines.append(
                f"  - `{step['record_id']}` {step['bug_class'] or 'pattern'} "
                f"severity={step['severity'] or 'unknown'} "
                f"pre={sorted(step['preconditions'])} post={sorted(step['postconditions'])}"
            )
    return "\n".join(lines) + "\n"


def clamp_limit(value: int) -> int:
    return max(0, min(int(value), MAX_LIMIT))


def clamp_hops(value: int) -> int:
    return max(2, min(int(value), MAX_HOPS_CAP))


def clamp_chains_per_scope(value: int | None) -> int | None:
    if value is None:
        return None
    parsed = int(value)
    if parsed <= 0:
        return None
    return max(1, min(parsed, MAX_CHAINS_PER_SCOPE_CAP))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR), help="Directory containing corpus tag YAML files")
    parser.add_argument("--limit", type=int, default=20, help=f"Maximum chains to emit, capped at {MAX_LIMIT}")
    parser.add_argument("--max-hops", type=int, default=4, help=f"Maximum steps per chain, capped at {MAX_HOPS_CAP}")
    parser.add_argument(
        "--max-chains-per-scope",
        type=int,
        default=0,
        help=(
            "Optional cap on raw chains enumerated per scope before ranking. "
            f"0 means uncapped; positive values are capped at {MAX_CHAINS_PER_SCOPE_CAP}."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    parser.add_argument("--out", default="-", help="Output path, or - for stdout")
    parser.add_argument(
        "--cache",
        default=None,
        help="Incremental step cache path. Unchanged tag files skip re-parse on the next run.",
    )
    parser.add_argument(
        "--predicates",
        default=None,
        help="JSONL of W5-F4 composable predicates (hackerman-predicate-compose.py --out). "
        "Predicate nodes join chains as additional steps via the shared token vocabulary.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tag_dir = Path(args.tag_dir)
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2
    cache_path = Path(args.cache) if args.cache else None
    predicate_jsonl = Path(args.predicates) if args.predicates else None
    payload = build_payload(
        tag_dir,
        clamp_limit(args.limit),
        clamp_hops(args.max_hops),
        cache_path=cache_path,
        predicate_jsonl=predicate_jsonl,
        max_chains_per_scope=clamp_chains_per_scope(args.max_chains_per_scope),
    )
    rendered = (
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if args.json
        else render_markdown(payload)
    )
    if args.out == "-":
        sys.stdout.write(rendered)
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
