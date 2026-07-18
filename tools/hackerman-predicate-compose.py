#!/usr/bin/env python3
"""hackerman-predicate-compose.py - composable typed exploit predicates.

Lane W5-F4 / plan H-predicate-composability.

Problem
-------
`hackerman-exploit-predicates.py` emits structural single-condition
predicates: it splits a record into `attacker_role` / `action` /
`precondition` / `vulnerable_asset` / `impact` rows. Each row is a flat
free-text description. The hackermind audit found these are NOT composable -
there is no typed state vocabulary, so you cannot reason "predicate A's
output satisfies predicate B's input".

Model
-----
This tool upgrades each corpus record into ONE composable predicate node:

  * requires_state  - precondition state/capability tokens the predicate
    REQUIRES before it can fire.
  * produces_state  - postcondition state/capability tokens the predicate
    PRODUCES once it fires.
  * yields_state    - legacy alias for produces_state.

Both token sets are drawn from the EXACT SAME fixed vocabulary as
`hackerman-chain-unify.py` (lane W5-F2). Predicates and chains therefore
speak one language: a predicate node from this tool and an exploit-chain
step from the unifier are token-compatible. Two predicates A and B
compose when `A.produces_state` intersects `B.requires_state` - the
intersection is the named bridging state.

This tool does NOT edit chain-unify; it imports its vocabulary and
`derive_preconditions` / `derive_postconditions` functions read-only.

Conservatism
------------
Token derivation is deterministic and stdlib-only (no LLM, no network).
A record with neither requires_state nor produces_state carries no usable
composability signal and is marked `non-composable` - it is never given
fabricated tokens. The structural predicate rows from the upstream miner
are preserved verbatim under `structural_predicates` so no information
is lost; this tool is purely additive.

Usage
-----
    hackerman-predicate-compose.py --tag-dir audit/corpus_tags/tags --json
    hackerman-predicate-compose.py --tag-dir <dir> --out agent_outputs/composable.jsonl
    hackerman-predicate-compose.py --tag-dir <dir> --query-yields state:protocol-funds-displaced --json
    hackerman-predicate-compose.py --tag-dir <dir> --query-requires state:reentrant-execution-context --json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

SCHEMA = "auditooor.hackerman_predicate_compose.v1"
SUMMARY_SCHEMA = "auditooor.hackerman_predicate_compose.summary.v1"
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"


def _load_module(file_name: str, mod_name: str) -> Any:
    """Load a hyphenated tools/ script as a module without editing it.

    The module is registered in `sys.modules` before `exec_module` so that
    `@dataclass`-decorated classes inside it resolve their owning module
    (Python 3.12+ dataclass machinery dereferences `cls.__module__`).
    """
    path = TOOLS_DIR / file_name
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {file_name}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# Consume the W5-F2 exploit-chain unifier vocabulary and derivation logic.
# We do NOT edit chain-unify; we read its closed token set so predicates and
# chains share one language.
_CHAIN = _load_module("hackerman-chain-unify.py", "_w5f4_chain_unify")
_PREDS = _load_module("hackerman-exploit-predicates.py", "_w5f4_exploit_predicates")

ALL_TOKENS = tuple(_CHAIN.ALL_TOKENS)
derive_preconditions = _CHAIN.derive_preconditions
derive_postconditions = _CHAIN.derive_postconditions
STATE_VOCABULARY_SOURCE = getattr(
    _PREDS,
    "STATE_VOCABULARY_SOURCE",
    "tools/hackerman-chain-unify.py:ALL_TOKENS:derive_preconditions:derive_postconditions",
)


def stable_hash(payload: Any, length: int = 16) -> str:
    data = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:length]


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _closed_state_tokens(tokens: Any) -> list[str]:
    if not isinstance(tokens, list):
        return []
    allowed = set(ALL_TOKENS)
    return sorted(_as_text(token) for token in tokens if _as_text(token) in allowed)


def compose_record(structural_row: dict[str, Any]) -> dict[str, Any]:
    """Upgrade one structural-predicate row into a composable predicate node.

    `structural_row` is one record emitted by hackerman-exploit-predicates.py.
    The structural predicate rows are preserved verbatim; we add typed
    requires_state / produces_state token sets drawn from the chain-unify
    vocabulary so the predicate composes with exploit-chain steps.
    """
    attack_class = _as_text(structural_row.get("attack_class"))
    impact_class = ""
    impacts = structural_row.get("impacts")
    if isinstance(impacts, list) and impacts and isinstance(impacts[0], dict):
        impact_class = _as_text(impacts[0].get("impact_class"))
    attacker_role = _as_text(structural_row.get("attacker_role"))

    # precondition free-text lines: required_preconditions plus the action
    # narrative, mirroring chain-unify.normalize_step so token derivation is
    # identical to what the unifier would produce for the same record.
    precondition_lines = [_as_text(x) for x in (structural_row.get("preconditions") or []) if _as_text(x)]
    precondition_lines.extend(_as_text(a) for a in (structural_row.get("actions") or []) if _as_text(a))

    has_upstream_state = (
        "requires_state" in structural_row
        or "produces_state" in structural_row
        or "yields_state" in structural_row
    )
    if has_upstream_state:
        requires = set(_closed_state_tokens(structural_row.get("requires_state")))
        produces = set(
            _closed_state_tokens(
                structural_row.get("produces_state", structural_row.get("yields_state"))
            )
        )
    else:
        attack_classes = (attack_class,) if attack_class else ()
        requires = derive_preconditions(precondition_lines, attacker_role, attack_classes)
        produces = derive_postconditions(attack_classes, impact_class)

    composable = bool(requires or produces)
    produces_state = sorted(produces)
    node: dict[str, Any] = {
        "schema": SCHEMA,
        "record_id": _as_text(structural_row.get("record_id")),
        "source_audit_ref": _as_text(structural_row.get("source_audit_ref")),
        "tag_file": _as_text(structural_row.get("tag_file")),
        "target_repo": _as_text(structural_row.get("target_repo")),
        "target_language": _as_text(structural_row.get("target_language")),
        "target_component": _as_text(structural_row.get("target_component")),
        "bug_class": _as_text(structural_row.get("bug_class")),
        "attack_class": attack_class,
        "impact_class": impact_class,
        "attacker_role": attacker_role,
        "requires_state": sorted(requires),
        "produces_state": produces_state,
        "yields_state": produces_state,
        "state_vocabulary_source": _as_text(
            structural_row.get("state_vocabulary_source")
        )
        or STATE_VOCABULARY_SOURCE,
        "composable": composable,
        # structural predicate rows preserved verbatim - additive, lossless.
        "structural_predicates": structural_row.get("predicates", []),
    }
    node["predicate_id"] = "predcompose:" + stable_hash(
        {
            "record_id": node["record_id"],
            "requires": node["requires_state"],
            "yields": node["yields_state"],
        },
        16,
    )
    return node


def build_payload(tag_dir: Path) -> dict[str, Any]:
    structural = _PREDS.extract_rows(tag_dir)
    nodes = [compose_record(row) for row in structural.get("records", [])]
    nodes.sort(key=lambda n: n["record_id"])

    composable = [n for n in nodes if n["composable"]]
    non_composable = [n for n in nodes if not n["composable"]]

    # composability graph stats: for each token, how many predicates yield it
    # vs require it. A token with both producers and consumers is a live
    # composition bridge.
    yields_index: dict[str, list[str]] = {tok: [] for tok in ALL_TOKENS}
    requires_index: dict[str, list[str]] = {tok: [] for tok in ALL_TOKENS}
    for node in composable:
        for tok in node["produces_state"]:
            yields_index.setdefault(tok, []).append(node["record_id"])
        for tok in node["requires_state"]:
            requires_index.setdefault(tok, []).append(node["record_id"])

    token_stats = []
    composition_pairs = 0
    for tok in sorted(ALL_TOKENS):
        producers = sorted(yields_index.get(tok, []))
        consumers = sorted(requires_index.get(tok, []))
        bridge = bool(producers and consumers)
        if bridge:
            composition_pairs += len(producers) * len(consumers)
        token_stats.append(
            {
                "token": tok,
                "producer_count": len(producers),
                "consumer_count": len(consumers),
                "is_composition_bridge": bridge,
            }
        )

    digest = stable_hash(
        {
            "schema": SUMMARY_SCHEMA,
            "tag_dir": str(tag_dir),
            "nodes": [(n["predicate_id"], n["record_id"]) for n in nodes],
        },
        64,
    )
    return {
        "schema": SUMMARY_SCHEMA,
        "context_pack_id": f"{SUMMARY_SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "source_tag_dir": str(tag_dir),
        "shared_vocabulary_source": "tools/hackerman-chain-unify.py",
        "vocabulary_token_count": len(ALL_TOKENS),
        "total_records": len(nodes),
        "composable_predicates": len(composable),
        "non_composable_predicates": len(non_composable),
        "composition_bridge_pairs": composition_pairs,
        "token_stats": token_stats,
        "predicates": nodes,
    }


def query_payload(payload: dict[str, Any], requires: str | None, yields: str | None) -> dict[str, Any]:
    """Query path: filter composable predicates by a state token.

    `--query-requires X` returns predicates that REQUIRE X (consumers of X).
    `--query-yields X`   returns predicates that PRODUCE X (legacy name).
    Supplying both narrows to predicates that require one and yield the other -
    a single-predicate composition pivot.
    """
    matches = []
    for node in payload["predicates"]:
        if not node["composable"]:
            continue
        if requires is not None and requires not in node["requires_state"]:
            continue
        if yields is not None and yields not in node["produces_state"]:
            continue
        matches.append(
            {
                "predicate_id": node["predicate_id"],
                "record_id": node["record_id"],
                "bug_class": node["bug_class"],
                "attack_class": node["attack_class"],
                "requires_state": node["requires_state"],
                "produces_state": node["produces_state"],
                "yields_state": node["yields_state"],
            }
        )
    return {
        "schema": f"{SCHEMA}.query",
        "source_tag_dir": payload["source_tag_dir"],
        "query_requires": requires,
        "query_yields": yields,
        "match_count": len(matches),
        "matches": matches,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Hackerman Composable Exploit Predicates",
        "",
        f"- Schema: `{payload['schema']}`",
        f"- Source tag dir: `{payload['source_tag_dir']}`",
        f"- Shared vocabulary: `{payload['shared_vocabulary_source']}` "
        f"({payload['vocabulary_token_count']} tokens)",
        f"- Total records: {payload['total_records']}",
        f"- Composable predicates: {payload['composable_predicates']}",
        f"- Non-composable predicates (no token signal): {payload['non_composable_predicates']}",
        f"- Composition bridge pairs: {payload['composition_bridge_pairs']}",
        "",
        "Each predicate carries typed `requires_state` / `produces_state` token "
        "sets drawn from the exploit-chain unifier vocabulary. Predicate A "
        "composes with predicate B when `A.produces_state` intersects "
        "`B.requires_state`. Tokens are derived deterministically; predicates "
        "with no token signal are marked non-composable.",
        "",
        "## State token composition stats",
        "",
        "| token | producers | consumers | bridge |",
        "| --- | --- | --- | --- |",
    ]
    for stat in payload["token_stats"]:
        lines.append(
            f"| `{stat['token']}` | {stat['producer_count']} | "
            f"{stat['consumer_count']} | {'yes' if stat['is_composition_bridge'] else 'no'} |"
        )
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR), help="Directory of corpus tag YAML files")
    parser.add_argument("--out", default=None, help="Write output to this path. Use '-' for stdout.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    parser.add_argument("--query-requires", default=None, help="Return predicates that require this state token")
    parser.add_argument("--query-yields", default=None, help="Return predicates that yield this state token")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tag_dir = Path(args.tag_dir)
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2

    payload = build_payload(tag_dir)

    if args.query_requires is not None or args.query_yields is not None:
        result: Any = query_payload(payload, args.query_requires, args.query_yields)
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    elif args.json:
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    elif args.out is not None:
        # default file output is JSONL of predicate nodes (one node per line)
        rendered = "".join(
            json.dumps(node, sort_keys=True) + "\n" for node in payload["predicates"]
        )
    else:
        rendered = render_markdown(payload)

    if args.out is None or args.out == "-":
        sys.stdout.write(rendered)
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
