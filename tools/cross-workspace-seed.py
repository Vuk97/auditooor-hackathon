#!/usr/bin/env python3
# r36-rebuttal: registered in .auditooor/agent_pathspec.json as lane cross-seed-fix3; orchestrator commits
"""
cross-workspace-seed.py — Pull prior cross-workspace learnings at audit-start.

FIX 3 (cross-workspace-seed as a wired, mandatory pipeline step).

At audit start, derive the workspace's protocol family / language signals,
pull prior learnings for the SAME family/language from the corpus via the
vault MCP callables, and write them to
``<ws>/.auditooor/cross_workspace_seed.json`` plus a brief-injectable markdown
block at ``<ws>/.auditooor/cross_workspace_seed.md`` so the next dispatch
brief surfaces e.g. prior Morpho-Blue invariants automatically when a new
Morpho-family workspace is audited.

Three corpus pulls (each advisory; a vault failure degrades gracefully and
NEVER fails the audit):
  1. vault_known_dead_ends   — confirmed-futile candidate paths to skip.
  2. vault_corpus_search     — prior findings keyed by attack-surface
                               language / target_domain (same protocol family).
  3. vault_cross_language_pattern_lift — patterns liftable from a sibling
                               language into this workspace's language.

RELATED TOOLS (tool-duplication preflight, CLAUDE.md operational anchor):
  - tools/cross-ws-pattern-mapper.py        : maps CCIA attack angles across
        workspaces (which bug class found where). DOES NOT pull corpus
        learnings INTO a fresh workspace's seed at audit-start; it is a
        cross-workspace coverage matrix, not a per-workspace intake seed.
  - tools/cross-workspace-state-aggregator.py : repo-level state DASHBOARD
        (filed/paid counts). Post-hoc reporting, not intake seeding.
  - tools/cross-workspace-finding-linker.py : finding-to-finding linkage
        GRAPH across workspaces. Post-hoc, not intake.
  - tools/cross-workspace-duplicate-check.py: dedup gate before filing.
  GAP THIS TOOL FILLS: none of the above runs at audit-start, derives the
  workspace's family/language, pulls prior same-family learnings from the
  corpus, and writes a brief-injectable seed. This tool is the intake-seed
  step; the others are coverage/dedup/reporting steps.

Usage:
    cross-workspace-seed.py --workspace <ws> [--limit N] [--vault-server PATH]
        [--json] [--quiet]

Exit codes:
    0  seed written (even if vault pulls degraded — degraded is recorded, not fatal)
    2  usage error (missing/invalid workspace)
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.cross_workspace_seed.v1"

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VAULT_SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"

# Map common file extensions -> corpus target_language token.
# Only the source-bearing extensions matter; config/asset extensions are
# intentionally excluded so they don't drown the primary-language signal.
EXT_TO_LANGUAGE: Dict[str, str] = {
    ".sol": "solidity",
    ".go": "go",
    ".rs": "rust",
    ".move": "move",
    ".cairo": "cairo",
    ".vy": "vyper",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".py": "python",
    ".circom": "circom",
    ".nr": "noir",
}

# r36-rebuttal: registered lane cross-seed-fix3; orchestrator commits
# Security-relevant compiled / chain languages. When ANY of these is present
# in meaningful volume, it is chosen as the primary language even if a
# scripting language (TS/JS/Py) has a higher raw file count. dYdX is the
# canonical case: its monorepo has more `.ts` (indexer/frontend) than `.go`,
# but the security surface and corpus findings are keyed on `go`. Choosing
# `typescript` would miss every same-family corpus record.
SECURITY_LANGUAGES = frozenset(
    {"solidity", "go", "rust", "move", "cairo", "vyper", "circom", "noir"}
)

# Map repo-name / asset substrings -> protocol-family / target_domain token.
# Ordered most-specific first; first match wins.
FAMILY_SIGNALS: List[Tuple[str, str]] = [
    ("morpho", "morpho-blue"),
    ("aave", "aave"),
    ("compound", "compound"),
    ("euler", "euler"),
    ("uniswap", "uniswap"),
    ("curve", "curve"),
    ("balancer", "balancer"),
    ("erc4626", "erc4626-vault"),
    ("erc-4626", "erc4626-vault"),
    ("dydx", "dydx-perps"),
    ("cosmos", "cosmos-sdk"),
    ("cometbft", "cosmos-sdk"),
    ("tendermint", "cosmos-sdk"),
    ("substrate", "substrate"),
    ("polkadot", "substrate"),
    ("parachain", "substrate"),
    ("hyperbridge", "cross-chain-bridge"),
    ("ismp", "cross-chain-bridge"),
    ("bridge", "cross-chain-bridge"),
    ("optimism", "l2-rollup"),
    ("arbitrum", "l2-rollup"),
    ("rollup", "l2-rollup"),
    ("spark", "bitcoin-statechain"),
    ("statechain", "bitcoin-statechain"),
    ("lightning", "bitcoin-lightning"),
    ("frost", "threshold-signing"),
    ("solana", "solana"),
    ("anchor", "solana"),
    ("aztec", "zk-rollup"),
    ("zk", "zk-rollup"),
    ("circom", "zk-circuit"),
]


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_workspace(raw: str) -> Optional[Path]:
    if not raw:
        return None
    p = Path(os.path.expanduser(raw)).resolve()
    if not p.is_dir():
        return None
    return p


def _load_intake(ws: Path) -> Dict[str, Any]:
    f = ws / "INTAKE_BASELINE.json"
    if not f.is_file():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _read_targets_tsv(ws: Path) -> List[str]:
    """Return non-comment repo tokens from targets.tsv."""
    f = ws / "targets.tsv"
    repos: List[str] = []
    if not f.is_file():
        return repos
    try:
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # first column is the repo url/token
            parts = line.split()
            first = parts[0] if parts else ""
            if first:
                repos.append(first.lower())
    except OSError:
        return repos
    return repos


def derive_language(intake: Dict[str, Any], ws: Path) -> Tuple[str, Dict[str, int]]:
    """Derive the primary corpus language token from extension counts.

    Returns (language_token_or_empty, source_ext_counts_for_audit).
    Falls back to a live filesystem scan if INTAKE_BASELINE.json has no counts.
    """
    counts = intake.get("file_extension_counts") or {}
    if not isinstance(counts, dict) or not counts:
        counts = _scan_extension_counts(ws)

    lang_tally: Counter = Counter()
    source_ext_counts: Dict[str, int] = {}
    for ext, n in counts.items():
        if not isinstance(n, int):
            continue
        lang = EXT_TO_LANGUAGE.get(str(ext).lower())
        if lang:
            lang_tally[lang] += n
            source_ext_counts[str(ext).lower()] = n

    # r36-rebuttal: registered lane cross-seed-fix3; orchestrator commits
    if not lang_tally:
        return "", source_ext_counts
    # Prefer a security-relevant compiled/chain language when present in
    # meaningful volume, even if a scripting language has a higher raw count.
    sec = [(lang, n) for lang, n in lang_tally.items() if lang in SECURITY_LANGUAGES]
    if sec:
        sec.sort(key=lambda kv: kv[1], reverse=True)
        return sec[0][0], source_ext_counts
    primary = lang_tally.most_common(1)[0][0]
    return primary, source_ext_counts


def _scan_extension_counts(ws: Path, max_files: int = 200000) -> Dict[str, int]:
    """Lightweight fallback extension scan (only source-bearing extensions)."""
    counts: Counter = Counter()
    seen = 0
    wanted = set(EXT_TO_LANGUAGE.keys())
    for root, dirs, files in os.walk(ws):
        # skip noise dirs
        dirs[:] = [
            d
            for d in dirs
            if d not in (".git", "node_modules", "target", ".auditooor", "prior_audits")
        ]
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in wanted:
                counts[ext] += 1
            seen += 1
            if seen >= max_files:
                return dict(counts)
    return dict(counts)


def derive_families(intake: Dict[str, Any], repos: List[str]) -> List[str]:
    """Derive protocol-family / target_domain tokens from repos + assets.

    Returns a de-duplicated, order-preserving list (most-significant first).
    """
    haystacks: List[str] = []
    haystacks.extend(repos)
    assets = intake.get("assets_in_scope") or []
    if isinstance(assets, list):
        haystacks.extend(str(a).lower() for a in assets)
    summary = intake.get("summary")
    if isinstance(summary, str):
        haystacks.append(summary.lower())

    blob = " ".join(haystacks)
    families: List[str] = []
    for needle, family in FAMILY_SIGNALS:
        if needle in blob and family not in families:
            families.append(family)
    return families


# r36-rebuttal: registered lane cross-seed-fix3; orchestrator commits
# Per-call vault timeout. The server cold-loads on each subprocess spawn and a
# corpus_search over the full tagged corpus can take >60s; 150s is the
# graceful ceiling before recording a `timeout:` degrade reason.
VAULT_CALL_TIMEOUT = int(os.environ.get("CROSS_SEED_VAULT_TIMEOUT", "150"))


def _call_vault(
    vault_server: Path,
    callable_name: str,
    args_obj: Dict[str, Any],
    timeout: int = VAULT_CALL_TIMEOUT,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Invoke a vault callable as a subprocess. Returns (parsed_json, error)."""
    if not vault_server.is_file():
        return None, f"vault-server-missing:{vault_server}"
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(vault_server),
                "--call",
                callable_name,
                "--args",
                json.dumps(args_obj),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        return None, f"timeout:{callable_name}"
    except OSError as exc:  # pragma: no cover - defensive
        return None, f"oserror:{exc}"
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip().splitlines()
        return None, f"rc={proc.returncode}:{msg[-1] if msg else 'no-output'}"
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError:
        return None, "json-decode-error"


def build_seed(
    ws: Path,
    *,
    limit: int = 15,
    vault_server: Path = DEFAULT_VAULT_SERVER,
    vault_caller=None,
) -> Dict[str, Any]:
    """Build the cross-workspace seed payload.

    ``vault_caller`` is an injectable ``(name, args) -> (json, err)`` callable
    used by tests to avoid spawning the real server.
    """
    if vault_caller is None:

        def vault_caller(name: str, args_obj: Dict[str, Any]):  # type: ignore[misc]
            return _call_vault(vault_server, name, args_obj)

    intake = _load_intake(ws)
    repos = _read_targets_tsv(ws)
    language, source_ext_counts = derive_language(intake, ws)
    families = derive_families(intake, repos)
    ws_name = ws.name

    seed: Dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at_utc": _now_utc(),
        "workspace": ws_name,
        "workspace_path": str(ws),
        "derived": {
            "primary_language": language,
            "families": families,
            "source_extension_counts": source_ext_counts,
            "repos": repos,
        },
        "pulls": {},
        "degraded": False,
        "degraded_reasons": [],
    }

    # ---- Pull 1: known dead ends (skip futile candidate paths) ----
    dead_json, dead_err = vault_caller(
        "vault_known_dead_ends", {"workspace": ws_name, "limit": limit}
    )
    if dead_err or not isinstance(dead_json, dict):
        seed["degraded"] = True
        seed["degraded_reasons"].append(f"known_dead_ends:{dead_err or 'bad-payload'}")
        seed["pulls"]["known_dead_ends"] = {"count": 0, "items": []}
    else:
        items = dead_json.get("dead_ends") or []
        seed["pulls"]["known_dead_ends"] = {
            "count": len(items),
            "items": items[:limit],
            "context_pack_id": dead_json.get("context_pack_id"),
        }

    # ---- Pull 2: same-family corpus findings (by language + domain) ----
    corpus_items: List[Dict[str, Any]] = []
    corpus_meta: List[Dict[str, Any]] = []
    queries: List[Dict[str, Any]] = []
    if language:
        queries.append({"language": language})
    for fam in families:
        queries.append({"target_domain": fam})
    if not queries:
        # nothing to key on; record an explicit no-signal query for transparency
        queries.append({})
    for q in queries:
        cj, cerr = vault_caller("vault_corpus_search", {"query": q, "limit": limit})
        if cerr or not isinstance(cj, dict):
            seed["degraded"] = True
            seed["degraded_reasons"].append(
                f"corpus_search:{json.dumps(q)}:{cerr or 'bad-payload'}"
            )
            corpus_meta.append({"query": q, "matched": 0, "error": cerr or "bad-payload"})
            continue
        if cj.get("degraded"):
            corpus_meta.append({"query": q, "matched": 0, "degraded_reason": cj.get("reason")})
            continue
        recs = cj.get("records") or []
        corpus_items.extend(recs)
        corpus_meta.append(
            {
                "query": q,
                "matched": cj.get("total_records_matched", len(recs)),
                "returned": len(recs),
                "context_pack_id": cj.get("context_pack_id"),
            }
        )
    # de-dup corpus items by record_id, keep order
    seen_ids = set()
    deduped: List[Dict[str, Any]] = []
    for rec in corpus_items:
        rid = rec.get("record_id") or json.dumps(rec, sort_keys=True)
        if rid in seen_ids:
            continue
        seen_ids.add(rid)
        deduped.append(rec)
    seed["pulls"]["same_family_corpus"] = {
        "count": len(deduped),
        "items": deduped[: limit * 2],
        "queries": corpus_meta,
    }

    # ---- Pull 3: cross-language pattern lift ----
    if language:
        lj, lerr = vault_caller(
            "vault_cross_language_pattern_lift",
            {"workspace_path": str(ws), "target_language": language, "limit": limit},
        )
        if lerr or not isinstance(lj, dict):
            seed["degraded"] = True
            seed["degraded_reasons"].append(
                f"cross_language_pattern_lift:{lerr or 'bad-payload'}"
            )
            seed["pulls"]["cross_language_pattern_lift"] = {"count": 0, "items": []}
        else:
            cands = lj.get("lift_candidates") or []
            seed["pulls"]["cross_language_pattern_lift"] = {
                "count": len(cands),
                "items": cands[:limit],
                "source_language": lj.get("source_language"),
                "target_language": lj.get("target_language"),
                "context_pack_id": lj.get("context_pack_id"),
            }
    else:
        seed["pulls"]["cross_language_pattern_lift"] = {
            "count": 0,
            "items": [],
            "note": "no primary language derived; skipped lift",
        }

    seed["totals"] = {
        "known_dead_ends": seed["pulls"].get("known_dead_ends", {}).get("count", 0),
        "same_family_corpus": seed["pulls"].get("same_family_corpus", {}).get("count", 0),
        "cross_language_lift": seed["pulls"]
        .get("cross_language_pattern_lift", {})
        .get("count", 0),
    }
    return seed


def render_brief_markdown(seed: Dict[str, Any]) -> str:
    """Render a compact brief-injectable markdown block from the seed."""
    d = seed.get("derived", {})
    lines: List[str] = []
    lines.append("## Cross-Workspace Seed (prior same-family / same-language learnings)")
    lines.append("")
    lines.append(
        f"- Primary language: `{d.get('primary_language') or 'unknown'}` | "
        f"Families: {', '.join(d.get('families') or []) or 'unknown'}"
    )
    if seed.get("degraded"):
        lines.append(
            f"- NOTE: seed pulls partially degraded: {', '.join(seed.get('degraded_reasons') or [])}"
        )
    lines.append("")

    # r36-rebuttal: registered lane cross-seed-fix3; orchestrator commits
    dead = seed.get("pulls", {}).get("known_dead_ends", {})
    lines.append(f"### Known dead-ends to SKIP ({dead.get('count', 0)})")
    for it in (dead.get("items") or [])[:10]:
        # dead-end records arrive in two shapes: the promoted-record shape
        # (record_id / kill_reason / kill_verdict) and the mined-triage shape
        # (attack_class / file / reason / verdict). Handle both.
        rid = (
            it.get("record_id")
            or it.get("candidate_id")
            or it.get("attack_class")
            or it.get("file")
            or "?"
        )
        reason = (
            it.get("kill_reason")
            or it.get("reason")
            or it.get("kill_verdict")
            or it.get("verdict")
            or ""
        )
        lines.append(f"- `{rid}` — {reason}")
    if not (dead.get("items")):
        lines.append("- (none recorded for this workspace)")
    lines.append("")

    corpus = seed.get("pulls", {}).get("same_family_corpus", {})
    lines.append(f"### Prior same-family corpus findings to re-test ({corpus.get('count', 0)})")
    for it in (corpus.get("items") or [])[:12]:
        rid = it.get("record_id") or "?"
        ac = it.get("attack_class") or it.get("bug_class") or ""
        sev = it.get("severity_at_finding") or ""
        dom = it.get("target_domain") or ""
        lines.append(f"- `{rid}` — class=`{ac}` sev=`{sev}` domain=`{dom}`")
    if not (corpus.get("items")):
        lines.append("- (no same-family corpus matches)")
    lines.append("")

    lift = seed.get("pulls", {}).get("cross_language_pattern_lift", {})
    lines.append(
        f"### Cross-language patterns liftable into `{d.get('primary_language') or '?'}` ({lift.get('count', 0)})"
    )
    for it in (lift.get("items") or [])[:10]:
        if isinstance(it, dict):
            label = (
                it.get("pattern")
                or it.get("attack_class")
                or it.get("record_id")
                or json.dumps(it)[:80]
            )
        else:
            label = str(it)[:80]
        lines.append(f"- {label}")
    if not (lift.get("items")):
        lines.append("- (no lift candidates)")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_seed(ws: Path, seed: Dict[str, Any]) -> Tuple[Path, Path]:
    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "cross_workspace_seed.json"
    md_path = out_dir / "cross_workspace_seed.md"
    json_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_brief_markdown(seed), encoding="utf-8")
    return json_path, md_path


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pull prior cross-workspace learnings at audit-start."
    )
    ap.add_argument(
        "--workspace", "--ws", dest="workspace", required=True, help="workspace path"
    )
    ap.add_argument(
        "--limit", type=int, default=15, help="max items per corpus pull (default 15)"
    )
    ap.add_argument(
        "--vault-server",
        default=str(DEFAULT_VAULT_SERVER),
        help="path to vault-mcp-server.py",
    )
    ap.add_argument("--json", action="store_true", help="print the seed JSON to stdout")
    ap.add_argument("--quiet", action="store_true", help="suppress the human summary line")
    args = ap.parse_args(argv)

    ws = _resolve_workspace(args.workspace)
    if ws is None:
        print(
            f"[cross-seed] ERR workspace not found or not a directory: {args.workspace}",
            file=sys.stderr,
        )
        return 2

    limit = max(1, min(int(args.limit), 200))
    seed = build_seed(
        ws, limit=limit, vault_server=Path(os.path.expanduser(args.vault_server))
    )
    json_path, md_path = write_seed(ws, seed)

    if args.json:
        print(json.dumps(seed, indent=2))
    if not args.quiet:
        t = seed.get("totals", {})
        d = seed.get("derived", {})
        degraded = " (DEGRADED)" if seed.get("degraded") else ""
        print(
            f"[cross-seed] {ws.name}: lang={d.get('primary_language') or '?'} "
            f"families={d.get('families') or []} -> "
            f"dead_ends={t.get('known_dead_ends', 0)} "
            f"corpus={t.get('same_family_corpus', 0)} "
            f"lift={t.get('cross_language_lift', 0)}{degraded}",
            file=sys.stderr,
        )
        print(f"[cross-seed] wrote {json_path} + {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
