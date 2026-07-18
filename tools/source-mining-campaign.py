#!/usr/bin/env python3
"""source-mining-campaign.py — V5 CAMPAIGN PR 3 (source-mining wrapper).

Stdlib-only wrapper around `tools/dispatch-preflight.py` and
`tools/llm-dispatch.py` that runs a domain-bucketed source-mining campaign:

  1. Initialize campaign state via `tools/campaign-state.py init
     --lane source_mine` (vendored stub fallback when PR 2 has not
     landed yet).
  2. Slice workspace source by domain. When
     `tools/coverage-introspect.py` exposes a surface enumerator
     (PR #262 / Gap 46), use it; otherwise fall back to a small
     deterministic domain heuristic so the wrapper never depends on a
     specific PR's helper signature.
  3. Build per-domain packets sized to Codex's window guidance
     ("50k-150k tokens for Kimi, larger but bounded for Minimax").
     Hard upper bound is `--packet-budget` characters (NOT tokens —
     character budgets are hermetic and don't drift with tokenizer
     versions).
  4. Kimi candidate-extraction pass via `dispatch-preflight.py
     --template source-extract`, which then calls `llm-dispatch.py`.
     The prompt template embeds the SOURCE_MINING_RUNBOOK restriction
     language so the model cannot emit a "likely new", "High",
     "Critical", or "safe to submit" verdict from a single pass.
  5. Minimax red-team pass via `dispatch-preflight.py --template
     adversarial-kill`, which then calls `llm-dispatch.py`. The
     forwarded args include `--input-is-truncated` whenever the packet
     exceeds ~70K characters (Codex's "larger but bounded" hint plus
     the existing dispatch foot-gun #13d closure).
  6. Artifact summary writes survivors / rejected / source_coverage /
     summary.md to `--out` (default: workspace's
     `source_mining/<YYYY-MM-DD>/`).
  7. Promotion gate enforced via deterministic 4-step rule:
       (a) Kimi cited an exact source line the wrapper can grep.
       (b) Minimax did not classify the candidate
           REJECT_DUPLICATE / REJECT_OOS /
           REJECT_MISSING_PRODUCTION_PATH /
           REJECT_MOCK_OR_TEST_ONLY / REJECT_INSUFFICIENT_IMPACT.
       (c) The wrapper emitted a Claude PoC task placeholder line in
           summary.md (the operator runs it; the wrapper never
           promotes a candidate to a finding).
       (d) The candidate did not trip the deterministic OOS /
           impossible-trigger filter.
     Failing ANY of (a)-(d) routes the candidate to `rejected.json`
     with a reason field. Surviving candidates are written to
     `survivors.json` as KEEP_FOR_LOCAL_VERIFICATION (NEVER as
     "submission-ready" — that decision is operator/Codex territory).

Hard rules (Codex review-gate):
  * Stdlib only. No requests, anthropic, httpx, yaml, etc.
  * Use existing `dispatch-preflight.py` / `llm-dispatch.py` rather
    than inventing a new provider layer. The wrapper shells out via
    `subprocess` and reads the captured provider stdout.
  * Never auto-promote a candidate. The wrapper writes triage
    artifacts only.
  * Resume support: re-running on the same `--out` directory skips
    packets that already have a recorded `kimi_candidates.json` entry
    AND a recorded `minimax_challenges.json` entry. State init is
    idempotent (campaign-state stub no-op on subsequent calls).
  * Default-on budget guard: the wrapper does NOT override
    AUDITOOOR_LLM_BUDGET_GUARD. Operators opt out at the env-var
    level if they really mean it.

Exit codes:
   0  campaign completed (all packets dispatched OR resumed clean)
   2  argument or filesystem error (cannot-run)
   3  dispatch failure that the wrapper deliberately surfaces (e.g.
      every Kimi packet failed and operator passed --strict)

Usage::

    python3 tools/source-mining-campaign.py \\
        --workspace ~/audits/<project> \\
        --providers kimi,minimax \\
        --packet-budget 250000 \\
        --out ~/audits/<project>/source_mining/$(date +%Y%m%d)
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional

HERE = Path(__file__).resolve().parent


def _load_local_module(name: str, path: Path) -> Any:
    """Load a sibling module by absolute path, without depending on sys.path."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module {name!r} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


# Local import: every survivor record stamps ``evidence_class:
# generated_hypothesis`` (item #14). Survivors are KEEP_FOR_LOCAL_VERIFICATION;
# they are never proof until a PoC executes and a manifest is recorded.
_evidence_class = _load_local_module(
    "_source_mining_evidence_class", HERE / "evidence_class.py"
)

REPO = Path(__file__).resolve().parents[1]
LLM_DISPATCH = REPO / "tools" / "llm-dispatch.py"
DISPATCH_PREFLIGHT = REPO / "tools" / "dispatch-preflight.py"
CAMPAIGN_STATE = REPO / "tools" / "campaign-state.py"  # PR 2 dependency
COVERAGE_INTROSPECT = REPO / "tools" / "coverage-introspect.py"
PROMOTE_TYPED_CANDIDATE = REPO / "tools" / "promote-typed-candidate.py"
LLM_CALIBRATION_LOG = REPO / "tools" / "llm-calibration-log.py"

SCHEMA_VERSION = "auditooor.source_mining_campaign.v1"
OUTCOME_ROUTING_SCHEMA = "auditooor.outcome_calibrated_routing.v1"

EXIT_OK = 0
EXIT_CANNOT_RUN = 2
EXIT_ERROR = 3

# Codex window guidance, expressed as character budgets (NOT tokens —
# tokenizer drift would silently change behaviour). The Kimi cap mirrors
# the observed CLI window (~250k context); the wrapper keeps Kimi packets
# at ~60-70% of that to leave room for the response and instructions.
KIMI_PACKET_CHAR_CAP = 150_000
MINIMAX_PACKET_CHAR_CAP = 700_000  # Minimax CLI ~1M context, room for output
MINIMAX_TRUNCATION_THRESHOLD = 70_000  # foot-gun #13d trigger

# Default model max-tokens passed through to llm-dispatch.py. The dispatch
# tool defaults to 16000 already; we surface the override here so a
# campaign script can dial it without editing the wrapper.
DEFAULT_MAX_TOKENS = 16000

SOURCE_MINING_PROVIDER_TASKS: dict[str, tuple[str, ...]] = {
    "kimi": ("source-extraction",),
    "minimax": ("adversarial-kill", "contradiction-search"),
}

LOCAL_VERIFICATION_BLOCKERS = (
    "line_cite_grep_verified",
    "m14_pattern_library_grep",
    "submission_corpus_dedupe_check",
    "impact_contract_exact_row",
    "poc_execution_manifest",
)

# OOS / impossible-trigger filter. Conservative substrings — false
# positives just mean a candidate is held for operator review, which is
# the safe failure mode. False negatives let an OOS candidate slip
# through to the survivors list, so the substrings here are deliberately
# narrow and case-insensitive.
OOS_MARKERS = (
    "out-of-scope",
    "out of scope",
    "oos:",
    "oos ",
    "leaked private key",
    "admin can drain",
    "owner can rug",
    "if owner is malicious",
    "assuming compromised admin",
    "centralization risk",
    "unfair admin",
)
IMPOSSIBLE_TRIGGER_MARKERS = (
    "requires infinite gas",
    "requires hash collision",
    "break sha-256",
    "break keccak",
    "factor rsa",
    "if ecrecover is broken",
    "post-quantum",
)

# Domain bucket heuristics — used when coverage-introspect's surface
# enumerator is unavailable or returns zero categories. Match against
# the lower-cased file path. Keep this list small and well-typed: the
# fallback is a courtesy, not a replacement for coverage-introspect.
DOMAIN_HEURISTICS: list[tuple[str, tuple[str, ...]]] = [
    ("oracle-pricing", ("oracle", "price", "feed", "pyth", "chainlink", "redstone")),
    ("vault-share-math", ("vault", "shares", "erc4626", "preview", "convert")),
    ("auth-roles", ("auth", "role", "owner", "access", "admin", "permission")),
    ("bridge-messaging", ("bridge", "endpoint", "lzreceive", "wormhole", "hyperlane")),
    ("crypto-verifier", ("verifier", "ecdsa", "merkle", "eip712", "schnorr")),
    ("settlement-orderbook", ("settle", "match", "orderbook", "auction")),
    ("clone-factory-upgrade", ("factory", "clone", "proxy", "uups", "upgrade")),
    ("economics-fees", ("fee", "reward", "incentive", "yield", "stake")),
]
DOMAIN_FALLBACK = "general"


# ---------------------------------------------------------------------------
# Vendored campaign-state stub (PR 2 dependency)
# ---------------------------------------------------------------------------

def _campaign_state_init(out_dir: Path, *, lane: str = "source_mine") -> dict[str, Any]:
    """Initialize a campaign-state record.

    When `tools/campaign-state.py` exists (PR 2 merged), shell out to it
    in --init-or-noop mode so the wrapper inherits whatever schema the
    skeleton landed with. Otherwise, write a minimal stub state file
    so resume detection and the artifact summary still work.

    Idempotent: re-running on an existing state file leaves it alone
    apart from a `last_seen_utc` field bump.
    """
    state_path = out_dir / "campaign_state.json"
    out_dir.mkdir(parents=True, exist_ok=True)

    # If PR 2 has landed, prefer its tool. Detect by file existence AND
    # support for the `init` subcommand (which is the only contract
    # PR 2 commits to). If the subprocess exits non-zero we fall back
    # to the vendored stub rather than crashing the campaign.
    if CAMPAIGN_STATE.is_file():
        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(CAMPAIGN_STATE),
                    "init",
                    "--lane",
                    lane,
                    "--out",
                    str(state_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            if proc.returncode == 0:
                # Re-read what PR 2 wrote so the summary reflects whatever
                # schema it picked.
                try:
                    return json.loads(state_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        # Fall-through to stub on any failure — graceful degradation.

    # Vendored stub: idempotent JSON file.
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state = {}
    else:
        state = {}
    state.setdefault("schema", SCHEMA_VERSION + ".state.stub")
    state.setdefault("lane", lane)
    state.setdefault("created_at_utc", datetime.datetime.now(datetime.timezone.utc).isoformat())
    state["last_seen_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return state


def _load_calibration_module():
    """Load llm-calibration-log.py without importing its hyphenated filename."""
    if not LLM_CALIBRATION_LOG.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "source_mining_llm_calibration_log", str(LLM_CALIBRATION_LOG)
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def build_outcome_routing_manifest(
    *,
    providers: tuple[str, ...],
    survivors: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    pending_review: list[dict[str, Any]],
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    """Explain why source-mining model output is input-only.

    Kimi/Minimax source-mining output is useful corpus input, not proof. This
    manifest ties each provider lane to the calibration router and records the
    hard local-verification blockers, including the M14 grep-precheck trap.
    """
    generated = generated_at_utc or datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
    calibration = _load_calibration_module()
    provider_rows: list[dict[str, Any]] = []
    for provider in providers:
        for task_type in SOURCE_MINING_PROVIDER_TASKS.get(provider, ()):
            if calibration is None or not hasattr(calibration, "routing_status"):
                route = {
                    "provider": provider,
                    "task_type": task_type,
                    "primary_allowed": False,
                    "advisory_only": True,
                    "reason": "routing-helper-missing",
                }
            else:
                route = calibration.routing_status(provider, task_type)
            provider_rows.append(
                {
                    "provider": provider,
                    "task_type": task_type,
                    "calibration_reason": route.get("reason"),
                    "calibration_primary_allowed": bool(
                        route.get("primary_allowed")
                    ),
                    "calibration_advisory_only": bool(
                        route.get("advisory_only", True)
                    ),
                    "source_mining_routing_status": (
                        "input_only_local_verification_required"
                    ),
                    "m14_trap_required": task_type == "contradiction-search",
                    "local_verification_required": True,
                    "sample_count": route.get("sample_count", route.get("decided")),
                    "precision_pct": route.get("precision_pct"),
                    "min_samples": route.get("min_samples"),
                    "min_precision": route.get("min_precision"),
                }
            )
    return {
        "schema": OUTCOME_ROUTING_SCHEMA,
        "generated_at_utc": generated,
        "source": "source-mining-campaign",
        "overall_routing_status": "input_only_local_verification_required",
        "llm_corpus_mining_is_proof": False,
        "local_verification_required": True,
        "m14_trap_required": True,
        "local_verification_blockers": list(LOCAL_VERIFICATION_BLOCKERS),
        "provider_rows": provider_rows,
        "counts": {
            "survivors": len(survivors),
            "rejected": len(rejected),
            "pending_review": len(pending_review),
        },
        "rule": (
            "Provider output may seed detector/harness/source-proof work only. "
            "No survivor is submit-ready until line cites, M14 pattern-library "
            "grep, submission-corpus dedupe, exact impact contract, and PoC "
            "execution manifest are locally verified."
        ),
    }


def stamp_outcome_routing(
    candidates: list[dict[str, Any]],
    *,
    manifest_relpath: str = "outcome_calibrated_routing.json",
) -> None:
    """Annotate survivor/pending rows with the source-mining routing posture."""
    for cand in candidates:
        cand["outcome_calibrated_routing"] = {
            "routing_status": "input_only_local_verification_required",
            "manifest": manifest_relpath,
            "local_verification_required": True,
            "m14_trap_required": True,
            "blocked_until": list(LOCAL_VERIFICATION_BLOCKERS),
        }


def load_impact_worklist_context(workspace: Path, *, limit: int = 20) -> dict[str, Any]:
    """Load listed-impact worklists for source-mining packet routing.

    This context is planning-only. It tells providers which roots/components
    need source review and preserves NOT_SUBMIT_READY posture in every packet.
    """
    path = workspace / ".auditooor" / "impact_family_worklists.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {
            "status": "unreadable",
            "artifact": str(path),
            "submission_posture": "NOT_SUBMIT_READY",
            "submit_ready": False,
        }
    rows = payload.get("worklists") if isinstance(payload.get("worklists"), list) else []
    context_rows: list[dict[str, Any]] = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        context_rows.append({
            "impact_id": row.get("impact_id", ""),
            "impact_family": row.get("impact_family", ""),
            "impact": row.get("impact", ""),
            "proof_class": row.get("proof_class") or row.get("required_evidence_class", ""),
            "required_artifacts": row.get("required_artifacts", []),
            "relevant_source_roots": row.get("relevant_source_roots", []),
            "components": row.get("components", [])[:8],
            "oos_traps": row.get("oos_traps", [])[:8],
            "next_command": row.get("next_command", ""),
            "submission_posture": "NOT_SUBMIT_READY",
            "submit_ready": False,
        })
    return {
        "status": "present",
        "artifact": str(path),
        "worklist_count": len(rows),
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_ready": False,
        "worklists": context_rows,
    }


def render_impact_worklist_context(context: dict[str, Any]) -> str:
    if not context:
        return "No impact_family_worklists.json present; do not select severity or draft report text."
    lines = [
        "Impact-family worklists are planning inputs only.",
        "Every row remains NOT_SUBMIT_READY until exact impact proof and execution evidence exist.",
        f"artifact: {context.get('artifact', '')}",
    ]
    for row in context.get("worklists", [])[:20]:
        roots = ", ".join(row.get("relevant_source_roots") or []) or "unmapped"
        component_ids = [
            str(component.get("component_id") or component.get("source_component") or "")
            for component in row.get("components", [])
            if str(component.get("component_id") or component.get("source_component") or "").strip()
        ]
        lines.append(
            "- {impact_id} family={family} proof={proof} roots={roots} components={components} required={required} oos_traps={traps}".format(
                impact_id=row.get("impact_id", ""),
                family=row.get("impact_family", ""),
                proof=row.get("proof_class", ""),
                roots=roots,
                components=", ".join(component_ids[:8]) or "unmapped",
                required=", ".join(row.get("required_artifacts") or []),
                traps="; ".join(row.get("oos_traps") or [])[:500],
            )
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Domain slicing
# ---------------------------------------------------------------------------

def _slice_domains_via_coverage_introspect(workspace: Path, ext: str = "sol") -> dict[str, list[str]]:
    """Try to use coverage-introspect's surface enumerator.

    Returns a {domain: [relpath, ...]} mapping when the helper is
    available and returns at least one category; returns {} on any
    failure so the caller falls through to the heuristic.

    coverage-introspect is Solidity-shaped (parses pragma + import
    headers); for non-.sol workspaces (Rust/Soroban, Cairo, Move, Vy)
    skip it and fall through to the extension-aware heuristic.
    I18 (#335) fix.
    """
    if ext != "sol":
        return {}
    if not COVERAGE_INTROSPECT.is_file():
        return {}
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "_ci_surface", str(COVERAGE_INTROSPECT)
        )
        if spec is None or spec.loader is None:
            return {}
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if not hasattr(mod, "phase1_surface"):
            return {}
        surf = mod.phase1_surface(workspace)
        by_cat = surf.get("by_category") or {}
        if not isinstance(by_cat, dict) or not by_cat:
            return {}
        # Coverage-introspect categories are already deterministic.
        return {str(k): sorted(v) for k, v in by_cat.items() if v}
    except Exception:  # broad on purpose — graceful degradation
        return {}


def _slice_domains_heuristic(workspace: Path, ext: str = "sol") -> dict[str, list[str]]:
    """Fallback domain slicer. Walks workspace/src/**.<ext>, tags by name.

    I18 (#335): the extension is parameterised so non-Solidity workspaces
    (Rust/Soroban, Cairo, Move) can use the same campaign engine. When
    ext='rs', the walker also descends into `contracts/` because
    Rust/Soroban repos often use that layout instead of `src/`.
    """
    ext = ext.lstrip(".").lower()
    src = workspace / "src"
    out: dict[str, list[str]] = {}
    if not src.is_dir():
        # Some workspaces use contracts/ rather than src/. Scan both.
        candidates = [workspace / "contracts", workspace]
    else:
        candidates = [src]
        # For Rust/Soroban specifically, contracts/ is the canonical
        # crate layout (e.g. K2 has src/contracts/<crate>/src/*.rs);
        # include it alongside src/ so the slicer doesn't miss the
        # actual crate sources.
        if ext == "rs":
            extra = workspace / "contracts"
            if extra.is_dir():
                candidates.append(extra)
    seen: set[Path] = set()
    glob_pat = f"*.{ext}"
    for root in candidates:
        if not root.is_dir():
            continue
        for path in root.rglob(glob_pat):
            if path in seen:
                continue
            seen.add(path)
            rel_low = str(path.relative_to(workspace)).lower()
            # Skip obvious non-production paths. Anchor with `/` AND check
            # path-segment leading position so `tests/harness.rs` (no
            # leading slash, top-level) is also skipped — same intent as
            # the original `/tests/` substring check but doesn't depend
            # on whether there's a leading slash.
            skip_segments = ("lib", "test", "tests", "mock", "mocks", "_archive", "fuzz", "external")
            path_parts_low = [p.lower() for p in path.relative_to(workspace).parts]
            if any(seg in path_parts_low for seg in skip_segments):
                continue
            matched: str | None = None
            for domain, kws in DOMAIN_HEURISTICS:
                if any(kw in rel_low for kw in kws):
                    matched = domain
                    break
            domain = matched or DOMAIN_FALLBACK
            try:
                rel = str(path.relative_to(workspace))
            except ValueError:
                rel = str(path)
            out.setdefault(domain, []).append(rel)
    return {k: sorted(v) for k, v in out.items() if v}


def slice_domains(workspace: Path, ext: str = "sol") -> dict[str, list[str]]:
    """Public domain slicer. Prefers coverage-introspect (for `.sol`
    only), falls back to a deterministic heuristic. Always returns a
    dict (possibly empty). I18 (#335): `ext` parameter selects file
    extension to mine — `sol` (default), `rs`, `cairo`, `move`, `vy`."""
    via_ci = _slice_domains_via_coverage_introspect(workspace, ext)
    if via_ci:
        return _augment_domains_with_factory_config_liveness(workspace, via_ci, ext=ext)
    return _augment_domains_with_factory_config_liveness(
        workspace, _slice_domains_heuristic(workspace, ext), ext=ext
    )


def _augment_domains_with_factory_config_liveness(
    workspace: Path,
    domains: dict[str, list[str]],
    *,
    ext: str = "sol",
) -> dict[str, list[str]]:
    """Add a config/liveness packet for factory-created pool families.

    coverage-introspect can correctly bucket math/zap files while omitting
    factory/config files that explain why a bad pool can exist. Preserve its
    categories, but add a small deterministic bucket for deployment/config
    liveness shapes so source-mining packets include factories, amp/base/fee
    config, swaps, and interfaces.
    """
    if ext.lstrip(".").lower() != "sol":
        return domains

    out = {k: sorted(set(v)) for k, v in domains.items()}
    routed: set[str] = set()
    for path in workspace.rglob("*.sol"):
        try:
            rel_path = path.relative_to(workspace)
        except ValueError:
            continue
        parts = [p.lower() for p in rel_path.parts]
        if {"lib", "vendor", "node_modules", "out", "cache", "test", "tests"} & set(parts):
            continue
        rel = str(rel_path)
        rel_low = rel.lower()
        if "/src/" not in f"/{rel_low}":
            continue
        rel_norm = f"/{rel_low}"
        if (
            "/src/factories/" in rel_norm
            or "/src/interfaces/" in rel_norm
            or rel_norm.endswith(("/src/amp.sol", "/src/base.sol", "/src/fees.sol", "/src/swap.sol"))
        ):
            routed.add(rel)
    if routed:
        existing = set(out.get("factory-config-liveness", []))
        out["factory-config-liveness"] = sorted(existing | routed)
    return {k: sorted(v) for k, v in out.items() if v}


def _make_line_cite_re(ext: str) -> "re.Pattern[str]":
    """Build the cite-validation regex for a given file extension.
    A valid cite is `<path>.<ext>:<line>` or `<path>.<ext>:<lstart>-<lend>`."""
    safe = re.escape(ext.lstrip(".").lower())
    return re.compile(rf"\.{safe}:\d+(?:-\d+)?$")


# ---------------------------------------------------------------------------
# Packet builder
# ---------------------------------------------------------------------------

# Restriction language baked into both prompt templates. Matches the
# SOURCE_MINING_RUNBOOK Hard Guardrails section. Also enforces the
# Codex "Kimi alone cannot promote" rule by forbidding the four banned
# verdict phrases.
_RESTRICTION_BLOCK = (
    "RESTRICTIONS:\n"
    "- Do NOT use the words 'likely new', 'High', 'Critical', or "
    "'safe to submit' anywhere in your response.\n"
    "- Do NOT propose severities, do NOT mark anything as "
    "submission-ready, do NOT draft external report text.\n"
    "- Cite EXACT source files and line ranges (file.sol:LSTART-LEND).\n"
    "- Reject candidates that depend on admin action, leaked keys, "
    "compromised owner, mock verifiers, missing-production-path, or "
    "out-of-scope clauses.\n"
    "- Output JSON-line records only. One JSON object per line. No "
    "prose, no markdown headings, no severity inflation."
)


def _read_truth_block(workspace: Path) -> str:
    """Read the small, hermetic truth block for the campaign packet.

    Pulls SCOPE.md, OOS clauses, and known-issue notes when present.
    Capped per-file at 8 KB so a 4 MB SCOPE.md does not blow the
    packet budget. Files that are missing are silently skipped — the
    caller surfaces the omission via `source_coverage.json`.
    """
    pieces: list[str] = []
    candidates = [
        ("SCOPE.md", workspace / "SCOPE.md"),
        ("OOS_CHECKLIST.md", workspace / "OOS_CHECKLIST.md"),
        ("README.md", workspace / "README.md"),
    ]
    for label, path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > 8 * 1024:
            text = text[: 8 * 1024] + "\n[TRUNCATED]"
        pieces.append(f"=== {label} ===\n{text}\n")
    if not pieces:
        return "[no truth files present in workspace]"
    return "\n".join(pieces)


def _indent_block(text: str, prefix: str = "  ") -> str:
    lines = text.splitlines() or [""]
    return "\n".join(prefix + line for line in lines)


def _read_memory_context_block(workspace: Path) -> str:
    """Return a bounded MCP memory context block for dispatch templates.

    Dispatch preflight requires an explicit ``memory_context:`` section.  The
    source-mining wrapper already runs inside workspaces that usually have
    memory-context receipts, but older packets did not surface that receipt in
    the prompt, so valid provider campaigns were refused before dispatch.
    """
    aud = workspace / ".auditooor"
    refs: list[str] = []
    lines: list[str] = []

    last_recall = aud / "last_mcp_recall.json"
    if last_recall.is_file():
        try:
            payload = json.loads(last_recall.read_text(encoding="utf-8"))
            if payload.get("context_pack_id"):
                lines.append(f"context_pack_id: {payload.get('context_pack_id')}")
            if payload.get("context_pack_hash"):
                lines.append(f"context_pack_hash: {payload.get('context_pack_hash')}")
            refs.append(str(last_recall.relative_to(workspace)))
        except (OSError, ValueError):
            refs.append(str(last_recall.relative_to(workspace)))

    receipt = aud / "memory_context_receipt.json"
    if receipt.is_file():
        try:
            payload = json.loads(receipt.read_text(encoding="utf-8"))
            lines.append(f"memory_receipt_schema: {payload.get('schema', 'unknown')}")
            if payload.get("generated_at"):
                lines.append(f"memory_receipt_generated_at: {payload.get('generated_at')}")
            summary = payload.get("summary")
            if isinstance(summary, dict):
                compact = json.dumps(summary, sort_keys=True)[:1000]
                lines.append(f"memory_receipt_summary: {compact}")
            refs.append(str(receipt.relative_to(workspace)))
        except (OSError, ValueError):
            refs.append(str(receipt.relative_to(workspace)))

    pack_dir = aud / "memory_context_packs"
    if pack_dir.is_dir():
        pack_refs = sorted(p.name for p in pack_dir.glob("*.json"))[:8]
        if pack_refs:
            lines.append("memory_context_pack_files:")
            lines.extend(f"- .auditooor/memory_context_packs/{name}" for name in pack_refs)
            refs.extend(f".auditooor/memory_context_packs/{name}" for name in pack_refs)

    if not lines:
        lines.extend([
            "context_pack_id: local-workspace-memory-context-unavailable",
            "context_pack_hash: unavailable",
            "memory_receipt_status: missing",
        ])

    if refs:
        lines.append("source_refs:")
        lines.extend(f"- {ref}" for ref in refs[:12])
    return "\n".join(lines)


def build_kimi_packet(
    *,
    workspace: Path,
    domain: str,
    files: list[str],
    truth_block: str,
    impact_worklist_context: dict[str, Any] | None = None,
    char_cap: int = KIMI_PACKET_CHAR_CAP,
) -> tuple[str, dict[str, Any]]:
    """Build a Kimi candidate-extraction packet.

    Returns (packet_text, coverage_record). The coverage record names
    every file we considered and every file we skipped (with reason),
    so `source_coverage.json` can be reconstructed without re-walking
    the workspace.
    """
    memory_context = _read_memory_context_block(workspace)
    template_preamble = (
        f"workspace_path: {workspace}\n"
        "memory_context: |\n"
        f"{_indent_block(memory_context)}\n"
        "target_files:\n"
        + "".join(f"  - {rel}\n" for rel in files)
        + "hypotheses:\n"
        f"  - Source-mining candidate extraction for domain {domain}\n"
        "prior_failed_attempts: none\n"
        "expected_output_shape: |\n"
        "  JSON object per line with candidate_id, source_files, bug_shape,\n"
        "  reachable_non_privileged_path, required_state, impact_hypothesis,\n"
        "  scope_risk, oos_risk, prior_art_risk, exact_checks_needed_next.\n\n"
    )
    header = (
        template_preamble
        + f"You are reading a bounded source packet for workspace "
        f"`{workspace.name}`, domain `{domain}`.\n\n"
        f"{_RESTRICTION_BLOCK}\n\n"
        f"=== TRUTH BLOCK ===\n{truth_block}\n"
        f"\n=== LISTED IMPACT WORKLIST CONTEXT (NOT_SUBMIT_READY) ===\n"
        f"{render_impact_worklist_context(impact_worklist_context or {})}\n"
    )
    body_parts: list[str] = []
    coverage: dict[str, Any] = {
        "domain": domain,
        "files_considered": list(files),
        "files_included": [],
        "files_skipped": [],
        "impact_worklist_context": {
            "status": (impact_worklist_context or {}).get("status", "missing"),
            "artifact": (impact_worklist_context or {}).get("artifact", ""),
            "worklist_count": (impact_worklist_context or {}).get("worklist_count", 0),
            "submission_posture": "NOT_SUBMIT_READY",
            "submit_ready": False,
        },
    }
    used = len(header)
    for rel in files:
        path = workspace / rel
        if not path.is_file():
            coverage["files_skipped"].append({"file": rel, "reason": "missing"})
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            coverage["files_skipped"].append({"file": rel, "reason": f"unreadable: {e}"})
            continue
        chunk = f"\n=== {rel} ===\n{text}\n"
        if used + len(chunk) > char_cap:
            coverage["files_skipped"].append({"file": rel, "reason": "char-budget-exceeded"})
            continue
        body_parts.append(chunk)
        coverage["files_included"].append(rel)
        used += len(chunk)
    instruction = (
        "\n\n=== TASK ===\n"
        "For every candidate bug class extractable from the source "
        "above, emit one JSON object per line with the fields:\n"
        "  candidate_id (string, kebab-case)\n"
        "  source_files (list of 'file.sol:LSTART-LEND' strings)\n"
        "  bug_shape (one short sentence)\n"
        "  reachable_non_privileged_path (string)\n"
        "  required_state (string)\n"
        "  impact_hypothesis (string, no severity)\n"
        "  scope_risk (string)\n"
        "  oos_risk (string)\n"
        "  prior_art_risk (string)\n"
        "  exact_checks_needed_next (string)\n"
    )
    return header + "".join(body_parts) + instruction, coverage


def build_minimax_packet(
    *,
    workspace: Path,
    domain: str,
    truth_block: str,
    kimi_candidates: list[dict[str, Any]],
    char_cap: int = MINIMAX_PACKET_CHAR_CAP,
) -> tuple[str, bool]:
    """Build a Minimax red-team packet. Returns (text, truncated_flag).

    `truncated_flag` is True when the candidate list was clipped to fit
    the packet — the wrapper will pass `--input-is-truncated` so
    dispatch's foot-gun #13d notice fires.
    """
    candidate_lines: list[str] = []
    used = 0
    truncated = False
    for cand in kimi_candidates:
        line = json.dumps(cand, sort_keys=True) + "\n"
        if used + len(line) > char_cap:
            truncated = True
            break
        candidate_lines.append(line)
        used += len(line)

    memory_context = _read_memory_context_block(workspace)
    template_preamble = (
        f"workspace_path: {workspace}\n"
        "memory_context: |\n"
        f"{_indent_block(memory_context)}\n"
        "candidate_list:\n"
        + "".join(
            f"  - {cand.get('candidate_id', 'candidate')}\n"
            for cand in kimi_candidates[:20]
        )
        + "oos_text: |\n"
        "  See TRUTH BLOCK below; if no OOS clauses are present there, treat as none.\n"
        f"truncation_flag: {'truncated' if truncated else 'complete'}\n"
        "expected_output_shape: |\n"
        "  JSON object per line with candidate_id, classification, reason,\n"
        "  and next_check. Reject weak candidates; do not upgrade severity.\n\n"
    )
    header = (
        template_preamble
        + f"You are red-teaming source-mining candidates for workspace "
        f"`{workspace.name}`, domain `{domain}`. Your job is to REJECT "
        f"weak candidates, not to be encouraging.\n\n"
        f"{_RESTRICTION_BLOCK}\n\n"
        f"=== TRUTH BLOCK ===\n{truth_block}\n\n"
        "=== TASK ===\n"
        "For every candidate listed below, emit one JSON object per line "
        "with the fields:\n"
        "  candidate_id (string)\n"
        "  classification (one of "
        "KEEP_FOR_LOCAL_VERIFICATION, REJECT_DUPLICATE, REJECT_OOS, "
        "REJECT_MISSING_PRODUCTION_PATH, REJECT_MOCK_OR_TEST_ONLY, "
        "REJECT_INSUFFICIENT_IMPACT, NEEDS_MORE_SOURCE)\n"
        "  reason (one short sentence)\n"
        "  next_check (string; minimum source path to verify)\n"
        "Do not upgrade severity. Do not output prose.\n\n"
        "=== CANDIDATES ===\n"
    )
    return header + "".join(candidate_lines), truncated


# ---------------------------------------------------------------------------
# LLM dispatch shell-out
# ---------------------------------------------------------------------------

def _default_runner(
    provider: str, prompt_text: str, *, audit_dir: Path,
    timeout: float, max_tokens: int, input_is_truncated: bool,
    task_type: str | None = None,
    workspace: Path | None = None,
) -> tuple[int, str, str]:
    """Real runner: shell out through `tools/dispatch-preflight.py`.

    Wrapping `subprocess.run` in a function with this exact signature
    is what lets tests inject a hermetic dispatcher with the same
    arguments — no thread of `argv`-parsing-shims needed.
    """
    audit_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", suffix=".prompt.md", delete=False
    ) as tmp:
        tmp.write(prompt_text)
        prompt_path = Path(tmp.name)
    try:
        template = task_type or (
            "adversarial-kill" if provider == "minimax" else "source-extract"
        )
        output_path = audit_dir / "dispatch_outputs" / (
            f"{prompt_path.stem}-{provider}-{template}.jsonl"
        )
        forward_args = [
            "--audit-dir",
            str(audit_dir),
            "--max-tokens",
            str(max_tokens),
            "--timeout",
            str(timeout),
            # I14 fix (#330): source-mine packets are NOT strategic
            # prompts. The packet is "find bugs in this Solidity source"
            # plus an embedded SCOPE/OOS truth-block. The strategic-LLM
            # gate (PR #278) rejects packets when SCOPE.md happens to
            # quote a bounty README that mentions "roadmap" or similar.
            # That's a workspace-content false positive — the packet
            # asks for code-level vulnerability candidates, period.
            # The campaign opts in explicitly so the gate stops false-
            # positive-rejecting valid mining work.
            "--strategic-llm-allowed",
        ]
        if input_is_truncated:
            forward_args.append("--input-is-truncated")
        argv = [
            sys.executable,
            str(DISPATCH_PREFLIGHT),
            "--template",
            template,
            "--prompt-file",
            str(prompt_path),
            "--workspace",
            str((workspace or audit_dir.parent).resolve()),
            "--audit-log",
            str(audit_dir / "dispatch_audit.jsonl"),
            "--provider",
            provider,
            "--output-file",
            str(output_path),
            "--timeout",
            str(timeout),
            "--forward",
            " ".join(shlex.quote(arg) for arg in forward_args),
        ]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, check=False,
                timeout=timeout + 30,
            )
            stdout = proc.stdout
            if output_path.is_file():
                try:
                    stdout = output_path.read_text(encoding="utf-8")
                except OSError:
                    stdout = proc.stdout
            return proc.returncode, stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            return EXIT_ERROR, "", f"timeout: {e}"
        except Exception as e:  # broad — never let a dispatch crash kill the loop
            return EXIT_ERROR, "", f"dispatch-exception: {e}"
    finally:
        try:
            prompt_path.unlink()
        except OSError:
            pass


def _dispatch_llm(
    *,
    provider: str,
    prompt_text: str,
    audit_dir: Path,
    timeout: float,
    max_tokens: int,
    input_is_truncated: bool = False,
    task_type: str | None = None,
    workspace: Path | None = None,
    runner: Callable[..., tuple[int, str, str]] | None = None,
) -> tuple[int, str, str]:
    """Run a single LLM dispatch. Returns (rc, stdout, stderr).

    `runner(provider, prompt_text, audit_dir=, timeout=, max_tokens=,
    input_is_truncated=)` is dependency-injected for tests so the
    unittest suite never touches the network.
    """
    if runner is None:
        return _default_runner(
            provider, prompt_text,
            audit_dir=audit_dir, timeout=timeout,
            max_tokens=max_tokens,
            input_is_truncated=input_is_truncated,
            task_type=task_type,
            workspace=workspace,
        )
    try:
        return runner(
            provider, prompt_text,
            audit_dir=audit_dir, timeout=timeout,
            max_tokens=max_tokens,
            input_is_truncated=input_is_truncated,
        )
    except Exception as e:
        return EXIT_ERROR, "", f"injected-runner-error: {e}"


# ---------------------------------------------------------------------------
# JSON-lines parser (lenient — LLMs sometimes wrap output in fences)
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]+?)```", re.MULTILINE)


def parse_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse JSON-lines output from an LLM.

    Tolerates fenced blocks, leading/trailing prose, and a single
    JSON-array response (some models prefer arrays). Lines that fail
    to parse are silently dropped — they were never valid candidates.
    """
    if not text:
        return []
    out: list[dict[str, Any]] = []
    # If the entire response is a fenced block, unwrap it first.
    fences = _FENCE_RE.findall(text)
    sources = fences if fences else [text]
    for src in sources:
        # Try array-form first.
        stripped = src.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                arr = json.loads(stripped)
                if isinstance(arr, list):
                    for item in arr:
                        if isinstance(item, dict):
                            out.append(item)
                    continue
            except ValueError:
                pass
        # Line-by-line.
        for line in src.splitlines():
            line = line.strip().rstrip(",")
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


# ---------------------------------------------------------------------------
# Promotion gate
# ---------------------------------------------------------------------------

def _has_oos_marker(cand: dict[str, Any]) -> str | None:
    """Return the matched OOS marker if any candidate field trips it."""
    for field in ("scope_risk", "oos_risk", "bug_shape", "impact_hypothesis"):
        val = cand.get(field)
        if not isinstance(val, str):
            continue
        low = val.lower()
        for marker in OOS_MARKERS:
            if marker in low:
                return marker
    return None


def _has_impossible_trigger(cand: dict[str, Any]) -> str | None:
    """Return the matched impossible-trigger marker if any field trips it."""
    for field in ("required_state", "bug_shape", "reachable_non_privileged_path"):
        val = cand.get(field)
        if not isinstance(val, str):
            continue
        low = val.lower()
        for marker in IMPOSSIBLE_TRIGGER_MARKERS:
            if marker in low:
                return marker
    return None


# A valid cite is `<path>.<ext>:<line>` or `<path>.<ext>:<lstart>-<lend>`. The
# trailing `:LINE` is REQUIRED; bare `src/Foo.<ext>` does not count as a cite
# because the wrapper cannot grep a specific location to verify.
# I18 (#335): default-`.sol`, but the validator factory below accepts any ext.
_LINE_CITE_RE = re.compile(r"\.sol:\d+(?:-\d+)?$")
_LINE_CITE_RE_RS = re.compile(r"\.rs:\d+(?:-\d+)?$")


def _has_line_cite(cand: dict[str, Any], ext: str = "sol") -> bool:
    """True iff at least one source_files entry looks like a line cite.
    The cite extension is parameterised by `ext` so non-Solidity
    workspaces validate against `.rs:LINE`, `.cairo:LINE`, etc.
    I18 (#335) generalises this from the Solidity-only default."""
    files = cand.get("source_files")
    if not isinstance(files, list) or not files:
        return False
    # Hot paths: cached compiled regexes for the two extensions auditooor
    # encounters today (.sol, .rs). For other extensions, build on demand.
    if ext == "sol":
        pat = _LINE_CITE_RE
    elif ext == "rs":
        pat = _LINE_CITE_RE_RS
    else:
        pat = _make_line_cite_re(ext)
    for entry in files:
        if not isinstance(entry, str):
            continue
        if pat.search(entry):
            return True
    return False


_MINIMAX_REJECT_VERDICTS = {
    "REJECT_DUPLICATE",
    "REJECT_OOS",
    "REJECT_MISSING_PRODUCTION_PATH",
    "REJECT_MOCK_OR_TEST_ONLY",
    "REJECT_INSUFFICIENT_IMPACT",
}


def apply_promotion_gate(
    kimi_candidates: list[dict[str, Any]],
    minimax_challenges: list[dict[str, Any]],
    *,
    providers: tuple[str, ...] = ("kimi", "minimax"),
    ext: str = "sol",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply the 4-step promotion gate. Return (survivors, rejected, pending).

    Each rejected entry includes a `rejection_reason` field. Each
    surviving entry is annotated with `status:
    KEEP_FOR_LOCAL_VERIFICATION` (NEVER submission-ready) and a
    `claude_poc_task` placeholder string the operator must execute.

    When the campaign intentionally runs a strict provider subset, candidates
    that are missing the disabled provider's evidence are held in
    `pending_review` instead of being falsely rejected. This keeps Kimi-only
    source reading useful while preserving strict dual-provider behavior.
    """
    provider_set = set(providers)
    by_id: dict[str, dict[str, Any]] = {}
    for ch in minimax_challenges:
        cid = ch.get("candidate_id")
        if isinstance(cid, str):
            by_id[cid] = ch

    # Dedupe Kimi candidates by candidate_id — a multi-domain campaign
    # can surface the same candidate from two adjacent buckets, and the
    # promotion-gate output must not double-count survivors. First-seen
    # wins so the original domain assignment is preserved in the
    # survivor record.
    seen_ids: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for cand in kimi_candidates:
        cid = cand.get("candidate_id")
        if isinstance(cid, str) and cid in seen_ids:
            continue
        if isinstance(cid, str):
            seen_ids.add(cid)
        deduped.append(cand)

    survivors: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for cand in deduped:
        cid = cand.get("candidate_id")
        rec = dict(cand)
        # (a) line cite. I18 (#335): cite extension is parameterised so
        # non-Solidity workspaces validate `.rs:LINE` etc.
        if not _has_line_cite(cand, ext=ext):
            if "kimi" not in provider_set:
                rec["pending_reason"] = "pending-kimi-line-cite"
                rec["status"] = "PENDING_KIMI_REVIEW"
                pending.append(rec)
                continue
            rec["rejection_reason"] = "missing-line-cite"
            rejected.append(rec)
            continue
        # (d) deterministic OOS / impossible filters (run before
        # Minimax check so an admin-key candidate is rejected even if
        # Minimax silently kept it).
        oos = _has_oos_marker(cand)
        if oos is not None:
            rec["rejection_reason"] = f"oos-marker:{oos}"
            rejected.append(rec)
            continue
        imp = _has_impossible_trigger(cand)
        if imp is not None:
            rec["rejection_reason"] = f"impossible-trigger:{imp}"
            rejected.append(rec)
            continue
        # (b) Minimax kill-or-hold.
        challenge = by_id.get(cid) if isinstance(cid, str) else None
        if challenge is None:
            if "minimax" not in provider_set:
                rec["pending_reason"] = "pending-minimax-review"
                rec["status"] = "PENDING_MINIMAX_REVIEW"
                pending.append(rec)
                continue
            rec["rejection_reason"] = "no-minimax-challenge-for-candidate"
            rejected.append(rec)
            continue
        verdict = challenge.get("classification")
        if verdict in _MINIMAX_REJECT_VERDICTS:
            rec["rejection_reason"] = f"minimax:{verdict}"
            rec["minimax_reason"] = challenge.get("reason", "")
            rejected.append(rec)
            continue
        # Codex spec step (b): only KEEP_FOR_LOCAL_VERIFICATION promotes.
        # NEEDS_MORE_SOURCE is a hold state — Minimax did NOT clear the
        # candidate, just said it could not decide on the truncated input.
        # Treating it as a survivor would silently promote candidates that
        # the red-team explicitly flagged as inconclusive (Minimax pre-
        # review attack-class `silent-promote`, attack #6).
        if verdict == "NEEDS_MORE_SOURCE":
            rec["rejection_reason"] = "minimax:NEEDS_MORE_SOURCE"
            rec["minimax_reason"] = challenge.get("reason", "")
            rejected.append(rec)
            continue
        if verdict != "KEEP_FOR_LOCAL_VERIFICATION":
            rec["rejection_reason"] = f"minimax:unknown-verdict:{verdict}"
            rejected.append(rec)
            continue
        # (c) Claude PoC task placeholder.
        provider_mapping_claims: dict[str, Any] = {}
        for claim_key in (
            "severity",
            "severity_lower_bound",
            "severity_claim",
            "selected_impact",
        ):
            if claim_key in rec:
                provider_mapping_claims[claim_key] = rec.pop(claim_key)
        if provider_mapping_claims:
            rec.setdefault("provider_non_authoritative_claims", {})[
                "severity_or_impact"
            ] = provider_mapping_claims
        rec["status"] = "KEEP_FOR_LOCAL_VERIFICATION"
        rec["submission_posture"] = "NOT_SUBMIT_READY"
        rec["candidate_kind"] = "source_mining_generated_hypothesis"
        rec["selected_impact"] = ""
        rec["severity"] = "none"
        rec["impact_contract_required"] = True
        rec["impact_contract_id"] = ""
        rec["minimax_classification"] = verdict
        rec["minimax_reason"] = challenge.get("reason", "")
        rec["claude_poc_task"] = (
            f"Operator: verify line cite and create an impact_contract for "
            f"{cid} before PoC/harness/report work; check OOS_CHECKLIST.md "
            f"before any submission draft."
        )
        # Item #14: a survivor is a generated hypothesis. Promotion to
        # ``scaffolded_unverified`` happens when poc-scaffold.py produces a
        # scaffold; promotion to ``executed_with_manifest`` happens only
        # via tools/poc-execution-record.py.
        _evidence_class.stamp(rec, _evidence_class.GENERATED_HYPOTHESIS)
        survivors.append(rec)
    return survivors, rejected, pending


def _is_no_network_consent_error(rc: int, stderr: str) -> bool:
    """True when llm-dispatch failed because network consent was not granted."""
    return rc == EXIT_CANNOT_RUN and "cannot-run: no-consent" in (stderr or "")


def _is_auth_failed_error(rc: int, stderr: str) -> bool:
    """I9: True when llm-dispatch failed because the provider returned an
    authentication error (HTTP 401 / 403). Distinct from no-consent
    (operator hasn't granted network access) and from generic dispatch
    failure (5xx, transport error). The Kimi OAuth path is the most
    common trigger: the access_token expires every ~15 minutes and the
    dispatcher's refresh-via-CLI flow can fail (CLI missing, CLI
    timeout, refresh endpoint down). Without this classifier the
    campaign rolled them up as 0/0 silently — same shape as I1's
    no-consent silent-zero.

    Distinguishes by stderr substring rather than rc because the
    dispatch tool exits 3 (generic dispatch-failed) for both auth
    errors and 5xx; the difference is in the JSON payload's
    error.type field which we expose through the stderr excerpt."""
    if rc == 0:
        return False
    s = (stderr or "").lower()
    return (
        "http-401" in s
        or "http-403" in s
        or "authentication_error" in s
        or "api key appears to be invalid" in s
        or "api key appears to be expired" in s
    )


def _is_strategic_llm_disallowed_error(rc: int, stderr: str) -> bool:
    """I14 (#330): True when llm-dispatch refused the packet via the
    strategic-LLM policy gate (PR #278). Source-mine packets pass
    `--strategic-llm-allowed` post-#330 fix, so this classifier exists
    primarily as a regression guard: if the source-mine campaign ever
    drops the flag (or a future code path forgets it), all packets
    will be rejected with `cannot-run: strategic-llm-disallowed` and
    the rollup will fail loudly instead of producing silent zero
    survivors. Mirrors the no-consent and auth-failed shapes (I1, I9).
    """
    if rc == 0:
        return False
    return (
        rc == EXIT_CANNOT_RUN
        and "cannot-run: strategic-llm-disallowed" in (stderr or "")
    )


def _is_budget_skip_error(rc: int, stderr: str) -> bool:
    """I11 (#326): True when llm-dispatch's rolling-window budget guard
    refused the packet (`AUDITOOOR_LLM_BUDGET_GUARD=1` default-on,
    active ceilings come from tools/calibration/llm_budget.json). The
    dispatcher emits
    `budget-skip: tokens budget exhausted: <used>/<cap> in last
    <window>min` on stderr and `all providers exhausted` in the JSON
    error envelope when both Kimi and Minimax hit the cap.

    Without this classifier, an entire campaign run AFTER the budget
    is already exhausted reports `outcome: ok survivors=0` silently,
    same anti-pattern I9 (#320) auth-failed and I14 (#330)
    strategic-llm closed for their respective error classes.

    The dispatcher's exit code on budget-skip is non-zero (the
    fallback chain bubbles the error up). We anchor on the
    `budget-skip` substring in stderr — the dispatcher emits it
    verbatim from `tools/llm-dispatch.py` per its budget-guard path.
    """
    if rc == 0:
        return False
    s = (stderr or "").lower()
    return rc != 0 and ("budget-skip" in s or "tokens budget exhausted" in s)


# ---------------------------------------------------------------------------
# Artifact writer
# ---------------------------------------------------------------------------

def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Typed deep_candidate.v1 emission (PR #291 schema integration)
# ---------------------------------------------------------------------------
# Original wiring landed in PR #291 as a standalone stub at this same path
# (commit 9b5362643 on main). The PR #296 rebase replaced the stub with the
# full campaign wrapper and intentionally deferred the typed-schema
# integration to keep the rebase reviewable. This block restores the
# integration: every survivor of the 4-step promotion gate is emitted as a
# `deep_candidate.v1` record under `<workspace>/deep_candidates/`, so
# downstream consumers (campaign-telemetry, the deep validators) see typed
# input rather than free-form JSONL.

_DEEP_CANDIDATE_LIB: Optional[Any] = None


def _load_deep_candidate_lib() -> Optional[Any]:
    """Lazy-load `tools/lib/deep_candidate.py`. Cached after first call."""
    global _DEEP_CANDIDATE_LIB
    if _DEEP_CANDIDATE_LIB is not None:
        return _DEEP_CANDIDATE_LIB
    spec_path = REPO / "tools" / "lib" / "deep_candidate.py"
    if not spec_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "_deep_candidate_lib_sm", spec_path
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_deep_candidate_lib_sm", module)
    spec.loader.exec_module(module)
    _DEEP_CANDIDATE_LIB = module
    return module


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read one JSON object per line. Skips comments and malformed lines."""
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for ln, raw in enumerate(fh, 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                print(
                    f"[source-mining-campaign] WARN malformed JSON on "
                    f"line {ln}: {exc}",
                    file=sys.stderr,
                )
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


def _survivor_to_typed_kwargs(
    survivor: dict[str, Any], idx: int
) -> dict[str, Any]:
    """Map a 4-step-gate survivor onto the deep_candidate.v1 build_candidate
    signature. Survivors that did not surface a clean field default to the
    advisory-floor (confidence='low', promotion_status='investigate')."""
    bug = str(
        survivor.get("bug_shape")
        or survivor.get("candidate_id")
        or f"survivor-{idx}"
    )
    cid = str(
        survivor.get("candidate_id")
        or f"source_mine.kimi.{bug}.{idx}"
    )
    files_raw = (
        survivor.get("files")
        or survivor.get("file_paths")
        or survivor.get("source_files")
        or []
    )
    if isinstance(files_raw, str):
        files_raw = [files_raw]
    files = [str(f) for f in files_raw] or [
        "<workspace-relative path TBD — see survivors.json>",
    ]
    claim = str(
        survivor.get("description")
        or survivor.get("bug_shape")
        or bug
    )
    trigger = str(
        survivor.get("trigger")
        or "See `survivors.json` for the full Kimi/Minimax claim payload."
    )
    impact = str(
        survivor.get("impact")
        or "Tier-B advisory; impact pending production-path confirmation."
    )
    reproduction = str(
        survivor.get("repro")
        or survivor.get("reproduction")
        or survivor.get("claude_poc_task")
        or (
            "manual: open cited files, reproduce trigger in a Foundry "
            "test, link the test path here"
        )
    )
    return {
        "lane": "source_mine",
        "candidate_id": cid,
        "files": files,
        "claim": claim,
        "trigger": trigger,
        "impact": impact,
        "reproduction": reproduction,
        "confidence": "low",
        "promotion_status": "investigate",
        "blocking_questions": [
            "Has an independent re-reading of the cited file confirmed the trigger?",
            "Is the bug class actually covered by an existing reference/patterns.dsl entry?",
            "Does the workspace exhibit this on a production path (not lib/test/mock)?",
        ],
        "tool": "source-mining-campaign.py",
        "lane_payload": {
            "raw_survivor": survivor,
        },
    }


def emit_typed_candidates(
    workspace: Path,
    survivors: list[dict[str, Any]],
) -> tuple[int, list[Path]]:
    """Write one deep_candidate.v1 file per survivor under
    `<workspace>/deep_candidates/source_mine/`. Returns (count, paths).

    Failure modes are non-fatal to the campaign: if the lib is missing or
    a single survivor fails validation, log to stderr and continue. The
    typed-candidate emission is an enrichment, not a gate."""
    lib = _load_deep_candidate_lib()
    if lib is None:
        print(
            "[source-mining-campaign] deep_candidate lib not found; "
            "skipping typed emission",
            file=sys.stderr,
        )
        return 0, []
    written: list[Path] = []
    for idx, survivor in enumerate(survivors):
        try:
            kwargs = _survivor_to_typed_kwargs(survivor, idx)
            doc = lib.build_candidate(workspace=workspace, **kwargs)
            out_path = lib.write_candidate(doc, workspace=workspace)
        except Exception as exc:  # noqa: BLE001 — emission is best-effort
            print(
                f"[source-mining-campaign] WARN typed emission failed for "
                f"idx={idx}: {exc}",
                file=sys.stderr,
            )
            continue
        written.append(out_path)
    if written:
        print(
            f"[source-mining-campaign] typed_candidates emitted="
            f"{len(written)} workspace={workspace}",
            file=sys.stderr,
        )
    return len(written), written


def run_typed_candidate_promotion(
    *,
    workspace: Path,
    out_dir: Path,
    typed_paths: list[Path],
) -> tuple[Path | None, Path | None]:
    """Best-effort promotion summary for source-mining typed candidates.

    This does not mutate candidate JSON and does not make campaign success
    depend on promotion. It gives operators an immediate sorted work queue
    (`rejected` / `needs_poc` / `poc_ready`) beside the source-mining artifacts.
    """
    if not typed_paths or not PROMOTE_TYPED_CANDIDATE.is_file():
        return None, None
    json_out = out_dir / "typed_candidate_promotions.json"
    md_out = out_dir / "typed_candidate_promotions.md"
    tasks_json_out = out_dir / "poc_tasks.json"
    tasks_md_out = out_dir / "poc_tasks.md"
    brief_dir = out_dir / "poc_task_briefs"
    dossier_dir = out_dir / "production_path_dossiers"
    cmd = [
        sys.executable,
        str(PROMOTE_TYPED_CANDIDATE),
        "--workspace",
        str(workspace),
        "--require-line-cite",
        "--require-production-path",
        "--out-json",
        str(json_out),
        "--out-md",
        str(md_out),
        "--out-tasks-json",
        str(tasks_json_out),
        "--out-tasks-md",
        str(tasks_md_out),
        "--out-brief-dir",
        str(brief_dir),
        "--out-dossier-dir",
        str(dossier_dir),
        *[str(path) for path in typed_paths],
    ]
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        print(
            f"[source-mining-campaign] WARN typed promotion failed to start: {exc}",
            file=sys.stderr,
        )
        return None, None
    if proc.returncode != 0:
        print(
            "[source-mining-campaign] WARN typed promotion failed "
            f"rc={proc.returncode}: {proc.stderr.strip()[-400:]}",
            file=sys.stderr,
        )
        return None, None
    print(
        f"[source-mining-campaign] typed_candidate_promotions json={json_out} md={md_out}",
        file=sys.stderr,
    )
    return json_out, md_out


def emit_from_jsonl(workspace: Path, jsonl: Path) -> int:
    """Standalone CLI: convert a wrapper-output JSONL file (one survivor
    per line) into deep_candidate.v1 emissions. Mirrors PR #291's
    pre-rebase entrypoint so existing callers don't break."""
    lib = _load_deep_candidate_lib()
    if lib is None:
        print(
            "[source-mining-campaign] ERR deep_candidate lib not found",
            file=sys.stderr,
        )
        return 2
    survivors = _read_jsonl(jsonl)
    if not survivors:
        print(
            "[source-mining-campaign] no survivors found; nothing emitted",
            file=sys.stderr,
        )
        return 0
    count, _ = emit_typed_candidates(workspace, survivors)
    print(
        f"[source-mining-campaign] OK emitted={count} workspace={workspace}",
        file=sys.stderr,
    )
    return 0


def write_artifacts(
    *,
    out_dir: Path,
    domains: dict[str, list[str]],
    providers: tuple[str, ...],
    kimi_candidates: list[dict[str, Any]],
    minimax_challenges: list[dict[str, Any]],
    survivors: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    pending_review: list[dict[str, Any]],
    source_coverage: dict[str, Any],
    workspace: Path,
    emit_typed: bool = True,
) -> dict[str, Path]:
    """Write the Codex-mandated artifact set to out_dir."""
    paths: dict[str, Path] = {}
    routing_manifest = build_outcome_routing_manifest(
        providers=providers,
        survivors=survivors,
        rejected=rejected,
        pending_review=pending_review,
    )
    stamp_outcome_routing(survivors)
    stamp_outcome_routing(pending_review)

    paths["kimi_candidates"] = out_dir / "kimi_candidates.json"
    _atomic_write_json(paths["kimi_candidates"], kimi_candidates)

    paths["minimax_challenges"] = out_dir / "minimax_challenges.json"
    _atomic_write_json(paths["minimax_challenges"], minimax_challenges)

    paths["survivors"] = out_dir / "survivors.json"
    _atomic_write_json(paths["survivors"], survivors)

    paths["rejected"] = out_dir / "rejected.json"
    _atomic_write_json(paths["rejected"], rejected)

    paths["pending_review"] = out_dir / "survivors_pending_minimax_review.json"
    _atomic_write_json(paths["pending_review"], pending_review)

    paths["outcome_calibrated_routing"] = out_dir / "outcome_calibrated_routing.json"
    _atomic_write_json(paths["outcome_calibrated_routing"], routing_manifest)

    paths["source_coverage"] = out_dir / "source_coverage.json"
    _atomic_write_json(paths["source_coverage"], source_coverage)

    # Markdown summary — operator-facing.
    md_lines = [
        f"# source-mining-campaign — {workspace.name}",
        f"",
        f"- workspace: `{workspace}`",
        f"- generated_at_utc: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"- domains: {len(domains)}",
        f"- kimi_candidates: {len(kimi_candidates)}",
        f"- minimax_challenges: {len(minimax_challenges)}",
        f"- survivors: {len(survivors)}",
        f"- pending_review: {len(pending_review)}",
        f"- rejected: {len(rejected)}",
        f"- outcome_routing: `{paths['outcome_calibrated_routing'].name}`",
        f"- routing_status: `{routing_manifest['overall_routing_status']}`",
        "",
        "## Survivors (KEEP_FOR_LOCAL_VERIFICATION — NOT submission-ready)",
        "",
    ]
    if not survivors:
        md_lines.append("- (none)")
    for cand in survivors:
        cid = cand.get("candidate_id", "<no-id>")
        shape = cand.get("bug_shape", "")
        md_lines.append(f"- **{cid}** — {shape}")
        md_lines.append(f"  - claude_poc_task: {cand.get('claude_poc_task', '')}")
        md_lines.append(
            f"  - allocation_status: {cand.get('allocation_status', 'blocked_missing_impact_contract')}"
        )
        md_lines.append("  - routing: input-only until local verification + M14 grep")
    md_lines += ["", "## Pending Provider Review (NOT rejected)", ""]
    if not pending_review:
        md_lines.append("- (none)")
    for cand in pending_review:
        cid = cand.get("candidate_id", "<no-id>")
        reason = cand.get("pending_reason", "")
        shape = cand.get("bug_shape", "")
        md_lines.append(f"- **{cid}** — {reason}: {shape}")
    md_lines += ["", "## Rejected (deterministic gate or Minimax veto)", ""]
    if not rejected:
        md_lines.append("- (none)")
    for cand in rejected:
        cid = cand.get("candidate_id", "<no-id>")
        reason = cand.get("rejection_reason", "")
        md_lines.append(f"- **{cid}** — {reason}")
    md_lines += [
        "",
        "## Promotion gate",
        "",
        "This wrapper does NOT promote candidates to findings. Each",
        "survivor requires:",
        "1. Operator-run PoC or source-proof.",
        "2. Independent grep against `reference/patterns.dsl/`.",
        "3. OOS/known-issue cross-check.",
        "4. Codex review of any submission draft.",
        "5. Outcome-calibrated routing remains input-only until the",
        "   `outcome_calibrated_routing.json` blockers are locally verified.",
        "6. High-severity harness/PoC/report allocation is blocked until an",
        "   exact impact contract is locked; only scope/impact-analysis work is allowed.",
        "",
    ]
    paths["summary"] = out_dir / "summary.md"
    _atomic_write_text(paths["summary"], "\n".join(md_lines))

    # Typed deep_candidate.v1 emission (PR #291 schema integration). This
    # is best-effort enrichment for downstream consumers; failures here
    # never fail the campaign because survivors are already on disk in
    # `survivors.json` regardless.
    if emit_typed and survivors:
        count, typed_paths = emit_typed_candidates(workspace, survivors)
        if typed_paths:
            paths["typed_candidates_dir"] = typed_paths[0].parent
            promo_json, promo_md = run_typed_candidate_promotion(
                workspace=workspace,
                out_dir=out_dir,
                typed_paths=typed_paths,
            )
            if promo_json is not None:
                paths["typed_candidate_promotions_json"] = promo_json
            if promo_md is not None:
                paths["typed_candidate_promotions_md"] = promo_md
                tasks_json = out_dir / "poc_tasks.json"
                tasks_md = out_dir / "poc_tasks.md"
                if tasks_json.is_file():
                    paths["poc_tasks_json"] = tasks_json
                if tasks_md.is_file():
                    paths["poc_tasks_md"] = tasks_md
                brief_dir = out_dir / "poc_task_briefs"
                if brief_dir.is_dir() and any(brief_dir.glob("*.md")):
                    paths["poc_task_briefs_dir"] = brief_dir
                dossier_dir = out_dir / "production_path_dossiers"
                if dossier_dir.is_dir() and any(dossier_dir.glob("*.json")):
                    paths["production_path_dossiers_dir"] = dossier_dir

    return paths


# ---------------------------------------------------------------------------
# Resume detection
# ---------------------------------------------------------------------------

def _packet_resume_path(out_dir: Path, domain: str, provider: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", domain)
    return out_dir / "packets" / f"{safe}_{provider}_done.json"


def _packet_already_done(out_dir: Path, domain: str, provider: str) -> bool:
    return _packet_resume_path(out_dir, domain, provider).is_file()


def _record_packet_done(out_dir: Path, domain: str, provider: str, payload: dict[str, Any]) -> None:
    path = _packet_resume_path(out_dir, domain, provider)
    _atomic_write_json(path, payload)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_campaign(
    *,
    workspace: Path,
    out_dir: Path,
    providers: tuple[str, ...],
    packet_budget: int,
    timeout: float,
    max_tokens: int,
    runner: Callable[..., tuple[int, str, str]] | None = None,
    domain_slicer: Callable[..., dict[str, list[str]]] | None = None,
    emit_typed: bool = True,
    ext: str = "sol",
) -> dict[str, Any]:
    """Run the campaign end-to-end. Pure-function-ish: I/O happens via
    parameters so tests can scaffold a temp workspace and inject a
    mock dispatcher. Returns a manifest dict.

    I18 (#335): `ext` selects the file extension to mine — `sol`
    (default), `rs` (Rust/Soroban), `cairo`, `move`, or `vy`. The
    extension parameterises the workspace walker, the line-cite
    validator, and is included in the manifest for traceability.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "packets").mkdir(exist_ok=True)

    state = _campaign_state_init(out_dir, lane="source_mine")
    truth_block = _read_truth_block(workspace)
    impact_worklist_context = load_impact_worklist_context(workspace)
    slicer = domain_slicer or slice_domains
    # Pass `ext` to the slicer when it accepts it; the default
    # slice_domains accepts ext, but custom slicers (test injectables)
    # may not.
    try:
        domains = slicer(workspace, ext=ext)
    except TypeError:
        domains = slicer(workspace)

    audit_dir = out_dir / "agent_outputs"

    all_kimi: list[dict[str, Any]] = []
    all_minimax: list[dict[str, Any]] = []
    dispatch_attempt_count = 0
    no_network_consent_count = 0
    consent_skipped_domains: list[str] = []
    # I9: count packets where every dispatch returned an authentication
    # error (HTTP 401/403). When ALL dispatches fail with auth-failed,
    # the campaign exits non-zero so silent zero-survivors no longer
    # masquerade as "no findings". Mirrors the no-consent rollup.
    auth_failed_count = 0
    auth_failed_domains: list[str] = []
    # I14 (#330): regression guard. Source-mine packets pass
    # `--strategic-llm-allowed` so the strategic-LLM gate doesn't
    # false-positive on truth-blocks that quote bounty READMEs
    # mentioning "roadmap" / etc. If the flag is ever dropped (code
    # rot, refactor mistake), this counter catches the all-rejected
    # case loudly via the same shape as I1 (no-consent) and I9
    # (auth-failed) — outcome = `cannot-run: strategic-llm-disallowed`.
    strategic_disallowed_count = 0
    strategic_disallowed_domains: list[str] = []
    # I11 (#326): rolling-window budget guard exhaustion. When EVERY
    # non-consent / non-auth dispatch is refused with `budget-skip`,
    # the rollup exits loud (`outcome: cannot-run: budget-exhausted`)
    # with a remediation hint. Without this, a campaign run AFTER
    # the budget is already spent reports `outcome: ok survivors=0`
    # which is the silent-zero anti-pattern I1/I9/I14 close for
    # their classes.
    budget_skip_count = 0
    budget_skip_domains: list[str] = []
    coverage: dict[str, Any] = {
        "schema": SCHEMA_VERSION + ".source_coverage",
        "workspace": str(workspace),
        "domains": {},
        "files_skipped_global": [],
        "impact_worklist_context": {
            "status": impact_worklist_context.get("status", "missing"),
            "artifact": impact_worklist_context.get("artifact", ""),
            "worklist_count": impact_worklist_context.get("worklist_count", 0),
            "submission_posture": "NOT_SUBMIT_READY",
            "submit_ready": False,
        },
    }

    use_kimi = "kimi" in providers
    use_minimax = "minimax" in providers

    for domain, files in domains.items():
        # Kimi pass.
        if use_kimi and not _packet_already_done(out_dir, domain, "kimi"):
            kimi_packet, dom_coverage = build_kimi_packet(
                workspace=workspace,
                domain=domain,
                files=files,
                truth_block=truth_block,
                impact_worklist_context=impact_worklist_context,
                char_cap=min(packet_budget, KIMI_PACKET_CHAR_CAP),
            )
            coverage["domains"][domain] = dom_coverage
            rc, stdout, stderr = _dispatch_llm(
                provider="kimi",
                prompt_text=kimi_packet,
                audit_dir=audit_dir,
                timeout=timeout,
                max_tokens=max_tokens,
                input_is_truncated=False,
                task_type="source-extract",
                workspace=workspace,
                runner=runner,
            )
            dispatch_attempt_count += 1
            if _is_no_network_consent_error(rc, stderr):
                no_network_consent_count += 1
                consent_skipped_domains.append(domain)
            elif _is_auth_failed_error(rc, stderr):
                auth_failed_count += 1
                auth_failed_domains.append(domain)
            elif _is_strategic_llm_disallowed_error(rc, stderr):
                strategic_disallowed_count += 1
                strategic_disallowed_domains.append(domain)
            elif _is_budget_skip_error(rc, stderr):
                budget_skip_count += 1
                budget_skip_domains.append(domain)
            cand = parse_jsonl(stdout) if rc == 0 else []
            for c in cand:
                c["_provider"] = "kimi"
                c["_domain"] = domain
            all_kimi.extend(cand)
            # Persist the per-domain results into the marker file itself so
            # resume can rebuild `all_kimi` without depending on the
            # post-loop `kimi_candidates.json` aggregate (which only exists
            # after the campaign reaches `write_artifacts`). Closes Kimi
            # pre-review concern #4-5 and Minimax pre-review attack #4
            # ("crash between marker write and artifact write").
            _record_packet_done(out_dir, domain, "kimi", {
                "rc": rc, "candidate_count": len(cand),
                "candidates": cand,
                "stderr_excerpt": stderr[:500] if stderr else "",
            })
        elif use_kimi:
            # Resume — load per-domain candidates from the marker file.
            # Falls back to the aggregate kimi_candidates.json when the
            # marker is from a pre-fix run that didn't carry the
            # `candidates` field. Stale candidates from a prior run with a
            # different slicer ARE reused: callers who change the slicer
            # mid-campaign should delete the marker first (documented in
            # the runbook).
            marker = _packet_resume_path(out_dir, domain, "kimi")
            try:
                rec = json.loads(marker.read_text(encoding="utf-8"))
                cand = rec.get("candidates")
                if isinstance(cand, list):
                    all_kimi.extend(cand)
                else:
                    # Pre-fix marker: fall back to the aggregate.
                    prior = out_dir / "kimi_candidates.json"
                    if prior.is_file():
                        agg = json.loads(prior.read_text(encoding="utf-8"))
                        if isinstance(agg, list):
                            all_kimi.extend(c for c in agg if c.get("_domain") == domain)
            except (OSError, ValueError):
                pass
        else:
            # Coverage record even when not running Kimi — caller can see what
            # would have shipped.
            coverage["domains"].setdefault(domain, {
                "domain": domain, "files_considered": list(files),
                "files_included": [], "files_skipped": [
                    {"file": f, "reason": "kimi-disabled"} for f in files
                ],
            })

        # Minimax pass — only when Kimi produced something for this domain
        # (no candidates → nothing to red-team).
        if use_minimax and not _packet_already_done(out_dir, domain, "minimax"):
            domain_kimi = [c for c in all_kimi if c.get("_domain") == domain]
            if not domain_kimi:
                _record_packet_done(out_dir, domain, "minimax", {
                    "rc": 0, "challenge_count": 0,
                    "challenges": [],
                    "skipped": "no-kimi-candidates",
                })
                continue
            minimax_packet, truncated = build_minimax_packet(
                workspace=workspace,
                domain=domain,
                truth_block=truth_block,
                kimi_candidates=domain_kimi,
                char_cap=min(packet_budget * 4, MINIMAX_PACKET_CHAR_CAP),
            )
            input_is_truncated = truncated or len(minimax_packet) > MINIMAX_TRUNCATION_THRESHOLD
            rc, stdout, stderr = _dispatch_llm(
                provider="minimax",
                prompt_text=minimax_packet,
                audit_dir=audit_dir,
                timeout=timeout,
                max_tokens=max_tokens,
                input_is_truncated=input_is_truncated,
                task_type="adversarial-kill",
                workspace=workspace,
                runner=runner,
            )
            dispatch_attempt_count += 1
            if _is_no_network_consent_error(rc, stderr):
                no_network_consent_count += 1
                consent_skipped_domains.append(domain)
            elif _is_auth_failed_error(rc, stderr):
                auth_failed_count += 1
                auth_failed_domains.append(domain)
            elif _is_strategic_llm_disallowed_error(rc, stderr):
                strategic_disallowed_count += 1
                strategic_disallowed_domains.append(domain)
            elif _is_budget_skip_error(rc, stderr):
                budget_skip_count += 1
                budget_skip_domains.append(domain)
            challenges = parse_jsonl(stdout) if rc == 0 else []
            for c in challenges:
                c["_provider"] = "minimax"
                c["_domain"] = domain
            all_minimax.extend(challenges)
            _record_packet_done(out_dir, domain, "minimax", {
                "rc": rc, "challenge_count": len(challenges),
                "challenges": challenges,
                "stderr_excerpt": stderr[:500] if stderr else "",
                "input_is_truncated": input_is_truncated,
            })
        elif use_minimax:
            # Resume — load per-domain challenges from the marker file.
            # Without this branch, `all_minimax` stays empty for the
            # already-completed domain and `apply_promotion_gate` would
            # reject every candidate as `no-minimax-challenge-for-
            # candidate`. Closes Kimi pre-review #5.
            marker = _packet_resume_path(out_dir, domain, "minimax")
            try:
                rec = json.loads(marker.read_text(encoding="utf-8"))
                ch = rec.get("challenges")
                if isinstance(ch, list):
                    all_minimax.extend(ch)
            except (OSError, ValueError):
                pass

    if dispatch_attempt_count > 0 and no_network_consent_count == dispatch_attempt_count:
        manifest = {
            "schema": SCHEMA_VERSION + ".manifest",
            "state": state,
            "outcome": "cannot-run: no-network-consent",
            "out_dir": str(out_dir),
            "providers": list(providers),
            "domain_count": len(domains),
            "kimi_candidate_count": len(all_kimi),
            "minimax_challenge_count": len(all_minimax),
            "survivor_count": 0,
            "rejected_count": 0,
            "pending_review_count": 0,
            "consent_skipped_domains": len(set(consent_skipped_domains)),
            "consent_skipped_domain_names": sorted(set(consent_skipped_domains)),
            "auth_failed_count": auth_failed_count,
            "auth_failed_domains": sorted(set(auth_failed_domains)),
            "dispatch_attempt_count": dispatch_attempt_count,
            "no_network_consent_count": no_network_consent_count,
            "artifacts": {},
        }
        _atomic_write_json(out_dir / "kimi_candidates.json", all_kimi)
        _atomic_write_json(out_dir / "minimax_challenges.json", all_minimax)
        _atomic_write_json(out_dir / "survivors.json", [])
        _atomic_write_json(out_dir / "rejected.json", [])
        _atomic_write_json(out_dir / "survivors_pending_minimax_review.json", [])
        _atomic_write_json(out_dir / "source_coverage.json", coverage)
        return manifest

    # I9: when ALL non-consent dispatches failed with auth-failed, exit
    # non-zero with a clear classification. Mirrors the no-consent path
    # above but on a separate failure mode (HTTP 401/403). Without this
    # the campaign rolled them up as 0/0/0 and downstream telemetry
    # treated it as "no findings" — same shape as I1's silent zero.
    non_consent_attempts = dispatch_attempt_count - no_network_consent_count
    if non_consent_attempts > 0 and auth_failed_count == non_consent_attempts:
        manifest = {
            "schema": SCHEMA_VERSION + ".manifest",
            "state": state,
            "outcome": "cannot-run: auth-failed",
            "out_dir": str(out_dir),
            "providers": list(providers),
            "domain_count": len(domains),
            "kimi_candidate_count": len(all_kimi),
            "minimax_challenge_count": len(all_minimax),
            "survivor_count": 0,
            "rejected_count": 0,
            "pending_review_count": 0,
            "consent_skipped_domains": len(set(consent_skipped_domains)),
            "consent_skipped_domain_names": sorted(set(consent_skipped_domains)),
            "auth_failed_count": auth_failed_count,
            "auth_failed_domains": sorted(set(auth_failed_domains)),
            "dispatch_attempt_count": dispatch_attempt_count,
            "no_network_consent_count": no_network_consent_count,
            "artifacts": {},
        }
        _atomic_write_json(out_dir / "kimi_candidates.json", all_kimi)
        _atomic_write_json(out_dir / "minimax_challenges.json", all_minimax)
        _atomic_write_json(out_dir / "survivors.json", [])
        _atomic_write_json(out_dir / "rejected.json", [])
        _atomic_write_json(out_dir / "survivors_pending_minimax_review.json", [])
        _atomic_write_json(out_dir / "source_coverage.json", coverage)
        return manifest

    # I14 (#330) regression guard: when EVERY non-consent non-auth-failed
    # dispatch hit the strategic-LLM gate, exit non-zero with a clear
    # classification. Without the strategic-allowed flag (post-fix), this
    # path should be cold; if any code rot drops the flag, this catches
    # the all-rejected case loudly.
    non_consent_or_auth = (
        dispatch_attempt_count - no_network_consent_count - auth_failed_count
    )
    if non_consent_or_auth > 0 and strategic_disallowed_count == non_consent_or_auth:
        manifest = {
            "schema": SCHEMA_VERSION + ".manifest",
            "state": state,
            "outcome": "cannot-run: strategic-llm-disallowed",
            "out_dir": str(out_dir),
            "providers": list(providers),
            "domain_count": len(domains),
            "kimi_candidate_count": len(all_kimi),
            "minimax_challenge_count": len(all_minimax),
            "survivor_count": 0,
            "rejected_count": 0,
            "pending_review_count": 0,
            "consent_skipped_domains": len(set(consent_skipped_domains)),
            "consent_skipped_domain_names": sorted(set(consent_skipped_domains)),
            "auth_failed_count": auth_failed_count,
            "auth_failed_domains": sorted(set(auth_failed_domains)),
            "strategic_disallowed_count": strategic_disallowed_count,
            "strategic_disallowed_domains": sorted(set(strategic_disallowed_domains)),
            "dispatch_attempt_count": dispatch_attempt_count,
            "no_network_consent_count": no_network_consent_count,
            "artifacts": {},
        }
        _atomic_write_json(out_dir / "kimi_candidates.json", all_kimi)
        _atomic_write_json(out_dir / "minimax_challenges.json", all_minimax)
        _atomic_write_json(out_dir / "survivors.json", [])
        _atomic_write_json(out_dir / "rejected.json", [])
        _atomic_write_json(out_dir / "survivors_pending_minimax_review.json", [])
        _atomic_write_json(out_dir / "source_coverage.json", coverage)
        return manifest

    # I11 (#326): when EVERY non-consent / non-auth / non-strategic
    # dispatch hit the rolling-window budget guard, exit non-zero with
    # a clear classification + remediation hint. Without this, a campaign
    # run AFTER the budget is already spent reports `outcome: ok
    # survivors=0` which misleads operators into thinking the run
    # actually inspected the workspace.
    non_consent_auth_or_strategic = (
        dispatch_attempt_count
        - no_network_consent_count
        - auth_failed_count
        - strategic_disallowed_count
    )
    if non_consent_auth_or_strategic > 0 and budget_skip_count == non_consent_auth_or_strategic:
        manifest = {
            "schema": SCHEMA_VERSION + ".manifest",
            "state": state,
            "outcome": "cannot-run: budget-exhausted",
            "out_dir": str(out_dir),
            "providers": list(providers),
            "domain_count": len(domains),
            "kimi_candidate_count": len(all_kimi),
            "minimax_challenge_count": len(all_minimax),
            "survivor_count": 0,
            "rejected_count": 0,
            "pending_review_count": 0,
            "consent_skipped_domains": len(set(consent_skipped_domains)),
            "consent_skipped_domain_names": sorted(set(consent_skipped_domains)),
            "auth_failed_count": auth_failed_count,
            "auth_failed_domains": sorted(set(auth_failed_domains)),
            "strategic_disallowed_count": strategic_disallowed_count,
            "strategic_disallowed_domains": sorted(set(strategic_disallowed_domains)),
            "budget_skip_count": budget_skip_count,
            "budget_skip_domains": sorted(set(budget_skip_domains)),
            "dispatch_attempt_count": dispatch_attempt_count,
            "no_network_consent_count": no_network_consent_count,
            "artifacts": {},
            "remediation": (
                "Either wait for the rolling token-window to reset, or tune "
                "tools/calibration/llm_budget.json / "
                "AUDITOOOR_LLM_BUDGET_CONFIG for a paid-tier audited run. "
                "Keep the guard enabled so spend remains logged; use "
                "AUDITOOOR_LLM_BUDGET_GUARD=0 only when deliberately "
                "accepting unbounded spend."
            ),
        }
        _atomic_write_json(out_dir / "kimi_candidates.json", all_kimi)
        _atomic_write_json(out_dir / "minimax_challenges.json", all_minimax)
        _atomic_write_json(out_dir / "survivors.json", [])
        _atomic_write_json(out_dir / "rejected.json", [])
        _atomic_write_json(out_dir / "survivors_pending_minimax_review.json", [])
        _atomic_write_json(out_dir / "source_coverage.json", coverage)
        return manifest

    if no_network_consent_count:
        print(
            "[source-mining-campaign] WARN some provider dispatches were skipped "
            f"for missing network consent: {no_network_consent_count}/"
            f"{dispatch_attempt_count}",
            file=sys.stderr,
        )

    if auth_failed_count:
        print(
            "[source-mining-campaign] WARN some provider dispatches failed "
            f"authentication (HTTP 401/403): {auth_failed_count}/"
            f"{dispatch_attempt_count} — refresh credentials and re-run "
            "(`kimi --print` interactively to refresh OAuth, or set "
            "KIMI_API_KEY)",
            file=sys.stderr,
        )

    if strategic_disallowed_count:
        print(
            "[source-mining-campaign] WARN some provider dispatches were "
            f"refused by the strategic-LLM gate: {strategic_disallowed_count}/"
            f"{dispatch_attempt_count} — verify --strategic-llm-allowed is "
            "still being passed to llm-dispatch (regression guard for I14)",
            file=sys.stderr,
        )

    if budget_skip_count:
        print(
            "[source-mining-campaign] WARN some provider dispatches were "
            f"skipped by the rolling-window budget guard: {budget_skip_count}/"
            f"{dispatch_attempt_count} — wait for the window to reset, or "
            "tune tools/calibration/llm_budget.json / "
            "AUDITOOOR_LLM_BUDGET_CONFIG for a paid-tier audited run "
            "(I11 regression telemetry).",
            file=sys.stderr,
        )

    survivors, rejected, pending_review = apply_promotion_gate(
        all_kimi,
        all_minimax,
        providers=providers,
        ext=ext,
    )

    paths = write_artifacts(
        out_dir=out_dir,
        domains=domains,
        providers=providers,
        kimi_candidates=all_kimi,
        minimax_challenges=all_minimax,
        survivors=survivors,
        rejected=rejected,
        pending_review=pending_review,
        source_coverage=coverage,
        workspace=workspace,
        emit_typed=emit_typed,
    )

    return {
        "schema": SCHEMA_VERSION + ".manifest",
        "state": state,
        "out_dir": str(out_dir),
        "providers": list(providers),
        "domain_count": len(domains),
        "kimi_candidate_count": len(all_kimi),
        "minimax_challenge_count": len(all_minimax),
        "survivor_count": len(survivors),
        "rejected_count": len(rejected),
        "pending_review_count": len(pending_review),
        "consent_skipped_domains": len(set(consent_skipped_domains)),
        "consent_skipped_domain_names": sorted(set(consent_skipped_domains)),
        "auth_failed_count": auth_failed_count,
        "auth_failed_domains": sorted(set(auth_failed_domains)),
        "strategic_disallowed_count": strategic_disallowed_count,
        "strategic_disallowed_domains": sorted(set(strategic_disallowed_domains)),
        "budget_skip_count": budget_skip_count,
        "budget_skip_domains": sorted(set(budget_skip_domains)),
        "dispatch_attempt_count": dispatch_attempt_count,
        "no_network_consent_count": no_network_consent_count,
        "ext": ext,
        "artifacts": {k: str(v) for k, v in paths.items()},
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="source-mining-campaign",
        description=(
            "Source-mining campaign wrapper around tools/llm-dispatch.py. "
            "Runs Kimi candidate-extraction + Minimax red-team passes, "
            "applies the 4-step promotion gate, and writes "
            "survivors/rejected/source_coverage artifacts. Never auto-"
            "promotes a candidate to a finding — operator review required."
        ),
    )
    p.add_argument("--workspace", required=True, help="path to ~/audits/<project>")
    p.add_argument(
        "--providers",
        default="kimi,minimax",
        help="comma-separated subset of {kimi,minimax} (default: kimi,minimax)",
    )
    p.add_argument(
        "--packet-budget",
        type=int,
        default=KIMI_PACKET_CHAR_CAP,
        help=f"per-packet character budget (default: {KIMI_PACKET_CHAR_CAP})",
    )
    p.add_argument(
        "--out",
        required=False,
        default=None,
        help=(
            "output dir (typically source_mining/<YYYY-MM-DD>). Required "
            "for the campaign loop; ignored under --from-jsonl."
        ),
    )
    p.add_argument(
        "--timeout", type=float, default=180.0, help="per-dispatch timeout seconds"
    )
    p.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help="max-tokens passed to llm-dispatch (default: 16000)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="enumerate domains and write source_coverage.json only; no LLM calls",
    )
    p.add_argument(
        "--no-emit-typed-candidates",
        action="store_true",
        help=(
            "Disable the typed deep_candidate.v1 emission for survivors. "
            "Default-on so downstream telemetry / deep validators see "
            "structured input."
        ),
    )
    p.add_argument(
        "--ext",
        default="sol",
        choices=["sol", "rs", "cairo", "move", "vy"],
        help=(
            "I18 (#335): file extension to mine. Default `sol` (Solidity). "
            "`rs` enables Rust/Soroban workspaces (descends into "
            "`contracts/<crate>/src/*.rs` alongside `src/`). `cairo` / "
            "`move` / `vy` are reserved for future engagements. The "
            "extension parameterises the workspace walker, line-cite "
            "validator, and is recorded in the manifest."
        ),
    )
    p.add_argument(
        "--from-jsonl",
        type=Path,
        default=None,
        help=(
            "Standalone mode: re-emit typed deep_candidate.v1 records "
            "from a wrapper-output JSONL (one survivor per line). When "
            "set, the campaign loop is skipped and only the typed "
            "emission runs. Requires --workspace and --emit-candidate."
        ),
    )
    p.add_argument(
        "--emit-candidate",
        action="store_true",
        help=(
            "Required opt-in gate for the standalone --from-jsonl mode. "
            "Mirrors PR #291's pre-rebase contract: a stub that wrote "
            "by default would be a foot-gun. Ignored when the full "
            "campaign loop runs (campaign emits by default; use "
            "--no-emit-typed-candidates to disable)."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_argparser()
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(json.dumps({
            "reason": "cannot-run: workspace-not-a-dir",
            "workspace": str(workspace),
        }), file=sys.stderr)
        return EXIT_CANNOT_RUN

    # Standalone re-emit mode (PR #291 entrypoint preserved). Skips the
    # full campaign loop — useful when an operator wants to convert an
    # existing survivors JSONL into typed records without re-running LLMs.
    if args.from_jsonl is not None:
        if not args.emit_candidate:
            print(
                "[source-mining-campaign] --emit-candidate is required "
                "for --from-jsonl (opt-in gate)",
                file=sys.stderr,
            )
            return EXIT_CANNOT_RUN
        jsonl_path = args.from_jsonl.expanduser().resolve()
        if not jsonl_path.is_file():
            print(json.dumps({
                "reason": "cannot-run: jsonl-not-a-file",
                "jsonl": str(jsonl_path),
            }), file=sys.stderr)
            return EXIT_CANNOT_RUN
        return emit_from_jsonl(workspace, jsonl_path)

    if not args.out:
        print(json.dumps({
            "reason": "cannot-run: --out is required for the campaign loop",
        }), file=sys.stderr)
        return EXIT_CANNOT_RUN

    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    providers_raw = [s.strip().lower() for s in args.providers.split(",") if s.strip()]
    providers = tuple(p for p in providers_raw if p in ("kimi", "minimax"))
    if not providers:
        print(json.dumps({
            "reason": "cannot-run: no-valid-providers",
            "providers": providers_raw,
        }), file=sys.stderr)
        return EXIT_CANNOT_RUN

    if args.dry_run:
        domains = slice_domains(workspace, ext=args.ext)
        coverage = {
            "schema": SCHEMA_VERSION + ".source_coverage",
            "workspace": str(workspace),
            "ext": args.ext,
            "dry_run": True,
            "domains": {
                d: {
                    "domain": d,
                    "files_considered": files,
                    "files_included": [],
                    "files_skipped": [{"file": f, "reason": "dry-run"} for f in files],
                }
                for d, files in domains.items()
            },
        }
        _atomic_write_json(out_dir / "source_coverage.json", coverage)
        print(json.dumps({
            "outcome": "dry-run-ok",
            "out_dir": str(out_dir),
            "domain_count": len(domains),
            "ext": args.ext,
        }))
        return EXIT_OK

    manifest = run_campaign(
        workspace=workspace,
        out_dir=out_dir,
        providers=providers,
        packet_budget=int(args.packet_budget),
        timeout=float(args.timeout),
        max_tokens=int(args.max_tokens),
        emit_typed=not args.no_emit_typed_candidates,
        ext=args.ext,
    )
    _atomic_write_json(out_dir / "manifest.json", manifest)
    if manifest.get("outcome") == "cannot-run: no-network-consent":
        print(json.dumps({
            "outcome": "cannot-run: no-network-consent",
            "out_dir": str(out_dir),
            "detail": (
                "All provider dispatches refused network access. Set "
                "AUDITOOOR_LLM_NETWORK_CONSENT=1 for real source mining."
            ),
            "consent_skipped_domains": manifest.get("consent_skipped_domains", 0),
        }), file=sys.stderr)
        return EXIT_ERROR
    if manifest.get("outcome") == "cannot-run: auth-failed":
        # I9: parallel exit path for the auth-failed silent-zero case.
        # Without this, a campaign whose every Kimi/Minimax call returned
        # HTTP 401 would emit "outcome=ok survivors=0" — operator-visible
        # signal "no bugs found" when really nothing got past auth.
        print(json.dumps({
            "outcome": "cannot-run: auth-failed",
            "out_dir": str(out_dir),
            "detail": (
                "All provider dispatches failed authentication "
                "(HTTP 401/403). For Kimi: run `kimi --print` "
                "interactively once to refresh the OAuth token, or "
                "set KIMI_API_KEY directly. For Minimax: verify "
                "MINIMAX_API_KEY / settings.json env."
            ),
            "auth_failed_count": manifest.get("auth_failed_count", 0),
            "auth_failed_domains": manifest.get("auth_failed_domains", []),
        }), file=sys.stderr)
        return EXIT_ERROR
    if manifest.get("outcome") == "cannot-run: strategic-llm-disallowed":
        # I14 (#330) regression-guard exit. Source-mine packets pass
        # `--strategic-llm-allowed` so this should be cold under normal
        # operation. If the flag is dropped (refactor mistake, code
        # rot), this catches all-rejected loudly instead of silent zero.
        print(json.dumps({
            "outcome": "cannot-run: strategic-llm-disallowed",
            "out_dir": str(out_dir),
            "detail": (
                "All provider dispatches were rejected by the strategic-LLM "
                "gate. Source-mine packets must pass `--strategic-llm-allowed` "
                "to llm-dispatch (regression guard for I14 #330). Verify the "
                "_dispatch_llm helper still includes the flag."
            ),
            "strategic_disallowed_count": manifest.get("strategic_disallowed_count", 0),
            "strategic_disallowed_domains": manifest.get("strategic_disallowed_domains", []),
        }), file=sys.stderr)
        return EXIT_ERROR
    if manifest.get("outcome") == "cannot-run: budget-exhausted":
        # I11 (#326): rolling-window budget guard exhausted across every
        # dispatch. Mirrors the I9 / I14 loud-fail pattern. Without this
        # branch, the campaign would print `outcome: ok survivors=0` and
        # the operator would think the workspace was actually mined.
        print(json.dumps({
            "outcome": "cannot-run: budget-exhausted",
            "out_dir": str(out_dir),
            "detail": manifest.get("remediation", (
                "All provider dispatches were skipped by the rolling-window "
                "budget guard. Wait for the window to reset, or tune "
                "tools/calibration/llm_budget.json / "
                "AUDITOOOR_LLM_BUDGET_CONFIG for a paid-tier audited run. "
                "Keep the guard enabled unless deliberately accepting "
                "unbounded spend."
            )),
            "budget_skip_count": manifest.get("budget_skip_count", 0),
            "budget_skip_domains": manifest.get("budget_skip_domains", []),
        }), file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps({
        "outcome": "ok",
        "out_dir": str(out_dir),
        "survivors": manifest["survivor_count"],
        "rejected": manifest["rejected_count"],
        "pending_review": manifest.get("pending_review_count", 0),
    }))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
