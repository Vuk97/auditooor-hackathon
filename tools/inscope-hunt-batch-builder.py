#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-INSCOPE-HUNT-WORKLIST registered via agent-pathspec-register.py -->
"""Build an IN-SCOPE-AUTHORITATIVE per-function hunt task-batch directly from
``<ws>/.auditooor/inscope_units.jsonl`` (the manifest the coverage gates treat as
authoritative), bypassing the monorepo-wide ranked-candidate selection that
`make hunt-scoped` uses.

WHY: on a multi-language monorepo the ranked-candidate worklist is scope-polluted
(observed on OP Stack: a 239-task hunt-scoped plan was ~92% OUT-OF-SCOPE - cannon,
op-batcher, op-chain-ops, docs/tutorials, Alt-DA, kona - and many anchors were
unresolvable, start_line=0). The in-scope manifest is the clean, complete set. This
builder emits one per_fn_workspace_hunt_v2 task per in-scope unit:
  - Solidity units carry a function name -> per-FUNCTION hunt.
  - Go/Rust units are file-level (function == "") -> per-FILE hunt (the agent audits
    every function in the file).
Each task's prompt instructs the sonnet agent to READ the real source itself and
cite a real file:line (R76-clean by construction - no embedded excerpt to drift).

CLI:
  python3 tools/inscope-hunt-batch-builder.py --workspace <ws> \
      [--out /tmp/<ws>_inscope_hunt_batch.jsonl] [--limit N] [--lang solidity|go|rust] \
      [--only-uncovered]
Output: a task-batch JSONL consumable by tools/haiku-fanout-dispatcher.py plan.
Exit: 0 ok (prints count + path); 2 usage / no manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

# RANK-2 wiring: surface operator-declared acknowledged-OOS issues from the
# structured known-issues registry (.auditooor/known_issues.json) into the
# hunt-agent's KNOWN-ISSUES DEDUP line, so a paid agent dedups against the
# registry up front instead of rediscovering an acknowledged issue. ADDITIVE.
_AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
try:
    from tools.lib import known_issues_registry as _ki_registry  # type: ignore
except Exception:  # pragma: no cover - direct-script fallback
    try:
        sys.path.insert(0, str(_AUDITOOOR_ROOT / "tools" / "lib"))
        import known_issues_registry as _ki_registry  # type: ignore
    except Exception:
        _ki_registry = None  # type: ignore


def _known_issue_dedup_note(ws_path: str) -> str:
    """RANK-2 additive: build an extra dedup hint for the prompt from the
    structured known-issues registry. Returns '' when the registry is absent /
    empty / the shared lib is unavailable (so the base prompt is unchanged)."""
    if _ki_registry is None or not ws_path:
        return ""
    try:
        issues = _ki_registry.load_known_oos(Path(ws_path))
    except Exception:  # pragma: no cover - defensive, never break prompt build
        return ""
    if not issues:
        return ""
    parts = []
    for issue in issues[:8]:
        terms = ", ".join((issue.get("keywords") or [])[:5])
        label = issue.get("id") or issue.get("title") or "known-issue"
        parts.append(f"[{issue.get('status')}] {label}"
                     + (f" ({terms})" if terms else ""))
    return (
        " REGISTERED OOS/ACKNOWLEDGED (auditooor.known_issues.json - do NOT file "
        "a rediscovery of these absent an extension-distinct argument; set "
        "dupe_check to the matching id if your candidate overlaps): "
        + "; ".join(parts) + "."
    )


def _stable_task_id(t: dict) -> str:
    """Content-stable task id from the function anchor (file basename + fn + line).

    The per-task hunt sidecar is written to the SHARED MIMO dir named by task_id.
    A sequential ``inscope_hunt_{i:05d}`` restarts at 00000 every dispatch wave, so
    each new wave OVERWRITES the prior wave's same-numbered sidecars -> fires-ago
    functions silently revert to untouched and the coverage count never converges
    (the cross-wave-overwrite churn bug). A content-stable id makes the filename
    deterministic per function: different functions never collide, and re-hunting a
    function idempotently overwrites ITS OWN sidecar.

    (unit x FRAME): when the task carries an ``impact`` field (--per-impact-frames),
    the impact is folded into the key so per-frame tasks of the SAME function get
    DISTINCT task_ids (and therefore distinct sidecar slugs via brick 1). A task with
    NO impact yields the exact legacy id (byte-identical - backward-compatible).
    """
    fa = t.get("function_anchor") or {}
    key = f"{Path(str(fa.get('file', ''))).name}:{fa.get('fn', '')}:{fa.get('start_line', 0)}"
    _impact = str(t.get("impact") or "").strip()
    if _impact:
        key = f"{key}::I={_impact}"
    return f"inscope_hunt_{hashlib.sha1(key.encode('utf-8')).hexdigest()[:12]}"


# ---------------------------------------------------------------------------
# (unit x IMPACT-FRAME) expansion - opt-in --per-impact-frames.
#
# R47 REUSE: the impact->mechanism taxonomy is owned by
# completeness-matrix-build.py::_MECHANISM_LIBRARY_SEED (the SAME source the
# completeness gate's mechanism axis materializes). We import that seed rather
# than re-declaring an impact taxonomy here, so brick 2 (task generation) and
# brick 3 (gate crediting) share ONE source of truth for "which impact frames
# are in-scope for this ws's languages".
# ---------------------------------------------------------------------------
_MECH_LIB_SEED = None


def _mech_lib_seed() -> dict:
    """Lazy-load _MECHANISM_LIBRARY_SEED from the sibling completeness-matrix-build.py
    (hyphenated filename -> importlib by path). Returns {} on any failure so the flag
    degrades to a no-op expansion (never crashes the default path)."""
    global _MECH_LIB_SEED
    if _MECH_LIB_SEED is not None:
        return _MECH_LIB_SEED
    try:
        _p = Path(__file__).resolve().parent / "completeness-matrix-build.py"
        _s = _ilu.spec_from_file_location("completeness_matrix_build_seed", _p)
        _mod = _ilu.module_from_spec(_s)
        _s.loader.exec_module(_mod)
        _MECH_LIB_SEED = dict(getattr(_mod, "_MECHANISM_LIBRARY_SEED", {}) or {})
    except Exception:  # pragma: no cover - defensive; flag degrades to no-op
        _MECH_LIB_SEED = {}
    return _MECH_LIB_SEED


# Map an inscope/fcc `lang` token to the mechanism-library language vocabulary
# (which uses "solidity"/"go"/"rust"/"move"). The library's languages list is the
# authority; we normalize a unit's short lang to it.
_LANG_TO_MECH = {
    "sol": "solidity", "solidity": "solidity",
    "go": "go", "rs": "rust", "rust": "rust",
    "move": "move", "cairo": "zk", "vy": "vyper", "vyper": "vyper",
}


def _inscope_impacts_for_lang(lang: str) -> list[str]:
    """In-scope IMPACT FRAMES for a single unit language, derived from the shared
    mechanism-library seed: an impact is in-scope for the language iff at least one
    of its mechanisms lists that language. Deterministic, sorted. Empty list when
    the seed is unavailable or the language maps to no mechanism (-> no expansion,
    the task stays single-frame == legacy)."""
    mech_lang = _LANG_TO_MECH.get((lang or "").lower())
    if not mech_lang:
        return []
    lib = _mech_lib_seed()
    impacts: set[str] = set()
    for impact, mechs in lib.items():
        for m in mechs:
            if mech_lang in (m.get("languages") or []):
                impacts.add(impact)
                break
    return sorted(impacts)


def _expand_task_per_impact(task: dict, lang: str) -> list[dict]:
    """Expand ONE per-function task into one task per in-scope impact frame for the
    unit's language. Sets task['impact']=<impact_id> on each and rewrites the prompt's
    impact instruction to hunt THAT ONE impact deeply. If no in-scope impact frame is
    derivable (unknown lang / seed missing), returns the original task UNCHANGED so the
    flag never drops a unit. Backward-compat: only invoked under --per-impact-frames."""
    impacts = _inscope_impacts_for_lang(lang)
    if not impacts:
        return [task]
    out: list[dict] = []
    base_prompt = task.get("prompt", "")
    for imp in impacts:
        t = dict(task)
        t["impact"] = imp
        t["prompt"] = _per_impact_prompt_prefix(imp) + base_prompt
        out.append(t)
    return out


def _per_impact_prompt_prefix(impact: str) -> str:
    """A single-frame focusing instruction prepended to the per-function prompt so the
    agent hunts THIS ONE impact deeply (not 'all impacts'). The base prompt still
    carries the full SEVERITY.md rubric (a candidate must still map to an in-scope row);
    this only narrows the ADVERSARY GOAL for this frame."""
    return (
        f"IMPACT FRAME (this task hunts ONE impact deeply): your ADVERSARY GOAL for this "
        f"task is achieving **{impact}** against the target. Reason specifically about "
        f"whether an attacker can drive the target to produce a `{impact}` outcome; do NOT "
        f"spread across every impact class - a sibling task covers each other frame. If the "
        f"target cannot produce `{impact}`, that source-cited rule-out for THIS frame IS "
        f"genuine coverage (set applies_to_target='no', notes='frame-ruled-out: {impact}').\n\n"
    )

TASK_TYPE = "per_fn_workspace_hunt_v2"

# ---------------------------------------------------------------------------
# DEPRIORITIZE-ONLY body scorer (language-agnostic)
# Assigns each task a priority integer BEFORE the --limit slice so that
# high-value functions sort FIRST and trivial getters/constructors LAST.
# NEVER drops a function - only reorders. All tasks are still emitted unless
# --limit truncates, and with --limit the kept K are always the top-ranked K.
# ---------------------------------------------------------------------------
import re as _re

# Patterns that increase priority (state-write / external-call / auth-gate /
# control-flow / value-transfer) - matched case-insensitively against the
# embedded body text or the function name. All patterns are generic: they
# fire for Solidity, Go, and Rust source alike.
_HIGH_PATTERNS: list[tuple[int, str]] = [
    # value transfer / fund movement
    (10, r"\btransfer\b"),
    (10, r"\.call\b"),
    (10, r"\.send\b"),
    (10, r"\bwithdraw"),
    (10, r"\bdeposit\b"),
    (10, r"\bmint\b"),
    (10, r"\bburn\b"),
    (10, r"\bliquidat"),
    (10, r"\brepay\b"),
    (10, r"\bborrow\b"),
    # auth / access control
    (8, r"\bonlyOwner\b"),
    (8, r"\bonlyRole\b"),
    (8, r"\bonlyAdmin\b"),
    (8, r"\brequire\b"),
    (8, r"\brevert\b"),
    (8, r"\bpanic!\b"),       # Rust panic
    (8, r"\bassert\b"),
    (8, r"\bmodifier\b"),
    # state-write indicators
    (6, r"\[.*\]\s*="),        # mapping/array assignment
    (6, r"\bself\.\w+\s*="),   # Rust field write
    (6, r"\b\w+\s*:="),        # Go short assign (heuristic)
    (6, r"\bstorage\b"),
    (6, r"\bemit\b"),
    (6, r"\bevent\b"),
    (6, r"\bdelegate"),
    # control flow complexity
    (4, r"\bfor\b"),
    (4, r"\bwhile\b"),
    (4, r"\bloop\b"),          # Rust loop
    (4, r"\bif\b"),
    (4, r"\bmatch\b"),         # Rust/Go match
    (4, r"\bselect\b"),        # Go select
]

# Patterns that mark a function as TRIVIAL (pure getter / simple constructor)
# - reduce priority when matched and no high patterns fire.
_LOW_PATTERNS: list[tuple[int, str]] = [
    (-8, r"^\s*return\s+\w+[\s;]*$"),       # single-line "return x"
    (-8, r"^\s*return\s+self\.\w+[\s;]*$"),  # Rust getter
    (-6, r"\bview\b"),                       # Solidity view fn
    (-6, r"\bpure\b"),                       # Solidity pure fn
    (-4, r"^\s*//"),                         # comment-only body
]

# Function-name heuristics (applied to the fn name, not the body)
_NAME_LOW = _re.compile(
    r"^(get[A-Z_]|is[A-Z_]|has[A-Z_]|view[A-Z_]|name$|symbol$|decimals$"
    r"|totalSupply$|owner$|version$|constructor$|initialize$|init$)",
    _re.IGNORECASE,
)
_NAME_HIGH = _re.compile(
    r"(transfer|withdraw|deposit|liquidat|repay|borrow|mint|burn|execute|"
    r"dispatch|settle|resolve|create|update|set[A-Z_]|remove|delete|"
    r"pause|unpause|lock|unlock|slash|claim|redeem|bridge|swap)",
    _re.IGNORECASE,
)


def _score_body(fn_name: str, body_text: str) -> int:
    """Return a priority integer for a function.

    Higher = more likely to be value-moving / security-relevant.
    Pure one-line getters and simple view functions score low (negative).
    The score is used ONLY for ordering; no function is ever dropped.
    """
    score = 0
    text = (body_text or "").strip()

    # Name-level heuristics (cheap, applied first)
    if fn_name and _NAME_HIGH.search(fn_name):
        score += 12
    if fn_name and _NAME_LOW.match(fn_name):
        score -= 6

    if not text:
        # No body available - treat as unknown, neutral score
        return score

    # Body-level patterns
    text_lower = text.lower()
    for pts, pat in _HIGH_PATTERNS:
        if _re.search(pat, text, _re.IGNORECASE):
            score += pts

    # Low patterns only reduce if no strong high signal
    if score < 8:
        for pts, pat in _LOW_PATTERNS:
            if _re.search(pat, text, _re.MULTILINE | _re.IGNORECASE):
                score += pts

    # Single-line bodies (trivial getters) get an additional penalty
    non_empty_lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("//")]
    if len(non_empty_lines) <= 2:
        score -= 4

    return score

# Language-agnostic body extractor (sibling tool) - loaded by path (hyphenated filename).
import importlib.util as _ilu
_FSE = None
def _fse():
    global _FSE
    if _FSE is None:
        _p = Path(__file__).resolve().parent / "function-source-extractor.py"
        _s = _ilu.spec_from_file_location("function_source_extractor", _p)
        _FSE = _ilu.module_from_spec(_s)
        _s.loader.exec_module(_FSE)
    return _FSE

# In-scope path roots are validated against the manifest itself (the manifest is
# already scope-filtered), but we re-assert the OOS denylist as defense in depth so
# a future manifest regression cannot leak OOS units into a hunt wave.
_OOS_SUBSTR = (
    "/kona/", "/op-alloy/", "/rollup-boost/", "/op-rbuilder/", "/op-revm/",
    "/alloy-op-evm/", "/alloy-op-hardforks/", "/revm-ee-tests/", "/op-reth-test-engine/",
    "/op-batcher/", "/op-chain-ops/", "/op-program/", "/op-challenger/", "/op-deployer/",
    "/docs/", "/tutorials/", "/test/", "/tests/", "_test.go", ".t.sol", "/mocks/", "/cannon/",
)
# Optional ACCELERATION-ONLY hint set: if a path matches one of these it is
# definitely in-scope, but a NON-match must NOT drop a unit - the manifest
# (inscope_units.jsonl) is already the authoritative scope-filtered set, so the
# correct test is denylist-only. (Before 2026-06-27 this was a hardcoded
# Optimism-only POSITIVE allowlist that dropped EVERY unit on any non-OP
# workspace -> 0 tasks; Morpho exposed it: 655 in-scope units -> 0 hunt tasks.)
_IN_SCOPE_HINT_SUBSTR = (
    "packages/contracts-bedrock/src/", "/op-node/", "/op-dispute-mon/", "/op-reth/",
)


def _is_in_scope(rel: str) -> bool:
    # The manifest is authoritative-in-scope; only RE-ASSERT the OOS denylist as
    # defense-in-depth against a manifest regression. Never require a positive
    # allowlist match (that is workspace-specific and wrongly drops everything).
    r = "/" + rel.strip("/")
    return not any(o in r for o in _OOS_SUBSTR)


def _program_label(ws_path: str) -> str:
    """Human program label for the prompt, derived from the workspace (never a
    hardcoded program). Prefers a 'Program:'/title line in SCOPE.md, else the
    workspace dir name."""
    name = Path(ws_path).name if ws_path else "this"
    if ws_path:
        scope = Path(ws_path) / "SCOPE.md"
        if scope.is_file():
            try:
                for ln in scope.read_text(encoding="utf-8", errors="replace").splitlines()[:12]:
                    s = ln.strip().lstrip("# ").strip()
                    if s.lower().startswith("scope -"):
                        return s[len("scope -"):].strip() or name
            except OSError:
                pass
    return name


def _impact_anchor(ws_path: str = "") -> str:
    """Impact rubric for the hunt prompt, derived VERBATIM from the workspace's
    SEVERITY.md (R52/R38) - NOT a hardcoded per-program rubric. A candidate must
    map to one of these rows or it is out-of-scope.

    GENERIC FIX (hyperlane step-3, 2026-06-21): this previously hardcoded the OP
    Stack rubric (dispute bonds / fee vaults / op-dispute-mon), so every non-
    optimism workspace hunted against the wrong severity rows.
    """
    sev_text = ""
    if ws_path:
        sev = Path(ws_path) / "SEVERITY.md"
        if sev.is_file():
            try:
                sev_text = sev.read_text(encoding="utf-8", errors="replace")
            except OSError:
                sev_text = ""
    if sev_text:
        rows = [ln.strip() for ln in sev_text.splitlines()
                if ln.strip().startswith("- ") and len(ln.strip()) > 6]
        body = "\n".join(f"  {r}" for r in rows[:60])
        if body:
            return (
                "IMPACT CLASSES (VERBATIM rows from this program's SEVERITY.md - map any candidate "
                "to one row; NO matching row => out-of-scope, drop, R52/R38):\n" + body +
                "\n  Generic DoS/griefing without fund loss is OOS (R35); privileged-only "
                "(owner/governance) paths are OOS (R24/R48). Honor the SCOPE.md explicit-OOS list."
            )
    return (
        "IMPACT CLASSES: map any candidate VERBATIM to an in-scope impact row in the workspace "
        "SEVERITY.md; if no row matches it is out-of-scope (R52/R38). Generic DoS/griefing without "
        "fund loss is OOS (R35); privileged-only (owner/governance) paths are OOS (R24/R48)."
    )


def _load_pack_intel(ws: Path, rel_file: str, fn: str) -> str:
    """HYBRID priming: if a pre_flight_pack exists for (contract, fn), return its PRE-COMPUTED
    INTEL (hunter brief + attack-class evidence + function shape + invariants) as priming text.
    NEVER returns source body - the pack has none. Empirical (optimism 2026-06-16, 3-arm
    experiment): pack-ONLY hunting produced 5/10 false-positive HIGHs by hallucinating un-seen
    guards; hybrid (pack-prime + real source read) added signal at zero R76 cost. So this intel
    is ACCELERANT ONLY and the prompt hard-requires reading the real source regardless."""
    if not fn:
        return ""  # file-level (Go/Rust) units have no per-fn pack
    contract = Path(rel_file).stem  # AnchorStateRegistry.sol -> AnchorStateRegistry
    pack = ws / ".auditooor" / "pre_flight_packs" / f"pre_flight_pack_{contract}_{fn}.json"
    if not pack.is_file():
        return ""
    try:
        d = json.loads(pack.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError, OSError):
        return ""
    def _clip(v, n):
        s = v if isinstance(v, str) else json.dumps(v)
        return s[:n]
    parts = []
    for key, cap in (("per_function_hunter_brief", 3000), ("attack_class_evidence", 1500),
                     ("function_shape", 800), ("invariants_touched", 1200), ("dead_ends_scoped", 600),
                     ("cross_language_analogues", 1200)):
        if d.get(key):
            parts.append(f"  [{key}]: {_clip(d[key], cap)}")
    if not parts:
        return ""
    return (
        "PRE-COMPUTED INTEL (PRIMING ONLY - an accelerant, NOT evidence):\n" + "\n".join(parts) +
        "\n  !! This intel may be STALE/WRONG/INCOMPLETE and contains NO function body. You MUST "
        "still READ THE REAL SOURCE (STEP 1) and cite only lines you actually read. NEVER cite this "
        "intel as code (pack-only hunting hallucinated 5/10 false-positive HIGHs in testing). Use it "
        "only to prime which attack angles to check against the real source.\n\n"
    )


def _embedded_body_block(rel_file: str, fn: str, line: int, body: str, dep_count: int = 0) -> str:
    """Inline the SELF-CONTAINED extract: the REAL target body PLUS its referenced same-file
    guards/modifiers/callees (mechanically resolved). Empirical (optimism 2026-06-16): bare-body
    is R76-clean but over-flags 7/10 (missing guards); embedding the same-file guards/callees gives
    the agent the context inline -> no whole-file Read needed (the ~10-15x token win) AND no
    over-flag (it sees the guards). Read the file ONLY for CROSS-FILE/imported callees if a finding
    truly hinges on one."""
    dep_note = (
        f"The target body PLUS its {dep_count} referenced same-file guard/callee/modifier "
        "definition(s) are included below (SELF-CONTAINED). You should NOT need to read the file; "
        "Read it ONLY for a CROSS-FILE/imported callee a finding genuinely hinges on."
        if dep_count else
        "The target body is below. It references no resolvable same-file callees; if a finding hinges "
        "on an external/inherited symbol, Read the file for just that symbol (not the whole file)."
    )
    return (
        f"TARGET FUNCTION + CONTEXT (mechanically extracted VERBATIM from {rel_file}:{line} - REAL "
        f"code, your primary input; cite from it):\n```\n{body}\n```\n  !! {dep_note}\n\n"
    )


def _build_prompt(ws_path: str, rel_file: str, fn: str, lang: str, pack_intel: str = "",
                  body_block: str = "") -> str:
    target = (
        f"the function `{fn}` in {rel_file}" if fn
        else f"EVERY exported/public function in {rel_file} (file-level unit)"
    )
    step1 = (
        ("STEP 1 - The target body is provided inline below (verbatim). Use it as your primary code; "
         f"Read {ws_path}/{rel_file} ONLY for the specific referenced guards/callees you need to judge "
         "severity. Do NOT reason about code you have not seen.\n\n")
        if body_block else
        ("STEP 1 - READ THE REAL SOURCE YOURSELF: use Read/Bash(grep) to open "
         f"{ws_path}/{rel_file} and locate the target. Do NOT reason about code you have not read.\n\n")
    )
    return (
        f"You are a security auditor for the {_program_label(ws_path)} bug bounty "
        f"(workspace {ws_path}). Hunt {target}.\n\n"
        f"{step1}"
        f"{body_block}"
        f"{pack_intel}"
        f"{_impact_anchor(ws_path)}\n\n"
        "KNOWN-ISSUES DEDUP: dedup against prior_audits/ (in-tree published reports), in-tree "
        "comments/known-issue markers, known_dead_ends, AND the structured known-issues registry "
        ".auditooor/known_issues.json. Any HIGH+ candidate MUST carry the "
        "caveat 'operator confirms novelty before filing'."
        f"{_known_issue_dedup_note(ws_path)}\n\n"
        "Output STRICT JSON only (no prose around it), keys (all required):\n"
        "  applies_to_target: yes|no|maybe\n  confidence: low|medium|high\n"
        "  candidate_finding: one-sentence brief anchored to the target\n"
        "  file_line: 'path:line' - a REAL line you read (R76 HARD RULE: must exist; if you "
        "cannot read+anchor it, set applies_to_target='no', notes='unable-to-anchor')\n"
        "  code_excerpt: 1-3 lines VERBATIM from the source you read\n"
        "  severity_estimate: LOW|MEDIUM|HIGH|CRITICAL|NA\n"
        "  rubric_row_cited: verbatim in-scope impact row, or 'NA'\n"
        "  dupe_check: cross-ref prior_audits/ + in-tree known-issue; 'novel' if none\n"
        "  falsification_attempt: the specific source check that would disprove this\n"
        "  notes: string\n\n"
        "Most functions on this heavily-audited codebase are clean / source-cited-ruled-out - "
        "that is the expected honest result. applies_to_target='no' with a one-line source-cited "
        "reason IS genuine coverage. Only raise a candidate you can defend on the real source.\n\n"
        "MANDATORY SIDECAR EMIT (G14 + crediting): after deciding, you MUST record the verdict in "
        "the CREDITABLE structured shape - pass the fields as flags, NOT as one prose string, or "
        "function-coverage classifies it hollow/uncredited:\n"
        "  python3 tools/workflow-drill-sidecar-emit.py --workspace <ws> --task-id <this task_id> \\\n"
        "    --applies-to-target <yes|no|maybe> --confidence <low|medium|high> \\\n"
        "    --file-line '<the REAL path:line you read>' --code-excerpt '<verbatim 1-3 lines>' \\\n"
        "    --verdict <CONFIRMED|KILL> --severity <LOW|MEDIUM|HIGH|CRITICAL|NA> --reasoning '<one line>'\n"
        "The --file-line MUST be a real source line you read (R76). A KILL/clean rule-out with a real "
        "--file-line is genuine coverage and credits durably; a bare prose --verdict with no --file-line "
        "does NOT credit. Verify the sidecar wrote before returning."
    )


def _line_from_unit(u: dict) -> int:
    """Best-effort 1-based decl line from an inscope_units row's file_line ('path:line')."""
    fl = str(u.get("file_line") or "")
    if ":" in fl:
        tail = fl.rsplit(":", 1)[1]
        if tail.isdigit():
            return int(tail)
    return 0


# ---------------------------------------------------------------------------
# A2 - COVERAGE-PLANE DRAIN (default-OFF env AUDITOOOR_PLANE_DRAIN=1)
#
# The materialized .auditooor/coverage_plane.jsonl carries one row per
# (unit x impact-frame) cell with a status in {not-enumerated, covered,
# out-of-scope-fcc-filtered}. Before this, the two hunt builders expanded
# per-impact-frame ONLY from the STATIC _MECHANISM_LIBRARY_SEED / PER_IMPACT_FRAMES
# env and NEVER read the plane, so a materialized "776 not-enumerated cells"
# residual (NUVA) was drained by nothing. When AUDITOOOR_PLANE_DRAIN=1 AND the
# plane file is present, we emit ONE hunt task per not-enumerated cell,
# provenance-tagged source_of_truth='coverage_plane'. Absent/opt-out ->
# byte-identical to the legacy seed/PER_IMPACT_FRAMES expansion (this function is
# never called and no output changes).
# ---------------------------------------------------------------------------
_PLANE_DRAIN_STATUS = "not-enumerated"


def _plane_drain_enabled() -> bool:
    """A2 gate: env AUDITOOOR_PLANE_DRAIN=1 (default OFF)."""
    return os.environ.get("AUDITOOOR_PLANE_DRAIN", "").strip().lower() in ("1", "true", "yes", "on")


def _plane_cell_file_fn_line(cell: dict) -> tuple[str, str, int]:
    """Extract (rel_file, fn, decl_line) from a coverage_plane.jsonl row. Prefers
    the explicit `file`/`function` columns; recovers the decl line from the tail of
    the `unit` token ('<file>::<fn>::<file>:<line>') when present. Returns line 0
    when no line is derivable (the builder body-extractor tolerates 0)."""
    rel = str(cell.get("file") or cell.get("asset") or "").strip()
    fn = str(cell.get("function") or "").strip()
    line = 0
    unit = str(cell.get("unit") or "")
    if ":" in unit:
        tail = unit.rsplit(":", 1)[1]
        if tail.isdigit():
            line = int(tail)
    return rel, fn, line


def build_plane_drain_tasks(ws: Path, lang_filter: str | None, limit: int | None,
                            embed_source: bool = True):
    """A2: emit one hunt task per NOT-ENUMERATED coverage_plane.jsonl cell.

    Each task carries task['impact']=<frame> and source_of_truth='coverage_plane'
    so a dispatched hunt drains the exact cells the completeness plane flagged as
    never-enumerated. Returns (None, err) when the plane file is absent so the
    caller can fall back to the legacy per-function/seed expansion (env-off parity).
    """
    plane = ws / ".auditooor" / "coverage_plane.jsonl"
    if not plane.is_file():
        return None, f"no coverage_plane: {plane}"
    ws_path = str(ws)
    tasks: list[dict] = []
    seen: set[str] = set()
    for line in plane.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            cell = json.loads(line)
        except ValueError:
            continue
        if str(cell.get("status") or "").strip() != _PLANE_DRAIN_STATUS:
            continue
        rel, fn, decl_line = _plane_cell_file_fn_line(cell)
        if not rel or not _is_in_scope(rel):
            continue
        lang = str(cell.get("lang") or "").lower()
        # normalize the plane's long lang token to the builder's short vocab where possible
        _short = {"solidity": "solidity", "sol": "solidity", "go": "go", "rust": "rust",
                  "rs": "rust", "move": "move"}.get(lang, lang)
        if lang_filter and _short != lang_filter:
            continue
        frame = str(cell.get("frame") or "").strip()
        key = f"{rel}::{fn}::{frame}"
        if key in seen:
            continue
        seen.add(key)
        body_block = ""
        if embed_source and decl_line > 0:
            try:
                body, _end, _deps = _fse().extract_self_contained(ws, rel, decl_line)
                if body.strip():
                    body_block = _embedded_body_block(rel, fn, decl_line, body, _deps)
            except Exception:  # pragma: no cover - body extraction is best-effort
                body_block = ""
        _body_text = ""
        if body_block:
            _m = _re.search(r"```\n(.*?)```", body_block, _re.DOTALL)
            _body_text = _m.group(1) if _m else ""
        base_prompt = _build_prompt(ws_path, rel, fn, _short, "", body_block)
        prompt = (_per_impact_prompt_prefix(frame) + base_prompt) if frame else base_prompt
        t = {
            "task_id": "",  # filled by _stable_task_id below (folds impact frame in)
            "task_type": TASK_TYPE,
            "workspace": ws.name,
            "workspace_path": ws_path,
            "source_question_id": "coverage-plane-not-enumerated",
            "source_of_truth": "coverage_plane",
            "impact": frame,
            "function_anchor": {"file": f"{ws_path}/{rel}", "fn": fn,
                                "start_line": decl_line, "end_line": 0},
            "rank": -1, "score": 0, "priority": _score_body(fn, _body_text),
            "pack_primed": False,
            "body_embedded": bool(body_block),
            "prompt": prompt,
            "max_tokens": 1500,
        }
        tasks.append(t)
    tasks.sort(key=lambda t: -t["priority"])
    for t in tasks:
        t["task_id"] = _stable_task_id(t)
    if limit:
        tasks = tasks[:limit]
    return tasks, None


# ---------------------------------------------------------------------------
# B2 - FUZZ-TARGET PRIORITY BOOST (default-OFF env AUDITOOOR_FUZZ_BOOST=1)
#
# .auditooor/fuzz_targets.jsonl is the value-moving enumeration that today feeds
# ONLY the fuzz-completeness gate; the hunt builder never read it. When
# AUDITOOOR_FUZZ_BOOST=1 and the file exists, a hunt task whose function joins a
# fuzz target (needs_campaign) gets an ADVISORY priority boost so value-moving
# functions sort earlier under --limit. Env-off -> the boost set is never built
# and ordering is byte-identical.
#
# JOIN: the builder has no _fn_cluster_key helper (the task brief named one that
# does not exist); we join on the fuzz row's `functions[]` (and the fn-cluster
# token) normalized to (basename::fn) AND a fn-name-only fallback, mirroring the
# builder's existing basename::fn convention (units_filter / covered_fn_keys).
# ---------------------------------------------------------------------------
_FUZZ_BOOST_POINTS = 15


def _fuzz_boost_enabled() -> bool:
    """B2 gate: env AUDITOOOR_FUZZ_BOOST=1 (default OFF)."""
    return os.environ.get("AUDITOOOR_FUZZ_BOOST", "").strip().lower() in ("1", "true", "yes", "on")


def _load_fuzz_boost_keys(ws: Path) -> tuple[set[str], set[str]]:
    """Return (basename_fn_keys, fn_only_keys) for fuzz targets that still
    need_campaign. Keys are lowercased. Empty sets when the file is absent so the
    caller applies no boost (env-on-but-no-file is byte-identical to off)."""
    fz = ws / ".auditooor" / "fuzz_targets.jsonl"
    if not fz.is_file():
        return set(), set()
    import os as _os
    bn_keys: set[str] = set()
    fn_keys: set[str] = set()
    for line in fz.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not isinstance(r, dict):
            continue
        # advisory boost only for targets still flagged as needing a campaign;
        # a finished/N-A target should not re-prioritize a hunt.
        if r.get("needs_campaign") is False:
            continue
        base = _os.path.basename(str(r.get("asset_path") or r.get("asset_basename") or "")).lower()
        fns = r.get("functions") if isinstance(r.get("functions"), list) else []
        # include the fn_cluster token as a fallback fn key
        cluster = str(r.get("fn_cluster") or "").strip().lower()
        if cluster:
            fn_keys.add(cluster)
        for fn in fns:
            f = str(fn or "").strip()
            if not f:
                continue
            fn_keys.add(f.lower())
            if base:
                bn_keys.add(f"{base}::{f.lower()}")
    return bn_keys, fn_keys


def _apply_fuzz_boost(ws: Path, tasks: list[dict]) -> None:
    """B2: in-place advisory priority boost for hunt tasks whose function joins a
    campaign-pending fuzz target. No-op when the env is OFF or the file is absent."""
    if not _fuzz_boost_enabled():
        return
    bn_keys, fn_keys = _load_fuzz_boost_keys(ws)
    if not bn_keys and not fn_keys:
        return
    import os as _os
    for t in tasks:
        fa = t.get("function_anchor") or {}
        fn = str(fa.get("fn") or "").strip().lower()
        if not fn:
            continue
        base = _os.path.basename(str(fa.get("file") or "")).lower()
        if f"{base}::{fn}" in bn_keys or fn in fn_keys:
            t["priority"] = int(t.get("priority") or 0) + _FUZZ_BOOST_POINTS
            t["fuzz_boosted"] = True


def build_tasks(ws: Path, lang_filter: str | None, only_uncovered: bool, limit: int | None,
                with_pack_intel: bool = False, embed_source: bool = False,
                per_impact_frames: bool = False):
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None, f"no inscope manifest: {manifest}"
    ws_path = str(ws)
    tasks = []
    seen = set()
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            u = json.loads(line)
        except ValueError:
            continue
        rel = str(u.get("file") or "").strip()
        if not rel or not _is_in_scope(rel):
            continue
        lang = str(u.get("lang") or "").lower()
        if lang_filter and lang != lang_filter:
            continue
        if only_uncovered and u.get("prior_covered") is True:
            continue
        fn = str(u.get("function") or "").strip()
        key = f"{rel}::{fn}"
        if key in seen:
            continue
        seen.add(key)
        pack_intel = _load_pack_intel(ws, rel, fn) if with_pack_intel else ""
        body_block = ""
        decl_line = _line_from_unit(u)
        if embed_source and decl_line > 0:
            body, _end, _deps = _fse().extract_self_contained(ws, rel, decl_line)
            if body.strip():
                body_block = _embedded_body_block(rel, fn, decl_line, body, _deps)
        # Compute priority from embedded body (if present) or fn name alone.
        # Body text is extracted from body_block between the ``` fences when available.
        _body_text = ""
        if body_block:
            _m = _re.search(r"```\n(.*?)```", body_block, _re.DOTALL)
            _body_text = _m.group(1) if _m else ""
        _priority = _score_body(fn, _body_text)
        _base = {
            "task_id": f"inscope_hunt_{len(tasks):05d}",
            "task_type": TASK_TYPE,
            "workspace": ws.name,
            "workspace_path": ws_path,
            "source_question_id": "inscope-units-authoritative",
            "function_anchor": {"file": f"{ws_path}/{rel}", "fn": fn, "start_line": decl_line, "end_line": 0},
            "rank": -1, "score": 0, "priority": _priority,
            "pack_primed": bool(pack_intel),
            "body_embedded": bool(body_block),
            "prompt": _build_prompt(ws_path, rel, fn, lang, pack_intel, body_block),
            "max_tokens": 1500,
        }
        # (unit x IMPACT-FRAME) expansion: OFF by default (byte-identical to legacy).
        # ON -> one task per in-scope impact frame for this unit's language.
        if per_impact_frames:
            tasks.extend(_expand_task_per_impact(_base, lang))
        else:
            tasks.append(_base)
    # DEPRIORITIZE-ONLY stable sort: value-moving fns FIRST, trivial getters LAST.
    # Applied BEFORE the --limit slice so the kept K tasks are always the top-ranked K.
    # NEVER drops a function - all tasks present without --limit; order only changes.
    _apply_fuzz_boost(ws, tasks)  # B2: advisory value-moving priority boost (env-gated, default OFF)
    tasks.sort(key=lambda t: -t["priority"])
    # Content-stable task_ids (NOT sequential): a sequential id restarts at 00000
    # each wave and clobbers prior waves' sidecars in the shared MIMO dir. See
    # _stable_task_id docstring (cross-wave-overwrite churn fix).
    for t in tasks:
        t["task_id"] = _stable_task_id(t)
    if limit:
        tasks = tasks[:limit]
    return tasks, None


_LANG_ALIAS = {"solidity": "sol", "sol": "sol", "go": "go", "rust": "rs", "rs": "rs"}


def _load_units_filter(units_file: str | None) -> set[str] | None:
    """Load an explicit unit allow-list (one `file::function` or `path::fn` per line,
    e.g. the hunt-coverage gate's queued_not_scanned list) into a set of normalized
    `basename::function` keys. Returns None when no file is given (no filtering).
    Matching on basename::fn is robust to the gate emitting either a bare basename
    (`OmniBridge.sol::finTransfer`) or a full path (`src/mpc/.../lib.rs::foo`)."""
    if not units_file:
        return None
    p = Path(units_file)
    if not p.is_file():
        return None
    keys: set[str] = set()
    import os as _os
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or "::" not in line:
            continue
        filepart, fn = line.split("::", 1)
        fn = fn.split("(", 1)[0].strip().lower()
        base = _os.path.basename(filepart.strip()).lower()
        if base and fn:
            keys.add(f"{base}::{fn}")
    return keys


def build_tasks_per_function(ws: Path, lang_filter: str | None, only_uncovered: bool,
                             limit: int | None, with_pack_intel: bool = False,
                             embed_source: bool = True,
                             units_filter: set[str] | None = None,
                             per_impact_frames: bool = False):
    """UNIVERSAL per-function worklist for ALL languages (sol/go/rust), driven off the
    scope-correct per-function list in .auditooor/function_coverage_completeness.json (already
    in-scope-filtered). Unlike build_tasks (inscope_units, file-level for Go/Rust) this gives a
    task per FUNCTION in every language, each with the mechanically-extracted body embedded +
    corpus-pack priming. only_uncovered keeps classification in {untouched, hollow}."""
    cov = ws / ".auditooor" / "function_coverage_completeness.json"
    if not cov.is_file():
        return None, ("no per-function list: " + str(cov) +
                      " (run: python3 tools/function-coverage-completeness.py --workspace <ws> --write)")
    try:
        fns = json.loads(cov.read_text(encoding="utf-8", errors="replace")).get("functions") or []
    except (json.JSONDecodeError, ValueError):
        return None, f"unparseable function list: {cov}"
    want = _LANG_ALIAS.get((lang_filter or "").lower()) if lang_filter else None
    ws_path = str(ws)
    tasks = []
    for f in fns:
        rel = str(f.get("file") or "").strip()
        fn = str(f.get("name") or "").strip()
        ln = int(f.get("line") or 0)
        lang = str(f.get("lang") or "").lower()
        if not rel or not fn or ln <= 0:
            continue
        if want and lang != want:
            continue
        if only_uncovered and f.get("classification") not in ("untouched", "hollow"):
            continue
        if units_filter is not None:
            import os as _os
            if f"{_os.path.basename(rel).lower()}::{fn.lower()}" not in units_filter:
                continue
        pack_intel = _load_pack_intel(ws, rel, fn) if with_pack_intel else ""
        body_block = ""
        if embed_source:
            body, _end, _deps = _fse().extract_self_contained(ws, rel, ln)
            if body.strip():
                body_block = _embedded_body_block(rel, fn, ln, body, _deps)
        # Compute priority from embedded body (if present) or fn name alone.
        _body_text = ""
        if body_block:
            _m = _re.search(r"```\n(.*?)```", body_block, _re.DOTALL)
            _body_text = _m.group(1) if _m else ""
        _priority = _score_body(fn, _body_text)
        _base = {
            "task_id": f"inscope_hunt_{len(tasks):05d}",
            "task_type": TASK_TYPE,
            "workspace": ws.name,
            "workspace_path": ws_path,
            "source_question_id": "per-function-coverage-authoritative",
            "function_anchor": {"file": f"{ws_path}/{rel}", "fn": fn, "start_line": ln, "end_line": 0},
            "rank": -1, "score": 0, "lang": lang,
            "classification": f.get("classification"),
            "priority": _priority,
            "pack_primed": bool(pack_intel),
            "body_embedded": bool(body_block),
            "prompt": _build_prompt(ws_path, rel, fn, lang, pack_intel, body_block),
            "max_tokens": 1500,
        }
        # (unit x IMPACT-FRAME) expansion: OFF by default (byte-identical to legacy).
        # ON -> one task per in-scope impact frame for this unit's language.
        if per_impact_frames:
            tasks.extend(_expand_task_per_impact(_base, lang))
        else:
            tasks.append(_base)
    # DEPRIORITIZE-ONLY stable sort: value-moving fns FIRST, trivial getters LAST.
    # Applied BEFORE the --limit slice so the kept K tasks are always the top-ranked K.
    # NEVER drops a function - all tasks present without --limit; order only changes.
    _apply_fuzz_boost(ws, tasks)  # B2: advisory value-moving priority boost (env-gated, default OFF)
    tasks.sort(key=lambda t: -t["priority"])
    # Content-stable task_ids (NOT sequential): a sequential id restarts at 00000
    # each wave and clobbers prior waves' sidecars in the shared MIMO dir. See
    # _stable_task_id docstring (cross-wave-overwrite churn fix).
    for t in tasks:
        t["task_id"] = _stable_task_id(t)
    if limit:
        tasks = tasks[:limit]
    return tasks, None


PATH_TASK_TYPE = "per_path_dataflow_hunt_v1"


def _path_stable_task_id(p: dict) -> str:
    """Content-stable task id for a dataflow path task (source@line -> sink@line)."""
    src = p.get("source") or {}
    snk = p.get("sink") or {}
    key = (f"{Path(str(src.get('file') or '')).name}:{src.get('line') or 0}"
           f"->{Path(str(snk.get('file') or '')).name}:{snk.get('line') or 0}"
           f":{p.get('path_id', '')}")
    return f"inscope_path_{hashlib.sha1(key.encode('utf-8')).hexdigest()[:12]}"


def _build_path_prompt(ws_path: str, p: dict) -> str:
    """Hunt prompt framed around a tainted SOURCE -> value-moving SINK def-use flow,
    its inter-procedural hops, and its guard status. The path is the UNIT - the agent
    must judge whether the flow can be driven adversarially end-to-end."""
    src = p.get("source") or {}
    snk = p.get("sink") or {}
    src_file = str(src.get("file") or "")
    snk_file = str(snk.get("file") or "")
    src_line = src.get("line") or 0
    snk_line = snk.get("line") or 0
    hops = p.get("hops") or []
    hop_lines = []
    for h in hops:
        hop_lines.append(
            f"    - {h.get('fn') or '?'} via {h.get('via') or '?'} "
            f"({h.get('from_var') or '?'} -> {h.get('to_var') or '?'}) "
            f"@ {h.get('file') or '?'}:{h.get('line') or 0}"
            + ("  [GUARDED]" if h.get("guarded") else "")
        )
    hop_block = "\n".join(hop_lines) if hop_lines else "    - (no inter-procedural hops; intra-function flow)"
    guard_note = (
        "UNGUARDED: no require/assert/compare dominates this slice per the engine."
        if p.get("unguarded") else
        "A guard was found on the slice - VERIFY it actually constrains the tainted value end-to-end."
    )
    conf = p.get("confidence") or "?"
    conf_note = (
        "engine confidence is HEURISTIC/advisory (name-substring fallback) - treat as a lead, prove on source."
        if conf in ("heuristic",) or p.get("degraded") else
        f"engine confidence={conf} (IR-backed for semantic-ssa)."
    )
    return (
        f"You are a security auditor for the {_program_label(ws_path)} bug bounty "
        f"(workspace {ws_path}). Hunt this DATA-FLOW PATH (the unit is the flow, not one function).\n\n"
        f"FLOW: tainted SOURCE `{src.get('var') or '?'}` ({src.get('kind') or '?'}) in "
        f"`{src.get('fn') or '?'}` @ {src_file}:{src_line}\n"
        f"  -> value-moving SINK `{snk.get('callee') or '?'}` (arg_pos {snk.get('arg_pos')}) in "
        f"`{snk.get('fn') or '?'}` @ {snk_file}:{snk_line}\n"
        f"  call_depth={p.get('call_depth')} hop(s):\n{hop_block}\n"
        f"  GUARD STATUS: {guard_note}\n  ENGINE: {conf_note}\n\n"
        "STEP 1 - READ THE REAL SOURCE YOURSELF: open the SOURCE function, every hop function, and "
        "the SINK function above; trace whether attacker-controlled input at the SOURCE reaches the "
        "SINK with no effective guard. Do NOT reason about code you have not read (R76).\n\n"
        f"{_impact_anchor(ws_path)}\n\n"
        "KNOWN-ISSUES DEDUP: dedup against prior_audits/, in-tree known-issue markers, known_dead_ends, "
        "AND .auditooor/known_issues.json. Any HIGH+ candidate MUST carry 'operator confirms novelty "
        f"before filing'.{_known_issue_dedup_note(ws_path)}\n\n"
        "Output STRICT JSON only, keys: applies_to_target (yes|no|maybe), confidence (low|medium|high), "
        "candidate_finding (one sentence anchored to the flow), file_line ('path:line' you actually read - "
        "R76), code_excerpt (1-3 verbatim lines), severity_estimate (LOW|MEDIUM|HIGH|CRITICAL|NA), "
        "rubric_row_cited (verbatim in-scope row or 'NA'), dupe_check, falsification_attempt (the source "
        "check that disproves the flow being exploitable - e.g. a guard you confirm dominates), notes.\n\n"
        "An unguarded multi-hop flow is a LEAD, not a finding - most resolve to a guard the engine missed "
        "(cross-file/inherited) or a non-attacker-controlled source. A source-cited rule-out IS genuine "
        "coverage. Emit the verdict via tools/workflow-drill-sidecar-emit.py with the REAL --file-line."
    )


def build_tasks_from_units_explicit(ws: Path, units_file: str, limit: int | None = None):
    """Emit a body-embedded hunt task for EVERY `file::function` in an explicit unit
    list (the hunt-coverage gate's queued_not_scanned), resolving each unit's source
    file + declaration line directly from source ON-DEMAND. Unlike the completeness-
    filtered path, this reaches units ABSENT from function_coverage_completeness.json -
    the under-extracted Cairo / internal / missed entrypoints - so the queue-driven
    coverage hunt can credit the WHOLE queue. near-intents 2026-06-26."""
    import os as _os
    p = Path(units_file)
    if not p.is_file():
        return None, f"units file not found: {units_file}"
    ws_path = str(ws)
    src_root = ws / "src"
    skip = ("/node_modules/", "/.cargo/", "/vendor/", "/build/", "/target/", "/.git/")
    _resolved: dict = {}

    def _resolve(fp: str):
        if fp in _resolved:
            return _resolved[fp]
        cand = ws / fp
        if not cand.is_file() and src_root.is_dir():
            base = fp.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            for m in src_root.rglob(base):
                sp = str(m).replace("\\", "/")
                if m.is_file() and not any(s in sp for s in skip):
                    cand = m
                    break
        _resolved[fp] = cand if cand.is_file() else None
        return _resolved[fp]

    _ext_lang = {".sol": "sol", ".rs": "rs", ".go": "go", ".cairo": "cairo", ".move": "move"}
    _decl_rx = {".sol": r"\bfunction\s+([A-Za-z_]\w*)", ".rs": r"\bfn\s+([A-Za-z_]\w*)",
                ".cairo": r"\bfn\s+([A-Za-z_]\w*)", ".go": r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)",
                ".move": r"\bfun\s+([A-Za-z_]\w*)"}

    def _first_decl(src_path) -> tuple:
        """(fn_name, 1-based line) of the first function decl in a file - used to turn a
        FILE-ONLY queue unit (no ::, a whole-file obligation) into a concrete hunt task;
        hunting any fn in the file writes the file-level token that credits the obligation."""
        rx = _decl_rx.get(src_path.suffix.lower())
        if not rx:
            return "", 0
        try:
            for i, l in enumerate(src_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                m = _re.search(rx, l)
                if m:
                    return m.group(1), i
        except OSError:
            pass
        return "", 0

    tasks = []
    seen = set()
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        if "::" in line:
            fp, fn = line.split("::", 1)
            fn = fn.split("(", 1)[0].strip()
        else:
            fp, fn = line, ""   # FILE-ONLY whole-file obligation
        src = _resolve(fp.strip())
        if not src:
            continue
        if not fn:
            fn, _fl = _first_decl(src)
            if not fn:
                continue
        try:
            rel = str(src.relative_to(ws))
        except ValueError:
            rel = str(src)
        if (rel, fn) in seen:
            continue
        seen.add((rel, fn))
        ext = src.suffix.lower()
        lang = _ext_lang.get(ext, ext.lstrip("."))
        decl_re = (rf"\bfunction\s+{_re.escape(fn)}\b" if ext == ".sol"
                   else rf"\bfn\s+{_re.escape(fn)}\b")
        text = src.read_text(encoding="utf-8", errors="replace")
        ln = 0
        for i, l in enumerate(text.splitlines(), 1):
            if _re.search(decl_re, l):
                ln = i
                break
        if ln <= 0:
            continue
        body, _end, _deps = _fse().extract_self_contained(ws, rel, ln)
        body_block = _embedded_body_block(rel, fn, ln, body, _deps) if body.strip() else ""
        tasks.append({
            "task_id": f"inscope_hunt_{len(tasks):05d}",
            "task_type": TASK_TYPE,
            "workspace": ws.name,
            "workspace_path": ws_path,
            "source_question_id": "queue-driven-coverage",
            "function_anchor": {"file": f"{ws_path}/{rel}", "fn": fn, "start_line": ln, "end_line": 0},
            "rank": -1, "score": 0, "lang": lang,
            "classification": "queued",
            "priority": _score_body(fn, body if body else ""),
            "pack_primed": False,
            "body_embedded": bool(body_block),
            "prompt": _build_prompt(ws_path, rel, fn, lang, "", body_block),
            "max_tokens": 1500,
        })
        if limit and len(tasks) >= limit:
            break
    return tasks, None


def build_path_tasks(ws: Path, lang_filter: str | None, only_uncovered: bool,
                     limit: int | None):
    """PATH-MODE worklist: one task per UNGUARDED multi-hop / storage-mediated def-use
    path from .auditooor/dataflow_paths.jsonl. Falls back to the per-function builder for
    units with NO path so coverage is never reduced. ADDITIVE / opt-in (--unit path).

    A path is emitted iff: not degraded, unguarded, and either call_depth>=1 (multi-hop)
    or any storage-via hop (storage-mediated cross-fn def-use). Guarded / degrade / single
    intra-fn slices are left to per-function coverage."""
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    if not df.is_file():
        # No dataflow slice present -> behave exactly as per-function default.
        return build_tasks_per_function(ws, lang_filter, only_uncovered, limit,
                                        with_pack_intel=False, embed_source=True)
    ws_path = str(ws)
    want = (lang_filter or "").lower() or None
    tasks = []
    seen = set()
    covered_fn_keys: set[str] = set()
    for line in df.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            p = json.loads(line)
        except ValueError:
            continue
        if p.get("degraded"):
            continue
        if want and str(p.get("language") or "").lower() != want:
            continue
        if not p.get("unguarded"):
            continue
        has_storage_hop = any((h.get("via") == "storage") for h in (p.get("hops") or []))
        if int(p.get("call_depth") or 0) < 1 and not has_storage_hop:
            continue
        src = p.get("source") or {}
        snk = p.get("sink") or {}
        key = (f"{src.get('file')}:{src.get('line')}->{snk.get('file')}:{snk.get('line')}")
        if key in seen:
            continue
        seen.add(key)
        # Priority: more hops + storage-mediation rank higher.
        prio = 10 + 2 * int(p.get("call_depth") or 0) + (4 if has_storage_hop else 0)
        tasks.append({
            "task_id": _path_stable_task_id(p),
            "task_type": PATH_TASK_TYPE,
            "workspace": ws.name,
            "workspace_path": ws_path,
            "source_question_id": "dataflow-paths-authoritative",
            "path_id": p.get("path_id"),
            "function_anchor": {
                "file": str(src.get("file") or ""),
                "fn": str(src.get("fn") or ""),
                "start_line": int(src.get("line") or 0),
                "end_line": int(snk.get("line") or 0),
            },
            "sink_anchor": {"file": str(snk.get("file") or ""), "fn": str(snk.get("fn") or ""),
                            "line": int(snk.get("line") or 0)},
            "call_depth": p.get("call_depth"),
            "confidence": p.get("confidence"),
            "rank": -1, "score": 0, "priority": prio,
            "pack_primed": False,
            "body_embedded": False,
            "prompt": _build_path_prompt(ws_path, p),
            "max_tokens": 1500,
        })
        for u in (p.get("source") or {}, p.get("sink") or {}):
            f = u.get("file")
            fn = u.get("fn")
            if f and fn:
                covered_fn_keys.add(f"{f}::{fn}")
    tasks.sort(key=lambda t: -t["priority"])
    # FALLBACK: per-function tasks for units that did NOT participate in any emitted
    # path, so path mode never covers FEWER units than function mode.
    fn_tasks, fn_err = build_tasks_per_function(ws, lang_filter, only_uncovered, None,
                                                with_pack_intel=False, embed_source=True)
    if fn_tasks:
        for t in fn_tasks:
            fa = t.get("function_anchor") or {}
            # function_anchor.file is absolute (ws_path/rel); path source.file is the
            # engine's path form. Compare on basename+fn to dedup conservatively.
            fkey = f"{Path(str(fa.get('file') or '')).name}::{fa.get('fn') or ''}"
            covered_basenames = {f"{Path(k.split('::')[0]).name}::{k.split('::')[1]}"
                                 for k in covered_fn_keys if '::' in k}
            if fkey in covered_basenames:
                continue
            tasks.append(t)
    if limit:
        tasks = tasks[:limit]
    return tasks, None


# ---------------------------------------------------------------------------
# B3 - DATAFLOW PATH FOLLOW-THROUGH (default-OFF env AUDITOOOR_PATH_FOLLOWTHROUGH=1)
#
# function-coverage-completeness.py::_compute_path_coverage already surfaces
# uncovered_unguarded_gaps (an unguarded def-use path whose source/sink endpoint
# is NOT both real-attack covered) - but NOTHING seeded a hunt from those gaps
# (SSV 5290 unguarded -> 0 path sidecars). We REUSE that computation (never
# duplicate the slice-reader): read the persisted path_coverage.uncovered_unguarded_gaps
# from function_coverage_completeness.json (or recompute via _compute_path_coverage
# when the persisted block is absent), then join each gap to hunt_findings_sidecars/
# by source/sink file:line and emit a per_path_dataflow_hunt task for each gap whose
# endpoints are NOT already covered by an EXISTING sidecar (true un-followed set).
# ADDITIVE / opt-in: env-off -> this function is never called, output unchanged.
# ---------------------------------------------------------------------------
PATH_FOLLOWTHROUGH_TASK_TYPE = "per_path_dataflow_hunt"


def _path_followthrough_enabled() -> bool:
    """B3 gate: env AUDITOOOR_PATH_FOLLOWTHROUGH=1 (default OFF)."""
    return os.environ.get("AUDITOOOR_PATH_FOLLOWTHROUGH", "").strip().lower() in ("1", "true", "yes", "on")


def _fcc_module():
    """Import function-coverage-completeness.py by path (hyphenated filename) so we
    REUSE _compute_path_coverage instead of re-implementing the slice reader."""
    _p = Path(__file__).resolve().parent / "function-coverage-completeness.py"
    _s = _ilu.spec_from_file_location("function_coverage_completeness_b3", _p)
    _mod = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_mod)
    return _mod


def _sidecar_covered_file_lines(ws: Path) -> set[str]:
    """Set of 'basename:line' anchors already hunted (a hunt_findings_sidecars/ entry
    exists for that file:line). Used to EXCLUDE gaps whose endpoint is already
    followed through. Empty when the dir is absent."""
    out: set[str] = set()
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    if not d.is_dir():
        return out
    for jf in d.glob("*.json"):
        try:
            rec = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, ValueError, OSError):
            continue
        fa = rec.get("function_anchor") if isinstance(rec, dict) else None
        if isinstance(fa, dict) and fa.get("file") and fa.get("line") is not None:
            out.add(f"{Path(str(fa.get('file'))).name}:{fa.get('line')}")
        # result.file_line ('path:Lnn' or 'path:nn') is a second anchor source
        res = rec.get("result") if isinstance(rec, dict) else None
        fl = res.get("file_line") if isinstance(res, dict) else None
        if isinstance(fl, str) and ":" in fl:
            base = Path(fl.rsplit(":", 1)[0]).name
            ln = fl.rsplit(":", 1)[1].lstrip("Ll")
            if ln.isdigit():
                out.add(f"{base}:{ln}")
    return out


def _load_uncovered_unguarded_gaps(ws: Path) -> list[dict]:
    """Return path_coverage.uncovered_unguarded_gaps, preferring the persisted
    function_coverage_completeness.json; recompute via _compute_path_coverage when
    that block is absent/stale. Empty list when no dataflow slice exists."""
    cov = ws / ".auditooor" / "function_coverage_completeness.json"
    if cov.is_file():
        try:
            d = json.loads(cov.read_text(encoding="utf-8", errors="replace"))
            pc = d.get("path_coverage")
            if isinstance(pc, dict) and pc.get("uncovered_unguarded_gaps") is not None:
                return list(pc.get("uncovered_unguarded_gaps") or [])
        except (json.JSONDecodeError, ValueError, OSError):
            pass
    # Recompute path coverage from the slice by reusing the fcc computation
    # (evaluate() is the fcc public entry; it internally calls _compute_path_coverage
    # and stores the block under result['path_coverage']). REUSE - never duplicate.
    try:
        mod = _fcc_module()
        result = mod.evaluate(ws) if hasattr(mod, "evaluate") else None
        if isinstance(result, dict):
            pc = result.get("path_coverage")
            if isinstance(pc, dict):
                return list(pc.get("uncovered_unguarded_gaps") or [])
    except Exception:  # pragma: no cover - recompute is best-effort
        pass
    return []


def _gap_endpoint(gap: dict, which: str) -> tuple[str, str, int]:
    """(rel_file, fn/callee, line) for a gap endpoint ('source' | 'sink'). Prefers
    the additive machine-parseable B3 fields; falls back to parsing the prose string."""
    if which == "source":
        f = str(gap.get("source_file") or "")
        fn = str(gap.get("source_fn") or "")
        ln = gap.get("source_line")
        prose = str(gap.get("source") or "")
    else:
        f = str(gap.get("sink_file") or "")
        fn = str(gap.get("sink_callee") or "")
        ln = gap.get("sink_line")
        prose = str(gap.get("sink") or "")
    if not f and prose:
        # prose form: 'file:line (fn)'
        head = prose.split(" (", 1)[0]
        if ":" in head:
            f, tail = head.rsplit(":", 1)
            if tail.isdigit():
                ln = int(tail)
        if "(" in prose:
            fn = prose.split("(", 1)[1].rstrip(") ")
    try:
        ln_i = int(ln) if ln is not None else 0
    except (TypeError, ValueError):
        ln_i = 0
    return f, fn, ln_i


def build_path_followthrough_tasks(ws: Path, limit: int | None):
    """B3: emit one per_path_dataflow_hunt task per uncovered UNGUARDED dataflow gap
    whose endpoints are NOT already followed through (no matching hunt sidecar).
    Returns (None, err) when no gaps exist so the caller falls back to the legacy
    dispatch (env-on-but-no-slice is byte-identical to off)."""
    gaps = _load_uncovered_unguarded_gaps(ws)
    if not gaps:
        return None, "no uncovered_unguarded_gaps (no dataflow slice / all covered)"
    ws_path = str(ws)
    sidecar_lines = _sidecar_covered_file_lines(ws)
    tasks: list[dict] = []
    seen: set[str] = set()
    for gap in gaps:
        if not isinstance(gap, dict):
            continue
        # only-unguarded (the persisted block is already unguarded-filtered; re-assert)
        if gap.get("unguarded") is False:
            continue
        s_file, s_fn, s_line = _gap_endpoint(gap, "source")
        k_file, k_callee, k_line = _gap_endpoint(gap, "sink")
        if not s_file or not k_file:
            continue
        s_base = Path(s_file).name
        k_base = Path(k_file).name
        # EXCLUDE gaps already followed through: either endpoint has a hunt sidecar.
        if f"{s_base}:{s_line}" in sidecar_lines or f"{k_base}:{k_line}" in sidecar_lines:
            continue
        key = f"{s_base}:{s_line}->{k_base}:{k_line}:{gap.get('path_id') or ''}"
        if key in seen:
            continue
        seen.add(key)
        prio = 10 + 2 * int(gap.get("call_depth") or 0)
        prompt = (
            f"You are a security auditor for the {_program_label(ws_path)} bug bounty "
            f"(workspace {ws_path}). FOLLOW THROUGH this UNCOVERED UNGUARDED data-flow gap "
            "(the unit is the flow; neither endpoint has been hunted yet).\n\n"
            f"FLOW: tainted SOURCE `{s_fn or '?'}` @ {s_file}:{s_line}\n"
            f"  -> value-moving SINK `{k_callee or '?'}` @ {k_file}:{k_line}\n"
            f"  call_depth={gap.get('call_depth')} confidence={gap.get('confidence')}\n"
            "  GUARD STATUS: UNGUARDED - the engine found no require/assert/compare dominating "
            "this slice; VERIFY on the real source whether a cross-file/inherited guard the engine "
            "missed actually constrains the tainted value end-to-end.\n\n"
            "STEP 1 - READ THE REAL SOURCE YOURSELF: open the SOURCE and SINK functions above and "
            "trace whether attacker-controlled input at the SOURCE reaches the SINK with no effective "
            "guard. Do NOT reason about code you have not read (R76).\n\n"
            f"{_impact_anchor(ws_path)}\n\n"
            "KNOWN-ISSUES DEDUP: dedup against prior_audits/, in-tree known-issue markers, "
            "known_dead_ends, AND .auditooor/known_issues.json. Any HIGH+ candidate MUST carry "
            f"'operator confirms novelty before filing'.{_known_issue_dedup_note(ws_path)}\n\n"
            "Output STRICT JSON only, keys: applies_to_target (yes|no|maybe), confidence "
            "(low|medium|high), candidate_finding (one sentence anchored to the flow), file_line "
            "('path:line' you actually read - R76), code_excerpt (1-3 verbatim lines), "
            "severity_estimate (LOW|MEDIUM|HIGH|CRITICAL|NA), rubric_row_cited, dupe_check, "
            "falsification_attempt (the source check that disproves exploitability), notes.\n\n"
            "An uncovered unguarded flow is a LEAD, not a finding - most resolve to a guard the engine "
            "missed or a non-attacker-controlled source. A source-cited rule-out IS genuine coverage. "
            "Emit the verdict via tools/workflow-drill-sidecar-emit.py with the REAL --file-line."
        )
        tasks.append({
            "task_id": f"inscope_pathft_{hashlib.sha1(key.encode('utf-8')).hexdigest()[:12]}",
            "task_type": PATH_FOLLOWTHROUGH_TASK_TYPE,
            "workspace": ws.name,
            "workspace_path": ws_path,
            "source_question_id": "uncovered-unguarded-dataflow-gap",
            "source_of_truth": "path_coverage",
            "path_id": gap.get("path_id"),
            "function_anchor": {"file": s_file, "fn": s_fn, "start_line": s_line, "end_line": k_line},
            "sink_anchor": {"file": k_file, "fn": k_callee, "line": k_line},
            "call_depth": gap.get("call_depth"),
            "confidence": gap.get("confidence"),
            "rank": -1, "score": 0, "priority": prio,
            "pack_primed": False, "body_embedded": False,
            "prompt": prompt,
            "max_tokens": 1500,
        })
    tasks.sort(key=lambda t: -t["priority"])
    if limit:
        tasks = tasks[:limit]
    return tasks, None


# ---------------------------------------------------------------------------
# B5 - DETECTOR -> HUNT PROMOTER (default-OFF env AUDITOOOR_DETECTOR_PROMOTE_HUNT=1)
#
# audit-hacker-logic-bridge.py builds detector_action_graph.json (+ per-hit graphs
# under detector_action_graphs/) that are SELF-DECLARED advisory_only and never
# seeded a hunt task (grep detector_promoted_hunt in this builder = 0). When
# AUDITOOOR_DETECTOR_PROMOTE_HUNT=1 we convert each RESOLVED detector graph (a
# detector_hit with a concrete file:line) into ONE hunt task
# task_type='detector_promoted_hunt', so the resolved detector signal actually
# reaches the paid per-fn hunt (dedup on file:line + detector slug). Env-off ->
# this function is never called and output is byte-identical.
# ---------------------------------------------------------------------------
PROMOTED_TASK_TYPE = "detector_promoted_hunt"


def _detector_promote_enabled() -> bool:
    """B5 gate: env AUDITOOOR_DETECTOR_PROMOTE_HUNT=1 (default OFF)."""
    return os.environ.get("AUDITOOOR_DETECTOR_PROMOTE_HUNT", "").strip().lower() in ("1", "true", "yes", "on")


def _iter_detector_graphs(ws: Path):
    """Yield every detector_action_graph JSON object for the workspace: the legacy
    single detector_action_graph.json PLUS each per-hit graph under
    detector_action_graphs/. Malformed / missing files are skipped."""
    legacy = ws / ".auditooor" / "detector_action_graph.json"
    graph_dir = ws / ".auditooor" / "detector_action_graphs"
    candidates = []
    if legacy.is_file():
        candidates.append(legacy)
    if graph_dir.is_dir():
        candidates.extend(sorted(graph_dir.glob("*.json")))
    for jf in candidates:
        try:
            d = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, ValueError, OSError):
            continue
        if isinstance(d, dict):
            yield d


def _detector_hit_file_line(hit: dict) -> tuple[str, int]:
    """Parse ('file', line) from a detector_hit.file_path ('rel/path.rs:116')."""
    fp = str(hit.get("file_path") or "").strip()
    if not fp:
        return "", 0
    if ":" in fp:
        head, tail = fp.rsplit(":", 1)
        tail = tail.lstrip("Ll")
        if tail.isdigit():
            return head, int(tail)
    return fp, 0


def build_detector_promoted_tasks(ws: Path, lang_filter: str | None, limit: int | None):
    """B5: promote each RESOLVED detector_action_graph (detector_hit with a concrete
    file:line) into one detector_promoted_hunt task. Returns (None, err) when no
    resolved graph exists so the caller falls back to the legacy dispatch."""
    ws_path = str(ws)
    tasks: list[dict] = []
    seen: set[str] = set()
    for d in _iter_detector_graphs(ws):
        hit = d.get("detector_hit") if isinstance(d.get("detector_hit"), dict) else {}
        slug = str(hit.get("detector_slug") or "").strip()
        rel, line = _detector_hit_file_line(hit)
        if not rel or line <= 0 or not slug:
            continue  # unresolved graph (no concrete file:line) - not promotable
        if not _is_in_scope(rel):
            continue
        if lang_filter:
            ext = Path(rel).suffix.lower()
            _lang = {".sol": "solidity", ".go": "go", ".rs": "rust"}.get(ext)
            if _lang and _lang != lang_filter:
                continue
        key = f"{Path(rel).name}:{line}:{slug}"
        if key in seen:
            continue
        seen.add(key)
        severity = str(hit.get("severity") or "").strip().upper()
        snippet = str(hit.get("snippet") or "").strip()[:400]
        obligations = []
        for po in (d.get("proof_obligations") or [])[:4]:
            if isinstance(po, dict) and po.get("title"):
                obligations.append(str(po.get("title"))[:160])
        oblig_block = ""
        if obligations:
            oblig_block = ("PROOF OBLIGATIONS (from the detector action graph - confirm each on real "
                           "source):\n" + "\n".join(f"  - {o}" for o in obligations) + "\n\n")
        prompt = (
            f"You are a security auditor for the {_program_label(ws_path)} bug bounty "
            f"(workspace {ws_path}). A static detector produced a RESOLVED advisory signal; "
            "VERIFY it on real source and drive it to a terminal verdict (finding or source-cited "
            "rule-out).\n\n"
            f"DETECTOR SIGNAL: `{slug}`"
            + (f" (detector severity hint: {severity})" if severity else "")
            + f"\n  anchored at {rel}:{line}\n"
            + (f"  snippet: {snippet}\n" if snippet else "")
            + "\n"
            f"{oblig_block}"
            "STEP 1 - READ THE REAL SOURCE YOURSELF: open the anchored file:line, read the "
            "surrounding function, and judge whether the detector signal is a real exploitable "
            "issue or a fixture/vendor/false-positive match. Do NOT reason about code you have not "
            "read (R76). A detector hit is a LEAD, not a finding.\n\n"
            f"{_impact_anchor(ws_path)}\n\n"
            "KNOWN-ISSUES DEDUP: dedup against prior_audits/, in-tree known-issue markers, "
            "known_dead_ends, AND .auditooor/known_issues.json. Any HIGH+ candidate MUST carry "
            f"'operator confirms novelty before filing'.{_known_issue_dedup_note(ws_path)}\n\n"
            "Output STRICT JSON only, keys: applies_to_target (yes|no|maybe), confidence "
            "(low|medium|high), candidate_finding (one sentence anchored to the signal), file_line "
            "('path:line' you actually read - R76), code_excerpt (1-3 verbatim lines), "
            "severity_estimate (LOW|MEDIUM|HIGH|CRITICAL|NA), rubric_row_cited, dupe_check, "
            "falsification_attempt (the source check that disproves the signal), notes.\n\n"
            "Most detector hits on a heavily-audited codebase are clean / fixture / already-known - "
            "a source-cited rule-out IS genuine coverage. Emit the verdict via "
            "tools/workflow-drill-sidecar-emit.py with the REAL --file-line."
        )
        prio = _score_body(slug, snippet)
        prio += {"CRITICAL": 12, "HIGH": 8, "MEDIUM": 4}.get(severity, 0)
        tasks.append({
            "task_id": f"inscope_detprom_{hashlib.sha1(key.encode('utf-8')).hexdigest()[:12]}",
            "task_type": PROMOTED_TASK_TYPE,
            "workspace": ws.name,
            "workspace_path": ws_path,
            "source_question_id": "detector-action-graph-promoted",
            "source_of_truth": "detector_action_graph",
            "detector_slug": slug,
            "function_anchor": {"file": f"{ws_path}/{rel}", "fn": "", "start_line": line, "end_line": 0},
            "rank": -1, "score": 0, "priority": prio,
            "pack_primed": False, "body_embedded": False,
            "prompt": prompt,
            "max_tokens": 1500,
        })
    if not tasks:
        return None, "no resolved detector_action_graph rows to promote"
    tasks.sort(key=lambda t: -t["priority"])
    if limit:
        tasks = tasks[:limit]
    return tasks, None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="In-scope-authoritative per-fn hunt task-batch builder")
    ap.add_argument("--workspace", "--ws", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--lang", choices=["solidity", "go", "rust"], default=None)
    ap.add_argument("--only-uncovered", action="store_true",
                    help="emit only units NOT prior_covered by the engine token-pass")
    ap.add_argument("--with-pack-intel", action="store_true",
                    help="HYBRID mode: prime each task with its pre_flight_pack intel (hunter brief + "
                         "attack-class evidence + shape) as ACCELERANT, while still hard-requiring the "
                         "real-source read (R76). Empirically beats source-only on signal at zero R76 cost; "
                         "pack-only hunting is banned (hallucinates false HIGHs).")
    ap.add_argument("--embed-source", action="store_true",
                    help="Embed the mechanically-extracted REAL function body inline (all languages, "
                         "via function-source-extractor) + a read-for-context instruction. Empirically "
                         "R76-clean + ~28x fewer tokens than whole-file reads; the context instruction "
                         "fixes the bare-body over-flagging. Requires a per-fn decl line (file_line).")
    ap.add_argument("--per-function", action="store_true",
                    help="UNIVERSAL per-function worklist for ALL languages (sol/go/rust) from the "
                         "scope-correct .auditooor/function_coverage_completeness.json (not the "
                         "file-level inscope_units). Implies --embed-source. This is the canonical "
                         "body-pack hunt input - per function, every language, any workspace.")
    ap.add_argument("--units-file", default=None,
                    help="explicit unit allow-list: one `file::function` (or `path::fn`) per "
                         "line - emit hunt tasks ONLY for these units. Matches on basename::fn so "
                         "the hunt-coverage gate's queued_not_scanned list drives the worklist "
                         "directly (queue-aligned coverage), instead of the heatmap-derived "
                         "uncovered set which is a DIFFERENT set than the gate's queue_units_strict. "
                         "Implies --per-function. No file / empty -> no filtering.")
    ap.add_argument("--per-impact-frames", action=argparse.BooleanOptionalAction,
                    default=(os.environ.get("PER_IMPACT_FRAMES", "1") != "0"),
                    help="(unit x IMPACT-FRAME) expansion. DEFAULT = ON, gated by the SAME "
                         "PER_IMPACT_FRAMES env knob that gates the sibling live path "
                         "(per-fn-mimo-batch-gen.py) so both canonical hunt entrypoints "
                         "(make hunt-scoped AND make hunt-batch-bodypack) emit the plane "
                         "identically without a per-Makefile flag. Opt out ws-wide with "
                         "PER_IMPACT_FRAMES=0 (byte-identical-to-legacy, frame-less) or per-call "
                         "with --no-per-impact-frames; force ON with --per-impact-frames. "
                         "ON -> EXPAND each per-function task into one "
                         "task per in-scope IMPACT FRAME for the unit's language (the impact "
                         "families from completeness-matrix-build.py::_MECHANISM_LIBRARY_SEED "
                         "filtered to the ws language, e.g. solidity -> direct-theft / "
                         "permanent-freeze / insolvency / temp-freeze-griefing / ...). Each task "
                         "carries task['impact']=<impact_id>, a distinct task_id (impact folded "
                         "into the stable id), a frame-distinct sidecar slug (brick 1's __I- "
                         "suffix), and a prompt that hunts THAT ONE impact deeply. Pairs with the "
                         "completeness gate's per-(fn x impact) crediting.")
    ap.add_argument("--unit", choices=["function", "path", "path-followthrough"], default="function",
                    help="Hunt UNIT (default 'function' = unchanged behavior). 'path' reads "
                         ".auditooor/dataflow_paths.jsonl and emits one per_path task per UNGUARDED "
                         "multi-hop/storage-mediated def-use flow (source@L -> sink@L, N hops, guard "
                         "status), falling back to per-function for units with no path. ADDITIVE/opt-in: "
                         "when dataflow_paths.jsonl is absent, path mode degrades to per-function. The "
                         "default 'function' path is byte-identical to before this flag existed. "
                         "'path-followthrough' (B3; also gated by env AUDITOOOR_PATH_FOLLOWTHROUGH=1) "
                         "REUSES function-coverage-completeness._compute_path_coverage's "
                         "uncovered_unguarded_gaps and emits one per_path_dataflow_hunt task per "
                         "uncovered UNGUARDED gap whose endpoints are NOT already hunted (joined to "
                         "hunt_findings_sidecars/ by file:line). Absent slice -> falls back to the "
                         "legacy dispatch (env-on-but-no-slice is byte-identical to off).")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[inscope-hunt-batch-builder] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    # A2 - coverage-plane drain (default-OFF env AUDITOOOR_PLANE_DRAIN=1). When ON
    # and .auditooor/coverage_plane.jsonl exists, drain the not-enumerated cells
    # directly (source_of_truth='coverage_plane'). Absent plane -> fall through to
    # the legacy dispatch so env-on-but-no-plane is still byte-identical. Env-off
    # skips this branch entirely (byte-identical to before A2 existed).
    # B3 - dataflow path follow-through (env AUDITOOOR_PATH_FOLLOWTHROUGH=1 OR
    # --unit path-followthrough). Emits per_path_dataflow_hunt tasks from the
    # uncovered_unguarded_gaps. Only fires when a gap set exists; otherwise falls
    # through to the legacy dispatch below (env-on-but-no-slice == byte-identical).
    _b3 = (args.unit == "path-followthrough") or _path_followthrough_enabled()
    if _b3:
        ft_tasks, ft_err = build_path_followthrough_tasks(ws, args.limit)
        if ft_tasks is not None:
            tasks, err = ft_tasks, ft_err
        else:
            _b3 = False  # no gaps -> fall through to legacy dispatch
    # B5 - detector->hunt promoter (env AUDITOOOR_DETECTOR_PROMOTE_HUNT=1). Promotes
    # resolved detector_action_graph rows into detector_promoted_hunt tasks. Only
    # fires when a resolved graph exists; else falls through (env-on-but-no-graph ==
    # byte-identical). Precedence AFTER B3's explicit path-followthrough opt-in.
    _b5 = False
    if not _b3 and _detector_promote_enabled():
        dp_tasks, dp_err = build_detector_promoted_tasks(ws, args.lang, args.limit)
        if dp_tasks is not None:
            tasks, err = dp_tasks, dp_err
            _b5 = True
    if _b3 or _b5:
        pass  # tasks already set from B3 (path-followthrough) or B5 (detector promote)
    elif _plane_drain_enabled() and (ws / ".auditooor" / "coverage_plane.jsonl").is_file():
        tasks, err = build_plane_drain_tasks(ws, args.lang, args.limit, embed_source=True)
    elif args.units_file and Path(args.units_file).is_file():
        # Explicit unit list (e.g. the gate's queued_not_scanned): resolve + body-extract
        # every unit from source on-demand, so units ABSENT from the completeness list
        # (under-extracted Cairo / internals / missed entrypoints) are still hunted.
        tasks, err = build_tasks_from_units_explicit(ws, args.units_file, args.limit)
    elif args.unit == "path":
        tasks, err = build_path_tasks(ws, args.lang, args.only_uncovered, args.limit)
    elif args.per_function:
        tasks, err = build_tasks_per_function(ws, args.lang, args.only_uncovered, args.limit,
                                              args.with_pack_intel, embed_source=True,
                                              per_impact_frames=args.per_impact_frames)
    else:
        tasks, err = build_tasks(ws, args.lang, args.only_uncovered, args.limit, args.with_pack_intel,
                                 args.embed_source, per_impact_frames=args.per_impact_frames)
    if err:
        print(f"[inscope-hunt-batch-builder] ERR {err}", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else Path(f"/tmp/{ws.name}_inscope_hunt_batch.jsonl")
    out.write_text("".join(json.dumps(t) + "\n" for t in tasks), encoding="utf-8")
    primed = sum(1 for t in tasks if t.get("pack_primed"))
    embedded = sum(1 for t in tasks if t.get("body_embedded"))
    extra = (f" ({primed} pack-primed)" if args.with_pack_intel else "") + \
            (f" ({embedded} body-embedded)" if (args.embed_source or args.per_function) else "")
    print(f"[inscope-hunt-batch-builder] wrote {len(tasks)} in-scope hunt tasks{extra} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
