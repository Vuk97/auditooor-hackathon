#!/usr/bin/env python3
"""capability-wiring-integrity-check.py - mechanical whole-flow wiring audit.

Generalises the manual grep audit that found ~40 orphan capabilities. For every
row in ``reference/capability_inventory.jsonl`` it STATICALLY asserts the five
flow dimensions that a capability must satisfy to actually run inside the audit
funnel (not just exist as a built-but-dormant tool + test):

  INVOKED    a pipeline stage runs the cap's tool. The INVOKER corpus is the set
             of AUTO-RUN drivers: tools/audit-deep.sh (deep auto-emit stages),
             tools/audit-completeness-check.py (the L37 gate-signals auto-run
             their own tool), and the REQUIRED steps of readme_runbook_steps.json.
             An ADVISORY (required=false) runbook step is operator-optional and
             does NOT count as automatic invocation - which is exactly why the
             rust-detector-runner lanes (advisory runbook step only, never in
             audit-deep) come out not-invoked.
  FEEDS-FROM the cap declares >=1 upstream input (artifact OR source). Tri-state:
             present / none (explicit empty) / unknown (no inputs key).
  FEEDS-TO   a DISTINCT consumer references the cap's output artifact / REL
             constant. The CONSUMER corpus is tools/auto-coverage-closer.py, the
             tools/*-to-exploit-queue.py drains, tools/exploit-queue.py,
             tools/audit-completeness-check.py, and readme_runbook_steps.json.
             audit-deep.sh is deliberately NOT in the consumer corpus so an
             emitter that merely echoes its own output path does not self-credit.
             A secondary "declared" credit applies when the row's ``consumers``
             names an existing tool file / make-target / gate function.
  DAG-ORDER  funnel-phase ordering: the emit phase must not come AFTER the
             consume phase. Phases: audit-deep auto-emit = 2, hunt/coverage-closer
             = 3, exploit-queue/drains = 4, audit-complete gate = 5. emit_phase
             <= consumer_phase is OK (a gate lane that emits AND consumes in the
             same audit-complete run is emit==consume==5, which is fine); only
             emit_phase > consumer_phase (consumed strictly before emitted) is a
             wrong-order BROKEN-FLOW. This phase model is used instead of fragile
             per-tool runbook line matching, which mis-fires on incidental prose.
  ENFORCED   whether the cap is an L37 gate signal or a report-only advisory.

Verdict per cap:
  * unknown      - missing tool-file OR emit-artifact metadata (CONSERVATIVE:
                   never fabricate an orphan from an under-specified row).
  * ORPHAN       - has both, but missing INVOKED or missing FEEDS-TO.
  * BROKEN-FLOW  - invoked + fed-to but source-less (explicit empty inputs) OR
                   wrong DAG-order.
  * WIRED        - all dimensions satisfied.

Advisory-first: default is WARN (rc 0) with a JSON report on stdout. Under
``--enforce`` / env AUDITOOOR_WIRING_INTEGRITY_ENFORCE=1 / AUDITOOOR_L37_STRICT=1
it fails closed (rc 1) listing every ORPHAN / BROKEN-FLOW. It NEVER hard-blocks by
default.

capability_set_hash = sha256 over the sorted ``id<TAB>name<TAB>status`` of every
cap. It supports the STALE-DONE-ON-CAPABILITY-CHANGE rule: a done marker earned
under an older hash is stale because the capability set (or a cap's landed
status) has since changed.

RECONCILIATION / AUTHORITY vs capability-orphan-closure-check.py
---------------------------------------------------------------
This tool asserts a STRICT whole-funnel INVOKED->FEEDS-TO flow; it is the
authority on "does this cap actually run inside the audit funnel". A cap the
strict test cannot resolve (no executable tool_file OR no emit artifact in
``outputs``) used to default to 'unknown' - and because ~96% of rows lack an
``outputs`` key, ~1661/1738 rows fell into 'unknown' and were NEVER counted as
problems, so `orphan=0` read as clean even under --enforce. That is vacuous.

Two fixes make the vacuity load-bearing:
  1. UNKNOWN-RATIO guard - under --enforce, a `unknown/total` fraction above
     ``--max-unknown-ratio`` (default 0.20) is a FAIL. A mostly-unclassified
     inventory can no longer read as green.
  2. CLOSURE RECONCILIATION - before defaulting a row to 'unknown', consult
     capability-orphan-closure-check.py, which classifies EVERY cap by
     REACHABILITY (surface-wired categories + transitive WIRED via the
     Makefile/hooks/pre-submit corpus). A cap that closure PROVES WIRED is
     credited 'wired' here (feeds_to_method='closure-wired') instead of
     'unknown'. This reconciles the two tools (previously disagreeing by
     ~1420 with no single source of truth). We stay CONSERVATIVE: closure
     reachability can only RESCUE a row from 'unknown'; it NEVER fabricates an
     ORPHAN/BROKEN-FLOW from an under-specified row (this tool remains the
     authority for those two fail verdicts).

CLI: capability-wiring-integrity-check.py --repo <path> [--json] [--enforce]
     [--max-unknown-ratio F]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.capability_wiring_integrity.v1"

# Default ceiling on the unknown fraction under --enforce. Above this, the
# 'unknown' bucket is too large for a green verdict to be meaningful (a mostly-
# unclassified inventory silently reading as clean is the exact vacuity this
# guard closes). Overridable via --max-unknown-ratio.
DEFAULT_MAX_UNKNOWN_RATIO = 0.20

# STRICT-only floor on the invoked=True fraction (over the RESOLVABLE denominator,
# i.e. rows where INVOKED could be determined). Today the live repo sits at ~14%
# invoked=True with the rest wired-by-closure only; the roadmap north-star is 100%.
# This floor is deliberately LOW for this advisory-first wave (the STRICT path
# exists + is tested but is NOT yet joined to the L37 umbrella / audit-complete),
# so it flips only when a set regresses well below today's baseline. Overridable
# via --min-invoked-ratio / env AUDITOOOR_WIRING_MIN_INVOKED_RATIO.
DEFAULT_MIN_INVOKED_RATIO = 0.10

# Sources scanned for the wiring dimensions (repo-relative).
INVENTORY_REL = "reference/capability_inventory.jsonl"
AUDIT_DEEP_REL = "tools/audit-deep.sh"
RUNBOOK_REL = "tools/readme_runbook_steps.json"
CLOSER_REL = "tools/auto-coverage-closer.py"
EXPLOIT_QUEUE_REL = "tools/exploit-queue.py"
AUDIT_COMPLETE_REL = "tools/audit-completeness-check.py"
DRAIN_GLOB = "*-to-exploit-queue.py"

# Path token (a real artifact filename with a known audit-artifact extension).
_PATH_RE = re.compile(r"[\w][\w./\-]*\.(?:jsonl|json|md|txt|csv|ndjson)\b")
# _SIGNAL_ORDER tuple entries look like ("signal-name", "fail-verdict").
_SIGNAL_RE = re.compile(r"\(\s*\"([a-z0-9][a-z0-9\-]+)\"\s*,\s*\"fail-[a-z0-9\-]+\"\s*\)")


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_inventory(repo: Path) -> list[dict]:
    rows: list[dict] = []
    inv = repo / INVENTORY_REL
    for line in _read_text(inv).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def compute_capability_set_hash(rows: list[dict]) -> str:
    """sha256 over sorted ``id<TAB>name<TAB>status`` (status is the version proxy)."""
    parts = sorted(
        f"{r.get('id', '')}\t{r.get('name', '')}\t{r.get('status', '')}"
        for r in rows
    )
    h = hashlib.sha256()
    h.update("\n".join(parts).encode("utf-8"))
    return h.hexdigest()


def current_capability_set_hash(repo: Path | None = None) -> str | None:
    """The capability_set_hash for the LIVE inventory, or None if it can't be
    computed. This is THE shared source of truth for the T1 mechanic
    (stale-done-on-capability-set-hash-change): the done-marker stamps this at
    write-time and audit-done-guard re-compares it. Both callers MUST route
    through this one function so a hash written by the gate matches a hash read
    by the guard byte-for-byte. Never raises - a missing/corrupt inventory
    returns None, which callers treat as "cannot verify staleness" (grandfather),
    never as a spurious mismatch.
    """
    try:
        if repo is None:
            repo = Path(__file__).resolve().parent.parent
        rows = load_inventory(Path(repo))
        if not rows:
            return None
        return compute_capability_set_hash(rows)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Corpora
# --------------------------------------------------------------------------- #
def _required_runbook_step_text(runbook: dict) -> str:
    """Concatenate what_must_be_done ONLY for required (non-advisory) steps."""
    chunks: list[str] = []
    for step in runbook.get("steps", []) or []:
        if step.get("required"):
            chunks.append(json.dumps(step.get("what_must_be_done", "")))
    return "\n".join(chunks)


def build_corpora(repo: Path) -> dict:
    """Return the invoker / consumer text corpora + parsed helpers."""
    audit_deep = _read_text(repo / AUDIT_DEEP_REL)
    closer = _read_text(repo / CLOSER_REL)
    exploit_queue = _read_text(repo / EXPLOIT_QUEUE_REL)
    audit_complete = _read_text(repo / AUDIT_COMPLETE_REL)

    try:
        runbook = json.loads(_read_text(repo / RUNBOOK_REL) or "{}")
    except json.JSONDecodeError:
        runbook = {}
    runbook_json = json.dumps(runbook)
    required_steps = _required_runbook_step_text(runbook)

    drains_text_parts: list[str] = []
    tools_dir = repo / "tools"
    for drain in sorted(tools_dir.glob(DRAIN_GLOB)):
        drains_text_parts.append(_read_text(drain))
    drains_text = "\n".join(drains_text_parts)

    # INVOKER: only AUTO-RUN drivers. audit-deep (deep auto-emit), audit-complete
    # (gate signals auto-run their tool), required runbook steps. NOT advisory
    # runbook steps.
    invoker = "\n".join([audit_deep, audit_complete, required_steps])

    # CONSUMER parts, each tagged with a funnel PHASE (for DAG-order). audit-deep
    # is deliberately absent (emitter self-echo would false-credit FEEDS-TO).
    consumer_parts = {
        "closer": (closer, 3),
        "drains": (drains_text, 4),
        "exploit_queue": (exploit_queue, 4),
        "audit_complete": (audit_complete, 5),
        "runbook": (runbook_json, 3),
    }

    # L37 gate-signal names (for ENFORCED classification).
    signals = set(_SIGNAL_RE.findall(audit_complete))

    return {
        "invoker": invoker,
        "consumer_parts": consumer_parts,
        "signals": signals,
        "audit_deep": audit_deep,
        "audit_complete": audit_complete,
    }


# --------------------------------------------------------------------------- #
# Metadata mining
# --------------------------------------------------------------------------- #
def _mine_artifacts(items) -> set[str]:
    """Extract artifact path tokens from a list of strings and/or dicts."""
    arts: set[str] = set()
    if not items:
        return arts
    for it in items:
        if isinstance(it, str):
            arts.update(_PATH_RE.findall(it))
        elif isinstance(it, dict):
            for key in ("destination", "path", "artifact", "name"):
                v = it.get(key)
                if isinstance(v, str):
                    arts.update(_PATH_RE.findall(v))
    return arts


def _tool_files(file_paths) -> list[str]:
    """Basenames of the cap's executable tool files (exclude tests/)."""
    out: list[str] = []
    for p in file_paths or []:
        if not isinstance(p, str):
            continue
        if "/tests/" in p or p.startswith("tests/") or "test_" in os.path.basename(p):
            continue
        if p.endswith(".py") or p.endswith(".sh"):
            out.append(os.path.basename(p))
    return out


def _declared_consumer_exists(consumers, repo: Path) -> bool:
    """Secondary FEEDS-TO credit: a declared consumer that concretely exists.

    Catches caps wired into OTHER subsystems (not the scanned canonical funnel)
    so they are not falsely flagged orphan. Evidence = the consumer string names
    an existing tools/ file, a ``make <target>``, or an audit-completeness-check
    gate function.
    """
    for c in consumers or []:
        if not isinstance(c, str):
            continue
        low = c.strip()
        if not low:
            continue
        if low.startswith("make ") or "make scan-" in low or "make audit" in low:
            return True
        if "audit-completeness-check.py:" in low or "check_" in low:
            return True
        # A tools/xxx.py token that exists on disk.
        for tok in re.findall(r"[\w./\-]+\.py", low):
            base = os.path.basename(tok)
            if (repo / "tools" / base).is_file():
                return True
    return False


# --------------------------------------------------------------------------- #
# Per-cap evaluation
# --------------------------------------------------------------------------- #
# Funnel phase ordinals (for DAG-order).
_PHASE_AUDIT_DEEP = 2
_PHASE_AUDIT_COMPLETE = 5


def evaluate_row(row: dict, corpora: dict, repo: Path) -> dict:
    cap_id = row.get("id", "")
    name = row.get("name", "")
    status = row.get("status", "")

    tool_files = _tool_files(row.get("file_paths"))
    emit_arts = _mine_artifacts(row.get("outputs"))
    emit_basenames = {os.path.basename(a) for a in emit_arts}

    invoker = corpora["invoker"]
    consumer_parts = corpora["consumer_parts"]

    # --- INVOKED ---------------------------------------------------------- #
    invoked = None
    invoked_by: list[str] = []
    if tool_files:
        for tf in tool_files:
            if tf in invoker:
                invoked_by.append(tf)
        invoked = bool(invoked_by)

    # --- FEEDS-TO --------------------------------------------------------- #
    feeds_to = None
    feeds_to_method = "unknown"
    feeds_to_via: list[str] = []
    consumer_phase = None
    if emit_basenames:
        for bn in sorted(emit_basenames):
            for part, (txt, phase) in consumer_parts.items():
                if bn in txt:
                    feeds_to_via.append(f"{bn}@{part}")
                    # DEEPEST consumer phase: the flow is valid as long as SOME
                    # consumer reads the artifact at/after the emit phase. Taking
                    # the max avoids a false wrong-order when the artifact also
                    # appears in an earlier verification reference (e.g. a runbook
                    # artifact_check).
                    consumer_phase = phase if consumer_phase is None else max(consumer_phase, phase)
        canonical = bool(feeds_to_via)
        declared = _declared_consumer_exists(row.get("consumers"), repo)
        if canonical:
            feeds_to, feeds_to_method = True, "canonical"
        elif declared:
            feeds_to, feeds_to_method = True, "declared"
        else:
            feeds_to, feeds_to_method = False, "none"

    # --- FEEDS-FROM ------------------------------------------------------- #
    raw_inputs = row.get("inputs")
    if raw_inputs is None:
        feeds_from = "unknown"
    elif len(raw_inputs) == 0:
        feeds_from = "none"
    else:
        feeds_from = "present"

    # --- ENFORCED --------------------------------------------------------- #
    signals = corpora["signals"]
    slug = str(name).strip().lower().replace(" ", "-")
    enforcement = "advisory"
    if slug in signals or cap_id in signals:
        enforcement = "gate-signal"
    else:
        # A consumers/notes reference to a check_<x> in the L37 registry.
        blob = json.dumps(row.get("consumers", [])) + json.dumps(row.get("notes", ""))
        if "check_" in blob and ("audit-completeness-check" in blob or "L37" in blob):
            enforcement = "gate-signal"

    # --- DAG-ORDER (funnel-phase) ----------------------------------------- #
    order = "unknown"
    emit_phase = None
    if invoked:
        if any(tf in corpora["audit_deep"] for tf in tool_files):
            emit_phase = _PHASE_AUDIT_DEEP
        elif any(tf in corpora["audit_complete"] for tf in tool_files):
            emit_phase = _PHASE_AUDIT_COMPLETE
        else:
            # Auto-run via a required runbook step (hunt phase).
            emit_phase = 3
    if emit_phase is not None and consumer_phase is not None:
        order = "ok" if emit_phase <= consumer_phase else "wrong"

    # --- VERDICT ---------------------------------------------------------- #
    reasons: list[str] = []
    if invoked is None or feeds_to is None:
        verdict = "unknown"
        if invoked is None:
            reasons.append("no executable tool_file in inventory row (INVOKED undeterminable)")
        if feeds_to is None:
            reasons.append("no emit artifact in outputs (FEEDS-TO undeterminable)")
    elif not invoked:
        verdict = "ORPHAN"
        reasons.append(
            f"not-invoked: no auto-run pipeline stage runs {tool_files}"
        )
    elif not feeds_to:
        verdict = "ORPHAN"
        reasons.append(
            f"output-dead-ends: no consumer references {sorted(emit_basenames)}"
        )
    elif feeds_from == "none":
        verdict = "BROKEN-FLOW"
        reasons.append("source-less: invoked + fed-to but declares zero inputs")
    elif order == "wrong":
        verdict = "BROKEN-FLOW"
        reasons.append(
            f"wrong-dag-order: emit phase {emit_phase} > consumer phase {consumer_phase}"
        )
    else:
        verdict = "WIRED"

    return {
        "id": cap_id,
        "name": name,
        "category": row.get("category", ""),
        "status": status,
        "verdict": verdict,
        "invoked": invoked,
        "invoked_by": invoked_by,
        "feeds_from": feeds_from,
        "feeds_to": feeds_to,
        "feeds_to_method": feeds_to_method,
        "feeds_to_via": feeds_to_via,
        "dag_order": order,
        "emit_phase": emit_phase,
        "consumer_phase": consumer_phase,
        "enforcement": enforcement,
        "tool_files": tool_files,
        "emit_artifacts": sorted(emit_basenames),
        "reasons": reasons,
    }


# --------------------------------------------------------------------------- #
# Closure reconciliation (import capability-orphan-closure-check.py)
# --------------------------------------------------------------------------- #
def _load_closure_module(repo: Path):
    """Import tools/capability-orphan-closure-check.py as a module (hyphenated
    filename -> importlib). Returns the module or None if unavailable."""
    path = repo / "tools" / "capability-orphan-closure-check.py"
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "_capability_orphan_closure_check", str(path)
        )
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None


def closure_wired_keys(repo: Path) -> set[str]:
    """Set of cap_id + name for every cap the closure-check classifies WIRED.

    WIRED in the closure tool = reachable from a gate/stage/make-target/hook,
    directly OR transitively, plus the surface-wired categories. This is the
    reachability evidence we import to shrink the 'unknown' bucket. Returns an
    empty set (no reconciliation) if the closure tool cannot be run - fully
    backward compatible.
    """
    mod = _load_closure_module(repo)
    if mod is None:
        return set()
    try:
        # The closure module resolves paths against its own REPO_ROOT (its
        # parent-of-tools), which is the same repo we were handed in the normal
        # case. Load its inventory + declarations and classify.
        inv_path = repo / INVENTORY_REL
        caps = mod.load_inventory(inv_path)
        decl_path = repo / "reference" / "capability_closure_declarations.json"
        declarations, policy = mod.load_declarations(decl_path)
        results = mod.classify(caps, declarations, policy)
    except Exception:
        return set()
    keys: set[str] = set()
    for r in results:
        if r.get("disposition") == "WIRED":
            if r.get("cap_id"):
                keys.add(str(r["cap_id"]))
            if r.get("name"):
                keys.add(str(r["name"]))
    return keys


# --------------------------------------------------------------------------- #
# Non-vacuity (STRICT): a capability that emits NO artifact on a REAL workspace
# is not truly wired - it is wired-by-declaration but dormant. This is the
# firing-side complement of the static flow check: FEEDS-TO proves a consumer
# *would* read the artifact, but only a real emit on a live workspace proves the
# producer *actually ran and produced it*.
# --------------------------------------------------------------------------- #
def scan_workspace_artifacts(workspace: Path) -> set[str]:
    """Set of basenames of every NON-EMPTY file under ``<workspace>/.auditooor``
    (recursive). An empty (0-byte) artifact does NOT count as a real emit - a
    stage that touched an empty file is still vacuous. Returns an empty set if the
    workspace has no ``.auditooor`` dir (nothing was produced there)."""
    arts: set[str] = set()
    base = workspace / ".auditooor"
    if not base.is_dir():
        return arts
    for p in base.rglob("*"):
        try:
            if p.is_file() and p.stat().st_size > 0:
                arts.add(p.name)
        except OSError:
            continue
    return arts


def _row_vacuity(e: dict, ws_basenames: set[str] | None) -> None:
    """Annotate a WIRED row with emit_present_on_ws + vacuous (in place).

    Vacuity semantics (only meaningful for verdict WIRED):
      * closure-only rescue (feeds_to_method == 'closure-wired'): the row was
        rescued by transitive reachability and declares NO emit artifact we can
        verify - it emits nothing checkable, so it is VACUOUS by construction.
      * WIRED with no emit artifact at all: same - nothing to prove fired.
      * WIRED with emit artifacts + a workspace supplied: VACUOUS iff none of its
        declared artifacts materialised (non-empty) on that workspace.
      * WIRED with emit artifacts + NO workspace: cannot disprove firing from
        static metadata alone -> NOT vacuous (conservative).
    """
    e["emit_present_on_ws"] = None
    e["vacuous"] = False
    if e.get("verdict") != "WIRED":
        return
    if e.get("feeds_to_method") == "closure-wired":
        e["vacuous"] = True
        return
    emit_bn = e.get("emit_artifacts") or []
    if not emit_bn:
        e["vacuous"] = True
        return
    if ws_basenames is not None:
        present = any(bn in ws_basenames for bn in emit_bn)
        e["emit_present_on_ws"] = present
        e["vacuous"] = not present


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def run(
    repo: Path,
    enforce: bool,
    max_unknown_ratio: float = DEFAULT_MAX_UNKNOWN_RATIO,
    strict: bool = False,
    workspace: Path | None = None,
    min_invoked_ratio: float = DEFAULT_MIN_INVOKED_RATIO,
) -> tuple[dict, int]:
    rows = load_inventory(repo)
    corpora = build_corpora(repo)
    cap_hash = compute_capability_set_hash(rows)

    evaluated = [evaluate_row(r, corpora, repo) for r in rows]

    # --- CLOSURE RECONCILIATION: rescue 'unknown' rows the closure-check proves
    # WIRED (reachable). CONSERVATIVE: this can only move a row OUT of 'unknown'
    # into 'wired'; it never fabricates an ORPHAN/BROKEN-FLOW.
    closure_keys = closure_wired_keys(repo)
    rescued_by_closure = 0
    if closure_keys:
        for e in evaluated:
            if e["verdict"] != "unknown":
                continue
            if str(e.get("id")) in closure_keys or str(e.get("name")) in closure_keys:
                e["verdict"] = "WIRED"
                e["feeds_to_method"] = "closure-wired"
                e["reasons"] = [
                    "closure-reconciled: capability-orphan-closure-check.py "
                    "classifies this cap WIRED (surface/transitive reachable)"
                ]
                rescued_by_closure += 1

    # STRICT implies enforce (fail-closed).
    if strict:
        enforce = True

    orphans = [e for e in evaluated if e["verdict"] == "ORPHAN"]
    broken = [e for e in evaluated if e["verdict"] == "BROKEN-FLOW"]
    wired = [e for e in evaluated if e["verdict"] == "WIRED"]
    unknown = [e for e in evaluated if e["verdict"] == "unknown"]

    problems = len(orphans) + len(broken)

    total = len(evaluated)
    unknown_ratio = (len(unknown) / total) if total else 0.0
    unknown_ratio_exceeded = enforce and (unknown_ratio > max_unknown_ratio)

    # --- INVOKED-FRACTION metric ----------------------------------------- #
    # invoked=True over the RESOLVABLE denominator (rows where INVOKED could be
    # determined at all). This is the north-star firing metric the roadmap drives
    # toward 100% (today ~14%).
    invoked_true = sum(1 for e in evaluated if e["invoked"] is True)
    invoked_resolvable = sum(1 for e in evaluated if e["invoked"] is not None)
    invoked_fraction = (invoked_true / invoked_resolvable) if invoked_resolvable else 0.0
    invoked_fraction_low = strict and (invoked_fraction < min_invoked_ratio)

    # --- NON-VACUITY (STRICT) -------------------------------------------- #
    # A WIRED cap that emits no verifiable artifact (closure-only) or whose emit
    # artifact never materialised on the supplied real workspace is not truly
    # wired. Annotate every row; count the vacuous WIRED rows.
    ws_basenames = scan_workspace_artifacts(workspace) if workspace is not None else None
    for e in evaluated:
        _row_vacuity(e, ws_basenames)
    vacuous_wired = [e for e in wired if e.get("vacuous")]
    # How many WIRED rows we could actually check a real emit for on the ws.
    ws_emit_checked = sum(
        1 for e in wired if e.get("emit_present_on_ws") is not None
    ) if workspace is not None else 0
    ws_emit_present = sum(
        1 for e in wired if e.get("emit_present_on_ws") is True
    ) if workspace is not None else 0
    vacuity_failed = strict and bool(vacuous_wired)

    strict_failed = invoked_fraction_low or vacuity_failed

    if enforce:
        if problems or unknown_ratio_exceeded or strict_failed:
            verdict = "fail-wiring-integrity"
        else:
            verdict = "pass-wiring-integrity"
    else:
        verdict = "WARN-wiring-integrity" if problems else "pass-wiring-integrity"

    def _slim(e: dict) -> dict:
        return {
            "id": e["id"],
            "name": e["name"],
            "category": e["category"],
            "reasons": e["reasons"],
        }

    report = {
        "schema": SCHEMA,
        "repo": str(repo),
        "capability_set_hash": cap_hash,
        "enforce": enforce,
        "verdict": verdict,
        "counts": {
            "total": total,
            "wired": len(wired),
            "orphan": len(orphans),
            "broken_flow": len(broken),
            "unknown": len(unknown),
        },
        "wired_by_closure": rescued_by_closure,
        "unknown_ratio": round(unknown_ratio, 4),
        "max_unknown_ratio": max_unknown_ratio,
        "unknown_ratio_exceeded": unknown_ratio_exceeded,
        "strict": strict,
        "workspace": str(workspace) if workspace is not None else None,
        "invoked": {
            "invoked_true": invoked_true,
            "resolvable": invoked_resolvable,
            "invoked_fraction": round(invoked_fraction, 4),
            "min_invoked_ratio": min_invoked_ratio,
            "invoked_fraction_low": invoked_fraction_low,
        },
        "non_vacuity": {
            "vacuous_wired": len(vacuous_wired),
            "ws_emit_checked": ws_emit_checked,
            "ws_emit_present": ws_emit_present,
            "vacuity_failed": vacuity_failed,
        },
        "orphans": [_slim(e) for e in orphans],
        "broken_flows": [_slim(e) for e in broken],
        "vacuous_wired": [_slim(e) for e in vacuous_wired],
        "rows": evaluated,
    }

    rc = 1 if (enforce and (problems or unknown_ratio_exceeded or strict_failed)) else 0
    return report, rc


def _print_human(report: dict) -> None:
    c = report["counts"]
    print(f"[capability-wiring-integrity] {report['verdict']}")
    print(f"  capability_set_hash: {report['capability_set_hash']}")
    print(
        f"  total={c['total']} wired={c['wired']} orphan={c['orphan']} "
        f"broken_flow={c['broken_flow']} unknown={c['unknown']}"
    )
    ratio = report.get("unknown_ratio", 0.0)
    cap = report.get("max_unknown_ratio", DEFAULT_MAX_UNKNOWN_RATIO)
    flag = " EXCEEDED" if report.get("unknown_ratio_exceeded") else ""
    print(
        f"  unknown_ratio={ratio:.4f} (max={cap:.4f}){flag}"
        f"  wired_by_closure={report.get('wired_by_closure', 0)}"
    )
    if report.get("unknown_ratio_exceeded"):
        print(
            f"  FAIL: unknown fraction {ratio:.2%} exceeds ceiling {cap:.2%} - "
            f"too many caps unclassified for a meaningful green"
        )
    inv = report.get("invoked", {})
    if inv:
        print(
            f"  invoked_true={inv.get('invoked_true')} / resolvable={inv.get('resolvable')} "
            f"= {inv.get('invoked_fraction', 0.0):.2%} (min={inv.get('min_invoked_ratio', 0.0):.2%})"
            + (" LOW" if inv.get("invoked_fraction_low") else "")
        )
    nv = report.get("non_vacuity", {})
    if report.get("strict"):
        ws = report.get("workspace") or "(none)"
        print(
            f"  non-vacuity[strict] ws={ws} vacuous_wired={nv.get('vacuous_wired')} "
            f"ws_emit_present={nv.get('ws_emit_present')}/{nv.get('ws_emit_checked')} checked"
            + (" FAIL" if nv.get("vacuity_failed") else "")
        )
    if report["orphans"]:
        print(f"  ORPHANS ({len(report['orphans'])}):")
        for e in report["orphans"]:
            print(f"    - {e['id']} ({e['name']}): {'; '.join(e['reasons'])}")
    if report["broken_flows"]:
        print(f"  BROKEN-FLOW ({len(report['broken_flows'])}):")
        for e in report["broken_flows"]:
            print(f"    - {e['id']} ({e['name']}): {'; '.join(e['reasons'])}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Capability whole-flow wiring integrity check.")
    ap.add_argument("--repo", default=None, help="auditooor-mcp repo root (default: infer from script location)")
    ap.add_argument("--json", action="store_true", help="emit JSON report on stdout")
    ap.add_argument("--enforce", action="store_true", help="fail-closed (rc 1) on any ORPHAN / BROKEN-FLOW or unknown-ratio breach")
    ap.add_argument(
        "--strict",
        action="store_true",
        help=(
            "STRICT firing gate (implies --enforce): also FAIL on invoked-fraction "
            "below the floor and on any VACUOUS WIRED cap (closure-only, or a cap "
            "whose emit artifact never materialised on --workspace). Advisory-first "
            "wave: exists + tested but not yet joined to the L37 umbrella. "
            "Env AUDITOOOR_WIRING_STRICT=1."
        ),
    )
    ap.add_argument(
        "--workspace",
        default=None,
        help="real workspace root (checked for <ws>/.auditooor emit artifacts under --strict non-vacuity)",
    )
    ap.add_argument(
        "--max-unknown-ratio",
        type=float,
        default=None,
        help=(
            "under --enforce, FAIL when unknown/total exceeds this fraction "
            f"(default {DEFAULT_MAX_UNKNOWN_RATIO}; env AUDITOOOR_WIRING_MAX_UNKNOWN_RATIO)"
        ),
    )
    ap.add_argument(
        "--min-invoked-ratio",
        type=float,
        default=None,
        help=(
            "under --strict, FAIL when invoked_true/resolvable is below this fraction "
            f"(default {DEFAULT_MIN_INVOKED_RATIO}; env AUDITOOOR_WIRING_MIN_INVOKED_RATIO)"
        ),
    )
    args = ap.parse_args(argv)

    if args.repo:
        repo = Path(args.repo).resolve()
    else:
        repo = Path(__file__).resolve().parent.parent

    strict = args.strict or os.environ.get("AUDITOOOR_WIRING_STRICT") == "1"

    enforce = (
        args.enforce
        or strict
        or os.environ.get("AUDITOOOR_WIRING_INTEGRITY_ENFORCE") == "1"
        or os.environ.get("AUDITOOOR_L37_STRICT") == "1"
    )

    if args.max_unknown_ratio is not None:
        max_unknown_ratio = args.max_unknown_ratio
    else:
        env_ratio = os.environ.get("AUDITOOOR_WIRING_MAX_UNKNOWN_RATIO")
        try:
            max_unknown_ratio = float(env_ratio) if env_ratio else DEFAULT_MAX_UNKNOWN_RATIO
        except ValueError:
            max_unknown_ratio = DEFAULT_MAX_UNKNOWN_RATIO

    if args.min_invoked_ratio is not None:
        min_invoked_ratio = args.min_invoked_ratio
    else:
        env_min = os.environ.get("AUDITOOOR_WIRING_MIN_INVOKED_RATIO")
        try:
            min_invoked_ratio = float(env_min) if env_min else DEFAULT_MIN_INVOKED_RATIO
        except ValueError:
            min_invoked_ratio = DEFAULT_MIN_INVOKED_RATIO

    workspace = Path(args.workspace).resolve() if args.workspace else None

    report, rc = run(
        repo,
        enforce,
        max_unknown_ratio,
        strict=strict,
        workspace=workspace,
        min_invoked_ratio=min_invoked_ratio,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)

    return rc


if __name__ == "__main__":
    try:
        rc = main()
    except BrokenPipeError:
        # Downstream (e.g. `| head`) closed the pipe; exit quietly.
        try:
            sys.stdout.close()
        except Exception:
            pass
        rc = 0
    sys.exit(rc)
