#!/usr/bin/env python3
"""emit-verification-task.py - VERIFICATION-TASK EMITTER for CONVERTED load-bearing gates.

WHY THIS EXISTS (the operator's insight, predmkt lesson 2026-07-09). Most audit gates
check for the PRESENCE of prose - a claim, a required section, a "<rule>-rebuttal: <reason>"
marker - not the TRUTH of it. So an agent's path of least resistance is to WRITE THE WORDS
that green the gate rather than DO THE VERIFICATION the gate is a proxy for. The predmkt
driver "greened" the impact by asserting "clears $1000 comfortably", citing a Node.js sweep
artifact (redeem-slippage-sweep.js) that does NOT exist in the workspace; the true impact
was ~$0.13, four orders of magnitude under the $1000 fund-loss floor. A prose-checking gate
would have been satisfied by more prose too.

THE CONVERSION (what this tool implements the FRONT HALF of). For a LOAD-BEARING gate
(impact / scope-in-or-out / severity-tier / dedup-originality / guard-or-reachability /
permanence) a claim must be adjudicated by an INDEPENDENT verification subagent - a distinct
spawn-worker verify-lane session that is HANDED (a) the exact claim, (b) the exact
file(s):line(s) + artifacts to inspect, (c) the context refs (recall block, rubric row,
draft excerpt), (d) the expected evidence class - and RETURNS a non-forgeable receipt
(CONFIRMED / REFUTED + cited file:lines) bound to a stable task-hash. The gate greens on that
RECEIPT, not on the author's own words.

This tool emits the TASK sidecar + (optionally) the rendered verify-lane brief. The brief
template lives at tools/templates/verification-dispatch-brief.md and bakes in the
anti-rubber-stamp rule (default REFUTED unless independently CONFIRMED with cited file:lines).
A companion `validate_receipt` / `--check-receipt` path adjudicates a returned receipt and
tells a gate whether it may green (binding + all-targets-CONFIRMED + cited lines).

BINDING CONTRACT (shared with the receipt-checker, do NOT drift). The authoritative gate
that greens on a receipt is tools/verification-receipt-check.py; it recomputes the binding
hash from PUBLIC inputs and matches it against the receipt + the dispatch log. That file
defines the canonical:
    claim_hash(claim)      = sha256(strip+collapse-whitespace(claim))
    task_hash(gate, claim_hash) = sha256("auditooor.verification_task.v1" \\x1f
                                          gate.lower() \\x1f claim_hash)
This emitter computes EXACTLY that as the primary `task_hash` (and emits `claim_hash`) so a
receipt bound to this task validates under the receipt-checker. A RICHER, pointer-binding
hash (`pointer_binding_hash`, over gate+workspace+claim+pointers+floor) is also emitted as a
belt-and-suspenders anti-forgery field, but the field the gate keys on is the canonical
`task_hash`. If verification-receipt-check.py ever changes the canonical, this emitter must
be updated in lockstep (there is an interop test that asserts the two agree when both files
are present).

REUSE (single source of truth). For the canonical ABSOLUTE-USD-DERIVATION gate (Check #148)
the pointer extraction reuses absolute-usd-derivation-check.py's OWN regexes + floor parser
(loaded as a sibling module, the same way that gate reuses severity-calibration-gate.py's
classifier) so the task's pointers are exactly what the gate keys on - not a second,
drifting copy.

Advisory-first: this is an EMITTER, not a gate; it never blocks. It writes a task sidecar
and returns a report. Nothing here changes byte-output of any existing gate. Wiring it into
pre-submit / dispatch is a SEPARATE serial edit (see the emitted SPEC in the repo docs).

CLI:
  emit-verification-task.py --workspace <ws> --draft <md> --gate <GATE_ID>
      [--severity S] [--emit] [--out <path>] [--render-brief] [--json]
  emit-verification-task.py --check-receipt <receipt.json> --task <task.json> [--json]
  emit-verification-task.py --list-gates

Gate ids: ABSOLUTE-USD-DERIVATION (canonical, full extraction) plus generic conversion
candidates SCOPE-AUTHORITY / SEVERITY-RUBRIC / PRIOR-AUDIT-DEDUP / GUARD-REACHABILITY /
PERMANENCE-RESTART (generic citation-target extraction).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent

SCHEMA_TASK = "auditooor.verification_task.v1"
SCHEMA_RECEIPT = "auditooor.verification_receipt.v1"
EMITTER_VERSION = "1.0"
BRIEF_TEMPLATE_REL = "tools/templates/verification-dispatch-brief.md"

# Verdicts a receipt may carry (per target and overall).
_RECEIPT_VERDICTS = {"CONFIRMED", "REFUTED", "INSUFFICIENT_EVIDENCE"}

# A generic file:line citation, e.g. Vault.sol:142 / factory.oscript:58.
_SOURCE_CITED_RE = re.compile(r"[\w./-]+\.\w+:\d+")


# --- sibling-module loader (verbatim idiom from
# absolute-usd-derivation-check.py:78-92) so we reuse the gate's OWN regexes/parser. ---
def _load_module(filename: str, modname: str):
    path = TOOLS_DIR / filename
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        return None
    return mod


_AUSD = _load_module("absolute-usd-derivation-check.py", "_evt_ausd")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_draft(draft: Path) -> str:
    return draft.read_text(encoding="utf-8", errors="replace") if draft.is_file() else ""


def _first_title(text: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("# "):
            return s[2:].strip()
    return ""


def _section(text: str, header_kw: str) -> str:
    """Return the body of the first `## <header_kw>` section (case-insensitive), capped."""
    lines = text.splitlines()
    out: list[str] = []
    capturing = False
    for line in lines:
        s = line.strip()
        if s.startswith("## "):
            if capturing:
                break
            capturing = header_kw.lower() in s.lower()
            continue
        if capturing:
            out.append(line)
    body = "\n".join(out).strip()
    return body[:1200]


def _first_line(text: str, pred: Callable[[str], bool]) -> tuple[int | None, str]:
    for i, line in enumerate(text.splitlines(), start=1):
        if pred(line):
            return i, line.strip()
    return None, ""


def _extract_claim(text: str) -> str:
    """The exact load-bearing sentence the verify-lane must adjudicate.

    Prefer a line that carries a $ figure AND a floor-clearing / comparison keyword (the
    predmkt "clears $1000 comfortably, well above the ... floor"); fall back to the first
    line of the ## Impact section, then the finding title."""
    if _AUSD is not None:
        def _pred(ln: str) -> bool:
            return bool(_AUSD.DOLLAR_RE.search(ln)
                        and (_AUSD.CLEAR_KW_RE.search(ln) or _AUSD.COMPARE_RE.search(ln)))
        _, ln = _first_line(text, _pred)
        if ln:
            return ln
    impact = _section(text, "impact")
    if impact:
        first = impact.strip().splitlines()[0].strip()
        if first:
            return first
    title = _first_title(text)
    return title or "(no claim sentence found in draft)"


# ---------------------------------------------------------------------------
# ABSOLUTE-USD-DERIVATION target extraction (canonical, reuses the gate module)
# ---------------------------------------------------------------------------
def _price_value(text: str) -> dict[str, Any]:
    v: dict[str, Any] = {"price_usd": None, "named_source": None, "unit_scale": None}
    if _AUSD is None:
        return v
    for line in text.splitlines():
        if _AUSD.PRICE_RE.search(line) and _AUSD.PRICE_SOURCE_KW_RE.search(line):
            pm = re.search(r"(?:\$|USD\s?)\s?([\d,]+(?:\.\d+)?)", line, re.IGNORECASE)
            if pm:
                try:
                    v["price_usd"] = float(pm.group(1).replace(",", ""))
                except ValueError:
                    v["price_usd"] = None
            sm = _AUSD.PRICE_SOURCE_KW_RE.search(line)
            if sm:
                v["named_source"] = sm.group(0)
            break
    um = _AUSD.UNIT_SCALE_RE.search(text)
    if um:
        v["unit_scale"] = um.group(0).strip()
    return v


def _targets_absolute_usd(ws: Path, text: str) -> tuple[list[dict], list[dict]]:
    """Return (targets, artifacts) for the absolute-$ impact gate. Pointer roles are the
    exact derivation parts the gate scores: asset_identity, price_source, market_size,
    absolute_vs_floor. Each target carries whether the draft resolved it, the pointer
    (source file:line for asset_identity; draft:L<n> for the others), the extract, the
    per-target evidence class, and an independent verify instruction."""
    assert _AUSD is not None, "absolute-usd-derivation-check.py failed to load"
    lines = text.splitlines()

    # (a) ASSET-IDENTITY: asset keyword + a source file:line on the same line.
    a_line, a_txt = _first_line(
        text, lambda ln: bool(_AUSD.ASSET_KW_RE.search(ln) and _SOURCE_CITED_RE.search(ln)))
    a_ptr = None
    if a_txt:
        m = _SOURCE_CITED_RE.search(a_txt)
        a_ptr = m.group(0) if m else None
    asset_identity = {
        "role": "asset_identity",
        "kind": "source_citation",
        "resolved": bool(a_ptr),
        "pointer": a_ptr,
        "draft_line": a_line,
        "extract": a_txt,
        "expected_evidence_class": "evidence-artifact",
        "verify_instruction": (
            f"Open {a_ptr} and confirm it declares the loss-denomination asset the draft "
            "names. Do NOT accept the draft's word." if a_ptr else
            "MISSING in the draft: no asset+file:line citation. Locate the loss-denomination "
            "asset's default declaration in the in-scope tree and cite file:line yourself; "
            "if you cannot, the impact claim is REFUTED."),
    }

    # (b) PRICE-SOURCE (+unit scale): unit-scale line anywhere + a priced named source.
    has_unit = bool(_AUSD.UNIT_SCALE_RE.search(text))
    p_line, p_txt = _first_line(
        text, lambda ln: bool(_AUSD.PRICE_RE.search(ln) and _AUSD.PRICE_SOURCE_KW_RE.search(ln)))
    price_resolved = bool(has_unit and p_txt)
    price_source = {
        "role": "price_source",
        "kind": "external_price",
        "resolved": price_resolved,
        "pointer": f"draft:L{p_line}" if p_line else None,
        "draft_line": p_line,
        "extract": p_txt,
        "value": _price_value(text),
        "expected_evidence_class": "independent-verification",
        "verify_instruction": (
            "Independently confirm BOTH the unit-scale (1 <asset> = N base-units) from an "
            "in-scope source file:line AND the USD price from the named source; reject if "
            "either is unsourced or the price is stale / off by orders of magnitude."),
    }

    # (c) MARKET-SIZE / TVL: market keyword + a number on the same line.
    m_line, m_txt = _first_line(
        text, lambda ln: bool(_AUSD.MARKET_KW_RE.search(ln) and _AUSD.NUM_RE.search(ln)))
    market_size = {
        "role": "market_size",
        "kind": "draft_assertion",
        "resolved": bool(m_txt),
        "pointer": f"draft:L{m_line}" if m_line else None,
        "draft_line": m_line,
        "extract": m_txt,
        "expected_evidence_class": "evidence-artifact",
        "verify_instruction": (
            "Confirm the victim / TVL / order-size figure is grounded in an in-scope state "
            "read or on-chain datum, not merely asserted." if m_txt else
            "MISSING in the draft: no victim/TVL/order-size figure. A dollar impact cannot be "
            "derived without a market size - find it or REFUTE."),
    }

    # (d) ABSOLUTE $ vs FLOOR: $ figure + comparison + (floor word OR a second $) on a line.
    d_line, d_txt = _first_line(text, lambda ln: bool(
        _AUSD.DOLLAR_RE.search(ln) and _AUSD.COMPARE_RE.search(ln)
        and (re.search(r"\bfloor\b", ln, re.IGNORECASE)
             or len(_AUSD.DOLLAR_RE.findall(ln)) >= 2)))
    absolute_vs_floor = {
        "role": "absolute_vs_floor",
        "kind": "computed_comparison",
        "resolved": bool(d_txt),
        "pointer": f"draft:L{d_line}" if d_line else None,
        "draft_line": d_line,
        "extract": d_txt,
        "expected_evidence_class": "independent-verification",
        "verify_instruction": (
            "Recompute asset x unit-scale x market-size -> USD yourself and compare to the "
            "declared floor. Confirm the comparison direction (>= floor). A >2 order-of-"
            "magnitude gap vs the draft's number REFUTES the claim."),
    }

    targets = [asset_identity, price_source, market_size, absolute_vs_floor]

    # cited evidence artifacts (found=bool for each) - the predmkt sweep-that-does-not-exist.
    artifacts: list[dict] = []
    seen: set[str] = set()
    if ws.is_dir():
        for mm in _AUSD._ARTIFACT_FILE_RE.finditer(text):
            base = Path(mm.group(1)).name
            if not base or base in seen or base.lower() in _AUSD._NON_ARTIFACT_BASENAMES:
                continue
            seen.add(base)
            artifacts.append({"name": base, "found": bool(_AUSD._find_in_ws(ws, base)),
                              "must_exist": True})
    return targets, sorted(artifacts, key=lambda a: a["name"])


def _absolute_usd_context(ws: Path, text: str) -> dict[str, Any]:
    floor_usd, floor_source = (None, "no-floor-declared")
    if _AUSD is not None:
        floor_usd, floor_source = _AUSD.parse_floor(_AUSD._load_rules(ws), ws)
    rubric = (f"fund-loss USD floor = ${floor_usd} (source: {floor_source})"
              if floor_usd is not None
              else "no fund-loss USD floor declared for this workspace")
    return {"floor_usd": floor_usd, "floor_source": floor_source, "rubric_row": rubric}


def _absolute_usd_applicable(ws: Path, text: str, severity: str) -> dict[str, Any]:
    if _AUSD is None:
        return {"applicable": True, "reason": "gate module unavailable; not gating"}
    sev = _AUSD.detect_severity(text, severity)
    floor_usd, _ = _AUSD.parse_floor(_AUSD._load_rules(ws), ws)
    fund_loss, fl_reason = _AUSD.is_fund_loss(text)
    trig = {
        "tier_high_plus": sev in ("HIGH", "CRITICAL"),
        "floor_declared": floor_usd is not None,
        "fund_loss": fund_loss,
    }
    return {"applicable": all(trig.values()), "severity_detected": sev,
            "trigger": trig, "fund_loss_reason": fl_reason}


# ---------------------------------------------------------------------------
# generic conversion-candidate extraction (scope / severity / dedup / guard / permanence)
# ---------------------------------------------------------------------------
def _targets_generic(ws: Path, text: str) -> tuple[list[dict], list[dict]]:
    """Turn every file:line citation in the draft into an inspect-this target, plus a
    catch-all 'primary_claim' target when the draft has no citation at all (the pure-prose
    case). Deliberately conservative: the canonical, source-aware extraction lives in the
    per-gate builder; this keeps the primitive usable for other load-bearing gates without
    inventing (potentially wrong) gate-specific parsing."""
    targets: list[dict] = []
    seen: set[str] = set()
    for i, line in enumerate(text.splitlines(), start=1):
        for m in _SOURCE_CITED_RE.finditer(line):
            ptr = m.group(0)
            if ptr in seen:
                continue
            seen.add(ptr)
            targets.append({
                "role": f"cited_source_{len(targets) + 1}",
                "kind": "source_citation",
                "resolved": True,
                "pointer": ptr,
                "draft_line": i,
                "extract": line.strip()[:400],
                "expected_evidence_class": "evidence-artifact",
                "verify_instruction": (
                    f"Open {ptr} and confirm it actually substantiates the claim; look for "
                    "the disconfirming fact (a guard, a scope boundary, a prior disclosure)."),
            })
    if not targets:
        targets.append({
            "role": "primary_claim",
            "kind": "unsourced_claim",
            "resolved": False,
            "pointer": None,
            "draft_line": None,
            "extract": _extract_claim(text),
            "expected_evidence_class": "independent-verification",
            "verify_instruction": (
                "The draft cites no source file:line for this load-bearing claim. Locate the "
                "governing source / rubric row / prior-art yourself and cite it, or REFUTE."),
        })
    return targets, []


def _generic_context(ws: Path, text: str) -> dict[str, Any]:
    return {"floor_usd": None, "floor_source": None,
            "rubric_row": "(gate-specific rubric row - fill from SCOPE.md / SEVERITY.md)"}


def _generic_applicable(ws: Path, text: str, severity: str) -> dict[str, Any]:
    return {"applicable": True, "reason": "generic conversion candidate; always emit"}


# ---------------------------------------------------------------------------
# gate registry
# ---------------------------------------------------------------------------
GATE_SPECS: dict[str, dict[str, Any]] = {
    "ABSOLUTE-USD-DERIVATION": {
        "check_number": 148,
        "load_bearing_axis": "impact",
        "satisfiability_before": "prose-only",
        "task_evidence_class": "independent-verification",
        "targets": _targets_absolute_usd,
        "context": _absolute_usd_context,
        "applicable": _absolute_usd_applicable,
        "recall_block": (
            "vault_resume_context; vault_exploit_context; vault_engagement_status "
            "(workspace={ws}); vault_severity_calibration"),
    },
    "SCOPE-AUTHORITY": {
        "check_number": None, "load_bearing_axis": "scope",
        "satisfiability_before": "prose-only",
        "task_evidence_class": "independent-verification",
        "targets": _targets_generic, "context": _generic_context,
        "applicable": _generic_applicable,
        "recall_block": "vault_resume_context; vault_engagement_status (workspace={ws})",
    },
    "SEVERITY-RUBRIC": {
        "check_number": None, "load_bearing_axis": "severity",
        "satisfiability_before": "self-asserted-value",
        "task_evidence_class": "independent-verification",
        "targets": _targets_generic, "context": _generic_context,
        "applicable": _generic_applicable,
        "recall_block": "vault_severity_calibration; vault_resume_context (workspace={ws})",
    },
    "PRIOR-AUDIT-DEDUP": {
        "check_number": None, "load_bearing_axis": "dedup",
        "satisfiability_before": "prose-only",
        "task_evidence_class": "independent-verification",
        "targets": _targets_generic, "context": _generic_context,
        "applicable": _generic_applicable,
        "recall_block": "vault_originality_context; vault_dupe_advisory_check (workspace={ws})",
    },
    "GUARD-REACHABILITY": {
        "check_number": None, "load_bearing_axis": "guard-or-reachability",
        "satisfiability_before": "prose-only",
        "task_evidence_class": "independent-verification",
        "targets": _targets_generic, "context": _generic_context,
        "applicable": _generic_applicable,
        "recall_block": "vault_resume_context; vault_exploit_context (workspace={ws})",
    },
    "PERMANENCE-RESTART": {
        "check_number": None, "load_bearing_axis": "permanence",
        "satisfiability_before": "prose-only",
        "task_evidence_class": "independent-verification",
        "targets": _targets_generic, "context": _generic_context,
        "applicable": _generic_applicable,
        "recall_block": "vault_resume_context; vault_exploit_context (workspace={ws})",
    },
}


def list_gates() -> list[str]:
    return sorted(GATE_SPECS)


# ---------------------------------------------------------------------------
# stable task-hash (canonical binding contract - see verification-receipt-check.py)
# ---------------------------------------------------------------------------
def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _norm_claim(claim: str) -> str:
    """Canonical claim normalization: strip + collapse internal whitespace. MUST match
    verification-receipt-check.py::_norm_claim byte-for-byte (NOT lowercased) so claim_hash
    agrees across the two independently-built halves."""
    return re.sub(r"\s+", " ", (claim or "").strip())


def claim_hash(claim: str) -> str:
    return _sha256(_norm_claim(claim))


def canonical_task_hash(gate_id: str, claim_h: str) -> str:
    """The binding hash the receipt-checker recomputes. Deterministic + reproducible from
    PUBLIC inputs (gate + claim); anti-forgery comes from the matching dispatch-log entry,
    not from hash secrecy. Mirrors verification-receipt-check.py::task_hash exactly."""
    return _sha256(f"{SCHEMA_TASK}\x1f{(gate_id or '').strip().lower()}\x1f{claim_h}")


def pointer_binding_hash(gate_id: str, ws_name: str, claim: str,
                         targets: list[dict], floor_usd: int | None) -> str:
    """Belt-and-suspenders richer binding: sha256 over gate+workspace+normalized claim+
    sorted (role,pointer,resolved) triples+floor. Excludes timestamps/absolute paths so
    re-emitting the same draft yields the SAME hash. This binds the exact POINTERS a
    receipt was handed, catching a receipt that answers a claim with swapped targets."""
    payload = {
        "gate_id": gate_id,
        "workspace": ws_name,
        "claim": _norm_claim(claim),
        "floor_usd": floor_usd,
        "targets": sorted(
            [[str(t.get("role")), str(t.get("pointer")), bool(t.get("resolved"))]
             for t in targets]),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _sha256(blob)


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def build_task(ws: Path, draft: Path, gate_id: str, severity: str = "auto") -> dict[str, Any]:
    gate_id = gate_id.upper()
    if gate_id not in GATE_SPECS:
        raise ValueError(
            f"unknown gate {gate_id!r}; known: {', '.join(list_gates())}")
    spec = GATE_SPECS[gate_id]
    ws = ws.expanduser().resolve()
    text = _read_draft(draft)

    claim = _extract_claim(text)
    targets, artifacts = spec["targets"](ws, text)
    ctx = spec["context"](ws, text)
    appl = spec["applicable"](ws, text, severity)
    floor_usd = ctx.get("floor_usd")

    claim_h = claim_hash(claim)
    task_hash = canonical_task_hash(gate_id, claim_h)  # the field the gate binds on
    ptr_hash = pointer_binding_hash(gate_id, ws.name, claim, targets, floor_usd)
    gate_slug = re.sub(r"[^a-z0-9]+", "-", gate_id.lower()).strip("-")
    task_id = f"verify_{ws.name}_{gate_slug}_{task_hash[:12]}"

    unresolved = [t["role"] for t in targets if not t.get("resolved")]
    missing_artifacts = [a["name"] for a in artifacts if not a.get("found")]

    return {
        "schema": SCHEMA_TASK,
        "emitter_version": EMITTER_VERSION,
        "task_id": task_id,
        "task_hash": task_hash,
        "claim_hash": claim_h,
        "pointer_binding_hash": ptr_hash,
        "gate_id": gate_id,
        "check_number": spec.get("check_number"),
        "load_bearing_axis": spec["load_bearing_axis"],
        "satisfiability_before": spec["satisfiability_before"],
        "expected_evidence_class": spec["task_evidence_class"],
        "adjudication_required": True,
        "gate_applicable": bool(appl.get("applicable")),
        "applicability": appl,
        "workspace": ws.name,
        "workspace_path": str(ws),
        "draft": str(draft.expanduser().resolve()) if draft else "",
        "claim": claim,
        "targets": targets,
        "unresolved_target_roles": unresolved,
        "artifacts_to_check": artifacts,
        "missing_artifacts": missing_artifacts,
        "context_refs": {
            "recall_block": spec["recall_block"].format(ws=ws.name),
            "rubric_row": ctx.get("rubric_row"),
            "draft_excerpt": _section(text, "impact") or claim,
            "draft_path": str(draft.expanduser().resolve()) if draft else "",
            "workspace_path": str(ws),
        },
        "receipt_schema": SCHEMA_RECEIPT,
        # union of what verification-receipt-check.py REQUIRES (gate_id/claim/claim_hash/
        # task_hash/author_lane/verifier_lane/verdict/evidence) plus this emitter's local
        # adjudication fields (per_target/cited_file_lines/disconfirming/adjudicator_session).
        "expected_receipt_fields": [
            "schema", "task_hash", "claim", "claim_hash", "gate_id",
            "author_lane", "verifier_lane", "verdict", "evidence", "per_target",
            "cited_file_lines", "disconfirming_evidence_checked",
            "adjudicator_session", "adjudicated_at",
        ],
        "anti_rubber_stamp": (
            "Default verdict is REFUTED. Move a target to CONFIRMED only after independently "
            "opening the cited file:line (or locating the missing datum yourself) and finding "
            "it substantiates the sub-claim. Restating the draft is NOT confirmation. Overall "
            "verdict is CONFIRMED only if EVERY target is CONFIRMED with a real cited file:line."
        ),
        "brief_template": BRIEF_TEMPLATE_REL,
        "emitted_at": _now_iso(),
    }


# ---------------------------------------------------------------------------
# brief rendering
# ---------------------------------------------------------------------------
def _targets_block(task: dict) -> str:
    out: list[str] = []
    for t in task.get("targets", []):
        status = "RESOLVED in draft" if t.get("resolved") else "UNRESOLVED - go find it"
        ptr = t.get("pointer") or "(none - missing from draft)"
        out.append(
            f"- role `{t.get('role')}` [{status}] evidence-class=`{t.get('expected_evidence_class')}`\n"
            f"    pointer: `{ptr}`\n"
            f"    draft says: {t.get('extract') or '(nothing)'}\n"
            f"    your task: {t.get('verify_instruction')}")
    return "\n".join(out) if out else "- (no targets extracted)"


def _artifacts_block(task: dict) -> str:
    arts = task.get("artifacts_to_check", [])
    if not arts:
        return "- (no evidence artifacts cited by the draft)"
    out = []
    for a in arts:
        mark = "FOUND" if a.get("found") else "ABSENT -> auto-REFUTE if the claim rests on it"
        out.append(f"- `{a.get('name')}` [{mark}]")
    return "\n".join(out)


def render_brief(task: dict, template_path: Path | None = None) -> str:
    tpl_path = template_path or (REPO_ROOT / BRIEF_TEMPLATE_REL)
    tpl = tpl_path.read_text(encoding="utf-8")
    ctx = task.get("context_refs", {})
    subs = {
        "{{GATE_ID}}": str(task.get("gate_id", "")),
        "{{LOAD_BEARING_AXIS}}": str(task.get("load_bearing_axis", "")),
        "{{WORKSPACE}}": str(task.get("workspace", "")),
        "{{WORKSPACE_PATH}}": str(task.get("workspace_path", "")),
        "{{DRAFT_PATH}}": str(task.get("draft", "")),
        "{{TASK_ID}}": str(task.get("task_id", "")),
        "{{TASK_HASH}}": str(task.get("task_hash", "")),
        "{{CHECK_NUMBER}}": str(task.get("check_number") or "n/a"),
        "{{CLAIM_HASH}}": str(task.get("claim_hash", "")),
        "{{SATISFIABILITY_BEFORE}}": str(task.get("satisfiability_before", "")),
        "{{RECALL_BLOCK}}": str(ctx.get("recall_block", "")),
        "{{RUBRIC_ROW}}": str(ctx.get("rubric_row", "")),
        "{{CLAIM}}": str(task.get("claim", "")),
        "{{DRAFT_EXCERPT}}": str(ctx.get("draft_excerpt", "")),
        "{{TARGETS_BLOCK}}": _targets_block(task),
        "{{ARTIFACTS_BLOCK}}": _artifacts_block(task),
        "{{RECEIPT_SCHEMA}}": str(task.get("receipt_schema", SCHEMA_RECEIPT)),
    }
    rendered = tpl
    for k, v in subs.items():
        rendered = rendered.replace(k, v)
    return rendered


# ---------------------------------------------------------------------------
# emit to disk
# ---------------------------------------------------------------------------
def _tasks_dir(ws: Path) -> Path:
    return ws / ".auditooor" / "verification_tasks"


def emit(ws: Path, draft: Path, gate_id: str, severity: str = "auto",
         out: Path | None = None, render: bool = False) -> dict[str, Any]:
    task = build_task(ws, draft, gate_id, severity)
    d = _tasks_dir(ws.expanduser().resolve())
    d.mkdir(parents=True, exist_ok=True)
    task_path = out.expanduser().resolve() if out else (d / f"{task['task_id']}.json")
    task_path.parent.mkdir(parents=True, exist_ok=True)
    task_path.write_text(json.dumps(task, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = {"task": task, "task_path": str(task_path)}
    if render:
        brief = render_brief(task)
        brief_path = task_path.with_suffix(".brief.md")
        brief_path.write_text(brief, encoding="utf-8")
        result["brief_path"] = str(brief_path)
    # append a compact index row for downstream consumers.
    idx = d / "index.jsonl"
    row = {"task_id": task["task_id"], "task_hash": task["task_hash"],
           "gate_id": task["gate_id"], "draft": task["draft"],
           "gate_applicable": task["gate_applicable"], "emitted_at": task["emitted_at"]}
    with idx.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return result


# ---------------------------------------------------------------------------
# receipt adjudication (the BACK half: gate greens on the receipt, not on prose)
# ---------------------------------------------------------------------------
def validate_receipt(task: dict, receipt: dict) -> dict[str, Any]:
    """Adjudicate a returned verify-lane receipt against the task it claims to answer.

    A gate may GREEN only when `greened` is True: the receipt binds to THIS task-hash, is a
    well-formed verification_receipt, carries an adjudicator session (a distinct session ran),
    the overall verdict is CONFIRMED, and EVERY task target has a per_target CONFIRMED verdict
    with a real (non-draft) cited file:line, plus non-empty disconfirming-evidence. Anything
    else -> not greened (the receipt itself may still be `accepted` = validly bound but
    REFUTED / insufficient)."""
    reasons: list[str] = []

    if not isinstance(receipt, dict):
        return {"accepted": False, "greened": False, "reasons": ["receipt is not an object"]}
    if receipt.get("schema") != SCHEMA_RECEIPT:
        reasons.append(f"schema != {SCHEMA_RECEIPT}")
    rhash = str(receipt.get("task_hash") or "")
    thash = str(task.get("task_hash") or "")
    bound = bool(thash) and rhash == thash
    if not bound:
        reasons.append("task_hash does not bind to this task (receipt not for this claim)")
    if receipt.get("gate_id") and receipt.get("gate_id") != task.get("gate_id"):
        reasons.append("gate_id mismatch")
    session = str(receipt.get("adjudicator_session") or "").strip()
    if not session:
        reasons.append("no adjudicator_session (cannot prove a distinct session ran)")
    verdict = str(receipt.get("verdict") or "").upper()
    if verdict not in _RECEIPT_VERDICTS:
        reasons.append(f"overall verdict {verdict!r} not in {sorted(_RECEIPT_VERDICTS)}")

    accepted = bound and bool(session) and receipt.get("schema") == SCHEMA_RECEIPT

    per = receipt.get("per_target") or {}
    per_target_ok = True
    required_roles = [t.get("role") for t in task.get("targets", [])]
    for role in required_roles:
        pt = per.get(role) if isinstance(per, dict) else None
        if not isinstance(pt, dict):
            per_target_ok = False
            reasons.append(f"target {role!r}: no per_target verdict")
            continue
        pv = str(pt.get("verdict") or "").upper()
        if pv != "CONFIRMED":
            per_target_ok = False
            reasons.append(f"target {role!r}: verdict {pv or 'MISSING'} (not CONFIRMED)")
            continue
        cfl = str(pt.get("cited_file_line") or "").strip()
        if not cfl or cfl.startswith("draft:") or not _SOURCE_CITED_RE.search(cfl):
            per_target_ok = False
            reasons.append(f"target {role!r}: CONFIRMED without a real source file:line")

    disconfirming = receipt.get("disconfirming_evidence_checked")
    anti_stamp_ok = isinstance(disconfirming, list) and len(disconfirming) > 0
    if not anti_stamp_ok:
        reasons.append("no disconfirming_evidence_checked (rubber-stamp risk)")

    greened = bool(accepted and verdict == "CONFIRMED" and required_roles
                   and per_target_ok and anti_stamp_ok)
    return {
        "accepted": accepted,
        "bound": bound,
        "overall_verdict": verdict,
        "per_target_ok": per_target_ok,
        "anti_rubber_stamp_ok": anti_stamp_ok,
        "greened": greened,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", "--ws", dest="workspace", type=Path)
    ap.add_argument("--draft", type=Path)
    ap.add_argument("--gate", default="ABSOLUTE-USD-DERIVATION")
    ap.add_argument("--severity", default="auto")
    ap.add_argument("--emit", action="store_true", help="write the task sidecar to disk")
    ap.add_argument("--out", type=Path, help="explicit task sidecar path (implies --emit)")
    ap.add_argument("--render-brief", action="store_true",
                    help="also render the verify-lane brief next to the task")
    ap.add_argument("--check-receipt", type=Path,
                    help="adjudicate a returned receipt JSON (needs --task)")
    ap.add_argument("--task", type=Path, help="task JSON for --check-receipt")
    ap.add_argument("--list-gates", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.list_gates:
        for g in list_gates():
            s = GATE_SPECS[g]
            print(f"{g}  axis={s['load_bearing_axis']}  "
                  f"satisfiability_before={s['satisfiability_before']}")
        return 0

    if args.check_receipt:
        if not args.task or not args.task.is_file():
            print("[emit-verification-task] --check-receipt requires --task <task.json>")
            return 2
        task = json.loads(args.task.read_text(encoding="utf-8"))
        receipt = json.loads(args.check_receipt.read_text(encoding="utf-8"))
        res = validate_receipt(task, receipt)
        if args.json:
            print(json.dumps(res, indent=2, sort_keys=True))
        else:
            print(f"[emit-verification-task] greened={res['greened']} "
                  f"accepted={res['accepted']} verdict={res.get('overall_verdict')}")
            for r in res["reasons"]:
                print(f"  - {r}")
        return 0 if res["greened"] else 1

    if not args.workspace or not args.draft:
        print("[emit-verification-task] need --workspace and --draft (or --list-gates / "
              "--check-receipt)")
        return 2
    if not args.draft.is_file():
        print(f"[emit-verification-task] no such draft: {args.draft}")
        return 2

    do_emit = bool(args.emit or args.out or args.render_brief)
    if do_emit:
        res = emit(args.workspace, args.draft, args.gate, args.severity,
                   out=args.out, render=bool(args.render_brief))
        task = res["task"]
    else:
        task = build_task(args.workspace, args.draft, args.gate, args.severity)
        res = {"task": task, "task_path": None}

    if args.json:
        print(json.dumps(task, indent=2, sort_keys=True))
    else:
        print(f"[emit-verification-task] {task['gate_id']} axis={task['load_bearing_axis']} "
              f"applicable={task['gate_applicable']}")
        print(f"  task_id:   {task['task_id']}")
        print(f"  task_hash: {task['task_hash']}")
        print(f"  claim:     {task['claim'][:120]}")
        for t in task["targets"]:
            print(f"  target {t['role']:<18} resolved={t['resolved']!s:<5} "
                  f"pointer={t['pointer']}")
        if task["missing_artifacts"]:
            print(f"  MISSING artifacts: {', '.join(task['missing_artifacts'])}")
        if res.get("task_path"):
            print(f"  wrote: {res['task_path']}")
        if res.get("brief_path"):
            print(f"  brief: {res['brief_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
