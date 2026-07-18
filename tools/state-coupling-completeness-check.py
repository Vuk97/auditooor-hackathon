#!/usr/bin/env python3
"""state-coupling-completeness-check.py - audit-complete signal for the State-Coupling
Graph (SCG) dimension. Mirrors coupled-state-completeness-check.py, but reads the
frozen state_coupling_edge.v1 artifact and gates ONLY on PROMOTABLE semantic-ssa edges.

An edge is OPEN when it is promotable (persistent-state / VMF-grounded with writers -
i.e. citable, not a syntactic-advisory prompt) AND lacks a probe verdict. Syntactic /
non-promotable edges are advisory and NEVER gate (they cannot false-RED the audit).

Writes:
  <ws>/.auditooor/state_coupling_completeness.json            (verdict + open, ALWAYS)
  <ws>/.auditooor/state_coupling_completeness_pass.marker     (ONLY when 0 open)

Probe verdicts: an edge is PROBED if its evidence.probe_verdict is set OR
<ws>/.auditooor/state_coupling_probes.jsonl carries {edge_id, verdict} for it.

ADVISORY-FIRST: WARN by default (rc 0 even with open edges). The legacy
AUDITOOOR_L37_STRICT=1 environment preserves its existing open-edge gate. Explicit
--strict additionally requires a non-degraded semantic substrate and typed evidence
for terminal closure and probes.

Usage: python3 tools/state-coupling-completeness-check.py --workspace <ws> [--json] [--no-emit] [--strict]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent

_TERMINAL_EMPTY_STATUSES = {
    "clean", "cited-empty", "not-applicable", "n/a", "na",
}
_DEGRADED_STATUSES = {
    "degraded", "failed", "error", "blocked", "timeout", "missing",
    "starved", "unresolved", "unknown", "incomplete",
}
_EVIDENCE_KEYS = (
    "source_refs", "source_cites", "citations", "evidence", "grounding",
    "rationale", "note", "proof", "artifact", "evidence_refs",
)


def _load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _non_placeholder(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in {
            "", "n/a", "na", "none", "null", "unknown", "tbd", "todo", "?",
        }
    return value not in (None, False, [], {})


def _has_evidence(record: dict) -> bool:
    """Require a non-placeholder citation/proof, not merely a status word."""
    if not isinstance(record, dict):
        return False
    for key in _EVIDENCE_KEYS:
        value = record.get(key)
        if isinstance(value, (list, tuple)):
            if any(_non_placeholder(item) for item in value):
                return True
        elif isinstance(value, dict):
            if _has_evidence(value):
                return True
        elif _non_placeholder(value):
            return True
    return False


def _terminal_empty_closure(ws: Path) -> tuple[str | None, str | None]:
    """Find a typed, cited empty/N/A result for a zero-row strict run."""
    aud = ws / ".auditooor"
    paths = (
        aud / "state_coupling_terminal.json",
        aud / "state_coupling_conserved_accounting.json",
        aud / "state_coupling_completeness.json",
    )
    for path in paths:
        if not path.is_file():
            continue
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        status = str(
            rec.get("terminal_status") or rec.get("substrate_status") or
            rec.get("assessment_status") or rec.get("status") or
            rec.get("verdict") or ""
        ).strip().lower()
        if status in _TERMINAL_EMPTY_STATUSES and _has_evidence(rec):
            return status, str(path)
    return None, None


def _strict_substrate_issues(ws: Path, edges: list[dict], promotable: list[dict],
                             open_edges: list[dict]) -> list[str]:
    """Check the producer contract that legacy advisory mode intentionally skips."""
    issues: list[str] = []
    semantic_edges = [e for e in edges if e.get("confidence") == "semantic-ssa"]
    syntactic_edges = [e for e in edges if e.get("confidence") != "semantic-ssa"]
    if syntactic_edges and not semantic_edges:
        issues.append("semantic substrate missing: input contains syntactic-only edges")

    acct_path = ws / ".auditooor" / "state_coupling_conserved_accounting.json"
    acct = {}
    if acct_path.is_file():
        try:
            loaded = json.loads(acct_path.read_text(encoding="utf-8"))
            acct = loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            issues.append("semantic substrate accounting is unreadable")
    degraded = bool(
        acct.get("degraded") or acct.get("dataflow_degraded") or
        acct.get("slice_go_arm_degraded") or acct.get("slice_go_degraded_inscope") or
        acct.get("slither_degraded_inscope")
    )
    resolution = str(acct.get("slice_resolution_status") or "").strip().lower()
    if resolution in _DEGRADED_STATUSES or resolution.startswith("0-go-feeder-degraded"):
        degraded = True
    if degraded:
        issues.append("semantic substrate is degraded")

    # A semantic row is enough to establish the substrate for a non-empty run. An
    # empty run needs an explicit typed closure; otherwise zero rows are starvation.
    if not edges:
        status, path = _terminal_empty_closure(ws)
        if not status:
            issues.append("semantic substrate missing: no edges and no cited empty/N/A closure")
        else:
            # Keep the path in the failure/report vocabulary without treating its
            # presence as a hand-written green marker.
            _ = path
    elif not semantic_edges:
        issues.append("semantic substrate missing: no semantic-ssa edge")
    elif not promotable and not open_edges:
        status, _path = _terminal_empty_closure(ws)
        if not status:
            issues.append("semantic terminal closure is untyped or uncited")
    return issues


def _probe_evidence_backed(edge: dict) -> bool:
    evidence = edge.get("evidence") or {}
    if not evidence.get("probe_verdict"):
        return True
    probe = {
        key: evidence.get(key)
        for key in ("probe_evidence", "probe_rationale", "probe_source_refs",
                    "source_refs", "source_cites", "rationale", "note", "proof")
    }
    return _has_evidence(probe)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-emit", action="store_true",
                    help="use the existing edges (do not re-emit the SCG)")
    ap.add_argument("--strict", action="store_true",
                    help="fail on open rows, starved/degraded semantic input, or uncited closure")
    a = ap.parse_args(argv)
    ws = a.workspace.resolve()
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    scs = _load_module("state_coupling_schema", "state_coupling_schema.py")

    if not a.no_emit:
        try:
            scg = _load_module("state_coupling_graph", "state-coupling-graph.py")
            scg.main(["--workspace", str(ws), "--emit"])
        except Exception as exc:  # noqa: BLE001 - surface, never fake a clean pass
            print(f"[state-coupling-completeness-check] WARN: SCG emit failed: {exc}",
                  file=sys.stderr)

    edges = scs.read_edges(ws)
    # probed set: from a probes sidecar (edge_id -> verdict + RATIONALE). A probe verdict
    # CLOSES a promotable coupled-state lead, so it must not be hand-greenable: a bare
    # {"edge_id": X, "verdict": "ok"} with NO rationale is a silent hand-green (the #1 sin).
    # Require a citable WHY (note / evidence / source_cites / rationale), mirroring the
    # disposition-rationale gate (Check #146). Rationale-less verdicts are IGNORED -> the edge
    # stays OPEN and the gate fails-closed under STRICT until a real cited probe lands.
    probed: set[str] = set()
    invalid_probe_ids: set[str] = set()
    probes = aud / "state_coupling_probes.jsonl"
    _rationale_keys = ("note", "evidence", "source_cites", "source_refs",
                       "citations", "rationale", "proof", "evidence_refs")
    if probes.is_file():
        for l in probes.read_text(encoding="utf-8", errors="replace").splitlines():
            l = l.strip()
            if not l:
                continue
            try:
                p = json.loads(l)
            except ValueError:
                continue
            edge_id = p.get("edge_id")
            has_rationale = any(p.get(k) for k in _rationale_keys)
            if edge_id and (p.get("verdict") or p.get("probe_verdict")) and has_rationale:
                probed.add(edge_id)
            elif edge_id and (p.get("verdict") or p.get("probe_verdict")):
                invalid_probe_ids.add(str(edge_id))

    # --- SCG env-gated subtype arms: advisory-first demotion (2026-07-10) ------------------
    # check_state_coupling now sets SCG_XCONTRACT/SCG_INTERRUPTION/SCG_SHARED_CURSOR=1 so the 3
    # subtype arms EMIT and feed the hunt as advisory review candidates. But they must NOT gate
    # (false-RED) a green ws by default. The xcontract "12th kind" is the hazard: it sets
    # evidence.promotable=True UNCONDITIONALLY (state-coupling-graph.py:1144 -> S is a subset of
    # state_vars by construction of _xc_split_cells, so the all() can never be False), yet it is
    # advisory-first (verdict="needs-fuzz", auto_credit=False, advisory=True). Because this gate
    # keys ONLY on evidence.promotable (never on verdict/advisory/auto_credit), an xcontract edge
    # would gate identically to a CONFIRMED base conserved-with edge. So demote the 3 arms to
    # advisory unless the dedicated opt-in AUDITOOOR_SCG_SUBTYPES_STRICT=1 is set. PROVABLY
    # DISJOINT from every base always-on gating edge: base same-contract conserved-with has NO
    # subtype (tier="value-conservation"); base co-accumulation has subtype="co-accumulation";
    # only the xcontract arm emits subtype/tier=="cross-contract-conservation". Fleet-measured
    # 2026-07-10: new_promotable_from_subtypes == 0 on nuva/morpho/etherfi/ssv-network.
    # R1 handle-freshness (14th kind) joins the advisory-first subtype arms: emitted for the hunt +
    # exploit-queue but demoted from gating unless its DEDICATED early-adopter enforce env is set
    # (AUDITOOOR_HANDLE_FRESHNESS_ENFORCE) - the "advisory-first BUILD but ENFORCED" contract. The
    # TERMINAL flip (design-report convention, L37-strict after >=3 clean ws) is a one-line removal
    # of "stale-handle-after-recycle" from this tuple, after which a strong-witness edge flows the
    # BASE _promotable path and fails-closed under plain AUDITOOOR_L37_STRICT like a conserved-with.
    _SCG_SUBTYPE_KINDS = ("interruption", "freshness-coupled-to-shared-cursor",
                          "stale-handle-after-recycle")

    def _is_env_gated_scg_subtype(e):
        ev = e.get("evidence", {}) or {}
        # xcontract (A13) - the ONLY subtype arm that reuses a base gating kind (conserved-with),
        # so disambiguate strictly by subtype/tier, never by kind alone.
        if e.get("kind") == "conserved-with" and (
                ev.get("subtype") == "cross-contract-conservation"
                or ev.get("tier") == "cross-contract-conservation"):
            return True
        # interruption + shared-cursor carry a base-disjoint kind of their own; both are already
        # non-promotable by construction - this branch is defense-in-depth so a future promotable
        # flip cannot silently start gating without the opt-in.
        if e.get("kind") in _SCG_SUBTYPE_KINDS:
            return True
        return False

    def _promotable(e):
        if _is_env_gated_scg_subtype(e):
            opt_in = os.environ.get("AUDITOOOR_SCG_SUBTYPES_STRICT") == "1"
            # DEDICATED early-adopter enforce env for the R1 handle-freshness arm (backlog:156):
            # under it a strong-witness (3-leg) stale-handle-after-recycle edge un-demotes to an
            # open promotable edge and fails-closed - the arm is ENFORCED, not left advisory.
            if e.get("kind") == "stale-handle-after-recycle" and \
                    os.environ.get("AUDITOOOR_HANDLE_FRESHNESS_ENFORCE") == "1":
                opt_in = True
            if not opt_in:
                return False  # advisory-first: emitted for the hunt, but never gates by default
        return bool(e.get("evidence", {}).get("promotable"))

    def _probed(e):
        return bool(e.get("evidence", {}).get("probe_verdict")) or \
            e.get("edge_id") in probed

    # --- AUTO-CLOSE proven-conserved conservation-class edges (co-accumulation v2 GATE fix,
    # 2026-07-10) -------------------------------------------------------------------------
    # THE FLEET-RED ROOT: the Track-1 dataflow broadening promotes every ERC20 mint/burn
    # balanceOf<->totalSupply co-accumulation to promotable=True (state-coupling-graph.py
    # _coaccum_promotes:1983). This gate computed open_edges keying ONLY on promotable (below),
    # NEVER on the partial-flush VIOLATOR proof (evidence.nviol). So a CLEAN ERC20 - where v1's
    # conserving-transfer exclusion (_coaccum_violators) correctly drove nviol=0 - STILL counted
    # as an open edge -> fail-state-coupling-open -> rc=1 under AUDITOOOR_L37_STRICT. v1 changed
    # only nviol, which this gate ignored, so it had no effect on rc. This is the GATE half.
    #
    # CORRECT SEMANTICS (verifier direction): fail-closed on a SUSPECTED partial-flush
    # (nviol>0, a real one-sided / unbalanced writer that desyncs sum(member) from the
    # aggregate), NOT on the mere existence of a PROVEN-conserved coupled edge. A co-accumulation
    # / conserved-with edge that carries a partial-flush conservation proof (evidence.nviol) with
    # ZERO violators has every writer of the coupled set either fully coupling BOTH cells or
    # value-conserving (net-zero member-to-member transfer). sum(member) == aggregate is PROVEN
    # held, so the edge is proven-conserved - CLOSED/probed, not an open probe obligation.
    #
    # SCOPED to the conservation/co-accumulation edge CLASS (the sum(member)==aggregate teeth):
    # evidence.nviol is emitted ONLY by the co-accumulation (subtype="co-accumulation") and the
    # cross-contract-conservation arms (kind="conserved-with" both). The ordering / freshness /
    # interruption / base value-conservation kinds carry NO nviol conservation proof, so they are
    # NEVER auto-closed here - they stay open and fail-closed exactly as before (per the task:
    # "do NOT auto-close other coupled-state kinds ... that lack an nviol conservation proof").
    # Only an edge with nviol>0 stays open to fail strict -> the partial-flush teeth are intact.
    def _conservation_proven_closed(e):
        if e.get("kind") != "conserved-with":
            return False  # only the conservation kind bears the sum(member)==aggregate teeth
        nviol = (e.get("evidence", {}) or {}).get("nviol")
        if nviol is None:
            return False  # no partial-flush conservation proof present -> never auto-close
        try:
            return int(nviol) == 0
        except (TypeError, ValueError):
            return False

    promotable = [e for e in edges if _promotable(e)]
    auto_closed = [e for e in promotable
                   if not _probed(e) and _conservation_proven_closed(e)]
    open_edges = [e for e in promotable
                  if not _probed(e) and not _conservation_proven_closed(e)]
    advisory_edges = [e for e in edges if not _promotable(e)]

    env_strict = os.environ.get("AUDITOOOR_L37_STRICT") == "1"
    strict = bool(a.strict or env_strict)
    explicit_strict_issues = (
        _strict_substrate_issues(ws, edges, promotable, open_edges)
        if a.strict else []
    )
    if a.strict and invalid_probe_ids:
        explicit_strict_issues.append(
            "unresolved required probes: missing rationale/evidence for "
            + ", ".join(sorted(invalid_probe_ids)[:8])
        )
    strict_failures = list(explicit_strict_issues)
    if a.strict:
        for edge in promotable:
            if not _probe_evidence_backed(edge):
                strict_failures.append(
                    f"unresolved required probe: {edge.get('edge_id', '?')} has an uncited probe verdict")
    if strict and open_edges:
        strict_failures.insert(0, f"{len(open_edges)} promotable edge(s) remain open")
    if strict_failures:
        verdict = "fail-state-coupling-open" if open_edges else "fail-state-coupling-strict"
    elif open_edges:
        verdict = "warn-state-coupling-open"
    else:
        verdict = "pass-state-coupling-completeness"

    # UNCOVERED-SURFACE worklist (operator-demanded 2026-07-08): the failing gate must NAME
    # what to audit, not just a count. For each open edge, carry the actionable probe target:
    # the coupled cells, the impact class, the obligation (the human probe question), and the
    # VIOLATORS with file:line (the exact site that mutates one cell and OMITS the other).
    # audit-next-step surfaces this; a hunter reads it as "probe <fn>@<file:line>: does it move
    # <cell_a> and <cell_b> together?". Without this the actionable data died at the gate.
    def _worklist_row(e: dict) -> dict:
        ev = e.get("evidence", {}) or {}
        viols = []
        for v in (e.get("violators") or [])[:8]:
            if not isinstance(v, dict):
                continue
            loc = v.get("file", "?")
            if v.get("line"):
                loc = f"{loc}:{v['line']}"
            viols.append({
                "site": loc,
                "fn": v.get("fn", "?"),
                "mutates": v.get("mutates") or [],
                "omits": v.get("omits") or [],
            })
        return {
            "edge_id": e.get("edge_id"),
            "kind": e.get("kind"),
            "language": e.get("language"),
            "confidence": e.get("confidence"),
            "tier": ev.get("tier"),
            "cell_a": e.get("cell_a"),
            "cell_b": e.get("cell_b"),
            "impact_class": e.get("impact_class"),
            "probe_question": e.get("obligation"),
            "violators": viols,
        }

    open_details = [_worklist_row(e) for e in open_edges][:50]
    # R1 handle-freshness UN-ANALYZED flag (anti-silent-suppression): the arm persists
    # state_coupling_handle_freshness.json during --emit; when it found a recyclable-handle holder in
    # a language it could NOT analyze (parser gap / unsupported language) it sets unanalyzed_inscope.
    # Surface it so check_state_coupling can fail-closed under the dedicated enforce env - a STARVED
    # arm must not masquerade as a clean 0. Absent/stale-safe: the sidecar is rewritten every --emit.
    hf_unanalyzed = False
    hf_examples: list = []
    hf_p = aud / "state_coupling_handle_freshness.json"
    if hf_p.is_file():
        try:
            _hf = json.loads(hf_p.read_text(encoding="utf-8"))
            hf_unanalyzed = bool(_hf.get("unanalyzed_inscope"))
            hf_examples = _hf.get("unanalyzed_examples") or []
        except (OSError, ValueError):
            hf_unanalyzed = False
    result = {
        "schema_version": "auditooor.state_coupling_completeness_signal.v1",
        "verdict": verdict,
        "total_edges": len(edges),
        "promotable_edges": len(promotable),
        "advisory_edges": len(advisory_edges),
        # PROVEN-conserved conservation-class edges (nviol==0) auto-closed at the gate: NOT
        # open (proven-conserved, not a probe obligation). Surfaced for anti-silent-suppression
        # so the drain is auditable - a promotable conservation edge that vanished from open_edges
        # is accounted here, not silently dropped.
        "auto_closed_conserved_edges": len(auto_closed),
        "open_edges": len(open_edges),
        "strict": strict,
        "explicit_strict": bool(a.strict),
        "advisory": not strict,
        "strict_failures": strict_failures,
        "invalid_probe_ids": sorted(invalid_probe_ids),
        "open_edge_ids": [e["edge_id"] for e in open_edges][:50],
        "open_edge_details": open_details,
        # R1 handle-freshness: a recyclable-handle holder in an unsupported language the arm could
        # NOT resolve. check_state_coupling reads this and fails-closed under the dedicated enforce
        # env so a STARVED handle-freshness arm cannot masquerade as a clean 0.
        "handle_freshness_unanalyzed_inscope": hf_unanalyzed,
        "handle_freshness_unanalyzed_examples": hf_examples[:8],
    }
    (aud / "state_coupling_completeness.json").write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    marker = aud / "state_coupling_completeness_pass.marker"
    if not open_edges and not strict_failures:
        marker.write_text(verdict + "\n", encoding="utf-8")
    elif marker.is_file():
        marker.unlink()  # stale pass -> remove so the runbook step goes RED

    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if strict_failures:
            tag = "FAIL" if strict else "WARN"
        else:
            tag = "WARN" if open_edges else "PASS"
        print(f"[state-coupling-completeness-check] {tag}: {len(open_edges)} open / "
              f"{len(promotable)} promotable / {len(edges)} edge(s) "
              f"(strict={strict}, advisory={not strict})", file=sys.stderr)
        for failure in strict_failures:
            print(f"  strict: {failure}", file=sys.stderr)
        # Name the UNCOVERED SURFACE - what to audit, not just a count.
        if open_details:
            print("  UNCOVERED COUPLED-STATE SURFACE (probe each; a violator that moves one "
                  "cell and OMITS the other is the desync):", file=sys.stderr)
            for d in open_details[:20]:
                print(f"  - [{d['kind']}] {d['cell_a']} <-> {d['cell_b']}  "
                      f"({d['language']}/{d['confidence']}, impact={d['impact_class']})",
                      file=sys.stderr)
                for v in d["violators"][:4]:
                    om = ",".join(v["omits"]) or "-"
                    print(f"      violator {v['fn']} @ {v['site']}  "
                          f"mutates={','.join(v['mutates']) or '-'}  OMITS={om}",
                          file=sys.stderr)
                if d.get("probe_question"):
                    print(f"      probe: {d['probe_question']}", file=sys.stderr)
    return 1 if strict_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
