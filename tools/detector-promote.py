#!/usr/bin/env python3
"""detector-promote.py — propose tier promotions/demotions (Phase 12 of PR #84).

Companion to `tools/detector-tier.sh` — that script performs actual writes.
This script READS ONLY and emits a Markdown proposal to
`docs/archive/TIER_PROMOTION_PROPOSALS.md`. The user (or a separate tool) applies the
bumps.

Evidence criteria (deliberately simple — see ARCHITECTURE.md):
  * Promote D -> E  if >= 5 TP AND 0 FP AND fixture currently present.
  * Promote E -> S  if >= 10 TP across 2+ distinct engagements AND <= 1 FP total.
  * Demote to D    if >= 3 FP AND TP:FP ratio < 2:1 AND currently above D.

Inputs:
  detectors/_hits_ledger.yaml           historical tp/fp per detector name
  detectors/_tier_registry.yaml         canonical tier assignments
  reference/patterns.dsl/*.yaml         per-pattern `tier:` fallback
  detectors/rust_wave1/test_fixtures/   `<name>_positive.rs` presence = fixture OK

Output:
  docs/archive/TIER_PROMOTION_PROPOSALS.md
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("[error] PyYAML required: pip3 install pyyaml\n")
    sys.exit(1)


ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = ROOT / "detectors" / "_hits_ledger.yaml"
REGISTRY_PATH = ROOT / "detectors" / "_tier_registry.yaml"
PATTERNS_DIR = ROOT / "reference" / "patterns.dsl"
FIXTURES_DIR = ROOT / "detectors" / "rust_wave1" / "test_fixtures"
OUT_PATH = ROOT / "docs" / "TIER_PROMOTION_PROPOSALS.md"


def _load_detectorization_gate_summary(workspace: Path | None) -> dict[str, dict[str, int]]:
    if workspace is None:
        return {}
    inventory = workspace / ".auditooor" / "corpus_detectorization_inventory.json"
    if not inventory.is_file():
        return {}
    try:
        payload = json.loads(inventory.read_text(encoding="utf-8"))
    except Exception:
        return {}
    rows = payload.get("rows") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return {}
    summary: dict[str, dict[str, int]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        lane = str(row.get("detector_or_lane") or "").strip()
        if not lane:
            continue
        contract = row.get("impact_contract_summary")
        if not isinstance(contract, dict) or not contract.get("required"):
            continue
        lane_summary = summary.setdefault(lane, {"reportable_rows": 0, "mapped_rows": 0, "blocked_rows": 0})
        lane_summary["reportable_rows"] += 1
        if contract.get("status") == "mapped" and str(contract.get("selected_impact") or "").strip():
            lane_summary["mapped_rows"] += 1
        else:
            lane_summary["blocked_rows"] += 1
    return summary


def _load_yaml(path: Path, default):
    if not path.exists():
        return default
    try:
        return yaml.safe_load(path.read_text()) or default
    except Exception as e:
        sys.stderr.write(f"[warn] could not parse {path}: {e}\n")
        return default


def _fixture_present(name: str) -> bool:
    """A detector name is considered fixture-covered if a matching
    `<name>_positive.rs` exists under rust_wave1/test_fixtures/."""
    if not FIXTURES_DIR.exists():
        return False
    # hits-ledger names often use dashes; fixture filenames use underscores.
    snake = name.replace("-", "_")
    return (FIXTURES_DIR / f"{snake}_positive.rs").exists()


def _pattern_tier(name: str) -> str | None:
    """Fallback: read tier from reference/patterns.dsl/<name>.yaml if present."""
    p = PATTERNS_DIR / f"{name}.yaml"
    if not p.exists():
        return None
    data = _load_yaml(p, {})
    t = data.get("tier") if isinstance(data, dict) else None
    return t if t in ("S", "E", "A", "B", "D") else None


def _current_tier(name: str, registry_tiers: dict) -> str:
    entry = registry_tiers.get(name)
    # Recognize the full tier alphabet so A/B-tier detectors don't get
    # silently bucketed as D and surfaced as fresh D->E promotion candidates.
    if entry and entry.get("tier") in ("S", "E", "A", "B", "D"):
        return entry["tier"]
    pt = _pattern_tier(name)
    return pt if pt else "D"


def _distinct_engagements(entry: dict) -> int:
    catches = entry.get("real_catches") or []
    return len({c.get("workspace") for c in catches if c.get("workspace")})


# Stateful fields demanded by KNOWN_LIMITATIONS_BURNDOWN_MAP.json rows
# P0-7 / P1-6 / P1-7. A factory-pool detector must declare these on its
# registry row before the promotion path can emit a medium_shaped_unsubmitted
# decision (i.e. before claim-side severity gates can run).
_FACTORY_STATEFUL_FIELDS = (
    "entrypoint",
    "invalid_config",
    "tracked_pool",
    "liquidity_acceptance",
    "downstream_liveness",
    "conservative_severity_state",
)


def _check_factory_pool_state_flow(detector_row: dict, registry: dict, hits_ledger: dict) -> str:
    """Stateful-gate decision for factory->pool->liveness detectors.

    detector_row is the registry-tier entry (a dict from registry["tiers"][name]);
    the 6 fields below must be populated on it for a Medium-shaped decision to
    be emitted. registry/hits_ledger are passed in for future cross-checks
    (e.g. distinct-engagement enforcement on Medium claims).

    Returns one of:
      - "medium_shaped_unsubmitted"  all 6 fields present and well-typed,
                                     factory + pool + liveness chain expressed.
      - "low_shaped_unsubmitted"     >=1 but <6 fields present (partial chain).
      - "not_factory_shape"          0 fields present; caller falls through to
                                     the standard TP/FP-based gate.

    NO FABRICATION: this function only reads what was authored on the registry
    row. Missing/malformed fields demote the decision; they do not get
    silently filled in.
    """
    if not isinstance(detector_row, dict):
        return "not_factory_shape"

    present = {}
    for fld in _FACTORY_STATEFUL_FIELDS:
        val = detector_row.get(fld)
        if val is None:
            continue
        # Type checks per field — must match the burndown-map contract.
        if fld == "liquidity_acceptance":
            if not isinstance(val, bool):
                continue
        elif fld == "downstream_liveness":
            # Function chain: list of strings (e.g. ["swap","_invariant"]).
            if not (isinstance(val, list) and val and all(isinstance(x, str) and x for x in val)):
                continue
        else:
            # entrypoint / invalid_config / tracked_pool / conservative_severity_state
            # are non-empty strings.
            if not (isinstance(val, str) and val.strip()):
                continue
        present[fld] = val

    if not present:
        return "not_factory_shape"

    # All 6 must be present AND the conservative severity state must be
    # explicit (Medium/Low/etc) for medium-shaped emission.
    if len(present) == len(_FACTORY_STATEFUL_FIELDS):
        sev_state = present["conservative_severity_state"].strip().lower()
        if sev_state in ("medium", "med", "low", "informational", "info"):
            # Medium-shaped only when severity-state is the conservative
            # Medium/Low band; Critical/High require independent proof gates
            # outside this stateful check.
            return "medium_shaped_unsubmitted"
    return "low_shaped_unsubmitted"


def build_proposals(workspace: Path | None = None):
    ledger = _load_yaml(LEDGER_PATH, {"detectors": {}})
    registry = _load_yaml(REGISTRY_PATH, {"tiers": {}})
    det_ledger = (ledger.get("detectors") or {})
    registry_tiers = (registry.get("tiers") or {})

    gate_summary = _load_detectorization_gate_summary(workspace)
    promote_de, promote_es, demote = [], [], []
    stateful_decisions: list[dict] = []

    # Iterate over the union of ledger and registry names so detectors with no
    # tp/fp history but a populated registry row (the common factory case)
    # still get evaluated by the stateful gate.
    seen: set[str] = set()
    names = list(det_ledger.keys()) + [n for n in registry_tiers.keys() if n not in det_ledger]
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        entry = det_ledger.get(name) or {}
        reg_row = registry_tiers.get(name) or {}

        tp = int(entry.get("tp", 0) or 0)
        fp = int(entry.get("fp", 0) or 0)
        engagements = _distinct_engagements(entry)
        cur = _current_tier(name, registry_tiers)
        fx = _fixture_present(name)

        # ---- Stateful factory-pool gate (runs BEFORE TP/FP promote logic) ----
        decision = _check_factory_pool_state_flow(reg_row, registry, det_ledger)
        if decision != "not_factory_shape":
            stateful_decisions.append({
                "name": name,
                "decision": decision,
                "current_tier": cur,
                "tp": tp, "fp": fp,
                "fixture": fx,
                "entrypoint": reg_row.get("entrypoint"),
                "invalid_config": reg_row.get("invalid_config"),
                "tracked_pool": reg_row.get("tracked_pool"),
                "liquidity_acceptance": reg_row.get("liquidity_acceptance"),
                "downstream_liveness": reg_row.get("downstream_liveness"),
                "conservative_severity_state": reg_row.get("conservative_severity_state"),
            })
            # If medium_shaped_unsubmitted, do NOT also emit a stale TP/FP
            # demotion: the stateful claim is the canonical signal.
            if decision == "medium_shaped_unsubmitted":
                continue

        # D -> E
        if cur == "D" and tp >= 5 and fp == 0 and fx:
            promote_de.append({
                "name": name, "tp": tp, "fp": fp,
                "engagements": engagements, "fixture": fx,
                "impact_gate": gate_summary.get(name, {}),
            })

        # E -> S (requires >= 2 distinct engagements in real_catches)
        elif cur == "E" and tp >= 10 and engagements >= 2 and fp <= 1:
            promote_es.append({
                "name": name, "tp": tp, "fp": fp,
                "engagements": engagements, "fixture": fx,
                "impact_gate": gate_summary.get(name, {}),
            })

        # Demote (anything currently above D that went noisy)
        if cur != "D" and fp >= 3 and (tp / max(fp, 1)) < 2:
            ratio = f"{tp}:{fp}"
            demote.append({
                "name": name, "tp": tp, "fp": fp,
                "ratio": ratio, "current_tier": cur,
            })

    return promote_de, promote_es, demote, stateful_decisions


def _table(rows, headers):
    if not rows:
        return "_(none)_\n"
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(r[h]) for h in headers) + " |")
    return "\n".join(out) + "\n"


def _impact_gate_label(row: dict) -> str:
    gate = row.get("impact_gate") if isinstance(row.get("impact_gate"), dict) else {}
    reportable = int(gate.get("reportable_rows", 0) or 0)
    blocked = int(gate.get("blocked_rows", 0) or 0)
    mapped = int(gate.get("mapped_rows", 0) or 0)
    if reportable == 0:
        return "n/a"
    if blocked > 0:
        return f"blocked {blocked}/{reportable}"
    return f"mapped {mapped}/{reportable}"


def render(promote_de, promote_es, demote, workspace: Path | None = None,
           stateful_decisions: list[dict] | None = None) -> str:
    stateful_decisions = stateful_decisions or []
    today = date.today().isoformat()
    lines = [
        "# Tier promotion proposals",
        "",
        f"_Generated: {today} by `tools/detector-promote.py` "
        "(PR #84 phase 12) — READ-ONLY proposal. "
        "Apply with `tools/detector-tier.sh promote|demote|ship <name>`._",
        "",
        "## Criteria",
        "",
        "| Transition | Rule |",
        "|---|---|",
        "| D -> E | >= 5 TP AND 0 FP AND positive fixture exists |",
        "| E -> S | >= 10 TP across 2+ distinct engagements AND <= 1 FP total |",
        "| -> D (demote) | >= 3 FP AND TP:FP ratio < 2:1 |",
        "",
        "Detector tier promotion is coverage/accounting only. Reportable/high-severity "
        "detectorization still requires an exact workspace impact-contract summary before "
        "operators treat queue rows as reportable work.",
        "",
        "Distinct-engagement count = unique `workspace` values in the ledger's "
        "`real_catches` list.",
        "",
        f"Impact-contract gate workspace: `{workspace}`" if workspace else "Impact-contract gate workspace: `(not provided)`",
        "",
        f"## D -> E candidates ({len(promote_de)})",
        "",
        _table(
            [{"detector": r["name"], "tp": r["tp"], "fp": r["fp"],
              "engagements": r["engagements"],
              "fixture": "yes" if r["fixture"] else "no",
              "impact_gate": _impact_gate_label(r)}
             for r in promote_de],
            ["detector", "tp", "fp", "engagements", "fixture", "impact_gate"],
        ),
        "",
        f"## E -> S candidates ({len(promote_es)})",
        "",
        _table(
            [{"detector": r["name"], "tp": r["tp"], "fp": r["fp"],
              "engagements": r["engagements"],
              "fixture": "yes" if r["fixture"] else "no",
              "impact_gate": _impact_gate_label(r)}
             for r in promote_es],
            ["detector", "tp", "fp", "engagements", "fixture", "impact_gate"],
        ),
        "",
        f"## Demotion candidates ({len(demote)})",
        "",
        _table(
            [{"detector": r["name"], "current_tier": r["current_tier"],
              "tp": r["tp"], "fp": r["fp"], "tp:fp": r["ratio"]}
             for r in demote],
            ["detector", "current_tier", "tp", "fp", "tp:fp"],
        ),
        "",
        f"## Factory-pool stateful decisions ({len(stateful_decisions)})",
        "",
        "Stateful gate (KNOWN_LIMITATIONS_BURNDOWN_MAP P0-7 / P1-6 / P1-7) — "
        "factory->pool->liveness detectors must declare entrypoint, invalid_config, "
        "tracked_pool, liquidity_acceptance, downstream_liveness, and "
        "conservative_severity_state on their registry row before "
        "`medium_shaped_unsubmitted` may be emitted.",
        "",
        _table(
            [{"detector": r["name"], "decision": r["decision"],
              "entrypoint": str(r.get("entrypoint") or "-"),
              "tracked_pool": str(r.get("tracked_pool") or "-"),
              "liquidity_acceptance": str(r.get("liquidity_acceptance")),
              "severity_state": str(r.get("conservative_severity_state") or "-")}
             for r in stateful_decisions],
            ["detector", "decision", "entrypoint", "tracked_pool",
             "liquidity_acceptance", "severity_state"],
        ),
        "",
        "---",
        "",
        "_This file is regenerated on every run; do not edit by hand._",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=None)
    args = parser.parse_args()
    workspace = args.workspace.expanduser().resolve() if args.workspace else None
    promote_de, promote_es, demote, stateful_decisions = build_proposals(workspace)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(render(promote_de, promote_es, demote, workspace,
                               stateful_decisions=stateful_decisions))
    medium_shaped = [d for d in stateful_decisions if d["decision"] == "medium_shaped_unsubmitted"]
    low_shaped = [d for d in stateful_decisions if d["decision"] == "low_shaped_unsubmitted"]
    summary = (
        f"{len(promote_de)} D->E candidates, "
        f"{len(promote_es)} E->S candidates, "
        f"{len(demote)} demotions, "
        f"{len(medium_shaped)} medium_shaped_unsubmitted, "
        f"{len(low_shaped)} low_shaped_unsubmitted"
    )
    print(f"[ok] wrote {OUT_PATH.relative_to(ROOT)}  ({summary})")
    for r in promote_de:
        print(f"  D->E  {r['name']}  (tp={r['tp']} fp={r['fp']})")
    for r in promote_es:
        print(f"  E->S  {r['name']}  (tp={r['tp']} fp={r['fp']} eng={r['engagements']})")
    for r in demote:
        print(f"  demote  {r['name']}  ({r['current_tier']}; {r['ratio']})")
    for r in stateful_decisions:
        print(f"  stateful  {r['name']}  decision={r['decision']}  "
              f"entrypoint={r.get('entrypoint')!r}  "
              f"sev_state={r.get('conservative_severity_state')!r}")


if __name__ == "__main__":
    main()
