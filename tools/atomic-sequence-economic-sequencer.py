#!/usr/bin/env python3
"""atomic-sequence-economic-sequencer.py - the multi-tx/same-block economic
sequence reasoning query (LOGIC CAPABILITY #4, docs/LOGIC_ARSENAL_ROADMAP.md).

This is a PATH / COMPOSITION query over an OWNED state-edge graph, NOT a token
detector. The finding is an ordered TRIPLE of functions sharing a state node with
a role ordering, gated by an atomicity-guard reachability negative - never a
`token X present, token Y absent` verdict on any single body.

THE INVARIANT (flash-loan / atomic economic-sequence class - bZx, Harvest,
Warp, Cheese, the whole `borrow->pump->withdraw` family)
  A protocol is safe against an atomic economic sequence when: for every value
  quantity C that both an INBOUND (credit / borrowed / minted) path RAISES and an
  OUTBOUND (spend / redeem / withdraw / liquidate) path CONSUMES, no single
  atomic transaction can (1) raise C via the inbound path, (2) MUTATE the coupled
  accounting/price state that depends on C, and (3) drain via the outbound path -
  UNLESS an atomicity guard (nonReentrant across the whole sequence, a
  commit-reveal / block-delay, or a pre/post snapshot conservation check) breaks
  the composition. The economic sequence is:

      [ borrowed / credited value SOURCE  s ]
                     |  writes-up (produces_state) the coupled value cell C
                     v
      [ same-block state MUTATION on cell C ]
                     |  read-down (requires_state) by
                     v
      [ value SPEND / withdraw / redeem   y ]

  If  s  and  y  are distinct value-moving functions that BOTH touch a coupled
  value-conservation cell C (s in the SOURCE role, y in the SPEND role) and NO
  atomicity guard covers the s..y path, the triple  (s -> C -> y)  is an
  atomic-sequence economic hypothesis (borrow->pump->withdraw /
  deposit->donate->liquidate / borrow->vote->execute).

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  (a) The unit of the finding is a PATH of three nodes over the state-edge graph
      (source-node -> shared coupled cell -> spend-node), not a boolean over one
      function's text. Removing the shared-cell node, or the role ordering, or the
      distinctness of s and y, dissolves the finding - none of which a token
      predicate can express.
  (b) Membership in SOURCE / SPEND is a per-node predicate (exactly as the owned
      set-difference hunter's `solvency_guard_pred` is a per-node predicate), but
      the LOGIC is the JOIN: a value-conservation cell that carries BOTH a
      source-role AND a spend-role writer, ordered producer->consumer. A cell with
      only a source, only a spend, or a non-value (freshness / config) coupling
      does NOT fire - a set relation, not a match.
  (c) The atomicity guard is a REACHABILITY NEGATIVE over the coupling's own
      guarded-reader closure + a snapshot/commit ledger-cell scan; a guard reached
      anywhere on the s..y path KILLS the lead (impossible for a same-body regex).

OWNED BACKENDS CONSUMED (no new graph engine is built here)
  <ws>/.auditooor/state_coupling_edges.jsonl  (schema state_coupling_edge.v1,
      produced by coupled-state-completeness.py) - the requires_state->produces_
      state coupling edges: each edge names a value cell C, its writers_a /
      writers_b / violators (the mutators of C) and, in evidence, the
      guarded_readers of the coupling.
  <ws>/.auditooor/value_moving_functions.json  (the SAME input VCIS,
      value-conservation-invariant-synth.py, consumes) - per-function
      transfer_hit / transfer_evidence (direction: inbound vs outbound) +
      ledger_write_evidence (the conservation credit fields). Two value-movers
      writing the SAME ledger field are ALSO a produces->requires state edge, so
      the graph unions {state_coupling cells} with {shared-ledger-field cells}.
  <ws>/.auditooor/oracle_reachability_hypotheses.jsonl  (ORL, oracle-
      reachability-lane.py) - OPTIONAL strengthener: if the spend y (or a member
      of cell C) carries an attacker-movable oracle read, the class upgrades from
      deposit->redeem to the borrow->PUMP->withdraw flash-loan template.

OUTPUT
  <ws>/.auditooor/atomic_sequence_obligations.jsonl - one row per sequenced
  hypothesis, schema `auditooor.atomic_sequence_economic_sequence.v1`,
  exploit_queue-ingest compatible. exploit-queue.py ingests it via
  _gather_from_atomic_sequence_obligations -> the queue -> per-fn-mimo-batch-gen
  OPEN-OBLIGATIONS block on the SPEND function (the extraction point).

  A summary is printed / emitted (--json) with the value-cell census, the
  source/spend partition per cell, and the sequenced triples (proving the JOIN is
  non-vacuous), plus a CITED reason when a workspace is genuinely empty.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

# ---------------------------------------------------------------------------
# scope OOS guard (single source of truth); degrade to a conservative default.
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:  # pragma: no cover
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + str(rel).replace("\\", "/")).lower()
            return any(m in n for m in (
                "/test/", "/tests/", "_test.", ".t.sol", "/mock", "/vendor/",
                "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
            ))


# ---------------------------------------------------------------------------
# Value-CONSERVATION coupled-cell classes. Only a coupling over a *value*
# quantity can carry an economic sequence; a freshness / config / authz coupling
# cannot be pumped-and-drained, so it is EXCLUDED from the cell universe (this is
# why the axelar single freshness-desync edge does NOT fire - it is not a value
# cell, and that exclusion is the set relation, not a token filter).
# ---------------------------------------------------------------------------
_VALUE_CELL_CLASSES = {
    "value-conservation-break",
    "cross-domain-conservation",
    "dual-accounting-asymmetry",
    "supply-desync",
    "collateral-desync",
    "accounting-desync",
}
_VALUE_CELL_KINDS = {
    "cross-domain-conservation",
    "dual-accounting",
    "supply-conservation",
    "conservation-coupled",
}


# ---------------------------------------------------------------------------
# Direction node-predicates. A per-node predicate over a value-moving function's
# transfer_evidence + name (exactly as solvency_guard_pred is a per-node predicate
# in the owned set-difference hunter). The LOGIC is the shared-cell JOIN wrapped
# around it, NOT this classifier.
#   INBOUND  (SOURCE / credit / borrowed / minted): value flows IN under the
#            actor's control -> raises the protected quantity.
#   OUTBOUND (SPEND / redeem / withdraw / liquidate): value flows OUT gated on the
#            protected quantity.
# ---------------------------------------------------------------------------
# transfer_evidence tokens that mark an INBOUND (pull / credit) transfer.
_INBOUND_EV = re.compile(
    r"safetransferfrom\s*\(\s*msg\.sender|"       # ERC20 pull from caller
    r"transferfrom\s*\(\s*msg\.sender|"
    r"safetransferfrom\s*\(\s*_?\w*sender|"
    r"sendcoins\w*\(\s*markertypes\.withbypass|"  # cosmos bypass-deposit into vault
    r"sendcoinsfromaccounttomodule|"              # cosmos deposit into module
    r"\bmint\b",
    re.IGNORECASE,
)
# transfer_evidence tokens that mark an OUTBOUND (push / pay-out) transfer.
_OUTBOUND_EV = re.compile(
    r"safetransfer\s*\(\s*(?!from)|"              # ERC20 push (transfer, not From)
    r"\.safetransfer\(user|\.safetransfer\(owner|\.safetransfer\(_?\w*recipient|"
    r"sendcoins\w*\(\s*markertypes\.withtransfer|"
    r"sendcoins\s*\(\s*ctx\s*,\s*(owner|vault|exported|\w*recipient)|"
    r"sendcoinsfrommoduletoaccount|sendcoinsfrommoduletomodule|"
    r"\bburn\b",
    re.IGNORECASE,
)
# fn-name direction fallbacks (used ONLY to break a tie when transfer_evidence is
# ambiguous; never the sole basis for a fired sequence - the JOIN still requires a
# distinct source+spend on the SAME coupled value cell).
_INBOUND_NAME = re.compile(
    r"deposit|swapin|\bmint\b|stake|borrow|credit|lock\b|escrow", re.IGNORECASE)
_OUTBOUND_NAME = re.compile(
    r"withdraw|redeem|swapout|\bburn\b|sweep|unlock|release|liquidat|"
    r"payout|claim|refund", re.IGNORECASE)

# ledger cell tokens that indicate a same-tx atomicity guard already present
# (a pre/post snapshot or a commit-reveal / block-delay checkpoint anywhere on the
# path breaks the atomic composition -> KILLS the sequence).
_ATOMIC_GUARD_TOKEN = re.compile(
    r"snapshot|checkpoint|commit(?:ment|reveal|hash)|"
    r"lastblock|blockheight|block\.number|blocknumber|"
    r"nonreentrant|reentrancyguard|_locked|_status\b",
    re.IGNORECASE,
)


def _short(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    return s.split("(")[0].replace("*", "").split(".")[-1].strip()


class VMFEntry:
    __slots__ = ("fn", "file", "line", "lang", "transfer_hit",
                 "transfer_evidence", "ledger_fields", "role", "guard_hit")

    def __init__(self, d: dict):
        self.fn = str(d.get("function") or "")
        self.file = str(d.get("file") or "")
        self.line = int(d.get("line") or 0)
        self.lang = str(d.get("language") or d.get("lang") or "")
        self.transfer_hit = bool(d.get("transfer_hit"))
        self.transfer_evidence = [str(x) for x in (d.get("transfer_evidence") or [])]
        self.ledger_fields = [str(x) for x in (d.get("ledger_write_evidence") or [])]
        self.role = self._classify()
        self.guard_hit = any(
            _ATOMIC_GUARD_TOKEN.search(x) for x in
            (self.transfer_evidence + self.ledger_fields + [self.fn]))

    def _classify(self) -> str:
        """SOURCE / SPEND / NEUTRAL per-node role. transfer_evidence is the
        primary signal (an OWNED extraction), fn-name is a tie-breaker only."""
        ev = " ".join(self.transfer_evidence)
        inb = bool(_INBOUND_EV.search(ev))
        outb = bool(_OUTBOUND_EV.search(ev))
        if inb and not outb:
            return "SOURCE"
        if outb and not inb:
            return "SPEND"
        if not self.transfer_hit:
            # a non-transfer accounting writer (mutator) - a legitimate MUTATE hop
            # but never on its own a value source or spend.
            return "NEUTRAL"
        # transfer_evidence ambiguous (both / neither): fall back to fn-name.
        n = self.fn
        if _INBOUND_NAME.search(n) and not _OUTBOUND_NAME.search(n):
            return "SOURCE"
        if _OUTBOUND_NAME.search(n) and not _INBOUND_NAME.search(n):
            return "SPEND"
        return "NEUTRAL"


def load_vmf(ws: Path) -> dict[str, VMFEntry]:
    """Fold value_moving_functions.json into {bare-fn-name -> VMFEntry}. Last
    writer wins on a name collision but role is upgraded to a firing role
    (SOURCE/SPEND) if any duplicate carries it, so a name shadowed by a NEUTRAL
    entry does not suppress a real value-mover."""
    p = ws / ".auditooor" / "value_moving_functions.json"
    out: dict[str, VMFEntry] = {}
    if not p.is_file():
        return out
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return out
    for f in d.get("functions") or []:
        e = VMFEntry(f)
        key = _short(e.fn)
        prev = out.get(key)
        if prev is None:
            out[key] = e
            continue
        # keep the entry with a firing role / concrete file
        if prev.role == "NEUTRAL" and e.role != "NEUTRAL":
            out[key] = e
        elif not prev.file and e.file:
            out[key] = e
        # union ledger fields so shared-field edges are not lost
        prev = out[key]
        for lf in e.ledger_fields:
            if lf not in prev.ledger_fields:
                prev.ledger_fields.append(lf)
    return out


class Cell:
    """A coupled VALUE state node in the state-edge graph. members = the fns that
    write/mutate the cell (produces_state); the SOURCE members raise it, the SPEND
    members consume it."""
    __slots__ = ("cid", "label", "origin", "impact_class", "members",
                 "guarded_readers", "obligation")

    def __init__(self, cid: str, label: str, origin: str):
        self.cid = cid
        self.label = label
        self.origin = origin          # 'state-coupling' | 'shared-ledger-field'
        self.impact_class = ""
        self.members: set[str] = set()
        self.guarded_readers: set[str] = set()
        self.obligation = ""


def _is_value_edge(edge: dict) -> bool:
    ic = str(edge.get("impact_class") or "").lower()
    kind = str(edge.get("kind") or "").lower()
    tier = str((edge.get("evidence") or {}).get("tier") or "").lower()
    if any(c in ic for c in _VALUE_CELL_CLASSES):
        return True
    if any(k in kind for k in _VALUE_CELL_KINDS):
        return True
    if "conservation" in tier or "dual-accounting" in tier:
        return True
    return False


def build_cells(ws: Path, vmf: dict[str, VMFEntry]) -> tuple[list[Cell], dict]:
    """Build the VALUE-cell universe from (a) state_coupling_edges.jsonl value
    edges and (b) shared-ledger-field cells among value_moving_functions. Returns
    (cells, diag)."""
    cells: list[Cell] = []
    diag = {"state_coupling_edges_total": 0, "state_coupling_value_edges": 0,
            "shared_field_cells": 0}

    # (a) state_coupling_edges value cells
    p = ws / ".auditooor" / "state_coupling_edges.jsonl"
    if p.is_file():
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    edge = json.loads(line)
                except Exception:
                    continue
                diag["state_coupling_edges_total"] += 1
                if not _is_value_edge(edge):
                    continue
                diag["state_coupling_value_edges"] += 1
                cid = str(edge.get("edge_id") or f"edge{diag['state_coupling_edges_total']}")
                label = (f"{edge.get('cell_a')}<->{edge.get('cell_b')}")
                c = Cell("sc:" + cid, label, "state-coupling")
                c.impact_class = str(edge.get("impact_class") or "")
                c.obligation = str(edge.get("obligation") or "")
                for src in ("writers_a", "writers_b"):
                    for fn in (edge.get(src) or []):
                        c.members.add(_short(str(fn)))
                for v in (edge.get("violators") or []):
                    if v.get("fn"):
                        c.members.add(_short(str(v["fn"])))
                ev = edge.get("evidence") or {}
                for gr in (ev.get("guarded_readers") or []):
                    c.guarded_readers.add(_short(str(gr)))
                for mm in (ev.get("marker_only_movers") or []):
                    # a marker-only mover mints/burns the external value marker -
                    # a first-class SOURCE even if absent from vmf.
                    c.members.add(_short(str(mm)))
                cells.append(c)

    # (b) shared-ledger-field cells: two value-movers writing the SAME conservation
    #     ledger field is a produces_state->requires_state edge over that field.
    field_writers: dict[str, set[str]] = {}
    for key, e in vmf.items():
        for lf in e.ledger_fields:
            field_writers.setdefault(lf, set()).add(key)
    for field, writers in sorted(field_writers.items()):
        if len(writers) < 2:
            continue
        diag["shared_field_cells"] += 1
        c = Cell("lf:" + field, f"ledger-field:{field}", "shared-ledger-field")
        c.impact_class = "ledger-field-conservation"
        c.members = set(writers)
        cells.append(c)
    return cells, diag


def load_oracle_pump(ws: Path) -> set[str]:
    """Set of consuming-fn names that carry an attacker-movable oracle read (ORL).
    Used ONLY to upgrade a fired sequence's template to borrow->PUMP->withdraw;
    never a firing precondition."""
    p = ws / ".auditooor" / "oracle_reachability_hypotheses.jsonl"
    out: set[str] = set()
    if not p.is_file():
        return out
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            fn = r.get("consuming_fn") or r.get("function") or r.get("fn")
            if fn:
                out.add(_short(str(fn)))
    return out


def sequence_cell(c: Cell, vmf: dict[str, VMFEntry],
                  oracle_pump: set[str]) -> list[dict]:
    """The PATH query for one cell: partition members into SOURCE / SPEND roles,
    then emit one sequenced hypothesis per (source, spend) pair that is NOT covered
    by an atomicity guard. Returns a list of sequence dicts (may be empty)."""
    sources: list[str] = []
    spends: list[str] = []
    for m in sorted(c.members):
        e = vmf.get(m)
        role = e.role if e else ""
        if role == "SOURCE":
            sources.append(m)
        elif role == "SPEND":
            spends.append(m)
    seqs: list[dict] = []
    for s in sources:
        for y in spends:
            if s == y:
                continue
            # atomicity-guard reachability negative: a snapshot/commit/reentrancy
            # guard on the SPEND, on the SOURCE, or a guarded-reader on the
            # coupling breaks the atomic composition -> KILL.
            guarded_by = []
            if y in c.guarded_readers or s in c.guarded_readers:
                guarded_by.append("coupling.guarded_readers")
            if vmf.get(y) and vmf[y].guard_hit:
                guarded_by.append(f"snapshot/commit-guard@{y}")
            if vmf.get(s) and vmf[s].guard_hit:
                guarded_by.append(f"snapshot/commit-guard@{s}")
            if guarded_by:
                continue  # atomic composition broken by a guard on the path
            pumped = (y in oracle_pump) or bool(oracle_pump & c.members)
            seqs.append({"source": s, "spend": y, "pumped": pumped})
    return seqs


_TEMPLATE = {
    ("share", True): "flashloan-oracle-pump-withdraw",
    ("share", False): "deposit-inflate-share-redeem",
}


def _pick_template(c: Cell, pumped: bool) -> tuple[str, str]:
    if pumped:
        return ("flashloan-oracle-pump-withdraw", "borrow->pump->withdraw")
    lab = c.label.lower()
    if "share" in lab or "supply" in lab:
        return ("deposit-inflate-share-redeem", "deposit->donate->liquidate")
    if "reward" in lab or "vote" in lab or "poll" in lab:
        return ("credit-inflate-claim-execute", "borrow->vote->execute")
    return ("atomic-credit-mutate-spend", "borrow->mutate->spend")


def make_obligation(c: Cell, seq: dict, vmf: dict[str, VMFEntry],
                    invariant_id: str) -> dict:
    s, y = seq["source"], seq["spend"]
    se, ye = vmf.get(s), vmf.get(y)
    attack_class, family = _pick_template(c, seq["pumped"])
    s_ref = (se.file + (f":{se.line}" if se and se.line else "")) if se else ""
    y_ref = (ye.file + (f":{ye.line}" if ye and ye.line else "")) if ye else ""
    src_refs = [r for r in (y_ref, s_ref) if r]
    lang = (ye.lang if ye else "") or (se.lang if se else "")
    root = (
        f"Atomic economic sequence ({family}): the borrowed/credited value source "
        f"'{s}' RAISES the coupled value cell [{c.label}] (produces_state) and the "
        f"spend '{y}' CONSUMES it (requires_state) with NO atomicity guard "
        f"(nonReentrant across the sequence / commit-reveal / pre-post snapshot) "
        f"covering the s..y path. An attacker can, in ONE tx/block, run "
        f"{s} -> mutate {c.label} -> {y} to extract value the conservation "
        f"invariant should forbid."
    )
    return {
        "schema": "auditooor.atomic_sequence_economic_sequence.v1",
        "obligation_type": "atomic-sequence-economic-sequence",
        "contract": (ye.file.rsplit("/", 1)[-1].split(".")[0] if ye and ye.file else ""),
        "function": y,               # extraction point = the spend
        "spend_function": y,
        "source_function": s,
        "coupled_cell": c.label,
        "cell_origin": c.origin,
        "cell_impact_class": c.impact_class,
        "language": lang,
        "sequence": [
            {"step": 1, "role": "borrowed-source", "fn": s, "ref": s_ref,
             "effect": "produces_state (raises the coupled value cell)"},
            {"step": 2, "role": "state-mutation", "cell": c.label,
             "effect": "same-block coupled-cell desync"},
            {"step": 3, "role": "spend", "fn": y, "ref": y_ref,
             "effect": "requires_state (drains gated on the coupled value cell)"},
        ],
        "source_refs": src_refs,
        "attack_class": attack_class,
        "sequence_family": family,
        "oracle_pump": seq["pumped"],
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "ATOMICITY_GUARD: prove NO guard breaks the s..y composition - a "
            "nonReentrant spanning both, a commit-reveal / block-delay between the "
            "credit and the spend, or a pre/post snapshot conservation check that "
            "reverts the desync KILLS the lead.",
            "SAME_BLOCK_COMPOSABILITY: show the source and spend are callable by "
            "the SAME actor in one tx/block (no cross-block settlement, no "
            "per-epoch gate) and both reach the coupled cell.",
            "NET_EXTRACTION: quantify that the sequence leaves the actor net-ahead "
            "at the conservation cell's expense (share-inflation / over-redemption "
            "/ price-pumped withdrawal), not a fee/rounding wash.",
        ],
        "next_command": (
            f"read {y} + {s} bodies; if they share the coupled cell [{c.label}] "
            f"atomically with no guard, author the pre/post conservation invariant "
            f"harness and drive an executed same-block PoC."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--invariant-id",
                    default="INV-ATOMIC-SEQUENCE-CONSERVATION",
                    help="broken_invariant_id stamped on every obligation")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/atomic_sequence_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit 3 if BOTH owned backends "
                         "(state_coupling_edges + value_moving_functions) are "
                         "absent (the state-edge graph could not be built)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    vmf = load_vmf(ws)
    cells, diag = build_cells(ws, vmf)
    oracle_pump = load_oracle_pump(ws)

    backends_present = (
        (ws / ".auditooor" / "state_coupling_edges.jsonl").is_file()
        or (ws / ".auditooor" / "value_moving_functions.json").is_file())

    obligations: list[dict] = []
    cell_reports: list[dict] = []
    n_cell_with_source = n_cell_with_spend = 0
    seen = set()
    for c in cells:
        seqs = sequence_cell(c, vmf, oracle_pump)
        srcs = sorted(m for m in c.members
                      if vmf.get(m) and vmf[m].role == "SOURCE")
        spds = sorted(m for m in c.members
                      if vmf.get(m) and vmf[m].role == "SPEND")
        if srcs:
            n_cell_with_source += 1
        if spds:
            n_cell_with_spend += 1
        cell_reports.append({
            "cell": c.label, "origin": c.origin,
            "impact_class": c.impact_class,
            "sources": srcs, "spends": spds,
            "n_sequences": len(seqs),
        })
        for seq in seqs:
            dk = (c.label, seq["source"], seq["spend"])
            if dk in seen:
                continue
            seen.add(dk)
            obligations.append(make_obligation(c, seq, vmf, args.invariant_id))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "atomic_sequence_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")
        # Capability-vacuity-telltale: the sequencer RAN over a real state-edge backend
        # (backends_present) and produced 0 sequenced obligations. PERSIST an explicit
        # cited-empty examined-record so the reasoner-firing gate scores this
        # FIRED_CLEAN (ran, examined, recorded 0) not silently VACUOUS. Gated on a
        # present backend - an absent backend is a genuine substrate_vacuous, not clean.
        if not obligations and backends_present:
            fh.write(json.dumps({
                "schema": "auditooor.atomic_sequence_economic.examined_record.v1",
                "note": ("cited-empty: atomic-sequence economic sequencer ran over the "
                         "coupled state-edge backend, 0 produces->requires survivors"),
                "survivors": [],
                "report": {"reasoner": "atomic-sequence-economic-sequencer",
                           "totals": {"examined": len(cells),
                                      "cells_with_source": n_cell_with_source,
                                      "cells_with_spend": n_cell_with_spend}},
            }) + "\n")

    empty_reason = ""
    if not obligations:
        if not backends_present:
            empty_reason = ("no owned state-edge backend present "
                            "(state_coupling_edges.jsonl + value_moving_functions.json "
                            "both absent) - run coupled-state-completeness.py first")
        elif not cells:
            empty_reason = ("no VALUE-conservation coupled cell in the graph "
                            "(all state_coupling edges are freshness/config/authz "
                            "couplings, and no ledger field is written by >=2 "
                            "value-movers) - genuinely nothing to sequence")
        elif n_cell_with_source == 0 or n_cell_with_spend == 0:
            empty_reason = (
                f"value cells exist ({len(cells)}) but no single cell carries BOTH "
                f"a source-role AND a spend-role value-mover "
                f"(cells-with-source={n_cell_with_source}, "
                f"cells-with-spend={n_cell_with_spend}) - the produces->requires "
                f"economic pairing is absent (cited-empty, not vacuous)")
        else:
            empty_reason = ("source+spend cells exist but every candidate pair is "
                            "covered by an atomicity guard (snapshot/commit/"
                            "reentrancy) - all sequences KILLED by a guard")

    summary = {
        "schema": "auditooor.atomic_sequence_economic_sequencer.v1",
        "workspace": str(ws),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "backends_present": backends_present,
        "n_value_moving_fns": len(vmf),
        "n_value_cells": len(cells),
        "cells_with_source": n_cell_with_source,
        "cells_with_spend": n_cell_with_spend,
        "n_sequences": len(obligations),
        "diag": diag,
        "oracle_pump_fns": sorted(oracle_pump),
        "cell_reports": cell_reports,
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "empty_reason": empty_reason,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[atomic-sequence] {ws.name}: value-cells={len(cells)} "
              f"(src={n_cell_with_source}, spend={n_cell_with_spend}) "
              f"-> {len(obligations)} sequenced economic hypothesis(es)")
        for cr in cell_reports:
            if cr["n_sequences"]:
                print(f"  CELL {cr['cell']} [{cr['origin']}] "
                      f"src={cr['sources']} spend={cr['spends']} "
                      f"-> {cr['n_sequences']} seq")
        for ob in obligations[:40]:
            print(f"  SEQ {ob['sequence_family']}: {ob['source_function']} "
                  f"-> [{ob['coupled_cell']}] -> {ob['spend_function']}")
        if empty_reason:
            print(f"  EMPTY (cited): {empty_reason}", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and not backends_present:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
