#!/usr/bin/env python3
"""Z2 - zk-lookup-membership-bound: a GENERAL lookup-argument set-membership
INVARIANT / trust-enforcement screen (advisory-first, verdict=needs-fuzz).

NORTH-STAR METHOD (applied inside this capability):
  A TRUSTED ENFORCEMENT is bypassable or its private invariant is unsound.
  - Delegated-and-trusted safety property: "a lookup argument forces value v to
    be a MEMBER of table T, so v is range/table-constrained and no other value
    can pass." Downstream constraints, range checks and gadget callers all TRUST
    that a `meta.lookup(...)` binds membership.
  - Private invariant (INV-ZK-LOOKUP-MEMBERSHIP-BOUND): membership binds iff
    (1) the TABLE side is a COMMITTED fixed column - not an advice/witness the
        prover controls (else the prover supplies BOTH sides and any v "matches");
    (2) the lookup input is enforced by a COMMITTED selector - not an advice tag
        the prover can zero on a malicious row (a zeroed input trivially hits the
        table's 0 entry, selector-gated-OFF -> membership check disabled per row);
    (3) for logUp/plookup-style arguments, the MULTIPLICITY column is itself
        range/bool constrained ("squeezed") - an unconstrained multiplicity lets
        the argument be satisfied with fabricated counts.
  - Attack the invariant: if ANY of (1)(2)(3) is not provably enforced, the
    delegated membership property is UNSOUND and a false value obtains a valid
    proof. An attacker-drivable weakening (advice on the table side, an advice
    on/off tag, a free multiplicity) is the type-erased silent-fail boundary -
    no upstream visibility, reachable from any prover-chosen witness.

This is an ENFORCEMENT/INVARIANT class, NOT a bug-shape detector: it does not
match a specific circuit (e.g. "word-in-byte-table"); it enumerates every lookup
enforcement point and drives the three membership-binding sub-invariants over it,
completeness over the lookup set - impact-agnostic (theft / forged-note /
range-bypass all reduce to "membership did not bind").

ADVISORY-FIRST: every emission is verdict="needs-fuzz" (NO-AUTO-CREDIT); this
tool NEVER fails closed (exit 0 always) and NEVER auto-credits a finding. It is
a hypothesis feeder for the hunt/fuzz lanes.

FP-guard / low-FP direction: a table column is treated as COMMITTED by default
and only flagged when it is PROVABLY prover-controllable (references an advice
column bound in the same closure). A lookup gated by a committed selector is
SILENT. This is the "silent on benign, fires only when a guard is weakened"
posture required for mutation-verification on real fleet code.

DEDUP (TIER-W3 line 144):
  - E4 (halo2-constraint-completeness) passes on a present-but-vacuous lookup: it
    only asks "does a gate reference an advice col with NO returned Constraints".
    Z2 asks whether the lookup BINDS (committed table + selector + multiplicity) -
    E4 is gate-EXISTENCE, Z2 is gate-BINDS.
  - Z1 (halo2 witness-underdetermination) is advice residual-freedom inside a
    create_gate (no boolean/inverse pin); it does NOT model lookup table-side
    set-membership. Disjoint locus (meta.lookup vs meta.create_gate).
  - A4 (global-uniqueness namespace) is write-collision on handle ISSUANCE, not
    table set-MEMBERSHIP of a looked-up value. Disjoint.
  covered_by is null by construction for every emission.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "zk-lookup-membership-bound/v1"
INVARIANT = "INV-ZK-LOOKUP-MEMBERSHIP-BOUND"
ENV_FLAG = "AUDITOOOR_ZK_LOOKUP_BIND"  # advisory-first: gating for wiring parity

SOURCE_SUFFIXES = {".rs"}
SKIP_DIRS = {".git", "target", "node_modules", "__pycache__", ".venv", "build", "dist"}

# --- NON-VACUITY / neutralization knob ---------------------------------------
# The test flips this to False to neutralize the CORE predicate (the committed-
# table binding check). With it off, every table side is treated as committed and
# the planted "uncommitted-table" positive MUST stop firing - proving the arm is
# load-bearing (not a tautology).
CORE_TABLE_BINDING_CHECK = True

# --- regexes -----------------------------------------------------------------
_LOOKUP_RE = re.compile(
    r"\bmeta\s*\.\s*(?P<kind>lookup_any|lookup)\s*\(\s*\|[^|]*\|")
# advice bindings inside a closure: `let z = meta.query_advice(config.col, ..)`
_QA_VAR = re.compile(
    r"\blet\s+(?P<v>\w+)\s*=\s*meta\s*\.\s*query_advice\s*\(\s*(?P<col>[\w.]+)")
# any query_advice column reference (even not let-bound)
_QA_COL = re.compile(r"\bmeta\s*\.\s*query_advice\s*\(\s*(?P<col>[\w.]+)")
# committed gating columns: selector / fixed
_QCOMMIT_VAR = re.compile(
    r"\blet\s+(?P<v>\w+)\s*=\s*meta\s*\.\s*query_(?:selector|fixed)\s*\(")
_QCOMMIT_ANY = re.compile(r"\bmeta\s*\.\s*query_(?:selector|fixed)\s*\(")
_IDENT = re.compile(r"[A-Za-z_]\w*")
# advice column names that read as an on/off tag the prover can choose
_TAG_NAME = re.compile(r"^(?:q_|q$|sel|tag|enable|en_|flag|is_|active|on_|use_)", re.I)
# multiplicity columns (logUp / plookup) that must be squeezed. Conservative
# (only mult/multiplicity) to stay silent on fleet advice cols like `m_i`/`count`.
_MULT_NAME = re.compile(r"(?:^|_)(?:mult|multiplicity)(?:$|_)", re.I)
# a range/bool constraint anchoring a multiplicity column
_MULT_PIN_TMPL = (
    r"(?:bool_check|range_check|range_constrain|assert_range|is_bool|"
    r"lookup_range_check)\s*\([^)]*\b{col}\b"
    r"|\b{col}\b[\w.'()\s]*\*[\w.'()\s]*\(\s*(?:1|one|F::ONE|F::one\(\))\s*-\s*{col}\b")


def _match_delim(text: str, open_idx: int, opener: str, closer: str) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _last_seg(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]


def _split_top_level(s: str, sep: str = ",") -> list[str]:
    """Split s on sep at bracket/paren depth 0."""
    parts: list[str] = []
    depth = 0
    cur = []
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return parts


def _top_level_tuples(vec_body: str) -> list[str]:
    """Return each top-level `( ... )` group inside a vec![ ... ] / [ ... ] body."""
    tuples: list[str] = []
    i = 0
    n = len(vec_body)
    while i < n:
        if vec_body[i] == "(":
            end = _match_delim(vec_body, i, "(", ")")
            tuples.append(vec_body[i + 1:end - 1])
            i = end
        else:
            i += 1
    return tuples


def _returned_vec(body: str) -> str | None:
    """Return the content of the lookup's returned `vec![ ... ]` (or `[ ... ]`)."""
    m = None
    for m in re.finditer(r"vec!\s*\[", body):
        pass  # take the last vec! (the returned tuple list)
    if m is not None:
        br = body.find("[", m.end() - 1)
        return body[br + 1:_match_delim(body, br, "[", "]") - 1]
    # fallback: last top-level `[ ... ]`
    last = body.rfind("[")
    if last < 0:
        return None
    return body[last + 1:_match_delim(body, last, "[", "]") - 1]


def _table_is_advice_controlled(table_expr: str,
                                advice_vars: set[str],
                                advice_cols: set[str]) -> str | None:
    """Return the offending advice token if the TABLE side is prover-controllable,
    else None. Default (no advice token) => committed => None (low-FP)."""
    if not CORE_TABLE_BINDING_CHECK:
        return None  # neutralized: every table treated as committed
    toks = _IDENT.findall(table_expr)
    # dotted last-segments (config.running_sum -> running_sum)
    segs = {_last_seg(d) for d in re.findall(r"[\w.]+", table_expr) if "." in d}
    for t in toks:
        if t in advice_vars:
            return t
    for s in segs:
        if s in advice_cols:
            return s
    return None


def _input_gate_prover_controlled(input_expr: str,
                                   advice_vars: set[str],
                                   committed_present: bool) -> str | None:
    """Return an advice on/off tag gating the input if the lookup has NO committed
    selector/fixed gating at all (prover can disable the row); else None."""
    if committed_present:
        return None  # a committed selector/fixed gates this lookup -> sound gating
    for v in advice_vars:
        if _TAG_NAME.search(v) and re.search(r"\b" + re.escape(v) + r"\b", input_expr):
            # used as a multiplier (gate), not merely present
            if re.search(r"\b" + re.escape(v) + r"\b\s*\*|\*\s*" + re.escape(v) + r"\b",
                         input_expr):
                return v
    return None


def _unsqueezed_multiplicities(body: str, whole_text: str,
                               advice_vars: set[str]) -> list[str]:
    """Return multiplicity-named advice cols used in the lookup with NO range/bool
    pin anywhere in the file (logUp/plookup 'squeezed multiplicities' sub-invariant)."""
    out: list[str] = []
    for v in advice_vars:
        if not _MULT_NAME.search(v):
            continue
        pin = re.compile(_MULT_PIN_TMPL.format(col=re.escape(v)))
        if pin.search(whole_text):
            continue
        out.append(v)
    return out


def analyze_text(text: str, path: str = "<mem>") -> list[dict[str, Any]]:
    """Enumerate every lookup enforcement point and drive the three membership-
    binding sub-invariants. Returns advisory needs-fuzz hypotheses."""
    hyps: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for m in _LOOKUP_RE.finditer(text):
        kind = m.group("kind")
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        body = text[brace:_match_delim(text, brace, "{", "}")]
        line = text.count("\n", 0, m.start()) + 1

        advice_vars = {qm.group("v") for qm in _QA_VAR.finditer(body)}
        advice_cols = {_last_seg(qm.group("col")) for qm in _QA_COL.finditer(body)}
        committed_present = bool(_QCOMMIT_ANY.search(body))

        vec_body = _returned_vec(body)
        tuples = _top_level_tuples(vec_body) if vec_body else []

        def _emit(arm: str, detail: dict[str, Any], note: str) -> None:
            key = (path, line, arm, detail.get("table_expr")
                   or detail.get("gate_tag") or detail.get("mult_col") or "")
            if key in seen:
                return
            seen.add(key)
            rec = {
                "schema": SCHEMA,
                "invariant": INVARIANT,
                "axis": "lookup-membership-binding",
                "arm": arm,
                "advisory": True,
                "verdict": "needs-fuzz",         # NO-AUTO-CREDIT
                "file": path,
                "line": line,
                "lookup_kind": kind,
                "covered_by": None,              # DEDUP: E4/Z1/A4 disjoint
                "note": note,
            }
            rec.update(detail)
            hyps.append(rec)

        # (1) committed-table sub-invariant (CORE)
        for tup in tuples:
            # drop whitespace-only parts so a Rust trailing comma
            # `(input, table_col,)` still yields [input, table_col] (not [.., ''])
            parts = [p for p in _split_top_level(tup, ",") if p.strip()]
            if len(parts) < 2:
                continue
            input_expr = ",".join(parts[:-1])
            table_expr = parts[-1].strip()
            adv = _table_is_advice_controlled(table_expr, advice_vars, advice_cols)
            if adv is not None:
                _emit("uncommitted-table",
                      {"table_expr": table_expr, "advice_token": adv},
                      ("lookup TABLE side references an advice/witness column "
                       f"'{adv}' - membership set is prover-controllable, so any "
                       "value 'matches' (set-membership does not bind)"))
            # (2) selector-gated-off sub-invariant
            tag = _input_gate_prover_controlled(input_expr, advice_vars,
                                                committed_present)
            if tag is not None:
                _emit("selector-gated-off",
                      {"gate_tag": tag, "input_expr": input_expr.strip()[:120]},
                      ("lookup input is gated by advice tag "
                       f"'{tag}' with no committed selector/fixed - prover can "
                       "zero the input on a malicious row, disabling the "
                       "membership check (a zeroed input hits the table 0-entry)"))

        # (3) multiplicity sub-invariant (logUp / plookup)
        for mv in _unsqueezed_multiplicities(body, text, advice_vars):
            _emit("multiplicity-unchecked",
                  {"mult_col": mv},
                  (f"multiplicity/count column '{mv}' used in a lookup argument "
                   "is not range/bool constrained anywhere - fabricated "
                   "multiplicities can satisfy the argument"))
    return hyps


def _iter_source_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    found: list[Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        try:
            if p.stat().st_size > 4 * 1024 * 1024:
                continue
        except OSError:
            continue
        found.append(p)
    return found


def run(target: Path) -> list[dict[str, Any]]:
    hyps: list[dict[str, Any]] = []
    for f in _iter_source_files(target):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if ".lookup" not in text:
            continue
        hyps.extend(analyze_text(text, str(f)))
    return hyps


def enabled() -> bool:
    """Advisory-first wiring gate (parity with other Z-lane tools). OFF by default;
    analysis still runs on demand - this only governs auto-emission in a pipeline."""
    return os.environ.get(ENV_FLAG, "").strip().lower() in {"1", "true", "yes", "on"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Z2 zk-lookup-membership-bound: general lookup-argument "
                    "set-membership invariant screen (advisory, needs-fuzz)")
    ap.add_argument("target", help="halo2/plonkish circuit .rs file or directory")
    ap.add_argument("--json", action="store_true", help="emit JSON to stdout")
    args = ap.parse_args(argv)

    target = Path(args.target).resolve()
    if not target.exists():
        sys.stderr.write(f"error: path not found: {target}\n")
        return 2

    hyps = run(target)
    # Advisory sidecar for the hunt corpus (folded by auto-coverage-closer's
    # NETNEW_ADVISORY list) when run over a directory: JSONL, one needs-fuzz /
    # no-auto-credit row per hypothesis, under <target>/.auditooor/.
    if target.is_dir():
        _sd = target / ".auditooor"
        _sd.mkdir(parents=True, exist_ok=True)
        with open(_sd / "zk_lookup_membership_hypotheses.jsonl", "w", encoding="utf-8") as _sf:
            for _h in hyps:
                _sf.write(json.dumps({
                    **_h, "capability": "Z2",
                    "verdict": "needs-fuzz", "advisory": True, "auto_credit": False,
                }) + "\n")
    if args.json:
        print(json.dumps({
            "schema": SCHEMA,
            "invariant": INVARIANT,
            "target": str(target),
            "hypotheses": hyps,
            "count": len(hyps),
        }, indent=2))
    else:
        if not hyps:
            print(f"[z2] no unbound-lookup hypotheses in {target} (silent = benign)")
        for h in hyps:
            print(f"\n{h['file']}:{h['line']}  [{h['arm']}]  ({h['lookup_kind']})")
            print(f"  verdict={h['verdict']} (advisory)  inv={h['invariant']}")
            print(f"  {h['note']}")
        print(f"\n[z2] {len(hyps)} advisory hypothesis(es); verdict=needs-fuzz "
              "(NO-AUTO-CREDIT)")
    # advisory-first: NEVER fail-close.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
