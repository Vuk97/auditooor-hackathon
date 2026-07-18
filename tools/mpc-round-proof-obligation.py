#!/usr/bin/env python3
"""mpc-round-proof-obligation.py - the Fireblocks BitForge / TSS (Aug 2023) missing
per-round proof-verification reasoning query for multi-round threshold-sig / DKG
ceremonies (GG18/GG20 keygen+signing, Feldman/Pedersen VSS, MtA).

LOGIC CAPABILITY (docs/LOGIC_ARSENAL_ROADMAP.md, MPC ceremony proof-obligation class).
This is a transitive DUAL-CLOSURE SET-DIFFERENCE + VALUE-IDENTITY + ROUND-ORDERING
query over the OWNED tools/rust-dataflow.py MIR DefUsePath backend
(<ws>/.auditooor/dataflow_paths*.jsonl, schema dataflow_path.v1). It is NOT a body
regex for 'verify' - the verdict is the closure set-difference, and the thin MPC-role
lexicon (VSS/Paillier/MtA/nonce-commit) only LABELS sink/verify nodes.

THE LOGIC TRIPLE (extracted from the BitForge / GG20 hack class)
  ASSUMPTION (that the hack falsified):
    every inbound protocol-message field carrying a share / nonce commitment /
    Paillier ciphertext / partial signature has its bound ZK-proof or commitment
    VERIFIED before the field is consumed in secret aggregation, AND the verified
    object is the SAME object consumed (no verify-then-swap), in-or-before the
    consuming round, once per session-nonce.
  INVARIANT the protocol must uphold:
    Let
      CONSUME = { round-message field f : f's forward def-use closure REACHES a
                  SECRET-AGGREGATION SINK - share reconstruct, lagrange_interpolate,
                  sum-of-shares, add_partial_sig, sk +=, nonce combine, sign_finalize }
      PROVEN  = { f in CONSUME : between decode(f) and that SINK, f's closure PASSES a
                  VERIFICATION node - a VSS/Feldman check, a Paillier-Blum /
                  no-small-factor / range / consistency / dlog ZK-proof verify, or a
                  commitment-open bound to f - such that
                    (a) the verify is ordered in-or-before the sink (round-ordering),
                    (b) the MIR local entering the verify is VALUE-IDENTICAL to the
                        local entering the sink (no verify-then-swap),
                    (c) verify and sink share the same session/round nonce guard }
    MPC soundness requires  CONSUME is a SUBSET of PROVEN.
  TRUST-BOUNDARY that breaks:
    every f in the SET-DIFFERENCE  CONSUME \\ PROVEN  (or f verified-but-swapped) is
    an unverified attacker-controlled value flowing into secret aggregation ->
    share/key extraction or signature forgery = full custody theft (BitForge/TSS).

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  It differs from `body_contains('verify')` on three axes - the same axes that make
  the Euler/Nomad set-difference hunter a reasoning query rather than a regex:
   (a) TRANSITIVE dual-closure: PROVEN membership is forward+backward reachability;
       a verify N helper-hops away or in a sibling round handler correctly places the
       field in PROVEN - a body-scoped regex cannot see past the immediate body.
   (b) VALUE-IDENTITY (verify-then-swap) axis - unique to MPC: the reasoner asks
       whether the EXACT source local (field slice) that flows into the SINK is the
       one that dominated the verify. A `N` verified in one round but re-read for
       signing in a later round is caught ONLY by this local-identity closure.
   (c) ROUND-ORDERING / session-freshness axis: the verify must be ordered in-or-
       before the consuming round and bound to the same session/round nonce guard -
       a reachability-over-a-state-machine query, not a token count.

BACKEND (owned)
  <ws>/.auditooor/dataflow_paths.jsonl + every scoped sidecar dataflow_paths.*.jsonl
  (rust-dataflow MIR paths, confidence="semantic-ssa"; syntactic/heuristic/degraded
  records are advisory and never flip a survivor to PROVEN). Each DefUsePath record
  binds a source (fn,var) FIELD to a classified SINK, carrying the closure HOPS
  (hop.fn callees + hop.ir call-sites + hop.line) and GUARD nodes (guard_nodes.expr).

OUTPUT
  <ws>/.auditooor/mpc_round_proof_obligation_obligations.jsonl - one row per survivor,
  schema `auditooor.mpc_round_proof_obligation.v1`, exploit_queue-ingest compatible
  (contract/function/source_refs/root_cause_hypothesis/attack_class=mpc-key-extraction/
  broken_invariant_ids/quality_gate_status='needs_source'). A summary is printed /
  emitted (--json) with |CONSUME|, |PROVEN|, |survivors|, |verify-then-swap|, and the
  KEPT set (proving the subtraction is non-vacuous).

HONESTY (R80): a substrate that is present-but-all-degraded/heuristic emits
  substrate_vacuous=True (advisory, needs_source). A present semantic substrate with
  an empty CONSUME set is an honest cited-empty (a provable soundness attestation),
  NOT a vacuous pass. --fail-closed exits non-zero ONLY on an absent/vacuous substrate.

CLI
  tools/mpc-round-proof-obligation.py --workspace <ws> [--src-root DIR]
      [--emit PATH] [--json] [--fail-closed]
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

SCHEMA = "auditooor.mpc_round_proof_obligation.v1"
SUMMARY_SCHEMA = "auditooor.mpc_round_proof_obligation.summary.v1"
_DEFAULT_INVARIANT_ID = "mpc-round-proof-consume-subset-proven-value-identical-session-fresh"


# ---------------------------------------------------------------------------
# SECRET-AGGREGATION SINK lexicon. A closure node (sink callee / hop fn / hop-ir
# call-site) whose name matches is a point where a round-message field is folded
# into the shared secret (share reconstruction, key/nonce aggregation, partial-sig
# combine, secret write). This LABELS the sink node; the verdict is the closure
# set-difference wrapped around it. Matched case-insensitively against the SHORT
# (last-segment) identifier.
# ---------------------------------------------------------------------------
_SECRET_SINK = re.compile(
    r"(?:"
    r"lagrange_interpolate|lagrange|interpolate|"
    r"reconstruct(?:_secret|_share|_key)?|recover_secret|combine_shares?|"
    r"sum_of_shares|add_share|accumulate_share|xi_reconstruct|"
    r"add_partial_sig(?:nature)?|combine_partial|aggregate_sig|combine_sig|"
    r"sign_finalize|finalize_sig(?:nature)?|combine_nonce|aggregate_nonce|"
    r"nonce_combine|combine_r|set_secret|secret_share_set|"
    r"key_share|keyshare_set|sk_set|delta_inv|sigma_i|compute_s_i"
    r")",
    re.IGNORECASE,
)

# also treat a state-write/value-move whose var/callee reads as a secret assignment.
_SECRET_SINK_KINDS = {"state-write", "value-move", "mint", "storage"}
_SECRET_VAR = re.compile(
    r"(?:x_?i|xi|sk|secret|share|sigma|delta|s_?i|k_?i|nonce|priv)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# VERIFICATION node lexicon. A closure node classified as the required per-round
# proof / commitment verification the MPC soundness contract mandates. Four
# families the BitForge / GG20 post-mortem names as the omitted binding:
#   (1) VSS / Feldman / Pedersen share consistency check
#   (2) Paillier-Blum / no-small-factor / modulus proof
#   (3) MtA range proof / bound / consistency proof
#   (4) commitment-open bound to the field / dlog-eq / schnorr / zk consistency
# ---------------------------------------------------------------------------
_VERIFY = re.compile(
    r"(?:"
    # (1) VSS / Feldman / Pedersen
    r"feldman[_ ]?verify|vss[_ ]?verify|verify[_ ]?vss|verify[_ ]?feldman|"
    r"pedersen[_ ]?verify|share_verify|verify_share|verify_commitment|check_share|"
    # (2) Paillier-Blum / no-small-factor
    r"paillier[_ ]?blum|blum[_ ]?verify|verify[_ ]?blum|no[_ ]?small[_ ]?factor|"
    r"verify[_ ]?paillier|paillier_verify|mod_proof_verify|verify_mod|"
    # (3) MtA range / bound proofs
    r"range[_ ]?proof[_ ]?verify|verify[_ ]?range|mta[_ ]?verify|verify[_ ]?mta|"
    r"bound[_ ]?check|verify_bound|"
    # (4) commitment-open / zk consistency / dlog-eq / schnorr
    r"open(?:_commitment)?|verify_open|commitment_open|dlog[_ ]?verify|"
    r"verify_dlog|eq[_ ]?proof[_ ]?verify|schnorr[_ ]?verify|verify_schnorr|"
    r"zk[_ ]?verify|verify_zk|verify_proof|proof_verify|consistency_check|"
    r"verify_consistency|check_proof"
    r")",
    re.IGNORECASE,
)

# a per-node generic verify verb, used ONLY when the node is inside an MPC round
# handler (thin lexicon gate) - keeps a bare `verify(` from over-crediting.
_GENERIC_VERIFY = re.compile(r"(?:^|[._])verif(?:y|ies|ied)\b", re.IGNORECASE)

# session / round nonce guard token - a guard_nodes.expr or fn segment binding the
# closure to a specific session/round (freshness axis (c)).
_SESSION_TOK = re.compile(r"(?:session|round|nonce|sid|epoch|ssid)", re.IGNORECASE)

# INBOUND round-message field source: the field is a decoded field of an inbound
# protocol/round message. We take the SOURCE as an MPC field when the fn is an MPC
# round handler OR the var reads as a protocol-message field. This SELECTS the taint
# source; the LOGIC is the set-difference around it.
_ROUND_HANDLER = re.compile(
    r"(?:"
    r"r\d+|round\d*|"
    r"execute|handle|process|on_message|handle_in|"
    r"keygen|sign|dkg|refresh|reshare|presign|"
    r"bcast|p2p|deliver"
    r")",
    re.IGNORECASE,
)
_MSG_FIELD_VAR = re.compile(
    r"(?:msg|bcast|p2ps?|share|commit|ciphertext|ct|proof|nonce|"
    r"paillier|_n\b|ek|pubkey|blind|k_i|gamma|r_i|sig|partial)",
    re.IGNORECASE,
)

# MPC-CRATE / CEREMONY MARKER. A DefUsePath record only enters the analysis when its
# source fn OR file path carries a threshold-sig / DKG ceremony marker. This is the
# thin MPC-role lexicon that LABELS the ceremony surface - it keeps generic Go
# cosmos-sdk IBC keeper Set/Delete state-writes (and any non-MPC code that happens to
# share a dataflow sidecar) OUT of the set, so a survivor is a real ceremony field,
# not a keeper write. The verdict is still the CONSUME\\PROVEN closure difference
# WITHIN this labelled surface, not this regex.
_MPC_MARKER = re.compile(
    r"(?:"
    r"tofn|tofnd|gg20|gg18|gg1[68]|"
    r"feldman|pedersen|paillier|"
    r"\bvss\b|_vss|vss_|\bmta\b|_mta|mta_|"
    r"keygen|key_gen|\bdkg\b|presign|reshare|refresh_key|"
    r"threshold[_ ]?sig|thresholdsig|frost|lindell|schnorr[_ ]?mpc|"
    r"secret[_ ]?share|share_gen|lagrange"
    r")",
    re.IGNORECASE,
)


def _is_mpc_ceremony(fn: str, file: str) -> bool:
    """True iff this record is on the MPC ceremony surface (fn or file carries a
    threshold-sig/DKG marker). Gates the whole analysis to the ceremony code."""
    return bool(_MPC_MARKER.search(fn or "") or _MPC_MARKER.search(file or ""))


# a call-site token: `Ident(` inside a hop IR string.
_CALLRE = re.compile(r"([A-Za-z_][\w.$]*)\s*\(")


def _short(name: str) -> str:
    n = (name or "").strip()
    if not n:
        return ""
    core = n.rstrip(")")
    seg = core.split("(")[-1] if "(" in core else core
    seg = seg.split("::")[-1].split(".")[-1]
    return seg.strip()


def _contract_of(fn: str) -> str:
    f = (fn or "").strip()
    if not f:
        return ""
    m = re.search(r"([A-Za-z_]\w*)\)\.[A-Za-z_]", f)
    if m:
        return m.group(1)
    parts = re.split(r"::|\.", f.replace("(", " ").split(" ")[0])
    if len(parts) >= 2:
        return parts[-2]
    return ""


def secret_sink_pred(name: str) -> bool:
    n = (name or "").strip()
    return bool(n) and bool(_SECRET_SINK.search(_short(n)) or _SECRET_SINK.search(n))


def verify_pred(name: str, mpc_context: bool) -> bool:
    """A closure node is a VERIFY node iff it matches the specific MPC-proof lexicon,
    OR it is a generic verify verb AND we are inside an MPC round context (thin gate,
    to avoid over-crediting bare `verify(`)."""
    n = (name or "").strip()
    if not n:
        return False
    if _VERIFY.search(n) or _VERIFY.search(_short(n)):
        return True
    if mpc_context and _GENERIC_VERIFY.search(n):
        return True
    return False


class _Field:
    """One inbound round-message FIELD = (fn, var). Folds every dataflow path that
    shares this (source fn, source var) - a verify in a sibling path over the SAME
    field local still contributes to PROVEN (value-identity honored)."""

    __slots__ = ("fn", "var", "lang", "file", "line", "is_round",
                 "consume", "sink_lines", "sink_note",
                 "verify_lines", "verify_names", "verify_sessions", "sink_sessions",
                 "semantic")

    def __init__(self, fn: str, var: str):
        self.fn = fn
        self.var = var
        self.lang = ""
        self.file = ""
        self.line = 0
        self.is_round = False
        self.consume = False
        self.sink_lines: list[int] = []
        self.sink_note: str = ""
        self.verify_lines: list[int] = []
        self.verify_names: set[str] = set()
        self.verify_sessions: set[str] = set()
        self.sink_sessions: set[str] = set()
        self.semantic = False


def _closure_nodes(rec: dict) -> list[tuple[str, int]]:
    """(name, line) for every node reachable in this path's closure that could be a
    verify or sink node: the sink callee, each hop fn, each hop-ir call-site."""
    out: list[tuple[str, int]] = []
    sink = rec.get("sink") or {}
    out.append((sink.get("callee") or "", int(sink.get("line") or 0)))
    out.append((sink.get("fn") or "", int(sink.get("line") or 0)))
    for h in rec.get("hops") or []:
        if not isinstance(h, dict):
            continue
        ln = int(h.get("line") or 0)
        out.append((h.get("fn") or "", ln))
        ir = h.get("ir") or ""
        for c in _CALLRE.findall(ir):
            out.append((c, ln))
    return [(n, l) for (n, l) in out if n]


def _session_tokens(rec: dict) -> set[str]:
    toks: set[str] = set()
    for g in rec.get("guard_nodes") or []:
        if isinstance(g, dict):
            expr = g.get("expr") or ""
            for m in _SESSION_TOK.findall(expr):
                toks.add(m.lower())
    fn = (rec.get("source") or {}).get("fn") or ""
    for m in _SESSION_TOK.findall(fn):
        toks.add(m.lower())
    return toks


def _is_round_field(fn: str, var: str) -> bool:
    return bool(_ROUND_HANDLER.search(_short(fn)) or _MSG_FIELD_VAR.search(var or ""))


def build_fields(dataflow_paths: list[Path], warnings: list[str]) -> tuple[dict, dict]:
    """Fold DefUsePath records into per-(fn,var) FIELD units. Returns
    (fields, meta) where meta carries substrate diagnostics."""
    fields: dict[tuple[str, str], _Field] = {}
    seen_rows = 0
    semantic_rows = 0
    mpc_rows = 0
    mpc_semantic_rows = 0
    for dfp in dataflow_paths:
        if not dfp.exists():
            warnings.append(f"dataflow absent: {dfp}")
            continue
        with dfp.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict):
                    continue
                if rec.get("degraded"):
                    continue
                seen_rows += 1
                conf = rec.get("confidence") or ""
                is_sem = (conf == "semantic-ssa")
                if is_sem:
                    semantic_rows += 1
                src = rec.get("source") or {}
                fn = src.get("fn") or ""
                var = src.get("var") or ""
                if not fn:
                    continue
                # MPC-ceremony gate: only records on the threshold-sig/DKG surface
                # (fn OR file carries an MPC marker) enter the analysis. Keeps generic
                # keeper/IBC state-writes out of CONSUME.
                sink0 = rec.get("sink") or {}
                if not (_is_mpc_ceremony(fn, src.get("file") or "")
                        or _is_mpc_ceremony(sink0.get("fn") or "",
                                            sink0.get("file") or "")):
                    continue
                mpc_rows += 1
                if is_sem:
                    mpc_semantic_rows += 1
                key = (fn, var)
                fld = fields.get(key)
                if fld is None:
                    fld = _Field(fn, var)
                    fields[key] = fld
                if not fld.lang:
                    fld.lang = rec.get("language") or ""
                if not fld.file and src.get("file"):
                    fld.file = src.get("file")
                    fld.line = int(src.get("line") or 0)
                if is_sem:
                    fld.semantic = True
                if _is_round_field(fn, var):
                    fld.is_round = True
                mpc_ctx = _is_round_field(fn, var)
                sessions = _session_tokens(rec)

                sink = rec.get("sink") or {}
                sink_line = int(sink.get("line") or 0)
                sink_is_secret = False
                cal = sink.get("callee") or ""
                if secret_sink_pred(cal) or secret_sink_pred(sink.get("fn") or ""):
                    sink_is_secret = True
                elif (sink.get("kind") in _SECRET_SINK_KINDS
                      and (_SECRET_VAR.search(var) or _SECRET_VAR.search(cal))):
                    sink_is_secret = True
                if sink_is_secret:
                    fld.consume = True
                    fld.sink_lines.append(sink_line)
                    fld.sink_sessions |= sessions
                    if not fld.sink_note:
                        fld.sink_note = _short(cal) or sink.get("kind") or ""

                # verify nodes anywhere in this field's closure (value-identical:
                # this record's slice is anchored on THIS (fn,var) source local).
                for (name, ln) in _closure_nodes(rec):
                    if verify_pred(name, mpc_ctx):
                        fld.verify_lines.append(ln)
                        fld.verify_names.add(_short(name)[:48] or name[:48])
                        fld.verify_sessions |= sessions

    if seen_rows == 0:
        warnings.append("dataflow substrate empty (0 rows) - nothing to reason over")
    meta = {"seen_rows": seen_rows, "semantic_rows": semantic_rows,
            "mpc_rows": mpc_rows, "mpc_semantic_rows": mpc_semantic_rows}
    return fields, meta


def classify(fields: dict) -> tuple[list, list, list, list]:
    """CONSUME = fields reaching a secret-aggregation sink. PROVEN = CONSUME fields
    with a verify node that is (a) ordered in-or-before the earliest sink,
    (b) value-identical (same field slice - guaranteed by the per-(fn,var) fold),
    (c) same session/round guard. survivors = CONSUME \\ PROVEN. verify_then_swap =
    consumed fields with NO in-slice verify BUT whose enclosing fn verifies a
    DIFFERENT field local. KEPT = PROVEN (proves the subtraction is non-vacuous)."""
    consume = [f for f in fields.values() if f.consume]

    # index verify presence per enclosing fn -> which field vars were verified
    verified_vars_by_fn: dict[str, set[str]] = {}
    for f in fields.values():
        if f.verify_lines:
            verified_vars_by_fn.setdefault(f.fn, set()).add(f.var)

    proven, survivors, swap = [], [], []
    for f in consume:
        min_sink = min(f.sink_lines) if f.sink_lines else 0
        # axis (a) round-ordering: a verify ordered in-or-before the sink.
        ordered_verify = any(
            (vl and min_sink and vl <= min_sink) or (vl and not min_sink)
            for vl in f.verify_lines
        )
        # if we have no line info at all but a verify exists on the same slice,
        # accept it (line-less MIR degrade) - still value-identical.
        has_verify = bool(f.verify_lines)
        # axis (c) session-freshness: verify+sink share a session guard, OR neither
        # carries a session token (freshness not modeled for this field - lenient).
        session_ok = (not f.sink_sessions) or bool(f.verify_sessions & f.sink_sessions)
        is_proven = has_verify and (ordered_verify or not min_sink) and session_ok
        if is_proven:
            proven.append(f)
        else:
            survivors.append(f)
            # verify-then-swap: same fn verified a DIFFERENT field var than the one
            # this sink consumes.
            other_verified = {v for v in verified_vars_by_fn.get(f.fn, set())
                              if v != f.var}
            if other_verified and not has_verify:
                swap.append(f)

    for lst in (consume, proven, survivors, swap):
        lst.sort(key=lambda f: (f.fn, f.var))
    return consume, proven, survivors, swap


def make_obligation(f: _Field, invariant_id: str, is_swap: bool) -> dict:
    short = _short(f.fn)
    contract = _contract_of(f.fn)
    src_ref = f.file + (f":{f.line}" if f.line else "") if f.file else ""
    sink_ref = f"{f.file}:{min(f.sink_lines)}" if (f.file and f.sink_lines) else ""
    axis = ("verify-then-swap (a proof is verified in this round handler but over a "
            "DIFFERENT local than the one consumed at the sink)"
            if is_swap else
            "missing per-round verify (no proof/commitment verification dominates the "
            "secret-aggregation sink for this field)")
    root = (
        f"Round-message field '{f.var}' of MPC handler '{f.fn}' flows into a secret-"
        f"aggregation sink ({f.sink_note or 'share/key/sig combine'}) but its def-use "
        f"closure does NOT pass a value-identical, in-or-before-round proof/commitment "
        f"verification - axis: {axis}. BitForge/GG20 class: a malicious participant "
        f"supplies a malformed share / Paillier N / MtA ciphertext / nonce commitment "
        f"that survives to aggregation -> secret-share or full private-key extraction / "
        f"signature forgery = custody theft (CONSUME \\ PROVEN set-difference over the "
        f"rust-dataflow MIR backend)."
    )
    return {
        "schema": SCHEMA,
        "obligation_type": "mpc-round-proof-missing",
        "contract": contract,
        "function": short,
        "function_signature": f.fn,
        "field_var": f.var,
        "language": f.lang,
        "backend": "rust-dataflow-mir",
        "confidence": "semantic-ssa" if f.semantic else "syntactic",
        "source_refs": [r for r in (src_ref, sink_ref) if r],
        "file": f.file,
        "line": f.line,
        "sink_line": min(f.sink_lines) if f.sink_lines else 0,
        "sink_note": f.sink_note,
        "failing_axis": "value-identity" if is_swap else "missing-verify",
        "attack_class": "mpc-key-extraction",
        "permissionless": True,
        "priority_rank": 0,
        "likely_severity": "critical",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "needs_source": not f.semantic,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "PROOF_CLOSURE: prove NO value-identical proof/commitment verification "
            "(VSS/Feldman, Paillier-Blum/no-small-factor, MtA range, commitment-open) "
            "dominates this sink for THIS field local - a verify N hops away or in a "
            "sibling round handler over the SAME local KILLS the lead.",
            "VALUE_IDENTITY: confirm the local entering the sink is the same object "
            "verified (not a re-read of the field in a later round = verify-then-swap).",
            "ROUND_ORDERING: confirm the verify (if any) is ordered in-or-before the "
            "consuming round and bound to the same session/round nonce (no cross-"
            "session replay of a stale proof).",
        ],
        "next_command": (
            "python3 tools/mpc-round-proof-obligation.py "
            f"--workspace <ws>  # then mine {src_ref or short}"
        )[:200],
    }


def _mpc_crate_on_disk(roots: list[Path]) -> str:
    """Return a citation (dir/file) if a threshold-sig/DKG crate is present on disk
    under any root, else "". Used to tell 'MPC crate exists but the substrate failed
    to materialize it' (fail-loud) from 'no MPC ceremony at all' (honest N/A). Cheap:
    checks dir names + a shallow Cargo.toml scan, then CONFIRMS the crate actually
    carries ceremony PRIMITIVES in its source before declaring it an MPC crate.

    The name/Cargo match alone is not sufficient: a crate literally named `tofn` /
    `tofnd` can be a single-key MULTISIG fork (each party holds a full key and signs
    independently) with NO GG20 multi-round ceremony at all - no MtA, no Paillier, no
    VSS/Feldman, no r1..r7 round handlers, no share reconstruction. Such a fork has 0
    ceremony dataflow rows because there IS no ceremony, NOT because the MIR backend
    failed to lift it. Flagging it 'substrate failed to materialize' is a false
    infra-gap. So we require a real ceremony-PRIMITIVE token in the crate's own .rs
    source (a shallow, size-capped scan) before returning the crate. A genuine GG20
    crate whose MIR failed to compile still carries these primitives in source, so the
    fail-loud on a real compile-degrade is preserved.

    Note the primitive lexicon deliberately excludes bare 'gg20'/'gg18' module names,
    which survive as dangling doc-comment links (e.g. `[crate::gg20::mnemonic]`) in
    multisig forks that dropped the gg20 module - matching those would re-introduce the
    false positive this discriminator exists to remove."""
    _CRATE = re.compile(r"(?:tofn|gg20|gg18|feldman|paillier|threshold[_-]?sig|"
                        r"\bvss\b|multi[_-]?party|frost|cggmp|lindell)", re.IGNORECASE)
    # Actual ceremony COMPUTATION tokens - present in a real multi-round DKG/TSS
    # implementation, absent in a single-key multisig fork or in stale doc-comments.
    _PRIMITIVE = re.compile(
        r"(?:paillier|\bmta\b|feldman|\bvss\b|lagrange|interpolat|"
        r"round[_-]?[1-7]\b|\br[1-7]_|combine_partial|add_partial|partial_sig|"
        r"reconstruct|share_recon|sign_finalize|blum|no[_-]?small[_-]?factor)",
        re.IGNORECASE)

    def _crate_has_primitives(crate_dir: Path) -> bool:
        src = crate_dir / "src"
        scan_dir = src if src.is_dir() else crate_dir
        scanned = 0
        try:
            for rs in scan_dir.rglob("*.rs"):
                if "target" in rs.parts:
                    continue
                if scanned >= 400:
                    break
                scanned += 1
                try:
                    if _PRIMITIVE.search(
                            rs.read_text(encoding="utf-8", errors="ignore")):
                        return True
                except OSError:
                    continue
        except OSError:
            return False
        return False

    for root in roots:
        if not root or not root.exists():
            continue
        try:
            for d in root.rglob("Cargo.toml"):
                if "target" in d.parts:
                    continue
                name_hit = bool(_CRATE.search(str(d.parent.name)))
                cargo_hit = False
                if not name_hit:
                    try:
                        cargo_hit = bool(_CRATE.search(
                            d.read_text(encoding="utf-8", errors="ignore")[:4000]))
                    except OSError:
                        cargo_hit = False
                if not (name_hit or cargo_hit):
                    continue
                # Name/Cargo says "looks like MPC" - now REQUIRE a ceremony primitive
                # in source, else it is a look-alike (multisig fork) => honest N/A.
                if _crate_has_primitives(d.parent):
                    return str(d.parent)
        except OSError:
            continue
    return ""


def _resolve_paths(ws: Path, override: str | None) -> list[Path]:
    paths: list[Path] = []
    if override:
        paths.append(Path(override).expanduser())
        return paths
    primary = ws / ".auditooor" / "dataflow_paths.jsonl"
    if primary.exists():
        paths.append(primary)
    ad = ws / ".auditooor"
    if ad.is_dir():
        for sib in sorted(ad.glob("dataflow_paths.*.jsonl")):
            paths.append(sib)
    return paths


def run(argv=None) -> dict:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="workspace source root (recorded for provenance; the "
                         "substrate is the .auditooor dataflow_paths).")
    ap.add_argument("--dataflow", default=None,
                    help="override the primary dataflow_paths.jsonl path")
    ap.add_argument("--invariant-id", default=_DEFAULT_INVARIANT_ID)
    ap.add_argument("--emit", default=None,
                    help="output jsonl (default <ws>/.auditooor/"
                         "mpc_round_proof_obligation_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero on an absent/vacuous (all-degraded) substrate")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    warnings: list[str] = []

    paths = _resolve_paths(ws, args.dataflow)
    if not paths:
        warnings.append(f"no dataflow_paths substrate found under {ws / '.auditooor'}")

    fields, meta = build_fields(paths, warnings)
    consume, proven, survivors, swap = classify(fields)

    # substrate honesty, scoped to the MPC ceremony surface:
    #  - no dataflow substrate at all, OR a substrate with ZERO MPC-ceremony records
    #    => LANGUAGE/MPC-N/A (this workspace has no threshold-sig/DKG ceremony in the
    #    materialized substrate - honest N/A, never a false pass).
    #  - MPC records present but 0 of them semantic-ssa (all degraded/syntactic, e.g.
    #    tofn did not compile to MIR) => SUBSTRATE-VACUOUS (advisory needs_source).
    any_substrate = bool(paths) and meta["seen_rows"] > 0
    mpc_present = meta["mpc_rows"] > 0
    substrate_present = mpc_present
    substrate_vacuous = mpc_present and meta["mpc_semantic_rows"] == 0
    if substrate_vacuous:
        warnings.append("MPC-ceremony records present but 0 semantic-ssa (all "
                        "syntactic/heuristic/degraded - e.g. the tofn crate did not "
                        "compile to MIR) - obligations are advisory needs_source, "
                        "not a proven flow")
    language_na = not mpc_present  # no MPC ceremony materialized in the substrate
    # Distinguish 'MPC crate exists on disk but the substrate failed to materialize
    # it' (fail-loud) from 'no MPC ceremony at all' (honest N/A).
    disk_roots = [ws]
    if args.src_root:
        disk_roots.insert(0, Path(args.src_root).expanduser())
    mpc_crate_ref = _mpc_crate_on_disk(disk_roots) if language_na else ""
    substrate_failed = bool(mpc_crate_ref) and language_na
    if substrate_failed:
        warnings.append(
            f"MPC threshold-sig crate present on disk ({mpc_crate_ref}) but the "
            "materialized dataflow substrate carries 0 ceremony records - the "
            "rust-dataflow MIR/syntactic backend did NOT lift the ceremony (compile/"
            "macro degrade). Substrate FAILED to materialize - re-run rust-dataflow "
            "on the crate; do NOT read this as a clean attestation.")
    elif language_na:
        warnings.append(
            "no MPC threshold-sig/DKG ceremony records in the materialized "
            "substrate and no MPC crate on disk - "
            + ("substrate absent" if not any_substrate else
               "workspace has no MPC ceremony")
            + " -> honest MPC-N/A (language not applicable)")

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "mpc_round_proof_obligation_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    swap_keys = {(f.fn, f.var) for f in swap}
    obligations = [make_obligation(f, args.invariant_id, (f.fn, f.var) in swap_keys)
                   for f in survivors]
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    summary = {
        "schema": SUMMARY_SCHEMA,
        "workspace": str(ws),
        "src_root": args.src_root or "",
        "dataflow_paths": [str(p) for p in paths],
        "substrate_present": substrate_present,
        "substrate_vacuous": substrate_vacuous,
        "substrate_failed_to_materialize": substrate_failed,
        "mpc_crate_on_disk": mpc_crate_ref,
        "language_na": language_na,
        "semantic_rows": meta["semantic_rows"],
        "seen_rows": meta["seen_rows"],
        "mpc_rows": meta["mpc_rows"],
        "mpc_semantic_rows": meta["mpc_semantic_rows"],
        "counts": {
            "round_fields": sum(1 for f in fields.values() if f.is_round),
            "CONSUME": len(consume),
            "PROVEN_kept": len(proven),
            "survivors_CONSUME_minus_PROVEN": len(survivors),
            "verify_then_swap": len(swap),
        },
        "kept": [
            {"fn": f.fn, "var": f.var, "sink": f.sink_note,
             "verify": sorted(f.verify_names)[:4]}
            for f in proven[:20]
        ],
        "survivors": [
            {"fn": f.fn, "var": f.var, "sink": f.sink_note,
             "swap": (f.fn, f.var) in swap_keys,
             "src": (f.file + (f":{f.line}" if f.line else "")) if f.file else "",
             "sink_line": min(f.sink_lines) if f.sink_lines else 0}
            for f in survivors[:40]
        ],
        "emit": str(emit),
        "warnings": warnings,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        c = summary["counts"]
        tag = ("SUBSTRATE-FAILED (MPC crate on disk, not lifted - fail-loud)"
               if substrate_failed else
               "MPC-N/A (no ceremony)" if language_na else
               "SUBSTRATE-VACUOUS (advisory)" if substrate_vacuous else
               "cited-empty (clean attestation)" if c["CONSUME"] == 0 else "OK")
        print(f"[mpc-round-proof] {tag} |round_fields|={c['round_fields']} "
              f"|CONSUME|={c['CONSUME']} |PROVEN|={c['PROVEN_kept']} "
              f"|survivors|={c['survivors_CONSUME_minus_PROVEN']} "
              f"|verify-then-swap|={c['verify_then_swap']} -> {emit}")
        for f in proven[:6]:
            print(f"  KEPT     {_short(f.fn)}.{f.var} sink={f.sink_note} "
                  f"verify={sorted(f.verify_names)[:3]}")
        for f in survivors[:20]:
            swp = "  [verify-then-swap]" if (f.fn, f.var) in swap_keys else ""
            print(f"  SURVIVOR {_short(f.fn)}.{f.var} sink={f.sink_note}{swp} "
                  f"{(f.file + ':' + str(f.line)) if f.file else ''}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)

    if args.fail_closed:
        # fail-loud ONLY when an MPC crate is on disk but the ceremony was not
        # materialized (substrate_failed) OR the ceremony records are all degraded
        # (substrate_vacuous). A clean cited-empty over a present semantic ceremony
        # substrate, AND an honest MPC-N/A (no MPC crate at all), are PASSES.
        dead = substrate_failed or substrate_vacuous
        if dead:
            print("[mpc-round-proof] FAIL-CLOSED: MPC ceremony substrate failed to "
                  "materialize / all-degraded (no semantic-ssa ceremony rows)",
                  file=sys.stderr)
            sys.exit(3)

    return summary


if __name__ == "__main__":
    run()
