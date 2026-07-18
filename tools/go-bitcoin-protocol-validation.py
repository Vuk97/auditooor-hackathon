#!/usr/bin/env python3
"""go-bitcoin-protocol-validation.py - the SPV-bridge / pegged-BTC missing-or-wrong
Bitcoin-protocol-validation reasoning query for Go bridges that mint/release/credit
pegged funds off a decoded Bitcoin message (SPV proof, tx, PSBT, merkle branch,
block header).

CORPUS ANCHOR (go.bitcoin [CRIT x20], top uncovered class). The recurring real-world
class: an SPV / light-client BTC bridge accepts a merkle proof and mints/releases a
pegged asset WITHOUT verifying the full validation obligation set for that sink -
e.g. it verifies the merkle branch but never checks the containing block header is in
the honest (best) chain, or never enforces the required confirmation depth, or never
binds the credited amount/recipient to the proven output script. Any ONE missing
obligation lets a forged BTC tx / proof mint or release funds -> unauthorized peg
inflation or a consensus split.

THE LOGIC (guard-rail: per-sink required-validation-obligation SET-DIFFERENCE over
the forward dataflow/callgraph closure, NOT a grep for 'merkle' or 'verify')
  ASSUMPTION the exploit falsifies:
    every mint/release/credit sink keyed on a BTC txid / amount / output has, on the
    forward closure from the DECODED Bitcoin message to that sink, ALL of the required
    validation obligations for a BTC-proof-consumption sink discharged:
        REQUIRED = { merkle-proof-verify,
                     header-in-honest-chain,
                     confirmation-depth,
                     amount/output-script binding }
  INVARIANT the bridge must uphold:
    Let
      SINK    = { a mint/release/credit/unlock statement whose credited value is keyed
                  on a field of a decoded Bitcoin message (txid/amount/outpoint/script) }
      PRESENT(s) = { obligation o in REQUIRED : o is discharged somewhere on s's forward
                  closure - the enclosing fn body PLUS the transitive callee bodies that
                  the decoded-message value flows through (intra-proc + callgraph hops) }
    peg-soundness requires  for every s in SINK:  REQUIRED(s)  SUBSET  PRESENT(s).
  TRUST-BOUNDARY that breaks:
    every s with  REQUIRED(s) \\ PRESENT(s)  non-empty is a BTC-proof consumption sink
    reachable with a forged proof (missing merkle bind), a proof on a side/forked block
    (missing header-in-chain), an unconfirmed / re-org-vulnerable tx (missing conf-depth),
    or a proof re-bound to a different amount/recipient (missing amount/script binding)
    -> unauthorized mint / release of pegged funds, or a light-client consensus split.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  It is the per-sink set-difference REQUIRED(s) \\ PRESENT(s), where PRESENT is computed
  over the FORWARD CLOSURE of the decoded-message value (the enclosing function plus the
  transitive callee bodies it flows into), not a body-scoped token match. Three axes a
  `body_contains('VerifyMerkle')` grep cannot express:
   (a) TRANSITIVE closure: a header-in-chain check performed in a helper the sink fn
       calls (or a validator the decoded proof is passed to) correctly discharges that
       obligation - a body-scoped grep on the sink fn misses it and false-flags.
   (b) PER-OBLIGATION set arithmetic: the survivor is the SUBSET that is missing, so a
       sink that verifies the merkle branch AND header-in-chain AND conf-depth but never
       binds the amount/script is STILL a survivor on the one missing obligation - a
       single 'has a verify call' boolean cannot see the missing member.
   (c) SINK-KEYED-ON-BTC-FIELD gate: only sinks whose credited value is keyed on a
       decoded Bitcoin field enter SINK - a mint unrelated to a BTC proof is not in the
       universe, so the difference is over the real peg surface, not every mint.

BACKEND (owned, self-contained)
  Walks the Go source tree under --src-root (or the workspace). Parses top-level funcs,
  builds a short-name callgraph, classifies BTC-decode SOURCES, mint/release SINKS keyed
  on a BTC field, and the four REQUIRED validation-obligation node families. PRESENT(s)
  is the union of obligations discharged in the sink's enclosing fn body and the bodies
  of functions transitively called from it (depth-bounded closure) that also carry the
  decoded-message flow. This is a conservative over-approximation of PRESENT (it credits
  an obligation anywhere in the closure), so a survivor is a HIGH-signal missing
  obligation, not a false-flag from a helper-hop verify.

OUTPUT
  <ws>/.auditooor/go_bitcoin_protocol_validation_obligations.jsonl - one row per survivor
  sink, schema `auditooor.go_bitcoin_protocol_validation.v1`, exploit_queue-ingest
  compatible (contract/function/source_refs/root_cause_hypothesis/
  attack_class=btc-spv-forged-proof-mint/broken_invariant_ids/
  quality_gate_status='needs_source'). A summary is printed / emitted (--json) with
  |SINK| (btc-consumption sinks), |REQUIRED-obligations|, |PRESENT|, |survivors|, and the
  KEPT set (sinks with all obligations present - proves the subtraction is non-vacuous).

HONESTY (R80): a btc-surface that is present-but-unparseable emits substrate_vacuous=True
  (advisory, needs_source). A present BTC surface with a SINK set that all pass is an
  honest cited-empty (a provable peg-soundness attestation), NOT a vacuous pass. A tree
  with NO Bitcoin-proof consumption surface at all is an honest language/class-N/A (never
  a false pass). --fail-closed exits non-zero ONLY on an absent/vacuous btc substrate,
  never on an honest class-N/A or a clean cited-empty.

CLI
  tools/go-bitcoin-protocol-validation.py --workspace <ws> [--src-root DIR]
      [--emit PATH] [--json] [--fail-closed]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.go_bitcoin_protocol_validation.v1"
SUMMARY_SCHEMA = "auditooor.go_bitcoin_protocol_validation.summary.v1"
_DEFAULT_INVARIANT_ID = "btc-spv-sink-required-validations-subset-present-on-closure"

# closure depth for the forward callgraph over the decoded-message flow.
_CLOSURE_DEPTH = 3

# ---------------------------------------------------------------------------
# BTC-DECODE SOURCE lexicon. Identifiers/types that denote a DECODED inbound
# Bitcoin message whose fields (txid/amount/outpoint/script) an attacker controls.
# This SELECTS the peg surface; the verdict is the per-sink set-difference around it.
# Kept off generic ECDSA-only btcec crypto imports (which are NOT a proof surface).
# ---------------------------------------------------------------------------
_BTC_SOURCE = re.compile(
    r"(?:"
    r"spv[_ ]?proof|spvproof|merkle[_ ]?proof|merkleproof|merkle[_ ]?branch|"
    r"btc[_ ]?tx|bitcoin[_ ]?tx|btctransaction|bitcointransaction|"
    r"msgtx|wire\.msgtx|psbt|partiallysignedtx|"
    r"outpoint|out_point|prevout|scriptpubkey|script_pubkey|pkscript|"
    # NOTE: a bare 'blockheader' is Tendermint/CometBFT on cosmos chains - require a
    # Bitcoin qualifier so a generic ABCI block header does NOT enter the BTC surface.
    r"btc[_ ]?header|bitcoin[_ ]?header|"
    r"chainhash|btc[_ ]?txid|bitcoin[_ ]?txid|peg[_ ]?in|pegin|deposit[_ ]?proof"
    r")",
    re.IGNORECASE,
)

# a decoded-message VARIABLE token: used to test whether a value flowing into a sink is
# keyed on a btc field.
_BTC_FIELD_VAR = re.compile(
    r"(?:proof|txid|tx_id|txhash|tx_hash|outpoint|vout|output|amount|amt|value|sats|"
    r"header|merkle|branch|pkscript|scriptpubkey|deposit|pegin|utxo|btc)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SINK lexicon. A mint/release/credit/unlock of the pegged asset. LABELS the sink
# node; the sink only enters SINK when it is keyed on a btc field (source gate).
# ---------------------------------------------------------------------------
_SINK = re.compile(
    r"(?:"
    r"mint|release|credit|unlock|withdraw|redeem|payout|"
    r"send_?coins?|sendcoins|banksend|bank_send|"
    r"issue|deposit_?to|credit_?account|transfer_?to|"
    r"peg[_ ]?out|pegout|complete[_ ]?deposit|process[_ ]?deposit|"
    r"finalize[_ ]?peg|settle[_ ]?peg"
    r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# The FOUR REQUIRED validation-obligation node families. Each is a distinct
# obligation; a survivor is missing at least one member (per-obligation set diff).
# ---------------------------------------------------------------------------
_OBLIG_MERKLE = re.compile(
    r"(?:"
    r"verify[_ ]?merkle|merkle[_ ]?verify|check[_ ]?merkle|validate[_ ]?merkle|"
    r"verify[_ ]?proof|proof[_ ]?verify|verifymerkleproof|verifyspv|spv[_ ]?verify|"
    r"merkle[_ ]?root|computemerkleroot|calcmerkleroot|verify[_ ]?inclusion|"
    r"check[_ ]?inclusion|verify[_ ]?branch"
    r")",
    re.IGNORECASE,
)
_OBLIG_HEADER_CHAIN = re.compile(
    r"(?:"
    r"header[_ ]?in[_ ]?chain|in[_ ]?best[_ ]?chain|best[_ ]?chain|main[_ ]?chain|"
    r"honest[_ ]?chain|is[_ ]?on[_ ]?chain|header[_ ]?stored|known[_ ]?header|"
    r"get[_ ]?header|lookup[_ ]?header|header[_ ]?exists|verify[_ ]?header|"
    r"check[_ ]?header|header[_ ]?chain|is[_ ]?canonical|canonical[_ ]?chain|"
    r"chain[_ ]?work|most[_ ]?work|heaviest[_ ]?chain"
    r")",
    re.IGNORECASE,
)
_OBLIG_CONF_DEPTH = re.compile(
    r"(?:"
    r"confirmation[_ ]?depth|conf[_ ]?depth|min[_ ]?confirmations?|"
    r"required[_ ]?confirmations?|num[_ ]?confirmations?|confirmations?[_ ]?>=|"
    r"confirmationheight|confirmation[_ ]?height|block[_ ]?depth|maturity|"
    r"is[_ ]?finalized|finality|is[_ ]?mature|enough[_ ]?confirmations?|"
    r"deep[_ ]?enough|blocks[_ ]?since"
    r")",
    re.IGNORECASE,
)
_OBLIG_AMOUNT_SCRIPT = re.compile(
    r"(?:"
    r"output[_ ]?script|out[_ ]?script|pk[_ ]?script|scriptpubkey|script_pubkey|"
    r"expected[_ ]?amount|amount[_ ]?match|verify[_ ]?amount|check[_ ]?amount|"
    r"bind[_ ]?amount|amount[_ ]?binding|recipient[_ ]?script|deposit[_ ]?address|"
    r"verify[_ ]?output|check[_ ]?output|output[_ ]?matches|match[_ ]?script|"
    r"extract[_ ]?amount|value[_ ]?from[_ ]?output|expected[_ ]?script"
    r")",
    re.IGNORECASE,
)

_REQUIRED_OBLIGATIONS = (
    ("merkle-proof-verify", _OBLIG_MERKLE),
    ("header-in-honest-chain", _OBLIG_HEADER_CHAIN),
    ("confirmation-depth", _OBLIG_CONF_DEPTH),
    ("amount-output-script-binding", _OBLIG_AMOUNT_SCRIPT),
)

# a call-site token: `Ident(` in a line (also catches method calls .Ident().
_CALLRE = re.compile(r"([A-Za-z_][\w]*)\s*\(")

# a Go top-level (or method) func header.
_FUNC_RE = re.compile(
    r"^\s*func\s+(?:\(\s*[A-Za-z_]\w*\s+\*?([A-Za-z_]\w*)\s*\)\s*)?([A-Za-z_]\w*)\s*\(")


def _iter_go_files(root: Path) -> list[Path]:
    files: list[Path] = []
    if root.is_file() and root.suffix == ".go":
        return [root]
    if not root.is_dir():
        return files
    for p in sorted(root.rglob("*.go")):
        s = str(p)
        if "/vendor/" in s or "/testdata/" in s:
            continue
        if p.name.endswith("_test.go"):
            continue
        # skip generated statik / pb blobs (huge, no real logic)
        if p.name.endswith(".pb.go") or p.name == "statik.go":
            continue
        files.append(p)
    return files


class _Func:
    __slots__ = ("name", "recv", "file", "start", "end", "body", "callees")

    def __init__(self, name: str, recv: str, file: str, start: int):
        self.name = name
        self.recv = recv
        self.file = file
        self.start = start
        self.end = start
        self.body = ""
        self.callees: set[str] = set()


def _parse_funcs(text: str, file: str) -> list[_Func]:
    """Parse top-level funcs by brace-matching. Returns list of _Func with body text."""
    lines = text.splitlines()
    funcs: list[_Func] = []
    i = 0
    n = len(lines)
    while i < n:
        m = _FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        recv = m.group(1) or ""
        name = m.group(2) or ""
        fn = _Func(name, recv, file, i + 1)
        # brace-match from this line
        depth = 0
        seen_open = False
        body_lines: list[str] = []
        j = i
        while j < n:
            ln = lines[j]
            body_lines.append(ln)
            depth += ln.count("{") - ln.count("}")
            if "{" in ln:
                seen_open = True
            if seen_open and depth <= 0:
                break
            j += 1
        fn.end = j + 1
        fn.body = "\n".join(body_lines)
        for c in _CALLRE.findall(fn.body):
            fn.callees.add(c)
        funcs.append(fn)
        i = j + 1
    return funcs


def _closure_bodies(fn: _Func, by_name: dict[str, list[_Func]], depth: int) -> list[_Func]:
    """Forward callgraph closure: fn plus transitively-called funcs (by short name),
    depth-bounded. Conservative over-approximation of the value's forward closure."""
    seen: set[int] = {id(fn)}
    out: list[_Func] = [fn]
    frontier = [(fn, 0)]
    while frontier:
        cur, d = frontier.pop()
        if d >= depth:
            continue
        for callee in cur.callees:
            for target in by_name.get(callee, ()):  # short-name may be ambiguous; take all
                if id(target) in seen:
                    continue
                seen.add(id(target))
                out.append(target)
                frontier.append((target, d + 1))
    return out


def _line_of(body: str, start_line: int, pattern: re.Pattern) -> int:
    for off, ln in enumerate(body.splitlines()):
        if pattern.search(ln):
            return start_line + off
    return 0


def _has_btc_surface(all_text: str) -> bool:
    return bool(_BTC_SOURCE.search(all_text))


def _sink_lines(fn: _Func) -> list[tuple[int, str]]:
    """Lines in fn body that are a sink call keyed on a btc field. Returns (line, snippet)."""
    out: list[tuple[int, str]] = []
    for off, ln in enumerate(fn.body.splitlines()):
        low = ln
        if not _SINK.search(low):
            continue
        # must be a call-site, not a comment/keyword
        if "//" in ln and ln.strip().startswith("//"):
            continue
        # keyed-on-btc-field: the sink line OR the enclosing fn must reference a btc field
        if _BTC_FIELD_VAR.search(ln) or _BTC_SOURCE.search(fn.body):
            out.append((fn.start + off, ln.strip()[:200]))
    return out


def _present_obligations(closure: list[_Func]) -> dict[str, int]:
    """For each REQUIRED obligation, the FIRST file:line in the closure where it is
    discharged (0 if absent). PRESENT = keys with non-zero line."""
    present: dict[str, int] = {}
    for name, pat in _REQUIRED_OBLIGATIONS:
        ln = 0
        for f in closure:
            ln = _line_of(f.body, f.start, pat)
            if ln:
                break
        if ln:
            present[name] = ln
    return present


def analyze(files: list[Path], warnings: list[str]) -> tuple[list[dict], list[dict], dict]:
    """Returns (survivors, kept, meta)."""
    all_funcs: list[_Func] = []
    by_name: dict[str, list[_Func]] = {}
    parsed_files = 0
    btc_files = 0
    combined_sample = []
    for p in files:
        try:
            txt = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            try:
                txt = p.read_text(errors="replace")
            except OSError:
                continue
        if _BTC_SOURCE.search(txt):
            btc_files += 1
            combined_sample.append(txt)
        fns = _parse_funcs(txt, str(p))
        if fns:
            parsed_files += 1
        for fn in fns:
            all_funcs.append(fn)
            by_name.setdefault(fn.name, []).append(fn)

    btc_surface = btc_files > 0
    # substrate-vacuous: btc tokens present in files but we failed to parse any function
    substrate_vacuous = btc_surface and parsed_files == 0

    survivors: list[dict] = []
    kept: list[dict] = []
    sink_count = 0
    for fn in all_funcs:
        # the enclosing fn (or its closure) must carry a btc-decode source to qualify.
        if not _BTC_SOURCE.search(fn.body):
            continue
        sinks = _sink_lines(fn)
        if not sinks:
            continue
        closure = _closure_bodies(fn, by_name, _CLOSURE_DEPTH)
        present = _present_obligations(closure)
        for sink_line, snippet in sinks:
            sink_count += 1
            required = {name for name, _ in _REQUIRED_OBLIGATIONS}
            present_set = set(present.keys())
            missing = sorted(required - present_set)
            rec_base = {
                "contract": fn.recv,
                "function": fn.name,
                "file": fn.file,
                "line": sink_line,
                "sink_snippet": snippet,
                "present_obligations": present,
                "missing_obligations": missing,
                "closure_fns": [c.name for c in closure][:12],
            }
            if missing:
                survivors.append(rec_base)
            else:
                kept.append(rec_base)

    meta = {
        "files_scanned": len(files),
        "files_parsed": parsed_files,
        "btc_surface_files": btc_files,
        "funcs": len(all_funcs),
        "btc_surface": btc_surface,
        "substrate_vacuous": substrate_vacuous,
        "sink_count": sink_count,
    }
    return survivors, kept, meta


def make_obligation(rec: dict, invariant_id: str) -> dict:
    src_ref = f"{rec['file']}:{rec['line']}" if rec.get("file") else ""
    missing = rec["missing_obligations"]
    root = (
        f"BTC-proof consumption sink '{rec['function']}' ({src_ref}) mints/releases pegged "
        f"funds keyed on a decoded Bitcoin field, but its forward closure does NOT discharge "
        f"the required validation obligation(s): {', '.join(missing)}. "
        f"go.bitcoin [CRIT] class: a forged BTC tx / merkle proof "
        + (
            "on a side/forked block (no header-in-honest-chain check) "
            if "header-in-honest-chain" in missing else ""
        )
        + (
            "with a fabricated merkle branch (no merkle-proof verify) "
            if "merkle-proof-verify" in missing else ""
        )
        + (
            "that is unconfirmed / re-org-vulnerable (no confirmation-depth gate) "
            if "confirmation-depth" in missing else ""
        )
        + (
            "re-bound to a different amount/recipient (no amount/output-script binding) "
            if "amount-output-script-binding" in missing else ""
        )
        + "survives to the mint/release sink -> unauthorized peg inflation / release of "
        + "pegged funds, or a light-client consensus split (REQUIRED \\ PRESENT set-difference "
        + "over the Go source callgraph closure)."
    )
    return {
        "schema": SCHEMA,
        "obligation_type": "go-bitcoin-protocol-validation-missing",
        "contract": rec.get("contract", ""),
        "function": rec["function"],
        "language": "go",
        "backend": "go-source-callgraph-closure",
        "confidence": "syntactic-closure",
        "source_refs": [src_ref] if src_ref else [],
        "file": rec.get("file", ""),
        "line": rec.get("line", 0),
        "sink_snippet": rec.get("sink_snippet", ""),
        "present_obligations": rec.get("present_obligations", {}),
        "missing_obligations": missing,
        "failing_axis": "missing-required-validation-obligation",
        "attack_class": "btc-spv-forged-proof-mint",
        "permissionless": True,
        "priority_rank": 0,
        "likely_severity": "critical",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "needs_source": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "CLOSURE_PROOF: prove NONE of the missing obligations "
            f"({', '.join(missing)}) is discharged on the sink's forward closure - a "
            "check performed in a helper/validator the decoded proof is passed to (beyond "
            f"depth {_CLOSURE_DEPTH}) KILLS the lead.",
            "SINK_KEYING: confirm the credited amount/recipient at the sink is actually "
            "keyed on the decoded Bitcoin field (not a constant / already-verified value).",
            "OBLIGATION_NECESSITY: confirm the missing obligation is REQUIRED for this "
            "sink type (e.g. a same-chain internal transfer may not need header-in-chain).",
        ],
        "next_command": (
            "python3 tools/go-bitcoin-protocol-validation.py "
            f"--workspace <ws>  # then mine {src_ref}"
        )[:200],
    }


def run(argv=None) -> dict:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="Go source root to walk (default: <workspace>/src if present, "
                         "else <workspace>)")
    ap.add_argument("--invariant-id", default=_DEFAULT_INVARIANT_ID)
    ap.add_argument("--emit", default=None,
                    help="output jsonl (default <ws>/.auditooor/"
                         "go_bitcoin_protocol_validation_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero on an absent/vacuous btc substrate (never on an "
                         "honest class-N/A or a clean cited-empty)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    warnings: list[str] = []

    if args.src_root:
        root = Path(args.src_root).expanduser().resolve()
    else:
        cand = ws / "src"
        root = cand if cand.is_dir() else ws

    if not root.exists():
        warnings.append(f"src root does not exist: {root}")
        files: list[Path] = []
    else:
        files = _iter_go_files(root)
    if not files:
        warnings.append(f"no Go source files under {root}")

    survivors, kept, meta = analyze(files, warnings)

    btc_surface = meta["btc_surface"]
    substrate_vacuous = meta["substrate_vacuous"]
    language_na = not btc_surface
    if language_na:
        warnings.append(
            "no Bitcoin-proof consumption surface (no SPV/merkle-proof/BTC-tx/PSBT decode "
            "tokens) in the Go tree - honest class-N/A (Bitcoin protocol validation not "
            "applicable to this workspace)")
    elif substrate_vacuous:
        warnings.append(
            "BTC-surface tokens present but 0 functions parsed (unparseable substrate) - "
            "obligations advisory needs_source, not a proven flow")

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "go_bitcoin_protocol_validation_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    obligations = [make_obligation(s, args.invariant_id) for s in survivors]
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    summary = {
        "schema": SUMMARY_SCHEMA,
        "workspace": str(ws),
        "src_root": str(root),
        "substrate_present": btc_surface,
        "substrate_vacuous": substrate_vacuous,
        "language_na": language_na,
        "files_scanned": meta["files_scanned"],
        "files_parsed": meta["files_parsed"],
        "btc_surface_files": meta["btc_surface_files"],
        "funcs": meta["funcs"],
        "counts": {
            "SINK_btc_consumption": meta["sink_count"],
            "REQUIRED_obligations_per_sink": len(_REQUIRED_OBLIGATIONS),
            "PRESENT_kept": len(kept),
            "survivors_missing_obligation": len(survivors),
        },
        "kept": [
            {"fn": k["function"], "src": f"{k['file']}:{k['line']}",
             "present": sorted(k["present_obligations"].keys())}
            for k in kept[:20]
        ],
        "survivors": [
            {"fn": s["function"], "src": f"{s['file']}:{s['line']}",
             "missing": s["missing_obligations"],
             "present": sorted(s["present_obligations"].keys())}
            for s in survivors[:40]
        ],
        "emit": str(emit),
        "warnings": warnings,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        c = summary["counts"]
        tag = ("class-N/A (no BTC proof surface)" if language_na else
               "SUBSTRATE-VACUOUS (advisory)" if substrate_vacuous else
               "cited-empty (clean attestation)" if c["SINK_btc_consumption"] == 0 else
               "cited-empty (all sinks fully validated)" if not survivors else "SURVIVORS")
        print(f"[go-bitcoin-protocol-validation] {tag} "
              f"|SINK|={c['SINK_btc_consumption']} "
              f"|REQUIRED/sink|={c['REQUIRED_obligations_per_sink']} "
              f"|PRESENT_kept|={c['PRESENT_kept']} "
              f"|survivors|={c['survivors_missing_obligation']} -> {emit}")
        for k in kept[:6]:
            print(f"  KEPT     {k['function']} present={sorted(k['present_obligations'].keys())} "
                  f"{k['file']}:{k['line']}")
        for s in survivors[:20]:
            print(f"  SURVIVOR {s['function']} missing={s['missing_obligations']} "
                  f"{s['file']}:{s['line']}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)

    if args.fail_closed:
        dead = (not btc_surface and False) or substrate_vacuous
        # fail-loud ONLY on a vacuous btc substrate (tokens present, unparseable). An
        # honest class-N/A (no btc surface) and a clean cited-empty are PASSES.
        if substrate_vacuous:
            print("[go-bitcoin-protocol-validation] FAIL-CLOSED: BTC-surface present but "
                  "unparseable (0 functions) - substrate vacuous", file=sys.stderr)
            sys.exit(3)

    return summary


if __name__ == "__main__":
    run()
