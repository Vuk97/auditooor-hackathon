#!/usr/bin/env python3
"""crossimpl-consensus-divergence.py  (capability RANK-22, HIGH x2)

CROSS-IMPLEMENTATION CONSENSUS DIVERGENCE reasoner - a strict-vs-lenient
ACCEPTANCE-SET divergence screen over CONSENSUS-RELEVANT paths. This is a
GENERAL logic class (never a grep for "Contains").

THE INVARIANT (north-star method, applied to the parse/validate layer)
----------------------------------------------------------------------
Delegated-and-trusted safety property:
    "Every code path that decides accept/reject for a given INPUT TYPE on a
     consensus-relevant path (tx validation, ante, msg routing, block
     processing) agrees on the SAME acceptance set - the set of byte-strings
     it accepts is identical to every other path validating that same input."

The PRIVATE invariant the enforcement leans on:
    "Two paths validating the SAME input agree ONLY IF they use the SAME
     acceptance predicate. A path whose predicate is a LENIENT matcher
     (substring / prefix / suffix / fold / partial-regex / raw ==) accepts a
     SUPERSET of the inputs a STRICT canonical decoder (bech32 decode, hex
     decode + full validate, Unmarshal + ValidateBasic) accepts. When both a
     lenient predicate AND a strict predicate exist for one input type on a
     consensus path, their acceptance sets DIVERGE."

Attack the invariant:
    A crafted input is ACCEPTED by the lenient path and REJECTED by the strict
    path (or vice-versa). Different nodes / different sub-modules that reach
    different paths reach DIFFERENT state for the same block -> consensus split
    / chain-halt / double-spend. Anchor: bech32 non-canonical-encoding splits,
    amino non-canonical accept, address-string prefix-match spoof.

SURVIVOR (the reported lead)
----------------------------
An (input-subject, LENIENT fn) pair where:
  * the LENIENT fn carries a lenient acceptance signal on that subject,
  * the LENIENT fn is reachable on a CONSENSUS-RELEVANT path,
  * the LENIENT fn does NOT itself also strictly-decode that subject
    (it is a lenient-ONLY acceptance),
  * a DISTINCT STRICT sibling fn validating the SAME subject EXISTS (or the
    canonical form is otherwise established elsewhere) - so the two acceptance
    sets provably diverge.
A lenient path with NO strict sibling is NOT a survivor here (no divergence
partner is proven); it is enumerated only as an advisory lead.

ADVISORY-FIRST
--------------
Every emitted obligation carries quality_gate_status="needs_source",
advisory_only=True, auto_credit=False. The tool NEVER auto-credits and NEVER
fail-closes in default mode. --fail-closed (or env
AUDITOOOR_CROSSIMPL_DIVERGENCE_STRICT=1) only raises the exit code when the
source substrate never materialized (0 fns indexed) - a vacuous, NOT honest,
empty. Honest states are distinguished:
  * substrate_vacuous   : 0 fns indexed - source never materialized.
  * class_absent (cited-empty) : real substrate, but no lenient-vs-strict
    acceptance-set divergence pair on a consensus path - the class N/A.
The kill/confirm is a DIFFERENTIAL input: craft a byte-string the lenient path
accepts and the strict path rejects, feed both, assert divergent accept/reject.

Language: Go (.go) primary (Cosmos / cross-chain address+payload parsing).
Silent on trees with no Go consensus substrate.

Usage:
  --workspace/--ws <ws>   scan the ws source tree -> .auditooor/
                          crossimpl_consensus_divergence_obligations.jsonl + summary
  --src-root <dir>        override source root (default <ws>/src, else <ws>)
  --emit <path>           override obligations sidecar path
  --json                  print the summary as JSON
  --fail-closed           exit non-zero iff substrate_vacuous (0 fns indexed)

Schema: auditooor.crossimpl_consensus_divergence.v1
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = "auditooor.crossimpl_consensus_divergence.v1"
INVARIANT_ID = "INV-CROSSIMPL-ACCEPTANCE-SET-AGREEMENT"

# ---------------------------------------------------------------------------
# Input-SUBJECT taxonomy - the input TYPE two paths might both validate.
# A fn "touches" a subject if any of its tokens fire. Subjects are the axis we
# group lenient-vs-strict acceptance predicates over.
# ---------------------------------------------------------------------------
SUBJECTS: dict[str, str] = {
    "address": r"address|acc[_-]?addr|valaddr|bech32|\baddr\b|recipient|sender",
    "chain":   r"chain[_-]?name|chain[_-]?id|source[_-]?chain|dest(ination)?[_-]?chain|\bchain\b",
    "denom":   r"denom|\bcoin\b|token[_-]?symbol|\basset\b|ibc[_-]?denom",
    "payload": r"payload|\bcalldata\b|\bmsg[_-]?data\b|command[_-]?id|\bcommand\b|\bevent\b",
    "amount":  r"amount|\bcoins?\b|\bvalue\b|\bfee\b",
    "hash":    r"\bhash\b|tx[_-]?hash|txid|block[_-]?hash|merkle",
    "signature": r"signature|\bsig\b|\bproof\b|\bseal\b",
    "pubkey":  r"pub[_-]?key|pubkey|verifier[_-]?set|operator[_-]?key",
    "symbol":  r"\bsymbol\b|\bname\b|\blabel\b",
}

# ---------------------------------------------------------------------------
# LENIENT acceptance signals - the predicate accepts a SUPERSET (substring /
# prefix / suffix / case-fold / partial regex / raw string equality without a
# canonical decode). These are the acceptance-set WIDENERS.
# ---------------------------------------------------------------------------
LENIENT_SIGNALS: list[tuple[str, str]] = [
    ("strings.Contains", r"strings\.Contains\s*\("),
    ("strings.HasPrefix", r"strings\.HasPrefix\s*\("),
    ("strings.HasSuffix", r"strings\.HasSuffix\s*\("),
    ("strings.EqualFold", r"strings\.EqualFold\s*\("),
    ("strings.Index", r"strings\.Index\s*\("),
    ("strings.Trim", r"strings\.Trim(Left|Right|Prefix|Suffix|Space)?\s*\("),
    ("strings.ToLower-compare", r"strings\.ToLower\s*\([^)]*\)\s*==|==\s*strings\.ToLower\s*\("),
    ("bytes.Contains", r"bytes\.Contains\s*\("),
    ("bytes.HasPrefix", r"bytes\.HasPrefix\s*\("),
    ("bytes.HasSuffix", r"bytes\.HasSuffix\s*\("),
    ("regexp.MatchString-partial", r"regexp\.MatchString\s*\(|\.MatchString\s*\("),
    ("strings.Split-accept", r"strings\.Split(N|After)?\s*\("),
]

# ---------------------------------------------------------------------------
# STRICT acceptance signals - a canonical decode + full validate. The predicate
# accepts the CANONICAL subset only. These are the acceptance-set NARROWERS.
# ---------------------------------------------------------------------------
STRICT_SIGNALS: list[tuple[str, str]] = [
    ("bech32.Decode", r"bech32\.(Decode|DecodeAndConvert|DecodeNoLimit|ConvertAndEncode)\s*\("),
    ("sdk.AccAddressFromBech32", r"sdk\.(Acc|Val|Cons)Address(FromBech32|FromHex)\s*\("),
    ("AccAddressFromBech32", r"AccAddressFromBech32\s*\(|ValAddressFromBech32\s*\("),
    ("hex.DecodeString", r"hex\.DecodeString\s*\("),
    ("common.IsHexAddress", r"common\.(IsHexAddress|HexToAddress)\s*\("),
    ("json.Unmarshal", r"json\.Unmarshal\s*\("),
    ("proto.Unmarshal", r"proto\.Unmarshal\s*\(|\.Unmarshal\s*\("),
    ("ValidateBasic", r"\.ValidateBasic\s*\(|func[^\n]*ValidateBasic"),
    ("Validate-call", r"\.Validate\s*\(\)"),
    ("sdk.ParseCoins", r"sdk\.Parse(Coins?(Normalized)?|DecCoins?)\s*\("),
    ("big.SetString-ok", r"SetString\s*\([^)]*\)"),
    ("strconv.Parse", r"strconv\.Parse(Uint|Int|Float)\s*\("),
    ("canonical-decode", r"[Cc]anonical|DecodeAndValidate|ParseAndValidate"),
]

# ---------------------------------------------------------------------------
# CONSENSUS-RELEVANT path taxonomy - the fn is reachable on a state-deciding
# path. file OR fn signal qualifies.
# ---------------------------------------------------------------------------
CONSENSUS_FILE_RE = re.compile(
    r"keeper|msg[_-]?server|handler|ante|abci|module\.go|"
    r"execut|deliver|process[_-]?proposal|begin[_-]?block|end[_-]?block|"
    r"genesis|grpc_msg|/msg|tx\.go|command|gateway|verifier|voting|poll",
    re.I)
CONSENSUS_FN_RE = re.compile(
    r"ValidateBasic|AnteHandle|Msg[A-Z]|Handle|DeliverTx|CheckTx|"
    r"ProcessProposal|BeginBlock|EndBlock|Execute|Route|Verify|Process|"
    r"Validate|Decode|Parse|Confirm|Vote|Apply|OnRecv|OnAck|Ingest",
    re.I)

# test / generated / harness exclusion
EXCLUDE_RE = re.compile(
    r"(^|/)(vendor|third_party|\.auditooor|node_modules|testdata|mocks?|"
    r"generated)(/|$)|_test\.go$|\.pb\.go$|\.pb\.gw\.go$|\.pulsar\.go$",
    re.I)

FUNC_RE = re.compile(
    r"func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?P<params>\([^{]*?\))",
    re.S)


@dataclass
class Fn:
    name: str
    file: str
    line: int
    body: str
    header: str
    consensus: bool
    subjects: set = field(default_factory=set)
    lenient: dict = field(default_factory=dict)   # subject -> [signal names]
    strict: dict = field(default_factory=dict)    # subject -> [signal names]


def _iter_go_files(root: Path):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git",)]
        for fn in fns:
            if not fn.endswith(".go"):
                continue
            p = Path(dp) / fn
            rel = str(p)
            if EXCLUDE_RE.search(rel):
                continue
            yield p


def _extract_body(text: str, open_brace_idx: int) -> str:
    depth = 0
    i = open_brace_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace_idx:i + 1]
        i += 1
    return text[open_brace_idx:]


def _classify_subjects(hay: str) -> set:
    out = set()
    for subj, pat in SUBJECTS.items():
        if re.search(pat, hay, re.I):
            out.add(subj)
    return out


def _match_signals(body: str, table) -> list[str]:
    hits = []
    for name, pat in table:
        if re.search(pat, body):
            hits.append(name)
    return hits


def build_fn_index(root: Path, counter: dict | None = None) -> list[Fn]:
    fns: list[Fn] = []
    for p in _iter_go_files(root):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p)
        file_consensus = bool(CONSENSUS_FILE_RE.search(rel))
        for m in FUNC_RE.finditer(text):
            if counter is not None:
                counter["total_go_funcs"] = counter.get("total_go_funcs", 0) + 1
            name = m.group("name")
            params = m.group("params") or ""
            brace = text.find("{", m.end() - 1)
            if brace < 0:
                continue
            body = _extract_body(text, brace)
            if len(body) < 4:
                continue
            line = text.count("\n", 0, m.start()) + 1
            header = name + params
            consensus = file_consensus or bool(CONSENSUS_FN_RE.search(header))
            subj = _classify_subjects(header + " " + body)
            len_hits = _match_signals(body, LENIENT_SIGNALS)
            str_hits = _match_signals(body, STRICT_SIGNALS)
            if not subj or (not len_hits and not str_hits):
                # not a subject-validating predicate - skip
                continue
            lenient = {}
            strict = {}
            for s in subj:
                if len_hits:
                    lenient[s] = len_hits
                if str_hits:
                    strict[s] = str_hits
            fns.append(Fn(
                name=name, file=rel, line=line, body=body, header=header,
                consensus=consensus, subjects=subj,
                lenient=lenient, strict=strict))
    return fns


def analyze(fns: list[Fn]) -> dict:
    # per-subject: lenient fns, strict fns
    lenient_by_subj: dict[str, list[Fn]] = {}
    strict_by_subj: dict[str, list[Fn]] = {}
    for f in fns:
        for s in f.lenient:
            lenient_by_subj.setdefault(s, []).append(f)
        for s in f.strict:
            strict_by_subj.setdefault(s, []).append(f)

    validation_fns = len(fns)
    lenient_consensus = 0
    strict_sibling_subjects = set()
    survivors = []

    for s, lfns in lenient_by_subj.items():
        strict_fns = strict_by_subj.get(s, [])
        strict_ids = {(x.file, x.name) for x in strict_fns}
        has_strict_sibling = False
        for lf in lfns:
            if not lf.consensus:
                continue
            lenient_consensus += 1
            # lenient-ONLY acceptance: this fn does NOT itself strictly decode s
            if s in lf.strict:
                continue
            # a DISTINCT strict sibling exists for the same subject
            siblings = [x for x in strict_fns if (x.file, x.name) != (lf.file, lf.name)]
            if not siblings:
                continue
            has_strict_sibling = True
            sib = siblings[0]
            survivors.append({
                "subject": s,
                "lenient_fn": lf.name,
                "lenient_file": lf.file,
                "lenient_line": lf.line,
                "lenient_signals": sorted({x for v in [lf.lenient[s]] for x in v}),
                "strict_sibling_fn": sib.name,
                "strict_sibling_file": sib.file,
                "strict_sibling_line": sib.line,
                "strict_signals": sorted(set(sib.strict.get(s, []))),
                "n_strict_siblings": len(siblings),
            })
        if has_strict_sibling:
            strict_sibling_subjects.add(s)

    return {
        "validation_fns": validation_fns,
        "lenient_on_consensus_path": lenient_consensus,
        "strict_sibling_subjects": sorted(strict_sibling_subjects),
        "survivors": survivors,
    }


def make_obligation(sv: dict) -> dict:
    src_ref = f"{sv['lenient_file']}:{sv['lenient_line']}"
    sib_ref = f"{sv['strict_sibling_file']}:{sv['strict_sibling_line']}"
    root = (
        f"Function '{sv['lenient_fn']}' validates the input subject "
        f"'{sv['subject']}' with a LENIENT acceptance predicate "
        f"({', '.join(sv['lenient_signals'])}) on a CONSENSUS-RELEVANT path, "
        f"while a DISTINCT sibling '{sv['strict_sibling_fn']}' ({sib_ref}) "
        f"validates the SAME subject with a STRICT canonical decode "
        f"({', '.join(sv['strict_signals']) or 'canonical-decode'}). A lenient "
        f"substring/prefix/fold/partial matcher accepts a SUPERSET of the "
        f"canonical decoder's acceptance set: a crafted '{sv['subject']}' is "
        f"ACCEPTED by '{sv['lenient_fn']}' and REJECTED by "
        f"'{sv['strict_sibling_fn']}' (or vice-versa). Two nodes / sub-modules "
        f"reaching different paths for one block reach DIFFERENT state -> "
        f"consensus split / halt / double-spend (non-canonical bech32 / amino / "
        f"address-prefix-spoof class)."
    )
    return {
        "schema": SCHEMA,
        "obligation_type": "crossimpl-acceptance-set-divergence",
        "contract": "",
        "function": sv["lenient_fn"],
        "function_signature": sv["lenient_fn"],
        "language": "go",
        "source_refs": [src_ref, sib_ref],
        "file": sv["lenient_file"],
        "line": sv["lenient_line"],
        "input_subject": sv["subject"],
        "lenient_predicate": {
            "fn": sv["lenient_fn"], "ref": src_ref,
            "signals": sv["lenient_signals"],
        },
        "strict_sibling_predicate": {
            "fn": sv["strict_sibling_fn"], "ref": sib_ref,
            "signals": sv["strict_signals"],
            "n_siblings": sv["n_strict_siblings"],
        },
        "attack_class": "cross-implementation-consensus-divergence",
        "permissionless": True,
        "priority_rank": 0,
        "likely_severity": "high",
        "broken_invariant_ids": [INVARIANT_ID],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "auto_credit": False,
        "needs_source": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "SAME_INPUT: confirm the lenient fn and the strict sibling genuinely "
            "consume the SAME input type (same subject, same wire representation) "
            "- not two subjects that merely share a token. Cite both param types.",
            "ACCEPTANCE_DIVERGE: craft a concrete byte-string the lenient "
            "predicate ACCEPTS and the strict canonical decode REJECTS (e.g. a "
            "non-canonical bech32, mixed-case address, prefix-collision, "
            "trailing-byte payload). Feed BOTH, assert divergent accept/reject.",
            "CONSENSUS_REACH: prove the lenient path is on a state-deciding path "
            "(tx validation / ante / msg routing / block processing) that a node "
            "actually executes for a block - not an off-path helper or a CLI-only "
            "parse. Cite the caller chain to the consensus entry point.",
            "STATE_SPLIT: show the divergent accept/reject produces DIFFERENT "
            "post-state (different node halts, or one applies a tx the other "
            "rejects) - executed differential, not asserted.",
        ],
        "next_command": (
            "read both fn bodies; if they validate the same input with divergent "
            "strictness on a consensus path, craft the differential input and "
            "drive an executed state-split PoC (accept-vs-reject over the CUT)."
        ),
    }


def run(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", "--ws", dest="workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="override source root (default <ws>/src, else <ws>)")
    ap.add_argument("--emit", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero iff the source substrate never "
                         "materialized (0 fns indexed) - a vacuous, not honest, "
                         "empty")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if args.src_root:
        root = Path(args.src_root).expanduser().resolve()
    else:
        root = ws / "src" if (ws / "src").is_dir() else ws

    counter: dict = {}
    fns = build_fn_index(root, counter)
    total_go_funcs = counter.get("total_go_funcs", 0)
    res = analyze(fns)

    obligations = []
    seen = set()
    for sv in res["survivors"]:
        dk = (sv["lenient_file"], sv["lenient_line"], sv["subject"],
              sv["strict_sibling_file"], sv["strict_sibling_fn"])
        if dk in seen:
            continue
        seen.add(dk)
        obligations.append(make_obligation(sv))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "crossimpl_consensus_divergence_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    # vacuous = the Go source substrate never materialized (no functions at all),
    # NOT merely "no subject-validating predicate" (that is an honest cited-empty).
    substrate_vacuous = (total_go_funcs == 0)
    n_survivors = len(res["survivors"])
    class_present = n_survivors > 0
    # honest cited-empty: real substrate indexed, but no divergence pair
    honest_cited_empty = (not substrate_vacuous) and (not class_present)

    summary = {
        "schema": SCHEMA,
        "workspace": str(ws),
        "src_root": str(root),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_go_functions_scanned": total_go_funcs,
        "n_validation_fns_indexed": res["validation_fns"],
        "n_lenient_on_consensus_path": res["lenient_on_consensus_path"],
        "n_strict_sibling_subjects": len(res["strict_sibling_subjects"]),
        "strict_sibling_subjects": res["strict_sibling_subjects"],
        "n_survivors": n_survivors,
        "survivors": res["survivors"][:60],
        "kept": [
            {"subject": s["subject"], "lenient_fn": s["lenient_fn"],
             "lenient_ref": f"{s['lenient_file']}:{s['lenient_line']}",
             "strict_sibling_fn": s["strict_sibling_fn"],
             "strict_ref": f"{s['strict_sibling_file']}:{s['strict_sibling_line']}"}
            for s in res["survivors"][:60]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "class_present": class_present,
        "substrate_vacuous": substrate_vacuous,
        "honest_cited_empty_class_absent": honest_cited_empty,
        "advisory_only": True,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[crossimpl-consensus-divergence] {ws.name}: "
              f"validation-fns={res['validation_fns']} "
              f"lenient-on-consensus-path={res['lenient_on_consensus_path']} "
              f"strict-sibling-subjects={len(res['strict_sibling_subjects'])} "
              f"survivors={n_survivors} -> {len(obligations)} obligation(s)")
        for s in summary["kept"][:60]:
            print(f"  SURVIVOR subject={s['subject']} LENIENT {s['lenient_fn']} "
                  f"@ {s['lenient_ref']}  vs STRICT {s['strict_sibling_fn']} "
                  f"@ {s['strict_ref']}")
        if honest_cited_empty:
            print("  HONEST-CITED-EMPTY: real substrate indexed, but no "
                  "lenient-vs-strict acceptance-set divergence pair on a "
                  "consensus path - the class does NOT apply (N/A).")
        if substrate_vacuous:
            print("  WARN VACUOUS: 0 validation fns indexed - Go consensus "
                  "substrate never materialized (NOT an honest empty).",
                  file=sys.stderr)
        print(f"  -> {emit}")

    strict_env = os.environ.get("AUDITOOOR_CROSSIMPL_DIVERGENCE_STRICT") == "1"
    if (args.fail_closed or strict_env) and substrate_vacuous:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(run())
