#!/usr/bin/env python3
"""abci-phase-predicate-symmetry-screen.py - the ABCI++ CROSS-PHASE ACCEPTANCE-
SYMMETRY screen (EXT02).

GENERAL LOGIC / CROSS-PHASE EQUIVALENCE class (never a bug SHAPE). It instantiates
one delegated-and-trusted safety property that NO single function owns and that
lives only in the COMPOSITION of two independently-correct consensus handlers:

  PHASE-PAIR EQUIVALENCE : an ABCI++ producer phase (PrepareProposal / ExtendVote)
    emits or admits an artifact (a proposed block / a vote extension) that a
    DIFFERENT consumer phase (ProcessProposal / VerifyVoteExtension) later runs its
    OWN acceptance predicate over, on possibly-different local state and inputs. The
    trusted invariant is  producer-ACCEPT  is a SUBSET of  consumer-ACCEPT : every
    artifact the producer is willing to emit must satisfy every predicate the
    consumer enforces. If the consumer enforces a predicate the producer does not
    re-establish, the producer can emit an artifact the consumer REJECTS -> the two
    phases disagree across nodes -> a liveness / DoS divergence (chain halt / round
    stall), with no access-control or reentrancy defect anywhere.

  ATTACK : the consumer's acceptance predicate set is a STRICT superset of what the
    producer guarantees. A proposer-controlled input (mempool ordering, per-sender
    nonce/sequence, total block gas, tx/extension size, signature set) feeds a
    consumer-only predicate; a crafted-but-producer-accepted block trips the
    consumer-only check on every validator.

ANCHOR : cosmos-sdk GHSA-2557-x9mg-76w8 / ASA-2024-002 - the default
PrepareProposalHandler with a SenderNonceMempool produced blocks whose per-sender
nonces were non-sequential; PrepareProposal ACCEPTED them but ProcessProposal /
block-validation REJECTED them, halting the two phases against each other.

WHY NET-NEW : both phases are individually permissioned and reentrancy-free. The
defect is a cross-phase equivalence invariant that emerges from diffing the
acceptance predicates of two distinct handlers plus a mempool - a per-function
detector reasoning inside one body can never see it.

ENFORCEMENT POINTS (the phase-pair graph, producer -> consumer, consumer is the
stricter re-check):
  * PrepareProposal   -> ProcessProposal
  * ExtendVote        -> VerifyVoteExtension
(The spec also lists ProcessProposal->FinalizeBlock and mempool-admission->block-
validity; FinalizeBlock re-executes everything and mempool CheckTx is opaque, so
those are enumerated as methodology dimensions in the summary, not fired inline.)

GENERAL SCREEN (impact-agnostic, no gas/nonce silo):
  1. Enumerate every phase handler (method or `XxxHandler()` closure builder),
     keyed by receiver type + file, mapped to a producer/consumer role + pair.
  2. For a pair whose PRODUCER and CONSUMER are both present on the same receiver,
     extract the CONSUMER's acceptance-predicate items from its guard lines:
       - per-item VALIDATION CALLS (Verify* / Validate* / Check* / Decode* / Ante*),
         normalized by stripping the phase prefix so ProcessProposalVerifyTx and
         PrepareProposalVerifyTx are the SAME shared validator;
       - acceptance DIMENSIONS (gas / size / sequence / signature / height / time /
         hash) inferred from the operand segments;
       - domain OPERANDS (comparison / len() field bases) that are neither.
     A CONSUMER item is COVERED iff the PRODUCER body references the same operand,
     the same normalized validator, or any token of the same dimension. Every
     UNCOVERED item is a phase-asymmetry lead (FIRE).
  3. If a CUSTOM consumer (>=1 validator call or gas/size/sequence/signature dim)
     has NO producer for its receiver anywhere in the tree, emit a lower-tier
     `producer-missing` lead (the default-producer + custom-consumer ASA shape).

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. Default exit 0. The opt-in env
AUDITOOOR_ABCI_PHASE_SYMMETRY_STRICT (or --strict) raises the exit code only on a
fired `phase-asymmetry` (severity-eligible) row; `producer-missing` never trips
strict. The real verdict needs an author attestation citing where the producer re-
establishes the predicate, or a differential harness feeding a Prepare-accepted
block into Process across simulated nodes.

Language: Go only (ABCI++ is a Cosmos-SDK / CometBFT surface). Silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/abci_phase_predicate_symmetry_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a phase-asymmetry fires
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.abci_phase_predicate_symmetry_hypotheses.v1"
_SIDE_NAME = "abci_phase_predicate_symmetry_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_ABCI_PHASE_SYMMETRY_STRICT"
_CAPABILITY = "EXT02"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "docs"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"example|e2e|simulation|fixtures)(/|$)")

# --- machine-generated source exclusion (copied from
#     tools/declared-control-mutator-completeness-screen.py::_is_generated_source)
_GENERATED_SUFFIXES = (
    ".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go", "_generated.go",
)
_GENERATED_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)


def _is_generated_source(path: Path) -> bool:
    if path.name.lower().endswith(_GENERATED_SUFFIXES):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except (OSError, UnicodeError):
        return False
    return bool(_GENERATED_SENTINEL.search(head))


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(".go"):
                continue
            if low.endswith("_test.go"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _is_generated_source(p):
                continue
            yield p


# --- comment / string masking (preserve newlines + length) ------------------
def _mask_comments(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
    quote = ""
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_str:
            out.append(" ")
            if c == "\\" and quote != "`":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c in ('"', "'", "`"):
            in_str = True
            quote = c
            out.append(" ")
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


# --- Go function extraction (brace-matched, with receiver type) -------------
# func (recv *Type) Name(...)  |  func (recv Type) Name(...)  |  func Name(...)
_GO_METHOD_RE = re.compile(
    r"^\s*func\s*\(\s*\w+\s+\*?\s*([A-Za-z_]\w*)\s*\)\s*([A-Za-z_]\w*)\s*\(")
_GO_FUNC_RE = re.compile(r"^\s*func\s+([A-Za-z_]\w*)\s*\(")


def _go_functions(lines):
    """Yield (name, receiver_type, decl_idx, [(abs_idx, line), ...]) per top-level
    Go function/method. Brace-matched so an inner returned closure is folded into
    the outer builder's body (that is where the handler predicate lives)."""
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        m = _GO_METHOD_RE.match(line)
        recv = None
        name = None
        if m:
            recv, name = m.group(1), m.group(2)
        else:
            mf = _GO_FUNC_RE.match(line)
            if mf:
                recv, name = "", mf.group(1)
        if name is None:
            i += 1
            continue
        depth = 0
        started = False
        body = []
        j = i
        while j < n:
            ln = lines[j]
            depth += ln.count("{") - ln.count("}")
            body.append((j, ln))
            if "{" in ln:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield name, recv, i, body
        i = max(j, i + 1)


# --- phase role map ---------------------------------------------------------
# base name (after stripping a trailing "Handler") -> (role, pair, partner_base)
_PHASE_MAP = {
    "prepareproposal": ("producer", "prepare_process", "processproposal"),
    "processproposal": ("consumer", "prepare_process", "prepareproposal"),
    "extendvote": ("producer", "vote_ext", "verifyvoteextension"),
    "verifyvoteextension": ("consumer", "vote_ext", "extendvote"),
}
_PAIR_LABEL = {
    "prepare_process": "PrepareProposal->ProcessProposal",
    "vote_ext": "ExtendVote->VerifyVoteExtension",
}
# phase-name / machinery tokens that are NEVER an input dimension
_PHASE_STOP = {
    "prepareproposal", "processproposal", "extendvote", "verifyvoteextension",
    "prepare", "process", "proposal", "extend", "verify", "vote", "extension",
    "handler", "noop",
}


def _phase_of(name: str):
    base = name.lower()
    if base.endswith("handler"):
        base = base[: -len("handler")]
    return _PHASE_MAP.get(base), base


# --- acceptance DIMENSION lexicon (segment match) ---------------------------
# each dimension: an artifact-acceptance axis a producer must re-establish.
_DIMENSIONS = {
    "gas": ("gas",),
    "sequence": ("sequence", "seq", "nonce"),
    "signature": ("signature", "signer", "signers", "pubkey", "sig"),
    "height": ("height",),
    "time": ("time", "timestamp"),
    "hash": ("hash",),
}
# content-acceptance dimensions (tx-level, not node-local plumbing) that qualify a
# consumer as a genuine re-checker for the producer-missing arm.
_CONTENT_DIMS = {"gas", "size", "sequence", "signature"}

# validator call-name core (a per-item acceptance check).
_VALIDATOR_RE = re.compile(
    r"\b((?:[A-Za-z_]\w*)?(?:Verify|Validate|Decode|Ante)(?:[A-Za-z_]\w*)?"
    r"|(?:[A-Za-z_]*)Check(?:Tx|Total|Block|Gas|Bytes|Size|Proposal)[A-Za-z_]*)"
    r"\s*\(")
# phase / plumbing prefixes stripped when normalizing a validator name.
_VALIDATOR_STRIP = ("prepareproposal", "processproposal", "extendvote",
                    "verifyvoteextension", "prepare", "process", "proposal",
                    "app", "h", "tx")
# a validator call whose RAW name is one of these is the phase's own dispatch /
# declaration (the consumer calling the configured handler, or its own decl line),
# NOT a per-item acceptance validator - never an asymmetry item.
_PHASE_BASE_NAMES = {
    "prepareproposal", "processproposal", "extendvote", "verifyvoteextension",
    "verifyvoteext", "voteextension", "voteext", "prepareproposalhandler",
    "processproposalhandler", "extendvotehandler",
    "verifyvoteextensionhandler",
}
# segments that denote consensus-phase / ABCI response machinery (not an input
# dimension). An identifier whose segments are ALL machinery/stopwords is dropped.
_MACH_SEGS = {
    "response", "request", "accept", "reject", "status", "prepare", "process",
    "proposal", "extend", "verify", "vote", "votes", "extension", "extensions",
    "ext", "handler", "resp", "req", "abci",
    # (de)serialization / codec is symmetric machinery: a producer's Marshal
    # re-establishes what a consumer's Unmarshal decodes - not an input dimension.
    "marshal", "unmarshal", "encode", "decode", "parse", "deserialize",
    "serialize", "sprintf", "errorf",
}


def _is_machinery(name: str) -> bool:
    segs = _segments(name)
    if not segs:
        return True
    return all(s in _MACH_SEGS or s in _STOPWORDS for s in segs)


# transport verbs + proto request/response wrappers + phase nouns. A validator
# call whose name reduces to ONLY these is proto/dispatch plumbing
# (`ToRequestVerifyVoteExtension`, `GetVerifyVoteExtension`, the handler's own
# dispatch), never a per-item content validator.
_TRANSPORT_SEGS = {"to", "get", "set", "new", "from", "make", "build",
                   "request", "response", "req", "resp", "toproto", "fromproto"}
_PHASE_NOUN_SEGS = {"prepare", "process", "proposal", "extend", "vote", "votes",
                    "verify", "extension", "extensions", "handler", "ext",
                    "abci"}


def _validator_is_machinery(raw: str) -> bool:
    segs = [s for s in _segments(raw)
            if s not in _TRANSPORT_SEGS and s not in _PHASE_NOUN_SEGS]
    return len(segs) == 0

_RELOP_RE = re.compile(r"(<=|>=|==|!=|<|>)")

# generic identifiers / packages that never denote an acceptance input.
_STOPWORDS = {
    "i", "j", "k", "n", "x", "y", "z", "err", "nil", "ok", "res", "req", "resp",
    "request", "response", "status", "abci", "sdk", "ctx", "context", "len",
    "cap", "make", "true", "false", "range", "return", "val", "v", "e", "t", "b",
    "s", "buf", "tx", "txs", "bz", "this", "self", "app", "h", "cli", "w", "for",
    "if", "case", "switch", "else", "func", "type", "var", "const", "int", "int64",
    "uint", "uint64", "string", "bool", "byte", "error", "new", "get", "set",
    "reject", "accept", "result", "logger", "log", "info", "debug", "field",
    "found", "plan", "start", "add", "record", "since",
}
_PACKAGES = {"bytes", "json", "fmt", "rand", "errors", "time", "strings",
             "binary", "hex", "proto", "types", "mempool", "baseapp",
             "telemetry", "metrics", "coreheader", "cmtproto", "math"}


def _field_base(expr: str) -> str:
    seg = re.sub(r"\[[^\]]*\]", "", expr)
    parts = [p.strip() for p in seg.split(".") if p.strip()]
    return parts[-1] if parts else seg.strip()


def _segments(name: str):
    s = re.sub(r"_", " ", name)
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)
    return [w.lower() for w in s.split() if w]


def _dim_of(name: str):
    segs = set(_segments(name))
    # SIZE is special-cased: the bare segment `bytes` is too loose (the tx-bytes
    # loop vars `txBytes` / `txBz` / `voteBytes` are not size bounds). Require an
    # explicit `size` segment or a max/limit + bytes combo (MaxTxBytes / MaxBytes).
    if "size" in segs or ("bytes" in segs and (
            "max" in segs or "limit" in segs or "maximum" in segs)):
        return "size"
    for dim, toks in _DIMENSIONS.items():
        if any(t in segs for t in toks):
            return dim
    return None


def _norm_validator(name: str) -> str:
    s = name.lower()
    for pre in _VALIDATOR_STRIP:
        if s.startswith(pre) and len(s) > len(pre):
            s = s[len(pre):]
    return s


def _all_tokens(body):
    """Every identifier segment referenced anywhere in a function body (lowercased,
    field-base + segments). This is the producer's coverage vocabulary - a broad
    (conservative) set so a token the producer mentions in ANY context counts as
    coverage (advisory-first errs toward SILENCE)."""
    toks = set()
    dims = set()
    validators = set()
    for _idx, line in body:
        for m in re.finditer(r"[A-Za-z_]\w*", line):
            w = m.group(0)
            wl = w.lower()
            toks.add(wl)
            for seg in _segments(w):
                toks.add(seg)
            d = _dim_of(w)
            if d:
                dims.add(d)
        for vm in _VALIDATOR_RE.finditer(line):
            validators.add(_norm_validator(vm.group(1)))
        # producer size-coverage: an allocation with a length, or a len() use
        if re.search(r"\bmake\s*\(\s*\[\s*\]\s*byte", line) or re.search(
                r"\blen\s*\(", line):
            dims.add("size")
    return toks, dims, validators


def _guard_items(body):
    """From a CONSUMER body, extract acceptance-predicate items on guard lines.
    Returns a dict item_key -> {kind, sample_line, sample_idx, detail}."""
    items = {}

    def _add(key, kind, idx, line, detail):
        if key not in items:
            items[key] = {
                "kind": kind, "line_idx": idx,
                "sample": line.strip()[:200], "detail": detail,
            }

    def _drop_operand(fb: str) -> bool:
        fbl = fb.lower()
        return (not fbl or fbl.isdigit() or fbl in _STOPWORDS
                or fbl in _PACKAGES or fbl in _PHASE_STOP or _is_machinery(fb))

    for idx, line in body:
        # never mine the declaration / signature line: the handler's OWN phase name
        # (`func (app *BaseApp) VerifyVoteExtension(...)`) is not an acceptance item.
        if re.match(r"^\s*func\b", line):
            continue
        is_guard = bool(
            re.search(r"\b(if|case|switch|for)\b", line)
            or _RELOP_RE.search(line))
        has_validator = bool(_VALIDATOR_RE.search(line))
        if not (is_guard or has_validator):
            continue

        # (a) validator calls (acceptance checks) - captured wherever they appear,
        # but NOT the phase's own dispatch call (`app.verifyVoteExt(...)`).
        for vm in _VALIDATOR_RE.finditer(line):
            raw = vm.group(1).lower()
            if raw in _PHASE_BASE_NAMES or _validator_is_machinery(vm.group(1)):
                continue
            norm = _norm_validator(vm.group(1))
            if not norm or norm in _STOPWORDS or norm in _PHASE_BASE_NAMES:
                continue
            _add(("validator", norm), "validator", idx, line, vm.group(1))

        if not is_guard:
            continue

        # (a2) DIMENSION pass over every field-base on the guard line (curated
        # vocab -> safe). Uses field-bases (rightmost segment of a dotted chain) so
        # a package selector like `bytes.Equal` yields `Equal` (no dim), while
        # `app.checkTotalBlockGas` yields the gas dim and `req.MaxTxBytes` the size
        # dim - catching content checks written as calls, not just comparisons.
        for tm in re.finditer(r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*", line):
            fb = _field_base(tm.group(0))
            dim = _dim_of(fb)
            if dim:
                _add(("dim", dim), "dimension", idx, line, dim)

        # (b) len(EXPR) <relop> N  -> operand = field base of EXPR (+ size dim)
        for lm in re.finditer(r"\blen\s*\(\s*([^)]+?)\s*\)", line):
            fb = _field_base(lm.group(1))
            if not _drop_operand(fb):
                _add(("operand", fb.lower()), "operand", idx, line, fb)

        # (c) comparison operands (both sides) -> dimension or domain operand
        parts = _RELOP_RE.split(line)
        p = 1
        while p < len(parts) - 1:
            for side in (parts[p - 1], parts[p + 1]):
                for tm in re.finditer(r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*",
                                      side):
                    fb = _field_base(tm.group(0))
                    dim = _dim_of(fb)
                    if dim:
                        _add(("dim", dim), "dimension", idx, line, dim)
                    elif not _drop_operand(fb):
                        _add(("operand", fb.lower()), "operand", idx, line, fb)
            p += 2
    return items


def _item_covered(key, item, prod_toks, prod_dims, prod_validators) -> bool:
    kind = key[0]
    val = key[1]
    if kind == "validator":
        return val in prod_validators
    if kind == "dim":
        return val in prod_dims
    # operand: exact token OR the operand maps to a dimension the producer has
    if val in prod_toks:
        return True
    dim = _dim_of(val)
    if dim and dim in prod_dims:
        return True
    return False


def _consumer_is_content_checker(items) -> bool:
    for key in items:
        if key[0] == "validator":
            return True
        if key[0] == "dim" and key[1] in _CONTENT_DIMS:
            return True
    return False


def _stable_id(rel, receiver, pair, item_key):
    h = hashlib.sha1()
    h.update(f"{rel}|{receiver}|{pair}|{item_key}".encode())
    return h.hexdigest()[:16]


def _row(rel, pair, receiver, producer_fn, consumer_fn, consumer_line,
         kind, item, detail, sample, producer_covers, producer_passthrough,
         severity_eligible, fires, question):
    prod_lbl, cons_lbl = _PAIR_LABEL[pair].split("->")
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, receiver, pair, str(item)),
        "file": rel,
        "line": consumer_line + 1,
        "function": consumer_fn,
        "lang": "go",
        "kind": kind,
        "pair": _PAIR_LABEL[pair],
        "producer_phase": prod_lbl,
        "consumer_phase": cons_lbl,
        "producer_function": producer_fn,
        "consumer_function": consumer_fn,
        "receiver_type": receiver,
        "asymmetric_item": str(item),
        "asymmetric_detail": detail,
        "consumer_predicate": sample,
        "producer_covers": producer_covers,
        "producer_passthrough": producer_passthrough,
        "severity_eligible": severity_eligible,
        "fires": fires,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
        "question": question,
    }


# --- passthrough / noop producer recognizer ---------------------------------
_PASSTHROUGH_RE = re.compile(
    r"return\s+&?\s*\w*\{?\s*(Txs\s*:\s*req\.Txs|"
    r"Status\s*:\s*\w*_ACCEPT|VoteExtension\s*:\s*\[\s*\]\s*byte)")


def _is_passthrough(body) -> bool:
    text = "\n".join(l for _i, l in body)
    if _VALIDATOR_RE.search(text):
        return False
    if _RELOP_RE.search(re.sub(r"req\.Height\s*<\s*1", "", text)):
        # has some real comparison beyond the boilerplate height>=1 guard
        # (still could be passthrough; only trust the explicit return form)
        pass
    return bool(_PASSTHROUGH_RE.search(text))


# --- tree scan --------------------------------------------------------------
def _collect_phase_fns(root: Path):
    """Return list of phase-fn records across the tree."""
    fns = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            raw = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not re.search(r"(PrepareProposal|ProcessProposal|ExtendVote|"
                         r"VerifyVoteExtension)", raw):
            continue
        text = _mask_comments(raw)
        lines = text.split("\n")
        for name, recv, decl_idx, body in _go_functions(lines):
            phase, base = _phase_of(name)
            if phase is None:
                continue
            role, pair, partner = phase
            fns.append({
                "rel": rel, "name": name, "receiver": recv or "",
                "role": role, "pair": pair, "partner": partner,
                "base": base, "decl_idx": decl_idx, "body": body,
            })
    return fns


def scan_tree(root: Path):
    fns = _collect_phase_fns(root)
    rows = []

    # group by (rel, receiver, pair): pairing is same-file + same-receiver.
    groups = {}
    for f in fns:
        groups.setdefault((f["rel"], f["receiver"], f["pair"]), []).append(f)

    # index of receiver -> set of (base) producer roles present ANYWHERE (for the
    # producer-missing arm - a consumer with no producer for its receiver at all).
    recv_has_producer = {}  # (receiver, pair) -> bool
    for f in fns:
        if f["role"] == "producer":
            recv_has_producer[(f["receiver"], f["pair"])] = True

    seen_producer_missing = set()

    for (rel, receiver, pair), members in groups.items():
        producers = [m for m in members if m["role"] == "producer"]
        consumers = [m for m in members if m["role"] == "consumer"]

        for cons in consumers:
            items = _guard_items(cons["body"])
            if not items:
                continue

            if producers:
                prod = producers[0]
                ptoks, pdims, pvals = _all_tokens(prod["body"])
                passthrough = _is_passthrough(prod["body"])
                for key, meta in items.items():
                    covered = _item_covered(key, meta, ptoks, pdims, pvals)
                    if covered:
                        continue
                    plbl, clbl = _PAIR_LABEL[pair].split("->")
                    q = (f"phase-asymmetry: predicate `{meta['detail']}` "
                         f"({meta['kind']}) is enforced in {clbl} "
                         f"(`{cons['name']}`) but {plbl} (`{prod['name']}`) does "
                         f"not re-establish it; can a proposer emit a "
                         f"{plbl}-accepted artifact that trips this "
                         f"{clbl}-only check across nodes (liveness/DoS "
                         f"divergence)? Attest where the producer re-enforces it, "
                         f"or run a Prepare->Process differential harness.")
                    rows.append(_row(
                        rel, pair, receiver, prod["name"], cons["name"],
                        meta["line_idx"], "phase-asymmetry", key[1],
                        meta["detail"], meta["sample"],
                        False, passthrough, True, True, q))
            else:
                # producer-missing arm: consumer is a genuine content re-checker
                # but no producer exists for this receiver anywhere in the tree.
                if recv_has_producer.get((receiver, pair)):
                    continue
                if not _consumer_is_content_checker(items):
                    continue
                mk = (rel, receiver, pair)
                if mk in seen_producer_missing:
                    continue
                seen_producer_missing.add(mk)
                plbl, clbl = _PAIR_LABEL[pair].split("->")
                # summarize the content items
                content = sorted({
                    (k[1] if k[0] != "validator" else f"validator:{k[1]}")
                    for k in items
                    if k[0] == "validator" or (k[0] == "dim"
                                               and k[1] in _CONTENT_DIMS)
                })
                # anchor to the first content-item line
                anchor_idx = min(
                    meta["line_idx"] for key, meta in items.items()
                    if key[0] == "validator" or (key[0] == "dim"
                                                 and key[1] in _CONTENT_DIMS))
                q = (f"producer-missing: custom {clbl} (`{cons['name']}`, "
                     f"receiver `{receiver}`) enforces content predicates "
                     f"{content} but no custom {plbl} is defined for this "
                     f"receiver - the default/base producer may not re-establish "
                     f"them (the ASA-2024-002 default-producer + custom-consumer "
                     f"shape). Confirm the wired {plbl} enforces {content}, else "
                     f"a proposer can build a block this {clbl} rejects.")
                rows.append(_row(
                    rel, pair, receiver, "<none-for-receiver>", cons["name"],
                    anchor_idx, "producer-missing", ",".join(content),
                    ",".join(content), "", False, False, False, True, q))
    return rows


def scan_file(path: Path, rel: str):
    """Single-file scan (pairing limited to what the file contains)."""
    root = path.parent
    # reuse scan_tree machinery but only over this one file
    raw = path.read_text(encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lines = text.split("\n")
    fns = []
    for name, recv, decl_idx, body in _go_functions(lines):
        phase, base = _phase_of(name)
        if phase is None:
            continue
        role, pair, partner = phase
        fns.append({
            "rel": rel, "name": name, "receiver": recv or "",
            "role": role, "pair": pair, "partner": partner,
            "base": base, "decl_idx": decl_idx, "body": body,
        })
    rows = []
    groups = {}
    for f in fns:
        groups.setdefault((f["rel"], f["receiver"], f["pair"]), []).append(f)
    for (rel_, receiver, pair), members in groups.items():
        producers = [m for m in members if m["role"] == "producer"]
        consumers = [m for m in members if m["role"] == "consumer"]
        for cons in consumers:
            items = _guard_items(cons["body"])
            if not items or not producers:
                continue
            prod = producers[0]
            ptoks, pdims, pvals = _all_tokens(prod["body"])
            passthrough = _is_passthrough(prod["body"])
            for key, meta in items.items():
                if _item_covered(key, meta, ptoks, pdims, pvals):
                    continue
                plbl, clbl = _PAIR_LABEL[pair].split("->")
                q = (f"phase-asymmetry: `{meta['detail']}` enforced in {clbl} "
                     f"not re-established in {plbl}.")
                rows.append(_row(
                    rel_, pair, receiver, prod["name"], cons["name"],
                    meta["line_idx"], "phase-asymmetry", key[1],
                    meta["detail"], meta["sample"], False, passthrough,
                    True, True, q))
    return rows


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    sev = [r for r in fired if r.get("severity_eligible")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "phase_pairs_enumerated": sorted(_PAIR_LABEL.values()) + [
            "ProcessProposal->FinalizeBlock (methodology: re-executes all)",
            "mempool-admission->block-validity (methodology: CheckTx opaque)",
        ],
        "enforcement_points": len(rows),
        "fired": len(fired),
        "phase_asymmetry": sum(
            1 for r in fired if r.get("kind") == "phase-asymmetry"),
        "producer_missing": sum(
            1 for r in fired if r.get("kind") == "producer-missing"),
        "severity_eligible_fired": len(sev),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT02 ABCI++ cross-phase acceptance-symmetry screen (advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(
        _STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["severity_eligible_fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["severity_eligible_fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
