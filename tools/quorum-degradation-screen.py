#!/usr/bin/env python3
"""quorum-degradation-screen.py - the K-of-N QUORUM-DEGRADATION screen (MQ-B04).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("a TRUSTED ENFORCEMENT is bypassable or its private invariant is
unsound") for one delegated-and-trusted safety property that no existing screen
reaches: the K-of-N aggregation threshold.

  DELEGATED-TRUSTED INVARIANT : an aggregator declares a quorum / threshold K and is
    trusted to only USE its aggregated result (a median, a committee/multisig signature
    set, a validator/attestation tally, a multi-oracle answer) when at least K DISTINCT,
    LIVE inputs agree.
  PRIVATE INVARIANT           : inputs are FILTERED upstream of the aggregation - stale
    ones dropped, zero/sentinel ones skipped, duplicates de-duped, reverting ones caught
    - so the RAW input count N is NOT the SURVIVING distinct-and-live count. The private
    invariant is that the SURVIVING count is RE-ASSERTED against K (`count >= quorum`,
    `support >= threshold`, `len(valid) < K -> revert`) BEFORE the aggregated result is
    committed / returned / acted on.
  ATTACK                      : an attacker who controls the input set drives most inputs
    to be filtered (feeds stale / zero / duplicate / reverting entries) so the surviving
    count silently collapses below K, yet - because only the RAW length (or nothing) was
    checked, never the post-filter survivor count - the aggregator still emits a result
    trusted as "K-of-N agreed". One live input then decides a median / passes a quorum /
    forges a committee decision. The filtering is attacker-drivable and there is no
    upstream visibility (the consumer sees a normal result, not a degraded one).

Enforcement points = each function that is a K-of-N aggregator: it (a) references a
threshold token (quorum / threshold / min-signers / majority `len(x)/2`) AND (b) loops
over / tallies a member-domain collection (signers, oracles, reports, votes, answers,
attestations, validators, guardians, ...). Per point the screen answers:
  {threshold_expr, aggregation_evidence, filter_evidence, reasserts_survivor_count?}
and flags (WARN, verdict=needs-fuzz) ONLY when a threshold is declared AND the inputs are
filtered/tallied AND the surviving count is NOT re-asserted against the threshold.

It is ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode. The strict
env AUDITOOOR_QUORUM_DEGRADATION_STRICT (opt-in, or --strict) only raises the exit code; it
still emits no credit. Language-general: implemented for Solidity (.sol) and Go (.go), the
two fleet languages where K-of-N aggregators live (committee sig count / oracle quorum /
validator majority); silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/quorum_degradation_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir (test / ad-hoc), print rows as JSON
  --file <f>         scan a single .sol/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a degraded aggregator exists
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

HYP_SCHEMA = "auditooor.quorum_degradation_hypotheses.v1"
CAPABILITY = "MQ-B04-quorum-degradation"
_SIDE_NAME = "quorum_degradation_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_QUORUM_DEGRADATION_STRICT"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "node_modules", "forge-std", "mocks"}
# test / mock / script dirs+files are excluded: a quorum aggregator there is not a
# production trust surface (harnesses tally benignly / with synthetic members)
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|script|scripts|examples|"
    r"chimera_harnesses|poc-tests)(/|$)", re.IGNORECASE)
_TEST_FILE_HINT = re.compile(r"(\.t\.sol$|_test\.go$|Mock|Harness|Halmos_|PoC_|Invariant_)")

# --- threshold (K) tokens -----------------------------------------------------
# name-based: a variable/const/param whose identifier names a K-of-N threshold
_THRESHOLD_TOKEN = re.compile(
    r"(?:\b\w*("
    r"quorum|threshold|"
    r"min(?:imum)?[_]?(?:sig(?:ner|nature)?s?|signers?|validators?|responses?|"
    r"answers?|oracles?|confirmations?|approvals?|votes?|participants?|members?|"
    r"weight)|"
    r"required(?:sig\w*|signers?|count|approvals?|votes?)?|"
    r"num[_]?required|sig[_]?threshold"
    r")\w*\b)"
    # `nSigners` / `n_signers` is only a K token as a STANDALONE identifier - anchored
    # so it does NOT match mid-word (e.g. `NewCancu[nSigner]` constructor => not a K).
    r"|(?:\bn[_]?signers?\b)", re.IGNORECASE)
# expression-based majority: `len(x)/2`, `x.length/2`, `total/2`, `... / 2 + 1`
_THRESHOLD_EXPR = re.compile(
    r"(?:len\s*\([^)]*\)|\b\w+\.length|\b\w*(?:signers?|members?|total|count)\w*)"
    r"\s*/\s*2")

# --- member-domain collection / aggregation evidence --------------------------
_AGG_DOMAIN = re.compile(
    r"\b\w*("
    r"support|votes?|tally|tallies|survivors?|"
    r"signers?|signature|oracles?|reports?|answers?|prices?|attestations?|"
    r"participants?|validators?|members?|guardians?|approv\w*|confirm\w*|"
    r"responses?|variants?|feeds?"
    r")\w*\b", re.IGNORECASE)

# --- filter / prune-upstream evidence (raw N != surviving count) --------------
_FILTER_SIG = re.compile(
    r"(\bcontinue\b|\bskip\b|\btry\s*\{|\bcatch\b|"
    r"\brevert\b|\brequire\s*\(|"                       # per-element reject
    r"==\s*0\b|<=\s*0\b|>\s*0\b|"                        # zero / sentinel
    r"address\s*\(\s*0\s*\)|== *nil|!= *nil|err\s*!=\s*nil|"  # nil / zero-addr
    r"stale|updatedAt|expired|deadline|"                # staleness
    r"\bseen\b|\bprev\w*\b|<=\s*prev|already|duplicate|dedup|sorted|"  # dedup
    r"isGuardian|_isGuardian|isValid|isActive|isMember)", re.IGNORECASE)

# --- survivor-TALLY evidence: the function actually COUNTS how many inputs survived
# (a counter increment, or an append/push into a survivors collection). This is the
# discriminating essence of a K-of-N aggregator - "count the valid ones, compare to K" -
# and requiring it drops the vast Go noise floor where a `threshold`-named gas/fee config
# and a ubiquitous `err != nil` filter co-occur without any quorum tally.
_TALLY_SIG = re.compile(
    r"(?:\b\w*(?:count|counter|valid|support|votes?|tally|approv\w*|confirm\w*|"
    r"signatures?|sigs?|survivors?|signers?|weight|quorum|num|total)\w*\s*(?:\+\+|\+=))"
    r"|(?:\+\+\s*\w*(?:count|valid|support|votes?|tally|approv|confirm|sig|weight|num))"
    r"|(?:append\s*\(\s*[\w.]*(?:valid|survivor|signer|sig|support|approv|confirm|vote|"
    r"member|result|report|answer|price))"
    r"|\.push\s*\(", re.IGNORECASE)

# --- count/survivor terms for the re-assertion detector -----------------------
_COUNT_TERM = re.compile(
    r"\b(?:\w+\.)*\w*("
    r"support|votes?|tally|tallies|count|valid\w*|survivors?|num\w*|"
    r"len|length|total|approvals?|confirmations?|responses?|answers?|"
    r"signatures?|signers?|weight|n"
    r")\w*\b|\blen\s*\(", re.IGNORECASE)

# comparison operators that can re-assert a surviving count against K. `==` is included
# because a threshold-equality (`validSigs == $.threshold`, `count == quorum`) is a real
# K-of-N re-assertion; it only ever ADDS a guard (both operands must independently be a
# count term and a threshold term), so it can only make the screen quieter, never noisier.
_CMP = re.compile(r"(<=|>=|==|<|>)")

# function-start: Solidity `function name(` OR Go `func (recv) name(` / `func name(`
_FN_START = re.compile(
    r"^\s*(?:function\s+([A-Za-z_]\w*)|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*))\b")


def _mask_comments(text: str) -> str:
    """Replace `//` line and `/* */` block comments with spaces, preserving newlines
    and per-line length so 0-based line indices stay source-aligned. Not string-literal
    aware (over-masks a `//` inside a string) - that errs toward SILENCE (can only drop a
    would-be token, never invent one), the safe direction for an advisory screen. Without
    this a comment mentioning `quorum` / `>= threshold` would be miscredited as a real
    threshold token or a real re-assertion guard."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
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


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        rp = dp.replace(os.sep, "/")
        if _TEST_HINT.search(rp):
            continue
        for f in fn:
            if not (f.endswith(".sol") or f.endswith(".go")):
                continue
            if _TEST_HINT.search(f) or _TEST_FILE_HINT.search(f):
                continue
            yield Path(dp) / f


def _fn_bodies(lines):
    """Yield (fn_name, start_line_idx, body_line_list) for each Solidity/Go function,
    brace-matched. Language-general (both use `{`..`}` block bodies)."""
    i = 0
    n = len(lines)
    while i < n:
        m = _FN_START.match(lines[i])
        if not m:
            i += 1
            continue
        fn = m.group(1) or m.group(2)
        depth = 0
        started = False
        body = []
        j = i
        while j < n:
            line = lines[j]
            depth += line.count("{") - line.count("}")
            body.append(line)
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield fn, i, body
        i = max(j, i + 1)


def _threshold_evidence(body_text):
    """Return the first threshold token/expr matched (name or majority), or None."""
    m = _THRESHOLD_TOKEN.search(body_text)
    if m:
        return m.group(0)
    m = _THRESHOLD_EXPR.search(body_text)
    if m:
        return m.group(0)
    return None


def _threshold_terms(body_text):
    """Set of concrete threshold sub-strings present (both name tokens + majority exprs),
    used by the re-assertion detector to test whether a comparison's other operand IS the
    declared K."""
    terms = set(m.group(0) for m in _THRESHOLD_TOKEN.finditer(body_text))
    for m in _THRESHOLD_EXPR.finditer(body_text):
        terms.add(m.group(0))
    return terms


_GO_ALIAS = re.compile(
    r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)+)\s*:=\s*(.+)")


def _balanced_comma_split(s):
    """Split `s` on top-level commas only, keeping `(...)`/`[...]`/`{...}` groups intact
    (so `weight, c.TimeoutQuorum()` -> ['weight', 'c.TimeoutQuorum()'])."""
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts]


def _go_line_aliases(line):
    """For a single-line Go tuple assignment `a, b := X, Y` (the `if a, b := X, Y; a<b`
    quorum idiom), return {a: X, b: Y}. Only when the ident-count equals the top-level
    RHS expr-count; RHS is taken up to the first top-level `;` (the condition separator).
    Lets `got < want` re-assert when `got`/`want` alias a count/threshold expression."""
    m = _GO_ALIAS.search(line)
    if not m:
        return {}
    names = [n.strip() for n in m.group(1).split(",")]
    rhs = m.group(2)
    depth, cut = 0, len(rhs)
    for i, ch in enumerate(rhs):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ";" and depth == 0:
            cut = i
            break
    exprs = _balanced_comma_split(rhs[:cut])
    if len(names) != len(exprs):
        return {}
    return {n: e for n, e in zip(names, exprs) if e}


def _last_operand(expr):
    """Rightmost comparison operand of `expr`, keeping BALANCED `(...)` call groups intact
    (so `NumTrueBitsBefore(size)` / `len(sigs)` survive as the survivor-count call form
    rather than truncating to `size)` / `sigs)`), and stopping at an unbalanced boundary:
    an unmatched `(` (a `require(` / `if (` prefix), a `;` Go statement separator, a brace,
    or a `&`/`|` connective."""
    depth = 0
    i = len(expr) - 1
    while i >= 0:
        c = expr[i]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and c in "&|;{}":
            break
        i -= 1
    return expr[i + 1:]


def _reasserts_survivor(body, threshold_terms):
    """The private-invariant guard: is the SURVIVING count re-asserted against K?

    True iff some line holds a comparison `A <op> B` where exactly one side is a
    COUNT/survivor term and the OTHER side references a threshold term (name or majority
    `len(x)/2`). Covers `count >= quorum`, `support >= threshold`, `sigs.length < quorum`,
    `tally.Votes > len(signers)/2`, `len(valid) < K`, the weighted-quorum `weight <
    quorumWeight`, the balanced-call `NumTrueBitsBefore(size) < Threshold`, and the Go
    `if got, want := <count>, <threshold>; got < want` tuple-alias idiom.

    Returns (bool, matched_line_or_None).
    """
    for line in body:
        # Go single-line tuple aliases (`if got, want := count, threshold; got < want`)
        aliases = _go_line_aliases(line)
        for cm in _CMP.finditer(line):
            lhs = line[:cm.start()]
            rhs = line[cm.end():]
            # Extract each comparison operand. LHS: balanced-paren-aware walk left to the
            # last opening boundary. RHS: text up to the next joining boundary (its split
            # set omits a bare `)` / `(`, so a balanced majority `len(signers)/2` stays
            # intact - splitting at its inner `)` truncated the threshold and mis-declared
            # a guarded aggregator as un-reasserted - the clique/HashConsensus false-fire).
            lhs_tail = _last_operand(lhs)
            rhs_head = re.split(r"(?:&&|\|\||[&|;{},])", rhs)[0]
            # resolve a bare Go alias token to its assigned expression before matching
            l_op = aliases.get(lhs_tail.strip(), lhs_tail)
            r_op = aliases.get(rhs_head.strip(), rhs_head)
            l_count = bool(_COUNT_TERM.search(l_op))
            r_count = bool(_COUNT_TERM.search(r_op))
            # threshold side = literal token present OR a majority /2 expr on that side
            l_thr = _side_is_threshold(l_op, threshold_terms)
            r_thr = _side_is_threshold(r_op, threshold_terms)
            if (l_count and r_thr) or (r_count and l_thr):
                return True, line.strip()
    return False, None


def _side_is_threshold(side, threshold_terms):
    if _THRESHOLD_TOKEN.search(side) or _THRESHOLD_EXPR.search(side):
        return True
    for t in threshold_terms:
        if t and t in side:
            return True
    return False


def _stable_id(file_rel, fn, thr):
    h = hashlib.sha1()
    h.update(f"{file_rel}|{fn}|{thr}".encode())
    return h.hexdigest()[:16]


def scan_file(path: Path, rel: str, file_text: str = None):
    """Return a list of enforcement-point rows for one .sol/.go file."""
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lines = text.split("\n")
    lang = "go" if rel.endswith(".go") else "solidity"
    rows = []
    for fn, start_idx, body in _fn_bodies(lines):
        # a `main` entrypoint (CLI / cmd tool) is never a production K-of-N aggregator
        # trust surface; its threshold-ish tokens are flag/log prose, not a quorum.
        if fn == "main":
            continue
        body_text = "\n".join(body)
        # (a) a threshold K must be declared / referenced in the function
        thr = _threshold_evidence(body_text)
        if not thr:
            continue
        # (b) the function must aggregate over a member-domain collection: a loop AND a
        # domain term. Both are required so a lone threshold reference (e.g. a setter) is
        # not an aggregator.
        has_loop = bool(re.search(r"\bfor\b\s*[\(\w]", body_text))
        agg = _AGG_DOMAIN.search(body_text)
        if not (has_loop and agg):
            continue
        # (c) filter / prune-upstream evidence: raw N != surviving count
        filt = _FILTER_SIG.search(body_text)
        if not filt:
            continue
        # (d) survivor-TALLY: the function counts how many inputs survived (the K-of-N
        # discriminator). Without it a `threshold`-named fee config + a stray filter is
        # not a quorum aggregator.
        tally = _TALLY_SIG.search(body_text)
        if not tally:
            continue
        # the private-invariant guard: is the surviving count re-asserted against K?
        thr_terms = _threshold_terms(body_text)
        reasserts, guard_line = _reasserts_survivor(body, thr_terms)
        fires = not reasserts
        rows.append({
            "schema": HYP_SCHEMA,
            "capability": CAPABILITY,
            "id": _stable_id(rel, fn, thr),
            "file": rel,
            "function": fn,
            "line": start_idx + 1,               # 1-indexed source line of the fn
            "lang": lang,
            "threshold_expr": thr,
            "aggregation_evidence": agg.group(0),
            "filter_evidence": filt.group(0).strip(),
            "tally_evidence": tally.group(0).strip(),
            "reasserts_survivor_count": reasserts,
            "guard_line": guard_line,
            "fires": fires,
            # advisory-first contract (never auto-credit, never fail-close)
            "verdict": "needs-fuzz",
            "advisory": True,
            "auto_credit": False,
            "question": (
                f"`{fn}` is a K-of-N aggregator: it references threshold `{thr}`, tallies "
                f"`{agg.group(0)}`, and filters inputs (`{filt.group(0).strip()}`). Is the "
                f"SURVIVING distinct-and-live count re-asserted against the threshold before "
                f"the aggregated result is used, or can an attacker drive inputs to be "
                f"filtered so fewer than K live inputs decide the result?"),
        })
    return rows


def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        rows.extend(scan_file(p, rel))
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
    return {
        "schema": HYP_SCHEMA,
        "capability": CAPABILITY,
        "aggregators": len(rows),
        "fired": len(fired),
        "silent_reasserted": sum(1 for r in rows if r.get("reasserts_survivor_count")),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def _resolve_ws(arg):
    ws = Path(arg)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / arg
        if cand.exists():
            ws = cand
    return ws


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MQ-B04 K-of-N quorum-degradation screen (advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in ("", "0", "false")

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

    ws = _resolve_ws(args.workspace)
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    # ADVISORY-FIRST: default exit 0; strict elevates only when a degraded aggregator exists
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
