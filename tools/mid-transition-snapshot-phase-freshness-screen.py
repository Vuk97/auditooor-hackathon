#!/usr/bin/env python3
"""mid-transition-snapshot-phase-freshness-screen.py - EXT2-01, the CROSS-LAYER
PHASE-FRESHNESS screen (a snapshot/checkpoint/proof of a LOWER or independent
layer's state, captured while that layer is MID-TRANSITION, pinned as
authoritative by an upstream enforcer).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("A TRUSTED ENFORCEMENT is bypassable or its private invariant
is unsound") for one temporal-composition property that no per-function detector
owns:

  TRUSTED ENFORCEMENT : an upstream module reads a LOWER / independent layer's
    state through a SNAPSHOT / CHECKPOINT / PROOF (a beacon-chain validator
    proof, an L2 output-root / withdrawal proof, an oracle report, a bridge
    checkpoint) and CREDITS / RECORDS / FINALIZES an authoritative quantity
    (shares / balance / a report / an unlock) from a value read out of it.
  PRIVATE INVARIANT   : that snapshot must be REJECTED while the lower layer is
    MID-TRANSITION - i.e. occupying a TRANSIENT state it can only hold during an
    upgrade, a deposit/withdraw queue, an epoch rollover, a prune, an exit, or a
    migration window (effectiveBalance reset to 0, activationEpoch / exitEpoch =
    FAR_FUTURE_EPOCH, a 'pending'/'sweeping'/'exiting' status, a dispute game
    still IN_PROGRESS). The freshness / validity check is only sound if it is a
    PHASE check that rejects that window - not merely an AGE check.
  ATTACK              : the upstream freshness gate is AGE-based (timestamp /
    roundId / refSlot) or absent, so a snapshot captured INSIDE the transition
    window PASSES the age check yet pins a stale mid-transition value; the lower
    layer later 'restores' that field to a different value, leaving the upstream
    enforcer blind to the corrupted lower-layer state.

This is CRITICALLY DISTINCT from the standard oracle-staleness detector: that
checks AGE-freshness (how OLD is the value); this checks PHASE-freshness (was the
value captured while the source was mid-transition). A snapshot can be perfectly
fresh by age and still pin a transient value - the phase-freshness gap. Anchor:
the Certora / Spearbit FV of EigenLayer's Electra/Pectra integration, where a
31-ETH validator in the deposit queue has effectiveBalance reset to 0 and
activationEpoch = FAR_FUTURE_EPOCH; an EigenLayer checkpoint captured in that
window preserves a stale balance, later restored, so shares represent an
unactivated validator. Concrete guard: activationEpoch != FAR_FUTURE_EPOCH before
crediting shares.

Enforcement points = every non-view function that (1) CONSUMES a cross-layer
snapshot/checkpoint/proof, (2) references a LOWER-LAYER TRANSIENT state field, and
(3) drives an authoritative CREDIT/RECORD/FINALIZE sink. The screen answers per
point:
  {snapshot_tokens, transient_tokens, sink_tokens, has_phase_guard,
   phase_guard_kinds, has_age_freshness, lang}
and flags (WARN, verdict='needs-fuzz') ONLY when the point CONSUMES a cross-layer
snapshot, references a lower-layer transient field, drives an authoritative sink,
and has NO PHASE-FRESHNESS guard rejecting the transition window (a bare AGE check
does NOT suppress it - that is exactly the gap).

Reachability: the snapshot/transient/sink/guard tokens are resolved over the
function body PLUS the bodies of same-file internal helpers it calls (1 hop), so a
guard that lives in a `_verify...` helper still suppresses the flag on the public
entrypoint that calls it (the real lido ValidatorExitDelayVerifier shape).

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_PHASE_FRESHNESS_STRICT (or --strict) only raises the exit
code when a severity-eligible point fired. Machine-generated / test / sim /
chimera code is excluded (shared synthetic_target_exclusion + the .go/.sol
_is_generated_source screen).

Language-general: Solidity (.sol) and Go (.go). Silent on other trees.

Usage:
  --workspace/--ws <ws>  scan <ws>/src -> .auditooor/<sidecar>.jsonl + summary
  --source <dir>         scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>             scan a single .sol/.go file, print rows as JSON
  --check                re-read the emitted sidecar, print cert verdict (advisory)
  --strict               (or env) elevate exit code when a fired point exists
  --json                 machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# --- shared exclusion helpers (MANDATORY reuse) ----------------------------
from lib.synthetic_target_exclusion import (  # noqa: E402
    is_chimera_mutation_harness_path,
    is_codegen_path,
    is_test_target_path,
)


def _load_generated_source_screen():
    """Import _is_generated_source from the hyphen-named declared-control screen."""
    spec = importlib.util.spec_from_file_location(
        "_declared_control_mutator_completeness_screen",
        TOOLS_DIR / "declared-control-mutator-completeness-screen.py",
    )
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            return getattr(mod, "_is_generated_source", None)
        except Exception:
            return None
    return None


_IS_GENERATED_SOURCE = _load_generated_source_screen()


HYP_SCHEMA = "auditooor.mid_transition_snapshot_phase_freshness_hypotheses.v1"
_SIDE_NAME = "mid_transition_snapshot_phase_freshness_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_PHASE_FRESHNESS_STRICT"
_CAPABILITY = "EXT2_01"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "chimera_harnesses", "coverage",
              # non-production tooling: CLI mains + deploy/ops rigs are not the
              # audited attack surface (attackers do not call your deploy script).
              "cmd", "ops", "deployer", "interopgen", "tooling", "devtools"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|simulation|simapp|sim|testdata|e2e|op-e2e|devstack|devnet|"
    r"op-devstack|op-test-sequencer)(/|$)", re.I)


# --------------------------------------------------------------------------- #
# Lexicons (matched as substrings over comment-masked, lower-cased text).      #
# --------------------------------------------------------------------------- #

# (1) A cross-layer SNAPSHOT / CHECKPOINT / PROOF that READS and verifies a
#     LOWER/independent layer's state. Substring match, but deliberately NOT the
#     bare word "beacon": `depositToBeaconChain` / `pauseBeaconChainDeposits` are
#     WRITES to the beacon chain (a deposit), not a proof READ of its state. Every
#     token here denotes an actual verified-state artifact (a proof / merkle / ssz
#     root / validator witness / oracle-consensus report).
_SNAPSHOT_SUBSTR = (
    "proof", "checkpoint", "snapshot", "stateroot", "state_root",
    "outputroot", "output_root", "merkle", "attestation", "consensusstate",
    "consensus_state", "lightclient", "light_client", "historicalheader",
    "historical_summaries", "validatorfields", "validatorwitness",
    "beaconstate", "beacon_state", "beaconblockroot", "beacon_block_root",
    "ssz.", " ssz", "sszproof", "witnesses",
)

# (2a) STRONG lower-layer TRANSIENT-state tokens (beacon/validator/queue
#      lifecycle - a value/status a source can only hold mid-transition).
_STRONG_TRANSIENT = (
    "activationepoch", "activationeligibilityepoch", "exitepoch",
    "withdrawableepoch", "effectivebalance", "far_future", "farfuture",
    "pendingactivation", "pendingdeposit", "activationqueue", "depositqueue",
    "withdrawalqueue", "validatorstage", "validatorstatus", "beaconchain",
)
# (2b) GENERIC cross-layer transition tokens (reorg / dispute / migration /
#      epoch rollover). Needs >=2 distinct of these (or >=1 strong) to qualify -
#      keeps the point tied to a genuine lower-layer phase, not config noise.
_GENERIC_TRANSIENT = (
    "validator", "slashed", "sweeping", "exiting", "inprogress", "in_progress",
    "gamestatus", "disputegame", "dispute", "challeng", "finaliz",
    "blacklistedgame", "reorg", "midtransition", "mid_transition", "rollover",
    "epoch", "refslot", "pending", "sweep", "activation", "withdrawable",
)

# (3) AUTHORITATIVE sink: a credit / record / finalize that pins the snapshot.
_SINK_VERBS = (
    "mint", "credit", "deposit", "stake", "increasebalance", "addshares",
    "add_shares", "recordbalance", "updatebalance", "report", "unlock",
    "settle", "finalizewithdrawal", "finalize_withdrawal", "creditshares",
)
_ACCT_WRITE_RE = re.compile(
    r"(?:balance|shares|locked|total|credit|deposited|staked|amount|minted)"
    r"[\w.]*\s*(?:\+=|-=|=(?!=))")

# AGE-freshness tokens (a bare age check does NOT suppress a phase flag - it is
# the whole point of the class that an age check passes yet pins a phase value).
_AGE_FRESHNESS_SUBSTR = (
    "block.timestamp", "block.number", "updatedat", "updated_at", "roundid",
    "round_id", "staleness", "stale", "maxage", "max_age", "lastupdate",
    "last_update", "deadline", "expiry", "expiration", "refslottimestamp",
    "proofslottimestamp",
)


# --------------------------------------------------------------------------- #
# PHASE-FRESHNESS guard (the CORE PREDICATE).                                  #
# Returns (bool, list[str]) - whether the effective text rejects a             #
# mid-transition value, and which guard kinds matched.                         #
# --------------------------------------------------------------------------- #

_EPOCH_FIELD_RE = re.compile(r"(activation|exit|withdrawable|eligibility)\w*epoch")
_SENTINEL_TXT = ("far_future", "farfuture", "0xffffffffffffffff")
_EPOCH_PIN_RE = re.compile(
    r"(activation|exit|withdrawable|eligibility)\w*epoch\s*[:]?=?=?\s*"
    r"(far_future|farfuture|type\s*\(\s*uint64\s*\)\s*\.\s*max|0xffffffffffffffff)")
_STAGE_ENUM_RE = re.compile(
    r"(status|stage)\s*(==|!=)\s*[\w.]*?"
    r"(active|pending|exit|slash|withdraw|activated|proven|predeposited|"
    r"deposited|none|compensated|in_progress|inprogress|defender|challenger|"
    r"dispute|sweeping)")
_STAGE_GUARD_RE = re.compile(r"(require|revert|if)\s*\([^)]{0,120}\.(stage|status)\b")
_INVALID_STAGE_RE = re.compile(r"revert\s+\w*invalid\w*(stage|status)")
_EFFBAL_NONZERO_RE = re.compile(r"effectivebalance\s*(==|!=|>|>=)\s*0")
_SLASHED_GUARD_RE = re.compile(
    r"(require|revert|if)\s*\([^)]{0,120}\bslashed\b|"
    r"\bslashed\b\s*(==|!=)")
_TYPE_UINT64_MAX_RE = re.compile(r"type\s*\(\s*uint64\s*\)\s*\.\s*max")
_GAMESTATUS_RE = re.compile(r"(status\s*(==|!=)|gamestatus\.|\.status\(\)\s*(==|!=))")


def _has_phase_guard(text: str):
    """CORE PREDICATE: does `text` (comment-masked, lower-cased, fn + 1-hop
    helpers) contain a guard that REJECTS a mid-transition lower-layer value?

    A bare age-freshness compare is deliberately NOT counted here - the whole
    class is that an age check passes while a phase value is pinned.
    """
    kinds: list[str] = []
    # 1. far-future sentinel co-occurring with (or pinned to) an epoch field
    if any(s in text for s in _SENTINEL_TXT) and _EPOCH_FIELD_RE.search(text):
        kinds.append("far_future_epoch")
    elif _EPOCH_PIN_RE.search(text):
        kinds.append("far_future_epoch")
    if _TYPE_UINT64_MAX_RE.search(text) and _EPOCH_FIELD_RE.search(text) \
            and "far_future_epoch" not in kinds:
        kinds.append("far_future_epoch")
    # 2. validator/dispute status or stage transient enum check
    if (_STAGE_ENUM_RE.search(text) or _STAGE_GUARD_RE.search(text)
            or _INVALID_STAGE_RE.search(text)):
        kinds.append("status_stage_check")
    # 3. effective-balance nonzero (rejects a queue-zeroed balance)
    if _EFFBAL_NONZERO_RE.search(text):
        kinds.append("effective_balance_nonzero")
    # 4. slashed rejection
    if _SLASHED_GUARD_RE.search(text):
        kinds.append("slashed_check")
    # 5. L2 dispute-game phase check
    if "gamestatus" in text and _GAMESTATUS_RE.search(text):
        kinds.append("dispute_game_status")
    elif re.search(r"\.status\(\)\s*(==|!=)", text) and (
            "game" in text or "dispute" in text):
        kinds.append("dispute_game_status")
    # de-dupe preserving order
    seen: set[str] = set()
    ordered = [k for k in kinds if not (k in seen or seen.add(k))]
    return (bool(ordered), ordered)


# --------------------------------------------------------------------------- #
# Comment masking (blank // + /* */ + string literals, preserve line indices). #
# --------------------------------------------------------------------------- #

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
            if c == "\\":
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


# --------------------------------------------------------------------------- #
# Function extraction (brace-matched, Solidity + Go).                          #
# --------------------------------------------------------------------------- #

_FN_DECL_RE = re.compile(
    r"^\s*(?:"
    r"function\s+([A-Za-z_]\w*)"                 # Solidity function foo
    r"|(constructor)\b"                          # Solidity constructor
    r"|(fallback|receive)\s*\("                  # Solidity fallback/receive
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"   # Go func (recv) Foo / func Foo
    r")")

_VIEW_RE = re.compile(r"\b(view|pure)\b")


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3) or m.group(4)


def _functions(lines):
    """Yield dicts: name, decl_idx, sig, body_text, is_view for each fn body."""
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = _fn_name(m)
        # gather signature up to the opening brace (or `;` for a decl-only fn)
        sig_parts = []
        j = i
        brace_pos = -1
        semi = False
        while j < n:
            ln = lines[j]
            sig_parts.append(ln)
            if "{" in ln:
                brace_pos = ln.index("{")
                break
            if ";" in ln and "{" not in ln:
                semi = True
                break
            j += 1
        sig = " ".join(p.strip() for p in sig_parts)
        if semi or brace_pos < 0:
            i = j + 1
            continue
        # brace-match the body
        depth = 0
        body_lines = []
        k = j
        started = False
        col = brace_pos
        while k < n:
            ln = lines[k]
            start_col = col if k == j else 0
            for ci in range(start_col, len(ln)):
                ch = ln[ci]
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            body_lines.append(ln)
            if started and depth <= 0:
                break
            k += 1
            col = 0
        body_text = "\n".join(body_lines)
        is_view = bool(_VIEW_RE.search(sig)) and "function" in sig
        yield {
            "name": name,
            "decl_idx": i,
            "sig": sig,
            "body_text": body_text,
            "is_view": is_view,
        }
        i = k + 1


_IDENT_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def _called_local(fn_body: str, local_names: set) -> set:
    out = set()
    for m in _IDENT_CALL_RE.finditer(fn_body):
        nm = m.group(1)
        if nm in local_names:
            out.add(nm)
    return out


# --------------------------------------------------------------------------- #
# Per-file scan.                                                               #
# --------------------------------------------------------------------------- #

def _count_hits(text: str, tokens) -> list:
    return sorted({t for t in tokens if t in text})


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = "go" if rel.lower().endswith(".go") else "solidity"
    lines = text.split("\n")
    fns = list(_functions(lines))
    if not fns:
        return []

    by_name = {}
    for f in fns:
        # keep the LAST body under a name for helper resolution (overloads rare)
        by_name[f["name"]] = f
    local_names = set(by_name.keys())

    rows = []
    for f in fns:
        if f["is_view"]:
            continue  # a view/pure fn cannot credit / pin authoritative state
        own = (f["sig"] + "\n" + f["body_text"])
        # 1-hop same-file helper bodies folded in (guard-in-helper reachability)
        callees = _called_local(f["body_text"], local_names) - {f["name"]}
        helper_txt = "\n".join(by_name[c]["body_text"] for c in sorted(callees))
        eff = (own + "\n" + helper_txt).lower()

        snap = _count_hits(eff, _SNAPSHOT_SUBSTR)
        if not snap:
            continue
        strong = _count_hits(eff, _STRONG_TRANSIENT)
        generic = _count_hits(eff, _GENERIC_TRANSIENT)
        transient_ok = bool(strong) or len(generic) >= 2
        if not transient_ok:
            continue
        sink_verbs = _count_hits(eff, _SINK_VERBS)
        acct_write = bool(_ACCT_WRITE_RE.search(eff))
        if not sink_verbs and not acct_write:
            continue

        has_guard, guard_kinds = _has_phase_guard(eff)
        has_age = bool(_count_hits(eff, _AGE_FRESHNESS_SUBSTR))
        fires = not has_guard

        transient_tokens = (strong + generic)[:8]
        sink_tokens = sink_verbs[:] + (["<accounting-write>"] if acct_write else [])
        rows.append(_row(
            rel, f["name"], f["decl_idx"], lang, snap[:6], transient_tokens,
            sink_tokens[:6], has_guard, guard_kinds, has_age, bool(strong),
            fires))
    return rows


def _stable_id(rel, name, decl_idx):
    h = hashlib.sha1(f"{rel}:{name}:{decl_idx}:{_CAPABILITY}".encode()).hexdigest()
    return f"{_CAPABILITY}-{h[:12]}"


def _row(rel, name, decl_idx, lang, snap, transient_tokens, sink_tokens,
         has_guard, guard_kinds, has_age, strong, fires):
    if fires:
        age_clause = (
            "The fn carries an AGE-freshness check but NO phase check - the exact "
            "gap: an age-fresh snapshot still pins a transient value."
            if has_age else
            "The fn has neither an age nor a phase check on the snapshotted "
            "value.")
        question = (
            f"`{name}` consumes a cross-layer snapshot/proof ({','.join(snap)}) "
            f"referencing lower-layer transient state ({','.join(transient_tokens[:4])}) "
            f"and drives an authoritative sink ({','.join(sink_tokens[:3])}) with NO "
            f"phase-freshness guard rejecting a mid-transition value "
            f"(activationEpoch/exitEpoch==FAR_FUTURE_EPOCH, effectiveBalance==0, "
            f"pending/sweeping/exiting status, dispute IN_PROGRESS). {age_clause} "
            f"Can an attacker time the checkpoint so a mid-transition value is pinned "
            f"as authoritative and later restored to a different value?")
    else:
        question = (
            f"`{name}` consumes a snapshot/proof and drives an authoritative sink "
            f"but a phase-freshness guard is present ({','.join(guard_kinds)}); "
            f"verify the guard covers every transient window of the pinned field.")
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, name, decl_idx),
        "file": rel,
        "line": decl_idx + 1,
        "function": name,
        "lang": lang,
        "snapshot_tokens": snap,
        "transient_tokens": transient_tokens,
        "sink_tokens": sink_tokens,
        "has_strong_transient": strong,
        "has_phase_guard": has_guard,
        "phase_guard_kinds": guard_kinds,
        "has_age_freshness": has_age,
        "fires": fires,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
        "question": question,
    }


# --------------------------------------------------------------------------- #
# Source-tree walk (shared exclusion screens).                                 #
# --------------------------------------------------------------------------- #

def _excluded(path: Path) -> bool:
    sp = str(path)
    if is_test_target_path(sp) or is_chimera_mutation_harness_path(sp):
        return True
    if is_codegen_path(sp):
        return True
    if _IS_GENERATED_SOURCE is not None:
        try:
            if _IS_GENERATED_SOURCE(path):
                return True
        except Exception:
            pass
    return False


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".go")):
                continue
            if low.endswith("_test.go") or low.endswith(".t.sol"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _excluded(p):
                continue
            yield p


def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
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
        "capability": _CAPABILITY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "guarded_silent": sum(1 for r in rows if r.get("has_phase_guard")),
        "fired_with_age_only": sum(
            1 for r in fired if r.get("has_age_freshness")),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT2-01 mid-transition snapshot phase-freshness screen (advisory)")
    ap.add_argument("--workspace", "--ws", dest="workspace")
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
        return 1 if (strict and any(r.get("fires") for r in rows)) else 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 1 if (strict and any(r.get("fires") for r in rows)) else 0

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
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
