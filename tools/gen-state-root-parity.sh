#!/usr/bin/env bash
# gen-state-root-parity.sh — Wave 3 differential-fuzz scaffold (state-root parity)
#
# Purpose:
#   Scaffold a state-root parity differential-fuzz harness for a Rust DLT /
#   execution-layer workspace (e.g. `base-reth`). The generated harness runs
#   identical block/transaction inputs through:
#     1. The IN-TREE EVM under audit (the workspace crate)
#     2. A REFERENCE ORACLE (revm crates.io, geth optional)
#   and asserts state-root parity.
#
#   A single state-root divergence in a DLT scope is typically a Critical:
#   it implies the in-tree client computes a different post-state than the
#   reference, which would fork the chain.
#
# Scope:
#   - This is a SCAFFOLD generator, not a working fuzzer.
#   - The generated harness will need operator wiring to the real in-tree
#     EVM crate paths. See docs/STATE_ROOT_PARITY.md.
#
# Usage:
#   gen-state-root-parity.sh --workspace <ws> [--force]
#
# Behavior:
#   - Detects whether <ws> is a Cargo workspace AND has revm / alloy-consensus
#     / reth dependencies.
#   - If yes: scaffolds <ws>/differential_fuzz/state_root_parity/{Cargo.toml,
#     src/main.rs, corpus/*.json, Makefile}
#   - If no: prints a clear "skipped: not a Rust DLT workspace" log line
#     and exits 0. Solidity-only workspaces self-skip.
#   - Idempotent: re-running does not overwrite an existing scaffold unless
#     --force is passed.
#
# Exit codes:
#   0 — success (scaffold generated, or self-skipped cleanly)
#   1 — argument error / fatal IO error
#
# Wave 3 EE link:
#   Wired into tools/audit-deep.sh as a new step in the default profile.
#   Operator wires the generated harness, removes the explicit wiring marker,
#   then runs:
#     cd <ws>/differential_fuzz/state_root_parity && make fuzz-state-root

set -euo pipefail

# ── argument parsing ─────────────────────────────────────────────────────────
WORKSPACE=""
FORCE=0
# E1 (decode-differential axis) state. Advisory, OFF by default: only runs when
# --emit-decode-differential is passed OR env GEN_DECODE_DIFFERENTIAL=1.
E1_EMIT="${GEN_DECODE_DIFFERENTIAL:-0}"
E1_OUT=""
E1_SCAN_ROOT=""
E1_SCAFFOLD_DIR=""

usage() {
    cat <<'USAGE'
Usage: gen-state-root-parity.sh --workspace <ws> [--force]

Options:
  --workspace <path>    Path to the audit workspace (Cargo workspace expected)
  --force               Overwrite an existing scaffold (default: skip)
  -h, --help            Show this help

E1 decode-differential axis (advisory, OFF by default):
  --emit-decode-differential   Emit round-trip decode/serialize malleability
                               hypotheses (verdict=needs-fuzz, NO-AUTO-CREDIT).
                               Also enabled by env GEN_DECODE_DIFFERENTIAL=1.
  --out <path>                 hypotheses jsonl (default: stdout scratch)
  --decode-scan-root <path>    scan this subtree instead of the whole ws
  --scaffold-dir <path>        also emit a Rust round-trip harness scaffold here
                               (NEVER point this at a live shared ws)

  This axis is COMPLEMENTARY to state-root parity: state-root parity is
  EXECUTION post-state divergence (Rust-only oracle); the decode-differential
  axis is DECODE/serialization malleability (serialize(read(b)) == b). It does
  NOT re-derive execution parity. Cross-client C++<->Rust is DEFERRED; only the
  in-tree Rust round-trip oracle is emitted.

Self-skips on:
  - Non-existent workspace
  - Solidity-only workspaces (no Cargo.toml)
  - Cargo workspaces without revm / alloy-consensus / reth dependencies
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workspace)
            WORKSPACE="${2:-}"; shift 2 ;;
        --workspace=*)
            WORKSPACE="${1#--workspace=}"; shift ;;
        --force)
            FORCE=1; shift ;;
        --emit-decode-differential)
            E1_EMIT=1; shift ;;
        --out)
            E1_OUT="${2:-}"; shift 2 ;;
        --out=*)
            E1_OUT="${1#--out=}"; shift ;;
        --decode-scan-root)
            E1_SCAN_ROOT="${2:-}"; shift 2 ;;
        --decode-scan-root=*)
            E1_SCAN_ROOT="${1#--decode-scan-root=}"; shift ;;
        --scaffold-dir)
            E1_SCAFFOLD_DIR="${2:-}"; shift 2 ;;
        --scaffold-dir=*)
            E1_SCAFFOLD_DIR="${1#--scaffold-dir=}"; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "[gen-state-root-parity] error: unknown arg: $1" >&2
            usage >&2
            exit 1 ;;
    esac
done

if [[ -z "$WORKSPACE" ]]; then
    echo "[gen-state-root-parity] error: --workspace is required" >&2
    usage >&2
    exit 1
fi

if [[ ! -d "$WORKSPACE" ]]; then
    echo "[gen-state-root-parity] skipped: workspace path does not exist: $WORKSPACE"
    exit 0
fi

# ── E1: decode-differential (round-trip malleability) axis ───────────────────
# Advisory, OFF by default. Emits needs-fuzz hypotheses for any Rust type that
# exposes BOTH a hand-written decode (fn read/deserialize/decode/from_bytes) AND
# a hand-written encode (fn write/serialize/encode/to_bytes) on the same impl,
# where the decode does NOT re-check a canonical form. Oracle:
#   serialize(read(b)) == b   (canonical round-trip)
# A malleable decode (accepts >1 encoding of one value) breaks this and is a
# transaction-malleability class bug.
#
# Predicate (load-bearing):
#   FIRES  iff  hand-written decode+encode pair AND read body has NO canonical
#               / round-trip self-guard.
#   SUPPRESS on: single-direction only; derive-only (no hand-written decode);
#               read body contains a canonical / re-serialize-compare guard.
#
# Round-trip scaffold is NOT evidence; every row stays verdict=needs-fuzz.
run_decode_differential() {
    local ws="$1" out="$2" scan_root="$3" scaffold_dir="$4"
    local root="${scan_root:-$ws}"
    GSRP_WS="$ws" GSRP_ROOT="$root" GSRP_OUT="$out" GSRP_SCAFFOLD="$scaffold_dir" \
        python3 - "$root" <<'PY'
import json, os, re, sys

ROOT = sys.argv[1]
WS = os.environ.get("GSRP_WS", ROOT)
OUT = os.environ.get("GSRP_OUT", "")
SCAFFOLD = os.environ.get("GSRP_SCAFFOLD", "")

# Predicate regexes (edit these = mutate the predicate; tests pin non-vacuity).
DECODE_RE = re.compile(r'\bfn\s+(read|deserialize|decode|from_bytes)\b')
ENCODE_RE = re.compile(r'\bfn\s+(write|serialize|encode|to_bytes)\b')
FN_RE     = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+')
CANON_RE  = re.compile(r'canonical|round.?trip|non_canonical|reject[^\n]*non|re-?serialize', re.I)
IMPL_RE   = re.compile(r'^\s*impl\b[^{]*?\bfor\s+([A-Za-z_]\w*)|^\s*impl(?:<[^>]*>)?\s+([A-Za-z_]\w*)')
TYPE_RE   = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+([A-Za-z_]\w*)')
PRUNE = ('/target/', '/.git/', '/differential_fuzz/', '/scanners/',
         '/node_modules/', '/.auditooor/', '/tests/', '/test/')

def rust_files(root):
    for dp, dn, fn in os.walk(root):
        s = dp.replace('\\', '/') + '/'
        if any(p in s for p in PRUNE):
            dn[:] = []
            continue
        for f in fn:
            if f.endswith('.rs'):
                yield os.path.join(dp, f)

def enclosing_type(lines, idx):
    # nearest preceding impl/struct/enum header
    for j in range(idx, -1, -1):
        m = IMPL_RE.match(lines[j])
        if m:
            return m.group(1) or m.group(2)
        m = TYPE_RE.match(lines[j])
        if m:
            return m.group(1)
    return None

def fn_body(lines, idx):
    # from the decode fn line to the next fn header (bounded)
    out = [lines[idx]]
    for j in range(idx + 1, min(idx + 80, len(lines))):
        if FN_RE.match(lines[j]):
            break
        out.append(lines[j])
    return '\n'.join(out)

rows = []
acct = {"files_scanned": 0, "decode_fns": 0, "encode_fns": 0,
        "pairs": 0, "canon_suppressed": 0, "single_dir_suppressed": 0,
        "emitted": 0}
seen = set()

for path in rust_files(ROOT):
    try:
        lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    except OSError:
        continue
    acct["files_scanned"] += 1
    dec = [(i, m.group(1)) for i, ln in enumerate(lines)
           for m in [DECODE_RE.search(ln)] if m]
    enc = [(i, m.group(1)) for i, ln in enumerate(lines)
           for m in [ENCODE_RE.search(ln)] if m]
    acct["decode_fns"] += len(dec)
    acct["encode_fns"] += len(enc)
    if not dec:
        continue
    if not enc:
        acct["single_dir_suppressed"] += len(dec)   # decode-only: FP-guard
        continue
    for (di, dname) in dec:
        typ = enclosing_type(lines, di) or os.path.basename(path)[:-3]
        # nearest encode counterpart (prefer preceding, else following)
        prev = [(i, n) for (i, n) in enc if i < di]
        nxt = [(i, n) for (i, n) in enc if i > di]
        ei, ename = (prev[-1] if prev else nxt[0])
        acct["pairs"] += 1
        body = fn_body(lines, di)
        if CANON_RE.search(body):
            acct["canon_suppressed"] += 1
            continue
        rel = os.path.relpath(path, WS)
        key = (rel, typ, di + 1)
        if key in seen:
            continue
        seen.add(key)
        row = {
            "id": "E1",
            "axis": "decode-differential-roundtrip",
            "type": typ,
            "file": rel,
            "decode_fn": dname,
            "decode_line": di + 1,
            "encode_fn": ename,
            "encode_line": ei + 1,
            "oracle": "serialize(read(b)) == b  (canonical round-trip)",
            "attack_class": "serialization-malleability",
            "verdict": "needs-fuzz",
            "auto_credit": False,
            "evidence_class": "scaffolded_unverified",
            # DEDUP (A1): distinct axis from state-root EXECUTION parity; do NOT
            # re-derive covered_by. gen-state-root-parity emits no such rows.
            "covered_by": None,
            "dedup_axis": "decode-serialization-malleability != execution-state-root-parity",
            "defer": "cross-client C++<->Rust deferred; in-tree Rust round-trip only",
            "detector": "gen-state-root-parity.sh:emit-decode-differential",
        }
        rows.append(row)

acct["emitted"] = len(rows)

if OUT:
    os.makedirs(os.path.dirname(os.path.abspath(OUT)), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8') as fh:
        for r in rows:
            fh.write(json.dumps(r) + '\n')
else:
    for r in rows:
        print(json.dumps(r))

# Optional in-tree round-trip harness scaffold (NEVER into a shared ws).
if SCAFFOLD and rows:
    os.makedirs(SCAFFOLD, exist_ok=True)
    hpath = os.path.join(SCAFFOLD, "roundtrip_fuzz.rs")
    with open(hpath, 'w', encoding='utf-8') as fh:
        fh.write("// AUTO-GENERATED decode-differential round-trip harness (E1).\n")
        fh.write("// Oracle: serialize(read(b)) == b canonical. needs-fuzz, no auto-credit.\n")
        fh.write("// Cross-client C++<->Rust DEFERRED; in-tree Rust round-trip only.\n\n")
        for r in rows:
            fh.write(
                "// {t}::{d} <-> {t}::{e}  ({f}:{dl})\n".format(
                    t=r["type"], d=r["decode_fn"], e=r["encode_fn"],
                    f=r["file"], dl=r["decode_line"]))
            fh.write(
                "// fuzz_target!(|b: &[u8]| {{ if let Ok(v) = {t}::{d}(&mut &*b) "
                "{{ assert_eq!(v.{e}(), b, \"non-canonical decode: {t}\"); }} }});\n\n"
                .format(t=r["type"], d=r["decode_fn"], e=r["encode_fn"]))

sys.stderr.write(
    "[gen-state-root-parity][E1] " + json.dumps(acct) + "\n")
sys.stderr.write(
    "[gen-state-root-parity][E1] emitted %d needs-fuzz round-trip hypotheses\n"
    % len(rows))
PY
}

if [[ "$E1_EMIT" == "1" ]]; then
    echo "[gen-state-root-parity] E1 decode-differential axis (advisory, needs-fuzz)" >&2
    run_decode_differential "$WORKSPACE" "$E1_OUT" "$E1_SCAN_ROOT" "$E1_SCAFFOLD_DIR"
    exit 0
fi

# ── detection: is this a Rust DLT workspace? ─────────────────────────────────
# Rule:
#   1. Must contain at least one Cargo.toml
#   2. Must reference revm OR alloy-consensus OR reth in some Cargo.toml
#      (we grep recursively but bound the depth to keep it cheap)
#
# We deliberately do NOT require a top-level workspace manifest — many reth
# forks ship a virtual workspace several directories deep. We also prune
# auditooor-generated fuzz/scaffold directories so re-runs in a live engagement
# do not mistake our own harness crates for the audited source.

cargo_files() {
    find "$WORKSPACE" \
        \( -path "*/target" -o -path "*/node_modules" -o -path "*/.git" \
           -o -path "*/.auditooor" -o -path "*/build" -o -path "*/out" \
           -o -path "*/differential_fuzz" -o -path "*/scanners" \) -prune \
        -o -type f -name 'Cargo.toml' -print 2>/dev/null
}

if ! cargo_files | head -1 | grep -q . ; then
    echo "[gen-state-root-parity] skipped: not a Rust DLT workspace (no Cargo.toml found under $WORKSPACE)"
    exit 0
fi

# Search for the dependency markers. We tolerate any of the three.
DEP_MATCH=""
while IFS= read -r cargo_file; do
    if grep -qE '^[[:space:]]*(revm|alloy-consensus|reth(_|-)?[a-z_-]*)[[:space:]]*=' "$cargo_file" 2>/dev/null; then
        DEP_MATCH="$cargo_file"
        break
    fi
done < <(cargo_files)

if [[ -z "$DEP_MATCH" ]]; then
    echo "[gen-state-root-parity] skipped: not a Rust DLT workspace (no revm / alloy-consensus / reth dep in any Cargo.toml under $WORKSPACE)"
    exit 0
fi

echo "[gen-state-root-parity] detected Rust DLT workspace via: $DEP_MATCH"

# ── try to detect a candidate in-tree reth/evm crate to point at ─────────────
# Heuristic: score Cargo.toml packages and prefer the real execution/EVM crate
# over utility CLI/test crates. Fall back to the detected dep file's parent.
INTREE_CRATE_DIR=""
INTREE_SCORE=0
while IFS= read -r cargo_file; do
    pkg_name=$(grep -m1 -E '^[[:space:]]*name[[:space:]]*=' "$cargo_file" 2>/dev/null \
        | sed -E 's/.*=[[:space:]]*"([^"]+)".*/\1/' || true)
    dir=$(dirname "$cargo_file")
    score=0
    if [[ "$pkg_name" == *evm* || "$pkg_name" == *executor* || "$pkg_name" == *execution* || "$pkg_name" == *reth* ]]; then
        score=10
    fi
    if [[ "$dir" == */crates/execution/evm || "$pkg_name" == *execution-evm* ]]; then
        score=100
    elif [[ "$dir" == */crates/execution/* && ( "$pkg_name" == *evm* || "$pkg_name" == *executor* || "$pkg_name" == *payload* ) ]]; then
        score=85
    elif [[ "$dir" == *evm* || "$dir" == *executor* ]]; then
        score=70
    elif [[ "$pkg_name" == *reth* ]]; then
        score=40
    fi
    if [[ "$dir" == *utilities* || "$pkg_name" == *cli* || "$pkg_name" == *test* || "$pkg_name" == *devnet* ]]; then
        score=$((score - 30))
    fi
    if [[ "$score" -gt "$INTREE_SCORE" ]]; then
        INTREE_SCORE="$score"
        INTREE_CRATE_DIR="$dir"
    fi
done < <(cargo_files)

if [[ -z "$INTREE_CRATE_DIR" ]]; then
    INTREE_CRATE_DIR=$(dirname "$DEP_MATCH")
fi

# Compute relative path from the scaffold dir to the in-tree crate dir.
# Scaffold lives at: <ws>/differential_fuzz/state_root_parity/
# So the relative prefix to <ws> root is "../../"
WS_ABS=$(cd "$WORKSPACE" && pwd)
INTREE_ABS=$(cd "$INTREE_CRATE_DIR" && pwd)
# Strip the workspace prefix from the in-tree crate path; if the in-tree dir
# is OUTSIDE the workspace (rare), fall back to the absolute path.
if [[ "$INTREE_ABS" == "$WS_ABS"* ]]; then
    REL_FROM_WS="${INTREE_ABS#$WS_ABS/}"
    INTREE_REL_PATH="../../$REL_FROM_WS"
else
    INTREE_REL_PATH="$INTREE_ABS"
fi

echo "[gen-state-root-parity] candidate in-tree crate dir: $INTREE_CRATE_DIR"
echo "[gen-state-root-parity] generated path = $INTREE_REL_PATH"

# ── output paths ─────────────────────────────────────────────────────────────
OUT_DIR="$WORKSPACE/differential_fuzz/state_root_parity"
SRC_DIR="$OUT_DIR/src"
CORPUS_DIR="$OUT_DIR/corpus"

# ── idempotency guard ────────────────────────────────────────────────────────
if [[ -d "$OUT_DIR" && "$FORCE" != "1" ]]; then
    echo "[gen-state-root-parity] skipped: scaffold already exists at $OUT_DIR (use --force to overwrite)"
    exit 0
fi

mkdir -p "$SRC_DIR" "$CORPUS_DIR"

# ── Cargo.toml ───────────────────────────────────────────────────────────────
# Note: revm version is pinned to a recent (2026-Q1) release line. Operators
# should bump if the in-tree crate uses a different revm major.
cat > "$OUT_DIR/Cargo.toml" <<CARGO_EOF
# AUTO-GENERATED by tools/gen-state-root-parity.sh (Wave 3 differential-fuzz scaffold)
# Operator: adjust [dependencies.in_tree_evm] path if the heuristic guessed wrong.
# See docs/STATE_ROOT_PARITY.md for the full operator workflow.

[package]
name = "state_root_parity"
version = "0.1.0"
edition = "2021"
publish = false

[[bin]]
name = "state_root_parity"
path = "src/main.rs"

[dependencies]
# Reference oracle — pinned to a recent revm line. Bump as needed.
# TODO verify revm API: see src/main.rs lines 1..end for call sites
revm = { version = "14", default-features = false, features = ["std"] }

# Block/tx parsing primitives (matches reth ecosystem)
alloy-consensus = "0.5"
alloy-primitives = "0.8"
alloy-rlp = "0.3"

# JSON corpus parsing
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error reporting
anyhow = "1"
hex = "0.4"

# IN-TREE EVM under audit. The path below was guessed from the workspace
# layout — operator MUST verify it points at the real in-tree EVM crate.
# If the guess is wrong, set the correct path or rename to match the real
# crate name in the in-tree workspace.
[dependencies.in_tree_evm]
path = "$INTREE_REL_PATH"
# package = "<real-package-name>"   # TODO: set if dir-name != package-name
optional = true

[features]
# Default to oracle-only build so the scaffold compiles even before the
# operator wires up the in-tree crate. Once the path above is verified,
# enable: cargo build --features in-tree
default = []
in-tree = ["dep:in_tree_evm"]
CARGO_EOF

# ── src/main.rs ──────────────────────────────────────────────────────────────
# The harness reads a JSON block on stdin, runs it through both EVMs, and
# prints both state roots + a parity verdict. The in-tree path is gated on
# the `in-tree` feature so the scaffold compiles before operator wiring.
cat > "$SRC_DIR/main.rs" <<'RUST_EOF'
// state_root_parity — differential-fuzz harness (state-root parity)
//
// Wave 3 scaffold generated by tools/gen-state-root-parity.sh.
//
// CONTRACT:
//   - stdin: a single JSON `BlockInput` (see schema below)
//   - stdout: a single JSON `ParityResult` line containing both state roots
//             and a `parity` boolean
//   - exit code: 0 always (a divergence is a finding, not a tool error)
//
// IMPORTANT — operator must wire the oracle and in-tree paths:
//   The reference-oracle path uses revm directly. The in-tree path is gated
//   behind the `in-tree` cargo feature and currently calls a placeholder
//   function that the operator must replace with the real in-tree EVM
//   executor entry point.
//
// FAIL-CLOSED MARKER:
//   STATE_ROOT_PARITY_WIRING_REQUIRED
//   `make fuzz-state-root` refuses to run while this marker is present.
//   Remove it only after both run_oracle() and run_in_tree() execute real
//   clients and no placeholder roots remain.
//
// TODO verify revm API:
//   This file is written against revm v14 (latest at scaffold time, 2026).
//   If the in-tree workspace pins a different revm major, adjust:
//     - DatabaseRef trait import
//     - Evm::builder().with_db(...).with_block_env(...).with_tx_env(...).build()
//     - tx.transact_commit() / tx.transact() return shape
//   See https://docs.rs/revm/14/ for the canonical API.
//
// SCHEMA (BlockInput):
//   {
//     "name": "human-readable corpus name",
//     "block_number": 1,
//     "timestamp": 1700000000,
//     "gas_limit": 30000000,
//     "base_fee_per_gas": 1000000000,
//     "coinbase": "0x0000000000000000000000000000000000000000",
//     "prevrandao": "0x00...00",
//     "txs": [ { "from": "0x..", "to": "0x..", "value": "0x..", ... } ],
//     "pre_state": { "0x..": { "balance": "0x..", "nonce": 0, "code": "0x..", "storage": {} } }
//   }

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
//  Schemas
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct BlockInput {
    #[serde(default)]
    name: String,
    #[serde(default)]
    block_number: u64,
    #[serde(default)]
    timestamp: u64,
    #[serde(default = "default_gas_limit")]
    gas_limit: u64,
    #[serde(default)]
    base_fee_per_gas: u64,
    #[serde(default)]
    coinbase: String,
    #[serde(default)]
    prevrandao: String,
    #[serde(default)]
    txs: Vec<serde_json::Value>,
    #[serde(default)]
    pre_state: serde_json::Value,
}

fn default_gas_limit() -> u64 { 30_000_000 }

#[derive(Debug, Serialize)]
struct ParityResult {
    name: String,
    oracle_state_root: String,
    in_tree_state_root: String,
    parity: bool,
    notes: Vec<String>,
    harness_wired: bool,
    evidence_class: String,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Reference oracle (revm crates.io)
// ─────────────────────────────────────────────────────────────────────────────

/// Run the block through the revm reference oracle and return the post-state root.
///
/// TODO verify revm API: the body below is a stub. Operator must:
///   1. Build a `revm::db::CacheDB` seeded from `block.pre_state`
///   2. For each tx in `block.txs`, populate `Evm::tx_mut()` and call
///      `evm.transact_commit()`
///   3. Compute the trie state root from the resulting CacheDB account map
///      using `alloy_trie::root::state_root`
///
/// The current implementation returns a deterministic placeholder so the
/// scaffold builds and CI smoke runs are non-trivial; replace before using
/// the harness for real parity comparisons.
fn run_oracle(block: &BlockInput) -> Result<String> {
    // Placeholder: deterministic hash over the JSON input so two identical
    // inputs yield identical placeholder roots.
    let canonical = serde_json::to_string(&serde_json::json!({
        "name": block.name,
        "block_number": block.block_number,
        "timestamp": block.timestamp,
        "gas_limit": block.gas_limit,
        "txs": block.txs,
        "pre_state": block.pre_state,
    }))?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    canonical.hash(&mut hasher);
    let h = hasher.finish();
    Ok(format!("0xORACLE{:016x}", h))
}

fn harness_wired() -> bool {
    false
}

// ─────────────────────────────────────────────────────────────────────────────
//  In-tree EVM under audit
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "in-tree")]
fn run_in_tree(block: &BlockInput) -> Result<String> {
    // TODO operator: replace this with a call into the real in-tree EVM
    //                executor. Example for a reth-style fork:
    //
    //   use in_tree_evm::executor::EvmExecutor;
    //   let executor = EvmExecutor::new();
    //   let post_state = executor.execute_block(block_env, txs, pre_state_db)?;
    //   Ok(format!("0x{}", hex::encode(post_state.state_root)))
    //
    // Until then, we mirror the oracle logic so the scaffold reports parity
    // by construction (operator will see "parity: true" everywhere — a
    // signal that the in-tree wiring is not yet done).
    run_oracle(block).map(|s| s.replace("0xORACLE", "0xINTREE"))
}

#[cfg(not(feature = "in-tree"))]
fn run_in_tree(_block: &BlockInput) -> Result<String> {
    // Without the `in-tree` feature, return a sentinel so divergence is
    // obvious. Operators flipping this on will replace the body in the
    // cfg(feature) branch above.
    Ok("0xINTREE_NOT_WIRED".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Driver
// ─────────────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let mut input = String::new();
    use std::io::Read;
    std::io::stdin()
        .read_to_string(&mut input)
        .context("reading stdin")?;
    let block: BlockInput =
        serde_json::from_str(&input).context("parsing BlockInput JSON from stdin")?;

    let mut notes: Vec<String> = Vec::new();

    let oracle_root = match run_oracle(&block) {
        Ok(r) => r,
        Err(e) => {
            notes.push(format!("oracle error: {e:#}"));
            String::from("0xORACLE_ERROR")
        }
    };

    let in_tree_root = match run_in_tree(&block) {
        Ok(r) => r,
        Err(e) => {
            notes.push(format!("in-tree error: {e:#}"));
            String::from("0xINTREE_ERROR")
        }
    };

    let parity = oracle_root == in_tree_root;
    if !parity {
        notes.push(
            "DIVERGENCE — investigate as potential Critical (state-root parity violation)"
                .to_string(),
        );
    }

    let result = ParityResult {
        name: block.name.clone(),
        oracle_state_root: oracle_root,
        in_tree_state_root: in_tree_root,
        parity,
        notes,
        harness_wired: harness_wired(),
        evidence_class: "scaffolded_unverified".to_string(),
    };

    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
RUST_EOF

# ── corpus/ — 10 hand-crafted edge-case blocks ──────────────────────────────
# Each file is a minimal BlockInput that exercises a known EVM-level edge
# case where state-root divergence has historically appeared in EL clients.

write_corpus() {
    local name="$1"
    local body="$2"
    cat > "$CORPUS_DIR/${name}.json" <<JSON_EOF
$body
JSON_EOF
}

write_corpus "01_empty_block" '{
  "name": "empty_block",
  "block_number": 1,
  "timestamp": 1700000000,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "txs": [],
  "pre_state": {}
}'

write_corpus "02_single_tx_state_change" '{
  "name": "single_tx_state_change",
  "block_number": 2,
  "timestamp": 1700000012,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000001",
  "txs": [
    { "from": "0x1111111111111111111111111111111111111111",
      "to":   "0x2222222222222222222222222222222222222222",
      "value": "0x0de0b6b3a7640000",
      "gas_limit": 21000,
      "gas_price": "0x3b9aca00",
      "input": "0x" }
  ],
  "pre_state": {
    "0x1111111111111111111111111111111111111111": {
      "balance": "0x56bc75e2d63100000",
      "nonce": 0,
      "code": "0x",
      "storage": {}
    }
  }
}'

write_corpus "03_contract_creation" '{
  "name": "contract_creation",
  "block_number": 3,
  "timestamp": 1700000024,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000002",
  "txs": [
    { "from": "0x1111111111111111111111111111111111111111",
      "to": null,
      "value": "0x0",
      "gas_limit": 1000000,
      "gas_price": "0x3b9aca00",
      "input": "0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea2646970667358221220" }
  ],
  "pre_state": {
    "0x1111111111111111111111111111111111111111": {
      "balance": "0x56bc75e2d63100000",
      "nonce": 1,
      "code": "0x",
      "storage": {}
    }
  }
}'

write_corpus "04_selfdestruct" '{
  "name": "selfdestruct",
  "block_number": 4,
  "timestamp": 1700000036,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000003",
  "txs": [
    { "from": "0x1111111111111111111111111111111111111111",
      "to":   "0xdead00000000000000000000000000000000dead",
      "value": "0x0",
      "gas_limit": 200000,
      "gas_price": "0x3b9aca00",
      "input": "0x" }
  ],
  "pre_state": {
    "0xdead00000000000000000000000000000000dead": {
      "balance": "0x0de0b6b3a7640000",
      "nonce": 0,
      "code": "0x6000ff",
      "storage": {}
    },
    "0x1111111111111111111111111111111111111111": {
      "balance": "0x56bc75e2d63100000",
      "nonce": 0,
      "code": "0x",
      "storage": {}
    }
  }
}'

write_corpus "05_eip4844_blob_tx" '{
  "name": "eip4844_blob_tx",
  "block_number": 5,
  "timestamp": 1700000048,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000004",
  "txs": [
    { "type": "0x3",
      "from": "0x1111111111111111111111111111111111111111",
      "to":   "0x2222222222222222222222222222222222222222",
      "value": "0x0",
      "gas_limit": 100000,
      "max_fee_per_gas": "0x3b9aca00",
      "max_priority_fee_per_gas": "0x3b9aca00",
      "max_fee_per_blob_gas": "0x3b9aca00",
      "blob_versioned_hashes": [
        "0x0100000000000000000000000000000000000000000000000000000000000001"
      ],
      "input": "0x" }
  ],
  "pre_state": {
    "0x1111111111111111111111111111111111111111": {
      "balance": "0x56bc75e2d63100000",
      "nonce": 0,
      "code": "0x",
      "storage": {}
    }
  }
}'

write_corpus "06_eip7702_delegate" '{
  "name": "eip7702_delegate",
  "block_number": 6,
  "timestamp": 1700000060,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000005",
  "txs": [
    { "type": "0x4",
      "from": "0x1111111111111111111111111111111111111111",
      "to":   "0x1111111111111111111111111111111111111111",
      "value": "0x0",
      "gas_limit": 100000,
      "max_fee_per_gas": "0x3b9aca00",
      "max_priority_fee_per_gas": "0x3b9aca00",
      "authorization_list": [
        { "chain_id": 1,
          "address": "0x3333333333333333333333333333333333333333",
          "nonce": 0,
          "y_parity": 0,
          "r": "0x0000000000000000000000000000000000000000000000000000000000000001",
          "s": "0x0000000000000000000000000000000000000000000000000000000000000001" }
      ],
      "input": "0x" }
  ],
  "pre_state": {
    "0x1111111111111111111111111111111111111111": {
      "balance": "0x56bc75e2d63100000",
      "nonce": 0,
      "code": "0x",
      "storage": {}
    }
  }
}'

write_corpus "07_gas_limit_boundary" '{
  "name": "gas_limit_boundary",
  "block_number": 7,
  "timestamp": 1700000072,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000006",
  "txs": [
    { "from": "0x1111111111111111111111111111111111111111",
      "to":   "0x2222222222222222222222222222222222222222",
      "value": "0x0",
      "gas_limit": 30000000,
      "gas_price": "0x3b9aca00",
      "input": "0x" }
  ],
  "pre_state": {
    "0x1111111111111111111111111111111111111111": {
      "balance": "0x56bc75e2d63100000",
      "nonce": 0,
      "code": "0x",
      "storage": {}
    }
  }
}'

write_corpus "08_gas_refund_boundary" '{
  "name": "gas_refund_boundary",
  "block_number": 8,
  "timestamp": 1700000084,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000007",
  "txs": [
    { "from": "0x1111111111111111111111111111111111111111",
      "to":   "0x4444444444444444444444444444444444444444",
      "value": "0x0",
      "gas_limit": 200000,
      "gas_price": "0x3b9aca00",
      "input": "0xa9059cbb" }
  ],
  "pre_state": {
    "0x4444444444444444444444444444444444444444": {
      "balance": "0x0",
      "nonce": 0,
      "code": "0x6000556000556000",
      "storage": {
        "0x0000000000000000000000000000000000000000000000000000000000000000": "0x000000000000000000000000000000000000000000000000000000000000002a"
      }
    },
    "0x1111111111111111111111111111111111111111": {
      "balance": "0x56bc75e2d63100000",
      "nonce": 0,
      "code": "0x",
      "storage": {}
    }
  }
}'

write_corpus "09_large_calldata" '{
  "name": "large_calldata",
  "block_number": 9,
  "timestamp": 1700000096,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000008",
  "txs": [
    { "from": "0x1111111111111111111111111111111111111111",
      "to":   "0x2222222222222222222222222222222222222222",
      "value": "0x0",
      "gas_limit": 5000000,
      "gas_price": "0x3b9aca00",
      "input_length_bytes": 131072,
      "input": "0xdeadbeef" }
  ],
  "pre_state": {
    "0x1111111111111111111111111111111111111111": {
      "balance": "0x56bc75e2d63100000",
      "nonce": 0,
      "code": "0x",
      "storage": {}
    }
  }
}'

write_corpus "10_max_state_touch" '{
  "name": "max_state_touch",
  "block_number": 10,
  "timestamp": 1700000108,
  "gas_limit": 30000000,
  "base_fee_per_gas": 1000000000,
  "coinbase": "0x0000000000000000000000000000000000000000",
  "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000009",
  "txs": [
    { "from": "0x1111111111111111111111111111111111111111",
      "to":   "0x5555555555555555555555555555555555555555",
      "value": "0x0",
      "gas_limit": 10000000,
      "gas_price": "0x3b9aca00",
      "input": "0x" }
  ],
  "pre_state": {
    "0x5555555555555555555555555555555555555555": {
      "balance": "0x0",
      "nonce": 0,
      "code": "0x366000600037366000600037",
      "storage": {
        "0x0000000000000000000000000000000000000000000000000000000000000000": "0x01",
        "0x0000000000000000000000000000000000000000000000000000000000000001": "0x02",
        "0x0000000000000000000000000000000000000000000000000000000000000002": "0x03",
        "0x0000000000000000000000000000000000000000000000000000000000000003": "0x04",
        "0x0000000000000000000000000000000000000000000000000000000000000004": "0x05"
      }
    },
    "0x1111111111111111111111111111111111111111": {
      "balance": "0x56bc75e2d63100000",
      "nonce": 0,
      "code": "0x",
      "storage": {}
    }
  }
}'

# ── Makefile ─────────────────────────────────────────────────────────────────
cat > "$OUT_DIR/Makefile" <<'MAKE_EOF'
# state_root_parity — Wave 3 differential-fuzz harness Makefile
#
# Targets:
#   make build          — cargo build (oracle-only, no in-tree wiring required)
#   make build-in-tree  — cargo build --features in-tree (requires operator wiring)
#   make check-wired    — fail closed until operator removes the wiring marker
#   make fuzz-state-root — loop the corpus through the harness; report any divergence
#   make clean

CARGO ?= cargo
HARNESS ?= ./target/debug/state_root_parity
CORPUS_DIR ?= corpus

.PHONY: build build-in-tree check-wired fuzz-state-root clean

build:
	$(CARGO) build

build-in-tree:
	$(CARGO) build --features in-tree

check-wired:
	@if grep -q 'STATE_ROOT_PARITY_WIRING_REQUIRED' src/main.rs; then \
		echo "[state-root-parity] REFUSING: harness is still scaffold-only."; \
		echo "[state-root-parity] Wire run_oracle() and run_in_tree() to real executors, then remove STATE_ROOT_PARITY_WIRING_REQUIRED from src/main.rs."; \
		exit 2; \
	fi

# fuzz-state-root: feed each corpus file through the harness on stdin; the
# harness prints a single JSON line per block. We grep for `"parity":false`
# and count divergences; non-zero divergences exit non-zero so CI catches it.
fuzz-state-root: check-wired build-in-tree
	@echo "[fuzz-state-root] running $$(ls $(CORPUS_DIR)/*.json | wc -l | tr -d ' ') corpus blocks against $(HARNESS)"
	@divergences=0; \
	for f in $(CORPUS_DIR)/*.json; do \
		echo "[corpus] $$f"; \
		out=$$($(HARNESS) < $$f); \
		echo "  -> $$out"; \
		if echo "$$out" | grep -q '"parity":false'; then \
			divergences=$$((divergences + 1)); \
			echo "  !! DIVERGENCE (potential Critical)"; \
		fi; \
	done; \
	echo "[fuzz-state-root] divergences = $$divergences"; \
	if [ $$divergences -gt 0 ]; then exit 1; fi

clean:
	$(CARGO) clean
MAKE_EOF

# ── README pointer (small, links to docs/STATE_ROOT_PARITY.md upstream) ─────
cat > "$OUT_DIR/README.md" <<'README_EOF'
# state_root_parity — Wave 3 differential-fuzz scaffold

This directory was auto-generated by `tools/gen-state-root-parity.sh`.

It contains a state-root parity harness for the in-tree EVM under audit,
diffed against revm (crates.io) as the reference oracle.

**See `docs/STATE_ROOT_PARITY.md` in the auditooor repo for the full operator workflow.**

Quick start:

    make build              # builds oracle-only (no in-tree wiring required)
    make check-wired        # fails until real oracle + in-tree wiring is done

Wire the oracle and in-tree paths:

  1. Edit `Cargo.toml` `[dependencies.in_tree_evm]` path to point at the real
     in-tree EVM crate.
  2. Edit `src/main.rs` `run_oracle()` and `run_in_tree()` to call real executors.
  3. Remove `STATE_ROOT_PARITY_WIRING_REQUIRED` from `src/main.rs`.
  4. `make fuzz-state-root`

Any `"parity":false` line after `check-wired` passes is a candidate Critical finding.
README_EOF

# ── final summary ────────────────────────────────────────────────────────────
corpus_count=$(ls "$CORPUS_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ')
echo "[gen-state-root-parity] generated:"
echo "  - $OUT_DIR/Cargo.toml"
echo "  - $SRC_DIR/main.rs"
echo "  - $OUT_DIR/Makefile"
echo "  - $OUT_DIR/README.md"
echo "  - $CORPUS_DIR/*.json ($corpus_count files)"
echo "[gen-state-root-parity] OK"
exit 0
