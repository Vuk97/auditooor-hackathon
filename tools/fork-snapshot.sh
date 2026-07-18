#!/usr/bin/env bash
# fork-snapshot.sh — capture on-chain state evidence for OFF.A-class findings (Issue U5, R43).
#
# For any finding that claims live-state impact, automates:
#   1. Parse every `cast call <addr> '<sig>' [args...]` snippet from the finding markdown.
#   2. Re-run each against the caller-supplied RPC at a pinned block (or latest).
#   3. Commit the results to <ws>/findings/<id>/fork_state_<YYYY-MM-DD>_block<N>.json
#   4. Append a row to <ws>/findings/FORK_SNAPSHOTS_INDEX.md
#
# This prevents "I checked last week" drift: every live-state claim travels with a
# machine-readable snapshot captured at a specific block, same RPC the reviewer can re-run.
#
# Usage:
#   ./tools/fork-snapshot.sh <workspace> <finding-id> <rpc-url> [--block N]
#
# Example:
#   ./tools/fork-snapshot.sh ~/audits/polymarket-clob2 OFF.A https://polygon-bor.publicnode.com
#   ./tools/fork-snapshot.sh ~/audits/polymarket-clob2 R18.C https://polygon-bor.publicnode.com --block 85600000
#
# Exits: 0 ok | 1 bad args | 2 finding not found | 3 cast not installed | 4 no snippets

set -u

WS="${1:-}"
FID="${2:-}"
RPC="${3:-}"
BLOCK="latest"
shift 3 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --block) BLOCK="$2"; shift 2 ;;
    *)       shift ;;
  esac
done

if [ -z "$WS" ] || [ -z "$FID" ] || [ -z "$RPC" ]; then
  cat >&2 <<'USAGE'
usage: fork-snapshot.sh <workspace> <finding-id> <rpc-url> [--block N]

  <workspace>   audit workspace root (contains findings/ or submissions/)
  <finding-id>  e.g. OFF.A, R18.C, D14
  <rpc-url>     archive-capable RPC if --block is historical
  --block N     pin to a specific block (default: latest)
USAGE
  exit 1
fi

if [ ! -d "$WS" ]; then
  echo "[error] workspace not found: $WS" >&2
  exit 1
fi

# Resolve the markdown source. Accept findings/, submissions/, or drafts/, with or without full filename.
# Also accept a direct absolute path to a .md file as <finding-id>.
MD=""
if [ -f "$FID" ]; then
  MD="$FID"
fi
if [ -z "$MD" ]; then
  for cand in \
    "$WS/findings/$FID.md" \
    "$WS/submissions/$FID.md" \
    "$WS/drafts/$FID.md"; do
    [ -f "$cand" ] && MD="$cand" && break
  done
fi

if [ -z "$MD" ]; then
  # fallback: glob for a file that begins with $FID-
  for d in "$WS/findings" "$WS/submissions" "$WS/drafts"; do
    [ -d "$d" ] || continue
    HIT=$(ls "$d"/${FID}*.md 2>/dev/null | head -1)
    [ -n "$HIT" ] && MD="$HIT" && break
  done
fi

if [ -z "$MD" ]; then
  echo "[error] no markdown for finding '$FID' under $WS/{findings,submissions,drafts}/" >&2
  exit 2
fi

if ! command -v cast >/dev/null 2>&1; then
  cat >&2 <<'REMED'
[error] `cast` not installed.

fork-snapshot.sh requires Foundry's cast. Install it:

  curl -L https://foundry.paradigm.xyz | bash
  foundryup

Or with brew:

  brew install foundry

Then re-run.
REMED
  exit 3
fi

# Resolve the block number up-front so every query in this snapshot pins to the same height.
if [ "$BLOCK" = "latest" ]; then
  BLOCK_NUM=$(cast block-number --rpc-url "$RPC" 2>/dev/null)
  if [ -z "$BLOCK_NUM" ]; then
    echo "[error] cast block-number failed against $RPC" >&2
    exit 1
  fi
else
  BLOCK_NUM="$BLOCK"
fi

# Output layout
OUT_DIR="$WS/findings/$FID"
mkdir -p "$OUT_DIR"
DATE=$(date -u +%Y-%m-%d)
OUT_JSON="$OUT_DIR/fork_state_${DATE}_block${BLOCK_NUM}.json"
CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "=== fork-snapshot ==="
echo "finding:      $FID"
echo "markdown:     $MD"
echo "rpc:          $RPC"
echo "block:        $BLOCK_NUM"
echo "output:       $OUT_JSON"
echo ""

# Extract `cast call` snippets via embedded python (handles line-continuation and comments).
TMP_SNIPPETS=$(mktemp)
trap 'rm -f "$TMP_SNIPPETS"' EXIT

python3 - "$MD" > "$TMP_SNIPPETS" <<'PYEOF'
import re
import sys
import json

path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()

# Join backslash-continuations into logical lines.
logical = []
buf = ""
for raw in lines:
    # strip trailing newline (keep leading whitespace)
    line = raw.rstrip("\n")
    # strip inline shell comment only on lines that are part of a cast call (we detect later);
    # we keep comments in the buffer and strip per-token below.
    if line.endswith("\\"):
        buf += line[:-1] + " "
    else:
        buf += line
        logical.append(buf)
        buf = ""
if buf:
    logical.append(buf)

# Find lines that contain a `cast call ` invocation (allow `$ ` shell prompt prefix).
cast_re = re.compile(r"cast\s+call\s+(0x[0-9a-fA-F]{40})\s+(.+)")
snippets = []
for ll in logical:
    m = cast_re.search(ll)
    if not m:
        continue
    addr = m.group(1)
    tail = m.group(2)

    # Strip inline `# comment` (but preserve # inside quotes — unlikely in cast calls).
    # Walk char-by-char respecting single/double quotes.
    out = []
    in_s = False
    in_d = False
    i = 0
    while i < len(tail):
        c = tail[i]
        if c == "'" and not in_d:
            in_s = not in_s
            out.append(c)
        elif c == '"' and not in_s:
            in_d = not in_d
            out.append(c)
        elif c == "#" and not in_s and not in_d:
            break
        else:
            out.append(c)
        i += 1
    tail = "".join(out).strip()

    # Tokenize respecting single/double quotes.
    tokens = []
    cur = ""
    in_s = False
    in_d = False
    for c in tail:
        if c == "'" and not in_d:
            in_s = not in_s
            continue
        if c == '"' and not in_s:
            in_d = not in_d
            continue
        if c.isspace() and not in_s and not in_d:
            if cur:
                tokens.append(cur)
                cur = ""
        else:
            cur += c
    if cur:
        tokens.append(cur)

    if not tokens:
        continue

    signature = tokens[0]
    rest = tokens[1:]

    # Split args vs flags. Flags begin with `--` and consume one following value.
    args = []
    skip = False
    for idx, t in enumerate(rest):
        if skip:
            skip = False
            continue
        if t.startswith("--"):
            skip = True
            continue
        args.append(t)

    snippets.append({
        "address": addr,
        "signature": signature,
        "args": args,
    })

# Dedupe identical (addr, sig, args) tuples while preserving order.
seen = set()
deduped = []
for s in snippets:
    key = (s["address"].lower(), s["signature"], tuple(s["args"]))
    if key in seen:
        continue
    seen.add(key)
    deduped.append(s)

json.dump(deduped, sys.stdout)
PYEOF

COUNT=$(python3 -c "import json,sys; print(len(json.load(open('$TMP_SNIPPETS'))))")

if [ "$COUNT" -eq 0 ]; then
  echo "[warn] no cast call snippets parsed from $MD" >&2
  exit 4
fi

echo "parsed $COUNT unique cast call snippet(s). executing..."
echo ""

# Execute each query and collect results. Build final JSON with python for correctness.
RESULTS_TMP=$(mktemp)
trap 'rm -f "$TMP_SNIPPETS" "$RESULTS_TMP"' EXIT

: > "$RESULTS_TMP"

# Iterate via python to preserve structure; shell out cast per query.
python3 - "$TMP_SNIPPETS" "$RPC" "$BLOCK_NUM" "$RESULTS_TMP" <<'PYEOF'
import json, subprocess, sys

snippets_path, rpc, block, out_path = sys.argv[1:5]
with open(snippets_path) as f:
    snippets = json.load(f)

results = []
for s in snippets:
    cmd = ["cast", "call", s["address"], s["signature"], *s["args"],
           "--rpc-url", rpc, "--block", block]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        result = proc.stdout.strip() if proc.returncode == 0 else ""
        err = proc.stderr.strip() if proc.returncode != 0 else ""
    except subprocess.TimeoutExpired:
        result = ""
        err = "timeout"
    row = {
        "address": s["address"],
        "signature": s["signature"],
        "args": s["args"],
        "result": result,
    }
    if err:
        row["error"] = err
    results.append(row)
    # progress to stderr
    tag = "ok " if result and not err else "err"
    print(f"  [{tag}] {s['address']} {s['signature']} -> {result[:60]}{(' | '+err) if err else ''}",
          file=sys.stderr)

with open(out_path, "w") as f:
    json.dump(results, f)
PYEOF

# Final JSON assembly: wrap with metadata.
python3 - "$RESULTS_TMP" "$FID" "$CAPTURED_AT" "$RPC" "$BLOCK_NUM" "$OUT_JSON" <<'PYEOF'
import json, sys
results_path, fid, captured_at, rpc, block, out_path = sys.argv[1:7]
with open(results_path) as f:
    queries = json.load(f)
doc = {
    "finding_id": fid,
    "captured_at": captured_at,
    "rpc_url": rpc,
    "block_number": int(block),
    "queries": queries,
}
with open(out_path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(out_path)
PYEOF

# Append to index
INDEX="$WS/findings/FORK_SNAPSHOTS_INDEX.md"
if [ ! -f "$INDEX" ]; then
  mkdir -p "$WS/findings"
  cat > "$INDEX" <<'HDR'
# Fork-State Snapshots Index

Each row records a `cast call` snapshot captured by `tools/fork-snapshot.sh`
pinned to a specific mainnet block. Re-run any row with the same RPC+block to
reproduce the evidence.

| date | finding | block | rpc | queries | file |
|------|---------|-------|-----|---------|------|
HDR
fi

REL_JSON="findings/$FID/$(basename "$OUT_JSON")"
printf "| %s | %s | %s | %s | %s | %s |\n" \
  "$DATE" "$FID" "$BLOCK_NUM" "$RPC" "$COUNT" "\`$REL_JSON\`" \
  >> "$INDEX"

echo ""
echo "wrote:  $OUT_JSON"
echo "index:  $INDEX"
echo "=== done ==="
