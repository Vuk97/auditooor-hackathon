#!/usr/bin/env bash
# mine-fix-diffs.sh — walk commits whose messages match security keywords and
# extract pre/post diffs for each changed .sol file.
#
# Usage:
#   bash tools/mine-fix-diffs.sh <github-org/repo> <since-date> [--max-pages N]
#
# Example:
#   bash tools/mine-fix-diffs.sh morpho-org/morpho-blue 2023-01-01
#   bash tools/mine-fix-diffs.sh Uniswap/v4-core 2023-01-01 --max-pages 5
#
# Output:
#   /tmp/r55_fixdiffs/<org>-<repo>/<short-sha>/
#     diff.patch        — raw unified diff
#     meta.json         — commit SHA, message, changed files, quality signals
#   /tmp/r55_fixdiffs/<org>-<repo>/findings.json  — manifest of all candidates

set -euo pipefail

# ── args ─────────────────────────────────────────────────────────────────────
REPO="${1:-}"
SINCE="${2:-2023-01-01}"
MAX_PAGES=10

if [[ -z "$REPO" ]]; then
  echo "Usage: $0 <org/repo> <since-date> [--max-pages N]" >&2
  exit 1
fi

shift 2
while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-pages) MAX_PAGES="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

# ── config ────────────────────────────────────────────────────────────────────
ORG="${REPO%%/*}"
REPONAME="${REPO##*/}"
OUTDIR="/tmp/r55_fixdiffs/${ORG}-${REPONAME}"
SINCE_ISO="${SINCE}T00:00:00Z"

# Security keyword regex (POSIX ERE for jq)
KEYWORD_REGEX='fix|audit|vuln|secur|CVE|bounty|disclos|reentr|overflow|underflow|[HMC]-[0-9]|spearbit|trail.of.bits|cantina|sherlock|code4rena|immunefi|[Tt]o[Bb][-_ ][A-Z]|access.control|privilege'

# Max lines changed to consider "small enough" for a clean pattern
MAX_LINES_SMALL=50
MAX_LINES_MEDIUM=200

mkdir -p "$OUTDIR"

echo "[mine-fix-diffs] repo=$REPO since=$SINCE max-pages=$MAX_PAGES"
echo "[mine-fix-diffs] output -> $OUTDIR"

# ── walk commits ──────────────────────────────────────────────────────────────
TOTAL_WALKED=0
SECURITY_HITS=0
SOL_HITS=0
FINDINGS=()

for PAGE in $(seq 1 "$MAX_PAGES"); do
  COMMITS=$(gh api "repos/${REPO}/commits?since=${SINCE_ISO}&per_page=100&page=${PAGE}" 2>/dev/null || echo "[]")
  COUNT=$(echo "$COMMITS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)

  if [[ "$COUNT" -eq 0 ]]; then
    break
  fi

  echo "[mine-fix-diffs] page=$PAGE commits=$COUNT"
  TOTAL_WALKED=$(( TOTAL_WALKED + COUNT ))

  # Filter commits that match security keywords
  MATCHED=$(echo "$COMMITS" | python3 -c "
import json, re, sys
pattern = re.compile(r'$KEYWORD_REGEX', re.IGNORECASE)
data = json.load(sys.stdin)
out = []
for c in data:
    msg = c['commit']['message']
    if pattern.search(msg):
        out.append({'sha': c['sha'], 'msg': msg.split('\n')[0][:120]})
print(json.dumps(out))
" 2>/dev/null || echo "[]")

  MATCH_COUNT=$(echo "$MATCHED" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
  echo "[mine-fix-diffs]   keyword matches=$MATCH_COUNT"
  SECURITY_HITS=$(( SECURITY_HITS + MATCH_COUNT ))

  # For each matched commit, fetch the full diff and check for .sol files
  while IFS= read -r ENTRY; do
    SHA=$(echo "$ENTRY" | python3 -c "import json,sys; print(json.load(sys.stdin)['sha'])")
    MSG=$(echo "$ENTRY" | python3 -c "import json,sys; print(json.load(sys.stdin)['msg'])")
    SHORT="${SHA:0:7}"

    COMMIT_DATA=$(gh api "repos/${REPO}/commits/${SHA}" 2>/dev/null || echo "{}")
    SOL_FILES=$(echo "$COMMIT_DATA" | python3 -c "
import json,sys
d = json.load(sys.stdin)
files = d.get('files', [])
sol = [f for f in files if f['filename'].endswith('.sol') and 'test' not in f['filename'].lower() and 'mock' not in f['filename'].lower()]
print(json.dumps(sol))
" 2>/dev/null || echo "[]")

    SOL_COUNT=$(echo "$SOL_FILES" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
    if [[ "$SOL_COUNT" -eq 0 ]]; then
      continue
    fi

    SOL_HITS=$(( SOL_HITS + 1 ))
    COMMIT_DIR="$OUTDIR/$SHORT"
    mkdir -p "$COMMIT_DIR"

    # Write meta.json
    echo "$COMMIT_DATA" | python3 -c "
import json,sys,re
d = json.load(sys.stdin)
files = d.get('files', [])
sol_files = [f for f in files if f['filename'].endswith('.sol') and 'test' not in f['filename'].lower() and 'mock' not in f['filename'].lower()]
total_add = sum(f.get('additions',0) for f in sol_files)
total_del = sum(f.get('deletions',0) for f in sol_files)
total_chg = total_add + total_del

# Quality signals
if total_chg < $MAX_LINES_SMALL:
    size_class = 'small'
elif total_chg < $MAX_LINES_MEDIUM:
    size_class = 'medium'
else:
    size_class = 'large'

msg = d['commit']['message']
# Extract audit tags
tags = re.findall(r'(?:cantina|spearbit|tob|abdk|certora|sherlock)[-_ ][A-Za-z0-9-]+|[HMC]-\d+|CVE-\d+-\d+', msg, re.IGNORECASE)

meta = {
    'sha': d['sha'],
    'short_sha': d['sha'][:7],
    'message': msg.split('\n')[0][:200],
    'full_message': msg[:600],
    'audit_tags': tags,
    'sol_files': [{'file': f['filename'], 'additions': f['additions'], 'deletions': f['deletions']} for f in sol_files],
    'total_lines_changed': total_chg,
    'size_class': size_class,
}
print(json.dumps(meta, indent=2))
" > "$COMMIT_DIR/meta.json" 2>/dev/null

    # Write diff.patch
    echo "$SOL_FILES" | python3 -c "
import json,sys
files = json.load(sys.stdin)
for f in files:
    patch = f.get('patch', '')
    if patch:
        print('--- a/' + f['filename'])
        print('+++ b/' + f['filename'])
        print(patch)
        print()
" > "$COMMIT_DIR/diff.patch" 2>/dev/null

    echo "[mine-fix-diffs]   CANDIDATE $SHORT: $(echo "$MSG" | head -c 80) [sol_files=$SOL_COUNT]"

    # Accumulate findings
    FINDINGS+=("$COMMIT_DIR/meta.json")
  done < <(echo "$MATCHED" | python3 -c "
import json,sys
for item in json.load(sys.stdin):
    print(json.dumps(item))
")

done

# ── write findings.json manifest ──────────────────────────────────────────────
python3 -c "
import json, os, sys

findings_dir = '$OUTDIR'
out = []
for entry in sorted(os.listdir(findings_dir)):
    meta_path = os.path.join(findings_dir, entry, 'meta.json')
    if os.path.isfile(meta_path):
        with open(meta_path) as f:
            m = json.load(f)
        out.append(m)

out.sort(key=lambda x: x.get('total_lines_changed', 9999))
with open(os.path.join(findings_dir, 'findings.json'), 'w') as f:
    json.dump(out, f, indent=2)
print(f'[manifest] wrote {len(out)} entries -> {findings_dir}/findings.json')
"

echo ""
echo "[mine-fix-diffs] SUMMARY"
echo "  Total commits walked : $TOTAL_WALKED"
echo "  Keyword matches      : $SECURITY_HITS"
echo "  With .sol changes    : $SOL_HITS"
echo "  Output               : $OUTDIR"
