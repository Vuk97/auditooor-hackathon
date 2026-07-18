#!/usr/bin/env bash
# c3-compute.sh — compute stop-criterion C3 (≥1 TP per 50 detector hits).
#
# R50 update (Issue #156): the raw denominator is dominated by Tier-D + OOS
# file noise. This version emits BOTH the raw ratio and a scoped ratio that
# filters hits by:
#   1. detector tier (default S,E — skip Tier-D noise)  [--tier]
#   2. severity floor (default MEDIUM+)                  [--severity]
#   3. in-scope source paths only                        [--in-scope-only]
#
# Hit sources per workspace:
#   (a) <ws>/custom-detectors.log     lines  `^\s*[SEV] <fn> (<path>#Ln-m) — <detector>: …`
#   (b) <ws>/PATTERN_HITS.md           header `### ### <pattern>` → `**Hits: N**` +
#                                       path-prefixed file lines under the fenced block
#
# TP counts come from detectors/_hits_ledger.yaml entries tagged
#   workspace: <ws>   verdict: TP
#
# Target: scoped global ratio ≥ 0.02 (1 TP per 50 scoped hits).
#
# Usage:
#   ./tools/c3-compute.sh [--audits-dir PATH] [--threshold 0.02] [--quiet]
#                         [--tier S,E] [--severity MEDIUM+|ALL]
#                         [--in-scope-only] [--json]
#
# Exit code:
#   0 — scoped global ratio >= threshold
#   1 — scoped global ratio <  threshold
#   2 — usage / no workspaces

set -u

AUDITS_DIR="${HOME}/audits"
THRESHOLD="0.02"
QUIET=0
JSON=0
TIER_FILTER="S,E"
SEVERITY_FILTER="MEDIUM+"
IN_SCOPE_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --audits-dir) AUDITS_DIR="$2"; shift 2 ;;
        --threshold)  THRESHOLD="$2"; shift 2 ;;
        --tier)       TIER_FILTER="$2"; shift 2 ;;
        --severity)   SEVERITY_FILTER="$2"; shift 2 ;;
        --in-scope-only) IN_SCOPE_ONLY=1; shift ;;
        --quiet)      QUIET=1; shift ;;
        --json)       JSON=1; shift ;;
        -h|--help) sed -n '1,35p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="$AUDITOOOR_DIR/detectors/_hits_ledger.yaml"
TIER_REG="$AUDITOOOR_DIR/detectors/_tier_registry.yaml"
DSL_DIR="$AUDITOOOR_DIR/reference/patterns.dsl"
STATUS="$AUDITOOOR_DIR/reference/c3_status.txt"

if [ ! -d "$AUDITS_DIR" ]; then
    echo "[c3-compute] audits dir not found: $AUDITS_DIR" >&2; exit 2
fi
if [ ! -f "$LEDGER" ]; then
    echo "[c3-compute] ledger not found: $LEDGER" >&2; exit 2
fi

ws_dirs=()
for d in "$AUDITS_DIR"/*/; do
    [ -d "$d" ] || continue
    ws_dirs+=("${d%/}")
done
[ "${#ws_dirs[@]}" = 0 ] && { echo "[c3-compute] no workspaces under $AUDITS_DIR" >&2; exit 2; }

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# One python3 pass does the heavy lifting. Everything below is wiring.
if ! command -v python3 >/dev/null 2>&1; then
    echo "[c3-compute] python3 required" >&2; exit 2
fi

OUT_JSON=$(AUDITS_DIR="$AUDITS_DIR" \
          LEDGER="$LEDGER" TIER_REG="$TIER_REG" DSL_DIR="$DSL_DIR" \
          TIER_FILTER="$TIER_FILTER" SEVERITY_FILTER="$SEVERITY_FILTER" \
          IN_SCOPE_ONLY="$IN_SCOPE_ONLY" THRESHOLD="$THRESHOLD" \
          python3 - <<'PY'
import os, re, json, sys, glob

AUDITS_DIR      = os.environ["AUDITS_DIR"]
LEDGER          = os.environ["LEDGER"]
TIER_REG        = os.environ["TIER_REG"]
DSL_DIR         = os.environ["DSL_DIR"]
TIER_FILTER     = set(t.strip() for t in os.environ["TIER_FILTER"].split(",") if t.strip())
SEVERITY_FILTER = os.environ["SEVERITY_FILTER"].upper()
IN_SCOPE_ONLY   = os.environ["IN_SCOPE_ONLY"] == "1"
THRESHOLD       = float(os.environ["THRESHOLD"])

SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
def sev_floor(tag):
    if tag == "ALL": return 0
    if tag.endswith("+"):
        base = tag[:-1]
    else:
        base = tag
    return SEV_RANK.get(base, 2)
SEV_MIN = sev_floor(SEVERITY_FILTER)

# --- tier registry: { detector-name -> tier letter } ---
tier_of = {}
if os.path.exists(TIER_REG):
    with open(TIER_REG) as f:
        cur = None
        for line in f:
            m = re.match(r"^  ([A-Za-z0-9_\-]+):\s*$", line)
            if m:
                cur = m.group(1); continue
            m = re.match(r"^    tier:\s*([A-Z])\s*$", line)
            if m and cur:
                tier_of[cur] = m.group(1)

# --- pattern DSL: { pattern-name -> severity string } ---
pattern_severity = {}
if os.path.isdir(DSL_DIR):
    for p in glob.glob(os.path.join(DSL_DIR, "*.yaml")):
        name = os.path.splitext(os.path.basename(p))[0]
        try:
            with open(p) as f:
                for line in f:
                    m = re.match(r"^severity:\s*([A-Za-z]+)", line)
                    if m:
                        pattern_severity[name] = m.group(1).upper()
                        break
        except Exception:
            pass

# --- out-of-scope path heuristics ---
OOS_RE = re.compile(
    r"/(test|tests|mocks?|forge-std|node_modules|out|cache|artifacts)/"
    r"|/lib/(?!.+/src/)"        # /lib/ except pulled-in protocol src
    r"|/scripts?/"
)
def in_scope_path(path, scope_hints):
    if not path:
        return False
    p = path
    if OOS_RE.search(p):
        return False
    # If SCOPE.md enumerated explicit .sol files, require membership.
    if scope_hints:
        tail = os.path.basename(p)
        if not any(tail == h or tail.endswith("/" + h) or h in p for h in scope_hints):
            # don't hard-fail: still accept if path is clearly inside src/ trunk
            if "/src/" not in p:
                return False
    return True

# --- per-workspace scope hints from SCOPE.md ---
def scope_hints(ws_path):
    hints = set()
    f = os.path.join(ws_path, "SCOPE.md")
    if not os.path.exists(f):
        return hints
    with open(f) as fh:
        for line in fh:
            for m in re.finditer(r"([A-Z][A-Za-z0-9_]+\.sol)", line):
                hints.add(m.group(1))
    return hints

# --- parse custom-detectors.log ---
HIT_LINE = re.compile(
    r"^\s*\[(?P<sev>LOW|MEDIUM|HIGH|CRITICAL|INFO)\]\s+.+?\(([^()]*?)#L?\d"
    r".*?(?:—|--)\s+(?P<det>[A-Za-z0-9_\-]+)\s*:"
)
HIT_LINE_LOOSE = re.compile(
    r"^\s*\[(?P<sev>LOW|MEDIUM|HIGH|CRITICAL|INFO)\]\s+.+?\(([^()]+)\)"
    r"\s+(?:—|--)?\s*(?P<det>[A-Za-z0-9_\-]*)"
)
def parse_custom_log(log_path):
    rows = []
    if not os.path.exists(log_path):
        return rows
    with open(log_path, errors="replace") as fh:
        for line in fh:
            m = HIT_LINE.match(line) or HIT_LINE_LOOSE.match(line)
            if not m:
                continue
            sev = m.group("sev").upper()
            # Extract inner (path#Lxx-yy)
            inner_m = re.search(r"\(([^()]+?)#L?\d", line)
            path = inner_m.group(1) if inner_m else ""
            det = (m.group("det") or "").strip()
            rows.append({"sev": sev, "path": path, "det": det, "src": "custom-log"})
    return rows

# --- parse PATTERN_HITS.md ---
PATH_LINE = re.compile(r"^(/[^ :]+\.sol):\d+:")
HEADER_RE = re.compile(r"^###\s+###\s+(.*?)$")
HITS_RE   = re.compile(r"^\*\*Hits:\s*(\d+)\s*\*\*\s*$")
def parse_pattern_hits(path):
    rows = []
    if not os.path.exists(path):
        return rows
    cur_pat = None
    with open(path, errors="replace") as fh:
        for line in fh:
            m = HEADER_RE.match(line)
            if m:
                raw = m.group(1)
                # extract a detector-ish slug: first token or "P##" or lowercase identifier
                slug = re.findall(r"[A-Za-z0-9_\-]+", raw)
                cur_pat = slug[0] if slug else raw
                continue
            if HITS_RE.match(line):
                continue
            pm = PATH_LINE.match(line.rstrip())
            if pm:
                p = pm.group(1)
                sev = pattern_severity.get(cur_pat or "", "MEDIUM")
                rows.append({"sev": sev.upper(), "path": p, "det": cur_pat or "", "src": "pattern-hits"})
    return rows

# --- TP counts per workspace (incl. aliases) ---
def ws_match(w, ledger_ws):
    if w == ledger_ws: return True
    stem = re.sub(r"-(v\d+|blue|rc\d*)$", "", ledger_ws)
    if stem == w: return True
    if ledger_ws.startswith(w + "-"): return True
    return False

def tp_for(ws):
    n = 0
    cur = ""
    verdict = ""
    if not os.path.exists(LEDGER): return 0
    with open(LEDGER) as fh:
        for line in fh:
            m = re.match(r"\s*-\s*workspace:\s*(\S+)", line)
            if m:
                # new entry; reset
                if cur and verdict == "TP" and ws_match(ws, cur):
                    n += 1
                cur = m.group(1).strip()
                verdict = ""
                continue
            m = re.match(r"\s+verdict:\s*(\S+)", line)
            if m:
                verdict = m.group(1).strip()
    if cur and verdict == "TP" and ws_match(ws, cur):
        n += 1
    return n

# --- iterate workspaces ---
results = []
for d in sorted(glob.glob(os.path.join(AUDITS_DIR, "*/"))):
    ws = os.path.basename(d.rstrip("/"))
    hints = scope_hints(d)
    rows  = parse_custom_log(os.path.join(d, "custom-detectors.log"))
    rows += parse_pattern_hits(os.path.join(d, "PATTERN_HITS.md"))

    raw = len(rows)
    scoped = 0
    by_reason_dropped = {"tier": 0, "severity": 0, "oos": 0}
    for r in rows:
        det = r.get("det", "")
        tier = tier_of.get(det, "")
        if TIER_FILTER:
            # Resolve effective tier:
            #   - explicit entry in _tier_registry.yaml wins
            #   - else: custom-detectors.log hits are already tier-filtered at
            #     execution ("tier filter: S,E default" in run_custom.py header),
            #     so treat unknown-tier log hits as implicit E
            #   - else: if detector has a DSL yaml in reference/patterns.dsl/ we
            #     treat it as implicit Tier-E (first-class pattern with fixtures)
            #   - else: unregistered (P## bug_patterns_observed #s) → drop
            if tier:
                eff_tier = tier
            elif r.get("src") == "custom-log" and det:
                eff_tier = "E"
            elif det and det in pattern_severity:
                eff_tier = "E"
            else:
                eff_tier = ""
            if not eff_tier or eff_tier not in TIER_FILTER:
                by_reason_dropped["tier"] += 1
                continue
        sev_n = SEV_RANK.get(r.get("sev", "MEDIUM"), 2)
        if sev_n < SEV_MIN:
            by_reason_dropped["severity"] += 1
            continue
        if IN_SCOPE_ONLY and not in_scope_path(r.get("path", ""), hints):
            by_reason_dropped["oos"] += 1
            continue
        scoped += 1

    tp = tp_for(ws)
    results.append({
        "workspace": ws,
        "raw_hits": raw,
        "scoped_hits": scoped,
        "tp": tp,
        "raw_ratio":   (tp / raw)    if raw    > 0 else 0.0,
        "scoped_ratio":(tp / scoped) if scoped > 0 else 0.0,
        "dropped": by_reason_dropped,
    })

total_raw    = sum(r["raw_hits"]    for r in results)
total_scoped = sum(r["scoped_hits"] for r in results)
total_tp     = sum(r["tp"]          for r in results)
g_raw    = (total_tp / total_raw)    if total_raw    else 0.0
g_scoped = (total_tp / total_scoped) if total_scoped else 0.0
verdict_raw    = "PASS" if g_raw    >= THRESHOLD else "FAIL"
verdict_scoped = "PASS" if g_scoped >= THRESHOLD else "FAIL"

print(json.dumps({
    "workspaces":      results,
    "total_raw":       total_raw,
    "total_scoped":    total_scoped,
    "total_tp":        total_tp,
    "global_raw":      g_raw,
    "global_scoped":   g_scoped,
    "verdict_raw":     verdict_raw,
    "verdict_scoped":  verdict_scoped,
    "threshold":       THRESHOLD,
    "tier_filter":     sorted(TIER_FILTER),
    "severity_filter": SEVERITY_FILTER,
    "in_scope_only":   IN_SCOPE_ONLY,
}))
PY
)

# ---------- formatting ----------
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TMP=$(mktemp -t c3_status.XXXX)

python3 - "$NOW" "$OUT_JSON" "$STATUS" >"$TMP" <<'PY'
import json, sys, os, re

now = sys.argv[1]
data = json.loads(sys.argv[2])
status_path = sys.argv[3]

def line(fmt, *a): print(fmt % a)

line("# C3 status — ≥1 TP per 50 detector hits  (threshold %.2f)", data["threshold"])
line("# Generated: %s", now)
line("# Scoping: tier=%s  severity=%s  in_scope_only=%s",
     ",".join(data["tier_filter"]) or "ALL",
     data["severity_filter"],
     "yes" if data["in_scope_only"] else "no")
print()
print(f"{'workspace':<24}  {'raw_hits':>8}  {'scoped':>8}  {'tp':>4}  "
      f"{'raw_ratio':>10}  {'scoped_ratio':>12}")
print(f"{'-'*24:<24}  {'-'*8:>8}  {'-'*8:>8}  {'-'*4:>4}  "
      f"{'-'*10:>10}  {'-'*12:>12}")
for w in data["workspaces"]:
    print(f"{w['workspace']:<24}  {w['raw_hits']:>8d}  {w['scoped_hits']:>8d}  "
          f"{w['tp']:>4d}  {w['raw_ratio']:>10.4f}  {w['scoped_ratio']:>12.4f}")
print()
print(f"{'GLOBAL (sum)':<24}  {data['total_raw']:>8d}  {data['total_scoped']:>8d}  "
      f"{data['total_tp']:>4d}  {data['global_raw']:>10.4f}  {data['global_scoped']:>12.4f}")
print()
print(f"Verdict (raw):    {data['verdict_raw']}    (global {data['global_raw']:.4f} vs {data['threshold']:.2f})")
print(f"Verdict (scoped): {data['verdict_scoped']}    (global {data['global_scoped']:.4f} vs {data['threshold']:.2f})")
print()
print("# Interpretation:")
print("#   raw    = every detector hit, incl. Tier-D noise + test/mock files + Info/Low.")
print("#            Useful as a noise ceiling but not a signal ratio.")
print("#   scoped = Tier-S/E hits only, Medium+ severity, in-scope source files.")
print("#            This is the number C3 is supposed to gate on.")
print()
print("--- previous history ---")

if os.path.exists(status_path):
    with open(status_path) as f:
        content = f.read()
    if "--- previous history ---" in content:
        tail = content.split("--- previous history ---", 1)[1]
        sys.stdout.write(tail)
    else:
        sys.stdout.write(content)
PY

mv "$TMP" "$STATUS"

# ---------- human / json output ----------
if [ "$JSON" = 1 ]; then
    printf '%s\n' "$OUT_JSON"
elif [ "$QUIET" = 0 ]; then
    echo "=== c3-compute (R50 scoped) ==="
    echo "  tier=$TIER_FILTER severity=$SEVERITY_FILTER in_scope_only=$IN_SCOPE_ONLY threshold=$THRESHOLD"
    python3 - "$OUT_JSON" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
for w in d["workspaces"]:
    print(f"  {w['workspace']:<24} raw={w['raw_hits']:<5} "
          f"scoped={w['scoped_hits']:<5} tp={w['tp']:<2} "
          f"raw={w['raw_ratio']:.4f} scoped={w['scoped_ratio']:.4f} "
          f"(dropped tier={w['dropped']['tier']} sev={w['dropped']['severity']} oos={w['dropped']['oos']})")
print()
print(f"  GLOBAL raw={d['global_raw']:.4f} ({d['verdict_raw']})  "
      f"scoped={d['global_scoped']:.4f} ({d['verdict_scoped']})")
PY
    echo "  Written: $STATUS"
fi

# Exit on the SCOPED verdict — that's the honest number.
verdict_scoped=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["verdict_scoped"])' "$OUT_JSON")
[ "$verdict_scoped" = "PASS" ] && exit 0 || exit 1
