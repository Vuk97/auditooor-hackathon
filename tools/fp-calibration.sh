#!/usr/bin/env bash
# tools/fp-calibration.sh — FP calibration against known-clean reference codebases.
#
# SKILL_ISSUES #52 infrastructure. Runs detectors/run_custom.py against OpenZeppelin
# contracts, Solady, and Solmate (all considered clean by convention). Every hit is
# a CANDIDATE false-positive. Emits docs/archive/FP_CALIBRATION_REPORT.md with per-detector
# FP counts, top-20 noisiest detectors, and recommended remediation.
#
# Does NOT download anything. Operator must pre-clone at pinned versions into
# ~/.calibration-workspaces/ (see docs/archive/FP_CALIBRATION.md for the one-liner).
# Exits 0 gracefully with instructions if workspaces are missing.
#
# Usage:
#   bash tools/fp-calibration.sh                # full run (S+E tiers)
#   TIER=ALL  bash tools/fp-calibration.sh      # include Tier-D drafts
#   WS_ROOT=/custom/path bash tools/fp-calibration.sh
#   bash tools/fp-calibration.sh --smoke        # hermetic in-tree fixture corpus
#
# --smoke mode (P1-4 burn-down): scan the in-tree miniature clean corpus at
# tests/fixtures/fp_calibration_corpus/ instead of the operator-supplied
# workspaces. Emits a calibration manifest sidecar (the JSON read by
# tools/fp-calibration-manifest.py) into LOG_DIR so CI can prove the loop
# wired end-to-end without anyone first cloning OZ/Solady/Solmate.
#
# See: docs/archive/FP_CALIBRATION.md, SKILL_ISSUES.md #52

set -euo pipefail

# ─── Argument parsing (long-flag --smoke + legacy env vars) ─────────────────
SMOKE_MODE=0
for arg in "$@"; do
  case "$arg" in
    --smoke) SMOKE_MODE=1 ;;
    -h|--help)
      sed -n '1,30p' "$0"
      exit 0
      ;;
    *)
      echo "[fp-calibration] unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WS_ROOT="${WS_ROOT:-$HOME/.calibration-workspaces}"
TIER="${TIER:-S,E}"
LOG_DIR="${LOG_DIR:-/tmp/fp-calibration}"
REPORT="$REPO_ROOT/docs/archive/FP_CALIBRATION_REPORT.md"
SMOKE_CORPUS="$REPO_ROOT/tests/fixtures/fp_calibration_corpus"
SMOKE_MANIFEST_OUT="${SMOKE_MANIFEST_OUT:-$LOG_DIR/smoke_manifest.json}"

# Prefer real Foundry forge over PATH collisions (e.g. AI CLI tool named forge)
if [[ -x "$HOME/.foundry/bin/forge" ]]; then
    export PATH="$HOME/.foundry/bin:$PATH"
fi

# Pinned versions — update here when bumping.
# Format: slug|git-url|pinned-tag
LIBS=(
  "openzeppelin-contracts|https://github.com/OpenZeppelin/openzeppelin-contracts|v5.1.0"
  "solady|https://github.com/Vectorized/solady|v0.0.287"
  "solmate|https://github.com/transmissions11/solmate|v7"
)

mkdir -p "$LOG_DIR"

# ─── Smoke mode: hermetic in-tree corpus ────────────────────────────────────
if [ "$SMOKE_MODE" = "1" ]; then
  if [ ! -d "$SMOKE_CORPUS" ]; then
    echo "[fp-calibration] smoke corpus missing: $SMOKE_CORPUS" >&2
    echo "[fp-calibration] expected by tools/fp-calibration.sh --smoke" >&2
    exit 2
  fi
  smoke_log="$LOG_DIR/scan_smoke.log"
  echo "[fp-calibration] SMOKE mode — corpus: $SMOKE_CORPUS"
  echo "[fp-calibration] tier filter:        $TIER"
  echo "[fp-calibration] log dir:            $LOG_DIR"
  echo ""
  # The smoke corpus is hermetic: no compilation chain required, the
  # detector pipeline is allowed to skip / no-op gracefully. We capture
  # output but never fail the smoke run on detector errors — this script
  # only proves the wiring + manifest emission, not detector quality.
  python3 "$REPO_ROOT/detectors/run_custom.py" --tier="$TIER" "$SMOKE_CORPUS" \
      >"$smoke_log" 2>&1 || true

  # Always emit the smoke manifest, even if the detector chain skipped.
  # Downstream tests rely on the file existing with the expected schema.
  python3 - "$smoke_log" "$SMOKE_MANIFEST_OUT" "$SMOKE_CORPUS" <<'PY'
import datetime, hashlib, json, pathlib, re, sys
log_path  = pathlib.Path(sys.argv[1])
out_path  = pathlib.Path(sys.argv[2])
corpus    = pathlib.Path(sys.argv[3])

running_re = re.compile(r"^=== Running (\S+) ===")
hit_re     = re.compile(r"^\s*\[(HIGH|MEDIUM|LOW|INFORMATIONAL|OPTIMIZATION)\]")

executed: list[str] = []
hits: dict[str, int] = {}
text = log_path.read_text(errors="ignore") if log_path.exists() else ""
current = None
for line in text.splitlines():
    m = running_re.match(line)
    if m:
        current = m.group(1)
        executed.append(current)
        continue
    if current and hit_re.match(line):
        hits[current] = hits.get(current, 0) + 1

# Hash the corpus tree contents (deterministic, sorted).
hasher = hashlib.sha256()
files = sorted(p for p in corpus.rglob("*.sol") if p.is_file())
for p in files:
    rel = p.relative_to(corpus).as_posix()
    hasher.update(rel.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(p.read_bytes())
corpus_hash = hasher.hexdigest()[:16]

now = datetime.datetime.now(datetime.timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)
manifest = {
    "schema_version": "auditooor.fp_calibration_smoke.v1",
    "mode": "smoke",
    "generated_iso": now,
    "corpus_root": str(corpus),
    "corpus_file_count": len(files),
    "corpus_hash": corpus_hash,
    "detectors_executed": sorted(set(executed)),
    "hits_by_detector": dict(sorted(hits.items())),
    "total_hits": sum(hits.values()),
}
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(f"[fp-calibration] smoke manifest: {out_path}")
print(f"[fp-calibration] corpus_hash={corpus_hash} files={len(files)} "
      f"detectors_executed={len(set(executed))} total_hits={sum(hits.values())}")
PY
  echo ""
  echo "[fp-calibration] smoke done."
  exit 0
fi

# ─── Preflight: do the workspaces exist? ────────────────────────────────────
missing=()
for entry in "${LIBS[@]}"; do
  slug="${entry%%|*}"
  if [ ! -d "$WS_ROOT/$slug" ]; then
    missing+=("$slug")
  fi
done

if [ ${#missing[@]} -gt 0 ]; then
  echo "[fp-calibration] calibration workspaces missing. Clone them first:"
  echo ""
  echo "  mkdir -p $WS_ROOT && cd $WS_ROOT"
  for entry in "${LIBS[@]}"; do
    slug="${entry%%|*}"; rest="${entry#*|}"
    url="${rest%%|*}"; tag="${rest##*|}"
    if [ ! -d "$WS_ROOT/$slug" ]; then
      echo "  git clone --depth 1 --branch $tag $url $slug"
    fi
  done
  echo ""
  echo "  Then re-run: make fp-calibration  (or bash tools/fp-calibration.sh)"
  echo ""
  echo "[fp-calibration] skipping (0 workspaces available). Exiting 0."
  exit 0
fi

# ─── Scan each library, log hits ────────────────────────────────────────────
echo "[fp-calibration] workspace root: $WS_ROOT"
echo "[fp-calibration] tier filter:   $TIER"
echo "[fp-calibration] log dir:       $LOG_DIR"
echo ""

for entry in "${LIBS[@]}"; do
  slug="${entry%%|*}"
  ws="$WS_ROOT/$slug"
  log="$LOG_DIR/scan_${slug}.log"
  echo "[fp-calibration] scanning $slug ..."
  # Graceful: a single library failing to compile doesn't abort the full run.
  if ! python3 "$REPO_ROOT/detectors/run_custom.py" --tier="$TIER" "$ws" \
         >"$log" 2>&1; then
    echo "[fp-calibration]   WARN: scan failed — see $log (continuing)"
  fi
done

# ─── Aggregate hits into a report via Python (easier than awk gymnastics) ──
python3 - "$LOG_DIR" "$REPORT" "${LIBS[@]}" <<'PY'
import sys, re, collections, pathlib, datetime
log_dir = pathlib.Path(sys.argv[1])
report  = pathlib.Path(sys.argv[2])
libs    = [e.split("|")[0] for e in sys.argv[3:]]

# hits[detector][library] = count
hits = collections.defaultdict(lambda: collections.defaultdict(int))
executed = set()

# Parse run_custom.py output. Format:
#   === Running <detector_arg> ===
#   [<IMPACT>] <description>...   (one line per hit)
#   === Running <next_detector> ===
running_re = re.compile(r"^=== Running (\S+) ===")
hit_re     = re.compile(r"^\s*\[(HIGH|MEDIUM|LOW|INFORMATIONAL|OPTIMIZATION)\]")

for lib in libs:
    log = log_dir / f"scan_{lib}.log"
    if not log.exists():
        continue
    current = None
    for line in log.read_text(errors="ignore").splitlines():
        m = running_re.match(line)
        if m:
            current = m.group(1)
            executed.add(current)
            continue
        if current and hit_re.match(line):
            hits[current][lib] += 1

# Totals
totals = {d: sum(hits[d].values()) for d in hits}
ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)

# ─── Emit report ───
out = []
out.append("# FP Calibration Report")
out.append("")
out.append(f"*Generated:* {datetime.datetime.now().isoformat(timespec='seconds')}")
out.append("")
out.append("Runs the custom detector library against **known-clean reference "
           "codebases** (OpenZeppelin, Solady, Solmate). Any hit is a **candidate "
           "false-positive** — these libraries are peer-reviewed and considered "
           "the ground-truth baseline.")
out.append("")
out.append("See `docs/archive/FP_CALIBRATION.md` for the sprint plan and remediation "
           "workflow. This report is regenerated by `make fp-calibration`.")
out.append("")
out.append("## Summary")
out.append("")
out.append(f"- **Detectors executed:** {len(executed)}")
out.append(f"- **Detectors with ≥1 FP:** {len(hits)}")
out.append(f"- **Total candidate FPs:** {sum(totals.values())}")
out.append(f"- **Libraries scanned:** {', '.join(libs)}")
out.append("")

out.append("## Per-detector FP counts")
out.append("")
hdr = "| Detector | " + " | ".join(libs) + " | Total |"
sep = "|" + "---|" * (len(libs) + 2)
out.append(hdr); out.append(sep)
for d, tot in ranked:
    row = [d] + [str(hits[d].get(l, 0)) for l in libs] + [str(tot)]
    out.append("| " + " | ".join(row) + " |")
if not ranked:
    out.append("| *(no hits — clean)* | " + " | ".join(["0"]*len(libs)) + " | 0 |")
out.append("")

out.append("## Top-20 noisiest detectors")
out.append("")
out.append("Highest-priority remediation candidates. Each firing on OZ/Solady/"
           "Solmate is an FP by construction — the detector's precondition is "
           "too permissive.")
out.append("")
out.append("| Rank | Detector | FP count | Recommended action |")
out.append("|---|---|---|---|")
for i, (d, tot) in enumerate(ranked[:20], 1):
    if tot >= 50:
        action = "**Graveyard** — precondition catastrophically broad."
    elif tot >= 10:
        action = "**Demote to Tier-D** and tighten precondition."
    else:
        action = "Add library-path suppressor or tighten DSL filter."
    out.append(f"| {i} | `{d}` | {tot} | {action} |")
if not ranked:
    out.append("| — | *(library is clean — no remediation needed)* | 0 | — |")
out.append("")

out.append("## Remediation playbook")
out.append("")
out.append("1. **FP count ≥ 50 across libs** → move to `detectors/wave_graveyard/` "
           "with a citation pointing at this report. These detectors are signal-"
           "free on real production code.")
out.append("2. **FP count 10-49** → demote tier (S→E, E→D) via "
           "`make tier-move DET=<name> FROM=<t> TO=<t>` and open a tightening "
           "task. Re-run calibration before re-promoting.")
out.append("3. **FP count 1-9** → inspect hits manually. Often fixed by adding "
           "a source-path filter (`/openzeppelin/`, `/solady/`, `/solmate/`) to "
           "the detector's `SKIP_KEYWORDS` or DSL `path_exclude`.")
out.append("4. **FP count 0** → detector is calibrated. Leave alone.")
out.append("")
out.append("See SKILL_ISSUES.md #52 for background and the full sprint plan.")
out.append("")

report.parent.mkdir(parents=True, exist_ok=True)
report.write_text("\n".join(out))
print(f"[fp-calibration] wrote {report}")
print(f"[fp-calibration] detectors with FPs: {len(hits)} / executed: {len(executed)}")
print(f"[fp-calibration] total candidate FPs: {sum(totals.values())}")
PY

echo ""
echo "[fp-calibration] done. Report: $REPORT"
