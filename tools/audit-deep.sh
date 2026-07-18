#!/usr/bin/env bash
# audit-deep.sh - opt-in escalation atop `make audit`.
#
# v3 Slice 4 deliverable. Aggregates the slow / opt-in tools documented in
# docs/TOOL_COST_BENEFIT.md, gracefully skipping any that are not on PATH.
#
# Usage:
#   tools/audit-deep.sh <workspace>
#
# The Makefile target `make audit-deep WS=<path>` is the user-facing entry;
# this script is what the recipe ultimately invokes (so the logic is
# testable in isolation by tools/tests/test_audit_deep_target.sh).
#
# Contract:
#   - Always exits 0 unless the workspace argument itself is invalid (exit 2).
#   - Missing optional tools (halmos, medusa, mythril, kontrol, echidna)
#     produce a one-line note in the report and DO NOT fail the run.
#   - Writes a single human-readable report to:
#       <workspace>/.audit_logs/audit_deep_report.md
#   - Pointers to per-tool artifacts (symbolic_runs/, fuzz_runs/) are listed
#     in the report; no JSON aggregation here - the underlying runners
#     already write their own manifests.
#
# Discipline:
#   - Stdlib + bash only. No new pip deps.
#   - Status vocabulary mirrors tools/ci-preflight.sh on purpose (✓ / ✗).
#   - Never runs `make audit` itself - that is the caller's responsibility
#     (the Makefile recipe chains the two with `&&`). Keeps this script's
#     side effects narrow and the test surface small.
#   - The companion DRY_RUN=1 path (set via env or --dry-run) writes the
#     report header + planned commands and exits 0 without invoking any
#     external tool. Used by tools/tests/test_audit_deep_target.sh.

set -uo pipefail

DRY_RUN="${AUDIT_DEEP_DRY_RUN:-0}"
# V4 P4: deep audit can be parameterized by profile. The default profile is
# the v3 Slice 4 behavior (halmos / medusa / echidna / slither aggregation).
# `medium` is the WF-4 bounded hunt-prep profile: it reuses the default
# flow but executes halmos/medusa/echidna with short live timeouts instead
# of rendering planned-only engine commands. `econ` is the V4 P4
# economic-security profile (actor model + state machine + Tier-B advisory
# report). `math` is the V4 P2 math-invariant profile. `crypto` is the V4
# P3 verifier / proof-system review profile (Workstream C; Tier-B advisory).
# `all` runs the bounded handoff-oriented sequence default -> math -> econ
# -> crypto and emits a combined manifest.
# Selectable via --profile or env var DEEP_PROFILE so the Makefile recipe can
# stay one-line.
PROFILE="${DEEP_PROFILE:-default}"
# I17 fix (#334): opt-in auto-scaffold of invariant harness before halmos/medusa.
SCAFFOLD="${AUDIT_DEEP_SCAFFOLD:-0}"

usage() {
    cat <<EOF
usage: tools/audit-deep.sh [--dry-run] [--live] [--scaffold] [--profile NAME] [--project-root PATH] <workspace>

  --dry-run         Render the planned tool invocations into the report
                    and exit 0 without invoking any external tool.
                    Equivalent to AUDIT_DEEP_DRY_RUN=1 in the env.
  --live            ACTUALLY execute halmos / medusa / echidna instead of
                    just rendering "planned" command strings. Without this
                    flag, the inner symbolic-runner / fuzz-runner are
                    invoked with --dry-run (their own dry-run) so the
                    engines never execute - only Slither runs for real.
                    The default is intentionally cheap (planned + slither)
                    so existing callers don't get surprise multi-hour runs.
                    Equivalent to AUDIT_DEEP_LIVE=1 (legacy) or
                    AUDITOOOR_AUDIT_DEEP_LIVE=1 in the env.
                    See I12 (#327) for the regression this closes.
                    Also requires the inner runners' I13 fix (#328) which
                    auto-detects the forge project root so the engines
                    actually find the build artifacts.
  --scaffold        Auto-scaffold an invariant harness for the highest-ranked
                    contract from mining_priorities.json before invoking halmos
                    and medusa. Only active when --live is also set.
                    Equivalent to AUDIT_DEEP_SCAFFOLD=1 in the env.
                    See I17 (#334). When an invariant ledger exists, this also
                    runs the advisory Recon/Chimera ledger scaffold bridge for
                    Solidity rows and writes
                    <ws>/.audit_logs/chimera_scaffold_manifest.json.
  --profile NAME    Pick a deep-audit profile. Supported names:
                      all      bounded handoff sweep - runs default, math,
                               econ, and crypto sequentially, preserves each
                               profile log/report, and emits
                               audit_deep_all_manifest.json for Kimi/Minimax.
                               Budget guard:
                               AUDIT_DEEP_ALL_MAX_SECONDS (default 1800).
                      coverage-gaps  V5 Gap-46 - surface enumeration +
                               library-coverage cross-check + bounded
                               Kimi/Minimax gap-surfacing pass. OPT-IN
                               only - NEVER part of `all` (Codex P0 #3
                               final-pass: gate on 3-5 real-workspace
                               runs first). Stdlib-only Python; the LLM
                               pass is hard-bounded to 30 calls per run
                               via AUDITOOOR_LLM_BUDGET_GUARD=1.
                      default  v3 Slice 4 - halmos/medusa/echidna/slither
                      medium   WF-4 bounded hunt-prep - default flow with
                               real engine execution under short caps
                               (halmos 120s, medusa/echidna 300s by default).
                      crypto   V4 P3 - verifier / proof-system review.
                               Detects verifier-shaped contracts under the
                               workspace, emits a Kimi/Minimax work packet
                               and a Tier-B advisory crypto_deep_report.md
                               based on templates/crypto_verifier_review.md.
                               Does NOT call halmos / medusa.
                      econ     V4 P4 - actor model + state machine
                               + Tier-B advisory report (no exploit proof).
                               Reads <ws>/economic_hypotheses/*.md (the
                               output of engage stage 16); does NOT call
                               halmos / medusa.
                      math     V4 P2 - math-invariant mining (Tier B
                               advisory). Calls tools/math-invariant-miner.py
                               against <ws>/src/**.sol (or --contracts glob)
                               and emits MATH_SPEC.md + math_spec.json under
                               <ws>/math_invariants/. Stdlib-only Python; does
                               NOT call halmos / medusa / slither.
                    Equivalent to DEEP_PROFILE=NAME in the env.
  --project-root PATH
                    Forge project root to forward to the symbolic/fuzz
                    runners when the target Foundry project is nested outside
                    audit-deep's default auto-detection path. Equivalent to
                    FOUNDRY_PROJECT_ROOT=PATH or PROJECT_ROOT=PATH in the env.
                    Existing behavior is unchanged when unset.
  --help            Show this help.

Env vars added by WF-4 patches (iter18):
  SKIP_REGEX=1               WF-4 Patch B: skip the regex-detectors arsenal
                             step (saves 2-10min wall-clock). Default fires
                             the wave17 + rust_wave1 + wave14 + go_wave1 +
                             every other wave*/ regex detector on the
                             workspace and writes audit-deep-regex-detectors.txt.
  AUDIT_DEEP_R37_STRICT=1    WF-4 Patch A: promote the R37 verification-tier
                             audit from warn-only to fail-closed. Default
                             warns on non-PASS; strict mode records the
                             entry in failed[]. STRICT=1 also promotes.
  SKIP_DETECTOR_SMOKE=1      WF-4 Patch H: skip the fast detector-smoke
                             unit-test stitch step. Default runs
                             tools.tests.test_run_detector and
                             tools.tests.test_inventory_smoke_test after
                             deep steps and records pass/fail in Summary.
  AUDIT_DEEP_DETECTOR_SMOKE_STRICT=1
                             Promote detector-smoke unit-test failure from
                             advisory failed[] signal to final non-zero exit.

The workspace must already exist. The script writes its report to
<workspace>/.audit_logs/audit_deep_report.md (canonical, all profiles).
Profile-specific artifacts:
  all              audit_deep_all_report.md + audit_deep_all_manifest.json
  coverage-gaps    coverage_surface.json + coverage_by_category.json +
                   coverage_gaps_kimi.md + coverage_gaps_minimax.md +
                   coverage_gaps_ranked.md +
                   .audit_logs/coverage_introspect_manifest.json
  default          audit_deep_<TS>.md
  medium           audit_deep_medium_<TS>.md
  econ             econ_deep_report.md + ACTORS.md + STATE_MACHINE.md
  math             math_invariants/MATH_SPEC.md + math_invariants/math_spec.json
  crypto           crypto_work_packet.json + crypto_deep_report.md
  cross-lane       .audit_logs/cross_lane_correlations.json +
                   .audit_logs/cross_lane_correlations.md (all profiles)
  deep-counterexamples
                   deep_counterexamples/collection_manifest.json +
                   deep_counterexamples/*.deep_counterexample.v1.json +
                   deep_counterexamples/execution_queue.{json,md}
The script never fails just because an optional binary is not installed.
EOF
}

WORKSPACE=""
# I12 fix (#327): --live drops the hardcoded `--dry-run` flag from the
# inner symbolic-runner / fuzz-runner invocations so halmos / medusa /
# echidna actually execute. Defaults stay opt-in (dry-run-of-runners +
# slither-only) so existing callers don't get surprise multi-hour runs.
LIVE="${AUDITOOOR_AUDIT_DEEP_LIVE:-${AUDIT_DEEP_LIVE:-0}}"
PROJECT_ROOT_OVERRIDE="${FOUNDRY_PROJECT_ROOT:-${PROJECT_ROOT:-}}"
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --live)    LIVE=1; shift ;;
        --scaffold) SCAFFOLD=1; shift ;;
        --project-root)
            if [ $# -lt 2 ]; then
                echo "[audit-deep] --project-root requires a PATH argument" >&2
                exit 2
            fi
            PROJECT_ROOT_OVERRIDE="$2"; shift 2 ;;
        --project-root=*)
            PROJECT_ROOT_OVERRIDE="${1#--project-root=}"; shift ;;
        --profile)
            if [ $# -lt 2 ]; then
                echo "[audit-deep] --profile requires a NAME argument" >&2
                exit 2
            fi
            PROFILE="$2"; shift 2 ;;
        --profile=*)
            PROFILE="${1#--profile=}"; shift ;;
        --help|-h) usage; exit 0 ;;
        --)        shift; break ;;
        -*)
            echo "[audit-deep] unknown flag: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [ -z "$WORKSPACE" ]; then
                WORKSPACE="$1"
            else
                echo "[audit-deep] only one workspace may be passed (got '$WORKSPACE' and '$1')" >&2
                exit 2
            fi
            shift
            ;;
    esac
done

if [ -z "$WORKSPACE" ]; then
    echo "[audit-deep] ERR no workspace passed" >&2
    usage >&2
    exit 2
fi
if [ ! -d "$WORKSPACE" ]; then
    echo "[audit-deep] ERR workspace not found or not a directory: $WORKSPACE" >&2
    exit 2
fi

case "$PROFILE" in
    all|coverage-gaps|default|medium|crypto|econ|math) ;;
    *)
        echo "[audit-deep] ERR unknown profile: $PROFILE (supported: all, coverage-gaps, crypto, default, medium, econ, math)" >&2
        exit 2
        ;;
esac

DEFAULT_PROFILE_LABEL="default"
AUDIT_DEEP_MEDIUM_MODE=0
if [ "$PROFILE" = "medium" ]; then
    DEFAULT_PROFILE_LABEL="medium"
    AUDIT_DEEP_MEDIUM_MODE=1
    LIVE=1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib/tool-availability.sh
. "$HERE/lib/tool-availability.sh"

LOG_DIR="$WORKSPACE/.audit_logs"
mkdir -p "$LOG_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$LOG_DIR/audit_deep_report.md"
R37_HANDOFF_STATUS="not-run"
R37_HANDOFF_LOG=""
REGEX_HANDOFF_STATUS="not-run"
REGEX_HANDOFF_OUTPUT="$WORKSPACE/audit-deep-regex-detectors.txt"
REGEX_HANDOFF_MANIFEST="$WORKSPACE/.audit_logs/regex_detectors_manifest.json"
DETECTOR_SMOKE_HANDOFF_STATUS="not-run"
DETECTOR_SMOKE_HANDOFF_LOG="$LOG_DIR/detector_smoke_unit_tests_${TS}.log"
DETECTOR_SMOKE_FAIL=0

# ---------------------------------------------------------------------------
# V5-P0-11 / Gap 21: per-profile timestamped reports + canonical symlink.
#
# Before this fix, every profile handler ended with `cp $RUN_LOG $REPORT`
# where $REPORT is the shared `audit_deep_report.md`. The result was a
# last-profile-wins overwrite when an operator ran multiple profiles back
# to back (or DEEP_PROFILE=all). This helper writes each profile's report
# to `audit_deep_<profile>_<TS>.md` and (re)points the canonical
# `audit_deep_report.md` symlink at the latest. Older per-profile reports
# are NEVER touched.
#
# `audit_deep_<profile>_<TS>.md` is the durable artifact. The canonical
# symlink is a convenience so existing readers (`cat
# .audit_logs/audit_deep_report.md`) keep working.
#
# When run on filesystems that do not support symlinks (Windows, some
# Docker layers, some sandbox configs), we fall back to a copy and warn.
# ---------------------------------------------------------------------------
publish_profile_report() {
    # publish_profile_report <profile_label> <source_run_log>
    #
    # 1. Copies the source run log to LOG_DIR/audit_deep_<label>_<TS>.md
    #    (idempotent - never overwrites a prior <TS> report).
    # 2. Re-points $REPORT (audit_deep_report.md) at the per-profile file
    #    via a symlink, falling back to a copy.
    local profile_label="$1"
    local source_log="$2"
    local per_profile="$LOG_DIR/audit_deep_${profile_label}_${TS}.md"

    run_cross_lane_correlate "$source_log"

    cp "$source_log" "$per_profile"

    # Replace the canonical pointer atomically. `ln -sf` re-targets a
    # symlink in a single rename operation; if symlink creation fails
    # (uncommon filesystems), fall back to copy.
    rm -f "$REPORT"
    if ln -sf "$(basename "$per_profile")" "$REPORT" 2>/dev/null; then
        :
    else
        cp "$per_profile" "$REPORT"
        echo "[audit-deep] WARN canonical audit_deep_report.md fell back to copy (symlink unsupported)" >&2
    fi
}

# ---------------------------------------------------------------------------
# I17 fix (#334): auto-scaffold invariant harness before halmos/medusa.
# I20 (#341) + I21 (#342): resolve test dir from foundry.toml; emit both
# Invariant_* and Property_* harnesses when --scaffold is active.
# When --scaffold AND --live are set, peek at mining_priorities.json,
# resolve the highest-ranked contract source under src/, and call
# gen-invariants.sh if the harness doesn't already exist.
# Idempotent: never overwrites an existing harness.
# ---------------------------------------------------------------------------
maybe_scaffold() {
    local contract_name contract_path harness_file resolved_test_dir
    local mp_path="$WORKSPACE/swarm/mining_priorities.json"

    if [ "$SCAFFOLD" != "1" ] || [ "$LIVE" != "1" ]; then
        return 0
    fi

    if [ ! -f "$mp_path" ]; then
        {
            echo "- scaffold: SKIPPED (no mining_priorities.json; cannot auto-pick contract)"
        } >> "$RUN_LOG"
        return 0
    fi

    contract_name=""
    if command -v python3 >/dev/null 2>&1; then
        contract_name="$(
            python3 - "$mp_path" <<'PY' 2>/dev/null || true
import json, re, sys
path = sys.argv[1]
try:
    data = json.loads(open(path).read())
except Exception:
    sys.exit(0)
if not isinstance(data, list):
    sys.exit(0)
for entry in data:
    if not isinstance(entry, dict):
        continue
    c = entry.get("contract")
    if isinstance(c, str) and c.strip():
        print(c.strip()); sys.exit(0)
    cs = entry.get("contracts")
    if isinstance(cs, list):
        for x in cs:
            if isinstance(x, str) and x.strip():
                print(x.strip()); sys.exit(0)
    title = entry.get("title") or ""
    if isinstance(title, str) and title:
        m = re.search(r":\s+([A-Z][A-Za-z0-9_]+)\.[a-zA-Z_]", title)
        if not m:
            m = re.search(r"\b([A-Z][A-Za-z0-9_]+)\.[a-zA-Z_]", title)
        if m:
            print(m.group(1)); sys.exit(0)
PY
        )"
    fi

    if [ -z "$contract_name" ]; then
        {
            echo "- scaffold: SKIPPED (mining_priorities.json has no extractable contract)"
        } >> "$RUN_LOG"
        return 0
    fi

    # I20: resolve the workspace's configured test directory.
    resolved_test_dir="test"
    if command -v python3 >/dev/null 2>&1; then
        resolved_test_dir="$(python3 "$HERE/lib/resolve-forge-test-dir.py" "$WORKSPACE" 2>/dev/null || echo test)"
    fi

    harness_file="$WORKSPACE/$resolved_test_dir/Invariant_${contract_name}.t.sol"
    if [ -f "$harness_file" ]; then
        {
            echo "- scaffold: REUSE existing harness \`$harness_file\`"
        } >> "$RUN_LOG"
        return 0
    fi

    contract_path=""
    if [ -d "$WORKSPACE/src" ]; then
        contract_path="$(find "$WORKSPACE/src" -name "${contract_name}.sol" -print 2>/dev/null | head -n 1 || true)"
    fi

    if [ -z "$contract_path" ] || [ ! -f "$contract_path" ]; then
        {
            echo "- scaffold: SKIPPED (contract source not found under \`$WORKSPACE/src/\` for \`$contract_name\`)"
        } >> "$RUN_LOG"
        return 0
    fi

    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- scaffold: planned \`bash $HERE/gen-invariants.sh '$contract_path' '$WORKSPACE' --engine both\`"
            echo "- scaffold: skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        return 0
    fi

    if bash "$HERE/gen-invariants.sh" "$contract_path" "$WORKSPACE" --engine both >>"$RUN_LOG" 2>&1; then
        {
            echo "- scaffold: OK wrote \`$harness_file\` (SETUP-INCOMPLETE; auditor must wire setUp)"
        } >> "$RUN_LOG"
    else
        {
            echo "- scaffold: FAIL gen-invariants.sh exited non-zero for \`$contract_name\`"
        } >> "$RUN_LOG"
    fi
}

run_deep_candidate_adjudicate() {
    # run_deep_candidate_adjudicate <source_run_log>
    #
    # FIX 1: wire validate-deep-candidate.py (schema + V5 advisory-floor
    # adjudicator) into the deep flow so each emitted deep_candidate.v1 record
    # under <ws>/deep_candidates/*.json is actually run through the validator
    # and a per-candidate verdict recorded to a sidecar JSON. Advisory: never
    # fails the run; just turns produced candidates into kept/killed verdicts.
    local source_log="$1"
    local cand_dir="$WORKSPACE/deep_candidates"
    local verdict_json="$LOG_DIR/deep_candidate_adjudication.json"

    {
        echo
        echo "## Deep candidate adjudication (validate-deep-candidate)"
        echo
    } >> "$source_log"

    if [ ! -f "$HERE/validate-deep-candidate.py" ] || ! command -v python3 >/dev/null 2>&1; then
        echo "- status: SKIPPED validate-deep-candidate.py or python3 missing" >> "$source_log"
        return 0
    fi

    if [ ! -d "$cand_dir" ] || [ -z "$(find "$cand_dir" -name '*.json' -print -quit 2>/dev/null)" ]; then
        echo "- status: SKIPPED no deep_candidates/*.json to adjudicate" >> "$source_log"
        return 0
    fi

    # The validator's main() takes one-or-more candidate paths and returns
    # rc=0 only when ALL are valid. We want a per-candidate verdict sidecar,
    # so we drive it from a small Python wrapper that calls validate() per file.
    if python3 - "$cand_dir" "$verdict_json" "$HERE" <<'PY' >>"$source_log" 2>&1; then
import json, sys
from pathlib import Path

cand_dir, out_path, here = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, here)
import importlib.util
spec = importlib.util.spec_from_file_location(
    "validate_deep_candidate", str(Path(here) / "validate-deep-candidate.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

results = []
for p in sorted(cand_dir.rglob("*.json")):
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        results.append({"candidate": str(p), "verdict": "parse_error",
                        "errors": [str(exc)]})
        continue
    ok, errors = mod.validate(doc)
    results.append({
        "candidate": str(p),
        "verdict": "kept" if ok else "killed",
        "errors": errors,
    })

kept = sum(1 for r in results if r["verdict"] == "kept")
killed = len(results) - kept
payload = {
    "schema_id": "auditooor.deep_candidate_adjudication.v1",
    "candidate_count": len(results),
    "kept": kept,
    "killed": killed,
    "results": results,
}
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
print(f"deep-candidate-adjudicate: {len(results)} candidate(s), "
      f"{kept} kept, {killed} killed -> {out_path}")
PY
        {
            echo "- status: SUCCESS"
            echo "- verdict-json: \`$verdict_json\`"
            echo "- note: advisory; killed = schema/advisory-floor invalid, kept = valid for promotion gates"
        } >> "$source_log"
    else
        echo "- status: SUCCESS_WARN deep-candidate-adjudicate failed (see log above)" >> "$source_log"
    fi
}

run_adversarial_candidate_verify() {
    # run_adversarial_candidate_verify <source_run_log>
    #
    # FIX 2: wire adversarial-candidate-verify.py (THREE-lens refutation panel)
    # into the deep flow so Medium+ candidates from the deep lane
    # (<ws>/deep_candidates/*.json) and the exploit queue
    # (<ws>/.auditooor/exploit_queue.json rows) are run through the 3-lens
    # refutation and the surviving/refuted panel verdict recorded to a sidecar.
    # Advisory + gated on candidates existing: skips cleanly when none.
    local source_log="$1"
    local verify_json="$LOG_DIR/adversarial_candidate_verify.json"
    local cand_dir="$WORKSPACE/deep_candidates"
    local exploit_queue="$WORKSPACE/.auditooor/exploit_queue.json"

    {
        echo
        echo "## Adversarial candidate verification (3-lens refutation panel)"
        echo
    } >> "$source_log"

    if [ ! -f "$HERE/adversarial-candidate-verify.py" ] || ! command -v python3 >/dev/null 2>&1; then
        echo "- status: SKIPPED adversarial-candidate-verify.py or python3 missing" >> "$source_log"
        return 0
    fi

    if python3 - "$cand_dir" "$exploit_queue" "$verify_json" "$HERE" <<'PY' >>"$source_log" 2>&1; then
import json, sys
from pathlib import Path

cand_dir = Path(sys.argv[1])
exploit_queue = Path(sys.argv[2])
out_path = Path(sys.argv[3])
here = sys.argv[4]
sys.path.insert(0, here)
import importlib.util
spec = importlib.util.spec_from_file_location(
    "adversarial_candidate_verify",
    str(Path(here) / "adversarial-candidate-verify.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _is_medium_plus(sev):
    return isinstance(sev, str) and RANK.get(sev.strip().lower(), 0) >= 2


results = []

# Deep-lane candidates: flatten each JSON into searchable text via the tool's
# own loader, derive severity, run the panel on Medium+ only.
if cand_dir.is_dir():
    for p in sorted(cand_dir.rglob("*.json")):
        try:
            text, obj = mod._load_candidate(p)
        except Exception as exc:
            results.append({"candidate": str(p), "panel_verdict": "error",
                            "reason": str(exc)})
            continue
        sev, sev_src = mod._severity(text, p, "auto", obj)
        if not _is_medium_plus(sev):
            continue
        payload = mod.evaluate(text, sev, sev_src, strict=False)
        results.append({
            "candidate": str(p),
            "source": "deep_candidates",
            "severity": payload.get("severity"),
            "panel_verdict": payload.get("panel_verdict"),
            "refutation_count": payload.get("refutation_count"),
            "reason": payload.get("reason"),
        })

# Exploit-queue rows: each row is a candidate. Flatten its string fields into
# searchable text and use likely_severity as the severity signal.
if exploit_queue.is_file():
    try:
        q = json.loads(exploit_queue.read_text(encoding="utf-8")).get("queue", [])
    except Exception:
        q = []
    for row in q:
        if not isinstance(row, dict):
            continue
        sev = row.get("likely_severity") or row.get("severity")
        if not _is_medium_plus(sev):
            continue
        chunks = []

        def _walk(v):
            if isinstance(v, str):
                chunks.append(v)
            elif isinstance(v, dict):
                for k, vv in v.items():
                    chunks.append(str(k)); _walk(vv)
            elif isinstance(v, list):
                for vv in v:
                    _walk(vv)
        _walk(row)
        text = "\n".join(chunks)
        payload = mod.evaluate(text, sev.strip().lower(), "exploit_queue:likely_severity",
                               strict=False)
        results.append({
            "candidate": row.get("lead_id") or row.get("title") or "exploit_queue_row",
            "source": "exploit_queue",
            "severity": payload.get("severity"),
            "panel_verdict": payload.get("panel_verdict"),
            "refutation_count": payload.get("refutation_count"),
            "reason": payload.get("reason"),
        })

survived = sum(1 for r in results
               if r.get("panel_verdict") in ("pass-survived-panel",
                                             "pass-refutations-ruled-out"))
killed = sum(1 for r in results if r.get("panel_verdict") == "fail-killed-by-panel")
out = {
    "schema_id": "auditooor.adversarial_candidate_verify_batch.v1",
    "medium_plus_count": len(results),
    "survived": survived,
    "killed": killed,
    "results": results,
}
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
if not results:
    print("adversarial-candidate-verify: no Medium+ candidates; skipped cleanly")
else:
    print(f"adversarial-candidate-verify: {len(results)} Medium+ candidate(s), "
          f"{survived} survived, {killed} killed -> {out_path}")
PY
        {
            echo "- status: SUCCESS"
            echo "- verify-json: \`$verify_json\`"
            echo "- note: advisory; fail-killed-by-panel = majority-refuted (>=2/3 lenses) before FINAL_LEADS"
        } >> "$source_log"
    else
        echo "- status: SUCCESS_WARN adversarial-candidate-verify failed (see log above)" >> "$source_log"
    fi
}

run_cross_lane_correlate() {
    # run_cross_lane_correlate <source_run_log>
    #
    # Cheap/default-on V5 G2 pass. It never calls an LLM; it only joins
    # already-emitted deep_candidate.v1 records by overlapping `files[]`.
    local source_log="$1"
    local json_out="$LOG_DIR/cross_lane_correlations.json"
    local md_out="$LOG_DIR/cross_lane_correlations.md"

    {
        echo
        echo "## Cross-lane candidate correlation"
        echo
    } >> "$source_log"

    if [ -x "$HERE/cross-lane-correlate.py" ] && command -v python3 >/dev/null 2>&1; then
        if python3 "$HERE/cross-lane-correlate.py" \
            --workspace "$WORKSPACE" \
            --out-json "$json_out" \
            --out-md "$md_out" \
            >>"$source_log" 2>&1; then
            {
                echo "- status: SUCCESS"
                echo "- json: \`$json_out\`"
                echo "- markdown: \`$md_out\`"
            } >> "$source_log"
        else
            echo "- status: SUCCESS_WARN cross-lane-correlate failed (see log above)" >> "$source_log"
        fi
    else
        echo "- status: SKIPPED cross-lane-correlate.py or python3 missing" >> "$source_log"
    fi

    {
        echo
        echo "## Typed candidate promotion"
        echo
    } >> "$source_log"

    local promo_json="$LOG_DIR/typed_candidate_promotions.json"
    local promo_md="$LOG_DIR/typed_candidate_promotions.md"
    local promo_dossier_dir="$LOG_DIR/production_path_dossiers"
    if [ -f "$HERE/promote-typed-candidate.py" ] && command -v python3 >/dev/null 2>&1; then
        if python3 "$HERE/promote-typed-candidate.py" \
            --workspace "$WORKSPACE" \
            --require-production-path \
            --out-json "$promo_json" \
            --out-md "$promo_md" \
            --out-dossier-dir "$promo_dossier_dir" \
            >>"$source_log" 2>&1; then
            {
                echo "- status: SUCCESS"
                echo "- json: \`$promo_json\`"
                echo "- markdown: \`$promo_md\`"
                echo "- production path dossiers: \`$promo_dossier_dir\`"
                echo "- note: advisory only; \`poc_ready\` now requires a proven candidate-level production path and still requires normal pre-submit gates"
            } >> "$source_log"
        else
            echo "- status: SUCCESS_WARN promote-typed-candidate failed (see log above)" >> "$source_log"
        fi
    else
        echo "- status: SKIPPED promote-typed-candidate.py or python3 missing" >> "$source_log"
    fi

    # FIX 1 + FIX 2: run the two candidate ADJUDICATORS so produced candidates
    # actually get verdicted (kept/killed + survived/refuted). Both are advisory
    # and gated on candidates existing; they skip cleanly when none.
    run_deep_candidate_adjudicate "$source_log"
    run_adversarial_candidate_verify "$source_log"

    {
        echo
        echo "## Hunter Handoff (WF-4 Patch F)"
        echo
        echo "- detector-arsenal-status: $REGEX_HANDOFF_STATUS"
        echo "- detector-arsenal-output: \`$REGEX_HANDOFF_OUTPUT\`"
        echo "- detector-arsenal-manifest: \`$REGEX_HANDOFF_MANIFEST\`"
        echo "- detector-smoke-unit-tests-status: $DETECTOR_SMOKE_HANDOFF_STATUS"
        echo "- detector-smoke-unit-tests-log: \`$DETECTOR_SMOKE_HANDOFF_LOG\`"
        echo "- r37-tier-audit-status: $R37_HANDOFF_STATUS"
        if [ -n "$R37_HANDOFF_LOG" ]; then
            echo "- r37-tier-audit-log: \`$R37_HANDOFF_LOG\`"
        else
            echo "- r37-tier-audit-log: (none)"
        fi
        echo "- cross-lane-correlation-json: \`$json_out\`"
        echo "- cross-lane-correlation-markdown: \`$md_out\`"
        echo "- typed-candidate-promotion-json: \`$promo_json\`"
        echo "- typed-candidate-promotion-markdown: \`$promo_md\`"
        echo "- production-path-dossiers: \`$promo_dossier_dir\`"
        echo "- deep-candidate-adjudication-json: \`$LOG_DIR/deep_candidate_adjudication.json\`"
        echo "- adversarial-candidate-verify-json: \`$LOG_DIR/adversarial_candidate_verify.json\`"
        echo "- deep-counterexample-collection-manifest: \`$WORKSPACE/deep_counterexamples/collection_manifest.json\`"
        echo "- deep-counterexample-execution-queue: \`$WORKSPACE/deep_counterexamples/execution_queue.json\`"
        echo "- note: this section is the minimal artifact packet for hunter-side review before filing."
    } >> "$source_log"
}

run_deep_counterexample_collect() {
    # run_deep_counterexample_collect <source_run_log>
    #
    # V6 wiring slice: audit-deep already tells operators where fuzz/symbolic
    # runner manifests live; make that evidence durable by collecting
    # status=counterexample manifests into the common deep_counterexample.v1
    # schema every time. This is intentionally best-effort and advisory: without
    # a generated Forge replay path, records stay replay-impossible until an
    # agent wires a real replay and records proof with poc-execution-record.
    local source_log="$1"
    local collection_manifest="$WORKSPACE/deep_counterexamples/collection_manifest.json"

    {
        echo
        echo "## Deep counterexample collection"
        echo
    } >> "$source_log"

    if [ -f "$HERE/deep-counterexample-collect.py" ] && command -v python3 >/dev/null 2>&1; then
        if python3 "$HERE/deep-counterexample-collect.py" \
            --workspace "$WORKSPACE" \
            >>"$source_log" 2>&1; then
            {
                echo "- status: SUCCESS"
                echo "- manifest: \`$collection_manifest\`"
                echo "- note: advisory unless each record has a generated Forge replay and executed PoC manifest"
            } >> "$source_log"
        else
            echo "- status: SUCCESS_WARN deep-counterexample-collect failed (see log above)" >> "$source_log"
        fi
    else
        echo "- status: SKIPPED deep-counterexample-collect.py or python3 missing" >> "$source_log"
    fi
}

run_r37_audit() {
    # run_r37_audit <source_run_log>
    #
    # WF-4 Patch A: wire R37 (hackerman-record-tier-declared-at-emit) audit
    # into audit-deep. Cheap (<5s, stdlib-only Python) and prevents tier-
    # tagging silent drift between iterations. The R37 audit walks the
    # auditooor corpus's verification_tier compliance and reports
    # compliant / non_compliant / exempt counts.
    #
    # Default: warn-only. With AUDIT_DEEP_R37_STRICT=1 (or STRICT=1), the
    # underlying tool's --strict flag is set, which exits non-zero on
    # overall_status != PASS. The non-zero rc is recorded in failed[] but
    # never aborts the run - the run summary remains the operator's signal.
    local source_log="$1"
    local r37_tool="$HERE/wave2-rule-37-emit-time-tier-audit.py"
    local r37_strict="${AUDIT_DEEP_R37_STRICT:-${STRICT:-0}}"
    local r37_log="$LOG_DIR/r37_audit_${TS}.log"
    local r37_args=("$r37_tool" "--workspace" "$REPO_ROOT" "--json")
    R37_HANDOFF_LOG="$r37_log"

    if [ "$r37_strict" = "1" ]; then
        r37_args+=("--strict")
    fi

    {
        echo
        echo "## R37 verification-tier audit (WF-4 Patch A)"
        echo
    } >> "$source_log"

    if [ ! -f "$r37_tool" ]; then
        R37_HANDOFF_STATUS="skipped:tool-missing"
        {
            echo "- status: SKIPPED (tool missing: \`$r37_tool\`)"
            echo "- note: R37 audit relies on tools/wave2-rule-37-emit-time-tier-audit.py"
        } >> "$source_log"
        skipped+=("r37-verification-tier-audit (tool missing)")
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        R37_HANDOFF_STATUS="skipped:python3-missing"
        {
            echo "- status: SKIPPED (python3 missing)"
        } >> "$source_log"
        skipped+=("r37-verification-tier-audit (python3 missing)")
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        R37_HANDOFF_STATUS="skipped:dry-run"
        {
            echo "- status: SKIPPED (DRY_RUN=1)"
            echo "- planned-command: \`python3 ${r37_args[*]}\`"
        } >> "$source_log"
        skipped+=("r37-verification-tier-audit (DRY_RUN=1)")
        return 0
    fi

    local r37_json=""
    local r37_rc=0
    r37_json="$(python3 "${r37_args[@]}" 2>"$r37_log")"
    r37_rc=$?

    {
        echo "- raw-log: \`$r37_log\`"
        echo "- strict-mode: $r37_strict"
        echo "- rc: $r37_rc"
        if [ -n "$r37_json" ]; then
            python3 - <<PY 2>/dev/null || echo "- summary: (unparseable JSON; see raw-log)"
import json, sys
raw = """$(printf '%s' "$r37_json" | sed 's/"/\\"/g')"""
try:
    payload = json.loads(raw)
except Exception as exc:
    print(f"- summary: parse error ({exc})")
    sys.exit(0)
overall = payload.get("overall_status", "UNKNOWN")
compliant = payload.get("compliant_records", payload.get("compliant", "?"))
non_compliant = payload.get("non_compliant_records", payload.get("non_compliant", "?"))
exempt = payload.get("exempt_records", payload.get("exempt", "?"))
print(f"- overall-status: {overall}")
print(f"- compliant-records: {compliant}")
print(f"- non-compliant-records: {non_compliant}")
print(f"- exempt-records: {exempt}")
PY
        fi
    } >> "$source_log"

    if [ "$r37_rc" -eq 0 ]; then
        R37_HANDOFF_STATUS="success"
        ran+=("r37-verification-tier-audit")
        {
            echo "- status: SUCCESS"
        } >> "$source_log"
    else
        if [ "$r37_strict" = "1" ]; then
            R37_HANDOFF_STATUS="failed:strict-rc-$r37_rc"
            failed+=("r37-verification-tier-audit (rc=$r37_rc, strict)")
            {
                echo "- status: FAIL (strict-mode, rc=$r37_rc)"
                echo "- effect: failed[] arr records this entry; run summary visible"
            } >> "$source_log"
        else
            R37_HANDOFF_STATUS="warn:non-strict-rc-$r37_rc"
            ran+=("r37-verification-tier-audit (warn rc=$r37_rc)")
            {
                echo "- status: WARN (non-strict, rc=$r37_rc)"
                echo "- effect: advisory only; promote with AUDIT_DEEP_R37_STRICT=1 to fail-closed"
            } >> "$source_log"
        fi
    fi
}

run_routing_integrity_audit() {
    # run_routing_integrity_audit <source_run_log>
    #
    # CAP-routing-integrity-check wiring: B2 advisory-first routing-integrity
    # gate. Reads the SHARED hacker-question corpus
    # (audit/corpus_tags/derived/hacker_questions_library.jsonl, enriched
    # upstream by tools/lift28-enrich-corpora.py -> resolve_target_languages)
    # and asserts each record's target_languages contain the NATIVE language(s)
    # derived from its attack-class taxonomy anchor
    # (tools/lib/per_function_target_patterns.py:derive_native_target_languages).
    # Catches the trusted-enforcement-unsoundness where Go/Rust/Move/Cairo/ZK
    # classes were skewed to a Solidity shape and thus never fired on their
    # native surface when a worker lane filters by target_language.
    #
    # It emits audit/corpus_tags/derived/routing_integrity_report.json (schema
    # auditooor.routing_integrity_report.v1), which the routing-FIX consumer
    # (tools/lift28-enrich-corpora.py) + vault_hacker_questions per-language
    # routing read downstream. Running it here (repo-corpus advisory phase,
    # alongside the R37 tier audit) is DAG-correct: the enriched corpus already
    # exists, and the report is produced BEFORE the hunt-dispatch step consumes
    # the language-filtered library.
    #
    # Default: warn-only (the tool exits 0 even on mismatches). With
    # AUDIT_DEEP_ROUTING_STRICT=1 (or STRICT=1) the tool's --strict flag is set,
    # which exits non-zero on any mismatch; the non-zero rc is recorded in
    # failed[] but never aborts the run. Cheap (<5s, stdlib-only Python).
    local source_log="$1"
    local ri_tool="$HERE/routing-integrity-check.py"
    local ri_strict="${AUDIT_DEEP_ROUTING_STRICT:-${STRICT:-0}}"
    local ri_log="$LOG_DIR/routing_integrity_${TS}.log"
    local ri_args=("$ri_tool")

    if [ "$ri_strict" = "1" ]; then
        ri_args+=("--strict")
    fi

    {
        echo
        echo "## Routing-integrity corpus audit (CAP-routing-integrity-check)"
        echo
    } >> "$source_log"

    if [ ! -f "$ri_tool" ]; then
        {
            echo "- status: SKIPPED (tool missing: \`$ri_tool\`)"
            echo "- note: routing-integrity relies on tools/routing-integrity-check.py"
        } >> "$source_log"
        skipped+=("routing-integrity-audit (tool missing)")
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        {
            echo "- status: SKIPPED (python3 missing)"
        } >> "$source_log"
        skipped+=("routing-integrity-audit (python3 missing)")
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- status: SKIPPED (DRY_RUN=1)"
            echo "- planned-command: \`python3 ${ri_args[*]}\`"
        } >> "$source_log"
        skipped+=("routing-integrity-audit (DRY_RUN=1)")
        return 0
    fi

    local ri_json=""
    local ri_rc=0
    ri_json="$(python3 "${ri_args[@]}" 2>"$ri_log")"
    ri_rc=$?

    {
        echo "- raw-log: \`$ri_log\`"
        echo "- report: \`audit/corpus_tags/derived/routing_integrity_report.json\`"
        echo "- consumer: tools/lift28-enrich-corpora.py + vault_hacker_questions per-language routing"
        echo "- strict-mode: $ri_strict"
        echo "- rc: $ri_rc"
        if [ -n "$ri_json" ]; then
            python3 - <<PY 2>/dev/null || echo "- summary: (unparseable JSON; see raw-log)"
import json, sys
raw = """$(printf '%s' "$ri_json" | sed 's/"/\\"/g')"""
try:
    payload = json.loads(raw)
except Exception as exc:
    print(f"- summary: parse error ({exc})")
    sys.exit(0)
print(f"- verdict: {payload.get('verdict', 'UNKNOWN')}")
print(f"- records-checked: {payload.get('records_checked', '?')}")
print(f"- records-native-decidable: {payload.get('records_native_decidable', '?')}")
print(f"- mismatch-count: {payload.get('mismatch_count', '?')}")
PY
        fi
    } >> "$source_log"

    if [ "$ri_rc" -eq 0 ]; then
        ran+=("routing-integrity-audit")
        {
            echo "- status: SUCCESS"
        } >> "$source_log"
    else
        if [ "$ri_strict" = "1" ]; then
            failed+=("routing-integrity-audit (rc=$ri_rc, strict)")
            {
                echo "- status: FAIL (strict-mode, rc=$ri_rc)"
                echo "- effect: failed[] arr records this entry; run summary visible"
            } >> "$source_log"
        else
            ran+=("routing-integrity-audit (warn rc=$ri_rc)")
            {
                echo "- status: WARN (non-strict, rc=$ri_rc)"
                echo "- effect: advisory only; promote with AUDIT_DEEP_ROUTING_STRICT=1 to fail-closed"
            } >> "$source_log"
        fi
    fi
}

run_regex_detectors() {
    # run_regex_detectors <source_run_log>
    #
    # WF-4 Patch B: wire regex-detectors (wave17 1,525; rust_wave1 518;
    # go_wave1 14; etc.) into audit-deep. Without this, audit-deep fires
    # only the small DSL backend detectors (<5% of the 3,202 live arsenal).
    #
    # Output: <ws>/audit-deep-regex-detectors.txt (and the underlying
    # tool writes its own manifest at <ws>/.audit_logs/regex_detectors_manifest.json).
    # Time budget: 2-10 minutes wall-clock. Guarded by SKIP_REGEX=1 env var
    # for the fast-path callers who already ran regex-detectors separately.
    local source_log="$1"
    local out_txt="$REGEX_HANDOFF_OUTPUT"
    local runner="$HERE/../detectors/run_regex_detectors.py"

    {
        echo
        echo "## Regex detector arsenal (WF-4 Patch B)"
        echo
    } >> "$source_log"

    if [ "${SKIP_REGEX:-0}" = "1" ]; then
        REGEX_HANDOFF_STATUS="skipped:skip-regex"
        {
            echo "- status: SKIPPED (SKIP_REGEX=1)"
            echo "- note: regex detectors deliberately skipped by caller (env SKIP_REGEX=1)"
        } >> "$source_log"
        skipped+=("regex-detectors (SKIP_REGEX=1)")
        return 0
    fi
    if [ ! -f "$runner" ]; then
        REGEX_HANDOFF_STATUS="skipped:runner-missing"
        {
            echo "- status: SKIPPED (runner missing: \`$runner\`)"
        } >> "$source_log"
        skipped+=("regex-detectors (runner missing)")
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        REGEX_HANDOFF_STATUS="skipped:python3-missing"
        {
            echo "- status: SKIPPED (python3 missing)"
        } >> "$source_log"
        skipped+=("regex-detectors (python3 missing)")
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        REGEX_HANDOFF_STATUS="skipped:dry-run"
        {
            echo "- status: SKIPPED (DRY_RUN=1)"
            echo "- planned-command: \`python3 $runner '$WORKSPACE' --workspace '$WORKSPACE'\`"
        } >> "$source_log"
        skipped+=("regex-detectors (DRY_RUN=1)")
        return 0
    fi

    {
        echo "- output: \`$out_txt\`"
        echo "- runner: \`$runner\`"
        echo "- note: time budget ~2-10min wall-clock; guard with SKIP_REGEX=1 to short-circuit"
    } >> "$source_log"

    local rd_rc=0
    python3 "$runner" "$WORKSPACE" --workspace "$WORKSPACE" >"$out_txt" 2>&1 || rd_rc=$?

    if [ "$rd_rc" -eq 0 ]; then
        REGEX_HANDOFF_STATUS="success"
        ran+=("regex-detectors")
        {
            echo "- status: SUCCESS"
            echo "- stdout-tail:"
            echo '  ```'
            tail -20 "$out_txt" | sed 's/^/  /'
            echo '  ```'
        } >> "$source_log"
    else
        REGEX_HANDOFF_STATUS="warn:rc-$rd_rc"
        ran+=("regex-detectors (rc=$rd_rc)")
        {
            echo "- status: WARN (rc=$rd_rc; see output file)"
            echo "- stdout-tail:"
            echo '  ```'
            tail -20 "$out_txt" | sed 's/^/  /'
            echo '  ```'
        } >> "$source_log"
    fi
}

run_detector_smoke_unit_tests() {
    # run_detector_smoke_unit_tests <source_run_log>
    #
    # WF-4 Patch H: stitch the fast detector-smoke regression unit tests into
    # audit-deep so a hunt-prep report says whether the local detector runner
    # and inventory smoke harness are intact before the operator dispatches
    # workers. Default is advisory; STRICT=1 or
    # AUDIT_DEEP_DETECTOR_SMOKE_STRICT=1 promotes failure to final non-zero.
    local source_log="$1"
    local strict="${AUDIT_DEEP_DETECTOR_SMOKE_STRICT:-${STRICT:-0}}"
    local cmd="python3 -m unittest tools.tests.test_run_detector tools.tests.test_inventory_smoke_test -v"

    {
        echo
        echo "## Detector smoke unit tests (WF-4 Patch H)"
        echo
        echo "- log: \`$DETECTOR_SMOKE_HANDOFF_LOG\`"
        echo "- strict-mode: $strict"
    } >> "$source_log"

    if [ "${SKIP_DETECTOR_SMOKE:-0}" = "1" ]; then
        DETECTOR_SMOKE_HANDOFF_STATUS="skipped:skip-detector-smoke"
        {
            echo "- status: SKIPPED (SKIP_DETECTOR_SMOKE=1)"
        } >> "$source_log"
        skipped+=("detector-smoke-unit-tests (SKIP_DETECTOR_SMOKE=1)")
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        DETECTOR_SMOKE_HANDOFF_STATUS="skipped:python3-missing"
        {
            echo "- status: SKIPPED (python3 missing)"
        } >> "$source_log"
        skipped+=("detector-smoke-unit-tests (python3 missing)")
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        DETECTOR_SMOKE_HANDOFF_STATUS="skipped:dry-run"
        {
            echo "- status: SKIPPED (DRY_RUN=1)"
            echo "- planned-command: \`$cmd\`"
        } >> "$source_log"
        skipped+=("detector-smoke-unit-tests (DRY_RUN=1)")
        return 0
    fi

    local smoke_rc=0
    (cd "$REPO_ROOT" && $cmd) >"$DETECTOR_SMOKE_HANDOFF_LOG" 2>&1 || smoke_rc=$?
    {
        echo "- command: \`$cmd\`"
        echo "- rc: $smoke_rc"
        echo "- log-tail:"
        echo '  ```'
        tail -30 "$DETECTOR_SMOKE_HANDOFF_LOG" | sed 's/^/  /'
        echo '  ```'
    } >> "$source_log"

    if [ "$smoke_rc" -eq 0 ]; then
        DETECTOR_SMOKE_HANDOFF_STATUS="success"
        ran+=("detector-smoke-unit-tests")
        echo "- status: SUCCESS" >> "$source_log"
    else
        DETECTOR_SMOKE_HANDOFF_STATUS="failed:rc-$smoke_rc"
        failed+=("detector-smoke-unit-tests (rc=$smoke_rc)")
        {
            echo "- status: FAIL (rc=$smoke_rc)"
            echo "- effect: failed[] records this; strict mode exits non-zero after report publication"
        } >> "$source_log"
        if [ "$strict" = "1" ]; then
            DETECTOR_SMOKE_FAIL=1
        fi
    fi
}

emit_typed_candidate_promotion_banner() {
    # emit_typed_candidate_promotion_banner <source_run_log>
    #
    # WF-4 Patch E: surface the typed-candidate-promotion queue at the TOP
    # of the run report (just below the header) so the operator's first
    # screen-pass sees the hunt-prep signal. Reads
    # <ws>/.audit_logs/typed_candidate_promotions.json (emitted earlier by
    # run_cross_lane_correlate via promote-typed-candidate.py) and prepends
    # a banner section to the per-invocation report.
    #
    # Idempotent: prepends only once (looks for the banner marker before
    # inserting). Safe when the JSON is missing or empty (emits a
    # "no candidates" banner so an empty queue still shows visibly at top).
    local source_log="$1"
    local promo_json="$LOG_DIR/typed_candidate_promotions.json"
    local banner_marker="## TYPED CANDIDATE PROMOTION QUEUE (WF-4 Patch E)"

    if grep -qF "$banner_marker" "$source_log" 2>/dev/null; then
        return 0
    fi

    local count="0"
    local decision_summary="(no candidates promoted)"
    if [ -f "$promo_json" ] && command -v python3 >/dev/null 2>&1; then
        count="$(python3 - "$promo_json" <<'PY' 2>/dev/null || echo 0
import json, sys
try:
    payload = json.loads(open(sys.argv[1]).read())
    print(payload.get("candidate_count", 0))
except Exception:
    print(0)
PY
        )"
        decision_summary="$(python3 - "$promo_json" <<'PY' 2>/dev/null || echo '(unparseable)'
import json, sys
try:
    payload = json.loads(open(sys.argv[1]).read())
    dc = payload.get("decision_counts") or {}
    if not dc:
        print("(none)")
    else:
        parts = [f"{k}: {v}" for k, v in sorted(dc.items()) if v]
        print(", ".join(parts) if parts else "(all zero)")
except Exception as exc:
    print(f"(error: {exc})")
PY
        )"
    fi

    local banner_file
    banner_file="$(mktemp)"
    {
        echo
        echo "$banner_marker"
        echo
        if [ "$count" = "0" ] || [ -z "$count" ]; then
            echo "- candidate-count: 0"
            echo "- review: no typed candidates promoted this run; check 'Steps' below for skipped/blocked engines"
        else
            echo "- candidate-count: $count"
            echo "- review these $count candidates first (decisions: $decision_summary)"
            echo "- full queue markdown: \`$LOG_DIR/typed_candidate_promotions.md\`"
            echo "- full queue json: \`$promo_json\`"
        fi
        echo
        echo "_(See \`## Typed candidate promotion\` later in this report for the full queue table; this banner is the WF-4 Patch E top-of-report surface.)_"
        echo
    } > "$banner_file"

    # Prepend the banner just below the tool-availability table. We use
    # awk to insert after the FIRST blank line that follows the
    # "## Tool availability" section so the banner lands immediately
    # above "## MCP Memory Context Receipt" or "## Steps".
    local tmp_out
    tmp_out="$(mktemp)"
    awk -v inject="$banner_file" '
        BEGIN { injected = 0; in_tool = 0; saw_blank_after = 0 }
        /^## Tool availability/ { in_tool = 1 }
        {
            print
            if (in_tool == 1 && /^\| slither \|/) {
                in_tool = 2  # next blank line is our trigger
                next
            }
            if (in_tool == 2 && /^$/ && injected == 0) {
                while ((getline line < inject) > 0) print line
                close(inject)
                injected = 1
                in_tool = 0
            }
        }
        END {
            if (injected == 0) {
                while ((getline line < inject) > 0) print line
                close(inject)
            }
        }
    ' "$source_log" > "$tmp_out"

    mv "$tmp_out" "$source_log"
    rm -f "$banner_file"
}

run_deep_counterexample_queue() {
    # run_deep_counterexample_queue <source_run_log>
    #
    # After collection, immediately turn normalized records into a
    # model-routed execution queue. This is still advisory, but it prevents the
    # operator handoff from stopping at raw JSON.
    local source_log="$1"
    local queue_json="$WORKSPACE/deep_counterexamples/execution_queue.json"
    local queue_md="$WORKSPACE/deep_counterexamples/execution_queue.md"

    {
        echo
        echo "## Deep counterexample execution queue"
        echo
    } >> "$source_log"

    if [ -f "$HERE/deep-counterexample-queue.py" ] && command -v python3 >/dev/null 2>&1; then
        if python3 "$HERE/deep-counterexample-queue.py" \
            --workspace "$WORKSPACE" \
            >>"$source_log" 2>&1; then
            {
                echo "- status: SUCCESS"
                echo "- json: \`$queue_json\`"
                echo "- markdown: \`$queue_md\`"
                echo "- note: queue rows are model-routed work items, not proof"
            } >> "$source_log"
        else
            echo "- status: SUCCESS_WARN deep-counterexample-queue failed (see log above)" >> "$source_log"
        fi
    else
        echo "- status: SKIPPED deep-counterexample-queue.py or python3 missing" >> "$source_log"
    fi
}

# ---------------------------------------------------------------------------
# Handoff-oriented aggregate profile.
#
# `--profile all` intentionally reuses the existing profile handlers as child
# processes instead of duplicating their logic here. This keeps the aggregate
# mode low-risk: default/math/econ/crypto remain independently testable, while
# the all-profile adds only ordering, budget accounting, and a bounded
# Kimi/Minimax manifest.
#
# Budget guard:
#   AUDIT_DEEP_ALL_MAX_SECONDS=<seconds> (default 1800, 0 disables)
#
# The guard is checked before starting each profile. It does not attempt to
# SIGKILL an already-running child because the individual profiles already use
# bounded/dry-run wrappers where needed (e.g. slither-resilient --timeout 120).
# ---------------------------------------------------------------------------
all_deep_audit() {
    local profiles max_seconds started_at all_report manifest tsv
    profiles="${AUDIT_DEEP_ALL_PROFILES:-default math econ crypto}"
    # audit-run-full completion paths rely on a current-run deep manifest.
    # If the all-profile budget cap fires, skipped_budget rows can make the
    # generic manifest block deep-freshness even when Solidity engines passed.
    # For run-bound executions, default to unlimited unless the operator
    # explicitly sets AUDIT_DEEP_ALL_MAX_SECONDS.
    if [ -n "${AUDITOOOR_AUDIT_RUN_FULL_ID:-}" ] && [ -z "${AUDIT_DEEP_ALL_MAX_SECONDS:-}" ]; then
        max_seconds="0"
    else
        max_seconds="${AUDIT_DEEP_ALL_MAX_SECONDS:-1800}"
    fi
    started_at="$(date -u +%s)"
    all_report="$LOG_DIR/audit_deep_all_report.md"
    manifest="$LOG_DIR/audit_deep_all_manifest.json"
    tsv="$LOG_DIR/audit_deep_all_${TS}.tsv"
    : > "$tsv"

    {
        echo "# audit-deep all-profile report"
        echo
        echo "- workspace: \`$WORKSPACE\`"
        echo "- timestamp (UTC): $TS"
        echo "- profile: all"
        echo "- dry-run: $DRY_RUN"
        if [ -n "$PROJECT_ROOT_OVERRIDE" ]; then
            echo "- project-root: \`$PROJECT_ROOT_OVERRIDE\`"
        fi
        echo "- budget seconds: $max_seconds"
        echo "- child profiles: \`$profiles\`"
        echo "- tier: B (advisory / handoff packet)"
        echo
        echo "## Guardrails"
        echo
        echo "- This is an opt-in deep sweep, not part of \`make audit\` or \`engage.py --stage all\`."
        echo "- Child reports are advisory mining input; they are not submission proof."
        echo "- Kimi/Minimax should review the manifest packet, not the whole repository."
        echo "- Any candidate still needs source-line verification, production-path proof, and a PoC or equivalent proof before filing."
        echo
        echo "## Child profile runs"
        echo
    } > "$all_report"

    local profile now elapsed status rc child_log child_report
    for profile in $profiles; do
        now="$(date -u +%s)"
        elapsed=$((now - started_at))
        child_log="$LOG_DIR/audit_deep_all_${TS}_${profile}.log"
        child_report="$LOG_DIR/audit_deep_all_${TS}_${profile}_report.md"

        if [ "$max_seconds" != "0" ] && [ "$elapsed" -ge "$max_seconds" ]; then
            status="skipped_budget"
            rc=0
            {
                echo "### $profile"
                echo
                echo "- status: $status"
                echo "- elapsed before start: ${elapsed}s"
                echo "- reason: budget exhausted before starting profile"
                echo
            } >> "$all_report"
            printf '%s\t%s\t%s\t%s\t%s\n' "$profile" "$status" "$rc" "" "" >> "$tsv"
            continue
        fi

        {
            echo "### $profile"
            echo
            echo "- started after: ${elapsed}s"
            echo "- stdout/stderr log: \`$child_log\`"
        } >> "$all_report"

        AUDIT_DEEP_DRY_RUN="$DRY_RUN" FOUNDRY_PROJECT_ROOT="$PROJECT_ROOT_OVERRIDE" \
            bash "$0" --profile "$profile" "$WORKSPACE" >"$child_log" 2>&1
        rc=$?
        if [ "$rc" -eq 0 ]; then
            status="success"
        else
            status="failed"
        fi

        if [ -f "$REPORT" ]; then
            cp "$REPORT" "$child_report"
        else
            child_report=""
        fi

        {
            echo "- status: $status"
            echo "- exit code: $rc"
            if [ -n "$child_report" ]; then
                echo "- captured report: \`$child_report\`"
            else
                echo "- captured report: (missing)"
            fi
            echo
        } >> "$all_report"
        printf '%s\t%s\t%s\t%s\t%s\n' "$profile" "$status" "$rc" "$child_log" "$child_report" >> "$tsv"
    done

    {
        echo "## Kimi/Minimax handoff"
        echo
        echo "Send this bounded packet instead of the whole repository:"
        echo
        echo "- manifest JSON: \`$manifest\`"
        echo "- all-profile report: \`$all_report\`"
        echo "- child profile logs/reports listed in the manifest"
        echo "- deep counterexample collection manifest, if any:"
        echo "  \`$WORKSPACE/deep_counterexamples/collection_manifest.json\`"
        echo "- deep counterexample execution queue, if any:"
        echo "  \`$WORKSPACE/deep_counterexamples/execution_queue.json\`"
        echo "- exact engagement scope/OOS text"
        echo "- minimal source snippets for candidates the LLM is asked to judge"
        echo
        echo "Prompt contract: ask for in-scope production paths, exact source citations,"
        echo "OOS clause clearance, and the PoC assertion needed to prove each candidate."
        echo "Any mock/admin/project-inaction/missing-production-path candidate must be"
        echo "marked \`UNSAFE_TO_SUBMIT\`."
    } >> "$all_report"

    run_deep_counterexample_collect "$all_report"
    run_deep_counterexample_queue "$all_report"

    if command -v python3 >/dev/null 2>&1; then
        AUDIT_DEEP_ALL_TSV="$tsv" \
        AUDIT_DEEP_ALL_MANIFEST="$manifest" \
        AUDIT_DEEP_ALL_WORKSPACE="$WORKSPACE" \
        AUDIT_DEEP_ALL_TIMESTAMP="$TS" \
        AUDIT_DEEP_ALL_DRY_RUN="$DRY_RUN" \
        AUDIT_DEEP_ALL_BUDGET="$max_seconds" \
        AUDIT_DEEP_ALL_EXPECTED_PROFILES="$profiles" \
        AUDIT_DEEP_ALL_RUN_ID="${AUDITOOOR_AUDIT_RUN_FULL_ID:-}" \
        AUDIT_DEEP_ALL_REPORT="$all_report" \
        AUDIT_DEEP_ALL_DEEP_CE_MANIFEST="$WORKSPACE/deep_counterexamples/collection_manifest.json" \
        AUDIT_DEEP_ALL_DEEP_CE_QUEUE="$WORKSPACE/deep_counterexamples/execution_queue.json" \
        python3 - <<'PY'
import json
import os
from pathlib import Path

rows = []
tsv = Path(os.environ["AUDIT_DEEP_ALL_TSV"])
if tsv.exists():
    for line in tsv.read_text().splitlines():
        profile, status, rc, log, report = (line.split("\t") + ["", "", "", "", ""])[:5]
        rows.append(
            {
                "profile": profile,
                "status": status,
                "exit_code": int(rc or 0),
                "log": log or None,
                "captured_report": report or None,
            }
        )
expected_profiles = [
    item for item in os.environ.get("AUDIT_DEEP_ALL_EXPECTED_PROFILES", "").split()
    if item
]

payload = {
    "schema": "auditooor.audit_deep_all.v1",
    "workspace": os.environ["AUDIT_DEEP_ALL_WORKSPACE"],
    "run_id": os.environ.get("AUDIT_DEEP_ALL_RUN_ID") or None,
    "timestamp_utc": os.environ["AUDIT_DEEP_ALL_TIMESTAMP"],
    "dry_run": os.environ["AUDIT_DEEP_ALL_DRY_RUN"] == "1",
    "budget_seconds": int(os.environ["AUDIT_DEEP_ALL_BUDGET"]),
    "expected_profiles": expected_profiles,
    "report": os.environ["AUDIT_DEEP_ALL_REPORT"],
    "typed_candidate_promotion": str(
        Path(os.environ["AUDIT_DEEP_ALL_WORKSPACE"])
        / ".audit_logs"
        / "typed_candidate_promotions.json"
    ),
    "cross_lane_correlations": str(
        Path(os.environ["AUDIT_DEEP_ALL_WORKSPACE"])
        / ".audit_logs"
        / "cross_lane_correlations.json"
    ),
    "deep_counterexample_collection": os.environ["AUDIT_DEEP_ALL_DEEP_CE_MANIFEST"],
    "deep_counterexample_queue": os.environ["AUDIT_DEEP_ALL_DEEP_CE_QUEUE"],
    "profiles": rows,
    "llm_handoff_guardrails": [
        "Tier-B advisory only; not proof or a submission gate.",
        "Review bounded artifacts, not the whole repository.",
        "Require exact source citations, non-privileged production path, OOS clearance, and PoC assertion.",
        "Mark mock/admin/project-inaction/missing-production-path candidates UNSAFE_TO_SUBMIT.",
    ],
}
Path(os.environ["AUDIT_DEEP_ALL_MANIFEST"]).write_text(json.dumps(payload, indent=2) + "\n")
PY
    else
        echo "- manifest JSON skipped: python3 not on PATH" >> "$all_report"
    fi

    # V5-P0-11 / Gap 21: per-profile + canonical symlink. Each child
    # profile already wrote its own per-profile report, and child captured
    # reports live under audit_deep_all_${TS}_<profile>_report.md. The
    # canonical symlink now points at the all-profile aggregate so an
    # operator running DEEP_PROFILE=all sees the aggregate first.
    publish_profile_report "all" "$all_report"

    echo "[audit-deep] OK profile=all report=$REPORT"
    echo "[audit-deep]    per-profile: $LOG_DIR/audit_deep_all_${TS}.md"
    echo "[audit-deep]    all-report: $all_report"
    if [ -f "$manifest" ]; then
        echo "[audit-deep]    manifest: $manifest"
    fi
    return 0
}

if [ "$PROFILE" = "all" ]; then
    all_deep_audit
    exit $?
fi

# ---------------------------------------------------------------------------
# V4 P4 - econ profile handler.
#
# When DEEP_PROFILE=econ (or --profile econ), we skip the halmos/medusa
# default chain and instead call tools/econ-actor-modeler.py against the
# workspace's economic_hypotheses/*.md (output of engage stage 16). The
# modeler emits ACTORS.md / STATE_MACHINE.md / econ_deep_report.md as
# WORKSPACE-LOCAL artifacts under .audit_logs/, plus matching JSON.
#
# Tier discipline:
#   - Tier B / advisory.
#   - Report explicitly distinguishes "economic plausibility" (always
#     declarable) from "exploit proven" (needs PoC + concrete params).
#   - DO NOT cite the report as exploit evidence in a submission; it is
#     scoping / threat-model context only. Per V4 §5.4 + the engagement
#     Tier-B convention.
#
# Always exit 0 (graceful), even when the hypotheses file is missing - the
# modeler emits a "INDETERMINATE - run economic-hypotheses.sh first" report
# in that case so the operator gets actionable guidance.
# ---------------------------------------------------------------------------
econ_deep_audit() {
    local hypos_dir hypos_file shape
    hypos_dir="$WORKSPACE/economic_hypotheses"
    local actors_md="$LOG_DIR/ACTORS.md"
    local sm_md="$LOG_DIR/STATE_MACHINE.md"
    local actors_json="$LOG_DIR/actors.json"
    local sm_json="$LOG_DIR/state_machine.json"
    local report_file="$LOG_DIR/econ_deep_report.md"
    local econ_fuzz_dir="$WORKSPACE/economic_fuzz"
    local econ_fuzz_manifest="$LOG_DIR/econ_fuzzer_scaffold.json"
    local run_log="$LOG_DIR/audit_deep_econ_${TS}.md"
    local canonical_report="$LOG_DIR/audit_deep_report.md"

    # V5-P0-10 / Gap 20: accept three input shapes for hypotheses.
    #
    #   1. <ws>/economic_hypotheses/*.md   - directory + glob (canonical)
    #   2. <ws>/economic_hypotheses.md     - singular file (older skill output)
    #   3. (nothing)                       - missing input; modeler emits
    #                                         INDETERMINATE report.
    #
    # We try each shape in order; the first that matches wins. We never
    # error on missing input - the modeler handles that gracefully.
    shape="missing"
    if [ -d "$hypos_dir" ]; then
        hypos_file="$(find "$hypos_dir" -maxdepth 1 -name '*.md' -print 2>/dev/null | sort | head -n 1 || true)"
        if [ -n "${hypos_file:-}" ]; then
            shape="directory"
        fi
    fi
    if [ -z "${hypos_file:-}" ] && [ -f "$WORKSPACE/economic_hypotheses.md" ]; then
        hypos_file="$WORKSPACE/economic_hypotheses.md"
        shape="singular_file"
    fi
    if [ -z "${hypos_file:-}" ]; then
        hypos_file="$hypos_dir/_missing.md"
        shape="missing"
        echo "[audit-deep] WARN econ profile: no hypotheses input found at \`$hypos_dir/*.md\` or \`$WORKSPACE/economic_hypotheses.md\` - modeler will emit INDETERMINATE report" >&2
    fi

    {
        echo "# audit-deep econ-profile report"
        echo
        echo "- workspace: \`$WORKSPACE\`"
        echo "- timestamp (UTC): $TS"
        echo "- profile: econ (V4 P4)"
        echo "- dry-run: $DRY_RUN"
        echo "- hypotheses input: \`$hypos_file\`"
        echo "- input shape: $shape (V5-P0-10 / Gap 20)"
        echo "- tier: B (advisory)"
        echo
    } > "$run_log"

    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "## Steps (dry-run)"
            echo
            echo "- planned: \`python3 tools/econ-actor-modeler.py --hypos \"$hypos_file\" \\"
            echo "    --actors-md \"$actors_md\" --actors-json \"$actors_json\" \\"
            echo "    --sm-md \"$sm_md\" --sm-json \"$sm_json\" --report \"$report_file\"\`"
            echo "- planned: \`python3 tools/econ-fuzzer-scaffold.py --workspace \"$WORKSPACE\" \\"
            echo "    --hypos \"$hypos_file\" --out-dir \"$econ_fuzz_dir\" --manifest \"$econ_fuzz_manifest\"\`"
            echo "- skipped (DRY_RUN=1)"
            echo
            echo "## Summary"
            echo
            echo "- ran: (none, dry-run)"
            echo "- skipped: econ-actor-modeler, econ-fuzzer-scaffold (DRY_RUN=1)"
        } >> "$run_log"
    else
        {
            echo "## Steps"
            echo
            echo "- ran: \`python3 tools/econ-actor-modeler.py\` against \`$hypos_file\`"
        } >> "$run_log"
        if command -v python3 >/dev/null 2>&1; then
            python3 "$HERE/econ-actor-modeler.py" \
                --hypos "$hypos_file" \
                --actors-md "$actors_md" \
                --actors-json "$actors_json" \
                --sm-md "$sm_md" \
                --sm-json "$sm_json" \
                --report "$report_file" \
                >>"$run_log" 2>&1 || echo "  (econ-actor-modeler exit $?)" >> "$run_log"
            python3 "$HERE/econ-fuzzer-scaffold.py" \
                --workspace "$WORKSPACE" \
                --hypos "$hypos_file" \
                --out-dir "$econ_fuzz_dir" \
                --manifest "$econ_fuzz_manifest" \
                >>"$run_log" 2>&1 || echo "  (econ-fuzzer-scaffold exit $?)" >> "$run_log"
        else
            echo "- skipped: python3 not on PATH" >> "$run_log"
        fi
        {
            echo
            echo "## Outputs"
            echo
            echo "- ACTORS.md: \`$actors_md\`"
            echo "- actors.json: \`$actors_json\`"
            echo "- STATE_MACHINE.md: \`$sm_md\`"
            echo "- state_machine.json: \`$sm_json\`"
            echo "- econ_deep_report.md (advisory): \`$report_file\`"
            echo "- EconomicInvariantFuzz.t.sol: \`$econ_fuzz_dir/EconomicInvariantFuzz.t.sol\`"
            echo "- medusa_econ_fuzz.json: \`$econ_fuzz_dir/medusa_econ_fuzz.json\`"
            echo "- econ_fuzzer_scaffold.json: \`$econ_fuzz_manifest\`"
            echo
            echo "## Tier discipline"
            echo
            echo "- Tier: **B (advisory)**"
            echo "- This profile distinguishes \"economic plausibility\" (always declarable)"
            echo "  from \"exploit proven\" (requires PoC + concrete parameters)."
            echo "- The generated fuzz harness is runnable scaffold, not exploit proof until"
            echo "  the placeholder assertions are replaced with concrete protocol invariants."
            echo "- DO NOT cite \`econ_deep_report.md\` or the generated scaffold as exploit evidence in a submission body."
            echo "- See \`docs/STAGE_REFERENCE.md\` and \`docs/ENGAGE.md\` for invocation context."
        } >> "$run_log"
    fi

    # V5-P0-11 / Gap 21: per-profile report + canonical symlink.
    publish_profile_report "econ" "$run_log"

    echo "[audit-deep] OK profile=econ report=$canonical_report"
    echo "[audit-deep]    per-profile: $LOG_DIR/audit_deep_econ_${TS}.md"
    echo "[audit-deep]    artifacts: ACTORS.md, STATE_MACHINE.md, econ_deep_report.md (under $LOG_DIR), EconomicInvariantFuzz.t.sol (under $econ_fuzz_dir)"
    return 0
}

if [ "$PROFILE" = "econ" ]; then
    econ_deep_audit
    exit $?
fi

# ---------------------------------------------------------------------------
# V4 P2 - math profile handler.
#
# When --profile math (or DEEP_PROFILE=math), we skip the halmos/medusa
# default chain and instead call tools/math-invariant-miner.py against the
# workspace's Solidity sources. The miner is stdlib-only Python (no new
# dependency), and emits:
#   <ws>/math_invariants/MATH_SPEC.md
#   <ws>/math_invariants/math_spec.json
# plus a canonical run report at <ws>/.audit_logs/audit_deep_report.md.
#
# Tier discipline:
#   - Tier B / advisory.
#   - The conservation laws + monotonicity hints + flagged one-sided
#     mutations are CANDIDATES - they need analyst review before being
#     filed as findings. Per V4 §2 Workstream B.
#   - DO NOT cite MATH_SPEC.md as exploit evidence in a submission body
#     without an accompanying PoC.
#
# Always exit 0 (graceful), even when the workspace has no .sol files -
# the miner emits an empty-contracts report in that case.
# ---------------------------------------------------------------------------
math_deep_audit() {
    local math_out="$WORKSPACE/math_invariants"
    local report_md="$math_out/MATH_SPEC.md"
    local report_json="$math_out/math_spec.json"
    local run_log="$LOG_DIR/audit_deep_math_${TS}.md"
    local canonical_report="$LOG_DIR/audit_deep_report.md"
    local cmd="python3 $HERE/math-invariant-miner.py --workspace \"$WORKSPACE\" --output-dir \"$math_out\""

    {
        echo "# audit-deep math-profile report"
        echo
        echo "- workspace: \`$WORKSPACE\`"
        echo "- timestamp (UTC): $TS"
        echo "- profile: math (V4 P2)"
        echo "- dry-run: $DRY_RUN"
        echo "- tier: B (advisory)"
        echo
        echo "## Step 5 - DEEP_PROFILE=math math-invariant mining"
        echo
    } > "$run_log"

    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
            echo
            echo "## Summary"
            echo
            echo "- ran: (none, dry-run)"
            echo "- skipped: math-invariant-miner (DRY_RUN=1)"
        } >> "$run_log"
    elif command -v python3 >/dev/null 2>&1; then
        {
            echo "- ran: \`$cmd\`"
        } >> "$run_log"
        mkdir -p "$math_out"
        python3 "$HERE/math-invariant-miner.py" \
            --workspace "$WORKSPACE" \
            --output-dir "$math_out" \
            >>"$run_log" 2>&1 || echo "  (math-invariant-miner exit $?)" >> "$run_log"
        if [ -f "$report_md" ] && [ -f "$report_json" ]; then
            {
                echo
                echo "## Outputs"
                echo
                echo "- MATH_SPEC.md: \`$report_md\`"
                echo "- math_spec.json: \`$report_json\`"
                echo
                echo "## Tier discipline"
                echo
                echo "- Tier: **B (advisory)**"
                echo "- See \`docs/ROADMAP_10_OF_10_V4.md\` §2 Workstream B for invocation context."
                echo "- DO NOT cite \`MATH_SPEC.md\` as exploit evidence in a submission body."
            } >> "$run_log"
        else
            {
                echo "- WARN: expected MATH_SPEC artifacts not produced"
            } >> "$run_log"
        fi
    else
        {
            echo "- skipped: python3 not on PATH"
        } >> "$run_log"
    fi

    # V5-P0-11 / Gap 21: per-profile report + canonical symlink.
    publish_profile_report "math" "$run_log"

    echo "[audit-deep] OK profile=math report=$canonical_report"
    echo "[audit-deep]    per-profile: $LOG_DIR/audit_deep_math_${TS}.md"
    if [ -f "$report_md" ]; then
        echo "[audit-deep]    artifacts: MATH_SPEC.md, math_spec.json (under $math_out)"
    fi
    return 0
}

if [ "$PROFILE" = "math" ]; then
    math_deep_audit
    exit $?
fi

# ---------------------------------------------------------------------------
# V4 P3 - crypto profile handler.
#
# Workstream C: verifier / proof-system review. Per
# docs/ROADMAP_10_OF_10_V4.md Section 2 C and Section 4 P3, this profile:
#   1. detects verifier-shaped contracts under the workspace,
#   2. emits a JSON work packet for downstream Kimi/Minimax LLM dispatch,
#   3. emits <ws>/.audit_logs/crypto_deep_report.md based on
#      templates/crypto_verifier_review.md.
# It is opt-in (only fires when --profile crypto / DEEP_PROFILE=crypto),
# Tier-B (NEVER part of the default `make audit` chain), and never fails
# the deep run on its own.
#
# Tier discipline:
#   - Tier B / advisory.
#   - Sections classified as DEFENSE_IN_DEPTH_ONLY when verifier markers
#     (Plonk/Groth/Risc0/SP1/Aggregate/Snark) are present; OPEN otherwise.
#   - DO NOT cite the report as exploit evidence in a submission body; it
#     is scoping / threat-model context only. Per V4 §5.4 + Tier-B.
# ---------------------------------------------------------------------------
crypto_deep_audit() {
    local scan_root packet template crypto_report run_log canonical_report
    scan_root="$WORKSPACE"
    if [ -d "$WORKSPACE/contracts" ]; then
        scan_root="$WORKSPACE/contracts"
    fi
    packet="$LOG_DIR/crypto_work_packet.json"
    crypto_report="$LOG_DIR/crypto_deep_report.md"
    template="$HERE/../templates/crypto_verifier_review.md"
    run_log="$LOG_DIR/audit_deep_crypto_${TS}.md"
    canonical_report="$LOG_DIR/audit_deep_report.md"

    {
        echo "# audit-deep crypto-profile report"
        echo
        echo "- workspace: \`$WORKSPACE\`"
        echo "- timestamp (UTC): $TS"
        echo "- profile: crypto (V4 P3)"
        echo "- dry-run: $DRY_RUN"
        echo "- scan root: \`$scan_root\`"
        echo "- template: \`$template\`"
        echo "- tier: B (advisory)"
        echo
    } > "$run_log"

    local cmd
    # V5-P0-09 / Gap 19: pass --workspace so the runner can preflight the
    # in-scope verifier surface and auto-skip on non-verifier protocols.
    cmd="python3 $HERE/crypto-deep-runner.py --workspace \"$WORKSPACE\" --root \"$scan_root\" --template \"$template\" --packet-out \"$packet\" --report-out \"$crypto_report\""

    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "## Steps (dry-run)"
            echo
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
            echo
            echo "## Summary"
            echo
            echo "- ran: (none, dry-run)"
            echo "- skipped: crypto-deep-runner (DRY_RUN=1)"
        } >> "$run_log"
    else
        {
            echo "## Steps"
            echo
        } >> "$run_log"
        if [ ! -f "$template" ]; then
            {
                echo "- skipped: template not found at \`$template\`"
                echo
                echo "## Summary"
                echo
                echo "- ran: (none)"
                echo "- skipped: crypto-deep-runner (no template)"
            } >> "$run_log"
        elif command -v python3 >/dev/null 2>&1; then
            {
                echo "- ran: \`$cmd\`"
            } >> "$run_log"
            python3 "$HERE/crypto-deep-runner.py" \
                --workspace "$WORKSPACE" \
                --root "$scan_root" \
                --template "$template" \
                --packet-out "$packet" \
                --report-out "$crypto_report" \
                >>"$run_log" 2>&1 || echo "  (crypto-deep-runner exit $?)" >> "$run_log"
            {
                echo
                echo "## Outputs"
                echo
                echo "- crypto work packet (JSON): \`$packet\`"
                echo "- crypto_deep_report.md (advisory): \`$crypto_report\`"
                echo
                echo "## Tier discipline"
                echo
                echo "- Tier: **B (advisory)**"
                echo "- Sections without verifier markers (Plonk/Groth/Risc0/SP1/Aggregate/Snark)"
                echo "  are classified as OPEN; sections WITH markers are DEFENSE_IN_DEPTH_ONLY."
                echo "- DO NOT cite \`crypto_deep_report.md\` as exploit evidence in a submission body."
                echo "- See \`docs/STAGE_REFERENCE.md\` and \`docs/ENGAGE.md\` for invocation context."
            } >> "$run_log"
        else
            echo "- skipped: python3 not on PATH" >> "$run_log"
        fi
    fi

    # V5-P0-11 / Gap 21: per-profile report + canonical symlink.
    publish_profile_report "crypto" "$run_log"

    echo "[audit-deep] OK profile=crypto report=$canonical_report"
    echo "[audit-deep]    per-profile: $LOG_DIR/audit_deep_crypto_${TS}.md"
    echo "[audit-deep]    artifacts: crypto_work_packet.json, crypto_deep_report.md (under $LOG_DIR)"
    return 0
}

if [ "$PROFILE" = "crypto" ]; then
    crypto_deep_audit
    exit $?
fi

# ---------------------------------------------------------------------------
# V5 Gap-46 / Codex P0 #3 - coverage-gaps profile handler.
#
# When --profile coverage-gaps (or DEEP_PROFILE=coverage-gaps), we skip the
# halmos/medusa/etc default chain and instead call
# tools/coverage-introspect.py against the workspace's Solidity sources.
# The introspector is stdlib-only Python (no new dependency) and emits:
#
#   <ws>/coverage_surface.json
#   <ws>/coverage_by_category.json
#   <ws>/coverage_gaps_kimi.md
#   <ws>/coverage_gaps_minimax.md
#   <ws>/coverage_gaps_ranked.md
#   <ws>/.audit_logs/coverage_introspect_manifest.json
#
# plus a canonical run report at <ws>/.audit_logs/audit_deep_report.md.
#
# Tier discipline:
#   - Tier B / advisory.
#   - Survivors are CANDIDATE bug-class shapes; production-path proof + PoC
#     required before filing. The phase-4 Claude-side M14-trap re-greps
#     reference/patterns.dsl/ to catch any covering pattern Minimax missed.
#   - **Opt-in only**. NEVER appended to `all_deep_audit`'s profile chain
#     until 3-5 real-workspace runs prove signal quality (Codex PR #253
#     final-pass comment).
#   - The LLM pass is hard-bounded to 30 calls per run (the script enforces
#     it); AUDITOOOR_LLM_BUDGET_GUARD=1 is set in the child env so the
#     dispatcher's accounting also fires.
#
# Always exit 0 (graceful), even when the workspace has no .sol files -
# the introspector emits a zero-category surface JSON in that case.
# ---------------------------------------------------------------------------
coverage_gaps_audit() {
    local run_log canonical_report cmd
    run_log="$LOG_DIR/audit_deep_coverage_gaps_${TS}.md"
    canonical_report="$LOG_DIR/audit_deep_report.md"
    cmd="python3 $HERE/coverage-introspect.py \"$WORKSPACE\""

    {
        echo "# audit-deep coverage-gaps profile report"
        echo
        echo "- workspace: \`$WORKSPACE\`"
        echo "- timestamp (UTC): $TS"
        echo "- profile: coverage-gaps (V5 Gap-46 / Codex P0 #3)"
        echo "- dry-run: $DRY_RUN"
        echo "- tier: B (advisory)"
        echo "- opt-in: never part of \`DEEP_PROFILE=all\` until proven on 3-5 real workspaces"
        echo
    } > "$run_log"

    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "## Steps (dry-run)"
            echo
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
            echo
            echo "## Summary"
            echo
            echo "- ran: (none, dry-run)"
            echo "- skipped: coverage-introspect (DRY_RUN=1)"
        } >> "$run_log"
    elif command -v python3 >/dev/null 2>&1; then
        {
            echo "## Steps"
            echo
            echo "- ran: \`$cmd\`"
        } >> "$run_log"
        AUDITOOOR_LLM_BUDGET_GUARD=1 \
        python3 "$HERE/coverage-introspect.py" \
            "$WORKSPACE" \
            >>"$run_log" 2>&1 || echo "  (coverage-introspect exit $?)" >> "$run_log"
        {
            echo
            echo "## Outputs"
            echo
            echo "- coverage_surface.json: \`$WORKSPACE/coverage_surface.json\`"
            echo "- coverage_by_category.json: \`$WORKSPACE/coverage_by_category.json\`"
            echo "- coverage_gaps_kimi.md: \`$WORKSPACE/coverage_gaps_kimi.md\`"
            echo "- coverage_gaps_minimax.md: \`$WORKSPACE/coverage_gaps_minimax.md\`"
            echo "- coverage_gaps_ranked.md (advisory): \`$WORKSPACE/coverage_gaps_ranked.md\`"
            echo "- manifest: \`$LOG_DIR/coverage_introspect_manifest.json\`"
            echo
            echo "## Tier discipline"
            echo
            echo "- Tier: **B (advisory)**"
            echo "- Survivors are CANDIDATE bug-class shapes; PoC + production-path required before filing."
            echo "- See \`docs/V5_CAPABILITY_GAPS_2026-04-26.md\` Gap 46 for invocation context."
        } >> "$run_log"
    else
        echo "- skipped: python3 not on PATH" >> "$run_log"
    fi

    # V5-P0-11 / Gap 21: per-profile report + canonical symlink.
    publish_profile_report "coverage_gaps" "$run_log"

    echo "[audit-deep] OK profile=coverage-gaps report=$canonical_report"
    echo "[audit-deep]    per-profile: $LOG_DIR/audit_deep_coverage_gaps_${TS}.md"
    if [ -f "$WORKSPACE/coverage_gaps_ranked.md" ]; then
        echo "[audit-deep]    artifacts: coverage_surface.json, coverage_by_category.json, coverage_gaps_*.md (under $WORKSPACE)"
    fi
    return 0
}

if [ "$PROFILE" = "coverage-gaps" ]; then
    coverage_gaps_audit
    exit $?
fi

# Per-invocation log file so successive runs don't clobber each other's
# report. The latest run's path is also kept at the canonical filename
# above for easy `make audit-deep && cat $WS/.audit_logs/audit_deep_report.md`.
RUN_LOG="$LOG_DIR/audit_deep_${TS}.md"

write_mcp_memory_receipt_section() {
    local receipt="$WORKSPACE/.auditooor/memory_context_receipt.json"
    local tmp="$LOG_DIR/memory_context_receipt_check_${TS}.json"
    local rc=0

    {
        echo "## MCP Memory Context Receipt"
        echo
        if [ ! -f "$receipt" ]; then
            echo "- status: missing"
            echo "- receipt_path: \`$receipt\`"
            echo "- note: no memory receipt exists for this workspace; audit-deep continues."
            echo
            return 0
        fi
        echo "- receipt_path: \`$receipt\`"
    } >> "$RUN_LOG"

    if command -v python3 >/dev/null 2>&1; then
        python3 "$HERE/memory-context-load.py" --workspace "$WORKSPACE" --check --strict --require-proof --json >"$tmp" 2>>"$RUN_LOG"
        rc=$?
        python3 - "$tmp" "$rc" >>"$RUN_LOG" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
rc = int(sys.argv[2])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"- status: WARN receipt check returned unreadable JSON (rc={rc}): {exc}")
    print()
    raise SystemExit(0)

print(f"- status: {'PASS' if rc == 0 else 'WARN'}")
print(f"- check_rc: `{rc}`")
print(f"- check_status: `{payload.get('status', 'unknown')}`")
print(f"- strict_ready: `{str(payload.get('strict_ready') is True).lower()}`")
print(f"- receipt_proof_status: `{payload.get('receipt_proof_status', 'unknown')}`")
print(f"- required_count: `{payload.get('required_count', 0)}`")
print(f"- loaded_count: `{payload.get('loaded_count', 0)}`")

for key in ("invalid_contexts", "missing_contexts", "stale_contexts"):
    rows = payload.get(key) or []
    if rows:
        print(f"- {key}: `{len(rows)}`")
        for row in rows[:5]:
            reason = row.get("reason", "unknown") if isinstance(row, dict) else str(row)
            rid = row.get("requirement_id") if isinstance(row, dict) else ""
            prefix = f"{rid}: " if rid else ""
            print(f"  - `{prefix}{reason}`")

print()
PY
        if [ "$rc" -eq 0 ]; then
            ran+=("mcp-memory-receipt-check")
        else
            ran+=("mcp-memory-receipt-check (warn rc=$rc)")
        fi
    else
        echo "- status: WARN" >> "$RUN_LOG"
        echo "- reason: python3 unavailable; cannot validate existing receipt" >> "$RUN_LOG"
        echo >> "$RUN_LOG"
        ran+=("mcp-memory-receipt-check (warn python3 unavailable)")
    fi

    python3 - "$receipt" >>"$RUN_LOG" 2>/dev/null <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    receipt = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
loaded = [row for row in receipt.get("loaded_contexts", []) if isinstance(row, dict)]
print("### Loaded MCP Context Evidence")
print()
if not loaded:
    print("- _(none)_")
else:
    for row in loaded[:8]:
        print(f"- requirement_id: `{row.get('requirement_id', '')}`")
        print(f"  - tool: `{row.get('tool', '')}`")
        print(f"  - context_kind: `{row.get('context_kind', '')}`")
        print(f"  - context_pack_id: `{row.get('context_pack_id', '')}`")
        print(f"  - context_pack_hash: `{row.get('context_pack_hash', '')}`")
        print(f"  - pack_path: `{row.get('pack_path', '')}`")
print()
PY
}

{
    echo "# audit-deep report"
    echo
    echo "- workspace: \`$WORKSPACE\`"
    echo "- timestamp (UTC): $TS"
    echo "- profile: $DEFAULT_PROFILE_LABEL"
    echo "- dry-run: $DRY_RUN"
    if [ "$AUDIT_DEEP_MEDIUM_MODE" = "1" ]; then
        echo "- medium bounds: halmos=${AUDIT_DEEP_MEDIUM_HALMOS_TIMEOUT:-120}s medusa=${AUDIT_DEEP_MEDIUM_MEDUSA_TIMEOUT:-300}s echidna=${AUDIT_DEEP_MEDIUM_ECHIDNA_TIMEOUT:-300}s"
    fi
    if [ -n "$PROJECT_ROOT_OVERRIDE" ]; then
        echo "- project-root: \`$PROJECT_ROOT_OVERRIDE\`"
    fi
    echo
    echo "## Tool availability"
    echo
    echo "| tool | status | version |"
    echo "|---|---|---|"
    for row in \
        "forge:$HAS_FORGE:$FORGE_VERSION" \
        "cast:$HAS_CAST:$CAST_VERSION" \
        "anvil:$HAS_ANVIL:$ANVIL_VERSION" \
        "halmos:$HAS_HALMOS:$HALMOS_VERSION" \
        "kontrol:0:" \
        "medusa:$HAS_MEDUSA:$MEDUSA_VERSION" \
        "echidna:$HAS_ECHIDNA:$ECHIDNA_VERSION" \
        "mythril:$HAS_MYTHRIL:$MYTHRIL_VERSION" \
        "slither:$HAS_SLITHER:$SLITHER_VERSION"
    do
        name="${row%%:*}"
        rest="${row#*:}"
        has="${rest%%:*}"
        ver="${rest#*:}"
        if [ "$has" = "1" ]; then
            sym="✓"
        else
            sym="✗"
        fi
        if [ -z "$ver" ]; then ver="-"; fi
        echo "| $name | $sym | $ver |"
    done
    echo
} > "$RUN_LOG"

skipped=()
ran=()
failed=()
execution_truth=()

write_mcp_memory_receipt_section

{
    echo "## Steps"
    echo
} >> "$RUN_LOG"

record_execution_truth() {
    # record_execution_truth <tool> <state> <detail>
    #
    # State vocabulary is intentionally small and proof-oriented:
    # planned  = audit-deep itself was --dry-run; no inner runner invoked
    # dry_run  = inner runner invoked with --dry-run; no engine invocation
    # blocked  = setup/tooling prevented even a dry-run/live runner pass
    # executed = inner runner was invoked in live mode and completed
    execution_truth+=("$1|$2|$3")
}

write_go_dlt_audit_enforcement_manifest() {
    # write_go_dlt_audit_enforcement_manifest <status> <reason> <marker_exists> <marker_fresh> <check_rc> <check_stdout>
    #
    # Go/DLT workspaces now persist a small enforcement receipt so later
    # agents have a durable answer to "did this run after a real make audit?"
    # instead of inferring from markdown alone.
    local status="$1"
    local reason="$2"
    local marker_exists="$3"
    local marker_fresh="$4"
    local check_rc="$5"
    local check_stdout="$6"
    local manifest="$LOG_DIR/go_dlt_audit_enforcement.json"
    local marker_path="$WORKSPACE/.audit_logs/audit_completion.json"

    if ! command -v python3 >/dev/null 2>&1; then
        return 0
    fi

    AUDIT_DEEP_GO_DLT_MANIFEST="$manifest" \
    AUDIT_DEEP_GO_DLT_WORKSPACE="$WORKSPACE" \
    AUDIT_DEEP_GO_DLT_TIMESTAMP="$TS" \
    AUDIT_DEEP_GO_DLT_PROFILE="$PROFILE" \
    AUDIT_DEEP_GO_DLT_DRY_RUN="$DRY_RUN" \
    AUDIT_DEEP_GO_DLT_STATUS="$status" \
    AUDIT_DEEP_GO_DLT_REASON="$reason" \
    AUDIT_DEEP_GO_DLT_MARKER_PATH="$marker_path" \
    AUDIT_DEEP_GO_DLT_MARKER_EXISTS="$marker_exists" \
    AUDIT_DEEP_GO_DLT_MARKER_FRESH="$marker_fresh" \
    AUDIT_DEEP_GO_DLT_CHECK_RC="$check_rc" \
    AUDIT_DEEP_GO_DLT_CHECK_STDOUT="$check_stdout" \
    AUDIT_DEEP_GO_DLT_REPORT="$REPORT" \
    python3 - <<'PY' >/dev/null 2>&1
import json
import os
from pathlib import Path

def to_bool(value: str) -> bool:
    return value == "1"

payload = {
    "schema": "auditooor.go_dlt_audit_enforcement.v1",
    "workspace": os.environ["AUDIT_DEEP_GO_DLT_WORKSPACE"],
    "timestamp_utc": os.environ["AUDIT_DEEP_GO_DLT_TIMESTAMP"],
    "profile": os.environ["AUDIT_DEEP_GO_DLT_PROFILE"],
    "dry_run": to_bool(os.environ["AUDIT_DEEP_GO_DLT_DRY_RUN"]),
    "status": os.environ["AUDIT_DEEP_GO_DLT_STATUS"],
    "reason": os.environ["AUDIT_DEEP_GO_DLT_REASON"],
    "required_commands": [
        "make audit WS=<workspace>",
        "make audit-deep WS=<workspace>",
    ],
    "audit_completion": {
        "path": os.environ["AUDIT_DEEP_GO_DLT_MARKER_PATH"],
        "exists": to_bool(os.environ["AUDIT_DEEP_GO_DLT_MARKER_EXISTS"]),
        "fresh_for_workspace": to_bool(os.environ["AUDIT_DEEP_GO_DLT_MARKER_FRESH"]),
        "check_rc": int(os.environ["AUDIT_DEEP_GO_DLT_CHECK_RC"]),
        "check_stdout": os.environ["AUDIT_DEEP_GO_DLT_CHECK_STDOUT"],
    },
    "audit_deep_report": os.environ["AUDIT_DEEP_GO_DLT_REPORT"],
}
Path(os.environ["AUDIT_DEEP_GO_DLT_MANIFEST"]).write_text(
    json.dumps(payload, indent=2) + "\n",
    encoding="utf-8",
)
PY
}

# ---------------------------------------------------------------------------
# Typed deep-engine skip emission (deep-engine-typed-skip fix).
#
# An HONEST typed deep-engine skip: a documented, justified
# `.auditooor/stage_skips.json` record that audit-completeness-check.py credits
# as a `typed-skip` disposition (NOT a hollow false-pass and NOT a faked harness
# count) for a language arm that genuinely has NO applicable coverage-guided
# engine in this run.
#
# Fires only when, on this workspace, the deep run produced NO genuine
# coverage-guided engine evidence:
#   - non-EVM (Go / Rust / Move / Cairo) source is present but no
#     `fuzz_runs/*/manifest.json` (and no `.audit_logs/audit_deep_all_manifest`)
#     shows a positively-executed non-EVM harness (a Cosmos Go chain has no
#     medusa / echidna equivalent wired), AND/OR
#   - the EVM coverage-guided fuzzers (medusa / halmos / echidna) produced no
#     executed harness (blocked rc=2 / not installed / no forge project root).
#
# This NEVER overwrites a genuine engine run: when ANY coverage-guided engine
# DID execute a harness, no skip is written. The record carries a precise reason
# (derived from the actual on-disk engine state), a UTC timestamp, and the
# current audit-run-full run_id when one is present, so the freshness authority
# can couple it; the completeness check ALSO credits it coupling-independent.
# A pre-existing genuine (engine-ran) state removes any stale skip key.
# ---------------------------------------------------------------------------
emit_typed_deep_engine_skip() {
    local log="$1"
    command -v python3 >/dev/null 2>&1 || return 0
    {
        echo "### Typed deep-engine skip (deep-engine-typed-skip)"
        echo
    } >> "$log"
    AUDIT_DEEP_TS_WORKSPACE="$WORKSPACE" \
    AUDIT_DEEP_TS_TIMESTAMP="$TS" \
    AUDIT_DEEP_TS_PROFILE="$PROFILE" \
    AUDIT_DEEP_TS_DRY_RUN="$DRY_RUN" \
    AUDIT_DEEP_TS_LIVE="$LIVE" \
    AUDIT_DEEP_TS_RUN_ID="${AUDITOOOR_AUDIT_RUN_FULL_ID:-}" \
    python3 - >>"$log" 2>&1 <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

ws = Path(os.environ["AUDIT_DEEP_TS_WORKSPACE"])
ts = os.environ.get("AUDIT_DEEP_TS_TIMESTAMP") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
run_id = (os.environ.get("AUDIT_DEEP_TS_RUN_ID") or "").strip()
dry_run = os.environ.get("AUDIT_DEEP_TS_DRY_RUN") == "1"
skip_key = "NO_AUDIT_DEEP_REASON"
skip_json = ws / ".auditooor" / "stage_skips.json"

# A DRY_RUN deep pass intentionally runs no engines; never emit a skip that
# would credit a no-op planning run as honest coverage.
if dry_run:
    print("- dry-run: no engines invoked; typed deep-engine skip NOT emitted")
    raise SystemExit(0)

# --- Detect in-scope non-EVM + EVM source languages (prune vendored/build) ---
SKIP_PARTS = {
    "vendor", "node_modules", ".git", "lib", "out", "artifacts", "cache",
    "target", "third_party", "external", "test", "tests", "mocks", "mock",
    "poc-tests", "poc_execution", ".audit_logs", ".auditooor", "submissions",
    "prior_audits", "reports", "docs",
}
NON_EVM_EXTS = {".go": "go", ".rs": "rust", ".move": "move", ".cairo": "cairo"}
EVM_EXTS = {".sol", ".vy"}
non_evm_langs: dict[str, int] = {}
evm_files = 0
roots = [ws / "src", ws / "contracts", ws / "programs", ws / "x", ws]
seen_root = set()
for root in roots:
    rk = str(root.resolve()) if root.exists() else str(root)
    if rk in seen_root or not root.is_dir():
        continue
    seen_root.add(rk)
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part.lower() in SKIP_PARTS or part.startswith(".") for part in p.parts):
            continue
        suf = p.suffix.lower()
        lang = NON_EVM_EXTS.get(suf)
        if lang:
            non_evm_langs[lang] = non_evm_langs.get(lang, 0) + 1
        elif suf in EVM_EXTS:
            evm_files += 1

# --- Did a genuine coverage-guided engine execute a harness this run? ---
def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def _posint(obj, keys):
    best = 0
    for k in keys:
        v = obj.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            try:
                best = max(best, int(v))
            except (ValueError, TypeError):
                pass
    return best

non_evm_engine_ran = False
evm_engine_harness_ran = False
_COUNT_KEYS = (
    "tests_passed", "tests_run", "harness_count", "executed_harnesses",
    "properties_checked", "executed_generated_harness_count",
)
for sub in ("fuzz_runs", ".audit_logs/fuzz_runs"):
    d = ws / sub
    if not d.is_dir():
        continue
    for man in d.glob("*/manifest.json"):
        obj = _load(man)
        if not isinstance(obj, dict):
            continue
        engine = str(obj.get("engine") or "").lower()
        status = str(obj.get("status") or "").lower()
        count = _posint(obj, _COUNT_KEYS)
        ran = status in ("pass", "ok", "counterexample") and count > 0
        if engine in ("medusa", "halmos", "echidna"):
            if ran:
                evm_engine_harness_ran = True
        elif ran:
            non_evm_engine_ran = True

# Genuine executed EVM engine GENERATED harnesses (solidity-deep-audit manifest).
sda_manifest = ws / ".auditooor" / "solidity-deep-audit" / "manifest.json"
obj = _load(sda_manifest)
if isinstance(obj, dict):
    if int(obj.get("executed_generated_harness_count") or 0) > 0:
        evm_engine_harness_ran = True

# A non-EVM audit-deep-all manifest with a positive executed count also counts.
adm = ws / ".audit_logs" / "audit_deep_all_manifest.json"
obj = _load(adm)
if isinstance(obj, dict):
    if _posint(obj, _COUNT_KEYS) > 0:
        non_evm_engine_ran = True

# --- Decide whether to emit a typed skip ---
reasons = []
if non_evm_langs and not non_evm_engine_ran:
    arm = "/".join(sorted(non_evm_langs))
    reasons.append(
        f"non-EVM ({arm}) source present ({sum(non_evm_langs.values())} files) "
        "but no applicable coverage-guided engine produced an executed harness "
        "this run (no medusa/echidna-equivalent wired for this arm; scanners ran)"
    )
if evm_files and not evm_engine_harness_ran:
    reasons.append(
        f"EVM coverage-guided fuzzers (medusa/halmos/echidna) produced no executed "
        f"engine harness for the {evm_files} in-scope .sol/.vy file(s) "
        "(blocked / not installed / no single forge project root on a mixed layout)"
    )

if not reasons:
    # A genuine coverage-guided engine ran for every present arm; no honest skip
    # to declare. Remove any STALE skip key so a real engine run is not masked.
    if skip_json.is_file():
        try:
            payload = json.loads(skip_json.read_text(encoding="utf-8"))
        except Exception:
            payload = None
        if isinstance(payload, dict) and skip_key in payload:
            payload.pop(skip_key, None)
            if payload:
                skip_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            else:
                try:
                    skip_json.unlink()
                except OSError:
                    pass
            print(f"- genuine coverage-guided engine ran; removed stale {skip_key} skip key")
    print("- genuine coverage-guided engine evidence present for every arm; no typed skip emitted")
    raise SystemExit(0)

reason = "typed deep-engine skip: " + "; ".join(reasons)
entry = {
    "reason": reason,
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "audit_deep_timestamp": ts,
    "profile": os.environ.get("AUDIT_DEEP_TS_PROFILE") or "default",
    "non_evm_langs": non_evm_langs,
    "evm_files": evm_files,
    "non_evm_engine_ran": non_evm_engine_ran,
    "evm_engine_harness_ran": evm_engine_harness_ran,
}
if run_id:
    entry["run_id"] = run_id
    entry["audit_run_id"] = run_id

skip_json.parent.mkdir(parents=True, exist_ok=True)
payload = {}
if skip_json.is_file():
    try:
        existing = json.loads(skip_json.read_text(encoding="utf-8"))
        if isinstance(existing, dict):
            payload = existing
    except Exception:
        payload = {}
payload[skip_key] = entry
skip_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"- emitted typed deep-engine skip -> {skip_json}")
print(f"- reason: {reason}")
PY
    echo >> "$log"
}

# ---------------------------------------------------------------------------
# I17 fix (#334): auto-scaffold invariant harness before halmos/medusa.
# ---------------------------------------------------------------------------
if [ "$SCAFFOLD" = "1" ]; then
    {
        echo "### Step 0 - Auto-scaffold invariant harness (I17 #334)"
        echo
    } >> "$RUN_LOG"
    maybe_scaffold
    echo >> "$RUN_LOG"
fi

# ---------------------------------------------------------------------------
# Step 0b - Invariant ledger presence (PR #511 Slice 5).
#
# CHEAP early gate: detects whether <ws>/.auditooor/invariant_ledger.json
# exists. The whole step is a self-skip if the ledger is absent - this MUST
# NOT break audit-deep for a workspace that does not yet have one. That is
# precisely the silent-zero pattern Slice 5 closes: we always log, loudly,
# whether the ledger is present + which mode the run is in.
#
# Default: WARN (one log line + report row).
# REQUIRE_INVARIANT_LEDGER=1: missing ledger marks audit-deep step rc != 0.
# ---------------------------------------------------------------------------
INVARIANT_LEDGER_JSON="$WORKSPACE/.auditooor/invariant_ledger.json"
INVARIANT_LEDGER_PRESENT=0
INVARIANT_LEDGER_FAIL=0
CHIMERA_SCAFFOLD_FAIL=0
REQUIRE_INVARIANT_LEDGER="${REQUIRE_INVARIANT_LEDGER:-0}"
REQUIRE_HIGH_IMPACT_INVARIANTS="${REQUIRE_HIGH_IMPACT_INVARIANTS:-0}"

{
    echo "### Step 0b - Invariant ledger presence (PR #511 Slice 5)"
    echo
} >> "$RUN_LOG"

if [ -f "$INVARIANT_LEDGER_JSON" ]; then
    INVARIANT_LEDGER_PRESENT=1
    {
        echo "- present: \`$INVARIANT_LEDGER_JSON\`"
        echo "- mode: REQUIRE_INVARIANT_LEDGER=$REQUIRE_INVARIANT_LEDGER REQUIRE_HIGH_IMPACT_INVARIANTS=$REQUIRE_HIGH_IMPACT_INVARIANTS"
        echo "- late summary: Step 12 will run \`invariant-ledger.py --check --emit-closeout\`"
    } >> "$RUN_LOG"
    echo "[audit-deep] invariant ledger detected: $INVARIANT_LEDGER_JSON"
else
    if [ "$REQUIRE_INVARIANT_LEDGER" = "1" ]; then
        INVARIANT_LEDGER_FAIL=1
        {
            echo "- FAIL: no invariant ledger present (REQUIRE_INVARIANT_LEDGER=1)"
            echo "- expected: \`$INVARIANT_LEDGER_JSON\`"
            echo "- remediation: run \`make invariant-ledger WS=$WORKSPACE\` to scaffold (PR #511 Slice 2)"
        } >> "$RUN_LOG"
        echo "[audit-deep] FAIL: no invariant ledger present (run \`make invariant-ledger WS=$WORKSPACE\` to scaffold) (REQUIRE_INVARIANT_LEDGER=1)" >&2
        skipped+=("invariant-ledger (FAIL: REQUIRE_INVARIANT_LEDGER=1)")
    else
        {
            echo "- WARN: no invariant ledger present (run \`make invariant-ledger WS=<ws>\` to scaffold)"
            echo "- expected: \`$INVARIANT_LEDGER_JSON\`"
            echo "- escalation: set REQUIRE_INVARIANT_LEDGER=1 to promote this WARN to FAIL"
        } >> "$RUN_LOG"
        echo "[audit-deep] WARN: no invariant ledger present (run \`make invariant-ledger WS=$WORKSPACE\` to scaffold)"
        skipped+=("invariant-ledger (no ledger; WARN - set REQUIRE_INVARIANT_LEDGER=1 to FAIL)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 0c - Recon/Chimera ledger scaffold bridge (PR #524).
#
# This is deliberately scaffold-only. It turns Solidity-shaped invariant rows
# into Chimera-compatible harness directories only when AUDIT_DEEP_SCAFFOLD=1
# or --scaffold is set; default audit-deep only logs that the bridge is
# available. Generated outputs stay scaffolded_unverified and are not proof.
# ---------------------------------------------------------------------------
{
    echo "### Step 0c - Recon/Chimera ledger scaffold bridge (PR #524)"
    echo
} >> "$RUN_LOG"

CHIMERA_LEDGER_MANIFEST="$LOG_DIR/chimera_scaffold_manifest.json"
CHIMERA_LEDGER_TOOL="$HERE/chimera-ledger-scaffold.py"
AUDIT_DEEP_CHIMERA_MAX_ROWS="${AUDIT_DEEP_CHIMERA_MAX_ROWS:-25}"
AUDIT_DEEP_CHIMERA_STRICT_HANDLERS="${AUDIT_DEEP_CHIMERA_STRICT_HANDLERS:-1}"
if [ "$INVARIANT_LEDGER_PRESENT" != "1" ]; then
    {
        echo "- skipped: no invariant ledger present (see Step 0b)"
    } >> "$RUN_LOG"
    skipped+=("chimera-ledger-scaffold (no ledger)")
elif [ ! -f "$CHIMERA_LEDGER_TOOL" ]; then
    {
        echo "- skipped: tools/chimera-ledger-scaffold.py not present"
    } >> "$RUN_LOG"
    if [ "$SCAFFOLD" = "1" ]; then
        CHIMERA_SCAFFOLD_FAIL=1
        echo "[audit-deep] FAIL: AUDIT_DEEP_SCAFFOLD requested but chimera-ledger-scaffold.py is missing" >&2
    fi
    skipped+=("chimera-ledger-scaffold (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    {
        echo "- skipped: python3 not on PATH"
    } >> "$RUN_LOG"
    if [ "$SCAFFOLD" = "1" ]; then
        CHIMERA_SCAFFOLD_FAIL=1
        echo "[audit-deep] FAIL: AUDIT_DEEP_SCAFFOLD requested but python3 is missing" >&2
    fi
    skipped+=("chimera-ledger-scaffold (python3 missing)")
elif [ "$SCAFFOLD" != "1" ]; then
    {
        echo "- skipped: set AUDIT_DEEP_SCAFFOLD=1 or pass --scaffold to generate advisory Chimera harnesses"
        echo "- output when enabled: \`$CHIMERA_LEDGER_MANIFEST\`"
    } >> "$RUN_LOG"
    skipped+=("chimera-ledger-scaffold (AUDIT_DEEP_SCAFFOLD not set)")
else
    chimera_args=(--workspace "$WORKSPACE" --manifest "$CHIMERA_LEDGER_MANIFEST" --require-concrete-binding --max-rows "$AUDIT_DEEP_CHIMERA_MAX_ROWS" --print-json)
    if [ "$DRY_RUN" = "1" ]; then
        chimera_args+=(--dry-run)
    fi
    if [ "$AUDIT_DEEP_CHIMERA_STRICT_HANDLERS" != "0" ]; then
        chimera_args+=(--strict-handlers)
    fi
    printf -v chimera_cmd '%q ' python3 "$CHIMERA_LEDGER_TOOL" "${chimera_args[@]}"
    {
        echo "- ran: \`${chimera_cmd% }\`"
        echo "- proof boundary: generated harnesses are scaffolded_unverified until poc-execution-record proves impact"
        echo "- strict_handlers: $AUDIT_DEEP_CHIMERA_STRICT_HANDLERS"
        echo "- max_rows: $AUDIT_DEEP_CHIMERA_MAX_ROWS"
    } >> "$RUN_LOG"
    if python3 "$CHIMERA_LEDGER_TOOL" "${chimera_args[@]}" >>"$RUN_LOG" 2>&1; then
        ran+=("chimera-ledger-scaffold")
        {
            echo "- status: SUCCESS"
            echo "- manifest: \`$CHIMERA_LEDGER_MANIFEST\`"
        } >> "$RUN_LOG"
    else
        echo "- status: FAIL chimera-ledger-scaffold failed (see log above)" >> "$RUN_LOG"
        CHIMERA_SCAFFOLD_FAIL=1
        failed+=("chimera-ledger-scaffold")
    fi
fi
# wave-2 #7: register scaffolded chimera harnesses as mutation-verified invariants. The
# registrar is the only writer of chimera-invariant mode into mutation_verify_coverage.json;
# it was README-manual-only, so under cron/AFK the scaffold compute was never converted to
# invariant-fuzz yield. LIVE-gated (it runs real kill campaigns); rc=1 (a harness not
# verified) is advisory and does NOT fail audit-deep.
CHIMERA_REGISTRAR_TOOL="$HERE/chimera-invariant-registrar.py"
if [ "$LIVE" = "1" ] && [ -f "$CHIMERA_REGISTRAR_TOOL" ] && [ -d "$WORKSPACE/chimera_harnesses" ]; then
    if python3 "$CHIMERA_REGISTRAR_TOOL" --ws "$WORKSPACE" >> "$RUN_LOG" 2>&1; then
        ran+=("chimera-invariant-registrar")
    else
        ran+=("chimera-invariant-registrar (advisory: unverified harness)")
    fi
elif [ -f "$CHIMERA_REGISTRAR_TOOL" ]; then
    echo "- skipped: chimera-invariant-registrar needs LIVE=1 + <ws>/chimera_harnesses/" >> "$RUN_LOG"
    skipped+=("chimera-invariant-registrar (needs LIVE)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 1 - Halmos / symbolic-execution-validator.
# ---------------------------------------------------------------------------
{
    echo "### Step 1 - Halmos symbolic execution"
    echo
} >> "$RUN_LOG"

if [ "$HAS_HALMOS" = "1" ]; then
    # I12 fix (#327): when --live (or AUDIT_DEEP_LIVE=1) is set, drop the
    # hardcoded --dry-run so halmos actually executes. Default keeps the
    # cheap "render planned command" behaviour so existing callers don't
    # get surprise multi-hour runs.
    if [ "$LIVE" = "1" ]; then
        runner_args=(--engine halmos)
        run_label="ran-live"
    else
        runner_args=(--engine halmos --dry-run)
        run_label="ran-planned-only"
    fi
    if [ "$AUDIT_DEEP_MEDIUM_MODE" = "1" ]; then
        runner_args+=(--timeout "${AUDIT_DEEP_MEDIUM_HALMOS_TIMEOUT:-120}")
        run_label="ran-medium-bounded"
    fi
    if [ -n "$PROJECT_ROOT_OVERRIDE" ]; then
        runner_args+=(--project-root "$PROJECT_ROOT_OVERRIDE")
    fi
    cmd="bash $HERE/symbolic-runner.sh \"$WORKSPACE\" ${runner_args[*]}"
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        record_execution_truth "halmos" "planned" "audit-deep --dry-run; inner symbolic-runner not invoked"
        skipped+=("halmos (DRY_RUN=1)")
    else
        {
            echo "- $run_label: \`$cmd\`"
        } >> "$RUN_LOG"
        # Best-effort: redirect stdout/stderr to the run log; never fail.
        runner_rc=0
        bash "$HERE/symbolic-runner.sh" "$WORKSPACE" "${runner_args[@]}" >>"$RUN_LOG" 2>&1 || runner_rc=$?
        if [ "$runner_rc" -ne 0 ]; then
            echo "  (symbolic-runner exit $runner_rc)" >> "$RUN_LOG"
            echo "- execution-truth: blocked (symbolic-runner rc=$runner_rc)" >> "$RUN_LOG"
            record_execution_truth "halmos" "blocked" "symbolic-runner rc=$runner_rc"
            skipped+=("halmos (blocked: symbolic-runner rc=$runner_rc)")
        elif [ "$LIVE" = "1" ]; then
            echo "- execution-truth: executed (live runner completed)" >> "$RUN_LOG"
            record_execution_truth "halmos" "executed" "live symbolic-runner completed"
            ran+=("halmos (live)")
        else
            echo "- execution-truth: dry_run (inner symbolic-runner used --dry-run; engine not invoked)" >> "$RUN_LOG"
            record_execution_truth "halmos" "dry_run" "inner symbolic-runner used --dry-run; pass --live to execute"
            skipped+=("halmos (dry-run; pass --live or AUDIT_DEEP_LIVE=1 to actually execute)")
        fi
    fi
else
    {
        echo "- skipped: halmos not installed (\`tools/lib/tool-availability.sh\`)"
        echo "- effect: symbolic runner will skip; A-AUTH theorems unproven"
    } >> "$RUN_LOG"
    record_execution_truth "halmos" "blocked" "halmos not installed"
    skipped+=("halmos (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 2 - Medusa fuzz.
# ---------------------------------------------------------------------------
{
    echo "### Step 2 - Medusa coverage-guided fuzz"
    echo
} >> "$RUN_LOG"

if [ "$HAS_MEDUSA" = "1" ]; then
    if [ "$LIVE" = "1" ]; then
        runner_args=(--engine medusa)
        run_label="ran-live"
    else
        runner_args=(--engine medusa --dry-run)
        run_label="ran-planned-only"
    fi
    if [ "$AUDIT_DEEP_MEDIUM_MODE" = "1" ]; then
        runner_args+=(--timeout "${AUDIT_DEEP_MEDIUM_MEDUSA_TIMEOUT:-300}")
        run_label="ran-medium-bounded"
    fi
    if [ -n "$PROJECT_ROOT_OVERRIDE" ]; then
        runner_args+=(--project-root "$PROJECT_ROOT_OVERRIDE")
    fi
    cmd="bash $HERE/fuzz-runner.sh \"$WORKSPACE\" ${runner_args[*]}"
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        record_execution_truth "medusa" "planned" "audit-deep --dry-run; inner fuzz-runner not invoked"
        skipped+=("medusa (DRY_RUN=1)")
    else
        {
            echo "- $run_label: \`$cmd\`"
        } >> "$RUN_LOG"
        runner_rc=0
        bash "$HERE/fuzz-runner.sh" "$WORKSPACE" "${runner_args[@]}" >>"$RUN_LOG" 2>&1 || runner_rc=$?
        if [ "$runner_rc" -ne 0 ]; then
            echo "  (fuzz-runner exit $runner_rc)" >> "$RUN_LOG"
            echo "- execution-truth: blocked (fuzz-runner rc=$runner_rc)" >> "$RUN_LOG"
            record_execution_truth "medusa" "blocked" "fuzz-runner rc=$runner_rc"
            skipped+=("medusa (blocked: fuzz-runner rc=$runner_rc)")
        elif [ "$LIVE" = "1" ]; then
            echo "- execution-truth: executed (live runner completed)" >> "$RUN_LOG"
            record_execution_truth "medusa" "executed" "live fuzz-runner completed"
            ran+=("medusa (live)")
        else
            echo "- execution-truth: dry_run (inner fuzz-runner used --dry-run; engine not invoked)" >> "$RUN_LOG"
            record_execution_truth "medusa" "dry_run" "inner fuzz-runner used --dry-run; pass --live to execute"
            skipped+=("medusa (dry-run; pass --live or AUDIT_DEEP_LIVE=1 to actually execute)")
        fi
    fi
else
    {
        echo "- skipped: medusa not installed (\`tools/lib/tool-availability.sh\`)"
        echo "- effect: fuzz runner will skip; Foundry invariant still runs under \`make audit\`"
    } >> "$RUN_LOG"
    record_execution_truth "medusa" "blocked" "medusa not installed"
    skipped+=("medusa (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 3 - Echidna fuzz (alt fuzzer; see TOOL_COST_BENEFIT.md tier=debug-only).
# Only invoked if echidna is available AND medusa is NOT - otherwise medusa
# is the preferred path per the cost-benefit doc.
# ---------------------------------------------------------------------------
{
    echo "### Step 3 - Echidna fuzz (debug-only fallback)"
    echo
} >> "$RUN_LOG"

if [ "$HAS_ECHIDNA" = "1" ] && [ "$HAS_MEDUSA" != "1" ]; then
    if [ "$LIVE" = "1" ]; then
        runner_args=(--engine echidna)
        run_label="ran-live"
    else
        runner_args=(--engine echidna --dry-run)
        run_label="ran-planned-only"
    fi
    if [ "$AUDIT_DEEP_MEDIUM_MODE" = "1" ]; then
        runner_args+=(--timeout "${AUDIT_DEEP_MEDIUM_ECHIDNA_TIMEOUT:-300}")
        run_label="ran-medium-bounded"
    fi
    if [ -n "$PROJECT_ROOT_OVERRIDE" ]; then
        runner_args+=(--project-root "$PROJECT_ROOT_OVERRIDE")
    fi
    cmd="bash $HERE/fuzz-runner.sh \"$WORKSPACE\" ${runner_args[*]}"
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        skipped+=("echidna (DRY_RUN=1)")
    else
        {
            echo "- $run_label: \`$cmd\`"
        } >> "$RUN_LOG"
        bash "$HERE/fuzz-runner.sh" "$WORKSPACE" "${runner_args[@]}" \
            >>"$RUN_LOG" 2>&1 || echo "  (fuzz-runner exit $?)" >> "$RUN_LOG"
        if [ "$LIVE" = "1" ]; then
            ran+=("echidna (live)")
        else
            ran+=("echidna (planned-only; pass --live or AUDIT_DEEP_LIVE=1 to actually execute)")
        fi
    fi
elif [ "$HAS_ECHIDNA" = "1" ]; then
    {
        echo "- skipped: medusa already covers this slot (cost-benefit tier=debug-only)"
    } >> "$RUN_LOG"
    skipped+=("echidna (medusa preferred)")
else
    {
        echo "- skipped: echidna not installed"
    } >> "$RUN_LOG"
    skipped+=("echidna (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 4 - Slither full-IR run (calibration-style).
# Only invoked when slither is on PATH; the deep run is a per-workspace
# detector pass, NOT the multi-codebase clean-codebase calibration (that one
# stays manual via `python3 tools/clean-codebase-calibrate.py`).
# ---------------------------------------------------------------------------
{
    echo "### Step 4 - Slither full-IR per-workspace run"
    echo
} >> "$RUN_LOG"

if [ "$HAS_SLITHER" = "1" ]; then
    cmd="bash $HERE/slither-resilient.sh --timeout 120 -- \"$WORKSPACE\""
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        skipped+=("slither (DRY_RUN=1)")
    else
        {
            echo "- ran: \`$cmd\`"
        } >> "$RUN_LOG"
        bash "$HERE/slither-resilient.sh" --timeout 120 -- "$WORKSPACE" \
            >>"$RUN_LOG" 2>&1 || echo "  (slither exit $?)" >> "$RUN_LOG"
        ran+=("slither")
    fi
else
    {
        echo "- skipped: slither not installed"
    } >> "$RUN_LOG"
    skipped+=("slither (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 5 - Wave 2 Cosmos backend executor (PR for issue #482-adjacent uplift).
# Runs the first non-Solidity DSL executor: `cosmos-detector-runner.py`. The
# runner self-skips when there is no Cosmos-SDK go.mod, no .go files, or no
# DSL row carries `backend: cosmos`, so it's always safe to invoke. Always
# exits 0 (lead generator). Findings JSON lands at
# <workspace>/.auditooor/cosmos_findings.json with
# `evidence_class: scaffolded_unverified` (Wave 1 vocabulary). See
# docs/COSMOS_BACKEND.md.
# ---------------------------------------------------------------------------
{
    echo "### Step 5 - Wave 2 cosmos-backend DSL executor"
    echo
} >> "$RUN_LOG"

cosmos_runner="$HERE/cosmos-detector-runner.py"
if [ -x "$cosmos_runner" ] || [ -f "$cosmos_runner" ]; then
    cmd="python3 $cosmos_runner \"$WORKSPACE\""
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        skipped+=("cosmos-detect (DRY_RUN=1)")
    else
        {
            echo "- ran: \`$cmd\`"
        } >> "$RUN_LOG"
        python3 "$cosmos_runner" "$WORKSPACE" --quiet \
            >>"$RUN_LOG" 2>&1 || echo "  (cosmos-detect exit $?)" >> "$RUN_LOG"
        ran+=("cosmos-detect")
    fi
else
    {
        echo "- skipped: cosmos-detector-runner.py not present"
    } >> "$RUN_LOG"
    skipped+=("cosmos-detect (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 5b - Go/DLT advisory scanners.
#
# These grep-grade scanners are lead generators for Go DLT workspaces. They
# intentionally stay advisory and NOT_SUBMIT_READY: findings still require
# source-line validation, production-path proof, and PoC/equivalent evidence
# before submission. The step self-skips when no non-vendor Go files exist,
# honors global DRY_RUN, and never turns scanner output into a gate.
# ---------------------------------------------------------------------------
{
    echo "### Step 5b - Go/DLT advisory scanners"
    echo
} >> "$RUN_LOG"

GO_DLT_FILE_COUNT=$(find "$WORKSPACE" \
    \( -path "*/vendor" -o -path "*/node_modules" -o -path "*/.git" \
       -o -path "*/.auditooor" -o -path "*/build" -o -path "*/out" \
       -o -path "*/target" \) -prune \
    -o -type f -name "*.go" -print 2>/dev/null | head -1 | wc -l | tr -d ' ')
go_txid_runner="$HERE/go-txid-chain-truth-scan.py"
go_refund_runner="$HERE/go-refund-tweak-survivability-scan.py"
go_txid_out="$WORKSPACE/.auditooor/go_txid_chain_truth_scan.json"
go_refund_out="$WORKSPACE/.auditooor/go_refund_tweak_survivability_scan.json"
go_dlt_enforcement_manifest="$LOG_DIR/go_dlt_audit_enforcement.json"
go_dlt_marker_path="$WORKSPACE/.audit_logs/audit_completion.json"
go_dlt_marker_exists=0
go_dlt_marker_fresh=0
go_dlt_marker_check_rc=1
go_dlt_marker_check_out=""
GO_DLT_AUDIT_ENFORCEMENT_FAIL=0

if [ "${GO_DLT_FILE_COUNT:-0}" -eq 0 ]; then
    {
        echo "- skipped: no non-vendor Go files detected"
    } >> "$RUN_LOG"
    skipped+=("go-dlt-advisory-scanners (no Go files)")
else
    if [ -f "$go_dlt_marker_path" ]; then
        go_dlt_marker_exists=1
    fi
    # Generic prereq-ordering fix: inside a full pipeline (hunt-full / audit-run-full),
    # `make audit` runs as Step 1 and audit-deep as Step 2; on a real target the gap
    # between them routinely exceeds the 30-min default marker-freshness window, which
    # then falsely fails go-dlt-audit-enforcement as "audit evidence missing". When the
    # audit prereq was intentionally skipped (AUDIT_DEEP_SKIP_AUDIT_PREREQ set, i.e. the
    # marker was just written by Step 1), widen the freshness window so the in-pipeline
    # gap is accepted. Applies to ANY workspace, not a per-target hack.
    go_dlt_marker_max_age_args=""
    if [ -n "${AUDIT_DEEP_SKIP_AUDIT_PREREQ:-}" ]; then
        go_dlt_marker_max_age_args="--max-age-seconds ${AUDIT_DEEP_GO_DLT_MARKER_MAX_AGE_SECONDS:-86400}"
    fi
    if command -v python3 >/dev/null 2>&1 && [ -f "$HERE/audit-completion-marker.py" ]; then
        go_dlt_marker_check_out="$(python3 "$HERE/audit-completion-marker.py" check --workspace "$WORKSPACE" $go_dlt_marker_max_age_args 2>&1)"
        go_dlt_marker_check_rc=$?
        if [ "$go_dlt_marker_check_rc" -eq 0 ]; then
            go_dlt_marker_fresh=1
        fi
    elif [ "$go_dlt_marker_exists" -eq 1 ]; then
        go_dlt_marker_fresh=1
        go_dlt_marker_check_rc=0
        go_dlt_marker_check_out="marker-present (freshness check unavailable: python3 or tool missing)"
    else
        go_dlt_marker_check_out="marker-missing"
    fi

    if [ "$go_dlt_marker_exists" -eq 1 ]; then
        write_go_dlt_audit_enforcement_manifest "pass" \
            "canonical make audit evidence present before Go/DLT audit-deep step" \
            "$go_dlt_marker_exists" "$go_dlt_marker_fresh" "$go_dlt_marker_check_rc" "$go_dlt_marker_check_out"
    else
        GO_DLT_AUDIT_ENFORCEMENT_FAIL=1
        write_go_dlt_audit_enforcement_manifest "fail" \
            "run make audit WS=<workspace> before audit-deep for Go/DLT workspaces; advisory scanners are not valid without canonical audit evidence" \
            "$go_dlt_marker_exists" "$go_dlt_marker_fresh" "$go_dlt_marker_check_rc" "$go_dlt_marker_check_out"
    fi

    {
        echo "- gate manifest: \`$go_dlt_enforcement_manifest\`"
        echo "- required commands: \`make audit WS=<workspace>\` then \`make audit-deep WS=<workspace>\`"
        echo "- audit completion marker: \`$go_dlt_marker_path\`"
        if [ "$go_dlt_marker_exists" -eq 1 ]; then
            echo "- audit prerequisite: PASS (canonical audit evidence present)"
            if [ "$go_dlt_marker_fresh" -eq 1 ]; then
                echo "- audit freshness: PASS (marker is fresh for current workspace/toolchain)"
            else
                echo "- audit freshness: WARN (marker exists but rerun is recommended before relying on freshness)"
            fi
            echo "- audit marker check rc: $go_dlt_marker_check_rc"
            echo "- audit marker check: $go_dlt_marker_check_out"
        else
            echo "- audit prerequisite: FAIL (canonical audit evidence missing)"
            echo "- remediation: run \`make audit WS=$WORKSPACE\` before Go/DLT audit-deep"
            echo "- audit marker check rc: $go_dlt_marker_check_rc"
            echo "- audit marker check: $go_dlt_marker_check_out"
        fi
    } >> "$RUN_LOG"

    if [ "$go_dlt_marker_exists" -ne 1 ]; then
        {
            echo "- skipped: Go/DLT advisory scanners blocked until canonical audit evidence exists"
        } >> "$RUN_LOG"
        failed+=("go-dlt-audit-enforcement (make audit evidence missing)")
        skipped+=("go-dlt-advisory-scanners (blocked: make audit evidence missing)")
    elif ! command -v python3 >/dev/null 2>&1; then
        {
            echo "- skipped: python3 not on PATH"
        } >> "$RUN_LOG"
        skipped+=("go-dlt-advisory-scanners (python3 missing)")
    else
        {
            echo "- posture: advisory_only=true submission_posture=NOT_SUBMIT_READY"
            echo "- txid artifact: \`$go_txid_out\`"
            echo "- refund/key-tweak artifact: \`$go_refund_out\`"
        } >> "$RUN_LOG"

        if [ "$DRY_RUN" = "1" ]; then
            {
                if [ -f "$go_txid_runner" ]; then
                    echo "- planned: \`python3 $go_txid_runner \"$WORKSPACE\" > \"$go_txid_out\"\`"
                else
                    echo "- skipped: go-txid-chain-truth-scan.py not present"
                fi
                if [ -f "$go_refund_runner" ]; then
                    echo "- planned: \`python3 $go_refund_runner \"$WORKSPACE\" --json > \"$go_refund_out\"\`"
                else
                    echo "- skipped: go-refund-tweak-survivability-scan.py not present"
                fi
                if [ -f "$HERE/go-detector-runner.py" ]; then
                    echo "- planned: \`AUDITOOR_G{2,4,5,6,7,8,9,11,12,13,14,15}_*=1 AUDITOOOR_G_CONSENSUS_WRITE_DETERMINISM=1 python3 $HERE/go-detector-runner.py --workspace \"$WORKSPACE\"\` (13 advisory lanes incl G-CENSUS -> *_hypotheses.jsonl)"
                fi
                echo "- skipped (DRY_RUN=1)"
            } >> "$RUN_LOG"
            skipped+=("go-dlt-advisory-scanners (DRY_RUN=1)")
        else
            mkdir -p "$WORKSPACE/.auditooor"
            go_dlt_ran=0

            if [ -f "$go_txid_runner" ]; then
                {
                    echo "- ran: \`python3 $go_txid_runner \"$WORKSPACE\" > \"$go_txid_out\"\`"
                } >> "$RUN_LOG"
                if python3 "$go_txid_runner" "$WORKSPACE" >"$go_txid_out" 2>>"$RUN_LOG"; then
                    count=$(python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(len(d.get("findings", [])))
except Exception:
    print(0)' "$go_txid_out" 2>/dev/null || echo 0)
                    echo "- output txid-chain-truth: $count findings (NOT_SUBMIT_READY)" >> "$RUN_LOG"
                    go_dlt_ran=1
                else
                    rc=$?
                    echo "  (go-txid-chain-truth-scan exit $rc)" >> "$RUN_LOG"
                    failed+=("go-txid-chain-truth-scan (exit $rc)")
                fi
            else
                {
                    echo "- skipped: go-txid-chain-truth-scan.py not present"
                } >> "$RUN_LOG"
                skipped+=("go-txid-chain-truth-scan (not installed)")
            fi

            if [ -f "$go_refund_runner" ]; then
                {
                    echo "- ran: \`python3 $go_refund_runner \"$WORKSPACE\" --json > \"$go_refund_out\"\`"
                } >> "$RUN_LOG"
                if python3 "$go_refund_runner" "$WORKSPACE" --json >"$go_refund_out" 2>>"$RUN_LOG"; then
                    count=$(python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(len(d.get("findings", [])))
except Exception:
    print(0)' "$go_refund_out" 2>/dev/null || echo 0)
                    echo "- output refund/key-tweak survivability: $count findings (NOT_SUBMIT_READY)" >> "$RUN_LOG"
                    go_dlt_ran=1
                else
                    rc=$?
                    echo "  (go-refund-tweak-survivability-scan exit $rc)" >> "$RUN_LOG"
                    failed+=("go-refund-tweak-survivability-scan (exit $rc)")
                fi
            else
                {
                    echo "- skipped: go-refund-tweak-survivability-scan.py not present"
                } >> "$RUN_LOG"
                skipped+=("go-refund-tweak-survivability-scan (not installed)")
            fi

            # Go wave-2 advisory lanes (G2/G4/G5/G6/G7/G8/G11/G12/G13). These are
            # env-gated OFF in go-detector-runner main(); the pipeline never set the
            # AUDITOOR_G* envs, so the 9 lanes were built-but-dormant orphans
            # (methodology_capability_must_be_wired_not_just_built). Auto-run them
            # advisory-first here (verdict=needs-fuzz, NO auto-credit, never a gate);
            # the emitted *_hypotheses.jsonl are folded into the hunt corpus by
            # auto-coverage-closer (GO_ADVISORY_HYPOTHESES_REL, feeds-to). A non-zero
            # exit is advisory and never breaks the scan.
            go_adv_runner="$HERE/go-detector-runner.py"
            if [ -f "$go_adv_runner" ]; then
                {
                    echo "- ran: \`go-detector-runner.py --workspace \$WORKSPACE\` (G2/G4/G5/G6/G7/G8/G9/G11/G12/G13/G14/G15 advisory lanes)"
                } >> "$RUN_LOG"
                if AUDITOOR_G2_ATTACKER_DIVISOR_ZERO=1 \
                   AUDITOOR_G4_NONDET_TIME_FLOAT_RAND=1 \
                   AUDITOOR_G5_UNMARSHAL_TYPE_AMBIGUITY=1 \
                   AUDITOOR_G6_GOROUTINE_FANOUT_UNSYNC=1 \
                   AUDITOOR_G7_ONESIDED_ACCEPTANCE=1 \
                   AUDITOOR_G8_DECODE_MALFORMED_TRUSTED=1 \
                   AUDITOOR_G9_DECODE_CONSUMPTION_TYPE_NIL=1 \
                   AUDITOOR_G11_INGRESS_UNBOUNDED_PANIC=1 \
                   AUDITOOR_G12_GOROUTINE_NO_RECOVER=1 \
                   AUDITOOR_G13_CTX_CANCELLATION_IGNORED_VERDICT=1 \
                   AUDITOOR_G14_SENTINEL_LOSS=1 \
                   AUDITOOR_G15_ITER_BOUND_BYPASS=1 \
                   AUDITOOOR_G_CONSENSUS_WRITE_DETERMINISM=1 \
                   python3 "$go_adv_runner" --workspace "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
                    adv_rows=$(cat \
                        "$WORKSPACE/.auditooor/attacker_divisor_zero_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/nondeterministic_time_float_rand_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/unmarshal_type_ambiguity_first_match_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/goroutine_fanout_unsync_shared_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/onesided_acceptance_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/decode_malformed_then_trusted_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/decode_consumption_type_nil_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/ingress_unbounded_loop_or_panic_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/goroutine_no_toplevel_recover_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/ctx_cancellation_ignored_verdict_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/sentinel_loss_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/iter_bound_bypass_hypotheses.jsonl" \
                        "$WORKSPACE/.auditooor/consensus_write_determinism_census_hypotheses.jsonl" \
                        2>/dev/null | grep -c . || echo 0)
                    echo "- output go advisory lanes: $adv_rows hypotheses across 13 jsonls (verdict=needs-fuzz, NOT_SUBMIT_READY; folded into hunt corpus by auto-coverage-closer)" >> "$RUN_LOG"
                    go_dlt_ran=1
                else
                    rc=$?
                    echo "  (go-detector-runner advisory lanes exit $rc; advisory, continuing)" >> "$RUN_LOG"
                    skipped+=("go-detector-advisory-lanes (exit $rc)")
                fi
            else
                echo "- skipped: go-detector-runner.py not present" >> "$RUN_LOG"
                skipped+=("go-detector-advisory-lanes (not installed)")
            fi

            if [ "$go_dlt_ran" -eq 1 ]; then
                ran+=("go-dlt-advisory-scanners")
            fi
        fi
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 5c - Rust wave-2 advisory detector lanes (RU3/RU6/RU7/RU9/RU10/RU11).
#
# tools/rust-detector-runner.py carries 6 env-gated advisory axes that emit
# needs-fuzz hypotheses jsonls, but the runner was NEVER invoked by audit-deep
# (only standalone `make scan-rust`), so the 6 axes were built-but-dormant orphans
# (methodology_capability_must_be_wired_not_just_built). Auto-run them advisory-first
# here for any Rust workspace (verdict=needs-fuzz, NO auto-credit, never a gate);
# auto-coverage-closer folds the emitted jsonls (RUST_ADVISORY_HYPOTHESES_REL) into
# the hunt corpus (feeds-to). A non-zero exit is advisory and never breaks the scan.
# Mirrors the Go Step 5b stanza.
# ---------------------------------------------------------------------------
{
    echo "### Step 5c - Rust wave-2 advisory detector lanes"
    echo
} >> "$RUN_LOG"
RUST_ADV_FILE_COUNT=$(find "$WORKSPACE" \
    \( -path "*/target" -o -path "*/node_modules" -o -path "*/.git" \
       -o -path "*/.auditooor" -o -path "*/build" -o -path "*/out" \) -prune \
    -o -type f -name "*.rs" -print 2>/dev/null | head -1 | wc -l | tr -d ' ')
rust_adv_runner="$HERE/rust-detector-runner.py"
if [ "${RUST_ADV_FILE_COUNT:-0}" -eq 0 ]; then
    echo "- skipped: no non-vendor Rust files detected" >> "$RUN_LOG"
    skipped+=("rust-advisory-lanes (no Rust files)")
elif [ "$DRY_RUN" = "1" ]; then
    echo "- planned: \`AUDITOOR_RUST_{OOB,NONDET,LOCKPOISON,STRSLICE,ENTROPY,DROPSAFETY,PANIC_REACH}_AXIS=1 python3 $rust_adv_runner --workspace \"$WORKSPACE\"\` (7 advisory lanes -> rust_*_hypotheses.jsonl)" >> "$RUN_LOG"
    skipped+=("rust-advisory-lanes (DRY_RUN=1)")
elif [ ! -f "$rust_adv_runner" ]; then
    echo "- skipped: rust-detector-runner.py not present" >> "$RUN_LOG"
    skipped+=("rust-advisory-lanes (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("rust-advisory-lanes (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    echo "- ran: \`rust-detector-runner.py --workspace \$WORKSPACE\` (RU3/RU6/RU7/RU9/RU10/RU11/RU2 advisory axes)" >> "$RUN_LOG"
    if AUDITOOR_RUST_OOB_AXIS=1 \
       AUDITOOR_RUST_NONDET_AXIS=1 \
       AUDITOOR_RUST_LOCKPOISON_AXIS=1 \
       AUDITOOR_RUST_STRSLICE_AXIS=1 \
       AUDITOOR_RUST_ENTROPY_AXIS=1 \
       AUDITOOR_RUST_DROPSAFETY_AXIS=1 \
       AUDITOOR_RUST_PANIC_REACH_AXIS=1 \
       python3 "$rust_adv_runner" --workspace "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        rust_adv_rows=$(cat \
            "$WORKSPACE/.auditooor/rust_oob_hypotheses.jsonl" \
            "$WORKSPACE/.auditooor/rust_nondet_hypotheses.jsonl" \
            "$WORKSPACE/.auditooor/rust_lockpoison_hypotheses.jsonl" \
            "$WORKSPACE/.auditooor/rust_strslice_hypotheses.jsonl" \
            "$WORKSPACE/.auditooor/rust_entropy_hypotheses.jsonl" \
            "$WORKSPACE/.auditooor/rust_dropsafety_hypotheses.jsonl" \
            "$WORKSPACE/.auditooor/rust_panic_reach_hypotheses.jsonl" \
            2>/dev/null | grep -c . || echo 0)
        echo "- output rust advisory lanes: $rust_adv_rows hypotheses across 7 jsonls (verdict=needs-fuzz, NOT_SUBMIT_READY; folded into hunt corpus by auto-coverage-closer)" >> "$RUN_LOG"
        ran+=("rust-advisory-lanes")
    else
        rc=$?
        echo "  (rust-detector-runner advisory lanes exit $rc; advisory, continuing)" >> "$RUN_LOG"
        skipped+=("rust-advisory-lanes (exit $rc)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 5f - net-new general-logic advisory capability lanes (2026-07-11).
# Six standalone screens (EVM + Go), advisory-first (needs-fuzz, no-auto-credit),
# emitting *_hypotheses.jsonl folded into the hunt corpus by auto-coverage-closer
# (GO_ADVISORY / NETNEW_ADVISORY lists). Each exits non-fatal (advisory). General
# invariant/enforcement classes (A6 cache/source writer-set coherence, A7
# cross-module sibling reentrancy, A15 stale-grant survival, E9 ordering-dependent
# invariant, G10 Go slice-aliasing, R12 Go goroutine-lifecycle), NOT bug-shape
# detectors; each adversarially fleet-FP-verified (0 FP on green fleet code).
# ---------------------------------------------------------------------------
{
    echo "### Step 5f - net-new advisory capability lanes"
    echo
} >> "$RUN_LOG"
if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "- planned: A6/A7/A15/E9/G10/R12 advisory screens -> *_hypotheses.jsonl" >> "$RUN_LOG"
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("netnew-advisory-lanes (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    for nn_tool in \
        cache-source-writer-set-coherence.py \
        stale-grant-survival-screen.py \
        ordering-dependent-invariant-tagger.py \
        go-goroutine-lifecycle-census.py \
        rust-eager-alloc-nomax-screen.py \
        deserialize-precap-amplification-screen.py \
        deploy-initialize-ordering-window.py \
        arch-invariant-suspension-window.py \
        async-cancel-coupled-state-screen.py \
        rust-unsafe-soundness-obligation.py \
        go-unbounded-alloc-noprogress-screen.py \
        lifecycle-transition-graph-screen.py \
        deferred-execution-param-binding-screen.py \
        quorum-degradation-screen.py \
        total-order-comparator-screen.py \
        declared-control-mutator-completeness-screen.py \
        narrowing-lossy-cast-screen.py \
        recover-completeness-screen.py \
        rounding-direction-consistency-screen.py \
        operand-commensurability-screen.py \
        randomness-unbiasability-screen.py \
        abci-phase-predicate-symmetry-screen.py \
        verifier-executor-divergence-screen.py \
        raii-drop-glue-bypass-on-error-path-screen.py \
        multi-source-field-authority-differential-screen.py \
        cross-layer-cardinality-divergence-screen.py \
        nested-length-prefix-parent-bound-screen.py \
        rust-send-sync-bound-omission-share-boundary-screen.py \
        guard-predicate-soundness-screen.py \
        mid-transition-snapshot-phase-freshness-screen.py \
        generic-type-vs-runtime-selector-desync-screen.py \
        non-monotonic-guard-composition-screen.py \
        object-graph-xref-consistency-screen.py \
        failopen-classifier-default-arm-screen.py \
        queue-fairness-resource-mutation-screen.py \
        parse-consume-byte-conservation-screen.py \
        traversal-terminal-canonicalization-screen.py \
        ephemeral-reset-conservation-screen.py \
        extcall-boundary-invalidation-screen.py \
        domain-disjointness-assumption-screen.py \
        compiler-known-bug-shape-join-screen.py \
        crypto-preimage-soundness-screen.py \
        noncanonical-serialization-screen.py \
        selector-dispatch-collision-screen.py \
        gas-repricing-fragility-screen.py \
        toolchain-flag-drift-screen.py \
        transmute-type-confusion-screen.py \
        panic-during-drop-screen.py \
        release-silent-overflow-screen.py \
        consensus-map-order-return-screen.py \
        division-rounds-against-beneficiary-screen.py \
        width-narrowing-cast-screen.py \
        vault-maxexit-rounding-screen.py \
        discarded-fallible-result-screen.py ; do
        if [ -f "$HERE/$nn_tool" ]; then
            python3 "$HERE/$nn_tool" --workspace "$WORKSPACE" >>"$RUN_LOG" 2>&1 \
                || echo "  ($nn_tool advisory exit $?; continuing)" >> "$RUN_LOG"
        fi
    done
    # A7 takes a positional workspace; G10 is env-gated with --ws.
    if [ -f "$HERE/cross-module-sibling-reentrancy.py" ]; then
        python3 "$HERE/cross-module-sibling-reentrancy.py" "$WORKSPACE" >>"$RUN_LOG" 2>&1 \
            || echo "  (cross-module-sibling-reentrancy.py advisory exit $?; continuing)" >> "$RUN_LOG"
    fi
    if [ -f "$HERE/go-slice-aliasing-screen.py" ]; then
        AUDITOOOR_GO_SLICE_ALIASING=1 python3 "$HERE/go-slice-aliasing-screen.py" --ws "$WORKSPACE" >>"$RUN_LOG" 2>&1 \
            || echo "  (go-slice-aliasing-screen.py advisory exit $?; continuing)" >> "$RUN_LOG"
    fi
    # A10 + Z2 + C1 take a positional workspace/target; write their sidecar only for a dir.
    for nn_pos in proxy-storage-slot-bijection-screen.py zk-lookup-membership-bound.py js-oscript-value-moving-surface.py ; do
        if [ -f "$HERE/$nn_pos" ]; then
            python3 "$HERE/$nn_pos" "$WORKSPACE" >>"$RUN_LOG" 2>&1 \
                || echo "  ($nn_pos advisory exit $?; continuing)" >> "$RUN_LOG"
        fi
    done
    # E12 needs --emit to write its sidecar; R4 uses --root not --workspace.
    if [ -f "$HERE/inclusion-proof-positional-soundness.py" ]; then
        python3 "$HERE/inclusion-proof-positional-soundness.py" --workspace "$WORKSPACE" --emit >>"$RUN_LOG" 2>&1 \
            || echo "  (inclusion-proof-positional-soundness.py advisory exit $?; continuing)" >> "$RUN_LOG"
    fi
    if [ -f "$HERE/cross-client-consensus-divergence.py" ]; then
        python3 "$HERE/cross-client-consensus-divergence.py" --root "$WORKSPACE" >>"$RUN_LOG" 2>&1 \
            || echo "  (cross-client-consensus-divergence.py advisory exit $?; continuing)" >> "$RUN_LOG"
    fi
    # R3 uses --ws (not --workspace); writes delegation_trust_closure.jsonl.
    if [ -f "$HERE/arch-delegation-trust-closure.py" ]; then
        python3 "$HERE/arch-delegation-trust-closure.py" --ws "$WORKSPACE" >>"$RUN_LOG" 2>&1 \
            || echo "  (arch-delegation-trust-closure.py advisory exit $?; continuing)" >> "$RUN_LOG"
    fi
    nn_rows=$(cat \
        "$WORKSPACE/.auditooor/cache_source_writer_set_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/cross_module_sibling_reentrancy.jsonl" \
        "$WORKSPACE/.auditooor/stale_grant_survival_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/ordering_dependent_invariant_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/go_slice_aliasing.jsonl" \
        "$WORKSPACE/.auditooor/goroutine_lifecycle_safety_census_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/rust_eager_alloc_nomax_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/storage_slot_bijection_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/e7_precap_amplification_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/deploy_initialize_ordering_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/invariant_suspension_window_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/async_cancel_coupled_state_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/e12_inclusion_position_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/cross_client_consensus_divergence_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/zk_lookup_membership_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/js_oscript_value_moving_surface_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/delegation_trust_closure.jsonl" \
        "$WORKSPACE/.auditooor/rust_unsafe_soundness_obligation_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/go_unbounded_alloc_noprogress_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/lifecycle_transition_graph_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/deferred_execution_param_binding_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/quorum_degradation_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/total_order_comparator_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/declared_control_mutator_completeness_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/narrowing_lossy_cast_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/recover_completeness_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/rounding_direction_consistency_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/operand_commensurability_hypotheses.jsonl" \
        "$WORKSPACE/.auditooor/randomness_unbiasability_hypotheses.jsonl" \
        2>/dev/null | grep -c . || echo 0)
    echo "- output net-new advisory lanes: $nn_rows hypotheses across 6 screens (verdict=needs-fuzz, NOT_SUBMIT_READY; folded into hunt corpus by auto-coverage-closer)" >> "$RUN_LOG"
    ran+=("netnew-advisory-lanes")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Wave 3 Rust wiring (Steps 6-8). Three Rust-side tools shipped without ever
# being wired into audit-deep:
#   * tools/anchor-detector-runner.py        (PR #486 - backend: anchor)
#   * tools/rust-source-graph.py             (PR #462 - single-crate)
#   * tools/rust-cross-crate-graph.py        (PR #484 - cross-crate)
# Each step mirrors the Step 5 cosmos shape: pre-flight self-skip when the
# workspace doesn't look Rust, dry-run honoured, exit 0 always (lead
# generators, not gates).
# ---------------------------------------------------------------------------

# Pre-flight discovery - used by Steps 6, 7, 8. We deliberately walk a small
# bounded set (top-level + programs/contracts/crates) to keep this cheap and
# match the runners' own discover_crates() logic. find -prune skips heavy
# and generated dirs (target, node_modules, .git, .auditooor, scanners) so
# scanner scratch does not get mistaken for audited Rust source.
RUST_RS_COUNT=$(find "$WORKSPACE" \
    \( -path "*/target" -o -path "*/node_modules" -o -path "*/.git" \
       -o -path "*/.auditooor" -o -path "*/build" -o -path "*/out" \
       -o -path "*/scanners" \) -prune \
    -o -type f -name "*.rs" -print 2>/dev/null | head -1 | wc -l | tr -d ' ')
RUST_CARGO_FILES=$(find "$WORKSPACE" \
    \( -path "*/target" -o -path "*/node_modules" -o -path "*/.git" \
       -o -path "*/.auditooor" -o -path "*/build" -o -path "*/out" \
       -o -path "*/scanners" \) -prune \
    -o -type f -name "Cargo.toml" -print 2>/dev/null)
RUST_CARGO_COUNT=$(printf "%s\n" "$RUST_CARGO_FILES" | grep -c . || true)

# Declared project roots are operator intent hardened by
# project-source-root-readiness.  Keep the canonical engagement-wide graph
# behavior unchanged, but also produce named graphs for each validated Rust
# root so Base rc28-clean scans do not depend on manual artifact handoff.
RUST_DECLARED_ROOT_SPECS=$(PYTHONPATH="$HERE/.." python3 - "$WORKSPACE" <<'PY' 2>/dev/null || true
import sys
from pathlib import Path

from tools.lib.project_source_roots import declared_rust_project_root_specs

for row in declared_rust_project_root_specs(Path(sys.argv[1])):
    print(f"{row['artifact_slug']}\t{row['path']}")
PY
)

rust_named_root_count() {
    printf "%s\n" "$RUST_DECLARED_ROOT_SPECS" | grep -c . || true
}

rust_named_root_has_cross_crates() {
    # rust_named_root_has_cross_crates <rel-root>
    local rel_root="$1"
    local abs_root="$WORKSPACE/$rel_root"
    local count
    count=$(find "$abs_root" \
        \( -path "*/target" -o -path "*/node_modules" -o -path "*/.git" \
           -o -path "*/.auditooor" -o -path "*/build" -o -path "*/out" \
           -o -path "*/scanners" \) -prune \
        -o -type f -name Cargo.toml -exec sh -c '[ -d "$(dirname "$1")/src" ] && printf . || true' sh {} \; \
        2>/dev/null | wc -c | tr -d ' ')
    [ "${count:-0}" -ge 2 ]
}

# Anchor pre-flight: either a Cargo.toml mentioning `anchor-lang`, or a
# `programs/<crate>/src` layout. This matches anchor-detector-runner.py's own
# discover_anchor_files() (programs/contracts/<crate>/src).
ANCHOR_DETECTED=0
ANCHOR_REASON="no Rust workspace detected"
if [ -n "$RUST_CARGO_FILES" ]; then
    if printf "%s\n" "$RUST_CARGO_FILES" | xargs grep -l "anchor-lang" 2>/dev/null | head -1 | grep -q .; then
        ANCHOR_DETECTED=1
        ANCHOR_REASON=""
    fi
fi
if [ "$ANCHOR_DETECTED" -eq 0 ]; then
    if find "$WORKSPACE/programs" -mindepth 3 -maxdepth 3 -type d -name "src" 2>/dev/null | head -1 | grep -q .; then
        ANCHOR_DETECTED=1
        ANCHOR_REASON=""
    fi
fi

# Rust-source-graph pre-flight: any *.rs file plus at least one Cargo.toml.
RUST_GRAPH_DETECTED=0
RUST_GRAPH_REASON="no Rust workspace detected"
if [ "${RUST_RS_COUNT:-0}" -gt 0 ] && [ "${RUST_CARGO_COUNT:-0}" -gt 0 ]; then
    RUST_GRAPH_DETECTED=1
    RUST_GRAPH_REASON=""
fi

# Cross-crate pre-flight: workspace-root Cargo.toml has [workspace] OR there
# are 2+ crate Cargo.toml files anywhere under the engagement root. The
# recursive Cargo-root check mirrors rust-cross-crate-graph.py after Base/reth
# dogfooding showed real DLT sources often live under external/<project>/...
# instead of directly under WS/crates.
RUST_CROSS_DETECTED=0
RUST_CROSS_REASON="no Rust workspace detected"
if [ -f "$WORKSPACE/Cargo.toml" ] && grep -qE '^\[workspace\]' "$WORKSPACE/Cargo.toml" 2>/dev/null; then
    RUST_CROSS_DETECTED=1
    RUST_CROSS_REASON=""
fi
if [ "$RUST_CROSS_DETECTED" -eq 0 ]; then
    SUBCRATE_COUNT=$(find "$WORKSPACE" \
        \( -path "*/target" -o -path "*/node_modules" -o -path "*/.git" \
           -o -path "*/.auditooor" -o -path "*/build" -o -path "*/out" \
           -o -path "*/scanners" \) -prune \
        -o -type f -name Cargo.toml -exec sh -c '[ -d "$(dirname "$1")/src" ] && printf . || true' sh {} \; \
        2>/dev/null | wc -c | tr -d ' ')
    if [ "${SUBCRATE_COUNT:-0}" -ge 2 ]; then
        RUST_CROSS_DETECTED=1
        RUST_CROSS_REASON=""
    fi
fi
if [ "$RUST_CROSS_DETECTED" -eq 0 ] && [ "${RUST_CARGO_COUNT:-0}" -gt 0 ] && [ -n "$RUST_GRAPH_REASON" ]; then
    : # keep the no-Rust-workspace reason
elif [ "$RUST_CROSS_DETECTED" -eq 0 ] && [ "${RUST_CARGO_COUNT:-0}" -gt 0 ]; then
    RUST_CROSS_REASON="single-crate workspace (Step 7 covers this)"
fi
if [ "$RUST_CROSS_DETECTED" -eq 0 ] && [ "$(rust_named_root_count)" -gt 0 ]; then
    while IFS="$(printf '\t')" read -r _slug rel_root; do
        [ -n "$rel_root" ] || continue
        if rust_named_root_has_cross_crates "$rel_root"; then
            RUST_CROSS_DETECTED=1
            RUST_CROSS_REASON=""
            break
        fi
    done <<EOF
$RUST_DECLARED_ROOT_SPECS
EOF
fi

# ---------------------------------------------------------------------------
# Step 6 - Wave 3 Anchor backend DSL executor (PR #486 wiring).
# Runs `tools/anchor-detector-runner.py` against an Anchor (Solana)
# workspace. Self-skips when the workspace shows no `anchor-lang` Cargo dep
# and no `programs/<crate>/src` layout. Always exits 0 (lead generator).
# Findings JSON lands at <workspace>/.auditooor/anchor_findings.json.
# See docs/ANCHOR_BACKEND.md.
# ---------------------------------------------------------------------------
{
    echo "### Step 6 - Wave 3 anchor-backend DSL executor"
    echo
} >> "$RUN_LOG"

anchor_runner="$HERE/anchor-detector-runner.py"
if [ "$ANCHOR_DETECTED" -eq 0 ]; then
    {
        echo "- skipped: $ANCHOR_REASON"
    } >> "$RUN_LOG"
    skipped+=("anchor-detect ($ANCHOR_REASON)")
elif [ -x "$anchor_runner" ] || [ -f "$anchor_runner" ]; then
    cmd="python3 $anchor_runner --workspace \"$WORKSPACE\""
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        skipped+=("anchor-detect (DRY_RUN=1)")
    else
        {
            echo "- ran: \`$cmd\`"
        } >> "$RUN_LOG"
        python3 "$anchor_runner" --workspace "$WORKSPACE" \
            >>"$RUN_LOG" 2>&1 || echo "  (anchor-detect exit $?)" >> "$RUN_LOG"
        if [ -f "$WORKSPACE/.auditooor/anchor_findings.json" ]; then
            count=$(python3 -c "import json,sys
try:
  d=json.load(open('$WORKSPACE/.auditooor/anchor_findings.json'))
  print(len(d.get('findings',[])))
except Exception:
  print(0)" 2>/dev/null || echo 0)
            echo "- output: $count findings" >> "$RUN_LOG"
        fi
        ran+=("anchor-detect")
    fi
else
    {
        echo "- skipped: anchor-detector-runner.py not present"
    } >> "$RUN_LOG"
    skipped+=("anchor-detect (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 7 - Wave 3 Rust source graph (single-crate, PR #462 wiring).
# Runs `tools/rust-source-graph.py` to build the per-crate syntactic
# inventory the production-path-dossier needs to gate Rust candidates.
# Self-skips when no `*.rs` files or no Cargo.toml are detected. Always
# exits 0 (lead generator). Graph JSON lands at
# <workspace>/.auditooor/rust_source_graph.json. See
# docs/RUST_SOURCE_GRAPH.md.
# ---------------------------------------------------------------------------
{
    echo "### Step 7 - Wave 3 rust-source-graph (single-crate)"
    echo
} >> "$RUN_LOG"

rust_graph_runner="$HERE/rust-source-graph.py"
if [ "$RUST_GRAPH_DETECTED" -eq 0 ]; then
    {
        echo "- skipped: $RUST_GRAPH_REASON"
    } >> "$RUN_LOG"
    skipped+=("rust-source-graph ($RUST_GRAPH_REASON)")
elif [ -x "$rust_graph_runner" ] || [ -f "$rust_graph_runner" ]; then
    cmd="python3 $rust_graph_runner --workspace \"$WORKSPACE\""
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            if [ "$(rust_named_root_count)" -gt 0 ]; then
                while IFS="$(printf '\t')" read -r slug rel_root; do
                    [ -n "$slug" ] && [ -n "$rel_root" ] || continue
                    named_out="$WORKSPACE/.auditooor/rust_source_graph.$slug.json"
                    echo "- planned named root: \`python3 $rust_graph_runner --workspace \"$WORKSPACE/$rel_root\" --out \"$named_out\"\`"
                done <<EOF
$RUST_DECLARED_ROOT_SPECS
EOF
            fi
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        skipped+=("rust-source-graph (DRY_RUN=1)")
    else
        {
            echo "- ran: \`$cmd\`"
        } >> "$RUN_LOG"
        python3 "$rust_graph_runner" --workspace "$WORKSPACE" \
            >>"$RUN_LOG" 2>&1 || echo "  (rust-source-graph exit $?)" >> "$RUN_LOG"
        if [ -f "$WORKSPACE/.auditooor/rust_source_graph.json" ]; then
            count=$(python3 -c "import json,sys
try:
  d=json.load(open('$WORKSPACE/.auditooor/rust_source_graph.json'))
  print(sum(1 for k in d if not k.startswith('_')))
except Exception:
  print(0)" 2>/dev/null || echo 0)
            echo "- output: $count crates" >> "$RUN_LOG"
        fi
        if [ "$(rust_named_root_count)" -gt 0 ]; then
            while IFS="$(printf '\t')" read -r slug rel_root; do
                [ -n "$slug" ] && [ -n "$rel_root" ] || continue
                root_abs="$WORKSPACE/$rel_root"
                named_out="$WORKSPACE/.auditooor/rust_source_graph.$slug.json"
                if [ ! -d "$root_abs" ]; then
                    echo "- warning: declared Rust root missing for named graph: $rel_root" >> "$RUN_LOG"
                    failed+=("rust-source-graph:$slug (missing root)")
                    continue
                fi
                echo "- ran named root: \`python3 $rust_graph_runner --workspace \"$root_abs\" --out \"$named_out\"\`" >> "$RUN_LOG"
                if python3 "$rust_graph_runner" --workspace "$root_abs" --out "$named_out" >>"$RUN_LOG" 2>&1; then
                    if [ -f "$named_out" ]; then
                        count=$(python3 -c "import json,sys
try:
  d=json.load(open('$named_out'))
  print(sum(1 for k in d if not k.startswith('_')))
except Exception:
  print(0)" 2>/dev/null || echo 0)
                        echo "- output named root $slug: $count crates -> $named_out" >> "$RUN_LOG"
                    else
                        echo "- warning: named Rust source graph did not appear: $named_out" >> "$RUN_LOG"
                        failed+=("rust-source-graph:$slug (missing output)")
                    fi
                else
                    rc=$?
                    echo "  (rust-source-graph named root $slug exit $rc)" >> "$RUN_LOG"
                    failed+=("rust-source-graph:$slug (exit $rc)")
                fi
            done <<EOF
$RUST_DECLARED_ROOT_SPECS
EOF
        fi
        ran+=("rust-source-graph")
    fi
else
    {
        echo "- skipped: rust-source-graph.py not present"
    } >> "$RUN_LOG"
    skipped+=("rust-source-graph (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 8 - Wave 3 Rust cross-crate import graph (PR #484 wiring).
# Runs `tools/rust-cross-crate-graph.py` to build workspace dep graph +
# `use`-statement import edges. Self-skips on single-crate workspaces (the
# tool only adds value when there are 2+ in-workspace crates) and on
# non-Rust workspaces. Always exits 0. Graph JSON lands at
# <workspace>/.auditooor/rust_cross_crate_graph.json.
# ---------------------------------------------------------------------------
{
    echo "### Step 8 - Wave 3 rust-cross-crate-graph"
    echo
} >> "$RUN_LOG"

rust_cross_runner="$HERE/rust-cross-crate-graph.py"
if [ "$RUST_CROSS_DETECTED" -eq 0 ]; then
    {
        echo "- skipped: $RUST_CROSS_REASON"
    } >> "$RUN_LOG"
    skipped+=("rust-cross-crate-graph ($RUST_CROSS_REASON)")
elif [ -x "$rust_cross_runner" ] || [ -f "$rust_cross_runner" ]; then
    cmd="python3 $rust_cross_runner --workspace \"$WORKSPACE\""
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            if [ "$(rust_named_root_count)" -gt 0 ]; then
                while IFS="$(printf '\t')" read -r slug rel_root; do
                    [ -n "$slug" ] && [ -n "$rel_root" ] || continue
                    if rust_named_root_has_cross_crates "$rel_root"; then
                        named_out="$WORKSPACE/.auditooor/rust_cross_crate_graph.$slug.json"
                        echo "- planned named root: \`python3 $rust_cross_runner --workspace \"$WORKSPACE/$rel_root\" --out \"$named_out\"\`"
                    else
                        echo "- skipped named root $slug: single-crate root (source graph covers this)"
                    fi
                done <<EOF
$RUST_DECLARED_ROOT_SPECS
EOF
            fi
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        skipped+=("rust-cross-crate-graph (DRY_RUN=1)")
    else
        {
            echo "- ran: \`$cmd\`"
        } >> "$RUN_LOG"
        python3 "$rust_cross_runner" --workspace "$WORKSPACE" \
            >>"$RUN_LOG" 2>&1 || echo "  (rust-cross-crate-graph exit $?)" >> "$RUN_LOG"
        if [ -f "$WORKSPACE/.auditooor/rust_cross_crate_graph.json" ]; then
            count=$(python3 -c "import json,sys
try:
  d=json.load(open('$WORKSPACE/.auditooor/rust_cross_crate_graph.json'))
  print(d.get('_meta',{}).get('edge_count',0))
except Exception:
  print(0)" 2>/dev/null || echo 0)
            echo "- output: $count edges" >> "$RUN_LOG"
        fi
        if [ "$(rust_named_root_count)" -gt 0 ]; then
            while IFS="$(printf '\t')" read -r slug rel_root; do
                [ -n "$slug" ] && [ -n "$rel_root" ] || continue
                root_abs="$WORKSPACE/$rel_root"
                named_out="$WORKSPACE/.auditooor/rust_cross_crate_graph.$slug.json"
                if [ ! -d "$root_abs" ]; then
                    echo "- warning: declared Rust root missing for named cross-crate graph: $rel_root" >> "$RUN_LOG"
                    failed+=("rust-cross-crate-graph:$slug (missing root)")
                    continue
                fi
                if ! rust_named_root_has_cross_crates "$rel_root"; then
                    echo "- skipped named root $slug: single-crate root (source graph covers this)" >> "$RUN_LOG"
                    continue
                fi
                echo "- ran named root: \`python3 $rust_cross_runner --workspace \"$root_abs\" --out \"$named_out\"\`" >> "$RUN_LOG"
                if python3 "$rust_cross_runner" --workspace "$root_abs" --out "$named_out" >>"$RUN_LOG" 2>&1; then
                    if [ -f "$named_out" ]; then
                        count=$(python3 -c "import json,sys
try:
  d=json.load(open('$named_out'))
  print(d.get('_meta',{}).get('edge_count',0))
except Exception:
  print(0)" 2>/dev/null || echo 0)
                        echo "- output named root $slug: $count edges -> $named_out" >> "$RUN_LOG"
                    else
                        echo "- warning: named Rust cross-crate graph did not appear: $named_out" >> "$RUN_LOG"
                        failed+=("rust-cross-crate-graph:$slug (missing output)")
                    fi
                else
                    rc=$?
                    echo "  (rust-cross-crate-graph named root $slug exit $rc)" >> "$RUN_LOG"
                    failed+=("rust-cross-crate-graph:$slug (exit $rc)")
                fi
            done <<EOF
$RUST_DECLARED_ROOT_SPECS
EOF
        fi
        ran+=("rust-cross-crate-graph")
    fi
else
    {
        echo "- skipped: rust-cross-crate-graph.py not present"
    } >> "$RUN_LOG"
    skipped+=("rust-cross-crate-graph (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 9 - zkBugs corpus freshness check.
#
# Wave 3 pipeline wiring (codex/wave3-zkbugs-pipeline-wiring). This is a pure
# read-only freshness probe. It does NOT auto-pull the zkBugs corpus because
# `make zkbugs-pull LIVE=1` dispatches to LLM providers, which costs money
# and must remain an explicit operator action. Step 9 only writes a one-line
# recommendation to $RUN_LOG when the corpus is stale.
#
# Inputs:
#   - <ws>/.auditooor/zkbugs_last_pull - UTC ISO-8601 timestamp written by the
#     zkbugs-pull recipe after a successful LIVE run.
#
# Behavior:
#   - Missing timestamp file -> append a "NEVER pulled" recommendation.
#   - Timestamp older than 14 days -> append a "stale (>14 days)" recommendation.
#   - Otherwise -> append a "fresh" line. Always exits 0.
#
# This step intentionally appears AFTER the cosmos-backend executor (Step 5)
# and any in-flight Wave 3 capability uplift steps (6-8) so it is the last
# step before the run summary.
# ---------------------------------------------------------------------------
{
    echo "### Step 9 - zkBugs corpus freshness check"
    echo
} >> "$RUN_LOG"

zkbugs_ts_file="$WORKSPACE/.auditooor/zkbugs_last_pull"
zkbugs_stale_days="${AUDIT_DEEP_ZKBUGS_STALE_DAYS:-14}"
if [ ! -f "$zkbugs_ts_file" ]; then
    {
        echo "- status: NEVER pulled (no \`$zkbugs_ts_file\`)"
        echo "- recommendation: run \`make zkbugs-pull LIVE=1 ZKBUGS_ROOT=<path>\` to refresh the corpus"
        echo "- note: provider calls cost money; this step does NOT auto-pull"
    } >> "$RUN_LOG"
else
    zkbugs_age_seconds=0
    if command -v python3 >/dev/null 2>&1; then
        zkbugs_age_seconds="$(python3 - "$zkbugs_ts_file" <<'PY' 2>/dev/null || echo 0
import sys
from datetime import datetime, timezone
try:
    raw = open(sys.argv[1]).read().strip()
    ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - ts
    print(int(delta.total_seconds()))
except Exception:
    print(0)
PY
        )"
    fi
    zkbugs_threshold_seconds=$(( zkbugs_stale_days * 86400 ))
    if [ "${zkbugs_age_seconds:-0}" -gt "$zkbugs_threshold_seconds" ]; then
        {
            echo "- status: STALE (>${zkbugs_stale_days} days since last pull)"
            echo "- last pull: \`$(cat "$zkbugs_ts_file" 2>/dev/null || echo unknown)\`"
            echo "- recommendation: run \`make zkbugs-pull LIVE=1 ZKBUGS_ROOT=<path>\` to refresh the corpus"
            echo "- note: provider calls cost money; this step does NOT auto-pull"
        } >> "$RUN_LOG"
    else
        {
            echo "- status: fresh (<${zkbugs_stale_days} days)"
            echo "- last pull: \`$(cat "$zkbugs_ts_file" 2>/dev/null || echo unknown)\`"
        } >> "$RUN_LOG"
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 10 - Wave 3 reth backend DSL executor.
# Runs `tools/reth-detector-runner.py` against reth/op-reth/base-reth-shaped
# Cargo workspaces. The runner self-skips when no Cargo.toml mentions reth,
# alloy, or revm, so it is safe on Solidity-only and non-DLT workspaces.
# Findings JSON lands at <workspace>/.auditooor/reth_findings.json with
# `evidence_class: scaffolded_unverified`. See docs/RETH_BACKEND.md.
# ---------------------------------------------------------------------------
{
    echo "### Step 10 - Wave 3 reth-backend DSL executor"
    echo
} >> "$RUN_LOG"

reth_runner="$HERE/reth-detector-runner.py"
if [ -x "$reth_runner" ] || [ -f "$reth_runner" ]; then
    cmd="python3 $reth_runner \"$WORKSPACE\""
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        skipped+=("reth-detect (DRY_RUN=1)")
    else
        {
            echo "- ran: \`$cmd\`"
        } >> "$RUN_LOG"
        python3 "$reth_runner" "$WORKSPACE" --quiet \
            >>"$RUN_LOG" 2>&1 || echo "  (reth-detect exit $?)" >> "$RUN_LOG"
        if [ -f "$WORKSPACE/.auditooor/reth_findings.json" ]; then
            count=$(python3 -c "import json,sys
try:
  d=json.load(open('$WORKSPACE/.auditooor/reth_findings.json'))
  print(len(d.get('findings',[])))
except Exception:
  print(0)" 2>/dev/null || echo 0)
            echo "- output: $count findings" >> "$RUN_LOG"
        fi
        ran+=("reth-detect")
    fi
else
    {
        echo "- skipped: reth-detector-runner.py not present"
    } >> "$RUN_LOG"
    skipped+=("reth-detect (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 11 - state-root parity scaffold (Wave 3 differential-fuzz).
# Generates a state-root parity harness for Rust DLT / EL workspaces (e.g.
# base-reth). Self-skips on Solidity-only workspaces and on Cargo workspaces
# that don't reference revm / alloy-consensus / reth. Always exits 0.
# Running the actual fuzz is operator-driven via:
#   cd <ws>/differential_fuzz/state_root_parity && make fuzz-state-root
# See docs/STATE_ROOT_PARITY.md.
# ---------------------------------------------------------------------------
{
    echo "### Step 11 - state-root parity scaffold (Wave 3 differential-fuzz)"
    echo
} >> "$RUN_LOG"

state_root_parity_gen="$HERE/gen-state-root-parity.sh"
if [ -x "$state_root_parity_gen" ] || [ -f "$state_root_parity_gen" ]; then
    cmd="bash $state_root_parity_gen --workspace \"$WORKSPACE\""
    if [ "$DRY_RUN" = "1" ]; then
        {
            echo "- planned: \`$cmd\`"
            echo "- skipped (DRY_RUN=1)"
        } >> "$RUN_LOG"
        skipped+=("state-root-parity (DRY_RUN=1)")
    else
        {
            echo "- ran: \`$cmd\`"
        } >> "$RUN_LOG"
        bash "$state_root_parity_gen" --workspace "$WORKSPACE" \
            >>"$RUN_LOG" 2>&1 || echo "  (state-root-parity exit $?)" >> "$RUN_LOG"
        ran+=("state-root-parity")
    fi
else
    {
        echo "- skipped: gen-state-root-parity.sh not present"
    } >> "$RUN_LOG"
    skipped+=("state-root-parity (not installed)")
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 12 - Invariant ledger summary (PR #511 Slice 5).
#
# When the ledger is present, runs `invariant-ledger.py --check` followed by
# `--emit-closeout`, then writes the deep-summary artifacts:
#   <ws>/.audit_logs/invariant_ledger_deep_summary.json
#   <ws>/.audit_logs/invariant_ledger_deep_summary.md
#
# The `--emit-closeout` invocation also (re-)writes
# <ws>/.audit_logs/invariant_ledger_manifest.json - the same artifact
# tools/audit-closeout-check.py already consumes (PR #511 Slice 2 contract).
# Closeout reads the manifest; audit-deep authors it. One source of truth.
#
# When LIVE=1 AUDIT_DEEP_SCAFFOLD=1, rows whose `harness_target` is non-empty
# are LOGGED as a queue. Actual harness invocation is intentionally deferred
# to a follow-up: this slice closes the silent-zero gap, it does not yet
# auto-execute Foundry/Cargo targets.
#
# Self-skips with a clear note when no ledger is present (Step 0b already
# decided whether that is WARN or FAIL; Step 12 just respects the decision).
# ---------------------------------------------------------------------------
{
    echo "### Step 12 - Invariant ledger summary (PR #511 Slice 5)"
    echo
} >> "$RUN_LOG"

INVARIANT_LEDGER_DEEP_SUMMARY_JSON="$LOG_DIR/invariant_ledger_deep_summary.json"
INVARIANT_LEDGER_DEEP_SUMMARY_MD="$LOG_DIR/invariant_ledger_deep_summary.md"
INVARIANT_LEDGER_MANIFEST="$LOG_DIR/invariant_ledger_manifest.json"
INVARIANT_LEDGER_TOOL="$HERE/invariant-ledger.py"

if [ "$INVARIANT_LEDGER_PRESENT" != "1" ]; then
    {
        echo "- skipped: no invariant ledger present (see Step 0b)"
        echo "- remediation: run \`make invariant-ledger WS=$WORKSPACE\` to scaffold"
    } >> "$RUN_LOG"
    skipped+=("invariant-ledger-summary (no ledger)")
elif [ ! -f "$INVARIANT_LEDGER_TOOL" ]; then
    {
        echo "- skipped: tools/invariant-ledger.py not present in this checkout"
    } >> "$RUN_LOG"
    skipped+=("invariant-ledger-summary (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    {
        echo "- skipped: python3 not on PATH"
    } >> "$RUN_LOG"
    skipped+=("invariant-ledger-summary (python3 missing)")
elif [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $INVARIANT_LEDGER_TOOL --workspace $WORKSPACE --check\`"
        echo "- planned: \`python3 $INVARIANT_LEDGER_TOOL --workspace $WORKSPACE --emit-closeout\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("invariant-ledger-summary (DRY_RUN=1)")
else
    check_args=(--workspace "$WORKSPACE")
    if [ "$REQUIRE_HIGH_IMPACT_INVARIANTS" = "1" ]; then
        check_args+=(--require-high-impact-harness)
    else
        check_args+=(--check)
    fi

    {
        echo "- ran: \`python3 $INVARIANT_LEDGER_TOOL ${check_args[*]}\`"
    } >> "$RUN_LOG"

    set +e
    python3 "$INVARIANT_LEDGER_TOOL" "${check_args[@]}" \
        >>"$RUN_LOG" 2>&1
    check_rc=$?
    # audit-deep normally runs without errexit. Keep nonzero advisory
    # subprocesses recordable instead of aborting later strict checks.
    set +e 2>/dev/null || true

    {
        echo "- check rc: $check_rc"
    } >> "$RUN_LOG"

    # Seed candidate invariant rows from scope/spec/intel BEFORE the closeout,
    # but ONLY when the ledger is empty (rows: []). --emit-closeout requires a
    # non-empty ledger; an --init-only ledger makes it exit nonzero ("zero rows")
    # and the manifest is never written. Auto-authored harness scaffolds do NOT
    # seed the ledger, so without this step every workspace whose ledger was only
    # scaffolded fails the closeout (surfaced on near-intents 2026-06-25). We gate
    # on rows==0 so a populated/operator-curated ledger is left exactly as-is (no
    # row-count drift); --from-scope only ADDS candidate rows and never mutates
    # existing rows. Advisory: a seed failure does not abort - emit-closeout below
    # still records its own rc honestly.
    ledger_row_count=$(python3 -c "import json,sys;
try:
    print(len(json.load(open('$INVARIANT_LEDGER_JSON')).get('rows',[])))
except Exception:
    print(-1)" 2>/dev/null || echo -1)
    if [ "${ledger_row_count:-0}" = "0" ]; then
        {
            echo "- ledger rows: 0 (empty); running --from-scope pre-closeout seed"
            echo "- ran: \`python3 $INVARIANT_LEDGER_TOOL --workspace $WORKSPACE --from-scope\`"
        } >> "$RUN_LOG"
        set +e
        python3 "$INVARIANT_LEDGER_TOOL" --workspace "$WORKSPACE" --from-scope \
            >>"$RUN_LOG" 2>&1
        seed_rc=$?
        set +e 2>/dev/null || true
        {
            echo "- from-scope seed rc: $seed_rc"
        } >> "$RUN_LOG"
    else
        {
            echo "- ledger rows: $ledger_row_count (populated); skipping --from-scope seed (preserve curated rows)"
        } >> "$RUN_LOG"
    fi
    {
        echo "- ran: \`python3 $INVARIANT_LEDGER_TOOL --workspace $WORKSPACE --emit-closeout\`"
    } >> "$RUN_LOG"

    # PR #518 follow-up: capture --emit-closeout rc into emit_rc so the
    # outer step can gate ran[] / failed[] on actual subprocess success
    # rather than just step-attempted. Pre-fix this rc was logged but
    # otherwise discarded - a broken invariant-ledger.py (ImportError /
    # missing dep / malformed-JSON LedgerError) silently dropped the
    # manifest and audit-deep still claimed `ran: invariant-ledger-summary`.
    set +e
    python3 "$INVARIANT_LEDGER_TOOL" --workspace "$WORKSPACE" --emit-closeout \
        >>"$RUN_LOG" 2>&1
    emit_rc=$?
    set +e 2>/dev/null || true
    if [ "$emit_rc" -ne 0 ]; then
        echo "  (invariant-ledger emit-closeout exit $emit_rc)" >> "$RUN_LOG"
        echo "[audit-deep] FAIL: invariant-ledger --emit-closeout rc=$emit_rc; manifest NOT written" >> "$RUN_LOG"
        echo "[audit-deep] FAIL: invariant-ledger --emit-closeout rc=$emit_rc; manifest NOT written" >&2
    fi

    # Emit the deep-summary artifacts. Stdlib-only Python so no new deps.
    python3 - "$WORKSPACE" "$INVARIANT_LEDGER_MANIFEST" \
        "$INVARIANT_LEDGER_DEEP_SUMMARY_JSON" "$INVARIANT_LEDGER_DEEP_SUMMARY_MD" \
        "$LIVE" "$SCAFFOLD" <<'PY' >>"$RUN_LOG" 2>&1 || \
        echo "  (deep-summary emitter exit $?)" >> "$RUN_LOG"
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

ws_arg, manifest_p, out_json, out_md, live_flag, scaffold_flag = sys.argv[1:7]
ws = Path(ws_arg)
mp = Path(manifest_p)

manifest = {}
try:
    manifest = json.loads(mp.read_text(encoding="utf-8")) if mp.is_file() else {}
except Exception as exc:
    manifest = {"_error": f"manifest unreadable: {exc!r}"}

ledger_p = ws / ".auditooor" / "invariant_ledger.json"
rows = []
try:
    payload = json.loads(ledger_p.read_text(encoding="utf-8"))
    rows = payload.get("rows", []) if isinstance(payload, dict) else (
        payload if isinstance(payload, list) else []
    )
except Exception as exc:
    rows = []
    manifest.setdefault("_error", f"ledger unreadable: {exc!r}")

queued = []
for r in rows:
    if not isinstance(r, dict):
        continue
    target = (r.get("harness_target") or "").strip()
    if not target:
        continue
    queued.append({
        "id": r.get("id", "?"),
        "scope_asset": r.get("scope_asset", ""),
        "severity": r.get("severity"),
        "status": r.get("status", "unknown"),
        "required_engine": r.get("required_engine", "unknown"),
        "harness_target": target,
        "owner": r.get("owner", "unknown"),
    })

deep = {
    "schema": "auditooor.invariant_ledger_deep_summary.v1",
    "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "workspace": str(ws),
    "manifest_path": str(mp),
    "ledger_path": str(ledger_p),
    "live": live_flag == "1",
    "scaffold": scaffold_flag == "1",
    "harness_queue_mode": "log-only",  # Slice 5 ships logging; execution is a follow-up
    "row_count": int(manifest.get("row_count", len(rows)) or 0),
    "status_counts": manifest.get("status_counts") or {},
    "high_impact_total": int(manifest.get("high_impact_total", 0) or 0),
    "high_impact_ok": int(manifest.get("high_impact_ok", 0) or 0),
    "high_impact_missing": int(
        (manifest.get("high_impact_total", 0) or 0)
        - (manifest.get("high_impact_ok", 0) or 0)
    ),
    "issue_count": len(manifest.get("issues") or []),
    "harness_queue": queued,
}

oj = Path(out_json)
oj.parent.mkdir(parents=True, exist_ok=True)
oj.write_text(json.dumps(deep, indent=2) + "\n", encoding="utf-8")

lines = [
    "# Invariant ledger deep summary",
    "",
    f"- workspace: `{ws}`",
    f"- manifest: `{mp}`",
    f"- generated: {deep['generated']}",
    f"- row_count: {deep['row_count']}",
    f"- high_impact: {deep['high_impact_ok']}/{deep['high_impact_total']} backed by harness/replay/blocker"
    + (f" ({deep['high_impact_missing']} missing)" if deep['high_impact_missing'] else ""),
    f"- issues: {deep['issue_count']}",
    f"- live: {deep['live']}  scaffold: {deep['scaffold']}  harness_queue_mode: {deep['harness_queue_mode']}",
    "",
    "## Status counts",
    "",
]
sc = deep["status_counts"] or {}
if not sc:
    lines.append("- (none)")
else:
    for k, v in sorted(sc.items()):
        lines.append(f"- {k}: {v}")

lines += ["", "## Harness queue (rows with non-empty harness_target)", ""]
if not queued:
    lines.append("- (none)")
else:
    lines.append("| id | severity | status | engine | harness_target | owner |")
    lines.append("|---|---|---|---|---|---|")
    for q in queued:
        lines.append(
            f"| {q['id']} | {q['severity'] or '-'} | {q['status']} | "
            f"{q['required_engine']} | `{q['harness_target']}` | {q['owner']} |"
        )

lines += [
    "",
    "## Mode notes",
    "",
    f"- LIVE=1 AUDIT_DEEP_SCAFFOLD=1 currently LOGS the harness queue; actual",
    f"  Foundry/Cargo invocation is a planned follow-up (Slice 5 closes the",
    f"  silent-zero gap; harness execution lands in a later slice).",
    f"- Closeout reads `<ws>/.audit_logs/invariant_ledger_manifest.json`",
    f"  (PR #511 Slice 2 contract). This deep summary is supplemental.",
    "",
]

om = Path(out_md)
om.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"[audit-deep] invariant-ledger deep summary -> {om}")
print(f"[audit-deep] invariant-ledger deep summary -> {oj}")
PY

    if [ "$LIVE" = "1" ] && [ "$SCAFFOLD" = "1" ]; then
        {
            echo "- LIVE=1 AUDIT_DEEP_SCAFFOLD=1: harness queue logged in deep summary (no auto-invocation)"
        } >> "$RUN_LOG"
    fi

    # REQUIRE_HIGH_IMPACT_INVARIANTS escalates check rc to step failure.
    if [ "$REQUIRE_HIGH_IMPACT_INVARIANTS" = "1" ] && [ "$check_rc" -ne 0 ]; then
        INVARIANT_LEDGER_FAIL=1
        {
            echo "- FAIL: invariant-ledger check rc=$check_rc with REQUIRE_HIGH_IMPACT_INVARIANTS=1"
            echo "- effect: audit-deep step exits non-zero"
        } >> "$RUN_LOG"
        echo "[audit-deep] FAIL: invariant-ledger check rc=$check_rc (REQUIRE_HIGH_IMPACT_INVARIANTS=1)" >&2
    fi

    # PR #518 follow-up: emit_rc != 0 means manifest was NOT written.
    # The manifest is the single-source-of-truth handoff to closeout
    # (see Pointers section + audit-closeout-check.py:3155). A silent
    # emit-closeout failure breaks the wire contract Slice 5 promised
    # to close, so under EITHER strict env-var we promote it to a
    # step failure. Default mode logs FAIL but exits 0 - the failed[]
    # array preserves the signal for the closeout to read.
    if [ "$emit_rc" -ne 0 ]; then
        failed+=("invariant-ledger-summary (emit-closeout rc=$emit_rc; manifest not written)")
        if [ "$REQUIRE_INVARIANT_LEDGER" = "1" ] || [ "$REQUIRE_HIGH_IMPACT_INVARIANTS" = "1" ]; then
            INVARIANT_LEDGER_FAIL=1
            {
                echo "- FAIL: invariant-ledger --emit-closeout rc=$emit_rc with REQUIRE_INVARIANT_LEDGER=$REQUIRE_INVARIANT_LEDGER REQUIRE_HIGH_IMPACT_INVARIANTS=$REQUIRE_HIGH_IMPACT_INVARIANTS"
                echo "- effect: audit-deep step exits non-zero (manifest missing)"
            } >> "$RUN_LOG"
            echo "[audit-deep] FAIL: invariant-ledger --emit-closeout rc=$emit_rc; manifest NOT written (strict env-var)" >&2
        fi
    fi

    # PR #518 follow-up: only count invariant-ledger-summary as "ran"
    # when the underlying subprocesses succeeded. A tool crash (ImportError,
    # malformed-JSON LedgerError, etc.) lands in failed[] instead so the
    # operator-visible Summary doesn't lie about subprocess success.
    if [ "$check_rc" -eq 0 ] && [ "$emit_rc" -eq 0 ]; then
        ran+=("invariant-ledger-summary")
    elif [ "$emit_rc" -eq 0 ]; then
        # check failed (e.g. schema/artifact issues) but emit-closeout
        # still succeeded - the manifest exists and contains the issues.
        # That's a partial success: we keep ran[] truthful by recording
        # it as "(check rc=N)" so the operator sees both.
        ran+=("invariant-ledger-summary (check rc=$check_rc; manifest written)")
    fi
fi
echo >> "$RUN_LOG"

# WF-4 Patch H: fast detector runner/inventory-smoke unit-test stitch. Runs
# before Summary so pass/fail lands in ran[] / skipped[] / failed[].
run_detector_smoke_unit_tests "$RUN_LOG"

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
{
    echo "## Summary"
    echo
    echo "### Execution Truth"
    echo
    echo "| tool | state | detail |"
    echo "|---|---|---|"
    if [ "${#execution_truth[@]}" -eq 0 ]; then
        echo "| (none) | planned | no Halmos/Medusa execution path reached |"
    else
        for row in "${execution_truth[@]}"; do
            tool="${row%%|*}"
            rest="${row#*|}"
            state="${rest%%|*}"
            detail="${rest#*|}"
            echo "| $tool | $state | $detail |"
        done
    fi
    echo
    echo "- ran: ${ran[*]:-(none)}"
    echo "- skipped: ${skipped[*]:-(none)}"
    echo "- failed: ${failed[*]:-(none)}"
    echo
    echo "## Pointers"
    echo
    echo "- per-run log: \`$RUN_LOG\`"
    echo "- canonical latest: \`$REPORT\`"
    echo "- symbolic per-run manifest dir: \`$WORKSPACE/symbolic_runs/<timestamp>/manifest.json\`"
    echo "- fuzz per-run manifest dir: \`$WORKSPACE/fuzz_runs/<timestamp>/manifest.json\`"
    echo "- cosmos-backend findings: \`$WORKSPACE/.auditooor/cosmos_findings.json\` (see docs/COSMOS_BACKEND.md)"
    echo "- Go/DLT audit enforcement manifest: \`$go_dlt_enforcement_manifest\`"
    echo "- Go txid chain-truth advisory scan: \`$WORKSPACE/.auditooor/go_txid_chain_truth_scan.json\` (NOT_SUBMIT_READY)"
    echo "- Go refund/key-tweak survivability advisory scan: \`$WORKSPACE/.auditooor/go_refund_tweak_survivability_scan.json\` (NOT_SUBMIT_READY)"
    echo "- anchor-backend findings: \`$WORKSPACE/.auditooor/anchor_findings.json\` (see docs/ANCHOR_BACKEND.md)"
    echo "- reth-backend findings: \`$WORKSPACE/.auditooor/reth_findings.json\` (see docs/RETH_BACKEND.md)"
    echo "- rust source graph: \`$WORKSPACE/.auditooor/rust_source_graph.json\` (see docs/RUST_SOURCE_GRAPH.md)"
    echo "- rust cross-crate graph: \`$WORKSPACE/.auditooor/rust_cross_crate_graph.json\`"
    if [ "$(rust_named_root_count)" -gt 0 ]; then
        while IFS="$(printf '\t')" read -r slug rel_root; do
            [ -n "$slug" ] && [ -n "$rel_root" ] || continue
            echo "- declared Rust root graph ($slug from $rel_root): \`$WORKSPACE/.auditooor/rust_source_graph.$slug.json\`"
            echo "- declared Rust root cross-crate graph ($slug from $rel_root): \`$WORKSPACE/.auditooor/rust_cross_crate_graph.$slug.json\`"
        done <<EOF
$RUST_DECLARED_ROOT_SPECS
EOF
    fi
    echo "- state-root parity scaffold: \`$WORKSPACE/differential_fuzz/state_root_parity/\` (see docs/STATE_ROOT_PARITY.md)"
    echo "- invariant ledger summary: \`$INVARIANT_LEDGER_DEEP_SUMMARY_MD\` (see docs/INVARIANT_LEDGER.md)"
    echo "- invariant ledger manifest: \`$INVARIANT_LEDGER_MANIFEST\` (consumed by tools/audit-closeout-check.py)"
    echo
    echo "See \`docs/TOOL_COST_BENEFIT.md\` for the per-tool cost-benefit rubric."
} >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 13 - Novel-vector invariant mining (orphan-producer wiring; FIX 1).
#
# tools/novel-vector-invariant-miner.py derives TARGET-SPECIFIC invariants and
# is the producer that tools/audit-completeness-check.py signal (l) looks for
# at <ws>/.auditooor/novel_vector_invariants*.json. It was never invoked, so
# the gate could never be honestly satisfied. This stage discovers in-scope
# source files, runs the miner per-file (best-effort), and ALWAYS writes the
# workspace-level gate-shaped JSON at
#   <ws>/.auditooor/novel_vector_invariants.json
# with schema `auditooor.novel_vector_invariants.v1` (carries the
# `novel_vector` substring the gate matches on), honestly marking a
# 0-target run via empty_marker_written=True.
#
# Tier discipline:
#   - Tier B / advisory. Derived invariants are CANDIDATE specs; a
#     counterexample needs analyst review + a PoC before filing.
#   - rc-tolerant: never fails the deep run.
# ---------------------------------------------------------------------------
{
    echo "### Step 13 - Novel-vector invariant mining (FIX 1)"
    echo
} >> "$RUN_LOG"

NOVEL_VECTOR_TOOL="$HERE/novel-vector-invariant-miner.py"
NOVEL_VECTOR_JSON="$WORKSPACE/.auditooor/novel_vector_invariants.json"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $NOVEL_VECTOR_TOOL --workspace $WORKSPACE\` (per in-scope file)"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("novel-vector-invariant-miner (DRY_RUN=1)")
elif [ ! -f "$NOVEL_VECTOR_TOOL" ]; then
    echo "- skipped: tools/novel-vector-invariant-miner.py not present" >> "$RUN_LOG"
    skipped+=("novel-vector-invariant-miner (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("novel-vector-invariant-miner (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if AUDIT_DEEP_NV_TOOL="$NOVEL_VECTOR_TOOL" \
       AUDIT_DEEP_NV_WORKSPACE="$WORKSPACE" \
       AUDIT_DEEP_NV_OUT="$NOVEL_VECTOR_JSON" \
       python3 - >>"$RUN_LOG" 2>&1 <<'PY'
import json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

tool = Path(os.environ["AUDIT_DEEP_NV_TOOL"])
ws = Path(os.environ["AUDIT_DEEP_NV_WORKSPACE"])
out = Path(os.environ["AUDIT_DEEP_NV_OUT"])

# Discover in-scope source files (bounded). Skip vendored / build trees.
SKIP_PARTS = {"vendor", "node_modules", ".git", "lib", "out", "target",
              "third_party", "external", "test", "tests", "mocks", "mock"}
EXTS = {".sol": "solidity", ".rs": "rust", ".go": "go", ".move": "move"}
roots = [ws / "src", ws / "contracts", ws / "programs", ws]
seen = set()
targets = []
for root in roots:
    if not root.is_dir():
        continue
    for p in sorted(root.rglob("*")):
        if len(targets) >= 8:
            break
        if not p.is_file() or p.suffix not in EXTS:
            continue
        if any(part.lower() in SKIP_PARTS for part in p.parts):
            continue
        rp = p.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        targets.append((p, EXTS[p.suffix]))
    if len(targets) >= 8:
        break

per_file = []
derived_total = 0
ad = ws / ".auditooor"
ad.mkdir(parents=True, exist_ok=True)
for idx, (path, lang) in enumerate(targets):
    jsonl = ad / f"novel_vector_invariants_{idx}.jsonl"
    try:
        r = subprocess.run(
            [sys.executable, str(tool), "--workspace", str(ws),
             "--contract", str(path), "--lang", lang,
             "--output", str(jsonl)],
            capture_output=True, text=True, timeout=120,
        )
        n = 0
        if jsonl.exists():
            n = sum(1 for line in jsonl.read_text().splitlines() if line.strip())
        derived_total += n
        per_file.append({"file": str(path), "lang": lang, "rc": r.returncode,
                         "derived": n, "jsonl": str(jsonl)})
        print(f"  - {path.name} ({lang}): rc={r.returncode} derived={n}")
    except Exception as exc:  # rc-tolerant
        per_file.append({"file": str(path), "lang": lang, "error": str(exc)})
        print(f"  - {path.name} ({lang}): error {exc}")

payload = {
    "schema": "auditooor.novel_vector_invariants.v1",
    "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "workspace": str(ws.resolve()),
    "tool": str(tool),
    "advisory_only": True,
    "target_repo_count": len(targets),
    "derived_invariant_count": derived_total,
    "empty_marker_written": len(targets) == 0,
    "per_file": per_file,
}
out.write_text(json.dumps(payload, indent=2) + "\n")
print(f"  novel_vector_invariants.json written: targets={len(targets)} derived={derived_total}")
PY
    then
        ran+=("novel-vector-invariant-miner")
        echo "- output: \`$NOVEL_VECTOR_JSON\` (schema auditooor.novel_vector_invariants.v1)" >> "$RUN_LOG"
    else
        echo "- WARN: novel-vector stage exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("novel-vector-invariant-miner (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 14 - Chain-synthesis hunt-time stage (orphan-producer wiring; FIX 2).
#
# tools/chain-synthesizer-hunt-time.py synthesizes compound attack chains and
# emits records carrying schema id `auditooor.chain_synthesized.v1`. That is
# the citation source tools/r73-chain-derived-check.py + pre-submit-check.sh
# require a draft to reference. The producer was never run, so the gate could
# not be honestly satisfied. This stage runs it, writing JSONL into
#   <ws>/.auditooor/chain_synthesized.jsonl
#
# Tier discipline: Tier B / advisory; chains are CANDIDATE paths needing
# source verification + a PoC before filing. rc-tolerant.
# ---------------------------------------------------------------------------
{
    echo "### Step 14 - Chain-synthesis hunt-time stage (FIX 2)"
    echo
} >> "$RUN_LOG"

CHAIN_SYNTH_TOOL="$HERE/chain-synthesizer-hunt-time.py"
CHAIN_SYNTH_JSONL="$WORKSPACE/.auditooor/chain_synthesized.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $CHAIN_SYNTH_TOOL --workspace $WORKSPACE --output $CHAIN_SYNTH_JSONL\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("chain-synthesizer-hunt-time (DRY_RUN=1)")
elif [ ! -f "$CHAIN_SYNTH_TOOL" ]; then
    echo "- skipped: tools/chain-synthesizer-hunt-time.py not present" >> "$RUN_LOG"
    skipped+=("chain-synthesizer-hunt-time (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("chain-synthesizer-hunt-time (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$CHAIN_SYNTH_TOOL" --workspace "$WORKSPACE" --output "$CHAIN_SYNTH_JSONL" >>"$RUN_LOG" 2>&1; then
        ran+=("chain-synthesizer-hunt-time")
        echo "- output: \`$CHAIN_SYNTH_JSONL\` (schema auditooor.chain_synthesized.v1 - r73 citation source)" >> "$RUN_LOG"
    else
        echo "- WARN: chain-synthesis stage exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("chain-synthesizer-hunt-time (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 15 - Fork-divergence hunt stage (orphan-producer wiring; FIX 3).
#
# tools/fork-divergence-hunt-stage.py emits not-backported upstream security
# commits as proof-obligation-queue tasks and stamps a `fork_divergence_last_run`
# marker on <ws>/.auditooor/proof_obligation_queue.json - the artifact
# tools/audit-completeness-check.py signal (k) credits for fork / vendored
# targets. The producer was never invoked, so fork targets always failed the
# gate. This stage detects whether the workspace is a fork / vendored target
# (mirroring the gate's _detect_fork heuristic) and runs the producer only
# then; non-fork workspaces skip cleanly. The tool itself also no-ops with
# verdict `not-a-fork` if our heuristic over-fires.
#
# Tier discipline: Tier B / advisory; queued leads need source verification +
# a PoC before filing. rc-tolerant.
# ---------------------------------------------------------------------------
{
    echo "### Step 15 - Fork-divergence hunt stage (FIX 3)"
    echo
} >> "$RUN_LOG"

FORK_DIVERGENCE_TOOL="$HERE/fork-divergence-hunt-stage.py"
# Fork / vendored detection mirroring audit-completeness-check.py _detect_fork:
# pinned git rev / git dep in Cargo.toml, replace/pseudo-version in go.mod, a
# non-empty vendored upstream tree, or an explicit fork marker file.
AUDIT_DEEP_IS_FORK=0
AUDIT_DEEP_FORK_REASON=""
for _cargo in "$WORKSPACE/Cargo.toml" "$WORKSPACE/src/Cargo.toml"; do
    [ -f "$_cargo" ] || continue
    if grep -Eq 'git[[:space:]]*=.*(rev|tag|branch)[[:space:]]*=' "$_cargo" 2>/dev/null \
       || grep -Eq '^[[:space:]]*rev[[:space:]]*=' "$_cargo" 2>/dev/null; then
        AUDIT_DEEP_IS_FORK=1; AUDIT_DEEP_FORK_REASON="Cargo.toml pinned git rev/dep"; break
    fi
done
if [ "$AUDIT_DEEP_IS_FORK" = "0" ]; then
    for _gomod in "$WORKSPACE/go.mod" "$WORKSPACE/src/go.mod"; do
        [ -f "$_gomod" ] || continue
        if grep -Eq '^[[:space:]]*replace[[:space:]]' "$_gomod" 2>/dev/null \
           || grep -Eq '\-[0-9]{14}-[0-9a-f]{12}' "$_gomod" 2>/dev/null; then
            AUDIT_DEEP_IS_FORK=1; AUDIT_DEEP_FORK_REASON="go.mod replace/pseudo-version"; break
        fi
    done
fi
if [ "$AUDIT_DEEP_IS_FORK" = "0" ]; then
    for _vend in vendor third_party external; do
        if [ -d "$WORKSPACE/$_vend" ] && [ -n "$(ls -A "$WORKSPACE/$_vend" 2>/dev/null)" ]; then
            AUDIT_DEEP_IS_FORK=1; AUDIT_DEEP_FORK_REASON="vendored upstream tree: $_vend/"; break
        fi
    done
fi
if [ "$AUDIT_DEEP_IS_FORK" = "0" ]; then
    for _marker in "FORK_OF.txt" ".auditooor/fork_target.json" "FORK.md"; do
        if [ -e "$WORKSPACE/$_marker" ]; then
            AUDIT_DEEP_IS_FORK=1; AUDIT_DEEP_FORK_REASON="explicit fork marker: $_marker"; break
        fi
    done
fi

if [ "$AUDIT_DEEP_IS_FORK" != "1" ]; then
    echo "- skipped: workspace is not a detected fork / vendored target (non-fork targets skip cleanly)" >> "$RUN_LOG"
    skipped+=("fork-divergence-hunt-stage (not a fork target)")
elif [ "$DRY_RUN" = "1" ]; then
    {
        echo "- detected fork target: $AUDIT_DEEP_FORK_REASON"
        echo "- planned: \`python3 $FORK_DIVERGENCE_TOOL --workspace $WORKSPACE --emit-queue\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("fork-divergence-hunt-stage (DRY_RUN=1)")
elif [ ! -f "$FORK_DIVERGENCE_TOOL" ]; then
    echo "- skipped: tools/fork-divergence-hunt-stage.py not present" >> "$RUN_LOG"
    skipped+=("fork-divergence-hunt-stage (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("fork-divergence-hunt-stage (python3 missing)")
else
    echo "- detected fork target: $AUDIT_DEEP_FORK_REASON" >> "$RUN_LOG"
    mkdir -p "$WORKSPACE/.auditooor"
    # --out persists the full hunt-stage payload (incl. the resolved
    # `upstream_clone` key) so the D5 sub-stage below can reuse the same clone
    # discovery for its stage-2 ancestry verify instead of re-discovering it.
    if python3 "$FORK_DIVERGENCE_TOOL" --workspace "$WORKSPACE" --emit-queue \
         --out "$WORKSPACE/.auditooor/fork_divergence_hunt_stage.json" >>"$RUN_LOG" 2>&1; then
        ran+=("fork-divergence-hunt-stage")
        echo "- output: \`$WORKSPACE/.auditooor/proof_obligation_queue.json\` (fork_divergence_last_run marker)" >> "$RUN_LOG"
    else
        echo "- WARN: fork-divergence stage exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("fork-divergence-hunt-stage (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 15b - Fork pseudo-version mislabel (D5).
#
# tools/fork-pseudo-version-mislabel.py detects go.mod `replace` pseudo-version
# entries (vX.Y.Z-0.<ts>-<sha12>) whose version prefix claims lineage from one
# upstream tag while the embedded SHA may descend from a different tag (a fork
# mislabel that hides which upstream code is actually vendored). It was a
# standalone detector never invoked by the pipeline, so on fork targets it sat
# unwired. This sub-stage runs it whenever Step 15 detected a fork target,
# reusing Step 15's resolved upstream clone (from the hunt-stage sidecar) for
# the stage-2 `--verify` ancestry check when one is available; otherwise it
# emits the stage-1 offline scan (needs_verification=true), which is advisory.
#
# Tier discipline: Tier B / advisory. The detector returns rc 0 even when it
# flags entries, so it never fails the deep run. Skips cleanly on non-fork /
# DRY_RUN / tool-missing / python3-missing, mirroring Step 15's guard branches.
# ---------------------------------------------------------------------------
{
    echo "### Step 15b - Fork pseudo-version mislabel (D5)"
    echo
} >> "$RUN_LOG"

D5_TOOL="$HERE/fork-pseudo-version-mislabel.py"
if [ "$AUDIT_DEEP_IS_FORK" != "1" ]; then
    echo "- skipped: workspace is not a detected fork / vendored target" >> "$RUN_LOG"
    skipped+=("fork-pseudo-version-mislabel (not a fork target)")
elif [ "$DRY_RUN" = "1" ]; then
    {
        echo "- detected fork target: $AUDIT_DEEP_FORK_REASON"
        echo "- planned: \`python3 $D5_TOOL <go.mod> --out $WORKSPACE/.auditooor/fork_pseudo_version_mislabel.json\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("fork-pseudo-version-mislabel (DRY_RUN=1)")
elif [ ! -f "$D5_TOOL" ]; then
    echo "- skipped: tools/fork-pseudo-version-mislabel.py not present" >> "$RUN_LOG"
    skipped+=("fork-pseudo-version-mislabel (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("fork-pseudo-version-mislabel (python3 missing)")
else
    # Reuse the upstream clone Step 15 already resolved (written to the
    # hunt-stage sidecar under the `upstream_clone` key). When present and a
    # git repo, run stage-2 verify; otherwise stage-1 offline is acceptable.
    D5_UPSTREAM_CLONE=""
    _d5_sidecar="$WORKSPACE/.auditooor/fork_divergence_hunt_stage.json"
    if [ -f "$_d5_sidecar" ]; then
        D5_UPSTREAM_CLONE="$(python3 - "$_d5_sidecar" <<'PYEOF' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    c = d.get("upstream_clone") or ""
    print(c)
except Exception:
    print("")
PYEOF
)"
    fi
    mkdir -p "$WORKSPACE/.auditooor"
    _d5_out="$WORKSPACE/.auditooor/fork_pseudo_version_mislabel.json"
    _d5_any=0
    _d5_ran=0
    for _gomod in "$WORKSPACE/go.mod" "$WORKSPACE/src/go.mod"; do
        [ -f "$_gomod" ] || continue
        _d5_any=1
        d5_args=("$_gomod" --out "$_d5_out")
        if [ -n "$D5_UPSTREAM_CLONE" ] && [ -d "$D5_UPSTREAM_CLONE/.git" ]; then
            d5_args+=(--verify --upstream-clone "$D5_UPSTREAM_CLONE")
            echo "- $_gomod: stage-2 verify against upstream clone $D5_UPSTREAM_CLONE" >> "$RUN_LOG"
        else
            echo "- $_gomod: stage-1 offline scan (no upstream clone; needs_verification=true, advisory)" >> "$RUN_LOG"
        fi
        if python3 "$D5_TOOL" "${d5_args[@]}" >>"$RUN_LOG" 2>&1; then
            _d5_ran=1
            echo "- output: \`$_d5_out\`" >> "$RUN_LOG"
        else
            echo "- WARN: fork-pseudo-version-mislabel exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        fi
    done
    if [ "$_d5_any" = "0" ]; then
        echo "- skipped: no go.mod at \$WORKSPACE/go.mod or \$WORKSPACE/src/go.mod" >> "$RUN_LOG"
        skipped+=("fork-pseudo-version-mislabel (no go.mod)")
    elif [ "$_d5_ran" = "1" ]; then
        ran+=("fork-pseudo-version-mislabel")
    else
        skipped+=("fork-pseudo-version-mislabel (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 16 - Economic attack-hypothesis enumeration (orphan-producer wiring;
# FIX 1).
#
# tools/economic-hypotheses.sh (grep-based, stdlib-only - no slither dep) and
# its IR sibling tools/economic-hypotheses-ir.py enumerate the economic attack
# surface (oracle reads, flashloan callbacks, rate/rounding math, LP-share
# math, slippage/deadline guards) per Solidity contract. Neither producer was
# ever invoked by the pipeline, so its output was an orphan and never reached
# the hunt/MIMO briefs. This stage runs economic-hypotheses.sh per in-scope
# .sol file (best-effort, bounded), and ALWAYS writes the workspace-level
# JSON the brief injector consumes at
#   <ws>/.auditooor/economic_hypotheses.json
# (schema auditooor.economic_hypotheses.v1). The per-file markdown the .sh
# emits is preserved under <ws>/economic_hypotheses/ as before.
#
# Tier discipline: Tier B / advisory. The enumeration NARROWS the surface; it
# does NOT declare findings. rc-tolerant: never fails the deep run.
# ---------------------------------------------------------------------------
{
    echo "### Step 16 - Economic attack-hypothesis enumeration (FIX 1)"
    echo
} >> "$RUN_LOG"

ECON_HYP_TOOL="$HERE/economic-hypotheses.sh"
ECON_HYP_JSON="$WORKSPACE/.auditooor/economic_hypotheses.json"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`bash $ECON_HYP_TOOL <in-scope .sol>\` (per file) -> \`$ECON_HYP_JSON\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("economic-hypotheses (DRY_RUN=1)")
elif [ ! -f "$ECON_HYP_TOOL" ]; then
    echo "- skipped: tools/economic-hypotheses.sh not present" >> "$RUN_LOG"
    skipped+=("economic-hypotheses (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("economic-hypotheses (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if AUDIT_DEEP_ECON_TOOL="$ECON_HYP_TOOL" \
       AUDIT_DEEP_ECON_WORKSPACE="$WORKSPACE" \
       AUDIT_DEEP_ECON_OUT="$ECON_HYP_JSON" \
       python3 - >>"$RUN_LOG" 2>&1 <<'PY'
import json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

tool = Path(os.environ["AUDIT_DEEP_ECON_TOOL"])
ws = Path(os.environ["AUDIT_DEEP_ECON_WORKSPACE"])
out = Path(os.environ["AUDIT_DEEP_ECON_OUT"])

# Discover in-scope Solidity files (bounded). Skip vendored / build / test trees.
SKIP_PARTS = {"vendor", "node_modules", ".git", "lib", "out", "target",
              "third_party", "external", "test", "tests", "mocks", "mock",
              "cache", "script", "scripts"}
roots = [ws / "src", ws / "contracts", ws]
seen = set()
targets = []
for root in roots:
    if not root.is_dir():
        continue
    for p in sorted(root.rglob("*.sol")):
        if len(targets) >= 12:
            break
        if not p.is_file():
            continue
        if any(part.lower() in SKIP_PARTS for part in p.parts):
            continue
        rp = p.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        targets.append(p)
    if len(targets) >= 12:
        break

per_file = []
md_total = 0
for path in targets:
    try:
        r = subprocess.run(
            ["bash", str(tool), str(path)],
            capture_output=True, text=True, timeout=120,
        )
        # Default output path: <contract-dir>/economic_hypotheses/<basename>.md
        md = path.parent / "economic_hypotheses" / (path.stem + ".md")
        md_exists = md.exists()
        if md_exists:
            md_total += 1
        per_file.append({"file": str(path), "rc": r.returncode,
                         "markdown": str(md), "markdown_written": md_exists})
        print(f"  - {path.name}: rc={r.returncode} markdown_written={md_exists}")
    except Exception as exc:  # rc-tolerant
        per_file.append({"file": str(path), "error": str(exc)})
        print(f"  - {path.name}: error {exc}")

payload = {
    "schema": "auditooor.economic_hypotheses.v1",
    "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "workspace": str(ws.resolve()),
    "tool": str(tool),
    "advisory_only": True,
    "target_file_count": len(targets),
    "markdown_written_count": md_total,
    "empty_marker_written": len(targets) == 0,
    "per_file": per_file,
}
out.write_text(json.dumps(payload, indent=2) + "\n")
print(f"  economic_hypotheses.json written: targets={len(targets)} markdown={md_total}")
PY
    then
        ran+=("economic-hypotheses")
        echo "- output: \`$ECON_HYP_JSON\` (schema auditooor.economic_hypotheses.v1; injected into hunt/MIMO briefs)" >> "$RUN_LOG"
    else
        echo "- WARN: economic-hypotheses stage exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("economic-hypotheses (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 17 - Per-chain blast-radius enumeration (orphan-producer wiring; FIX 2).
#
# tools/per-chain-blast-radius-enumerator.py enumerates every additional chain
# / consensus-client / configuration that ALSO routes through an affected
# component via register_*/set_*/add_*/addClient*/registerChain* call sites.
# It was orphan + siloed (only reachable via an explicit --filed-finding-path).
# This stage runs it advisory at hunt time, ONLY for cross-chain / bridge
# targets (workspaces whose source tree actually contains chain-registration
# anchors), and writes a workspace-level summary at
#   <ws>/.auditooor/per_chain_blast_radius/_workspace_summary.json
# so the surface exists pre-finding and the briefs can surface it when a unit
# is cross-chain. The producer's run() is called directly against the
# workspace source tree (no specific finding required).
#
# Tier discipline: Tier B / advisory. rc-tolerant.
# ---------------------------------------------------------------------------
{
    echo "### Step 17 - Per-chain blast-radius enumeration (FIX 2)"
    echo
} >> "$RUN_LOG"

PER_CHAIN_TOOL="$HERE/per-chain-blast-radius-enumerator.py"
PER_CHAIN_JSON="$WORKSPACE/.auditooor/per_chain_blast_radius/_workspace_summary.json"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $PER_CHAIN_TOOL\` (workspace-level cross-chain enumeration) -> \`$PER_CHAIN_JSON\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("per-chain-blast-radius (DRY_RUN=1)")
elif [ ! -f "$PER_CHAIN_TOOL" ]; then
    echo "- skipped: tools/per-chain-blast-radius-enumerator.py not present" >> "$RUN_LOG"
    skipped+=("per-chain-blast-radius (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("per-chain-blast-radius (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor/per_chain_blast_radius"
    if AUDIT_DEEP_PCB_TOOL="$PER_CHAIN_TOOL" \
       AUDIT_DEEP_PCB_WORKSPACE="$WORKSPACE" \
       AUDIT_DEEP_PCB_OUT="$PER_CHAIN_JSON" \
       python3 - >>"$RUN_LOG" 2>&1 <<'PY'
import importlib.util, json, os, sys
from datetime import datetime, timezone
from pathlib import Path

tool = Path(os.environ["AUDIT_DEEP_PCB_TOOL"])
ws = Path(os.environ["AUDIT_DEEP_PCB_WORKSPACE"])
out = Path(os.environ["AUDIT_DEEP_PCB_OUT"])

spec = importlib.util.spec_from_file_location("per_chain_blast", str(tool))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Workspace-level enumeration: grep the source tree for registration anchors +
# chain tokens directly (no specific finding). A cross-chain target has >=1
# registration anchor; non-cross-chain targets get an honest empty summary.
src_root = ws / "src" if (ws / "src").is_dir() else ws
anchors, chains, warnings = mod.grep_registrations(src_root, None)
is_cross_chain = len(anchors) > 0 or len(chains) > 0

payload = {
    "schema_version": "auditooor.per_chain_blast_radius.v1",
    "scope": "workspace-summary",
    "workspace": str(ws.resolve()),
    "tool": str(tool),
    "advisory_only": True,
    "is_cross_chain_target": is_cross_chain,
    "registration_anchor_count": len(anchors),
    "registration_anchors": anchors[:50],
    "registered_chains": chains,
    "blast_radius_count": max(0, len(chains) - 1) if chains else 0,
    "warnings": warnings,
    "generated_at": datetime.now(timezone.utc).isoformat(),
}
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print(f"  per_chain_blast_radius summary: cross_chain={is_cross_chain} "
      f"anchors={len(anchors)} chains={len(chains)}")
PY
    then
        ran+=("per-chain-blast-radius")
        echo "- output: \`$PER_CHAIN_JSON\` (schema auditooor.per_chain_blast_radius.v1; cross-chain summary, injected into briefs when unit is cross-chain)" >> "$RUN_LOG"
    else
        echo "- WARN: per-chain-blast-radius stage exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("per-chain-blast-radius (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 18 - Proof-obligation queue (dead-queue wiring; FIX 3).
#
# tools/proof-obligation-queue.py builds bounded proof-task rows from the
# hacker brief / detector action graph / chained-attack plans and writes
#   <ws>/.auditooor/proof_obligation_queue.json
# Standalone (make proof-obligation-queue) was the ONLY producer; nothing in
# the audit-deep / audit execution plane ran it, so the queue that
# fork-divergence signal (k) and detector-proof routing reference was never
# produced as part of a documented run.
#
# Ordering note: Step 15 (fork-divergence) STAMPS a fork_divergence_last_run
# marker onto THIS SAME file for detected fork targets via --emit-queue. To
# avoid clobbering that marker, this stage runs ONLY when the workspace is NOT
# a detected fork (AUDIT_DEEP_IS_FORK != 1, computed in Step 15). Fork targets
# already get the queue from Step 15.
#
# Tier discipline: Tier B / advisory; rows need concrete source/PoC proof
# before submission. rc-tolerant.
# ---------------------------------------------------------------------------
{
    echo "### Step 18 - Proof-obligation queue (FIX 3)"
    echo
} >> "$RUN_LOG"

PROOF_OBLIGATION_TOOL="$HERE/proof-obligation-queue.py"
PROOF_OBLIGATION_JSON="$WORKSPACE/.auditooor/proof_obligation_queue.json"
if [ "${AUDIT_DEEP_IS_FORK:-0}" = "1" ]; then
    echo "- skipped: fork target; Step 15 fork-divergence already emitted the proof-obligation queue (avoids clobbering fork_divergence_last_run marker)" >> "$RUN_LOG"
    skipped+=("proof-obligation-queue (fork target; emitted by Step 15)")
elif [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $PROOF_OBLIGATION_TOOL --workspace $WORKSPACE --out $PROOF_OBLIGATION_JSON\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("proof-obligation-queue (DRY_RUN=1)")
elif [ ! -f "$PROOF_OBLIGATION_TOOL" ]; then
    echo "- skipped: tools/proof-obligation-queue.py not present" >> "$RUN_LOG"
    skipped+=("proof-obligation-queue (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("proof-obligation-queue (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$PROOF_OBLIGATION_TOOL" --workspace "$WORKSPACE" --out "$PROOF_OBLIGATION_JSON" >>"$RUN_LOG" 2>&1; then
        ran+=("proof-obligation-queue")
        echo "- output: \`$PROOF_OBLIGATION_JSON\` (referenced by fork-divergence signal k + detector-proof routing)" >> "$RUN_LOG"
    else
        echo "- WARN: proof-obligation-queue stage exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("proof-obligation-queue (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 19 - Detector proof/fixture-gap queue (dead-queue wiring; FIX 4).
#
# tools/detector-proof-gap-queue.py emits the detector proof/fixture gap queue
# that feeds the detector-proof briefs. Standalone (make detector-proof-gap-queue)
# was the ONLY producer; the audit execution plane never ran it, so the queue
# was a dead artifact no run reached. This stage runs it advisory and writes a
# per-workspace copy at
#   <ws>/.audit_logs/detector_proof_gap_queue.json (+ .md)
# It builds a fresh inventory from the repo root (the detector arsenal lives in
# the repo, not the workspace) so the queue reflects the live detector set.
#
# Tier discipline: Tier B / advisory. rc-tolerant; bounded by the tool's own
# section/full-throttle limits.
# ---------------------------------------------------------------------------
{
    echo "### Step 19 - Detector proof/fixture-gap queue (FIX 4)"
    echo
} >> "$RUN_LOG"

DETECTOR_PROOF_GAP_TOOL="$HERE/detector-proof-gap-queue.py"
DETECTOR_PROOF_GAP_JSON="$LOG_DIR/detector_proof_gap_queue.json"
DETECTOR_PROOF_GAP_MD="$LOG_DIR/detector_proof_gap_queue.md"
if [ "${SKIP_DETECTOR_PROOF_GAP:-0}" = "1" ]; then
    echo "- skipped: SKIP_DETECTOR_PROOF_GAP=1 (caller opted out)" >> "$RUN_LOG"
    skipped+=("detector-proof-gap-queue (SKIP_DETECTOR_PROOF_GAP=1)")
elif [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $DETECTOR_PROOF_GAP_TOOL --repo-root $REPO_ROOT --refresh-from-repo --json-out $DETECTOR_PROOF_GAP_JSON --md-out $DETECTOR_PROOF_GAP_MD\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("detector-proof-gap-queue (DRY_RUN=1)")
elif [ ! -f "$DETECTOR_PROOF_GAP_TOOL" ]; then
    echo "- skipped: tools/detector-proof-gap-queue.py not present" >> "$RUN_LOG"
    skipped+=("detector-proof-gap-queue (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("detector-proof-gap-queue (python3 missing)")
else
    if python3 "$DETECTOR_PROOF_GAP_TOOL" \
        --repo-root "$REPO_ROOT" \
        --refresh-from-repo \
        --json-out "$DETECTOR_PROOF_GAP_JSON" \
        --md-out "$DETECTOR_PROOF_GAP_MD" >>"$RUN_LOG" 2>&1; then
        ran+=("detector-proof-gap-queue")
        echo "- output: \`$DETECTOR_PROOF_GAP_JSON\` (+ .md) - feeds detector-proof briefs" >> "$RUN_LOG"
    else
        echo "- WARN: detector-proof-gap-queue stage exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("detector-proof-gap-queue (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 20 - Value-moving function enumeration (VMF prereq for Steps 21-23).
#
# tools/value-moving-functions.py walks every in-scope source file and emits
#   <ws>/.auditooor/value_moving_functions.json
# This artifact is the shared input for VCIS (Step 21), SADL (Step 22), and
# CRC (Step 23), and is consumed by audit-honesty-check.py PATH 2 (the
# hollow-per-function-harnesses gate). Running it here - before VCIS/SADL/CRC
# - is the correct topological position: fast (stdlib-only, no LLM, no
# engine), additive, idempotent (already skips OOS paths), and rc-tolerant.
# Guarded by DRY_RUN and python3 availability, same as every other step.
# ---------------------------------------------------------------------------
{
    echo "### Step 20 - Value-moving function enumeration (VMF prereq)"
    echo
} >> "$RUN_LOG"

VMF_TOOL="$HERE/value-moving-functions.py"
VMF_JSON="$WORKSPACE/.auditooor/value_moving_functions.json"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $VMF_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("value-moving-functions (DRY_RUN=1)")
elif [ ! -f "$VMF_TOOL" ]; then
    echo "- skipped: tools/value-moving-functions.py not present" >> "$RUN_LOG"
    skipped+=("value-moving-functions (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("value-moving-functions (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$VMF_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("value-moving-functions")
        echo "- output: \`$VMF_JSON\` (feeds Steps 21/22/23 + audit-honesty-check PATH 2)" >> "$RUN_LOG"
    else
        echo "- WARN: value-moving-functions exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("value-moving-functions (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 21 - Value-Conservation Invariant Synthesis (VCIS).
#
# tools/value-conservation-invariant-synth.py reads value_moving_functions.json
# and emits <ws>/.auditooor/vcis/  (Properties_VCIS.sol, medusa.json,
# echidna.yaml, vcis_manifest.json).
#
# Every entry in vcis_manifest.json carries verdict="needs-fuzz". The harnesses
# remain needs-fuzz until the mutation-verify step kills a planted mutant.
# This step is OFFLINE + FAST (no engine execution); the medusa/echidna RUN is
# the existing LIVE step. The vcis_manifest.json is registered with the
# mutation-verify coverage file via Step 21b below so a real fuzz+mutation pass
# can credit per_function_verified (no auto-credit here).
# ---------------------------------------------------------------------------
{
    echo "### Step 21 - Value-Conservation Invariant Synthesis (VCIS)"
    echo
} >> "$RUN_LOG"

VCIS_TOOL="$HERE/value-conservation-invariant-synth.py"
VCIS_DIR="$WORKSPACE/.auditooor/vcis"
VCIS_MANIFEST="$VCIS_DIR/vcis_manifest.json"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $VCIS_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("vcis (DRY_RUN=1)")
elif [ ! -f "$VCIS_TOOL" ]; then
    echo "- skipped: tools/value-conservation-invariant-synth.py not present" >> "$RUN_LOG"
    skipped+=("vcis (tool missing)")
elif [ ! -f "$VMF_JSON" ]; then
    echo "- skipped: value_moving_functions.json absent (Step 20 must have been skipped)" >> "$RUN_LOG"
    skipped+=("vcis (vmf-json missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("vcis (python3 missing)")
else
    mkdir -p "$VCIS_DIR"
    if python3 "$VCIS_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("vcis")
        echo "- output: \`$VCIS_DIR\` (harnesses + vcis_manifest.json, all verdict=needs-fuzz)" >> "$RUN_LOG"
        # Step 21b: register VCIS harnesses with the mutation-verify coverage
        # sidecar so the LIVE medusa/echidna pass can credit per_function_verified.
        # We append a vcis_registration block into
        #   <ws>/.auditooor/mutation_verify_coverage.json
        # (creating or patching the file) so mutation-verify-coverage.py's
        # --discover-vcis flag can locate the harnesses.  All entries remain
        # verdict=needs-fuzz until an actual fuzz+mutation run kills a mutant.
        # This is an additive metadata-only write; it does NOT set any count
        # above zero and does NOT flip any gate.
        MUTATION_VERIFY_COVERAGE="$WORKSPACE/.auditooor/mutation_verify_coverage.json"
        python3 - "$VCIS_MANIFEST" "$MUTATION_VERIFY_COVERAGE" >> "$RUN_LOG" 2>&1 <<'PYEOF'
import json, os, sys, pathlib
vcis_manifest_path = pathlib.Path(sys.argv[1])
mvc_path = pathlib.Path(sys.argv[2])
try:
    manifest = json.loads(vcis_manifest_path.read_text(encoding="utf-8"))
except Exception as e:
    print(f"WARN: could not read vcis_manifest.json: {e}")
    sys.exit(0)
verdicts = manifest.get("verdicts", [])
if not verdicts:
    print("NOTE: vcis_manifest has no verdicts - nothing to register")
    sys.exit(0)
existing = {}
if mvc_path.is_file():
    try:
        existing = json.loads(mvc_path.read_text(encoding="utf-8"))
    except Exception:
        existing = {}
if not isinstance(existing, dict):
    existing = {}
# Merge under a top-level "vcis_registration" key.
# ALL entries carry verdict=needs-fuzz - no auto-credit.
reg = existing.get("vcis_registration") or {}
for v in verdicts:
    key = f"{v.get('file','?')}::{v.get('function','?')}"
    if key not in reg:
        reg[key] = {
            "file": v.get("file"),
            "function": v.get("function"),
            "property_form": v.get("property_form"),
            "harness_path": str(vcis_manifest_path.parent / "Properties_VCIS.sol"),
            "verdict": "needs-fuzz",
            "note": "registered by audit-deep Step 21b; run mutation-verify-coverage.py to earn genuine credit",
        }
existing["vcis_registration"] = reg
# counts block: never increment per_function_verified here (no-auto-credit rule).
counts = existing.get("counts") or {}
if "per_function_verified" not in counts:
    counts["per_function_verified"] = 0
if "vcis_registered" not in counts:
    counts["vcis_registered"] = 0
counts["vcis_registered"] = len(reg)
existing["counts"] = counts
existing.setdefault("schema", "auditooor.mutation_verify_coverage.v1")
mvc_path.parent.mkdir(parents=True, exist_ok=True)
mvc_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
print(f"NOTE: registered {len(reg)} VCIS harness(es) in mutation_verify_coverage.json (all needs-fuzz)")
PYEOF
    else
        echo "- WARN: vcis exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("vcis (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 22 - Self-Dealing / Identity-Collapse Hypothesis Lane (SADL).
#
# tools/self-dealing-hypothesis-lane.py reads value_moving_functions.json and
# emits <ws>/.auditooor/self_dealing_hypotheses.jsonl  (one record per
# address-param collapse pair per value-moving function).
#
# Every record carries attack_class="self-dealing-identity-collapse" and
# verdict="needs-fuzz".  The hypothesis corpus is FOLDED into
# per_fn_hacker_questions.jsonl by auto-coverage-closer.py so the hunt sees
# these as fuel.  SADL never auto-credits any gate.
# ---------------------------------------------------------------------------
{
    echo "### Step 22 - Self-Dealing / Identity-Collapse Hypothesis Lane (SADL)"
    echo
} >> "$RUN_LOG"

SADL_TOOL="$HERE/self-dealing-hypothesis-lane.py"
SADL_JSONL="$WORKSPACE/.auditooor/self_dealing_hypotheses.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $SADL_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("sadl (DRY_RUN=1)")
elif [ ! -f "$SADL_TOOL" ]; then
    echo "- skipped: tools/self-dealing-hypothesis-lane.py not present" >> "$RUN_LOG"
    skipped+=("sadl (tool missing)")
elif [ ! -f "$VMF_JSON" ]; then
    echo "- skipped: value_moving_functions.json absent (Step 20 must have been skipped)" >> "$RUN_LOG"
    skipped+=("sadl (vmf-json missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("sadl (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$SADL_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("sadl")
        echo "- output: \`$SADL_JSONL\` (verdict=needs-fuzz; folded into per_fn_hacker_questions by auto-coverage-closer)" >> "$RUN_LOG"
    else
        echo "- WARN: sadl exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("sadl (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 23 - Callback-before-Settlement / Reentrancy Composition Lane (CRC).
#
# tools/callback-reentrancy-composition.py reads value_moving_functions.json
# and emits <ws>/.auditooor/callback_reentrancy_hypotheses.jsonl (one record
# per (callback-window fn, reentry-target fn) pair).
#
# Every record carries attack_class="reentrancy-into-settlement" and
# verdict="needs-fuzz".  The hypothesis corpus is FOLDED into
# per_fn_hacker_questions.jsonl by auto-coverage-closer.py.  CRC never
# auto-credits any gate.
# ---------------------------------------------------------------------------
{
    echo "### Step 23 - Callback-before-Settlement / Reentrancy Composition Lane (CRC)"
    echo
} >> "$RUN_LOG"

CRC_TOOL="$HERE/callback-reentrancy-composition.py"
CRC_JSONL="$WORKSPACE/.auditooor/callback_reentrancy_hypotheses.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $CRC_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("crc (DRY_RUN=1)")
elif [ ! -f "$CRC_TOOL" ]; then
    echo "- skipped: tools/callback-reentrancy-composition.py not present" >> "$RUN_LOG"
    skipped+=("crc (tool missing)")
elif [ ! -f "$VMF_JSON" ]; then
    echo "- skipped: value_moving_functions.json absent (Step 20 must have been skipped)" >> "$RUN_LOG"
    skipped+=("crc (vmf-json missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("crc (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$CRC_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("crc")
        echo "- output: \`$CRC_JSONL\` (verdict=needs-fuzz; folded into per_fn_hacker_questions by auto-coverage-closer)" >> "$RUN_LOG"
    else
        echo "- WARN: crc exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("crc (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# Step 24 - Share-Inflation / Donation-Attack Hypothesis Lane (SIDL).
#
# tools/share-inflation-lane.py reads the workspace source tree and emits:
#   <ws>/.auditooor/share_inflation_hypotheses.jsonl  - one record per
#       deposit/mint fn per attack class (donation + first-depositor);
#       every record carries verdict=needs-fuzz.
#   <ws>/.auditooor/share_inflation_invariants.jsonl  - SHARE-PRICE-INTEGRITY
#       invariant specs for the fuzzer oracle.
#
# The hypothesis corpus is FOLDED into per_fn_hacker_questions.jsonl by
# auto-coverage-closer.py.  SIDL never auto-credits any gate.
# ---------------------------------------------------------------------------
{
    echo "### Step 24 - Share-Inflation / Donation-Attack Hypothesis Lane (SIDL)"
    echo
} >> "$RUN_LOG"

SIDL_TOOL="$HERE/share-inflation-lane.py"
SIDL_JSONL="$WORKSPACE/.auditooor/share_inflation_hypotheses.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $SIDL_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("sidl (DRY_RUN=1)")
elif [ ! -f "$SIDL_TOOL" ]; then
    echo "- skipped: tools/share-inflation-lane.py not present" >> "$RUN_LOG"
    skipped+=("sidl (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("sidl (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$SIDL_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("sidl")
        echo "- output: \`$SIDL_JSONL\` (verdict=needs-fuzz; folded into per_fn_hacker_questions by auto-coverage-closer)" >> "$RUN_LOG"
    else
        echo "- WARN: sidl exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("sidl (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# Step 25 - Oracle Price Reachability Lane (ORL).
#
# tools/oracle-reachability-lane.py reads the workspace source tree and emits:
#   <ws>/.auditooor/oracle_reachability_hypotheses.jsonl  - one record per
#       value-moving function whose oracle read is attacker-movable and
#       unguarded; every record carries verdict=needs-fuzz.
#
# The hypothesis corpus is FOLDED into per_fn_hacker_questions.jsonl by
# auto-coverage-closer.py.  ORL never auto-credits any gate.
# ---------------------------------------------------------------------------
{
    echo "### Step 25 - Oracle Price Reachability Lane (ORL)"
    echo
} >> "$RUN_LOG"

ORL_TOOL="$HERE/oracle-reachability-lane.py"
ORL_JSONL="$WORKSPACE/.auditooor/oracle_reachability_hypotheses.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $ORL_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("orl (DRY_RUN=1)")
elif [ ! -f "$ORL_TOOL" ]; then
    echo "- skipped: tools/oracle-reachability-lane.py not present" >> "$RUN_LOG"
    skipped+=("orl (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("orl (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$ORL_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("orl")
        echo "- output: \`$ORL_JSONL\` (verdict=needs-fuzz; folded into per_fn_hacker_questions by auto-coverage-closer)" >> "$RUN_LOG"
    else
        echo "- WARN: orl exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("orl (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 26 - Rounding Drain Lane (RDL).
#
# tools/rounding-drain-lane.py reads the workspace source tree and emits:
#   <ws>/.auditooor/rounding_drain_hypotheses.jsonl  - one record per
#       value-moving function with a DRAINABLE or AMBIGUOUS rounding op
#       (mulDivDown/mulDivUp on intake/payout; Go sdk.Dec.Quo/TruncateInt;
#        Rust checked_div/.floor()/.ceil()); every record verdict=needs-fuzz.
#   <ws>/.auditooor/rounding_drain_invariants.jsonl  - exact/monotone
#       conservation invariant specs for the fuzzer oracle.
#
# WHAT RDL DETECTS: per-operation rounding that favors the USER instead of
# the protocol. Repeated, it compounds into a real drain. VCIS solvency-floor
# (balanceOf >= liabilities) is written with >= slack and tolerates 1-wei
# per-call rounding - RDL is the dedicated lane for this class.
#
# NO-FLOOD: only DRAINABLE or AMBIGUOUS rounding is flagged; provably
# protocol-favoring rounds (payout + mulDivDown, intake + mulDivUp) score 0.
#
# The hypothesis corpus is FOLDED into per_fn_hacker_questions.jsonl by
# auto-coverage-closer.py.  RDL never auto-credits any gate.
# ---------------------------------------------------------------------------
{
    echo "### Step 26 - Rounding Drain Lane (RDL)"
    echo
} >> "$RUN_LOG"

RDL_TOOL="$HERE/rounding-drain-lane.py"
RDL_JSONL="$WORKSPACE/.auditooor/rounding_drain_hypotheses.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $RDL_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("rdl (DRY_RUN=1)")
elif [ ! -f "$RDL_TOOL" ]; then
    echo "- skipped: tools/rounding-drain-lane.py not present" >> "$RUN_LOG"
    skipped+=("rdl (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("rdl (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$RDL_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("rdl")
        echo "- output: \`$RDL_JSONL\` (verdict=needs-fuzz; folded into per_fn_hacker_questions by auto-coverage-closer)" >> "$RUN_LOG"
    else
        echo "- WARN: rdl exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("rdl (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 27 - MEV / Ordering Lane (MOL).
#
# tools/mev-ordering-lane.py reads value_moving_functions.json and emits:
#   <ws>/.auditooor/mev_ordering_hypotheses.jsonl - one record per
#       ordering-sensitive value-mover (reads mutable price/pool state in-call)
#       that LACKS ordering protection (checked slippage/minOut, deadline,
#       commit-reveal, TWAP-settle); every record verdict=needs-fuzz,
#       attack_class=sandwich-front-run-ordering.
#
# WHAT MOL DETECTS: value-movers whose payout depends on mutable in-call state
# an adversary can move by ordering a tx before/after the victim's (sandwich,
# front-run, JIT-liquidity). NO-FLOOD: slippage/deadline-protected entrypoints
# and fixed-price (e.g. fixed-tick) movers score 0.
#
# The hypothesis corpus is FOLDED into per_fn_hacker_questions.jsonl by
# auto-coverage-closer.py.  MOL never auto-credits any gate.
# ---------------------------------------------------------------------------
{
    echo "### Step 27 - MEV / Ordering Lane (MOL)"
    echo
} >> "$RUN_LOG"

MOL_TOOL="$HERE/mev-ordering-lane.py"
MOL_JSONL="$WORKSPACE/.auditooor/mev_ordering_hypotheses.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $MOL_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("mol (DRY_RUN=1)")
elif [ ! -f "$MOL_TOOL" ]; then
    echo "- skipped: tools/mev-ordering-lane.py not present" >> "$RUN_LOG"
    skipped+=("mol (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("mol (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$MOL_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("mol")
        echo "- output: \`$MOL_JSONL\` (verdict=needs-fuzz; folded into per_fn_hacker_questions by auto-coverage-closer)" >> "$RUN_LOG"
    else
        echo "- WARN: mol exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("mol (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 28 - Access-Control Coverage Lane (ACL-COV).
#
# tools/access-control-coverage.py detects privileged admin/governance
# functions callable WITHOUT the expected authorization guard, across all
# three language families:
#   - Solidity:      tools/acl-matrix.py (requires Slither; skipped cleanly
#                    with a typed-skip note if Slither is absent)
#   - Go/Cosmos:     tools/detectors/go_permissionless_admin_key_sentinel.py
#                    (stdlib-only, always runs when Go source present)
#   - Rust/Substrate: detectors/rust-substrate-origin-privileged-effect-missing-guard.py
#                    (stdlib-only, always runs when Rust source present)
#
# Output:  <ws>/.auditooor/access_control_hypotheses.jsonl
#   One record per hit; every record verdict=needs-fuzz (NO auto-credit).
#   OOS/test/.auditooor files are dropped by scope_exclusion.
#   Slither-absent = Solidity arm emits a typed-skip note, does not crash.
#
# The hypothesis corpus is FOLDED into per_fn_hacker_questions.jsonl by
# auto-coverage-closer.py.  ACL-COV never auto-credits any gate.
# ---------------------------------------------------------------------------
{
    echo "### Step 28 - Access-Control Coverage Lane (ACL-COV)"
    echo
} >> "$RUN_LOG"

ACL_TOOL="$HERE/access-control-coverage.py"
ACL_JSONL="$WORKSPACE/.auditooor/access_control_hypotheses.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $ACL_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("acl-cov (DRY_RUN=1)")
elif [ ! -f "$ACL_TOOL" ]; then
    echo "- skipped: tools/access-control-coverage.py not present" >> "$RUN_LOG"
    skipped+=("acl-cov (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("acl-cov (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$ACL_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("acl-cov")
        echo "- output: \`$ACL_JSONL\` (verdict=needs-fuzz; folded into per_fn_hacker_questions by auto-coverage-closer)" >> "$RUN_LOG"
    else
        echo "- WARN: acl-cov exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("acl-cov (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 28b - Authority Blast-Radius (A3, authority SCOPE sibling of ACL-COV).
#
# tools/authority-blast-radius.py flags a single role guarding sinks of DIFFERING
# impact classes (over-broad blast radius) OR a powerful role grantable by a
# strictly weaker role (privilege inversion). Reuses acl-matrix role_uses/
# role_grants/priv_writes; ownership-transfer fns are excluded (two-step-ownership
# lane owns them). Emits <ws>/.auditooor/authority_blast_radius_hypotheses.jsonl
# (verdict=needs-fuzz, never auto-credits); the FEEDS-TO drain folds the rows into
# the source-mined exploit queue so they compound into exploit-conversion.
# ---------------------------------------------------------------------------
A3_TOOL="$HERE/authority-blast-radius.py"
A3_DRAIN="$HERE/authority-blast-radius-to-exploit-queue.py"
A3_JSONL="$WORKSPACE/.auditooor/authority_blast_radius_hypotheses.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $A3_TOOL --workspace $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("authority-blast-radius (DRY_RUN=1)")
elif [ ! -f "$A3_TOOL" ]; then
    echo "- skipped: tools/authority-blast-radius.py not present" >> "$RUN_LOG"
    skipped+=("authority-blast-radius (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("authority-blast-radius (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$A3_TOOL" --workspace "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("authority-blast-radius")
        echo "- output: \`$A3_JSONL\` (verdict=needs-fuzz; feeds hunt review + exploit queue)" >> "$RUN_LOG"
        if [ -f "$A3_DRAIN" ]; then
            if python3 "$A3_DRAIN" --ws "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
                echo "- feeds-to: A3 rows drained into exploit_queue.source_mined.json" >> "$RUN_LOG"
            else
                echo "- WARN: A3 exploit-queue drain non-zero (advisory, continuing)" >> "$RUN_LOG"
            fi
        fi
    else
        echo "- WARN: authority-blast-radius exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("authority-blast-radius (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

# ---------------------------------------------------------------------------
# Step 29 - Init/Upgrade Lane (IUL).
#
# tools/init-upgrade-lane.py detects unprotected initializers (initialize/init/
# reinitialize lacking initializer/_disableInitializers/bool guard) and unguarded
# upgrade-authorizers (_authorizeUpgrade/upgradeTo/setImplementation lacking a
# guard) - the init/upgrade blind-spot class. EIP-2535 Diamond Init* contracts
# fold into ONE aggregate (diamondCut-protected, not individual flags). Emits
# <ws>/.auditooor/init_upgrade_hypotheses.jsonl (verdict=needs-fuzz, never
# auto-credits), folded into the hunt corpus by auto-coverage-closer (IUL).
# ---------------------------------------------------------------------------
{
    echo "### Step 29 - Init/Upgrade Lane (IUL)"
    echo
} >> "$RUN_LOG"

IUL_TOOL="$HERE/init-upgrade-lane.py"
IUL_JSONL="$WORKSPACE/.auditooor/init_upgrade_hypotheses.jsonl"
if [ "$DRY_RUN" = "1" ]; then
    {
        echo "- planned: \`python3 $IUL_TOOL $WORKSPACE\`"
        echo "- skipped (DRY_RUN=1)"
    } >> "$RUN_LOG"
    skipped+=("iul (DRY_RUN=1)")
elif [ ! -f "$IUL_TOOL" ]; then
    echo "- skipped: tools/init-upgrade-lane.py not present" >> "$RUN_LOG"
    skipped+=("iul (tool missing)")
elif ! command -v python3 >/dev/null 2>&1; then
    echo "- skipped: python3 not on PATH" >> "$RUN_LOG"
    skipped+=("iul (python3 missing)")
else
    mkdir -p "$WORKSPACE/.auditooor"
    if python3 "$IUL_TOOL" "$WORKSPACE" >>"$RUN_LOG" 2>&1; then
        ran+=("iul")
        echo "- output: \`$IUL_JSONL\` (verdict=needs-fuzz; folded into per_fn_hacker_questions by auto-coverage-closer)" >> "$RUN_LOG"
    else
        echo "- WARN: iul exited non-zero (advisory, continuing)" >> "$RUN_LOG"
        skipped+=("iul (advisory non-zero)")
    fi
fi
echo >> "$RUN_LOG"

run_deep_counterexample_collect "$RUN_LOG"
run_deep_counterexample_queue "$RUN_LOG"

# Typed deep-engine skip emission (deep-engine-typed-skip fix). Runs AFTER all
# engine steps so it sees the real on-disk coverage-guided-engine evidence. It
# emits an honest, justified `.auditooor/stage_skips.json` typed-skip ONLY for
# language arms with NO executed coverage-guided engine; it never masks a
# genuine engine run (and removes a stale skip key when one did run).
emit_typed_deep_engine_skip "$RUN_LOG"

# WF-4 Patch A: R37 verification-tier audit (warn-only by default; STRICT=1
# promotes to fail-closed). Cheap (<5s stdlib-only).
run_r37_audit "$RUN_LOG"

# CAP-routing-integrity-check: B2 routing-integrity corpus audit. Runs in the
# same repo-corpus advisory phase as R37 (upstream corpus already enriched;
# report produced BEFORE hunt-dispatch consumes the language-filtered library).
# Warn-only by default; AUDIT_DEEP_ROUTING_STRICT=1 / STRICT=1 fails closed.
# Emits routing_integrity_report.json for the lift28 routing-fix consumer.
run_routing_integrity_audit "$RUN_LOG"

# WF-4 Patch B: regex detector arsenal (wave17 + rust_wave1 + go_wave1 + ...).
# Guarded by SKIP_REGEX=1 for fast-path callers. Time budget 2-10min.
run_regex_detectors "$RUN_LOG"

# WF-4 Patch E: prepend typed-candidate-promotion banner to the top of the
# report so the operator's first screen-pass sees the hunt-prep signal.
# Reads the promote-typed-candidate.py JSON emitted earlier by
# run_cross_lane_correlate (called from publish_profile_report).
# Must be called BEFORE publish_profile_report or AFTER it has written the
# typed_candidate_promotions.json - we call it right before publish to
# ensure the banner lands in BOTH the per-invocation and per-profile files.
# However, the JSON is written INSIDE publish_profile_report -> run_cross_lane_correlate,
# so we need to write banner AFTER publish but THEN re-publish the symlink.
# Simpler approach: call publish, then call the banner emitter, then re-symlink.

# V5-P0-11 / Gap 21: per-profile report + canonical symlink.
# The default profile already wrote to a per-invocation $RUN_LOG (see
# `RUN_LOG="$LOG_DIR/audit_deep_${TS}.md"` above) so the prior `cp` was
# the source of the last-profile-wins overwrite. Re-point the canonical
# symlink at the per-invocation file so siblings (math, econ, crypto,
# coverage_gaps) are no longer overwritten.
publish_profile_report "$DEFAULT_PROFILE_LABEL" "$RUN_LOG"

# WF-4 Patch E: now that typed_candidate_promotions.json exists, prepend
# the banner to BOTH the per-invocation log AND the per-profile report.
emit_typed_candidate_promotion_banner "$RUN_LOG"
_per_profile_report="$LOG_DIR/audit_deep_${DEFAULT_PROFILE_LABEL}_${TS}.md"
if [ -f "$_per_profile_report" ]; then
    emit_typed_candidate_promotion_banner "$_per_profile_report"
fi

echo "[audit-deep] OK report=$REPORT"
echo "[audit-deep]    per-profile: $LOG_DIR/audit_deep_${DEFAULT_PROFILE_LABEL}_${TS}.md"
echo "[audit-deep] ran: ${ran[*]:-(none)}"
echo "[audit-deep] skipped: ${skipped[*]:-(none)}"
echo "[audit-deep] failed: ${failed[*]:-(none)}"

# Final fail-loud gate (PR #511 Slice 5).
if [ "$INVARIANT_LEDGER_FAIL" = "1" ]; then
    echo "[audit-deep] FAIL: invariant-ledger gate triggered" >&2
    exit 1
fi
if [ "$CHIMERA_SCAFFOLD_FAIL" = "1" ]; then
    echo "[audit-deep] FAIL: chimera-scaffold gate triggered" >&2
    exit 1
fi
if [ "$GO_DLT_AUDIT_ENFORCEMENT_FAIL" = "1" ]; then
    echo "[audit-deep] FAIL: Go/DLT audit enforcement gate triggered" >&2
    exit 1
fi
if [ "$DETECTOR_SMOKE_FAIL" = "1" ]; then
    echo "[audit-deep] FAIL: detector-smoke unit-test gate triggered" >&2
    exit 1
fi

# Advisory: lane-volume-guard - flood diagnostics logged into run log.
# rc-tolerant: a flood is a lane-quality signal, NOT a workspace finding;
# it must NOT fail audit-deep. Guarded by tool-presence + DRY_RUN.
_LANE_VOL_GUARD="$HERE/lane-volume-guard.py"
if [ -f "$_LANE_VOL_GUARD" ] && [ "$DRY_RUN" != "1" ]; then
    echo "[audit-deep] advisory: running lane-volume-guard on $WORKSPACE" >> "$RUN_LOG"
    if python3 "$_LANE_VOL_GUARD" --workspace "$WORKSPACE" >> "$RUN_LOG" 2>&1; then
        echo "[audit-deep] advisory: lane-volume-guard PASS" >> "$RUN_LOG"
    else
        echo "[audit-deep] advisory: lane-volume-guard FLOOD/FAIL (see run log for diagnostics)" >> "$RUN_LOG"
    fi
fi

# Advisory: invariant-fuzz-credit-audit - surface DEPTH-false-credits where a
# sidecar is mutation_verified (harness QUALITY) but carries NO coverage-guided
# campaign meeting its call floor (fuzz DEPTH). rc-tolerant: this is a
# cross-cutting VISIBILITY net, NOT a workspace finding, and must NOT fail
# audit-deep (the hard-fail lives in the invariant-fuzz gate). Guarded by
# tool-presence + DRY_RUN.
_IFCA_TOOL="$HERE/invariant-fuzz-credit-audit.py"
if [ -f "$_IFCA_TOOL" ] && [ "$DRY_RUN" != "1" ]; then
    echo "[audit-deep] advisory: running invariant-fuzz-credit-audit on $WORKSPACE" >> "$RUN_LOG"
    if python3 "$_IFCA_TOOL" --workspace "$WORKSPACE" >> "$RUN_LOG" 2>&1; then
        echo "[audit-deep] advisory: invariant-fuzz-credit-audit PASS (see run log for suspect count)" >> "$RUN_LOG"
    else
        echo "[audit-deep] advisory: invariant-fuzz-credit-audit WARN (see run log for suspect depth-false-credits)" >> "$RUN_LOG"
    fi || true
fi

# REQUIRED (step-4d): executed-depth-conversion emit-obligations. The arsenal pass
# demotes units to needs-llm-depth verdicts and the executed-refutation gate flags
# grep-only value-mover NEGATIVES; this enumerates BOTH populations into per-unit
# executed-refutation OBLIGATIONS (.auditooor/executed_depth_obligations/) that the
# depth lane drives into poc_execution_records. Deterministic + idempotent; rc-tolerant
# (advisory here - the runbook step-4d + audit-complete auto-emit are the enforcement).
_EDC_TOOL="$HERE/executed-depth-conversion.py"
if [ -f "$_EDC_TOOL" ] && [ "$DRY_RUN" != "1" ]; then
    echo "[audit-deep] step-4d: executed-depth-conversion emit-obligations on $WORKSPACE" >> "$RUN_LOG"
    if python3 "$_EDC_TOOL" emit-obligations --workspace "$WORKSPACE" >> "$RUN_LOG" 2>&1; then
        echo "[audit-deep] step-4d: executed_depth_obligations emitted" >> "$RUN_LOG"
    else
        echo "[audit-deep] step-4d: executed-depth-conversion WARN (advisory non-zero)" >> "$RUN_LOG"
    fi || true
fi

exit 0
