#!/usr/bin/env bash
# scan-all-modules-multisolc.sh — full-coverage scan for mixed-solc codebases.
#
# SKILL_ISSUES #163 (R55 Polymarket blocker): `run_custom.py` on a full source
# tree fails when subtrees use different solc versions (Polymarket had 0.8.15 /
# 0.8.28 / 0.8.30 / 0.8.34 across v1-uma / v1-neg-risk / v1-fee-module / src-v2).
# Slither's compile step aborts with "Invalid compilation" as soon as any
# subtree's pragma can't be satisfied.
#
# This tool walks each `<workspace>/src*/*/` subdir, detects its pragma, uses
# solc-select to switch to the right solc, runs `run_custom.py` per-subtree,
# and concatenates all output into a unified `<workspace>/custom-detectors.log`.
#
# Usage:
#   ./tools/scan-all-modules-multisolc.sh <workspace> [--tier S,E] [--force]
#
# Requirements:
#   - solc-select installed and on PATH (`pip install solc-select`)
#   - python3 with slither-analyzer
#
# Exit codes:
#   0 — all subtrees scanned OK (or gracefully skipped)
#   1 — usage error
#   2 — no subtrees found
#   3 — all subtrees failed (every solc switch or compile failed)

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDITOOOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_CUSTOM="$AUDITOOOR_DIR/detectors/run_custom.py"
SCAN_TIMEOUT_SECS=900

# Track temp workspaces created by the per-profile workspace rewrite (#212).
# Use a registry FILE rather than a bash array — the temp ws is created in a
# subshell ($(make_temp_workspace_for_profile ...)) whose array writes never
# reach the parent. We append paths to TMP_WS_REGISTRY from the subshell.
TMP_WS_REGISTRY=$(mktemp -t auditooor_tmp_ws_registry.XXXXXX)
export TMP_WS_REGISTRY
cleanup_temp_workspaces() {
    if [ -f "$TMP_WS_REGISTRY" ]; then
        while IFS= read -r d; do
            [ -n "$d" ] && [ -d "$d" ] && rm -rf "$d"
        done < "$TMP_WS_REGISTRY"
        rm -f "$TMP_WS_REGISTRY"
    fi
}
trap cleanup_temp_workspaces EXIT INT TERM

usage() {
    cat >&2 <<'EOF'
scan-all-modules-multisolc.sh — full-coverage scan across mixed-solc subtrees.

Usage:
    ./tools/scan-all-modules-multisolc.sh <workspace> [--tier TIER_LIST] [--force]

Walks each <workspace>/src*/*/ subdir, detects its pragma via `grep -m1 pragma`,
selects matching solc via solc-select, runs run_custom.py per subtree, and
concatenates outputs into <workspace>/custom-detectors.log.

Options:
  --tier TIER_LIST   comma-separated (default: S,E)
  --force            overwrite existing custom-detectors.log

Filed as SKILL_ISSUES #163.
EOF
    exit 1
}

[ "$#" -lt 1 ] && usage

WS="$1"; shift
TIER="S,E,A,B"   # include validated A + smoke-tested B by default (strata 2026-06-30: B-tier glider detectors were silently never firing); D stays opt-in
FORCE=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --tier)   TIER="$2"; shift 2 ;;
        --tier=*) TIER="${1#--tier=}"; shift ;;
        --force)  FORCE=1; shift ;;
        -h|--help) usage ;;
        *) echo "[err] unknown arg: $1" >&2; usage ;;
    esac
done

[ -d "$WS" ] || { echo "[err] workspace not found: $WS" >&2; exit 1; }

command -v solc-select >/dev/null 2>&1 || {
    echo "[err] solc-select not found on PATH. pip install solc-select" >&2
    exit 1
}

LOG="$WS/custom-detectors.log"
ERR="$WS/custom-detectors-errors.log"
if [ -s "$LOG" ] && [ "$FORCE" -eq 0 ]; then
    echo "[err] $LOG already has content — pass --force to overwrite" >&2
    exit 1
fi
: > "$LOG"
: > "$ERR"

# ----- foundry.toml profile parsing (SKILL_ISSUES #204 — Phase 37b fix) -----
# Workspaces with multiple Foundry profiles (Polymarket: default + poc-uma +
# poc-adapters + poc-exchange) need per-subtree FOUNDRY_PROFILE so `forge build`
# (invoked by crytic-compile via `forge config --json`) picks the right
# `src=` and `remappings=`. Without this, Polymarket's workspace remapping
# `src/=src/v1/neg-risk/` shadows every non-negrisk import → 4/5 v1 subtrees
# fail to compile under Slither.
#
# resolve_profile_for_subtree <subtree_path> -> echoes "<profile_name>" or
# nothing if the workspace has no foundry.toml or no matching profile.
TOML_FILE="$WS/foundry.toml"
resolve_profile_for_subtree() {
    local subtree="$1"
    [ -f "$TOML_FILE" ] || return 0
    local rel="${subtree#$WS/}"
    python3 - "$TOML_FILE" "$rel" <<'PY' 2>/dev/null
import sys
from pathlib import Path
toml_path, subtree_rel = sys.argv[1], sys.argv[2]
try:
    import tomllib
    with open(toml_path, "rb") as f:
        data = tomllib.load(f)
except Exception:
    # Hand-rolled minimal parser: only need [profile.X] / src = "..."
    data = {"profile": {}}
    cur = None
    import re
    for line in Path(toml_path).read_text().splitlines():
        s = line.strip()
        if s.startswith("[profile.") and s.endswith("]"):
            name = s[len("[profile."):-1]
            cur = data["profile"].setdefault(name, {})
            continue
        if cur is None:
            continue
        m = re.match(r'^src\s*=\s*"([^"]+)"', s)
        if m:
            cur["src"] = m.group(1)
profiles = data.get("profile", {}) or {}
# Exact match first
for name, cfg in profiles.items():
    if cfg.get("src") == subtree_rel:
        print(name)
        sys.exit(0)
# Fallback: longest matching src that is a prefix of subtree_rel
best = None
best_len = 0
for name, cfg in profiles.items():
    src = cfg.get("src", "")
    if src and (subtree_rel == src or subtree_rel.startswith(src + "/")):
        if len(src) > best_len:
            best, best_len = name, len(src)
if best:
    print(best)
PY
}

# enumerate_profile_subtrees -> echoes one absolute path per non-default
# profile whose `src` exists on disk. Used to expand top-level subtrees that
# have no direct profile match (e.g. `src/v1` → `src/v1/uma` via [profile.poc-uma]).
enumerate_profile_subtrees() {
    [ -f "$TOML_FILE" ] || return 0
    python3 - "$TOML_FILE" "$WS" <<'PY' 2>/dev/null
import sys
from pathlib import Path
toml_path, ws = sys.argv[1], sys.argv[2]
try:
    import tomllib
    with open(toml_path, "rb") as f:
        data = tomllib.load(f)
except Exception:
    data = {"profile": {}}
    cur = None
    import re
    for line in Path(toml_path).read_text().splitlines():
        s = line.strip()
        if s.startswith("[profile.") and s.endswith("]"):
            cur = data["profile"].setdefault(s[len("[profile."):-1], {})
            continue
        if cur is None:
            continue
        m = re.match(r'^src\s*=\s*"([^"]+)"', s)
        if m:
            cur["src"] = m.group(1)
for name, cfg in (data.get("profile") or {}).items():
    if name == "default":
        continue
    src = cfg.get("src")
    if not src:
        continue
    p = Path(ws) / src
    if p.is_dir():
        print(p)
PY
}

# ----- temp workspace per-profile builder (SKILL_ISSUES #212 — option c) -----
# When `remappings.txt` co-exists with `[profile.X].remappings = [...]`, forge
# silently drops the toml-defined remappings (they don't appear in
# `forge config --json`). Slither/crytic-compile then resolves imports against
# the workspace wildcards (e.g. `src/=src/v1/neg-risk/`) which corrupts every
# non-negrisk import.
#
# Workaround: copy the subtree into /tmp, symlink lib/, and write a stripped
# foundry.toml whose [profile.default] block contains the original profile's
# inline remappings — and crucially, NO `remappings.txt` in the temp root. With
# remappings.txt absent, forge honors the toml-defined remappings array, and
# crytic-compile sees the correct longest-prefix overrides.
#
# Usage: tmp_ws=$(make_temp_workspace_for_profile "$WS" "$profile" "$pragma")
# Echoes the absolute path of the new temp workspace root, or empty on failure.
make_temp_workspace_for_profile() {
    local src_ws="$1"
    local profile="$2"
    local pragma="$3"
    [ -z "$profile" ] && return 0
    [ -f "$src_ws/foundry.toml" ] || return 0
    local sanitized="${profile//\//_}"
    sanitized="${sanitized// /_}"
    local tmp_root
    tmp_root=$(mktemp -d -t "auditooor_scan_${sanitized}.XXXXXX") || return 0
    # Resolve the profile's src= so we can both copy the right subtree AND
    # rewrite it to live at $tmp_root/src/ (avoiding forge's deep-src
    # remapping-dedup quirk — see #212). If the profile's src= is "src/v1/uma",
    # we copy that subtree contents to $tmp_root/src/ so all `src/...` imports
    # resolve naturally without needing a `src/=...` remap.
    local profile_src
    profile_src=$(python3 - "$src_ws/foundry.toml" "$profile" <<'PY' 2>/dev/null
import sys, re
src_toml, profile = sys.argv[1], sys.argv[2]
try:
    import tomllib
    data = tomllib.load(open(src_toml, "rb"))
except Exception:
    data = {"profile": {}}
    cur = None
    for line in open(src_toml).read().splitlines():
        s = line.strip()
        if s.startswith("[profile.") and s.endswith("]"):
            cur = data["profile"].setdefault(s[len("[profile."):-1], {})
            continue
        if cur is None:
            continue
        m = re.match(r'^src\s*=\s*"([^"]+)"', s)
        if m:
            cur["src"] = m.group(1)
print((data.get("profile",{}).get(profile,{}) or {}).get("src","src"))
PY
)
    [ -z "$profile_src" ] && profile_src="src"

    # Symlink heavyweight dirs (lib/, etc). Skip src* (we copy a remapped
    # subset below). Skip workspace foundry config — we generate our own.
    local entry
    for entry in "$src_ws"/*; do
        [ -e "$entry" ] || continue
        local base; base=$(basename "$entry")
        case "$base" in
            foundry.toml|remappings.txt|out|out-*|cache) continue ;;
            src|src-*|contracts) continue ;;
            *) ln -s "$entry" "$tmp_root/$base" 2>/dev/null || true ;;
        esac
    done

    # Copy ONLY the profile's source subtree, mounted at $tmp_root/src.
    # cp -RL materializes symlinks (src-v2 is itself a symlink in Polymarket).
    if [ -d "$src_ws/$profile_src" ]; then
        cp -RL "$src_ws/$profile_src" "$tmp_root/src" 2>/dev/null \
            || cp -R "$src_ws/$profile_src" "$tmp_root/src" 2>/dev/null \
            || true
    else
        # Fallback: copy whole top-level src/
        cp -RL "$src_ws/src" "$tmp_root/src" 2>/dev/null || cp -R "$src_ws/src" "$tmp_root/src" 2>/dev/null || true
    fi
    # Generate the stripped foundry.toml. We rename the chosen profile to
    # `default` so FOUNDRY_PROFILE doesn't need to be exported in the temp
    # workspace (and forge won't fall back to a different default block that
    # might pull in remappings.txt-style wildcards).
    python3 - "$src_ws/foundry.toml" "$profile" "$pragma" "$tmp_root/foundry.toml" <<'PY' 2>/dev/null
import sys, re
src_toml, profile, pragma, dst_toml = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    import tomllib
    with open(src_toml, "rb") as f:
        data = tomllib.load(f)
except Exception:
    data = {"profile": {}}
    cur = None
    for line in open(src_toml).read().splitlines():
        s = line.strip()
        if s.startswith("[profile.") and s.endswith("]"):
            cur = data["profile"].setdefault(s[len("[profile."):-1], {})
            continue
        if cur is None:
            continue
        for key in ("src", "out", "evm_version", "solc"):
            m = re.match(rf'^{key}\s*=\s*"([^"]+)"', s)
            if m:
                cur[key] = m.group(1)
        m = re.match(r'^libs\s*=\s*\[(.*)\]', s)
        if m:
            cur["libs"] = re.findall(r'"([^"]+)"', m.group(1))
        m = re.match(r'^remappings\s*=\s*\[(.*)\]', s)
        if m:
            cur["remappings"] = re.findall(r'"([^"]+)"', m.group(1))

profiles = data.get("profile") or {}
cfg = profiles.get(profile) or profiles.get("default") or {}
orig_src = cfg.get("src", "src")
libs = cfg.get("libs") or ["lib"]
remaps = cfg.get("remappings") or []
solc = cfg.get("solc") or pragma or ""
evm = cfg.get("evm_version") or "paris"

# If the chosen profile inherits remappings (none of its own), fall back to
# the [profile.default] block first, then to remappings.txt — but for the
# remappings.txt fallback, FILTER OUT any destructive wildcard whose LHS is
# `src/` (those entries are exactly the ones #212 is fighting against:
# `src/=src/v1/neg-risk/` corrupts every non-negrisk subtree's imports).
import os as _os
src_ws_dir = _os.path.dirname(_os.path.abspath(src_toml))
if not remaps:
    default_cfg = profiles.get("default") or {}
    remaps = list(default_cfg.get("remappings") or [])
remappings_txt = _os.path.join(src_ws_dir, "remappings.txt")
if _os.path.isfile(remappings_txt):
    extra = []
    for line in open(remappings_txt).read().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        lhs = line.split("=", 1)[0]
        # SKIP destructive wildcards that the deep-path subtree explicitly
        # wants to bypass (the whole reason for #212).
        if lhs in ("src/", "src"):
            continue
        # Avoid duplicating an LHS the profile already defines.
        if any(r.startswith(lhs + "=") for r in remaps):
            continue
        extra.append(line)
    remaps = list(remaps) + extra

# IMPORTANT: the temp workspace mounts the profile's src subtree at $tmp/src
# (regardless of orig_src like "src/v1/uma"). So set src="src" in the toml,
# and drop any remap whose LHS is the deep orig_src path (would no longer
# match in the temp layout). Imports like `src/interfaces/IBulletinBoard.sol`
# now resolve naturally to $tmp/src/interfaces/IBulletinBoard.sol — no remap
# needed; this sidesteps forge's identity-remap dedup quirk that was
# clobbering `src/v1/uma/=` and corrupting the wildcard rewrite.
src = "src"
if orig_src and orig_src != "src":
    # Drop identity/self-referential remaps tied to the deep path.
    remaps = [r for r in remaps if not r.startswith(f"{orig_src}/=")]

lines = [
    "[profile.default]",
    f'src = "{src}"',
    'out = "out"',
    f'libs = [{", ".join(chr(34)+l+chr(34) for l in libs)}]',
    f'evm_version = "{evm}"',
    "optimizer = true",
]
if solc:
    lines.append(f'solc = "{solc}"')
else:
    lines.append("auto_detect_solc = true")
if remaps:
    lines.append("remappings = [")
    for r in remaps:
        lines.append(f'    "{r}",')
    lines.append("]")
open(dst_toml, "w").write("\n".join(lines) + "\n")
PY
    if [ ! -s "$tmp_root/foundry.toml" ]; then
        rm -rf "$tmp_root"
        return 0
    fi
    # Register for cleanup via file (subshell-safe — see TMP_WS_REGISTRY).
    [ -n "${TMP_WS_REGISTRY:-}" ] && echo "$tmp_root" >> "$TMP_WS_REGISTRY"
    echo "$tmp_root"
}

# ----- discover subtrees -----
# A subtree is a subdir of $WS/src*/ that contains at least one *.sol file
# outside test/mock/script paths.
SUBTREES=()
while IFS= read -r subdir; do
    [ -z "$subdir" ] && continue
    # Must contain at least one non-test .sol
    if find "$subdir" -maxdepth 4 -name "*.sol" \
        -not -path "*/test/*" -not -path "*/mocks/*" \
        -not -path "*/script/*" -not -path "*/tests/*" 2>/dev/null | \
        head -1 | grep -q .; then
        SUBTREES+=("$subdir")
    fi
done < <(find "$WS" -maxdepth 4 -type d 2>/dev/null | \
    awk '/\/src[^\/]*\/[^\/]+$/' | \
    grep -vE '/(test|tests|mock|mocks|dev|script|scripts|lib|out)(/|$)' | sort -u)

# SKILL_ISSUES #204: if a discovered subtree has no matching profile but the
# foundry.toml declares profiles whose `src=` points DEEPER (e.g. src/v1 has
# no profile but [profile.poc-uma] sets src=src/v1/uma), expand. Replace any
# such bare top-level subtree with its profile-backed children.
# Bash 3 compat (macOS default): no associative arrays — use a delimited string.
if [ -f "$TOML_FILE" ]; then
    EXPANDED=()
    REPLACED_LIST="|"
    while IFS= read -r psub; do
        [ -z "$psub" ] && continue
        for s in "${SUBTREES[@]}"; do
            case "$psub" in
                "$s"/*) REPLACED_LIST="${REPLACED_LIST}${s}|" ;;
            esac
        done
        EXPANDED+=("$psub")
    done < <(enumerate_profile_subtrees)
    NEW_SUBTREES=()
    for s in "${SUBTREES[@]}"; do
        case "$REPLACED_LIST" in
            *"|${s}|"*) ;;
            *) NEW_SUBTREES+=("$s") ;;
        esac
    done
    for e in "${EXPANDED[@]}"; do
        already=0
        for n in "${NEW_SUBTREES[@]}"; do
            [ "$n" = "$e" ] && already=1 && break
        done
        [ "$already" -eq 0 ] && NEW_SUBTREES+=("$e")
    done
    if [ "${#NEW_SUBTREES[@]}" -gt 0 ]; then
        SUBTREES=("${NEW_SUBTREES[@]}")
    fi
fi

if [ "${#SUBTREES[@]}" -eq 0 ]; then
    echo "[err] no source subtrees found under $WS/src*/ (need at least one non-test .sol)" >&2
    exit 2
fi

echo "[info] workspace: $WS"
echo "[info] subtrees found: ${#SUBTREES[@]}"
printf '  %s\n' "${SUBTREES[@]}"
echo "[info] tier: $TIER"
echo "[info] aggregate log: $LOG"
echo

# ----- detect pragma helper -----
# R79 T4 fix: reject 0.9+ upper-bound versions (they don't exist in solc-select),
# reject pre-0.4 versions, prefer mode of remaining versions.
detect_pragma() {
    local subdir="$1"
    local p
    # Prefer the most-common pragma in the subtree (mode), filtering bogus versions.
    p=$(grep -hE '^[[:space:]]*pragma[[:space:]]+solidity' \
         "$subdir"/*.sol 2>/dev/null | head -20 | \
         grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | \
         grep -vE '^(0\.9\.|1\.|0\.[0-3]\.)' | \
         sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
    if [ -z "$p" ]; then
        # Try recursive
        p=$(grep -rhE '^[[:space:]]*pragma[[:space:]]+solidity' \
             "$subdir" --include="*.sol" 2>/dev/null | head -40 | \
             grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | \
             grep -vE '^(0\.9\.|1\.|0\.[0-3]\.)' | \
             sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
    fi
    # Normalize X.Y → X.Y.0 (solc-select wants three-part)
    if [[ "$p" =~ ^[0-9]+\.[0-9]+$ ]]; then
        p="${p}.0"
    fi
    echo "$p"
}

# ----- scan each subtree -----
OK_COUNT=0
FAIL_COUNT=0
TOTAL_HITS=0

for subdir in "${SUBTREES[@]}"; do
    name="${subdir#$WS/}"
    pragma=$(detect_pragma "$subdir")
    if [ -z "$pragma" ]; then
        echo "[skip] $name — no pragma detected"
        echo "=== subtree: $name (SKIPPED — no pragma) ===" >> "$LOG"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        continue
    fi

    # SKILL_ISSUES #204: resolve foundry.toml profile for this subtree so
    # crytic-compile picks up the right `src=` + `remappings=` via FOUNDRY_PROFILE.
    profile=$(resolve_profile_for_subtree "$subdir")
    if [ -n "$profile" ]; then
        echo "[scan] $name  pragma=$pragma  profile=$profile"
    else
        echo "[scan] $name  pragma=$pragma"
    fi

    # Install + switch solc (idempotent)
    solc-select install "$pragma" >/dev/null 2>&1 || true
    if ! solc-select use "$pragma" >/dev/null 2>&1; then
        echo "  [fail] solc-select couldn't switch to $pragma" >&2
        {
            echo "=== subtree: $name (SKIPPED — solc $pragma unavailable) ==="
            echo ""
        } >> "$LOG"
        echo "$name: solc $pragma unavailable" >> "$ERR"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        continue
    fi

    # Run scan
    tmp_out=$(mktemp -t "scan-${name//\//_}.XXXXXX")
    rc=0
    # SKILL_ISSUES #212 (option c): when this subtree has a non-default
    # profile AND the workspace also carries a remappings.txt, build a temp
    # workspace whose foundry.toml has the profile's remappings inline and NO
    # remappings.txt. Re-target the scan at the temp subtree.
    scan_target="$subdir"
    if [ -n "$profile" ] && [ "$profile" != "default" ] && [ -f "$WS/remappings.txt" ]; then
        tmp_ws=$(make_temp_workspace_for_profile "$WS" "$profile" "$pragma")
        if [ -n "$tmp_ws" ] && [ -d "$tmp_ws/src" ]; then
            # Temp ws mounts profile src subtree at $tmp_ws/src/ (regardless
            # of original deep path like src/v1/uma). Scan that.
            scan_target="$tmp_ws/src"
            echo "  [tmp-ws] $tmp_ws (stripped foundry.toml, no remappings.txt)"
        fi
    fi
    # SKILL_ISSUES #204: export FOUNDRY_PROFILE for the child so `forge config`
    # / `forge build` (called by crytic-compile) pick up the matching profile's
    # src + remappings. With #212 temp-ws active, the profile is renamed to
    # `default` inside the temp workspace, so we unset FOUNDRY_PROFILE.
    if [ "$scan_target" != "$subdir" ]; then
        unset FOUNDRY_PROFILE
    elif [ -n "$profile" ]; then
        export FOUNDRY_PROFILE="$profile"
    else
        unset FOUNDRY_PROFILE
    fi
    # perl alarm fallback (no `timeout` on macOS default)
    perl -e '
        my $secs = shift @ARGV;
        my $pid = fork();
        die "fork: $!" unless defined $pid;
        if ($pid == 0) { exec @ARGV or die "exec: $!"; }
        local $SIG{ALRM} = sub { kill("TERM", $pid); sleep 2; kill("KILL", $pid); exit 124; };
        alarm($secs);
        waitpid($pid, 0);
        exit($? >> 8);
    ' "$SCAN_TIMEOUT_SECS" \
        python3 "$RUN_CUSTOM" "$scan_target" --tier "$TIER" >"$tmp_out" 2>&1 || rc=$?

    if [ $rc -eq 0 ]; then
        {
            echo "=== subtree: $name (pragma=$pragma, OK) ==="
            cat "$tmp_out"
            echo ""
        } >> "$LOG"
        hits=$(awk '/^\[done\] total hits:/ { s += $NF } END { print s+0 }' "$tmp_out")
        TOTAL_HITS=$((TOTAL_HITS + hits))
        OK_COUNT=$((OK_COUNT + 1))
        echo "  [ok] hits=$hits"
    else
        # R79 T9: surface the actual compile error. The first line is often a
        # benign `[ok] loaded N detectors` banner that masks the real failure,
        # so extract the key failure signals directly.
        fail_cause=$(grep -E "^Error|error compiling|Unable to resolve|InvalidCompilation|No solc version exists|ParserError|incompatible versions" "$tmp_out" 2>/dev/null | head -3)
        if [ -z "$fail_cause" ]; then
            fail_cause=$(tail -n 3 "$tmp_out" | head -c 300)
        fi
        {
            echo "=== subtree: $name (pragma=$pragma, FAIL exit=$rc) ==="
            echo "--- cause ---"
            echo "$fail_cause"
            echo "--- last 20 lines ---"
            tail -n 20 "$tmp_out"
            echo ""
        } >> "$LOG"
        {
            echo "--- $name (pragma=$pragma, exit=$rc) ---"
            echo "$fail_cause"
        } >> "$ERR"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        # Print the cause line to stderr so operator sees it without grep.
        cause_one_line=$(echo "$fail_cause" | head -1 | head -c 160)
        echo "  [fail] exit=$rc — ${cause_one_line:-<no clear error line>}"
    fi
    rm -f "$tmp_out"
done

echo
echo "========== SUMMARY =========="
echo "Subtrees scanned OK : $OK_COUNT"
echo "Subtrees failed     : $FAIL_COUNT"
echo "Total hits          : $TOTAL_HITS"
echo "Aggregate log       : $LOG"
echo "Error log           : $ERR"
echo "============================="

if [ "$OK_COUNT" -eq 0 ]; then
    echo "[err] every subtree failed; check $ERR" >&2
    exit 3
fi
exit 0
