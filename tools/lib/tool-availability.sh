# shellcheck shell=bash
# tool-availability.sh — probe the host for external binaries auditooor may use.
#
# Sourced by:
#   - tools/ci-preflight.sh (the `make ci-preflight` driver)
#   - bash test scripts that want a clean up-front skip instead of a mid-run
#     "command not found".
#
# Contract:
#   - Source, do not execute. The script sets env vars in the caller's shell.
#   - Never exits on its own; never touches the filesystem. Pure PATH probing.
#   - Sets exactly one of 1 or 0 per tool:
#       HAS_FORGE, HAS_CAST, HAS_ANVIL,
#       HAS_MEDUSA, HAS_ECHIDNA,
#       HAS_HALMOS, HAS_MYTHRIL,
#       HAS_SLITHER,
#       HAS_JQ, HAS_PYTHON3,
#       HAS_TIMEOUT     (GNU `timeout` OR `gtimeout` — many offline tests need it)
#   - Sets a companion *_VERSION var with either a plain version string, the
#     literal "version-unknown" when the binary is present but `--version`
#     output cannot be parsed, or empty when the binary is missing.
#   - Defines two helper functions:
#       tool_availability_critical_ok   — returns 0 iff forge + python3 are both present.
#       tool_availability_report_line <name> <HAS> <VER> — print one row for the preflight table.
#
# The status vocabulary emitted downstream is deliberately narrow: the
# preflight emits only "✓" (present), "✗" (missing), "YES", "NO". No other
# status strings leak from here into submission gates.

# Guard against double-sourcing.
if [ "${_AUDITOOOR_TOOL_AVAILABILITY_SOURCED:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi
_AUDITOOOR_TOOL_AVAILABILITY_SOURCED=1

# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------

_ta_first_nonempty_line() {
    awk 'NF {print; exit}' 2>/dev/null || true
}

# _ta_probe_version <binary> <args...>
#   Run the binary with a version flag and normalize the output. Never fails.
#   Prints either a short version string or the literal "version-unknown".
_ta_probe_version() {
    local bin="$1"; shift
    local raw
    raw="$("$bin" "$@" 2>&1 | _ta_first_nonempty_line)"
    if [ -z "$raw" ]; then
        printf '%s' "version-unknown"
        return 0
    fi
    local trimmed="$raw"
    trimmed="${trimmed#forge Version: }"
    trimmed="${trimmed#cast Version: }"
    trimmed="${trimmed#anvil Version: }"
    trimmed="${trimmed#medusa version }"
    trimmed="${trimmed#Echidna }"
    trimmed="${trimmed#halmos }"
    trimmed="${trimmed#Mythril version }"
    trimmed="${trimmed#mythril }"
    trimmed="${trimmed#jq-}"
    trimmed="${trimmed#Python }"
    case "$trimmed" in
        ""|*" "*[a-zA-Z]*" "*" "*" "*" "*" "*) # long prose -> unknown
            printf '%s' "version-unknown"
            ;;
        *)
            printf '%s' "$trimmed"
            ;;
    esac
}

# _ta_probe <VARNAME> <binary> [version_args...]
#   Sets HAS_<VARNAME>=0|1 and <VARNAME>_VERSION.
_ta_probe() {
    local upper="$1"; shift
    local bin="$1"; shift
    if command -v "$bin" >/dev/null 2>&1; then
        eval "HAS_${upper}=1"
        local ver
        ver="$(_ta_probe_version "$bin" "$@")"
        eval "${upper}_VERSION=\"\$ver\""
    else
        eval "HAS_${upper}=0"
        eval "${upper}_VERSION=\"\""
    fi
}

# ---------------------------------------------------------------------------
# Probe every tool. Additions here should also update:
#   - tools/ci-preflight.sh (the printed table)
#   - docs/CI_SETUP.md
# ---------------------------------------------------------------------------

_ta_probe FORGE    forge   --version
_ta_probe CAST     cast    --version
_ta_probe ANVIL    anvil   --version
_ta_probe MEDUSA   medusa  --version
_ta_probe ECHIDNA  echidna --version
_ta_probe HALMOS   halmos  --version
_ta_probe MYTHRIL  myth    version
_ta_probe SLITHER  slither --version
_ta_probe JQ       jq      --version
_ta_probe PYTHON3  python3 --version

# TIMEOUT: treat GNU `timeout` OR `gtimeout` as satisfying the requirement.
# Several offline tests (fuzz runner, symbolic runner) need one of them to
# bound engine runs. macOS ships neither by default.
if command -v timeout >/dev/null 2>&1; then
    HAS_TIMEOUT=1
    TIMEOUT_VERSION="$(_ta_probe_version timeout --version)"
    TIMEOUT_VARIANT="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    HAS_TIMEOUT=1
    TIMEOUT_VERSION="$(_ta_probe_version gtimeout --version)"
    TIMEOUT_VARIANT="gtimeout"
else
    HAS_TIMEOUT=0
    TIMEOUT_VERSION=""
    TIMEOUT_VARIANT=""
fi

# ---------------------------------------------------------------------------
# Public helpers the preflight script composes.
# ---------------------------------------------------------------------------

# tool_availability_critical_ok
#   Return 0 if the tools we consider critical for a useful CI run are
#   present. Critical = forge + python3. Everything else is optional:
#   the relevant offline tests skip cleanly if an optional tool is missing.
#
#   Regression test guardrail (test_missing_forge_fails_preflight):
#   forge MUST stay in the critical set. Do not add `|| true` or an OR chain
#   that would let forge be missing and still return 0.
tool_availability_critical_ok() {
    if [ "${HAS_FORGE:-0}" = "1" ] && [ "${HAS_PYTHON3:-0}" = "1" ]; then
        return 0
    fi
    return 1
}

# tool_availability_report_line <display-name> <HAS_VAR> <VERSION_VAR>
tool_availability_report_line() {
    local name="$1"
    local has="$2"
    local ver="$3"
    local pad
    pad=$(printf '%*s' $((9 - ${#name})) '')
    local missing_suffix
    case "$name" in
        forge)    missing_suffix="foundry-gated tests will FAIL" ;;
        cast)     missing_suffix="fork-replay live smoke will skip" ;;
        anvil)    missing_suffix="fork-replay live smoke will skip" ;;
        medusa)   missing_suffix="fuzz runner will skip" ;;
        echidna)  missing_suffix="fuzz runner will skip" ;;
        halmos)   missing_suffix="symbolic runner will skip" ;;
        mythril)  missing_suffix="symbolic runner will skip" ;;
        slither)  missing_suffix="static-analysis helpers will skip" ;;
        jq)       missing_suffix="shell JSON helpers will skip" ;;
        python3)  missing_suffix="offline test suite will FAIL" ;;
        timeout)  missing_suffix="fuzz/symbolic runner tests install shim" ;;
        *)        missing_suffix="dependent tests will skip" ;;
    esac
    if [ "$has" = "1" ]; then
        printf '  %s:%s✓ %s\n' "$name" "$pad" "${ver:-version-unknown}"
    else
        printf '  %s:%s✗ not installed (%s)\n' "$name" "$pad" "$missing_suffix"
    fi
}
