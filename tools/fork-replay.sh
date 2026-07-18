#!/usr/bin/env bash
# fork-replay.sh — Polygon historical contested-tx replay harness.
#
# Forks Polygon at `tx.block_number - 1`, replays a single tx, snapshots
# pre/post state for watched addresses, emits balance deltas, and writes a YAML
# summary. Invariant assertions are still lightweight; use the delta artifacts
# as the economic-proof substrate for High+ claims.
#
# Usage:
#   tools/fork-replay.sh [--watch <address>] [--erc20 <token>] <workspace> <tx-hash> [<rpc-url>]
#
# Example:
#   tools/fork-replay.sh audit/findings/ghost-fill-2026-02 \
#       0xdeadbeef...beefdead                                \
#       https://polygon-rpc.com
#
# Output:
#   <workspace>/fork_replay/<tx-hash>_replay.yaml
#   <workspace>/fork_replay/<tx-hash>_pre_state.json
#   <workspace>/fork_replay/<tx-hash>_post_state.json
#   <workspace>/fork_replay/<tx-hash>_deltas.json
#   <workspace>/fork_replay/<tx-hash>_manifest.json
#   <workspace>/fork_replay/<tx-hash>_trace.json   (debug_traceTransaction)
#
# Dependencies: foundry (cast, anvil). Uses `cast rpc` + `cast run` rather than
# a Forge test harness so callers don't need to compile anything.

set -Eeuo pipefail

usage() {
    cat <<'EOF'
usage: tools/fork-replay.sh [options] <workspace> <tx-hash> [rpc-url]

Options:
  --watch <address>             Add an address to pre/post native balance snapshots.
                                May be repeated. Default scope addresses are always watched.
  --erc20 <token>               Track ERC20 balanceOf(address) for every watched address.
                                May be repeated.
  --watch-erc20 <tok>:<holder>[=<label>]
                                Targeted ERC20 watch: track ONE holder's balance of ONE token.
                                Optional =<label> tags the row (e.g. victim/protocol/attacker).
                                May be repeated. Deduplicated by lowercase token:holder.
  --watch-native <addr>[=<label>]
                                Labeled alias for --watch. Emits a targeted native row with
                                the given label. Deduplicated by lowercase address.
  --watch-config <path>         Load a strict JSON watch config and expand it into the same
                                --watch-erc20 / --watch-native pipeline as CLI flags.
                                Default (if file exists): <workspace>/monitoring/fork_replay.watch.json.
                                Config specs are processed BEFORE CLI specs, so on conflicts
                                the config label wins (first-seen dedup).
  --no-watch-config             Disable automatic loading of the default config file even
                                if it exists. Ignored if --watch-config is also given.
  --out-dir <dir>               Override artifact directory (default: <workspace>/fork_replay).
  -h, --help                    Show this help.

Environment:
  POLYGON_RPC                   Fallback RPC when [rpc-url] is omitted.
  ANVIL_PORT                    Local anvil fork port (default: 8546).
EOF
}

EXTRA_WATCH_ADDRS=()
ERC20_TOKENS=()
# TARGETED_WATCHES: each entry "kind|token|holder|label". kind = erc20|native.
# For native, token is the empty string.
TARGETED_WATCHES=()
TARGETED_KEYS=()
OUT_DIR_OVERRIDE=""
POSITIONAL=()
# Deferred CLI watch specs — collected during arg parsing and processed AFTER
# the watch config file is loaded, so config-provided specs land first and
# their labels win dedup conflicts.
CLI_WATCH_ERC20=()
CLI_WATCH_NATIVE=()
WATCH_CONFIG_PATH=""
WATCH_CONFIG_DISABLED=0
WATCH_CONFIG_EXPLICIT=0

validate_address_early() {
    local label="$1"
    local addr="$2"
    if [[ ! "${addr}" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
        echo "error: ${label} must be 0x + 40 hex chars (got: ${addr})" >&2
        exit 2
    fi
}

add_targeted_watch() {
    local kind="$1"   # erc20 or native
    local token="$2"  # may be empty for native
    local holder="$3"
    local label="$4"
    local tok_lc hol_lc key
    if [[ -n "${token}" ]]; then
        tok_lc="$(printf '%s' "${token}" | tr '[:upper:]' '[:lower:]')"
    else
        tok_lc="native"
    fi
    hol_lc="$(printf '%s' "${holder}" | tr '[:upper:]' '[:lower:]')"
    key="${tok_lc}:${hol_lc}"
    local existing
    if ((${#TARGETED_KEYS[@]})); then
        for existing in "${TARGETED_KEYS[@]}"; do
            if [[ "${existing}" == "${key}" ]]; then
                echo "[fork-replay] note: duplicate targeted watch ${key} ignored (keeping first label)" >&2
                return
            fi
        done
    fi
    TARGETED_KEYS+=("${key}")
    TARGETED_WATCHES+=("${kind}|${token}|${holder}|${label}")
}

parse_watch_erc20_spec() {
    # Expected: <token>:<holder>[=<label>]
    local spec="$1"
    local label=""
    if [[ "${spec}" == *"="* ]]; then
        label="${spec#*=}"
        spec="${spec%%=*}"
    fi
    if [[ "${spec}" != *":"* ]]; then
        echo "error: --watch-erc20 expects <token>:<holder>[=<label>] (got: $1)" >&2
        exit 2
    fi
    local token="${spec%%:*}"
    local holder="${spec#*:}"
    if [[ -z "${token}" || -z "${holder}" ]]; then
        echo "error: --watch-erc20 expects <token>:<holder>[=<label>] (got: $1)" >&2
        exit 2
    fi
    validate_address_early "--watch-erc20 token" "${token}"
    validate_address_early "--watch-erc20 holder" "${holder}"
    add_targeted_watch "erc20" "${token}" "${holder}" "${label}"
}

parse_watch_native_spec() {
    # Expected: <address>[=<label>]
    local spec="$1"
    local label=""
    if [[ "${spec}" == *"="* ]]; then
        label="${spec#*=}"
        spec="${spec%%=*}"
    fi
    if [[ -z "${spec}" ]]; then
        echo "error: --watch-native expects <address>[=<label>] (got: $1)" >&2
        exit 2
    fi
    validate_address_early "--watch-native" "${spec}"
    add_targeted_watch "native" "" "${spec}" "${label}"
    # Also add to the broadcast watch list so the existing addresses map stays consistent.
    EXTRA_WATCH_ADDRS+=("${spec}")
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --watch)
            if [[ -z "${2:-}" ]]; then echo "error: --watch requires an address" >&2; exit 2; fi
            EXTRA_WATCH_ADDRS+=("$2")
            shift 2
            ;;
        --erc20)
            if [[ -z "${2:-}" ]]; then echo "error: --erc20 requires a token address" >&2; exit 2; fi
            ERC20_TOKENS+=("$2")
            shift 2
            ;;
        --watch-erc20)
            if [[ -z "${2:-}" ]]; then echo "error: --watch-erc20 requires <token>:<holder>[=<label>]" >&2; exit 2; fi
            CLI_WATCH_ERC20+=("$2")
            shift 2
            ;;
        --watch-native)
            if [[ -z "${2:-}" ]]; then echo "error: --watch-native requires <address>[=<label>]" >&2; exit 2; fi
            CLI_WATCH_NATIVE+=("$2")
            shift 2
            ;;
        --watch-config)
            if [[ -z "${2:-}" ]]; then echo "error: --watch-config requires a path" >&2; exit 2; fi
            WATCH_CONFIG_PATH="$2"
            WATCH_CONFIG_EXPLICIT=1
            shift 2
            ;;
        --no-watch-config)
            WATCH_CONFIG_DISABLED=1
            shift
            ;;
        --out-dir)
            if [[ -z "${2:-}" ]]; then echo "error: --out-dir requires a path" >&2; exit 2; fi
            OUT_DIR_OVERRIDE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do POSITIONAL+=("$1"); shift; done
            ;;
        -*)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

WS="${POSITIONAL[0]:-}"
TX="${POSITIONAL[1]:-}"
RPC="${POSITIONAL[2]:-${POLYGON_RPC:-https://polygon-rpc.com}}"

if [[ -z "${WS}" || -z "${TX}" ]]; then
    usage >&2
    exit 2
fi

if [[ ! "${TX}" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo "error: tx-hash must be 0x + 64 hex chars (got: ${TX})" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Watch-config loading (PR 105)
# ---------------------------------------------------------------------------
# Strict JSON schema:
# {
#   "schema_version": 1,
#   "native_watches": [ {"address": "0x...", "label": "victim"} ],
#   "erc20_watches":  [ {"token": "0x...", "holder": "0x...", "label": "..."} ]
# }
#
# Config specs are emitted as `--watch-native <addr>[=<label>]` or
# `--watch-erc20 <tok>:<holder>[=<label>]` lines on stdout; the shell then
# feeds them into the same pipeline as CLI flags. Config specs are processed
# BEFORE CLI specs, so config labels win on dedup conflicts (first-seen wins).
# Any validation failure exits non-zero BEFORE any RPC call.
load_watch_config_expand() {
    local cfg_path="$1"
    python3 - "${cfg_path}" <<'PY'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    raw = path.read_text()
except OSError as exc:
    print(f"[fork-replay] config error: cannot read {path}: {exc}", file=sys.stderr)
    sys.exit(2)

try:
    data = json.loads(raw)
except json.JSONDecodeError as exc:
    print(f"[fork-replay] config error: malformed JSON in {path}: {exc}", file=sys.stderr)
    sys.exit(2)

if not isinstance(data, dict):
    print(f"[fork-replay] config error: top-level value in {path} must be an object", file=sys.stderr)
    sys.exit(2)

ALLOWED_TOP = {"schema_version", "native_watches", "erc20_watches"}
extra = set(data.keys()) - ALLOWED_TOP
if extra:
    print(f"[fork-replay] config error: unknown top-level keys in {path}: {sorted(extra)}", file=sys.stderr)
    sys.exit(2)

if "schema_version" not in data:
    print(f"[fork-replay] config error: missing required key 'schema_version' in {path}", file=sys.stderr)
    sys.exit(2)
if data["schema_version"] != 1:
    print(f"[fork-replay] config error: unsupported schema_version {data['schema_version']!r} in {path} (expected 1)", file=sys.stderr)
    sys.exit(2)

ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

def _is_str(x):
    return isinstance(x, str)

native_watches = data.get("native_watches", [])
if not isinstance(native_watches, list):
    print(f"[fork-replay] config error: 'native_watches' in {path} must be a list", file=sys.stderr)
    sys.exit(2)
erc20_watches = data.get("erc20_watches", [])
if not isinstance(erc20_watches, list):
    print(f"[fork-replay] config error: 'erc20_watches' in {path} must be a list", file=sys.stderr)
    sys.exit(2)

# Validate & emit native lines.
for idx, entry in enumerate(native_watches):
    if not isinstance(entry, dict):
        print(f"[fork-replay] config error: native_watches[{idx}] must be an object", file=sys.stderr)
        sys.exit(2)
    allowed = {"address", "label"}
    extra_e = set(entry.keys()) - allowed
    if extra_e:
        print(f"[fork-replay] config error: native_watches[{idx}] has unknown keys {sorted(extra_e)}", file=sys.stderr)
        sys.exit(2)
    if "address" not in entry:
        print(f"[fork-replay] config error: native_watches[{idx}] missing required 'address'", file=sys.stderr)
        sys.exit(2)
    addr = entry["address"]
    if not _is_str(addr) or not ADDR_RE.match(addr):
        print(f"[fork-replay] config error: native_watches[{idx}].address must be 0x + 40 hex chars (got {addr!r})", file=sys.stderr)
        sys.exit(2)
    label = entry.get("label", "")
    if label is not None and not _is_str(label):
        print(f"[fork-replay] config error: native_watches[{idx}].label must be a string", file=sys.stderr)
        sys.exit(2)
    label = label or ""
    if "=" in label or any(c.isspace() for c in label):
        print(f"[fork-replay] config error: native_watches[{idx}].label may not contain '=' or whitespace (got {label!r})", file=sys.stderr)
        sys.exit(2)
    spec = f"{addr}={label}" if label else addr
    print(f"--watch-native\t{spec}")

# Validate & emit erc20 lines.
for idx, entry in enumerate(erc20_watches):
    if not isinstance(entry, dict):
        print(f"[fork-replay] config error: erc20_watches[{idx}] must be an object", file=sys.stderr)
        sys.exit(2)
    allowed = {"token", "holder", "label"}
    extra_e = set(entry.keys()) - allowed
    if extra_e:
        print(f"[fork-replay] config error: erc20_watches[{idx}] has unknown keys {sorted(extra_e)}", file=sys.stderr)
        sys.exit(2)
    for required in ("token", "holder"):
        if required not in entry:
            print(f"[fork-replay] config error: erc20_watches[{idx}] missing required '{required}'", file=sys.stderr)
            sys.exit(2)
    token = entry["token"]
    holder = entry["holder"]
    if not _is_str(token) or not ADDR_RE.match(token):
        print(f"[fork-replay] config error: erc20_watches[{idx}].token must be 0x + 40 hex chars (got {token!r})", file=sys.stderr)
        sys.exit(2)
    if not _is_str(holder) or not ADDR_RE.match(holder):
        print(f"[fork-replay] config error: erc20_watches[{idx}].holder must be 0x + 40 hex chars (got {holder!r})", file=sys.stderr)
        sys.exit(2)
    label = entry.get("label", "")
    if label is not None and not _is_str(label):
        print(f"[fork-replay] config error: erc20_watches[{idx}].label must be a string", file=sys.stderr)
        sys.exit(2)
    label = label or ""
    if "=" in label or any(c.isspace() for c in label):
        print(f"[fork-replay] config error: erc20_watches[{idx}].label may not contain '=' or whitespace (got {label!r})", file=sys.stderr)
        sys.exit(2)
    spec = f"{token}:{holder}"
    if label:
        spec = f"{spec}={label}"
    print(f"--watch-erc20\t{spec}")
PY
}

# Determine effective config path.
DEFAULT_WATCH_CONFIG="${WS}/monitoring/fork_replay.watch.json"
EFFECTIVE_WATCH_CONFIG=""
if [[ ${WATCH_CONFIG_DISABLED} -eq 1 && ${WATCH_CONFIG_EXPLICIT} -eq 0 ]]; then
    EFFECTIVE_WATCH_CONFIG=""
elif [[ -n "${WATCH_CONFIG_PATH}" ]]; then
    # Explicit override: file MUST exist.
    if [[ ! -f "${WATCH_CONFIG_PATH}" ]]; then
        echo "[fork-replay] config error: --watch-config path does not exist: ${WATCH_CONFIG_PATH}" >&2
        exit 2
    fi
    EFFECTIVE_WATCH_CONFIG="${WATCH_CONFIG_PATH}"
elif [[ -f "${DEFAULT_WATCH_CONFIG}" ]]; then
    EFFECTIVE_WATCH_CONFIG="${DEFAULT_WATCH_CONFIG}"
fi

if [[ -n "${EFFECTIVE_WATCH_CONFIG}" ]]; then
    echo "[fork-replay] loading watch config: ${EFFECTIVE_WATCH_CONFIG}" >&2
    # Capture expansion output; python script exits nonzero on validation failure.
    WATCH_CONFIG_LINES="$(load_watch_config_expand "${EFFECTIVE_WATCH_CONFIG}")" || exit $?
    while IFS=$'\t' read -r flag spec; do
        [[ -z "${flag}" ]] && continue
        case "${flag}" in
            --watch-native) parse_watch_native_spec "${spec}" ;;
            --watch-erc20)  parse_watch_erc20_spec "${spec}" ;;
            *) echo "[fork-replay] config error: unexpected expansion flag ${flag}" >&2; exit 2 ;;
        esac
    done <<< "${WATCH_CONFIG_LINES}"
fi

# Now process deferred CLI watch specs AFTER config, so config labels win dedup.
if ((${#CLI_WATCH_ERC20[@]})); then
    for spec in "${CLI_WATCH_ERC20[@]}"; do
        parse_watch_erc20_spec "${spec}"
    done
fi
if ((${#CLI_WATCH_NATIVE[@]})); then
    for spec in "${CLI_WATCH_NATIVE[@]}"; do
        parse_watch_native_spec "${spec}"
    done
fi

OUT_DIR="${OUT_DIR_OVERRIDE:-${WS}/fork_replay}"
mkdir -p "${OUT_DIR}"

STATE_FILE="${OUT_DIR}/${TX}_state.json"
PRE_STATE_FILE="${OUT_DIR}/${TX}_pre_state.json"
POST_STATE_FILE="${OUT_DIR}/${TX}_post_state.json"
PRE_TARGETED_FILE="${OUT_DIR}/${TX}_pre_targeted.json"
POST_TARGETED_FILE="${OUT_DIR}/${TX}_post_targeted.json"
DELTAS_FILE="${OUT_DIR}/${TX}_deltas.json"
MANIFEST_FILE="${OUT_DIR}/${TX}_manifest.json"
TRACE_FILE="${OUT_DIR}/${TX}_trace.json"
YAML_FILE="${OUT_DIR}/${TX}_replay.yaml"

# In-scope CLOB v1/v2 addresses (from audit/scope.json).
# R89 should read scope.json dynamically; skeleton hardcodes the high-signal ones.
SCOPE_ADDRS=(
    "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e" # CTFExchange v1
    "0xC5d563A36AE78145C45a50134d48A1215220f80a" # NegRiskCTFExchange v1
    "0xE111180000d2663C0091e4f400237545B87B996B" # CTFExchangeV2
    "0xe2222d279d744050d28e00520010520000310F59" # NegRiskCTFExchangeV2
    "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045" # CTF / ConditionalTokens
    "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296" # NegRiskAdapter
    "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB" # USDC.e collateral
)

WATCH_ADDRS=()

validate_address() {
    local label="$1"
    local addr="$2"
    if [[ ! "${addr}" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
        echo "error: ${label} must be 0x + 40 hex chars (got: ${addr})" >&2
        exit 2
    fi
}

add_watch_addr() {
    local addr="$1"
    validate_address "--watch" "${addr}"
    local want
    want="$(printf '%s' "${addr}" | tr '[:upper:]' '[:lower:]')"
    local existing
    if ((${#WATCH_ADDRS[@]})); then
        for existing in "${WATCH_ADDRS[@]}"; do
            if [[ "$(printf '%s' "${existing}" | tr '[:upper:]' '[:lower:]')" == "${want}" ]]; then
                return
            fi
        done
    fi
    WATCH_ADDRS+=("${addr}")
}

for ADDR in "${SCOPE_ADDRS[@]}"; do
    add_watch_addr "${ADDR}"
done
if ((${#EXTRA_WATCH_ADDRS[@]})); then
    for ADDR in "${EXTRA_WATCH_ADDRS[@]}"; do
        add_watch_addr "${ADDR}"
    done
fi
if ((${#ERC20_TOKENS[@]})); then
    for TOKEN in "${ERC20_TOKENS[@]}"; do
        validate_address "--erc20" "${TOKEN}"
    done
fi

json_quote() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

snapshot_state() {
    local outfile="$1"
    local rpc="$2"
    local label="$3"
    local block_number
    block_number="$(cast block-number --rpc-url "${rpc}" 2>/dev/null || echo "unknown")"

    {
        echo "{"
        echo "  \"schema_version\": 1,"
        echo "  \"snapshot\": $(json_quote "${label}"),"
        echo "  \"block_number\": $(json_quote "${block_number}"),"
        echo "  \"addresses\": {"
    } > "${outfile}"

    local first_addr=1
    local addr
    for addr in "${WATCH_ADDRS[@]}"; do
        local codehash
        local native_balance
        local slot0
        codehash="$(cast keccak "$(cast code "${addr}" --rpc-url "${rpc}" 2>/dev/null || echo 0x)")"
        native_balance="$(cast balance "${addr}" --rpc-url "${rpc}" 2>/dev/null || echo 0)"
        slot0="$(cast storage "${addr}" 0 --rpc-url "${rpc}" 2>/dev/null || echo 0x)"
        if [[ ${first_addr} -eq 0 ]]; then echo "    ," >> "${outfile}"; fi
        first_addr=0
        {
            echo "    $(json_quote "${addr}"): {"
            echo "      \"codeHash\": $(json_quote "${codehash}"),"
            echo "      \"nativeBalanceWei\": $(json_quote "${native_balance}"),"
            echo "      \"slot0\": $(json_quote "${slot0}"),"
            echo "      \"erc20Balances\": {"
        } >> "${outfile}"

        local first_token=1
        local token
        if ((${#ERC20_TOKENS[@]})); then
            for token in "${ERC20_TOKENS[@]}"; do
                local token_balance
                token_balance="$(cast call "${token}" "balanceOf(address)(uint256)" "${addr}" --rpc-url "${rpc}" 2>/dev/null || echo "error")"
                if [[ ${first_token} -eq 0 ]]; then echo "        ," >> "${outfile}"; fi
                first_token=0
                echo "        $(json_quote "${token}"): $(json_quote "${token_balance}")" >> "${outfile}"
            done
        fi
        {
            echo "      }"
            echo "    }"
        } >> "${outfile}"
    done
    {
        echo "  }"
        echo "}"
    } >> "${outfile}"
}

snapshot_targeted() {
    # Writes a JSON array of targeted-watch rows with current balances.
    # Each entry: {label, kind, token, holder, balance (string|null), error (string|null)}.
    local outfile="$1"
    local rpc="$2"
    : > "${outfile}.rows.tmp"
    if ((${#TARGETED_WATCHES[@]} == 0)); then
        echo "[]" > "${outfile}"
        rm -f "${outfile}.rows.tmp"
        return
    fi
    local entry kind token holder label balance err
    for entry in "${TARGETED_WATCHES[@]}"; do
        kind="${entry%%|*}"; entry="${entry#*|}"
        token="${entry%%|*}"; entry="${entry#*|}"
        holder="${entry%%|*}"; entry="${entry#*|}"
        label="${entry}"
        balance=""
        err=""
        if [[ "${kind}" == "erc20" ]]; then
            if ! balance="$(cast call "${token}" "balanceOf(address)(uint256)" "${holder}" --rpc-url "${rpc}" 2>/dev/null)"; then
                balance=""
                err="balanceOf reverted or call failed"
            fi
            # An empty/unparseable return (e.g. "0x") also counts as an error.
            if [[ -z "${balance}" ]]; then
                err="${err:-balanceOf returned empty result}"
            fi
        else
            if ! balance="$(cast balance "${holder}" --rpc-url "${rpc}" 2>/dev/null)"; then
                balance=""
                err="eth_getBalance failed"
            fi
            if [[ -z "${balance}" ]]; then
                err="${err:-eth_getBalance returned empty result}"
            fi
        fi
        printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' \
            "${kind}" "${token}" "${holder}" "${label}" "${balance}" "${err}" \
            >> "${outfile}.rows.tmp"
    done

    python3 - "${outfile}.rows.tmp" "${outfile}" <<'PY'
import json
import sys
from pathlib import Path

rows_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
rows = []
for line in rows_path.read_text().splitlines():
    if not line:
        continue
    parts = line.split("\x1f")
    # pad in case of trailing empties
    while len(parts) < 6:
        parts.append("")
    kind, token, holder, label, balance, err = parts[:6]
    rows.append({
        "kind": kind,
        "token": token or None,
        "holder": holder,
        "label": label,
        "balance": balance if balance else None,
        "error": err if err else None,
    })
out_path.write_text(json.dumps(rows, indent=2) + "\n")
PY
    rm -f "${outfile}.rows.tmp"
}

write_deltas() {
    local pre_file="$1"
    local post_file="$2"
    local out_file="$3"
    local pre_targeted="${4:-}"
    local post_targeted="${5:-}"
    python3 - "$pre_file" "$post_file" "$out_file" "$pre_targeted" "$post_targeted" <<'PY'
import json
import re
import sys
from pathlib import Path

pre = json.loads(Path(sys.argv[1]).read_text())
post = json.loads(Path(sys.argv[2]).read_text())
pre_targeted_path = sys.argv[4] if len(sys.argv) > 4 else ""
post_targeted_path = sys.argv[5] if len(sys.argv) > 5 else ""


def as_int(value):
    if value in (None, "", "error"):
        return None
    s = str(value).strip()
    if not s:
        return None
    # `cast call` may return "123 [0x7b]" or plain decimal or 0x-hex.
    m = re.match(r"^(-?0x[0-9a-fA-F]+|-?\d+)", s)
    if m:
        s = m.group(1)
    try:
        return int(s, 0)
    except ValueError:
        return None


addresses = sorted(set(pre.get("addresses", {})) | set(post.get("addresses", {})))
rows = {}
for address in addresses:
    before = pre.get("addresses", {}).get(address, {})
    after = post.get("addresses", {}).get(address, {})
    before_native = as_int(before.get("nativeBalanceWei"))
    after_native = as_int(after.get("nativeBalanceWei"))
    native_delta = None
    if before_native is not None and after_native is not None:
        native_delta = str(after_native - before_native)

    tokens = sorted(
        set(before.get("erc20Balances", {})) | set(after.get("erc20Balances", {}))
    )
    token_rows = {}
    for token in tokens:
        before_token = as_int(before.get("erc20Balances", {}).get(token))
        after_token = as_int(after.get("erc20Balances", {}).get(token))
        token_delta = None
        if before_token is not None and after_token is not None:
            token_delta = str(after_token - before_token)
        token_rows[token] = {
            "pre": None if before_token is None else str(before_token),
            "post": None if after_token is None else str(after_token),
            "delta": token_delta,
        }

    rows[address] = {
        "nativeWei": {
            "pre": None if before_native is None else str(before_native),
            "post": None if after_native is None else str(after_native),
            "delta": native_delta,
        },
        "erc20": token_rows,
    }

def _load_targeted(path):
    if not path:
        return []
    try:
        data = json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return data


pre_targeted = _load_targeted(pre_targeted_path)
post_targeted = _load_targeted(post_targeted_path)


def _key(entry):
    tok = (entry.get("token") or "native").lower()
    hol = (entry.get("holder") or "").lower()
    return f"{tok}:{hol}"


pre_by_key = {_key(e): e for e in pre_targeted}
post_by_key = {_key(e): e for e in post_targeted}

targeted_rows = []
# Preserve insertion order from pre (which is the first-seen CLI order after dedup).
seen_keys = set()
ordered_keys = []
for e in pre_targeted:
    k = _key(e)
    if k not in seen_keys:
        seen_keys.add(k)
        ordered_keys.append(k)
for e in post_targeted:
    k = _key(e)
    if k not in seen_keys:
        seen_keys.add(k)
        ordered_keys.append(k)

for key in ordered_keys:
    pre_entry = pre_by_key.get(key, {})
    post_entry = post_by_key.get(key, {})
    # Prefer the pre entry's identity fields; fall back to post.
    label = pre_entry.get("label") or post_entry.get("label") or ""
    kind = pre_entry.get("kind") or post_entry.get("kind") or "erc20"
    token = pre_entry.get("token") or post_entry.get("token")
    holder = pre_entry.get("holder") or post_entry.get("holder") or ""

    pre_err = pre_entry.get("error")
    post_err = post_entry.get("error")
    pre_bal = as_int(pre_entry.get("balance"))
    post_bal = as_int(post_entry.get("balance"))

    error_str = None
    if pre_err or post_err:
        parts = []
        if pre_err:
            parts.append(f"pre: {pre_err}")
        if post_err:
            parts.append(f"post: {post_err}")
        error_str = "; ".join(parts)
    elif pre_bal is None and pre_entry.get("balance") is not None:
        error_str = "pre: could not parse balance"
    elif post_bal is None and post_entry.get("balance") is not None:
        error_str = "post: could not parse balance"

    if error_str:
        pre_s = None if pre_bal is None else str(pre_bal)
        post_s = None if post_bal is None else str(post_bal)
        delta_s = None
    else:
        pre_s = None if pre_bal is None else str(pre_bal)
        post_s = None if post_bal is None else str(post_bal)
        delta_s = None
        if pre_bal is not None and post_bal is not None:
            delta_s = str(post_bal - pre_bal)
        else:
            # Balance missing on one side without an explicit error = treat as error.
            error_str = "missing balance on pre or post snapshot"

    row = {
        "label": label,
        "kind": kind,
        "token": token,
        "holder": holder,
        "pre": pre_s,
        "post": post_s,
        "delta": delta_s,
        "error": error_str,
    }
    targeted_rows.append(row)

Path(sys.argv[3]).write_text(
    json.dumps(
        {
            "schema_version": 1,
            "pre_block_number": pre.get("block_number"),
            "post_block_number": post.get("block_number"),
            "addresses": rows,
            "targeted_watches": targeted_rows,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
PY
}

echo "[fork-replay] tx=${TX}"
echo "[fork-replay] rpc=${RPC}"
echo "[fork-replay] watched addresses=${#WATCH_ADDRS[@]}, erc20 tokens=${#ERC20_TOKENS[@]}, targeted watches=${#TARGETED_WATCHES[@]}"

# 1. Resolve tx metadata.
TX_META="$(cast tx "${TX}" --rpc-url "${RPC}" --json)"
BLOCK_HEX="$(printf '%s' "${TX_META}" | jq -r '.blockNumber')"
BLOCK_DEC="$(cast to-dec "${BLOCK_HEX}")"
FROM_ADDR="$(printf '%s' "${TX_META}" | jq -r '.from')"
TO_ADDR="$(printf '%s' "${TX_META}" | jq -r '.to // empty')"
FORK_BLOCK=$((BLOCK_DEC - 1))

echo "[fork-replay] tx.block=${BLOCK_DEC}, fork at ${FORK_BLOCK}, from=${FROM_ADDR}, to=${TO_ADDR}"

# 2. Pull debug_traceTransaction for post-mortem diff. (Requires a trace-capable RPC.)
if ! cast rpc debug_traceTransaction "${TX}" '{"tracer":"callTracer"}' --rpc-url "${RPC}" \
        > "${TRACE_FILE}" 2>/dev/null ; then
    echo "[fork-replay] WARN: debug_traceTransaction unavailable on ${RPC} — leaving trace empty" >&2
    echo '{"note":"trace unavailable on this rpc"}' > "${TRACE_FILE}"
fi

# 3. Spin up anvil fork at block-1, replay tx, snapshot state.
ANVIL_PORT="${ANVIL_PORT:-8546}"
anvil --fork-url "${RPC}" --fork-block-number "${FORK_BLOCK}" \
      --port "${ANVIL_PORT}" --silent > /tmp/fork-replay-anvil.log 2>&1 &
ANVIL_PID=$!
trap 'kill ${ANVIL_PID} 2>/dev/null || true' EXIT

# Wait for anvil readiness (max 10s).
for _ in $(seq 1 20); do
    if cast block-number --rpc-url "http://127.0.0.1:${ANVIL_PORT}" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

LOCAL_RPC="http://127.0.0.1:${ANVIL_PORT}"

snapshot_state "${PRE_STATE_FILE}" "${LOCAL_RPC}" "pre-replay"
snapshot_targeted "${PRE_TARGETED_FILE}" "${LOCAL_RPC}"

# Roll one block forward and replay the tx via `cast run`. `cast run` executes
# the tx against the fork and prints the trace; we pipe it into the trace file
# as the "replay trace" (distinct from mainnet trace, so diffs are meaningful).
REPLAY_TRACE_FILE="${OUT_DIR}/${TX}_replay_trace.txt"
REPLAY_STATUS="executed"
if ! cast run "${TX}" --rpc-url "${LOCAL_RPC}" --quick > "${REPLAY_TRACE_FILE}" 2>&1 ; then
    echo "[fork-replay] WARN: cast run replay failed — see ${REPLAY_TRACE_FILE}" >&2
    REPLAY_STATUS="failed"
fi

# 4. Snapshot per-address post-state and derive native/ERC20 deltas. Slot list
#    is still intentionally small; targeted invariants should add exact slots
#    or higher-level calls around the claim being proven.
snapshot_state "${POST_STATE_FILE}" "${LOCAL_RPC}" "post-replay"
snapshot_targeted "${POST_TARGETED_FILE}" "${LOCAL_RPC}"
cp "${POST_STATE_FILE}" "${STATE_FILE}"
write_deltas "${PRE_STATE_FILE}" "${POST_STATE_FILE}" "${DELTAS_FILE}" "${PRE_TARGETED_FILE}" "${POST_TARGETED_FILE}"

# 5. Invariant assertions — STUB. R89 should port from audit/InvariantL4_scaffold.sol.
#    Current stub only checks: (a) tx recipient is in-scope, (b) no panic in replay trace.
INVARIANT_RESULTS=()
if printf '%s\n' "${WATCH_ADDRS[@]}" | grep -iq "^${TO_ADDR}$"; then
    INVARIANT_RESULTS+=("in_scope_target: pass")
else
    INVARIANT_RESULTS+=("in_scope_target: fail (to=${TO_ADDR})")
fi
if grep -q "Panic" "${REPLAY_TRACE_FILE}" 2>/dev/null; then
    INVARIANT_RESULTS+=("no_panic: fail")
else
    INVARIANT_RESULTS+=("no_panic: pass")
fi
# TODO R89: global_solvency, per_user_balance_delta, pause_consistency,
#           orderStatus_monotonic, ctf_supply_invariant.

# 6. Emit YAML summary.
{
    echo "tx: \"${TX}\""
    echo "rpc: \"${RPC}\""
    echo "block: ${BLOCK_DEC}"
    echo "fork_block: ${FORK_BLOCK}"
    echo "from: \"${FROM_ADDR}\""
    echo "to: \"${TO_ADDR}\""
    echo "artifacts:"
    echo "  pre_state: \"${PRE_STATE_FILE}\""
    echo "  post_state: \"${POST_STATE_FILE}\""
    echo "  state: \"${STATE_FILE}\""
    echo "  deltas: \"${DELTAS_FILE}\""
    echo "  manifest: \"${MANIFEST_FILE}\""
    echo "  mainnet_trace: \"${TRACE_FILE}\""
    echo "  replay_trace: \"${REPLAY_TRACE_FILE}\""
    echo "watched_addresses:"
    for ADDR in "${WATCH_ADDRS[@]}"; do
        echo "  - \"${ADDR}\""
    done
    echo "erc20_tokens:"
    if ((${#ERC20_TOKENS[@]})); then
        for TOKEN in "${ERC20_TOKENS[@]}"; do
            echo "  - \"${TOKEN}\""
        done
    fi
    echo "targeted_watches:"
    if ((${#TARGETED_WATCHES[@]})); then
        for ENTRY in "${TARGETED_WATCHES[@]}"; do
            IFS='|' read -r TW_KIND TW_TOKEN TW_HOLDER TW_LABEL <<< "${ENTRY}"
            echo "  - kind: \"${TW_KIND}\""
            echo "    token: \"${TW_TOKEN}\""
            echo "    holder: \"${TW_HOLDER}\""
            echo "    label: \"${TW_LABEL}\""
        done
    fi
    echo "invariants:"
    if ((${#INVARIANT_RESULTS[@]})); then
        for R in "${INVARIANT_RESULTS[@]}"; do
            echo "  - \"${R}\""
        done
    fi
    echo "schema_version: 1"
    echo "status: \"${REPLAY_STATUS}\""
} > "${YAML_FILE}"

python3 - "${MANIFEST_FILE}" "${TX}" "${RPC}" "${BLOCK_DEC}" "${FORK_BLOCK}" "${FROM_ADDR}" "${TO_ADDR}" "${REPLAY_STATUS}" "${PRE_STATE_FILE}" "${POST_STATE_FILE}" "${DELTAS_FILE}" "${TRACE_FILE}" "${REPLAY_TRACE_FILE}" "${YAML_FILE}" <<'PY'
import json
import sys
from pathlib import Path

(
    manifest_file,
    tx,
    rpc,
    block_dec,
    fork_block,
    from_addr,
    to_addr,
    status,
    pre_state,
    post_state,
    deltas,
    mainnet_trace,
    replay_trace,
    yaml_file,
) = sys.argv[1:]

Path(manifest_file).write_text(
    json.dumps(
        {
            "schema_version": 1,
            "status": status,
            "tx": tx,
            "rpc": rpc,
            "block": int(block_dec),
            "fork_block": int(fork_block),
            "from": from_addr,
            "to": to_addr,
            "artifacts": {
                "pre_state": pre_state,
                "post_state": post_state,
                "deltas": deltas,
                "mainnet_trace": mainnet_trace,
                "replay_trace": replay_trace,
                "summary": yaml_file,
            },
        },
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
PY

echo "[fork-replay] done -> ${YAML_FILE}"
