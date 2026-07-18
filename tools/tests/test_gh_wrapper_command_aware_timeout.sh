#!/usr/bin/env bash
# Regression: the auditooor gh wrapper must apply a COMMAND-AWARE timeout.
# A read-only BULK data command (issue/pr list, api, search) must get the long
# read timeout (so a legit multi-minute enumeration is NOT truncated), while the
# auth/token path keeps the tight anti-hang cap. Before the fix, a single 30s cap
# guillotined large `gh issue list` enumerations to empty -> silent unauth-curl
# fallback (Axelar known-issues intake 2026-07-12).
set -uo pipefail
WRAPPER="$(cd "$(dirname "$0")/.." && pwd)/auditooor-gh-wrapper.sh"
[ -x "$WRAPPER" ] || { echo "FAIL: wrapper not executable at $WRAPPER"; exit 1; }
command -v gtimeout >/dev/null 2>&1 || command -v timeout >/dev/null 2>&1 || {
  echo "SKIP: no timeout/gtimeout binary on this host"; exit 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# stub "real gh" that sleeps 3s then prints OK (simulates a slow enumeration)
STUB="$TMP/gh_stub.sh"
cat > "$STUB" <<'EOS'
#!/usr/bin/env bash
sleep 3
echo "OK $*"
EOS
chmod +x "$STUB"

# Skip freshness/token gates - we are testing the timeout classifier only.
export AUDITOOOR_REAL_GH="$STUB"
export AUDITOOOR_NO_FRESHNESS_CHECK=1
export AUDITOOOR_MCP_REQUIRED=0
export AUDITOOOR_GH_TIMEOUT_S=1      # tight cap (auth/token)
export AUDITOOOR_GH_READ_TIMEOUT_S=6 # generous cap (bulk read)

fails=0

# (1) read-only bulk: `issue list` -> 6s cap, stub sleeps 3s -> SURVIVES
out="$(bash "$WRAPPER" issue list --repo x/y --state all --limit 5000 2>/dev/null)"
if [[ "$out" == OK* ]]; then
  echo "PASS: read-only 'issue list' survived the tight cap (got: $out)"
else
  echo "FAIL: 'issue list' was truncated/killed under read timeout (out='$out')"; fails=$((fails+1))
fi

# (2) api (graphql/rest walk) -> also bulk-read -> SURVIVES
out2="$(bash "$WRAPPER" api graphql -f query='...' 2>/dev/null)"
if [[ "$out2" == OK* ]]; then
  echo "PASS: 'api' survived the tight cap"
else
  echo "FAIL: 'api' was killed under read timeout (out='$out2')"; fails=$((fails+1))
fi

# (3) auth token -> tight 1s cap, stub sleeps 3s -> KILLED (empty)
out3="$(bash "$WRAPPER" auth token 2>/dev/null)"
if [[ -z "$out3" ]]; then
  echo "PASS: 'auth token' still bounded by the tight anti-hang cap"
else
  echo "FAIL: 'auth token' NOT bounded by tight cap (out='$out3')"; fails=$((fails+1))
fi

if [ "$fails" -eq 0 ]; then echo "ALL PASS"; exit 0; else echo "$fails FAIL(s)"; exit 1; fi
