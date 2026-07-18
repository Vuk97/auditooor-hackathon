#!/usr/bin/env bash
# layer4-baseline.sh — mechanical scaffolder for Phase 5.5 (post-mechanical Layer 4)
#
# Usage: ./tools/layer4-baseline.sh <workspace-dir>
#
# Produces (all zero-token, mechanical):
#   <ws>/REDTEAM_REOPEN.md          — checklist of every CLOSED entry in FINDINGS.md
#   <ws>/adversarial_targets.md     — top-3 hot functions by complexity × state writes
#   <ws>/InvariantL4_scaffold.sol   — Foundry invariant test skeleton + handler
#   <ws>/LAYER4_STATUS.md           — "what ran, what needs an agent, token budget"
#
# The skill documentation (methodology/iteration_workflow.md §5.5) uses these
# artifacts as the entry point for Phase 5.5. The agent phases below consume
# the mechanically-generated files and spend ≤ 10k tokens total on a clean pass.
#
# Tracks:
#   R — Red-team closed findings (this script does the extraction; 1 agent reviews)
#   F — Foundry invariants (this script scaffolds; agent only fires on break)
#   A — Adversarial function read (this script picks targets; 3 agents read)

set -euo pipefail

WS="${1:-}"
if [ -z "$WS" ]; then
    echo "Usage: $0 <workspace-dir>" >&2
    exit 1
fi

if [ ! -d "$WS" ]; then
    echo "[error] workspace not found: $WS" >&2
    exit 1
fi

FINDINGS="$WS/FINDINGS.md"
OUT_REDTEAM="$WS/REDTEAM_CHECKLIST.md"
OUT_TARGETS="$WS/adversarial_targets.md"
OUT_SCAFFOLD="$WS/InvariantL4_scaffold.sol"
OUT_STATUS="$WS/LAYER4_STATUS.md"

echo "============================================================================"
echo "Layer 4 baseline — mechanical scaffolder"
echo "Workspace: $WS"
echo "============================================================================"
echo

# ---------------------------------------------------------------------------
# Track R — extract all CLOSED entries from FINDINGS.md
# ---------------------------------------------------------------------------
echo "[Track R] Extracting CLOSED findings..."

if [ ! -f "$FINDINGS" ]; then
    echo "  [skip] FINDINGS.md not found — run the audit first"
    CLOSED_COUNT=0
else
    python3 - "$FINDINGS" "$OUT_REDTEAM" <<'PY'
import re, sys

findings_path, out_path = sys.argv[1], sys.argv[2]
content = open(findings_path).read()

# Match every heading or table row that looks like a closed/rejected/informational entry.
# We capture (a) explicit "### #FOO —" headings, and (b) any row that contains CLOSED / ❌ / Informational.
closures = []

# Pattern 1: "### #<ID> — <title>" followed by "Status: ❌ CLOSED" or "| Status | ❌ CLOSED"
heading_re = re.compile(r"^#{3,4}\s+(#?[\w.\-]+)\s*[—\-:]\s*(.+?)$", re.M)
for m in heading_re.finditer(content):
    start = m.start()
    block = content[start:start+3000]  # next 3000 chars
    if re.search(r"(?i)(❌|closed|closure|not a bug|rejected|informational|close-as)", block):
        closures.append((m.group(1), m.group(2).strip()))

# Pattern 2: table rows with "CLOSE-AS-" verdicts (iter 22b style)
table_re = re.compile(r"^\|\s*\*?\*?(#[\w\.\-]+)\*?\*?\s+(.+?)\s*\|\s*(?:Info.*|Low.*|.*)\s*\|\s*\*?\*?(CLOSE[\w\-]*|INFORM[\w\-]*)\*?\*?", re.M)
for m in table_re.finditer(content):
    closures.append((m.group(1), m.group(2)[:80]))

# Dedupe, preserve order
seen = set()
unique = []
for id_, title in closures:
    key = id_.lstrip("#")
    if key not in seen:
        seen.add(key)
        unique.append((id_, title))

with open(out_path, "w") as f:
    f.write("# Red-Team Reopen Checklist (Track R)\n\n")
    f.write("**Generated:** mechanical extraction from FINDINGS.md by `layer4-baseline.sh`\n")
    f.write("**Next step:** dispatch ONE agent with `agent_briefs.md` Template R (red-team) — the agent applies the 5 adversarial prompts to each row below and promotes rows to REOPEN with $ math.\n\n")
    f.write("## Adversarial prompts to apply per row\n\n")
    f.write("1. What if the closure's premise misreads the source? (re-read file:line)\n")
    f.write("2. What if the OOS clause doesn't apply verbatim? (cite SCOPE.md word-for-word)\n")
    f.write("3. What if the attacker has NON-admin access? (permissionless path)\n")
    f.write("4. What about the cross-contract path? (other callers into X)\n")
    f.write("5. What's the $ math? (default UP when ambiguous, per anti-pattern #25)\n\n")
    f.write(f"## Closed findings to review ({len(unique)})\n\n")
    f.write("| # | ID | Title | Adversarial verdict (fill in) | Reopen? |\n")
    f.write("|---|---|---|---|---|\n")
    for i, (id_, title) in enumerate(unique, 1):
        f.write(f"| {i} | {id_} | {title} | _pending agent_ | _pending_ |\n")

print(f"  [ok] wrote {len(unique)} closed-entry rows to {out_path}")
sys.exit(0)
PY
    CLOSED_COUNT=$(grep -c "^|" "$OUT_REDTEAM" 2>/dev/null || echo 0)
    CLOSED_COUNT=$((CLOSED_COUNT - 1))  # minus header row
fi

echo

# ---------------------------------------------------------------------------
# Track A — rank functions by complexity × state-write count
# ---------------------------------------------------------------------------
echo "[Track A] Ranking hot functions by complexity..."

SRC_DIR=""
for candidate in "$WS/src" "$WS/ctf-exchange-v2/src" "$WS/contracts" "$WS/../src"; do
    if [ -d "$candidate" ]; then
        SRC_DIR="$candidate"
        break
    fi
done

if [ -z "$SRC_DIR" ]; then
    echo "  [skip] source directory not found — run from audit workspace root"
    HOTFUNC_COUNT=0
else
    # Heuristic: for each .sol file in src/, count lines per function,
    # then pick the top 3 functions (excluding tests/mocks/dev/scripts).
    python3 - "$SRC_DIR" "$OUT_TARGETS" <<'PY'
import re, sys, os
from pathlib import Path

src_dir, out_path = sys.argv[1], sys.argv[2]
SKIP_PATTERNS = ("/test/", "/tests/", "/dev/", "/mocks/", "/mock/", "/scripts/", "/script/")

functions = []  # (score, file, name, line, body_lines)

func_re = re.compile(r"^\s*function\s+(\w+)\s*\([^)]*\)\s*(?:(?:public|external|internal|private|view|pure|payable|override|virtual|returns|[\w,\s()])*)\s*\{", re.M)

for path in Path(src_dir).rglob("*.sol"):
    p = str(path)
    if any(s in p for s in SKIP_PATTERNS):
        continue
    try:
        text = path.read_text()
    except Exception:
        continue
    # Walk functions via simple brace matching
    for m in func_re.finditer(text):
        name = m.group(1)
        if name.startswith("_") and name in ("_authorizeUpgrade",):
            # still interesting
            pass
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[start:i]
        # Skip trivial functions (1-3 lines)
        body_lines = body.count("\n")
        if body_lines < 5:
            continue
        # Score = body lines + 2 * state-write count (heuristic for complexity)
        state_writes = len(re.findall(r"\b\w+\[[^\]]+\]\s*=", body)) + len(re.findall(r"\b\w+\s*\+=|\b\w+\s*-=|\+\+\w+|--\w+|\w+\+\+|\w+--", body))
        external_calls = len(re.findall(r"\.\w+\s*\(", body))
        score = body_lines + 3 * state_writes + 2 * external_calls
        line_no = text[:m.start()].count("\n") + 1
        rel_path = os.path.relpath(p, src_dir)
        functions.append((score, rel_path, name, line_no, body_lines, state_writes, external_calls))

functions.sort(reverse=True, key=lambda x: x[0])
top = functions[:10]

with open(out_path, "w") as f:
    f.write("# Adversarial Read Targets (Track A)\n\n")
    f.write("**Generated:** mechanical ranking by `layer4-baseline.sh` — complexity = body-lines + 3×state-writes + 2×external-calls\n")
    f.write("**Next step:** dispatch 3 parallel agents (one per top-3 function) with `agent_briefs.md` Template B, applying the 17-question adversarial reading checklist.\n\n")
    f.write("## Top-10 ranked (pick top 3 for agent dispatch)\n\n")
    f.write("| Rank | Score | File | Function | Line | Body | State writes | External calls |\n")
    f.write("|---|---|---|---|---|---|---|---|\n")
    for i, (score, path, name, line, body, sw, ec) in enumerate(top, 1):
        f.write(f"| {i} | {score} | `{path}` | `{name}` | {line} | {body}L | {sw} | {ec} |\n")
    f.write("\n")
    f.write("## Recommended dispatch\n\n")
    if len(top) >= 3:
        for i in range(3):
            s = top[i]
            f.write(f"- **Agent A{i+1}:** read `{s[1]}:{s[3]}` — `{s[2]}()` ({s[4]} lines, {s[5]} state writes, {s[6]} external calls)\n")
    f.write("\n## 17-question checklist to apply (per function)\n\n")
    f.write("State machine: 1) full list of state writes, 2) ordering/partial windows, 3) reentrancy path, 4) input ordering assumptions\n")
    f.write("Arithmetic: 5) overflow sites, 6) rounding direction & inverse pairing, 7) zero-fill-amount edge, 8) length-0/1/N branches\n")
    f.write("Access: 9) who is trusted, 10) can caller exceed their signed bounds, 11) self-match consequences\n")
    f.write("Cross-contract: 12) external callees, 13) reentrancy via those callees, 14) external preconditions\n")
    f.write("Fee: 15) computed on which side, 16) setter bounds, 17) fee-on-transfer compatibility\n")

print(f"  [ok] ranked {len(functions)} functions, wrote top-10 to {out_path}")
sys.exit(0)
PY
    HOTFUNC_COUNT=$(grep -c "^| [0-9]" "$OUT_TARGETS" 2>/dev/null || echo 0)
fi

echo

# ---------------------------------------------------------------------------
# Track F — scaffold the Foundry invariant test
# ---------------------------------------------------------------------------
echo "[Track F] Scaffolding Foundry invariant test..."

if [ -z "$SRC_DIR" ]; then
    echo "  [skip] source directory not found"
    INVARIANT_COUNT=0
else
    cat > "$OUT_SCAFFOLD" <<'SOL'
// SPDX-License-Identifier: MIT
// AUTO-SCAFFOLDED by tools/layer4-baseline.sh — adapt to your contract APIs before running.
// Drop this file in src/test/InvariantL4.t.sol and run:
//     PATH="$HOME/.foundry/bin:$PATH" forge test --match-path 'src/test/InvariantL4*' --fuzz-runs 10000

pragma solidity <0.9.0;

import { Test } from "@forge-std/src/Test.sol";
import { StdInvariant } from "@forge-std/src/StdInvariant.sol";

/// @dev Standard invariant library. Adapt the handler actions to your
/// contract API and uncomment/remove invariants that don't match the
/// contract shape.
contract Handler is Test {
    // TODO: import your contract-under-test and wire handler actions.

    // Example actions (uncomment as needed):
    // function placeAndMatchOrder(uint256 seed, uint256 amt, uint256 price) public { ... }
    // function wrap(uint256 amt) public { ... }
    // function unwrap(uint256 amt) public { ... }
    // function pauseUser() public { ... }
}

contract InvariantL4 is StdInvariant, Test {
    Handler internal handler;
    // TODO: deploy your system-under-test in setUp() and
    //       `targetContract(address(handler));`

    function setUp() public {
        handler = new Handler();
        targetContract(address(handler));
    }

    // -------------------------------------------------------------------
    // ERC20/ERC4626 core invariants (uncomment if your system has them)
    // -------------------------------------------------------------------

    // function invariant_erc20_sumOfBalances_eq_totalSupply() public view {
    //     // Sum of all known-user balances + exchange holdings == totalSupply
    //     assertEq(
    //         token.totalSupply(),
    //         token.balanceOf(alice) + token.balanceOf(brian) + token.balanceOf(exchange)
    //     );
    // }

    // function invariant_erc4626_totalAssets_gte_totalSupply_at_parity() public view {
    //     // totalAssets >= totalSupply when pricePerShare >= 1.0
    //     assertGe(vault.totalAssets(), vault.totalSupply());
    // }

    // -------------------------------------------------------------------
    // Vault-backing invariant (uncomment for wrap/unwrap systems)
    // -------------------------------------------------------------------

    // function invariant_vaultBackingRatio() public view {
    //     // Vault holds at least 1:1 underlying backing for every wrapped token
    //     uint256 backing = underlying1.balanceOf(VAULT) + underlying2.balanceOf(VAULT);
    //     assertGe(backing, wrappedToken.totalSupply());
    // }

    // -------------------------------------------------------------------
    // Order-book / CLOB invariants (uncomment for matching engines)
    // -------------------------------------------------------------------

    // function invariant_orderStatus_remaining_monotonic() public view {
    //     // handler records high-water mark; no order's remaining field ever increases
    //     for (uint256 i = 0; i < handler.trackedOrderCount(); i++) {
    //         bytes32 h = handler.trackedOrder(i);
    //         assertLe(orderbook.remaining(h), handler.initialRemaining(h));
    //     }
    // }

    // function invariant_match_atomic_no_partial_leftover() public view {
    //     // matchOrders either settles all makers or reverts — no partial leftover state
    //     assertEq(handler.abortedMatchCount(), handler.leftoverStateWrites());
    // }

    // -------------------------------------------------------------------
    // Fee invariants (uncomment for fee-charging systems)
    // -------------------------------------------------------------------

    // function invariant_fee_bounded_by_max() public view {
    //     // Every historical fee emission <= amount * maxFeeRate / 1e4
    //     assertLe(handler.maxObservedFee(), handler.maxObservedAmount() * exchange.maxFeeRate() / 10000);
    // }

    // function invariant_feeReceiver_only_increases() public view {
    //     // Fee receiver balance can only grow
    //     assertGe(token.balanceOf(feeReceiver), handler.prevFeeReceiverBalance());
    // }

    // -------------------------------------------------------------------
    // Pausability invariants (uncomment for pausable contracts)
    // -------------------------------------------------------------------

    // function invariant_userPause_monotonic() public view {
    //     // userPausedBlockAt[user] never decreases
    //     for (uint256 i = 0; i < handler.trackedUserCount(); i++) {
    //         address u = handler.trackedUser(i);
    //         assertGe(pausable.userPausedBlockAt(u), handler.prevPausedAt(u));
    //     }
    // }

    // -------------------------------------------------------------------
    // Access-control invariants (uncomment for role-based systems)
    // -------------------------------------------------------------------

    // function invariant_adminCount_consistent_with_role_mapping() public view {
    //     // adminCount (if tracked) matches the number of true bits in admins mapping
    //     uint256 count = 0;
    //     for (uint256 i = 0; i < handler.trackedAddrCount(); i++) {
    //         if (auth.admins(handler.trackedAddr(i))) count++;
    //     }
    //     assertEq(count, auth.adminCount());
    // }
}
SOL

    INVARIANT_COUNT=$(grep -c "^    // function invariant_" "$OUT_SCAFFOLD" 2>/dev/null || echo 0)
    echo "  [ok] wrote scaffold with $INVARIANT_COUNT standard invariants to $OUT_SCAFFOLD"
    echo "  [next] adapt to your contract APIs and run: forge test --match-path 'src/test/InvariantL4*' --fuzz-runs 10000"
fi

echo

# ---------------------------------------------------------------------------
# Write status file
# ---------------------------------------------------------------------------
cat > "$OUT_STATUS" <<EOF
# Layer 4 Baseline Status

**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Script:** \`tools/layer4-baseline.sh\`
**Workspace:** $WS

## Mechanical output (zero agent tokens)

| Track | Artifact | Rows | Next step |
|---|---|---|---|
| R (red-team) | \`REDTEAM_REOPEN.md\` | $CLOSED_COUNT closures | Dispatch 1 agent (adversarial review) |
| A (adversarial read) | \`adversarial_targets.md\` | $HOTFUNC_COUNT ranked functions | Dispatch 3 agents (top 3 functions) |
| F (invariants) | \`InvariantL4_scaffold.sol\` | $INVARIANT_COUNT scaffolded invariants | Adapt to API, run \`forge test\` |

## Token-budget estimate (agent phase)

| Track | Agents | Budget | Fires if |
|---|---|---|---|
| R | 1 | ~2000 tokens | always |
| A | 3 | ~4500 tokens (1500 each) | always |
| F | 0-1 | ~1500 tokens | only on invariant-break |

**Total budget:** ≤ 10k tokens for a clean Layer 4 pass.

## Phase 5.5 entry criteria (check before running agents)

- [ ] RUBRIC_COVERAGE.md ≥ 90% resolved
- [ ] 3+ consecutive zero-finding iterations
- [ ] No open High/Critical findings pending PoC

Only when all 3 hold do you proceed to the agent phase.

## Phase 5.5 exit criteria (before Phase 6 graceful termination)

- [ ] Track R: every reopen candidate has a PoC OR a sharper closure
- [ ] Track A: every HIGH-confidence candidate is source-verified
- [ ] Track F: every adapted invariant passes ≥10k fuzz runs OR documented-skip
EOF

echo "============================================================================"
echo "Layer 4 baseline complete."
echo
echo "Mechanical artifacts:"
echo "  - $OUT_REDTEAM ($CLOSED_COUNT closures to review)"
echo "  - $OUT_TARGETS ($HOTFUNC_COUNT hot functions ranked)"
echo "  - $OUT_SCAFFOLD ($INVARIANT_COUNT invariants scaffolded)"
echo "  - $OUT_STATUS (status + next steps)"
echo
echo "Next: read $OUT_STATUS and dispatch the agent phase per methodology §5.5."
echo "============================================================================"
