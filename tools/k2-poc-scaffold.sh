#!/usr/bin/env bash
# k2-poc-scaffold.sh
#
# Scaffold a new Code4rena K2 PoC (Rust test + Markdown writeup).
#
# Usage:
#   ./tools/k2-poc-scaffold.sh <workspace> <slug> <severity> <target-contract>
#
# Example:
#   ./tools/k2-poc-scaffold.sh ~/audits/k2/src missing-auth-borrow Critical kinetic-router
#
# What it does:
#   1. Appends a new `#[test] fn test_<slug>()` to <workspace>/tests/c4/src/lib.rs,
#      pre-populated with the standard Setup::new(&env) fixture and TODO markers.
#   2. Emits a canonical finding writeup at <workspace>/../pocs/<slug>.md
#      (so for workspace ~/audits/k2/src, writeup goes to ~/audits/k2/pocs/<slug>.md).
#   3. Prints the exact command to run the PoC.
#
# Notes:
#   - The slug must be a valid Rust identifier fragment (lowercase, digits, hyphens/underscores).
#     Hyphens are rewritten to underscores for the test function name.
#   - Safe to re-run: appends new tests only; will refuse to overwrite an existing <slug>.md.
#   - Does NOT modify the top-of-file imports (they already cover every in-scope contract).

set -euo pipefail

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

usage() {
    cat <<EOF >&2
Usage: $0 <workspace> <slug> <severity> <target-contract>

Arguments:
  workspace        Path to the K2 src/ workspace (e.g. ~/audits/k2/src)
  slug             Short identifier, lowercase/hyphens (e.g. missing-auth-borrow)
  severity         One of: Critical | High | Medium | Low | QA
  target-contract  Contract the finding primarily targets (e.g. kinetic-router)

Example:
  $0 ~/audits/k2/src missing-auth-borrow Critical kinetic-router
EOF
    exit 2
}

if [ "$#" -ne 4 ]; then
    usage
fi

WORKSPACE="$1"
SLUG="$2"
SEVERITY="$3"
TARGET_CONTRACT="$4"

# Validate workspace layout.
if [ ! -f "$WORKSPACE/tests/c4/src/lib.rs" ]; then
    echo "Error: '$WORKSPACE/tests/c4/src/lib.rs' not found. Is '$WORKSPACE' the K2 src/ workspace?" >&2
    exit 1
fi

# Validate slug shape.
if ! printf '%s' "$SLUG" | grep -Eq '^[a-z0-9][a-z0-9_-]*$'; then
    echo "Error: slug '$SLUG' must be lowercase alphanumerics plus hyphens/underscores (starting with a letter/digit)." >&2
    exit 1
fi

# Rust-safe identifier (hyphens -> underscores).
FN_SUFFIX="$(printf '%s' "$SLUG" | tr '-' '_')"
FN_NAME="test_${FN_SUFFIX}"

# Validate severity.
case "$SEVERITY" in
    Critical|High|Medium|Low|QA) ;;
    *)
        echo "Error: severity must be one of Critical | High | Medium | Low | QA (got '$SEVERITY')." >&2
        exit 1
        ;;
esac

LIB_RS="$WORKSPACE/tests/c4/src/lib.rs"
POCS_DIR="$(cd "$WORKSPACE/.." && pwd)/pocs"
MD_FILE="$POCS_DIR/${SLUG}.md"

mkdir -p "$POCS_DIR"

# --------------------------------------------------------------------------
# Refuse to clobber an existing test or writeup.
# --------------------------------------------------------------------------

if grep -q "fn ${FN_NAME}\b" "$LIB_RS"; then
    echo "Error: a test named '${FN_NAME}' already exists in $LIB_RS." >&2
    exit 1
fi

if [ -e "$MD_FILE" ]; then
    echo "Error: writeup '$MD_FILE' already exists — refusing to overwrite." >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Append the test function to lib.rs.
# --------------------------------------------------------------------------

# Ensure the file ends with a newline before we append.
if [ -s "$LIB_RS" ] && [ "$(tail -c 1 "$LIB_RS" | wc -l | tr -d ' ')" -eq 0 ]; then
    printf '\n' >> "$LIB_RS"
fi

cat >> "$LIB_RS" <<EOF

// =============================================================================
// PoC: ${SLUG} (${SEVERITY}) — target: ${TARGET_CONTRACT}
// Scaffolded by tools/k2-poc-scaffold.sh. Replace TODOs with exploit steps.
// =============================================================================

/// Proof-of-Concept for finding \`${SLUG}\` (severity: ${SEVERITY}).
///
/// Target contract: \`${TARGET_CONTRACT}\`.
///
/// This test passes by default. Replace the TODO markers with the
/// exploit sequence and the corresponding assertion; the final
/// \`assert!\` must fail on the vulnerable codebase and pass after the
/// fix (or vice-versa, per the writeup).
#[test]
fn ${FN_NAME}() {
    let env = Env::default();
    let setup = Setup::new(&env);

    // Sanity: the fresh fixture starts clean.
    assert_eq!(
        setup.asset_a_token.balance(&setup.user),
        USER_STARTING_BALANCE,
        "fixture broken: user should start with USER_STARTING_BALANCE of asset_a",
    );

    // ------------------------------------------------------------------
    // TODO: trigger the bug here.
    //
    // Typical shape:
    //   1. Put the protocol into the pre-exploit state
    //      (e.g. setup.router.supply(...), setup.router.borrow(...)).
    //   2. Execute the offending call — use .try_*() if the vulnerable
    //      path is expected to succeed or revert under specific conditions.
    //   3. Advance ledger time / sequence with env.ledger().set(...) if
    //      the bug needs accrual or TTL expiry.
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Assert exploit succeeded.
    //
    // Examples:
    //   let account = setup.router.get_user_account_data(&setup.user);
    //   assert!(account.health_factor < k2_shared::WAD,
    //           "bug: HF < 1.0 should have been rejected");
    //
    //   assert!(result.is_ok(), "bug: unsafe call succeeded");
    // ------------------------------------------------------------------
}
EOF

# --------------------------------------------------------------------------
# Emit the canonical finding writeup.
# --------------------------------------------------------------------------

RUN_CMD="cd ${WORKSPACE} && cargo test --package k2-c4 ${FN_NAME} -- --nocapture"

cat > "$MD_FILE" <<EOF
# Finding: ${SLUG}

**Target:** \`${TARGET_CONTRACT}\`
**Severity:** ${SEVERITY}

## Finding Title

<TODO: one-sentence title, e.g. "Missing auth on \`Router::borrow\` allows arbitrary debt minting">

## Summary

<TODO: 1-3 sentence description of the bug. What is broken and why.>

## Finding Description

<TODO: deeper walkthrough of the vulnerable code path. Reference the exact
function(s), lines, and invariant that is violated. Explain any preconditions
the attacker must set up first.>

## Impact

<TODO: what an attacker gains / what users lose. Quantify if possible
(e.g. "drains N% of reserve liquidity in one transaction").>

## Likelihood

<TODO: how easy is this to trigger in practice? Any attacker-controlled
knobs, any economic or permissioning barriers.>

## Proof of Concept

Extend the Code4rena PoC harness at \`tests/c4/src/lib.rs\`. The scaffolded
test is named \`${FN_NAME}\`. To run it:

\`\`\`bash
${RUN_CMD}
\`\`\`

\`\`\`rust
#[test]
fn ${FN_NAME}() {
    let env = Env::default();
    let setup = Setup::new(&env);

    // TODO: trigger the bug here.
    //   - Use setup.router, setup.oracle, setup.asset_a, setup.asset_b, etc.
    //   - Call setup.router.try_* when you want to observe a revert.
    //   - Advance time with env.ledger().set(LedgerInfo { timestamp: ..., .. });

    // Assert exploit succeeded.
    //   assert!(...);
}
\`\`\`

## Recommendation

<TODO: minimal patch that closes the issue. Reference the exact file/lines
the fix belongs in. If there are alternative designs, list them with tradeoffs.>
EOF

# --------------------------------------------------------------------------
# Done.
# --------------------------------------------------------------------------

echo "Scaffolded PoC '${SLUG}' (${SEVERITY}) targeting '${TARGET_CONTRACT}'."
echo "  Test function: ${FN_NAME}  in  ${LIB_RS}"
echo "  Writeup:       ${MD_FILE}"
echo ""
echo "Run it with:"
echo "  ${RUN_CMD}"
