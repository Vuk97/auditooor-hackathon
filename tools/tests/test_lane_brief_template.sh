#!/usr/bin/env bash
# Focused regression test for tools/lane-brief-template.sh (Capability Gap #28).
#
# Verifies:
#   1. hunt|drill|comp|fuzz lane types include the FULL hacker MCP stack.
#   2. filing lane type includes finalization + originality, NOT hacker stack.
#   3. tool-build lane type includes ONLY the foundation (no hacker, no filing).
#   4. Every generated brief includes the R36 / R55 / L34 discipline reminders.
#   5. Required-reply section uses the verbatim labels.
#   6. The Section 2 pathspec example mentions comma-separated literal files
#      (per CODEX-3 register API).
#   7. Required args are enforced (missing --lane-id / --lane-type / --workspace).
#   8. Invalid --lane-type values are rejected.
#   9. --output writes to a file and reports the line count.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TOOL="$REPO/tools/lane-brief-template.sh"

if [ ! -x "$TOOL" ]; then
  echo "[test_lane_brief_template] FAIL: $TOOL not executable" >&2
  exit 1
fi

SANDBOX="$(mktemp -d -t lane-brief-test.XXXXXX)"
trap 'rm -rf "$SANDBOX"' EXIT

FAIL=0
PASS=0

assert_contains() {
  local label="$1" file="$2" needle="$3"
  if grep -qF -- "$needle" "$file"; then
    PASS=$((PASS+1))
  else
    echo "[test_lane_brief_template] FAIL ($label): missing '$needle' in $file" >&2
    FAIL=$((FAIL+1))
  fi
}

assert_not_contains() {
  local label="$1" file="$2" needle="$3"
  if grep -qF -- "$needle" "$file"; then
    echo "[test_lane_brief_template] FAIL ($label): unexpected '$needle' in $file" >&2
    FAIL=$((FAIL+1))
  else
    PASS=$((PASS+1))
  fi
}

# ---------------------------------------------------------------------------
# Case 1-4: hunt|drill|comp|fuzz emit the full hacker stack.
# ---------------------------------------------------------------------------
for ltype in hunt drill comp fuzz; do
  OUT="$SANDBOX/brief-$ltype.md"
  bash "$TOOL" --lane-id "lane-$ltype-1" --lane-type "$ltype" \
    --workspace /tmp/fake-ws --severity HIGH --quiet --output "$OUT" \
    >/dev/null 2>&1
  if [ ! -s "$OUT" ]; then
    echo "[test_lane_brief_template] FAIL: $ltype produced empty output" >&2
    FAIL=$((FAIL+1))
    continue
  fi

  # Foundation (always-on) callables:
  assert_contains "$ltype-foundation" "$OUT" "vault_resume_context"
  assert_contains "$ltype-foundation" "$OUT" "vault_known_dead_ends"
  assert_contains "$ltype-foundation" "$OUT" "vault_invariant_library"
  assert_contains "$ltype-foundation" "$OUT" "vault_capability_inventory"
  assert_contains "$ltype-foundation" "$OUT" "vault_lane_cooldown_check"

  # Hacker stack (the gap-28 fix):
  assert_contains "$ltype-hackerstack" "$OUT" "vault_brain_prime_context"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_hackerman_chain_candidates"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_hackerman_detector_relationships"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_hackerman_exploit_predicates"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_hackerman_novel_vector_context"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_hacker_brief_for_lane_v3"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_chained_attack_plan_context"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_adversarial_hypothesis_differential"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_attack_class_taxonomy"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_attack_class_evidence_v3"
  assert_contains "$ltype-hackerstack" "$OUT" "vault_function_mindset"

  # Discipline reminders (R36 / R55 / L34 / R37 / R60 / R47 / R53):
  assert_contains "$ltype-discipline" "$OUT" "L34"
  assert_contains "$ltype-discipline" "$OUT" "R36"
  assert_contains "$ltype-discipline" "$OUT" "R55"
  assert_contains "$ltype-discipline" "$OUT" "R37"
  assert_contains "$ltype-discipline" "$OUT" "R60"
  assert_contains "$ltype-discipline" "$OUT" "R47 / R53"
  assert_contains "$ltype-oos-preflight" "$OUT" "dispatch_oos_preflight.py"
  assert_contains "$ltype-oos-preflight" "$OUT" "extension-distinct argument"

  # Required-reply labels (verbatim):
  assert_contains "$ltype-reply" "$OUT" "== LANE REPLY =="
  assert_contains "$ltype-reply" "$OUT" "context_pack_id:"
  assert_contains "$ltype-reply" "$OUT" "context_pack_hash:"
  assert_contains "$ltype-reply" "$OUT" "files_touched:"

  # CODEX-3 comma-separated literal pathspec example:
  assert_contains "$ltype-pathspec" "$OUT" "agent-pathspec-register.py register"
  assert_contains "$ltype-pathspec" "$OUT" "comma,separated,LITERAL,file,paths"
done

# ---------------------------------------------------------------------------
# Case 5: filing lane includes finalization + originality, NOT hacker stack.
# ---------------------------------------------------------------------------
OUT_FILING="$SANDBOX/brief-filing.md"
bash "$TOOL" --lane-id "lane-filing-1" --lane-type filing \
  --workspace /tmp/fake-ws --severity HIGH --quiet --output "$OUT_FILING" \
  >/dev/null 2>&1

assert_contains "filing-foundation" "$OUT_FILING" "vault_resume_context"
assert_contains "filing-foundation" "$OUT_FILING" "vault_invariant_library"
assert_contains "filing-stack" "$OUT_FILING" "vault_finalization_context"
assert_contains "filing-stack" "$OUT_FILING" "vault_originality_context"
assert_contains "filing-stack" "$OUT_FILING" "vault_dupe_rejection_context"
# Hacker stack callables must be ABSENT:
assert_not_contains "filing-no-hackerstack" "$OUT_FILING" "vault_brain_prime_context"
assert_not_contains "filing-no-hackerstack" "$OUT_FILING" "vault_hackerman_chain_candidates"
assert_not_contains "filing-no-hackerstack" "$OUT_FILING" "vault_adversarial_hypothesis_differential"
# Discipline + reply still present:
assert_contains "filing-discipline" "$OUT_FILING" "L34"
assert_contains "filing-oos-preflight" "$OUT_FILING" "dispatch_oos_preflight.py"
assert_contains "filing-reply" "$OUT_FILING" "== LANE REPLY =="

# ---------------------------------------------------------------------------
# Case 6: tool-build lane includes only the foundation (no hacker, no filing).
# ---------------------------------------------------------------------------
OUT_TOOLBUILD="$SANDBOX/brief-toolbuild.md"
bash "$TOOL" --lane-id "lane-toolbuild-1" --lane-type tool-build \
  --workspace /tmp/fake-ws --quiet --output "$OUT_TOOLBUILD" \
  >/dev/null 2>&1

assert_contains "toolbuild-foundation" "$OUT_TOOLBUILD" "vault_resume_context"
assert_contains "toolbuild-foundation" "$OUT_TOOLBUILD" "vault_capability_inventory"
assert_not_contains "toolbuild-no-hackerstack" "$OUT_TOOLBUILD" "vault_brain_prime_context"
assert_not_contains "toolbuild-no-hackerstack" "$OUT_TOOLBUILD" "vault_hackerman_chain_candidates"
assert_not_contains "toolbuild-no-filing" "$OUT_TOOLBUILD" "vault_finalization_context"
# Discipline + reply still present:
assert_contains "toolbuild-discipline" "$OUT_TOOLBUILD" "R36"
assert_contains "toolbuild-oos-preflight" "$OUT_TOOLBUILD" "dispatch_oos_preflight.py"
assert_contains "toolbuild-reply" "$OUT_TOOLBUILD" "== LANE REPLY =="

# ---------------------------------------------------------------------------
# Case 7: missing required args exits non-zero.
# ---------------------------------------------------------------------------
if bash "$TOOL" --lane-id missing-ws --lane-type hunt --quiet \
  >/dev/null 2>&1; then
  echo "[test_lane_brief_template] FAIL: missing --workspace should exit non-zero" >&2
  FAIL=$((FAIL+1))
else
  PASS=$((PASS+1))
fi

if bash "$TOOL" --lane-type hunt --workspace /tmp/x --quiet \
  >/dev/null 2>&1; then
  echo "[test_lane_brief_template] FAIL: missing --lane-id should exit non-zero" >&2
  FAIL=$((FAIL+1))
else
  PASS=$((PASS+1))
fi

# ---------------------------------------------------------------------------
# Case 8: invalid --lane-type rejected.
# ---------------------------------------------------------------------------
if bash "$TOOL" --lane-id bad --lane-type nonsense \
  --workspace /tmp/x --quiet >/dev/null 2>&1; then
  echo "[test_lane_brief_template] FAIL: invalid --lane-type should be rejected" >&2
  FAIL=$((FAIL+1))
else
  PASS=$((PASS+1))
fi

# ---------------------------------------------------------------------------
# Case 9: --output writes a file with non-zero line count and the script
# echoes a status line when not --quiet.
# ---------------------------------------------------------------------------
OUT_LOUD="$SANDBOX/brief-loud.md"
STATUS_LINE="$(bash "$TOOL" --lane-id loud --lane-type hunt \
  --workspace /tmp/fake-ws --output "$OUT_LOUD" 2>&1)"
if [ ! -s "$OUT_LOUD" ]; then
  echo "[test_lane_brief_template] FAIL: --output produced empty file" >&2
  FAIL=$((FAIL+1))
else
  PASS=$((PASS+1))
fi
case "$STATUS_LINE" in
  *"wrote: $OUT_LOUD"*) PASS=$((PASS+1)) ;;
  *)
    echo "[test_lane_brief_template] FAIL: status line missing 'wrote: $OUT_LOUD'" >&2
    echo "  got: $STATUS_LINE" >&2
    FAIL=$((FAIL+1))
    ;;
esac

echo "[test_lane_brief_template] PASS=$PASS FAIL=$FAIL"
exit $FAIL
