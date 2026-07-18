#!/usr/bin/env bash
# file-slither-bug.sh — DISABLED as of R76.
#
# Policy change: we no longer file upstream bugs at crytic/slither.
# Upstream turnaround is too slow for our engagements. We patch
# Slither locally via tools/apply-slither-patch.sh and carry the
# patches with us.
#
# If you hit a new Slither IR-gen crash:
#   1. Capture a minimal repro.
#   2. Add a defensive branch in tools/apply-slither-patch.sh.
#   3. Run bash tools/apply-slither-patch.sh to install the patch.
#   4. Document the crash class in the patch file's header comment.
#
# DO NOT re-open upstream filing. See reference/slither_issues_filed.md
# for the R76 policy and the 3 closed historical issues.

cat <<'MSG' >&2
[file-slither-bug.sh] DISABLED as of R76.

Policy: we patch Slither locally — we do not file upstream.

To add a local patch for a new IR-gen crash:
  1. Edit tools/apply-slither-patch.sh — add a defensive branch.
  2. Run: bash tools/apply-slither-patch.sh
  3. Document the crash class in the patch file header.

See reference/slither_issues_filed.md for the full policy.
MSG
exit 2
