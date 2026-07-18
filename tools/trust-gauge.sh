#!/usr/bin/env bash
# trust-gauge.sh — thin shell wrapper around tools/trust-gauge.py
#
# Build agent picked Python for the implementation (clean argparse, JSON
# emission, hermetic subprocess.run mocking in tests).  This shell entrypoint
# preserves the name promised in PR #127's plan / dispatch and is what the
# rest of the audit toolchain calls (other tools/*.sh wrappers exec a Python
# module the same way — see tools/originality-grep.sh / tools/scope-review.sh).
#
# Usage:
#   ./tools/trust-gauge.sh <submission.md> [--bundle] [--include-scope-verdict]
#                                          [--workspace <dir>]
#                                          [--out-dir <dir>] [--json-only]
#
# Exit codes are forwarded verbatim from trust-gauge.py:
#   0   READY
#   1   REVIEW
#   2   BLOCK
#   >=64 wrapper / tooling error

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/trust-gauge.py" "$@"
