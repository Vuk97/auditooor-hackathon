#!/usr/bin/env bash
# ws-resolve-guard.sh <label> <resolved-workspace-path>
#
# Shared fail-loud guard for every `make <target> WS=...` recipe. Two checks:
#
#   1. The resolved path must exist and be a directory (the pre-existing
#      `[ ! -d "$(_WS_RESOLVED)" ]` check every recipe used to inline).
#
#   2. The resolved path must not be an accidental STUB. Root cause: when
#      WS=<relative-name> is passed (no `~/audits/` prefix), `_WS_RESOLVED`
#      (Makefile ~3079) leaves it untouched and every downstream tool resolves
#      it relative to CURDIR - which, when `make` is invoked from inside
#      auditooor-mcp/, can silently match a near-empty leftover directory
#      right there (e.g. auditooor-mcp/dydx/ containing only
#      `.auditooor/mcp_call_log.jsonl`, auto-vivified by a prior MCP call's
#      `Path(...).mkdir(parents=True)`) instead of the REAL workspace at
#      ~/audits/dydx/. The old `-d` check happily passed on that stub, so
#      `make audit-complete WS=dydx` graded an empty directory and returned a
#      misleading "pass / no solidity source" verdict instead of erroring.
#
#      A stub is a directory with NO workspace marker (docs/SCOPE.md,
#      docs/SEVERITY.md, README*, src/, contracts/, test(s)/, submissions/)
#      and NO source file of a tracked audit language anywhere under it
#      (excluding .auditooor/, which is harness bookkeeping and proves
#      nothing about the workspace's real content).
set -euo pipefail

label="${1:?usage: ws-resolve-guard.sh <label> <resolved-path>}"
ws="${2:?usage: ws-resolve-guard.sh <label> <resolved-path>}"

if [ ! -d "$ws" ]; then
  echo "[$label] ERR workspace not found or not a directory: $ws" >&2
  exit 2
fi

has_marker=0
for marker in docs/SCOPE.md docs/SEVERITY.md README.md README src contracts test tests submissions; do
  if [ -e "$ws/$marker" ]; then
    has_marker=1
    break
  fi
done

has_source=0
if [ "$has_marker" -eq 0 ]; then
  if find "$ws" -path "$ws/.auditooor" -prune -o \
       -type f \( -name '*.sol' -o -name '*.go' -o -name '*.rs' -o -name '*.move' \
                  -o -name '*.vy' -o -name '*.cairo' -o -name '*.circom' -o -name '*.ts' \
                  -o -name '*.py' -o -name '*.js' -o -name '*.c' -o -name '*.cpp' \) \
       -print -quit 2>/dev/null | grep -q .; then
    has_source=1
  fi
fi

if [ "$has_marker" -eq 0 ] && [ "$has_source" -eq 0 ]; then
  {
    echo "[$label] ERR resolved workspace looks like an EMPTY STUB, not a real audit workspace: $ws"
    echo "  It has no docs/SCOPE.md, docs/SEVERITY.md, README, src/, contracts/, test(s)/,"
    echo "  submissions/ marker, and no source files (.sol/.go/.rs/.move/...) outside .auditooor/."
    echo "  This usually means WS=<relative-name> resolved against the WRONG cwd (e.g. an"
    echo "  auditooor-mcp/<name>/ leftover stub) instead of the real workspace, typically"
    echo "  under ~/audits/<name>. Refusing to silently grade the stub (would report a"
    echo "  misleading pass / no-solidity-source verdict). Pass an explicit path, e.g."
    echo "  WS=~/audits/<name>."
  } >&2
  exit 2
fi

exit 0
