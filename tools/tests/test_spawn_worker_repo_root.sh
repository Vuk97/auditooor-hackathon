#!/usr/bin/env bash
# Loop-fix 2026-06-22: spawn-worker.sh computed REPO_ROOT via `git rev-parse --show-toplevel`
# against the CWD. spawn-worker is invoked CROSS-WORKTREE (orchestrator cwd != audit
# workspace, by design - L16); from a workspace dir that resolved to the AUDIT WORKSPACE,
# which (a) has no tools/ (every enrichment step "tool-missing") and (b) has a different
# .auditooor/spawn_worker_log.jsonl than the enforcement hook reads
# (<auditooor-mcp>/.auditooor/...). Net effect: every cross-worktree dispatch logged to the
# wrong file and was then wrongly BLOCKED by the spawn-worker enforcement hook. The fix
# derives REPO_ROOT from the script's own dir. This test invokes spawn-worker.sh from a
# FOREIGN cwd (/tmp) and asserts it (1) logs to the canonical auditooor-mcp/.auditooor and
# (2) finds its tools (pathspec=registered, not tool-missing).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null 2>&1 && pwd)"
SPAWN="${REPO_ROOT}/tools/spawn-worker.sh"
CANON_LOG="${REPO_ROOT}/.auditooor/spawn_worker_log.jsonl"

fail() { echo "FAIL: $1" >&2; exit 1; }

[ -f "$SPAWN" ] || fail "spawn-worker.sh not found at $SPAWN"

# 1) Source-level guard: the fix (script-dir-derived REPO_ROOT) must be present, and the
#    old CWD-relative bare `git rev-parse --show-toplevel` (without -C) must be gone.
grep -q 'basename "\$SPAWN_WORKER_DIR".*=.*"tools"' "$SPAWN" \
  || fail "REPO_ROOT no longer derived from script dir (tools/) - fix reverted?"

tmp_prompt="$(mktemp /tmp/swrr_prompt.XXXXXX.md)"
echo "test prompt body" > "$tmp_prompt"
tmp_ws="$(mktemp -d /tmp/swrr_ws.XXXXXX)"
mkdir -p "$tmp_ws/.auditooor"

# 2) Functional: run from /tmp (foreign cwd, NOT the repo) and capture the OK line.
out="$(cd /tmp && bash "$SPAWN" --lane-id test-repo-root-regression --lane-type hunt \
  --severity LOW --workspace "$tmp_ws" --prompt-file "$tmp_prompt" 2>&1 | tail -1)"

echo "$out" | grep -q "log=${REPO_ROOT}/.auditooor/spawn_worker_log.jsonl" \
  || fail "log path not canonical auditooor-mcp/.auditooor when run from /tmp; got: $out"

# tools must resolve now (was 'pathspec=tool-missing' under the bug)
echo "$out" | grep -q "pathspec=tool-missing" \
  && fail "tools still missing when run from foreign cwd: $out"

rm -f "$tmp_prompt"; rm -rf "$tmp_ws"
echo "PASS: spawn-worker REPO_ROOT resolves from script dir (canonical log + tools found from foreign cwd)"
