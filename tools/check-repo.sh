#!/bin/sh
# tools/check-repo.sh — fail fast if not inside the auditooor repo tree.
# Source at start of any agent script. Exits non-zero if pwd is wrong.
#
# iter13 T5: iter12 lost 2 of 5 agents to wrong-worktree routing (landed in
# the clob2 polymarket trading-bot repo). Sourcing this at prompt start
# catches the misroute before any destructive action.
CURRENT="$(pwd -P)"

# Optional local guard for the persistent Claude machine. CI and other clones
# should not inherit a Mac-specific path; they are validated by git metadata.
EXPECTED_PREFIX="${AUDITOOOR_EXPECTED_PREFIX:-}"
if [ -n "$EXPECTED_PREFIX" ]; then
    case "$CURRENT" in
        $EXPECTED_PREFIX*)
            # In-repo or in one of its worktrees (prefix match). OK.
            ;;
        *)
            echo "[check-repo] ERR: pwd='$CURRENT' is outside $EXPECTED_PREFIX" >&2
            echo "[check-repo] ERR: did the agent get routed to the wrong worktree? Try 'cd $EXPECTED_PREFIX'." >&2
            exit 2
            ;;
    esac
fi

TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "[check-repo] ERR: pwd='$CURRENT' is not inside a git repo" >&2
    exit 2
}

# Repo identity is verified by the origin remote URL — NOT by the basename of
# the worktree directory. Auditooor worktrees commonly live at paths like
# /private/tmp/wt-<branch>/ or /Users/wolf/claude/wt-<branch>/, so a basename
# check on the toplevel breaks every detached worktree. The origin URL is the
# canonical "this is the right repo" signal.
ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"
case "$ORIGIN_URL" in
    *auditooor*|*Vuk97/auditooor*)
        ;;
    *)
        echo "[check-repo] ERR: origin remote does not look like auditooor: ${ORIGIN_URL:-<missing>}" >&2
        echo "[check-repo] ERR: git root was '$TOPLEVEL'" >&2
        exit 3
        ;;
esac

# Local persistent agents should usually have the long-lived claudeboy ref, but
# GitHub Actions PR checkouts may not. Treat this as optional unless the caller
# explicitly asks for it.
if [ "${AUDITOOOR_REQUIRE_CLAUDEBOY_REF:-0}" = "1" ]; then
    git rev-parse --verify origin/claudeboy >/dev/null 2>&1 || {
        echo "[check-repo] ERR: no origin/claudeboy ref. Wrong repo?" >&2
        exit 3
    }
fi

exit 0
